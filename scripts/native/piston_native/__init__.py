"""Execute selected PE x64 instructions with explicit fixture boundaries."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn import x86_const

PAGE = 4096


def integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


@dataclass(frozen=True)
class Section:
    rva: int
    size: int
    raw: int
    raw_size: int
    flags: int


class PEImage:
    """Validate and map sections, including zero-filled virtual tails."""

    def __init__(self, path: Path, expected_sha256: str | None = None):
        self.data = Path(path).read_bytes()
        self.sha256 = hashlib.sha256(self.data).hexdigest()
        if expected_sha256 is not None and self.sha256 != expected_sha256:
            raise ValueError("Binary SHA-256 does not match the fixture build")
        data = self.data
        if data[:2] != b"MZ" or len(data) < 64:
            raise ValueError("Expected a PE x64 image")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("Invalid PE signature")
        machine, count = struct.unpack_from("<HH", data, pe + 4)
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        optional = pe + 24
        if machine != 0x8664 or optional_size < 112 or struct.unpack_from("<H", data, optional)[0] != 0x20B:
            raise ValueError("Only PE32+ AMD64 is supported")
        self.base = struct.unpack_from("<Q", data, optional + 24)[0]
        self.header_size = struct.unpack_from("<I", data, optional + 60)[0]
        image_size = struct.unpack_from("<I", data, optional + 56)[0]
        self.sections = []
        for index in range(count):
            at = optional + optional_size + index * 40
            virtual_size, rva, raw_size, raw = struct.unpack_from("<IIII", data, at + 8)
            flags = struct.unpack_from("<I", data, at + 36)[0]
            size = max(virtual_size, raw_size)
            if raw + raw_size > len(data) or rva + size > image_size:
                raise ValueError("PE section exceeds the image or file")
            if any(rva < s.rva + s.size and s.rva < rva + size for s in self.sections):
                raise ValueError("Overlapping PE sections")
            self.sections.append(Section(rva, size, raw, raw_size, flags))
        if self.header_size > len(data):
            raise ValueError("PE headers exceed file")

    def read(self, address: int, size: int) -> bytes:
        result = bytearray()
        cursor = address - self.base
        while len(result) < size:
            section = next((s for s in self.sections if s.rva <= cursor < s.rva + s.size), None)
            if section is None:
                if not 0 <= cursor < self.header_size:
                    raise ValueError(f"Address outside PE sections: {address + len(result):#x}")
                take = min(size - len(result), self.header_size - cursor)
                result.extend(self.data[cursor:cursor + take])
            else:
                relative = cursor - section.rva
                take = min(size - len(result), section.size - relative)
                stored = min(take, max(0, section.raw_size - relative))
                result.extend(self.data[section.raw + relative:section.raw + relative + stored])
                result.extend(bytes(take - stored))
            cursor += take
        return bytes(result)

    def page(self, address: int) -> bytes:
        page = bytearray(PAGE)
        found = False
        for start, size, raw, stored in [(self.base, self.header_size, 0, self.header_size)] + [
            (self.base + s.rva, s.size, s.raw, s.raw_size) for s in self.sections
        ]:
            begin, end = max(address, start), min(address + PAGE, start + size)
            if begin >= end:
                continue
            found = True
            backed = min(end, start + stored)
            if backed > begin:
                page[begin - address:backed - address] = self.data[raw + begin - start:raw + backed - start]
        if not found:
            raise ValueError(f"Unmapped fixture access at {address:#x}")
        return bytes(page)

    def disassemble(self, address: int, size: int = 256):
        if not 1 <= size <= 65536:
            raise ValueError("Disassembly size must be 1 to 65536")
        return [{"address": hex(i.address), "bytes": i.bytes.hex(), "text": f"{i.mnemonic} {i.op_str}".strip()}
                for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(self.read(address, size), address)]


class NativeMachine:
    """Windows x64 ABI calls; fresh machine state isolates separate cases."""

    def __init__(self, image: PEImage, arena: int = 0x7000000000, arena_size: int = 0x40000):
        if any(arena < image.base + s.rva + s.size and image.base + s.rva < arena + arena_size for s in image.sections):
            raise ValueError("Fixture arena overlaps the binary image")
        self.image = image
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.loaded = set()
        self.arena, self.arena_size = arena, arena_size
        self.uc.mem_map(arena, arena_size)
        self.loaded.update(range(arena, arena + arena_size, PAGE))
        self.stop = arena + arena_size - PAGE
        self.stack = self.stop - PAGE + 8
        self.next_address = arena + 0x100
        self.boundaries = []
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)

    def _unmapped(self, machine, access, address, size, value, context):
        for page in range(address & -PAGE, (address + size + PAGE - 1) & -PAGE, PAGE):
            self.load_page(page)
        return True

    def load_page(self, address: int):
        page = address & -PAGE
        if page not in self.loaded:
            contents = self.image.page(page)
            self.uc.mem_map(page, PAGE)
            self.uc.mem_write(page, contents)
            self.loaded.add(page)

    def write(self, address: int, data: bytes):
        for page in range(address & -PAGE, (address + len(data) + PAGE - 1) & -PAGE, PAGE):
            self.load_page(page)
        self.uc.mem_write(address, data)

    def allocate(self, size: int = 128) -> int:
        if size <= 0:
            raise ValueError("Allocation size must be positive")
        address = self.next_address
        next_address = address + ((size + 31) & -32)
        if next_address > self.stack - PAGE:
            raise ValueError("Fixture arena exhausted")
        self.next_address = next_address
        return address

    def qword(self, address: int, value: int):
        self.write(address, struct.pack("<Q", value))

    def return_from_boundary(self, value: int = 0):
        self.uc.reg_write(x86_const.UC_X86_REG_RAX, value)
        stack = self.uc.reg_read(x86_const.UC_X86_REG_RSP)
        target = struct.unpack("<Q", self.uc.mem_read(stack, 8))[0]
        self.uc.reg_write(x86_const.UC_X86_REG_RSP, stack + 8)
        self.uc.reg_write(x86_const.UC_X86_REG_RIP, target)

    def hook_return(self, address: int, value: int = 0):
        self.boundaries.append({"address": hex(address), "kind": "return", "value": hex(value)})
        self.load_page(address)
        self.uc.hook_add(UC_HOOK_CODE, lambda *_: self.return_from_boundary(value), begin=address, end=address)

    @staticmethod
    def register(name: str):
        allowed = {"RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "RIP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "EFLAGS"}
        allowed.update(f"XMM{i}" for i in range(16))
        if name.upper() not in allowed:
            raise ValueError(f"Unsupported register: {name}")
        return getattr(x86_const, "UC_X86_REG_" + name.upper())

    def call(self, address: int, rcx=0, rdx=0, r8=0, r9=0, *, extra=(), registers=None, instruction_limit=30000, timeout_ms=1000):
        if not 1 <= instruction_limit <= 1000000 or not 1 <= timeout_ms <= 10000:
            raise ValueError("Invalid execution bounds")
        if len(extra) > 32:
            raise ValueError("Use at most 32 stack arguments")
        self.qword(self.stack, self.stop)
        for index, value in enumerate(extra):
            self.qword(self.stack + 0x28 + index * 8, value)
        for name, value in {"RSP": self.stack, "RCX": rcx, "RDX": rdx, "R8": r8, "R9": r9, **(registers or {})}.items():
            if name.upper() in {"RSP", "RIP"} and registers and name in registers:
                raise ValueError("The fixture owns RSP and RIP")
            self.uc.reg_write(self.register(name), integer(value))
        try:
            self.uc.emu_start(address, self.stop, count=instruction_limit, timeout=timeout_ms * 1000)
        except UcError as error:
            raise RuntimeError(f"Native instructions failed at {self.uc.reg_read(x86_const.UC_X86_REG_RIP):#x}: {error}") from error
        if self.uc.reg_read(x86_const.UC_X86_REG_RIP) != self.stop:
            raise RuntimeError("Native function did not return within the execution bounds")
        return self.uc.reg_read(x86_const.UC_X86_REG_RAX)
