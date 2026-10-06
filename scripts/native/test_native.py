import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

from piston_native import NativeMachine, PEImage
from piston_native.__main__ import compare, run_fixture


def pe_fixture(path):
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x8664, 2)
    struct.pack_into("<H", data, 0x94, 0xF0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 56, 0x4000, 0x200)
    for index, (rva, raw, flags) in enumerate([(0x1000, 0x200, 0x60000020), (0x2000, 0x400, 0xC0000040)]):
        at = optional + 0xF0 + index * 40
        struct.pack_into("<IIII", data, at + 8, 0x1000, rva, 0x200, raw)
        struct.pack_into("<I", data, at + 36, flags)
    # Windows ABI: add(rcx,rdx), fifth argument, deliberately infinite loop.
    data[0x200:0x207] = bytes.fromhex("4889c84801d0c3")
    data[0x210:0x216] = bytes.fromhex("488b442428c3")
    data[0x220:0x222] = bytes.fromhex("ebfe")
    data[0x230:0x236] = bytes.fromhex("e81b000000c3")
    data[0x250] = 0xC3
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.binary = Path(self.directory.name) / "fixture.exe"
        self.sha256 = pe_fixture(self.binary)
        self.image = PEImage(self.binary, self.sha256)

    def test_windows_abi_and_declared_boundaries(self):
        machine = NativeMachine(self.image)
        self.assertEqual(machine.call(self.image.base + 0x1000, 5, 7), 12)
        self.assertEqual(machine.call(self.image.base + 0x1010, extra=(123,)), 123)
        machine.hook_return(self.image.base + 0x1050, 42)
        self.assertEqual(machine.call(self.image.base + 0x1030), 42)
        self.assertEqual(len(machine.boundaries), 1)
        self.assertEqual(len(self.image.disassemble(self.image.base + 0x1000, 7)), 3)

    def test_virtual_tail_is_zero_and_unknown_memory_fails(self):
        machine = NativeMachine(self.image)
        machine.load_page(self.image.base + 0x2000)
        self.assertEqual(bytes(machine.uc.mem_read(self.image.base + 0x2200, 16)), bytes(16))
        with self.assertRaises(ValueError):
            machine.load_page(self.image.base + 0x4000)
        with self.assertRaises(ValueError):
            PEImage(self.binary, "0" * 64)
        with self.assertRaises(RuntimeError):
            machine.call(self.image.base + 0x1020, instruction_limit=10)

    def test_cases_are_isolated_and_translation_comparison_detects_mismatch(self):
        fixture = {"format": 1, "sha256": self.sha256, "cases": [
            {"id": str(n), "entry_rva": "0x1000", "registers": {"RCX": n, "RDX": 9},
             "input": {"a": n, "b": 9}, "observe": [{"name": "sum", "register": "RAX"}]} for n in range(4)
        ]}
        results = run_fixture(self.binary, fixture)
        comparator = Path(self.directory.name) / "compare.py"
        comparator.write_text("import sys,json\nfor line in sys.stdin:\n r=json.loads(line); print(json.dumps({'id':r['id'],'observed':{'sum':hex(r['input']['a']+r['input']['b'])}}))\n")
        self.assertEqual(compare(results, [sys.executable, str(comparator)]), [])
        results["cases"][1]["observed"]["sum"] = "0x0"
        self.assertEqual([r["id"] for r in compare(results, [sys.executable, str(comparator)])], ["1"])
        comparator.write_text("print('{}')")
        with self.assertRaises((ValueError, KeyError)):
            compare(results, [sys.executable, str(comparator)])

    def test_reject_duplicate_cases_and_invalid_memory_observations(self):
        case = {"id": "a", "entry_rva": "0x1000", "observe": [{"name": "memory", "address": "0x7000000000", "length": 0}]}
        fixture = {"format": 1, "sha256": self.sha256, "cases": [case]}
        with self.assertRaises(ValueError):
            run_fixture(self.binary, fixture)
        case["observe"] = [{"name": "sum", "register": "RAX"}]
        fixture["cases"].append(case)
        with self.assertRaises(ValueError):
            run_fixture(self.binary, fixture)


if __name__ == "__main__":
    unittest.main()
