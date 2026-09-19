#!/usr/bin/env python3
"""Capture a licensed Xodus executable handoff, then continue the normal launch."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from datetime import datetime, timezone


def digest(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write_private(path, content, executable=False):
    with open(path, "x", encoding="utf-8") as target:
        os.chmod(path, 0o700 if executable else 0o600)
        target.write(content)
        target.flush()
        os.fsync(target.fileno())


def entrypoint(script, action, state):
    return (f"#!{sys.executable}\nimport os, sys\n"
            f"os.execv({sys.executable!r}, [{sys.executable!r}, {str(script)!r}, "
            f"{action!r}, '--state', {str(state)!r}, '--'] + sys.argv[1:])\n")


@contextlib.contextmanager
def hook_lock(cli):
    lock = cli.with_name(".pistondecompiler-capture.lock")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def arm(cli, output):
    cli, output = cli.absolute(), output.absolute()
    if cli.is_symlink() or not cli.is_file():
        raise ValueError("Xodus must be an existing regular executable, not a symlink")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    script = Path(__file__).resolve()
    with hook_lock(cli):
        backup = cli.with_name("xodus-cli.pistondecompiler-original")
        if backup.exists():
            raise ValueError("A capture hook is already armed; disarm it first")
        with cli.open("rb") as source:
            if source.read(4) != b"\x7fELF":
                raise ValueError("Expected the original Linux Xodus executable")
        session = Path(tempfile.mkdtemp(prefix="hook-", dir=output))
        state_path = session / "state.json"
        capture = session / "capture"
        proxy = session / "proxy"
        write_private(capture, entrypoint(script, "capture", state_path), True)
        write_private(proxy, entrypoint(script, "intercept", state_path), True)
        state = dict(cli=str(cli), backup=str(backup), output=str(output),
                     capture=str(capture), original_sha256=digest(cli),
                     proxy_sha256=digest(proxy))
        write_private(state_path, json.dumps(state, indent=2) + "\n")
        # Prepare the replacement on the same filesystem, then switch atomically.
        fd, staging = tempfile.mkstemp(prefix=".capture-proxy-", dir=cli.parent)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(proxy.read_bytes())
                os.fchmod(target.fileno(), 0o700)
                target.flush()
                os.fsync(target.fileno())
            os.link(cli, backup)
            try:
                os.replace(staging, cli)
            except BaseException:
                backup.unlink()
                raise
        finally:
            Path(staging).unlink(missing_ok=True)
    return state_path


def restore(state):
    cli, backup = Path(state["cli"]), Path(state["backup"])
    if not backup.exists():
        if digest(cli) != state["original_sha256"]:
            raise ValueError("Xodus changed after capture was armed; refusing to overwrite it")
        return
    if digest(cli) != state["proxy_sha256"] or digest(backup) != state["original_sha256"]:
        raise ValueError("Xodus or its backup changed; refusing to overwrite either file")
    os.replace(backup, cli)


def intercept(state, args):
    cli = Path(state["cli"])
    with hook_lock(cli):
        if len(args) >= 3 and args[0] == "run":
            continuation = args[2]
            restore(state)
            args[2] = state["capture"]
            os.environ["PISTONDECOMPILER_CAPTURE_CONTINUE"] = continuation
            executable = cli
        else:
            backup = Path(state["backup"])
            executable = backup if backup.exists() else cli
    os.execv(str(executable), [str(cli), *args])


def pe_metadata(fd):
    size = os.fstat(fd).st_size
    dos = os.pread(fd, 64, 0)
    if len(dos) != 64 or dos[:2] != b"MZ":
        raise ValueError("Captured data has no DOS/PE header")
    offset = struct.unpack_from("<I", dos, 60)[0]
    header = os.pread(fd, 24, offset)
    if len(header) != 24 or header[:4] != b"PE\0\0":
        raise ValueError("Captured data has no valid PE signature")
    machine, sections = struct.unpack_from("<HH", header, 4)
    optional_size = struct.unpack_from("<H", header, 20)[0]
    optional = os.pread(fd, optional_size, offset + 24)
    if len(optional) < 64 or len(optional) != optional_size:
        raise ValueError("Truncated PE optional header")
    magic = struct.unpack_from("<H", optional)[0]
    if magic not in (0x10b, 0x20b) or not 1 <= sections <= 96:
        raise ValueError("Unsupported PE format or section count")
    section_offset = offset + 24 + optional_size
    table = os.pread(fd, sections * 40, section_offset)
    if len(table) != sections * 40:
        raise ValueError("Truncated PE section table")
    for index in range(sections):
        raw_size, raw_offset = struct.unpack_from("<II", table, index * 40 + 16)
        if raw_size and (raw_offset < section_offset + len(table) or raw_offset + raw_size > size):
            raise ValueError("PE section extends outside the captured file")
    return dict(size=size, machine=hex(machine), sections=sections, pe_format=hex(magic))


def capture_file(fd, output):
    metadata = pe_metadata(fd)
    handle, temporary = tempfile.mkstemp(prefix=".capture-", dir=output)
    hasher = hashlib.sha256()
    try:
        with os.fdopen(handle, "wb") as target:
            offset = 0
            while offset < metadata["size"]:
                block = os.pread(fd, min(4 << 20, metadata["size"] - offset), offset)
                if not block:
                    raise ValueError("Executable was truncated during capture")
                target.write(block)
                hasher.update(block)
                offset += len(block)
            target.flush()
            os.fsync(target.fileno())
        if os.fstat(fd).st_size != metadata["size"]:
            raise ValueError("Executable size changed during capture")
        metadata["sha256"] = hasher.hexdigest()
        destination = output / f"Minecraft.Windows.{hasher.hexdigest()}.exe"
        try:
            os.link(temporary, destination)
        except FileExistsError:
            if digest(destination) != hasher.hexdigest():
                raise ValueError("Existing capture has an unexpected checksum")
        metadata["file"] = str(destination)
        metadata["captured_at"] = datetime.now(timezone.utc).isoformat()
        return metadata
    finally:
        Path(temporary).unlink(missing_ok=True)


def capture(state, args, state_path):
    report = Path(state_path).parent / "result.json"
    try:
        entries = []
        for entry in os.environ.get("WINE_DLL_FILE_MAP", "").split("|"):
            descriptor, separator, mapped = entry.partition(":")
            if separator and descriptor.isdigit() and mapped.replace("\\", "/").rsplit("/", 1)[-1].lower() == "minecraft.windows.exe":
                entries.append(int(descriptor))
        if len(entries) != 1:
            raise ValueError("Expected one Minecraft.Windows.exe descriptor from Xodus")
        result = capture_file(entries[0], Path(state["output"]))
        write_private(report, json.dumps(dict(status="captured", **result), indent=2) + "\n")
        print(f"PistonDecompiler captured {result['file']}", file=sys.stderr, flush=True)
    except Exception as error:
        print(f"PistonDecompiler capture failed: {error}", file=sys.stderr, flush=True)
        if not report.exists():
            write_private(report, json.dumps(dict(status="failed", error=str(error))) + "\n")
    finally:
        # The generated BedrockOnLinux wrapper still receives every original FD.
        continuation = os.environ.pop("PISTONDECOMPILER_CAPTURE_CONTINUE", "")
        if continuation:
            os.execv(continuation, [continuation, *args])
    raise ValueError("Missing original launch wrapper; game launch was not continued")


def dump(source, output):
    output = output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    with source.open("rb") as image:
        result = capture_file(image.fileno(), output)
    report = Path(result["file"]).with_suffix(".json")
    if not report.exists():
        write_private(report, json.dumps(dict(status="captured", source=str(source), **result), indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    dump_parser = commands.add_parser("dump", help="Copy an open decrypted file, including a /proc/PID/fd/FD handle")
    dump_parser.add_argument("--source", type=Path, required=True)
    dump_parser.add_argument("--output", type=Path, required=True)
    arm_parser = commands.add_parser("arm", help="Capture the next Xodus run and restore the original CLI")
    arm_parser.add_argument("--cli", type=Path, required=True)
    arm_parser.add_argument("--output", type=Path, required=True)
    for action in ("disarm", "intercept", "capture"):
        command = commands.add_parser(action)
        command.add_argument("--state", type=Path, required=True)
        if action != "disarm":
            command.add_argument("args", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if options.action == "dump":
        print(json.dumps(dump(options.source, options.output), indent=2))
        return
    if options.action == "arm":
        print(arm(options.cli, options.output))
        return
    state = json.loads(options.state.read_text())
    if options.action == "disarm":
        with hook_lock(Path(state["cli"])):
            restore(state)
        print("Original Xodus CLI restored")
        return
    args = options.args[1:] if options.args[:1] == ["--"] else options.args
    if options.action == "intercept":
        intercept(state, args)
    else:
        capture(state, args, options.state)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.exit(f"Capture helper: {error}")
