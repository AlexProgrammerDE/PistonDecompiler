import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("capture-xodus.py")
spec = importlib.util.spec_from_file_location("capture_xodus", SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def pe_image():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HH", data, 132, 0x8664, 1)
    struct.pack_into("<H", data, 148, 240)
    struct.pack_into("<H", data, 152, 0x20b)
    struct.pack_into("<II", data, 152 + 240 + 16, 512, 512)
    data[512:] = bytes(range(256)) * 2
    return bytes(data)


class CaptureTests(unittest.TestCase):
    def test_capture_preserves_offset_and_has_private_atomic_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with tempfile.TemporaryFile() as source:
                data = pe_image()
                source.write(data)
                source.seek(173)
                result = helper.capture_file(source.fileno(), root)
                self.assertEqual(source.tell(), 173)
                self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(Path(result["file"]).read_bytes(), data)
                self.assertEqual(Path(result["file"]).stat().st_mode & 0o777, 0o600)
                self.assertEqual(helper.capture_file(source.fileno(), root)["file"], result["file"])
                self.assertEqual(len(list(root.iterdir())), 1)

    def test_dump_command_writes_verified_image_and_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "original.exe"
            source.write_bytes(pe_image())
            output = root / "captures"
            child = subprocess.run([sys.executable, SCRIPT, "dump", "--source", source, "--output", output], check=True, capture_output=True, text=True)
            result = json.loads(child.stdout)
            self.assertEqual(Path(result["file"]).read_bytes(), pe_image())
            report = json.loads(Path(result["file"]).with_suffix(".json").read_text())
            self.assertEqual(report["sha256"], result["sha256"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)

    def test_invalid_or_truncated_pe_is_not_published(self):
        data = pe_image()
        for payload in (b"encrypted" * 200, data[:700], data[:135]):
            with self.subTest(length=len(payload)), tempfile.TemporaryDirectory() as directory:
                with tempfile.TemporaryFile() as source:
                    source.write(payload)
                    source.flush()
                    with self.assertRaises(ValueError):
                        helper.capture_file(source.fileno(), Path(directory))
                    self.assertFalse(list(Path(directory).iterdir()))

    def test_hook_forwards_other_commands_then_restores_before_run(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "xodus-cli"
            shutil.copy2(shutil.which("echo"), cli)
            original = helper.digest(cli)
            state_path = helper.arm(cli, Path(directory) / "captures")
            state = json.loads(state_path.read_text())
            subprocess.run([cli, "--version"], check=True, capture_output=True)
            self.assertTrue(Path(state["backup"]).exists())
            child = subprocess.run([cli, "run", "/game", "/original-wrapper"], check=True, capture_output=True, text=True)
            self.assertEqual(child.stdout.split(), ["run", "/game", state["capture"]])
            self.assertEqual(helper.digest(cli), original)
            self.assertFalse(Path(state["backup"]).exists())
            helper.restore(state)

    def test_disarm_refuses_to_overwrite_an_updated_install(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "xodus-cli"
            shutil.copy2(shutil.which("echo"), cli)
            state_path = helper.arm(cli, Path(directory) / "captures")
            cli.write_bytes(b"changed install")
            state = json.loads(state_path.read_text())
            with self.assertRaises(ValueError):
                helper.restore(state)
            self.assertTrue(Path(state["backup"]).exists())
            self.assertEqual(cli.read_bytes(), b"changed install")

    def test_inherited_descriptor_capture_and_continuation(self):
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = root / "state.json"
                state.write_text(json.dumps(dict(output=str(root))))
                continuation = root / "continue.py"
                marker = root / "continued.json"
                continuation.write_text(
                    f"#!{sys.executable}\nimport json, os, sys\n"
                    "fd = int(os.environ['WINE_DLL_FILE_MAP'].split(':', 1)[0])\n"
                    f"with open({str(marker)!r}, 'w') as target:\n"
                    " json.dump(dict(args=sys.argv[1:],offset=os.lseek(fd,0,1),header=os.pread(fd,2,0).hex()),target)\n"
                )
                continuation.chmod(0o700)
                fd = os.memfd_create("capture-test", 0)
                try:
                    payload = pe_image() if valid else b"invalid image"
                    os.write(fd, payload)
                    os.lseek(fd, 7, os.SEEK_SET)
                    env = dict(os.environ,
                               WINE_DLL_FILE_MAP=f"{fd}:\\??\\Z:\\game\\Minecraft.Windows.exe",
                               PISTONDECOMPILER_CAPTURE_CONTINUE=str(continuation))
                    subprocess.run([sys.executable, SCRIPT, "capture", "--state", state, "--", "nt-executable"], env=env, pass_fds=(fd,), check=True, capture_output=True)
                    observed = json.loads(marker.read_text())
                    self.assertEqual(observed, dict(args=["nt-executable"], offset=7, header=payload[:2].hex()))
                    report = json.loads((root / "result.json").read_text())
                    self.assertEqual(report["status"], "captured" if valid else "failed")
                    self.assertEqual(len(list(root.glob("*.exe"))), int(valid))
                finally:
                    os.close(fd)


if __name__ == "__main__":
    unittest.main()
