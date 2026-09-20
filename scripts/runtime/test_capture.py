import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('capture', Path(__file__).with_name('capture.py'))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class JournalTest(unittest.TestCase):
    def test_only_torn_tail_is_discarded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'events.jsonl'
            path.write_bytes(b'{"sequence":1}\n{"sequence":2')
            self.assertEqual(capture.read_journal(path), [{'sequence': 1}])
            path.write_bytes(b'{"sequence":1}\ncorrupt\n{"sequence":3}\n')
            with self.assertRaises(json.JSONDecodeError):
                capture.read_journal(path)

    def test_recovery_keeps_session_identity_and_marks_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture.atomic_json(root / 'metadata.json', {'id': 'session', 'collector': 'test'})
            (root / 'events.jsonl').write_bytes(b'{"sequence":1}\n{"sequence":2')
            capture.atomic_json(root / 'progress.json', {'dropped_events': 5})
            trace = capture.finalize(root)
            self.assertEqual(trace['id'], 'session')
            self.assertEqual(trace['dropped_events'], 5)
            self.assertEqual(len(trace['events']), 1)
            self.assertEqual(json.loads((root / 'trace.json').read_text()), trace)


if __name__ == '__main__':
    unittest.main()
