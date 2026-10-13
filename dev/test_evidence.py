import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import evidence


class EvidenceTests(unittest.TestCase):
    def test_legacy_and_new_reports_survive_latest_view_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "report.json"
            legacy = b'{"legacy": true}\n'
            destination.write_bytes(legacy)
            with patch.object(evidence,"ROOT",root):
                first = evidence.write_evidence(destination,{"result":1})
                second = evidence.write_evidence(destination,{"result":2})
            history = root / ".stela/evidence/report"
            self.assertEqual((history / (hashlib.sha256(legacy).hexdigest()+".json")).read_bytes(),legacy)
            self.assertEqual(json.loads(first.read_text()),{"result":1})
            self.assertEqual(json.loads(second.read_text()),{"result":2})
            self.assertEqual(json.loads(destination.read_text()),{"result":2})
            self.assertEqual(len(list(history.glob("*.json"))),3)

    def test_native_evidence_key_binds_accounting_and_refuses_modified_archives(self):
        from evidence import retain_native_evidence
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = ("literal", b"source", b"native", {"source_map": [[4, 0]]}, {"instructions": 1}, b"harness")
            first = retain_native_evidence(*args, root=root)
            self.assertEqual(first, retain_native_evidence(*args, root=root))
            changed = retain_native_evidence(*args[:4], {"instructions": 2}, args[-1], root=root)
            self.assertNotEqual(first["native.bin"]["path"], changed["native.bin"]["path"])
            (root / first["native.bin"]["path"]).write_bytes(b"tampered")
            with self.assertRaisesRegex(AssertionError, 'Immutable native evidence changed'):
                retain_native_evidence(*args, root=root)
            for invalid in ("", ".", "..", "../literal", "nested/name", "nested\\name"):
                with self.assertRaises(ValueError):
                    retain_native_evidence(invalid, *args[1:], root=root)


if __name__ == "__main__":
    unittest.main()
