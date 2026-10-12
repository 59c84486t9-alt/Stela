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


if __name__ == "__main__":
    unittest.main()
