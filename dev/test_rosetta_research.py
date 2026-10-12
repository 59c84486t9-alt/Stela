"""Independent synthetic archive tests for catalog digest and payload integrity."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
import zlib

spec = importlib.util.spec_from_file_location("rosetta_research", Path(__file__).with_name("rosetta-research.py"))
research = importlib.util.module_from_spec(spec)
spec.loader.exec_module(research)


def archive(payload=b"original payload"):
    digest = hashlib.sha1(payload).hexdigest()
    xml = f'<xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum><file><data><offset>20</offset><length>{len(payload)}</length><archived-checksum style="sha1">{digest}</archived-checksum></data></file></toc></xar>'.encode()
    compressed = zlib.compress(xml)
    toc_digest = hashlib.sha1(compressed).digest()
    header = struct.pack(">4sHHQQI", b"xar!", 28, 1, len(compressed), len(xml), 1)
    return header + compressed + toc_digest + payload, toc_digest.hex()


class RosettaResearchTests(unittest.TestCase):
    def test_digest_is_compressed_toc_and_members_are_checked(self):
        data, digest = archive()
        self.assertNotEqual(hashlib.sha1(data).hexdigest(), digest)
        self.assertEqual(research.verify_xar(data, digest)["checked_archive_members"], 1)
        with self.assertRaisesRegex(ValueError, "payload checksum"):
            research.verify_xar(data[:-1] + bytes([data[-1] ^ 1]), digest)
        with self.assertRaisesRegex(ValueError, "TOC digest"):
            research.verify_xar(data, "00" * 20)

    def test_truncated_and_out_of_bounds_archives_fail(self):
        data, digest = archive()
        for malformed in (data[:20], data[:-1], data[:8] + struct.pack(">Q", 1 << 60) + data[16:]):
            with self.assertRaises(ValueError):
                research.verify_xar(malformed, digest)

    def test_software_update_urls_are_https_and_host_limited(self):
        self.assertEqual(research.apple_url(research.CATALOG), research.CATALOG)
        for url in ("http://swcdn.apple.com/test.pkg", "https://swcdn.apple.com.example.com/test.pkg", "https://user@swcdn.apple.com/test.pkg", "https://swcdn.apple.com:444/test.pkg"):
            with self.assertRaises(ValueError):
                research.apple_url(url)


if __name__ == "__main__":
    unittest.main()
