"""Review guards and evidence identity; no Apple inputs or native execution."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("rosetta_codegen", Path(__file__).with_name("rosetta-codegen-probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ReviewTests(unittest.TestCase):
    def test_register_only_return_and_internal_branch(self):
        for code in ("b82a000000c3", "85ff7402ffc0c3", "4889f84801f0c3"):
            probe.reviewed_source(bytes.fromhex(code))

    def test_rejects_unreviewed_host_effects(self):
        for code in (
            "488907c3",  # write through argument
            "488b07c3",  # read through argument
            "0f05c3",    # syscall
            "ffd0c3",    # indirect call
            "ffe0c3",    # indirect jump
            "7406c3",    # branch outside fixture
            "7401b800000000c3",  # branch into an instruction
            "4889c3c3",  # clobber RBX
            "41b401c3",  # clobber R12 byte
            "4889fcc3",  # clobber stack
            "c20800",    # RET with stack adjustment
            "b8",        # incomplete decoding
            "90",        # missing return
        ):
            with self.subTest(code=code), self.assertRaises(ValueError):
                probe.reviewed_source(bytes.fromhex(code))

    def test_reserved_nzcv_detector_requires_matching_register(self):
        # MRS X22,NZCV; UBFX W22,W22,#26,#1 (observed Apple parity read).
        observed = struct.pack("<II", 0xD53B4216, 0x531A6AD6)
        self.assertTrue(probe.requires_reserved_nzcv_bits(observed))
        mismatch = struct.pack("<II", 0xD53B4215, 0x531A6AD6)
        self.assertFalse(probe.requires_reserved_nzcv_bits(mismatch))
        self.assertFalse(probe.requires_reserved_nzcv_bits(observed[4:]))

    def test_artifact_key_binds_source_and_codegen_context(self):
        first, identity = probe.artifact_identity(b"\xc3")
        self.assertEqual((first, identity), probe.artifact_identity(b"\xc3"))
        self.assertNotEqual(first, probe.artifact_identity(b"\x90\xc3")[0])
        original = probe.CODEGEN_CONTEXT["ir_flags"]
        try:
            probe.CODEGEN_CONTEXT["ir_flags"] = original + 1
            self.assertNotEqual(first, probe.artifact_identity(b"\xc3")[0])
        finally:
            probe.CODEGEN_CONTEXT["ir_flags"] = original


if __name__ == "__main__":
    unittest.main()
