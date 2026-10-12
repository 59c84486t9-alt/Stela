"""Reject loader-fixture drift before asking native code to touch guest RAM."""
import importlib
from pathlib import Path
import platform
import struct
import tempfile
import unittest

mapped = importlib.import_module('mapped-image-differential')


class MachOFramingTests(unittest.TestCase):
    def test_truncated_command_is_rejected(self):
        header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 2, 1, 8, 0, 0)
        with self.assertRaisesRegex(AssertionError, 'bad load-command length'):
            mapped.commands(header + struct.pack('<II', 0x19, 72))


@unittest.skipUnless(platform.system() == 'Darwin', 'Apple linker fixture construction')
class LinkedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='mapped-fixture-test-')
        cls.image, cls.info, cls.provenance = mapped.build_fixture(Path(cls.temporary.name))
        cls.data = cls.image.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_original_call_returns_and_data_match_independent_oracle(self):
        for initial in mapped.states(all_flags=True):
            initial.sp = mapped.STACK_TOP
            initial.reserved = 0xfeedbeef
            initial.x[30] = mapped.STOP
            expected, pc, memory, frame, trace = mapped.original(self.data, self.info, initial)
            self.assertEqual((expected, pc, memory, frame), mapped.fixture_oracle(self.data, self.info, initial))
            self.assertEqual(len(trace), 17)
            self.assertEqual(expected['x'][4], 0)
            self.assertEqual(expected['x'][30], mapped.STOP)
            self.assertEqual(expected['nzcv'], initial.nzcv)

    def test_fixture_has_real_file_data_and_segment_zero_tail(self):
        segment = next(item for item in self.info['segments'] if item['name'] == '__DATA')
        self.assertEqual(segment['bytes'], 3 * mapped.PAGE)
        self.assertEqual(segment['file_bytes'], mapped.PAGE)
        self.assertEqual(struct.unpack_from('<Q', self.data, segment['file_offset'])[0], mapped.SEED)
        self.assertTrue(self.provenance['linked_executable_unchanged'])
        self.assertIsNotNone(self.info['entry_offset'])

    def test_chained_imports_must_not_be_ignored(self):
        data = bytearray(self.data)
        for _, command, body in mapped.commands(data):
            if command == 0x80000034:
                payload = struct.unpack_from('<I', body, 8)[0]
                struct.pack_into('<I', data, payload + 16, 1)
                break
        else:
            self.fail('expected chained-fixup command')
        with self.assertRaisesRegex(AssertionError, 'no chained imports'):
            mapped.layout(data)

    def test_actual_fixup_chains_must_not_be_ignored(self):
        data = bytearray(self.data)
        for _, command, body in mapped.commands(data):
            if command == 0x80000034:
                payload = struct.unpack_from('<I', body, 8)[0]
                starts = struct.unpack_from('<I', data, payload + 4)[0]
                struct.pack_into('<I', data, payload + starts + 4, 4)
                break
        else:
            self.fail('expected chained-fixup command')
        with self.assertRaisesRegex(AssertionError, 'actual pointer-fixup chains'):
            mapped.layout(data)


if __name__ == '__main__':
    unittest.main()
