"""Pure guards for the original dyld prefix/stack proof; no native execution."""
import copy
import importlib
import struct
import unittest
from pathlib import Path

from differential import State, state_dict

suite = importlib.import_module('dyld-entry-differential')


def thin():
    data = bytearray(0x40000)
    struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x100000c, 0x80000002, 7, 2, 360, 0, 0)
    struct.pack_into('<2I16s4Q4I', data, 32, 0x19, 72, b'__TEXT', 0, len(data), 0, len(data), 5, 5, 0, 0)
    struct.pack_into('<4I', data, 104, 5, 288, 6, 68)
    struct.pack_into('<Q', data, 104 + 272, suite.ENTRY)
    struct.pack_into('<5I', data, suite.ENTRY, *suite.PREFIX_WORDS)
    struct.pack_into('<I', data, suite.TARGET, suite.PACIBSP)
    return data


class DyldEntryGuards(unittest.TestCase):
    def test_raw_slice_selection_rejects_overlaps_wrong_subtype_and_truncation(self):
        image = thin()
        self.assertEqual(suite.classic_slice(image), (0, image))
        container = bytearray(4096) + image
        struct.pack_into('>2I', container, 0, 0xcafebabe, 1)
        struct.pack_into('>5I', container, 8, 0x100000c, 0x80000002, 4096, len(image), 12)
        self.assertEqual(suite.classic_slice(container), (4096, image))
        for position, value in [(12, 0x8000000c), (16, 4097), (20, len(image) + 1), (24, 32)]:
            changed = bytearray(container)
            struct.pack_into('>I', changed, position, value)
            with self.assertRaises(AssertionError):
                suite.classic_slice(changed)
        with self.assertRaises(AssertionError):
            suite.classic_slice(b'bad')

    def test_original_prefix_thread_and_pac_boundary_are_required(self):
        data = thin()
        view = suite.parse_dyld(data)
        self.assertEqual(view['prefix'], struct.pack('<5I', *suite.PREFIX_WORDS))
        self.assertEqual(len(view['thread_command']), 288)
        for offset in [suite.ENTRY, suite.ENTRY + 16, suite.TARGET, 104 + 8, 104 + 272, 36]:
            changed = bytearray(data)
            changed[offset] ^= 1
            with self.assertRaises(AssertionError):
                suite.parse_dyld(changed)

    def test_math_preserves_full_vector_fp_and_non_entry_register_state(self):
        initial = State()
        initial.x[:] = range(1, 32)
        initial.sp, initial.nzcv, initial.reserved = 0x220004000008, 0xf0000000, 0xa5a5
        initial.fpcr, initial.fpsr = 0x03c00000, 0x0800001f
        expected = suite.expected_state(initial)
        self.assertEqual(expected.x[0], initial.sp)
        self.assertEqual(expected.sp, initial.sp & ~15)
        self.assertEqual((expected.x[29], expected.x[30]), (0, 0))
        self.assertEqual(list(expected.x)[1:29], list(initial.x)[1:29])
        self.assertEqual(bytes(expected)[256:], bytes(initial)[256:])

    def test_original_regions_preserve_file_padding_and_zero_only_segment_tail(self):
        image = thin()
        image[-1] = 0x5a
        struct.pack_into('<Q', image, 32 + 32, len(image) + 4096)
        region = suite.original_segment_regions(image, 0x600000)[0]
        self.assertEqual(region['address'], 0x600000)
        self.assertEqual(region['data'][:len(image)], image)
        self.assertEqual(region['data'][-4096:], bytes(4096))
        with self.assertRaises(AssertionError):
            suite.original_segment_regions(image, (1 << 47) - 4096)
        struct.pack_into('<Q', image, 32 + 48, len(image) + 1)
        with self.assertRaises(AssertionError):
            suite.original_segment_regions(image, 0x600000)

    def test_original_kernel_arrays_preserve_bytes_and_require_bootstrap_scratch(self):
        arguments = {'argv': [[0xff], list(b'arg')], 'environment': [list(b'A=B')], 'apple': [list(b'entry=1')]}
        raw, payload = suite.original_kernel_args(0x8000, 4096, 0x600000, b'/m', arguments)
        self.assertEqual(raw % 16, 8)
        self.assertEqual(struct.unpack_from('<2Q', payload), (0x600000, 2))
        words = struct.unpack_from('<10Q', payload)
        self.assertEqual((words[4], words[6], words[9]), (0, 0, 0))
        for pointer, value in zip([words[2], words[3], words[5], words[7], words[8]],
                                  [b'\xff', b'arg', b'A=B', b'/m', b'entry=1']):
            self.assertEqual(payload[pointer - raw:pointer - raw + len(value) + 1], value + b'\0')
        with self.assertRaises(AssertionError):
            suite.original_kernel_args(0x8000, 1024, 0x600000, b'/m', arguments)
        arguments['argv'] = [[0]]
        with self.assertRaises(AssertionError):
            suite.original_kernel_args(0x8000, 4096, 0x600000, b'/m', arguments)

    def test_native_receipt_rejects_state_pac_source_and_cache_drift(self):
        expected = suite.expected_state(State())
        report = {'kind': 'native_block_run', 'abi': suite.ABI, 'complete_binary_verified': False,
                  'source_sha256': 'source', 'guest_base': 0, 'pc': suite.TARGET, 'state': state_dict(expected),
                  'outcome': {'reason': {'kind': 'unsupported', 'detail': str(suite.PACIBSP)},
                              'blocks_executed': 1, 'last_exit': [suite.TARGET, 1],
                              'compiled_blocks': 1, 'disk_cache_hits': 0, 'memory_cache_hits': 0}}
        suite.validate_native(report, expected, 'source', 0, True)
        for field, value in [('pc', suite.TARGET + 4), ('source_sha256', 'other'), ('complete_binary_verified', True)]:
            changed = copy.deepcopy(report)
            changed[field] = value
            with self.assertRaises(AssertionError):
                suite.validate_native(changed, expected, 'source', 0, True)
        changed = copy.deepcopy(report)
        changed['state']['v'][31][1] ^= 1
        with self.assertRaises(AssertionError):
            suite.validate_native(changed, expected, 'source', 0, True)

        changed = copy.deepcopy(report)
        changed['outcome']['reason']['kind'] = 'stop_address'
        with self.assertRaises(AssertionError):
            suite.validate_native(changed, expected, 'source', 0, True)

    def test_argument_audit_walks_real_bytes_and_rejects_rehashed_payload_tampering(self):
        raw, end = 0x8ef8, 0x9000
        data = bytearray(end - raw)
        struct.pack_into('<8Q', data, 0, 0x60000000000, 1, 0x8f60, 0, 0x8f62, 0, 0x8f66, 0)
        data[0x8f60 - raw:0x8f69 - raw] = b'x\0A=B\0/m\0'
        arguments = {'argv': [[ord('x')]], 'environment': [list(b'A=B')], 'apple': []}
        plan = {'stack_base': 0x8000, 'stack_bytes': 4096, 'raw_sp': raw, 'aligned_sp': raw & ~15,
                'argc': 1, 'argc_address': raw + 8, 'argv_address': raw + 16,
                'envp_address': raw + 32, 'apple_address': raw + 48, 'payload_address': raw,
                'initial_bytes': list(data), 'strings': [
                    {'kind': 'argv', 'index': 0, 'address': 0x8f60, 'bytes': 1},
                    {'kind': 'environment', 'index': 0, 'address': 0x8f62, 'bytes': 3},
                    {'kind': 'apple', 'index': 0, 'address': 0x8f66, 'bytes': 2}]}
        report = {'arguments': plan, 'main': {'load_base': 0x60000000000},
                  'argument_payload_sha256': suite.digest(data), 'argument_payload_after_sha256': suite.digest(data),
                  'stack': {'base': 0x8000, 'bytes': 4096, 'guard_bytes': 4096},
                  'mapped_regions': [{'guest_address': address, 'virtual_bytes': 4096, 'readable': access,
                                      'writable': access, 'executable': False}
                                     for address, access in [(0x7000, False), (0x8000, True), (0x9000, False)]]}
        suite.audit_arguments(report, Path('/m'), arguments)
        for offset, value in [(16, end), (24, 1), (48, raw + 16)]:
            changed = copy.deepcopy(report)
            damaged = bytearray(data)
            struct.pack_into('<Q', damaged, offset, value)
            changed['arguments']['initial_bytes'] = list(damaged)
            changed['argument_payload_sha256'] = changed['argument_payload_after_sha256'] = suite.digest(damaged)
            with self.assertRaises(AssertionError):
                suite.audit_arguments(changed, Path('/m'), arguments)
        changed = copy.deepcopy(report)
        changed['arguments']['initial_bytes'][-1] = 1
        changed['argument_payload_sha256'] = changed['argument_payload_after_sha256'] = suite.digest(bytes(changed['arguments']['initial_bytes']))
        with self.assertRaises(AssertionError):
            suite.audit_arguments(changed, Path('/m'), arguments)
        changed = copy.deepcopy(report)
        changed['mapped_regions'][0]['writable'] = True
        with self.assertRaises(AssertionError):
            suite.audit_arguments(changed, Path('/m'), arguments)


if __name__ == '__main__':
    unittest.main()
