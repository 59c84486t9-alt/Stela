"""Checks for the complete shared guest-state ABI and original ARM helpers."""
import ctypes
import struct
import unittest

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from differential import (State, states, state_dict, initialize_arm, capture_arm,
                          seed_extended_state, parse_fault_record)


class CompleteStateTests(unittest.TestCase):
    def test_layout_appends_simd_without_changing_integer_prefix(self):
        self.assertEqual(ctypes.sizeof(State), 784)
        self.assertEqual((State.x.offset, State.sp.offset, State.nzcv.offset, State.reserved.offset,
                          State.v.offset, State.fpcr.offset, State.fpsr.offset),
                         (0, 248, 256, 260, 264, 776, 780))
        self.assertEqual(ctypes.alignment(State), 8)

    def test_original_arm_roundtrip_reads_full_128_bits_and_fp_status(self):
        for initial in states(all_flags=True):
            initial.reserved = 0x12345678
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            initialize_arm(machine, initial)
            self.assertEqual(state_dict(capture_arm(machine, initial)), state_dict(initial))
            self.assertTrue(all(v[1] for v in initial.v))

    def test_extended_seed_is_deterministic_without_mutating_the_gpr_prefix(self):
        initial = states()[3]
        prefix = bytes(initial)[:State.v.offset]
        seed_extended_state(initial, 91)
        first = bytes(initial)
        seed_extended_state(initial, 91)
        self.assertEqual(first, bytes(initial))
        seed_extended_state(initial, 92)
        self.assertEqual(prefix, bytes(initial)[:State.v.offset])
        self.assertNotEqual(first[State.v.offset:], bytes(initial)[State.v.offset:])

    def test_fault_framing_uses_state_size_and_keeps_complete_initial_and_final(self):
        initial, final = states()[:2]
        header, event = (1, 2, 4096), (11, 0x1234, 0x4567)
        ram = b'\xa5' * 4096
        data = struct.pack('<3Q', *header) + bytes(initial) + struct.pack('<3Q', *event) + bytes(final) + ram
        actual_header, actual_initial, actual_event, actual_final, actual_ram = parse_fault_record(data)
        self.assertEqual((actual_header, actual_event, actual_ram), (header, event, ram))
        self.assertEqual(bytes(actual_initial), bytes(initial))
        self.assertEqual(bytes(actual_final), bytes(final))
        for length in (0, 24, 24 + ctypes.sizeof(State), 48 + 2 * ctypes.sizeof(State) - 1):
            with self.assertRaises(AssertionError):
                parse_fault_record(data[:length])


if __name__ == '__main__':
    unittest.main()
