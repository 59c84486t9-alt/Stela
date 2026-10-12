"""Guard block reference boundaries and the native aggregate-return ABI."""
import ctypes
import importlib
import platform
import unittest

block = importlib.import_module('block-differential')


class BlockHarnessTests(unittest.TestCase):
    def test_original_ret_executes_arbitrary_register(self):
        initial = block.State()
        initial.x[5] = 0x45678000
        initial.x[30] = 0x98760000
        initial.reserved = 0xfeedbeef
        case = block.make_case('ret-x5', {'op': 'ret', 'register': 5}, [])
        machine = block.machine_for({case['base']: case}, initial)
        state, pc = block.original_block(machine, case, initial.reserved)
        self.assertEqual(pc, initial.x[5])
        self.assertEqual(state, block.snapshot(initial))

    def test_blr_x30_captures_target_before_writing_link(self):
        initial = block.State()
        initial.x[30] = 0x45678000
        case = block.make_case('blr-x30', {'op': 'blr', 'register': 30}, [])
        expected, transfer = block.oracle(case, initial)
        machine = block.machine_for({case['base']: case}, initial)
        actual, pc = block.original_block(machine, case, initial.reserved)
        self.assertEqual(actual, expected)
        self.assertEqual(pc, 0x45678000)
        self.assertEqual(expected['x'][30], block.BASE + 4)
        self.assertEqual(transfer, {'next_pc': pc, 'kind': 3})

    def test_original_unmapped_fetch_before_boundary_is_failure(self):
        initial = block.State()
        initial.x[5] = 0x45678000
        case = block.make_case('bad-boundary', {'op': 'ret', 'register': 5}, [])
        # Intentionally lie about the source boundary. A fetch fault must not
        # make a partially executed block pass the original reference path.
        case['words'].append(0xd503201f)
        case['source_bytes'] += 4
        machine = block.machine_for({case['base']: case}, initial)
        with self.assertRaises(block.UcError):
            block.original_block(machine, case, initial.reserved)

    def test_zero_register_compare_ignores_sp(self):
        initial = block.State()
        initial.sp = 0x1234
        for nonzero, kind in ((0, 1), (1, 0)):
            case = block.make_case('zr', {'op': 'compare', 'bits': 64, 'nonzero': nonzero,
                                         'register': 31, 'offset': 3}, [])
            expected, transfer = block.oracle(case, initial)
            machine = block.machine_for({case['base']: case}, initial)
            actual, pc = block.original_block(machine, case, initial.reserved)
            self.assertEqual(actual, expected)
            self.assertEqual(pc, transfer['next_pc'])
            self.assertEqual(kind, transfer['kind'])

    def test_w_compare_masks_upper_half(self):
        initial = block.State()
        initial.x[0] = 0x100000000
        for bits, kind in ((32, 1), (64, 0)):
            case = block.make_case('width', {'op': 'compare', 'bits': bits, 'nonzero': 0,
                                            'register': 0, 'offset': 3}, [])
            _, transfer = block.oracle(case, initial)
            machine = block.machine_for({case['base']: case}, initial)
            _, pc = block.original_block(machine, case, initial.reserved)
            self.assertEqual(pc, transfer['next_pc'])
            self.assertEqual(kind, transfer['kind'])

    def test_condition_al_and_nv_are_always_taken(self):
        for condition in (14, 15):
            for flags in range(16):
                self.assertTrue(block.holds(condition, flags << 28))

    def test_nested_original_execution_matches_fixture_oracle(self):
        fixture = block.multiblock_cases()[0]
        blocks = {case['base']: case for case in fixture['blocks']}
        state = block.State()
        state.x[30] = block.BASE + 0x900
        machine = block.machine_for(blocks, state)
        pc, count = block.BASE, 0
        while pc in blocks and count < fixture['budget']:
            expected, transfer = block.oracle(blocks[pc], state)
            actual, pc = block.original_block(machine, blocks[pc], state.reserved)
            self.assertEqual(actual, expected)
            self.assertEqual(pc, transfer['next_pc'])
            for index, value in enumerate(actual['x']):
                state.x[index] = value
            state.sp, state.nzcv = actual['sp'], actual['nzcv']
            count += 1
        self.assertEqual(pc, block.BASE + 0x900)
        self.assertEqual(count, 5)
        self.assertEqual(state.x[0], fixture['x0'])

    @unittest.skipUnless(platform.machine() in ('x86_64', 'AMD64'), 'native x86-64 ABI')
    def test_ctypes_receives_rax_rdx_block_exit(self):
        # movabs rax,0x12345678; movabs rdx,3; ret. This tests the
        # independent bridge rather than depending on compiler output.
        code = bytes.fromhex('48b8785634120000000048ba0300000000000000c3')
        with block.executable(code) as address:
            returned = ctypes.CFUNCTYPE(block.BlockExit, ctypes.POINTER(block.State))(address)(ctypes.byref(block.State()))
            self.assertEqual((returned.next_pc, returned.kind), (0x12345678, 3))


class SynchronousTrapHarnessTests(unittest.TestCase):
    def test_original_svc_and_brk_interrupt_pcs_are_observed(self):
        cases = block.trap_cases()
        for operation, number, advance in [('svc', 2, 4), ('brk', 7, 0)]:
            case = next(case for case in cases if case['transfer'] == {'op': operation, 'immediate': 0x80} and not case['prefix'])
            initial = block.trap_initial_states()[7]
            state, observation = block.original_trap(case, initial)
            self.assertEqual(state, block.snapshot(initial))
            self.assertEqual(observation['interrupt'], {'number': number, 'observed_pc': case['base'] + advance})
            self.assertEqual(observation['trap']['instruction_pc'], case['base'])
            self.assertEqual(observation['trap']['exception_return_pc'], case['base'] + advance)
            self.assertEqual(observation['executed_addresses'], [case['base']])

    def test_all_original_trap_states_match_independent_prefix_oracle(self):
        for case in block.trap_cases():
            for initial in block.trap_initial_states():
                expected, transfer = block.oracle(case, initial)
                actual, observation = block.original_trap(case, initial)
                self.assertEqual(actual, expected)
                self.assertEqual(transfer, {'next_pc': observation['trap']['instruction_pc'], 'kind': 5})
                self.assertEqual(len(observation['executed_addresses']), case['source_bytes'] // 4)

    def test_original_fallthrough_to_trailing_bad_code_is_not_a_trap_success(self):
        case = block.trap_cases()[0]
        case['words'][case['source_bytes'] // 4 - 1] = 0xd503201f
        with self.assertRaisesRegex(AssertionError, 'beyond the reviewed trap boundary'):
            block.original_trap(case, block.trap_initial_states()[0])

    def test_original_early_trap_cannot_satisfy_false_consumed_extent(self):
        case = block.trap_cases()[0]
        case['source_bytes'] += 4
        with self.assertRaisesRegex(AssertionError, 'Original trap observation differs'):
            block.original_trap(case, block.trap_initial_states()[0])



if __name__ == '__main__':
    unittest.main()
