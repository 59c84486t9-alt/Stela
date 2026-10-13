"""Pure guards for the original dyld prefix/stack proof; no native execution."""
import copy
import importlib
import struct
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

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


class DataVmGuards(unittest.TestCase):
    def test_callback_model_preserves_unrelated_state_and_thunk_argument_effects(self):
        initial = State.from_buffer_copy(suite.states(all_flags=True)[15])
        before = bytes(initial)
        segment = {'flags':16,'preferred':0xc0000,'virtual_bytes':16384}
        expected = suite.vm_callback_expected(initial,segment,0x40000000000)
        self.assertEqual((expected.x[0],expected.x[1],expected.x[2],expected.x[3],expected.x[16]),(0,0,1,1,74))
        self.assertEqual(expected.nzcv, initial.nzcv & ~(1<<29))
        self.assertEqual(bytes(expected)[248:256],bytes(initial)[248:256])
        self.assertEqual(bytes(expected)[264:],bytes(initial)[264:])
        self.assertEqual(bytes(initial),before)
        segment['flags']=4
        unchanged=suite.vm_callback_expected(initial,segment,0x40000000000)
        wanted=State.from_buffer_copy(initial);wanted.x[8]=4
        self.assertEqual(bytes(unchanged),bytes(wanted))

    def test_vm_receipt_rejects_state_permissions_missing_ram_and_alias_region(self):
        state=State();data=bytes(16384)
        memory=[{'guest_address':suite.VM_META,'virtual_bytes':16384,'initial_bytes':list(data),'readable':True,'writable':False}]
        receipt=[{'address':suite.VM_META,'bytes':16384,'sha256':suite.digest(data)}]
        report={'kind':'native_block_run','abi':suite.ABI,'source_sha256':'source','data_vm_profile':suite.VM_PROFILE,
                'complete_binary_verified':False,'state':state_dict(state),'pc':suite.VM_STOP,
                'outcome':{'reason':{'kind':'stop_address'},'blocks_executed':2},'data_vm_events':[],
                'memory':{'memory_before':receipt,'memory_after':receipt,'memory_regions':[dict(memory[0],executable=False)],
                'memory_reads':[{'address':suite.VM_META,'bytes':16384,'hex':data.hex()}]}}
        suite.validate_vm_native(report,state,'source',memory,False)
        mutations=[]
        for field in ('memory_before','memory_after','memory_reads','memory_regions'):
            changed=copy.deepcopy(report);changed['memory'][field]=[];mutations.append(changed)
        changed=copy.deepcopy(report);changed['memory']['memory_regions'][0]['writable']=True;mutations.append(changed)
        changed=copy.deepcopy(report);changed['memory']['memory_regions'][0]['guest_address']+=16384;mutations.append(changed)
        changed=copy.deepcopy(report);changed['state']['v'][31][1]=1;mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(AssertionError):suite.validate_vm_native(changed,state,'source',memory,False)


class PageSizeCommpageGuards(unittest.TestCase):
    def test_thread_mode_retains_existing_cohorts_and_declares_original_live_inputs(self):
        base = suite.MACH_FIXTURE_BASES[0]
        self.assertEqual(len(suite.mach_port_cases(base, False)) * 4, 20)
        self.assertEqual(len(suite.mach_port_cases(base, True)) * 4, 16)
        cases = [case for flags in range(16) for case in suite.mach_thread_cases(base, flags)]
        full = [case for case in cases if case.thread_operation == 'initialize']
        self.assertEqual(len(full) * 2, 8)
        self.assertTrue(all(case.entry_offset == suite.MACH_INIT_ENTRY and case.stop_pc == suite.VM_STOP
                            and case.request_numbers == suite.MACH_INIT_REQUESTS for case in full))
        self.assertEqual({case.kernel_page_shift for case in full}, set(suite.PAGE_SIZE_KERNEL_SHIFTS))
        self.assertTrue(any(case.entry_offset == suite.THREAD_PLATFORM_SVC
                            and case.thread_operation == 'get' and case.selector_upper == suite.UINT32_MASK
                            and case.subcode_upper == suite.UINT32_MASK for case in cases))
        self.assertTrue({0, 1, suite.THREAD_VM_MAXIMUM - 1, suite.THREAD_VM_MAXIMUM,
                         suite.THREAD_VM_MAXIMUM + 1, suite.UINT64_MASK}.issubset(
                             {case.tsd_address for case in cases if case.thread_operation == 'set'}))

    def test_thread_receipt_rejects_identity_owner_and_tsd_transition_drift(self):
        base = suite.MACH_FIXTURE_BASES[0]
        case = suite.MachBootstrapCase(suite.THREAD_PLATFORM_WRAPPER, suite.VM_STOP, (),
                                 thread_operation='set', tsd_address=suite.THREAD_VM_MAXIMUM)
        report = {'thread_context': {'profile_id': suite.THREAD_PROFILE,
                  'address_space': suite.PAGE_SIZE_ADDRESS_SPACE, 'thread_id': 0x100000001,
                  'thread_specific_data': suite.THREAD_VM_MAXIMUM,
                  'guest_vm_max_address': suite.THREAD_VM_MAXIMUM},
                  'thread_service_events': [{'kind': 'platform', 'event': {
                      'completion': {'kind': 'set_thread_specific_data'}, 'declined': None,
                      'request': {'kind': 'set_thread_specific_data', 'address': suite.THREAD_VM_MAXIMUM},
                      'thread_specific_data_before': 0, 'thread_specific_data_after': suite.THREAD_VM_MAXIMUM}}]}
        suite.audit_thread_service(report, base, case)
        for key, value in [('profile_id', 'other'), ('address_space', 2), ('thread_id', 0),
                           ('thread_specific_data', 0), ('guest_vm_max_address', suite.THREAD_VM_MAXIMUM - 1)]:
            changed = copy.deepcopy(report)
            changed['thread_context'][key] = value
            with self.assertRaises(AssertionError):
                suite.audit_thread_service(changed, base, case)
        for key, value in [('completion', None), ('declined', 'unsupported'),
                           ('thread_specific_data_before', 1), ('thread_specific_data_after', 0),
                           ('request', {'kind': 'get_thread_specific_data'})]:
            changed = copy.deepcopy(report)
            changed['thread_service_events'][0]['event'][key] = value
            with self.assertRaises(AssertionError):
                suite.audit_thread_service(changed, base, case)

    def test_arm64_user_size_stays_16k_for_both_kernel_profiles(self):
        for kernel in suite.PAGE_SIZE_KERNEL_SHIFTS:
            page = suite.page_size_bytes(kernel)
            self.assertEqual((len(page), page[suite.PAGE_SIZE_USER_OFFSET], page[suite.PAGE_SIZE_KERNEL_OFFSET]),
                             (suite.PAGE_SIZE_BYTES, suite.PAGE_SIZE_USER_SHIFT, kernel))
            self.assertEqual(sum(value != 0 for value in page), 2)
        for kernel in (0, 13, 16):
            with self.assertRaises(AssertionError):
                suite.page_size_bytes(kernel)

    def test_receipt_rejects_wrong_fields_permissions_owner_or_bytes(self):
        kernel = suite.PAGE_SIZE_KERNEL_SHIFTS[0]
        page = {'profile_id': suite.PAGE_SIZE_PROFILE, 'address_space': suite.PAGE_SIZE_ADDRESS_SPACE,
                'region': {'guest_address': suite.PAGE_SIZE_BASE, 'virtual_bytes': suite.PAGE_SIZE_BYTES,
                           'readable': True, 'writable': False, 'executable': False},
                'supported_fields': [
                    {'address': suite.PAGE_SIZE_BASE + suite.PAGE_SIZE_USER_OFFSET,
                     'bytes': 1, 'value': suite.PAGE_SIZE_USER_SHIFT},
                    {'address': suite.PAGE_SIZE_BASE + suite.PAGE_SIZE_KERNEL_OFFSET, 'bytes': 1, 'value': kernel}],
                'page_sha256': suite.digest(suite.page_size_bytes(kernel))}
        suite.audit_page_size_commpage({'page_size_commpage': page}, kernel)
        mutations = []
        for key, value in [('profile_id', 'other'), ('address_space', suite.PAGE_SIZE_ADDRESS_SPACE + 1),
                           ('page_sha256', 'other')]:
            changed = copy.deepcopy(page)
            changed[key] = value
            mutations.append(changed)
        for key, value in [('guest_address', suite.PAGE_SIZE_BASE + suite.PAGE_SIZE_BYTES),
                           ('virtual_bytes', suite.PAGE_SIZE_BYTES // 2), ('writable', True),
                           ('readable', False), ('executable', True)]:
            changed = copy.deepcopy(page)
            changed['region'][key] = value
            mutations.append(changed)
        for key, value in [('address', suite.PAGE_SIZE_BASE + suite.PAGE_SIZE_USER_OFFSET - 1),
                           ('bytes', 2), ('value', kernel)]:
            changed = copy.deepcopy(page)
            changed['supported_fields'][0][key] = value
            mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(AssertionError):
                suite.audit_page_size_commpage({'page_size_commpage': changed}, kernel)

    def test_independent_global_audit_rejects_each_wrong_value_and_snapshot_extent(self):
        base, kernel = suite.MACH_FIXTURE_BASES[0], suite.PAGE_SIZE_KERNEL_SHIFTS[0]
        events = [{'result': 101}, {'result': 102}]
        raw = bytearray(suite.MACH_INIT_GLOBALS_BYTES)
        fields = [(suite.MACH_INIT_TASK_SELF, '<I', events[0]['result']),
                  (suite.MACH_INIT_REPLY_PORT, '<I', events[1]['result']),
                  (suite.MACH_INIT_KERNEL_SHIFT, '<I', kernel),
                  (suite.MACH_INIT_USER_SHIFT, '<I', suite.PAGE_SIZE_USER_SHIFT),
                  (suite.MACH_INIT_USER_SIZE, '<Q', suite.PAGE_SIZE_BYTES),
                  (suite.MACH_INIT_USER_MASK, '<Q', suite.PAGE_SIZE_BYTES - 1)]
        for address, encoding, value in fields:
            struct.pack_into(encoding, raw, address - suite.MACH_INIT_TASK_SELF, value)
        snapshot = {'address': base + suite.MACH_INIT_TASK_SELF, 'hex': raw.hex()}
        native = {'memory': {'memory_reads': [snapshot]}}
        suite.audit_page_size_globals(native, base, kernel, events)
        for address, _, _ in fields:
            corrupted = bytearray(raw)
            corrupted[address - suite.MACH_INIT_TASK_SELF] ^= 1
            changed = copy.deepcopy(native)
            changed['memory']['memory_reads'][0]['hex'] = corrupted.hex()
            with self.assertRaises(AssertionError):
                suite.audit_page_size_globals(changed, base, kernel, events)
        for reads in [[], [snapshot, snapshot], [dict(snapshot, address=snapshot['address'] + 1)],
                      [dict(snapshot, hex=raw[:-1].hex())]]:
            with self.assertRaises(AssertionError):
                suite.audit_page_size_globals({'memory': {'memory_reads': reads}}, base, kernel, events)


class ThreadRegisterGuards(unittest.TestCase):
    def test_trampoline_preserves_original_text_and_targets_original_functions(self):
        view = {'text': bytes(range(256)) * 16}
        base = suite.MACH_FIXTURE_BASES[0]
        regions = [{'address': base, 'virtual_bytes': 3 * suite.THREAD_FIXTURE_PAGE_BYTES}]
        for errno in suite.THREAD_ERRNO_VALUES:
            source, offset, region = suite.thread_errno_source(view, regions, base, errno)
            self.assertEqual(source[:len(view['text'])], view['text'])
            self.assertEqual(source[len(view['text']):offset], bytes(offset - len(view['text'])))
            words = struct.unpack('<3I', source[offset:])
            for instruction, target in ((0, suite.MACH_INIT_ENTRY), (2, suite.THREAD_ERRNO_ENTRY)):
                displacement = words[instruction] & ((1 << suite.A64_BRANCH_IMMEDIATE_BITS) - 1)
                if displacement & (1 << (suite.A64_BRANCH_IMMEDIATE_BITS - 1)):
                    displacement -= 1 << suite.A64_BRANCH_IMMEDIATE_BITS
                self.assertEqual(offset + instruction * suite.A64_INSTRUCTION_BYTES
                                 + displacement * suite.A64_INSTRUCTION_BYTES, target)
            self.assertEqual((words[1] >> suite.A64_MOVE_IMMEDIATE_SHIFT) & 0xffff, errno)
            self.assertEqual(region['address'], base + offset)
            self.assertEqual(region['data'][:len(source) - offset], source[offset:])
            self.assertEqual(region['initial_protection'], suite.UC_PROT_READ | suite.UC_PROT_EXEC)
        with self.assertRaises(AssertionError):
            suite.branch_with_link(0, 1)
        with self.assertRaises(AssertionError):
            suite.branch_with_link(0, 1 << (suite.A64_BRANCH_IMMEDIATE_BITS + 1))

    def test_helper_audit_rejects_state_memory_and_descriptor_drift(self):
        initial = suite.states(all_flags=True)[15]
        destination = suite.A64_ZERO_REGISTER_INDEX
        source, base, instruction_pc = b'probe', suite.MACH_FIXTURE_BASES[0], 0x1000
        regions = [{'address': base, 'virtual_bytes': 16, 'data': bytes(16)}]
        snapshot = [{'address': base, 'bytes': 16, 'sha256': suite.digest(bytes(16))}]
        native = {'kind': 'native_block_run', 'abi': suite.THREAD_REGISTER_PAUTH_ABI,
                  'complete_binary_verified': False, 'source_sha256': suite.digest(source), 'guest_base': base,
                  'state': state_dict(initial), 'memory': {'memory_before': snapshot, 'memory_after': snapshot},
                  'thread_context': {'thread_specific_data': 1}, 'outcome': {'thread_register_events': [{
                      'instruction': {'destination': destination, 'instruction_pc': instruction_pc,
                                      'next_pc': instruction_pc + suite.A64_INSTRUCTION_BYTES},
                      'next_pc': instruction_pc + suite.A64_INSTRUCTION_BYTES, 'value': 1}]}}
        machine = Mock()
        machine.reg_read.return_value, machine.mem_read.return_value = 1, bytes(16)
        with patch.object(suite, 'capture_arm', return_value=initial):
            suite.compare_thread_register_run(native, machine, initial, regions, base, source, destination, instruction_pc)
            mutations = []
            for key, value in [('abi', suite.ABI), ('source_sha256', 'other'), ('complete_binary_verified', True)]:
                changed = copy.deepcopy(native)
                changed[key] = value
                mutations.append(changed)
            changed = copy.deepcopy(native)
            changed['state']['v'][31][1] ^= 1
            mutations.append(changed)
            changed = copy.deepcopy(native)
            changed['memory']['memory_after'] = []
            mutations.append(changed)
            changed = copy.deepcopy(native)
            changed['thread_context']['thread_specific_data'] = 0
            mutations.append(changed)
            changed = copy.deepcopy(native)
            changed['outcome']['thread_register_events'][0]['instruction']['destination'] = 0
            mutations.append(changed)
            for changed in mutations:
                with self.assertRaises(AssertionError):
                    suite.compare_thread_register_run(changed, machine, initial, regions, base, source, destination, instruction_pc)


class StartupJoinGuards(unittest.TestCase):
    def test_timer_pause_counts_post_counter_instruction_only_on_resume(self):
        oracle = suite.StartupOracle.__new__(suite.StartupOracle)
        oracle.base = suite.MACH_FIXTURE_BASES[0]
        offset = suite.STARTUP_COUNTER_CONTINUATION
        oracle.image = bytes(offset) + b'\x01\x02\x03\x04'
        oracle.counter, oracle.pcs, oracle.checkpoints = None, [], []
        machine = Mock()
        machine.mem_read.return_value = oracle.image[offset:]
        machine.reg_read.return_value = 123
        oracle.code(machine, oracle.base + offset, suite.A64_INSTRUCTION_BYTES, None)
        self.assertEqual((oracle.counter, oracle.pcs), (123, []))
        machine.emu_stop.assert_called_once()
        oracle.code(machine, oracle.base + offset, suite.A64_INSTRUCTION_BYTES, None)
        self.assertEqual(oracle.pcs, [offset])
        machine.mem_read.return_value = b'changed'
        with self.assertRaises(AssertionError):
            oracle.code(machine, oracle.base + offset, suite.A64_INSTRUCTION_BYTES, None)

    def test_crossarch_audit_rejects_extra_service_and_unrelated_state_changes(self):
        before = state_dict(State())
        before['x'][3], before['nzcv'] = 0x123456, 0xf0000000
        after = copy.deepcopy(before)
        after['x'][0] = suite.DARWIN_ENOTSUP
        oracle = Mock(serviced=True, svcs=[{'before': before, 'after': after}])
        event = {'declined': None, 'request': {'number': suite.DARWIN_CROSSARCH_TRAP, 'arguments': [0],
                     'prototype': {'argument_count': 1, 'return_type': 'int'}, 'indirect': False},
                 'completion': {'kind': 'error', 'errno': suite.DARWIN_ENOTSUP}}
        native = {'crossarch_service_events': [event], 'crossarch_service_profile': 'darwin-crossarch-unavailable-v1'}
        suite.audit_startup_crossarch(native, oracle)
        for field, value in [('declined', 'unsupported'), ('completion', {'kind': 'error', 'errno': 22}),
                             ('request', {'number': suite.DARWIN_CROSSARCH_TRAP, 'arguments': [0, 0]})]:
            changed = copy.deepcopy(native)
            changed['crossarch_service_events'][0][field] = value
            with self.assertRaises(AssertionError):
                suite.audit_startup_crossarch(changed, oracle)
        for index in (1, 3, 30):
            changed = copy.deepcopy(after)
            changed['x'][index] ^= 1
            with self.assertRaises(AssertionError):
                suite.audit_startup_crossarch(native, Mock(serviced=True, svcs=[{'before': before, 'after': changed}]))
        pending = Mock(serviced=False, svcs=[{'before': before, 'after': copy.deepcopy(before)}])
        suite.audit_startup_crossarch({'crossarch_service_events': [], 'crossarch_service_profile': None}, pending)
        with self.assertRaises(AssertionError):
            suite.audit_startup_crossarch(native, pending)

    def test_clock_audit_requires_declared_fields_unchanged_bytes_and_single_counter_read(self):
        pac = Mock(CLOCK_PROFILE='clock', CLOCK_BASE=0x10000, CLOCK_BYTES=16)
        pac.clock_page.return_value = bytes(16)
        snapshot = {'counter': 123, 'sleep_ticks': suite.STARTUP_SLEEP_TICKS}
        native = {'clock': {'profile_id': pac.CLOCK_PROFILE, 'legacy_configuration': {'kdebug': 'disabled'},
            'legacy_commpage_profile': suite.STARTUP_CLOCK_PROFILE, 'source_id': 'explicit-finite-replay-v1',
            'snapshot': snapshot, 'events': [{'sequence': index, 'snapshot': snapshot} for index in (0, 1)],
            'page_sha256': suite.digest(bytes(16)),
            'region': {'guest_address': pac.CLOCK_BASE, 'virtual_bytes': pac.CLOCK_BYTES,
                       'readable': True, 'writable': False, 'executable': False}},
            'outcome': {'clock_events': [{'instruction': {'operation': {'kind': 'read_virtual_counter'}}, 'counter': 123}]}}
        suite.audit_startup_clock(native, pac, 123)
        for field, value in [('legacy_configuration', {'kdebug': None}), ('legacy_commpage_profile', 'other'),
                             ('page_sha256', suite.digest(bytes(15))), ('events', [])]:
            changed = copy.deepcopy(native)
            changed['clock'][field] = value
            with self.assertRaises(AssertionError):
                suite.audit_startup_clock(changed, pac, 123)
        changed = copy.deepcopy(native)
        changed['outcome']['clock_events'] *= 2
        with self.assertRaises(AssertionError):
            suite.audit_startup_clock(changed, pac, 123)


if __name__ == '__main__':
    unittest.main()
