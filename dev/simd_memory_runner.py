"""Shared SIMD memory adapter: frozen originals, native execution and runtime.

Uses the existing compiler/manifest, EL0 observer, MXCSR wrapper, fault observer
and owned-memory runtime interfaces. Family fixtures own independent semantics.
"""
from collections import Counter
from contextlib import contextmanager, ExitStack
import ctypes
import json
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import time

from differential import ROOT, BASE, State, state_dict, parse_fault_record, move
from evidence import write_evidence
from simd_fixtures import structure_memory as family, ordinary_memory, atomic_memory, atomic_pair_memory, ordered_unscaled_memory, limited_ordered_memory
import simd_original

BATCH_FUNCTIONS = 256
FOCUS = family.FOCUS
ATOMIC_FAMILIES = (atomic_memory, atomic_pair_memory, ordered_unscaled_memory, limited_ordered_memory)
ATOMIC_ORACLE_REVIEW = ROOT / '.stela/research/atomic-implementation/contracts/unicorn-signed-minmax/review-receipt.json'
ATOMIC_SMP_POINTER = ROOT / '.stela/research/atomic-implementation/smp/oracle/receipt.json'
PAIR_SMP_POINTER = ROOT / '.stela/research/casp-implementation/smp/oracle/receipt.json'
ORACLE_DIRECTORY = ROOT / '.stela/research/structured-memory-implementation/fixtures/oracle'
FAMILIES = {FOCUS: family, ordinary_memory.FOCUS: ordinary_memory, atomic_memory.FOCUS: atomic_memory, atomic_pair_memory.FOCUS: atomic_pair_memory, ordered_unscaled_memory.FOCUS: ordered_unscaled_memory, limited_ordered_memory.FOCUS: limited_ordered_memory}
ORACLE_DIRECTORIES = {FOCUS: ORACLE_DIRECTORY, ordinary_memory.FOCUS: ROOT / '.stela/research/ordinary-memory/fixtures/oracle',
                      atomic_memory.FOCUS: ROOT / '.stela/research/atomic-implementation/fixtures/oracle',
                      atomic_pair_memory.FOCUS: ROOT / '.stela/research/casp-implementation/fixtures/oracle',
                      ordered_unscaled_memory.FOCUS: ROOT / '.stela/research/ordered-unscaled-implementation/fixtures/oracle',
                      limited_ordered_memory.FOCUS: ROOT / '.stela/research/coverage-race/nonstreaming/limited-ordering/fixtures/oracle'}


def family_module(focus):
    if focus not in FAMILIES:
        raise ValueError('Unknown memory fixture focus: ' + focus)
    return FAMILIES[focus]


def dependencies(engine, family=family):
    paths = [Path(engine.__file__), Path(__file__), Path(family.__file__), Path(simd_original.__file__),
             ROOT / 'dev/differential.py', ROOT / 'dev/evidence.py', ROOT / 'dev/native-memory-faults.c',
             ROOT / 'dev/test_simd_fixtures.py']
    if family in (ordinary_memory, *ATOMIC_FAMILIES):
        paths += [ROOT / 'dev/memory-faults.py', ROOT / 'dev/simd_fixtures/structure_memory.py', ROOT / 'dev/a64_checklist.py']
    if family in ATOMIC_FAMILIES:
        paths += [ROOT / 'dev/simd_fixtures/memory_history.py']
    if family in (atomic_pair_memory, ordered_unscaled_memory, limited_ordered_memory):
        paths += [Path(atomic_memory.__file__)]
    if family is atomic_pair_memory:
        paths += [ROOT / 'dev/simd_atomic_original.py']
    if family is atomic_memory:
        paths += [ROOT / 'dev/simd_atomic_original.py', ATOMIC_ORACLE_REVIEW]
        review = json.loads(ATOMIC_ORACLE_REVIEW.read_bytes())
        paths += [ROOT / item['path'] for item in [*review['source_files'], review['witness'], *review['witness_files']]]
    return {str(path.relative_to(ROOT)): engine.digest(path.read_bytes()) for path in paths}


def prepare_original(engine, directory, focus=FOCUS):
    family = family_module(focus)
    directory = Path(directory)
    operations, cases = family.corpus()
    plan = engine.prepare_full_frame_numerical_oracle(directory, operations, cases, focus)
    memory = family.memory_template()
    memory_plan = {'ram_address': family.RAM_ADDRESS, 'ram_bytes': len(memory), 'initial_ram_sha256': engine.digest(memory)}
    simd_original.write_new(directory / 'memory.bin', memory)
    simd_original.write_new(directory / 'memory-plan.json', simd_original.json_bytes(memory_plan))
    sources = dependencies(engine, family)
    simd_original.write_new(directory / 'source-bindings.json', simd_original.json_bytes(sources))
    return {**plan, **family.inventory(), 'memory_plan': memory_plan,
            'capture_command': [sys.executable, str(Path(simd_original.__file__)), '--directory', str(directory),
                                '--focus', focus, '--source-bindings', str(directory / 'source-bindings.json'), '--capture']}


def load_original(engine, pointer, focus=FOCUS):
    family = family_module(focus)
    pointer_data, pointer_sha = engine.numerical_json(pointer)
    producer, receipt_sha = engine.numerical_json(ROOT / pointer_data['receipt']['path'], pointer_data['receipt']['sha256'])
    directory = ROOT / producer['directory']
    memory_plan = simd_original.memory_plan(directory)
    if (not producer.get('passed_transport_and_architectural_frame_checks') or memory_plan is None
            or producer['results_stride'] != memory_plan['record_bytes'] or pointer_data['directory'] != producer['directory']):
        raise AssertionError('Passing memory original full-frame/RAM capture required')
    for name, identity in producer['files'].items():
        if Path(name).name != name:
            raise AssertionError('Original memory evidence path escapes capture')
        data = (directory / name).read_bytes()
        if len(data) != identity['bytes'] or engine.digest(data) != identity['sha256']:
            raise AssertionError('Original memory capture changed: ' + name)
    operations, cases = family.corpus()
    expected_functions = [{**op, 'source_hex': struct.pack('<II', op['word'], engine.RET).hex()} for op in operations]
    if (json.loads((directory / 'functions.json').read_bytes()) != expected_functions
            or json.loads((directory / 'cases.json').read_bytes()) != [{k: v for k, v in case.items() if k != 'initial'} for case in cases]
            or (directory / 'inputs.bin').read_bytes() != b''.join(struct.pack('<Q', case['function']) + case['initial'] + bytes(8) for case in cases)
            or (directory / 'memory.bin').read_bytes() != family.memory_template() or producer['cases'] != len(cases)):
        raise AssertionError('Frozen memory corpus differs from primary original inputs')
    results = (directory / 'results.bin').read_bytes()
    stride = memory_plan['record_bytes']
    if len(results) != simd_original.HEADER_BYTES + len(cases) * stride:
        raise AssertionError('Original memory results framing differs')
    if family in ATOMIC_FAMILIES:
        if not producer.get('atomic_features'):
            raise AssertionError('Original atomic feature readbacks required')
        simd_original.validate_atomic_features(results, focus=focus)
    records, controls = [], Counter()
    memory = family.memory_template()
    for index, case in enumerate(cases):
        op, initial = operations[case['function']], State.from_buffer_copy(case['initial'])
        snapshot = results[simd_original.HEADER_BYTES + index * stride:simd_original.HEADER_BYTES + (index + 1) * stride]
        original = engine.full_frame_numerical_original_state(initial, snapshot[:1024])
        expected, expected_ram, fault = family.expected(op, initial, memory)
        observed_controls = State.from_buffer_copy(expected)
        observed_controls.fpcr, observed_controls.fpsr = original.fpcr, original.fpsr
        original_ram = snapshot[1024:]
        if fault or bytes(original) != bytes(observed_controls) or original_ram != expected_ram:
            raise AssertionError(json.dumps({'case': index, 'operation': op, 'original': state_dict(original),
                                            'expected': state_dict(observed_controls), 'RAM_equal': original_ram == expected_ram}))
        basis = 'direct_original' if bytes(original) == bytes(expected) else 'requested_control_storage_policy'
        controls[(initial.fpcr, original.fpcr, initial.fpsr, original.fpsr)] += 1
        records.append({**case, 'case': index, 'operation': op, 'expected': bytes(expected),
                        'primary_original': bytes(original), 'expected_ram': expected_ram, 'equality_basis': basis})
    return {'functions': operations, 'records': records, 'producer': producer, 'receipt_sha256': receipt_sha,
            'pointer_sha256': pointer_sha, 'control_readbacks': [{'requested_fpcr': a, 'original_fpcr': b,
                'requested_fpsr': c, 'original_fpsr': d, 'cases': count} for (a, b, c, d), count in sorted(controls.items())]}


@contextmanager
def fixed_private_ram(family=family):
    """Ask for the original address as a hint; never replace existing mappings."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    import mmap
    pointer = libc.mmap(family.RAM_ADDRESS, family.RAM_BYTES, mmap.PROT_READ | mmap.PROT_WRITE,
                        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    if pointer == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), 'Could not map bounded native fixture RAM')
    try:
        if pointer != family.RAM_ADDRESS:
            raise AssertionError('Native memory address hint refused; no existing mapping was replaced')
        yield pointer
    finally:
        if libc.munmap(pointer, family.RAM_BYTES):
            raise OSError(ctypes.get_errno(), 'Could not release native fixture RAM')


def execute_batches(engine, batches):
    family = family_module(batches[0]['cohort'])
    oracle = load_original(engine, batches[0]['oracle_path'], family.FOCUS)
    counts = Counter()
    with ExitStack() as mappings:
        functions = {}
        for batch in batches:
            pointer = mappings.enter_context(engine.executable(batch['native']))
            for local, offset in enumerate(batch['offsets']):
                functions[batch.get('function_indices', list(range(batch['function_base'], batch['function_base'] + len(batch['offsets']))))[local]] = pointer + offset
        ram_pointer = mappings.enter_context(fixed_private_ram(family))
        wrapper_pointer = mappings.enter_context(engine.executable(engine.NUMERICAL_MXCSR_WRAPPER))
        wrapper = ctypes.CFUNCTYPE(None, ctypes.POINTER(State), ctypes.c_void_p, ctypes.c_uint32,
                                  ctypes.POINTER(engine.NumericalNativeExit))(wrapper_pointer)
        memory = family.memory_template()
        selected_records = [record for record in oracle['records'] if record['function'] in functions]
        for record in selected_records:
            state = State.from_buffer_copy(record['initial'])
            ctypes.memmove(ram_pointer, memory, len(memory))
            observed = engine.NumericalNativeExit()
            wrapper(ctypes.byref(state), functions[record['function']], engine.NUMERICAL_MXCSR_ALL_MASKS, ctypes.byref(observed))
            actual_ram = ctypes.string_at(ram_pointer, family.RAM_BYTES)
            if (bytes(state) != record['expected'] or actual_ram != record['expected_ram']
                    or observed.mxcsr_before != engine.NUMERICAL_MXCSR_ALL_MASKS or observed.mxcsr_after != engine.NUMERICAL_MXCSR_ALL_MASKS):
                raise AssertionError(json.dumps({'case': record['case'], 'operation': record['operation'],
                    'native': state_dict(state), 'expected': state_dict(State.from_buffer_copy(record['expected'])),
                    'RAM_equal': actual_ram == record['expected_ram']}))
            counts[record['equality_basis']] += 1
            counts[record['path']] += 1
    return {'complete_native_state_RAM_comparisons': len(selected_records), 'guest_state_bytes': 784,
            'ram_bytes_per_comparison': family.RAM_BYTES, 'direct_original_math_native_comparisons': counts['direct_original'],
            'requested_control_storage_native_policy_comparisons': counts['requested_control_storage_policy'],
            'same_granule_comparisons': counts['same_granule'], 'crossing_comparisons': counts['crossing'],
            'caller_mxcsr_preservation_comparisons': len(selected_records)}



NORMAL_RBX_SENTINEL = 0xca5f16ab1c0ffee7
PUSH_RBX, POP_RBX, HOST_RET = b'\x53', b'\x5b', b'\xc3'
MOV_RBX_IMM64, CALL_REL32, MOV_RAX_RBX = b'\x48\xbb', b'\xe8', b'\x48\x89\xd8'
CALL_REL32_BYTES = len(CALL_REL32) + struct.calcsize('<i')


def normal_return_rbx_wrapper(native, entry, sentinel=NORMAL_RBX_SENTINEL):
    """Call the exact compiled leaf with ABI stack alignment and observe RBX."""
    if not 0 <= entry < len(native) or not 0 <= sentinel <= (1 << 64) - 1:
        raise ValueError('Invalid normal-return ABI entry/sentinel')
    setup = PUSH_RBX + MOV_RBX_IMM64 + struct.pack('<Q', sentinel)
    finish = MOV_RAX_RBX + POP_RBX + HOST_RET
    body_start = len(setup) + CALL_REL32_BYTES + len(finish)
    displacement = body_start + entry - (len(setup) + CALL_REL32_BYTES)
    prefix = setup + CALL_REL32 + struct.pack('<i', displacement) + finish
    return prefix + native, len(prefix)


def verify_pair_normal_abi(engine, batches, oracle, target_id):
    """Separate normal-return host preservation, never fault-resumption evidence."""
    selected = {}
    for record in oracle['records']:
        if record['compare_mode'] in ('match', 'low_mismatch'):
            selected.setdefault((record['function'], record['compare_mode']), record)
    counts, wrappers, observations = Counter(), [], []
    with fixed_private_ram(atomic_pair_memory) as ram_pointer:
        for batch in batches:
            for local, entry in enumerate(batch['offsets']):
                function = batch['function_indices'][local]
                wrapped, prefix_bytes = normal_return_rbx_wrapper(batch['native'], entry)
                wrappers.append({'function': function, 'native_sha256': engine.digest(batch['native']),
                    'entry': entry, 'wrapper_prefix_hex': wrapped[:prefix_bytes].hex(), 'wrapped_sha256': engine.digest(wrapped)})
                with engine.executable(wrapped) as address:
                    call = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.POINTER(State))(address)
                    for mode in ('match', 'low_mismatch'):
                        record = selected[function, mode]
                        state = State.from_buffer_copy(record['initial'])
                        ctypes.memmove(ram_pointer, atomic_pair_memory.memory_template(), atomic_pair_memory.RAM_BYTES)
                        returned = call(ctypes.byref(state))
                        ram = ctypes.string_at(ram_pointer, atomic_pair_memory.RAM_BYTES)
                        observations.append({'function': function, 'case': record['case'], 'mode': mode, 'returned_rbx': returned,
                            'actual_state_hex': bytes(state).hex(), 'actual_ram_sha256': engine.digest(ram)})
                        if returned != NORMAL_RBX_SENTINEL or bytes(state) != record['expected'] or ram != record['expected_ram']:
                            path = write_evidence(ROOT / f'.stela/casp-normal-abi-{target_id}-failure.json', observations)
                            raise AssertionError('CASP normal-return host ABI/State/RAM mismatch: ' + str(path))
                        counts['normal_return_rbx_checks'] += 1
    path = write_evidence(ROOT / f'.stela/casp-normal-abi-{target_id}-records.json', {'wrappers': wrappers, 'observations': observations})
    return {**counts, 'functions': len(wrappers), 'sentinel': NORMAL_RBX_SENTINEL,
        'records': {'path': str(path.relative_to(ROOT)), 'sha256': engine.digest(path.read_bytes())},
        'limits': 'Actual compiled leaf called with a seeded host RBX and checked complete guest State/RAM on normal return. Faulting execution terminates; no host fault-context restoration or resumption claim.'}

def runtime_checks(engine, cli, directory, compiler, target, target_id, oracle, family=family, selected_functions=None):
    """Canonical forms through actual owned-memory dispatcher/cache."""
    if family in ATOMIC_FAMILIES:
        representatives = {}
        for record in oracle['records']:
            op = record['operation']
            if (selected_functions is None or record['function'] in selected_functions) and not (30 in op['written_gprs']):
                representatives.setdefault(op['canonical_id'], record)
        records = list(representatives.values())
    else:
        records = [record for record in oracle['records'] if record['runtime']]
    counts, transcripts = Counter(), []
    for record in records:
        op, initial = record['operation'], State.from_buffer_copy(record['initial'])
        initial.x[30] = engine.STOP
        source = struct.pack('<II', op['word'], engine.RET)
        expected, expected_ram, fault = family.expected(op, initial, family.memory_template())
        if fault:
            raise AssertionError('Runtime success record faults in independent model')
        source_path, state_path, memory_path = [directory / name for name in ('runtime.arm64', 'runtime-state.json', 'runtime-memory.json')]
        source_path.write_bytes(source)
        state_path.write_text(json.dumps(state_dict(initial)))
        memory_path.write_text(json.dumps({'regions': [{'guest_address': family.RAM_ADDRESS, 'virtual_bytes': family.RAM_BYTES,
            'initial_bytes': list(family.memory_template()), 'readable': True, 'writable': True}]}))
        cache = directory / ('runtime-cache-' + str(record['function']))
        for warm in (False, True):
            report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path), '--guest-base', hex(BASE),
                '--stop-pc', hex(engine.STOP), '--cpu-target', target, '--state', str(state_path), '--block-budget', '16',
                '--cache-dir', str(cache), '--memory', str(memory_path), '--read-memory', f'{hex(family.RAM_ADDRESS)}:{family.RAM_BYTES}'], timeout=30))
            actual = engine.numerical_report_state(report['state'])
            if (report['compiler_source_sha256'] != compiler or report['target_cpu'] != target_id
                    or report['source_sha256'] != engine.digest(source) or report['pc'] != engine.STOP
                    or report['outcome']['reason']['kind'] != 'stop_address' or report['outcome']['floating_point_helpers']
                    or bytes(actual) != bytes(expected) or bytes.fromhex(report['memory']['memory_reads'][0]['hex']) != expected_ram
                    or warm and not report['outcome']['disk_cache_hits']):
                raise AssertionError('Structured memory runtime full state/RAM/cache mismatch')
            counts['complete_state_RAM_comparisons'] += 1
            counts['disk_cache_checks'] += int(warm)
            transcripts.append({'function': record['function'], 'warm': warm, 'initial_state_hex': bytes(initial).hex(), 'report': report})
    snapshot = write_evidence(ROOT / f'.stela/simd-{family.FOCUS}-{target_id}-runtime-records.json', transcripts)
    return {**counts, 'transcript': {'path': str(snapshot.relative_to(ROOT)), 'sha256': engine.digest(snapshot.read_bytes())},
            'limits': 'Runtime models are grounded in individual primary originals. No joined-original, fault delivery, process or performance credit.'}


def calibrated_originals(engine):
    """Reassess immutable32 actual original frames with both explicit policies."""
    index_path = ROOT / '.stela/research/structured-memory-planning/calibration/result.json'
    index, _ = engine.numerical_json(index_path)
    receipt, receipt_sha = engine.numerical_json(ROOT / index['receipt']['path'], index['receipt']['sha256'])
    directory = (ROOT / index['receipt']['path']).parent
    cases = json.loads((directory / 'cases.json').read_bytes())
    inputs = (directory / 'inputs.bin').read_bytes()
    raw = (directory / 'results.bin').read_bytes()
    seed = (directory / 'ram-seed.bin').read_bytes()
    bindings = json.loads((directory / 'bindings.json').read_bytes())
    for name, identity in receipt.items():
        if isinstance(identity, dict) and {'path', 'sha256', 'bytes'} <= identity.keys():
            data = (ROOT / identity['path']).read_bytes()
            if len(data) != identity['bytes'] or engine.digest(data) != identity['sha256']:
                raise AssertionError('Immutable calibration identity changed: ' + name)
    counts, records = Counter(), []
    shapes = family.shapes()
    for case, retained in zip(cases, receipt['results']):
        word = retained['instruction_word']
        candidates = []
        for shape in shapes:
            if shape['canonical_id'] != retained['canonical_id']:
                continue
            mask = ~(31 | 31 << 5 | (31 << 16 if shape['mode'] == 'register' else 0))
            if word & mask == shape['word'] & mask:
                candidates.append(shape)
        if len(candidates) != 1:
            raise AssertionError('Calibrated word does not identify exactly one fixture shape')
        values = {key: candidates[0][key] for key in ('layout', 'loading', 'structures', 'runs', 'vector_bytes', 'element_bytes', 'index', 'mode')}
        op = family.operation(**values, rt=word & 31, rn=word >> 5 & 31, rm=word >> 16 & 31)
        if op['word'] != word or op['canonical_id'] != retained['canonical_id']:
            raise AssertionError('Calibrated original word identity differs')
        initial = State.from_buffer_copy(inputs[case['index'] * 1024:case['index'] * 1024 + 784])
        snapshot = raw[1024 + case['index'] * 12288:1024 + (case['index'] + 1) * 12288]
        original = engine.full_frame_numerical_original_state(initial, snapshot[:1024])
        memory = snapshot[1024:1024 + len(seed)]
        limit = len(seed) if case['success_control'] else case['address'] - 0x48000000 + case['accessible_bytes']
        source, source_ram, fault = family.expected(op, initial, seed, 0x48000000, accessible=limit)
        predicted, predicted_ram, predicted_fault = family.expected(op, initial, seed, 0x48000000, accessible=limit, policy='qemu')
        if bytes(predicted) != bytes(original) or predicted_ram != memory or bool(predicted_fault) == case['success_control']:
            raise AssertionError('Independent explicit QEMU model differs from immutable actual calibration')
        equal = bytes(source) == bytes(original) and source_ram == memory
        classification = ('success_direct_original' if case['success_control'] else 'fault_direct_original') if equal else 'fault_classified_source_policy_difference'
        counts[classification] += 1
        records.append({'id': case['id'], 'canonical_id': op['canonical_id'], 'classification': classification,
            'original_frame_sha256': engine.digest(snapshot[:1024]), 'original_ram_sha256': engine.digest(memory),
            'source_policy_state_hex': bytes(source).hex(), 'raw_original_state_hex': bytes(original).hex(),
            'source_policy_ram_sha256': engine.digest(source_ram), 'source_fault': fault})
    if counts != Counter(success_direct_original=16, fault_direct_original=9, fault_classified_source_policy_difference=7):
        raise AssertionError('Calibrated original partitions changed: ' + str(counts))
    return {'receipt_sha256': receipt_sha, 'partitions': dict(counts), 'records': records,
            'limits': 'These32 observations are actual immutable original QEMU frames/RAM. Seven source-policy differences retain every raw byte; no UNKNOWN mask, normalization or direct-equality credit. They are not native fault observations.'}


def native_fault_selection(first_access_only=False, family=family):
    """Bounded family semantic cuts."""
    if family in (ordinary_memory, atomic_memory):
        return family.fault_selection(first_access_only)
    selected, seen, representatives = [], set(), {}
    shapes = family.shapes()
    for function, op in enumerate(shapes):
        # One maximal-width/index shape for each canonical address form.
        representatives[op['canonical_id']] = function
    def append(function, cut, protection=None, rn=None):
        protection = protection or ('structure_crossing' if cut else 'guard')
        rn = shapes[function]['rn'] if rn is None else rn
        key = function, rn, cut, protection
        if key not in seen:
            seen.add(key)
            selected.append({'function': function, 'rn': rn, 'cut': cut, 'protection': protection})
    for function in representatives.values():
        op = shapes[function]
        width, total = op['element_bytes'], op['total_bytes']
        for cut in (0, total // width // 2 * width, total - width):
            append(function, cut)
        if not op['loading']:
            append(function, 0, 'readonly')
    for function, op in enumerate(shapes):
        # Every scalar width, both Q widths, first/last lane and every list stage
        # get explicit byte cuts on maximal lists under one post-index mode.
        if op['mode'] != 'immediate' or op['structures'] != 4 and not (op['layout'] == 'multiple' and op['runs'] == 4):
            continue
        if op['layout'] == 'lane' and op['index'] not in (0, 16 // op['element_bytes'] - 1):
            continue
        width, total = op['element_bytes'], op['total_bytes']
        cuts = {0, total - width, total // width // 2 * width}
        cuts.update(stage * width for stage in range(op['structures']))
        cuts.update(range(1, width))
        cuts.update(total - width + byte for byte in range(1, width))
        for cut in sorted(cuts - {total}):
            append(function, cut)
    sp_representatives = {}
    for function, op in enumerate(shapes):
        sp_representatives[op['layout'], op['loading'], op['mode']] = function
    for function in sp_representatives.values():
        for protection in ('sp_alignment', 'sp_alignment8'):
            append(function, 0, protection, rn=31)
    return [case for case in selected if case['protection'] != 'structure_crossing'] if first_access_only else selected


def fault_operation(shape, rn, family=family, case=None):
    if family in (ordinary_memory, atomic_memory):
        return family.fault_operation(shape, case or {'rn': rn})
    values = {key: shape[key] for key in ('layout', 'loading', 'structures', 'runs',
              'vector_bytes', 'element_bytes', 'index', 'mode', 'rt', 'rm')}
    return family.operation(**values, rn=rn)


def retain_ordinary_fault_bytes(engine, source, native, data, case, mapping, family_focus=ordinary_memory.FOCUS):
    """Keep actual native transport and its exact program before validation."""
    files = {'source.arm64': source, 'native.bin': native, 'native-record.bin': data,
             'metadata.json': simd_original.json_bytes({'case': case, 'source_map': mapping})}
    key = engine.digest(b''.join(len(value).to_bytes(8, 'little') + value for value in files.values()))
    directory = ROOT / '.stela/native-evidence' / (family_focus.replace('_', '-') + '-faults') / key
    directory.mkdir(parents=True, exist_ok=True)
    identities = {}
    for name, value in files.items():
        simd_original.write_new(directory / name, value)
        identities[name] = {'path': str((directory / name).relative_to(ROOT)),
                            'sha256': engine.digest(value), 'bytes': len(value)}
    return identities

def ordinary_original_fault(oracle, source, initial, ram_address, page_size, readonly):
    """Reuse mapped-access fault oracle with explicit observed EL0/FP controls."""
    import unicorn
    from unicorn import arm64_const as arm
    initialize = oracle.initialize_arm
    observed = {}
    machine_reference = []
    def initialize_el0(machine, state):
        observed['before_setup'] = {'pstate': machine.reg_read(arm.UC_ARM64_REG_PSTATE),
                                   'cpacr_el1': machine.reg_read(arm.UC_ARM64_REG_CPACR_EL1)}
        machine.reg_write(arm.UC_ARM64_REG_PSTATE, state.nzcv & 0xf0000000)
        machine.reg_write(arm.UC_ARM64_REG_CPACR_EL1, simd_original.FP_ACCESS_ENABLED)
        initialize(machine, state)
        observed['before_execution'] = {name: machine.reg_read(register) for name, register in (
            ('pstate', arm.UC_ARM64_REG_PSTATE), ('cpacr_el1', arm.UC_ARM64_REG_CPACR_EL1),
            ('fpcr', arm.UC_ARM64_REG_FPCR), ('fpsr', arm.UC_ARM64_REG_FPSR))}
        if (observed['before_execution']['pstate'] & 15
                or observed['before_execution']['cpacr_el1'] & simd_original.FP_ACCESS_ENABLED != simd_original.FP_ACCESS_ENABLED):
            raise AssertionError('Ordinary Unicorn oracle refused explicit EL0/FP setup')
        machine_reference.append(machine)
    oracle.initialize_arm = initialize_el0
    try:
        state, ram, faults = oracle.arm_fault(source, initial, ram_address, page_size, readonly)
    finally:
        oracle.initialize_arm = initialize
    machine = machine_reference[0]
    observed['after_execution'] = {name: machine.reg_read(register) for name, register in (
        ('pstate', arm.UC_ARM64_REG_PSTATE), ('cpacr_el1', arm.UC_ARM64_REG_CPACR_EL1),
        ('fpcr', arm.UC_ARM64_REG_FPCR), ('fpsr', arm.UC_ARM64_REG_FPSR))}
    return state, ram, faults, {'engine_version': unicorn.__version__, 'requested_el': 0, **observed,
        'limits': 'Explicit PSTATE EL0 and FP access readbacks; Unicorn mem_map access permissions. Architectural MMU/TCR/SCTLR controls are not observed. No EL0 page-table permission, guest syndrome or hardware exception delivery claim.'}


def verify_declined(engine, cli, directory, family):
    records = []
    for index, case in enumerate(family.declined_encodings()):
        capability = case['reason'] in ('AtomicLoad16_host_capability', 'Cx16_host_capability')
        commands = ('compile-leaf', 'compile-block') if capability else ('compile-leaf',)
        for command in commands:
            path, output = directory / f'declined-{index}.arm64', directory / f'declined-{index}-{command}.native'
            source = struct.pack('<II', case['word'], engine.RET)
            path.write_bytes(source)
            completed = subprocess.run([str(cli), command, str(path), '--guest-base', hex(BASE),
                                        '--cpu-target', 'baseline', '--output-dir', str(output)], capture_output=True, text=True, timeout=30)
            if completed.returncode == 0 or (output / 'native.bin').exists():
                raise AssertionError('Declined memory input emitted native code: ' + str(case))
            if capability and 'HostCapabilityRequired' not in completed.stderr:
                raise AssertionError('Ordered baseline decline lost capability reason: ' + completed.stderr)
            records.append({**case, 'command': command, 'source_sha256': engine.digest(source), 'error': completed.stderr.strip()})
    return {'declined_before_execution': len(records), 'records': records}


def verify_faults(engine, cli, directory, compiler, target, target_id, family=family):
    if family in ATOMIC_FAMILIES:
        return verify_atomic_faults(engine, cli, directory, compiler, target, target_id, family)
    observer = directory / (family.FOCUS + '-fault-observer')
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(ROOT / 'dev/native-memory-faults.c'), '-o', str(observer)], check=True)
    records, counts = [], Counter()
    shapes = family.shapes()
    selections = native_fault_selection(first_access_only=target != 'baseline', family=family)
    operations_by_word = {}
    for case in selections:
        op = fault_operation(shapes[case['function']], case['rn'], family, case)
        case['word'] = op['word']
        operations_by_word.setdefault(op['word'], op)
    unique = list(operations_by_word)
    compiled = {}
    for start in range(0, len(unique), BATCH_FUNCTIONS):
        indexes = unique[start:start + BATCH_FUNCTIONS]
        operations = [operations_by_word[word] for word in indexes]
        programs = [{'operations': [{'kind': 'prefix', 'word': move(2, 1, 7, 99)}, op]} for op in operations]
        batch = engine.compile_batch(cli, directory, programs, 'fault-batch-' + str(start),
            cpu_target=target, target_id=target_id, allowed_mnemonics={'mov', 'movz', *[op['name'] for op in operations]},
            **({'source_validator': family.validate_source_words} if family is ordinary_memory else {}))
        if batch['compiler'] != compiler:
            raise AssertionError('Structured fault compiler changed')
        for local, key in enumerate(indexes):
            first = batch['offsets'][local]
            last = batch['offsets'][local + 1] if local + 1 < len(indexes) else len(batch['native'])
            native = batch['native'][first:last]
            entry = batch['entries'][local]
            source = batch['source'][entry * 4:(entry + 3) * 4]
            mapping = [[BASE + slot * 4, batch['instruction_offsets'][entry + slot] - first] for slot in range(3)]
            path = directory / f'fault-word-{key:08x}.bin'
            path.write_bytes(native)
            compiled[key] = source, native, mapping, path
    original_oracle = None
    if family is ordinary_memory:
        import importlib.util
        spec = importlib.util.spec_from_file_location('ordinary_original_faults', ROOT / 'dev/memory-faults.py')
        original_oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original_oracle)
    for index, case in enumerate(selections):
        op = operations_by_word[case['word']]
        source, native, mapping, native_path = compiled[case['word']]
        pre_offset = op['offset'] if family is ordinary_memory and op['layout'] != 'prefetch' else 0
        arguments = [str(observer), str(native_path), case['protection'], str(op['rn']), str(pre_offset)]
        if case['protection'] == 'structure_crossing':
            arguments.append(str(case['cut']))
        data = subprocess.check_output(arguments, timeout=10)
        raw_identity = retain_ordinary_fault_bytes(engine, source, native, data, case, mapping) if family is ordinary_memory else None
        (code_address, ram_address, page_size), initial, (number, pc, address), actual, ram = parse_fault_record(data)
        staged = State.from_buffer_copy(initial)
        staged.x[7] = 99
        expected, expected_ram, fault = family.expected(op, staged, b'\xa5' * page_size, ram_address)
        if case['protection'] == 'readonly':
            expected, expected_ram, fault = family.expected(op, staged, b'\xa5' * page_size, ram_address, readonly=True)
        mapped = [guest for guest, offset in mapping if offset <= pc - code_address]
        hint_completion = family is ordinary_memory and op['layout'] == 'prefetch'
        sp_fault = not hint_completion and case['protection'] in ('sp_alignment', 'sp_alignment8')
        fault_offset = pc - code_address
        boundary_valid = (number == signal.SIGILL and native[fault_offset:fault_offset + 2] == b'\x0f\x0b'
                          and fault is not None and fault['kind'] == 'sp_alignment') if sp_fault else (
                          number in (signal.SIGSEGV, signal.SIGBUS) and fault is not None
                          and fault['kind'] == 'memory' and address == fault['address'])
        if hint_completion:
            boundary_valid = number == 0 and fault is None
        if (not boundary_valid or not hint_completion and (not mapped or mapped[-1] != BASE + 4)
                or bytes(actual) != bytes(expected) or ram != expected_ram):
            raise AssertionError(json.dumps({'case': case, 'op': op, 'signal': number, 'native_address': address, 'fault': fault,
                'native': state_dict(actual), 'expected': state_dict(expected), 'RAM_equal': ram == expected_ram,
                **({'native_raw_record': raw_identity} if raw_identity else {})}))
        policy = 'unicorn' if family is ordinary_memory else 'qemu'
        qemu, qemu_ram, _ = family.expected(op, staged, b'\xa5' * page_size, ram_address,
            readonly=case['protection'] == 'readonly', policy=policy)
        original_fields = {}
        if original_oracle is not None and not sp_fault and not hint_completion:
            original, original_ram, original_faults, controls = ordinary_original_fault(
                original_oracle, source, initial, ram_address, page_size, case['protection'] == 'readonly')
            original_raw = write_evidence(ROOT / f'.stela/ordinary-memory-{target_id}-original-fault-{index}.json', {
                'case': case, 'source_hex': source.hex(), 'native_raw': raw_identity,
                'initial_state_hex': bytes(initial).hex(), 'original_state_hex': bytes(original).hex(),
                'original_ram_hex': original_ram.hex(), 'original_faults': original_faults, 'controls': controls})
            if bytes(original) != bytes(qemu) or original_ram != qemu_ram or any(item['pc'] != BASE + 4 for item in original_faults):
                raise AssertionError('Actual Unicorn ordinary fault differs from explicit emulator model: ' + str(case) + ' raw=' + str(original_raw))
            equal = bytes(original) == bytes(expected) and original_ram == expected_ram
            classification = 'original_native_full_state_RAM_equal' if equal else 'classified_unicorn_source_policy_difference'
            counts[classification] += 1
            original_fields = {'original_observation': True, 'original_engine': 'Unicorn mapped access',
                'original_classification': classification, 'original_controls': controls,
                'original_raw_record': {'path': str(original_raw.relative_to(ROOT)), 'sha256': engine.digest(original_raw.read_bytes())},
                'original_state_hex': bytes(original).hex(), 'original_ram_hex': original_ram.hex(),
                'original_faults': original_faults}
        counts['native_source_policy_full_state_RAM_checks'] += 1
        counts['native_prefetch_nonfault_checks' if hint_completion else 'native_sp_alignment_policy_fault_checks' if sp_fault else 'native_memory_address_fault_checks'] += 1
        counts['predicted_' + policy + '_difference_cases'] += int(bytes(qemu) != bytes(expected) or qemu_ram != expected_ram)
        records.append({**case, 'target_cpu': target_id, 'canonical_id': op['canonical_id'], 'source_sha256': engine.digest(source),
            'native_sha256': engine.digest(native), 'native_signal': number, 'native_fault_offset': None if hint_completion else pc - code_address,
            'fault_classification': 'prefetch_completed_without_data_fault' if hint_completion else 'enabled_sp_alignment_policy' if sp_fault else 'memory_address',
            'initial_state_hex': bytes(initial).hex(), 'native_state_hex': bytes(actual).hex(),
            'native_ram_hex': ram.hex(), **({'native_raw_record': raw_identity} if raw_identity else {}), policy + '_prediction_state_hex': bytes(qemu).hex(),
            policy + '_prediction_ram_sha256': engine.digest(qemu_ram), 'original_observation': False, **original_fields})
    snapshot = write_evidence(ROOT / f'.stela/simd-{family.FOCUS}-{target_id}-fault-records.json', records)
    return {**counts, 'target_cpu': target_id, 'selection': ('all_bounded_cuts' if target == 'baseline' else
                'first_access_sp_and_duplicate_store_second_element' if family is ordinary_memory else 'first_access_and_sp_policy'),
            'records': {'path': str(snapshot.relative_to(ROOT)), 'sha256': engine.digest(snapshot.read_bytes())},
            'limits': ('Full native/source-policy equality, including nonfaulting prefetch hints. SP alignment is source-policy-only UD2. Actual Unicorn mapped-access fault frames/RAM and controls are retained separately; emulator differences receive no equality credit. No QEMU EL0-MMU fault, hardware exception delivery or concurrency claim.' if family is ordinary_memory else 'Full native/source-policy equality. SP alignment uses the enabled pre-access UD2 policy, with no memory-address or guest-exception claim. QEMU columns are predictions only; immutable calibrated original observations are separately retained and classified.')}


def native_binary_accounting(engine, batch):
    """Inspect bounded instruction bodies including branch-skipped mask pools."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    native, offsets = batch['native'], batch['instruction_offsets']
    all_code, pool_bindings, bodies = {}, [], []
    for function, entry in zip(batch['functions'], batch['entries']):
        for slot, op in enumerate(function['operations']):
            start, end = offsets[entry + slot:entry + slot + 2]
            pending, code, pools = [start], {}, {}
            while pending:
                position = pending.pop()
                if position == end or position in code:
                    continue
                if not start <= position < end:
                    raise AssertionError('Native branch escapes original instruction interval')
                decoded = list(decoder.disasm(native[position:end], position, count=1))
                if len(decoded) != 1 or decoded[0].address != position or decoded[0].size <= 0:
                    raise AssertionError('Native body has an undecodable reachable instruction')
                instruction = decoded[0]
                following = position + instruction.size
                if following > end:
                    raise AssertionError('Source map splits an actual native instruction')
                if any(other < following and position < other + old.size for other, old in code.items()):
                    raise AssertionError('Native branch enters the middle of another instruction')
                code[position] = instruction
                for operand in instruction.operands:
                    if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                        target = following + operand.mem.disp
                        if instruction.mnemonic != 'movdqu' or operand.size != 16 or not start <= target <= end - 16:
                            raise AssertionError('Memory body has an undeclared RIP constant load')
                        pools[target] = 16
                        pool_bindings.append({'instruction_offset': position, 'pool_offset': target, 'bytes': 16,
                                              'sha256': engine.digest(native[target:target + 16])})
                if instruction.group(CS_GRP_CALL) or instruction.group(CS_GRP_RET):
                    raise AssertionError('Memory instruction body contains an unexpected call/return')
                if instruction.group(CS_GRP_JUMP):
                    if len(instruction.operands) != 1 or instruction.operands[0].type != X86_OP_IMM:
                        raise AssertionError('Memory body contains an indirect branch')
                    target = instruction.operands[0].imm
                    if not start <= target <= end:
                        raise AssertionError('Memory branch target escapes its source-map interval')
                    pending.append(target)
                    if instruction.mnemonic != 'jmp':
                        pending.append(following)
                elif instruction.mnemonic != 'ud2':
                    pending.append(following)
            owners = bytearray(end - start)
            for position, instruction in code.items():
                for byte in range(position - start, position + instruction.size - start):
                    if owners[byte]:
                        raise AssertionError('Native code spans overlap')
                    owners[byte] = 1
            for position, length in pools.items():
                for byte in range(position - start, position + length - start):
                    if owners[byte]:
                        raise AssertionError('Native mask pool overlaps code or another mask')
                    owners[byte] = 2
            if not owners or 0 in owners:
                raise AssertionError('Native source-map interval contains undeclared unreachable bytes')
            all_code.update(code)
            bodies.append({'canonical_id': op['canonical_id'], 'word': op['word'], 'start': start, 'end': end,
                           'native_bytes': end - start, 'reachable_instruction_bytes': owners.count(1),
                           'mask_pool_bytes': owners.count(2), 'reachable_instructions': len(code),
                           **{key: op[key] for key in ('layout', 'element_bytes', 'vector_bytes', 'runs', 'structures', 'index',
                                                      'rt', 'rt2', 'rn', 'rs', 'operation', 'order', 'offset', 'mode', 'hint', 'rm', 'option', 'shift') if key in op}})
        ret = offsets[entry + len(function['operations'])]
        if native[ret:ret + 1] != b'\xc3':
            raise AssertionError('Memory function lacks exact one-byte harness RET')
        all_code[ret] = next(decoder.disasm(native[ret:ret + 1], ret))
    body_bytes = sum(body['native_bytes'] for body in bodies)
    if body_bytes + len(batch['functions']) != len(native):
        raise AssertionError('Memory accounting does not partition full native bytes')
    return {'native_sha256': engine.digest(native), 'source_sha256': engine.digest(batch['source']),
            'static_native_bytes_including_ret': len(native), 'static_native_instructions_including_ret': len(all_code),
            'harness_ret_bytes': len(batch['functions']), 'harness_ret_instructions': len(batch['functions']),
            'static_body_native_bytes': body_bytes,
            'static_body_native_instructions': sum(body['reachable_instructions'] for body in bodies),
            'constant_pool_bytes': sum(body['mask_pool_bytes'] for body in bodies),
            'opcode_counts': dict(Counter(engine.native_mnemonic(op.mnemonic) for op in all_code.values())),
            'pool_bindings': pool_bindings, 'bodies': bodies,
            'limits': 'Static reachable instruction counts include both fast/fallback branches and terminal SP-policy UD2; sixteen-byte RIP mask pools are separately bound and excluded from instruction counts. No dynamic-count or timing credit.'}


def run(engine, cli, pointer=None, focus=FOCUS, atomic_smp_pointer=None):
    family = family_module(focus)
    pointer = Path(pointer) if pointer else ORACLE_DIRECTORIES[focus] / 'receipt.json'
    oracle = load_original(engine, pointer, focus)
    smp_pointer = Path(atomic_smp_pointer) if atomic_smp_pointer else PAIR_SMP_POINTER if family is atomic_pair_memory else ATOMIC_SMP_POINTER
    smp = load_atomic_smp_original(engine, smp_pointer, family) if family in (atomic_memory, atomic_pair_memory) else None
    sources, cli_sha, started = dependencies(engine, family), engine.digest(cli.read_bytes()), time.monotonic()
    cpu = json.loads(subprocess.check_output([str(cli), 'cpu-info']))
    if family in (atomic_memory, ordered_unscaled_memory, limited_ordered_memory) and not cpu.get('atomic_load16'):
        raise AssertionError('Full atomic proof requires checked AtomicLoad16 host capability; baseline is a bounded subset')
    if family is atomic_pair_memory and (not cpu.get('cx16') or 'cx16' not in cpu['detected_target'].split('+')[1:]):
        raise AssertionError('Full CASP proof requires independent checked Cx16 capability and target identity')
    selections = [('baseline', 'x86_64-baseline')]
    if cpu['detected_target'] != 'x86_64-baseline':
        selections.append(('native', cpu['detected_target']))
    profiles, faults, compiler = [], [], None
    with tempfile.TemporaryDirectory(prefix='stela-' + focus + '-') as temporary:
        for target, target_id in selections:
            directory = Path(temporary) / target_id
            directory.mkdir()
            batches, artifacts = [], []
            selected_functions = [index for index, op in enumerate(oracle['functions'])
                                  if family not in ATOMIC_FAMILIES or family.supported_on_profile(op, target if target == 'baseline' else target_id)]
            for start in range(0, len(selected_functions), BATCH_FUNCTIONS):
                indices = selected_functions[start:start + BATCH_FUNCTIONS]
                operations = [oracle['functions'][index] for index in indices]
                batch = engine.compile_batch(cli, directory, [{'operations': [op]} for op in operations], start,
                    cpu_target=target, target_id=target_id, guest_base=BASE + start * 8,
                    allowed_mnemonics={op['name'] for op in operations},
                    **({'source_validator': family.validate_source_words} if family in (ordinary_memory, *ATOMIC_FAMILIES) else {}))
                batch.update(cohort=focus, function_base=start, function_indices=indices, oracle_path=str(pointer))
                if compiler is not None and compiler != batch['compiler']:
                    raise AssertionError('Structured memory compiler changed')
                compiler = batch['compiler']
                accounting = native_binary_accounting(engine, batch)
                artifacts.append({'function_base': start, 'accounting': accounting,
                                  **({'source_decoder_validation': batch['source_decoder_validation']} if 'source_decoder_validation' in batch else {}),
                                  'files': engine.retain_native_binary_evidence(batch, accounting, [])})
                batches.append(batch)
            optional = {row['mnemonic'] for row in cpu['simd_opcodes'] if row['minimum_target'] != 'x86_64-baseline'}
            used = optional & {name for artifact in artifacts for name in artifact['accounting']['opcode_counts']}
            if target == 'baseline' and used:
                raise AssertionError('Baseline memory body emitted optional opcodes: ' + str(sorted(used)))
            raw = engine.bounded_cases(batches)
            runtime = runtime_checks(engine, cli, directory, compiler, target, target_id, oracle, family, set(selected_functions))
            profiles.append({'target_cpu': target_id, 'raw_native': raw, 'runtime': runtime, 'native_artifacts': artifacts, 'optional_opcodes_used': sorted(used),
                             **({'selected_functions': len(selected_functions), 'selected_canonical_forms': len({oracle['functions'][i]['canonical_id'] for i in selected_functions}),
                                 'capability_declined_functions': len(oracle['functions']) - len(selected_functions)} if family in ATOMIC_FAMILIES else {})})
            faults.append(verify_faults(engine, cli, directory, compiler, target, target_id, family))
            if family in ATOMIC_FAMILIES:
                profiles[-1]['concurrency'] = verify_atomic_concurrency(engine, cli, directory, compiler, target, target_id, family)
            if family is atomic_pair_memory:
                profiles[-1]['normal_host_abi'] = verify_pair_normal_abi(engine, batches, oracle, target_id)
        calibration = calibrated_originals(engine) if family.FOCUS == FOCUS else {
            'actual_QEMU_original_fault_observations': 0,
            'limits': 'Structured-memory calibration is not atomic-memory evidence. Actual mapped-access Unicorn frames are separately retained in faults.' if family is atomic_memory else 'Structured-memory calibration is not ordinary-memory evidence. Actual ordinary mapped-access Unicorn frames are separately retained in faults.'}
        declines = verify_declined(engine, cli, Path(temporary), family) if family in (ordinary_memory, *ATOMIC_FAMILIES) else None
    if family is atomic_memory:
        model_identity = profiles[0]['concurrency']['ordering_model']
        if (any(profile['concurrency']['ordering_model'] != model_identity for profile in profiles)
                or engine.digest((ROOT / model_identity['path']).read_bytes()) != model_identity['sha256']):
            raise AssertionError('Reviewed atomic ordering model changed during verification')
    if smp is not None and load_atomic_smp_original(engine, smp_pointer, family) != smp:
        raise AssertionError('Original SMP evidence changed during verification')
    if engine.digest(cli.read_bytes()) != cli_sha or dependencies(engine, family) != sources:
        raise AssertionError('Structured memory executable or source changed during verification')
    report = {'kind': 'simd_' + focus + '_arm_vs_native_x86', 'passed': True, **family.inventory(),
        'direct_original_math_native_comparisons': sum(profile['raw_native']['direct_original_math_native_comparisons'] for profile in profiles),
        'requested_control_storage_native_policy_comparisons': sum(profile['raw_native']['requested_control_storage_native_policy_comparisons'] for profile in profiles),
        'runtime_complete_state_RAM_comparisons': sum(profile['runtime']['complete_state_RAM_comparisons'] for profile in profiles),
        'native_source_policy_fault_checks': sum(profile['native_source_policy_full_state_RAM_checks'] for profile in faults),
        'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_sha, 'shared_sources_sha256': sources,
        'harness_source_sha256': sources[str(Path(engine.__file__).relative_to(ROOT))],
        'original_receipt_sha256': oracle['receipt_sha256'], 'original_producer': oracle['producer'],
        'control_readbacks': oracle['control_readbacks'], 'profiles': profiles, 'faults': faults, 'calibrated_original_faults': calibration,
        **({'declined_encodings': declines} if declines is not None else {}),
        **({'original_smp': smp} if smp is not None else {}),
        'verification_wall_seconds': time.monotonic() - started,
        'limits': ('Limited ordering complete State/RAM, runtime/cache, faults and bounded native byte histories under FEAT_LOR with LORID/LORC0 and no matching regions, Normal-WB/LSE2/SCA16. No configured-region, original concurrent ordering, guest exception delivery or application claim.' if family is limited_ordered_memory else 'CASP complete individual State/RAM, runtime/cache, faults, normal-return host ABI and separate bounded native/two-PE original byte histories in EL0 Normal-WB/LSE2/SCA16. No host fault resumption, whole-program concurrent runtime, complete memory-model or performance claim.' if family is atomic_pair_memory else 'Unscaled acquire/release complete State/RAM, runtime/cache, faults and bounded native byte histories in EL0 Normal-WB/LSE2/SCA16/LRCPC2. No original concurrent ordering, model-completeness or guest exception delivery claim.' if family is ordered_unscaled_memory else 'Declared EL0 shared coherent Normal-WB/LSE2/SCA16 cohort; individual original semantics, native/source fault checks and bounded native/original concurrent outcomes remain separate evidence. No complete memory-model, production concurrent runtime, guest exception delivery, Apple hardware, application or performance claim.' if family is atomic_memory else 'Declared private little-endian RAM/nonstreaming AdvSIMD profile. Success primary originals and native/source-policy faults are separate evidence. No guest exception delivery, concurrency, Apple hardware, application or performance credit.')}
    path = write_evidence(ROOT / f'.stela/simd-{focus}-differential-report.json', report)
    return path, report


def atomic_original_observation(oracle, source, initial, ram_address, page_size, readonly, library_identity):
    """Actual mapped-access MAX CPU event, including unsupported exceptions."""
    from unicorn import arm64_const as arm
    import unicorn
    initialize, machines, controls = oracle.initialize_arm, [], {}
    def initialize_el0(machine, state):
        machine.reg_write(arm.UC_ARM64_REG_PSTATE, state.nzcv & 0xf0000000)
        machine.reg_write(arm.UC_ARM64_REG_CPACR_EL1, simd_original.FP_ACCESS_ENABLED)
        initialize(machine, state)
        registers = {'ISAR0': (3, 0, 0, 6, 0), 'ISAR1': (3, 0, 0, 6, 1),
                     'MMFR2': (3, 0, 0, 7, 2), 'SCTLR': (3, 0, 1, 0, 0),
                     'TCR': (3, 0, 2, 0, 2), 'MAIR': (3, 0, 10, 2, 0), 'TTBR0': (3, 0, 2, 0, 0)}
        controls.update({name: machine.cpr_read(*encoding) for name, encoding in registers.items()})
        controls.update(pstate=machine.reg_read(arm.UC_ARM64_REG_PSTATE),
                        cpacr_el1=machine.reg_read(arm.UC_ARM64_REG_CPACR_EL1))
        machines.append(machine)
    oracle.initialize_arm = initialize_el0
    try:
        state, ram, faults, event = oracle.arm_fault(source, initial, ram_address, page_size, readonly,
                                                    allow_completion=True, retain_error=True, cpu_model=arm.UC_CPU_ARM64_MAX)
    finally:
        oracle.initialize_arm = initialize
    controls['final_pstate'] = machines[0].reg_read(arm.UC_ARM64_REG_PSTATE)
    features = {'Atomic': controls['ISAR0'] >> 20 & 15, 'LRCPC': controls['ISAR1'] >> 20 & 15,
                'AT': controls['MMFR2'] >> 32 & 15, 'A': controls['SCTLR'] >> 1 & 1,
                'nAA': controls['SCTLR'] >> 6 & 1, 'SA0': controls['SCTLR'] >> 4 & 1,
                'EL': controls['pstate'] >> 2 & 3}
    return state, ram, faults, event, {'engine': 'Unicorn', 'version': unicorn.__version__,
        'cpu': 'MAX', 'installed_library': library_identity, 'decoded_features': features, **controls,
        'limits': 'Actual controls retained. AT=0 lacks FEAT_LSE2 and cannot establish the selected primary-QEMU LSE2/SCA16 unaligned profile. Mapped-access emulation is not page-table permission or hardware exception evidence.'}




def atomic_oracle_review(engine):
    review, identity = engine.numerical_json(ATOMIC_ORACLE_REVIEW)
    if (review.get('kind') != 'reviewed_unicorn_2_1_4_narrow_signed_atomic_minmax_limitation'
            or not review.get('passed') or review['classification']['operations'] != ['signed_min', 'signed_max']
            or review['classification']['widths'] != [1, 2, 4] or not review['required_control_readbacks']):
        raise AssertionError('Narrow source-reviewed atomic oracle diagnosis required')
    for item in [*review['source_files'], review['witness'], *review['witness_files']]:
        data = (ROOT / item['path']).read_bytes()
        if len(data) != item['bytes'] or engine.digest(data) != item['sha256']:
            raise AssertionError('Atomic oracle review artifact changed: ' + item['path'])
    return review, {'path': str(ATOMIC_ORACLE_REVIEW.relative_to(ROOT)), 'sha256': identity}


def atomic_narrow_signed_oracle_difference(op, case, initial, memory, ram_address, expected, expected_ram,
                                          original, original_ram, event, faults, controls, review):
    """The reviewed 2.1.4 zero-extension defect, with exact complete effects."""
    width = op['element_bytes']
    address = initial.sp if op['rn'] == 31 else initial.x[op['rn']]
    position = address - ram_address
    if (controls.get('engine') != 'Unicorn' or controls.get('version') != review['engine_version']
            or controls.get('cpu') != 'MAX'
            or controls.get('installed_library', {}).get('sha256') != review['installed_library']['sha256']
            or any(controls.get(name) != value for name, value in review['required_control_readbacks'].items())
            or controls.get('pstate') != initial.nzcv & 0xf0000000
            or controls.get('final_pstate') != controls.get('pstate')
            or not (case['protection'] == 'mapped' or case['protection'] == 'structure_crossing' and case['cut'] >= width)
            or width not in (1, 2, 4)
            or op['layout'] != 'rmw' or op['operation'] not in ('signed_min', 'signed_max')
            or not event['completed'] or event['error'] is not None or faults
            or address % width or not 0 <= position <= len(memory) - width
            or bytes(original) != bytes(expected) or original_ram == expected_ram):
        return False
    source_state, source_ram, source_fault = atomic_memory.expected(op, initial, memory, ram_address)
    alternative_op = {**op, 'operation': op['operation'].replace('signed_', 'unsigned_', 1)}
    alternative_state, alternative_ram, alternative_fault = atomic_memory.expected(alternative_op, initial, memory, ram_address)
    return (source_fault is None and alternative_fault is None and bytes(expected) == bytes(source_state)
            and expected_ram == source_ram and bytes(original) == bytes(alternative_state)
            and original_ram == alternative_ram)


def verify_atomic_faults(engine, cli, directory, compiler, target, target_id, family=atomic_memory):
    import importlib.util
    import unicorn
    oracle_review, review_identity = atomic_oracle_review(engine) if family is atomic_memory else (None, None)
    library_path = Path(importlib.import_module('unicorn.unicorn_py3.unicorn').uclib._name).resolve()
    library_data = library_path.read_bytes()
    library_identity = {'path': str(library_path.relative_to(ROOT)), 'sha256': engine.digest(library_data), 'bytes': len(library_data)}
    if oracle_review is not None and (unicorn.__version__ != oracle_review['engine_version']
            or library_identity['sha256'] != oracle_review['installed_library']['sha256']
            or library_identity['bytes'] != oracle_review['installed_library']['bytes']):
        raise AssertionError('Actual loaded Unicorn differs from reviewed atomic oracle')
    observer = directory / 'atomic-fault-observer'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread', '-DSTELA_ATOMIC_CONCURRENCY',
                    str(ROOT / 'dev/native-memory-faults.c'), '-o', str(observer)], check=True)
    observer_data = observer.read_bytes()
    observer_path = ROOT / '.stela/native-evidence/atomic-memory-observer' / engine.digest(observer_data) / 'observer.bin'
    observer_path.parent.mkdir(parents=True, exist_ok=True)
    simd_original.write_new(observer_path, observer_data)
    observer_identity = {'path': str(observer_path.relative_to(ROOT)), 'sha256': engine.digest(observer_data),
                         'source_sha256': engine.digest((ROOT / 'dev/native-memory-faults.c').read_bytes()),
                         'build_flags': ['-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-pthread', '-DSTELA_ATOMIC_CONCURRENCY']}
    spec = importlib.util.spec_from_file_location('atomic_original_faults', ROOT / 'dev/memory-faults.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    shapes, counts, records = family.shapes(), Counter(), []
    selected = [case for case in family.fault_selection(target != 'baseline' and family is atomic_memory)
                if family.supported_on_profile(family.fault_operation(shapes[case['function']], case), target if target == 'baseline' else target_id)]
    operations = {family.fault_operation(shapes[case['function']], case)['word']:
                  family.fault_operation(shapes[case['function']], case) for case in selected}
    compiled, words = {}, list(operations)
    for start in range(0, len(words), BATCH_FUNCTIONS):
        group = words[start:start + BATCH_FUNCTIONS]
        programs = [{'operations': [{'kind': 'prefix', 'word': move(2, 1, 7, 99)}, operations[word]]} for word in group]
        batch = engine.compile_batch(cli, directory, programs, 'atomic-fault-' + str(start), cpu_target=target,
            target_id=target_id, allowed_mnemonics={'mov', 'movz', *[operations[word]['name'] for word in group]},
            source_validator=family.validate_source_words)
        if batch['compiler'] != compiler: raise AssertionError('Atomic fault compiler changed')
        for local, word in enumerate(group):
            first = batch['offsets'][local]
            last = batch['offsets'][local + 1] if local + 1 < len(group) else len(batch['native'])
            entry = batch['entries'][local]
            source, native = batch['source'][entry * 4:(entry + 3) * 4], batch['native'][first:last]
            mapping = [[BASE + slot * 4, batch['instruction_offsets'][entry + slot] - first] for slot in range(3)]
            path = directory / f'atomic-fault-{word:08x}.bin'
            path.write_bytes(native)
            compiled[word] = source, native, mapping, path
    for index, case in enumerate(selected):
        op = family.fault_operation(shapes[case['function']], case)
        source, native, mapping, path = compiled[op['word']]
        initial = (family.fault_initial_state(op, case, index) if hasattr(family, 'fault_initial_state')
                   else family.initial_state(op, index, 512, operand=0, compare=0))
        initial.fpcr, initial.fpsr = 0x03c00000, 0x0800001f
        if family is atomic_memory and case.get('compare_matches') and op['rs'] != 31:
            initial.x[op['rs']] = int.from_bytes(b'\xa5' * op['element_bytes'], 'little')
        initial_path = directory / 'atomic-fault-state.bin'
        initial_path.write_bytes(bytes(initial))
        arguments = [str(observer), str(path), case['protection'], str(op['rn']), str(op.get('offset', 0) - case.get('address_offset', 0))]
        if case['protection'] == 'mapped': arguments.append(str(case['low_offset']))
        elif case['protection'] == 'structure_crossing': arguments.append(str(case['cut']))
        arguments += ['--initial-state', str(initial_path)]
        try:
            completed = subprocess.run(arguments, capture_output=True, timeout=10)
        except subprocess.TimeoutExpired as error:
            raw = retain_ordinary_fault_bytes(engine, source, native, error.stdout or b'',
                {**case, 'timeout': True, 'stderr_hex': (error.stderr or b'').hex()}, mapping, family.FOCUS)
            raise AssertionError('Atomic native fault observer timed out: ' + str(raw)) from error
        data = completed.stdout
        raw = retain_ordinary_fault_bytes(engine, source, native, data,
            {**case, 'returncode': completed.returncode, 'stderr_hex': completed.stderr.hex()}, mapping, family.FOCUS)
        if completed.returncode:
            raise AssertionError('Atomic native fault observer failed: ' + str(raw))
        (code_address, ram_address, page_size), initial, (number, pc, native_address), actual, ram = parse_fault_record(data)
        staged = State.from_buffer_copy(initial)
        staged.x[7] = 99
        expected, expected_ram, fault = family.expected(op, staged, b'\xa5' * page_size,
            ram_address, readonly=case['protection'] == 'readonly')
        policy_fault = fault and fault['kind'] in ('sp_alignment', 'sca_alignment')
        requested = (family.effective_address(op, initial) if hasattr(family, 'effective_address')
                     else initial.sp if op['rn'] == 31 else initial.x[op['rn']])
        snapshot_read = (family.snapshot_read(op, initial) if hasattr(family, 'snapshot_read') else
                         op['operation'] in ('ldar', 'ldapr') and op['element_bytes'] > 1 and op['rn'] != 31
                         and (requested & 7) + op['element_bytes'] > 8 and (requested & 15) + op['element_bytes'] <= 16)
        expected_native_address = requested & ~15 if snapshot_read else fault['address'] if fault else None
        offset = pc - code_address
        mapped = [guest for guest, native_offset in mapping if native_offset <= offset]
        boundary = (number == 0 if fault is None else
                    number == signal.SIGILL and native[offset:offset + 2] == b'\x0f\x0b' if policy_fault else
                    number in (signal.SIGSEGV, signal.SIGBUS) and native_address == expected_native_address)
        if (not boundary or fault is not None and (not mapped or mapped[-1] != BASE + 4)
                or bytes(actual) != bytes(expected) or ram != expected_ram):
            raise AssertionError('Atomic native/source boundary mismatch: ' + str(case) + ' raw=' + str(raw))
        original, original_ram, faults, event, controls = atomic_original_observation(
            oracle, source, initial, ram_address, page_size, case['protection'] == 'readonly', library_identity)
        raw_original = write_evidence(ROOT / f'.stela/{"atomic" if family is atomic_memory else family.FOCUS}-{target_id}-original-fault-{index}.json', {
            'case': case, 'operation': op, 'native_raw': raw, 'oracle_review': review_identity, 'initial_state_hex': bytes(initial).hex(),
            'original_state_hex': bytes(original).hex(), 'original_ram_hex': original_ram.hex(),
            'faults': faults, 'event': event, 'controls': controls})
        equal = bytes(original) == bytes(expected) and original_ram == expected_ram
        if policy_fault:
            classification = 'source_policy_only_' + fault['kind']
        elif event['error'] and not faults:
            classification = 'oracle_exception_limitation'
        elif fault and event['completed']:
            permitted_state, permitted_ram, permitted_fault = family.expected(
                op, staged, b'\xa5' * page_size, ram_address, readonly=False)
            if permitted_fault or bytes(original) != bytes(permitted_state) or original_ram != permitted_ram:
                raise AssertionError('Unexplained completed atomic original frame: ' + str(raw_original))
            classification = 'oracle_missing_atomic_write_permission_check'
        elif equal:
            classification = 'original_native_full_state_RAM_equal'
        elif oracle_review is not None and atomic_narrow_signed_oracle_difference(op, case, staged, b'\xa5' * page_size, ram_address,
                expected, expected_ram, original, original_ram, event, faults, controls, oracle_review):
            classification = oracle_review['classification']['name']
        else:
            raise AssertionError('Unexplained atomic original frame: ' + str(raw_original))
        counts[classification] += 1
        counts['native_source_policy_full_state_RAM_checks'] += 1
        counts['native_completed_checks' if fault is None else 'native_policy_fault_checks' if policy_fault else 'native_memory_fault_checks'] += 1
        records.append({'case': case, 'operation': op, 'classification': classification,
            **({'oracle_alternative': {'comparison': 'unsigned_element', 'complete_State_equal': True,
                'complete_RAM_equal': True, 'signed_source_RAM_equal': False}}
               if oracle_review is not None and classification == oracle_review['classification']['name'] else {}),
            'initial_state_hex': bytes(initial).hex(), 'native_state_hex': bytes(actual).hex(), 'native_ram_hex': ram.hex(),
            'native_signal': number, 'requested_guest_address': requested, 'actual_native_fault_address': native_address,
            'selected_snapshot_read': snapshot_read, 'native_fault_offset': offset if number else None,
            'source_fault': fault, 'oracle_review': review_identity, 'native_raw_record': raw, 'original_raw_record': {
                'path': str(raw_original.relative_to(ROOT)), 'sha256': engine.digest(raw_original.read_bytes())}})
    if engine.digest(library_path.read_bytes()) != library_identity['sha256']:
        raise AssertionError('Loaded atomic oracle library changed during observation')
    path = write_evidence(ROOT / f'.stela/simd-{family.FOCUS}-{target_id}-fault-records.json', records)
    return {**counts, 'target_cpu': target_id, 'native_observer': observer_identity,
            **({'oracle_review': {**review_identity, 'source_files': oracle_review['source_files'],
                'witness': oracle_review['witness'], 'witness_files': oracle_review['witness_files']}} if oracle_review is not None else {}),
            'actual_oracle_library': library_identity, 'actual_oracle_features': controls['decoded_features'],
            'records': {'path': str(path.relative_to(ROOT)), 'sha256': engine.digest(path.read_bytes())},
            'limits': ('Native/source full state/RAM equality. SP/SCA UD2 are policy checks. Supplementary Unicorn MAX has AT=0/no FEAT_LSE2, so it cannot establish selected primary-QEMU LSE2/SCA16 unaligned semantics. Exact reviewed signed narrow min/max differences and actual mapped-access exceptions/completions receive no equality credit; no guest ESR/FAR delivery claim.' if family is atomic_memory else family.FOCUS + ' native/source full State/RAM and policy checks; actual mapped-access Unicorn observations retained independently. AT0 lacks selected LSE2/SCA16 unaligned semantics. No scalar min/max classification or prior concurrency evidence applies; no guest ESR/FAR delivery claim.')}


def atomic_ordering_model(engine):
    path = ROOT / '.stela/research/atomic-implementation/contracts/ordering-model-2.json'
    model, identity = engine.numerical_json(path)
    if model.get('kind') != 'arm_atomic_ordering_allowed_outcomes' or not model.get('source_receipts'):
        raise AssertionError('Root-reviewed authoritative atomic ordering model required')
    for item in model['source_receipts']:
        data = (ROOT / item['path']).read_bytes()
        if engine.digest(data) != item['sha256']:
            raise AssertionError('Atomic ordering model source changed')
    return model, {'path': str(path.relative_to(ROOT)), 'sha256': identity}



def validate_atomic_smp_trial(case, final_states, ram, model, family=atomic_memory):
    """Check every State/RAM byte against the reviewed outcomes or two orders."""
    if len(final_states) != 2 or any(len(state) != 784 for state in final_states) or len(ram) != 8192:
        raise AssertionError('Original SMP model input framing differs')
    if family is atomic_pair_memory:
        if any(len(program) != 1 for program in case['programs']):
            raise AssertionError('Original CASP requires one whole operation per PE')
        for order in ((0, 1), (1, 0)):
            memory, finals = case['memory'], list(case['initial'])
            for thread in order:
                state, memory, fault = family.history_expected(case['programs'][thread][0], State.from_buffer_copy(case['initial'][thread]), memory, family.RAM_ADDRESS)
                if fault: raise AssertionError('Original CASP success history model faulted')
                finals[thread] = bytes(state)
            if finals == final_states and memory == ram: return list(order)
        raise AssertionError('Original CASP full States/RAM have no exact source serialization')
    if case['kind'] == 4:
        relative = next(item for item in atomic_memory.concurrency_cases() if item['id'] == case['id'])
        atomic_memory.validate_litmus_case(relative, model)
        expected_inputs = [bytes(atomic_memory.relocate_state(raw, atomic_memory.RAM_ADDRESS)) for raw in relative['initial']]
        if case['programs'] != relative['programs'] or case['memory'] != relative['memory'] or case['initial'] != expected_inputs:
            raise AssertionError('Original SMP litmus source/model differs')
        pair = [State.from_buffer_copy(state) for state in final_states]
        outcome = (pair[1].x[1], pair[1].x[2]) if case['id'].startswith('publication_') else (pair[0].x[1], pair[1].x[1])
        if list(outcome) not in model['allowed_outcomes'][case['allowed_outcomes']]:
            raise AssertionError('Original SMP outcome outside reviewed Arm model')
        for initial, final, program in zip(case['initial'], final_states, case['programs']):
            if not atomic_memory.validate_preserved_program_state(program, initial, State.from_buffer_copy(final)):
                raise AssertionError('Original SMP litmus changed preserved State bytes')
        expected_ram = bytearray(case['memory'])
        expected_ram[:8] = expected_ram[64:72] = (1).to_bytes(8, 'little')
        if ram != bytes(expected_ram):
            raise AssertionError('Original SMP litmus changed unrelated RAM')
        return list(outcome)
    if case['id'] != 'cross8_ldar_swap_8_offset1' or any(len(program) != 1 for program in case['programs']):
        raise AssertionError('Unreviewed original SMP serialization case')
    for order in ((0, 1), (1, 0)):
        memory, finals = case['memory'], list(case['initial'])
        for thread in order:
            state, memory, fault = atomic_memory.expected(case['programs'][thread][0],
                State.from_buffer_copy(case['initial'][thread]), memory, atomic_memory.RAM_ADDRESS)
            if fault:
                raise AssertionError('Original SMP success model faulted')
            finals[thread] = bytes(state)
        if finals == final_states and memory == ram:
            return list(order)
    raise AssertionError('Original SMP cross8 full States/RAM have no exact serialization')


def load_atomic_smp_original(engine, pointer, family=atomic_memory):
    """Consume immutable two-PE transport; independently judge source outcomes."""
    import simd_atomic_original as smp
    pointer_data, pointer_sha = engine.numerical_json(pointer)
    receipt_path = ROOT / pointer_data['receipt']['path']
    producer, receipt_sha = engine.numerical_json(receipt_path, pointer_data['receipt']['sha256'])
    directory = ROOT / producer['directory']
    focus = smp.PAIR_FOCUS if family is atomic_pair_memory else smp.FOCUS
    pairs = smp.pair_default_pairs() if family is atomic_pair_memory else smp.default_pairs()
    expected_files, plan, _ = smp.input_files(pairs, focus=focus)
    model, model_identity = atomic_ordering_model(engine) if family is atomic_memory else (None, None)
    if (pointer_data.get('kind') != focus + '_original_oracle_capture_pointer'
            or producer.get('kind') != ('atomic_pair_original_two_pe_full_frame_qemu' if family is atomic_pair_memory else 'atomic_ordered_original_two_pe_full_frame_qemu')
            or producer.get('focus') != focus or not producer.get('passed_transport_and_architectural_frame_checks')
            or pointer_data['directory'] != producer['directory'] or receipt_path.parent != directory
            or pointer_data['files'] != producer['files'] or receipt_path.stat().st_size != pointer_data['receipt']['bytes']
            or producer['pairs'] != 8 or producer['trials'] != 2048 or producer['pes'] != 2
            or producer['input_stride'] != 1600 or producer['results_stride'] != 10240
            or producer['results_header_bytes'] != 1024 or producer['pe_header_bytes'] != 512):
        raise AssertionError('Passing exact default two-PE original capture required')
    required = {*expected_files, 'results.bin', 'observations.json', 'subjects.json', 'bindings.json',
                'guest.S', 'guest.elf', 'original_smp.py', 'prepared-artifacts.json'}
    if not required <= producer['files'].keys():
        raise AssertionError('Original SMP evidence omits source/inputs/raw output')
    for name, identity in producer['files'].items():
        if Path(name).name != name:
            raise AssertionError('Original SMP evidence path escapes capture')
        data = (directory / name).read_bytes()
        if len(data) != identity['bytes'] or engine.digest(data) != identity['sha256']:
            raise AssertionError('Original SMP capture changed: ' + name)
    for name, data in expected_files.items():
        if (directory / name).read_bytes() != data:
            raise AssertionError('Original SMP frozen default input differs: ' + name)
    if ((directory / 'original_smp.py').read_bytes() != Path(smp.__file__).read_bytes()
            or producer['producer_sha256'] != engine.digest(Path(smp.__file__).read_bytes())
            or producer['shared_original_producer_sha256'] != engine.digest(Path(simd_original.__file__).read_bytes())):
        raise AssertionError('Original SMP producer source changed')
    for name, identity in {**producer['source_receipts'], **producer['observer_dependencies']}.items():
        if engine.digest((ROOT / name).read_bytes()) != identity:
            raise AssertionError('Original SMP bound source changed: ' + name)
    bindings = json.loads((directory / 'bindings.json').read_bytes())
    if any(producer.get(key) != value for key, value in bindings.items() if key != 'limits') or (directory / 'guest.S').read_bytes() != smp.assembly(plan).encode():
        raise AssertionError('Original SMP observer assembly/bindings differ')
    subjects = smp.linked_subjects(directory / 'guest.elf', plan)
    if subjects != json.loads((directory / 'subjects.json').read_bytes()):
        raise AssertionError('Original SMP linked subject identity changed')
    observations = smp.validate_results(directory, plan, subjects)
    if observations != json.loads((directory / 'observations.json').read_bytes()):
        raise AssertionError('Original SMP retained frame observations differ')
    results, histograms = (directory / 'results.bin').read_bytes(), {}
    cases = {case['id']: case for case in pairs}
    for row in observations['records']:
        case = cases[row['pair']]
        begin = 1024 + row['record_index'] * 10240
        ram = results[begin + 2048:begin + 10240]
        outcome = validate_atomic_smp_trial(case, [bytes.fromhex(state) for state in row['final_state_hex']], ram, model, family)
        histograms.setdefault(case['id'], Counter())[tuple(outcome)] += 1
    return {'pointer': {'path': str(Path(pointer).relative_to(ROOT)), 'sha256': pointer_sha},
        'receipt': {'path': str(receipt_path.relative_to(ROOT)), 'sha256': receipt_sha},
        'producer': producer, 'ordering_model': model_identity,
        'complete_state_checks': 4096, 'complete_RAM_checks': 2048,
        **({'exact_pair_serialization_trials': 2048} if family is atomic_pair_memory else
           {'ordering_trials': 1792, 'cross8_exact_serialization_trials': 256}),
        'outcomes': {key: [{'values': list(values), 'count': count} for values, count in sorted(hist.items())]
                     for key, hist in histograms.items()},
        'limits': ('Actual two-PE EL0 Normal-MMU CASP/scalar originals; exact complete-State/byte serializations for8 reviewed overlapping atomic pairs. Finite observations do not prove complete memory-model behavior or hardware performance.' if family is atomic_pair_memory else 'Actual two-PE EL0 Normal-MMU QEMU originals. Seven restricted source-model memberships and one exact byte-history case; finite outcomes/frequencies are not complete memory-model proof or hardware performance.')}


def verify_atomic_concurrency(engine, cli, directory, compiler, target, target_id, family=atomic_memory):
    cases = [case for case in family.concurrency_cases()
             if all(family.supported_on_profile(op, target if target == 'baseline' else target_id) for program in case['programs']
                    for op in program if op['kind'] == family.FOCUS)]
    model, model_identity = atomic_ordering_model(engine) if family is atomic_memory else (None, None)
    allowed = model['allowed_outcomes'] if model is not None else {}
    observer = directory / 'atomic-fault-observer'
    counts, transcripts = Counter(), []
    for index, case in enumerate(cases):
        if model is not None: atomic_memory.validate_litmus_case(case, model)
        programs = [{'operations': program} for program in case['programs']]
        batch = engine.compile_batch(cli, directory, programs, 'atomic-concurrent-' + str(index),
            cpu_target=target, target_id=target_id, allowed_mnemonics={op['name'] for program in case['programs'] for op in program},
            source_validator=family.validate_source_words)
        if batch['compiler'] != compiler: raise AssertionError('Atomic concurrency compiler changed')
        accounting = native_binary_accounting(engine, batch)
        batch['cohort'] = family.FOCUS + '-concurrency'
        artifact = engine.retain_native_binary_evidence(batch, accounting, [])
        native_path, plan_path = directory / 'atomic-concurrent.bin', directory / 'atomic-concurrent-plan.bin'
        native_path.write_bytes(batch['native'])
        plan = family.concurrency_plan(case, batch['offsets'])
        plan_path.write_bytes(plan)
        try:
            completed = subprocess.run([str(observer), '--atomic-concurrency', str(native_path), str(plan_path)],
                                       capture_output=True, timeout=60)
        except subprocess.TimeoutExpired as error:
            raw = retain_ordinary_fault_bytes(engine, batch['source'], batch['native'], error.stdout or b'',
                {'id': case['id'], 'plan_hex': plan.hex(), 'timeout': True, 'stderr_hex': (error.stderr or b'').hex()},
                batch['manifest']['source_map'], family.FOCUS + '-concurrency')
            raise AssertionError('Bounded atomic worker timed out: ' + str(raw)) from error
        raw = retain_ordinary_fault_bytes(engine, batch['source'], batch['native'], completed.stdout,
            {'id': case['id'], 'plan_hex': plan.hex(), 'returncode': completed.returncode,
             'stderr_hex': completed.stderr.hex()}, batch['manifest']['source_map'], family.FOCUS + '-concurrency')
        if completed.returncode: raise AssertionError('Atomic concurrent worker failed: ' + str(raw))
        data = completed.stdout
        if len(data) < 72: raise AssertionError('Truncated concurrent header: ' + str(raw))
        magic, code, ram_address, alias_address, threads, iterations, count, snapshots, failed = struct.unpack_from('<9Q', data)
        if (magic != 0x31544c53524d5441 or threads != case['threads'] or iterations != case['iterations'] or failed
                or len(data) != 72 + count * 1600 + threads * 784 + snapshots * 8192):
            raise AssertionError('Concurrent transport framing differs: ' + str(raw))
        if case['kind'] != 4 and snapshots != 1:
            raise AssertionError('Concurrent history must retain exactly one final RAM snapshot')
        if case['kind'] != 2 and count != threads * iterations:
            raise AssertionError('Concurrent worker omitted an actual operation')
        rows, seen_iterations = [], [set() for _ in range(threads)]
        staged_inputs = [atomic_memory.relocate_state(case['initial'][thread], alias_address if case['alias'] and thread & 1 else ram_address) for thread in range(threads)]
        for slot in range(count):
            offset = 72 + slot * 1600
            thread, iteration, begin, end = struct.unpack_from('<4Q', data, offset)
            initial = State.from_buffer_copy(data[offset + 32:offset + 816])
            final = State.from_buffer_copy(data[offset + 816:offset + 1600])
            if not 0 <= thread < threads or not 0 <= iteration < iterations or begin >= end:
                raise AssertionError('Concurrent record index differs')
            seen_iterations[thread].add(iteration)
            if case['kind'] == 4:
                staged_inputs[thread] = atomic_memory.relocate_state(case['initial'][thread], ram_address)
            elif case['kind'] == 2:
                staged_inputs[thread].x[1] = (staged_inputs[thread].x[0] + 1) & ((1 << (8 * case['width'])) - 1)
            if bytes(initial) != bytes(staged_inputs[thread]):
                raise AssertionError('Concurrent input state/reset/continuity differs from fixed plan')
            program = case['programs'][thread]
            if not atomic_memory.validate_preserved_program_state(program, initial, final):
                raise AssertionError('Concurrent program changed unrelated full state: ' + str(raw))
            staged_inputs[thread] = State.from_buffer_copy(final)
            if case['kind'] == 3 or case['kind'] == 2 and final.x[0] == initial.x[0]:
                staged_inputs[thread].x[0] = final.x[1]
            address = alias_address if case['alias'] and thread & 1 else ram_address
            rows.append({'thread': thread, 'iteration': iteration, 'begin': begin, 'end': end,
                'initial_state_hex': bytes(initial).hex(), 'final_state_hex': bytes(final).hex(),
                'operation': program[0], 'ram_address': address})
        if any(values != set(range(iterations)) for values in seen_iterations):
            raise AssertionError('Concurrent iteration coverage differs from fixed plan')
        final_offset = 72 + count * 1600
        finals = [State.from_buffer_copy(data[final_offset + thread * 784:final_offset + (thread + 1) * 784]) for thread in range(threads)]
        if any(bytes(final) != bytes(expected) for final, expected in zip(finals, staged_inputs)):
            raise AssertionError('Concurrent final per-thread State differs from actual call history')
        ram_snapshots = data[final_offset + threads * 784:]
        final_ram = ram_snapshots[-8192:]
        if case['kind'] == 0:
            if not family.linearization_allowed(rows, case['memory'], ram_address, final_ram):
                raise AssertionError('Concurrent RMW history has no source linearization: ' + str(raw))
            counts['linearized_histories'] += 1
        elif case['kind'] in (1, 2, 3):
            old_values, successes = [], []
            width = case['width']
            for row in rows:
                initial, final = [State.from_buffer_copy(bytes.fromhex(row[key])) for key in ('initial_state_hex', 'final_state_hex')]
                op = row['operation']
                result_register = op['rs'] if op['layout'] == 'cas' else op['rt']
                old = final.x[result_register]
                if old >= 1 << (width * 8): raise AssertionError('Narrow concurrent result did not zero extend')
                witness = bytearray(case['memory'])
                witness[:width] = old.to_bytes(width, 'little')
                expected, _, fault = atomic_memory.expected(op, initial, witness, row['ram_address'])
                if fault or bytes(expected) != bytes(final): raise AssertionError('Concurrent complete-state operation mismatch')
                old_values.append(old)
                if op['layout'] == 'cas' and initial.x[op['rs']] == old: successes.append((old, row))
            value = int.from_bytes(final_ram[:width], 'little')
            if case['kind'] == 1:
                if sorted(old_values) != list(range(threads * iterations)) or value != threads * iterations:
                    raise AssertionError('Fetch-add tickets/final total differ')
                counts['unique_tickets'] += len(rows)
            elif case['kind'] == 2:
                if sorted(old for old, _ in successes) != list(range(threads * iterations)) or value != threads * iterations:
                    raise AssertionError('Contended CAS increment total/returns differ')
                events = [{'begin': row['begin'], 'end': row['end'], 'old': old,
                           'success': State.from_buffer_copy(bytes.fromhex(row['initial_state_hex'])).x[0] == old}
                          for row, old in zip(rows, old_values)]
                if not atomic_memory.cas_counter_history_allowed(events, threads * iterations):
                    raise AssertionError('CAS counter history violates exact source transition/real-time order')
                counts['cas_successes'] += len(successes)
                counts['cas_failures'] += len(rows) - len(successes)
            else:
                tokens = [value, *[state.x[0] for state in finals]]
                if sorted(tokens) != list(range(threads + 1)): raise AssertionError('SWP token conservation failed')
                counts['swap_transfers'] += len(rows)
            if final_ram[width:] != case['memory'][width:]: raise AssertionError('Concurrent atomic modified unrelated RAM')
        else:
            if snapshots != iterations: raise AssertionError('Litmus RAM snapshot count differs')
            outcomes = Counter()
            for iteration in range(iterations):
                pair = [State.from_buffer_copy(bytes.fromhex(next(row for row in rows if row['thread'] == thread and row['iteration'] == iteration)['final_state_hex'])) for thread in range(threads)]
                outcome = (pair[1].x[1], pair[1].x[2]) if case['id'].startswith('publication_') else (pair[0].x[1], pair[1].x[1])
                if list(outcome) not in allowed[case['allowed_outcomes']]:
                    raise AssertionError('Native litmus outcome outside reviewed Arm model: ' + str(raw))
                expected_ram = bytearray(case['memory'])
                expected_ram[:8], expected_ram[64:72] = (1).to_bytes(8, 'little'), (1).to_bytes(8, 'little')
                if ram_snapshots[iteration * 8192:(iteration + 1) * 8192] != bytes(expected_ram):
                    raise AssertionError('Litmus complete RAM changed beyond declared stores')
                outcomes[outcome] += 1
            counts['ordering_trials'] += iterations
        counts['complete_operation_state_checks'] += len(rows)
        transcripts.append({'id': case['id'], 'threads': threads, 'iterations': iterations, 'alias': case['alias'],
            'records': rows, 'raw_record': raw, 'native_artifact': artifact,
            **({'outcomes': [{'values': list(values), 'count': amount} for values, amount in sorted(outcomes.items())]} if case['kind'] == 4 else {})})
    path = write_evidence(ROOT / f'.stela/simd-{family.FOCUS}-{target_id}-concurrency-records.json', transcripts)
    return {**counts, 'cases': len(cases), 'target_cpu': target_id, 'ordering_model': model_identity,
        'records': {'path': str(path.relative_to(ROOT)), 'sha256': engine.digest(path.read_bytes())},
        'limits': 'Actual translated bodies on separate pthread States and one shared backing, including virtual aliases. Bounded histories/outcome membership only; finite absence and outcome frequencies are not memory-model completeness or application performance.'}
