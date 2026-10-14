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
from simd_fixtures import structure_memory as family
import simd_original

BATCH_FUNCTIONS = 256
FOCUS = family.FOCUS
ORACLE_DIRECTORY = ROOT / '.stela/research/structured-memory-implementation/fixtures/oracle'


def dependencies(engine):
    paths = [Path(engine.__file__), Path(__file__), Path(family.__file__), Path(simd_original.__file__),
             ROOT / 'dev/differential.py', ROOT / 'dev/evidence.py', ROOT / 'dev/native-memory-faults.c',
             ROOT / 'dev/test_simd_fixtures.py']
    return {str(path.relative_to(ROOT)): engine.digest(path.read_bytes()) for path in paths}


def prepare_original(engine, directory):
    directory = Path(directory)
    operations, cases = family.corpus()
    plan = engine.prepare_full_frame_numerical_oracle(directory, operations, cases, FOCUS)
    memory = family.memory_template()
    memory_plan = {'ram_address': family.RAM_ADDRESS, 'ram_bytes': len(memory), 'initial_ram_sha256': engine.digest(memory)}
    simd_original.write_new(directory / 'memory.bin', memory)
    simd_original.write_new(directory / 'memory-plan.json', simd_original.json_bytes(memory_plan))
    sources = dependencies(engine)
    simd_original.write_new(directory / 'source-bindings.json', simd_original.json_bytes(sources))
    return {**plan, **family.inventory(), 'memory_plan': memory_plan,
            'capture_command': [sys.executable, str(Path(simd_original.__file__)), '--directory', str(directory),
                                '--focus', FOCUS, '--source-bindings', str(directory / 'source-bindings.json'), '--capture']}


def load_original(engine, pointer):
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
def fixed_private_ram():
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
    oracle = load_original(engine, batches[0]['oracle_path'])
    counts = Counter()
    with ExitStack() as mappings:
        functions = {}
        for batch in batches:
            pointer = mappings.enter_context(engine.executable(batch['native']))
            for local, offset in enumerate(batch['offsets']):
                functions[batch['function_base'] + local] = pointer + offset
        ram_pointer = mappings.enter_context(fixed_private_ram())
        wrapper_pointer = mappings.enter_context(engine.executable(engine.NUMERICAL_MXCSR_WRAPPER))
        wrapper = ctypes.CFUNCTYPE(None, ctypes.POINTER(State), ctypes.c_void_p, ctypes.c_uint32,
                                  ctypes.POINTER(engine.NumericalNativeExit))(wrapper_pointer)
        memory = family.memory_template()
        for record in oracle['records']:
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
    return {'complete_native_state_RAM_comparisons': len(oracle['records']), 'guest_state_bytes': 784,
            'ram_bytes_per_comparison': family.RAM_BYTES, 'direct_original_math_native_comparisons': counts['direct_original'],
            'requested_control_storage_native_policy_comparisons': counts['requested_control_storage_policy'],
            'same_granule_comparisons': counts['same_granule'], 'crossing_comparisons': counts['crossing'],
            'caller_mxcsr_preservation_comparisons': len(oracle['records'])}


def runtime_checks(engine, cli, directory, compiler, target, target_id, oracle):
    """All150 canonical forms through actual owned-memory dispatcher/cache."""
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
    snapshot = write_evidence(ROOT / f'.stela/simd-{FOCUS}-{target_id}-runtime-records.json', transcripts)
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


def native_fault_selection(first_access_only=False):
    """Bounded semantic cuts; success separately covers all1134 shapes."""
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


def fault_operation(shape, rn):
    values = {key: shape[key] for key in ('layout', 'loading', 'structures', 'runs',
              'vector_bytes', 'element_bytes', 'index', 'mode', 'rt', 'rm')}
    return family.operation(**values, rn=rn)


def verify_faults(engine, cli, directory, compiler, target, target_id):
    observer = directory / 'structure-fault-observer'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(ROOT / 'dev/native-memory-faults.c'), '-o', str(observer)], check=True)
    records, counts = [], Counter()
    shapes = family.shapes()
    selections = native_fault_selection(first_access_only=target != 'baseline')
    unique = list(dict.fromkeys((case['function'], case['rn']) for case in selections))
    compiled = {}
    for start in range(0, len(unique), BATCH_FUNCTIONS):
        indexes = unique[start:start + BATCH_FUNCTIONS]
        operations = [fault_operation(shapes[function], rn) for function, rn in indexes]
        programs = [{'operations': [{'kind': 'prefix', 'word': move(2, 1, 7, 99)}, op]} for op in operations]
        batch = engine.compile_batch(cli, directory, programs, 'fault-batch-' + str(start),
            cpu_target=target, target_id=target_id, allowed_mnemonics={'mov', 'movz', *[op['name'] for op in operations]})
        if batch['compiler'] != compiler:
            raise AssertionError('Structured fault compiler changed')
        for local, key in enumerate(indexes):
            first = batch['offsets'][local]
            last = batch['offsets'][local + 1] if local + 1 < len(indexes) else len(batch['native'])
            native = batch['native'][first:last]
            entry = batch['entries'][local]
            source = batch['source'][entry * 4:(entry + 3) * 4]
            mapping = [[BASE + slot * 4, batch['instruction_offsets'][entry + slot] - first] for slot in range(3)]
            path = directory / f'fault-function-{key[0]}-rn{key[1]}.bin'
            path.write_bytes(native)
            compiled[key] = source, native, mapping, path
    for index, case in enumerate(selections):
        op = fault_operation(shapes[case['function']], case['rn'])
        source, native, mapping, native_path = compiled[case['function'], case['rn']]
        arguments = [str(observer), str(native_path), case['protection'], str(op['rn']), '0']
        if case['protection'] == 'structure_crossing':
            arguments.append(str(case['cut']))
        data = subprocess.check_output(arguments, timeout=10)
        (code_address, ram_address, page_size), initial, (number, pc, address), actual, ram = parse_fault_record(data)
        staged = State.from_buffer_copy(initial)
        staged.x[7] = 99
        expected, expected_ram, fault = family.expected(op, staged, b'\xa5' * page_size, ram_address)
        if case['protection'] == 'readonly':
            expected, expected_ram, fault = family.expected(op, staged, b'\xa5' * page_size, ram_address, readonly=True)
        mapped = [guest for guest, offset in mapping if offset <= pc - code_address]
        sp_fault = case['protection'] in ('sp_alignment', 'sp_alignment8')
        fault_offset = pc - code_address
        boundary_valid = (number == signal.SIGILL and native[fault_offset:fault_offset + 2] == b'\x0f\x0b'
                          and fault is not None and fault['kind'] == 'sp_alignment') if sp_fault else (
                          number in (signal.SIGSEGV, signal.SIGBUS) and fault is not None
                          and fault['kind'] == 'memory' and address == fault['address'])
        if (not boundary_valid or not mapped or mapped[-1] != BASE + 4
                or bytes(actual) != bytes(expected) or ram != expected_ram):
            raise AssertionError(json.dumps({'case': case, 'op': op, 'signal': number, 'native_address': address, 'fault': fault,
                'native': state_dict(actual), 'expected': state_dict(expected), 'RAM_equal': ram == expected_ram}))
        qemu, qemu_ram, _ = family.expected(op, staged, b'\xa5' * page_size, ram_address,
            readonly=case['protection'] == 'readonly', policy='qemu')
        counts['native_source_policy_full_state_RAM_checks'] += 1
        counts['native_sp_alignment_policy_fault_checks' if sp_fault else 'native_memory_address_fault_checks'] += 1
        counts['predicted_qemu_difference_cases'] += int(bytes(qemu) != bytes(expected) or qemu_ram != expected_ram)
        records.append({**case, 'target_cpu': target_id, 'canonical_id': op['canonical_id'], 'source_sha256': engine.digest(source),
            'native_sha256': engine.digest(native), 'native_signal': number, 'native_fault_offset': pc - code_address,
            'fault_classification': 'enabled_sp_alignment_policy' if sp_fault else 'memory_address',
            'initial_state_hex': bytes(initial).hex(), 'native_state_hex': bytes(actual).hex(),
            'native_ram_hex': ram.hex(), 'qemu_prediction_state_hex': bytes(qemu).hex(),
            'qemu_prediction_ram_sha256': engine.digest(qemu_ram), 'original_observation': False})
    snapshot = write_evidence(ROOT / f'.stela/simd-{FOCUS}-{target_id}-fault-records.json', records)
    return {**counts, 'target_cpu': target_id, 'selection': 'all_bounded_cuts' if target == 'baseline' else 'first_access_and_sp_policy',
            'records': {'path': str(snapshot.relative_to(ROOT)), 'sha256': engine.digest(snapshot.read_bytes())},
            'limits': 'Full native/source-policy equality. SP alignment uses the enabled pre-access UD2 policy, with no memory-address or guest-exception claim. QEMU columns are predictions only; immutable calibrated original observations are separately retained and classified.'}


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
                           'layout': op['layout'], 'element_bytes': op['element_bytes'], 'vector_bytes': op['vector_bytes'],
                           'runs': op['runs'], 'structures': op['structures'], 'index': op['index']})
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


def run(engine, cli, pointer=None):
    pointer = Path(pointer) if pointer else ORACLE_DIRECTORY / 'receipt.json'
    oracle = load_original(engine, pointer)
    sources, cli_sha, started = dependencies(engine), engine.digest(cli.read_bytes()), time.monotonic()
    cpu = json.loads(subprocess.check_output([str(cli), 'cpu-info']))
    selections = [('baseline', 'x86_64-baseline')]
    if cpu['detected_target'] != 'x86_64-baseline':
        selections.append(('native', cpu['detected_target']))
    profiles, faults, compiler = [], [], None
    with tempfile.TemporaryDirectory(prefix='stela-structure-memory-') as temporary:
        for target, target_id in selections:
            directory = Path(temporary) / target_id
            directory.mkdir()
            batches, artifacts = [], []
            for start in range(0, len(oracle['functions']), BATCH_FUNCTIONS):
                operations = oracle['functions'][start:start + BATCH_FUNCTIONS]
                batch = engine.compile_batch(cli, directory, [{'operations': [op]} for op in operations], start,
                    cpu_target=target, target_id=target_id, guest_base=BASE + start * 8,
                    allowed_mnemonics={op['name'] for op in operations})
                batch.update(cohort=FOCUS, function_base=start, oracle_path=str(pointer))
                if compiler is not None and compiler != batch['compiler']:
                    raise AssertionError('Structured memory compiler changed')
                compiler = batch['compiler']
                accounting = native_binary_accounting(engine, batch)
                artifacts.append({'function_base': start, 'accounting': accounting,
                                  'files': engine.retain_native_binary_evidence(batch, accounting, [])})
                batches.append(batch)
            optional = {row['mnemonic'] for row in cpu['simd_opcodes'] if row['minimum_target'] != 'x86_64-baseline'}
            used = optional & {name for artifact in artifacts for name in artifact['accounting']['opcode_counts']}
            if target == 'baseline' and used:
                raise AssertionError('Baseline memory body emitted optional opcodes: ' + str(sorted(used)))
            raw = engine.bounded_cases(batches)
            runtime = runtime_checks(engine, cli, directory, compiler, target, target_id, oracle)
            profiles.append({'target_cpu': target_id, 'raw_native': raw, 'runtime': runtime, 'native_artifacts': artifacts, 'optional_opcodes_used': sorted(used)})
            faults.append(verify_faults(engine, cli, directory, compiler, target, target_id))
        calibration = calibrated_originals(engine)
    if engine.digest(cli.read_bytes()) != cli_sha or dependencies(engine) != sources:
        raise AssertionError('Structured memory executable or source changed during verification')
    report = {'kind': 'simd_structure_memory_arm_vs_native_x86', 'passed': True, **family.inventory(),
        'direct_original_math_native_comparisons': sum(profile['raw_native']['direct_original_math_native_comparisons'] for profile in profiles),
        'requested_control_storage_native_policy_comparisons': sum(profile['raw_native']['requested_control_storage_native_policy_comparisons'] for profile in profiles),
        'runtime_complete_state_RAM_comparisons': sum(profile['runtime']['complete_state_RAM_comparisons'] for profile in profiles),
        'native_source_policy_fault_checks': sum(profile['native_source_policy_full_state_RAM_checks'] for profile in faults),
        'compiler_source_sha256': compiler, 'compiler_executable_sha256': cli_sha, 'shared_sources_sha256': sources,
        'harness_source_sha256': sources[str(Path(engine.__file__).relative_to(ROOT))],
        'original_receipt_sha256': oracle['receipt_sha256'], 'original_producer': oracle['producer'],
        'control_readbacks': oracle['control_readbacks'], 'profiles': profiles, 'faults': faults, 'calibrated_original_faults': calibration,
        'verification_wall_seconds': time.monotonic() - started,
        'limits': 'Declared private little-endian RAM/nonstreaming AdvSIMD profile. Success primary originals and native/source-policy faults are separate evidence. No guest exception delivery, concurrency, Apple hardware, application or performance credit.'}
    path = write_evidence(ROOT / f'.stela/simd-{FOCUS}-differential-report.json', report)
    return path, report
