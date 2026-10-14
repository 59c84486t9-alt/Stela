"""Shared full-state adapter for pure integer and crypto SIMD fixtures.

The CLI supplies its existing compiler, original snapshot reader, artifact/map
checks and MXCSR wrapper explicitly. Family modules own only words, inputs and
independent integer models. Historical cohort engines remain unchanged.
"""
from collections import Counter
from contextlib import ExitStack
import ctypes
import importlib
import hashlib
import json
from pathlib import Path
import struct
import sys
import subprocess
import tempfile
import time

from differential import ROOT, BASE, State, state_dict
from evidence import write_evidence
from simd_fixtures import FAMILIES
import simd_original

BATCH_FUNCTIONS = 512
MAXIMUM_RUNTIME_CASES = 96
CACHE_LOOP_ITERATIONS = 3
BRANCH_NEXT_INSTRUCTION = 0x14000001
MAXIMUM_MIXED_OPERATIONS = 8
ORIGINAL_INPUT_HEADER = 8
ORIGINAL_INPUT_STRIDE = 800
ORIGINAL_RECORD_BYTES = 1024
ORIGINAL_STATE_BYTES = 784
RETURN_REGISTER = 30
UNDEFINED_INSTRUCTION_ESR = 0x02000000
VECTOR_REGISTER_BITS = 5
VECTOR_LEFT_SHIFT = 5
VECTOR_LEFT_MASK = ((1 << VECTOR_REGISTER_BITS) - 1) << VECTOR_LEFT_SHIFT


def family_module(focus):
    if focus not in FAMILIES:
        raise ValueError('Unknown SIMD fixture family')
    return importlib.import_module('simd_fixtures.' + focus)


def fixture_corpus(family):
    operations, cases = family.corpus()
    if operations != family.functions() or not operations or not cases:
        raise AssertionError('Fixture functions/corpus disagree or are empty')
    if len({op['word'] for op in operations}) != len(operations):
        raise AssertionError('Each original word needs one fixture function')
    if {op['canonical_id'] for op in operations} != set(family.CANONICAL_FORMS):
        raise AssertionError('Fixture canonical form inventory differs')
    operations = [dict(op) if op.get('output_kind') == 'gpr' else dict(op, merge=op.get('merge', 'none'))
                  for op in operations]
    records = []
    for index, case in enumerate(cases):
        initial = case['initial']
        if len(initial) != ORIGINAL_STATE_BYTES or not 0 <= case['function'] < len(operations):
            raise AssertionError('Fixture input/state framing differs')
        records.append({**case, 'case': index, 'function_index': case['function']})
    runtime = [case for case in records if case.get('runtime')]
    if not 0 < len(runtime) <= MAXIMUM_RUNTIME_CASES:
        raise AssertionError('Fixture runtime selection exceeds its bounded budget')
    if {operations[case['function']]['canonical_id'] for case in runtime} != set(family.CANONICAL_FORMS):
        raise AssertionError('Runtime selection omits a canonical form')
    return operations, records


def dependencies(engine, family):
    paths = [Path(engine.__file__), Path(__file__), Path(family.__file__),
        Path(family.__file__).parent / '__init__.py', Path(simd_original.__file__), ROOT / 'dev/differential.py', ROOT / 'dev/evidence.py']
    guards = Path(__file__).parent / 'test_simd_fixtures.py'
    if guards.exists():
        paths.append(guards)
    return {str(path.relative_to(ROOT)): engine.digest(path.read_bytes()) for path in paths}


def oracle_path(focus):
    return ROOT / '.stela/research/integer-crypto-harness' / focus / 'oracle/receipt.json'


def prepare_original(engine, family, directory):
    """Freeze input/source bindings for the separately invoked shared observer."""
    operations, records = fixture_corpus(family)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    sources = dependencies(engine, family)
    binding_path = directory / 'source-bindings.json'
    data = (json.dumps(sources, indent=2) + '\n').encode()
    if binding_path.exists() and binding_path.read_bytes() != data:
        raise AssertionError('Frozen original source bindings changed')
    if not binding_path.exists():
        binding_path.write_bytes(data)
    plan = engine.prepare_full_frame_numerical_oracle(directory, operations, records, family.FOCUS)
    return {**plan, 'observer_sha256': engine.digest(Path(simd_original.__file__).read_bytes()),
        'fixture_sources_sha256':sources, 'capture_command':[sys.executable, str(Path(simd_original.__file__)),
            '--directory', str(directory), '--focus', family.FOCUS, '--source-bindings', str(binding_path), '--capture']}


def expected_state(family, operation, initial):
    expected = family.expected(operation, State.from_buffer_copy(initial))
    if not isinstance(expected, State):
        raise AssertionError('Fixture model must return a complete State')
    untouched = State.from_buffer_copy(expected)
    if operation.get('output_kind', 'vector') == 'gpr':
        written = operation.get('written_gprs')
        if (not isinstance(written, list)
                or any(type(index) is not int or not 0 <= index < RETURN_REGISTER + 1 for index in written)
                or len(written) != len(set(written))
                or type(operation.get('writes_sp')) is not bool
                or type(operation.get('writes_nzcv')) is not bool):
            raise AssertionError('Invalid register fixture destination metadata')
        if hasattr(family, 'validate_effects'):
            family.validate_effects(operation)
        for index in written:
            untouched.x[index] = initial.x[index]
        if operation['writes_sp']:
            untouched.sp = initial.sp
        if operation['writes_nzcv']:
            untouched.nzcv = initial.nzcv
    else:
        untouched.v[operation['d']][:] = initial.v[operation['d']]
    if bytes(untouched) != bytes(initial):
        raise AssertionError('Integer crypto model changed fields outside its destination')
    return expected


def load_original(engine, family, pointer_path):
    pointer, pointer_sha = engine.numerical_json(pointer_path)
    producer, receipt_sha = engine.numerical_json(ROOT / pointer['receipt']['path'], pointer['receipt']['sha256'])
    operations, cases = fixture_corpus(family)
    if (not producer.get('passed_transport_and_architectural_frame_checks') or producer['cases'] != len(cases)
            or pointer['directory'] != producer['directory']):
        raise AssertionError('Passing complete original capture required')
    directory = ROOT / producer['directory']
    for name, identity in producer['files'].items():
        if Path(name).name != name:
            raise AssertionError('Original evidence name escapes capture directory')
        data = (directory / name).read_bytes()
        if engine.digest(data) != identity['sha256'] or len(data) != identity['bytes']:
            raise AssertionError('Original capture file changed: ' + name)
    functions = json.loads((directory / 'functions.json').read_bytes())
    expected_functions = [{**op, 'source_hex':struct.pack('<II', op['word'], engine.RET).hex()} for op in operations]
    if functions != expected_functions:
        raise AssertionError('Captured words differ from frozen fixture encodings')
    metadata = json.loads((directory / 'cases.json').read_bytes())
    if metadata != [{key:value for key, value in case.items() if key != 'initial'} for case in cases]:
        raise AssertionError('Captured case metadata differs from the frozen fixture corpus')
    inputs, results, elf = ((directory / name).read_bytes() for name in ('inputs.bin', 'results.bin', 'guest.elf'))
    expected_inputs = b''.join(struct.pack('<Q', case['function']) + case['initial'] + bytes(8) for case in cases)
    if inputs != expected_inputs or len(results) != (len(cases) + 1) * ORIGINAL_RECORD_BYTES:
        raise AssertionError('Captured inputs/frame count differ from fixture corpus')
    records, readbacks, undefined_cases = [], Counter(), []
    for index, case in enumerate(cases):
        op = operations[case['function']]
        initial = State.from_buffer_copy(case['initial'])
        snapshot = results[(index + 1) * ORIGINAL_RECORD_BYTES:(index + 2) * ORIGINAL_RECORD_BYTES]
        original = engine.full_frame_numerical_original_state(initial, snapshot)
        esr, elr, current_el, cpacr, marker = struct.unpack_from('<5Q', snapshot, engine.VECTOR_NUMERICAL_EXCEPTION_OFFSET)
        fpcr, fpsr = struct.unpack_from('<2Q', snapshot, engine.VECTOR_NUMERICAL_READBACK_OFFSET)
        soft_variant = (family.FOCUS == 'tag_arithmetic' and op['name'] in ('addg', 'subg')
                        and op['soft_bits'] != 0)
        undefined = soft_variant and esr == UNDEFINED_INSTRUCTION_ESR
        subject_pc = elr if undefined else elr - 8
        if (not undefined and esr >> 26 != engine.FP_REGISTER_EC_SVC or current_el != 4
                or cpacr != engine.VECTOR_NUMERICAL_CPACR_FPEN or marker != engine.VECTOR_NUMERICAL_ORIGINAL_MARKER
                or engine.fp_register_elf_word(elf, subject_pc) != op['word']
                or engine.fp_register_elf_word(elf, subject_pc + 4) != engine.FP_REGISTER_SVC
                or fpcr != initial.fpcr & engine.FP_REGISTER_QEMU_MASKS['fpcr']
                or fpsr != initial.fpsr & engine.FP_REGISTER_QEMU_MASKS['fpsr']):
            raise AssertionError('Original subject/access/control evidence differs')
        mathematical = expected_state(family, op, initial)
        observed_controls = State.from_buffer_copy(initial if undefined else mathematical)
        observed_controls.fpcr, observed_controls.fpsr = fpcr, fpsr
        if bytes(original) != bytes(observed_controls):
            raise AssertionError(json.dumps({'case':index, 'operation':op, 'primary':state_dict(original),
                'expected_observed_controls':state_dict(observed_controls), 'initial':state_dict(initial)}))
        if undefined:
            undefined_cases.append(index)
        policy = (fpcr, fpsr) != (initial.fpcr, initial.fpsr)
        if op.get('output_kind', 'vector') != 'gpr':
            initial.x[RETURN_REGISTER] = original.x[RETURN_REGISTER] = mathematical.x[RETURN_REGISTER] = engine.STOP
        records.append({**case, 'initial':bytes(initial), 'expected':bytes(mathematical), 'primary_expected':bytes(original),
            'operation':op, 'equality_basis':('soft_fixed_execute_as_policy' if undefined else
                'requested_storage_policy' if policy else 'direct_original')})
        readbacks[(case['initial'][-8:].hex(), fpcr, fpsr)] += 1
    if undefined_cases != [row['case_index'] for row in producer.get('tag_soft_fixed_undefined_cases', [])]:
        raise AssertionError('Original soft-fixed UNDEF observations differ from producer receipt')
    return {'functions':operations, 'records':records, 'producer':producer, 'receipt_sha256':receipt_sha,
        'pointer_sha256':pointer_sha, 'control_readbacks':[{'requested_storage_hex':requested, 'fpcr':fpcr, 'fpsr':fpsr, 'cases':count}
            for (requested, fpcr, fpsr), count in sorted(readbacks.items())]}


def execute_batches(engine, batches):
    family = family_module(batches[0]['cohort'])
    oracle = load_original(engine, family, batches[0]['oracle_path'])
    counts, digest = Counter(), hashlib.sha256()
    examples = {}
    with ExitStack() as mappings:
        functions = {}
        for batch in batches:
            address = mappings.enter_context(engine.executable(batch['native']))
            for local, offset in enumerate(batch['offsets']):
                functions[batch['function_base'] + local] = address + offset
        address = mappings.enter_context(engine.executable(engine.NUMERICAL_MXCSR_WRAPPER))
        wrapper = ctypes.CFUNCTYPE(None, ctypes.POINTER(State), ctypes.c_void_p, ctypes.c_uint32,
            ctypes.POINTER(engine.NumericalNativeExit))(address)
        guard = ctypes.create_string_buffer(engine.NUMERICAL_GUARD_BYTES * 2 + ctypes.sizeof(State))
        state_address = ctypes.addressof(guard) + engine.NUMERICAL_GUARD_BYTES
        state_pointer = ctypes.cast(state_address, ctypes.POINTER(State))
        def invoke(record, mxcsr):
            ctypes.memmove(guard, engine.NUMERICAL_GUARD + record['initial'] + engine.NUMERICAL_GUARD, len(guard))
            observed = engine.NumericalNativeExit()
            wrapper(state_pointer, functions[record['function']], mxcsr, ctypes.byref(observed))
            # Leaf functions return void: BlockExit scratch is deliberately not interpreted.
            if observed.mxcsr_before != mxcsr or observed.mxcsr_after != mxcsr:
                raise AssertionError('Integer crypto changed caller MXCSR')
            if guard.raw[:engine.NUMERICAL_GUARD_BYTES] != engine.NUMERICAL_GUARD or guard.raw[-engine.NUMERICAL_GUARD_BYTES:] != engine.NUMERICAL_GUARD:
                raise AssertionError('Integer crypto changed owned RAM canaries')
            actual = ctypes.string_at(state_address, ctypes.sizeof(State))
            if actual != record['expected']:
                raise AssertionError(json.dumps({'case':record['case'], 'operation':record['operation'],
                    'actual':state_dict(State.from_buffer_copy(actual)), 'expected':state_dict(State.from_buffer_copy(record['expected']))}))
        for record in oracle['records']:
            invoke(record, engine.NUMERICAL_MXCSR_ALL_MASKS)
            counts[record['equality_basis']] += 1
            digest.update(struct.pack('<I', record['operation']['word']))
            digest.update(record['initial'])
            op = record['operation']
            examples.setdefault((op['canonical_id'], op['lane'], op['bytes'], op['scalar'], op.get('index')), record)
        for record in examples.values():
            for masks in (0, engine.NUMERICAL_MXCSR_ALL_MASKS):
                for status in (0, engine.NUMERICAL_MXCSR_ALL_STATUS):
                    for mode in range(4):
                        invoke(record, masks | status | mode << engine.NUMERICAL_MXCSR_ROUND_SHIFT)
                        counts['mxcsr_checks'] += 1
    return {'complete_native_state_comparisons':len(oracle['records']), 'direct_original_math_native_comparisons':counts['direct_original'],
        'requested_storage_native_policy_comparisons':counts['requested_storage_policy'],
        'soft_fixed_execute_as_native_policy_comparisons':counts['soft_fixed_execute_as_policy'], 'caller_mxcsr_preservation_comparisons':counts['mxcsr_checks'],
        'state_corpus_sha256':digest.hexdigest(), 'architectural_state_bytes':ctypes.sizeof(State),
        'limits':'All native/model bytes compare. Direct original equality excludes requested storage absent from captured FPCR/FPSR readbacks; those raw originals stay unchanged. Leaf RET is harness-owned. No numerical helper/refusal or supplementary Unicorn success is inferred.'}


def apply_operations(family, operations, initial):
    state = State.from_buffer_copy(initial)
    for op in operations:
        state = expected_state(family, op, state)
    return state


def runtime_checks(engine, family, oracle, cli, directory, compiler, target, target_id):
    selected = [record for record in oracle['records'] if record.get('runtime')]
    if any(record['operation'].get('output_kind') == 'gpr' for record in selected):
        normalized = []
        for record in selected:
            op = record['operation']
            if RETURN_REGISTER in (op.get('n'), op.get('m'), op.get('d')):
                raise AssertionError('Register fixture runtime RET normalization aliases an operand')
            initial = State.from_buffer_copy(record['initial'])
            initial.x[RETURN_REGISTER] = engine.STOP
            normalized.append({**record, 'initial': bytes(initial),
                               'expected': bytes(expected_state(family, op, initial))})
        selected = normalized
    if not 0 < len(selected) <= MAXIMUM_RUNTIME_CASES:
        raise AssertionError('Invalid runtime fixture selection')
    memory_address, memory = 0x240000000000, engine.NUMERICAL_GUARD * 16
    memory_path = directory / 'runtime-memory.json'
    memory_path.write_text(json.dumps({'regions':[{'guest_address':memory_address, 'virtual_bytes':len(memory),
        'initial_bytes':list(memory), 'readable':True, 'writable':True}]}))
    counts, transcripts = Counter(), []
    def invoke(code, initial, entry=BASE, budget=16, cache=None):
        source_path, state_path = directory / 'runtime.arm64', directory / 'runtime-state.json'
        source_path.write_bytes(code)
        state_path.write_text(json.dumps(state_dict(initial)))
        cache = cache or directory / 'runtime-cache'
        report = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path), '--guest-base', hex(BASE),
            '--entry', hex(entry), '--stop-pc', hex(engine.STOP), '--cpu-target', target, '--state', str(state_path),
            '--block-budget', str(budget), '--cache-dir', str(cache), '--memory', str(memory_path),
            '--read-memory', f'{hex(memory_address)}:{len(memory)}'], timeout=30))
        if report['compiler_source_sha256'] != compiler or report['target_cpu'] != target_id or report['source_sha256'] != engine.digest(code):
            raise AssertionError('Runtime compiler/source/target identity differs')
        ram = report['memory']
        if ram['memory_before'] != ram['memory_after'] or ram['memory_reads'][0]['hex'] != memory.hex():
            raise AssertionError('Register-only crypto changed owned guest RAM')
        if report['outcome']['floating_point_helpers']:
            raise AssertionError('Integer crypto entered a floating-point helper')
        counts['invocations'] += 1
        transcripts.append({'source_hex':code.hex(), 'initial_state_hex':bytes(initial).hex(), 'report':report})
        return report, engine.numerical_report_state(report['state'])
    def require(report, actual, expected, pc=None, reason='stop_address'):
        pc = engine.STOP if pc is None else pc
        if report['pc'] != pc or report['outcome']['reason']['kind'] != reason or bytes(actual) != bytes(expected):
            write_evidence(ROOT / f'.stela/simd-{family.FOCUS}-runtime-failure.json', {'kind':'simd_fixture_runtime_failure',
                'transcripts':transcripts, 'expected_state_hex':bytes(expected).hex(), 'expected_pc':pc, 'expected_reason':reason})
            raise AssertionError('Integer crypto runtime complete-state mismatch')
        counts['complete_state_comparisons'] += 1
    for record in selected:
        initial = State.from_buffer_copy(record['initial'])
        source = struct.pack('<II', record['operation']['word'], engine.RET)
        report, actual = invoke(source, initial)
        require(report, actual, State.from_buffer_copy(record['expected']))
        counts[record['equality_basis']] += 1
    representatives = {}
    for record in selected:
        representatives.setdefault(record['operation']['canonical_id'], record)
    for record in representatives.values():
        op, initial = record['operation'], State.from_buffer_copy(record['initial'])
        # B+4 forces a real dispatcher boundary after the subject; RET is the next block.
        source = struct.pack('<3I', op['word'], BRANCH_NEXT_INSTRUCTION, engine.RET)
        intermediate = expected_state(family, op, initial)
        cache = directory / ('resume-' + str(record['function']))
        first, actual = invoke(source, initial, budget=1, cache=cache)
        require(first, actual, intermediate, BASE + 8, 'budget_exhausted')
        final, actual = invoke(source, actual, entry=BASE + 8, budget=1, cache=cache)
        require(final, actual, intermediate)
        counts['budget_resume_checks'] += 1
        warm, actual = invoke(source, initial, cache=cache)
        require(warm, actual, intermediate)
        if not warm['outcome']['disk_cache_hits']:
            raise AssertionError('Fresh runtime did not reuse persistent code')
        counts['disk_cache_checks'] += 1
        source = struct.pack('<4I', op['word'], engine.NUMERICAL_SUBS_X10_ONE, engine.NUMERICAL_CBNZ_X10_BACK_TWO, engine.RET)
        loop_initial = State.from_buffer_copy(initial)
        loop_initial.x[10] = CACHE_LOOP_ITERATIONS
        expected = apply_operations(family, [op] * CACHE_LOOP_ITERATIONS, loop_initial)
        expected.x[10], expected.nzcv = 0, engine.NUMERICAL_ZERO_CARRY_FLAGS
        repeated, actual = invoke(source, loop_initial)
        require(repeated, actual, expected)
        if repeated['outcome']['memory_cache_hits'] < CACHE_LOOP_ITERATIONS - 1:
            raise AssertionError('Repeated accumulating instructions missed live cache reuse')
        counts['memory_cache_loop_checks'] += 1
    mixed = list(representatives.values())[:MAXIMUM_MIXED_OPERATIONS]
    operations = [dict(record['operation']) for record in mixed]
    for previous, operation in zip(operations, operations[1:]):
        operation['n'] = previous['d']
        operation['word'] = operation['word'] & ~VECTOR_LEFT_MASK | operation['n'] << VECTOR_LEFT_SHIFT
    initial = State.from_buffer_copy(mixed[0]['initial'])
    source = struct.pack('<' + 'I' * (len(operations) + 1), *[op['word'] for op in operations], engine.RET)
    report, actual = invoke(source, initial)
    require(report, actual, apply_operations(family, operations, initial))
    counts['mixed_dependency_chain_checks'] += 1
    snapshot = write_evidence(ROOT / f'.stela/simd-{family.FOCUS}-{target_id}-runtime-records.json', transcripts)
    return {**dict(counts), 'transcript':{'path':str(snapshot.relative_to(ROOT)), 'sha256':engine.digest(snapshot.read_bytes())},
        'limits':'Actual runtime full state, budget, disk/live cache and guest RAM checks use sequential integer models grounded in primary single-instruction originals. No joined-original, helper, enabled trap or performance credit.'}


def run(engine, cli, focus, pointer=None):
    family = family_module(focus)
    pointer = Path(pointer) if pointer else oracle_path(focus)
    oracle = load_original(engine, family, pointer)
    shared = dependencies(engine, family)
    cli_sha, started = engine.digest(cli.read_bytes()), time.monotonic()
    cpu = json.loads(subprocess.check_output([str(cli), 'cpu-info']))
    selections = [('baseline', 'x86_64-baseline')]
    if cpu['detected_target'] != 'x86_64-baseline':
        selections.append(('native', cpu['detected_target']))
    profiles, compiler = [], None
    with tempfile.TemporaryDirectory(prefix='stela-' + focus + '-') as temporary:
        for target, target_id in selections:
            directory = Path(temporary) / target_id
            directory.mkdir()
            batches, artifacts = [], []
            for start in range(0, len(oracle['functions']), BATCH_FUNCTIONS):
                operations = oracle['functions'][start:start + BATCH_FUNCTIONS]
                programs = [{'operations':[op]} for op in operations]
                batch = engine.compile_batch(cli, directory, programs, start, cpu_target=target, target_id=target_id,
                    guest_base=BASE + start * 8, allowed_mnemonics={op['name'] for op in operations},
                    **({'source_validator': family.validate_source_words} if hasattr(family, 'validate_source_words') else {}))
                batch.update(cohort=focus, function_base=start, oracle_path=str(pointer))
                if compiler is not None and batch['compiler'] != compiler:
                    raise AssertionError('Compiler changed during fixture preparation')
                compiler = batch['compiler']
                accounting = engine.native_binary_accounting(batch)
                retained = engine.retain_native_binary_evidence(batch, accounting, [])
                artifacts.append({'function_base':start, 'functions':len(operations), 'files':retained, 'accounting':accounting})
                batches.append(batch)
            raw = engine.bounded_cases(batches)
            runtime = runtime_checks(engine, family, oracle, cli, directory, compiler, target, target_id)
            used = set()
            optional = {row['mnemonic'] for row in cpu['simd_opcodes'] if row['minimum_target'] != 'x86_64-baseline'}
            for batch in batches:
                used.update(optional & {engine.native_mnemonic(op.mnemonic) for op in engine.decode_native_stream(batch['native'])})
            if hasattr(family, 'optional_opcodes') and used != set(family.optional_opcodes(target_id)):
                raise AssertionError((target_id, sorted(used), sorted(family.optional_opcodes(target_id))))
            profiles.append({'target_cpu':target_id, 'raw_native':raw, 'runtime':runtime, 'native_artifacts':artifacts,
                'optional_opcodes_used':sorted(used)})
    if engine.digest(cli.read_bytes()) != cli_sha or dependencies(engine, family) != shared:
        raise AssertionError('Executable/harness/fixture dependencies changed during verification')
    report = {'kind':f'simd_{focus}_arm_vs_native_x86', 'passed':True, 'canonical_forms':len(family.CANONICAL_FORMS),
        'functions':len(oracle['functions']), 'original_full_frame_captures':len(oracle['records']),
        'compiler_source_sha256':compiler, 'compiler_executable_sha256':cli_sha,
        'harness_source_sha256':shared[str(Path(engine.__file__).relative_to(ROOT))], 'shared_sources_sha256':shared,
        'original_oracle_receipt_sha256':oracle['receipt_sha256'], 'original_producer':oracle['producer'],
        'input_derivation':('Register-output raw native frames retain all original inputs, including X30. Runtime representatives exclude X30 operands; only their X30 becomes STOP for guest RET. Other families retain established X30 normalization. Original captures remain immutable; leaf native RET is harness-owned.'),
        'control_readbacks':oracle['control_readbacks'], 'profiles':profiles, 'verification_wall_seconds':time.monotonic() - started,
        'complete_native_state_comparisons':sum(profile['raw_native']['complete_native_state_comparisons'] for profile in profiles),
        'direct_original_math_native_comparisons':sum(profile['raw_native']['direct_original_math_native_comparisons'] for profile in profiles),
        'requested_storage_native_policy_comparisons':sum(profile['raw_native']['requested_storage_native_policy_comparisons'] for profile in profiles),
        'soft_fixed_execute_as_native_policy_comparisons':sum(profile['raw_native']['soft_fixed_execute_as_native_policy_comparisons'] for profile in profiles),
        'native_mxcsr_preservation_comparisons':sum(profile['raw_native']['caller_mxcsr_preservation_comparisons'] for profile in profiles),
        'runtime_complete_state_comparisons':sum(profile['runtime']['complete_state_comparisons'] for profile in profiles),
        'limits':'Declared nonstreaming register-only instruction profiles. Soft-fixed ADDG/SUBG UNDEF observations are a permitted source choice; execute-as-zero native policy comparisons receive no original equality credit. Full784B primary/model/native equality is distinct from requested FP storage unavailable in original readbacks. No numerical FP-enable refusals, model-only originals, joined-original, disabled-feature/access, Apple-hardware, process/OS or performance claim.'}
    path = write_evidence(ROOT / f'.stela/simd-{focus}-differential-report.json', report)
    return path, report
