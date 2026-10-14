"""Guarded native adapter for the versioned scalable execution context.

Families supply full immutable snapshots and independently modeled results.
Compilation and production manifest validation remain with the shared compiler
driver. This adapter executes the supplied machine-code bytes and compares only
explicitly required architectural components; missing original evidence fails.
"""

from contextlib import contextmanager
import ctypes
from dataclasses import replace
import hashlib
import json
import mmap
from pathlib import Path
import struct

from differential import executable
from scalable_frame import (
    Component, FIXED_VECTOR_BYTES,
    PREDICATE_COUNT, PRIMARY_BYTES, PRIMARY_FPCR_OFFSET, PRIMARY_VECTOR_OFFSET, Provenance,
    RAM_ADDRESS, RAM_BYTES, SVCR_SM, Snapshot, VECTOR_COUNT, compare, require_sme_length,
)


EXECUTION_CONTEXT_VERSION = 1
EXECUTION_CONTEXT_BYTES = 32
SCALABLE_VIEW_BYTES = 72
CANARY_BYTES = 64
CANARY = bytes((index * 29 + 17) & 255 for index in range(CANARY_BYTES))
HOST_RET = b'\xc3'
GUEST_RET_WORD = 0xd65f03c0
MAXIMUM_CHUNK_CASES = 128
V2_PROFILES = {
    'apple-streaming-sme-v2': ('max,sve=off,sme=on,sme_fa64=off', False),
    'sve-streaming-bf16-fa64-off-v2': ('max,sve=on,sme=on,sme_fa64=off', True),
}
FEATURE_FIELD_MASK = 15
ID_PFR0_SVE_SHIFT = 32
ID_PFR1_SME_SHIFT = 24
ID_SMFR0_FA64_SHIFT = 63
ID_SMFR0_SMEVER_SHIFT = 56
ID_MMFR2_AT_SHIFT = 32
ID_ZFR0_B16B16_SHIFT = 24
SME2_MINIMUM_FIELD = 2
LSE2_AT_FIELD = 1
B16B16_FEATURE_FIELD = 1
CPACR_FP_ACCESS = 3 << 20
CPACR_SME_ACCESS = 3 << 24
CPACR_SVE_ACCESS = 3 << 16
SMCR_FA64 = 1 << 31
SMCR_ZT0_ENABLE = 1 << 30
SMCR_LENGTH_MASK = 15
CURRENT_EL1 = 4
V2_PROFILE_FIELDS = (
    'CurrentEL', 'ID_AA64PFR0_EL1', 'ID_AA64PFR1_EL1',
    'ID_AA64ZFR0_EL1', 'ID_AA64SMFR0_EL1', 'ID_AA64PFR2_EL1',
    'CPACR_EL1', 'SMCR_EL1', 'SCTLR_EL1', 'TCR_EL1', 'MAIR_EL1',
    'TTBR0_EL1', 'ID_AA64MMFR2_EL1',
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    """Preserve immutable preparation bytes rather than replacing old evidence."""
    path = Path(path)
    with path.open('xb') as output:
        output.write(data)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def prepare_corpus(directory, cases, *, source_paths):
    """Freeze one bounded family chunk using the common lazy-case dictionary API."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    functions, function_indices, inputs, expected, metadata = [], {}, [], [], []
    ram_inputs, ram_expected = [], []
    length = None
    for index, case in enumerate(cases):
        if index >= MAXIMUM_CHUNK_CASES:
            raise ValueError('Split scalable corpora into bounded 128-case chunks')
        if case.get('fault') is not None:
            raise ValueError('Fault corpora need the separate original/native exception observer')
        operation = case['operation']
        word, canonical = operation['word'], operation['canonical_id']
        if type(word) is not int or not 0 <= word < 1 << 32 or type(canonical) is not str or not canonical:
            raise ValueError('Case operation needs its exact word and canonical identity')
        initial, model = case['initial'], case['expected']
        if not isinstance(initial, Snapshot) or not isinstance(model, Snapshot):
            raise ValueError('Cases must provide complete initial/model snapshots')
        require_sme_length(initial.svl_bytes)
        if length is None:
            length = initial.svl_bytes
        if initial.svl_bytes != length or model.svl_bytes != length:
            raise ValueError('One original chunk must use one declared vector length')
        if word not in function_indices:
            function_indices[word] = len(functions)
            functions.append({'word': word, 'id': canonical})
        function = function_indices[word]
        if functions[function]['id'] != canonical:
            raise ValueError('One source word has conflicting canonical identities')
        initial = replace(initial, case_index=index, function_index=function)
        model = replace(model, case_index=index, function_index=function)
        required = Component(case['required'])
        if not required & Component.PRIMARY or model.valid & required != required:
            raise ValueError('Model lacks a requested architectural component')
        inputs.append(initial.to_bytes())
        expected.append(model.to_bytes())
        ram, after_ram = case.get('ram'), case.get('expected_ram')
        if (ram is None) != (after_ram is None):
            raise ValueError('Memory cases require both complete initial and expected RAM')
        if ram is not None:
            if type(ram) is not bytes or type(after_ram) is not bytes or len(ram) != RAM_BYTES or len(after_ram) != RAM_BYTES:
                raise ValueError('Scalable RAM cases use the complete bounded 8192-byte region')
            ram_inputs.append(ram)
            ram_expected.append(after_ram)
        metadata.append({'case_index': index, 'function_index': function,
                         'operation': operation, 'required_components': int(required),
                         'input_sha256': initial.digest(), 'expected_sha256': model.digest()})
    if not inputs or ram_inputs and len(ram_inputs) != len(inputs):
        raise ValueError('Original chunks must be nonempty and uniformly register/RAM cases')
    source_paths = list(source_paths)
    paths = [Path(__file__), Path(__file__).with_name('scalable_frame.py'),
             *(Path(path) for path in source_paths)]
    if not source_paths:
        raise ValueError('Pure fixture source identities must be supplied')
    bindings = {str(path.resolve()): digest(path.read_bytes()) for path in paths}
    files = {'functions.json': json_bytes(functions), 'inputs.bin': b''.join(inputs),
             'expected.bin': b''.join(expected), 'cases.json': json_bytes(metadata),
             'source-bindings.json': json_bytes(bindings)}
    if ram_inputs:
        files.update({'ram-input.bin': b''.join(ram_inputs),
                      'ram-expected.bin': b''.join(ram_expected)})
    for name, data in files.items():
        write_new(directory / name, data)
    manifest = {'kind': 'scalable-fixture-corpus-v1', 'cases': len(inputs),
                'functions': len(functions), 'svl_bytes': length,
                'ram_address': RAM_ADDRESS if ram_inputs else None,
                'ram_bytes_per_case': RAM_BYTES if ram_inputs else 0,
                'sources': bindings, 'files': {name: {'sha256': digest(data), 'bytes': len(data)}
                                             for name, data in files.items()}}
    write_new(directory / 'manifest.json', json_bytes(manifest))
    return manifest


def read_snapshots(data):
    """Decode homogeneous canonical records without accepting truncated tails."""
    from scalable_frame import HEADER_BYTES, HEADER_PREFIX
    if len(data) < HEADER_BYTES:
        raise ValueError('Truncated scalable corpus')
    stride = HEADER_PREFIX.unpack_from(data)[3]
    if stride < HEADER_BYTES or len(data) % stride:
        raise ValueError('Scalable corpus record framing differs')
    return [Snapshot.from_bytes(data[start:start + stride])
            for start in range(0, len(data), stride)]


def load_original(directory):
    """Validate immutable original producer files and exact subject/frame bindings."""
    directory = Path(directory)
    receipt_bytes = (directory / 'receipt.json').read_bytes()
    receipt = json.loads(receipt_bytes)
    if receipt.get('kind') not in ('original-el0-scalable-state-v1', 'original-el0-scalable-state-v2') or not receipt.get('passed'):
        raise AssertionError('Passing scalable original capture is required')
    if receipt['kind'] == 'original-el0-scalable-state-v2':
        validate_v2_profile(receipt)
    for name, identity in receipt['files'].items():
        if Path(name).name != name:
            raise AssertionError('Original evidence path escapes its directory')
        data = (directory / name).read_bytes()
        if len(data) != identity['bytes'] or digest(data) != identity['sha256']:
            raise AssertionError('Immutable original capture changed: ' + name)
    if receipt['kind'] == 'original-el0-scalable-state-v2':
        raw = (directory / 'results.bin').read_bytes()
        values = struct.unpack_from('<' + 'Q' * len(V2_PROFILE_FIELDS), raw)
        observed = dict(zip(V2_PROFILE_FIELDS, values))
        declared = {name: int(value, 16) for name, value in receipt['actual_profile'].items()}
        if observed != declared:
            raise AssertionError('Declared v2 controls differ from actual raw header readbacks')
    inputs = read_snapshots((directory / 'inputs.bin').read_bytes())
    originals = read_snapshots((directory / 'frames.bin').read_bytes())
    functions = json.loads((directory / 'functions.json').read_bytes())
    cases = json.loads((directory / 'cases.json').read_bytes())
    if not len(inputs) == len(originals) == len(cases) == receipt['cases']:
        raise AssertionError('Original full-frame case count differs')
    if (receipt.get('profile_id') == 'sve-streaming-bf16-fa64-off-v2'
            and any(not initial.control('svcr') & SVCR_SM for initial in inputs)):
        raise AssertionError('BF16 profile requires streaming mode for every original input')
    for index, (initial, original, case) in enumerate(zip(inputs, originals, cases)):
        function = initial.function_index
        if (initial.case_index != index or original.case_index != index
                or original.function_index != function or not 0 <= function < len(functions)
                or case['source_word'] != functions[function]['word']
                or case['input_sha256'] != initial.digest()
                or case['snapshot_sha256'] != original.digest()
                or not original.provenance & Provenance.ARCHITECTURAL):
            raise AssertionError('Original word/input/frame identity differs')
    return {'receipt': receipt, 'receipt_sha256': digest(receipt_bytes),
            'functions': functions, 'inputs': inputs, 'originals': originals, 'cases': cases}


def validate_v2_profile(receipt):
    """Keep expanded oracle capabilities explicit and separate from v1 evidence."""
    identity = receipt.get('profile_id')
    if identity not in V2_PROFILES:
        raise AssertionError('Unknown versioned scalable original profile')
    cpu_profile, sve = V2_PROFILES[identity]
    if receipt.get('cpu_profile') != cpu_profile:
        raise AssertionError('Original CPU profile differs from its versioned identity')
    actual = {name: int(value, 16) for name, value in receipt['actual_profile'].items()}
    length = require_sme_length(receipt['requested_svl_bytes'])
    if (actual['CurrentEL'] != CURRENT_EL1
            or bool(actual['ID_AA64PFR0_EL1'] >> ID_PFR0_SVE_SHIFT & FEATURE_FIELD_MASK) != sve
            or actual['ID_AA64PFR1_EL1'] >> ID_PFR1_SME_SHIFT & FEATURE_FIELD_MASK < SME2_MINIMUM_FIELD
            or actual['ID_AA64SMFR0_EL1'] >> ID_SMFR0_FA64_SHIFT & 1
            or actual['SMCR_EL1'] & SMCR_FA64
            or actual['SMCR_EL1'] & (SMCR_ZT0_ENABLE | SMCR_LENGTH_MASK) != SMCR_ZT0_ENABLE | (length // FIXED_VECTOR_BYTES - 1)
            or actual['ID_AA64MMFR2_EL1'] >> ID_MMFR2_AT_SHIFT & FEATURE_FIELD_MASK != LSE2_AT_FIELD
            or actual['CPACR_EL1'] != (CPACR_FP_ACCESS | CPACR_SME_ACCESS | (CPACR_SVE_ACCESS if sve else 0))):
        raise AssertionError('Actual original access/feature profile differs')
    if sve and (actual['ID_AA64ZFR0_EL1'] >> ID_ZFR0_B16B16_SHIFT & FEATURE_FIELD_MASK != B16B16_FEATURE_FIELD
                or actual['ID_AA64SMFR0_EL1'] >> ID_SMFR0_SMEVER_SHIFT & FEATURE_FIELD_MASK not in (1, 2)):
        raise AssertionError('Actual streaming BF16 feature profile differs')
    selected = receipt['bindings']['selected_qemu']
    binary = selected.get('executed_binary', {})
    if (binary.get('kind') != 'thin-little-endian-mach-o-64-execute'
            or binary.get('sha256') != selected.get('binary', {}).get('sha256')
            or binary.get('path') != selected.get('binary', {}).get('path')
            or type(binary.get('bytes')) is not int or binary['bytes'] <= 0
            or not selected.get('build_receipt_sha256')):
        raise AssertionError('Actual executed QEMU Mach-O/build identity is unavailable')


def verify_prepared_corpus(directory, original_directory, native, entry_offsets,
                           *, compiled_source):
    """Join frozen fixtures, genuine original frames and exact native mini-functions.

    The compiler driver must validate its manifest/source maps before this call.
    This consumer additionally binds every subject word and native entry count to
    the original corpus rather than accepting a model-only execution report.
    """
    directory = Path(directory)
    manifest_bytes = (directory / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get('kind') != 'scalable-fixture-corpus-v1':
        raise AssertionError('Frozen scalable fixture manifest is required')
    for name, identity in manifest['files'].items():
        if Path(name).name != name:
            raise AssertionError('Fixture evidence path escapes its directory')
        data = (directory / name).read_bytes()
        if len(data) != identity['bytes'] or digest(data) != identity['sha256']:
            raise AssertionError('Frozen scalable fixture changed: ' + name)
    for path, identity in manifest['sources'].items():
        if digest(Path(path).read_bytes()) != identity:
            raise AssertionError('Scalable fixture source changed: ' + path)
    original = load_original(original_directory)
    inputs = read_snapshots((directory / 'inputs.bin').read_bytes())
    expected = read_snapshots((directory / 'expected.bin').read_bytes())
    cases = json.loads((directory / 'cases.json').read_bytes())
    functions = json.loads((directory / 'functions.json').read_bytes())
    captured_functions = [{key: value for key, value in function.items() if key != 'source_hex'}
                          for function in original['functions']]
    if (functions != captured_functions or len(entry_offsets) != len(functions)
            or len(inputs) != manifest['cases'] or len(expected) != len(inputs)
            or len(cases) != len(inputs) or len(original['inputs']) != len(inputs)
            or any(left.to_bytes() != right.to_bytes()
                   for left, right in zip(inputs, original['inputs']))):
        raise AssertionError('Original/native fixture source and input bindings differ')
    source = b''.join(struct.pack('<II', function['word'], GUEST_RET_WORD)
                      for function in functions)
    if compiled_source != source:
        raise AssertionError('Compiled mini-function words differ from original subjects')
    if any(type(offset) is not int or not 0 <= offset < len(native) for offset in entry_offsets):
        raise AssertionError('Native source-map entry offset differs')
    ram_bytes = manifest['ram_bytes_per_case']
    if ram_bytes:
        if ram_bytes != RAM_BYTES or manifest['ram_address'] != RAM_ADDRESS:
            raise AssertionError('Scalable RAM profile differs')
        # Until the producer publishes its separately bound full-RAM records,
        # a register-only original cannot grant memory equality credit.
        if not original['receipt'].get('ram_bytes_per_case') == RAM_BYTES:
            raise AssertionError('Complete original RAM observations are unavailable')
        ram_inputs = (directory / 'ram-input.bin').read_bytes()
        expected_ram = (directory / 'ram-expected.bin').read_bytes()
        original_ram = (Path(original_directory) / 'ram-results.bin').read_bytes()
        if (original['receipt'].get('ram_address') != RAM_ADDRESS
                or (Path(original_directory) / 'initial-ram.bin').read_bytes() != ram_inputs):
            raise AssertionError('Original initial RAM/profile differs from the frozen fixture')
        if len(original_ram) != len(inputs) * RAM_BYTES:
            raise AssertionError('Original scalable RAM record count differs')
    else:
        ram_inputs = expected_ram = original_ram = None
    rows = []
    for index, (initial, model, captured, observation, metadata) in enumerate(zip(
            inputs, expected, original['originals'], original['cases'], cases)):
        if not observation['completed_subject']:
            raise AssertionError('Normal native cohort contains an original subject exception')
        fpcr, fpsr = struct.unpack_from('<II', initial.primary, PRIMARY_FPCR_OFFSET)
        before = observation['initial_readbacks']
        if int(before['fpcr'], 16) != fpcr or int(before['fpsr'], 16) != fpsr:
            raise AssertionError('Requested FP storage differs from actual original pre-state; classify policy separately')
        if int(before['tpidr2_el0'], 16) != initial.control('tpidr2_el0'):
            raise AssertionError('Actual original TPIDR2 pre-state differs')
        start, end = index * RAM_BYTES, (index + 1) * RAM_BYTES
        rows.append(verify_native_case(native, initial, captured, model,
                                      required=metadata['required_components'],
                                      offset=entry_offsets[initial.function_index],
                                      ram=ram_inputs[start:end] if ram_inputs is not None else None,
                                      expected_ram=expected_ram[start:end] if expected_ram is not None else None,
                                      original_ram=original_ram[start:end] if original_ram is not None else None))
    return {'kind': 'scalable-original-model-native-v1', 'passed': True,
            'cases': len(rows), 'functions': len(functions),
            'svl_bytes': manifest['svl_bytes'],
            'corpus_manifest_sha256': digest(manifest_bytes),
            'original_receipt_sha256': original['receipt_sha256'],
            'compiled_source_sha256': digest(compiled_source),
            'native_sha256': digest(native), 'sources': manifest['sources'],
            'comparisons': rows,
            'limits': 'Strict direct original/model/native equality. Runtime/cache, caller MXCSR, resumable faults and performance need separate evidence.'}


class ScalableStateView(ctypes.Structure):
    _fields_ = [
        ('svl_bytes', ctypes.c_uint16), ('reserved', ctypes.c_uint8 * 6),
        ('svcr', ctypes.c_uint64), ('tpidr2_el0', ctypes.c_uint64),
        ('fpmr', ctypes.c_uint64), ('z_upper', ctypes.c_void_p),
        ('predicates', ctypes.c_void_p), ('ffr', ctypes.c_void_p),
        ('za', ctypes.c_void_p), ('zt0', ctypes.c_void_p),
    ]


class ExecutionContext(ctypes.Structure):
    _fields_ = [
        ('version', ctypes.c_uint32), ('bytes', ctypes.c_uint32),
        ('memory', ctypes.c_void_p), ('scalable', ctypes.POINTER(ScalableStateView)),
        ('system', ctypes.c_void_p),
    ]


class GuardedBuffer:
    """Own exact payload storage with independently checked leading/trailing bytes."""

    def __init__(self, data):
        if type(data) is not bytes:
            raise TypeError('Guarded native inputs must be immutable bytes')
        self.size = len(data)
        self.storage = ctypes.create_string_buffer(CANARY + data + CANARY,
                                                    CANARY_BYTES * 2 + self.size)
        self.address = ctypes.addressof(self.storage) + CANARY_BYTES

    def read(self):
        self.check()
        return ctypes.string_at(self.address, self.size)

    def check(self):
        raw = bytes(self.storage)
        if raw[:CANARY_BYTES] != CANARY or raw[CANARY_BYTES + self.size:] != CANARY:
            raise AssertionError('Native scalable state exceeded a register-bank boundary')


class NativeState:
    """One stable, reusable context; low Z bytes live solely in primary State."""

    def __init__(self, initial):
        require_sme_length(initial.svl_bytes)
        self.initial = initial
        length = initial.svl_bytes
        self.primary = GuardedBuffer(initial.primary)
        self.z_upper = GuardedBuffer(b''.join(row[FIXED_VECTOR_BYTES:] for row in initial.z))
        self.predicates = GuardedBuffer(b''.join(initial.p))
        self.ffr = GuardedBuffer(initial.ffr)
        self.za = GuardedBuffer(initial.za)
        self.zt0 = GuardedBuffer(initial.zt0)
        self.view_storage = GuardedBuffer(bytes(SCALABLE_VIEW_BYTES))
        self.view = ScalableStateView.from_address(self.view_storage.address)
        self.view.svl_bytes = length
        self.view.svcr = initial.control('svcr')
        self.view.tpidr2_el0 = initial.control('tpidr2_el0')
        self.view.fpmr = initial.control('fpmr')
        self.view.z_upper = self.z_upper.address
        self.view.predicates = self.predicates.address
        self.view.ffr = self.ffr.address
        self.view.za = self.za.address
        self.view.zt0 = self.zt0.address
        self.context_storage = GuardedBuffer(bytes(EXECUTION_CONTEXT_BYTES))
        self.context = ExecutionContext.from_address(self.context_storage.address)
        self.context.version = EXECUTION_CONTEXT_VERSION
        self.context.bytes = EXECUTION_CONTEXT_BYTES
        self.context.scalable = ctypes.pointer(self.view)
        self.context_before = bytes(self.context)
        self.view_header_before = bytes(self.view)[:ScalableStateView.svcr.offset]
        self.svcr_before = self.view.svcr
        self.view_pointers_before = bytes(self.view)[ScalableStateView.z_upper.offset:]

    def snapshot(self):
        primary = self.primary.read()
        upper = self.z_upper.read()
        predicates = self.predicates.read()
        self.view_storage.check()
        self.context_storage.check()
        if bytes(self.context) != self.context_before:
            raise AssertionError('Native instruction changed execution-context identity')
        if (bytes(self.view)[:ScalableStateView.svcr.offset] != self.view_header_before
                or bytes(self.view)[ScalableStateView.z_upper.offset:] != self.view_pointers_before):
            raise AssertionError('Native instruction changed scalable allocation identity')
        if self.view.svcr != self.svcr_before:
            raise AssertionError('Mode transitions require the runtime service boundary')
        length = self.initial.svl_bytes
        upper_bytes = length - FIXED_VECTOR_BYTES
        predicate_bytes = length // 8
        z = tuple(primary[PRIMARY_VECTOR_OFFSET + index * FIXED_VECTOR_BYTES:
                          PRIMARY_VECTOR_OFFSET + (index + 1) * FIXED_VECTOR_BYTES]
                  + upper[index * upper_bytes:(index + 1) * upper_bytes]
                  for index in range(VECTOR_COUNT))
        p = tuple(predicates[index * predicate_bytes:(index + 1) * predicate_bytes]
                  for index in range(PREDICATE_COUNT))
        controls = {**self.initial.controls, 'svcr': self.view.svcr,
                    'tpidr2_el0': self.view.tpidr2_el0, 'fpmr': self.view.fpmr}
        return replace(self.initial, primary=primary, z=z, p=p,
                       ffr=self.ffr.read(), za=self.za.read(), zt0=self.zt0.read(),
                       controls=controls, provenance=Provenance.NATIVE)

    def invoke(self, address):
        entry = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
                               ctypes.POINTER(ExecutionContext))(address)
        entry(self.primary.address, ctypes.byref(self.context))
        return self.snapshot()


@contextmanager
def private_ram(address=RAM_ADDRESS, size=RAM_BYTES):
    """Map a hint only; never replace another native allocation."""
    if type(address) is not int or type(size) is not int or address <= 0 or size <= 0:
        raise ValueError('Native RAM mapping requires a positive address and size')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                         ctypes.c_int, ctypes.c_int, ctypes.c_longlong]
    libc.mmap.restype = ctypes.c_void_p
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    pointer = libc.mmap(address, size, mmap.PROT_READ | mmap.PROT_WRITE,
                        mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
    if pointer == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_errno(), 'Native scalable RAM allocation failed')
    try:
        if pointer != address:
            raise AssertionError('Native RAM address hint was refused')
        yield pointer
    finally:
        if libc.munmap(pointer, size):
            raise OSError(ctypes.get_errno(), 'Native scalable RAM release failed')


def execute_native(native, initial, *, offset=0, ram=None, ram_address=RAM_ADDRESS):
    """Execute actual translated bytes; caller isolates expected faulting inputs."""
    if type(native) is not bytes or not native or not 0 <= offset < len(native):
        raise ValueError('Native machine code and entry offset are required')
    state = NativeState(initial)
    with executable(native) as address:
        if ram is None:
            return state.invoke(address + offset), None
        if type(ram) is not bytes or not ram:
            raise ValueError('Native RAM input must be nonempty immutable bytes')
        with private_ram(ram_address, len(ram)) as pointer:
            ctypes.memmove(pointer, ram, len(ram))
            observed = state.invoke(address + offset)
            return observed, ctypes.string_at(pointer, len(ram))


def verify_native_case(native, initial, original, expected, *, required,
                       offset=0, ram=None, expected_ram=None, original_ram=None):
    """Require original/model equality before executing the native comparison."""
    if not original.provenance & Provenance.ARCHITECTURAL:
        raise AssertionError('A genuine architectural original snapshot is required')
    original_comparison = compare(expected, original, required)
    if ram is not None and (expected_ram is None or original_ram is None
                            or expected_ram != original_ram):
        raise AssertionError('Complete original/model RAM equality is required')
    observed, observed_ram = execute_native(native, initial, offset=offset, ram=ram)
    native_comparison = compare(expected, observed, required)
    if ram is not None and observed_ram != expected_ram:
        raise AssertionError('Complete native RAM differs from original/model RAM')
    return {'passed': True, 'original': original_comparison,
            'native': native_comparison, 'native_sha256': hashlib.sha256(native).hexdigest(),
            'entry_offset': offset, 'initial_sha256': initial.digest(),
            'original_sha256': original.digest(), 'expected_sha256': expected.digest(),
            'native_state_sha256': observed.digest(), 'ram_bytes': len(ram) if ram else 0,
            'limits': 'Architectural components are explicit. No host-fault resumption, runtime/cache, caller-MXCSR, timing or application claim.'}


def source_bindings():
    paths = (Path(__file__), Path(__file__).with_name('scalable_frame.py'),
             Path(__file__).with_name('differential.py'))
    return {str(path.name): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


assert ctypes.sizeof(ScalableStateView) == SCALABLE_VIEW_BYTES
assert ctypes.sizeof(ExecutionContext) == EXECUTION_CONTEXT_BYTES
assert ScalableStateView.z_upper.offset == 32
assert ExecutionContext.scalable.offset == 16
