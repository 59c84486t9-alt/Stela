"""Portable full scalable snapshots, independent of production pointer layouts.

The wire format allocates every register bank. Validity records what an observer
actually captured; allocated diagnostic bytes never imply architectural access.
SME execution profiles select power-of-two lengths separately from this generic
SVE-compatible framing.
"""

from dataclasses import dataclass, field, replace
from enum import IntFlag
import hashlib
import struct


MAGIC = b'STELASV1'
VERSION = 1
HEADER_BYTES = 256
PRIMARY_BYTES = 784
GENERAL_REGISTER_COUNT = 31
VECTOR_COUNT = 32
PREDICATE_COUNT = 16
FIXED_VECTOR_BYTES = 16
PRIMARY_VECTOR_OFFSET = 264
PRIMARY_SP_OFFSET = 248
PRIMARY_NZCV_OFFSET = 256
PRIMARY_FPCR_OFFSET = 776
PRIMARY_FPSR_OFFSET = 780
NZCV_MASK = 0xf0000000
SEED_FPCR_MASK = 0x07c00000
SEED_FPSR_MASK = 0x0800001f
LOOKUP_TABLE_BYTES = 64
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256
BITS_PER_BYTE = 8
RECORD_ALIGNMENT = 16
RAM_ADDRESS = 0x140074000
RAM_BYTES = 8192
SME_LENGTHS = (16, 32, 64, 128, 256)
HEADER_PREFIX = struct.Struct('<8sIIQQQHHIII')
CONTROL_NAMES = (
    'svcr', 'tpidr2_el0', 'fpmr', 'esr', 'elr', 'far', 'spsr',
    'current_el', 'cpacr', 'smcr', 'zcr', 'sctlr', 'pfr0', 'pfr1',
    'zfr0', 'smfr0', 'rdsvl', 'observation_pc', 'status', 'choice_bits',
    'requested_svcr', 'requested_fpcr', 'requested_fpsr', 'marker',
    'reserved_control',
)
CONTROL_FORMAT = struct.Struct('<' + 'Q' * len(CONTROL_NAMES))
SVCR_SM = 1
SVCR_ZA = 2
SVCR_MASK = SVCR_SM | SVCR_ZA


class Component(IntFlag):
    PRIMARY = 1
    Z = 2
    P = 4
    FFR = 8
    ZA = 16
    ZT0 = 32
    SVCR = 64
    TPIDR2 = 128
    FPMR = 256


ALL_COMPONENTS = sum(Component)


class Provenance(IntFlag):
    ARCHITECTURAL = 1
    DEBUGGER_SUPPLEMENT = 2
    NATIVE = 4
    MODEL = 8


def validate_length(length):
    if type(length) is not int or not MIN_VECTOR_BYTES <= length <= MAX_VECTOR_BYTES or length % MIN_VECTOR_BYTES:
        raise ValueError('Vector length must be a 16-byte multiple through 256')
    return length


def require_sme_length(length):
    validate_length(length)
    if length not in SME_LENGTHS:
        raise ValueError('SME streaming profile requires a power-of-two length')
    return length


def offsets(svl_bytes):
    """Return canonical byte offsets, including the final aligned record size."""
    length = validate_length(svl_bytes)
    result = {'primary': HEADER_BYTES}
    result['z'] = result['primary'] + PRIMARY_BYTES
    result['p'] = result['z'] + VECTOR_COUNT * length
    result['ffr'] = result['p'] + PREDICATE_COUNT * (length // BITS_PER_BYTE)
    result['za'] = result['ffr'] + length // BITS_PER_BYTE
    result['zt0'] = result['za'] + length * length
    end = result['zt0'] + LOOKUP_TABLE_BYTES
    result['record_bytes'] = (end + RECORD_ALIGNMENT - 1) // RECORD_ALIGNMENT * RECORD_ALIGNMENT
    return result


@dataclass(frozen=True)
class Snapshot:
    svl_bytes: int
    primary: bytes
    z: tuple[bytes, ...]
    p: tuple[bytes, ...]
    ffr: bytes
    za: bytes
    zt0: bytes
    valid: Component
    controls: dict = field(default_factory=dict)
    provenance: Provenance = Provenance.MODEL
    vl_bytes: int = 0
    case_index: int = 0
    function_index: int = 0

    def __post_init__(self):
        length = validate_length(self.svl_bytes)
        if self.vl_bytes:
            validate_length(self.vl_bytes)
        if type(self.primary) is not bytes or len(self.primary) != PRIMARY_BYTES:
            raise ValueError('Primary State must contain exactly 784 bytes')
        for bank, count, size in ((self.z, VECTOR_COUNT, length),
                                  (self.p, PREDICATE_COUNT, length // BITS_PER_BYTE)):
            if not isinstance(bank, tuple) or len(bank) != count or any(type(row) is not bytes or len(row) != size for row in bank):
                raise ValueError('Scalable register bank framing differs')
        for value, size in ((self.ffr, length // BITS_PER_BYTE),
                            (self.za, length * length), (self.zt0, LOOKUP_TABLE_BYTES)):
            if type(value) is not bytes or len(value) != size:
                raise ValueError('Scalable component framing differs')
        if int(self.valid) & ~int(ALL_COMPONENTS) or not self.valid & Component.PRIMARY:
            raise ValueError('Unknown validity bits or missing primary State')
        if int(self.provenance) & ~sum(Provenance) or not self.provenance:
            raise ValueError('Observation provenance must be explicit')
        if set(self.controls) - set(CONTROL_NAMES):
            raise ValueError('Unknown control field')
        for name, value in self.controls.items():
            if type(value) is not int or not 0 <= value < 1 << 64:
                raise ValueError('Control field must fit u64: ' + name)
        if self.controls.get('reserved_control', 0):
            raise ValueError('Reserved control field must be zero')
        for index in (self.case_index, self.function_index):
            if type(index) is not int or not 0 <= index < 1 << 64:
                raise ValueError('Record indices must fit u64')
        if self.valid & Component.SVCR and self.control('svcr') & ~SVCR_MASK:
            raise ValueError('Unknown SVCR bits')
        if self.valid & Component.Z:
            for index, register in enumerate(self.z):
                start = PRIMARY_VECTOR_OFFSET + index * FIXED_VECTOR_BYTES
                if self.primary[start:start + FIXED_VECTOR_BYTES] != register[:FIXED_VECTOR_BYTES]:
                    raise ValueError('V and low Z aliases disagree')

    def control(self, name):
        if name not in CONTROL_NAMES:
            raise KeyError(name)
        return self.controls.get(name, 0)

    def to_bytes(self):
        layout = offsets(self.svl_bytes)
        result = bytearray(layout['record_bytes'])
        HEADER_PREFIX.pack_into(result, 0, MAGIC, VERSION, HEADER_BYTES,
                                len(result), self.case_index, self.function_index,
                                self.svl_bytes, self.vl_bytes, int(self.valid),
                                int(self.provenance), 0)
        CONTROL_FORMAT.pack_into(result, HEADER_PREFIX.size,
                                 *(self.control(name) for name in CONTROL_NAMES))
        components = (('primary', self.primary), ('z', b''.join(self.z)),
                      ('p', b''.join(self.p)), ('ffr', self.ffr),
                      ('za', self.za), ('zt0', self.zt0))
        for name, value in components:
            start = layout[name]
            result[start:start + len(value)] = value
        return bytes(result)

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes or len(data) < HEADER_BYTES:
            raise ValueError('Truncated scalable header')
        (magic, version, header_bytes, record_bytes, case, function,
         length, vl, valid, provenance, reserved) = HEADER_PREFIX.unpack_from(data)
        if (magic, version, header_bytes, reserved) != (MAGIC, VERSION, HEADER_BYTES, 0):
            raise ValueError('Unsupported scalable frame header')
        layout = offsets(length)
        if len(data) != record_bytes or record_bytes != layout['record_bytes']:
            raise ValueError('Scalable record size differs')
        controls = dict(zip(CONTROL_NAMES, CONTROL_FORMAT.unpack_from(data, HEADER_PREFIX.size)))
        predicate_bytes = length // BITS_PER_BYTE
        def bank(start, count, stride):
            return tuple(data[start + index * stride:start + (index + 1) * stride] for index in range(count))
        end = layout['zt0'] + LOOKUP_TABLE_BYTES
        if any(data[end:]):
            raise ValueError('Scalable frame padding must be zero')
        return cls(length, data[layout['primary']:layout['z']],
                   bank(layout['z'], VECTOR_COUNT, length),
                   bank(layout['p'], PREDICATE_COUNT, predicate_bytes),
                   data[layout['ffr']:layout['za']], data[layout['za']:layout['zt0']],
                   data[layout['zt0']:end], Component(valid), controls,
                   Provenance(provenance), vl, case, function)

    def digest(self):
        return hashlib.sha256(self.to_bytes()).hexdigest()


def compare(expected, actual, required):
    """Compare every requested architectural component, failing absent evidence."""
    required = Component(required)
    if int(required) & ~int(ALL_COMPONENTS) or not required & Component.PRIMARY:
        raise ValueError('Comparison must name known components and primary State')
    if expected.svl_bytes != actual.svl_bytes:
        raise AssertionError('Scalable comparison length differs')
    if required & expected.valid != required or required & actual.valid != required:
        raise AssertionError('Required architectural component was not observed')
    fields = ((Component.PRIMARY, 'primary'), (Component.Z, 'z'), (Component.P, 'p'),
              (Component.FFR, 'ffr'), (Component.ZA, 'za'), (Component.ZT0, 'zt0'))
    for component, name in fields:
        if required & component and getattr(expected, name) != getattr(actual, name):
            raise AssertionError('Architectural scalable component differs: ' + name)
    for component, name in ((Component.SVCR, 'svcr'), (Component.TPIDR2, 'tpidr2_el0'),
                            (Component.FPMR, 'fpmr')):
        if required & component and expected.control(name) != actual.control(name):
            raise AssertionError('Architectural scalable control differs: ' + name)
    return {'components': int(required), 'primary_bytes': PRIMARY_BYTES,
            'omitted_components': int(ALL_COMPONENTS & ~required)}


def snapshot_from_banks(svl_bytes, *, primary=None, z=None, p=None, ffr=None,
                        za=None, zt0=None, valid, controls=None,
                        provenance=Provenance.MODEL, vl_bytes=0,
                        case_index=0, function_index=0):
    """Construct a frame, making supplied Z bytes authoritative for low V aliases.

    If Z is omitted, its low bytes come from primary State and upper bytes are
    zero. This is input construction, never an observation or missing-state repair.
    """
    length = validate_length(svl_bytes)
    scalar = bytearray(bytes(PRIMARY_BYTES) if primary is None else primary)
    if len(scalar) != PRIMARY_BYTES:
        raise ValueError('Primary State must contain exactly 784 bytes')
    if z is None:
        z = tuple(bytes(scalar[PRIMARY_VECTOR_OFFSET + index * FIXED_VECTOR_BYTES:
                               PRIMARY_VECTOR_OFFSET + (index + 1) * FIXED_VECTOR_BYTES])
                  + bytes(length - FIXED_VECTOR_BYTES) for index in range(VECTOR_COUNT))
    else:
        z = tuple(z)
        if len(z) != VECTOR_COUNT or any(type(row) is not bytes or len(row) != length for row in z):
            raise ValueError('Supplied Z bank framing differs')
        for index, register in enumerate(z):
            start = PRIMARY_VECTOR_OFFSET + index * FIXED_VECTOR_BYTES
            scalar[start:start + FIXED_VECTOR_BYTES] = register[:FIXED_VECTOR_BYTES]
    predicate_bytes = length // BITS_PER_BYTE
    return Snapshot(length, bytes(scalar), z,
                    tuple(bytes(predicate_bytes) for _ in range(PREDICATE_COUNT)) if p is None else tuple(p),
                    bytes(predicate_bytes) if ffr is None else ffr,
                    bytes(length * length) if za is None else za,
                    bytes(LOOKUP_TABLE_BYTES) if zt0 is None else zt0,
                    valid, {} if controls is None else dict(controls), provenance,
                    vl_bytes, case_index, function_index)


def seeded_snapshot(svl_bytes, seed, *, svcr=SVCR_MASK, sme2=True,
                    case_index=0, function_index=0):
    """Deterministic dirty input banks with bounded ordinary FP controls.

    FFR and FPMR receive no architectural validity by default. An observer must
    establish their feature/access provenance before adding comparison credit.
    """
    length = require_sme_length(svl_bytes)
    if type(seed) is not bytes or type(svcr) is not int or svcr & ~SVCR_MASK:
        raise ValueError('A byte seed and known SVCR bits are required')
    def dirty(name, size):
        return hashlib.shake_256(seed + b'\0' + name.encode()).digest(size)
    primary = bytearray(dirty('primary', PRIMARY_BYTES))
    for offset, mask in ((PRIMARY_NZCV_OFFSET, NZCV_MASK),
                         (PRIMARY_FPCR_OFFSET, SEED_FPCR_MASK),
                         (PRIMARY_FPSR_OFFSET, SEED_FPSR_MASK)):
        value, = struct.unpack_from('<I', primary, offset)
        struct.pack_into('<I', primary, offset, value & mask)
    z = tuple(dirty('z' + str(index), length) for index in range(VECTOR_COUNT))
    p = tuple(dirty('p' + str(index), length // BITS_PER_BYTE) for index in range(PREDICATE_COUNT))
    valid = Component.PRIMARY | Component.SVCR | Component.TPIDR2
    if svcr & SVCR_SM:
        valid |= Component.Z | Component.P
    if svcr & SVCR_ZA:
        valid |= Component.ZA
        if sme2:
            valid |= Component.ZT0
    fpcr, fpsr = struct.unpack_from('<II', primary, PRIMARY_FPCR_OFFSET)
    controls = {'svcr': svcr, 'requested_svcr': svcr,
                'tpidr2_el0': int.from_bytes(dirty('tpidr2', 8), 'little'),
                'fpmr': 0, 'requested_fpcr': fpcr, 'requested_fpsr': fpsr}
    return snapshot_from_banks(length, primary=bytes(primary), z=z, p=p,
                               ffr=bytes(length // BITS_PER_BYTE),
                               za=dirty('za', length * length),
                               zt0=dirty('zt0', LOOKUP_TABLE_BYTES), valid=valid,
                               controls=controls, case_index=case_index,
                               function_index=function_index)


def snapshot_to_state(snapshot):
    """Project fixed scalar fields and active banks for pure family algorithms."""
    registers = struct.unpack_from('<' + 'Q' * GENERAL_REGISTER_COUNT, snapshot.primary)
    sp, = struct.unpack_from('<Q', snapshot.primary, PRIMARY_SP_OFFSET)
    nzcv, = struct.unpack_from('<I', snapshot.primary, PRIMARY_NZCV_OFFSET)
    fpcr, fpsr = struct.unpack_from('<II', snapshot.primary, PRIMARY_FPCR_OFFSET)
    return {'x': list(registers), 'sp': sp, 'nzcv': nzcv,
            'z': list(snapshot.z), 'p': [int.from_bytes(row, 'little') for row in snapshot.p],
            'fpcr': fpcr, 'fpsr': fpsr}


def snapshot_from_state(initial, state):
    """Apply a pure state projection while retaining unmodeled snapshot fields.

    The Z bank remains the authoritative input for low V aliases. This helper
    constructs modeled output only; it never fills missing observed components.
    """
    required = {'x', 'sp', 'nzcv', 'z', 'p'}
    if not required <= state.keys() or state.keys() - required - {'fpcr', 'fpsr'}:
        raise ValueError('Pure scalable state projection fields differ')
    registers = state['x']
    if len(registers) != GENERAL_REGISTER_COUNT:
        raise ValueError('Pure scalable state requires X0 through X30')
    for value in [*registers, state['sp']]:
        if type(value) is not int or not 0 <= value < 1 << 64:
            raise ValueError('Scalar projection fields must fit u64')
    for name in ('nzcv', 'fpcr', 'fpsr'):
        if name in state and (type(state[name]) is not int or not 0 <= state[name] < 1 << 32):
            raise ValueError('Scalar projection control must fit u32: ' + name)
    predicates = state['p']
    if len(predicates) != PREDICATE_COUNT:
        raise ValueError('Pure scalable state requires P0 through P15')
    if any(type(value) is not int or not 0 <= value < 1 << initial.svl_bytes for value in predicates):
        raise ValueError('Packed predicate exceeds its active vector length')
    primary = bytearray(initial.primary)
    struct.pack_into('<' + 'Q' * GENERAL_REGISTER_COUNT, primary, 0, *registers)
    struct.pack_into('<Q', primary, PRIMARY_SP_OFFSET, state['sp'])
    struct.pack_into('<I', primary, PRIMARY_NZCV_OFFSET, state['nzcv'])
    for name, offset in (('fpcr', PRIMARY_FPCR_OFFSET), ('fpsr', PRIMARY_FPSR_OFFSET)):
        if name in state:
            struct.pack_into('<I', primary, offset, state[name])
    joined = snapshot_from_banks(initial.svl_bytes, primary=bytes(primary), z=state['z'],
                                 p=tuple(value.to_bytes(initial.svl_bytes // BITS_PER_BYTE, 'little')
                                         for value in predicates), valid=initial.valid)
    return replace(initial, primary=joined.primary, z=joined.z, p=joined.p)


assert HEADER_PREFIX.size + CONTROL_FORMAT.size == HEADER_BYTES
