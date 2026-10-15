"""Pure SME2 integer multi-vector decode and register semantics.

Uses architectural little-endian Z banks. SME forms require SME2 and SM=1;
six transferred pair-N forms also permit SVE2.1 non-streaming access.
ZA and predicates are untouched. Saturation preserves FPSR.QC. Mode/access
exceptions belong to the execution boundary, not this register-only model.
"""
from __future__ import annotations
from dataclasses import dataclass
import itertools
import random

import scalable_frame as frame

_ENCODINGS = (
    ('add_mz_zzv_2x1', 'ADD', 0xff30ffe1, 0xc120a300),
    ('add_mz_zzv_4x1', 'ADD', 0xff30ffe3, 0xc120ab00),
    ('sclamp_mz_zz_2', 'SCLAMP', 0xff20fc01, 0xc120c400),
    ('sclamp_mz_zz_4', 'SCLAMP', 0xff20fc03, 0xc120cc00),
    ('smax_mz_zzv_2x1', 'SMAX', 0xff30ffe1, 0xc120a000),
    ('smax_mz_zzv_4x1', 'SMAX', 0xff30ffe3, 0xc120a800),
    ('smax_mz_zzw_2x2', 'SMAX', 0xff21ffe1, 0xc120b000),
    ('smax_mz_zzw_4x4', 'SMAX', 0xff23ffe3, 0xc120b800),
    ('smin_mz_zzv_2x1', 'SMIN', 0xff30ffe1, 0xc120a020),
    ('smin_mz_zzv_4x1', 'SMIN', 0xff30ffe3, 0xc120a820),
    ('smin_mz_zzw_2x2', 'SMIN', 0xff21ffe1, 0xc120b020),
    ('smin_mz_zzw_4x4', 'SMIN', 0xff23ffe3, 0xc120b820),
    ('sqcvt_z_mz2_', 'SQCVT', 0xfffffc20, 0xc123e000),
    ('sqcvt_z_mz4_', 'SQCVT', 0xff7ffc60, 0xc133e000),
    ('sqcvtn_z_mz4_', 'SQCVTN', 0xff7ffc60, 0xc133e040),
    ('sqcvtu_z_mz2_', 'SQCVTU', 0xfffffc20, 0xc163e000),
    ('sqcvtu_z_mz4_', 'SQCVTU', 0xff7ffc60, 0xc173e000),
    ('sqcvtun_z_mz4_', 'SQCVTUN', 0xff7ffc60, 0xc173e040),
    ('sqdmulh_mz_zzv_2x1', 'SQDMULH', 0xff30ffe1, 0xc120a400),
    ('sqdmulh_mz_zzv_4x1', 'SQDMULH', 0xff30ffe3, 0xc120ac00),
    ('sqdmulh_mz_zzw_2x2', 'SQDMULH', 0xff21ffe1, 0xc120b400),
    ('sqdmulh_mz_zzw_4x4', 'SQDMULH', 0xff23ffe3, 0xc120bc00),
    ('sqrshr_z_mz2_', 'SQRSHR', 0xfff0fc20, 0xc1e0d400),
    ('sqrshr_z_mz4_', 'SQRSHR', 0xff20fc60, 0xc120d800),
    ('sqrshrn_z_mz4_', 'SQRSHRN', 0xff20fc60, 0xc120dc00),
    ('sqrshru_z_mz2_', 'SQRSHRU', 0xfff0fc20, 0xc1f0d400),
    ('sqrshru_z_mz4_', 'SQRSHRU', 0xff20fc60, 0xc120d840),
    ('sqrshrun_z_mz4_', 'SQRSHRUN', 0xff20fc60, 0xc120dc40),
    ('srshl_mz_zzv_2x1', 'SRSHL', 0xff30ffe1, 0xc120a220),
    ('srshl_mz_zzv_4x1', 'SRSHL', 0xff30ffe3, 0xc120aa20),
    ('srshl_mz_zzw_2x2', 'SRSHL', 0xff21ffe1, 0xc120b220),
    ('srshl_mz_zzw_4x4', 'SRSHL', 0xff23ffe3, 0xc120ba20),
    ('uclamp_mz_zz_2', 'UCLAMP', 0xff20fc01, 0xc120c401),
    ('uclamp_mz_zz_4', 'UCLAMP', 0xff20fc03, 0xc120cc01),
    ('umax_mz_zzv_2x1', 'UMAX', 0xff30ffe1, 0xc120a001),
    ('umax_mz_zzv_4x1', 'UMAX', 0xff30ffe3, 0xc120a801),
    ('umax_mz_zzw_2x2', 'UMAX', 0xff21ffe1, 0xc120b001),
    ('umax_mz_zzw_4x4', 'UMAX', 0xff23ffe3, 0xc120b801),
    ('umin_mz_zzv_2x1', 'UMIN', 0xff30ffe1, 0xc120a021),
    ('umin_mz_zzv_4x1', 'UMIN', 0xff30ffe3, 0xc120a821),
    ('umin_mz_zzw_2x2', 'UMIN', 0xff21ffe1, 0xc120b021),
    ('umin_mz_zzw_4x4', 'UMIN', 0xff23ffe3, 0xc120b821),
    ('uqcvt_z_mz2_', 'UQCVT', 0xfffffc20, 0xc123e020),
    ('uqcvt_z_mz4_', 'UQCVT', 0xff7ffc60, 0xc133e020),
    ('uqcvtn_z_mz4_', 'UQCVTN', 0xff7ffc60, 0xc133e060),
    ('uqrshr_z_mz2_', 'UQRSHR', 0xfff0fc20, 0xc1e0d420),
    ('uqrshr_z_mz4_', 'UQRSHR', 0xff20fc60, 0xc120d820),
    ('uqrshrn_z_mz4_', 'UQRSHRN', 0xff20fc60, 0xc120dc20),
    ('urshl_mz_zzv_2x1', 'URSHL', 0xff30ffe1, 0xc120a221),
    ('urshl_mz_zzv_4x1', 'URSHL', 0xff30ffe3, 0xc120aa21),
    ('urshl_mz_zzw_2x2', 'URSHL', 0xff21ffe1, 0xc120b221),
    ('urshl_mz_zzw_4x4', 'URSHL', 0xff23ffe3, 0xc120ba21),
    ('sqcvtn_z_mz2_', 'SQCVTN', 0xfffffc20, 0x45314000),
    ('sqcvtun_z_mz2_', 'SQCVTUN', 0xfffffc20, 0x45315000),
    ('sqrshrn_z_mz2_', 'SQRSHRN', 0xfff0fc20, 0x45b02800),
    ('sqrshrun_z_mz2_', 'SQRSHRUN', 0xfff0fc20, 0x45b00800),
    ('uqcvtn_z_mz2_', 'UQCVTN', 0xfffffc20, 0x45314800),
    ('uqrshrn_z_mz2_', 'UQRSHRN', 0xfff0fc20, 0x45b03800),
)

BITS_PER_BYTE = 8
MIN_SVL_BITS = 128
MAX_SVL_BITS = 2048
LEGAL_SVLS_BITS = (128, 256, 512, 1024, 2048)
Z_REGISTER_COUNT = 32
SIZE_SHIFT = 22
SIZE_MASK = 3
GROUP_DESTINATION_SHIFT = 1
SOURCE_SINGLE_SHIFT = 16
SOURCE_PAIR_SHIFT = 17
SOURCE_QUAD_SHIFT = 18
CLAMP_LOWER_SHIFT = 5
CLAMP_UPPER_SHIFT = 16
REGISTER_MASK = 31


@dataclass(frozen=True)
class ArithmeticOperation:
    form_id: str
    mnemonic: str
    destination: int
    right: int
    group: int
    element_bits: int
    right_grouped: bool
    lower: int = 0


FORMS = tuple({'id': name, 'mnemonic': mnemonic, 'encoding_mask': hex(mask),
               'encoding_value': hex(opcode)}
              for name, mnemonic, mask, opcode in _ENCODINGS
              if not any(key in name for key in ('cvt', 'rshr')))


def arithmetic_decode(word):
    for form in FORMS:
        if word & int(form['encoding_mask'], 16) != int(form['encoding_value'], 16):
            continue
        form_id = form['id']
        group = 2 if form_id.endswith(('2x1', '2x2', '_2')) else 4
        destination = word & (Z_REGISTER_COUNT - group)
        grouped = 'zzw' in form_id
        clamp = 'clamp' in form_id
        if clamp:
            right = (word >> CLAMP_UPPER_SHIFT) & REGISTER_MASK
        elif grouped:
            shift = SOURCE_PAIR_SHIFT if group == 2 else SOURCE_QUAD_SHIFT
            right = ((word >> shift) & (REGISTER_MASK // group)) * group
        else:
            right = (word >> SOURCE_SINGLE_SHIFT) & 15
        return ArithmeticOperation(form_id, form['mnemonic'], destination, right,
                                   group, BITS_PER_BYTE << ((word >> SIZE_SHIFT) & SIZE_MASK),
                                   grouped, (word >> CLAMP_LOWER_SHIFT) & REGISTER_MASK if clamp else 0)
    return None


def signed(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def element_result(operation, left, right, lower=0):
    bits = operation.element_bits
    mask = (1 << bits) - 1
    mnemonic = operation.mnemonic
    if mnemonic == 'ADD':
        return (left + right) & mask
    unsigned = mnemonic.startswith('U')
    if not unsigned:
        left, right, lower = (signed(value, bits) for value in (left, right, lower))
    if mnemonic.endswith('MAX'):
        value = max(left, right)
    elif mnemonic.endswith('MIN'):
        value = min(left, right)
    elif mnemonic.endswith('CLAMP'):
        value = min(max(lower, left), right)
    elif mnemonic == 'SQDMULH':
        value = (2 * left * right) >> bits
        value = min(max(value, -(1 << (bits - 1))), (1 << (bits - 1)) - 1)
    elif mnemonic.endswith('RSHL'):
        # Shift is the whole signed element even for unsigned data operations.
        shift = signed(right, bits) if unsigned else right
        limit = bits + 1
        shift = min(max(shift, -limit), limit)
        value = left << shift if shift >= 0 else (left + (1 << (-shift - 1))) >> -shift
    else:
        raise ValueError(mnemonic)
    return value & mask


def arithmetic_execute(operation, registers, svl_bits):
    if svl_bits not in LEGAL_SVLS_BITS:
        raise ValueError('SME SVL must be a power of two in 128..2048')
    svl_bytes = svl_bits // BITS_PER_BYTE
    if len(registers) != Z_REGISTER_COUNT or any(len(z) != svl_bytes for z in registers):
        raise ValueError('Each of 32 Z registers must contain exactly SVL bytes')
    original = tuple(bytes(z) for z in registers)
    results = list(original)
    width = operation.element_bits // BITS_PER_BYTE
    for r in range(operation.group):
        destination = operation.destination + r
        right = operation.right + (r if operation.right_grouped else 0)
        output = bytearray(svl_bytes)
        for offset in range(0, svl_bytes, width):
            left_value = int.from_bytes(original[destination][offset:offset + width], 'little')
            right_value = int.from_bytes(original[right][offset:offset + width], 'little')
            lower_value = int.from_bytes(original[operation.lower][offset:offset + width], 'little')
            output[offset:offset + width] = element_result(operation, left_value, right_value, lower_value).to_bytes(width, 'little')
        results[destination] = bytes(output)
    return tuple(results)


NARROW_DESTINATION_REGISTER_MASK = 31
NARROW_SOURCE_PAIR_SHIFT = 6
NARROW_SOURCE_PAIR_MASK = 15
NARROW_SOURCE_QUARTET_SHIFT = 7
NARROW_SOURCE_QUARTET_MASK = 7
NARROW_SIZE_SHIFT = 23
NARROW_TSIZE_SHIFT = 22
NARROW_TSIZE_MASK = 3
NARROW_IMMEDIATE_SHIFT = 16
NARROW_PAIR_IMMEDIATE_MASK = 15
NARROW_QUARTET_IMMEDIATE_MASK = 31

TRANSFERRED_SVE_FORMS = frozenset(('sqcvtn_z_mz2_', 'sqcvtun_z_mz2_', 'sqrshrn_z_mz2_', 'sqrshrun_z_mz2_', 'uqcvtn_z_mz2_', 'uqrshrn_z_mz2_'))

NARROW_FORMS = tuple({'id': name, 'mnemonic': mnemonic, 'encoding_mask': hex(mask),
                      'encoding_value': hex(opcode)}
                     for name, mnemonic, mask, opcode in _ENCODINGS
                     if any(key in name for key in ('cvt', 'rshr')))


class ReservedEncoding(ValueError):
    """A matched instruction class has an unallocated element-size encoding."""


@dataclass(frozen=True)
class NarrowOperation:
    form_id: str
    mnemonic: str
    destination: int
    source_base: int
    group: int
    source_bits: int
    destination_bits: int
    shift: int
    source_signed: bool
    destination_signed: bool
    interleaved: bool
    streaming_only: bool = True


def narrowing_decode(word: int) -> NarrowOperation | None:
    if not 0 <= word < (1 << 32):
        raise ValueError('instruction must be a 32-bit word')
    for form in NARROW_FORMS:
        mask = int(form['encoding_mask'], 16)
        if word & mask != int(form['encoding_value'], 16):
            continue
        mnemonic = form['mnemonic']
        group = 2 if '_mz2_' in form['id'] else 4
        is_shift = 'RSHR' in mnemonic
        if group == 2:
            destination_bits = 16
            source_base = ((word >> NARROW_SOURCE_PAIR_SHIFT) & NARROW_SOURCE_PAIR_MASK) * group
            shift = destination_bits - ((word >> NARROW_IMMEDIATE_SHIFT) & NARROW_PAIR_IMMEDIATE_MASK) if is_shift else 0
        else:
            source_base = ((word >> NARROW_SOURCE_QUARTET_SHIFT) & NARROW_SOURCE_QUARTET_MASK) * group
            if is_shift:
                tsize = (word >> NARROW_TSIZE_SHIFT) & NARROW_TSIZE_MASK
                if tsize == 0:
                    raise ReservedEncoding('quartet narrowing shift tsize=0')
                destination_bits = BITS_PER_BYTE << (tsize.bit_length() - 1)
                immediate = (tsize << 5) | ((word >> NARROW_IMMEDIATE_SHIFT) & NARROW_QUARTET_IMMEDIATE_MASK)
                shift = BITS_PER_BYTE * destination_bits - immediate
            else:
                destination_bits = BITS_PER_BYTE << ((word >> NARROW_SIZE_SHIFT) & 1)
                shift = 0
        source_signed = mnemonic.startswith('S')
        destination_signed = source_signed and ('CVTU' not in mnemonic and 'RSHRU' not in mnemonic)
        return NarrowOperation(
            form_id=form['id'], mnemonic=mnemonic,
            destination=word & NARROW_DESTINATION_REGISTER_MASK,
            source_base=source_base, group=group,
            source_bits=group * destination_bits,
            destination_bits=destination_bits, shift=shift,
            source_signed=source_signed, destination_signed=destination_signed,
            interleaved=mnemonic.endswith('N'),
            streaming_only=form['id'] not in TRANSFERRED_SVE_FORMS,
        )
    return None


def narrowing_execute(state: list[bytes], word: int, svl_bits: int) -> list[bytes]:
    """Return a new Z bank, preserving every source on destination overlap.

    No flags, FPSR.QC, FPCR, predicate, ZA, memory or mode status is modified.
    Access traps and absent FEAT_SME2 are external to this register-only model.
    """
    operation = narrowing_decode(word)
    if operation is None:
        raise ValueError('word is outside the narrowing subset')
    if svl_bits not in LEGAL_SVLS_BITS:
        raise ValueError('SME SVL must be a power of two in [128, 2048]')
    vector_bytes = svl_bits // BITS_PER_BYTE
    if len(state) != Z_REGISTER_COUNT or any(type(z) is not bytes or len(z) != vector_bytes for z in state):
        raise ValueError('state requires exactly 32 immutable Z vectors of SVL bits')
    source_bytes = operation.source_bits // BITS_PER_BYTE
    destination_bytes = operation.destination_bits // BITS_PER_BYTE
    elements = svl_bits // operation.source_bits
    result = bytearray(vector_bytes)
    lower = -(1 << (operation.destination_bits - 1)) if operation.destination_signed else 0
    upper = (1 << (operation.destination_bits - int(operation.destination_signed))) - 1
    destination_mask = (1 << operation.destination_bits) - 1
    for register_offset in range(operation.group):
        source = state[operation.source_base + register_offset]
        for element in range(elements):
            start = element * source_bytes
            value = int.from_bytes(source[start:start + source_bytes], 'little', signed=operation.source_signed)
            if operation.shift:
                value = (value + (1 << (operation.shift - 1))) >> operation.shift
            value = min(upper, max(lower, value)) & destination_mask
            index = element * operation.group + register_offset if operation.interleaved else register_offset * elements + element
            start = index * destination_bytes
            result[start:start + destination_bytes] = value.to_bytes(destination_bytes, 'little')
    output = list(state)
    output[operation.destination] = bytes(result)
    return output


def decode(word):
    if type(word) is not int or not 0 <= word < (1 << 32):
        raise ValueError('instruction must be a 32-bit word')
    operation = arithmetic_decode(word)
    return operation if operation is not None else narrowing_decode(word)


def execute(registers, word, svl_bits):
    operation = decode(word)
    if isinstance(operation, ArithmeticOperation):
        return arithmetic_execute(operation, registers, svl_bits)
    if isinstance(operation, NarrowOperation):
        return tuple(narrowing_execute(list(registers), word, svl_bits))
    raise ValueError('word is outside SME2 integer multi-vector forms')


CORPUS_SEED = 0x534D45324E415252

def arithmetic_cases(svl_bytes):
    random_source = random.Random(0x534d4532)
    for form in FORMS:
        group = 2 if form['id'].endswith(('2x1', '2x2', '_2')) else 4
        clamp = 'clamp' in form['id']
        grouped = 'zzw' in form['id']
        source_shift = 16 if clamp or not grouped else 17 if group == 2 else 18
        for size in range(4):
            width = 1 << size
            bits = width * 8
            mask = (1 << bits) - 1
            for alias in ('distinct', 'first', 'last'):
                destination = 4
                source = 12 if alias == 'distinct' else destination if alias == 'first' else destination + group - 1
                if grouped: source = source // group * group
                lower = 20 if alias == 'distinct' else destination + group - 1
                word = int(form['encoding_value'], 16) | size << 22 | destination | (source // group if grouped else source) << source_shift
                if clamp: word |= lower << 5
                operation = decode(word)
                registers = [random_source.randbytes(svl_bytes) for _ in range(Z_REGISTER_COUNT)]
                values = (0, mask, 1 << (bits - 1), (1 << (bits - 1)) - 1, 1, 3, mask - 2)
                shifts = (0, 1, mask, bits, (-bits) & mask, bits + 1, (-bits - 1) & mask, 256 & mask, (-256) & mask)
                for r in range(group):
                    registers[destination + r] = b''.join(values[e % len(values)].to_bytes(width, 'little') for e in range(svl_bytes // width))
                for r in range(group if grouped else 1):
                    registers[source + r] = b''.join((shifts if form['mnemonic'].endswith('RSHL') else values)[e % len(shifts if form['mnemonic'].endswith('RSHL') else values)].to_bytes(width, 'little') for e in range(svl_bytes // width))
                if clamp:
                    registers[lower] = b''.join(values[(e + 3) % len(values)].to_bytes(width, 'little') for e in range(svl_bytes // width))
                yield {'word': word, 'operation': operation, 'initial': tuple(registers), 'alias': alias,
                               'expected': arithmetic_execute(operation, registers, svl_bytes * BITS_PER_BYTE)}


def configurations(form):
    """Yield group, destination bits, shift, and allocated size/immediate fields."""
    group = 2 if '_mz2_' in form['id'] else 4
    shifted = 'RSHR' in form['mnemonic']
    if group == 2:
        for immediate in range(16) if shifted else [0]:
            yield group, 16, 16 - immediate if shifted else 0, immediate << 16
    elif shifted:
        for tsize in [1, 2, 3]:
            bits = 8 if tsize == 1 else 16
            for immediate in range(32):
                yield group, bits, BITS_PER_BYTE * bits - ((tsize << 5) | immediate), (tsize << 22) | (immediate << 16)
    else:
        for size in [0, 1]:
            yield group, BITS_PER_BYTE << size, 0, size << 23


def boundary_patterns(operation):
    """Two eight-value sets cover source extremes and output/rounding thresholds."""
    source_mask = (1 << operation.source_bits) - 1
    source_sign = 1 << (operation.source_bits - 1)
    maximum = (1 << (operation.destination_bits - int(operation.destination_signed))) - 1
    minimum = -(1 << (operation.destination_bits - 1)) if operation.destination_signed else 0
    extrema = [0, 1, source_mask, source_mask - 1, source_sign, source_sign - 1, 2, (-2) & source_mask]
    if operation.shift:
        half = 1 << (operation.shift - 1)
        thresholds = [half - 1, half, half + 1, -half - 1, -half,
                      (maximum << operation.shift) + half - 1,
                      (maximum << operation.shift) + half,
                      (minimum << operation.shift) - half]
    else:
        thresholds = [minimum - 1, minimum, minimum + 1, maximum - 1, maximum, maximum + 1, 3, 4]
    return [[value & source_mask for value in pattern] for pattern in [extrema, thresholds]]


def narrowing_cases(svl_bytes, *, representative=False):
    """Return immutable input/output Z banks for all forms and allocated fields.

    `operation` is a frozen NarrowOperation. `alias` identifies the destination's
    position in its source group; distinct destinations are outside that group.
    `pattern` and `source_group` are supplementary identity fields. SME access,
    features and flags are supplied by the shared full-Snapshot adapter.
    """
    if svl_bytes * BITS_PER_BYTE not in LEGAL_SVLS_BITS:
        raise ValueError('SME SVL must be 16, 32, 64, 128 or 256 bytes')
    for form_index, form in enumerate(NARROW_FORMS):
        for configuration_index, (group, bits, shift, fields) in enumerate(configurations(form)):
            if representative and shift and shift not in {1, bits // 2, bits, group * bits // 2, group * bits}:
                continue
            for source in [0, Z_REGISTER_COUNT - group]:
                encoded_source = (source // group) << (6 if group == 2 else 7)
                word_base = int(form['encoding_value'], 16) | fields | encoded_source
                operation = narrowing_decode(word_base)
                source_bytes = operation.source_bits // BITS_PER_BYTE
                elements = svl_bytes // source_bytes
                for pattern_index, values in enumerate(boundary_patterns(operation)):
                    seed = CORPUS_SEED ^ (svl_bytes << 40) ^ (form_index << 32) ^ (configuration_index << 16) ^ (source << 8) ^ pattern_index
                    rng = random.Random(seed)
                    state = [rng.randbytes(svl_bytes) for _ in range(Z_REGISTER_COUNT)]
                    for register in range(group):
                        state[source + register] = b''.join(values[(register * elements + lane) % len(values)].to_bytes(source_bytes, 'little') for lane in range(elements))
                    initial = tuple(state)
                    distinct = Z_REGISTER_COUNT - 1 if source == 0 else 0
                    for destination in [*range(source, source + group), distinct]:
                        word = word_base | destination
                        operation = narrowing_decode(word)
                        yield {
                            'word': word,
                            'operation': operation,
                            'initial': initial,
                            'expected': tuple(narrowing_execute(state, word, svl_bytes * BITS_PER_BYTE)),
                            'alias': f'source-{destination - source}' if source <= destination < source + group else 'distinct',
                            'pattern': 'source-extrema' if pattern_index == 0 else 'output-rounding-boundaries',
                            'source_group': source,
                        }


def expected(operation, initial, ram=None):
    registers = execute(initial.z, operation['word'], initial.svl_bytes * BITS_PER_BYTE)
    result = frame.snapshot_from_banks(
        initial.svl_bytes, primary=initial.primary, z=registers, p=initial.p,
        ffr=initial.ffr, za=initial.za, zt0=initial.zt0, valid=initial.valid,
        controls=initial.controls, provenance=frame.Provenance.MODEL,
        vl_bytes=initial.vl_bytes, case_index=initial.case_index,
        function_index=initial.function_index)
    return result, ram, None


def scalable_cases(svl_bytes):
    """Lazy full-state cases, with architectural validity from the shared frame.

    The focused cohort includes every form, width, shift boundary and source
    alias. Exhaustive immediate and field models are retained separately.
    """
    frame.require_sme_length(svl_bytes)
    inputs = itertools.chain(arithmetic_cases(svl_bytes),
                             narrowing_cases(svl_bytes, representative=True))
    for index, case in enumerate(inputs):
        typed = case['operation']
        operation = {'word': case['word'], 'canonical_id': typed.form_id,
                     'alias': case['alias'],
                     'streaming_only': getattr(typed, 'streaming_only', True)}
        mode = frame.SVCR_SM | (frame.SVCR_ZA if index % 2 else 0)
        initial = frame.seeded_snapshot(svl_bytes,
                    ('sme-integer-vector:' + str(index)).encode(), svcr=mode,
                    case_index=index, function_index=index)
        initial = frame.snapshot_from_banks(
            svl_bytes, primary=initial.primary, z=case['initial'], p=initial.p,
            ffr=initial.ffr, za=initial.za, zt0=initial.zt0, valid=initial.valid,
            controls=initial.controls, case_index=index, function_index=index)
        result, _, _ = expected(operation, initial)
        yield {'operation': operation, 'initial': initial, 'expected': result,
               'required': initial.valid}
