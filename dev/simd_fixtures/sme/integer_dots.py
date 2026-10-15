"""Independent byte-oriented SME2 integer dot-product semantics.

ZA is the complete SVL-byte by SVL-byte array in ZAvector row order.
These pure models do not assert streaming runtime or hardware support.
"""
from dataclasses import dataclass, replace
import struct

import scalable_frame as frame

BITS_PER_BYTE = 8
SEGMENT_BITS = 128
MIN_SVL_BITS = 128
MAX_SVL_BITS = 2048
REGISTER_COUNT = 32
SELECTOR_SHIFT = 13
SELECTOR_MASK = 3
FIRST_SELECTOR_REGISTER = 8
OFFSET_MASK = 7
INDEX_SHIFT = 10
SIZE_SHIFT = 22


@dataclass(frozen=True)
class Dot:
    accumulator_bits: int
    terms: int
    groups: int
    vertical: bool
    left_signed: bool
    right_signed: bool
    right_selection: str
    left: int = 0
    right: int = 0
    selector: int = FIRST_SELECTOR_REGISTER
    offset: int = 0
    index: int = 0


@dataclass(frozen=True)
class Encoding:
    form: str
    mask: int
    value: int
    operation: Dot
    dynamic_size: bool
    left_shift: int
    left_mask: int
    left_scale: int
    right_shift: int
    right_mask: int
    right_scale: int


# Exact fixed-bit facts and field widths from Arm A64 XML 2026-06.
ENCODINGS = (
    Encoding('sdot_za32_zzi_2xi', 0xfff09038, 0xc1501000,
             Dot(32, 2, 2, False, True, True, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('sdot_za32_zzi_4xi', 0xfff09078, 0xc1509000,
             Dot(32, 2, 4, False, True, True, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('sdot_za32_zzv_2x1', 0xfff09c18, 0xc1601408,
             Dot(32, 2, 2, False, True, True, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('sdot_za32_zzv_4x1', 0xfff09c18, 0xc1701408,
             Dot(32, 2, 4, False, True, True, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('sdot_za32_zzw_2x2', 0xffe19c38, 0xc1e01408,
             Dot(32, 2, 2, False, True, True, 'group'),
             False, 6, 15, 2, 17, 15, 2),
    Encoding('sdot_za32_zzw_4x4', 0xffe39c78, 0xc1e11408,
             Dot(32, 2, 4, False, True, True, 'group'),
             False, 7, 7, 4, 18, 7, 4),
    Encoding('sdot_za_zzi_s2xi', 0xfff09038, 0xc1501020,
             Dot(32, 4, 2, False, True, True, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('sdot_za_zzi_d2xi', 0xfff09838, 0xc1d00008,
             Dot(64, 4, 2, False, True, True, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('sdot_za_zzi_s4xi', 0xfff09078, 0xc1509020,
             Dot(32, 4, 4, False, True, True, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('sdot_za_zzi_d4xi', 0xfff09878, 0xc1d08008,
             Dot(64, 4, 4, False, True, True, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('sdot_za_zzv_2x1', 0xffb09c18, 0xc1201400,
             Dot(32, 4, 2, False, True, True, 'vector'),
             True, 5, 31, 1, 16, 15, 1),
    Encoding('sdot_za_zzv_4x1', 0xffb09c18, 0xc1301400,
             Dot(32, 4, 4, False, True, True, 'vector'),
             True, 5, 31, 1, 16, 15, 1),
    Encoding('sdot_za_zzw_2x2', 0xffa19c38, 0xc1a01400,
             Dot(32, 4, 2, False, True, True, 'group'),
             True, 6, 15, 2, 17, 15, 2),
    Encoding('sdot_za_zzw_4x4', 0xffa39c78, 0xc1a11400,
             Dot(32, 4, 4, False, True, True, 'group'),
             True, 7, 7, 4, 18, 7, 4),
    Encoding('sudot_za_zzi_s2xi', 0xfff09038, 0xc1501038,
             Dot(32, 4, 2, False, True, False, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('sudot_za_zzi_s4xi', 0xfff09078, 0xc1509038,
             Dot(32, 4, 4, False, True, False, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('sudot_za_zzv_s2x1', 0xfff09c18, 0xc1201418,
             Dot(32, 4, 2, False, True, False, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('sudot_za_zzv_s4x1', 0xfff09c18, 0xc1301418,
             Dot(32, 4, 4, False, True, False, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('suvdot_za_zzi_s4xi', 0xfff09078, 0xc1508038,
             Dot(32, 4, 4, True, True, False, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('svdot_za32_zzi_2xi', 0xfff09038, 0xc1500020,
             Dot(32, 2, 2, True, True, True, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('svdot_za_zzi_s4xi', 0xfff09078, 0xc1508020,
             Dot(32, 4, 4, True, True, True, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('svdot_za_zzi_d4xi', 0xfff09878, 0xc1d08808,
             Dot(64, 4, 4, True, True, True, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('udot_za32_zzi_2xi', 0xfff09038, 0xc1501010,
             Dot(32, 2, 2, False, False, False, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('udot_za32_zzi_4xi', 0xfff09078, 0xc1509010,
             Dot(32, 2, 4, False, False, False, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('udot_za32_zzv_2x1', 0xfff09c18, 0xc1601418,
             Dot(32, 2, 2, False, False, False, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('udot_za32_zzv_4x1', 0xfff09c18, 0xc1701418,
             Dot(32, 2, 4, False, False, False, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('udot_za32_zzw_2x2', 0xffe19c38, 0xc1e01418,
             Dot(32, 2, 2, False, False, False, 'group'),
             False, 6, 15, 2, 17, 15, 2),
    Encoding('udot_za32_zzw_4x4', 0xffe39c78, 0xc1e11418,
             Dot(32, 2, 4, False, False, False, 'group'),
             False, 7, 7, 4, 18, 7, 4),
    Encoding('udot_za_zzi_s2xi', 0xfff09038, 0xc1501030,
             Dot(32, 4, 2, False, False, False, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('udot_za_zzi_d2xi', 0xfff09838, 0xc1d00018,
             Dot(64, 4, 2, False, False, False, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('udot_za_zzi_s4xi', 0xfff09078, 0xc1509030,
             Dot(32, 4, 4, False, False, False, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('udot_za_zzi_d4xi', 0xfff09878, 0xc1d08018,
             Dot(64, 4, 4, False, False, False, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('udot_za_zzv_2x1', 0xffb09c18, 0xc1201410,
             Dot(32, 4, 2, False, False, False, 'vector'),
             True, 5, 31, 1, 16, 15, 1),
    Encoding('udot_za_zzv_4x1', 0xffb09c18, 0xc1301410,
             Dot(32, 4, 4, False, False, False, 'vector'),
             True, 5, 31, 1, 16, 15, 1),
    Encoding('udot_za_zzw_2x2', 0xffa19c38, 0xc1a01410,
             Dot(32, 4, 2, False, False, False, 'group'),
             True, 6, 15, 2, 17, 15, 2),
    Encoding('udot_za_zzw_4x4', 0xffa39c78, 0xc1a11410,
             Dot(32, 4, 4, False, False, False, 'group'),
             True, 7, 7, 4, 18, 7, 4),
    Encoding('usdot_za_zzi_s2xi', 0xfff09038, 0xc1501028,
             Dot(32, 4, 2, False, False, True, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('usdot_za_zzi_s4xi', 0xfff09078, 0xc1509028,
             Dot(32, 4, 4, False, False, True, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('usdot_za_zzv_s2x1', 0xfff09c18, 0xc1201408,
             Dot(32, 4, 2, False, False, True, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('usdot_za_zzv_s4x1', 0xfff09c18, 0xc1301408,
             Dot(32, 4, 4, False, False, True, 'vector'),
             False, 5, 31, 1, 16, 15, 1),
    Encoding('usdot_za_zzw_s2x2', 0xffe19c38, 0xc1a01408,
             Dot(32, 4, 2, False, False, True, 'group'),
             False, 6, 15, 2, 17, 15, 2),
    Encoding('usdot_za_zzw_s4x4', 0xffe39c78, 0xc1a11408,
             Dot(32, 4, 4, False, False, True, 'group'),
             False, 7, 7, 4, 18, 7, 4),
    Encoding('usvdot_za_zzi_s4xi', 0xfff09078, 0xc1508028,
             Dot(32, 4, 4, True, False, True, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('uvdot_za32_zzi_2xi', 0xfff09038, 0xc1500030,
             Dot(32, 2, 2, True, False, False, 'indexed'),
             False, 6, 15, 2, 16, 15, 1),
    Encoding('uvdot_za_zzi_s4xi', 0xfff09078, 0xc1508030,
             Dot(32, 4, 4, True, False, False, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
    Encoding('uvdot_za_zzi_d4xi', 0xfff09878, 0xc1d08818,
             Dot(64, 4, 4, True, False, False, 'indexed'),
             False, 7, 7, 4, 16, 15, 1),
)


def decode(word):
    """Structural decode; callers enforce features and streaming/ZA mode."""
    for encoding in ENCODINGS:
        if word & encoding.mask != encoding.value:
            continue
        bits = encoding.operation.accumulator_bits
        if encoding.dynamic_size:
            bits <<= (word >> SIZE_SHIFT) & 1
        return replace(encoding.operation, accumulator_bits=bits,
                       left=((word >> encoding.left_shift) & encoding.left_mask) * encoding.left_scale,
                       right=((word >> encoding.right_shift) & encoding.right_mask) * encoding.right_scale,
                       selector=FIRST_SELECTOR_REGISTER + ((word >> SELECTOR_SHIFT) & SELECTOR_MASK),
                       offset=word & OFFSET_MASK,
                       index=((word >> INDEX_SHIFT) & (SEGMENT_BITS // bits - 1))
                       if encoding.operation.right_selection == 'indexed' else 0)
    return None


def validate(operation, z, za):
    if len(z) != REGISTER_COUNT:
        raise ValueError('Exactly 32 complete Z registers are required')
    svl_bytes = len(z[0])
    svl_bits = svl_bytes * BITS_PER_BYTE
    if not MIN_SVL_BITS <= svl_bits <= MAX_SVL_BITS or svl_bytes & (svl_bytes - 1):
        raise ValueError('SME SVL must be a power of two from 128 through 2048 bits')
    if any(len(register) != svl_bytes for register in z) or len(za) != svl_bytes * svl_bytes:
        raise ValueError('Complete Z and ZA dimensions must match SVL')
    if operation.accumulator_bits not in (32, 64) or operation.terms not in (2, 4):
        raise ValueError('Unsupported dot element dimensions')
    if operation.groups not in (2, 4) or operation.right_selection not in ('vector', 'group', 'indexed'):
        raise ValueError('Invalid source group shape')
    if operation.vertical and (operation.right_selection != 'indexed' or operation.groups != operation.terms):
        raise ValueError('Vertical forms require matching source group and dot term counts')
    if not 0 <= operation.left < REGISTER_COUNT or not 0 <= operation.right < REGISTER_COUNT:
        raise ValueError('Invalid Z register')
    if operation.right_selection == 'group' and operation.right + operation.groups > REGISTER_COUNT:
        raise ValueError('Aligned right source group exceeds register bank')
    if not FIRST_SELECTOR_REGISTER <= operation.selector <= FIRST_SELECTOR_REGISTER + SELECTOR_MASK:
        raise ValueError('Invalid ZA selector register')
    if not 0 <= operation.offset <= OFFSET_MASK:
        raise ValueError('Invalid ZA vector offset')
    if operation.right_selection == 'indexed' and not 0 <= operation.index < SEGMENT_BITS // operation.accumulator_bits:
        raise ValueError('Invalid per-segment index')
    return svl_bytes


def integer(data, index, width, signed):
    start = index * width
    return int.from_bytes(data[start:start + width], 'little', signed=signed)


def execute(operation, z, za, selector_value):
    """Return full ZA after modular accumulation; preserve every untouched byte."""
    svl_bytes = validate(operation, z, za)
    lane_bytes = operation.accumulator_bits // BITS_PER_BYTE
    source_bytes = lane_bytes // operation.terms
    lanes = svl_bytes // lane_bytes
    segment_lanes = SEGMENT_BITS // operation.accumulator_bits
    stride = svl_bytes // operation.groups
    # X(v,32) reads Wv. Addition is mathematical before the modulo; do not
    # truncate Wv+offset in the semantic model before wrapping by stride.
    base = ((selector_value & ((1 << 32) - 1)) + operation.offset) % stride
    result = bytearray(za)
    accumulator_mask = (1 << operation.accumulator_bits) - 1
    for group in range(operation.groups):
        row = base + group * stride
        for lane in range(lanes):
            right_lane = ((lane // segment_lanes) * segment_lanes + operation.index
                          if operation.right_selection == 'indexed' else lane)
            right_register = operation.right + (group if operation.right_selection == 'group' else 0)
            position = row * svl_bytes + lane * lane_bytes
            total = int.from_bytes(za[position:position + lane_bytes], 'little')
            for term in range(operation.terms):
                left_register = (operation.left + (term if operation.vertical else group)) % REGISTER_COUNT
                left_lane = lane * operation.terms + (group if operation.vertical else term)
                right_element = right_lane * operation.terms + term
                total += integer(z[left_register], left_lane, source_bytes, operation.left_signed) * integer(
                    z[right_register], right_element, source_bytes, operation.right_signed)
            result[position:position + lane_bytes] = (total & accumulator_mask).to_bytes(lane_bytes, 'little')
    return bytes(result)


def execute_lanes(operation, z, za, selector_value):
    """Second model: construct source matrices and lane arrays before multiplication."""
    svl_bytes = validate(operation, z, za)
    bits = operation.accumulator_bits // operation.terms
    item_bytes = bits // BITS_PER_BYTE
    lane_bytes = operation.accumulator_bits // BITS_PER_BYTE
    left = [[int.from_bytes(register[i:i + item_bytes], 'little', signed=operation.left_signed)
             for i in range(0, svl_bytes, item_bytes)] for register in z]
    right = [[int.from_bytes(register[i:i + item_bytes], 'little', signed=operation.right_signed)
              for i in range(0, svl_bytes, item_bytes)] for register in z]
    rows = [[int.from_bytes(za[row * svl_bytes + i:row * svl_bytes + i + lane_bytes], 'little')
             for i in range(0, svl_bytes, lane_bytes)] for row in range(svl_bytes)]
    rows_per_partition = svl_bytes // operation.groups
    selected = (selector_value % (1 << 32) + operation.offset) % rows_per_partition
    lanes_per_segment = SEGMENT_BITS // operation.accumulator_bits
    modulus = 1 << operation.accumulator_bits
    for group in range(operation.groups):
        target = rows[selected + group * rows_per_partition]
        for lane in range(len(target)):
            selected_right_lane = lane
            if operation.right_selection == 'indexed':
                selected_right_lane = lane - lane % lanes_per_segment + operation.index
            right_register = operation.right if operation.right_selection != 'group' else operation.right + group
            products = []
            for term in range(operation.terms):
                if operation.vertical:
                    left_register = (operation.left + term) % REGISTER_COUNT
                    left_index = lane * operation.terms + group
                else:
                    left_register = (operation.left + group) % REGISTER_COUNT
                    left_index = lane * operation.terms + term
                products.append(left[left_register][left_index] * right[right_register][selected_right_lane * operation.terms + term])
            target[lane] = (target[lane] + sum(products)) % modulus
    return b''.join(value.to_bytes(lane_bytes, 'little') for row in rows for value in row)


# The shared observer owns serialization and observation validity. FFR/FPMR
# receive no credit unless the observer establishes their independent access.
REQUIRED_COMPONENTS = (frame.Component.PRIMARY | frame.Component.Z | frame.Component.P |
                       frame.Component.ZA | frame.Component.ZT0 | frame.Component.SVCR |
                       frame.Component.TPIDR2)
GPR_BYTES = 8


def expected(operation, initial, ram=None):
    """Recompute selected ZA rows without changing any other frame component."""
    if not isinstance(initial, frame.Snapshot):
        raise TypeError('SME integer dot fixtures require a scalable Snapshot')
    needed = frame.Component.PRIMARY | frame.Component.Z | frame.Component.ZA | frame.Component.SVCR
    if initial.valid & needed != needed:
        raise ValueError('SME integer dot input lacks primary/Z/ZA/SVCR validity')
    if initial.control('svcr') & frame.SVCR_MASK != frame.SVCR_MASK:
        raise ValueError('SME integer dot execution requires streaming mode and ZA')
    operand = decode(operation['word'])
    if operand is None:
        raise ValueError('Word does not allocate an SME integer dot form')
    selector, = struct.unpack_from('<I', initial.primary, operand.selector * GPR_BYTES)
    za = execute(operand, initial.z, initial.za, selector)
    return replace(initial, za=za, provenance=frame.Provenance.MODEL), ram, None


def scalable_cases(svl_bytes):
    """All canonical forms, dynamic widths, aliases, indices and wrap cases."""
    frame.require_sme_length(svl_bytes)
    case_index = 0
    function_index = 0
    for encoding in ENCODINGS:
        for size in range(1 + encoding.dynamic_size):
            for variant in range(3):
                word = encoding.value | (size << SIZE_SHIFT)
                if variant:
                    word |= (encoding.left_mask << encoding.left_shift)
                    word |= (encoding.right_mask << encoding.right_shift)
                    word |= SELECTOR_MASK << SELECTOR_SHIFT | OFFSET_MASK
                    bits = encoding.operation.accumulator_bits << size
                    if encoding.operation.right_selection == 'indexed':
                        word |= (SEGMENT_BITS // bits - 1) << INDEX_SHIFT
                operand = decode(word)
                operation = {'word': word, 'canonical_id': encoding.form,
                             'family': 'sme_integer_dots', 'accumulator_bits': operand.accumulator_bits,
                             'terms': operand.terms, 'groups': operand.groups, 'vertical': operand.vertical,
                             'left_signed': operand.left_signed, 'right_signed': operand.right_signed}
                initial = frame.seeded_snapshot(svl_bytes, word.to_bytes(4, 'little') + bytes([variant]),
                                                case_index=case_index, function_index=function_index)
                primary = bytearray(initial.primary)
                selector = (0, 0xffffffff, 0xffffffffffffffff)[variant]
                struct.pack_into('<Q', primary, operand.selector * GPR_BYTES, selector)
                initial = replace(initial, primary=bytes(primary))
                if variant == 2:
                    # Extreme signed halfword products expose the PMADDWD-to-64
                    # overflow trap; mixed byte products expose signedness swaps.
                    source_bytes = operand.accumulator_bits // operand.terms // BITS_PER_BYTE
                    minimum = 1 << (source_bytes * BITS_PER_BYTE - 1)
                    pattern = minimum.to_bytes(source_bytes, 'little')
                    z = tuple(pattern * (svl_bytes // source_bytes) for _ in range(REGISTER_COUNT))
                    initial = frame.snapshot_from_banks(
                        svl_bytes, primary=initial.primary, z=z, p=initial.p, ffr=initial.ffr,
                        za=bytes([255]) * (svl_bytes * svl_bytes), zt0=initial.zt0,
                        valid=initial.valid, controls=initial.controls,
                        case_index=case_index, function_index=function_index)
                result, _, _ = expected(operation, initial)
                yield {'operation': operation, 'initial': initial, 'expected': result,
                       'required': REQUIRED_COMPONENTS}
                case_index += 1
                function_index += 1
