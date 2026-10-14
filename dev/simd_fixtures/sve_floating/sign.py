"""Independent bitwise model for predicated streaming FABS and FNEG."""

import struct

from scalable_frame import snapshot_from_banks

OPCODE_MASK = 0xff3fe000
ABSOLUTE_OPCODE = 0x041ca000
NEGATE_OPCODE = 0x041da000
SIZE_SHIFT = 22
SIZE_MASK = 3
SOURCE_SHIFT = 5
REGISTER_MASK = 31
PREDICATE_SHIFT = 10
PREDICATE_MASK = 7
FPCR_OFFSET = 776
FPCR_AH = 1 << 1
BITS_PER_BYTE = 8
# Size encoding: (element bytes, fraction bits).
FORMATS = {1: (2, 10), 2: (4, 23), 3: (8, 52)}


def expected(word, initial):
    """Preserve every component except active destination sign bits."""
    opcode = word & OPCODE_MASK
    size = (word >> SIZE_SHIFT) & SIZE_MASK
    if opcode not in (ABSOLUTE_OPCODE, NEGATE_OPCODE) or size not in FORMATS:
        raise ValueError('Not an allocated FABS/FNEG word')
    lane_bytes, fraction_bits = FORMATS[size]
    source = (word >> SOURCE_SHIFT) & REGISTER_MASK
    destination = word & REGISTER_MASK
    predicate = (word >> PREDICATE_SHIFT) & PREDICATE_MASK
    fpcr = struct.unpack_from('<I', initial.primary, FPCR_OFFSET)[0]
    sign = 1 << (lane_bytes * BITS_PER_BYTE - 1)
    fraction = (1 << fraction_bits) - 1
    exponent = (sign - 1) & ~fraction
    result = bytearray(initial.z[destination])
    for offset in range(0, initial.svl_bytes, lane_bytes):
        if not (initial.p[predicate][offset // BITS_PER_BYTE] >> (offset % BITS_PER_BYTE)) & 1:
            continue
        value = int.from_bytes(initial.z[source][offset:offset + lane_bytes], 'little')
        is_nan = value & exponent == exponent and value & fraction != 0
        if not (fpcr & FPCR_AH and is_nan):
            value = value & ~sign if opcode == ABSOLUTE_OPCODE else value ^ sign
        result[offset:offset + lane_bytes] = value.to_bytes(lane_bytes, 'little')
    z = list(initial.z)
    z[destination] = bytes(result)
    return snapshot_from_banks(
        initial.svl_bytes, primary=initial.primary, z=z, p=initial.p,
        ffr=initial.ffr, za=initial.za, zt0=initial.zt0, valid=initial.valid,
        controls=initial.controls, function_index=initial.function_index,
        case_index=initial.case_index,
    )
