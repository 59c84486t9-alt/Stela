"""Independent finite-value model for SVE floating immediate copies."""

import math
import struct

from scalable_frame import snapshot_from_banks

FCPY_MASK = 0xff30e000
FCPY_OPCODE = 0x0510c000
FDUP_MASK = 0xff3fe000
FDUP_OPCODE = 0x2539c000
SIZE_SHIFT = 22
SIZE_MASK = 3
REGISTER_MASK = 31
PREDICATE_SHIFT = 16
PREDICATE_MASK = 15
IMMEDIATE_SHIFT = 5
IMMEDIATE_MASK = 255
SIGN_MASK = 128
FRACTION_MASK = 15
EXPONENT_SHIFT = 4
EXPONENT_MASK = 7
EXPONENT_SIGN_BIAS = 4
EXPONENT_OFFSET = 3
SIGNIFICAND_SCALE = 16
BITS_PER_BYTE = 8
FORMATS = {1: 'e', 2: 'f', 3: 'd'}


def expected(word, initial):
    """Expand an exact finite VFP immediate; preserve every unrelated component."""
    if word & FCPY_MASK == FCPY_OPCODE:
        predicate = initial.p[(word >> PREDICATE_SHIFT) & PREDICATE_MASK]
    elif word & FDUP_MASK == FDUP_OPCODE:
        predicate = None
    else:
        raise ValueError('Not an FCPY/FDUP word')
    size = (word >> SIZE_SHIFT) & SIZE_MASK
    if size not in FORMATS:
        raise ValueError('Reserved floating immediate element size')
    immediate = (word >> IMMEDIATE_SHIFT) & IMMEDIATE_MASK
    exponent = (((immediate >> EXPONENT_SHIFT) & EXPONENT_MASK) ^ EXPONENT_SIGN_BIAS) - EXPONENT_OFFSET
    significand = (SIGNIFICAND_SCALE + (immediate & FRACTION_MASK)) / SIGNIFICAND_SCALE
    value = math.ldexp(-significand if immediate & SIGN_MASK else significand, exponent)
    lane = struct.pack('<' + FORMATS[size], value)
    destination = word & REGISTER_MASK
    result = bytearray(initial.z[destination])
    for offset in range(0, initial.svl_bytes, len(lane)):
        if predicate is None or (predicate[offset // BITS_PER_BYTE] >> (offset % BITS_PER_BYTE)) & 1:
            result[offset:offset + len(lane)] = lane
    z = list(initial.z)
    z[destination] = bytes(result)
    return snapshot_from_banks(
        initial.svl_bytes, primary=initial.primary, z=z, p=initial.p,
        ffr=initial.ffr, za=initial.za, zt0=initial.zt0, valid=initial.valid,
        controls=initial.controls, function_index=initial.function_index,
        case_index=initial.case_index,
    )
