"""Fixed AdvSIMD FP8 conversion layouts and complete-state mathematical cases.

Numerical expectations use the independent Fraction model in fp8.py. Original
execution is supplied separately by the FPMR-enabled architectural observer.
"""
from dataclasses import replace
import struct

import scalable_frame as frame
from simd_fixtures import fp8

ENCODINGS = (
    ('BF1CVTL_asimdmisc_V', 0x2ea17800, 'bfloat16', True, False),
    ('BF2CVTL_asimdmisc_V', 0x2ee17800, 'bfloat16', True, True),
    ('F1CVTL_asimdmisc_V', 0x2e217800, 'half', True, False),
    ('F2CVTL_asimdmisc_V', 0x2e617800, 'half', True, True),
    ('FCVTN_asimdsame2_D', 0x0e40f400, 'half', False, False),
    ('FCVTN_asimdsame2_H', 0x0e00f400, 'single', False, False),
)
Q = 1 << 30
REQUIRED = (frame.Component.PRIMARY | frame.Component.SVCR
            | frame.Component.TPIDR2 | frame.Component.FPMR)


def decode(word):
    for encoding in ENCODINGS:
        mask = 0xbffffc00 if encoding[3] else 0xbfe0fc00
        if word & mask == encoding[1]:
            return encoding, word & 31, word >> 5 & 31, word >> 16 & 31, bool(word & Q)
    return None


def execute(word, initial, *, full_a64=False):
    decoded = decode(word)
    if decoded is None:
        raise ValueError('outside allocated fixed FP8 conversions')
    encoding, destination, source, second, q = decoded
    if initial.valid & (frame.Component.PRIMARY | frame.Component.FPMR) != (
            frame.Component.PRIMARY | frame.Component.FPMR):
        raise ValueError('fixed FP8 requires explicit FPMR and primary state')
    if initial.control('svcr') & frame.SVCR_SM and not full_a64:
        raise ValueError('fixed AdvSIMD in streaming mode requires FullA64')
    _, _, format_, widening, source2 = encoding
    primary = bytearray(initial.primary)
    fpcr, fpsr = struct.unpack_from('<II', primary, frame.PRIMARY_FPCR_OFFSET)
    fpmr = initial.control('fpmr')
    vectors = tuple(initial.primary[frame.PRIMARY_VECTOR_OFFSET + register * 16:
                                    frame.PRIMARY_VECTOR_OFFSET + (register + 1) * 16]
                    for register in range(32))
    result = bytearray(vectors[destination] if not widening and format_ == 'single' and q
                       else bytes(16))
    exceptions = 0
    if widening:
        for lane, bits in enumerate(vectors[source][8 if q else 0:16 if q else 8]):
            value, status = fp8.from_fp8(format_, source2, fpcr, fpmr, bits)
            result[2 * lane:2 * lane + 2] = value.to_bytes(2, 'little')
            exceptions |= status
    else:
        width = 2 if format_ == 'half' else 4
        lanes = (8 if format_ == 'half' and not q else 16) // width
        start = 8 if format_ == 'single' and q else 0
        for group, register in enumerate((source, second)):
            for lane in range(lanes):
                bits = int.from_bytes(vectors[register][width * lane:width * (lane + 1)], 'little')
                value, status = fp8.to_fp8(format_, fpcr, fpmr, bits)
                result[start + group * lanes + lane] = value
                exceptions |= status
    start = frame.PRIMARY_VECTOR_OFFSET + destination * 16
    primary[start:start + 16] = result
    struct.pack_into('<I', primary, frame.PRIMARY_FPSR_OFFSET, fpsr | exceptions)
    z = list(initial.z)
    z[destination] = bytes(result) + bytes(initial.svl_bytes - 16)
    return replace(initial, primary=bytes(primary), z=tuple(z))


def scalable_cases(svl_bytes):
    """All six forms/Q arrangements with aliases, selectors, scales and status."""
    controls = (0, fp8.FPCR_AH, 1 << 26, 1 | 1 << 19 | 1 << 24,
                fp8.FPCR_AH | 1 << 25, 3 << 22, 1 << 22, fp8.FPCR_AH | 2 << 22)
    modes = (0, 1 | 1 << 3 | 1 << 6, 64 << 16 | 63 << 32,
             15 << 16 | 15 << 32 | 16 << 24,
             fp8.FPMR_OSC | 1 << 6 | 0x7f << 24,
             1 | 1 << 3 | 0x80 << 24,
             2 | 7 << 3 | 2 << 6,
             7 | 2 << 3 | 7 << 6 | 0xff << 24)
    patterns = {
        'byte': (0, 128, 1, 129, 0x3c, 0xbc, 0x7c, 0xfc, 0x7d, 0x7e, 0x7f, 0xff, 0x77, 0xf7, 0x7b, 0xfb),
        'half': (0, 0x8000, 1, 0x8001, 0x3c00, 0xbc00, 0x7c00, 0xfc00, 0x7c01, 0x7e00, 0x7bff, 0xfbff, 0x03ff, 0x0400),
        'single': (0, 0x80000000, 1, 0x80000001, 0x3f800000, 0xbf800000, 0x7f800000, 0xff800000, 0x7f800001, 0x7fc00000, 0x43e00000, 0xc3f00000, 0x38700000, 0x38800000),
    }
    index = 0
    for encoding in ENCODINGS:
        canonical, opcode, format_, widening, _ = encoding
        for q in (False, True):
            for variant in range(len(controls)):
                destination, source, second = ((31, 0, 30), (0, 31, 0), (0, 0, 0), (1, 1, 0),
                                               (0, 1, 0), (31, 31, 31), (30, 31, 30), (1, 0, 1))[variant]
                word = opcode | destination | source << 5 | (int(q) << 30)
                if not widening:
                    word |= second << 16
                initial = frame.seeded_snapshot(svl_bytes, b'fixed-fp8' + word.to_bytes(4, 'little') + bytes([variant]),
                                                svcr=0, case_index=index, function_index=index)
                primary = bytearray(initial.primary)
                struct.pack_into('<II', primary, frame.PRIMARY_FPCR_OFFSET, controls[variant], (1 << 27) | variant)
                width = 1 if widening else 2 if format_ == 'half' else 4
                values = patterns['byte' if widening else format_]
                z = tuple(b''.join(values[(lane + register + variant) % len(values)].to_bytes(width, 'little')
                                   for lane in range(svl_bytes // width)) for register in range(32))
                initial = frame.snapshot_from_banks(svl_bytes, primary=bytes(primary), z=z, p=initial.p,
                    ffr=initial.ffr, za=initial.za, zt0=initial.zt0, valid=initial.valid | frame.Component.FPMR,
                    controls=dict(initial.controls, fpmr=modes[variant]), case_index=index, function_index=index)
                yield {'operation': {'word': word, 'canonical_id': canonical, 'family': 'fixed_fp8_conversion'},
                       'initial': initial, 'expected': execute(word, initial), 'required': REQUIRED}
                index += 1
