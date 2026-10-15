"""SME2 absolute extrema and signed exponent scaling, with full Snapshot fixtures.

Mathematical lanes reuse the independent integer/Fraction SVE models. Originals
remain exact encoded subjects captured separately by scalable_original.
"""
from dataclasses import replace
import struct

import scalable_frame as frame
from simd_fixtures.sve_floating.faminmax import Operation, evaluate_lane
from simd_fixtures.sve_floating.arithmetic_special import scale_lane
from simd_fixtures.sve_floating.control import FP_EXCEPTION_ENABLE_MASK

# Factual pinned June2026 form identifiers, fixed masks/opcodes, group/layout.
ENCODINGS = (
    ('famax_mz_zzw_2x2', 0xff21ffe1, 0xc120b140, 2, True, 'famax'),
    ('famax_mz_zzw_4x4', 0xff23ffe3, 0xc120b940, 4, True, 'famax'),
    ('famin_mz_zzw_2x2', 0xff21ffe1, 0xc120b141, 2, True, 'famin'),
    ('famin_mz_zzw_4x4', 0xff23ffe3, 0xc120b941, 4, True, 'famin'),
    ('fscale_mz_zzv_2x1', 0xff30ffe1, 0xc120a180, 2, False, 'fscale'),
    ('fscale_mz_zzv_4x1', 0xff30ffe3, 0xc120a980, 4, False, 'fscale'),
    ('fscale_mz_zzw_2x2', 0xff21ffe1, 0xc120b180, 2, True, 'fscale'),
    ('fscale_mz_zzw_4x4', 0xff23ffe3, 0xc120b980, 4, True, 'fscale'),
)
REQUIRED = (frame.Component.PRIMARY | frame.Component.Z | frame.Component.P
            | frame.Component.ZA | frame.Component.ZT0 | frame.Component.SVCR
            | frame.Component.TPIDR2)


def decode(word):
    for canonical, mask, opcode, count, grouped, name in ENCODINGS:
        if word & mask != opcode:
            continue
        size = word >> 22 & 3
        if size == 0:
            return None
        return dict(word=word, canonical_id=canonical, count=count, grouped=grouped,
                    name=name, bits=8 << size, destination=word & (32 - count),
                    right=(word >> 16 & (32 - count)) if grouped else (word >> 16 & 15))
    return None


def expected(operation, initial, ram=None):
    op = decode(operation['word'])
    if op is None or not initial.control('svcr') & frame.SVCR_SM:
        raise ValueError('Allocated SME extrema/scale streaming subject required')
    if initial.valid & REQUIRED != REQUIRED:
        raise ValueError('Full observable SME state is required')
    fpcr, fpsr = struct.unpack_from('<II', initial.primary, frame.PRIMARY_FPCR_OFFSET)
    if not operation.get('full_a64', False):
        fpcr &= ~FP_EXCEPTION_ENABLE_MASK
    z = [bytearray(register) for register in initial.z]
    width = op['bits'] // 8
    for index in range(op['count']):
        destination = op['destination'] + index
        right = op['right'] + (index if op['grouped'] else 0)
        for offset in range(0, initial.svl_bytes, width):
            a = int.from_bytes(initial.z[destination][offset:offset + width], 'little')
            b = int.from_bytes(initial.z[right][offset:offset + width], 'little')
            if op['name'] == 'fscale':
                outcome = scale_lane(op['bits'], fpcr, a, b)
            else:
                kind = Operation.MINIMUM if op['name'] == 'famin' else Operation.MAXIMUM
                outcome = evaluate_lane(kind, op['bits'], fpcr, a, b)
            z[destination][offset:offset + width] = outcome.bits.to_bytes(width, 'little')
            fpsr |= outcome.exceptions
    primary = bytearray(initial.primary)
    struct.pack_into('<I', primary, frame.PRIMARY_FPSR_OFFSET, fpsr)
    result = frame.snapshot_from_banks(
        initial.svl_bytes, primary=bytes(primary), z=tuple(bytes(register) for register in z), p=initial.p, ffr=initial.ffr,
        za=initial.za, zt0=initial.zt0, valid=initial.valid, controls=initial.controls,
        provenance=frame.Provenance.MODEL, vl_bytes=initial.vl_bytes,
        case_index=initial.case_index, function_index=initial.function_index)
    return result, ram, None


def scalable_cases(svl_bytes):
    frame.require_sme_length(svl_bytes)
    case = 0
    for canonical, _mask, opcode, count, grouped, name in ENCODINGS:
        for size in (1, 2, 3):
            bits = 8 << size
            width = bits // 8
            fraction = {16: 10, 32: 23, 64: 52}[bits]
            one = {16: 15, 32: 127, 64: 1023}[bits] << fraction
            sign = 1 << (bits - 1)
            infinity = sign - (1 << fraction)
            numeric = (0, sign, 1, sign | 1, (1 << fraction) - 1, 1 << fraction,
                       one, sign | one, infinity - 1, infinity, sign | infinity,
                       infinity | 1, sign | infinity | (1 << (fraction - 1)) | 13)
            scales = (0, 1, 2, (1 << bits) - 1, sign, sign - 1)
            # Disjoint groups, full aliases, high groups and a broadcast alias
            # in the first/middle register catch sequential-commit mistakes.
            roles = ((0, 16 if grouped else 15), (32 - count, 32 - count if grouped else 0),
                     (0, 0), (0, 0 if grouped else 1))
            for pattern, (destination, right) in enumerate(roles):
                for fpcr in (0, 1 << 1, 1 << 25, (1 << 24) | (1 << 19) | 1,
                             1 << 22, 2 << 22, 3 << 22, FP_EXCEPTION_ENABLE_MASK):
                    word = opcode | size << 22 | right << 16 | destination
                    operation = dict(word=word, canonical_id=canonical, family='sme_extrema_scale', full_a64=False)
                    initial = frame.seeded_snapshot(svl_bytes, word.to_bytes(4, 'little') + fpcr.to_bytes(4, 'little'),
                                                    case_index=case, function_index=case)
                    z = [bytearray(register) for register in initial.z]
                    for index in range(count):
                        for lane in range(svl_bytes // width):
                            value = numeric[(lane + index + pattern) % len(numeric)]
                            start = lane * width
                            z[destination + index][start:start + width] = value.to_bytes(width, 'little')
                    for index in range(count if grouped else 1):
                        for lane in range(svl_bytes // width):
                            value = (scales[(lane + index + pattern) % len(scales)] if name == 'fscale'
                                     else numeric[(lane + index + pattern + 5) % len(numeric)])
                            start = lane * width
                            z[right + index][start:start + width] = value.to_bytes(width, 'little')
                    primary = bytearray(initial.primary)
                    struct.pack_into('<II', primary, frame.PRIMARY_FPCR_OFFSET, fpcr, 1 << 27)
                    initial = frame.snapshot_from_banks(svl_bytes, primary=bytes(primary), z=tuple(bytes(register) for register in z),
                        p=initial.p, ffr=initial.ffr, za=initial.za, zt0=initial.zt0, valid=initial.valid,
                        controls=dict(initial.controls, requested_fpcr=fpcr, requested_fpsr=1 << 27),
                        provenance=initial.provenance, vl_bytes=initial.vl_bytes, case_index=case, function_index=case)
                    result, _, _ = expected(operation, initial)
                    yield dict(operation=operation, initial=initial, expected=result, required=REQUIRED)
                    case += 1
