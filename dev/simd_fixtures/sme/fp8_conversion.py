"""Independent grouped SME FP8 conversion model and full-state fixtures.

Encoding/layout facts come from the hash-pinned June 2026 A64 XML. Numerical
results use the independent Fraction-based FP8 model, never production helpers.
This model is not an original execution oracle. CPU/FPMR access traps belong to
the observer; effective FA64 FP trap delivery is an explicit unsupported boundary.
"""
from dataclasses import dataclass, replace
import struct

import scalable_frame as frame
from simd_fixtures import fp8

WORD_MASK = (1 << 32) - 1
REGISTER_MASK = 31
SOURCE_SHIFT = 5
REGISTER_COUNT = 32
FPCR_RMODE_SHIFT = 22
FPCR_IGNORED_CONVERSION_BITS = (1 << 0 | 1 << 19 | 1 << 24 | 1 << 26)
FPSR_QC = 1 << 27
REQUIRED = (frame.Component.PRIMARY | frame.Component.Z
            | frame.Component.SVCR | frame.Component.FPMR)

# Canonical ID, fixed mask/value, wide element format, group count, widening,
# source2 selector, interleaved layout (deinterleaved for widening).
ENCODINGS = (
    ('bf1cvt_mz2_z8_', 0xfffffc01, 0xc166e000, 'bfloat16', 2, True, False, False),
    ('bf1cvtl_mz2_z8_', 0xfffffc01, 0xc166e001, 'bfloat16', 2, True, False, True),
    ('bf2cvt_mz2_z8_', 0xfffffc01, 0xc1e6e000, 'bfloat16', 2, True, True, False),
    ('bf2cvtl_mz2_z8_', 0xfffffc01, 0xc1e6e001, 'bfloat16', 2, True, True, True),
    ('bfcvt_z8_mz2_', 0xfffffc20, 0xc164e000, 'bfloat16', 2, False, False, False),
    ('f1cvt_mz2_z8_', 0xfffffc01, 0xc126e000, 'half', 2, True, False, False),
    ('f1cvtl_mz2_z8_', 0xfffffc01, 0xc126e001, 'half', 2, True, False, True),
    ('f2cvt_mz2_z8_', 0xfffffc01, 0xc1a6e000, 'half', 2, True, True, False),
    ('f2cvtl_mz2_z8_', 0xfffffc01, 0xc1a6e001, 'half', 2, True, True, True),
    ('fcvt_z8_mz2_', 0xfffffc20, 0xc124e000, 'half', 2, False, False, False),
    ('fcvt_z8_mz4_', 0xfffffc60, 0xc134e000, 'single', 4, False, False, False),
    ('fcvtn_z8_mz4_', 0xfffffc60, 0xc134e020, 'single', 4, False, False, True),
)


@dataclass(frozen=True)
class Operand:
    canonical_id: str
    format: str
    group: int
    widening: bool
    source2: bool
    interleaved: bool
    destination: int
    source: int

    @property
    def required(self):
        return REQUIRED

    @property
    def required_feature(self):
        return 'FEAT_SME2 && FEAT_FP8'


def decode(word):
    """Decode all and only twelve allocated grouped conversion forms."""
    if type(word) is not int or not 0 <= word <= WORD_MASK:
        raise ValueError('Instruction must be a raw u32')
    for identifier, mask, opcode, format_, group, widening, source2, layout in ENCODINGS:
        if word & mask == opcode:
            destination = word & (REGISTER_MASK & ~(group - 1) if widening else REGISTER_MASK)
            source = word >> SOURCE_SHIFT & (REGISTER_MASK if widening else REGISTER_MASK & ~(group - 1))
            return Operand(identifier, format_, group, widening, source2, layout,
                           destination, source)
    return None


def execute(word, initial, *, full_a64=False):
    """Snapshot all sources and atomically update active Z/V aliases and FPSR."""
    operand = decode(word)
    if operand is None:
        raise ValueError('Instruction is outside SME FP8 grouped conversions')
    if not isinstance(initial, frame.Snapshot):
        raise TypeError('SME FP8 fixtures require a scalable Snapshot')
    frame.require_sme_length(initial.svl_bytes)
    if initial.valid & REQUIRED != REQUIRED:
        raise ValueError('SME FP8 input lacks required valid state including FPMR')
    if not initial.control('svcr') & frame.SVCR_SM:
        raise ValueError('SME FP8 conversion requires streaming mode')
    if type(full_a64) is not bool:
        raise ValueError('full_a64 must be boolean')
    fpcr, fpsr = struct.unpack_from('<II', initial.primary, frame.PRIMARY_FPCR_OFFSET)
    effective_fpcr = fpcr if full_a64 else fpcr & ~fp8.FP_EXCEPTION_ENABLE_MASK
    fpmr = initial.control('fpmr')
    length = initial.svl_bytes
    results = [bytearray(length) for _ in range(2 if operand.widening else 1)]
    status = 0
    if operand.widening:
        for lane, bits in enumerate(initial.z[operand.source]):
            value, exceptions = fp8.from_fp8(operand.format, operand.source2,
                                            effective_fpcr, fpmr, bits)
            if operand.interleaved:
                register, element = lane % 2, lane // 2
            else:
                register, element = divmod(lane, length // 2)
            results[register][2 * element:2 * element + 2] = value.to_bytes(2, 'little')
            status |= exceptions
    else:
        width = 4 if operand.format == 'single' else 2
        elements = length // width
        for register in range(operand.group):
            source = initial.z[operand.source + register]
            for element in range(elements):
                bits = int.from_bytes(source[width * element:width * (element + 1)], 'little')
                value, exceptions = fp8.to_fp8(operand.format, effective_fpcr, fpmr, bits)
                lane = (operand.group * element + register if operand.interleaved
                        else register * elements + element)
                results[0][lane] = value
                status |= exceptions
    primary = bytearray(initial.primary)
    struct.pack_into('<I', primary, frame.PRIMARY_FPSR_OFFSET, fpsr | status)
    z = list(initial.z)
    for index, result in enumerate(results):
        z[operand.destination + index] = bytes(result)
        start = frame.PRIMARY_VECTOR_OFFSET + (operand.destination + index) * frame.FIXED_VECTOR_BYTES
        primary[start:start + frame.FIXED_VECTOR_BYTES] = result[:frame.FIXED_VECTOR_BYTES]
    return replace(initial, primary=bytes(primary), z=tuple(z), provenance=frame.Provenance.MODEL)


def expected(operation, initial, ram=None):
    return execute(operation['word'], initial), ram, None


def _encode(encoding, destination, source):
    _, mask, opcode, _, group, widening, _, _ = encoding
    if not 0 <= destination < REGISTER_COUNT or not 0 <= source < REGISTER_COUNT:
        raise ValueError('Z register outside architectural range')
    if (destination if widening else source) % group:
        raise ValueError('Grouped Z register must be aligned')
    word = opcode | destination | source << SOURCE_SHIFT
    if word & mask != opcode:
        raise ValueError('Operands change fixed instruction bits')
    return word


def scalable_cases(svl_bytes):
    """Twelve forms with aliases, register extremes and FP control/status edges.

    Reserved FPMR selectors produce the specified invalid-operation results.
    Streaming suppression of exception enables is exercised with dirty enables;
    full_a64=True callers separately exercise the unsupported trap boundary.
    """
    frame.require_sme_length(svl_bytes)
    controls = (0, fp8.FPCR_AH, FPCR_IGNORED_CONVERSION_BITS,
                fp8.FPCR_AH | FPCR_IGNORED_CONVERSION_BITS,
                fp8.FP_EXCEPTION_ENABLE_MASK, fp8.FPCR_AH | fp8.FP_EXCEPTION_ENABLE_MASK,
                1 << 25, fp8.FPCR_AH | 1 << 25)
    # Independent selector fields, ignored high scale bits, signed NSCALE
    # extremes, conversion saturation and invalid format selectors.
    fpmrs = (
        0, 1 | 1 << 3 | 1 << 6,
        1 | 63 << 16 | 15 << 32 | 15 << 24,
        1 << 3 | 127 << 16 | 63 << 32 | 0x80 << 24,
        1 << 6 | fp8.FPMR_OSC | 0x7f << 24,
        1 | 1 << 3 | 1 << 6 | fp8.FPMR_OSC | 0xff << 24,
        2 | 7 << 3 | 2 << 6,
        7 | 2 << 3 | 7 << 6 | fp8.FPMR_OSM | 0xff << 16 | 0xff << 32,
    )
    patterns = {
        'byte': (0x00, 0x80, 0x01, 0x81, 0x38, 0x3c, 0x7e, 0xfe,
                 0x7f, 0xff, 0x78, 0xf8, 0x7b, 0xfb, 0x04, 0x84),
        'half': (0, 0x8000, 1, 0x8001, 0x3c00, 0x3c80, 0x7bff, 0xfbff,
                 0x7c00, 0xfc00, 0x7c01, 0x7e00, 0x0400, 0x03ff),
        'bfloat16': (0, 0x8000, 1, 0x8001, 0x3f80, 0x3f88, 0x7f7f, 0xff7f,
                     0x7f80, 0xff80, 0x7f81, 0x7fc0, 0x0080, 0x007f),
        'single': (0, 0x80000000, 1, 0x80000001, 0x3f800000, 0x3f880000,
                   0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000,
                   0x7f800001, 0x7fc00000, 0x00800000, 0x007fffff),
    }
    index = 0
    for function_index, encoding in enumerate(ENCODINGS):
        group, widening = encoding[4:6]
        for variant, control in enumerate(controls):
            registers = ((0, 31 if widening else 32 - group),
                         (32 - group if widening else 31, 0),
                         (0, 0), (30, 31) if widening else (31, 32 - group),
                         (0, 1) if widening else (1, 0),
                         (2, 2) if widening else (group - 1, 0),
                         (0, 0), (32 - group if widening else 31, 32 - group))
            word = _encode(encoding, *registers[variant])
            operand = decode(word)
            initial = frame.seeded_snapshot(
                svl_bytes, b'sme-fp8-conversion-' + word.to_bytes(4, 'little') + bytes([variant]),
                case_index=index, function_index=function_index)
            primary = bytearray(initial.primary)
            fpcr = control | (variant % 4) << FPCR_RMODE_SHIFT
            fpsr = FPSR_QC | variant
            struct.pack_into('<II', primary, frame.PRIMARY_FPCR_OFFSET, fpcr, fpsr)
            width = 1 if widening else 4 if operand.format == 'single' else 2
            pattern = patterns['byte' if widening else operand.format]
            z = tuple(b''.join(pattern[(lane + register + variant) % len(pattern)].to_bytes(width, 'little')
                               for lane in range(svl_bytes // width))
                      for register in range(REGISTER_COUNT))
            initial = frame.snapshot_from_banks(
                svl_bytes, primary=bytes(primary), z=z, p=initial.p,
                ffr=initial.ffr, za=initial.za, zt0=initial.zt0,
                valid=initial.valid | frame.Component.FPMR,
                controls=dict(initial.controls, fpmr=fpmrs[variant],
                              requested_fpcr=fpcr, requested_fpsr=fpsr),
                case_index=index, function_index=function_index)
            operation = {'word': word, 'canonical_id': operand.canonical_id,
                         'family': 'sme_fp8_conversion', 'required_feature': operand.required_feature}
            yield {'operation': operation, 'initial': initial,
                   'expected': execute(word, initial), 'required': operand.required}
            index += 1
