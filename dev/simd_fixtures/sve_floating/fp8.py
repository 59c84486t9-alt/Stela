"""Whole-vector FP8 layouts; scalar numerical oracle supplied by shared FP8 core.

The callback receives (precision, source2, source_bits) on widening and
(precision, source_bits) on narrowing and returns (result_bits, exceptions).
This separates register placement from numerical semantics and avoids treating
this layout model as direct original-ARM evidence.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Encoding:
    canonical_id: str
    value: int
    precision: str
    widening: bool
    source2: bool = False
    top: bool = False

    @property
    def mask(self):
        return 0xfffffc00 if self.widening else 0xfffffc20


ENCODINGS = (
    Encoding('f1cvt_z_z8_b2h', 0x65083000, 'half', True),
    Encoding('f1cvtlt_z_z8_b2h', 0x65093000, 'half', True, top=True),
    Encoding('f2cvt_z_z8_b2h', 0x65083400, 'half', True, source2=True),
    Encoding('f2cvtlt_z_z8_b2h', 0x65093400, 'half', True, True, True),
    Encoding('bf1cvt_z_z8_b2bf', 0x65083800, 'bfloat16', True),
    Encoding('bf1cvtlt_z_z8_b2bf', 0x65093800, 'bfloat16', True, top=True),
    Encoding('bf2cvt_z_z8_b2bf', 0x65083c00, 'bfloat16', True, source2=True),
    Encoding('bf2cvtlt_z_z8_b2bf', 0x65093c00, 'bfloat16', True, True, True),
    Encoding('fcvtn_z8_mz2_h2b', 0x650a3000, 'half', False),
    Encoding('bfcvtn_z8_mz2_bf2b', 0x650a3800, 'bfloat16', False),
    Encoding('fcvtnb_z8_mz2_s2b', 0x650a3400, 'single', False),
    Encoding('fcvtnt_z8_mz2_s2b', 0x650a3c00, 'single', False, top=True),
)


def decode(word):
    for encoding in ENCODINGS:
        if word & encoding.mask == encoding.value:
            return encoding, (word >> 5) & 31, word & 31
    return None


def apply_layout(word, registers, from_fp8, to_fp8, fpsr=0):
    """Return complete new register bank/FPSR after successful staged conversion."""
    decoded = decode(word)
    if decoded is None:
        raise ValueError('not an allocated SVE FP8 conversion')
    encoding, source, destination = decoded
    if len(registers) != 32:
        raise ValueError('expected all 32 Z registers')
    length = len(registers[0])
    if length not in range(16, 257, 16) or any(len(reg) != length for reg in registers):
        raise ValueError('inconsistent or invalid vector length')
    inputs = tuple(bytes(register) for register in registers)
    result = bytearray(inputs[destination] if encoding.top and not encoding.widening else bytes(length))
    status = fpsr
    if encoding.widening:
        for lane, value in enumerate(inputs[source][int(encoding.top)::2]):
            bits, exceptions = from_fp8(encoding.precision, encoding.source2, value)
            result[2 * lane:2 * lane + 2] = bits.to_bytes(2, 'little')
            status |= exceptions
    else:
        width = 4 if encoding.precision == 'single' else 2
        for source_index, register in enumerate(inputs[source:source + 2]):
            for lane in range(length // width):
                bits = int.from_bytes(register[width * lane:width * (lane + 1)], 'little')
                value, exceptions = to_fp8(encoding.precision, bits)
                offset = (2 * lane + source_index) * (width // 2) + int(encoding.top)
                result[offset] = value
                status |= exceptions
    outputs = list(inputs)
    outputs[destination] = bytes(result)
    return tuple(outputs), status
