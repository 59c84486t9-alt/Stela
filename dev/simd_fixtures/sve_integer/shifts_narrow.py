#!/usr/bin/env python3
"""Data-only mathematical model of 26 SVE2/SME interleaved-width operations.

Core lane/vector functions are data-only. The execute adapter enforces the
Apple streaming-only profile; caller still owns feature and trap delivery checks.
`width` always names the smaller element width, in bits. Bytes are little endian.
"""
from __future__ import annotations
from copy import deepcopy
from dataclasses import dataclass

BYTE_BITS = 8
VECTOR_REGISTER_COUNT = 32
PREDICATE_REGISTER_COUNT = 16
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256
STREAMING_VECTOR_BYTES = (16, 32, 64, 128, 256)
SMALL_WIDTHS = (8, 16, 32)
REGISTER_BITS = 5
REGISTER_MASK = (1 << REGISTER_BITS) - 1
SOURCE_REGISTER_SHIFT = REGISTER_BITS
TSZH_SHIFT = 22
TSZL_SHIFT = 19
IMM3_SHIFT = 16
TSZL_MASK = 0b11
IMM3_MASK = 0b111

@dataclass(frozen=True)
class Form:
    mnemonic: str
    kind: str
    mask: int
    value: int
    top: bool
    signed_input: bool
    saturation: str | None
    rounding: bool

@dataclass(frozen=True)
class Decoded:
    form: Form
    width: int
    shift: int
    source: int
    destination: int

FORMS = {form.mnemonic: form for form in (
    Form('RSHRNB', 'narrow_shift', 0xffa0fc00, 0x45201800, False, False, None, True),
    Form('RSHRNT', 'narrow_shift', 0xffa0fc00, 0x45201c00, True, False, None, True),
    Form('SHRNB', 'narrow_shift', 0xffa0fc00, 0x45201000, False, False, None, False),
    Form('SHRNT', 'narrow_shift', 0xffa0fc00, 0x45201400, True, False, None, False),
    Form('SQRSHRNB', 'narrow_shift', 0xffa0fc00, 0x45202800, False, True, 'signed', True),
    Form('SQRSHRNT', 'narrow_shift', 0xffa0fc00, 0x45202c00, True, True, 'signed', True),
    Form('SQRSHRUNB', 'narrow_shift', 0xffa0fc00, 0x45200800, False, True, 'unsigned', True),
    Form('SQRSHRUNT', 'narrow_shift', 0xffa0fc00, 0x45200c00, True, True, 'unsigned', True),
    Form('SQSHRNB', 'narrow_shift', 0xffa0fc00, 0x45202000, False, True, 'signed', False),
    Form('SQSHRNT', 'narrow_shift', 0xffa0fc00, 0x45202400, True, True, 'signed', False),
    Form('SQSHRUNB', 'narrow_shift', 0xffa0fc00, 0x45200000, False, True, 'unsigned', False),
    Form('SQSHRUNT', 'narrow_shift', 0xffa0fc00, 0x45200400, True, True, 'unsigned', False),
    Form('SQXTNB', 'narrow_extract', 0xffa7fc00, 0x45204000, False, True, 'signed', False),
    Form('SQXTNT', 'narrow_extract', 0xffa7fc00, 0x45204400, True, True, 'signed', False),
    Form('SQXTUNB', 'narrow_extract', 0xffa7fc00, 0x45205000, False, True, 'unsigned', False),
    Form('SQXTUNT', 'narrow_extract', 0xffa7fc00, 0x45205400, True, True, 'unsigned', False),
    Form('SSHLLB', 'widen', 0xffa0fc00, 0x4500a000, False, True, None, False),
    Form('SSHLLT', 'widen', 0xffa0fc00, 0x4500a400, True, True, None, False),
    Form('UQRSHRNB', 'narrow_shift', 0xffa0fc00, 0x45203800, False, False, 'unsigned', True),
    Form('UQRSHRNT', 'narrow_shift', 0xffa0fc00, 0x45203c00, True, False, 'unsigned', True),
    Form('UQSHRNB', 'narrow_shift', 0xffa0fc00, 0x45203000, False, False, 'unsigned', False),
    Form('UQSHRNT', 'narrow_shift', 0xffa0fc00, 0x45203400, True, False, 'unsigned', False),
    Form('UQXTNB', 'narrow_extract', 0xffa7fc00, 0x45204800, False, False, 'unsigned', False),
    Form('UQXTNT', 'narrow_extract', 0xffa7fc00, 0x45204c00, True, False, 'unsigned', False),
    Form('USHLLB', 'widen', 0xffa0fc00, 0x4500a800, False, False, None, False),
    Form('USHLLT', 'widen', 0xffa0fc00, 0x4500ac00, True, False, None, False),
)}

def decode(word: int) -> Decoded:
    if not 0 <= word < 1 << 32:
        raise ValueError('instruction must fit in 32 bits')
    matches = [form for form in FORMS.values() if word & form.mask == form.value]
    if len(matches) != 1:
        raise ValueError('not exactly one owned canonical form')
    form = matches[0]
    tsize = ((word >> TSZH_SHIFT) & 1) << 2 | ((word >> TSZL_SHIFT) & TSZL_MASK)
    if not tsize or (form.kind == 'narrow_extract' and tsize not in (1, 2, 4)):
        raise ValueError('reserved element-size encoding')
    width = BYTE_BITS << (tsize.bit_length() - 1)
    encoded = (tsize << 3) | ((word >> IMM3_SHIFT) & IMM3_MASK)
    shift = (encoded - width if form.kind == 'widen' else 0
             if form.kind == 'narrow_extract' else 2 * width - encoded)
    return Decoded(form, width, shift, (word >> SOURCE_REGISTER_SHIFT) & REGISTER_MASK,
                   word & REGISTER_MASK)

def encode(mnemonic: str, width: int, shift: int, source: int = 1,
           destination: int = 0) -> int:
    form = FORMS[mnemonic.upper()]
    if width not in SMALL_WIDTHS or not all(0 <= reg <= REGISTER_MASK for reg in (source, destination)):
        raise ValueError('bad width or Z register')
    if form.kind == 'widen':
        if not 0 <= shift < width:
            raise ValueError('widen shift outside 0..width-1')
        encoded = width + shift
    elif form.kind == 'narrow_shift':
        if not 1 <= shift <= width:
            raise ValueError('narrow shift outside 1..width')
        encoded = 2 * width - shift
    else:
        if shift:
            raise ValueError('narrow extract has no shift')
        encoded = width
    tsize, imm3 = divmod(encoded, BYTE_BITS)
    word = form.value | source << SOURCE_REGISTER_SHIFT | destination
    word |= (tsize >> 2) << TSZH_SHIFT | (tsize & TSZL_MASK) << TSZL_SHIFT
    if form.kind != 'narrow_extract':
        word |= imm3 << IMM3_SHIFT
    assert decode(word) == Decoded(form, width, shift, source, destination)
    return word

def _signed(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit

def lane(mnemonic: str, width: int, shift: int, value: int) -> int:
    """Return one raw output lane; does not modify FPSR.QC or any other state."""
    form = FORMS[mnemonic.upper()]
    encode(form.mnemonic, width, shift)  # Central operand validation.
    source_bits = width if form.kind == 'widen' else 2 * width
    if not 0 <= value < 1 << source_bits:
        raise ValueError('input lane outside raw source width')
    integer = _signed(value, source_bits) if form.signed_input else value
    if form.kind == 'widen':
        return (integer << shift) & ((1 << (2 * width)) - 1)
    if form.rounding:
        integer += 1 << (shift - 1)  # Deliberately wider than source lane.
    integer >>= shift
    if form.saturation == 'signed':
        integer = min(max(integer, -(1 << (width - 1))), (1 << (width - 1)) - 1)
    elif form.saturation == 'unsigned':
        integer = min(max(integer, 0), (1 << width) - 1)
    return integer & ((1 << width) - 1)

def vector(mnemonic: str, width: int, shift: int, source: bytes,
           old_destination: bytes) -> bytes:
    """Apply complete VL operation; source/destination are pre-instruction snapshots."""
    form = FORMS[mnemonic.upper()]
    encode(form.mnemonic, width, shift)
    vector_bytes = len(source)
    if (not MIN_VECTOR_BYTES <= vector_bytes <= MAX_VECTOR_BYTES
            or vector_bytes % MIN_VECTOR_BYTES or len(old_destination) != vector_bytes):
        raise ValueError('VL must be a multiple of 128 bits from 128 through 2048')
    small_bytes = width // BYTE_BITS
    wide_bytes = 2 * small_bytes
    result = bytearray(old_destination if form.top and form.kind != 'widen'
                       else bytes(vector_bytes))
    for base in range(0, vector_bytes, wide_bytes):
        if form.kind == 'widen':
            start = base + int(form.top) * small_bytes
            raw = int.from_bytes(source[start:start + small_bytes], 'little')
            result[base:base + wide_bytes] = lane(form.mnemonic, width, shift, raw).to_bytes(wide_bytes, 'little')
        else:
            raw = int.from_bytes(source[base:base + wide_bytes], 'little')
            start = base + int(form.top) * small_bytes
            result[start:start + small_bytes] = lane(form.mnemonic, width, shift, raw).to_bytes(small_bytes, 'little')
    return bytes(result)

def apply_state(word: int, state: dict) -> dict:
    """Copy full fixture state and replace only decoded Zd, preserving aliased inputs."""
    op = decode(word)
    result = deepcopy(state)
    result['z'][op.destination] = vector(op.form.mnemonic, op.width, op.shift,
                                        state['z'][op.source], state['z'][op.destination])
    return result


def execute(instruction: Decoded, vectors: list[bytes], predicates: list[int],
            *, streaming: bool = True) -> list[bytes]:
    """Apply the Apple SME-only profile; no predicate or status is modified."""
    if not streaming:
        raise ValueError('Apple SME-only profile requires streaming mode')
    if len(vectors) != VECTOR_REGISTER_COUNT or len(predicates) != PREDICATE_REGISTER_COUNT:
        raise ValueError('wrong architectural register count')
    vector_bytes = len(vectors[0])
    if (vector_bytes not in STREAMING_VECTOR_BYTES
            or any(len(value) != vector_bytes for value in vectors)):
        raise ValueError('invalid streaming vector length')
    result = list(vectors)
    result[instruction.destination] = vector(
        instruction.form.mnemonic, instruction.width, instruction.shift,
        vectors[instruction.source], vectors[instruction.destination])
    return result
