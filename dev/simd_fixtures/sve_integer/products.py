"""Pure streaming-SVE integer products; byte arrays are independent of host ABI.

B/T selects alternating narrow elements. Saturation preserves FPSR.QC; source
snapshots also preserve predicate banks, flags, FP state, FFR, ZA/ZT and RAM.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

BITS_PER_BYTE = 8
SEGMENT_BYTES = 16
VECTOR_REGISTERS = 32
PREDICATE_REGISTERS = 16
MIN_VECTOR_BYTES = SEGMENT_BYTES
MAX_VECTOR_BYTES = 256
LANE_BYTES = (1, 2, 4, 8)
ROTATIONS = (0, 90, 180, 270)
LOW_PRODUCTS = ('MUL', 'MLA', 'MLS', 'MAD', 'MSB')
HIGH_PRODUCTS = ('SMULH', 'UMULH', 'SQDMULH', 'SQRDMULH', 'SQRDMLAH', 'SQRDMLSH')
COMPLEX_PRODUCTS = ('CMLA', 'SQRDCMLAH')
POLYNOMIAL_PRODUCTS = ('PMUL', 'PMULLB', 'PMULLT')
LONG_PRODUCTS = (
    'SMULLB', 'SMULLT', 'UMULLB', 'UMULLT', 'SQDMULLB', 'SQDMULLT',
    'SMLALB', 'SMLALT', 'SMLSLB', 'SMLSLT', 'UMLALB', 'UMLALT', 'UMLSLB', 'UMLSLT',
    'SQDMLALB', 'SQDMLALT', 'SQDMLALBT', 'SQDMLSLB', 'SQDMLSLT', 'SQDMLSLBT',
)


@dataclass(frozen=True)
class Operand:
    operation: str
    destination: int
    left: int
    right: int | None = None
    predicate: int | None = None
    element_bytes: int = 1
    index: int | None = None
    immediate: int | None = None
    accumulator: int | None = None
    rotation: int = 0


def _lanes(data, bits, signed=False):
    size = bits // BITS_PER_BYTE
    return [int.from_bytes(data[start:start+size], 'little', signed=signed)
            for start in range(0, len(data), size)]


def _pack(values, bits):
    mask = (1 << bits) - 1
    return b''.join((value & mask).to_bytes(bits // BITS_PER_BYTE, 'little') for value in values)


def _saturate(value, bits):
    bound = 1 << (bits - 1)
    return min(max(value, -bound), bound - 1)


def _validate(operand, vectors, predicates):
    if len(vectors) != VECTOR_REGISTERS or not vectors:
        raise ValueError('expected 32 Z registers')
    vl = len(vectors[0])
    if not MIN_VECTOR_BYTES <= vl <= MAX_VECTOR_BYTES or vl & (vl - 1):
        raise ValueError('invalid streaming vector length')
    if any(len(z) != vl for z in vectors):
        raise ValueError('vector lengths differ')
    if len(predicates) != PREDICATE_REGISTERS or any(len(p) != vl // BITS_PER_BYTE for p in predicates):
        raise ValueError('expected 16 packed predicates')
    registers = (operand.destination, operand.left, operand.right, operand.accumulator)
    if any(r is not None and not 0 <= r < VECTOR_REGISTERS for r in registers):
        raise ValueError('invalid vector register')
    if operand.predicate is not None and not 0 <= operand.predicate < 8:
        raise ValueError('governing predicate must be P0 through P7')
    op = operand.operation
    if op not in LOW_PRODUCTS + HIGH_PRODUCTS + COMPLEX_PRODUCTS + LONG_PRODUCTS + POLYNOMIAL_PRODUCTS:
        raise ValueError('unallocated integer product')
    size = operand.element_bytes
    if size not in LANE_BYTES or (op in LONG_PRODUCTS and size == 1):
        raise ValueError('unallocated element size')
    if op in POLYNOMIAL_PRODUCTS and size not in ((1,) if op == 'PMUL' else (2, 8)):
        raise ValueError('unallocated polynomial element size')
    if operand.index is not None:
        if op in POLYNOMIAL_PRODUCTS:
            raise ValueError('polynomial products have no indexed form')
        indexed_sizes = (4, 8) if op in LONG_PRODUCTS else ((2, 4) if op in COMPLEX_PRODUCTS else (2, 4, 8))
        if op in ('MAD', 'MSB', 'SMULH', 'UMULH') or op.endswith('BT') or size not in indexed_sizes:
            raise ValueError('unallocated indexed form')
        groups = SEGMENT_BYTES // size
        groups *= 2 if op in LONG_PRODUCTS else 1
        groups //= 2 if op in COMPLEX_PRODUCTS else 1
        if not 0 <= operand.index < groups:
            raise ValueError('index exceeds 128-bit segment')
    if operand.immediate is not None:
        if op != 'MUL' or not -128 <= operand.immediate <= 127 or operand.right is not None:
            raise ValueError('unallocated immediate product')
    elif operand.right is None:
        raise ValueError('missing vector multiplier')
    if operand.predicate is not None:
        if op not in LOW_PRODUCTS + ('SMULH', 'UMULH') or operand.index is not None or operand.immediate is not None:
            raise ValueError('unallocated predicated product')
        if op in ('MUL', 'MAD', 'MSB', 'SMULH', 'UMULH') and operand.left != operand.destination:
            raise ValueError('destructive source must be destination')
    elif op in ('MAD', 'MSB') or (op in ('MLA', 'MLS') and operand.index is None):
        raise ValueError('missing governing predicate')
    if operand.immediate is not None and (operand.index is not None or operand.predicate is not None or operand.left != operand.destination):
        raise ValueError('invalid destructive immediate product')
    if op in ('MAD', 'MSB'):
        if operand.accumulator is None:
            raise ValueError('MAD/MSB require Za accumulator')
    elif operand.accumulator is not None:
        raise ValueError('separate accumulator only belongs to MAD/MSB')
    if operand.rotation not in ROTATIONS or (op not in COMPLEX_PRODUCTS and operand.rotation != 0):
        raise ValueError('unallocated rotation')


def apply(operand: Operand, vectors: Sequence[bytes], predicates: Sequence[bytes]) -> tuple[bytes, ...]:
    """Return a Z-bank snapshot with only the declared destination changed."""
    _validate(operand, vectors, predicates)
    bank = tuple(bytes(vector) for vector in vectors)
    n, d = bank[operand.left], bank[operand.destination]
    m = bank[operand.right] if operand.right is not None else None
    bits = operand.element_bytes * BITS_PER_BYTE
    op = operand.operation
    if op in POLYNOMIAL_PRODUCTS:
        result = _polynomial_product(operand, n, m)
    elif op in LONG_PRODUCTS:
        result = _long_product(operand, n, m, d)
    elif op in COMPLEX_PRODUCTS:
        result = _complex_product(operand, n, m, d)
    else:
        signed = op.startswith('SQ') or op == 'SMULH'
        left = _lanes(n, bits, signed)
        right = _lanes(m, bits, signed) if m is not None else None
        old = _lanes(d, bits, op.startswith('SQ'))
        accumulator = _lanes(bank[operand.accumulator], bits) if operand.accumulator is not None else old
        segment_lanes = SEGMENT_BYTES // operand.element_bytes
        predicate = int.from_bytes(predicates[operand.predicate], 'little') if operand.predicate is not None else None
        out = old.copy()
        for e, a in enumerate(left):
            if predicate is not None and not (predicate >> (e * operand.element_bytes)) & 1:
                continue
            selected = e - e % segment_lanes + operand.index if operand.index is not None else e
            b = operand.immediate if operand.immediate is not None else right[selected]
            product = a * b
            if op == 'MUL': value = product
            elif op in ('MLA', 'MAD'): value = accumulator[e] + product
            elif op in ('MLS', 'MSB'): value = accumulator[e] - product
            elif op in ('SMULH', 'UMULH'): value = product >> bits
            elif op in ('SQDMULH', 'SQRDMULH'):
                rounding = 1 << (bits - 1) if op == 'SQRDMULH' else 0
                value = _saturate((2 * product + rounding) >> bits, bits)
            elif op in ('SQRDMLAH', 'SQRDMLSH'):
                product_sign = -1 if op == 'SQRDMLSH' else 1
                value = _saturate(((old[e] << bits) + product_sign * 2 * product + (1 << (bits - 1))) >> bits, bits)
            else: raise AssertionError('validated product lacks semantics')
            out[e] = value
        result = _pack(out, bits)
    out_bank = list(bank)
    out_bank[operand.destination] = result
    return tuple(out_bank)


def _long_product(operand, n, m, d):
    op = operand.operation
    bits = operand.element_bytes * BITS_PER_BYTE
    narrow_bits = bits // 2
    signed = not op.startswith('U')
    a, b = _lanes(n, narrow_bits, signed), _lanes(m, narrow_bits, signed)
    old = _lanes(d, bits, op.startswith('SQ'))
    segment_lanes = SEGMENT_BYTES // operand.element_bytes
    n_selector = int(op.endswith('T') and not op.endswith('BT'))
    m_selector = int(op.endswith('T'))
    out = []
    for e, accumulator in enumerate(old):
        selected = (e - e % segment_lanes) * 2 + operand.index if operand.index is not None else 2 * e + m_selector
        product = a[2 * e + n_selector] * b[selected]
        if op.startswith('SQ'): product = _saturate(2 * product, bits)
        if 'MLAL' in op: value = accumulator + product
        elif 'MLSL' in op: value = accumulator - product
        else: value = product
        if op.startswith('SQ'): value = _saturate(value, bits)
        out.append(value)
    return _pack(out, bits)


def _complex_product(operand, n, m, d):
    bits = operand.element_bytes * BITS_PER_BYTE
    rounded = operand.operation == 'SQRDCMLAH'
    first, second, out = _lanes(n, bits, True), _lanes(m, bits, True), _lanes(d, bits, rounded)
    rotation = operand.rotation // 90
    select_a, select_b = rotation & 1, (rotation & 1) ^ 1
    subtract = (select_a != rotation >> 1, bool(rotation >> 1))
    segment_pairs = SEGMENT_BYTES // (2 * operand.element_bytes)
    for pair in range(len(out) // 2):
        selected = pair - pair % segment_pairs + operand.index if operand.index is not None else pair
        a = first[2 * pair + select_a]
        products = (a * second[2 * selected + select_a], a * second[2 * selected + select_b])
        for component in (0, 1):
            lane = 2 * pair + component
            product = -products[component] if subtract[component] else products[component]
            value = out[lane] + product
            if rounded:
                wide = (out[lane] << bits) + 2 * product
                value = _saturate((wide + (1 << (bits - 1))) >> bits, bits)
            out[lane] = value
    return _pack(out, bits)


def _polynomial_product(operand, n, m):
    bits = operand.element_bytes * BITS_PER_BYTE
    widening = operand.operation != 'PMUL'
    source_bits = bits // 2 if widening else bits
    left, right = _lanes(n, source_bits), _lanes(m, source_bits)
    selection = int(operand.operation.endswith('T'))
    output = []
    for e in range(len(n) // operand.element_bytes):
        selected = 2 * e + selection if widening else e
        a, b = left[selected], right[selected]
        product = 0
        for bit in range(source_bits):
            if (b >> bit) & 1:
                product ^= a << bit
        output.append(product)
    return _pack(output, bits)
