"""Pure streaming-SVE core integer model, independent of compiler ABI and host ISA.

Sources are snapshotted before writes. This family preserves P, GPR/SP, NZCV,
FPCR/FPSR, FFR, ZA/ZT and RAM. Shared execution guards own mode and MOVPRFX legality.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

BITS_PER_BYTE = 8
VECTOR_REGISTERS = 32
PREDICATE_REGISTERS = 16
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256


@dataclass(frozen=True)
class Operand:
    operation: str
    destination: int
    left: int = 0
    right: int | None = None
    predicate: int | None = None
    element_bytes: int = 1
    immediate: int | None = None
    rotation: int = 0


def _lanes(data, bits, signed=False):
    step = bits // BITS_PER_BYTE
    return [int.from_bytes(data[i:i+step], 'little', signed=signed)
            for i in range(0, len(data), step)]

def apply(operand: Operand, vectors: Sequence[bytes], predicates: Sequence[bytes]) -> tuple[bytes, ...]:
    """Return new Z bank. GPR/SP/NZCV/FPCR/FPSR/FFR/ZA and RAM are untouched."""
    if len(vectors) != VECTOR_REGISTERS:
        raise ValueError('expected 32 Z registers')
    size = len(vectors[0])
    if size < MIN_VECTOR_BYTES or size > MAX_VECTOR_BYTES or size & (size - 1):
        raise ValueError('invalid architectural vector byte length')
    if len(vectors) != 32 or any(len(z) != size for z in vectors):
        raise ValueError('expected 32 equally sized Z registers')
    if len(predicates) != PREDICATE_REGISTERS or any(len(p) != size // BITS_PER_BYTE for p in predicates):
        raise ValueError('expected 16 packed predicates')
    if operand.element_bytes not in (1, 2, 4, 8):
        raise ValueError('unallocated element size')
    registers = [operand.destination, operand.left]
    if operand.right is not None:
        registers.append(operand.right)
    if any(not 0 <= r < VECTOR_REGISTERS for r in registers):
        raise ValueError('invalid vector register')
    if operand.predicate is not None and not 0 <= operand.predicate < PREDICATE_REGISTERS:
        raise ValueError('invalid predicate register')
    vectors = tuple(bytes(z) for z in vectors)
    op = operand.operation
    if ('DIV' in op or op in ('ADCLB', 'ADCLT', 'SBCLB', 'SBCLT')) and operand.element_bytes < 4:
        raise ValueError('unallocated divide/carry element size')
    if op.startswith(('SADD', 'UADD', 'SSUB', 'USUB')) and operand.element_bytes == 1:
        raise ValueError('unallocated widening element size')
    if op not in ('ABS', 'NEG') and operand.right is None and operand.immediate is None:
        raise ValueError('missing right operand')
    if op == 'CADD' and operand.rotation not in (0, 1):
        raise ValueError('unallocated complex rotation')
    bits = operand.element_bytes * BITS_PER_BYTE
    mask = (1 << bits) - 1
    signed = op.startswith('S') or op in ('ABS', 'NEG', 'CADD')
    left = _lanes(vectors[operand.left], bits, signed)
    old = _lanes(vectors[operand.destination], bits, signed)
    right = (_lanes(vectors[operand.right], bits, signed)
             if operand.right is not None else [operand.immediate] * len(left))
    out = old.copy()
    if op in ('ADCLB', 'ADCLT', 'SBCLB', 'SBCLT'):
        carry_source = _lanes(vectors[operand.left], bits)
        carry = _lanes(vectors[operand.right], bits)
        original = _lanes(vectors[operand.destination], bits)
        for e in range(0, len(out), 2):
            b = carry_source[e + int(op.endswith('T'))]
            b = mask ^ b if op.startswith('SBC') else b
            total = original[e] + b + (carry[e + 1] & 1)
            out[e], out[e + 1] = total & mask, int(total > mask)
    elif op == 'CADD':
        for e in range(0, len(out), 2):
            real, imaginary = left[e:e+2]
            other_real, other_imaginary = right[e:e+2]
            out[e] = real + (other_imaginary if operand.rotation else -other_imaginary)
            out[e+1] = imaginary + (-other_real if operand.rotation else other_real)
    elif op.startswith(('SADD', 'UADD', 'SSUB', 'USUB')):
        wide_left = 'W' in op
        select_left = int(op.endswith('T') and not op.endswith('BT'))
        select_right = int(op.endswith('T') or op.endswith('BT'))
        if op.endswith('TB'):
            select_left, select_right = 1, 0
        half_left = _lanes(vectors[operand.left], bits//2, signed)
        half_right = _lanes(vectors[operand.right], bits//2, signed)
        for e in range(len(out)):
            a = left[e] if wide_left else half_left[2*e+select_left]
            b = half_right[2*e+select_right]
            out[e] = a-b if 'SUB' in op else a+b
    else:
        predicate = int.from_bytes(predicates[operand.predicate], 'little') if operand.predicate is not None else None
        for e, a in enumerate(left):
            if predicate is not None and not ((predicate >> (e * bits//BITS_PER_BYTE)) & 1):
                continue
            b = right[e] if right[e] is not None else 0
            if op == 'ABS': result = abs(a)
            elif op == 'NEG': result = -a
            elif op == 'ADD': result = a+b
            elif op == 'SUB': result = a-b
            elif op == 'SUBR': result = b-a
            elif 'DIV' in op:
                if op.endswith('R'): a,b = b,a
                result = 0 if b == 0 else abs(a)//abs(b) * (-1 if (a<0) != (b<0) else 1)
            elif op.endswith('MIN'): result = min(a,b)
            elif op.endswith('MAX'): result = max(a,b)
            elif op.endswith('CLAMP'): result = min(max(a,old[e]),b)
            else: raise AssertionError(f'unmodeled operation {op}')
            out[e] = result
    result = b''.join((value & mask).to_bytes(bits//BITS_PER_BYTE, 'little') for value in out)
    bank = list(vectors)
    bank[operand.destination] = result
    return tuple(bank)
