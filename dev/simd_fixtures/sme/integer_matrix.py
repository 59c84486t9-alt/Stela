"""Independent integer SME matrix models using the shared scalable Snapshot.

Canonical identities and operand metadata come from pinned Arm A64 XML2026-06.
No private schema, production state layout or serializer is needed at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import struct

from scalable_frame import (
    Component, FIXED_VECTOR_BYTES, PRIMARY_BYTES, PRIMARY_VECTOR_OFFSET,
    Provenance, Snapshot, require_sme_length,
)

BITS_PER_BYTE = 8
VECTOR_REGISTER_COUNT = 32
PREDICATE_REGISTER_COUNT = 16
SEGMENT_BITS = 128
SELECTOR_MASK = (1 << 32) - 1
GPR_BYTES = 8
STACK_POINTER_OFFSET = 31 * GPR_BYTES
INITIAL_STACK_POINTER = 0x4007f000
REQUIRED = Component.PRIMARY | Component.Z | Component.P | Component.ZA | Component.SVCR


class OuterKind(Enum):
    MULTIPLY = 'outer_product'
    XNOR_COUNT = 'bitwise_outer_product'
    ADD_HORIZONTAL = 'add_horizontal'
    ADD_VERTICAL = 'add_vertical'


@dataclass(frozen=True)
class Outer:
    kind: OuterKind
    accumulator_bits: int
    source_bits: int
    products: int
    signed_left: bool
    signed_right: bool
    subtract: bool
    tile: int = 0
    predicate_left: int = 0
    predicate_right: int = 0
    left: int = 0
    right: int | None = 0


@dataclass(frozen=True)
class Long:
    source_bits: int
    accumulator_bits: int
    signed_left: bool
    signed_right: bool
    subtract: bool
    groups: int
    factor: int
    selector: int = 8
    offset: int = 0
    left: int = 0
    right: int = 0
    index: int | None = None
    group_right: bool = False


@dataclass(frozen=True)
class AddSub:
    subtract: bool
    sources: str
    element_bits: int
    groups: int
    selector: int = 8
    offset: int = 0
    left: int | None = None
    right: int = 0


def lane(data, index, bits, signed=False):
    size = bits // BITS_PER_BYTE
    begin = index * size
    return int.from_bytes(data[begin:begin + size], 'little', signed=signed)


def store_lane(data, begin, bits, value):
    size = bits // BITS_PER_BYTE
    data[begin:begin + size] = (value % (1 << bits)).to_bytes(size, 'little')


def active(predicate, index, bits):
    return bool(predicate & (1 << (index * (bits // BITS_PER_BYTE))))


def apply(operand, svl_bytes, x, z, p, za):
    """Return complete active ZA; preserve all other architectural components."""
    require_sme_length(svl_bytes)
    if len(x) != 31 or len(z) != VECTOR_REGISTER_COUNT or any(len(v) != svl_bytes for v in z):
        raise ValueError('register input shape differs from active SVL')
    if len(p) != PREDICATE_REGISTER_COUNT or len(za) != svl_bytes * svl_bytes:
        raise ValueError('predicate/ZA input shape differs from active SVL')
    result = bytearray(za)
    if isinstance(operand, Outer):
        bits = operand.accumulator_bits
        size = bits // BITS_PER_BYTE
        dimension = svl_bytes // size
        for row in range(dimension):
            for col in range(dimension):
                destination = (row * size + operand.tile) * svl_bytes + col * size
                delta = 0
                pn = p[operand.predicate_left]
                pm = p[operand.predicate_right]
                if operand.kind is OuterKind.MULTIPLY:
                    for term in range(operand.products):
                        n = row * operand.products + term
                        m = col * operand.products + term
                        if active(pn, n, operand.source_bits) and active(pm, m, operand.source_bits):
                            delta += (lane(z[operand.left], n, operand.source_bits, operand.signed_left)
                                      * lane(z[operand.right], m, operand.source_bits, operand.signed_right))
                elif active(pn, row, bits) and active(pm, col, bits):
                    if operand.kind is OuterKind.ADD_HORIZONTAL:
                        delta = lane(z[operand.left], col, bits)
                    elif operand.kind is OuterKind.ADD_VERTICAL:
                        delta = lane(z[operand.left], row, bits)
                    elif operand.kind is OuterKind.XNOR_COUNT:
                        delta = ((~(lane(z[operand.left], row, bits)
                                    ^ lane(z[operand.right], col, bits))) & ((1 << bits) - 1)).bit_count()
                    else:
                        raise ValueError('unknown outer-product kind')
                old = int.from_bytes(za[destination:destination + size], 'little')
                store_lane(result, destination, bits, old - delta if operand.subtract else old + delta)
        return bytes(result)
    if isinstance(operand, Long):
        stride = svl_bytes // operand.groups
        first_row = ((x[operand.selector] & SELECTOR_MASK) + operand.offset) % stride
        first_row -= first_row % operand.factor
        lanes = svl_bytes * BITS_PER_BYTE // operand.accumulator_bits
        segment_lanes = SEGMENT_BITS // operand.accumulator_bits
        for group in range(operand.groups):
            left = z[(operand.left + group) % VECTOR_REGISTER_COUNT]
            right = z[operand.right + group if operand.group_right else operand.right]
            for component in range(operand.factor):
                row = first_row + group * stride + component
                for element in range(lanes):
                    n = operand.factor * element + component
                    m = n if operand.index is None else (
                        operand.factor * (element - element % segment_lanes) + operand.index)
                    product = (lane(left, n, operand.source_bits, operand.signed_left)
                               * lane(right, m, operand.source_bits, operand.signed_right))
                    size = operand.accumulator_bits // BITS_PER_BYTE
                    destination = row * svl_bytes + element * size
                    old = int.from_bytes(za[destination:destination + size], 'little')
                    store_lane(result, destination, operand.accumulator_bits,
                               old - product if operand.subtract else old + product)
        return bytes(result)
    if not isinstance(operand, AddSub):
        raise TypeError('unknown integer matrix operand')
    stride = svl_bytes // operand.groups
    first_row = ((x[operand.selector] & SELECTOR_MASK) + operand.offset) % stride
    for group in range(operand.groups):
        row = first_row + group * stride
        left = (za[row * svl_bytes:(row + 1) * svl_bytes] if operand.sources == 'zw'
                else z[(operand.left + group) % VECTOR_REGISTER_COUNT])
        right = z[operand.right if operand.sources == 'zzv' else operand.right + group]
        for element in range(svl_bytes * BITS_PER_BYTE // operand.element_bits):
            value = lane(left, element, operand.element_bits)
            other = lane(right, element, operand.element_bits)
            destination = row * svl_bytes + element * (operand.element_bits // BITS_PER_BYTE)
            store_lane(result, destination, operand.element_bits,
                       value - other if operand.subtract else value + other)
    return bytes(result)


# Canonical minimum/maximum operands, including every dynamic-size allocation.
FORMS = (
    ('add_za_zw_2x2', 0xc1a01c10,
     AddSub(False, 'zw', 32, 2, 8, 0, None, 0)),
    ('add_za_zw_2x2', 0xc1e07fd7,
     AddSub(False, 'zw', 64, 2, 11, 7, None, 30)),
    ('add_za_zw_4x4', 0xc1a11c10,
     AddSub(False, 'zw', 32, 4, 8, 0, None, 0)),
    ('add_za_zw_4x4', 0xc1e17f97,
     AddSub(False, 'zw', 64, 4, 11, 7, None, 28)),
    ('add_za_zzv_2x1', 0xc1201810,
     AddSub(False, 'zzv', 32, 2, 8, 0, 0, 0)),
    ('add_za_zzv_2x1', 0xc16f7bf7,
     AddSub(False, 'zzv', 64, 2, 11, 7, 31, 15)),
    ('add_za_zzv_4x1', 0xc1301810,
     AddSub(False, 'zzv', 32, 4, 8, 0, 0, 0)),
    ('add_za_zzv_4x1', 0xc17f7bf7,
     AddSub(False, 'zzv', 64, 4, 11, 7, 31, 15)),
    ('add_za_zzw_2x2', 0xc1a01810,
     AddSub(False, 'zzw', 32, 2, 8, 0, 0, 0)),
    ('add_za_zzw_2x2', 0xc1fe7bd7,
     AddSub(False, 'zzw', 64, 2, 11, 7, 30, 30)),
    ('add_za_zzw_4x4', 0xc1a11810,
     AddSub(False, 'zzw', 32, 4, 8, 0, 0, 0)),
    ('add_za_zzw_4x4', 0xc1fd7b97,
     AddSub(False, 'zzw', 64, 4, 11, 7, 28, 28)),
    ('addha_za_pp_z_32', 0xc0900000,
     Outer(OuterKind.ADD_HORIZONTAL, 32, 32, 1, False, False, False, 0, 0, 0, 0, None)),
    ('addha_za_pp_z_32', 0xc090ffe3,
     Outer(OuterKind.ADD_HORIZONTAL, 32, 32, 1, False, False, False, 3, 7, 7, 31, None)),
    ('addha_za_pp_z_64', 0xc0d00000,
     Outer(OuterKind.ADD_HORIZONTAL, 64, 64, 1, False, False, False, 0, 0, 0, 0, None)),
    ('addha_za_pp_z_64', 0xc0d0ffe7,
     Outer(OuterKind.ADD_HORIZONTAL, 64, 64, 1, False, False, False, 7, 7, 7, 31, None)),
    ('addva_za_pp_z_32', 0xc0910000,
     Outer(OuterKind.ADD_VERTICAL, 32, 32, 1, False, False, False, 0, 0, 0, 0, None)),
    ('addva_za_pp_z_32', 0xc091ffe3,
     Outer(OuterKind.ADD_VERTICAL, 32, 32, 1, False, False, False, 3, 7, 7, 31, None)),
    ('addva_za_pp_z_64', 0xc0d10000,
     Outer(OuterKind.ADD_VERTICAL, 64, 64, 1, False, False, False, 0, 0, 0, 0, None)),
    ('addva_za_pp_z_64', 0xc0d1ffe7,
     Outer(OuterKind.ADD_VERTICAL, 64, 64, 1, False, False, False, 7, 7, 7, 31, None)),
    ('bmopa_za_pp_zz_32', 0x80800008,
     Outer(OuterKind.XNOR_COUNT, 32, 32, 1, False, False, False, 0, 0, 0, 0, 0)),
    ('bmopa_za_pp_zz_32', 0x809fffeb,
     Outer(OuterKind.XNOR_COUNT, 32, 32, 1, False, False, False, 3, 7, 7, 31, 31)),
    ('bmops_za_pp_zz_32', 0x80800018,
     Outer(OuterKind.XNOR_COUNT, 32, 32, 1, False, False, True, 0, 0, 0, 0, 0)),
    ('bmops_za_pp_zz_32', 0x809ffffb,
     Outer(OuterKind.XNOR_COUNT, 32, 32, 1, False, False, True, 3, 7, 7, 31, 31)),
    ('smlal_za_zzi_1', 0xc1c01000,
     Long(16, 32, True, True, False, 1, 2, 8, 0, 0, 0, 0, False)),
    ('smlal_za_zzi_1', 0xc1cfffe7,
     Long(16, 32, True, True, False, 1, 2, 11, 14, 31, 15, 7, False)),
    ('smlal_za_zzi_2xi', 0xc1d01000,
     Long(16, 32, True, True, False, 2, 2, 8, 0, 0, 0, 0, False)),
    ('smlal_za_zzi_2xi', 0xc1df7fc7,
     Long(16, 32, True, True, False, 2, 2, 11, 6, 30, 15, 7, False)),
    ('smlal_za_zzi_4xi', 0xc1d09000,
     Long(16, 32, True, True, False, 4, 2, 8, 0, 0, 0, 0, False)),
    ('smlal_za_zzi_4xi', 0xc1dfff87,
     Long(16, 32, True, True, False, 4, 2, 11, 6, 28, 15, 7, False)),
    ('smlal_za_zzv_1', 0xc1600c00,
     Long(16, 32, True, True, False, 1, 2, 8, 0, 0, 0, None, False)),
    ('smlal_za_zzv_1', 0xc16f6fe7,
     Long(16, 32, True, True, False, 1, 2, 11, 14, 31, 15, None, False)),
    ('smlal_za_zzv_2x1', 0xc1600800,
     Long(16, 32, True, True, False, 2, 2, 8, 0, 0, 0, None, False)),
    ('smlal_za_zzv_2x1', 0xc16f6be3,
     Long(16, 32, True, True, False, 2, 2, 11, 6, 31, 15, None, False)),
    ('smlal_za_zzv_4x1', 0xc1700800,
     Long(16, 32, True, True, False, 4, 2, 8, 0, 0, 0, None, False)),
    ('smlal_za_zzv_4x1', 0xc17f6be3,
     Long(16, 32, True, True, False, 4, 2, 11, 6, 31, 15, None, False)),
    ('smlal_za_zzw_2x2', 0xc1e00800,
     Long(16, 32, True, True, False, 2, 2, 8, 0, 0, 0, None, True)),
    ('smlal_za_zzw_2x2', 0xc1fe6bc3,
     Long(16, 32, True, True, False, 2, 2, 11, 6, 30, 30, None, True)),
    ('smlal_za_zzw_4x4', 0xc1e10800,
     Long(16, 32, True, True, False, 4, 2, 8, 0, 0, 0, None, True)),
    ('smlal_za_zzw_4x4', 0xc1fd6b83,
     Long(16, 32, True, True, False, 4, 2, 11, 6, 28, 28, None, True)),
    ('smlall_za_zzi_s', 0xc1000000,
     Long(8, 32, True, True, False, 1, 4, 8, 0, 0, 0, 0, False)),
    ('smlall_za_zzi_s', 0xc10fffe3,
     Long(8, 32, True, True, False, 1, 4, 11, 12, 31, 15, 15, False)),
    ('smlall_za_zzi_d', 0xc1800000,
     Long(16, 64, True, True, False, 1, 4, 8, 0, 0, 0, 0, False)),
    ('smlall_za_zzi_d', 0xc18fefe3,
     Long(16, 64, True, True, False, 1, 4, 11, 12, 31, 15, 7, False)),
    ('smlall_za_zzi_s2xi', 0xc1100000,
     Long(8, 32, True, True, False, 2, 4, 8, 0, 0, 0, 0, False)),
    ('smlall_za_zzi_s2xi', 0xc11f6fc7,
     Long(8, 32, True, True, False, 2, 4, 11, 4, 30, 15, 15, False)),
    ('smlall_za_zzi_d2xi', 0xc1900000,
     Long(16, 64, True, True, False, 2, 4, 8, 0, 0, 0, 0, False)),
    ('smlall_za_zzi_d2xi', 0xc19f67c7,
     Long(16, 64, True, True, False, 2, 4, 11, 4, 30, 15, 7, False)),
    ('smlall_za_zzi_s4xi', 0xc1108000,
     Long(8, 32, True, True, False, 4, 4, 8, 0, 0, 0, 0, False)),
    ('smlall_za_zzi_s4xi', 0xc11fef87,
     Long(8, 32, True, True, False, 4, 4, 11, 4, 28, 15, 15, False)),
    ('smlall_za_zzi_d4xi', 0xc1908000,
     Long(16, 64, True, True, False, 4, 4, 8, 0, 0, 0, 0, False)),
    ('smlall_za_zzi_d4xi', 0xc19fe787,
     Long(16, 64, True, True, False, 4, 4, 11, 4, 28, 15, 7, False)),
    ('smlall_za_zzv_1', 0xc1200400,
     Long(8, 32, True, True, False, 1, 4, 8, 0, 0, 0, None, False)),
    ('smlall_za_zzv_1', 0xc16f67e3,
     Long(16, 64, True, True, False, 1, 4, 11, 12, 31, 15, None, False)),
    ('smlall_za_zzv_2x1', 0xc1200000,
     Long(8, 32, True, True, False, 2, 4, 8, 0, 0, 0, None, False)),
    ('smlall_za_zzv_2x1', 0xc16f63e1,
     Long(16, 64, True, True, False, 2, 4, 11, 4, 31, 15, None, False)),
    ('smlall_za_zzv_4x1', 0xc1300000,
     Long(8, 32, True, True, False, 4, 4, 8, 0, 0, 0, None, False)),
    ('smlall_za_zzv_4x1', 0xc17f63e1,
     Long(16, 64, True, True, False, 4, 4, 11, 4, 31, 15, None, False)),
    ('smlall_za_zzw_2x2', 0xc1a00000,
     Long(8, 32, True, True, False, 2, 4, 8, 0, 0, 0, None, True)),
    ('smlall_za_zzw_2x2', 0xc1fe63c1,
     Long(16, 64, True, True, False, 2, 4, 11, 4, 30, 30, None, True)),
    ('smlall_za_zzw_4x4', 0xc1a10000,
     Long(8, 32, True, True, False, 4, 4, 8, 0, 0, 0, None, True)),
    ('smlall_za_zzw_4x4', 0xc1fd6381,
     Long(16, 64, True, True, False, 4, 4, 11, 4, 28, 28, None, True)),
    ('smlsl_za_zzi_1', 0xc1c01008,
     Long(16, 32, True, True, True, 1, 2, 8, 0, 0, 0, 0, False)),
    ('smlsl_za_zzi_1', 0xc1cfffef,
     Long(16, 32, True, True, True, 1, 2, 11, 14, 31, 15, 7, False)),
    ('smlsl_za_zzi_2xi', 0xc1d01008,
     Long(16, 32, True, True, True, 2, 2, 8, 0, 0, 0, 0, False)),
    ('smlsl_za_zzi_2xi', 0xc1df7fcf,
     Long(16, 32, True, True, True, 2, 2, 11, 6, 30, 15, 7, False)),
    ('smlsl_za_zzi_4xi', 0xc1d09008,
     Long(16, 32, True, True, True, 4, 2, 8, 0, 0, 0, 0, False)),
    ('smlsl_za_zzi_4xi', 0xc1dfff8f,
     Long(16, 32, True, True, True, 4, 2, 11, 6, 28, 15, 7, False)),
    ('smlsl_za_zzv_1', 0xc1600c08,
     Long(16, 32, True, True, True, 1, 2, 8, 0, 0, 0, None, False)),
    ('smlsl_za_zzv_1', 0xc16f6fef,
     Long(16, 32, True, True, True, 1, 2, 11, 14, 31, 15, None, False)),
    ('smlsl_za_zzv_2x1', 0xc1600808,
     Long(16, 32, True, True, True, 2, 2, 8, 0, 0, 0, None, False)),
    ('smlsl_za_zzv_2x1', 0xc16f6beb,
     Long(16, 32, True, True, True, 2, 2, 11, 6, 31, 15, None, False)),
    ('smlsl_za_zzv_4x1', 0xc1700808,
     Long(16, 32, True, True, True, 4, 2, 8, 0, 0, 0, None, False)),
    ('smlsl_za_zzv_4x1', 0xc17f6beb,
     Long(16, 32, True, True, True, 4, 2, 11, 6, 31, 15, None, False)),
    ('smlsl_za_zzw_2x2', 0xc1e00808,
     Long(16, 32, True, True, True, 2, 2, 8, 0, 0, 0, None, True)),
    ('smlsl_za_zzw_2x2', 0xc1fe6bcb,
     Long(16, 32, True, True, True, 2, 2, 11, 6, 30, 30, None, True)),
    ('smlsl_za_zzw_4x4', 0xc1e10808,
     Long(16, 32, True, True, True, 4, 2, 8, 0, 0, 0, None, True)),
    ('smlsl_za_zzw_4x4', 0xc1fd6b8b,
     Long(16, 32, True, True, True, 4, 2, 11, 6, 28, 28, None, True)),
    ('smlsll_za_zzi_s', 0xc1000008,
     Long(8, 32, True, True, True, 1, 4, 8, 0, 0, 0, 0, False)),
    ('smlsll_za_zzi_s', 0xc10fffeb,
     Long(8, 32, True, True, True, 1, 4, 11, 12, 31, 15, 15, False)),
    ('smlsll_za_zzi_d', 0xc1800008,
     Long(16, 64, True, True, True, 1, 4, 8, 0, 0, 0, 0, False)),
    ('smlsll_za_zzi_d', 0xc18fefeb,
     Long(16, 64, True, True, True, 1, 4, 11, 12, 31, 15, 7, False)),
    ('smlsll_za_zzi_s2xi', 0xc1100008,
     Long(8, 32, True, True, True, 2, 4, 8, 0, 0, 0, 0, False)),
    ('smlsll_za_zzi_s2xi', 0xc11f6fcf,
     Long(8, 32, True, True, True, 2, 4, 11, 4, 30, 15, 15, False)),
    ('smlsll_za_zzi_d2xi', 0xc1900008,
     Long(16, 64, True, True, True, 2, 4, 8, 0, 0, 0, 0, False)),
    ('smlsll_za_zzi_d2xi', 0xc19f67cf,
     Long(16, 64, True, True, True, 2, 4, 11, 4, 30, 15, 7, False)),
    ('smlsll_za_zzi_s4xi', 0xc1108008,
     Long(8, 32, True, True, True, 4, 4, 8, 0, 0, 0, 0, False)),
    ('smlsll_za_zzi_s4xi', 0xc11fef8f,
     Long(8, 32, True, True, True, 4, 4, 11, 4, 28, 15, 15, False)),
    ('smlsll_za_zzi_d4xi', 0xc1908008,
     Long(16, 64, True, True, True, 4, 4, 8, 0, 0, 0, 0, False)),
    ('smlsll_za_zzi_d4xi', 0xc19fe78f,
     Long(16, 64, True, True, True, 4, 4, 11, 4, 28, 15, 7, False)),
    ('smlsll_za_zzv_1', 0xc1200408,
     Long(8, 32, True, True, True, 1, 4, 8, 0, 0, 0, None, False)),
    ('smlsll_za_zzv_1', 0xc16f67eb,
     Long(16, 64, True, True, True, 1, 4, 11, 12, 31, 15, None, False)),
    ('smlsll_za_zzv_2x1', 0xc1200008,
     Long(8, 32, True, True, True, 2, 4, 8, 0, 0, 0, None, False)),
    ('smlsll_za_zzv_2x1', 0xc16f63e9,
     Long(16, 64, True, True, True, 2, 4, 11, 4, 31, 15, None, False)),
    ('smlsll_za_zzv_4x1', 0xc1300008,
     Long(8, 32, True, True, True, 4, 4, 8, 0, 0, 0, None, False)),
    ('smlsll_za_zzv_4x1', 0xc17f63e9,
     Long(16, 64, True, True, True, 4, 4, 11, 4, 31, 15, None, False)),
    ('smlsll_za_zzw_2x2', 0xc1a00008,
     Long(8, 32, True, True, True, 2, 4, 8, 0, 0, 0, None, True)),
    ('smlsll_za_zzw_2x2', 0xc1fe63c9,
     Long(16, 64, True, True, True, 2, 4, 11, 4, 30, 30, None, True)),
    ('smlsll_za_zzw_4x4', 0xc1a10008,
     Long(8, 32, True, True, True, 4, 4, 8, 0, 0, 0, None, True)),
    ('smlsll_za_zzw_4x4', 0xc1fd6389,
     Long(16, 64, True, True, True, 4, 4, 11, 4, 28, 28, None, True)),
    ('smopa_za32_pp_zz_16', 0xa0800008,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, True, True, False, 0, 0, 0, 0, 0)),
    ('smopa_za32_pp_zz_16', 0xa09fffeb,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, True, True, False, 3, 7, 7, 31, 31)),
    ('smopa_za_pp_zz_32', 0xa0800000,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, True, False, 0, 0, 0, 0, 0)),
    ('smopa_za_pp_zz_32', 0xa09fffe3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, True, False, 3, 7, 7, 31, 31)),
    ('smopa_za_pp_zz_64', 0xa0c00000,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, True, False, 0, 0, 0, 0, 0)),
    ('smopa_za_pp_zz_64', 0xa0dfffe7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, True, False, 7, 7, 7, 31, 31)),
    ('smops_za32_pp_zz_16', 0xa0800018,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, True, True, True, 0, 0, 0, 0, 0)),
    ('smops_za32_pp_zz_16', 0xa09ffffb,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, True, True, True, 3, 7, 7, 31, 31)),
    ('smops_za_pp_zz_32', 0xa0800010,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, True, True, 0, 0, 0, 0, 0)),
    ('smops_za_pp_zz_32', 0xa09ffff3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, True, True, 3, 7, 7, 31, 31)),
    ('smops_za_pp_zz_64', 0xa0c00010,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, True, True, 0, 0, 0, 0, 0)),
    ('smops_za_pp_zz_64', 0xa0dffff7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, True, True, 7, 7, 7, 31, 31)),
    ('sub_za_zw_2x2', 0xc1a01c18,
     AddSub(True, 'zw', 32, 2, 8, 0, None, 0)),
    ('sub_za_zw_2x2', 0xc1e07fdf,
     AddSub(True, 'zw', 64, 2, 11, 7, None, 30)),
    ('sub_za_zw_4x4', 0xc1a11c18,
     AddSub(True, 'zw', 32, 4, 8, 0, None, 0)),
    ('sub_za_zw_4x4', 0xc1e17f9f,
     AddSub(True, 'zw', 64, 4, 11, 7, None, 28)),
    ('sub_za_zzv_2x1', 0xc1201818,
     AddSub(True, 'zzv', 32, 2, 8, 0, 0, 0)),
    ('sub_za_zzv_2x1', 0xc16f7bff,
     AddSub(True, 'zzv', 64, 2, 11, 7, 31, 15)),
    ('sub_za_zzv_4x1', 0xc1301818,
     AddSub(True, 'zzv', 32, 4, 8, 0, 0, 0)),
    ('sub_za_zzv_4x1', 0xc17f7bff,
     AddSub(True, 'zzv', 64, 4, 11, 7, 31, 15)),
    ('sub_za_zzw_2x2', 0xc1a01818,
     AddSub(True, 'zzw', 32, 2, 8, 0, 0, 0)),
    ('sub_za_zzw_2x2', 0xc1fe7bdf,
     AddSub(True, 'zzw', 64, 2, 11, 7, 30, 30)),
    ('sub_za_zzw_4x4', 0xc1a11818,
     AddSub(True, 'zzw', 32, 4, 8, 0, 0, 0)),
    ('sub_za_zzw_4x4', 0xc1fd7b9f,
     AddSub(True, 'zzw', 64, 4, 11, 7, 28, 28)),
    ('sumlall_za_zzi_s', 0xc1000014,
     Long(8, 32, True, False, False, 1, 4, 8, 0, 0, 0, 0, False)),
    ('sumlall_za_zzi_s', 0xc10ffff7,
     Long(8, 32, True, False, False, 1, 4, 11, 12, 31, 15, 15, False)),
    ('sumlall_za_zzi_s2xi', 0xc1100030,
     Long(8, 32, True, False, False, 2, 4, 8, 0, 0, 0, 0, False)),
    ('sumlall_za_zzi_s2xi', 0xc11f6ff7,
     Long(8, 32, True, False, False, 2, 4, 11, 4, 30, 15, 15, False)),
    ('sumlall_za_zzi_s4xi', 0xc1108030,
     Long(8, 32, True, False, False, 4, 4, 8, 0, 0, 0, 0, False)),
    ('sumlall_za_zzi_s4xi', 0xc11fefb7,
     Long(8, 32, True, False, False, 4, 4, 11, 4, 28, 15, 15, False)),
    ('sumlall_za_zzv_s2x1', 0xc1200014,
     Long(8, 32, True, False, False, 2, 4, 8, 0, 0, 0, None, False)),
    ('sumlall_za_zzv_s2x1', 0xc12f63f5,
     Long(8, 32, True, False, False, 2, 4, 11, 4, 31, 15, None, False)),
    ('sumlall_za_zzv_s4x1', 0xc1300014,
     Long(8, 32, True, False, False, 4, 4, 8, 0, 0, 0, None, False)),
    ('sumlall_za_zzv_s4x1', 0xc13f63f5,
     Long(8, 32, True, False, False, 4, 4, 11, 4, 31, 15, None, False)),
    ('sumopa_za_pp_zz_32', 0xa0a00000,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, False, False, 0, 0, 0, 0, 0)),
    ('sumopa_za_pp_zz_32', 0xa0bfffe3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, False, False, 3, 7, 7, 31, 31)),
    ('sumopa_za_pp_zz_64', 0xa0e00000,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, False, False, 0, 0, 0, 0, 0)),
    ('sumopa_za_pp_zz_64', 0xa0ffffe7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, False, False, 7, 7, 7, 31, 31)),
    ('sumops_za_pp_zz_32', 0xa0a00010,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, False, True, 0, 0, 0, 0, 0)),
    ('sumops_za_pp_zz_32', 0xa0bffff3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, True, False, True, 3, 7, 7, 31, 31)),
    ('sumops_za_pp_zz_64', 0xa0e00010,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, False, True, 0, 0, 0, 0, 0)),
    ('sumops_za_pp_zz_64', 0xa0fffff7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, True, False, True, 7, 7, 7, 31, 31)),
    ('umlal_za_zzi_1', 0xc1c01010,
     Long(16, 32, False, False, False, 1, 2, 8, 0, 0, 0, 0, False)),
    ('umlal_za_zzi_1', 0xc1cffff7,
     Long(16, 32, False, False, False, 1, 2, 11, 14, 31, 15, 7, False)),
    ('umlal_za_zzi_2xi', 0xc1d01010,
     Long(16, 32, False, False, False, 2, 2, 8, 0, 0, 0, 0, False)),
    ('umlal_za_zzi_2xi', 0xc1df7fd7,
     Long(16, 32, False, False, False, 2, 2, 11, 6, 30, 15, 7, False)),
    ('umlal_za_zzi_4xi', 0xc1d09010,
     Long(16, 32, False, False, False, 4, 2, 8, 0, 0, 0, 0, False)),
    ('umlal_za_zzi_4xi', 0xc1dfff97,
     Long(16, 32, False, False, False, 4, 2, 11, 6, 28, 15, 7, False)),
    ('umlal_za_zzv_1', 0xc1600c10,
     Long(16, 32, False, False, False, 1, 2, 8, 0, 0, 0, None, False)),
    ('umlal_za_zzv_1', 0xc16f6ff7,
     Long(16, 32, False, False, False, 1, 2, 11, 14, 31, 15, None, False)),
    ('umlal_za_zzv_2x1', 0xc1600810,
     Long(16, 32, False, False, False, 2, 2, 8, 0, 0, 0, None, False)),
    ('umlal_za_zzv_2x1', 0xc16f6bf3,
     Long(16, 32, False, False, False, 2, 2, 11, 6, 31, 15, None, False)),
    ('umlal_za_zzv_4x1', 0xc1700810,
     Long(16, 32, False, False, False, 4, 2, 8, 0, 0, 0, None, False)),
    ('umlal_za_zzv_4x1', 0xc17f6bf3,
     Long(16, 32, False, False, False, 4, 2, 11, 6, 31, 15, None, False)),
    ('umlal_za_zzw_2x2', 0xc1e00810,
     Long(16, 32, False, False, False, 2, 2, 8, 0, 0, 0, None, True)),
    ('umlal_za_zzw_2x2', 0xc1fe6bd3,
     Long(16, 32, False, False, False, 2, 2, 11, 6, 30, 30, None, True)),
    ('umlal_za_zzw_4x4', 0xc1e10810,
     Long(16, 32, False, False, False, 4, 2, 8, 0, 0, 0, None, True)),
    ('umlal_za_zzw_4x4', 0xc1fd6b93,
     Long(16, 32, False, False, False, 4, 2, 11, 6, 28, 28, None, True)),
    ('umlall_za_zzi_s', 0xc1000010,
     Long(8, 32, False, False, False, 1, 4, 8, 0, 0, 0, 0, False)),
    ('umlall_za_zzi_s', 0xc10ffff3,
     Long(8, 32, False, False, False, 1, 4, 11, 12, 31, 15, 15, False)),
    ('umlall_za_zzi_d', 0xc1800010,
     Long(16, 64, False, False, False, 1, 4, 8, 0, 0, 0, 0, False)),
    ('umlall_za_zzi_d', 0xc18feff3,
     Long(16, 64, False, False, False, 1, 4, 11, 12, 31, 15, 7, False)),
    ('umlall_za_zzi_s2xi', 0xc1100010,
     Long(8, 32, False, False, False, 2, 4, 8, 0, 0, 0, 0, False)),
    ('umlall_za_zzi_s2xi', 0xc11f6fd7,
     Long(8, 32, False, False, False, 2, 4, 11, 4, 30, 15, 15, False)),
    ('umlall_za_zzi_d2xi', 0xc1900010,
     Long(16, 64, False, False, False, 2, 4, 8, 0, 0, 0, 0, False)),
    ('umlall_za_zzi_d2xi', 0xc19f67d7,
     Long(16, 64, False, False, False, 2, 4, 11, 4, 30, 15, 7, False)),
    ('umlall_za_zzi_s4xi', 0xc1108010,
     Long(8, 32, False, False, False, 4, 4, 8, 0, 0, 0, 0, False)),
    ('umlall_za_zzi_s4xi', 0xc11fef97,
     Long(8, 32, False, False, False, 4, 4, 11, 4, 28, 15, 15, False)),
    ('umlall_za_zzi_d4xi', 0xc1908010,
     Long(16, 64, False, False, False, 4, 4, 8, 0, 0, 0, 0, False)),
    ('umlall_za_zzi_d4xi', 0xc19fe797,
     Long(16, 64, False, False, False, 4, 4, 11, 4, 28, 15, 7, False)),
    ('umlall_za_zzv_1', 0xc1200410,
     Long(8, 32, False, False, False, 1, 4, 8, 0, 0, 0, None, False)),
    ('umlall_za_zzv_1', 0xc16f67f3,
     Long(16, 64, False, False, False, 1, 4, 11, 12, 31, 15, None, False)),
    ('umlall_za_zzv_2x1', 0xc1200010,
     Long(8, 32, False, False, False, 2, 4, 8, 0, 0, 0, None, False)),
    ('umlall_za_zzv_2x1', 0xc16f63f1,
     Long(16, 64, False, False, False, 2, 4, 11, 4, 31, 15, None, False)),
    ('umlall_za_zzv_4x1', 0xc1300010,
     Long(8, 32, False, False, False, 4, 4, 8, 0, 0, 0, None, False)),
    ('umlall_za_zzv_4x1', 0xc17f63f1,
     Long(16, 64, False, False, False, 4, 4, 11, 4, 31, 15, None, False)),
    ('umlall_za_zzw_2x2', 0xc1a00010,
     Long(8, 32, False, False, False, 2, 4, 8, 0, 0, 0, None, True)),
    ('umlall_za_zzw_2x2', 0xc1fe63d1,
     Long(16, 64, False, False, False, 2, 4, 11, 4, 30, 30, None, True)),
    ('umlall_za_zzw_4x4', 0xc1a10010,
     Long(8, 32, False, False, False, 4, 4, 8, 0, 0, 0, None, True)),
    ('umlall_za_zzw_4x4', 0xc1fd6391,
     Long(16, 64, False, False, False, 4, 4, 11, 4, 28, 28, None, True)),
    ('umlsl_za_zzi_1', 0xc1c01018,
     Long(16, 32, False, False, True, 1, 2, 8, 0, 0, 0, 0, False)),
    ('umlsl_za_zzi_1', 0xc1cfffff,
     Long(16, 32, False, False, True, 1, 2, 11, 14, 31, 15, 7, False)),
    ('umlsl_za_zzi_2xi', 0xc1d01018,
     Long(16, 32, False, False, True, 2, 2, 8, 0, 0, 0, 0, False)),
    ('umlsl_za_zzi_2xi', 0xc1df7fdf,
     Long(16, 32, False, False, True, 2, 2, 11, 6, 30, 15, 7, False)),
    ('umlsl_za_zzi_4xi', 0xc1d09018,
     Long(16, 32, False, False, True, 4, 2, 8, 0, 0, 0, 0, False)),
    ('umlsl_za_zzi_4xi', 0xc1dfff9f,
     Long(16, 32, False, False, True, 4, 2, 11, 6, 28, 15, 7, False)),
    ('umlsl_za_zzv_1', 0xc1600c18,
     Long(16, 32, False, False, True, 1, 2, 8, 0, 0, 0, None, False)),
    ('umlsl_za_zzv_1', 0xc16f6fff,
     Long(16, 32, False, False, True, 1, 2, 11, 14, 31, 15, None, False)),
    ('umlsl_za_zzv_2x1', 0xc1600818,
     Long(16, 32, False, False, True, 2, 2, 8, 0, 0, 0, None, False)),
    ('umlsl_za_zzv_2x1', 0xc16f6bfb,
     Long(16, 32, False, False, True, 2, 2, 11, 6, 31, 15, None, False)),
    ('umlsl_za_zzv_4x1', 0xc1700818,
     Long(16, 32, False, False, True, 4, 2, 8, 0, 0, 0, None, False)),
    ('umlsl_za_zzv_4x1', 0xc17f6bfb,
     Long(16, 32, False, False, True, 4, 2, 11, 6, 31, 15, None, False)),
    ('umlsl_za_zzw_2x2', 0xc1e00818,
     Long(16, 32, False, False, True, 2, 2, 8, 0, 0, 0, None, True)),
    ('umlsl_za_zzw_2x2', 0xc1fe6bdb,
     Long(16, 32, False, False, True, 2, 2, 11, 6, 30, 30, None, True)),
    ('umlsl_za_zzw_4x4', 0xc1e10818,
     Long(16, 32, False, False, True, 4, 2, 8, 0, 0, 0, None, True)),
    ('umlsl_za_zzw_4x4', 0xc1fd6b9b,
     Long(16, 32, False, False, True, 4, 2, 11, 6, 28, 28, None, True)),
    ('umlsll_za_zzi_s', 0xc1000018,
     Long(8, 32, False, False, True, 1, 4, 8, 0, 0, 0, 0, False)),
    ('umlsll_za_zzi_s', 0xc10ffffb,
     Long(8, 32, False, False, True, 1, 4, 11, 12, 31, 15, 15, False)),
    ('umlsll_za_zzi_d', 0xc1800018,
     Long(16, 64, False, False, True, 1, 4, 8, 0, 0, 0, 0, False)),
    ('umlsll_za_zzi_d', 0xc18feffb,
     Long(16, 64, False, False, True, 1, 4, 11, 12, 31, 15, 7, False)),
    ('umlsll_za_zzi_s2xi', 0xc1100018,
     Long(8, 32, False, False, True, 2, 4, 8, 0, 0, 0, 0, False)),
    ('umlsll_za_zzi_s2xi', 0xc11f6fdf,
     Long(8, 32, False, False, True, 2, 4, 11, 4, 30, 15, 15, False)),
    ('umlsll_za_zzi_d2xi', 0xc1900018,
     Long(16, 64, False, False, True, 2, 4, 8, 0, 0, 0, 0, False)),
    ('umlsll_za_zzi_d2xi', 0xc19f67df,
     Long(16, 64, False, False, True, 2, 4, 11, 4, 30, 15, 7, False)),
    ('umlsll_za_zzi_s4xi', 0xc1108018,
     Long(8, 32, False, False, True, 4, 4, 8, 0, 0, 0, 0, False)),
    ('umlsll_za_zzi_s4xi', 0xc11fef9f,
     Long(8, 32, False, False, True, 4, 4, 11, 4, 28, 15, 15, False)),
    ('umlsll_za_zzi_d4xi', 0xc1908018,
     Long(16, 64, False, False, True, 4, 4, 8, 0, 0, 0, 0, False)),
    ('umlsll_za_zzi_d4xi', 0xc19fe79f,
     Long(16, 64, False, False, True, 4, 4, 11, 4, 28, 15, 7, False)),
    ('umlsll_za_zzv_1', 0xc1200418,
     Long(8, 32, False, False, True, 1, 4, 8, 0, 0, 0, None, False)),
    ('umlsll_za_zzv_1', 0xc16f67fb,
     Long(16, 64, False, False, True, 1, 4, 11, 12, 31, 15, None, False)),
    ('umlsll_za_zzv_2x1', 0xc1200018,
     Long(8, 32, False, False, True, 2, 4, 8, 0, 0, 0, None, False)),
    ('umlsll_za_zzv_2x1', 0xc16f63f9,
     Long(16, 64, False, False, True, 2, 4, 11, 4, 31, 15, None, False)),
    ('umlsll_za_zzv_4x1', 0xc1300018,
     Long(8, 32, False, False, True, 4, 4, 8, 0, 0, 0, None, False)),
    ('umlsll_za_zzv_4x1', 0xc17f63f9,
     Long(16, 64, False, False, True, 4, 4, 11, 4, 31, 15, None, False)),
    ('umlsll_za_zzw_2x2', 0xc1a00018,
     Long(8, 32, False, False, True, 2, 4, 8, 0, 0, 0, None, True)),
    ('umlsll_za_zzw_2x2', 0xc1fe63d9,
     Long(16, 64, False, False, True, 2, 4, 11, 4, 30, 30, None, True)),
    ('umlsll_za_zzw_4x4', 0xc1a10018,
     Long(8, 32, False, False, True, 4, 4, 8, 0, 0, 0, None, True)),
    ('umlsll_za_zzw_4x4', 0xc1fd6399,
     Long(16, 64, False, False, True, 4, 4, 11, 4, 28, 28, None, True)),
    ('umopa_za32_pp_zz_16', 0xa1800008,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, False, False, False, 0, 0, 0, 0, 0)),
    ('umopa_za32_pp_zz_16', 0xa19fffeb,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, False, False, False, 3, 7, 7, 31, 31)),
    ('umopa_za_pp_zz_32', 0xa1a00000,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, False, False, 0, 0, 0, 0, 0)),
    ('umopa_za_pp_zz_32', 0xa1bfffe3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, False, False, 3, 7, 7, 31, 31)),
    ('umopa_za_pp_zz_64', 0xa1e00000,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, False, False, 0, 0, 0, 0, 0)),
    ('umopa_za_pp_zz_64', 0xa1ffffe7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, False, False, 7, 7, 7, 31, 31)),
    ('umops_za32_pp_zz_16', 0xa1800018,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, False, False, True, 0, 0, 0, 0, 0)),
    ('umops_za32_pp_zz_16', 0xa19ffffb,
     Outer(OuterKind.MULTIPLY, 32, 16, 2, False, False, True, 3, 7, 7, 31, 31)),
    ('umops_za_pp_zz_32', 0xa1a00010,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, False, True, 0, 0, 0, 0, 0)),
    ('umops_za_pp_zz_32', 0xa1bffff3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, False, True, 3, 7, 7, 31, 31)),
    ('umops_za_pp_zz_64', 0xa1e00010,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, False, True, 0, 0, 0, 0, 0)),
    ('umops_za_pp_zz_64', 0xa1fffff7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, False, True, 7, 7, 7, 31, 31)),
    ('usmlall_za_zzi_s', 0xc1000004,
     Long(8, 32, False, True, False, 1, 4, 8, 0, 0, 0, 0, False)),
    ('usmlall_za_zzi_s', 0xc10fffe7,
     Long(8, 32, False, True, False, 1, 4, 11, 12, 31, 15, 15, False)),
    ('usmlall_za_zzi_s2xi', 0xc1100020,
     Long(8, 32, False, True, False, 2, 4, 8, 0, 0, 0, 0, False)),
    ('usmlall_za_zzi_s2xi', 0xc11f6fe7,
     Long(8, 32, False, True, False, 2, 4, 11, 4, 30, 15, 15, False)),
    ('usmlall_za_zzi_s4xi', 0xc1108020,
     Long(8, 32, False, True, False, 4, 4, 8, 0, 0, 0, 0, False)),
    ('usmlall_za_zzi_s4xi', 0xc11fefa7,
     Long(8, 32, False, True, False, 4, 4, 11, 4, 28, 15, 15, False)),
    ('usmlall_za_zzv_s', 0xc1200404,
     Long(8, 32, False, True, False, 1, 4, 8, 0, 0, 0, None, False)),
    ('usmlall_za_zzv_s', 0xc12f67e7,
     Long(8, 32, False, True, False, 1, 4, 11, 12, 31, 15, None, False)),
    ('usmlall_za_zzv_s2x1', 0xc1200004,
     Long(8, 32, False, True, False, 2, 4, 8, 0, 0, 0, None, False)),
    ('usmlall_za_zzv_s2x1', 0xc12f63e5,
     Long(8, 32, False, True, False, 2, 4, 11, 4, 31, 15, None, False)),
    ('usmlall_za_zzv_s4x1', 0xc1300004,
     Long(8, 32, False, True, False, 4, 4, 8, 0, 0, 0, None, False)),
    ('usmlall_za_zzv_s4x1', 0xc13f63e5,
     Long(8, 32, False, True, False, 4, 4, 11, 4, 31, 15, None, False)),
    ('usmlall_za_zzw_s2x2', 0xc1a00004,
     Long(8, 32, False, True, False, 2, 4, 8, 0, 0, 0, None, True)),
    ('usmlall_za_zzw_s2x2', 0xc1be63c5,
     Long(8, 32, False, True, False, 2, 4, 11, 4, 30, 30, None, True)),
    ('usmlall_za_zzw_s4x4', 0xc1a10004,
     Long(8, 32, False, True, False, 4, 4, 8, 0, 0, 0, None, True)),
    ('usmlall_za_zzw_s4x4', 0xc1bd6385,
     Long(8, 32, False, True, False, 4, 4, 11, 4, 28, 28, None, True)),
    ('usmopa_za_pp_zz_32', 0xa1800000,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, True, False, 0, 0, 0, 0, 0)),
    ('usmopa_za_pp_zz_32', 0xa19fffe3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, True, False, 3, 7, 7, 31, 31)),
    ('usmopa_za_pp_zz_64', 0xa1c00000,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, True, False, 0, 0, 0, 0, 0)),
    ('usmopa_za_pp_zz_64', 0xa1dfffe7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, True, False, 7, 7, 7, 31, 31)),
    ('usmops_za_pp_zz_32', 0xa1800010,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, True, True, 0, 0, 0, 0, 0)),
    ('usmops_za_pp_zz_32', 0xa19ffff3,
     Outer(OuterKind.MULTIPLY, 32, 8, 4, False, True, True, 3, 7, 7, 31, 31)),
    ('usmops_za_pp_zz_64', 0xa1c00010,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, True, True, 0, 0, 0, 0, 0)),
    ('usmops_za_pp_zz_64', 0xa1dffff7,
     Outer(OuterKind.MULTIPLY, 64, 16, 4, False, True, True, 7, 7, 7, 31, 31)),
)
OPERANDS = {word: operand for _, word, operand in FORMS}


def expected(operation, initial, ram=None):
    """Recompute a directed fixture through the shared full Snapshot adapter."""
    if initial.valid & REQUIRED != REQUIRED:
        raise ValueError('complete primary/Z/P/ZA/SVCR input is required')
    if initial.control('svcr') != 3:
        raise ValueError('integer matrix corpus requires active SM and ZA')
    operand = OPERANDS[operation['word']]
    x = struct.unpack_from('<31Q', initial.primary)
    predicates = tuple(int.from_bytes(value, 'little') for value in initial.p)
    za = apply(operand, initial.svl_bytes, x, initial.z, predicates, initial.za)
    return replace(initial, za=za), ram, None


def scalable_cases(svl_bytes):
    """Yield all127 forms at minimum/maximum operands and two complete states."""
    require_sme_length(svl_bytes)
    for function_index, (canonical_id, word, _) in enumerate(FORMS):
        for plan in range(2):
            z = tuple(bytes((register * 61 + byte * 37 + plan * 83) % 256
                            for byte in range(svl_bytes))
                      for register in range(VECTOR_REGISTER_COUNT))
            predicate_value = (1 << svl_bytes) - 1 if not plan else 3
            p = tuple(predicate_value.to_bytes(svl_bytes // BITS_PER_BYTE, 'little')
                      for _ in range(PREDICATE_REGISTER_COUNT))
            za = bytes((byte * 131 + plan * 17) % 256
                       for byte in range(svl_bytes * svl_bytes))
            primary = bytearray(PRIMARY_BYTES)
            for register in range(31):
                struct.pack_into('<Q', primary, register * GPR_BYTES,
                                 (register + 1) * 0x0101010101010101)
            for selector in range(8, 12):
                struct.pack_into('<Q', primary, selector * GPR_BYTES,
                                 SELECTOR_MASK if plan else 0)
            struct.pack_into('<Q', primary, STACK_POINTER_OFFSET, INITIAL_STACK_POINTER)
            for register, vector in enumerate(z):
                begin = PRIMARY_VECTOR_OFFSET + register * FIXED_VECTOR_BYTES
                primary[begin:begin + FIXED_VECTOR_BYTES] = vector[:FIXED_VECTOR_BYTES]
            operation = {'word': word, 'canonical_id': canonical_id}
            initial = Snapshot(
                svl_bytes, bytes(primary), z, p, bytes(svl_bytes // BITS_PER_BYTE),
                za, bytes(64), REQUIRED, {'svcr': 3, 'requested_svcr': 3},
                Provenance.MODEL, case_index=function_index * 2 + plan,
                function_index=function_index,
            )
            output, _, fault = expected(operation, initial)
            yield {'operation': operation, 'initial': initial, 'expected': output,
                   'required': REQUIRED, 'fault': fault}
