"""Integer-only predicates for the pinned SVE floating-comparison family.

FPCR is the EFFECTIVE control word supplied by the shared streaming adapter;
raw FPCR storage is not altered. Ordinary streaming mode without FA64 masks
numerical trap enables before evaluation. A remaining enable explicitly refuses
active work. Inactive lanes do not evaluate numerical controls or their operands.
The architectural P setter, outside this pure model, owns storage above current PL.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .control import (
    FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_FZ16,
    FP_EXCEPTION_ENABLE_MASK, FP_EXCEPTION_ENABLE_SHIFT,
    FPSR_INPUT_DENORMAL, FPSR_INVALID,
)

BITS_PER_BYTE = 8
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256


class Kind(Enum):
    EQUAL = "FCMEQ"
    GREATER_EQUAL = "FCMGE"
    GREATER = "FCMGT"
    LESS_EQUAL = "FCMLE"
    LESS = "FCMLT"
    NOT_EQUAL = "FCMNE"
    UNORDERED = "FCMUO"
    ABSOLUTE_GREATER_EQUAL = "FACGE"
    ABSOLUTE_GREATER = "FACGT"


@dataclass(frozen=True)
class LaneResult:
    predicate: bool
    exceptions: int


@dataclass(frozen=True)
class VectorResult:
    predicate: bytes
    fpsr: int
    exceptions: int
    active_lanes: int


class UnsupportedControl(ValueError):
    """Enabled traps require the central precise exception-delivery boundary."""

    def __init__(self, enabled_exceptions: int):
        self.enabled_exceptions = enabled_exceptions
        super().__init__(f"enabled FP exceptions: {enabled_exceptions:#x}")


def _format(element_bits: int) -> tuple[int, int]:
    try:
        return {16: (10, 5), 32: (23, 8), 64: (52, 11)}[element_bits]
    except KeyError as error:
        raise ValueError("FP predicate elements must be Half, Single or Double") from error


def _unpack(element_bits: int, bits: int, fpcr: int) -> tuple[int, str, int]:
    fraction_bits, exponent_bits = _format(element_bits)
    sign_mask = 1 << (element_bits - 1)
    bits &= (1 << element_bits) - 1
    exponent_mask = ((1 << exponent_bits) - 1) << fraction_bits
    fraction = bits & ((1 << fraction_bits) - 1)
    exponent = bits & exponent_mask
    if exponent == exponent_mask:
        if fraction == 0:
            return bits, "infinity", 0
        quiet = bool(fraction & (1 << (fraction_bits - 1)))
        return bits, "quiet_nan" if quiet else "signaling_nan", 0
    if exponent:
        return bits, "normal", 0
    if not fraction:
        return bits, "zero", 0
    alternative = bool(fpcr & FPCR_AH)
    if element_bits == 16:
        flush = bool(fpcr & FPCR_FZ16)
    else:
        flush = bool(fpcr & FPCR_FIZ) or bool(fpcr & FPCR_FZ) and not alternative
    if flush:
        exceptions = (FPSR_INPUT_DENORMAL if element_bits != 16
                      and fpcr & FPCR_FZ and not alternative else 0)
        return bits & sign_mask, "zero", exceptions
    return bits, "denormal", 0


def evaluate_lane(kind: Kind, element_bits: int, fpcr: int,
                  left: int, right: int) -> LaneResult:
    """Evaluate one active lane without host floating point or NZCV effects."""
    if not isinstance(kind, Kind):
        raise ValueError("comparison kind must be a typed Kind")
    _format(element_bits)
    enabled = fpcr & FP_EXCEPTION_ENABLE_MASK
    if enabled:
        raise UnsupportedControl(enabled >> FP_EXCEPTION_ENABLE_SHIFT)
    left, left_class, left_status = _unpack(element_bits, left, fpcr)
    right, right_class, right_status = _unpack(element_bits, right, fpcr)
    exceptions = left_status | right_status
    left_nan = left_class in ("quiet_nan", "signaling_nan")
    right_nan = right_class in ("quiet_nan", "signaling_nan")
    if left_nan or right_nan:
        quiet_comparison = kind in (Kind.EQUAL, Kind.NOT_EQUAL, Kind.UNORDERED)
        if (not quiet_comparison or left_class == "signaling_nan"
                or right_class == "signaling_nan"):
            exceptions |= FPSR_INVALID
        return LaneResult(kind in (Kind.NOT_EQUAL, Kind.UNORDERED), exceptions)
    if (element_bits != 16 and fpcr & FPCR_AH
            and "denormal" in (left_class, right_class)):
        exceptions |= FPSR_INPUT_DENORMAL
    sign_mask = 1 << (element_bits - 1)
    if kind in (Kind.ABSOLUTE_GREATER_EQUAL, Kind.ABSOLUTE_GREATER):
        left &= ~sign_mask
        right &= ~sign_mask
    if left & ~sign_mask == 0 and right & ~sign_mask == 0:
        ordering = 0
    elif bool(left & sign_mask) != bool(right & sign_mask):
        ordering = -1 if left & sign_mask else 1
    else:
        ordering = (left > right) - (left < right)
        if left & sign_mask:
            ordering = -ordering
    passed = {
        Kind.EQUAL: ordering == 0,
        Kind.GREATER_EQUAL: ordering >= 0,
        Kind.GREATER: ordering > 0,
        Kind.LESS_EQUAL: ordering <= 0,
        Kind.LESS: ordering < 0,
        Kind.NOT_EQUAL: ordering != 0,
        Kind.UNORDERED: False,
        Kind.ABSOLUTE_GREATER_EQUAL: ordering >= 0,
        Kind.ABSOLUTE_GREATER: ordering > 0,
    }[kind]
    return LaneResult(passed, exceptions)


def evaluate_vector(kind: Kind, element_bits: int, fpcr: int, fpsr: int,
                    left: bytes, right: bytes | None,
                    governing: bytes) -> VectorResult:
    """Snapshot sources and construct all predicate groups before returning.

    Buffers span current VL/PL. None is the encoded positive-zero operand.
    Each group contains the result in its lowest bit and zero in every other
    bit, including inactive groups. P destination may alias its governor.
    """
    _format(element_bits)
    vector_bytes = len(left)
    if (not MIN_VECTOR_BYTES <= vector_bytes <= MAX_VECTOR_BYTES
            or vector_bytes & (vector_bytes - 1)):
        raise ValueError("vector bytes must match the central power-of-two VL profile")
    if right is not None and len(right) != vector_bytes:
        raise ValueError("both vector operands must span current VL")
    if len(governing) * BITS_PER_BYTE != vector_bytes:
        raise ValueError("predicate must contain one bit per vector byte")
    left = bytes(left)
    right = None if right is None else bytes(right)
    governing = int.from_bytes(bytes(governing), "little")
    lane_bytes = element_bits // BITS_PER_BYTE
    predicate = 0
    exceptions = 0
    active = 0
    for offset in range(0, vector_bytes, lane_bytes):
        if governing & (1 << offset):
            result = evaluate_lane(
                kind, element_bits, fpcr,
                int.from_bytes(left[offset:offset + lane_bytes], "little"),
                0 if right is None else int.from_bytes(right[offset:offset + lane_bytes], "little"),
            )
            predicate |= int(result.predicate) << offset
            exceptions |= result.exceptions
            active += 1
    return VectorResult(predicate.to_bytes(vector_bytes // BITS_PER_BYTE, "little"),
                        fpsr | exceptions, exceptions, active)
