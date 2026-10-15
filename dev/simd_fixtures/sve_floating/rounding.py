"""Integer-only oracle for the seven merging SVE FRINT operations.

The numerical profile has FP/FP16/AFP enabled. Controls are effective FPCR
values after the central streaming adapter; ordinary SM without FA64 masks
exception enables for evaluation while retaining raw architectural FPCR state.
Active numerical work with retained enables declines explicitly. Exception
delivery, SVE access checks and architectural upper-Z policy belong to the
execution harness. This model preserves provided container bytes above VL.
"""

from __future__ import annotations

from dataclasses import dataclass

from .control import (
    FPCR_AH,
    FPCR_DN,
    FPCR_FIZ,
    FPCR_FZ,
    FPCR_FZ16,
    FPCR_ROUNDING_MASK,
    FPCR_ROUNDING_SHIFT,
    FPSR_INEXACT,
    FPSR_INPUT_DENORMAL,
    FPSR_INVALID,
    FP_EXCEPTION_ENABLE_SHIFT,
    FP_EXCEPTION_MASK,
)

BITS_PER_BYTE = 8
SVE_VL_GRANULE_BYTES = 16
SVE_MAX_VL_BYTES = 256
ROUND_NEAREST_EVEN = 0
ROUND_POSITIVE = 1
ROUND_NEGATIVE = 2
ROUND_ZERO = 3
ROUND_NEAREST_AWAY = 4
OPERATIONS = ("FRINTA", "FRINTI", "FRINTM", "FRINTN", "FRINTP", "FRINTX", "FRINTZ")


@dataclass(frozen=True)
class LaneResult:
    bits: int
    exceptions: int


@dataclass(frozen=True)
class VectorResult:
    destination: bytes
    fpsr: int
    exceptions: int
    active_lanes: int


class UnsupportedControl(ValueError):
    """The enabled numerical exception boundary is not modeled as success."""

    def __init__(self, enabled_exceptions: int):
        self.enabled_exceptions = enabled_exceptions
        super().__init__(f"enabled FP exceptions: {enabled_exceptions:#x}")


def _format(element_bits: int) -> tuple[int, int, int]:
    try:
        return {16: (10, 5, 15), 32: (23, 8, 127), 64: (52, 11, 1023)}[element_bits]
    except KeyError as error:
        raise ValueError("FRINT element size must be 16, 32 or 64 bits") from error


def _rounding(operation: str, effective_fpcr: int) -> int:
    if operation not in OPERATIONS:
        raise ValueError(f"unsupported SVE integral-rounding operation: {operation}")
    if operation in ("FRINTI", "FRINTX"):
        return (effective_fpcr >> FPCR_ROUNDING_SHIFT) & FPCR_ROUNDING_MASK
    return {
        "FRINTA": ROUND_NEAREST_AWAY,
        "FRINTM": ROUND_NEGATIVE,
        "FRINTN": ROUND_NEAREST_EVEN,
        "FRINTP": ROUND_POSITIVE,
        "FRINTZ": ROUND_ZERO,
    }[operation]


def _encode_integer(magnitude: int, fraction_bits: int, bias: int) -> int:
    """Encode an exactly representable positive integer; zero is separate."""
    exponent = magnitude.bit_length() - 1
    if exponent <= fraction_bits:
        significand = magnitude << (fraction_bits - exponent)
    else:
        shift = exponent - fraction_bits
        assert magnitude & ((1 << shift) - 1) == 0
        significand = magnitude >> shift
    fraction_mask = (1 << fraction_bits) - 1
    return ((exponent + bias) << fraction_bits) | (significand & fraction_mask)


def evaluate_lane(operation: str, element_bits: int, effective_fpcr: int, value: int) -> LaneResult:
    """Return the result bits and fresh FPSR status for one active element.

    Controls have already passed through the central streaming adapter.
    Input upper bits are ignored. AHP/NEP do not affect these SVE operations.
    FPRoundInt suppresses AH=1 unpack-time IDC and has no post-round denormal
    processing; only FRINTX reports fractional IXC.
    """
    fraction_bits, exponent_bits, bias = _format(element_bits)
    rounding = _rounding(operation, effective_fpcr)
    enabled = (effective_fpcr >> FP_EXCEPTION_ENABLE_SHIFT) & FP_EXCEPTION_MASK
    if enabled:
        raise UnsupportedControl(enabled)
    lane_mask = (1 << element_bits) - 1
    sign_mask = 1 << (element_bits - 1)
    fraction_mask = (1 << fraction_bits) - 1
    exponent_max = (1 << exponent_bits) - 1
    quiet_bit = 1 << (fraction_bits - 1)
    value &= lane_mask
    sign = value & sign_mask
    fraction = value & fraction_mask
    exponent = (value >> fraction_bits) & exponent_max
    if exponent == exponent_max:
        if not fraction:
            return LaneResult(value, 0)
        exceptions = 0 if fraction & quiet_bit else FPSR_INVALID
        if effective_fpcr & FPCR_DN:
            default_sign = sign_mask if effective_fpcr & FPCR_AH else 0
            value = default_sign | (exponent_max << fraction_bits) | quiet_bit
        else:
            value |= quiet_bit
        return LaneResult(value, exceptions)
    if exponent == 0:
        if not fraction:
            return LaneResult(sign, 0)
        flush = bool(effective_fpcr & FPCR_FZ16) if element_bits == 16 else bool(
            effective_fpcr & FPCR_FIZ or effective_fpcr & FPCR_FZ and not effective_fpcr & FPCR_AH
        )
        if flush:
            exceptions = FPSR_INPUT_DENORMAL if (
                element_bits != 16 and effective_fpcr & FPCR_FZ and not effective_fpcr & FPCR_AH
            ) else 0
            return LaneResult(sign, exceptions)
        significand = fraction
        unbiased_exponent = 1 - bias
    else:
        significand = (1 << fraction_bits) | fraction
        unbiased_exponent = exponent - bias
    discarded_bits = fraction_bits - unbiased_exponent
    if discarded_bits <= 0:
        return LaneResult(value, 0)
    integer, remainder = divmod(significand, 1 << discarded_bits)
    increment = False
    if rounding in (ROUND_NEAREST_EVEN, ROUND_NEAREST_AWAY):
        midpoint = 1 << (discarded_bits - 1)
        increment = remainder > midpoint or remainder == midpoint and (
            rounding == ROUND_NEAREST_AWAY or bool(integer & 1)
        )
    elif rounding == ROUND_POSITIVE:
        increment = bool(remainder) and not sign
    elif rounding == ROUND_NEGATIVE:
        increment = bool(remainder) and bool(sign)
    integer += increment
    bits = sign | (_encode_integer(integer, fraction_bits, bias) if integer else 0)
    exceptions = FPSR_INEXACT if operation == "FRINTX" and remainder else 0
    return LaneResult(bits, exceptions)


def evaluate_vector(
    operation: str,
    element_bits: int,
    effective_fpcr: int,
    fpsr: int,
    source: bytes,
    destination: bytes,
    predicate: bytes | int,
    vl_bytes: int | None = None,
) -> VectorResult:
    """Evaluate a merging vector from snapshots, preserving inactive/tail bytes.

    effective_fpcr is supplied by the central streaming adapter; raw FPCR
    state is not modified. Tail preservation is a container policy; the central
    architectural Z setter owns final upper-Z behavior.
    Predicate bit e*(element_bits/8) controls lane e; other predicate bits are
    ignored. The source may alias destination. All-inactive vectors perform no
    numerical control check and generate no status. State commits only after
    all active lanes succeed, so unsupported controls leave caller data intact.
    """
    _format(element_bits)
    _rounding(operation, effective_fpcr)
    source = bytes(source)
    destination = bytes(destination)
    if vl_bytes is None:
        vl_bytes = len(destination)
    if not (SVE_VL_GRANULE_BYTES <= vl_bytes <= SVE_MAX_VL_BYTES):
        raise ValueError("VL must be between 16 and 256 bytes")
    if vl_bytes % SVE_VL_GRANULE_BYTES:
        raise ValueError("VL must be a multiple of 16 bytes")
    if len(source) < vl_bytes or len(destination) < vl_bytes:
        raise ValueError("vector snapshots are shorter than current VL")
    if isinstance(predicate, bytes):
        if len(predicate) * BITS_PER_BYTE < vl_bytes:
            raise ValueError("predicate snapshot is shorter than current PL")
        predicate = int.from_bytes(predicate, "little")
    if not isinstance(predicate, int) or predicate < 0:
        raise ValueError("predicate must be nonnegative bits or little-endian bytes")
    lane_bytes = element_bits // BITS_PER_BYTE
    result = bytearray(destination)
    exceptions = 0
    active_lanes = 0
    for offset in range(0, vl_bytes, lane_bytes):
        if predicate >> offset & 1:
            lane = evaluate_lane(
                operation,
                element_bits,
                effective_fpcr,
                int.from_bytes(source[offset:offset + lane_bytes], "little"),
            )
            result[offset:offset + lane_bytes] = lane.bits.to_bytes(lane_bytes, "little")
            exceptions |= lane.exceptions
            active_lanes += 1
    return VectorResult(bytes(result), fpsr | exceptions, exceptions, active_lanes)
