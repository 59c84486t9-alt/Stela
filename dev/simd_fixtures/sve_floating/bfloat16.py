"""Pure BF16 SVE models for the explicit streaming, non-FA64 profile.

All arithmetic uses exact rational numbers, independently of host FP controls.
This module models register results and cumulative status, not instruction
decoding, architectural state storage, or implementation-defined trap delivery.
"""

from dataclasses import dataclass
from fractions import Fraction

from .control import (
    FPCR_AH, FPCR_DN, FPCR_EBF, FPCR_FIZ, FPCR_FZ,
    FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT, FP_EXCEPTION_ENABLE_MASK,
    FPSR_INEXACT, FPSR_INPUT_DENORMAL, FPSR_INVALID, FPSR_OVERFLOW, FPSR_UNDERFLOW,
    effective_fpcr,
)


BF_BITS = 16
BF_FRACTION_BITS = 7
SINGLE_BITS = 32
SINGLE_FRACTION_BITS = 23
EXPONENT_BITS = 8
EXPONENT_BIAS = 127
MINIMUM_EXPONENT = -126
MAXIMUM_EXPONENT = 127
SEGMENT_BYTES = 16
MAXIMUM_VECTOR_BYTES = 256
BF_SIGN = 1 << (BF_BITS - 1)
SINGLE_SIGN = 1 << (SINGLE_BITS - 1)
BF_INFINITY = ((1 << EXPONENT_BITS) - 1) << BF_FRACTION_BITS
BF_FRACTION_MASK = (1 << BF_FRACTION_BITS) - 1
BF_QUIET = 1 << (BF_FRACTION_BITS - 1)
SINGLE_INFINITY = BF_INFINITY << BF_BITS
SINGLE_QUIET = BF_QUIET << BF_BITS
ROUND_NEAREST = 0
ROUND_POSITIVE = 1
ROUND_NEGATIVE = 2
ROUND_ZERO = 3


@dataclass(frozen=True)
class Profile:
    streaming: bool = True
    full_a64: bool = False
    afp: bool = True
    ebf16: bool = False


@dataclass(frozen=True)
class Outcome:
    value: bytes
    fpsr: int
    exceptions: int


class UnsupportedControl(ValueError):
    """The model cannot establish implementation-defined FP trap effects."""


@dataclass(frozen=True)
class _Operand:
    bits: int
    kind: str
    sign: int
    value: Fraction


def _power(exponent):
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)


class _Arithmetic:
    def __init__(self, fpcr, profile, *, suppress=False):
        self.fpcr = fpcr
        self.profile = profile
        self.suppress = suppress
        self.exceptions = 0
        if (not suppress and (not profile.streaming or profile.full_a64)
                and effective_fpcr(fpcr, streaming=profile.streaming, full_a64=profile.full_a64) & FP_EXCEPTION_ENABLE_MASK):
            raise UnsupportedControl("enabled FP traps require a separately selected delivery model")

    @property
    def alternative(self):
        return self.profile.afp and bool(self.fpcr & FPCR_AH)

    @property
    def rounding(self):
        return (self.fpcr >> FPCR_ROUNDING_SHIFT) & FPCR_ROUNDING_MASK

    def raise_status(self, flags):
        if not self.suppress:
            self.exceptions |= flags

    def default_nan(self):
        return SINGLE_INFINITY | SINGLE_QUIET | (SINGLE_SIGN if self.alternative else 0)

    def unpack(self, bits):
        sign = bits >> (SINGLE_BITS - 1)
        exponent = (bits >> SINGLE_FRACTION_BITS) & ((1 << EXPONENT_BITS) - 1)
        fraction = bits & ((1 << SINGLE_FRACTION_BITS) - 1)
        if exponent == (1 << EXPONENT_BITS) - 1:
            kind = "infinity" if fraction == 0 else "quiet" if bits & SINGLE_QUIET else "signaling"
            return _Operand(bits, kind, sign, Fraction())
        if exponent == 0:
            flush = bool(self.fpcr & FPCR_FZ) and not self.alternative
            fiz = self.profile.afp and bool(self.fpcr & FPCR_FIZ)
            if fraction == 0 or flush or fiz:
                if fraction and flush:
                    self.raise_status(FPSR_INPUT_DENORMAL)
                return _Operand(sign << (SINGLE_BITS - 1), "zero", sign, Fraction())
            value = fraction * _power(MINIMUM_EXPONENT - SINGLE_FRACTION_BITS)
            kind = "denormal"
        else:
            value = ((1 << SINGLE_FRACTION_BITS) | fraction) * _power(
                exponent - EXPONENT_BIAS - SINGLE_FRACTION_BITS)
            kind = "finite"
        return _Operand(bits, kind, sign, -value if sign else value)

    def nan(self, operands):
        indices = [i for i, op in enumerate(operands) if op.kind in ("quiet", "signaling")]
        if not indices:
            return None
        signaling = any(op.kind == "signaling" for op in operands)
        if self.alternative and len(indices) > 1:
            index = 0 if len(operands) == 2 else 1 if 1 in indices else 2
        else:
            index = next((i for i in indices if operands[i].kind == "signaling"), indices[0])
        if signaling:
            self.raise_status(FPSR_INVALID)
        return self.default_nan() if self.fpcr & FPCR_DN else operands[index].bits | SINGLE_QUIET

    def denorms(self, operands):
        if self.alternative and any(op.kind == "denormal" for op in operands):
            self.raise_status(FPSR_INPUT_DENORMAL)

    def _increment(self, retained, remainder, sign):
        if self.rounding == ROUND_NEAREST:
            return remainder > Fraction(1, 2) or remainder == Fraction(1, 2) and retained & 1
        if self.rounding == ROUND_POSITIVE:
            return bool(remainder) and not sign
        if self.rounding == ROUND_NEGATIVE:
            return bool(remainder) and bool(sign)
        return False

    def round(self, value, fraction_bits):
        sign = int(value < 0)
        magnitude = abs(value)
        exponent = magnitude.numerator.bit_length() - magnitude.denominator.bit_length()
        if magnitude < _power(exponent):
            exponent -= 1
        tiny = exponent < MINIMUM_EXPONENT
        if tiny and self.fpcr & FPCR_FZ and not self.alternative:
            self.raise_status(FPSR_UNDERFLOW)
            return sign << (SINGLE_BITS - 1)
        scale = max(exponent, MINIMUM_EXPONENT) - fraction_bits
        units = magnitude / _power(scale)
        retained = units.numerator // units.denominator
        remainder = units - retained
        unconstrained = magnitude / _power(exponent - fraction_bits)
        unconstrained_integer = unconstrained.numerator // unconstrained.denominator
        unconstrained_integer += int(self._increment(
            unconstrained_integer, unconstrained - unconstrained_integer, sign))
        rounded_exponent = exponent + int(unconstrained_integer == 1 << (fraction_bits + 1))
        if self.alternative and rounded_exponent < MINIMUM_EXPONENT and self.fpcr & FPCR_FZ:
            self.raise_status(FPSR_UNDERFLOW | FPSR_INEXACT)
            return sign << (SINGLE_BITS - 1)
        if tiny and remainder and (not self.alternative or rounded_exponent < MINIMUM_EXPONENT):
            self.raise_status(FPSR_UNDERFLOW)
        retained += int(self._increment(retained, remainder, sign))
        result_exponent = max(exponent, MINIMUM_EXPONENT)
        if retained >= 1 << (fraction_bits + 1):
            retained >>= 1
            result_exponent += 1
        if result_exponent > MAXIMUM_EXPONENT:
            self.raise_status(FPSR_OVERFLOW | FPSR_INEXACT)
            to_infinity = (self.rounding == ROUND_NEAREST
                           or self.rounding == ROUND_POSITIVE and not sign
                           or self.rounding == ROUND_NEGATIVE and sign)
            infinity = ((1 << EXPONENT_BITS) - 1) << fraction_bits
            bits = infinity if to_infinity else infinity - 1
        else:
            encoded_exponent = result_exponent + EXPONENT_BIAS if retained >= 1 << fraction_bits else 0
            bits = (encoded_exponent << fraction_bits) | (retained & ((1 << fraction_bits) - 1))
            if remainder:
                self.raise_status(FPSR_INEXACT)
        return (sign << (SINGLE_BITS - 1)) | (bits << (SINGLE_FRACTION_BITS - fraction_bits))

    def binary(self, kind, left, right, *, alternative_minmax=None,
               fraction_bits=BF_FRACTION_BITS):
        operands = (self.unpack(left), self.unpack(right))
        a, b = operands
        minmax = kind in ("min", "max")
        alt_minmax = self.alternative if alternative_minmax is None else alternative_minmax
        if minmax and alt_minmax:
            if a.kind == b.kind == "zero" and a.sign != b.sign:
                return b.bits
            if any(op.kind in ("quiet", "signaling") for op in operands):
                self.raise_status(FPSR_INVALID)
                return b.bits
        result = self.nan(operands)
        if result is not None:
            return result
        if minmax:
            if a.kind == b.kind == "zero":
                sign = a.sign | b.sign if kind == "min" else a.sign & b.sign
                result = sign << (SINGLE_BITS - 1)
            else:
                def key(op):
                    return (-1 if op.sign else 1, Fraction()) if op.kind == "infinity" else (0, op.value)
                chosen = a if (key(a) < key(b) if kind == "min" else key(a) > key(b)) else b
                if chosen.kind in ("zero", "infinity"):
                    result = chosen.bits
                elif alt_minmax:
                    result = chosen.bits
                else:
                    result = self.round(chosen.value, fraction_bits)
        elif kind in ("add", "sub"):
            sign_b = b.sign ^ int(kind == "sub")
            value_b = -b.value if kind == "sub" else b.value
            if a.kind == b.kind == "infinity" and a.sign != sign_b:
                self.raise_status(FPSR_INVALID)
                result = self.default_nan()
            elif a.kind == "infinity" or b.kind == "infinity":
                result = SINGLE_INFINITY | ((a.sign if a.kind == "infinity" else sign_b) << (SINGLE_BITS - 1))
            elif a.kind == b.kind == "zero" and a.sign == sign_b:
                result = a.sign << (SINGLE_BITS - 1)
            elif a.value + value_b == 0:
                result = int(self.rounding == ROUND_NEGATIVE) << (SINGLE_BITS - 1)
            else:
                result = self.round(a.value + value_b, fraction_bits)
        elif kind == "mul":
            if {a.kind, b.kind} == {"infinity", "zero"}:
                self.raise_status(FPSR_INVALID)
                result = self.default_nan()
            elif a.kind == "infinity" or b.kind == "infinity":
                result = SINGLE_INFINITY | ((a.sign ^ b.sign) << (SINGLE_BITS - 1))
            elif a.kind == "zero" or b.kind == "zero":
                result = (a.sign ^ b.sign) << (SINGLE_BITS - 1)
            else:
                result = self.round(a.value * b.value, fraction_bits)
        else:
            raise ValueError(f"unknown BF16 binary operation: {kind}")
        self.denorms(operands)
        return result

    def minmax_number(self, kind, left, right):
        a, b = self.unpack(left), self.unpack(right)
        replacement = SINGLE_INFINITY | (SINGLE_SIGN if kind == "max" else 0)
        if not (self.alternative and a.kind in ("quiet", "signaling") and b.kind in ("quiet", "signaling")):
            if a.kind == "quiet" and b.kind != "quiet":
                left = replacement
            elif a.kind != "quiet" and b.kind == "quiet":
                right = replacement
        return self.binary(kind, left, right, alternative_minmax=False)

    def fused(self, addend, left, right, fraction_bits):
        operands = tuple(self.unpack(bits) for bits in (addend, left, right))
        a, n, m = operands
        invalid_product = {n.kind, m.kind} == {"infinity", "zero"}
        result = self.nan(operands)
        if a.kind == "quiet" and invalid_product and not self.alternative:
            self.raise_status(FPSR_INVALID)
            return self.default_nan()
        if result is not None:
            return result
        product_sign = n.sign ^ m.sign
        product_infinite = n.kind == "infinity" or m.kind == "infinity"
        if invalid_product or a.kind == "infinity" and product_infinite and a.sign != product_sign:
            self.raise_status(FPSR_INVALID)
            return self.default_nan()
        if a.kind == "infinity" or product_infinite:
            result = SINGLE_INFINITY | ((a.sign if a.kind == "infinity" else product_sign) << (SINGLE_BITS - 1))
        elif a.kind == "zero" and (n.kind == "zero" or m.kind == "zero") and a.sign == product_sign:
            result = a.sign << (SINGLE_BITS - 1)
        else:
            value = a.value + n.value * m.value
            result = (self.round(value, fraction_bits) if value
                      else int(self.rounding == ROUND_NEGATIVE) << (SINGLE_BITS - 1))
        self.denorms(operands)
        return result


def _negate(bits, arithmetic):
    if arithmetic.alternative and bits & BF_INFINITY == BF_INFINITY and bits & BF_FRACTION_MASK:
        return bits
    return bits ^ BF_SIGN


def _classic_operand(bits):
    exponent = bits & SINGLE_INFINITY
    if exponent == 0:
        return _Operand(bits & SINGLE_SIGN, "zero", bits >> (SINGLE_BITS - 1), Fraction())
    return _Arithmetic(0, Profile()).unpack(bits)


def _round_odd(value):
    sign = SINGLE_SIGN if value < 0 else 0
    magnitude = abs(value)
    if magnitude < _power(MINIMUM_EXPONENT):
        return sign
    if magnitude >= _power(MAXIMUM_EXPONENT + 1):
        return sign | SINGLE_INFINITY
    exponent = magnitude.numerator.bit_length() - magnitude.denominator.bit_length()
    if magnitude < _power(exponent):
        exponent -= 1
    units = magnitude / _power(exponent - SINGLE_FRACTION_BITS)
    integer = units.numerator // units.denominator
    if units != integer:
        integer |= 1
    return sign | ((exponent + EXPONENT_BIAS) << SINGLE_FRACTION_BITS) | (integer & ((1 << SINGLE_FRACTION_BITS) - 1))


def _classic_binary(kind, left, right, nan):
    a, b = _classic_operand(left), _classic_operand(right)
    if a.kind in ("quiet", "signaling") or b.kind in ("quiet", "signaling"):
        return nan
    if kind == "mul":
        if {a.kind, b.kind} == {"infinity", "zero"}:
            return nan
        if a.kind == "infinity" or b.kind == "infinity":
            return SINGLE_INFINITY | ((a.sign ^ b.sign) << (SINGLE_BITS - 1))
        if a.kind == "zero" or b.kind == "zero":
            return (a.sign ^ b.sign) << (SINGLE_BITS - 1)
        return _round_odd(a.value * b.value)
    if a.kind == b.kind == "infinity" and a.sign != b.sign:
        return nan
    if a.kind == "infinity" or b.kind == "infinity":
        return a.bits if a.kind == "infinity" else b.bits
    if a.kind == b.kind == "zero" and a.sign == b.sign:
        return a.bits
    value = a.value + b.value
    return _round_odd(value) if value else 0


def _enhanced_dot(arithmetic, addend, left, right):
    """One Single-rounded exact product sum, then a separate Single add.

    The selected BFDotAdd profile forces DN and suppresses status; operand
    flushing, zero signs and rounding still use the requested FP controls.
    """
    operands = tuple(arithmetic.unpack(bits << BF_BITS) for bits in (*left, *right))
    if any(op.kind in ("quiet", "signaling") for op in operands):
        product_sum = arithmetic.default_nan()
    else:
        products = tuple((operands[index], operands[index + len(left)])
                         for index in range(len(left)))
        signs = tuple(a.sign ^ b.sign for a, b in products)
        infinite = tuple(a.kind == "infinity" or b.kind == "infinity"
                         for a, b in products)
        zero = tuple(a.kind == "zero" or b.kind == "zero" for a, b in products)
        invalid = (any({a.kind, b.kind} == {"infinity", "zero"} for a, b in products)
                   or all(infinite) and signs[0] != signs[1])
        if invalid:
            product_sum = arithmetic.default_nan()
        elif any(infinite):
            sign = signs[0] if infinite[0] else signs[1]
            product_sum = SINGLE_INFINITY | (sign << (SINGLE_BITS - 1))
        elif all(zero) and signs[0] == signs[1]:
            product_sum = signs[0] << (SINGLE_BITS - 1)
        else:
            exact = sum((a.value * b.value for a, b in products), Fraction())
            product_sum = (arithmetic.round(exact, SINGLE_FRACTION_BITS) if exact
                           else int(arithmetic.rounding == ROUND_NEGATIVE) << (SINGLE_BITS - 1))
    return arithmetic.binary("add", addend, product_sum, fraction_bits=SINGLE_FRACTION_BITS)


def evaluate(kind, destination, left, right, *, fpcr=0, fpsr=0, predicate=None,
             index=None, top=False, profile=Profile()):
    """Return complete destination bytes and status without modifying inputs.

    Kinds: add/sub/mul/min/max/minnm/maxnm/clamp/mla/mls/dot/mlal/mlsl.
    Predicates contain one bit per vector byte; BF lanes inspect bits 2*lane.
    Indexed sources repeat within each 128-bit segment, not across the full VL.
    BFCLAMP uses left as lower bound, right as upper bound, destination as value.
    BFDOT and widening operations reject predicates. Top selects odd BF lanes.
    """
    kinds = {"add", "sub", "mul", "min", "max", "minnm", "maxnm", "clamp", "mla", "mls", "dot", "mlal", "mlsl"}
    if kind not in kinds:
        raise ValueError(f"unknown BF16 operation: {kind}")
    if not isinstance(profile, Profile):
        raise TypeError("profile must be an explicit Profile")
    if any(not isinstance(control, int) or not 0 <= control < 1 << SINGLE_BITS
           for control in (fpcr, fpsr)):
        raise ValueError("FPCR and FPSR must be raw 32-bit values")
    length = len(destination)
    if not SEGMENT_BYTES <= length <= MAXIMUM_VECTOR_BYTES or length % SEGMENT_BYTES:
        raise ValueError("vector length must be 128..2048 bits in 128-bit increments")
    if len(left) != length or len(right) != length:
        raise ValueError("all vector inputs must have the same length")
    if predicate is not None and (not isinstance(predicate, int) or not 0 <= predicate < 1 << length):
        raise ValueError("predicate must contain one bit per vector byte")
    long = kind in ("dot", "mlal", "mlsl")
    if predicate is not None and (long or kind == "clamp"):
        raise ValueError("this operation has no predicated form")
    if top and kind not in ("mlal", "mlsl"):
        raise ValueError("top is only defined for widening multiply-add/subtract")
    if index is not None:
        maximum = SEGMENT_BYTES // (SINGLE_BITS // 8 if kind == "dot" else BF_BITS // 8)
        if kind not in ("mul", "mla", "mls", "dot", "mlal", "mlsl") or not 0 <= index < maximum:
            raise ValueError("invalid indexed source")
    enhanced_dot = kind == "dot" and profile.ebf16 and bool(fpcr & FPCR_EBF)
    suppress = kind == "dot" or kind in ("mlal", "mlsl") and profile.afp and fpcr & FPCR_AH
    effective_fpcr = fpcr
    if enhanced_dot:
        effective_fpcr |= FPCR_DN
    if suppress and kind != "dot":
        effective_fpcr = (fpcr | FPCR_FIZ | FPCR_FZ) & ~(FPCR_ROUNDING_MASK << FPCR_ROUNDING_SHIFT)
    arithmetic = _Arithmetic(effective_fpcr, profile, suppress=bool(suppress))
    result = bytearray(destination)
    lane_bytes = SINGLE_BITS // 8 if long else BF_BITS // 8
    def read(source, offset, size=BF_BITS // 8):
        return int.from_bytes(source[offset:offset + size], "little")
    for offset in range(0, length, lane_bytes):
        if predicate is not None and not (predicate >> offset) & 1:
            continue
        source_offset = offset + (BF_BITS // 8 if top else 0)
        segment = offset // SEGMENT_BYTES * SEGMENT_BYTES
        right_offset = source_offset if index is None else segment + index * (SINGLE_BITS // 8 if kind == "dot" else BF_BITS // 8)
        if kind == "dot":
            if enhanced_dot:
                left_pair = (read(left, offset), read(left, offset + BF_BITS // 8))
                right_pair = (read(right, right_offset), read(right, right_offset + BF_BITS // 8))
                value = _enhanced_dot(arithmetic, read(destination, offset, lane_bytes),
                                      left_pair, right_pair)
            else:
                first = _classic_binary("mul", read(left, offset) << BF_BITS, read(right, right_offset) << BF_BITS, arithmetic.default_nan())
                second = _classic_binary("mul", read(left, offset + BF_BITS // 8) << BF_BITS, read(right, right_offset + BF_BITS // 8) << BF_BITS, arithmetic.default_nan())
                pair = _classic_binary("add", first, second, arithmetic.default_nan())
                value = _classic_binary("add", read(destination, offset, lane_bytes), pair, arithmetic.default_nan())
        elif kind in ("mlal", "mlsl", "mla", "mls"):
            n, m = read(left, source_offset), read(right, right_offset)
            if kind in ("mlsl", "mls"):
                n = _negate(n, arithmetic)
            addend = read(destination, offset, lane_bytes)
            value = arithmetic.fused(addend if long else addend << BF_BITS, n << BF_BITS, m << BF_BITS,
                                     SINGLE_FRACTION_BITS if long else BF_FRACTION_BITS)
        elif kind == "clamp":
            maximum = arithmetic.minmax_number("max", read(left, offset) << BF_BITS, read(destination, offset) << BF_BITS)
            value = arithmetic.minmax_number("min", maximum, read(right, offset) << BF_BITS)
        elif kind in ("minnm", "maxnm"):
            value = arithmetic.minmax_number(kind[:-2], read(left, offset) << BF_BITS, read(right, offset) << BF_BITS)
        else:
            value = arithmetic.binary(kind, read(left, offset) << BF_BITS, read(right, right_offset) << BF_BITS)
        encoded = value if long else value >> BF_BITS
        result[offset:offset + lane_bytes] = encoded.to_bytes(lane_bytes, "little")
    return Outcome(bytes(result), fpsr | arithmetic.exceptions, arithmetic.exceptions)
