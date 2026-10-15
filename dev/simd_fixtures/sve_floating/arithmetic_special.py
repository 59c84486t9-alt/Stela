"""Exact SVE exponent operations and special arithmetic lane topology.

FPCR is profile-effective. Lane helpers return fresh status; scalable selection,
merging, sticky FPSR and destination commit belong to the caller. Tree leaves and
inactive outputs require no numerical helper and therefore no control refusal.
"""

from .control import (
    FPCR_AH, FPCR_ROUNDING_MASK, FPCR_ROUNDING_SHIFT,
    FP_EXCEPTION_ENABLE_MASK, FPSR_INPUT_DENORMAL, FPSR_INVALID,
)
from .conversion import UnsupportedFpControls
from .ieee import (
    FORMATS, LaneResult, Rounding, convert_nan, power_two, round_finite, unpack,
)


SEGMENT_BITS = 128
COMPLEX_COMPONENTS = 2
REAL_COMPONENT = 0


def _format(element_bits, fpcr, operands):
    if element_bits not in FORMATS:
        raise ValueError('Arithmetic requires 16, 32 or 64 bit elements')
    if not 0 <= fpcr < 1 << 32 or any(not 0 <= bits < 1 << element_bits for bits in operands):
        raise ValueError('Operand/control outside its bit width')
    if fpcr & FP_EXCEPTION_ENABLE_MASK:
        raise UnsupportedFpControls('Enabled FP exceptions are unsupported before effects')
    return FORMATS[element_bits]


def _post_denormal(format_, fpcr, category):
    return (FPSR_INPUT_DENORMAL if format_ != FORMATS[16] and fpcr & FPCR_AH
            and category == 'denormal' else 0)


def logb_lane(element_bits, fpcr, bits):
    """FPLogB returns signed integer exponent bits, including MinInt/MaxInt."""
    format_ = _format(element_bits, fpcr, (bits,))
    category, _, _, status = unpack(bits, format_, fpcr)
    minimum_integer = 1 << (element_bits - 1)
    if category in ('qnan', 'snan', 'zero'):
        return LaneResult(minimum_integer, status | FPSR_INVALID)
    if category == 'infinity':
        return LaneResult(minimum_integer - 1, status)
    exponent = bits >> format_.fraction_bits & format_.exponent_mask
    if exponent:
        result = exponent - format_.bias
    else:
        fraction = bits & format_.fraction_mask
        result = fraction.bit_length() + format_.minimum_exponent - format_.fraction_bits - 1
    status |= _post_denormal(format_, fpcr, category)
    return LaneResult(result & ((1 << element_bits) - 1), status)


def scale_lane(element_bits, fpcr, bits, scale_bits):
    """FPScale rounds value*2^signed-scale once after the architectural clamp."""
    format_ = _format(element_bits, fpcr, (bits, scale_bits))
    category, sign, value, status = unpack(bits, format_, fpcr)
    if category in ('qnan', 'snan'):
        if category == 'snan':
            status |= FPSR_INVALID
        return LaneResult(convert_nan(bits, format_, format_, fpcr), status)
    if category == 'zero':
        return LaneResult(format_.signed_zero(sign), status)
    if category == 'infinity':
        return LaneResult(format_.infinity(sign), status)
    scale_sign_bit = 1 << (element_bits - 1)
    scale = scale_bits - (1 << element_bits) if scale_bits & scale_sign_bit else scale_bits
    exponent = bits >> format_.fraction_bits & format_.exponent_mask
    minimum_scale = -(format_.fraction_bits + 1) - exponent
    maximum_scale = format_.exponent_mask + format_.fraction_bits + 1 - exponent
    scale = max(minimum_scale, min(scale, maximum_scale))
    rounding = Rounding(fpcr >> FPCR_ROUNDING_SHIFT & FPCR_ROUNDING_MASK)
    result = round_finite(value * power_two(scale), format_, fpcr, rounding)
    status |= result.exceptions | _post_denormal(format_, fpcr, category)
    return LaneResult(result.bits, status)


def reduce_tree(values, combine):
    """FPReduce evaluates the high half first, then combines (low, high)."""
    count = len(values)
    if count == 0 or count & (count - 1):
        raise ValueError('Floating reduction requires a power-of-two lane count')
    if count == 1:
        return values[0]
    half = count // 2
    high = reduce_tree(values[half:], combine)
    low = reduce_tree(values[:half], combine)
    return combine(low, high)


def pairwise_inputs(output_lane):
    """Return source role and adjacent input lanes for one active output."""
    if output_lane < 0:
        raise ValueError('Pairwise output lane must be nonnegative')
    if output_lane % COMPLEX_COMPONENTS == REAL_COMPONENT:
        return 'old_destination', output_lane, output_lane + 1
    return 'right', output_lane - 1, output_lane


def complex_inputs(pair, rotation, index=None, element_bits=32):
    """FCMLA (N lane, M lane, negate M) for each independent output component."""
    if pair < 0 or rotation not in (0, 1, 2, 3) or element_bits not in FORMATS:
        raise ValueError('Invalid complex pair, rotation or element width')
    left_component = rotation & 1
    right_component = left_component ^ 1
    right_pair = pair
    if index is not None:
        if element_bits not in (16, 32):
            raise ValueError('Indexed complex arithmetic requires Half or Single')
        pairs_per_segment = SEGMENT_BITS // (COMPLEX_COMPONENTS * element_bits)
        if not 0 <= index < pairs_per_segment:
            raise ValueError('Complex index outside its 128-bit segment')
        right_pair = pair - pair % pairs_per_segment + index
    left_lane = COMPLEX_COMPONENTS * pair + left_component
    return (
        (left_lane, COMPLEX_COMPONENTS * right_pair + left_component,
         bool((rotation & 1) ^ (rotation >> 1))),
        (left_lane, COMPLEX_COMPONENTS * right_pair + right_component,
         bool(rotation >> 1)),
    )
