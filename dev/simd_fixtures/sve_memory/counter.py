"""Shared pure CounterToPredicate model; predicate_bits is VL in bytes."""

COUNTER_INVERT = 1 << 15
COUNTER_FORMAT_MASK = 15


def counter_bits(counter: int, predicate_bits: int) -> int:
    """Exact CounterToPredicate width PL*4 including unused high counter bits."""
    shape = counter & COUNTER_FORMAT_MASK
    if not shape:
        return 0
    size = (shape & -shape).bit_length() - 1
    group = 1 << size
    maximum_bit = (predicate_bits * 4).bit_length() - 1
    count = (counter & ((1 << (maximum_bit + 1)) - 1)) >> (size + 1)
    inverted = bool(counter & COUNTER_INVERT)
    return sum(int((e < count) != inverted) << (e * group)
               for e in range(predicate_bits * 4 // group))
