"""Independent integer model of predicated FPAbsMin/FPAbsMax.

NaN selection retains the original sign/payload. Numeric results are positive
magnitudes, including subnormals under every flush control. No host FP is used.
"""
from dataclasses import dataclass
from enum import Enum

from .control import FPCR_DN, FP_EXCEPTION_ENABLE_MASK, FPSR_INVALID
from .conversion import UnsupportedFpControls
from .ieee import FORMATS, LaneResult


class Operation(Enum):
    MINIMUM = 'famin'
    MAXIMUM = 'famax'


@dataclass(frozen=True)
class VectorResult:
    destination: bytes
    fpsr: int
    exceptions: int
    active_lanes: int


def evaluate_lane(operation, element_bits, fpcr, left, right):
    if not isinstance(operation, Operation) or element_bits not in FORMATS:
        raise ValueError('Typed absolute extrema require H/S/D elements')
    if not 0 <= fpcr < 1 << 32 or any(not 0 <= bits < 1 << element_bits for bits in (left, right)):
        raise ValueError('Operand/control outside its bit width')
    if fpcr & FP_EXCEPTION_ENABLE_MASK:
        raise UnsupportedFpControls('Enabled FP exceptions are unsupported before effects')
    format_ = FORMATS[element_bits]
    magnitude_mask = (1 << (element_bits - 1)) - 1
    infinity = format_.infinity(0)
    quiet_bit = 1 << (format_.fraction_bits - 1)
    nans = [bits for bits in (left, right) if bits & magnitude_mask > infinity]
    if nans:
        signaling = [bits for bits in nans if not bits & quiet_bit]
        selected = signaling[0] if signaling else nans[0]
        result = infinity | quiet_bit if fpcr & FPCR_DN else selected | quiet_bit
        return LaneResult(result, FPSR_INVALID if signaling else 0)
    selection = min if operation == Operation.MINIMUM else max
    return LaneResult(selection(left & magnitude_mask, right & magnitude_mask))


def evaluate_vector(operation, element_bits, fpcr, fpsr, destination, right, governing):
    if element_bits not in FORMATS or not isinstance(operation, Operation):
        raise ValueError('Typed absolute extrema require H/S/D elements')
    length = len(destination)
    if length not in (16, 32, 64, 128, 256) or len(right) != length or len(governing) * 8 != length:
        raise ValueError('Operands must span current streaming VL/PL')
    destination, right, governing = bytes(destination), bytes(right), bytes(governing)
    result = bytearray(destination)
    element_bytes = element_bits // 8
    predicate = int.from_bytes(governing, 'little')
    exceptions = active = 0
    for offset in range(0, length, element_bytes):
        if not predicate & (1 << offset):
            continue
        lane = evaluate_lane(operation, element_bits, fpcr,
                             int.from_bytes(destination[offset:offset + element_bytes], 'little'),
                             int.from_bytes(right[offset:offset + element_bytes], 'little'))
        result[offset:offset + element_bytes] = lane.bits.to_bytes(element_bytes, 'little')
        exceptions |= lane.exceptions
        active += 1
    return VectorResult(bytes(result), fpsr | exceptions, exceptions, active)


def cases(vector_bytes):
    """Bounded full-bank differential inputs for the shared scalable runner."""
    from dataclasses import replace
    from scalable_frame import seeded_snapshot, snapshot_to_state, snapshot_from_state
    from .control import (FPCR_AH, FPCR_FIZ, FPCR_FZ, FPCR_FZ16, FPSR_QC,
                          effective_fpcr)

    controls = FPCR_AH | FPCR_FIZ | FPCR_FZ | FPCR_FZ16
    for operation in Operation:
        opcode = 0x650f8000 if operation == Operation.MINIMUM else 0x650e8000
        canonical = operation.value + '_z_p_zz_'
        for size, element_bits in enumerate((16, 32, 64), 1):
            format_ = FORMATS[element_bits]
            sign = 1 << (element_bits - 1)
            quiet = 1 << (format_.fraction_bits - 1)
            infinity = format_.infinity(0)
            one = format_.bias << format_.fraction_bits
            width = element_bits // 8
            for name, alias, active, fpcr, left_lanes, right_lanes in (
                ('finite', False, True, 0, (sign | one, one, sign, infinity), (one + 1, sign | one, 0, sign | infinity)),
                ('subnormal', False, True, controls, (sign | 1, 2, 0, sign | format_.fraction_mask), (2, sign | 1, sign, format_.fraction_mask)),
                ('nan_priority', False, True, controls, (sign | infinity | quiet | 1, infinity | 3, infinity | quiet | 2, one), (infinity | 7, sign | infinity | 9, one, sign | infinity | quiet | 5)),
                ('default_nan', False, True, controls | FPCR_DN, (sign | infinity | 1,), (infinity | quiet | 2,)),
                # QEMU's exception enable bits read as zero. Trap-control
                # refusal/inactive bypass is checked by the runtime tests.
                ('inactive', False, False, controls, (sign | infinity | 1,), (infinity | 3,)),
                ('alias', True, True, controls, (sign | 1, sign | one, infinity | 1, sign | infinity | quiet | 2), (0,)),
            ):
                initial = seeded_snapshot(vector_bytes, (canonical + name + str(element_bits)).encode())
                state = snapshot_to_state(initial)
                def repeat(lanes):
                    return b''.join(lanes[index % len(lanes)].to_bytes(width, 'little')
                                    for index in range(vector_bytes // width))
                state['z'][31] = repeat(left_lanes)
                state['z'][0] = repeat(right_lanes)
                # Odd lanes remain inactive poison; every nonleading bit is set.
                predicate = sum(1 << offset for offset in range(vector_bytes)
                                if offset % width or active and offset // width % 2 == 0)
                state['p'][7] = predicate
                state['fpcr'], state['fpsr'] = fpcr, FPSR_QC
                initial = snapshot_from_state(initial, state)
                initial = replace(initial, controls={**initial.controls, 'requested_fpcr': fpcr, 'requested_fpsr': FPSR_QC})
                right_register = 31 if alias else 0
                output = evaluate_vector(operation, element_bits,
                                         effective_fpcr(fpcr, streaming=True, full_a64=False),
                                         state['fpsr'], state['z'][31], state['z'][right_register],
                                         predicate.to_bytes(vector_bytes // 8, 'little'))
                state['z'][31], state['fpsr'] = output.destination, output.fpsr
                yield {'operation': {'word': opcode | size << 22 | 7 << 10 | right_register << 5 | 31,
                                     'canonical_id': canonical, 'case': name, 'element_bits': element_bits},
                       'initial': initial, 'expected': snapshot_from_state(initial, state),
                       'required': initial.valid}
