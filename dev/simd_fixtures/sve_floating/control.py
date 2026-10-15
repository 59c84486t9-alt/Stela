"""Architectural FP controls shared by pure streaming numerical models.

Imported raw storage stays unchanged. Effective controls suppress numerical trap
requests in ordinary streaming mode; cumulative exception status still updates.
"""

FPCR_FIZ = 1 << 0
FPCR_AH = 1 << 1
FPCR_NEP = 1 << 2
FPCR_EBF = 1 << 13
FPCR_FZ16 = 1 << 19
FPCR_ROUNDING_SHIFT = 22
FPCR_ROUNDING_MASK = 3
FPCR_FZ = 1 << 24
FPCR_DN = 1 << 25
FPCR_AHP = 1 << 26

FPSR_INVALID = 1 << 0
FPSR_DIVIDE_BY_ZERO = 1 << 1
FPSR_OVERFLOW = 1 << 2
FPSR_UNDERFLOW = 1 << 3
FPSR_INEXACT = 1 << 4
FPSR_INPUT_DENORMAL = 1 << 7
FPSR_QC = 1 << 27
FP_EXCEPTION_MASK = (
    FPSR_INVALID | FPSR_DIVIDE_BY_ZERO | FPSR_OVERFLOW | FPSR_UNDERFLOW
    | FPSR_INEXACT | FPSR_INPUT_DENORMAL
)
FP_EXCEPTION_ENABLE_SHIFT = 8
FP_EXCEPTION_ENABLE_MASK = FP_EXCEPTION_MASK << FP_EXCEPTION_ENABLE_SHIFT


def effective_fpcr(fpcr: int, *, streaming: bool, full_a64: bool) -> int:
    """Match FPProcessException's trap condition without altering raw storage."""
    return fpcr & ~FP_EXCEPTION_ENABLE_MASK if streaming and not full_a64 else fpcr


def conversion_fpcr(fpcr: int, *, streaming: bool, full_a64: bool) -> int:
    """FPConvertSVE ignores AHP independently of alternative FP behavior."""
    return effective_fpcr(fpcr, streaming=streaming, full_a64=full_a64) & ~FPCR_AHP
