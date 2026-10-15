//! Exact SSE2 interleave/deinterleave networks for complete 128-bit chunks.
//!
//! Split narrows only representable values, so PACK saturation cannot change
//! source bits. These kernels access no architectural state or guest memory.

use crate::TargetCpu;
use crate::aarch64::scalable::ElementSize;
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode as Host};

const SECOND_EVEN_XMM: u8 = 6;
const SECOND_ODD_XMM: u8 = 7;
const EVEN_DWORDS: u8 = 0x88;
const ODD_DWORDS: u8 = 0xdd;

fn copy(code: &mut Vec<u8>, destination: u8, source: u8, target: TargetCpu) {
    if destination != source {
        Host::MoveAligned.register(code, destination, source, target);
    }
}

/// Preserve both inputs, producing their concatenated even/odd element streams.
/// Outputs differ from inputs and XMM6/7. XMM6/7 are clobbered.
pub(crate) fn split(
    code: &mut Vec<u8>,
    first: u8,
    second: u8,
    even: u8,
    odd: u8,
    element: ElementSize,
    target: TargetCpu,
) {
    assert_ne!(even, odd);
    for output in [even, odd] {
        assert!(![first, second, SECOND_EVEN_XMM, SECOND_ODD_XMM].contains(&output));
    }
    assert!(![SECOND_EVEN_XMM, SECOND_ODD_XMM].contains(&first));
    assert!(![SECOND_EVEN_XMM, SECOND_ODD_XMM].contains(&second));
    match element {
        ElementSize::Word => {
            for (destination, source, control) in [
                (even, first, EVEN_DWORDS),
                (SECOND_EVEN_XMM, second, EVEN_DWORDS),
                (odd, first, ODD_DWORDS),
                (SECOND_ODD_XMM, second, ODD_DWORDS),
            ] {
                Host::ShuffleDword.register(code, destination, source, target);
                code.push(control);
            }
            Host::UnpackLowQword.register(code, even, SECOND_EVEN_XMM, target);
            Host::UnpackLowQword.register(code, odd, SECOND_ODD_XMM, target);
        }
        ElementSize::Doubleword => {
            copy(code, even, first, target);
            copy(code, odd, first, target);
            Host::UnpackLowQword.register(code, even, second, target);
            Host::UnpackHighQword.register(code, odd, second, target);
        }
        ElementSize::Byte | ElementSize::Halfword => {
            for (destination, source) in [
                (even, first),
                (odd, first),
                (SECOND_EVEN_XMM, second),
                (SECOND_ODD_XMM, second),
            ] {
                copy(code, destination, source, target);
            }
            let (left, right, pack) = if element == ElementSize::Byte {
                (
                    Shift::LeftWord,
                    Shift::RightWord,
                    Host::PackUnsignedWordToByte,
                )
            } else {
                (
                    Shift::LeftDword,
                    Shift::ArithmeticDword,
                    Host::PackSignedDwordToWord,
                )
            };
            for destination in [even, SECOND_EVEN_XMM] {
                left.emit(code, destination, element.bits() as u8);
                right.emit(code, destination, element.bits() as u8);
            }
            for destination in [odd, SECOND_ODD_XMM] {
                right.emit(code, destination, element.bits() as u8);
            }
            pack.register(code, even, SECOND_EVEN_XMM, target);
            pack.register(code, odd, SECOND_ODD_XMM, target);
        }
        ElementSize::Quadword => unreachable!("Whole-chunk routing needs no unpack network"),
    }
}

fn unpack(element: ElementSize, high: bool) -> Host {
    match (element, high) {
        (ElementSize::Byte, false) => Host::UnpackLowByte,
        (ElementSize::Byte, true) => Host::UnpackHighByte,
        (ElementSize::Halfword, false) => Host::UnpackLowWord,
        (ElementSize::Halfword, true) => Host::UnpackHighWord,
        (ElementSize::Word, false) => Host::UnpackLowDword,
        (ElementSize::Word, true) => Host::UnpackHighDword,
        (ElementSize::Doubleword, false) => Host::UnpackLowQword,
        (ElementSize::Doubleword, true) => Host::UnpackHighQword,
        (ElementSize::Quadword, _) => unreachable!("Whole-chunk routing needs no unpack network"),
    }
}

/// Interleave two chunks into low/high outputs. Outputs differ from each other
/// and from second. First may be an output; no GPRs or extra XMMs are clobbered.
pub(crate) fn merge(
    code: &mut Vec<u8>,
    first: u8,
    second: u8,
    low: u8,
    high: u8,
    element: ElementSize,
    target: TargetCpu,
) {
    assert_ne!(low, high);
    assert_ne!(low, second);
    assert_ne!(high, second);
    copy(code, low, first, target);
    copy(code, high, first, target);
    unpack(element, false).register(code, low, second, target);
    unpack(element, true).register(code, high, second, target);
}

const EVEN_MASK_XMM: u8 = 6;
const ODD_MASK_XMM: u8 = 7;

/// Concatenate even/odd byte-index streams using caller-prepared PSHUFB masks.
///
/// Clobbers both inputs and writes `even`/`odd`; preserves mask XMM6/XMM7.
/// Inputs and outputs are four distinct XMM0..5. The masks select eight bytes
/// into the low qword and zero the upper qword. Byte/Halfword lane masks belong
/// to the caller; this kernel does not infer element sizes or access state.
pub(crate) fn split_destructive(
    code: &mut Vec<u8>,
    first: u8,
    second: u8,
    even: u8,
    odd: u8,
    target: TargetCpu,
) {
    let registers = [first, second, even, odd];
    for (index, register) in registers.iter().enumerate() {
        assert!(*register < EVEN_MASK_XMM);
        assert!(!registers[..index].contains(register));
    }
    copy(code, even, first, target);
    copy(code, odd, first, target);
    Host::ByteShuffle.register(code, even, EVEN_MASK_XMM, target);
    Host::ByteShuffle.register(code, odd, ODD_MASK_XMM, target);
    copy(code, first, second, target);
    Host::ByteShuffle.register(code, first, EVEN_MASK_XMM, target);
    Host::ByteShuffle.register(code, second, ODD_MASK_XMM, target);
    Host::UnpackLowQword.register(code, even, first, target);
    Host::UnpackLowQword.register(code, odd, second, target);
}

const MODRM_RIP: u8 = 0x05;
const MODRM_REGISTER_SHIFT: u8 = 3;
const SHUFFLE_ZERO: u8 = 0x80;
const JMP_REL32: u8 = 0xe9;
const REL32_BYTES: usize = std::mem::size_of::<i32>();
const JUMP_BYTES: usize = std::mem::size_of::<u8>() + REL32_BYTES;
const CHUNK_BYTES: usize = crate::aarch64::scalable::VECTOR_CHUNK_BYTES;
const HALF_CHUNK_BYTES: usize = CHUNK_BYTES / 2;

/// Prepare even/odd Byte or Halfword routing masks in XMM6/7. Embedded masks
/// use MOVDQU loads, avoiding the alignment requirement of legacy PSHUFB memory.
/// Preserves XMM0..5 and every GPR. The caller owns checked SSSE3 selection.
pub(crate) fn prepare_split_masks(code: &mut Vec<u8>, element: ElementSize, target: TargetCpu) {
    assert!(target.supports(TargetCpu::Ssse3));
    assert!(matches!(element, ElementSize::Byte | ElementSize::Halfword));
    let load_bytes = Host::LoadUnaligned.encoding().len() + std::mem::size_of::<u8>() + REL32_BYTES;
    for (register, displacement) in [
        (EVEN_MASK_XMM, load_bytes + JUMP_BYTES),
        (ODD_MASK_XMM, JUMP_BYTES + CHUNK_BYTES),
    ] {
        Host::LoadUnaligned.append(code, target);
        code.push(MODRM_RIP | (register << MODRM_REGISTER_SHIFT));
        code.extend((displacement as i32).to_le_bytes());
    }
    code.push(JMP_REL32);
    code.extend((2 * CHUNK_BYTES as i32).to_le_bytes());
    for parity in 0..2 {
        for byte in 0..CHUNK_BYTES {
            code.push(if byte < HALF_CHUNK_BYTES {
                ((byte / element.bytes() * 2 + parity) * element.bytes() + byte % element.bytes())
                    as u8
            } else {
                SHUFFLE_ZERO
            });
        }
    }
}
