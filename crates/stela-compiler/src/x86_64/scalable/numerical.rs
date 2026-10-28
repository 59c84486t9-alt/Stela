//! Output staging frame for one scalable floating-point instruction.
//!
//! The body is entered with RSP eight bytes off 16-byte alignment. All sources
//! stay readable until `finish`, which commits every staged output byte at once.
//! No CALL or mode change may occur while the frame is live. RDI, R15 and
//! callee-saved GPRs survive; RAX/RCX/RDX, flags and the chosen XMM are clobbered.
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rdi, Rsp};
use crate::x86_64::asm::{Alu, Code, Mem, Size};

use super::{
    DWORD_BYTES, HALFWORD_BYTES, Host, QWORD_BYTES, clear_z_upper, store_z_chunk,
    write_predicate_chunk, xmm,
};
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::scalable::{VECTOR_CHUNK_BYTES, VectorLength, is_predicate_register, is_z_register},
    block::ExitKind,
};
use alloc::vec::Vec;

const MAX_OUTPUTS: usize = 4;
const CALL_ALIGNMENT_PAD: usize = core::mem::size_of::<usize>();
const PRIVATE_HEADER_BYTES: usize = 2 * VECTOR_CHUNK_BYTES;
const MAX_FRAME_BYTES: usize = PRIVATE_HEADER_BYTES
    + MAX_OUTPUTS * crate::aarch64::scalable::MAX_VECTOR_BYTES
    + CALL_ALIGNMENT_PAD;
const SAVED_MXCSR: u32 = 0;
const PRIVATE_MXCSR: u32 = 4;
const CAPTURED_HOST_STATUS: u32 = 8;
const PENDING_GUEST_FPSR: u32 = 12;
const MXCSR_ROUNDING_MASK: u32 = 3 << 13;
const MXCSR_EXCEPTION_MASKS: u32 = 0x1f80;
const MXCSR_STATUS_MASK: u32 = 0x3f;
const PACKED_P_CHUNK_BYTES: usize = core::mem::size_of::<u64>();
const PREDICATE_BITS16_BYTES: usize = core::mem::size_of::<u16>();
const REL32_BYTES: usize = core::mem::size_of::<i32>();
const CONDITIONAL_ESCAPE: u8 = 0x0f;
const FIRST_CONDITIONAL_REL32: u8 = 0x80;
const LAST_CONDITIONAL_REL32: u8 = 0x8f;
const COMMIT_XMM: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Output {
    Z(u8),
    Predicate(u8),
    /// Low128 write with architectural active-upper-Z clearing.
    V(u8),
}

impl Output {
    fn valid(self) -> bool {
        match self {
            Self::Z(register) | Self::V(register) => is_z_register(register),
            Self::Predicate(register) => is_predicate_register(register),
        }
    }

    fn overlaps(self, other: Self) -> bool {
        match (self, other) {
            (Self::Predicate(a), Self::Predicate(b)) => a == b,
            (Self::Z(a) | Self::V(a), Self::Z(b) | Self::V(b)) => a == b,
            _ => false,
        }
    }

    fn bytes(self, length: VectorLength) -> usize {
        match self {
            Self::Z(_) => length.bytes(),
            Self::Predicate(_) => length.predicate_bytes(),
            Self::V(_) => VECTOR_CHUNK_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Environment {
    /// The family proves that its admitted kernel has no host status effects.
    Exact,
    /// Save all caller MXCSR bits; family policy supplies rounding and flags.
    PrivateMxcsr,
}

#[derive(Debug)]
struct Slot {
    output: Output,
    offset: u32,
}

#[derive(Debug)]
pub(crate) struct Frame {
    length: VectorLength,
    environment: Environment,
    slots: Vec<Slot>,
    bytes: u32,
    guards_start: usize,
}

/// `[rsp + offset]` with a 32-bit displacement field.
fn stack(offset: u32) -> Mem {
    Mem::base_disp32(Rsp, offset as i32)
}

fn stack_vector(code: &mut Code, opcode: Host, register: u8, offset: u32, target: TargetCpu) {
    xmm(register);
    code.asm().simd(opcode, register, stack(offset), target);
}

/// Validate the full constant layout before emitting or reserving any bytes.
/// A source may alias a destination; two output slots may not overlap.
pub(crate) fn begin(
    code: &mut Code,
    length: VectorLength,
    outputs: &[Output],
    environment: Environment,
) -> Result<Frame, CompileError> {
    if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
        return Err(CompileError(
            "numerical frame requires one to four outputs".into(),
        ));
    }
    for (index, &output) in outputs.iter().enumerate() {
        if !output.valid() || outputs[..index].iter().any(|&prior| output.overlaps(prior)) {
            return Err(CompileError(
                "invalid or overlapping numerical outputs".into(),
            ));
        }
    }
    let mut offset = if environment == Environment::PrivateMxcsr {
        PRIVATE_HEADER_BYTES
    } else {
        0
    };
    let slots = outputs
        .iter()
        .map(|&output| {
            let slot = Slot {
                output,
                offset: offset as u32,
            };
            offset += output.bytes(length).next_multiple_of(VECTOR_CHUNK_BYTES);
            slot
        })
        .collect();
    let bytes = (offset + CALL_ALIGNMENT_PAD) as u32;
    assert!(bytes as usize <= MAX_FRAME_BYTES);
    let mut asm = code.asm();
    asm.alu_imm32(Alu::Sub, Size::Qword, Rsp, bytes as i32);
    if environment == Environment::PrivateMxcsr {
        asm.stmxcsr(stack(SAVED_MXCSR));
        asm.mov_rm_imm32(Size::Dword, stack(PENDING_GUEST_FPSR), 0);
    }
    Ok(Frame {
        length,
        environment,
        slots,
        bytes,
        guards_start: code.len(),
    })
}

/// Stage one complete 16-byte Z/V segment; other XMMs and guest banks survive.
pub(crate) fn stage_vector_chunk(
    code: &mut Code,
    frame: &Frame,
    output: usize,
    chunk: usize,
    source_xmm: u8,
    target: TargetCpu,
) {
    let slot = &frame.slots[output];
    assert!(matches!(slot.output, Output::Z(_) | Output::V(_)));
    assert!(chunk < slot.output.bytes(frame.length) / VECTOR_CHUNK_BYTES);
    stack_vector(
        code,
        Host::StoreUnaligned,
        source_xmm,
        slot.offset + (chunk * VECTOR_CHUNK_BYTES) as u32,
        target,
    );
}

/// Stage exactly two packed P bytes from low16 RAX, one per 16-byte Z chunk.
/// The caller has already cleared inactive and nonleading predicate bits.
pub(crate) fn stage_predicate_bits16(
    code: &mut Code,
    frame: &Frame,
    output: usize,
    z_chunk: usize,
) {
    let slot = &frame.slots[output];
    assert!(matches!(slot.output, Output::Predicate(_)));
    assert!(z_chunk < frame.length.chunks());
    code.asm().mov_store(
        Size::Word,
        stack(slot.offset + (z_chunk * PREDICATE_BITS16_BYTES) as u32),
        Rax,
    );
}

fn private(frame: &Frame) {
    assert_eq!(frame.environment, Environment::PrivateMxcsr);
}

/// Install only EAX rounding bits, masked exceptions, fresh status and no flush.
/// Effective guest control interpretation remains the instruction family's job.
pub(crate) fn install_mxcsr(code: &mut Code, frame: &Frame) {
    private(frame);
    let mut asm = code.asm();
    asm.alu_accumulator_imm32(Alu::And, Size::Dword, MXCSR_ROUNDING_MASK as i32);
    asm.alu_accumulator_imm32(Alu::Or, Size::Dword, MXCSR_EXCEPTION_MASKS as i32);
    asm.mov_store(Size::Dword, stack(PRIVATE_MXCSR), Rax);
    asm.ldmxcsr(stack(PRIVATE_MXCSR));
}

/// Return the six raw host status bits in ECX. This is not an ARM FPSR mapping.
pub(crate) fn capture_status(code: &mut Code, frame: &Frame) {
    private(frame);
    let mut asm = code.asm();
    asm.stmxcsr(stack(CAPTURED_HOST_STATUS));
    asm.mov_load(Size::Dword, Rcx, stack(CAPTURED_HOST_STATUS));
    asm.alu_imm32(Alu::And, Size::Dword, Rcx, MXCSR_STATUS_MASK as i32);
}

/// Clear host stage status after installation, retaining approved pending FPSR.
pub(crate) fn clear_status(code: &mut Code, frame: &Frame) {
    private(frame);
    code.asm().ldmxcsr(stack(PRIVATE_MXCSR));
}

/// Accumulate only family-approved guest FPSR bits from EAX, without committing.
pub(crate) fn add_fpsr(code: &mut Code, frame: &Frame) {
    private(frame);
    code.asm()
        .alu(Alu::Or, Size::Dword, stack(PENDING_GUEST_FPSR), Rax);
}

fn restore(code: &mut Code, frame: &Frame) {
    if frame.environment == Environment::PrivateMxcsr {
        code.asm().ldmxcsr(stack(SAVED_MXCSR));
    }
}

fn release(code: &mut Code, frame: &Frame) {
    code.asm()
        .alu_imm32(Alu::Add, Size::Qword, Rsp, frame.bytes as i32);
}

fn patch(code: &mut [u8], displacement: usize, destination: usize) {
    let relative = i32::try_from(destination as i64 - (displacement + REL32_BYTES) as i64)
        .expect("numerical guard exceeds rel32 range");
    code[displacement..displacement + REL32_BYTES].copy_from_slice(&relative.to_le_bytes());
}

/// Commit all staged outputs after the final guard. Every supplied conditional
/// rel32 displacement starts after its 0F8x opcode and targets shared cleanup.
/// Failure restores MXCSR/RSP before returning the still-unexecuted exact PC.
/// Success clobbers XMM0 and RAX/RDX, and private mode ORs approved FPSR once.
pub(crate) fn finish(
    code: &mut Code,
    frame: &Frame,
    failures: &[usize],
    pc: GuestAddress,
    target: TargetCpu,
) {
    for &displacement in failures {
        assert!(displacement >= frame.guards_start + 2 && displacement + REL32_BYTES <= code.len());
        assert_eq!(code[displacement - 2], CONDITIONAL_ESCAPE);
        assert!(
            (FIRST_CONDITIONAL_REL32..=LAST_CONDITIONAL_REL32).contains(&code[displacement - 1])
        );
    }
    restore(code, frame);
    for slot in &frame.slots {
        match slot.output {
            Output::Z(register) | Output::V(register) => {
                for chunk in 0..slot.output.bytes(frame.length) / VECTOR_CHUNK_BYTES {
                    stack_vector(
                        code,
                        Host::LoadUnaligned,
                        COMMIT_XMM,
                        slot.offset + (chunk * VECTOR_CHUNK_BYTES) as u32,
                        target,
                    );
                    store_z_chunk(code, register, chunk, COMMIT_XMM, frame.length, target);
                }
                if matches!(slot.output, Output::V(_)) {
                    clear_z_upper(code, register, COMMIT_XMM, frame.length, target);
                }
            }
            Output::Predicate(register) => {
                for offset in (0..frame.length.predicate_bytes()).step_by(PACKED_P_CHUNK_BYTES) {
                    let bytes = (frame.length.predicate_bytes() - offset).min(PACKED_P_CHUNK_BYTES);
                    let source = stack(slot.offset + offset as u32);
                    let mut asm = code.asm();
                    match bytes {
                        HALFWORD_BYTES => asm.movzx(Size::Dword, Rax, Size::Word, source),
                        DWORD_BYTES => asm.mov_load(Size::Dword, Rax, source),
                        QWORD_BYTES => asm.mov_load(Size::Qword, Rax, source),
                        _ => unreachable!("validated predicate width"),
                    }
                    write_predicate_chunk(
                        code,
                        register,
                        offset / PACKED_P_CHUNK_BYTES,
                        frame.length,
                    );
                }
            }
        }
    }
    if frame.environment == Environment::PrivateMxcsr {
        let fpsr = core::mem::offset_of!(GuestState, fpsr) as i32;
        let mut asm = code.asm();
        asm.mov_load(Size::Dword, Rax, stack(PENDING_GUEST_FPSR));
        asm.alu(Alu::Or, Size::Dword, Mem::base_disp32(Rdi, fpsr), Rax);
    }
    release(code, frame);
    if failures.is_empty() {
        return;
    }
    let success = code.asm().jmp();
    let abort = code.len();
    restore(code, frame);
    release(code, frame);
    crate::x86_64::block::direct_exit(code, pc, ExitKind::ScalableNumerical);
    for &displacement in failures {
        patch(code, displacement, abort);
    }
    code.asm().bind(success);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn invalid_layout_does_not_emit() {
        let length = VectorLength::from_bytes(256).unwrap();
        for outputs in [
            vec![],
            vec![Output::Z(32)],
            vec![Output::Predicate(16)],
            vec![Output::V(32)],
            vec![Output::Z(0), Output::V(0)],
            vec![Output::Predicate(1); 2],
            vec![Output::Z(0); 5],
        ] {
            let mut code = Code::from(vec![0xaa]);
            assert!(begin(&mut code, length, &outputs, Environment::Exact).is_err());
            assert_eq!(code, [0xaa]);
        }
    }

    #[test]
    fn bounded_call_aligned_layout() {
        for bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for environment in [Environment::Exact, Environment::PrivateMxcsr] {
                for outputs in [
                    vec![Output::Predicate(0)],
                    vec![Output::V(0)],
                    vec![Output::Z(0)],
                    vec![Output::Z(0), Output::Z(1), Output::Z(2), Output::Z(3)],
                ] {
                    let frame = begin(&mut Code::new(), length, &outputs, environment).unwrap();
                    assert_eq!(
                        frame.bytes as usize % VECTOR_CHUNK_BYTES,
                        CALL_ALIGNMENT_PAD
                    );
                    assert!(frame.bytes as usize <= MAX_FRAME_BYTES);
                    for slot in frame.slots {
                        assert_eq!(slot.offset as usize % VECTOR_CHUNK_BYTES, 0);
                    }
                }
            }
        }
    }
}
