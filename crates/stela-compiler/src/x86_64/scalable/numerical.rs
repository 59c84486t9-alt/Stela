//! Bounded output staging for one guarded scalable numerical instruction.
//!
//! The extended wrapper CALLs this body with RSP eight bytes from alignment.
//! Families retain all architectural sources until `finish`, stage every output
//! byte, and supply guards before any commit. No CALL, nested frame, or mode
//! change is permitted while this frame is live. RDI/R15 and callee-saved GPRs
//! survive; mechanics may clobber RAX/RCX/RDX, flags, and the selected XMM.

use super::{
    DWORD_BYTES, HALFWORD_BYTES, Host, QWORD_BYTES, clear_z_upper, store_z_chunk,
    write_predicate_chunk, xmm,
};
use crate::{
    CompileError, GuestAddress, GuestState, TargetCpu,
    aarch64::scalable::{VECTOR_CHUNK_BYTES, VectorLength, is_predicate_register, is_z_register},
    block::ExitKind,
};

const MAX_OUTPUTS: usize = 4;
const CALL_ALIGNMENT_PAD: usize = std::mem::size_of::<usize>();
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
const PACKED_P_CHUNK_BYTES: usize = std::mem::size_of::<u64>();
const PREDICATE_BITS16_BYTES: usize = std::mem::size_of::<u16>();
const REL32_BYTES: usize = std::mem::size_of::<i32>();
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const STMXCSR_RSP_DISP32: &[u8] = &[0x0f, 0xae, 0x9c, 0x24];
const LDMXCSR_RSP_DISP32: &[u8] = &[0x0f, 0xae, 0x94, 0x24];
const MOV_RSP_DISP32_IMM32: &[u8] = &[0xc7, 0x84, 0x24];
const MOV_RSP_DISP32_EAX: &[u8] = &[0x89, 0x84, 0x24];
const MOV_RSP_DISP32_AX: &[u8] = &[0x66, 0x89, 0x84, 0x24];
const MOV_EAX_RSP_DISP32: &[u8] = &[0x8b, 0x84, 0x24];
const MOV_ECX_RSP_DISP32: &[u8] = &[0x8b, 0x8c, 0x24];
const MOVZX_EAX_WORD_RSP_DISP32: &[u8] = &[0x0f, 0xb7, 0x84, 0x24];
const MOV_RAX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const OR_RSP_DISP32_EAX: &[u8] = &[0x09, 0x84, 0x24];
const AND_EAX_IMM32: &[u8] = &[0x25];
const OR_EAX_IMM32: &[u8] = &[0x0d];
const AND_ECX_IMM32: &[u8] = &[0x81, 0xe1];
const OR_STATE_FPSR_EAX: &[u8] = &[0x09, 0x87];
const JMP_REL32: u8 = 0xe9;
const CONDITIONAL_ESCAPE: u8 = 0x0f;
const FIRST_CONDITIONAL_REL32: u8 = 0x80;
const LAST_CONDITIONAL_REL32: u8 = 0x8f;
const MODRM_STACK_DISP32: u8 = 0x84;
const XMM_REGISTER_SHIFT: u8 = 3;
const SIB_STACK: u8 = 0x24;
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

fn memory(code: &mut Vec<u8>, opcode: &[u8], offset: u32) {
    code.extend(opcode);
    code.extend(offset.to_le_bytes());
}

fn stack_vector(code: &mut Vec<u8>, opcode: Host, register: u8, offset: u32, target: TargetCpu) {
    xmm(register);
    opcode.append(code, target);
    code.extend([
        MODRM_STACK_DISP32 | (register << XMM_REGISTER_SHIFT),
        SIB_STACK,
    ]);
    code.extend(offset.to_le_bytes());
}

/// Validate the full constant layout before emitting or reserving any bytes.
/// A source may alias a destination; two output slots may not overlap.
pub(crate) fn begin(
    code: &mut Vec<u8>,
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
    code.extend(SUB_RSP_IMM32);
    code.extend(bytes.to_le_bytes());
    if environment == Environment::PrivateMxcsr {
        memory(code, STMXCSR_RSP_DISP32, SAVED_MXCSR);
        memory(code, MOV_RSP_DISP32_IMM32, PENDING_GUEST_FPSR);
        code.extend(0u32.to_le_bytes());
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
    code: &mut Vec<u8>,
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
    code: &mut Vec<u8>,
    frame: &Frame,
    output: usize,
    z_chunk: usize,
) {
    let slot = &frame.slots[output];
    assert!(matches!(slot.output, Output::Predicate(_)));
    assert!(z_chunk < frame.length.chunks());
    memory(
        code,
        MOV_RSP_DISP32_AX,
        slot.offset + (z_chunk * PREDICATE_BITS16_BYTES) as u32,
    );
}

fn private(frame: &Frame) {
    assert_eq!(frame.environment, Environment::PrivateMxcsr);
}

/// Install only EAX rounding bits, masked exceptions, fresh status and no flush.
/// Effective guest control interpretation remains the instruction family's job.
pub(crate) fn install_mxcsr(code: &mut Vec<u8>, frame: &Frame) {
    private(frame);
    code.extend(AND_EAX_IMM32);
    code.extend(MXCSR_ROUNDING_MASK.to_le_bytes());
    code.extend(OR_EAX_IMM32);
    code.extend(MXCSR_EXCEPTION_MASKS.to_le_bytes());
    memory(code, MOV_RSP_DISP32_EAX, PRIVATE_MXCSR);
    memory(code, LDMXCSR_RSP_DISP32, PRIVATE_MXCSR);
}

/// Return the six raw host status bits in ECX. This is not an ARM FPSR mapping.
pub(crate) fn capture_status(code: &mut Vec<u8>, frame: &Frame) {
    private(frame);
    memory(code, STMXCSR_RSP_DISP32, CAPTURED_HOST_STATUS);
    memory(code, MOV_ECX_RSP_DISP32, CAPTURED_HOST_STATUS);
    code.extend(AND_ECX_IMM32);
    code.extend(MXCSR_STATUS_MASK.to_le_bytes());
}

/// Clear host stage status after installation, retaining approved pending FPSR.
pub(crate) fn clear_status(code: &mut Vec<u8>, frame: &Frame) {
    private(frame);
    memory(code, LDMXCSR_RSP_DISP32, PRIVATE_MXCSR);
}

/// Accumulate only family-approved guest FPSR bits from EAX, without committing.
pub(crate) fn add_fpsr(code: &mut Vec<u8>, frame: &Frame) {
    private(frame);
    memory(code, OR_RSP_DISP32_EAX, PENDING_GUEST_FPSR);
}

fn restore(code: &mut Vec<u8>, frame: &Frame) {
    if frame.environment == Environment::PrivateMxcsr {
        memory(code, LDMXCSR_RSP_DISP32, SAVED_MXCSR);
    }
}

fn release(code: &mut Vec<u8>, frame: &Frame) {
    code.extend(ADD_RSP_IMM32);
    code.extend(frame.bytes.to_le_bytes());
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
    code: &mut Vec<u8>,
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
                    let opcode = match bytes {
                        HALFWORD_BYTES => MOVZX_EAX_WORD_RSP_DISP32,
                        DWORD_BYTES => MOV_EAX_RSP_DISP32,
                        QWORD_BYTES => MOV_RAX_RSP_DISP32,
                        _ => unreachable!("validated predicate width"),
                    };
                    memory(code, opcode, slot.offset + offset as u32);
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
        memory(code, MOV_EAX_RSP_DISP32, PENDING_GUEST_FPSR);
        memory(
            code,
            OR_STATE_FPSR_EAX,
            std::mem::offset_of!(GuestState, fpsr) as u32,
        );
    }
    release(code, frame);
    if failures.is_empty() {
        return;
    }
    code.push(JMP_REL32);
    let success = code.len();
    code.extend([0; REL32_BYTES]);
    let abort = code.len();
    restore(code, frame);
    release(code, frame);
    crate::x86_64::block::direct_exit(code, pc, ExitKind::ScalableNumerical);
    for &displacement in failures {
        patch(code, displacement, abort);
    }
    let end = code.len();
    patch(code, success, end);
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let mut code = vec![0xaa];
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
                    let frame = begin(&mut Vec::new(), length, &outputs, environment).unwrap();
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
