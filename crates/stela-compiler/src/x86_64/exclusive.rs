//! Exclusive loads and stores through the per-thread reservation in the memory
//! service, which owns the access, ordering, faults and monitor state.
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Rm, Size};
use crate::x86_64::isa::SimdOpcode;

use super::{load, memory_context as memory, store};
use crate::{
    CompileError,
    aarch64::{
        AddressMode, Register,
        exclusive::{Data, Kind, Operand},
    },
    block::CheckedMemoryProfile,
    context::memory::{
        MEMORY_REQUEST_BYTES, MemoryOrder, MemoryRequirements, SpAlignmentRequirement,
        exclusive::{
            EXCLUSIVE_DATA_BYTES, EXCLUSIVE_OPERATION_OFFSET, EXCLUSIVE_ORDER_OFFSET,
            EXCLUSIVE_SHAPE_OFFSET, EXCLUSIVE_STATUS_OFFSET, EXCLUSIVE_VALUE_OFFSET,
            ExclusiveOperation, ExclusiveShape,
        },
        flags, host_caps, profile_requirements,
    },
};

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const WORD_BYTES: u8 = 4;
const DOUBLEWORD_BYTES: u8 = 8;
const PAIR_MEMBERS: u8 = 2;
const DOUBLEWORD_PAIR_BYTES: u8 = PAIR_MEMBERS * DOUBLEWORD_BYTES;
const GPR_COUNT: u8 = 31;
const VECTOR_BYTES: u32 = 16;
const STACK_ALIGNMENT_BYTES: u32 = 16;
const REQUEST_OFFSET: u32 = 0;
const DATA_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const SCRATCH_BYTES: u32 = (DATA_OFFSET + EXCLUSIVE_DATA_BYTES as u32)
    .div_ceil(STACK_ALIGNMENT_BYTES)
    * STACK_ALIGNMENT_BYTES;
const _: () = assert!(SCRATCH_BYTES <= i8::MAX as u32);

/// The scratch payload field at `offset`.
fn scratch(offset: u32) -> Mem {
    Mem::base_disp8(Gpr::Rsp, (DATA_OFFSET + offset) as i8)
}

/// One control specialization drives both the body's metadata and its emission.
/// The checked entry selects it from the live controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckedOperand {
    operand: Operand,
    profile: CheckedMemoryProfile,
}

impl CheckedOperand {
    pub(crate) fn new(
        operand: Operand,
        profile: CheckedMemoryProfile,
    ) -> Result<Self, CompileError> {
        validate(&operand)?;
        Ok(Self { operand, profile })
    }
}

fn data_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < GPR_COUNT) || register == Register::Zero
}

/// Constructed operands must obey the same register-role and constrained-UNDEF
/// boundary as the existing decoder. Decode errors require a source-bound
/// generic undefined-instruction exit; they never become successful transfers.
fn validate(operand: &Operand) -> Result<(), CompileError> {
    let Operand::Transfer {
        element_bytes,
        base,
        data,
        kind,
    } = *operand
    else {
        return Ok(());
    };
    let base_valid =
        matches!(base, Register::X(index) if index < GPR_COUNT) || base == Register::Sp;
    let data_valid = match data {
        Data::Scalar(register) => {
            matches!(
                element_bytes,
                BYTE_BYTES | HALFWORD_BYTES | WORD_BYTES | DOUBLEWORD_BYTES
            ) && data_register(register)
        }
        Data::Pair(registers) => {
            matches!(element_bytes, WORD_BYTES | DOUBLEWORD_BYTES)
                && registers.into_iter().all(data_register)
        }
    };
    let constrained = match (data, kind) {
        (Data::Pair([first, second]), Kind::Load { .. }) => first == second,
        (data, Kind::Store { status, .. }) => {
            if !data_register(status) {
                return Err(CompileError::new(
                    crate::CompileErrorKind::InvalidExclusiveStatusRegister,
                ));
            }
            let data_overlap = match data {
                Data::Scalar(register) => status == register,
                Data::Pair(registers) => registers.contains(&status),
            };
            data_overlap || base != Register::Sp && status == base
        }
        _ => false,
    };
    if !base_valid || !data_valid {
        return Err(CompileError::new(
            crate::CompileErrorKind::InvalidExclusiveTransfer,
        ));
    }
    if constrained {
        return Err(CompileError::new(
            crate::CompileErrorKind::ConstrainedExclusiveOperands,
        ));
    }
    Ok(())
}

fn descriptor(operand: &Operand) -> u32 {
    flags::EXCLUSIVE
        | match *operand {
            Operand::Clear => 0,
            Operand::Transfer { base, kind, .. } => {
                (if matches!(kind, Kind::Store { .. }) {
                    flags::WRITE
                } else {
                    0
                }) | if base != Register::Sp {
                    flags::TAG_CHECKED
                } else {
                    0
                }
            }
        }
}

fn total_bytes(element_bytes: u8, data: Data) -> u32 {
    u32::from(element_bytes)
        * if matches!(data, Data::Pair(_)) {
            u32::from(PAIR_MEMBERS)
        } else {
            1
        }
}

pub(crate) fn requirements(checked: &CheckedOperand) -> MemoryRequirements {
    let operand = &checked.operand;
    let Operand::Transfer {
        element_bytes,
        base,
        data,
        kind,
    } = *operand
    else {
        return MemoryRequirements {
            required_flags: flags::EXCLUSIVE,
            ..MemoryRequirements::default()
        };
    };
    let bytes = total_bytes(element_bytes, data);
    let required_host_caps = match kind {
        Kind::Load { .. }
            if bytes == u32::from(DOUBLEWORD_PAIR_BYTES)
                || bytes > u32::from(BYTE_BYTES)
                    && (base != Register::Sp
                        || checked.profile.sp_requirement()
                            == SpAlignmentRequirement::Disabled) =>
        {
            host_caps::ATOMIC_LOAD16
        }
        Kind::Store { .. } if bytes == u32::from(DOUBLEWORD_PAIR_BYTES) => host_caps::CX16,
        _ => 0,
    };
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: checked.profile.direct_address_requirements(),
        required_flags: descriptor(operand),
        required_host_caps,
        required_profile: profile_requirements::NATIVE_ACCESS
            | if base != Register::Sp {
                profile_requirements::TAG_GRANULES
            } else {
                0
            },
        required_sp_alignment: if base == Register::Sp {
            checked.profile.sp_requirement()
        } else {
            SpAlignmentRequirement::Any
        },
        ..MemoryRequirements::default()
    }
}

fn initialize(code: &mut Code) {
    let mut asm = code.asm();
    asm.simd(SimdOpcode::Xor, 0, Rm::Xmm(0), crate::TargetCpu::Baseline);
    for offset in (0..EXCLUSIVE_DATA_BYTES as u32).step_by(VECTOR_BYTES as usize) {
        asm.movdqu_store(scratch(offset), 0);
    }
}

fn set_field(code: &mut Code, offset: u32, value: u32) {
    // The complete payload was initialized. Zero-valued fields need no rewrite.
    if value != 0 {
        code.asm()
            .mov_rm_imm32(Size::Dword, scratch(offset), value as i32);
    }
}

fn stage(code: &mut Code, register: Register, bytes: u8, offset: u32) {
    if register == Register::Zero {
        return;
    }
    load(code, register);
    let size = match bytes {
        BYTE_BYTES => Size::Byte,
        HALFWORD_BYTES => Size::Word,
        WORD_BYTES => Size::Dword,
        DOUBLEWORD_BYTES => Size::Qword,
        _ => unreachable!("validated exclusive element width"),
    };
    code.asm().mov_store(size, scratch(offset), Gpr::Rax);
}

fn commit(code: &mut Code, register: Register, bytes: u8, offset: u32) {
    if register == Register::Zero {
        return;
    }
    let mut asm = code.asm();
    match bytes {
        BYTE_BYTES => asm.movzx(Size::Dword, Gpr::Rax, Size::Byte, scratch(offset)),
        HALFWORD_BYTES => asm.movzx(Size::Dword, Gpr::Rax, Size::Word, scratch(offset)),
        WORD_BYTES => asm.mov_load(Size::Dword, Gpr::Rax, scratch(offset)),
        DOUBLEWORD_BYTES => asm.mov_load(Size::Qword, Gpr::Rax, scratch(offset)),
        _ => unreachable!("validated exclusive result width"),
    }
    store(code, register);
}

fn transfer_data(code: &mut Code, data: Data, element_bytes: u8, loading: bool) {
    let emit = if loading { commit } else { stage };
    match data {
        Data::Scalar(register) => emit(code, register, element_bytes, EXCLUSIVE_VALUE_OFFSET),
        Data::Pair(registers) => {
            for (index, register) in registers.into_iter().enumerate() {
                emit(
                    code,
                    register,
                    element_bytes,
                    EXCLUSIVE_VALUE_OFFSET + index as u32 * u32::from(element_bytes),
                );
            }
        }
    }
}

/// The checked entry binds the body's requirements and the thread's memory
/// owner before execution. Each callback handles one exclusive access or CLREX;
/// on failure scratch space is released first.
pub(crate) fn emit_context(
    code: &mut Code,
    checked: &CheckedOperand,
    pc: u64,
) -> Result<(), CompileError> {
    let operand = &checked.operand;
    validate(operand)?;
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
    memory::begin(code);
    let (base, bytes, operation, order, shape) = match *operand {
        Operand::Clear => (
            None,
            0,
            ExclusiveOperation::Clear,
            MemoryOrder::Relaxed,
            ExclusiveShape::Scalar,
        ),
        Operand::Transfer {
            element_bytes,
            base,
            data,
            kind,
        } => {
            let (operation, order) = match kind {
                Kind::Load { acquire } => (
                    ExclusiveOperation::Load,
                    if acquire {
                        MemoryOrder::AcquireRcsc
                    } else {
                        MemoryOrder::Relaxed
                    },
                ),
                Kind::Store { release, .. } => (
                    ExclusiveOperation::Store,
                    if release {
                        MemoryOrder::Release
                    } else {
                        MemoryOrder::Relaxed
                    },
                ),
            };
            (
                Some(base),
                total_bytes(element_bytes, data),
                operation,
                order,
                if matches!(data, Data::Pair(_)) {
                    ExclusiveShape::Pair
                } else {
                    ExclusiveShape::Scalar
                },
            )
        }
    };
    let sp_failure = if checked.profile.sp_requirement() == SpAlignmentRequirement::Enabled {
        base.and_then(|base| memory::address::check_sp(code, base, pc))
    } else {
        None
    };
    if let Some(base) = base {
        memory::address::immediate(code, base, 0, AddressMode::Offset);
    } else {
        code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
    }
    memory::request(
        code,
        REQUEST_OFFSET,
        DATA_OFFSET,
        bytes,
        descriptor(operand),
        pc,
    );
    initialize(code);
    set_field(code, EXCLUSIVE_OPERATION_OFFSET, operation as u32);
    set_field(code, EXCLUSIVE_ORDER_OFFSET, order as u32);
    set_field(code, EXCLUSIVE_SHAPE_OFFSET, shape as u32);
    if let Operand::Transfer {
        element_bytes,
        data,
        kind: Kind::Store { .. },
        ..
    } = *operand
    {
        transfer_data(code, data, element_bytes, false);
    }
    memory::call(code, REQUEST_OFFSET);
    let callback_failure = memory::branch_failed(code);
    match *operand {
        Operand::Transfer {
            element_bytes,
            data,
            kind: Kind::Load { .. },
            ..
        } => transfer_data(code, data, element_bytes, true),
        Operand::Transfer {
            kind: Kind::Store { status, .. },
            ..
        } => commit(code, status, WORD_BYTES, EXCLUSIVE_STATUS_OFFSET),
        Operand::Clear => {}
    }
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
    let cleanup = code.len();
    crate::x86_64::asm::resolve(code, callback_failure, cleanup);
    if let Some(failure) = sp_failure {
        crate::x86_64::asm::resolve(code, failure, cleanup);
    }
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
    memory::address::return_if_failed(code);
    Ok(())
}

#[cfg(test)]
mod tests;
