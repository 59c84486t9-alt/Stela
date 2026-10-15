//! Checked exclusive transfers through the shared per-thread reservation owner.
//!
//! This adapter owns source snapshots and architectural result commits. The
//! runtime owns the indivisible memory quantity, ordering, translation, faults
//! and monitor state. No ordinary pair request or direct guest writer is used.

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
const SUB_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xc4];
const PXOR_XMM0_XMM0: &[u8] = &[0x66, 0x0f, 0xef, 0xc0];
const MOVDQU_RSP_DISP8_XMM0: &[u8] = &[0xf3, 0x0f, 0x7f, 0x44, 0x24];
const MOV_RSP_DISP8_IMM32: &[u8] = &[0xc7, 0x44, 0x24];
const MOV_RSP_DISP8_AL: &[u8] = &[0x88, 0x44, 0x24];
const MOV_RSP_DISP8_AX: &[u8] = &[0x66, 0x89, 0x44, 0x24];
const MOV_RSP_DISP8_EAX: &[u8] = &[0x89, 0x44, 0x24];
const MOV_RSP_DISP8_RAX: &[u8] = &[0x48, 0x89, 0x44, 0x24];
const MOVZX_EAX_BYTE_RSP_DISP8: &[u8] = &[0x0f, 0xb6, 0x44, 0x24];
const MOVZX_EAX_WORD_RSP_DISP8: &[u8] = &[0x0f, 0xb7, 0x44, 0x24];
const MOV_EAX_RSP_DISP8: &[u8] = &[0x8b, 0x44, 0x24];
const MOV_RAX_RSP_DISP8: &[u8] = &[0x48, 0x8b, 0x44, 0x24];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

/// One immutable control specialization feeds both consumed-body metadata and
/// native emission. The checked entry chooses this profile from actual controls.
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
                return Err(CompileError("invalid exclusive status register".into()));
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
        return Err(CompileError("invalid exclusive transfer operands".into()));
    }
    if constrained {
        return Err(CompileError(
            "constrained exclusive operands require a generic undefined-instruction boundary"
                .into(),
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
    }
}

fn initialize(code: &mut Vec<u8>) {
    code.extend(PXOR_XMM0_XMM0);
    for offset in (0..EXCLUSIVE_DATA_BYTES as u32).step_by(VECTOR_BYTES as usize) {
        code.extend(MOVDQU_RSP_DISP8_XMM0);
        code.push((DATA_OFFSET + offset) as u8);
    }
}

fn set_field(code: &mut Vec<u8>, offset: u32, value: u32) {
    // The complete payload was initialized. Zero-valued fields need no rewrite.
    if value != 0 {
        code.extend(MOV_RSP_DISP8_IMM32);
        code.push((DATA_OFFSET + offset) as u8);
        code.extend(value.to_le_bytes());
    }
}

fn stage(code: &mut Vec<u8>, register: Register, bytes: u8, offset: u32) {
    if register == Register::Zero {
        return;
    }
    load(code, register);
    code.extend(match bytes {
        BYTE_BYTES => MOV_RSP_DISP8_AL,
        HALFWORD_BYTES => MOV_RSP_DISP8_AX,
        WORD_BYTES => MOV_RSP_DISP8_EAX,
        DOUBLEWORD_BYTES => MOV_RSP_DISP8_RAX,
        _ => unreachable!("validated exclusive element width"),
    });
    code.push((DATA_OFFSET + offset) as u8);
}

fn commit(code: &mut Vec<u8>, register: Register, bytes: u8, offset: u32) {
    if register == Register::Zero {
        return;
    }
    code.extend(match bytes {
        BYTE_BYTES => MOVZX_EAX_BYTE_RSP_DISP8,
        HALFWORD_BYTES => MOVZX_EAX_WORD_RSP_DISP8,
        WORD_BYTES => MOV_EAX_RSP_DISP8,
        DOUBLEWORD_BYTES => MOV_RAX_RSP_DISP8,
        _ => unreachable!("validated exclusive result width"),
    });
    code.push((DATA_OFFSET + offset) as u8);
    store(code, register);
}

fn transfer_data(code: &mut Vec<u8>, data: Data, element_bytes: u8, loading: bool) {
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

/// The enclosing checked entry binds full-body requirements and the actual
/// per-thread memory owner before execution. One callback handles one exclusive
/// quantity or local CLREX; failures release scratch before returning to it.
pub(crate) fn emit_context(
    code: &mut Vec<u8>,
    checked: &CheckedOperand,
    pc: u64,
) -> Result<(), CompileError> {
    let operand = &checked.operand;
    validate(operand)?;
    code.extend(SUB_RSP_IMM8);
    code.push(SCRATCH_BYTES as u8);
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
        code.extend(XOR_EAX_EAX);
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
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    memory::patch_branch(code, callback_failure, cleanup);
    if let Some(failure) = sp_failure {
        memory::patch_branch(code, failure, cleanup);
    }
    code.extend(ADD_RSP_IMM8);
    code.push(SCRATCH_BYTES as u8);
    memory::address::return_if_failed(code);
    Ok(())
}

#[cfg(test)]
#[path = "exclusive/tests.rs"]
mod tests;
