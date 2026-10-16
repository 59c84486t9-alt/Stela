//! SIMD loads and stores through the memory service. One request covers the whole
//! access, including both pair elements; destinations and base writeback are
//! written only after it succeeds.

use super::{commit, read_vector, vector_offset};
use crate::aarch64::{
    AddressMode, Operation, Register, non_temporal, register_offset::IndexExtend, simd::Operand,
};
use crate::block::CheckedMemoryProfile;
use crate::context::memory::{
    MEMORY_REQUEST_BYTES, MemoryRequirements, SpAlignmentRequirement, flags, host_caps,
    profile_requirements,
};
use crate::x86_64::{memory_context as service, offset, store};
use alloc::vec::Vec;

const BYTE_BYTES: u8 = size_of::<u8>() as u8;
const HALFWORD_BYTES: u8 = size_of::<u16>() as u8;
const DWORD_BYTES: u8 = size_of::<u32>() as u8;
const QWORD_BYTES: u8 = size_of::<u64>() as u8;
const VECTOR_BYTES: u8 = size_of::<u128>() as u8;
const GPR_COUNT: u8 = 31;
const VECTOR_REGISTER_COUNT: u8 = 32;
const PAIR_ELEMENTS: u8 = 2;
const STAGING_BYTES: u8 = PAIR_ELEMENTS * VECTOR_BYTES;
const REQUEST_OFFSET: u32 = STAGING_BYTES as u32;
const WRITEBACK_OFFSET: u8 = STAGING_BYTES + MEMORY_REQUEST_BYTES as u8;
const STACK_ALIGNMENT: u8 = VECTOR_BYTES;
const SCRATCH_BYTES: u8 = WRITEBACK_OFFSET + STACK_ALIGNMENT;

const SUB_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xec];
const ADD_RSP_IMM8: &[u8] = &[0x48, 0x83, 0xc4];
const MOV_RSP_DISP8_RDX: &[u8] = &[0x48, 0x89, 0x54, 0x24];
const MOV_RAX_RSP_DISP8: &[u8] = &[0x48, 0x8b, 0x44, 0x24];
const MOV_RCX_STATE_DISP32: &[u8] = &[0x48, 0x8b, 0x8f];
const MOV_RSP_DISP8_RCX: &[u8] = &[0x48, 0x89, 0x4c, 0x24];
const MOVDQU_RSP_DISP8_XMM0: &[u8] = &[0xf3, 0x0f, 0x7f, 0x44, 0x24];
const MOVDQU_XMM0_RSP_DISP8: &[u8] = &[0xf3, 0x0f, 0x6f, 0x44, 0x24];
const MOVQ_XMM0_RSP_DISP8: &[u8] = &[0xf3, 0x0f, 0x7e, 0x44, 0x24];
const MOVD_XMM0_RSP_DISP8: &[u8] = &[0x66, 0x0f, 0x6e, 0x44, 0x24];
const MOVZX_ECX_BYTE_RSP_DISP8: &[u8] = &[0x0f, 0xb6, 0x4c, 0x24];
const MOVZX_ECX_WORD_RSP_DISP8: &[u8] = &[0x0f, 0xb7, 0x4c, 0x24];
const MOVD_XMM0_ECX: &[u8] = &[0x66, 0x0f, 0x6e, 0xc1];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

#[derive(Clone, Copy)]
enum Address {
    Immediate {
        displacement: i32,
        mode: AddressMode,
    },
    Register {
        index: Register,
        extend: IndexExtend,
        shift: u8,
    },
}

#[derive(Clone, Copy)]
struct Transfer {
    load: bool,
    bytes: u8,
    vectors: [u8; 2],
    elements: u8,
    base: Register,
    address: Address,
}

impl Transfer {
    fn from_operand(operand: &Operand) -> Option<Self> {
        Some(match *operand {
            Operand::Memory {
                load,
                bytes,
                vector,
                base,
                displacement,
                mode,
            } => Self {
                load,
                bytes,
                vectors: [vector, vector],
                elements: 1,
                base,
                address: Address::Immediate { displacement, mode },
            },
            Operand::MemoryPair {
                load,
                bytes,
                vectors,
                base,
                displacement,
                mode,
            } => Self {
                load,
                bytes,
                vectors,
                elements: PAIR_ELEMENTS,
                base,
                address: Address::Immediate { displacement, mode },
            },
            Operand::MemoryRegisterOffset(operand) => Self {
                load: operand.load,
                bytes: operand.bytes,
                vectors: [operand.vector, operand.vector],
                elements: 1,
                base: operand.base,
                address: Address::Register {
                    index: operand.index,
                    extend: operand.extend,
                    shift: operand.shift,
                },
            },
            _ => return None,
        })
    }

    fn from_non_temporal(operand: &non_temporal::Operand) -> Self {
        let non_temporal::Data::Vector(vectors) = operand.data else {
            unreachable!("checked SIMD non-temporal routing requires vector data")
        };
        Self {
            load: operand.load,
            bytes: operand.bytes,
            vectors,
            elements: PAIR_ELEMENTS,
            base: operand.base,
            address: Address::Immediate {
                displacement: operand.displacement,
                mode: AddressMode::Offset,
            },
        }
    }

    fn writeback(self) -> bool {
        matches!(self.address, Address::Immediate { mode, .. } if mode != AddressMode::Offset)
    }

    fn descriptor(self, non_temporal: bool) -> u32 {
        flags::ASIMD
            | if self.load { 0 } else { flags::WRITE }
            | if self.elements == PAIR_ELEMENTS {
                flags::PAIR
            } else {
                0
            }
            | if non_temporal { flags::NON_TEMPORAL } else { 0 }
            | if self.writeback()
                || self.base != Register::Sp
                || matches!(self.address, Address::Register { .. })
            {
                flags::TAG_CHECKED
            } else {
                0
            }
    }

    fn quantity_bytes(self) -> u8 {
        self.bytes * self.elements
    }

    fn naturally_aligned(self) -> bool {
        match self.address {
            Address::Immediate { displacement, mode } => {
                crate::x86_64::memory_store::aligned_immediate(
                    self.base,
                    displacement,
                    mode,
                    self.quantity_bytes(),
                )
            }
            Address::Register { index, shift, .. } => {
                crate::x86_64::memory_store::aligned_register_offset(
                    self.base,
                    index,
                    shift,
                    self.quantity_bytes(),
                )
            }
        }
    }
}

/// Decoder-derived fixed-width transfer with the actual selected SP policy.
/// The runtime must separately retain FP/System/Guest and memory authorities.
#[derive(Clone, Copy)]
pub(crate) struct CheckedOperand {
    transfer: Transfer,
    profile: CheckedMemoryProfile,
    non_temporal: bool,
}

impl CheckedOperand {
    pub(crate) fn from_operation(
        operation: &Operation,
        profile: CheckedMemoryProfile,
    ) -> Option<Self> {
        let (transfer, non_temporal) = match operation {
            Operation::Simd(operand) => (Transfer::from_operand(operand)?, false),
            Operation::MemoryNonTemporal(operand)
                if matches!(operand.data, non_temporal::Data::Vector(_)) =>
            {
                (Transfer::from_non_temporal(operand), true)
            }
            _ => return None,
        };
        let valid_base = matches!(transfer.base, Register::X(index) if index < GPR_COUNT)
            || transfer.base == Register::Sp;
        if !valid_base
            || !matches!(
                transfer.bytes,
                BYTE_BYTES | HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES | VECTOR_BYTES
            )
            || transfer
                .vectors
                .iter()
                .any(|vector| *vector >= VECTOR_REGISTER_COUNT)
            || (transfer.elements == PAIR_ELEMENTS && transfer.bytes < DWORD_BYTES)
            || (transfer.load
                && transfer.elements == PAIR_ELEMENTS
                && transfer.vectors[0] == transfer.vectors[1])
        {
            return None;
        }
        if let Address::Register { index, shift, .. } = transfer.address {
            let valid_index =
                matches!(index, Register::X(value) if value < GPR_COUNT) || index == Register::Zero;
            if !valid_index || ![0, transfer.bytes.trailing_zeros() as u8].contains(&shift) {
                return None;
            }
        }
        Some(Self {
            transfer,
            profile,
            non_temporal,
        })
    }

    pub(crate) fn requirements(&self) -> MemoryRequirements {
        transfer_requirements(self.transfer, self.non_temporal, self.profile)
    }

    pub(crate) fn emit_context(&self, code: &mut Vec<u8>, pc: u64) {
        emit_transfer(code, self.transfer, pc, self.non_temporal, self.profile);
    }
}

/// Bind the exact emitted body's service requirements before any guest effect.
/// ASIMD16/32 with LS64WB disabled has only aligned8 or byte parts. Smaller
/// dynamic reads may need an aligned16 host snapshot for an unaligned <=8 part.
#[cfg(test)]
pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    transfer_requirements(
        Transfer::from_operand(operand).expect("checked fixed SIMD memory operand"),
        false,
        CheckedMemoryProfile::SpAlignmentEnabled,
    )
}

#[cfg(test)]
pub(crate) fn requirements_non_temporal(operand: &non_temporal::Operand) -> MemoryRequirements {
    transfer_requirements(
        Transfer::from_non_temporal(operand),
        true,
        CheckedMemoryProfile::SpAlignmentEnabled,
    )
}

fn transfer_requirements(
    transfer: Transfer,
    non_temporal: bool,
    profile: CheckedMemoryProfile,
) -> MemoryRequirements {
    let required_flags = transfer.descriptor(non_temporal);
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: profile.address_requirements(false),
        required_flags,
        required_host_caps: if transfer.load
            && !(transfer.naturally_aligned()
                && (transfer.base != Register::Sp
                    || profile.sp_requirement() == SpAlignmentRequirement::Enabled))
            && matches!(
                transfer.quantity_bytes(),
                HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES
            ) {
            host_caps::ATOMIC_LOAD16
        } else {
            0
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if required_flags & flags::TAG_CHECKED != 0 {
                profile_requirements::TAG_GRANULES
            } else {
                0
            },
        required_sp_alignment: if transfer.base == Register::Sp {
            profile.sp_requirement()
        } else {
            SpAlignmentRequirement::Any
        },
    }
}

fn address(code: &mut Vec<u8>, transfer: Transfer, profile: CheckedMemoryProfile) {
    match transfer.address {
        Address::Immediate { displacement, mode } => {
            service::address::immediate_with_checks(
                code,
                transfer.base,
                displacement,
                mode,
                profile.address_checks(false),
            );
            if transfer.writeback() {
                code.extend(MOV_RSP_DISP8_RDX);
                code.push(WRITEBACK_OFFSET);
            }
        }
        Address::Register {
            index,
            extend,
            shift,
        } => {
            service::address::register_offset_with_checks(
                code,
                transfer.base,
                index,
                extend,
                shift,
                profile.address_checks(false),
            );
        }
    }
}

fn stage_sources(code: &mut Vec<u8>, transfer: Transfer) {
    for element in 0..transfer.elements {
        let vector = transfer.vectors[usize::from(element)];
        let displacement = element * transfer.bytes;
        if transfer.bytes == VECTOR_BYTES {
            read_vector(code, vector, 0);
            code.extend(MOVDQU_RSP_DISP8_XMM0);
        } else {
            // Reading full64 from independently live State is safe. The service
            // sees only the exact quantity; S-pair's second stage overwrites the
            // first stage's unused high32 before the callback can see it.
            code.extend(MOV_RCX_STATE_DISP32);
            code.extend(vector_offset(vector).to_le_bytes());
            code.extend(MOV_RSP_DISP8_RCX);
        }
        code.push(displacement);
    }
}

fn commit_loads(code: &mut Vec<u8>, transfer: Transfer) {
    for element in 0..transfer.elements {
        let displacement = element * transfer.bytes;
        code.extend(match transfer.bytes {
            BYTE_BYTES => MOVZX_ECX_BYTE_RSP_DISP8,
            HALFWORD_BYTES => MOVZX_ECX_WORD_RSP_DISP8,
            DWORD_BYTES => MOVD_XMM0_RSP_DISP8,
            QWORD_BYTES => MOVQ_XMM0_RSP_DISP8,
            VECTOR_BYTES => MOVDQU_XMM0_RSP_DISP8,
            _ => unreachable!("decoder validates fixed SIMD memory width"),
        });
        code.push(displacement);
        if transfer.bytes <= HALFWORD_BYTES {
            code.extend(MOVD_XMM0_ECX);
        }
        commit(code, transfer.vectors[usize::from(element)], 0);
    }
}

/// Checked entry
/// validates CPU/profile requirements; failure returns through its inner-body
/// epilogue after releasing scratch. RDI/R15 and full host MXCSR survive calls.
#[cfg(test)]
pub(crate) fn emit_context(code: &mut Vec<u8>, operand: &Operand, pc: u64) {
    emit_transfer(
        code,
        Transfer::from_operand(operand).expect("checked fixed SIMD memory operand"),
        pc,
        false,
        CheckedMemoryProfile::SpAlignmentEnabled,
    );
}

#[cfg(test)]
pub(crate) fn emit_non_temporal_context(
    code: &mut Vec<u8>,
    operand: &non_temporal::Operand,
    pc: u64,
) {
    emit_transfer(
        code,
        Transfer::from_non_temporal(operand),
        pc,
        true,
        CheckedMemoryProfile::SpAlignmentEnabled,
    );
}

fn emit_transfer(
    code: &mut Vec<u8>,
    transfer: Transfer,
    pc: u64,
    non_temporal: bool,
    profile: CheckedMemoryProfile,
) {
    debug_assert!(offset(transfer.base).is_some());
    code.extend(SUB_RSP_IMM8);
    code.push(SCRATCH_BYTES);
    service::begin(code);
    let mut failed = Vec::new();
    if profile.sp_requirement() == SpAlignmentRequirement::Enabled
        && let Some(failure) = service::address::check_sp(code, transfer.base, pc)
    {
        failed.push(failure);
    }
    address(code, transfer, profile);
    if !transfer.load {
        stage_sources(code, transfer);
    }
    service::request(
        code,
        REQUEST_OFFSET,
        0,
        u32::from(transfer.quantity_bytes()),
        transfer.descriptor(non_temporal),
        pc,
    );
    service::call(code, REQUEST_OFFSET);
    failed.push(service::branch_failed(code));
    if transfer.load {
        commit_loads(code, transfer);
    }
    if transfer.writeback() {
        code.extend(MOV_RAX_RSP_DISP8);
        code.push(WRITEBACK_OFFSET);
        store(code, transfer.base);
    }
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    for failure in failed {
        service::patch_branch(code, failure, cleanup);
    }
    code.extend(ADD_RSP_IMM8);
    code.push(SCRATCH_BYTES);
    service::address::return_if_failed(code);
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
