//! SIMD loads and stores through the memory service. One request covers the whole
//! access, including both pair elements; destinations and base writeback are
//! written only after it succeeds.
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Size};
use crate::x86_64::simd::encode::guest;

use super::{Host, commit, read_vector, vector_offset};
use crate::aarch64::{
    AddressMode, Operation, Register, literal, non_temporal, register_offset::IndexExtend,
    simd::Operand,
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

/// `[rsp + offset]` in the scratch frame, with an 8-bit displacement.
fn scratch(offset: u8) -> Mem {
    Mem::base_disp8(Gpr::Rsp, offset as i8)
}

#[derive(Clone, Copy)]
enum Address {
    Literal {
        address: u64,
    },
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
    base: Option<Register>,
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
                base: Some(base),
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
                base: Some(base),
                address: Address::Immediate { displacement, mode },
            },
            Operand::MemoryRegisterOffset(operand) => Self {
                load: operand.load,
                bytes: operand.bytes,
                vectors: [operand.vector, operand.vector],
                elements: 1,
                base: Some(operand.base),
                address: Address::Register {
                    index: operand.index,
                    extend: operand.extend,
                    shift: operand.shift,
                },
            },
            _ => return None,
        })
    }

    fn from_literal(operand: &literal::Operand) -> Option<Self> {
        let literal::Transfer::Simd { destination, bytes } = operand.transfer else {
            return None;
        };
        if !matches!(bytes, DWORD_BYTES | QWORD_BYTES | VECTOR_BYTES) {
            return None;
        }
        Some(Self {
            load: true,
            bytes,
            vectors: [destination, destination],
            elements: 1,
            base: None,
            address: Address::Literal {
                address: operand.address,
            },
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
            base: Some(operand.base),
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
            | if !matches!(self.address, Address::Literal { .. })
                && (self.writeback()
                    || self.base != Some(Register::Sp)
                    || matches!(self.address, Address::Register { .. }))
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
            Address::Literal { address } => {
                address.is_multiple_of(u64::from(self.quantity_bytes()))
            }
            Address::Immediate { displacement, mode } => {
                crate::x86_64::memory_store::aligned_immediate(
                    self.base.expect("register-based SIMD address"),
                    displacement,
                    mode,
                    self.quantity_bytes(),
                )
            }
            Address::Register { index, shift, .. } => {
                crate::x86_64::memory_store::aligned_register_offset(
                    self.base.expect("register-based SIMD address"),
                    index,
                    shift,
                    self.quantity_bytes(),
                )
            }
        }
    }
}

/// A fixed-width transfer from the decoder, with the selected SP policy.
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
            Operation::Literal(operand) => (Transfer::from_literal(operand)?, false),
            Operation::MemoryNonTemporal(operand)
                if matches!(operand.data, non_temporal::Data::Vector(_)) =>
            {
                (Transfer::from_non_temporal(operand), true)
            }
            _ => return None,
        };
        let valid_base = match transfer.address {
            Address::Literal { .. } => transfer.base.is_none(),
            _ => {
                matches!(transfer.base, Some(Register::X(index)) if index < GPR_COUNT)
                    || transfer.base == Some(Register::Sp)
            }
        };
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

    pub(crate) fn emit_context(&self, code: &mut Code, pc: u64) {
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
        required_address_checks: if matches!(transfer.address, Address::Literal { .. }) {
            Default::default()
        } else {
            profile.address_requirements(false)
        },
        required_flags,
        required_host_caps: if transfer.load
            && !(transfer.naturally_aligned()
                && (transfer.base != Some(Register::Sp)
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
        required_sp_alignment: if transfer.base == Some(Register::Sp) {
            profile.sp_requirement()
        } else {
            SpAlignmentRequirement::Any
        },
        ..MemoryRequirements::default()
    }
}

fn address(code: &mut Code, transfer: Transfer, profile: CheckedMemoryProfile) {
    match transfer.address {
        Address::Literal { address } => crate::x86_64::immediate(code, address),
        Address::Immediate { displacement, mode } => {
            service::address::immediate_with_checks(
                code,
                transfer.base.expect("register-based SIMD address"),
                displacement,
                mode,
                profile.address_checks(false),
            );
            if transfer.writeback() {
                code.asm()
                    .mov_store(Size::Qword, scratch(WRITEBACK_OFFSET), Gpr::Rdx);
            }
        }
        Address::Register {
            index,
            extend,
            shift,
        } => {
            service::address::register_offset_with_checks(
                code,
                transfer.base.expect("register-based SIMD address"),
                index,
                extend,
                shift,
                profile.address_checks(false),
            );
        }
    }
}

fn stage_sources(code: &mut Code, transfer: Transfer) {
    for element in 0..transfer.elements {
        let vector = transfer.vectors[usize::from(element)];
        let displacement = element * transfer.bytes;
        if transfer.bytes == VECTOR_BYTES {
            read_vector(code, vector, 0);
            Host::StoreUnaligned.emit(code, 0, scratch(displacement), crate::TargetCpu::Baseline);
        } else {
            // Reading full64 from independently live State is safe. The service
            // sees only the exact quantity; S-pair's second stage overwrites the
            // first stage's unused high32 before the callback can see it.
            let mut asm = code.asm();
            asm.mov_load(Size::Qword, Gpr::Rcx, guest(vector_offset(vector)));
            asm.mov_store(Size::Qword, scratch(displacement), Gpr::Rcx);
        }
    }
}

fn commit_loads(code: &mut Code, transfer: Transfer) {
    for element in 0..transfer.elements {
        let staged = scratch(element * transfer.bytes);
        let baseline = crate::TargetCpu::Baseline;
        match transfer.bytes {
            BYTE_BYTES => code.asm().movzx(Size::Dword, Gpr::Rcx, Size::Byte, staged),
            HALFWORD_BYTES => code.asm().movzx(Size::Dword, Gpr::Rcx, Size::Word, staged),
            DWORD_BYTES => code.asm().movd_to_xmm(0, staged),
            QWORD_BYTES => Host::MoveQword.emit(code, 0, staged, baseline),
            VECTOR_BYTES => Host::LoadUnaligned.emit(code, 0, staged, baseline),
            _ => unreachable!("decoder validates fixed SIMD memory width"),
        }
        if transfer.bytes <= HALFWORD_BYTES {
            code.asm().movd_to_xmm(0, Gpr::Rcx);
        }
        commit(code, transfer.vectors[usize::from(element)], 0);
    }
}

/// Checked entry
/// validates CPU/profile requirements; failure returns through its inner-body
/// epilogue after releasing scratch. RDI/R15 and full host MXCSR survive calls.
#[cfg(test)]
pub(crate) fn emit_context(code: &mut Code, operand: &Operand, pc: u64) {
    emit_transfer(
        code,
        Transfer::from_operand(operand).expect("checked fixed SIMD memory operand"),
        pc,
        false,
        CheckedMemoryProfile::SpAlignmentEnabled,
    );
}

#[cfg(test)]
pub(crate) fn emit_non_temporal_context(code: &mut Code, operand: &non_temporal::Operand, pc: u64) {
    emit_transfer(
        code,
        Transfer::from_non_temporal(operand),
        pc,
        true,
        CheckedMemoryProfile::SpAlignmentEnabled,
    );
}

fn emit_transfer(
    code: &mut Code,
    transfer: Transfer,
    pc: u64,
    non_temporal: bool,
    profile: CheckedMemoryProfile,
) {
    debug_assert!(transfer.base.is_none_or(|base| offset(base).is_some()));
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
    service::begin(code);
    let mut failed = Vec::new();
    if profile.sp_requirement() == SpAlignmentRequirement::Enabled
        && let Some(base) = transfer.base
        && let Some(failure) = service::address::check_sp(code, base, pc)
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
        code.asm()
            .mov_load(Size::Qword, Gpr::Rax, scratch(WRITEBACK_OFFSET));
        store(
            code,
            transfer.base.expect("writeback requires a register base"),
        );
    }
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
    let cleanup = code.len();
    for failure in failed {
        crate::x86_64::asm::resolve(code, failure, cleanup);
    }
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
    service::address::return_if_failed(code);
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
