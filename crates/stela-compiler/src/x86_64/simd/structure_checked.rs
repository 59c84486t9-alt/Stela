//! Fixed-width AdvSIMD structures through exact element memory-service requests.
//! The typed schedule owns access order and partial load commits. Guest addresses
//! are never host pointers; only private State and stack staging are dereferenced.
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Size};
use crate::x86_64::simd::encode::guest;

use super::{commit, vector_offset};
use crate::{
    TargetCpu,
    aarch64::{
        AddressMode, Operation, Register,
        register_offset::IndexExtend,
        simd::{
            Operand as SimdOperand,
            structure_memory::{Direction, Layout, LoadCommit, Operand, PostIndex},
        },
    },
    block::CheckedMemoryProfile,
    context::memory::{
        MEMORY_REQUEST_BYTES, MemoryRequirements, SpAlignmentRequirement, address::IncrementChoice,
        flags, host_caps, profile_requirements,
    },
    x86_64::{isa::SimdOpcode as Host, memory_context as service, store},
};
use alloc::vec::Vec;

const BYTE_BYTES: u8 = 1;
const HALFWORD_BYTES: u8 = 2;
const DWORD_BYTES: u8 = 4;
const QWORD_BYTES: u8 = 8;
const VECTOR_BYTES: u8 = 16;
const VECTOR_COUNT: u8 = 32;
const GPR_COUNT: u8 = 31;
const MAX_REGISTERS: u8 = 4;
const DATA_OFFSET: u8 = 0;
const BASE_OFFSET: u8 = QWORD_BYTES;
const WRITEBACK_OFFSET: u8 = BASE_OFFSET + QWORD_BYTES;
const REQUEST_OFFSET: u32 = 2 * VECTOR_BYTES as u32;
const SCRATCH_BYTES: u8 = REQUEST_OFFSET as u8 + MEMORY_REQUEST_BYTES as u8;

#[derive(Clone, Copy)]
pub(crate) struct CheckedOperand {
    operand: Operand,
    profile: CheckedMemoryProfile,
}

impl CheckedOperand {
    pub(crate) fn from_operation(
        operation: &Operation,
        profile: CheckedMemoryProfile,
    ) -> Option<Self> {
        let Operation::Simd(SimdOperand::StructureMemory(operand)) = operation else {
            return None;
        };
        let valid_base = matches!(operand.base, Register::X(index) if index < GPR_COUNT)
            || operand.base == Register::Sp;
        let valid_layout = match operand.layout {
            Layout::Multiple {
                repetitions,
                structures,
                vector_bytes,
            } => {
                (1..=MAX_REGISTERS).contains(&repetitions)
                    && (1..=MAX_REGISTERS).contains(&structures)
                    && (repetitions == 1 || structures == 1)
                    && matches!(vector_bytes, QWORD_BYTES | VECTOR_BYTES)
                    && operand.element_bytes <= vector_bytes
                    && !(structures > 1
                        && vector_bytes == QWORD_BYTES
                        && operand.element_bytes == QWORD_BYTES)
            }
            Layout::Lane { structures, index } => {
                (1..=MAX_REGISTERS).contains(&structures)
                    && u16::from(index) * u16::from(operand.element_bytes) < u16::from(VECTOR_BYTES)
            }
            Layout::Replicate {
                structures,
                vector_bytes,
            } => {
                operand.direction == Direction::Load
                    && (1..=MAX_REGISTERS).contains(&structures)
                    && matches!(vector_bytes, QWORD_BYTES | VECTOR_BYTES)
            }
        };
        if !valid_base
            || !valid_layout
            || operand.first_vector >= VECTOR_COUNT
            || !matches!(
                operand.element_bytes,
                BYTE_BYTES | HALFWORD_BYTES | DWORD_BYTES | QWORD_BYTES
            )
            || matches!(operand.post_index, PostIndex::Register(index) if index >= GPR_COUNT)
        {
            return None;
        }
        Some(Self {
            operand: *operand,
            profile,
        })
    }

    fn descriptor(self) -> u32 {
        flags::ASIMD
            | if self.operand.direction == Direction::Store {
                flags::WRITE
            } else {
                0
            }
            | if self.operand.base != Register::Sp || self.operand.post_index != PostIndex::None {
                flags::TAG_CHECKED
            } else {
                0
            }
    }

    pub(crate) fn requirements(self) -> MemoryRequirements {
        let required_flags = self.descriptor();
        MemoryRequirements {
            required_flags,
            required_host_caps: if self.operand.direction == Direction::Load
                && self.operand.element_bytes > BYTE_BYTES
                && (self.operand.base != Register::Sp
                    || self.profile.sp_requirement() != SpAlignmentRequirement::Enabled)
            {
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
            required_sp_alignment: if self.operand.base == Register::Sp {
                self.profile.sp_requirement()
            } else {
                SpAlignmentRequirement::Any
            },
            required_address_checks: if self.operand.post_index == PostIndex::None {
                self.profile.direct_address_requirements()
            } else {
                self.profile.address_requirements(false)
            }
            .with_increment_choice(IncrementChoice::Unchecked),
            ..MemoryRequirements::default()
        }
    }

    pub(crate) fn emit_context(self, code: &mut Code, pc: u64, target: TargetCpu) {
        let operand = self.operand;
        code.asm()
            .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
        service::begin(code);
        let mut failures = Vec::new();
        if self.profile.sp_requirement() == SpAlignmentRequirement::Enabled
            && let Some(failure) = service::address::check_sp(code, operand.base, pc)
        {
            failures.push(failure);
        }
        crate::x86_64::load(code, operand.base);
        save(code, Gpr::Rax, BASE_OFFSET);
        // Save original Rn and Xm-derived writeback before any callback. CPA2
        // result marking has no fault or guest effect and can be computed early.
        match operand.post_index {
            PostIndex::None => {}
            PostIndex::TransferredBytes => {
                service::address::immediate_with_checks(
                    code,
                    operand.base,
                    i32::from(operand.transferred_bytes()),
                    AddressMode::PostIndex,
                    self.profile.address_checks(false),
                );
                save(code, Gpr::Rdx, WRITEBACK_OFFSET);
            }
            PostIndex::Register(index) => {
                service::address::register_offset_with_checks(
                    code,
                    operand.base,
                    Register::X(index),
                    IndexExtend::Lsl,
                    0,
                    self.profile.address_checks(false),
                );
                save(code, Gpr::Rax, WRITEBACK_OFFSET);
            }
        }
        for access in operand.accesses() {
            if operand.direction == Direction::Store {
                let LoadCommit::Lane { index, .. } = access.commit else {
                    unreachable!("validated stores have lane sources")
                };
                scalar(
                    code,
                    false,
                    operand.element_bytes,
                    guest(vector_offset(access.vector) + u32::from(index * operand.element_bytes)),
                );
                // A full private staging store is safe; the request keeps the
                // exact element width and does not expose unused staging bytes.
                save(code, Gpr::Rcx, DATA_OFFSET);
            }
            restore(code, BASE_OFFSET);
            if access.byte_offset != 0 {
                code.asm().lea(
                    Size::Qword,
                    Gpr::Rax,
                    Mem::base_disp8(Gpr::Rax, access.byte_offset as i8),
                );
            }
            service::request(
                code,
                REQUEST_OFFSET,
                u32::from(DATA_OFFSET),
                u32::from(operand.element_bytes),
                self.descriptor(),
                pc,
            );
            service::call(code, REQUEST_OFFSET);
            failures.push(service::branch_failed(code));
            if operand.direction == Direction::Load {
                scalar(code, false, operand.element_bytes, slot(DATA_OFFSET));
                match access.commit {
                    LoadCommit::Lane { index, clear_upper } => {
                        scalar(
                            code,
                            true,
                            operand.element_bytes,
                            guest(
                                vector_offset(access.vector)
                                    + u32::from(index * operand.element_bytes),
                            ),
                        );
                        if clear_upper {
                            clear_upper_half(code, access.vector);
                        }
                    }
                    LoadCommit::Replicate { vector_bytes } => {
                        replicate(code, operand.element_bytes, vector_bytes, target);
                        commit(code, access.vector, 0);
                    }
                }
            }
        }
        if operand.post_index != PostIndex::None {
            restore(code, WRITEBACK_OFFSET);
            store(code, operand.base);
        }
        code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
        let cleanup = code.len();
        for failure in failures {
            crate::x86_64::asm::resolve(code, failure, cleanup);
        }
        code.asm()
            .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
        service::address::return_if_failed(code);
    }
}

/// `[rsp + offset]` in the scratch frame, with an 8-bit displacement.
fn slot(offset: u8) -> Mem {
    Mem::base_disp8(Gpr::Rsp, offset as i8)
}

/// Save `register` in the scratch slot at `offset`.
fn save(code: &mut Code, register: Gpr, offset: u8) {
    code.asm().mov_store(Size::Qword, slot(offset), register);
}

/// Reload RAX from the scratch slot at `offset`.
fn restore(code: &mut Code, offset: u8) {
    code.asm().mov_load(Size::Qword, Gpr::Rax, slot(offset));
}

/// Exact-width state/staging reads zero-extend narrow elements into RCX;
/// writes store RCX's low `bytes`.
fn scalar(code: &mut Code, write: bool, bytes: u8, memory: Mem) {
    let size = match bytes {
        BYTE_BYTES => Size::Byte,
        HALFWORD_BYTES => Size::Word,
        DWORD_BYTES => Size::Dword,
        QWORD_BYTES => Size::Qword,
        _ => unreachable!("validated structure element width"),
    };
    let mut asm = code.asm();
    if write {
        asm.mov_store(size, memory, Gpr::Rcx);
    } else if bytes <= HALFWORD_BYTES {
        asm.movzx(Size::Dword, Gpr::Rcx, size, memory);
    } else {
        asm.mov_load(size, Gpr::Rcx, memory);
    }
}

fn clear_upper_half(code: &mut Code, vector: u8) {
    code.asm().mov_rm_imm32(
        Size::Qword,
        guest(vector_offset(vector) + u32::from(QWORD_BYTES)),
        0,
    );
}

/// RCX contains one zero-extended, successfully read element. Rebuild an
/// optional shuffle mask after each callback; no host vector survives it.
fn replicate(code: &mut Code, bytes: u8, vector_bytes: u8, target: TargetCpu) {
    Host::MoveGprQword.register(code, 0, 1, TargetCpu::Baseline); // XMM0 <- RCX
    if bytes == BYTE_BYTES && vector_bytes == VECTOR_BYTES && target.supports(TargetCpu::Ssse3) {
        Host::Xor.register(code, 1, 1, TargetCpu::Baseline);
        Host::ByteShuffle.register(code, 0, 1, target);
        return;
    }
    if bytes == BYTE_BYTES {
        Host::UnpackLowByte.register(code, 0, 0, TargetCpu::Baseline);
    }
    match bytes {
        BYTE_BYTES | HALFWORD_BYTES if vector_bytes == QWORD_BYTES => {
            Host::ShuffleLowWord.register_imm(code, 0, 0, 0, TargetCpu::Baseline); // repeat low word, keeping the zero upper64
        }
        BYTE_BYTES | HALFWORD_BYTES => {
            Host::UnpackLowWord.register(code, 0, 0, TargetCpu::Baseline);
            Host::ShuffleDword.register_imm(code, 0, 0, 0, TargetCpu::Baseline); // repeat low dword
        }
        DWORD_BYTES if vector_bytes == VECTOR_BYTES => {
            Host::ShuffleDword.register_imm(code, 0, 0, 0, TargetCpu::Baseline);
        }
        DWORD_BYTES => Host::UnpackLowDword.register(code, 0, 0, TargetCpu::Baseline),
        QWORD_BYTES if vector_bytes == VECTOR_BYTES => {
            Host::UnpackLowQword.register(code, 0, 0, TargetCpu::Baseline);
        }
        QWORD_BYTES => {}
        _ => unreachable!("validated structure element width"),
    }
}

#[cfg(test)]
mod tests;
