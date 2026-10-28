//! Multi-vector loads and stores through the memory service. Loads commit after
//! the whole tuple succeeds; stores submit elements in ascending order.
use super::super::{isa::SimdOpcode as Host, scalable};
use super::memory as common;
use super::predicate::{emit_prepared_counter_chunk, prepare_counter};
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, Size, resolve};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::memory_multi::Operand,
    },
    context::memory::{
        MEMORY_REQUEST_BYTES, MEMORY_REQUEST_DATA_OFFSET, MemoryRequirements,
        SpAlignmentRequirement, flags, host_caps, profile_requirements,
    },
};

const HOST_QWORD_BYTES: u32 = size_of::<u64>() as u32;
const STACK_ALIGNMENT: u32 = 16;
const PACKED_CHUNK_BITS: usize = u64::BITS as usize;
const REQUEST_OFFSET: u32 = 0;
const ADDRESS_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const INDEX_OFFSET: u32 = ADDRESS_OFFSET + HOST_QWORD_BYTES;
const MASK_OFFSET: u32 = INDEX_OFFSET + HOST_QWORD_BYTES;
const VECTOR_TEMPORARY: u8 = 0;

#[derive(Debug, Clone, Copy)]
struct Scratch {
    data: u32,
    bytes: u32,
}

impl Scratch {
    fn new(tuple_bytes: usize) -> Self {
        let mask_bytes = tuple_bytes.div_ceil(PACKED_CHUNK_BITS) as u32 * HOST_QWORD_BYTES;
        let data = MASK_OFFSET + mask_bytes.next_multiple_of(STACK_ALIGNMENT);
        Self {
            data,
            bytes: data + tuple_bytes as u32,
        }
    }
}

fn stack_vector(code: &mut Code, offset: u32, loading: bool, target: TargetCpu) {
    let opcode = if loading {
        Host::LoadUnaligned
    } else {
        Host::StoreUnaligned
    };
    code.asm()
        .simd(opcode, VECTOR_TEMPORARY, stack(offset), target);
}

fn stack(offset: u32) -> Mem {
    Mem::base_disp32(Rsp, offset as i32)
}

fn prepare_iteration(code: &mut Code, operand: &Operand, length: VectorLength) {
    common::address(code, operand.address, length);
    let mut asm = code.asm();
    asm.mov_store(Size::Qword, stack(ADDRESS_OFFSET), Rax);
    asm.mov_rm_imm32(Size::Qword, stack(INDEX_OFFSET), 0);
}

fn prepare_vector_staging(
    code: &mut Code,
    operand: &Operand,
    scratch: Scratch,
    length: VectorLength,
    target: TargetCpu,
) {
    if operand.loading {
        Host::Xor.register(code, VECTOR_TEMPORARY, VECTOR_TEMPORARY, target);
    }
    for register in 0..operand.registers {
        for chunk in 0..length.chunks() {
            if !operand.loading {
                scalable::load_z_chunk(
                    code,
                    operand.first + register,
                    chunk,
                    VECTOR_TEMPORARY,
                    length,
                    target,
                );
            }
            let position = usize::from(register) * length.bytes() + chunk * VECTOR_CHUNK_BYTES;
            stack_vector(code, scratch.data + position as u32, false, target);
        }
    }
}

/// Decode PN once, then spill its packed mask before any memory callback.
/// The published chunk helper preserves R8/R9/R10 preparation state. Only
/// private-stack stores intervene, so no callback clobber crosses that interval.
fn prepare_predicate_staging(code: &mut Code, operand: &Operand, length: VectorLength) {
    let predicate_bits = usize::from(operand.registers) * length.bytes();
    scalable::read_predicate_chunk(code, operand.predicate, 0, length);
    prepare_counter(code, length);
    for chunk in 0..predicate_bits.div_ceil(PACKED_CHUNK_BITS) {
        emit_prepared_counter_chunk(code, chunk, length);
        code.asm().mov_store(
            Size::Qword,
            stack(MASK_OFFSET + chunk as u32 * HOST_QWORD_BYTES),
            Rax,
        );
    }
}

fn commit_load(
    code: &mut Code,
    operand: &Operand,
    scratch: Scratch,
    length: VectorLength,
    target: TargetCpu,
) {
    for register in 0..operand.registers {
        for chunk in 0..length.chunks() {
            let position = usize::from(register) * length.bytes() + chunk * VECTOR_CHUNK_BYTES;
            stack_vector(code, scratch.data + position as u32, true, target);
            scalable::store_z_chunk(
                code,
                operand.first + register,
                chunk,
                VECTOR_TEMPORARY,
                length,
                target,
            );
        }
    }
}

fn access_flags(operand: &Operand) -> u32 {
    // These PN-governed forms call the four-argument CreateAccDescSVE overload,
    // which sets descriptor.predicated=false independently of the PN mask.
    (if operand.loading { 0 } else { flags::WRITE })
        | if operand.tag_checked() {
            flags::TAG_CHECKED
        } else {
            0
        }
        | if operand.non_temporal {
            flags::NON_TEMPORAL
        } else {
            0
        }
}

/// Requirements of this complete body, admitted before any guest effect.
/// The shared SP check specializes SA-enabled execution: tuple-scaled immediate
/// and element-scaled register offsets keep every SP-base element naturally
/// aligned. Generic multibyte loads may need an enclosing atomic16 snapshot.
/// Scalar stores use XCHG and need no optional host capability.
pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_sp_alignment: if operand.address.base == Register::Sp {
            SpAlignmentRequirement::Enabled
        } else {
            SpAlignmentRequirement::Any
        },
        required_flags: access_flags(operand),
        required_host_caps: if operand.loading
            && operand.element != ElementSize::Byte
            && operand.address.base != Register::Sp
        {
            host_caps::ATOMIC_LOAD16
        } else {
            0
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if operand.tag_checked() {
                profile_requirements::TAG_GRANULES | profile_requirements::SCALABLE_TAG_CHECKS
            } else {
                0
            },
        ..MemoryRequirements::default()
    }
}

/// Candidate context-memory emission. Entry has RDI=State, R15=Context and
/// RSP=8 modulo16. Failure restores scratch then returns the inner body to its
/// outer context wrapper; success has EAX=0 and falls through. RDI/R15 survive.
pub(crate) fn emit(
    code: &mut Code,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) {
    use scalable::memory;
    let tuple_bytes = usize::from(operand.registers) * length.bytes();
    let scratch = Scratch::new(tuple_bytes);
    code.asm()
        .alu_imm32(Alu::Sub, Size::Qword, Rsp, scratch.bytes as i32);
    memory::begin(code);
    let alignment_failure = common::check_sp(code, operand.address.base, pc);
    prepare_iteration(code, operand, length);
    prepare_vector_staging(code, operand, scratch, length, target);
    prepare_predicate_staging(code, operand, length);
    let loop_start = code.len();
    let mut asm = code.asm();
    asm.mov_load(Size::Qword, Rcx, stack(INDEX_OFFSET));
    asm.bt(Size::Qword, stack(MASK_OFFSET), Rcx);
    let inactive = asm.jcc(Cond::Ae);
    asm.mov_load(Size::Qword, Rax, stack(ADDRESS_OFFSET));
    asm.alu(Alu::Add, Size::Qword, Rax, Rcx);
    memory::request(
        code,
        REQUEST_OFFSET,
        scratch.data,
        operand.element.bytes() as u32,
        access_flags(operand),
        pc,
    );
    // request() clobbers RCX/RDX. Reload the saved linear byte offset before
    // selecting this element's private staging, never an architectural Z slot.
    let mut asm = code.asm();
    asm.mov_load(Size::Qword, Rcx, stack(INDEX_OFFSET));
    asm.alu(
        Alu::Add,
        Size::Qword,
        stack(REQUEST_OFFSET + MEMORY_REQUEST_DATA_OFFSET),
        Rcx,
    );
    memory::call(code, REQUEST_OFFSET);
    let callback_failure = memory::branch_failed(code);
    let mut asm = code.asm();
    asm.bind(inactive);
    asm.alu_imm8(
        Alu::Add,
        Size::Qword,
        stack(INDEX_OFFSET),
        operand.element.bytes() as i8,
    );
    asm.alu_imm32(
        Alu::Cmp,
        Size::Qword,
        stack(INDEX_OFFSET),
        tuple_bytes as i32,
    );
    let repeat = asm.jcc(Cond::B);
    resolve(code, repeat, loop_start);
    if operand.loading {
        commit_load(code, operand, scratch, length, target);
    }
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    let cleanup = code.len();
    memory::patch_branch(code, callback_failure, cleanup);
    if let Some(failure) = alignment_failure {
        memory::patch_branch(code, failure, cleanup);
    }
    code.asm()
        .alu_imm32(Alu::Add, Size::Qword, Rsp, scratch.bytes as i32);
    common::return_if_failed(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
    const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];

    #[test]
    fn private_scratch_is_bounded_aligned_and_disjoint() {
        for vector_bytes in [16, 32, 64, 128, 256] {
            for registers in [2, 4] {
                let tuple_bytes = vector_bytes * registers;
                let scratch = Scratch::new(tuple_bytes);
                assert_eq!(scratch.bytes % STACK_ALIGNMENT, 0);
                assert!(scratch.data >= MASK_OFFSET + tuple_bytes.div_ceil(8) as u32);
                assert_eq!(scratch.bytes, scratch.data + tuple_bytes as u32);
                assert!(scratch.bytes <= 1200);
            }
        }
    }

    #[test]
    fn one_callback_site_handles_all_lengths_and_restores_stack_on_each_exit() {
        for vector_bytes in [16, 32, 64, 128, 256] {
            let length = VectorLength::from_bytes(vector_bytes).unwrap();
            for word in [0xa040_0000, 0xa060_e001, 0xa03f_6000, 0xa040_03e0] {
                let operand = crate::aarch64::sve::memory_multi::decode(word)
                    .unwrap()
                    .unwrap();
                let mut code = Code::new();
                emit(&mut code, &operand, length, TargetCpu::Baseline, 0x1000);
                let scratch = Scratch::new(usize::from(operand.registers) * vector_bytes);
                assert!(code.starts_with(SUB_RSP_IMM32));
                let cleanup = [ADD_RSP_IMM32, &scratch.bytes.to_le_bytes()].concat();
                assert_eq!(
                    code.windows(cleanup.len())
                        .filter(|bytes| *bytes == cleanup)
                        .count(),
                    1
                );
                assert_eq!(
                    code.windows(3)
                        .filter(|bytes| *bytes == [0xff, 0x57, 8])
                        .count(),
                    1
                );
                assert!(code.len() < 8192);
            }
        }
    }

    #[test]
    fn descriptors_and_preentry_requirements_use_actual_element_widths() {
        use crate::aarch64::sve::memory_multi::decode;
        const LD1B_PAIR_X5: u32 = 0xa040_00a0;
        const LD1D_PAIR_X5: u32 = 0xa040_60a0;
        const LD1D_PAIR_SP: u32 = 0xa040_63e0;
        const LDNT1D_PAIR_SP_REGISTER: u32 = 0xa000_63e1;
        const ST1D_QUAD_X5: u32 = 0xa060_e0a0;
        for (word, descriptor, capabilities, profile) in [
            (
                LD1B_PAIR_X5,
                flags::TAG_CHECKED,
                0,
                profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
            ),
            (
                LD1D_PAIR_X5,
                flags::TAG_CHECKED,
                host_caps::ATOMIC_LOAD16,
                profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
            ),
            (LD1D_PAIR_SP, 0, 0, profile_requirements::NATIVE_ACCESS),
            (
                LDNT1D_PAIR_SP_REGISTER,
                flags::TAG_CHECKED | flags::NON_TEMPORAL,
                0,
                profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
            ),
            (
                ST1D_QUAD_X5,
                flags::TAG_CHECKED | flags::WRITE,
                0,
                profile_requirements::NATIVE_ACCESS | profile_requirements::TAG_GRANULES,
            ),
        ] {
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(
                requirements(&operand),
                MemoryRequirements {
                    required_pointer_arithmetic: None,
                    required_address_checks: Default::default(),
                    required_sp_alignment: if operand.address.base == Register::Sp {
                        SpAlignmentRequirement::Enabled
                    } else {
                        SpAlignmentRequirement::Any
                    },
                    required_flags: descriptor,
                    required_host_caps: capabilities,
                    required_profile: profile
                        | if operand.tag_checked() {
                            profile_requirements::SCALABLE_TAG_CHECKS
                        } else {
                            0
                        },
                    ..MemoryRequirements::default()
                }
            );
            assert_eq!(
                access_flags(&operand) & (flags::SME | flags::SVE_PREDICATED),
                0
            );
        }
    }
}
