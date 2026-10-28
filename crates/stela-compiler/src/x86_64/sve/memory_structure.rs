//! SVE LD2/LD3/LD4 through the memory service. Destinations are written after
//! every element succeeds.
use super::super::{
    isa::SimdOpcode as Host,
    scalable::{self, memory},
};
use super::memory as transfer;
use crate::x86_64::asm::Gpr::{R8, Rax, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, ShiftOp, Size, resolve};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::{memory::Offset, memory_structure::Operand},
    },
    context::memory::{
        MEMORY_REQUEST_BYTES, MEMORY_REQUEST_DATA_OFFSET, MemoryRequirements,
        SpAlignmentRequirement, flags, host_caps, profile_requirements,
    },
};
use alloc::vec::Vec;

const POINTER_BYTES: u32 = size_of::<u64>() as u32;
const STACK_ALIGNMENT: u32 = 16;
const PREDICATE_CHUNK_BITS: usize = u64::BITS as usize;
const PREDICATE_SELECTED: u8 = 1;
const ZERO_XMM: u8 = 0;

#[derive(Debug, Clone, Copy)]
struct Scratch {
    data_bytes: u32,
    address: u32,
    lane: u32,
    predicate: u32,
    request: u32,
    bytes: u32,
}

impl Scratch {
    fn new(registers: u8, length: VectorLength) -> Self {
        let data_bytes = u32::from(registers) * length.bytes() as u32;
        let address = data_bytes;
        let lane = address + POINTER_BYTES;
        let predicate = lane + POINTER_BYTES;
        let request = data_bytes + 2 * STACK_ALIGNMENT;
        let bytes = request + MEMORY_REQUEST_BYTES as u32;
        debug_assert_eq!(bytes % STACK_ALIGNMENT, 0);
        Self {
            data_bytes,
            address,
            lane,
            predicate,
            request,
            bytes,
        }
    }
}

fn stack(offset: u32) -> Mem {
    Mem::base_disp32(Rsp, offset as i32)
}

fn stack_vector(code: &mut Code, opcode: Host, offset: u32, target: TargetCpu) {
    code.asm().simd(opcode, ZERO_XMM, stack(offset), target);
}

fn access_flags(operand: Operand) -> u32 {
    flags::SVE_PREDICATED
        | if operand.address.base != Register::Sp
            || matches!(operand.address.offset, Offset::Register { .. })
        {
            flags::TAG_CHECKED
        } else {
            0
        }
}

/// Source-derived requirements for every reached structured-load quantity.
/// Q reads need a coherent aligned16 snapshot even with a naturally aligned SP.
/// Smaller SP-based quantities are naturally aligned by the checked SP16 and
/// element-scaled offset; unconstrained multibyte GPR reads can cross host8.
pub(crate) fn requirements(operand: Operand) -> MemoryRequirements {
    let required_flags = access_flags(operand);
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_flags,
        required_host_caps: if operand.element == ElementSize::Quadword
            || (operand.element != ElementSize::Byte && operand.address.base != Register::Sp)
        {
            host_caps::ATOMIC_LOAD16
        } else {
            0
        },
        required_sp_alignment: if operand.address.base == Register::Sp {
            SpAlignmentRequirement::Enabled
        } else {
            SpAlignmentRequirement::Any
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if required_flags & flags::TAG_CHECKED != 0 {
                profile_requirements::TAG_GRANULES | profile_requirements::SCALABLE_TAG_CHECKS
            } else {
                0
            },
        ..MemoryRequirements::default()
    }
}

/// RDI/R15 and the entry RSP are preserved. Failures return their MemoryStatus
/// in EAX; success sets EAX to 0 and falls through. SP is checked even when
/// every lane is inactive.
pub(crate) fn emit(
    code: &mut Code,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) {
    let scratch = Scratch::new(operand.registers, length);
    let width = operand.element.bytes() as u32;
    let access_flags = access_flags(*operand);
    let mut failures = Vec::new();
    code.asm()
        .alu_imm32(Alu::Sub, Size::Qword, Rsp, scratch.bytes as i32);
    memory::begin(code);
    if let Some(failure) = transfer::check_sp(code, operand.address.base, pc) {
        failures.push(failure);
    }
    transfer::address(code, operand.address, length);
    let mut asm = code.asm();
    asm.mov_store(Size::Qword, stack(scratch.address), Rax);
    asm.mov_rm_imm32(Size::Qword, stack(scratch.lane), 0);
    Host::Xor.register(code, ZERO_XMM, ZERO_XMM, target);
    for offset in (0..scratch.data_bytes).step_by(VECTOR_CHUNK_BYTES) {
        stack_vector(code, Host::StoreUnaligned, offset, target);
    }
    // Each packed-P chunk governs up to64 vector bytes. The loop only retains
    // values in private stack slots because a C callback may clobber all XMMs
    // and caller-saved GPRs. Tuple callbacks retain element-major read order.
    let predicate_chunks = length.bytes().div_ceil(PREDICATE_CHUNK_BITS);
    for chunk in 0..predicate_chunks {
        scalable::read_predicate_chunk(code, operand.predicate, chunk, length);
        code.asm()
            .mov_store(Size::Qword, stack(scratch.predicate), Rax);
        let start = code.len();
        let mut asm = code.asm();
        asm.test_imm(
            Size::Byte,
            stack(scratch.predicate),
            i32::from(PREDICATE_SELECTED),
        );
        let inactive = asm.jcc(Cond::E);
        for tuple_index in 0..operand.registers {
            code.asm()
                .mov_load(Size::Qword, Rax, stack(scratch.address));
            memory::request(
                code,
                scratch.request,
                u32::from(tuple_index) * length.bytes() as u32,
                width,
                access_flags,
                pc,
            );
            let mut asm = code.asm();
            asm.mov_load(Size::Qword, R8, stack(scratch.lane));
            asm.alu(
                Alu::Add,
                Size::Qword,
                stack(scratch.request + MEMORY_REQUEST_DATA_OFFSET),
                R8,
            );
            memory::call(code, scratch.request);
            failures.push(memory::branch_failed(code));
            code.asm()
                .alu_imm32(Alu::Add, Size::Qword, stack(scratch.address), width as i32);
        }
        let mut asm = code.asm();
        let active_done = asm.jmp();
        asm.bind(inactive);
        asm.alu_imm32(
            Alu::Add,
            Size::Qword,
            stack(scratch.address),
            (u32::from(operand.registers) * width) as i32,
        );
        asm.bind(active_done);
        asm.shift_imm(
            ShiftOp::Shr,
            Size::Qword,
            stack(scratch.predicate),
            width as u8,
        );
        asm.alu_imm32(Alu::Add, Size::Qword, stack(scratch.lane), width as i32);
        let end = ((chunk + 1) * PREDICATE_CHUNK_BITS).min(length.bytes()) as u32;
        asm.alu_imm32(Alu::Cmp, Size::Qword, stack(scratch.lane), end as i32);
        let repeat = asm.jcc(Cond::B);
        resolve(code, repeat, start);
    }
    // Architectural Z writes begin only after all callbacks have succeeded.
    for tuple_index in 0..operand.registers {
        for chunk in 0..length.chunks() {
            let offset = usize::from(tuple_index) * length.bytes() + chunk * VECTOR_CHUNK_BYTES;
            stack_vector(code, Host::LoadUnaligned, offset as u32, target);
            scalable::store_z_chunk(
                code,
                operand.destination_register(tuple_index),
                chunk,
                ZERO_XMM,
                length,
                target,
            );
        }
    }
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    let cleanup = code.len();
    for failure in failures {
        crate::x86_64::asm::resolve(code, failure, cleanup);
    }
    code.asm()
        .alu_imm32(Alu::Add, Size::Qword, Rsp, scratch.bytes as i32);
    transfer::return_if_failed(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{scalable::ElementSize, sve::memory_structure};

    const LENGTHS: [usize; 5] = [16, 32, 64, 128, 256];
    const TEST_PC: u64 = 0x1_4000_1000;
    const MAX_REFERENCE_BODY_BYTES: usize = 8 * 1024;
    const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
    const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
    const CALL_MEMORY_CALLBACK: &[u8] = &[
        0xff,
        0x57,
        crate::context::memory::MEMORY_CALLBACK_OFFSET as u8,
    ];

    #[test]
    fn requirements_bind_predication_tags_and_wide_read_capability() {
        const WIDTH_CLASSES: [(u32, ElementSize, bool); 10] = [
            (0xa420_e000, ElementSize::Byte, true),
            (0xa420_c000, ElementSize::Byte, false),
            (0xa4a0_e000, ElementSize::Halfword, true),
            (0xa4a0_c000, ElementSize::Halfword, false),
            (0xa520_e000, ElementSize::Word, true),
            (0xa520_c000, ElementSize::Word, false),
            (0xa5a0_e000, ElementSize::Doubleword, true),
            (0xa5a0_c000, ElementSize::Doubleword, false),
            (0xa490_e000, ElementSize::Quadword, true),
            (0xa4a0_8000, ElementSize::Quadword, false),
        ];
        const SP_ENCODING: u32 = 31 << 5;
        for (class, element, immediate) in WIDTH_CLASSES {
            for base in [0, SP_ENCODING] {
                let operand = memory_structure::decode(class | base).unwrap().unwrap();
                let required = requirements(operand);
                assert_eq!(
                    required.required_sp_alignment,
                    if base == SP_ENCODING {
                        SpAlignmentRequirement::Enabled
                    } else {
                        SpAlignmentRequirement::Any
                    }
                );
                let tag_checked = !immediate || base != SP_ENCODING;
                assert_eq!(
                    required.required_flags,
                    flags::SVE_PREDICATED | if tag_checked { flags::TAG_CHECKED } else { 0 }
                );
                let wide_read = element == ElementSize::Quadword
                    || (element != ElementSize::Byte && base != SP_ENCODING);
                assert_eq!(
                    required.required_host_caps,
                    if wide_read {
                        host_caps::ATOMIC_LOAD16
                    } else {
                        0
                    }
                );
                assert_eq!(
                    required.required_profile,
                    profile_requirements::NATIVE_ACCESS
                        | if tag_checked {
                            profile_requirements::TAG_GRANULES
                                | profile_requirements::SCALABLE_TAG_CHECKS
                        } else {
                            0
                        }
                );
            }
        }
    }

    #[test]
    fn private_staging_and_requests_are_disjoint_and_stack_aligned() {
        for bytes in LENGTHS {
            let length = VectorLength::from_bytes(bytes).unwrap();
            for registers in 2..=4 {
                let scratch = Scratch::new(registers, length);
                assert_eq!(scratch.bytes % STACK_ALIGNMENT, 0);
                assert_eq!(scratch.address, u32::from(registers) * bytes as u32);
                assert!(scratch.predicate + POINTER_BYTES <= scratch.request);
                assert_eq!(scratch.request + MEMORY_REQUEST_BYTES as u32, scratch.bytes);
            }
        }
    }

    #[test]
    fn callback_body_grows_with_predicate_chunks_instead_of_each_byte_lane() {
        let operand = memory_structure::decode(0xa460_e000).unwrap().unwrap();
        assert_eq!(operand.element, ElementSize::Byte);
        for bytes in LENGTHS {
            let length = VectorLength::from_bytes(bytes).unwrap();
            let mut code = Code::new();
            emit(&mut code, &operand, length, TargetCpu::Baseline, TEST_PC);
            let calls = code
                .windows(CALL_MEMORY_CALLBACK.len())
                .filter(|window| *window == CALL_MEMORY_CALLBACK)
                .count();
            assert_eq!(
                calls,
                usize::from(operand.registers) * bytes.div_ceil(PREDICATE_CHUNK_BITS)
            );
            assert!(code.len() < MAX_REFERENCE_BODY_BYTES);
            assert!(code.starts_with(SUB_RSP_IMM32));
            let cleanup = code
                .windows(ADD_RSP_IMM32.len())
                .rposition(|bytes| bytes == ADD_RSP_IMM32)
                .unwrap();
            let immediate = cleanup + ADD_RSP_IMM32.len();
            assert_eq!(
                &code[immediate..immediate + size_of::<u32>()],
                &Scratch::new(operand.registers, length).bytes.to_le_bytes()
            );
        }
    }
}
