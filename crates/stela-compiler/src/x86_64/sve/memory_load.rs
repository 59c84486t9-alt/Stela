//! SVE loads through the memory service into a private staging buffer, so a
//! fault leaves the destination unchanged.
use super::super::{isa::SimdOpcode as Host, scalable};
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::Gpr::{Rax, Rcx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Mem, Patch, Rm, Size};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{ElementSize, VECTOR_CHUNK_BYTES, VectorLength},
        sve::{
            memory::Extension,
            memory_load::{Kind, Operand},
        },
    },
    context::memory::{
        MEMORY_REQUEST_BYTES, MemoryRequirements, SpAlignmentRequirement, flags, host_caps,
        profile_requirements,
    },
};
use alloc::vec::Vec;

const STACK_ALIGNMENT: u32 = 16;
const QWORD_BYTES: u32 = size_of::<u64>() as u32;
const PREDICATE_WORD_BITS: usize = u64::BITS as usize;
const REPEAT_LOW_DWORD: u8 = 0;

#[derive(Clone, Copy)]
struct Scratch {
    predicate: u32,
    address: u32,
    scalar: u32,
    request: u32,
    bytes: u32,
}

impl Scratch {
    fn new(length: VectorLength) -> Self {
        let predicate = length.bytes() as u32;
        let predicate_bytes =
            (length.predicate_bytes() as u32).div_ceil(STACK_ALIGNMENT) * STACK_ALIGNMENT;
        let address = predicate + predicate_bytes;
        let scalar = address + QWORD_BYTES;
        let request = scalar + QWORD_BYTES;
        Self {
            predicate,
            address,
            scalar,
            request,
            bytes: request + MEMORY_REQUEST_BYTES as u32,
        }
    }
}

fn stack(offset: u32) -> Mem {
    Mem::base_disp32(Rsp, offset as i32)
}

fn add_immediate(code: &mut Code, value: i32) {
    if value != 0 {
        code.asm()
            .alu_accumulator_imm32(Alu::Add, Size::Qword, value);
    }
}

fn predicate(code: &mut Code, operand: Operand, length: VectorLength, scratch: Scratch) {
    if let Some(predicate) = operand.predicate {
        for word in 0..length.predicate_bytes().div_ceil(QWORD_BYTES as usize) {
            scalable::read_predicate_chunk(code, predicate, word, length);
            code.asm().mov_store(
                Size::Qword,
                stack(scratch.predicate + word as u32 * QWORD_BYTES),
                Rax,
            );
        }
    }
}

fn inactive_branch(code: &mut Code, bit: usize, scratch: Scratch) -> Patch {
    let word = bit / PREDICATE_WORD_BITS;
    let mut asm = code.asm();
    asm.mov_load(
        Size::Qword,
        Rax,
        stack(scratch.predicate + word as u32 * QWORD_BYTES),
    );
    asm.bit_imm(
        BitTest::Bt,
        Size::Qword,
        Rax,
        (bit % PREDICATE_WORD_BITS) as u8,
    );
    asm.jcc(Cond::Ae)
}

fn access_flags(operand: Operand) -> u32 {
    (if operand.tag_checked {
        flags::TAG_CHECKED
    } else {
        0
    }) | (if operand.non_temporal {
        flags::NON_TEMPORAL
    } else {
        0
    }) | (if operand.predicate.is_some() {
        flags::SVE_PREDICATED
    } else {
        0
    })
}

/// Requirements for the complete consumed artifact, validated before entry.
/// Original SP16 plus encoded element-scaled offsets makes SP-base elements
/// naturally aligned; unconstrained multibyte GPR-base reads may cross8 inside16.
pub(crate) fn requirements(operand: Operand) -> MemoryRequirements {
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_sp_alignment: if operand.address.base == Register::Sp {
            SpAlignmentRequirement::Enabled
        } else {
            SpAlignmentRequirement::Any
        },
        required_flags: access_flags(operand),
        required_host_caps: if operand.memory_element != ElementSize::Byte
            && operand.address.base != Register::Sp
        {
            host_caps::ATOMIC_LOAD16
        } else {
            0
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if operand.tag_checked {
                profile_requirements::TAG_GRANULES | profile_requirements::SCALABLE_TAG_CHECKS
            } else {
                0
            },
        ..MemoryRequirements::default()
    }
}

fn request(
    code: &mut Code,
    operand: Operand,
    scratch: Scratch,
    source_offset: usize,
    destination_offset: u32,
    pc: u64,
    failed: &mut Vec<Patch>,
) {
    code.asm()
        .mov_load(Size::Qword, Rax, stack(scratch.address));
    add_immediate(code, source_offset as i32);
    scalable::memory::request(
        code,
        scratch.request,
        destination_offset,
        operand.memory_element.bytes() as u32,
        access_flags(operand),
        pc,
    );
    scalable::memory::call(code, scratch.request);
    failed.push(scalable::memory::branch_failed(code));
}

fn read_value(code: &mut Code, source: u32, element: ElementSize, extension: Extension) {
    let source = stack(source);
    let mut asm = code.asm();
    match (element, extension) {
        (ElementSize::Byte, Extension::Zero) => asm.movzx(Size::Dword, Rax, Size::Byte, source),
        (ElementSize::Halfword, Extension::Zero) => asm.movzx(Size::Dword, Rax, Size::Word, source),
        (ElementSize::Word, Extension::Zero) => asm.mov_load(Size::Dword, Rax, source),
        (ElementSize::Byte, Extension::Sign) => asm.movsx(Size::Qword, Rax, Size::Byte, source),
        (ElementSize::Halfword, Extension::Sign) => asm.movsx(Size::Qword, Rax, Size::Word, source),
        (ElementSize::Word, Extension::Sign) => asm.movsxd(Rax, source),
        (ElementSize::Doubleword, _) => asm.mov_load(Size::Qword, Rax, source),
        (ElementSize::Quadword, _) => unreachable!("SVE load scalar element is at most64 bits"),
    }
}

fn write_value(code: &mut Code, destination: u32, element: ElementSize) {
    let size = match element {
        ElementSize::Byte => Size::Byte,
        ElementSize::Halfword => Size::Word,
        ElementSize::Word => Size::Dword,
        ElementSize::Doubleword => Size::Qword,
        ElementSize::Quadword => unreachable!("SVE load scalar element is at most64 bits"),
    };
    code.asm().mov_store(size, stack(destination), Rax);
}

fn lanes(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    scratch: Scratch,
    pc: u64,
    failed: &mut Vec<Patch>,
) {
    let bytes = if operand.kind == Kind::ReplicateQuad {
        VECTOR_CHUNK_BYTES
    } else {
        length.bytes()
    };
    for lane in 0..bytes / operand.element.bytes() {
        let destination = (lane * operand.element.bytes()) as u32;
        let inactive = inactive_branch(code, lane * operand.element.bytes(), scratch);
        request(
            code,
            operand,
            scratch,
            lane * operand.memory_element.bytes(),
            destination,
            pc,
            failed,
        );
        if operand.extension == Extension::Sign {
            read_value(code, destination, operand.memory_element, operand.extension);
            write_value(code, destination, operand.element);
        }
        code.asm().bind(inactive);
    }
}

fn scalar_replicate(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    scratch: Scratch,
    pc: u64,
    failed: &mut Vec<Patch>,
    target: TargetCpu,
) {
    let mut active = Vec::new();
    for word in 0..length.predicate_bytes().div_ceil(QWORD_BYTES as usize) {
        code.asm().mov_load(
            Size::Qword,
            Rax,
            stack(scratch.predicate + word as u32 * QWORD_BYTES),
        );
        let first_bit = word * PREDICATE_WORD_BITS;
        let valid_bits = (length.bytes() - first_bit).min(PREDICATE_WORD_BITS);
        let mask = (0..valid_bits)
            .step_by(operand.element.bytes())
            .fold(0_u64, |mask, bit| mask | 1_u64 << bit);
        if mask != u64::MAX {
            let mut asm = code.asm();
            asm.mov_imm64(Rcx, mask);
            asm.alu(Alu::And, Size::Qword, Rax, Rcx);
        }
        let mut asm = code.asm();
        asm.test(Size::Qword, Rax, Rax);
        active.push(asm.jcc(Cond::Ne));
    }
    let mut asm = code.asm();
    let empty = asm.jmp();
    for active in active {
        asm.bind(active);
    }
    request(code, operand, scratch, 0, scratch.scalar, pc, failed);
    read_value(
        code,
        scratch.scalar,
        operand.memory_element,
        operand.extension,
    );
    code.asm().simd(Host::MoveGprQword, 0, Rax, target);
    match operand.element {
        ElementSize::Byte => {
            Host::UnpackLowByte.register(code, 0, 0, target);
            Host::UnpackLowWord.register(code, 0, 0, target);
            code.asm()
                .simd_imm(Host::ShuffleDword, 0, Rm::Xmm(0), REPEAT_LOW_DWORD, target);
        }
        ElementSize::Halfword => {
            Host::UnpackLowWord.register(code, 0, 0, target);
            code.asm()
                .simd_imm(Host::ShuffleDword, 0, Rm::Xmm(0), REPEAT_LOW_DWORD, target);
        }
        ElementSize::Word => {
            code.asm()
                .simd_imm(Host::ShuffleDword, 0, Rm::Xmm(0), REPEAT_LOW_DWORD, target);
        }
        ElementSize::Doubleword => Host::UnpackLowQword.register(code, 0, 0, target),
        ElementSize::Quadword => unreachable!("scalar replicate element is at most64 bits"),
    }
    for chunk in 0..length.chunks() {
        scalable::read_predicate_mask(
            code,
            operand.predicate.expect("replicate is predicated"),
            chunk,
            operand.element,
            crate::x86_64::scalable::MaskRegisters::new(1, 2),
            length,
            target,
        );
        Host::MoveAligned.register(code, 3, 0, target);
        Host::And.register(code, 3, 1, target);
        code.asm()
            .movdqu_store(stack((chunk * VECTOR_CHUNK_BYTES) as u32), 3);
    }
    code.asm().bind(empty);
}

fn commit(code: &mut Code, operand: Operand, length: VectorLength, target: TargetCpu) {
    if operand.kind == Kind::WholePredicate {
        for word in 0..length.predicate_bytes().div_ceil(QWORD_BYTES as usize) {
            code.asm()
                .mov_load(Size::Qword, Rax, stack(word as u32 * QWORD_BYTES));
            scalable::write_predicate_chunk(code, operand.data, word, length);
        }
    } else {
        if operand.kind == Kind::ReplicateQuad {
            code.asm().movdqu_load(0, stack(0));
        }
        for chunk in 0..length.chunks() {
            if operand.kind != Kind::ReplicateQuad {
                code.asm()
                    .movdqu_load(0, stack((chunk * VECTOR_CHUNK_BYTES) as u32));
            }
            scalable::store_z_chunk(code, operand.data, chunk, 0, length, target);
        }
    }
}

/// Emit one instruction backed by memory-service callbacks. Failure cleans up
/// and returns through the shared epilogue; success falls through. Both restore
/// the private stack allocation. SCTLR.A is 0; SP alignment is still checked.
pub(crate) fn emit(
    code: &mut Code,
    operand: Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) {
    let scratch = Scratch::new(length);
    code.asm()
        .alu_imm32(Alu::Sub, Size::Qword, Rsp, scratch.bytes as i32);
    scalable::memory::begin(code);
    let zero_chunks = match operand.kind {
        Kind::WholeVector | Kind::WholePredicate => 0,
        Kind::ReplicateQuad => 1,
        Kind::Contiguous | Kind::ReplicateScalar => length.chunks(),
    };
    let mut asm = code.asm();
    if zero_chunks != 0 {
        asm.simd(Host::Xor, 0, Rm::Xmm(0), TargetCpu::Baseline);
    }
    for chunk in 0..zero_chunks {
        asm.movdqu_store(stack((chunk * VECTOR_CHUNK_BYTES) as u32), 0);
    }
    predicate(code, operand, length, scratch);
    let mut failed = Vec::new();
    if let Some(fault) = super::memory::check_sp(code, operand.address.base, pc) {
        failed.push(fault);
    }
    super::memory::address(code, operand.address, length);
    code.asm()
        .mov_store(Size::Qword, stack(scratch.address), Rax);
    match operand.kind {
        Kind::Contiguous | Kind::ReplicateQuad => {
            lanes(code, operand, length, scratch, pc, &mut failed)
        }
        Kind::ReplicateScalar => {
            scalar_replicate(code, operand, length, scratch, pc, &mut failed, target)
        }
        Kind::WholeVector | Kind::WholePredicate => {
            let bytes = if operand.kind == Kind::WholePredicate {
                length.predicate_bytes()
            } else {
                length.bytes()
            };
            for byte in 0..bytes {
                request(code, operand, scratch, byte, byte as u32, pc, &mut failed);
            }
        }
    }
    commit(code, operand, length, target);
    code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
    let cleanup = code.len();
    for failed in failed {
        crate::x86_64::asm::resolve(code, failed, cleanup);
    }
    code.asm()
        .alu_imm32(Alu::Add, Size::Qword, Rsp, scratch.bytes as i32);
    super::memory::return_if_failed(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::sve::memory_load;

    const LD1B_Z1_P0_X5: u32 = 0xa400_a0a1;
    const LD1D_Z1_P0_X5: u32 = 0xa5e0_a0a1;
    const LD1D_Z1_P0_SP: u32 = 0xa5e0_a3e1;

    fn decoded(word: u32) -> Operand {
        memory_load::decode(word).unwrap().unwrap()
    }

    #[test]
    fn preflight_distinguishes_checked_bytes_generic_reads_and_aligned_sp() {
        let checked = flags::TAG_CHECKED | flags::SVE_PREDICATED;
        let checked_profile = profile_requirements::NATIVE_ACCESS
            | profile_requirements::TAG_GRANULES
            | profile_requirements::SCALABLE_TAG_CHECKS;
        assert_eq!(
            requirements(decoded(LD1B_Z1_P0_X5)),
            MemoryRequirements {
                required_pointer_arithmetic: None,
                required_address_checks: Default::default(),
                required_sp_alignment: SpAlignmentRequirement::Any,
                required_flags: checked,
                required_host_caps: 0,
                required_profile: checked_profile,
                ..MemoryRequirements::default()
            }
        );
        assert_eq!(
            requirements(decoded(LD1D_Z1_P0_X5)),
            MemoryRequirements {
                required_pointer_arithmetic: None,
                required_address_checks: Default::default(),
                required_sp_alignment: SpAlignmentRequirement::Any,
                required_flags: checked,
                required_host_caps: host_caps::ATOMIC_LOAD16,
                required_profile: checked_profile,
                ..MemoryRequirements::default()
            }
        );
        assert_eq!(
            requirements(decoded(LD1D_Z1_P0_SP)),
            MemoryRequirements {
                required_pointer_arithmetic: None,
                required_address_checks: Default::default(),
                required_sp_alignment: SpAlignmentRequirement::Enabled,
                required_flags: flags::SVE_PREDICATED,
                required_host_caps: 0,
                required_profile: profile_requirements::NATIVE_ACCESS,
                ..MemoryRequirements::default()
            }
        );
    }
}
