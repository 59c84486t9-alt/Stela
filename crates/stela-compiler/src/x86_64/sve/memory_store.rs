//! SVE stores through the memory service, one element per request in ascending
//! order. Sources and loop state live on the stack across calls.
use super::memory as shared_address;
use crate::x86_64::asm::BitTest;
use crate::x86_64::asm::Gpr::{R8, Rax, Rcx, Rsp};
use crate::x86_64::asm::{Alu, Code, Cond, Disp, Mem, Patch, Size, resolve};
use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{VECTOR_CHUNK_BYTES, VectorLength},
        sve::{
            memory::{Address, Offset},
            memory_store::{Operand, Store, WholeStore, WholeTarget},
        },
    },
    context::memory::{
        MEMORY_REQUEST_BYTES, MEMORY_REQUEST_DATA_OFFSET, MemoryRequirements,
        SpAlignmentRequirement, flags, host_caps, profile_requirements,
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{load_z_chunk, memory, read_predicate_chunk},
    },
};
use alloc::vec::Vec;

const REQUEST_OFFSET: u32 = 0;
const ADDRESS_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const INDEX_OFFSET: u32 = ADDRESS_OFFSET + size_of::<u64>() as u32;
const PREDICATE_OFFSET: u32 = INDEX_OFFSET + size_of::<u64>() as u32;
const STACK_ALIGNMENT_BYTES: u32 = 16;
const HOST_QWORD_BYTES: usize = size_of::<u64>();
const SOURCE_XMM: u8 = 0;
const _: () = assert!(INDEX_OFFSET <= i8::MAX as u32);
const _: () = assert!(REQUEST_OFFSET + MEMORY_REQUEST_DATA_OFFSET <= i8::MAX as u32);

struct Layout {
    source: u32,
    bytes: u32,
}

impl Layout {
    fn new(length: VectorLength, source_bytes: usize) -> Self {
        let source = align(PREDICATE_OFFSET + length.predicate_bytes() as u32);
        Self {
            source,
            bytes: align(source + source_bytes as u32),
        }
    }
}

fn align(bytes: u32) -> u32 {
    bytes.div_ceil(STACK_ALIGNMENT_BYTES) * STACK_ALIGNMENT_BYTES
}

fn stack(offset: u32) -> Mem {
    Mem::base_disp32(Rsp, offset as i32)
}

fn store_stack_chunk(code: &mut Code, offset: u32, target: TargetCpu) {
    code.asm()
        .simd(Host::StoreUnaligned, SOURCE_XMM, stack(offset), target);
}

fn stack_rax(code: &mut Code, offset: u32, store: bool) {
    let mut asm = code.asm();
    if store {
        asm.mov_store(Size::Qword, stack(offset), Rax);
    } else {
        asm.mov_load(Size::Qword, Rax, stack(offset));
    }
}

fn set_index(code: &mut Code) {
    code.asm().mov_rm_imm32(Size::Qword, stack(INDEX_OFFSET), 0);
}

fn load_index(code: &mut Code) {
    code.asm()
        .mov_load(Size::Dword, Rcx, Mem::base_disp8(Rsp, INDEX_OFFSET as i8));
}

fn add_stack(code: &mut Code, offset: u32, bytes: u8) {
    debug_assert!(bytes <= i8::MAX as u8);
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, stack(offset), bytes as i8);
}

fn copy_sources(
    code: &mut Code,
    source: u8,
    count: u8,
    layout: &Layout,
    length: VectorLength,
    target: TargetCpu,
) {
    for member in 0..count {
        let register =
            source.wrapping_add(member) % crate::aarch64::scalable::VECTOR_REGISTER_COUNT;
        for chunk in 0..length.chunks() {
            load_z_chunk(code, register, chunk, SOURCE_XMM, length, target);
            let offset = layout.source
                + (usize::from(member) * length.bytes() + chunk * VECTOR_CHUNK_BYTES) as u32;
            store_stack_chunk(code, offset, target);
        }
    }
}

fn copy_predicate(code: &mut Code, predicate: u8, destination: u32, length: VectorLength) {
    for chunk in 0..length.predicate_bytes().div_ceil(HOST_QWORD_BYTES) {
        read_predicate_chunk(code, predicate, chunk, length);
        stack_rax(code, destination + (chunk * HOST_QWORD_BYTES) as u32, true);
    }
}

/// Snapshot P and branch around all source staging when no element is active.
fn copy_active_predicate(code: &mut Code, store: &Store, length: VectorLength) -> Patch {
    let mask = (0..u64::BITS as usize)
        .step_by(store.element.bytes())
        .fold(0_u64, |bits, bit| bits | (1_u64 << bit));
    code.asm().alu(Alu::Xor, Size::Dword, R8, R8);
    for chunk in 0..length.predicate_bytes().div_ceil(HOST_QWORD_BYTES) {
        read_predicate_chunk(code, store.predicate, chunk, length);
        stack_rax(
            code,
            PREDICATE_OFFSET + (chunk * HOST_QWORD_BYTES) as u32,
            true,
        );
        if mask != u64::MAX {
            let mut asm = code.asm();
            asm.mov_imm64(Rcx, mask);
            asm.alu(Alu::And, Size::Qword, Rax, Rcx);
        }
        code.asm().alu(Alu::Or, Size::Qword, R8, Rax);
    }
    let mut asm = code.asm();
    asm.test(Size::Qword, R8, R8);
    asm.jcc(Cond::E)
}

fn submit(
    code: &mut Code,
    source: u32,
    bytes: u32,
    descriptor: u32,
    pc: u64,
    failures: &mut Vec<usize>,
) {
    stack_rax(code, ADDRESS_OFFSET, false);
    memory::request(code, REQUEST_OFFSET, source, bytes, descriptor, pc);
    // request() clobbers RCX. Reload the saved byte index only afterward and
    // point at the reached element in the immutable private source snapshot.
    // The request width selects its exact low bytes, including narrowing stores.
    load_index(code);
    let width = if source <= i8::MAX as u32 {
        Disp::Byte
    } else {
        Disp::Dword
    };
    let mut asm = code.asm();
    asm.lea(
        Size::Qword,
        Rax,
        Mem::indexed(Rsp, Rcx, 1, source as i32).with_width(width),
    );
    asm.mov_store(
        Size::Qword,
        Mem::base_disp8(Rsp, (REQUEST_OFFSET + MEMORY_REQUEST_DATA_OFFSET) as i8),
        Rax,
    );
    memory::call(code, REQUEST_OFFSET);
    failures.push(memory::branch_failed(code));
}

fn loop_end(code: &mut Code, step: u8, limit: u32, start: usize) {
    add_stack(code, INDEX_OFFSET, step);
    let mut asm = code.asm();
    asm.alu_imm32(Alu::Cmp, Size::Qword, stack(INDEX_OFFSET), limit as i32);
    let repeat = asm.jcc(Cond::B);
    resolve(code, repeat, start);
}

fn store_loop(
    code: &mut Code,
    store: &Store,
    layout: &Layout,
    length: VectorLength,
    pc: u64,
    failures: &mut Vec<usize>,
) {
    let start = code.len();
    load_index(code);
    let mut asm = code.asm();
    asm.bit(BitTest::Bt, Size::Qword, stack(PREDICATE_OFFSET), Rcx);
    let inactive = asm.jcc(Cond::Ae);
    let descriptor = descriptor(store.address, store.non_temporal, true);
    for member in 0..store.register_count {
        let source = layout.source + u32::from(member) * length.bytes() as u32;
        submit(
            code,
            source,
            store.memory_element.bytes() as u32,
            descriptor,
            pc,
            failures,
        );
        add_stack(code, ADDRESS_OFFSET, store.memory_element.bytes() as u8);
    }
    let mut asm = code.asm();
    let active_done = asm.jmp();
    asm.bind(inactive);
    add_stack(
        code,
        ADDRESS_OFFSET,
        store.memory_element.bytes() as u8 * store.register_count,
    );
    code.asm().bind(active_done);
    loop_end(
        code,
        store.element.bytes() as u8,
        length.bytes() as u32,
        start,
    );
}

fn whole_loop(
    code: &mut Code,
    store: &WholeStore,
    layout: &Layout,
    bytes: usize,
    pc: u64,
    failures: &mut Vec<usize>,
) {
    let start = code.len();
    submit(
        code,
        layout.source,
        1,
        descriptor(store.address, false, false),
        pc,
        failures,
    );
    add_stack(code, ADDRESS_OFFSET, 1);
    loop_end(code, 1, bytes as u32, start);
}

fn descriptor(address: Address, non_temporal: bool, predicated: bool) -> u32 {
    let tag_checked =
        address.base != Register::Sp || matches!(address.offset, Offset::Register { .. });
    flags::WRITE
        | if tag_checked { flags::TAG_CHECKED } else { 0 }
        | if non_temporal { flags::NON_TEMPORAL } else { 0 }
        | if predicated { flags::SVE_PREDICATED } else { 0 }
}

/// Requirements for the complete consumed body, checked before guest effects.
/// Q stores can reach one aligned16-byte part and therefore preflight CX16 even
/// when a particular invocation later selects empty predicates or split parts.
/// Narrow stores use scalar XCHG parts and require no 16-byte host capability.
/// Whole-register stores submit byte requests; ignored prefetch submits none.
pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    let (required_flags, required_host_caps) = match operand {
        Operand::Store(store) => (
            descriptor(store.address, store.non_temporal, true),
            if store.memory_element.bytes() == VECTOR_CHUNK_BYTES {
                host_caps::CX16
            } else {
                0
            },
        ),
        Operand::Whole(store) => (descriptor(store.address, false, false), 0),
        Operand::Prefetch(_) => return MemoryRequirements::default(),
    };
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_flags,
        required_host_caps,
        required_profile: profile_requirements::NATIVE_ACCESS
            | if required_flags & flags::TAG_CHECKED != 0 {
                profile_requirements::TAG_GRANULES | profile_requirements::SCALABLE_TAG_CHECKS
            } else {
                0
            },
        required_sp_alignment: match operand {
            Operand::Store(store) if store.address.base == Register::Sp => {
                SpAlignmentRequirement::Enabled
            }
            Operand::Whole(store) if store.address.base == Register::Sp => {
                SpAlignmentRequirement::Enabled
            }
            _ => SpAlignmentRequirement::Any,
        },
        ..MemoryRequirements::default()
    }
}

/// Returns the MemoryStatus in EAX with the private stack released; the caller
/// exits on nonzero. Alignment is not enforced, but the 16-byte SP check runs
/// before any offset, even with an empty predicate.
pub(crate) fn emit(
    code: &mut Code,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) {
    let (address, source_bytes) = match operand {
        Operand::Prefetch(_) => {
            // Hint_Prefetch has a documented implementation-defined ignored
            // behavior. The shared dispatcher already checked the mode.
            code.asm().alu(Alu::Xor, Size::Dword, Rax, Rax);
            return;
        }
        Operand::Store(store) => (
            store.address,
            usize::from(store.register_count) * length.bytes(),
        ),
        Operand::Whole(store) => (
            store.address,
            match store.target {
                WholeTarget::Vector(_) => length.bytes(),
                WholeTarget::Predicate(_) => length.predicate_bytes(),
            },
        ),
    };
    let layout = Layout::new(length, source_bytes);
    code.asm()
        .alu_imm32(Alu::Sub, Size::Qword, Rsp, layout.bytes as i32);
    memory::begin(code);
    let mut failures = Vec::new();
    if let Some(failure) = shared_address::check_sp(code, address.base, pc) {
        failures.push(failure);
    }
    shared_address::address(code, address, length);
    stack_rax(code, ADDRESS_OFFSET, true);
    set_index(code);
    let empty = match operand {
        Operand::Store(store) => {
            let empty = copy_active_predicate(code, store, length);
            copy_sources(
                code,
                store.source,
                store.register_count,
                &layout,
                length,
                target,
            );
            store_loop(code, store, &layout, length, pc, &mut failures);
            Some(empty)
        }
        Operand::Whole(store) => {
            match store.target {
                WholeTarget::Vector(source) => {
                    copy_sources(code, source, 1, &layout, length, target);
                }
                WholeTarget::Predicate(source) => {
                    copy_predicate(code, source, layout.source, length);
                }
            }
            whole_loop(code, store, &layout, source_bytes, pc, &mut failures);
            None
        }
        Operand::Prefetch(_) => unreachable!("prefetch returned before stack allocation"),
    };
    let mut asm = code.asm();
    if let Some(empty) = empty {
        asm.bind(empty);
    }
    asm.alu(Alu::Xor, Size::Dword, Rax, Rax);
    let cleanup = code.len();
    for failure in failures {
        memory::patch_branch(code, failure, cleanup);
    }
    code.asm()
        .alu_imm32(Alu::Add, Size::Qword, Rsp, layout.bytes as i32);
    shared_address::return_if_failed(code);
}
