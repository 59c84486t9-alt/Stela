//! Context-memory callback candidate for exact scalable store prefixes.
//!
//! Sources and loop state live in private stack storage across callback calls.
//! One request describes one reached Mem element; the runtime owns its exact
//! single-copy decomposition and physical writer participation. Whole-register
//! stores retain their specified ascending byte requests.
use super::memory as shared_address;
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

const REQUEST_OFFSET: u32 = 0;
const ADDRESS_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const INDEX_OFFSET: u32 = ADDRESS_OFFSET + size_of::<u64>() as u32;
const PREDICATE_OFFSET: u32 = INDEX_OFFSET + size_of::<u64>() as u32;
const STACK_ALIGNMENT_BYTES: u32 = 16;
const HOST_QWORD_BYTES: usize = size_of::<u64>();
const SOURCE_XMM: u8 = 0;
const X86_MODRM_DISP32: u8 = 0x84;
const X86_SIB_RSP: u8 = 0x24;
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const MOV_RSP_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const MOV_RAX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const MOV_ECX_RSP_DISP8: &[u8] = &[0x8b, 0x4c, 0x24];
const MOV_RSP_DISP32_IMM32_QWORD: &[u8] = &[0x48, 0xc7, 0x84, 0x24];
const ADD_RSP_DISP32_IMM8: &[u8] = &[0x48, 0x83, 0x84, 0x24];
const LEA_RAX_RSP_RCX_DISP8: &[u8] = &[0x48, 0x8d, 0x44, 0x0c];
const LEA_RAX_RSP_RCX_DISP32: &[u8] = &[0x48, 0x8d, 0x84, 0x0c];
const MOV_RSP_DISP8_RAX: &[u8] = &[0x48, 0x89, 0x44, 0x24];
const _: () = assert!(INDEX_OFFSET <= i8::MAX as u32);
const _: () = assert!(REQUEST_OFFSET + MEMORY_REQUEST_DATA_OFFSET <= i8::MAX as u32);
const CMP_RSP_DISP32_IMM32: &[u8] = &[0x48, 0x81, 0xbc, 0x24];
const BT_RSP_DISP32_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0x8c, 0x24];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const XOR_R8D_R8D: &[u8] = &[0x45, 0x31, 0xc0];
const MOVABS_RCX_IMM64: &[u8] = &[0x48, 0xb9];
const AND_RAX_RCX: &[u8] = &[0x48, 0x21, 0xc8];
const OR_R8_RAX: &[u8] = &[0x49, 0x09, 0xc0];
const TEST_R8_R8: &[u8] = &[0x4d, 0x85, 0xc0];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JMP_REL32: &[u8] = &[0xe9];
const JNC_REL32: &[u8] = &[0x0f, 0x83];
const JB_REL32: &[u8] = &[0x0f, 0x82];

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

fn store_stack_chunk(code: &mut Vec<u8>, offset: u32, target: TargetCpu) {
    Host::StoreUnaligned.append(code, target);
    code.extend([X86_MODRM_DISP32, X86_SIB_RSP]);
    code.extend(offset.to_le_bytes());
}

fn stack_rax(code: &mut Vec<u8>, offset: u32, store: bool) {
    code.extend(if store {
        MOV_RSP_DISP32_RAX
    } else {
        MOV_RAX_RSP_DISP32
    });
    code.extend(offset.to_le_bytes());
}

fn set_index(code: &mut Vec<u8>) {
    code.extend(MOV_RSP_DISP32_IMM32_QWORD);
    code.extend(INDEX_OFFSET.to_le_bytes());
    code.extend(0_u32.to_le_bytes());
}

fn load_index(code: &mut Vec<u8>) {
    code.extend(MOV_ECX_RSP_DISP8);
    code.push(INDEX_OFFSET as u8);
}

fn add_stack(code: &mut Vec<u8>, offset: u32, bytes: u8) {
    debug_assert!(bytes <= i8::MAX as u8);
    code.extend(ADD_RSP_DISP32_IMM8);
    code.extend(offset.to_le_bytes());
    code.push(bytes);
}

fn branch(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn copy_sources(
    code: &mut Vec<u8>,
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

fn copy_predicate(code: &mut Vec<u8>, predicate: u8, destination: u32, length: VectorLength) {
    for chunk in 0..length.predicate_bytes().div_ceil(HOST_QWORD_BYTES) {
        read_predicate_chunk(code, predicate, chunk, length);
        stack_rax(code, destination + (chunk * HOST_QWORD_BYTES) as u32, true);
    }
}

/// Snapshot P and branch around all source staging when no element is active.
fn copy_active_predicate(code: &mut Vec<u8>, store: &Store, length: VectorLength) -> usize {
    let mask = (0..u64::BITS as usize)
        .step_by(store.element.bytes())
        .fold(0_u64, |bits, bit| bits | (1_u64 << bit));
    code.extend(XOR_R8D_R8D);
    for chunk in 0..length.predicate_bytes().div_ceil(HOST_QWORD_BYTES) {
        read_predicate_chunk(code, store.predicate, chunk, length);
        stack_rax(
            code,
            PREDICATE_OFFSET + (chunk * HOST_QWORD_BYTES) as u32,
            true,
        );
        if mask != u64::MAX {
            code.extend(MOVABS_RCX_IMM64);
            code.extend(mask.to_le_bytes());
            code.extend(AND_RAX_RCX);
        }
        code.extend(OR_R8_RAX);
    }
    code.extend(TEST_R8_R8);
    branch(code, JZ_REL32)
}

fn submit(
    code: &mut Vec<u8>,
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
    if source <= i8::MAX as u32 {
        code.extend(LEA_RAX_RSP_RCX_DISP8);
        code.push(source as u8);
    } else {
        code.extend(LEA_RAX_RSP_RCX_DISP32);
        code.extend(source.to_le_bytes());
    }
    code.extend(MOV_RSP_DISP8_RAX);
    code.push((REQUEST_OFFSET + MEMORY_REQUEST_DATA_OFFSET) as u8);
    memory::call(code, REQUEST_OFFSET);
    failures.push(memory::branch_failed(code));
}

fn loop_end(code: &mut Vec<u8>, step: u8, limit: u32, start: usize) {
    add_stack(code, INDEX_OFFSET, step);
    code.extend(CMP_RSP_DISP32_IMM32);
    code.extend(INDEX_OFFSET.to_le_bytes());
    code.extend(limit.to_le_bytes());
    let repeat = branch(code, JB_REL32);
    memory::patch_branch(code, repeat, start);
}

fn store_loop(
    code: &mut Vec<u8>,
    store: &Store,
    layout: &Layout,
    length: VectorLength,
    pc: u64,
    failures: &mut Vec<usize>,
) {
    let start = code.len();
    load_index(code);
    code.extend(BT_RSP_DISP32_RCX);
    code.extend(PREDICATE_OFFSET.to_le_bytes());
    let inactive = branch(code, JNC_REL32);
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
    let active_done = branch(code, JMP_REL32);
    let inactive_start = code.len();
    memory::patch_branch(code, inactive, inactive_start);
    add_stack(
        code,
        ADDRESS_OFFSET,
        store.memory_element.bytes() as u8 * store.register_count,
    );
    let next_lane = code.len();
    memory::patch_branch(code, active_done, next_lane);
    loop_end(
        code,
        store.element.bytes() as u8,
        length.bytes() as u32,
        start,
    );
}

fn whole_loop(
    code: &mut Vec<u8>,
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
    }
}

/// Candidate extended body, returning MemoryStatus in EAX with private stack
/// storage released. The enclosing dispatcher must exit on nonzero status.
/// The declared Normal-RAM profile has AlignmentEnforced=false; original SP16
/// still checks before any offset, including the empty-predicate choice.
pub(crate) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) {
    let (address, source_bytes) = match operand {
        Operand::Prefetch(_) => {
            // Hint_Prefetch has a documented implementation-defined ignored
            // behavior. The shared dispatcher already checked the mode.
            code.extend(XOR_EAX_EAX);
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
    code.extend(SUB_RSP_IMM32);
    code.extend(layout.bytes.to_le_bytes());
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
    let success = code.len();
    if let Some(empty) = empty {
        memory::patch_branch(code, empty, success);
    }
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    for failure in failures {
        memory::patch_branch(code, failure, cleanup);
    }
    code.extend(ADD_RSP_IMM32);
    code.extend(layout.bytes.to_le_bytes());
    shared_address::return_if_failed(code);
}
