//! SME loads and stores through the memory service. Loads commit after every
//! element succeeds; stores submit one active element at a time.
use alloc::vec::Vec;
mod za;

use za::emit_za_body;

use crate::{
    TargetCpu,
    aarch64::{
        Register,
        scalable::{VECTOR_CHUNK_BYTES, VectorLength},
        sme::memory::{Direction, Offset, Operand, VectorTransfer},
    },
    context::{
        EXECUTION_CONTEXT_SCALABLE_OFFSET,
        memory::{
            MEMORY_REQUEST_ADDRESS_OFFSET, MEMORY_REQUEST_BYTES, MEMORY_REQUEST_DATA_OFFSET,
            MemoryRequirements, MemoryStatus, SpAlignmentRequirement, flags, host_caps,
            profile_requirements,
        },
    },
    x86_64::{
        isa::SimdOpcode as Host,
        scalable::{load_z_chunk, memory as service, read_predicate_chunk, store_z_chunk},
        sve::predicate::{emit_prepared_counter_chunk, prepare_counter},
    },
};

const HOST_WORD_BYTES: u32 = size_of::<u64>() as u32;
const STACK_ALIGNMENT: u32 = VECTOR_CHUNK_BYTES as u32;
const REQUEST_OFFSET: u32 = 0;
const ADDRESS_OFFSET: u32 = MEMORY_REQUEST_BYTES as u32;
const SELECTOR_OFFSET: u32 = ADDRESS_OFFSET + HOST_WORD_BYTES;
const ITERATION_OFFSET: u32 = SELECTOR_OFFSET + HOST_WORD_BYTES;
const PREDICATE_OFFSET: u32 = 64;
const MAX_VECTOR_GROUP: usize = 4;
const PREDICATE_GROUP_BITS_PER_BYTE: usize = 8;
const MIN_PREDICATE_SCRATCH_BYTES: usize = 32;
const ZT_BYTES: usize = 64;
const VALUE_XMM: u8 = 0;
const MODRM_STACK_DISP32: u8 = 0x84;
const STACK_SIB: u8 = 0x24;
const REGISTER_SHIFT: u8 = 3;
const SUB_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xec];
const ADD_RSP_IMM32: &[u8] = &[0x48, 0x81, 0xc4];
const MOV_RAX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const MOV_RSP_DISP32_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const MOV_RCX_RAX: &[u8] = &[0x48, 0x89, 0xc1];
const ADD_RAX_RCX: &[u8] = &[0x48, 0x01, 0xc8];
const ADD_RAX_IMM32: &[u8] = &[0x48, 0x05];
const SHL_RAX_IMM8: &[u8] = &[0x48, 0xc1, 0xe0];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];
const TEST_AL_IMM8: &[u8] = &[0xa8];
const JZ_REL32: &[u8] = &[0x0f, 0x84];
const JNC_REL32: &[u8] = &[0x0f, 0x83];
const JB_REL32: &[u8] = &[0x0f, 0x82];
const JMP_REL32: &[u8] = &[0xe9];
const RET: u8 = 0xc3;
const MOV_RCX_RSP_DISP32: &[u8] = &[0x48, 0x8b, 0x8c, 0x24];
const BT_RSP_DISP32_IMM8: &[u8] = &[0x48, 0x0f, 0xba, 0xa4, 0x24];
const FIRST_PREDICATE_BIT: u8 = 0;
const BT_RSP_DISP32_RCX: &[u8] = &[0x48, 0x0f, 0xa3, 0x8c, 0x24];
const ADD_RSP_DISP32_IMM8: &[u8] = &[0x48, 0x83, 0x84, 0x24];
const CMP_RSP_DISP32_IMM32: &[u8] = &[0x48, 0x81, 0xbc, 0x24];
const MOV_R8_CONTEXT_DISP8: &[u8] = &[0x4d, 0x8b, 0x47];
const MOV_R8_R8_DISP8: &[u8] = &[0x4d, 0x8b, 0x40];

struct Scratch {
    request: u32,
    address: u32,
    selector: u32,
    iteration: u32,
    predicate: u32,
    data: u32,
    bytes: u32,
}

struct Transfer {
    bytes: u32,
    element_bytes: u32,
    flags: u32,
    predicated: bool,
}

impl Scratch {
    fn new(length: VectorLength) -> Self {
        let predicate_bytes = (length.bytes() * MAX_VECTOR_GROUP / PREDICATE_GROUP_BITS_PER_BYTE)
            .max(MIN_PREDICATE_SCRATCH_BYTES) as u32;
        let data = (PREDICATE_OFFSET + predicate_bytes).next_multiple_of(STACK_ALIGNMENT);
        let data_bytes = (length.bytes() * MAX_VECTOR_GROUP).max(ZT_BYTES) as u32;
        Self {
            request: REQUEST_OFFSET,
            address: ADDRESS_OFFSET,
            selector: SELECTOR_OFFSET,
            iteration: ITERATION_OFFSET,
            predicate: PREDICATE_OFFSET,
            data,
            bytes: (data + data_bytes).next_multiple_of(STACK_ALIGNMENT),
        }
    }
}

fn required_host_caps(operand: &Operand) -> u32 {
    let (direction, bytes, base) = match operand {
        Operand::Vectors(transfer) => (
            transfer.direction,
            transfer.element.bytes(),
            transfer.address.base,
        ),
        Operand::Tile(transfer) => (
            transfer.direction,
            transfer.element.bytes(),
            transfer.address.base,
        ),
        Operand::ZaVector(_) | Operand::Zt(_) => return 0,
    };
    if direction == Direction::Store && bytes == VECTOR_CHUNK_BYTES {
        return host_caps::CX16;
    }
    // An unaligned element may cross an 8-byte host boundary while remaining
    // one 16-byte single-copy-atomic part. SP-based offsets keep natural
    // alignment after the 16-byte SP check.
    if direction == Direction::Load
        && bytes > 1
        && (bytes == VECTOR_CHUNK_BYTES || base != Register::Sp)
    {
        return host_caps::ATOMIC_LOAD16;
    }
    0
}

fn vector_flags(operand: &VectorTransfer) -> u32 {
    // These forms use the four-argument CreateAccDescSVE overload, whose
    // descriptor is unpredicated even though the operation tests a predicate.
    let mut access = 0;
    if operand.direction == Direction::Store {
        access |= flags::WRITE;
    }
    if operand.non_temporal {
        access |= flags::NON_TEMPORAL;
    }
    if matches!(operand.address.offset, Offset::Register(_)) || operand.address.base != Register::Sp
    {
        access |= flags::TAG_CHECKED;
    }
    access
}

/// Bind the complete body's immutable platform and policy requirements to entry.
/// The containing compiled manifest retains these even for inactive lanes.
pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    let (required_flags, base) = match operand {
        Operand::Vectors(transfer) => (vector_flags(transfer), transfer.address.base),
        Operand::Tile(transfer) => (
            za::access_flags(transfer.direction, true),
            transfer.address.base,
        ),
        Operand::ZaVector(transfer) => (
            za::access_flags(transfer.direction, transfer.base != Register::Sp),
            transfer.base,
        ),
        Operand::Zt(transfer) => (
            za::access_flags(transfer.direction, transfer.base != Register::Sp),
            transfer.base,
        ),
    };
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: Default::default(),
        required_flags,
        required_host_caps: required_host_caps(operand),
        required_profile: profile_requirements::NATIVE_ACCESS
            | if required_flags & flags::TAG_CHECKED != 0 {
                profile_requirements::TAG_GRANULES | profile_requirements::SCALABLE_TAG_CHECKS
            } else {
                0
            },
        required_sp_alignment: if base == Register::Sp {
            SpAlignmentRequirement::Enabled
        } else {
            SpAlignmentRequirement::Any
        },
        ..MemoryRequirements::default()
    }
}

/// Capability requirements are checked before any request, prefix reset or store.
pub(crate) fn validate_target(operand: &Operand, target: TargetCpu) -> Result<(), &'static str> {
    let required = required_host_caps(operand);
    if required & host_caps::CX16 != 0 && !target.supports(TargetCpu::Cx16) {
        return Err("SME 16-byte stores require the independent CX16 host capability");
    }
    if required & host_caps::ATOMIC_LOAD16 != 0 && !target.supports(TargetCpu::AtomicLoad16) {
        return Err("SME coherent wide reads require the independent AtomicLoad16 host capability");
    }
    Ok(())
}

pub(crate) fn emit(
    code: &mut Vec<u8>,
    operand: &Operand,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
) -> Result<(), &'static str> {
    validate_target(operand, target)?;
    let scratch = Scratch::new(length);
    stack_space(code, scratch.bytes, true);
    service::begin(code);
    let mut failures = Vec::new();
    match operand {
        Operand::Vectors(transfer) => {
            emit_vectors(code, transfer, length, target, pc, &scratch, &mut failures)
        }
        _ => emit_za_body(code, operand, length, target, pc, &scratch, &mut failures),
    }
    stack_space(code, scratch.bytes, false);
    let success = jump(code, JMP_REL32);
    let failure = code.len();
    stack_space(code, scratch.bytes, false);
    code.push(RET);
    let done = code.len();
    service::patch_branch(code, success, done);
    for displacement in failures {
        service::patch_branch(code, displacement, failure);
    }
    Ok(())
}

fn stack_space(code: &mut Vec<u8>, bytes: u32, reserve: bool) {
    code.extend(if reserve {
        SUB_RSP_IMM32
    } else {
        ADD_RSP_IMM32
    });
    code.extend(bytes.to_le_bytes());
}

fn load_guest(code: &mut Vec<u8>, register: Register) {
    crate::x86_64::load(code, register);
}

fn stack_load(code: &mut Vec<u8>, offset: u32) {
    code.extend(MOV_RAX_RSP_DISP32);
    code.extend(offset.to_le_bytes());
}

fn stack_store(code: &mut Vec<u8>, offset: u32) {
    code.extend(MOV_RSP_DISP32_RAX);
    code.extend(offset.to_le_bytes());
}

fn stack_vector(code: &mut Vec<u8>, load: bool, xmm: u8, offset: u32, target: TargetCpu) {
    if load {
        Host::LoadUnaligned
    } else {
        Host::StoreUnaligned
    }
    .append(code, target);
    code.push(MODRM_STACK_DISP32 | (xmm << REGISTER_SHIFT));
    code.push(STACK_SIB);
    code.extend(offset.to_le_bytes());
}

fn pointer(code: &mut Vec<u8>, field: u32) {
    code.extend(MOV_R8_CONTEXT_DISP8);
    code.push(EXECUTION_CONTEXT_SCALABLE_OFFSET as u8);
    code.extend(MOV_R8_R8_DISP8);
    code.push(field as u8);
}

fn jump(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
    code.extend(opcode);
    let displacement = code.len();
    code.extend(0_i32.to_le_bytes());
    displacement
}

fn check_sp(code: &mut Vec<u8>, base: Register, pc: u64, failures: &mut Vec<usize>) {
    if base != Register::Sp {
        return;
    }
    load_guest(code, base);
    code.extend(TEST_AL_IMM8);
    code.push((STACK_ALIGNMENT - 1) as u8);
    let aligned = jump(code, JZ_REL32);
    service::fault(code, MemoryStatus::StackAlignment, pc);
    failures.push(jump(code, JMP_REL32));
    let destination = code.len();
    service::patch_branch(code, aligned, destination);
}

fn transfer_loop(
    code: &mut Vec<u8>,
    transfer: Transfer,
    pc: u64,
    scratch: &Scratch,
    failures: &mut Vec<usize>,
) {
    service::request(
        code,
        scratch.request,
        scratch.data,
        transfer.element_bytes,
        transfer.flags,
        pc,
    );
    if transfer.bytes == transfer.element_bytes {
        let inactive = if transfer.predicated {
            code.extend(BT_RSP_DISP32_IMM8);
            code.extend(scratch.predicate.to_le_bytes());
            code.push(FIRST_PREDICATE_BIT);
            Some(jump(code, JNC_REL32))
        } else {
            None
        };
        service::call(code, scratch.request);
        failures.push(service::branch_failed(code));
        let destination = code.len();
        if let Some(branch) = inactive {
            service::patch_branch(code, branch, destination);
        }
        // The final address/data-pointer increments are dead private state in
        // the supported no-CPA profile. No later access consumes those values.
        return;
    }
    code.extend(XOR_EAX_EAX);
    stack_store(code, scratch.iteration);
    let head = code.len();
    let inactive = if transfer.predicated {
        code.extend(MOV_RCX_RSP_DISP32);
        code.extend(scratch.iteration.to_le_bytes());
        // Memory BT uses the complete nonnegative register bit index, advancing
        // its qword address for mask bits above63.
        code.extend(BT_RSP_DISP32_RCX);
        code.extend(scratch.predicate.to_le_bytes());
        Some(jump(code, JNC_REL32))
    } else {
        None
    };
    service::call(code, scratch.request);
    failures.push(service::branch_failed(code));
    let increment = code.len();
    if let Some(displacement) = inactive {
        service::patch_branch(code, displacement, increment);
    }
    for offset in [
        scratch.request + MEMORY_REQUEST_ADDRESS_OFFSET,
        scratch.request + MEMORY_REQUEST_DATA_OFFSET,
        scratch.iteration,
    ] {
        code.extend(ADD_RSP_DISP32_IMM8);
        code.extend(offset.to_le_bytes());
        code.push(transfer.element_bytes as u8);
    }
    code.extend(CMP_RSP_DISP32_IMM32);
    code.extend(scratch.iteration.to_le_bytes());
    code.extend(transfer.bytes.to_le_bytes());
    let repeat = jump(code, JB_REL32);
    service::patch_branch(code, repeat, head);
}

fn emit_vectors(
    code: &mut Vec<u8>,
    operand: &VectorTransfer,
    length: VectorLength,
    target: TargetCpu,
    pc: u64,
    scratch: &Scratch,
    failures: &mut Vec<usize>,
) {
    check_sp(code, operand.address.base, pc, failures);
    let loading = operand.direction == Direction::Load;
    if loading {
        Host::Xor.register(code, VALUE_XMM, VALUE_XMM, target);
    }
    for group in 0..operand.registers.count {
        let register = operand.registers.first + group * operand.registers.stride;
        for chunk in 0..length.chunks() {
            if !loading {
                load_z_chunk(code, register, chunk, VALUE_XMM, length, target);
            }
            let offset = scratch.data
                + u32::from(group) * length.bytes() as u32
                + (chunk * VECTOR_CHUNK_BYTES) as u32;
            stack_vector(code, false, VALUE_XMM, offset, target);
        }
    }
    read_predicate_chunk(code, operand.predicate, 0, length);
    prepare_counter(code, length);
    let mask_chunks = length.bytes() * usize::from(operand.registers.count) / u64::BITS as usize;
    for chunk in 0..mask_chunks.max(1) {
        emit_prepared_counter_chunk(code, chunk, length);
        stack_store(code, scratch.predicate + chunk as u32 * HOST_WORD_BYTES);
    }
    load_guest(code, operand.address.base);
    match operand.address.offset {
        Offset::VectorGroups(offset) => {
            let bytes =
                i32::from(offset) * i32::from(operand.registers.count) * length.bytes() as i32;
            if bytes != 0 {
                code.extend(ADD_RAX_IMM32);
                code.extend(bytes.to_le_bytes());
            }
        }
        Offset::Register(register) => {
            stack_store(code, scratch.address);
            load_guest(code, register);
            let scale = operand.element.bytes().trailing_zeros() as u8;
            if scale != 0 {
                code.extend(SHL_RAX_IMM8);
                code.push(scale);
            }
            code.extend(MOV_RCX_RAX);
            stack_load(code, scratch.address);
            code.extend(ADD_RAX_RCX);
        }
    }
    transfer_loop(
        code,
        Transfer {
            bytes: length.bytes() as u32 * u32::from(operand.registers.count),
            element_bytes: operand.element.bytes() as u32,
            flags: vector_flags(operand),
            predicated: true,
        },
        pc,
        scratch,
        failures,
    );
    if loading {
        for group in 0..operand.registers.count {
            let register = operand.registers.first + group * operand.registers.stride;
            for chunk in 0..length.chunks() {
                let offset = scratch.data
                    + u32::from(group) * length.bytes() as u32
                    + (chunk * VECTOR_CHUNK_BYTES) as u32;
                stack_vector(code, true, VALUE_XMM, offset, target);
                store_z_chunk(code, register, chunk, VALUE_XMM, length, target);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::sme::memory::decode;
    use alloc::vec;

    const GENERIC_HALFWORD_LOAD: u32 = 0xa140_2000;
    const SP_HALFWORD_LOAD: u32 = 0xa140_23e0;
    const QUADWORD_TILE_LOAD: u32 = 0xe1c0_0000;
    const QUADWORD_TILE_STORE: u32 = 0xe1e0_0000;
    const NOP: u8 = 0x90;

    #[test]
    fn missing_capabilities_decline_before_any_emitted_effect() {
        let length = VectorLength::from_bytes(VECTOR_CHUNK_BYTES).unwrap();
        for (word, target) in [
            (GENERIC_HALFWORD_LOAD, TargetCpu::Baseline),
            (GENERIC_HALFWORD_LOAD, TargetCpu::Cx16),
            (QUADWORD_TILE_LOAD, TargetCpu::Cx16),
            (QUADWORD_TILE_STORE, TargetCpu::AtomicLoad16),
        ] {
            let mut code = vec![NOP];
            assert!(emit(&mut code, &decode(word).unwrap(), length, target, 0).is_err());
            assert_eq!(code, [NOP]);
        }
    }

    #[test]
    fn read_and_write_requirements_are_independent() {
        assert!(
            validate_target(
                &decode(QUADWORD_TILE_LOAD).unwrap(),
                TargetCpu::AtomicLoad16
            )
            .is_ok()
        );
        assert!(validate_target(&decode(QUADWORD_TILE_STORE).unwrap(), TargetCpu::Cx16).is_ok());
        assert!(validate_target(&decode(SP_HALFWORD_LOAD).unwrap(), TargetCpu::Baseline).is_ok());
        for word in [0xe100_0000, 0xe120_0000, 0xe11f_8000, 0xe13f_8000] {
            assert!(validate_target(&decode(word).unwrap(), TargetCpu::Baseline).is_ok());
        }
    }

    #[test]
    fn private_scratch_covers_every_group_and_table_without_overlap() {
        for bytes in [16, 32, 64, 128, 256] {
            let scratch = Scratch::new(VectorLength::from_bytes(bytes).unwrap());
            assert_eq!(scratch.bytes % STACK_ALIGNMENT, 0);
            assert!(scratch.address >= scratch.request + MEMORY_REQUEST_BYTES as u32);
            assert!(scratch.selector >= scratch.address + HOST_WORD_BYTES);
            assert!(scratch.iteration >= scratch.selector + HOST_WORD_BYTES);
            assert!(scratch.predicate >= scratch.iteration + HOST_WORD_BYTES);
            assert!(
                scratch.data
                    >= scratch.predicate
                        + (bytes * MAX_VECTOR_GROUP / PREDICATE_GROUP_BITS_PER_BYTE) as u32
            );
            assert!(
                scratch.bytes >= scratch.data + (bytes * MAX_VECTOR_GROUP).max(ZT_BYTES) as u32
            );
        }
    }

    #[test]
    fn entry_requirements_keep_descriptor_roles_and_profile_preflight() {
        let generic = requirements(&decode(GENERIC_HALFWORD_LOAD).unwrap());
        assert_eq!(generic.required_flags, flags::TAG_CHECKED);
        assert_eq!(generic.required_host_caps, host_caps::ATOMIC_LOAD16);
        assert_eq!(generic.required_sp_alignment, SpAlignmentRequirement::Any);
        assert_eq!(
            generic.required_profile,
            profile_requirements::NATIVE_ACCESS
                | profile_requirements::SCALABLE_TAG_CHECKS
                | profile_requirements::TAG_GRANULES
        );
        let stack = requirements(&decode(SP_HALFWORD_LOAD).unwrap());
        assert_eq!(stack.required_flags, 0);
        assert_eq!(stack.required_host_caps, 0);
        assert_eq!(stack.required_sp_alignment, SpAlignmentRequirement::Enabled);
        assert_eq!(stack.required_profile, profile_requirements::NATIVE_ACCESS);
        let quad = requirements(&decode(QUADWORD_TILE_STORE).unwrap());
        assert_eq!(
            quad.required_flags,
            flags::SME | flags::TAG_CHECKED | flags::WRITE
        );
        assert_eq!(quad.required_host_caps, host_caps::CX16);
        assert_eq!(quad.required_sp_alignment, SpAlignmentRequirement::Any);
        assert_eq!(
            quad.required_profile,
            profile_requirements::NATIVE_ACCESS
                | profile_requirements::TAG_GRANULES
                | profile_requirements::SCALABLE_TAG_CHECKS
        );
        let table = requirements(&decode(0xe13f_83e0).unwrap());
        assert_eq!(table.required_flags, flags::SME | flags::WRITE);
        assert_eq!(table.required_host_caps, 0);
        assert_eq!(table.required_sp_alignment, SpAlignmentRequirement::Enabled);
        assert_eq!(table.required_profile, profile_requirements::NATIVE_ACCESS);
    }
}
