//! Checked GPR scalar transfers; the legacy direct emitter is independent.
//!
//! Typed operands come from the existing decoder. The containing checked CPU
//! profile is EL0/little-endian/LSE2 with A=false and CPA2 disabled; actual policy
//! privilege/SP/TBI/MTE and host requirements are admitted before native prefix.
use crate::x86_64::{
    load,
    memory_context::{self as service, address},
    store,
};
use crate::{
    aarch64::{
        AddressMode, MemoryTransfer, Operation, Register, Width, register_offset::IndexExtend,
    },
    block::CheckedMemoryProfile,
    context::memory::{
        MemoryRequirements, SpAlignmentRequirement, flags, host_caps, profile_requirements,
    },
};

const REQUEST_OFFSET: u32 = 0;
const DATA_OFFSET: u32 = 32;
const WRITEBACK_OFFSET: u32 = 40;
const SCRATCH_BYTES: u8 = 48;
const SUB_RSP: &[u8] = &[0x48, 0x83, 0xec, SCRATCH_BYTES];
const ADD_RSP: &[u8] = &[0x48, 0x83, 0xc4, SCRATCH_BYTES];
const MOV_RSP_RAX: &[u8] = &[0x48, 0x89, 0x84, 0x24];
const MOV_RSP_RDX: &[u8] = &[0x48, 0x89, 0x94, 0x24];
const MOV_RAX_RSP: &[u8] = &[0x48, 0x8b, 0x84, 0x24];
const XOR_EAX_EAX: &[u8] = &[0x31, 0xc0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Address {
    Immediate {
        displacement: i32,
        mode: AddressMode,
    },
    RegisterOffset {
        index: Register,
        extend: IndexExtend,
        shift: u8,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Operand {
    profile: CheckedMemoryProfile,
    transfer: MemoryTransfer,
    bytes: u8,
    data: Register,
    base: Register,
    address: Address,
    /// Retained source distinction. The initial EL0 profile makes this descriptor
    /// privilege equal to ordinary EL0; broader EL/UAO needs its actual CPU owner.
    unprivileged: bool,
}
fn data_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < 31) || register == Register::Zero
}
fn base_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < 31) || register == Register::Sp
}
impl Operand {
    /// This is a typed adapter, not a decoder. Allocated memory families that
    /// return None must decline; dispatch must never fall back to direct memory.
    pub(crate) fn from_operation(
        operation: &Operation,
        profile: CheckedMemoryProfile,
    ) -> Option<Self> {
        let operand = match *operation {
            Operation::Memory {
                transfer,
                bytes,
                data,
                base,
                displacement,
                mode,
            } => Self {
                profile,
                transfer,
                bytes,
                data,
                base,
                address: Address::Immediate { displacement, mode },
                unprivileged: false,
            },
            Operation::MemoryRegisterOffset(operand) => Self {
                profile,
                transfer: operand.transfer,
                bytes: operand.bytes,
                data: operand.data,
                base: operand.base,
                address: Address::RegisterOffset {
                    index: operand.index,
                    extend: operand.extend,
                    shift: operand.shift,
                },
                unprivileged: false,
            },
            Operation::MemoryUnprivileged(operand) => Self {
                profile,
                transfer: operand.transfer,
                bytes: operand.bytes,
                data: operand.data,
                base: operand.base,
                address: Address::Immediate {
                    displacement: operand.displacement,
                    mode: AddressMode::Offset,
                },
                unprivileged: true,
            },
            _ => return None,
        };
        if !matches!(operand.bytes, 1 | 2 | 4 | 8)
            || !data_register(operand.data)
            || !base_register(operand.base)
        {
            return None;
        }
        if let MemoryTransfer::Load { signed, width } = operand.transfer {
            let valid = matches!(
                (signed, width, operand.bytes),
                (false, Width::W32, 1 | 2 | 4)
                    | (false, Width::X64, 8)
                    | (true, Width::W32, 1 | 2)
                    | (true, Width::X64, 1 | 2 | 4)
            );
            if !valid {
                return None;
            }
        }
        if operand.unprivileged && operand.writeback() {
            return None;
        }
        match operand.address {
            Address::Immediate { mode, .. }
                if mode != AddressMode::Offset
                    && operand.base == operand.data
                    && operand.base != Register::Sp =>
            {
                return None;
            }
            Address::RegisterOffset { index, shift, .. }
                if !data_register(index)
                    || ![0, operand.bytes.trailing_zeros() as u8].contains(&shift) =>
            {
                return None;
            }
            _ => {}
        }
        Some(operand)
    }
    fn tag_checked(&self) -> bool {
        match self.address {
            Address::RegisterOffset { .. } => true,
            Address::Immediate { mode, .. } => {
                mode != AddressMode::Offset || self.base != Register::Sp
            }
        }
    }
    fn writeback(&self) -> bool {
        matches!(self.address, Address::Immediate { mode, .. } if mode != AddressMode::Offset)
    }
}

pub(crate) fn requirements(operand: &Operand) -> MemoryRequirements {
    let write = matches!(operand.transfer, MemoryTransfer::Store);
    let tag_checked = operand.tag_checked();
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: operand.profile.address_requirements(operand.unprivileged),
        required_flags: if write { flags::WRITE } else { 0 }
            | if tag_checked { flags::TAG_CHECKED } else { 0 },
        // Any dynamic multibyte read may cross the enclosing aligned8 while
        // remaining inside SCA16. The readonly16 snapshot capability is separate
        // from CX16. A future alignment proof can narrow this conservative gate.
        required_host_caps: if !write && operand.bytes > 1 {
            host_caps::ATOMIC_LOAD16
        } else {
            0
        },
        required_profile: profile_requirements::NATIVE_ACCESS
            | if tag_checked {
                profile_requirements::TAG_GRANULES
            } else {
                0
            },
        required_sp_alignment: if operand.base == Register::Sp {
            operand.profile.sp_requirement()
        } else {
            SpAlignmentRequirement::Any
        },
    }
}

fn result(code: &mut Vec<u8>, bytes: u8, signed: bool, width: Width) {
    if width == Width::X64 {
        code.push(0x48);
    }
    match (bytes, signed) {
        (1, false) => code.extend([0x0f, 0xb6]),
        (2, false) => code.extend([0x0f, 0xb7]),
        (1, true) => code.extend([0x0f, 0xbe]),
        (2, true) => code.extend([0x0f, 0xbf]),
        (4, true) => code.push(0x63),
        (4 | 8, false) => code.push(0x8b),
        _ => unreachable!("validated scalar result"),
    }
    code.extend([0x84, 0x24]);
    code.extend(DATA_OFFSET.to_le_bytes());
}

pub(crate) fn emit_context(code: &mut Vec<u8>, operand: &Operand, pc: u64) {
    let req = requirements(operand);
    code.extend(SUB_RSP);
    service::begin(code);
    let mut failures = vec![];
    if operand.profile.sp_requirement() == SpAlignmentRequirement::Enabled
        && let Some(failed) = address::check_sp(code, operand.base, pc)
    {
        failures.push(failed);
    }
    if matches!(operand.transfer, MemoryTransfer::Store) {
        load(code, operand.data);
        code.extend(MOV_RSP_RAX);
        code.extend(DATA_OFFSET.to_le_bytes());
    }
    match operand.address {
        Address::Immediate { displacement, mode } => address::immediate_with_checks(
            code,
            operand.base,
            displacement,
            mode,
            operand.profile.address_checks(operand.unprivileged),
        ),
        Address::RegisterOffset {
            index,
            extend,
            shift,
        } => address::register_offset_with_checks(
            code,
            operand.base,
            index,
            extend,
            shift,
            operand.profile.address_checks(operand.unprivileged),
        ),
    }
    if operand.writeback() {
        code.extend(MOV_RSP_RDX);
        code.extend(WRITEBACK_OFFSET.to_le_bytes());
    }
    service::request(
        code,
        REQUEST_OFFSET,
        DATA_OFFSET,
        u32::from(operand.bytes),
        req.required_flags,
        pc,
    );
    service::call(code, REQUEST_OFFSET);
    failures.push(service::branch_failed(code));
    if let MemoryTransfer::Load { signed, width } = operand.transfer
        && operand.data != Register::Zero
    {
        result(code, operand.bytes, signed, width);
        store(code, operand.data);
    }
    if operand.writeback() {
        code.extend(MOV_RAX_RSP);
        code.extend(WRITEBACK_OFFSET.to_le_bytes());
        store(code, operand.base);
    }
    code.extend(XOR_EAX_EAX);
    let cleanup = code.len();
    for failed in failures {
        service::patch_branch(code, failed, cleanup);
    }
    code.extend(ADD_RSP);
    address::return_if_failed(code);
}
