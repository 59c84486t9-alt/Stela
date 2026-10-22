//! Checked scalar loads and stores through the memory service. Guest registers
//! are written after the access completes.
use crate::x86_64::{
    load,
    memory_context::{self as service, address},
    store,
};
use crate::{
    aarch64::{
        AddressMode, MemoryTransfer, Operation, Register, Width, literal,
        register_offset::IndexExtend,
    },
    block::CheckedMemoryProfile,
    context::memory::{
        MemoryRequirements, SpAlignmentRequirement, flags, host_caps, profile_requirements,
    },
};
use alloc::vec;
use alloc::vec::Vec;

const DOUBLEWORD_BYTES: u8 = size_of::<u64>() as u8;
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
pub(crate) enum Address {
    Literal {
        address: u64,
    },
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
    /// Whether the source instruction was unprivileged. At EL0 this is the same
    /// as an ordinary access.
    unprivileged: bool,
    /// An MMU-off staged scalar load or store, never Normal-WB.
    m0_scalar: bool,
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
        if matches!(operation, Operation::Literal(_)) {
            // Literal PC arithmetic has no register base, SP check, writeback
            // or tag check. Keep the legacy staged read64 specialization closed.
            if profile == CheckedMemoryProfile::M0DeviceRamRead64Staged {
                return None;
            }
            return Self::literal_load(operation, profile, false);
        }
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
                m0_scalar: false,
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
                m0_scalar: false,
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
                m0_scalar: false,
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
        if profile == CheckedMemoryProfile::M0DeviceRamRead64Staged
            && (operand.bytes != DOUBLEWORD_BYTES
                || operand.transfer
                    != (MemoryTransfer::Load {
                        signed: false,
                        width: Width::X64,
                    })
                || !matches!(operand.base, Register::X(index) if index < 31)
                || !matches!(
                    operand.address,
                    Address::Immediate {
                        mode: AddressMode::Offset,
                        ..
                    }
                )
                || operand.unprivileged)
        {
            return None;
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
    /// The checked scalar adapter with the staged M0 capability. Literal
    /// operands are already lifted by the decoder.
    pub(crate) fn from_m0_scalar_load(operation: &Operation) -> Option<Self> {
        if matches!(operation, Operation::Literal(_)) {
            return Self::literal_load(operation, CheckedMemoryProfile::SpAlignmentDisabled, true);
        }
        let mut operand =
            Self::from_operation(operation, CheckedMemoryProfile::SpAlignmentDisabled)?;
        if operand.unprivileged || !matches!(operand.transfer, MemoryTransfer::Load { .. }) {
            return None;
        }
        operand.m0_scalar = true;
        Some(operand)
    }
    /// The one typed integer literal adapter for checked and staged profiles.
    /// Exact source address/width/extension were lifted by the shared decoder.
    fn literal_load(
        operation: &Operation,
        profile: CheckedMemoryProfile,
        m0_scalar: bool,
    ) -> Option<Self> {
        let Operation::Literal(operand) = *operation else {
            return None;
        };
        let literal::Transfer::Integer {
            destination,
            width,
            signed,
        } = operand.transfer
        else {
            return None;
        };
        let bytes = match (width, signed) {
            (Width::W32, false) | (Width::X64, true) => 4,
            (Width::X64, false) => DOUBLEWORD_BYTES,
            _ => return None,
        };
        data_register(destination).then_some(Self {
            profile,
            transfer: MemoryTransfer::Load { signed, width },
            bytes,
            data: destination,
            base: Register::Zero,
            address: Address::Literal {
                address: operand.address,
            },
            unprivileged: false,
            m0_scalar,
        })
    }
    /// The scalar store operand; unprivileged and literal forms are excluded.
    pub(crate) fn from_m0_scalar_store(operation: &Operation) -> Option<Self> {
        let mut operand =
            Self::from_operation(operation, CheckedMemoryProfile::SpAlignmentDisabled)?;
        if operand.unprivileged || operand.transfer != MemoryTransfer::Store {
            return None;
        }
        operand.m0_scalar = true;
        Some(operand)
    }
    pub(crate) fn bytes(self) -> u8 {
        self.bytes
    }
    pub(crate) fn data(self) -> Register {
        self.data
    }
    pub(crate) fn base(self) -> Register {
        self.base
    }
    pub(crate) fn transfer(self) -> MemoryTransfer {
        self.transfer
    }
    pub(crate) fn address(self) -> Address {
        self.address
    }

    fn tag_checked(&self) -> bool {
        match self.address {
            Address::Literal { .. } => false,
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
    if operand.m0_scalar {
        let write = operand.transfer == MemoryTransfer::Store;
        return MemoryRequirements {
            required_address_checks: Default::default(),
            required_pointer_arithmetic: None,
            required_flags: if write { flags::WRITE } else { 0 }
                | if operand.tag_checked() {
                    flags::TAG_CHECKED
                } else {
                    0
                },
            required_host_caps: 0,
            required_profile: if write {
                profile_requirements::M0_DEVICE_RAM_SCALAR_STORE
            } else {
                profile_requirements::M0_DEVICE_RAM_SCALAR_LOAD
            },
            // The EL1 runtime checks SP against SCTLR.SA before address
            // arithmetic.
            required_sp_alignment: SpAlignmentRequirement::Any,
            ..MemoryRequirements::default()
        };
    }
    if operand.profile == CheckedMemoryProfile::M0DeviceRamRead64Staged {
        // The runtime enforces the 8-byte alignment before the Device access;
        // no wider snapshot, tag plane or 16-byte atomicity is required.
        return MemoryRequirements {
            required_address_checks: Default::default(),
            required_pointer_arithmetic: None,
            required_flags: flags::TAG_CHECKED,
            required_host_caps: 0,
            required_profile: profile_requirements::M0_DEVICE_RAM_READ64,
            required_sp_alignment: SpAlignmentRequirement::Any,
            ..MemoryRequirements::default()
        };
    }
    let write = matches!(operand.transfer, MemoryTransfer::Store);
    let tag_checked = operand.tag_checked();
    MemoryRequirements {
        required_pointer_arithmetic: None,
        required_address_checks: if matches!(operand.address, Address::Literal { .. }) {
            Default::default()
        } else {
            operand.profile.address_requirements(operand.unprivileged)
        },
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
        ..MemoryRequirements::default()
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
        Address::Literal { address } => crate::x86_64::immediate(code, address),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, Lifter, aarch64::Decoder};
    const IMM19_MASK: u32 = (1 << 19) - 1;
    fn source(form: u32, immediate: i32, destination: u32) -> u32 {
        form | ((immediate as u32 & IMM19_MASK) << 5) | destination
    }
    #[test]
    fn checked_integer_literal_roles_width_extension_and_wrapping_source_pc_are_exact() {
        for (form, bytes, width, signed) in [
            (0x18000000, 4, Width::W32, false),
            (0x58000000, 8, Width::X64, false),
            (0x98000000, 4, Width::X64, true),
        ] {
            for pc in [0, 0x1004, u64::MAX - 3] {
                for immediate in [-262144, -1, 0, 1, 262143] {
                    for destination in [0, 10, 30, 31] {
                        let instruction = Decoder
                            .lift(GuestAddress(pc), source(form, immediate, destination))
                            .unwrap();
                        for profile in [
                            CheckedMemoryProfile::SpAlignmentEnabled,
                            CheckedMemoryProfile::SpAlignmentDisabled,
                        ] {
                            let operand =
                                Operand::from_operation(&instruction.operation, profile).unwrap();
                            assert_eq!(operand.bytes, bytes);
                            assert_eq!(operand.transfer, MemoryTransfer::Load { signed, width });
                            assert_eq!(
                                operand.address,
                                Address::Literal {
                                    address: pc.wrapping_add_signed(i64::from(immediate) * 4)
                                }
                            );
                            assert_eq!(operand.base, Register::Zero);
                            assert_eq!(
                                operand.data,
                                if destination == 31 {
                                    Register::Zero
                                } else {
                                    Register::X(destination as u8)
                                }
                            );
                            assert!(!operand.tag_checked());
                            assert!(!operand.writeback());
                            assert!(!operand.m0_scalar);
                            let required = requirements(&operand);
                            assert_eq!(required.required_flags, 0);
                            assert_eq!(required.required_sp_alignment, SpAlignmentRequirement::Any);
                            assert_eq!(required.required_host_caps, host_caps::ATOMIC_LOAD16);
                            let staged =
                                Operand::from_m0_scalar_load(&instruction.operation).unwrap();
                            assert!(staged.m0_scalar);
                            assert_ne!(
                                requirements(&staged).required_profile,
                                required.required_profile
                            );
                        }
                        assert!(
                            Operand::from_operation(
                                &instruction.operation,
                                CheckedMemoryProfile::M0DeviceRamRead64Staged
                            )
                            .is_none()
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn checked_literal_adapter_never_admits_simd_prefetch_or_reserved_encodings() {
        for word in [0x1c000000, 0x5c000000, 0x9c000000, 0xdc000000, 0xd8000000] {
            if let Ok(instruction) = Decoder.lift(GuestAddress(0x1000), word) {
                assert!(
                    Operand::from_operation(
                        &instruction.operation,
                        CheckedMemoryProfile::SpAlignmentDisabled
                    )
                    .is_none()
                );
            }
        }
    }
}
