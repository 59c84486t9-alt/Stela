//! Checked scalar loads and stores through the memory service. Guest registers
//! are written after the access completes.
use crate::x86_64::asm::{Alu, Code, Gpr, Mem, Size};
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

const DOUBLEWORD_BYTES: u8 = size_of::<u64>() as u8;
const REQUEST_OFFSET: u32 = 0;
const DATA_OFFSET: u32 = 32;
const WRITEBACK_OFFSET: u32 = 40;
const SCRATCH_BYTES: u8 = 48;

/// The private scratch slot at `offset`.
const fn scratch(offset: u32) -> Mem {
    Mem::base_disp32(Gpr::Rsp, offset as i32)
}

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
}
fn data_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < 31) || register == Register::Zero
}
fn base_register(register: Register) -> bool {
    matches!(register, Register::X(index) if index < 31) || register == Register::Sp
}
impl Operand {
    pub(crate) fn profile_success_traffic(&self) -> crate::block::profile::RegisterTraffic {
        let real = |register| u64::from(register != Register::Zero);
        crate::block::profile::RegisterTraffic {
            gpr_frame_loads: u64::from(self.transfer == MemoryTransfer::Store) * real(self.data)
                + u64::from(!matches!(self.address, Address::Literal { .. }))
                + match self.address {
                    Address::RegisterOffset { index, .. } => real(index),
                    _ => 0,
                }
                + u64::from(
                    self.base == Register::Sp
                        && self.profile.sp_requirement() == SpAlignmentRequirement::Enabled,
                ),
            gpr_direct_stores: u64::from(matches!(self.transfer, MemoryTransfer::Load { .. }))
                * real(self.data)
                + u64::from(self.writeback()),
            ..Default::default()
        }
    }

    /// This is a typed adapter, not a decoder. Allocated memory families that
    /// return None must decline; dispatch must never fall back to direct memory.
    pub(crate) fn from_operation(
        operation: &Operation,
        profile: CheckedMemoryProfile,
    ) -> Option<Self> {
        if matches!(operation, Operation::Literal(_)) {
            // Literal PC arithmetic has no register base, SP check, writeback
            // or tag check.
            return Self::literal_load(operation, profile);
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
    /// The one typed integer literal adapter for checked profiles. Exact
    /// source address/width/extension were lifted by the shared decoder.
    fn literal_load(operation: &Operation, profile: CheckedMemoryProfile) -> Option<Self> {
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
        })
    }
    /// An ordinary or literal integer load, without a checked profile's
    /// SP-alignment specialization.
    pub(crate) fn scalar_load(operation: &Operation) -> Option<Self> {
        let operand = Self::from_operation(operation, CheckedMemoryProfile::SpAlignmentDisabled)?;
        (!operand.unprivileged && matches!(operand.transfer, MemoryTransfer::Load { .. }))
            .then_some(operand)
    }
    /// An ordinary integer store; unprivileged and literal forms are excluded.
    pub(crate) fn scalar_store(operation: &Operation) -> Option<Self> {
        let operand = Self::from_operation(operation, CheckedMemoryProfile::SpAlignmentDisabled)?;
        (!operand.unprivileged && operand.transfer == MemoryTransfer::Store).then_some(operand)
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

fn result(code: &mut Code, bytes: u8, signed: bool, width: Width) {
    let size = Size::of(width == Width::X64);
    let data = scratch(DATA_OFFSET);
    let mut asm = code.asm();
    match (bytes, signed) {
        (1, false) => asm.movzx(size, Gpr::Rax, Size::Byte, data),
        (2, false) => asm.movzx(size, Gpr::Rax, Size::Word, data),
        (1, true) => asm.movsx(size, Gpr::Rax, Size::Byte, data),
        (2, true) => asm.movsx(size, Gpr::Rax, Size::Word, data),
        (4, true) => {
            debug_assert!(size == Size::Qword);
            asm.movsxd(Gpr::Rax, data);
        }
        (4 | 8, false) => asm.mov_load(size, Gpr::Rax, data),
        _ => unreachable!("validated scalar result"),
    }
}

pub(crate) fn emit_context(code: &mut Code, operand: &Operand, pc: u64) {
    let req = requirements(operand);
    code.asm()
        .alu_imm8(Alu::Sub, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
    service::begin(code);
    let mut failures = vec![];
    if operand.profile.sp_requirement() == SpAlignmentRequirement::Enabled
        && let Some(failed) = address::check_sp(code, operand.base, pc)
    {
        failures.push(failed);
    }
    if matches!(operand.transfer, MemoryTransfer::Store) {
        load(code, operand.data);
        code.asm()
            .mov_store(Size::Qword, scratch(DATA_OFFSET), Gpr::Rax);
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
        code.asm()
            .mov_store(Size::Qword, scratch(WRITEBACK_OFFSET), Gpr::Rdx);
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
        code.asm()
            .mov_load(Size::Qword, Gpr::Rax, scratch(WRITEBACK_OFFSET));
        store(code, operand.base);
    }
    code.asm().alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax);
    let cleanup = code.len();
    for failed in failures {
        service::patch_branch(code, failed, cleanup);
    }
    code.asm()
        .alu_imm8(Alu::Add, Size::Qword, Gpr::Rsp, SCRATCH_BYTES as i8);
    address::return_if_failed(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuestAddress, Lifter, aarch64::Decoder};

    #[test]
    fn profiled_register_offset_counts_actual_aliased_frame_loads_and_sp_check() {
        let operand = Operand::from_operation(
            &Operation::MemoryRegisterOffset(crate::aarch64::register_offset::Operand {
                transfer: MemoryTransfer::Store,
                bytes: 8,
                data: Register::X(0),
                base: Register::Sp,
                index: Register::X(0),
                extend: IndexExtend::Lsl,
                shift: 0,
            }),
            CheckedMemoryProfile::SpAlignmentEnabled,
        )
        .unwrap();
        let traffic = operand.profile_success_traffic();
        assert_eq!((traffic.gpr_frame_loads, traffic.gpr_direct_stores), (4, 0));
        let mut code = Code::new();
        emit_context(&mut code, &operand, 0x4000);
        for (register, count) in [(Register::X(0), 1), (Register::Sp, 2)] {
            let mut expected = Code::new();
            load(&mut expected, register);
            assert_eq!(
                code.windows(expected.len())
                    .filter(|window| *window == expected)
                    .count(),
                count
            );
        }
        // The aliased index is a read memory operand of ADD, not another MOV.
        let index_read = [0x48, 0x03, 0x87, 0, 0, 0, 0];
        assert_eq!(
            code.windows(index_read.len())
                .filter(|window| *window == index_read)
                .count(),
            1
        );
    }
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
                            let required = requirements(&operand);
                            assert_eq!(required.required_flags, 0);
                            assert_eq!(required.required_sp_alignment, SpAlignmentRequirement::Any);
                            assert_eq!(required.required_host_caps, host_caps::ATOMIC_LOAD16);
                        }
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
