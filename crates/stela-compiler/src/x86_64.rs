//! x86-64 code emission. RDI holds the guest state pointer throughout.
use crate::{
    Backend, GuestAddress, NativeBlock, UnsupportedReason,
    aarch64::{
        AddressMode, Instruction, Logical, MemoryTransfer, Operation, Register, RegisterExtend,
        Shift, WideMove, Width,
    },
};
use alloc::vec;
use alloc::vec::Vec;

pub struct Emitter;

/// Check semantic host requirements before either leaf or block emission.
pub(crate) fn validate_target(
    instruction: &Instruction,
    target: crate::TargetCpu,
) -> Result<(), UnsupportedReason> {
    validate_target_with(instruction, target, MemoryChecks::DEFAULT)
}

/// [`validate_target`] for code emitted with `checks`.
pub(crate) fn validate_target_with(
    instruction: &Instruction,
    target: crate::TargetCpu,
    checks: MemoryChecks,
) -> Result<(), UnsupportedReason> {
    if matches!(
        instruction.operation,
        Operation::Exclusive(_) | Operation::CheckedPointer(_)
    ) {
        return Err(UnsupportedReason::PrivilegedOperation {
            address: instruction.pc,
        });
    }
    if let Operation::Synchronization(operation) = &instruction.operation
        && !matches!(
            operation,
            crate::aarch64::system::synchronization::Operation::Yield
                | crate::aarch64::system::synchronization::Operation::ConsumptionBarrier
                | crate::aarch64::system::synchronization::Operation::SpeculationBarrier
        )
    {
        return Err(UnsupportedReason::PrivilegedOperation {
            address: instruction.pc,
        });
    }
    if let Operation::Ordered(operand) = &instruction.operation
        && ordered::requires_atomic_load16(operand, target, checks)
        && !target.supports(crate::TargetCpu::AtomicLoad16)
    {
        return Err(UnsupportedReason::HostCapabilityRequired {
            address: instruction.pc,
            required: crate::TargetCpu::AtomicLoad16,
        });
    }
    if let Operation::Atomic(operand) = &instruction.operation
        && atomic::requires_cx16(operand, target, checks)
        && !target.supports(crate::TargetCpu::Cx16)
    {
        return Err(UnsupportedReason::HostCapabilityRequired {
            address: instruction.pc,
            required: crate::TargetCpu::Cx16,
        });
    }
    Ok(())
}
pub mod amx;
mod atomic;
mod bitfield;
pub(crate) mod block;
pub mod chain;
pub(crate) mod checked_pointer;
mod conditional_select;
mod crc;
pub(crate) mod exclusive;
mod flags;
mod fp_register;
mod guest_range;
mod integer_math;
mod integer_minmax;
mod integer_unary;
pub mod isa;
mod literal;
pub(crate) mod memory_context;
pub(crate) mod memory_store;
mod non_temporal;
mod ordered;
mod pc_relative;
pub mod pointer;
mod pointer_checks;
mod prefetch;
mod region;
mod register_offset;
pub mod register_read;
mod scalable;
mod scalable_matrix;
mod simd;
pub(crate) use simd::memory_checked::CheckedOperand as CheckedFixedMemoryOperand;
pub mod cache_clean;
pub(crate) mod sme;
pub(crate) mod sve;
mod system;
mod tag_arithmetic;
mod unprivileged;
pub mod zero_block;

/// The System instructions a system-mode block ending in one completes
/// natively instead of exiting: DC ZVA zeroing a block of `zero_block`
/// bytes, and the DC clean operations of `cache_clean`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeSystem {
    pub zero_block: Option<u16>,
    pub cache_clean: cache_clean::Operations,
}

impl NativeSystem {
    /// Every System instruction exits.
    pub const NONE: Self = Self {
        zero_block: None,
        cache_clean: cache_clean::Operations::NONE,
    };
}

fn offset(register: Register) -> Option<u32> {
    match register {
        Register::X(index) => Some(u32::from(index) * 8),
        Register::Sp => Some(248),
        Register::Zero => None,
    }
}

/// Backend policy shared by block parsing and emission. Terminal numerical
/// mappings consume only their own word; conditional mappings retain a suffix.
pub(crate) fn numerical_always_exits(operation: &crate::aarch64::FloatingPointOperation) -> bool {
    simd::numerical_always_exits(operation)
}

fn load(code: &mut Vec<u8>, register: Register) {
    if let Some(offset) = offset(register) {
        code.extend([0x48, 0x8b, 0x87]); // mov rax,[rdi+disp32]
        code.extend(offset.to_le_bytes());
    } else {
        code.extend([0x31, 0xc0]);
    }
}

fn store(code: &mut Vec<u8>, register: Register) {
    if let Some(offset) = offset(register) {
        code.extend([0x48, 0x89, 0x87]); // mov [rdi+disp32],rax
        code.extend(offset.to_le_bytes());
    }
}

/// Direct ordinary-RAM profile. Guest virtual addresses equal native addresses;
/// the caller keeps code/state separate from guest mappings. Guest NZCV is untouched.
#[allow(clippy::too_many_arguments)]
fn memory(
    code: &mut Vec<u8>,
    checks: MemoryChecks,
    transfer: MemoryTransfer,
    bytes: u8,
    data: Register,
    base: Register,
    displacement: i32,
    mode: AddressMode,
) {
    memory_address(code, checks, base, displacement, mode, bytes);
    match transfer {
        MemoryTransfer::Store => {
            right_operand(code, data, Width::X64, Shift::Lsl, 0);
            memory_store::emit(
                code,
                bytes,
                0,
                memory_store::Source::Rcx,
                checks.stack_alignment
                    && memory_store::aligned_immediate(base, displacement, mode, bytes),
            );
        }
        MemoryTransfer::Load { signed, width } => {
            if width == Width::X64 {
                code.push(0x48);
            }
            match (bytes, signed) {
                (1, false) => code.extend([0x0f, 0xb6, 0x08]),
                (2, false) => code.extend([0x0f, 0xb7, 0x08]),
                (1, true) => code.extend([0x0f, 0xbe, 0x08]),
                (2, true) => code.extend([0x0f, 0xbf, 0x08]),
                (4, true) => code.extend([0x63, 0x08]), // movsxd rcx,[rax]
                (4 | 8, false) => code.extend([0x8b, 0x08]),
                _ => unreachable!("decoder validates signed scalar size"),
            }
            // Even a discarded load performs the memory access and can fault.
            if let Some(offset) = offset(data) {
                code.extend([0x48, 0x89, 0x8f]); // mov [rdi+disp32],rcx
                code.extend(offset.to_le_bytes());
            }
        }
    }
    // A failed native memory instruction cannot update the base register.
    memory_writeback(code, base, mode);
}

/// Guest checks fixed into a block's native memory accesses. Each failed
/// check raises a native #UD before the access, which the system-mode engine
/// turns into the guest's SP alignment or Alignment fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryChecks {
    /// SCTLR_ELx.SA (SA0 at EL0) is set: an access through an SP that is not
    /// 16-byte aligned faults.
    pub stack_alignment: bool,
    /// SCTLR_ELx.A is set: a data access not aligned to the size of each
    /// element it transfers faults (Arm `AlignmentEnforced`).
    pub alignment: bool,
    /// SCTLR_ELx.nAA is clear: a load-acquire or store-release that crosses a
    /// 16-byte granule faults. Atomics always fault there (FEAT_LSE2).
    pub ordered_granule: bool,
    /// Every access checks its address against the guest's two ranges
    /// ([`GUEST_RANGE_CHECK`]). `SystemModeV1` sets it for every block,
    /// whatever the engine asks, and no other profile does.
    pub(crate) guest_range: bool,
    /// No other agent accesses guest memory while the block runs: the
    /// system engine runs one PE at a time, and no device or host agent
    /// writes guest RAM meanwhile. Atomics, ordered accesses and barriers
    /// then need no LOCK, XCHG, MFENCE or 16-byte snapshot
    /// ([`plain_ordering`]). `SystemModeV1` sets it for every block, and no
    /// other profile does.
    pub(crate) single_agent: bool,
}

impl MemoryChecks {
    /// The process profiles' checks, and system mode's with SCTLR_ELx.SA set
    /// and A and nAA clear.
    pub const DEFAULT: Self = Self {
        stack_alignment: true,
        alignment: false,
        ordered_granule: true,
        guest_range: false,
        single_agent: false,
    };
    /// SCTLR_ELx's checks, as the system-mode engine selects them.
    pub const fn system(stack_alignment: bool, alignment: bool, ordered_granule: bool) -> Self {
        Self {
            stack_alignment,
            alignment,
            ordered_granule,
            guest_range: false,
            single_agent: false,
        }
    }
}

/// Whether atomics, ordered accesses and barriers lower to plain accesses:
/// for a single agent ([`MemoryChecks::single_agent`]), and in the
/// data-independent-timing mode, which requires one
/// ([`crate::TargetCpu::data_independent_timing`]) because LOCK, XCHG and
/// MFENCE are not on Intel's data operand independent timing list.
fn plain_ordering(target: crate::TargetCpu, checks: MemoryChecks) -> bool {
    checks.single_agent || target.data_independent_timing()
}

/// The system-mode check of the access address in RAX against the guest's
/// two ranges, the only parts of the host address space its shadow tables
/// map: bits 63:48 all clear (TTBR0, PML5 entry 0) or all set (TTBR1, entry
/// 511). Any other address raises #UD before the access, which the engine
/// turns into the fault the guest's translation gives it. Every other PML5
/// entry, Stela's window (entry 64) among them, is then out of a guest
/// access's reach. RCX and host flags are scratch.
pub(crate) const GUEST_RANGE_CHECK: [u8; 16] = [
    0x48, 0x89, 0xc1, // mov rcx,rax
    0x48, 0xc1, 0xf9, 48, // sar rcx,48: 0 or -1 in range
    0xff, 0xc1, // inc ecx: 1 or 0 in range
    0x83, 0xf9, 0x01, // cmp ecx,1
    0x76, 0x02, // jbe +2
    0x0f, 0x0b, // ud2
];

/// The end of each of the six host instructions of [`GUEST_RANGE_CHECK`],
/// which the region cost gates count one by one.
pub(crate) const GUEST_RANGE_CHECK_ENDS: [usize; 6] = [3, 7, 9, 12, 14, 16];

/// SCTLR_ELx.SA's check of an SP base in RAX, before the address addition
/// as Arm checks it ([`MemoryChecks::stack_alignment`]).
pub(crate) const STACK_ALIGNMENT_CHECK: [u8; 6] = [
    0xa8, 15, // test al,15
    0x74, 2, // jz +2
    0x0f, 0x0b, // ud2
];

/// The end of each of the three host instructions of
/// [`STACK_ALIGNMENT_CHECK`], which the region cost gates count.
pub(crate) const STACK_ALIGNMENT_CHECK_ENDS: [usize; 3] = [2, 4, 6];

fn guest_range_check(code: &mut Vec<u8>, checks: MemoryChecks) {
    if checks.guest_range {
        code.extend(GUEST_RANGE_CHECK);
    }
}

/// The checks of an access's final address in RAX: the guest range, then
/// SCTLR_ELx.A against `unit`, the bytes of each element it transfers.
fn address_checks(code: &mut Vec<u8>, checks: MemoryChecks, unit: u8) {
    guest_range_check(code, checks);
    alignment_check(code, checks, unit);
}

/// SCTLR_ELx.A's check of the effective address in RAX against `unit`, the
/// bytes of each element the access transfers.
fn alignment_check(code: &mut Vec<u8>, checks: MemoryChecks, unit: u8) {
    if checks.alignment && unit > 1 {
        debug_assert!(unit.is_power_of_two() && unit <= 16);
        code.extend([0xa8, unit - 1, 0x74, 2, 0x0f, 0x0b]); // test al,unit-1; jz +2; ud2
    }
}

/// RAX is the access address and RDX the potential writeback. `unit` is the
/// bytes of each element the access transfers, which SCTLR_ELx.A checks.
fn memory_address(
    code: &mut Vec<u8>,
    checks: MemoryChecks,
    base: Register,
    displacement: i32,
    mode: AddressMode,
    unit: u8,
) {
    load(code, base);
    if base == Register::Sp && checks.stack_alignment {
        // Arm checks SP alignment before address addition. A native UD2 is a
        // mapped fault boundary, not guest exception delivery.
        code.extend(STACK_ALIGNMENT_CHECK);
    }
    code.extend([0x48, 0x8d, 0x90]); // lea rdx,[rax+disp32]: potential writeback
    code.extend(displacement.to_le_bytes());
    if mode != AddressMode::PostIndex {
        code.extend([0x48, 0x89, 0xd0]); // mov rax,rdx: effective address
    }
    address_checks(code, checks, unit);
}

fn memory_writeback(code: &mut Vec<u8>, base: Register, mode: AddressMode) {
    if mode != AddressMode::Offset {
        code.extend([0x48, 0x89, 0x97]); // mov [rdi+disp32],rdx
        code.extend(
            offset(base)
                .expect("memory base cannot be ZR")
                .to_le_bytes(),
        );
    }
}

/// Pair loads stage both values before committing either guest destination.
/// Pair stores expose completed first-element writes if the second access faults.
/// Concurrent/128-bit single-copy atomic semantics are outside this RAM profile.
#[allow(clippy::too_many_arguments)]
fn memory_pair(
    code: &mut Vec<u8>,
    checks: MemoryChecks,
    transfer: MemoryTransfer,
    bytes: u8,
    data: [Register; 2],
    base: Register,
    displacement: i32,
    mode: AddressMode,
) {
    memory_address(code, checks, base, displacement, mode, bytes);
    match transfer {
        MemoryTransfer::Store => {
            right_operand(code, data[0], Width::X64, Shift::Lsl, 0);
            if let Some(offset) = offset(data[1]) {
                code.extend([0x4c, 0x8b, 0x87]); // mov r8,[rdi+disp32]
                code.extend(offset.to_le_bytes());
            } else {
                code.extend([0x45, 0x31, 0xc0]); // xor r8d,r8d
            }
            let aligned = checks.stack_alignment
                && memory_store::aligned_immediate(base, displacement, mode, bytes);
            memory_store::emit(code, bytes, 0, memory_store::Source::Rcx, aligned);
            memory_store::emit(code, bytes, bytes, memory_store::Source::R8, aligned);
        }
        MemoryTransfer::Load { signed, width } => {
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([if signed { 0x63 } else { 0x8b }, 0x08]);
            code.extend([
                if width == Width::X64 { 0x4c } else { 0x44 },
                if signed { 0x63 } else { 0x8b },
                0x40,
                bytes,
            ]);
            // Commit only after both loads succeeded, including discarded/ZR
            // destinations. RAX/RDX retain address and potential writeback.
            for (register, rex, modrm) in [(data[0], 0x48, 0x8f), (data[1], 0x4c, 0x87)] {
                if let Some(offset) = offset(register) {
                    code.extend([rex, 0x89, modrm]);
                    code.extend(offset.to_le_bytes());
                }
            }
        }
    }
    memory_writeback(code, base, mode);
}

fn right_operand(code: &mut Vec<u8>, register: Register, width: Width, shift: Shift, amount: u8) {
    if let Some(offset) = offset(register) {
        code.extend([0x48, 0x8b, 0x8f]);
        code.extend(offset.to_le_bytes());
    } else {
        code.extend([0x31, 0xc9]);
    }
    if amount != 0 {
        if width == Width::X64 {
            code.push(0x48);
        }
        code.extend([
            0xc1,
            match shift {
                Shift::Lsl => 0xe1,
                Shift::Lsr => 0xe9,
                Shift::Asr => 0xf9,
                Shift::Ror => 0xc9,
            },
            amount,
        ]);
    }
}

fn jump(
    code: &mut Vec<u8>,
    opcode: Option<u8>,
    pc: GuestAddress,
    target: GuestAddress,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
) {
    if let Some(opcode) = opcode {
        code.extend([0x0f, opcode]);
    } else {
        code.push(0xe9);
    }
    fixups.push((pc, target, code.len()));
    code.extend([0; 4]);
}

/// Evaluate ARM conditions from saved NZCV, independent of incidental host flags.
fn condition(code: &mut Vec<u8>, condition: u8) -> Option<u8> {
    if condition >= 14 {
        return None;
    } // AL and NV both satisfy ConditionHolds.
    code.extend([0x8b, 0x87, 0, 1, 0, 0]); // mov eax,[rdi+256]
    let positive = match condition / 2 {
        0..=3 => {
            let bit = [30, 29, 31, 28][usize::from(condition / 2)];
            code.push(0xa9);
            code.extend((1u32 << bit).to_le_bytes());
            0x85 // flag set -> JNZ
        }
        4 => {
            code.push(0x25);
            code.extend(0x60000000u32.to_le_bytes());
            code.push(0x3d);
            code.extend(0x20000000u32.to_le_bytes());
            0x84 // C && !Z
        }
        5 => {
            code.extend([0x89, 0xc1, 0xc1, 0xe9, 3, 0x31, 0xc8, 0xa9]);
            code.extend(0x10000000u32.to_le_bytes());
            0x84 // N == V
        }
        _ => {
            code.extend([0x89, 0xc1, 0xc1, 0xe9, 3, 0x31, 0xc1, 0x81, 0xe1]);
            code.extend(0x10000000u32.to_le_bytes());
            code.push(0x25);
            code.extend(0x40000000u32.to_le_bytes());
            code.extend([0x09, 0xc8]);
            0x84 // !Z && N == V
        }
    };
    Some(positive ^ (condition & 1))
}

fn immediate(code: &mut Vec<u8>, value: u64) {
    code.extend([0x48, 0xb8]); // movabs rax,imm64
    code.extend(value.to_le_bytes());
}

fn nzcv(code: &mut Vec<u8>, subtract: bool) {
    const STATE_NZCV_OFFSET: u32 = core::mem::offset_of!(crate::GuestState, nzcv) as u32;
    capture_nzcv(code, subtract);
    code.extend([0x89, 0x87]); // mov dword [rdi+GuestState.nzcv],eax
    code.extend(STATE_NZCV_OFFSET.to_le_bytes());
}

/// SETcc into AL, AH, DL and DH: N | Z << 8 and C | V << 8.
const CAPTURE_SIGN_AL: [u8; 3] = [0x0f, 0x98, 0xc0];
const CAPTURE_ZERO_AH: [u8; 3] = [0x0f, 0x94, 0xc4];
const CAPTURE_BELOW_DL: [u8; 3] = [0x0f, 0x92, 0xc2];
const CAPTURE_ABOVE_EQUAL_DL: [u8; 3] = [0x0f, 0x93, 0xc2];
const CAPTURE_OVERFLOW_DH: [u8; 3] = [0x0f, 0x90, 0xc6];
const AND_EAX_IMM32: u8 = 0x25;
const AND_EDX_IMM32: [u8; 2] = [0x81, 0xe2];
const SHL_EDX_IMM8: [u8; 2] = [0xc1, 0xe2];
const OR_EAX_EDX: [u8; 2] = [0x09, 0xd0];
const IMUL_EAX_EAX_IMM32: [u8; 2] = [0x69, 0xc0];
/// The SETcc bytes' low bits.
const CAPTURED_BITS: u32 = 0x0101;
/// C and V move above N and Z: N | C << 2 | Z << 8 | V << 10.
const CAPTURE_CARRY_SHIFT: u8 = 2;
/// One product moves N (bit 0) to 31, Z (8) to 30, C (2) to 29 and V (10)
/// to 28. Every other partial product lands below bit 28 or above bit 31,
/// on a bit no other lands on, so nothing carries into NZCV.
const CAPTURE_MULTIPLIER: u32 = (1 << 31) | (1 << 22) | (1 << 27) | (1 << 18);
const CAPTURE_NZCV_MASK: u32 = 0xf000_0000;

/// The host flags as an Arm NZCV word in EAX, without a data-dependent
/// branch or an instruction outside Intel's data operand independent timing
/// list (SETcc, AND, SHL, OR, IMUL). `borrow` takes C as an Arm subtraction
/// does, the complement of the host carry. Clobbers RDX; RCX is intact.
pub(crate) fn capture_nzcv(code: &mut Vec<u8>, borrow: bool) {
    code.extend(CAPTURE_SIGN_AL);
    code.extend(CAPTURE_ZERO_AH);
    code.extend(if borrow {
        CAPTURE_ABOVE_EQUAL_DL
    } else {
        CAPTURE_BELOW_DL
    });
    code.extend(CAPTURE_OVERFLOW_DH);
    code.push(AND_EAX_IMM32);
    code.extend(CAPTURED_BITS.to_le_bytes());
    code.extend(AND_EDX_IMM32);
    code.extend(CAPTURED_BITS.to_le_bytes());
    code.extend(SHL_EDX_IMM8);
    code.push(CAPTURE_CARRY_SHIFT);
    code.extend(OR_EAX_EDX);
    code.extend(IMUL_EAX_EAX_IMM32);
    code.extend(CAPTURE_MULTIPLIER.to_le_bytes());
    code.push(AND_EAX_IMM32);
    code.extend(CAPTURE_NZCV_MASK.to_le_bytes());
}

/// Shared semantic emission. Block compilation handles control transfers itself.
pub(crate) fn emit_instruction(
    code: &mut Vec<u8>,
    instruction: &Instruction,
    fixups: &mut Vec<(GuestAddress, GuestAddress, usize)>,
    target: crate::TargetCpu,
    checks: MemoryChecks,
) {
    match instruction.operation {
        Operation::FloatingPoint(_) => {
            unreachable!("numerical instructions require block emission")
        }
        Operation::FloatingPointRegister(operand) => fp_register::emit(code, &operand),
        Operation::Simd(operand) => simd::emit_for_target(code, &operand, target, checks),
        Operation::Bitfield(operand) => bitfield::emit(code, &operand),
        Operation::PcRelative(operand) => pc_relative::emit(code, &operand),
        Operation::ConditionalSelect(operand) => conditional_select::emit(code, &operand),
        Operation::ConditionalCompare(operand) => conditional_select::emit_compare(code, &operand),
        Operation::Crc(operand) => crc::emit(code, &operand, target),
        Operation::Flags(operand) => flags::emit(code, &operand),
        Operation::Synchronization(operand) => system::synchronization::emit(code, &operand)
            .expect("decoder admits only context-independent synchronization"),
        Operation::IntegerMath(operand) => integer_math::emit(code, &operand, target),
        Operation::IntegerMinMax(operand) => integer_minmax::emit(code, &operand),
        Operation::IntegerUnary(operand) => integer_unary::emit(code, &operand, target),
        Operation::Literal(operand) => literal::emit(code, &operand, checks),
        Operation::MemoryPair {
            transfer,
            bytes,
            data,
            base,
            displacement,
            mode,
        } => {
            memory_pair(
                code,
                checks,
                transfer,
                bytes,
                data,
                base,
                displacement,
                mode,
            );
        }
        Operation::Memory {
            transfer,
            bytes,
            data,
            base,
            displacement,
            mode,
        } => {
            memory(
                code,
                checks,
                transfer,
                bytes,
                data,
                base,
                displacement,
                mode,
            );
        }
        Operation::Branch { target } => jump(code, None, instruction.pc, target, fixups),
        Operation::BranchCondition {
            target,
            condition: cond,
        } => {
            let opcode = condition(code, cond);
            jump(code, opcode, instruction.pc, target, fixups);
        }
        Operation::BranchZero {
            target,
            source,
            width,
            nonzero,
        } => {
            load(code, source);
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([0x85, 0xc0]);
            jump(
                code,
                Some(if nonzero { 0x85 } else { 0x84 }),
                instruction.pc,
                target,
                fixups,
            );
        }
        Operation::BranchBit {
            target,
            source,
            bit,
            nonzero,
        } => {
            load(code, source);
            code.extend([0x48, 0x0f, 0xba, 0xe0, bit]); // bt rax,imm8
            jump(
                code,
                Some(if nonzero { 0x82 } else { 0x83 }),
                instruction.pc,
                target,
                fixups,
            );
        }
        Operation::AddSubCarry {
            width,
            subtract,
            flags,
            destination,
            left,
            right,
        } => {
            load(code, left);
            right_operand(code, right, width, Shift::Lsl, 0);
            // Arm's SBC is AddWithCarry(left, NOT(right), C): ADC of the
            // complement, whose host CF and OF are Arm's C and V. (CMC is
            // not on Intel's data operand independent timing list.)
            if subtract {
                if width == Width::X64 {
                    code.push(0x48);
                }
                code.extend([0xf7, 0xd1]); // not (e/r)cx
            }
            // Recover guest C after operand loads, including XOR-based
            // ZR loads that clobber host flags.
            code.extend([0x0f, 0xba, 0xa7, 0, 1, 0, 0, 29]); // bt [rdi+256],29
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([0x11, 0xc8]); // adc (e/r)ax,(e/r)cx
            store(code, destination);
            if flags {
                nzcv(code, false);
            }
        }
        Operation::AddSubRegister {
            width,
            subtract,
            flags,
            destination,
            left,
            right,
            shift,
            amount,
        } => {
            load(code, left);
            right_operand(code, right, width, shift, amount);
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([if subtract { 0x29 } else { 0x01 }, 0xc8]);
            store(code, destination);
            if flags {
                nzcv(code, subtract);
            }
        }
        Operation::AddSubExtended {
            width,
            subtract,
            flags,
            destination,
            left,
            right,
            extend,
            amount,
        } => {
            // Read both operands before a possibly overlapping destination/SP write.
            load(code, left);
            right_operand(code, right, Width::X64, Shift::Lsl, 0);
            match extend {
                RegisterExtend::Uxtb => code.extend([0x0f, 0xb6, 0xc9]), // movzx ecx,cl
                RegisterExtend::Uxth => code.extend([0x0f, 0xb7, 0xc9]), // movzx ecx,cx
                RegisterExtend::Uxtw => code.extend([0x89, 0xc9]),       // mov ecx,ecx
                RegisterExtend::Sxtb => code.extend([0x48, 0x0f, 0xbe, 0xc9]),
                RegisterExtend::Sxth => code.extend([0x48, 0x0f, 0xbf, 0xc9]),
                RegisterExtend::Sxtw => code.extend([0x48, 0x63, 0xc9]),
                RegisterExtend::Uxtx | RegisterExtend::Sxtx => {}
            }
            if amount != 0 {
                code.extend([0x48, 0xc1, 0xe1, amount]);
            }
            if width == Width::X64 {
                code.push(0x48);
            }
            // W32 arithmetic truncates both operands and zero-extends even WSP.
            code.extend([if subtract { 0x29 } else { 0x01 }, 0xc8]);
            store(code, destination);
            if flags {
                nzcv(code, subtract);
            }
        }
        Operation::MemoryRegisterOffset(operand) => register_offset::emit(code, &operand, checks),
        Operation::MemoryNonTemporal(operand) => non_temporal::emit(code, &operand, checks),
        Operation::MemoryUnprivileged(operand) => unprivileged::emit(code, &operand, checks),
        Operation::TagArithmetic(operand) => tag_arithmetic::emit(code, &operand),
        Operation::Atomic(operand) => atomic::emit(code, &operand, target, checks),
        Operation::Ordered(operand) => ordered::emit(code, &operand, target, checks),
        Operation::Prefetch(operand) => prefetch::emit(code, &operand),
        Operation::LogicalImmediate {
            width,
            kind,
            flags,
            destination,
            source,
            immediate,
        } => {
            load(code, source);
            code.extend([0x48, 0xb9]); // movabs rcx,logical bitmask
            code.extend(immediate.to_le_bytes());
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([
                match kind {
                    Logical::And => 0x21,
                    Logical::Or => 0x09,
                    Logical::Xor => 0x31,
                },
                0xc8,
            ]);
            store(code, destination); // MOV preserves the logical result flags.
            if flags {
                nzcv(code, false); // AND clears CF/OF, matching ARM C/V=0.
            }
        }
        Operation::LogicalRegister {
            width,
            kind,
            invert,
            flags,
            destination,
            left,
            right,
            shift,
            amount,
        } => {
            load(code, left);
            right_operand(code, right, width, shift, amount);
            if invert {
                if width == Width::X64 {
                    code.push(0x48);
                }
                code.extend([0xf7, 0xd1]);
            }
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([
                match kind {
                    Logical::And => 0x21,
                    Logical::Or => 0x09,
                    Logical::Xor => 0x31,
                },
                0xc8,
            ]);
            store(code, destination);
            if flags {
                nzcv(code, false);
            } // AND clears host CF/OF, matching ARM C/V=0.
        }
        Operation::Return => code.push(0xc3),
        Operation::Exclusive(_) => unreachable!("exclusive requires checked context emitter"),
        Operation::CheckedPointer(_) => {
            unreachable!("CPA arithmetic requires checked context emitter")
        }
        Operation::Nop => code.push(0x90),
        Operation::MoveWide {
            width,
            kind,
            destination,
            immediate: value,
            shift,
        } => {
            let value = u64::from(value) << shift;
            match kind {
                WideMove::Zero => immediate(code, value),
                WideMove::Not => immediate(code, !value),
                WideMove::Keep => {
                    load(code, destination);
                    code.extend([0x48, 0xb9]); // movabs rcx,mask
                    code.extend((!(0xffffu64 << shift)).to_le_bytes());
                    code.extend([0x48, 0x21, 0xc8, 0x48, 0xb9]); // and rax,rcx; movabs rcx,value
                    code.extend(value.to_le_bytes());
                    code.extend([0x48, 0x09, 0xc8]);
                }
            }
            if width == Width::W32 {
                code.extend([0x89, 0xc0]);
            } // mov eax,eax: zero-extend
            store(code, destination);
        }
        Operation::AddSub {
            width,
            subtract,
            flags,
            destination,
            source,
            immediate,
        } => {
            load(code, source);
            if width == Width::X64 {
                code.push(0x48);
            }
            code.extend([0x81, if subtract { 0xe8 } else { 0xc0 }]);
            code.extend(immediate.to_le_bytes());
            store(code, destination); // MOV leaves arithmetic flags unchanged.
            if flags {
                nzcv(code, subtract);
            }
        }
    }
}

impl Backend<Instruction> for Emitter {
    fn emit(&self, instructions: &[Instruction]) -> Result<NativeBlock, UnsupportedReason> {
        self.emit_for_target(instructions, crate::TargetCpu::Baseline)
    }
}
impl Emitter {
    pub fn emit_for_target(
        &self,
        instructions: &[Instruction],
        target: crate::TargetCpu,
    ) -> Result<NativeBlock, UnsupportedReason> {
        let mut block = NativeBlock {
            x86_64_code: vec![],
            source_map: vec![],
        };
        let code = &mut block.x86_64_code;
        let mut fixups = vec![];
        for instruction in instructions {
            validate_target(instruction, target)?;
            if matches!(instruction.operation, Operation::FloatingPoint(_)) {
                return Err(UnsupportedReason::NumericalRuntimeRequired {
                    address: instruction.pc,
                });
            }
            block.source_map.push((instruction.pc, code.len()));
            emit_instruction(
                code,
                instruction,
                &mut fixups,
                target,
                MemoryChecks::DEFAULT,
            );
        }
        let offsets: alloc::collections::BTreeMap<_, _> = block
            .source_map
            .iter()
            .map(|(pc, offset)| (pc.0, *offset))
            .collect();
        for (pc, target, displacement) in fixups {
            let error = || UnsupportedReason::UnresolvedDirectTarget {
                address: pc,
                target,
            };
            let destination = *offsets.get(&target.0).ok_or_else(error)?;
            let relative = destination as i128 - (displacement + 4) as i128;
            let relative = i32::try_from(relative).map_err(|_| error())?;
            code[displacement..displacement + 4].copy_from_slice(&relative.to_le_bytes());
        }
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::system::synchronization::{
        Operation as Synchronization, Requirement, Scope, WaitKind,
    };

    /// The check runs on the host and passes exactly the addresses whose
    /// bits 63:48 are all clear or all set.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn the_guest_range_check_passes_exactly_the_two_48_bit_ranges() {
        use core::ffi::c_void;
        unsafe extern "C" {
            fn mmap(
                address: *mut c_void,
                bytes: usize,
                protection: i32,
                flags: i32,
                fd: i32,
                offset: i64,
            ) -> *mut c_void;
            fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
            fn munmap(address: *mut c_void, bytes: usize) -> i32;
        }
        #[cfg(target_os = "macos")]
        const MAP_ANONYMOUS: i32 = 0x1000;
        #[cfg(target_os = "linux")]
        const MAP_ANONYMOUS: i32 = 0x20;
        const PAGE: usize = 4096;
        let (check, trap) = GUEST_RANGE_CHECK.split_at(GUEST_RANGE_CHECK.len() - 2);
        assert_eq!(trap, [0x0f, 0x0b]);
        assert_eq!(GUEST_RANGE_CHECK_ENDS[4], check.len());
        assert_eq!(GUEST_RANGE_CHECK_ENDS[5], GUEST_RANGE_CHECK.len());
        // mov rax,rdi; the check with `xor eax,eax` (a failure, also two
        // bytes) where its UD2 is; ret.
        let mut code = vec![0x48, 0x89, 0xf8];
        code.extend(check);
        code.extend([0x31, 0xc0, 0xc3]);
        // SAFETY: private anonymous memory, RX after the copy and unmapped
        // after the calls; the code touches no memory.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let passes = |address: u64| {
                let entry: unsafe extern "sysv64" fn(u64) -> u64 = core::mem::transmute(page);
                let result = entry(address);
                assert!(result == address || result == 0);
                result == address
            };
            for (address, expected) in [
                (1, true),
                (0x0000_ffff_ffff_ffff, true),
                (0xffff_0000_0000_0000, true),
                (u64::MAX, true),
                (0x0001_0000_0000_0000, false),
                // Stela's window, PML5 entry 64.
                (0x0040_0000_0000_0000, false),
                (0x00ff_ffff_ffff_ffff, false),
                (0xff00_0000_0000_0000, false),
                (0xfffe_ffff_ffff_ffff, false),
                (0x7fff_ffff_ffff_ffff, false),
                (0x8000_0000_0000_0000, false),
                // A tagged pointer.
                (0x0f00_0000_0000_1234, false),
            ] {
                assert_eq!(passes(address), expected, "{address:#x}");
            }
            let mut seed = 0x9e37_79b9_7f4a_7c15u64;
            for _ in 0..4096 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                // Bias half the samples to the ranges' edges.
                let top = match seed >> 62 {
                    0 => 0,
                    1 => 0xffff,
                    _ => (seed >> 16) & 0xffff,
                };
                let address = top << 48 | (seed.rotate_left(17) & 0xffff_ffff_ffff) | 1;
                assert_eq!(
                    passes(address),
                    matches!(address >> 48, 0 | 0xffff),
                    "{address:#x}"
                );
            }
            assert_eq!(munmap(page, PAGE), 0);
        }
    }

    #[test]
    fn constructed_context_operations_return_an_explicit_error() {
        const BARRIER_OPTION_OSH: u8 = 3;
        const BARRIER_OPTION_SY: u8 = 15;
        const BTI_JC_TARGETS: u8 = 3;
        const RESERVED_HINT_IMMEDIATE: u8 = 127;
        let pc = GuestAddress(0x1000);
        for operation in [
            Synchronization::DataCompletion {
                option: BARRIER_OPTION_OSH,
                scope: Scope::OuterShareable,
                requirement: Requirement::All,
                nxs: false,
            },
            Synchronization::InstructionSynchronization {
                option: BARRIER_OPTION_SY,
            },
            Synchronization::StoreBypassBarrier { physical: false },
            Synchronization::StoreBypassBarrier { physical: true },
            Synchronization::BranchTarget {
                targets: BTI_JC_TARGETS,
            },
            Synchronization::Wait {
                kind: WaitKind::Event,
                timeout_register: None,
            },
            Synchronization::SendEvent { local: false },
            Synchronization::ErrorSynchronization,
            Synchronization::TraceSynchronization,
            Synchronization::OtherHint {
                immediate: RESERVED_HINT_IMMEDIATE,
            },
        ] {
            let instructions = [
                Instruction {
                    pc,
                    operation: Operation::Nop,
                },
                Instruction {
                    pc: GuestAddress(pc.0 + size_of::<u32>() as u64),
                    operation: Operation::Synchronization(operation),
                },
            ];
            assert!(
                matches!(Emitter.emit_for_target(&instructions, crate::TargetCpu::Baseline),
            Err(UnsupportedReason::PrivilegedOperation { address }) if address == instructions[1].pc)
            );
        }
    }

    /// The capture's arithmetic on every flag combination: the SETcc bytes
    /// at their register positions, shifted, combined, multiplied and masked.
    #[test]
    fn the_flag_capture_packs_every_combination_into_nzcv() {
        for flags in 0u32..16 {
            let [n, z, c, v] = [3, 2, 1, 0].map(|bit| (flags >> bit) & 1);
            let accumulator = (n | z << 8) & CAPTURED_BITS;
            let data = (c | v << 8) & CAPTURED_BITS;
            let combined = accumulator | data << CAPTURE_CARRY_SHIFT;
            let packed = combined.wrapping_mul(CAPTURE_MULTIPLIER) & CAPTURE_NZCV_MASK;
            assert_eq!(packed, flags << 28, "NZCV {flags:#06b}");
        }
        let mut code = Vec::new();
        capture_nzcv(&mut code, false);
        let mut borrow = Vec::new();
        capture_nzcv(&mut borrow, true);
        // Only the carry's SETcc differs.
        assert_eq!(code.len(), borrow.len());
        assert_eq!(code[6..9], CAPTURE_BELOW_DL);
        assert_eq!(borrow[6..9], CAPTURE_ABOVE_EQUAL_DL);
    }
}
