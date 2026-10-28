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

pub(crate) const NOP: u8 = 0x90;

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
pub(crate) mod asm;
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
pub(crate) use region::AllocationStats;
mod register_offset;
pub mod register_read;
mod scalable;
mod scalable_matrix;
pub(crate) mod shared_memory;
mod simd;
mod stack_alignment;
pub(crate) use simd::CheckedMemoryOperand as CheckedFixedMemoryOperand;
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
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
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
    load_with(&mut asm::Asm::new(code), register);
}

/// RAX = the guest register (zero for XZR), from the frame at RDI.
fn load_with(asm: &mut asm::Asm, register: Register) {
    use asm::{Alu, Gpr, Mem, Size};
    match offset(register) {
        Some(offset) => asm.mov_load(
            Size::Qword,
            Gpr::Rax,
            Mem::base_disp32(Gpr::Rdi, offset as i32),
        ),
        None => asm.alu(Alu::Xor, Size::Dword, Gpr::Rax, Gpr::Rax),
    }
}

fn store(code: &mut Vec<u8>, register: Register) {
    store_with(&mut asm::Asm::new(code), register);
}

/// The guest register (nothing for XZR) = RAX, in the frame at RDI.
fn store_with(asm: &mut asm::Asm, register: Register) {
    use asm::{Gpr, Mem, Size};
    if let Some(offset) = offset(register) {
        asm.mov_store(
            Size::Qword,
            Mem::base_disp32(Gpr::Rdi, offset as i32),
            Gpr::Rax,
        );
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
    let access = Access::of(transfer == MemoryTransfer::Store, bytes.into());
    memory_address(code, checks, base, displacement, mode, bytes, access);
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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
    /// Every access checks its address against the guest's native ranges
    /// ([`RangeCheck`]). `SystemModeV1` sets it for every block, whatever
    /// the engine asks, and no other profile does.
    pub(crate) guest_range: bool,
    /// No other agent accesses guest memory while the block runs: the
    /// system engine runs one PE at a time, and no device or host agent
    /// writes guest RAM meanwhile. Atomics, ordered accesses and barriers
    /// then need no LOCK, XCHG, MFENCE or 16-byte snapshot
    /// ([`plain_ordering`]). `SystemModeV1` sets it for every block, and no
    /// other profile does.
    pub(crate) single_agent: bool,
    /// FEAT_CSV3: every access checks the guest range, those
    /// [`guest_range`] would leave to an earlier check through the same base
    /// included. A mispredicted check then never runs an access whose
    /// address its own check did not mask ([`RangeCheck`]).
    pub every_access_masked: bool,
    /// An earlier access of the block checked SP's alignment, which holds
    /// since ([`stack_alignment::checks`]): an access through SP relies on
    /// [`Self::stack_alignment`] without its own check.
    pub(crate) stack_checked: bool,
    /// The guest's native ranges on this host's placement
    /// (docs/design/system.md, "Host placement").
    pub range: RangeCheck,
    /// The translated variant (docs/design/system.md, "Host placement"):
    /// every access checks its address, as with
    /// [`Self::every_access_masked`], and a failed check calls the engine's
    /// translation helper through [`Self::translation_helper`] in place of
    /// the UD2.
    pub translated: bool,
    /// The address of the slot holding the translation helper's address,
    /// for the translated variant.
    pub translation_helper: u64,
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
        every_access_masked: false,
        stack_checked: false,
        range: RangeCheck::FIVE_LEVEL,
        translated: false,
        translation_helper: 0,
    };
    /// SCTLR_ELx's checks, as the system-mode engine selects them, and
    /// whether every access masks its address
    /// ([`Self::every_access_masked`]).
    pub const fn system(
        stack_alignment: bool,
        alignment: bool,
        ordered_granule: bool,
        every_access_masked: bool,
    ) -> Self {
        Self {
            stack_alignment,
            alignment,
            ordered_granule,
            guest_range: false,
            single_agent: false,
            every_access_masked,
            stack_checked: false,
            range: RangeCheck::FIVE_LEVEL,
            translated: false,
            translation_helper: 0,
        }
    }

    /// These checks on a host whose placement gives the guest `range`.
    pub const fn with_range(self, range: RangeCheck) -> Self {
        assert!(range.valid(), "a range check's fields fit its encoding");
        Self { range, ..self }
    }

    /// These checks in the translated variant, calling the helper whose
    /// address the slot at `helper` holds ([`Self::translated`]).
    pub const fn with_translation(self, helper: u64) -> Self {
        Self {
            translated: true,
            translation_helper: helper,
            ..self
        }
    }

    /// Whether every access checks the guest range, none left to an earlier
    /// check through the same base.
    pub(crate) const fn checks_every_access(self) -> bool {
        self.every_access_masked || self.translated
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
/// native ranges, the only parts of the host address space its shadow
/// tables map (docs/design/system.md, "Host placement"):
///
/// ```text
/// mov rcx,rax; sar rcx,shift; add ecx,bias (inc ecx for 1); cmp ecx,bound
/// jbe ok; ud2; ok: mov rcx,masked; cmova rax,rcx
/// ```
///
/// Five-level paging (LA57) gives the guest PML5 entries 0 and 511, so bits
/// 63:48 must be all clear or all set: shift 48, bias 1, bound 1. A
/// four-level host gives it the lower half and `[U, 2^64)`, with
/// `U = 0xffff_8000_0000_0000 + m * 2^41` and Stela's window and guard in
/// the `m` slices of 2 TiB below `U`: shift 41, bias `64 - m`, bound
/// `127 - m`. Any other address raises #UD before the access, which the
/// engine turns into the fault the guest's translation gives it, or into
/// the translated variant. Stela's memory is then out of a guest access's
/// reach. RCX and host flags are scratch.
///
/// The check's branch can be mispredicted, so past it a CMOVA, which uses
/// the comparison's flags and no prediction, replaces an out-of-range RAX
/// with `masked`, an unmapped address 2^40 or more from any mapped one, so
/// that no access's extent leaves it: an access that speculation runs past
/// a failed check never reaches Stela's memory (Intel's and AMD's
/// bounds-check bypass guidance). A passed check leaves RAX unchanged, and
/// the UD2 runs before the CMOVA with the guest's address.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RangeCheck {
    pub shift: u8,
    pub bias: u8,
    pub bound: u8,
    pub masked: u64,
}

/// The upper half's first address on a four-level host.
const UPPER_HALF: u64 = 0xffff_8000_0000_0000;
/// A four-level check's slices of 2 TiB.
const SLICE_SHIFT: u8 = 41;
/// The slices of each half.
const HALF_SLICES: u8 = 64;
/// The masked address's distance below `U`, inside the guard.
const MASK_BELOW_UPPER: u64 = 1 << 40;
/// The largest positive sign-extended imm8.
const IMM8_MAX: u8 = 127;
const OPCODE_INC: u8 = 1;

impl RangeCheck {
    /// Five-level paging (LA57): bits 63:48 all clear or all set; a failed
    /// check's masked address is PML5 entry 1, which no shadow root maps.
    pub const FIVE_LEVEL: Self = Self {
        shift: 48,
        bias: 1,
        bound: 1,
        masked: 1 << 48,
    };

    /// Four-level paging with Stela's window and guard in the `slices`
    /// slices of 2 TiB below `U` (2 to 63): the window's, then the guard,
    /// the whole slice below `U`, which takes the masked address.
    pub const fn four_level(slices: u8) -> Self {
        assert!(
            slices >= 2 && slices < HALF_SLICES,
            "a four-level placement takes 2 to 63 slices: at least one for \
             the window and the guard, the whole slice below U"
        );
        let upper = UPPER_HALF + ((slices as u64) << SLICE_SHIFT);
        Self {
            shift: SLICE_SHIFT,
            bias: HALF_SLICES - slices,
            bound: IMM8_MAX - slices,
            masked: upper - MASK_BELOW_UPPER,
        }
    }

    /// Whether the fields fit the check's encoding: a shift of an address
    /// and a bias and bound that are positive imm8s.
    pub const fn valid(self) -> bool {
        self.shift < u64::BITS as u8 && self.bias <= IMM8_MAX && self.bound <= IMM8_MAX
    }

    /// The bytes before the failure: the shift, the bias, the comparison
    /// and the branch over the failure, of `failure` bytes.
    fn test(self, code: &mut Vec<u8>, failure: u8) {
        code.extend([0x48, 0x89, 0xc1, 0x48, 0xc1, 0xf9, self.shift]); // mov rcx,rax; sar rcx,shift
        if self.bias == OPCODE_INC {
            code.extend([0xff, 0xc1]); // inc ecx
        } else {
            code.extend([0x83, 0xc1, self.bias]); // add ecx,bias
        }
        code.extend([0x83, 0xf9, self.bound, 0x76, failure]); // cmp ecx,bound; jbe past the failure
    }

    /// The mask after the check.
    fn mask(self, code: &mut Vec<u8>) {
        code.extend([0x48, 0xb9]); // mov rcx,masked
        code.extend(self.masked.to_le_bytes());
        code.extend([0x48, 0x0f, 0x47, 0xc1]); // cmova rax,rcx
    }

    /// The check with a UD2 failure.
    pub(crate) fn emit(self, code: &mut Vec<u8>) {
        self.test(code, UD2.len() as u8);
        code.extend(UD2);
        self.mask(code);
    }

    /// The translated variant's check: a failure calls the translation
    /// helper whose address the slot at `helper` holds, with the guest
    /// address in RCX and `access` in the two bytes after the call; the
    /// helper returns past them with the host address of the access in RAX,
    /// which skips the mask (docs/design/system.md, "Host placement").
    pub(crate) fn emit_translated(self, code: &mut Vec<u8>, helper: u64, access: Access) {
        self.test(code, TRANSLATION_CALL_BYTES);
        code.extend([0x48, 0x89, 0xc1, 0x48, 0xa1]); // mov rcx,rax; movabs rax,[helper]
        code.extend(helper.to_le_bytes());
        code.extend([0xff, 0xd0, access.bytes, access.flags]); // call rax; the access
        code.extend([0xeb, MASK_BYTES]); // jmp past the mask
        self.mask(code);
    }

    /// [`Self::emit`]'s bytes.
    #[cfg(test)]
    pub(crate) fn code(self) -> Vec<u8> {
        let mut code = Vec::new();
        self.emit(&mut code);
        code
    }

    /// If `code` starts with a check of any placement, its length and the
    /// end of each of its eight host instructions, which the region cost
    /// gates count one by one.
    pub(crate) fn at(code: &[u8]) -> Option<(usize, &'static [usize])> {
        // The ends with INC and with ADD, with a UD2 and with the
        // translated variant's call (whose two access bytes count as one).
        const ENDS: [[&[usize]; 2]; 2] = [
            [
                &[3, 7, 9, 12, 14, 16, 26, 30],
                &[3, 7, 9, 12, 14, 17, 27, 29, 31, 33, 43, 47],
            ],
            [
                &[3, 7, 10, 13, 15, 17, 27, 31],
                &[3, 7, 10, 13, 15, 18, 28, 30, 32, 34, 44, 48],
            ],
        ];
        let [0x48, 0x89, 0xc1, 0x48, 0xc1, 0xf9, shift, rest @ ..] = code else {
            return None;
        };
        let (add, rest) = match rest {
            [0xff, 0xc1, rest @ ..] => (0, rest),
            [0x83, 0xc1, _, rest @ ..] => (1, rest),
            _ => return None,
        };
        let [0x83, 0xf9, bound, 0x76, failure, rest @ ..] = rest else {
            return None;
        };
        let (translated, rest) = match (*failure, rest) {
            (2, [0x0f, 0x0b, rest @ ..]) => (0, rest),
            (TRANSLATION_CALL_BYTES, [0x48, 0x89, 0xc1, 0x48, 0xa1, rest @ ..]) => {
                let [
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    0xff,
                    0xd0,
                    _,
                    _,
                    0xeb,
                    MASK_BYTES,
                    rest @ ..,
                ] = rest
                else {
                    return None;
                };
                (1, rest)
            }
            _ => return None,
        };
        let [
            0x48,
            0xb9,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            0x48,
            0x0f,
            0x47,
            0xc1,
            ..,
        ] = rest
        else {
            return None;
        };
        if *shift >= u64::BITS as u8 || *bound > IMM8_MAX {
            return None;
        }
        let ends = ENDS[add][translated];
        Some((ends[ends.len() - 1], ends))
    }
}

const UD2: [u8; 2] = [0x0f, 0x0b];
/// The translated variant's call, from `mov rcx,rax` through the jump
/// past the mask.
const TRANSLATION_CALL_BYTES: u8 = 19;
/// `mov rcx,masked; cmova rax,rcx`.
const MASK_BYTES: u8 = 14;

/// What a guest access makes, which the translated variant's helper
/// translates its address for: the bytes it covers from its address
/// (saturating at 255: a larger access, DC ZVA's, is aligned to its size
/// and lies in one page) and whether it writes, is unprivileged or is an
/// atomic or exclusive access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Access {
    bytes: u8,
    flags: u8,
}

impl Access {
    const WRITE: u8 = 1;
    const ATOMIC: u8 = 4;

    /// An access of `bytes` that writes if `write`, else reads.
    pub(crate) const fn of(write: bool, bytes: u16) -> Self {
        Self {
            bytes: if bytes > u8::MAX as u16 {
                u8::MAX
            } else {
                bytes as u8
            },
            flags: if write { Self::WRITE } else { 0 },
        }
    }
    pub(crate) const fn read(bytes: u16) -> Self {
        Self::of(false, bytes)
    }
    pub(crate) const fn write(bytes: u16) -> Self {
        Self::of(true, bytes)
    }
    /// The same access, made by an atomic instruction, which needs the
    /// location itself.
    pub(crate) const fn atomic(self) -> Self {
        Self {
            flags: self.flags | Self::ATOMIC,
            ..self
        }
    }
}

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

/// The guest range check of `access`'s address in RAX, in the variant
/// `checks` selects.
pub(crate) fn range_check(code: &mut Vec<u8>, checks: MemoryChecks, access: Access) {
    if checks.translated {
        checks
            .range
            .emit_translated(code, checks.translation_helper, access);
    } else {
        checks.range.emit(code);
    }
}

fn guest_range_check(code: &mut Vec<u8>, checks: MemoryChecks, access: Access) {
    if checks.guest_range {
        range_check(code, checks, access);
    }
}

/// The checks of `access`'s final address in RAX: the guest range, then
/// SCTLR_ELx.A against `unit`, the bytes of each element it transfers. The
/// translated variant's host address keeps the guest address's offset in
/// its page, so the alignment checks see the same low bits.
fn address_checks(code: &mut Vec<u8>, checks: MemoryChecks, unit: u8, access: Access) {
    guest_range_check(code, checks, access);
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

/// RAX is the access address and, for pre- and post-index forms, RDX the
/// pending writeback ([`address_add`]). `unit` is the bytes of each element
/// the access transfers, which SCTLR_ELx.A checks, and `access` the whole
/// access.
#[allow(clippy::too_many_arguments)]
fn memory_address(
    code: &mut Vec<u8>,
    checks: MemoryChecks,
    base: Register,
    displacement: i32,
    mode: AddressMode,
    unit: u8,
    access: Access,
) {
    load(code, base);
    if base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
        // Arm checks SP alignment before address addition. A native UD2 is a
        // mapped fault boundary, not guest exception delivery.
        code.extend(STACK_ALIGNMENT_CHECK);
    }
    address_add(code, displacement, mode);
    address_checks(code, checks, unit, access);
}

const LEA_RAX_RAX_DISP8: [u8; 3] = [0x48, 0x8d, 0x40];
const LEA_RAX_RAX_DISP32: [u8; 3] = [0x48, 0x8d, 0x80];
const LEA_RDX_RAX_DISP8: [u8; 3] = [0x48, 0x8d, 0x50];
const LEA_RDX_RAX_DISP32: [u8; 3] = [0x48, 0x8d, 0x90];
const MOV_RDX_RAX: [u8; 3] = [0x48, 0x89, 0xc2];
const MOV_RAX_RDX: [u8; 3] = [0x48, 0x89, 0xd0];

/// An immediate offset added to the base in RAX, modulo 2^64 and without
/// touching host flags: RAX becomes the access address, and pre- and
/// post-index forms leave the pending writeback in RDX. An Offset access
/// leaves RDX unspecified and emits nothing for a zero offset.
pub(crate) fn address_add(code: &mut Vec<u8>, displacement: i32, mode: AddressMode) {
    let offset = mode == AddressMode::Offset;
    if displacement == 0 {
        if !offset {
            code.extend(MOV_RDX_RAX);
        }
        return;
    }
    let compact = i8::try_from(displacement).ok();
    code.extend(match (offset, compact.is_some()) {
        (true, true) => LEA_RAX_RAX_DISP8,
        (true, false) => LEA_RAX_RAX_DISP32,
        (false, true) => LEA_RDX_RAX_DISP8,
        (false, false) => LEA_RDX_RAX_DISP32,
    });
    match compact {
        Some(value) => code.push(value as u8),
        None => code.extend(displacement.to_le_bytes()),
    }
    if mode == AddressMode::PreIndex {
        code.extend(MOV_RAX_RDX);
    }
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
    let access = Access::of(transfer == MemoryTransfer::Store, 2 * u16::from(bytes));
    memory_address(code, checks, base, displacement, mode, bytes, access);
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
    right_operand_with(&mut asm::Asm::new(code), register, width, shift, amount);
}

/// RCX = the guest register (zero for XZR) shifted by `amount`.
fn right_operand_with(
    asm: &mut asm::Asm,
    register: Register,
    width: Width,
    shift: Shift,
    amount: u8,
) {
    use asm::{Alu, Gpr, Mem, ShiftOp, Size};
    match offset(register) {
        Some(offset) => asm.mov_load(
            Size::Qword,
            Gpr::Rcx,
            Mem::base_disp32(Gpr::Rdi, offset as i32),
        ),
        None => asm.alu(Alu::Xor, Size::Dword, Gpr::Rcx, Gpr::Rcx),
    }
    if amount != 0 {
        let op = match shift {
            Shift::Lsl => ShiftOp::Shl,
            Shift::Lsr => ShiftOp::Shr,
            Shift::Asr => ShiftOp::Sar,
            Shift::Ror => ShiftOp::Ror,
        };
        asm.shift_imm(op, Size::of(width == Width::X64), Gpr::Rcx, amount);
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
    condition_of(code, condition, false)
}

/// [`condition`], from the NZCV word already in EAX when `loaded`
/// ([`Rax::Nzcv`]). Clobbers EAX and ECX.
fn condition_of(code: &mut Vec<u8>, condition: u8, loaded: bool) -> Option<u8> {
    if condition >= 14 {
        return None;
    } // AL and NV both satisfy ConditionHolds.
    if !loaded {
        code.extend([0x8b, 0x87, 0, 1, 0, 0]); // mov eax,[rdi+256]
    }
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
        group => {
            // EAX ^= EAX >> 3 leaves N ^ V in bit 28 and Z in bit 30, whatever
            // the bits below NZCV hold.
            code.extend([0x89, 0xc1, 0xc1, 0xe9, 3, 0x31, 0xc8, 0xa9]);
            let mask: u32 = if group == 5 { 0x10000000 } else { 0x50000000 };
            code.extend(mask.to_le_bytes());
            0x84 // N == V, and for GT !Z
        }
    };
    Some(positive ^ (condition & 1))
}

/// What RAX holds after an instruction's emission, for the next one to
/// use instead of reloading it from the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Rax {
    Unknown,
    /// The emission ended by storing the NZCV word in EAX ([`nzcv`]).
    Nzcv,
    /// The emission ended by storing RAX to this register's frame slot
    /// ([`store`]).
    Guest(Register),
}

/// What RAX holds after `operation`'s emission by [`emit_instruction`].
pub(super) fn rax_after(operation: &Operation) -> Rax {
    match *operation {
        Operation::AddSub { flags: true, .. }
        | Operation::AddSubRegister { flags: true, .. }
        | Operation::AddSubExtended { flags: true, .. }
        | Operation::AddSubCarry { flags: true, .. }
        | Operation::LogicalImmediate { flags: true, .. }
        | Operation::LogicalRegister { flags: true, .. } => Rax::Nzcv,
        Operation::AddSub { destination, .. }
        | Operation::AddSubRegister { destination, .. }
        | Operation::AddSubExtended { destination, .. }
        | Operation::AddSubCarry { destination, .. }
        | Operation::LogicalImmediate { destination, .. }
        | Operation::LogicalRegister { destination, .. }
        | Operation::MoveWide { destination, .. }
        | Operation::Simd(
            crate::aarch64::simd::Operand::Immediate(
                crate::aarch64::simd::immediates::Operand::LaneMove(
                    crate::aarch64::simd::rearrange::Operand::Extract { destination, .. },
                ),
            )
            | crate::aarch64::simd::Operand::Rearrange(
                crate::aarch64::simd::rearrange::Operand::Extract { destination, .. },
            ),
        ) if destination != Register::Zero => Rax::Guest(destination),
        _ => Rax::Unknown,
    }
}

/// [`load`]'s bytes for a frame register.
pub(super) fn frame_load(register: Register) -> Option<[u8; 7]> {
    let mut code = Vec::new();
    load(&mut code, register);
    code.try_into().ok()
}

/// [`store`]'s bytes for a frame register.
pub(super) fn frame_store(register: Register) -> Option<[u8; 7]> {
    let mut code = Vec::new();
    store(&mut code, register);
    code.try_into().ok()
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
/// `lea eax,[rax+rdx*4]`: C and V move above N and Z, giving
/// N | C << 2 | Z << 8 | V << 10 in the low 16 bits.
pub(crate) const CAPTURE_COMBINE: [u8; 3] = [0x8d, 0x04, 0x90];
const IMUL_EAX_EAX_IMM32: [u8; 2] = [0x69, 0xc0];
/// The SETcc bytes' low bits.
#[cfg(test)]
const CAPTURED_BITS: u32 = 0x0101;
/// The scale of [`CAPTURE_COMBINE`].
#[cfg(test)]
const CAPTURE_CARRY_SHIFT: u8 = 2;
/// One product moves N (bit 0) to 31, Z (8) to 30, C (2) to 29 and V (10)
/// to 28. Every other partial product of the low 16 bits lands below bit 28
/// or above bit 31, on a bit no other lands on, so nothing carries into
/// NZCV; those of bits 16 and up, which the SETcc leave as they were, land
/// at bit 34 or above and drop out of the 32-bit product.
const CAPTURE_MULTIPLIER: u32 = (1 << 31) | (1 << 22) | (1 << 27) | (1 << 18);
const CAPTURE_NZCV_MASK: u32 = 0xf000_0000;
const _: () = assert!(CAPTURE_MULTIPLIER.trailing_zeros() + u16::BITS >= u32::BITS);

/// The host flags as an Arm NZCV word in EAX, without a data-dependent
/// branch or an instruction outside Intel's data operand independent timing
/// list (SETcc, LEA, IMUL, AND). `borrow` takes C as an Arm subtraction
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
    code.extend(CAPTURE_COMBINE);
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
        Operation::Nop => code.push(NOP),
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

    /// The capture runs on the host after 64-bit additions and subtractions
    /// of edge values, with RDX holding other bits, and packs Arm's NZCV.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn the_flag_capture_packs_arm_flags_of_host_arithmetic() {
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
        const MOV_RAX_RDI: [u8; 3] = [0x48, 0x89, 0xf8];
        const MOVABS_RDX: [u8; 2] = [0x48, 0xba];
        const OTHER_BITS: u64 = 0xa5a5_5a5a_c3c3_3c3c;
        const SUB_RAX_RSI: [u8; 3] = [0x48, 0x29, 0xf0];
        const ADD_RAX_RSI: [u8; 3] = [0x48, 0x01, 0xf0];
        const RET: u8 = 0xc3;
        const VALUES: [u64; 8] = [
            0,
            1,
            0x7fff,
            0x8000_0000,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            0xffff_ffff_ffff_fffe,
            u64::MAX,
        ];
        let arm = |left: u64, right: u64, borrow: bool| {
            let (result, carry, overflow) = if borrow {
                let (result, borrowed) = left.overflowing_sub(right);
                (
                    result,
                    !borrowed,
                    (left as i64).overflowing_sub(right as i64).1,
                )
            } else {
                let (result, carried) = left.overflowing_add(right);
                (
                    result,
                    carried,
                    (left as i64).overflowing_add(right as i64).1,
                )
            };
            let [n, z, c, v] = [result >> 63 == 1, result == 0, carry, overflow].map(u32::from);
            n << 31 | z << 30 | c << 29 | v << 28
        };
        for borrow in [false, true] {
            let mut code = MOV_RAX_RDI.to_vec();
            code.extend(MOVABS_RDX);
            code.extend(OTHER_BITS.to_le_bytes());
            code.extend(if borrow { SUB_RAX_RSI } else { ADD_RAX_RSI });
            capture_nzcv(&mut code, borrow);
            code.push(RET);
            // SAFETY: private anonymous memory, RX after the copy and
            // unmapped after the calls; the code touches no memory.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry: unsafe extern "sysv64" fn(u64, u64) -> u32 = core::mem::transmute(page);
                for left in VALUES {
                    for right in VALUES {
                        assert_eq!(
                            entry(left, right),
                            arm(left, right, borrow),
                            "{left:#x} {right:#x} borrow {borrow}"
                        );
                    }
                }
                assert_eq!(munmap(page, PAGE), 0);
            }
        }
    }

    /// Every condition runs on the host against every NZCV value, with and
    /// without bits below it set, from the frame and from EAX.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn conditions_hold_exactly_as_arm_defines_them() {
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
        const LOAD_EAX_NZCV: [u8; 6] = [0x8b, 0x87, 0, 1, 0, 0];
        const SET_FROM_JUMP: u8 = 0x10;
        const MOVZX_EAX_AL_RET: [u8; 4] = [0x0f, 0xb6, 0xc0, 0xc3];
        const LOW_BITS: u32 = 0x0fff_ffff;
        let holds = |condition: u8, nzcv: u32| {
            let (n, z, c, v) = (nzcv & 8 != 0, nzcv & 4 != 0, nzcv & 2 != 0, nzcv & 1 != 0);
            let result = match condition >> 1 {
                0 => z,
                1 => c,
                2 => n,
                3 => v,
                4 => c && !z,
                5 => n == v,
                _ => n == v && !z,
            };
            result != (condition & 1 == 1)
        };
        for loaded in [false, true] {
            for condition in 0..14 {
                let mut code = if loaded {
                    LOAD_EAX_NZCV.to_vec()
                } else {
                    vec![]
                };
                let jcc = condition_of(&mut code, condition, loaded).unwrap();
                code.extend([0x0f, jcc + SET_FROM_JUMP, 0xc0]);
                code.extend(MOVZX_EAX_AL_RET);
                // SAFETY: private anonymous memory, RX after the copy and
                // unmapped after the calls; the code reads only `state`.
                unsafe {
                    let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                    assert_ne!(page as usize, usize::MAX);
                    core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                    assert_eq!(mprotect(page, PAGE, 5), 0);
                    let entry: unsafe extern "sysv64" fn(*const crate::GuestState) -> u32 =
                        core::mem::transmute(page);
                    for nzcv in 0..16 {
                        for low in [0, LOW_BITS] {
                            let state = crate::GuestState {
                                nzcv: nzcv << 28 | low,
                                ..Default::default()
                            };
                            assert_eq!(
                                entry(&state) == 1,
                                holds(condition, nzcv),
                                "condition {condition} NZCV {nzcv:#x} low {low:#x}"
                            );
                        }
                    }
                    assert_eq!(munmap(page, PAGE), 0);
                }
            }
        }
    }

    /// The shared address additions run on the host against a guest frame:
    /// every immediate form leaves the access address in RAX and, with
    /// writeback, the new base in RDX; every index extension and shift,
    /// scaled or shifted first, and a ZR index add modulo 2^64.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn address_additions_compute_the_access_address_and_writeback() {
        use crate::aarch64::register_offset::IndexExtend;
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
        const MOV_RAX_RSI: [u8; 3] = [0x48, 0x89, 0xf0];
        const RET: u8 = 0xc3;
        const BASE: u64 = 0xffff_ffff_ffff_ff00;
        // Bit 31 set, so UXTW and SXTW differ, and high bits SXTW drops.
        const INDEX: u64 = 0x8000_0001_fedc_ba98;
        const INDEX_REGISTER: u8 = 5;
        #[repr(C)]
        struct Result {
            rax: u64,
            rdx: u64,
        }
        let run = |body: &dyn Fn(&mut Vec<u8>)| -> Result {
            let mut code = MOV_RAX_RSI.to_vec();
            body(&mut code);
            code.push(RET);
            let mut state = crate::GuestState::default();
            state.x[usize::from(INDEX_REGISTER)] = INDEX;
            // SAFETY: private anonymous memory, RX after the copy and
            // unmapped after the call; the code reads only `state`.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry: unsafe extern "sysv64" fn(*const crate::GuestState, u64) -> Result =
                    core::mem::transmute(page);
                let result = entry(&state, BASE);
                assert_eq!(munmap(page, PAGE), 0);
                result
            }
        };
        for displacement in [0, 8, -256, 0x1000, i32::MIN] {
            let added = BASE.wrapping_add_signed(i64::from(displacement));
            for (mode, address, writeback) in [
                (AddressMode::Offset, added, None),
                (AddressMode::PreIndex, added, Some(added)),
                (AddressMode::PostIndex, BASE, Some(added)),
            ] {
                let result = run(&|code| address_add(code, displacement, mode));
                assert_eq!(result.rax, address, "{mode:?} {displacement}");
                if let Some(writeback) = writeback {
                    assert_eq!(result.rdx, writeback, "{mode:?} {displacement}");
                }
            }
        }
        for extend in [
            IndexExtend::Uxtw,
            IndexExtend::Sxtw,
            IndexExtend::Lsl,
            IndexExtend::Sxtx,
        ] {
            let extended = match extend {
                IndexExtend::Uxtw => u64::from(INDEX as u32),
                IndexExtend::Sxtw => i64::from(INDEX as i32) as u64,
                IndexExtend::Lsl | IndexExtend::Sxtx => INDEX,
            };
            for shift in 0..=4 {
                let index = Register::X(INDEX_REGISTER);
                let result = run(&|code| register_offset::index_add(code, index, extend, shift));
                let expected = BASE.wrapping_add(extended << shift);
                assert_eq!(result.rax, expected, "{extend:?} {shift}");
                let zero =
                    run(&|code| register_offset::index_add(code, Register::Zero, extend, shift));
                assert_eq!(zero.rax, BASE, "ZR {extend:?} {shift}");
            }
        }
    }

    /// The check of each placement runs on the host and passes exactly the
    /// guest's native ranges: with five-level paging the addresses whose
    /// bits 63:48 are all clear or all set, with four-level paging the lower
    /// half and `[U, 2^64)`. Past a mispredicted branch the mask alone
    /// replaces every other address.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn the_guest_range_check_passes_exactly_the_native_ranges() {
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
        const LOWER_TOP: u64 = 1 << 47;
        let five = |address: u64| matches!(address >> 48, 0 | 0xffff);
        for slices in [None, Some(2), Some(3), Some(63)] {
            let range = slices.map_or(RangeCheck::FIVE_LEVEL, RangeCheck::four_level);
            let upper = slices.map_or(0, |slices| UPPER_HALF + (u64::from(slices) << SLICE_SHIFT));
            let native = |address: u64| match slices {
                None => five(address),
                Some(_) => address < LOWER_TOP || address >= upper,
            };
            let full = range.code();
            let (bytes, ends) = RangeCheck::at(&full).expect("a check");
            assert_eq!(bytes, full.len());
            let (check, rest) = full.split_at(ends[4]);
            let (trap, mask) = rest.split_at(ends[5] - ends[4]);
            assert_eq!(trap, UD2);
            assert_eq!(full.len(), if range.bias == 1 { 30 } else { 31 });
            // mov rax,rdi; the check with `xor eax,eax` (a failure, also two
            // bytes, whose flags the mask then leaves alone) where its UD2
            // is; the mask; ret. Then the same with the branch replaced by a
            // two-byte NOP, as a mispredicted check runs it.
            let mut code = vec![0x48, 0x89, 0xf8];
            code.extend(check);
            code.extend([0x31, 0xc0]);
            code.extend(mask);
            code.push(0xc3);
            let speculated = code.len();
            code.extend([0x48, 0x89, 0xf8]);
            code.extend(&check[..check.len() - 2]);
            code.extend([0x66, 0x90]);
            code.extend(mask);
            code.push(0xc3);
            // SAFETY: private anonymous memory, RX after the copy and
            // unmapped after the calls; the code touches no memory.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let passes = |address: u64| {
                    let entry: unsafe extern "sysv64" fn(u64) -> u64 = core::mem::transmute(page);
                    let result = entry(address);
                    assert!(result == address || result == 0);
                    let masked: unsafe extern "sysv64" fn(u64) -> u64 =
                        core::mem::transmute(page.cast::<u8>().add(speculated));
                    let expected = if result == address {
                        address
                    } else {
                        range.masked
                    };
                    assert_eq!(masked(address), expected, "{address:#x}");
                    result == address
                };
                let mut edges = vec![
                    1,
                    LOWER_TOP - 1,
                    LOWER_TOP,
                    0x0000_ffff_ffff_ffff,
                    0x0001_0000_0000_0000,
                    // The five-level window, PML5 entry 64.
                    0x0040_0000_0000_0000,
                    0x00ff_ffff_ffff_ffff,
                    0x7fff_ffff_ffff_ffff,
                    0x8000_0000_0000_0000,
                    0xff00_0000_0000_0000,
                    0xfffe_ffff_ffff_ffff,
                    0xffff_0000_0000_0000,
                    UPPER_HALF - 1,
                    // The four-level window's start.
                    UPPER_HALF,
                    u64::MAX,
                    // A tagged pointer.
                    0x0f00_0000_0000_1234,
                ];
                if slices.is_some() {
                    edges.extend([upper - 1, upper, range.masked, upper - (1 << 35)]);
                }
                for address in edges {
                    assert_eq!(passes(address), native(address), "{range:?} {address:#x}");
                }
                assert!(!native(range.masked) && !five(range.masked) || slices.is_some());
                let mut seed = 0x9e37_79b9_7f4a_7c15u64;
                for _ in 0..4096 {
                    seed = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    // Bias most samples to the ranges' edges.
                    let near = [0, LOWER_TOP, UPPER_HALF, upper, 1 << 48, 0xffff_u64 << 48];
                    let offset = (seed.rotate_left(17) & 0xffff_ffff) as i64 - (1 << 31);
                    let address = match seed >> 61 {
                        0 => seed,
                        top => near[(top as usize) % near.len()].wrapping_add_signed(offset << 9),
                    };
                    assert_eq!(passes(address), native(address), "{range:?} {address:#x}");
                }
                assert_eq!(munmap(page, PAGE), 0);
            }
        }
    }

    /// The translated variant's check runs on the host: a native address
    /// passes unchanged, and any other calls the helper, which finds the
    /// guest address in RCX and the access after its return address, and
    /// whose host address the access then uses unmasked. A mispredicted
    /// branch past the call still masks.
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn translated_checks_call_the_helper_outside_the_native_ranges() {
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
        const KEY: u32 = 0x5a5a_0000;
        let range = RangeCheck::four_level(2);
        let upper = UPPER_HALF + (2 << SLICE_SHIFT);
        let access = Access::write(24).atomic();
        // The helper: the access's two bytes into the key's low half, the
        // return address past them, RAX the guest address with the key.
        // mov rdx,[rsp]; movzx edx,word [rdx]; add qword [rsp],2;
        // mov rax,rcx; xor rax,KEY; xor rax,rdx; ret.
        let mut helper = vec![0x48, 0x8b, 0x14, 0x24, 0x0f, 0xb7, 0x12];
        helper.extend([0x48, 0x83, 0x04, 0x24, 0x02, 0x48, 0x89, 0xc8, 0x48, 0x35]);
        helper.extend(KEY.to_le_bytes());
        helper.extend([0x48, 0x31, 0xd0, 0xc3]);
        // SAFETY: private anonymous memory, RX after the copy and unmapped
        // after the calls; the code touches only the stack.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            let slot = alloc::boxed::Box::new(page as u64);
            // mov rax,rdi; the check; ret, then the same with the branch
            // always taken, as a misprediction runs it.
            let mut check = vec![];
            range.emit_translated(&mut check, &*slot as *const u64 as u64, access);
            let (bytes, ends) = RangeCheck::at(&check).unwrap();
            assert_eq!(bytes, check.len());
            let mut code = helper.clone();
            let entry = code.len();
            code.extend([0x48, 0x89, 0xf8]);
            code.extend(&check);
            code.push(0xc3);
            let speculated = code.len();
            code.extend([0x48, 0x89, 0xf8]);
            let branch = code.len() + ends[4] - 2;
            code.extend(&check);
            code[branch] = 0xeb; // jmp in place of jbe
            code.push(0xc3);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let run = |at: usize, address: u64| {
                let function: unsafe extern "sysv64" fn(u64) -> u64 =
                    core::mem::transmute(page.cast::<u8>().add(at));
                function(address)
            };
            let called = |address: u64| {
                address
                    ^ u64::from(KEY)
                    ^ u64::from(u16::from_le_bytes([access.bytes, access.flags]))
            };
            for address in [
                0,
                0x1234,
                (1 << 47) - 1,
                upper,
                u64::MAX,
                1 << 47,
                UPPER_HALF,
                upper - 1,
                range.masked,
                0x0040_0000_0000_0000,
            ] {
                let native = address < 1 << 47 || address >= upper;
                let expected = if native { address } else { called(address) };
                assert_eq!(run(entry, address), expected, "{address:#x}");
                let masked = if native { address } else { range.masked };
                assert_eq!(run(speculated, address), masked, "{address:#x}");
            }
            assert_eq!(munmap(page, PAGE), 0);
        }
    }

    /// A four-level placement's masked address lies in its guard, which no
    /// access extent leaves, and its fields fit the encoding.
    #[test]
    fn four_level_checks_mask_into_the_guard_below_the_upper_range() {
        for slices in 2..HALF_SLICES {
            let range = RangeCheck::four_level(slices);
            let upper = UPPER_HALF + (u64::from(slices) << SLICE_SHIFT);
            assert!(range.valid());
            assert!(range.masked >= upper - (1 << SLICE_SHIFT) && range.masked < upper);
            assert!(upper - range.masked >= 1 << 35);
            let mut code = Vec::new();
            range.emit(&mut code);
            // A bias of 1 (63 slices) is INC, as five-level paging's.
            let ends = if slices == HALF_SLICES - 1 {
                [3, 7, 9, 12, 14, 16, 26, 30]
            } else {
                [3, 7, 10, 13, 15, 17, 27, 31]
            };
            assert_eq!(RangeCheck::at(&code), Some((ends[7], &ends[..])));
        }
        assert_eq!(
            RangeCheck::at(&RangeCheck::FIVE_LEVEL.code()).unwrap().1,
            [3, 7, 9, 12, 14, 16, 26, 30]
        );
        let refused = MemoryChecks::DEFAULT.with_range(RangeCheck::four_level(2));
        assert_eq!(refused.range.bias, 62);
        assert_eq!(refused.range.bound, 125);
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
