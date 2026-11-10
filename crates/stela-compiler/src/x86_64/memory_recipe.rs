//! Shared scalar and pair memory emission with optional semantic spans.
//! Regions replace address/staging spans and copy the remaining bytes with
//! their encoder counts. Internal branches and call descriptors stay together.
use super::asm::{Alu, Checkpoint, Code, Cond, Gpr, Mem, Rm, Size, Span};
use super::masked_base::Plan;
use super::{
    Access, AddressMode, ImmediateAddress, MemoryChecks, MemoryTransfer, Register, Shift, Width,
    accessed, address_add, address_checks, alignment_check, load, memory_store, memory_writeback,
    right_operand, stack_alignment_check, stack_alignment_check_register,
};
use crate::{
    GuestAddress,
    aarch64::{Instruction, Operation},
};
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Base,
    StackAlignment,
    Offset,
    Checks,
    Stage { element: usize, host: Gpr },
    Load { element: usize, host: Gpr },
    Store,
    Commit,
    Writeback,
}
impl Kind {
    fn address_prefix(self) -> bool {
        matches!(self, Self::Base | Self::StackAlignment | Self::Offset)
    }
}
#[derive(Debug, Clone, Copy)]
pub(super) struct Segment {
    pub kind: Kind,
    pub span: Span,
}
#[derive(Debug, Default)]
pub(super) struct Recipe {
    segments: Vec<Segment>,
    clobbers: u16,
}
impl Recipe {
    fn mark(&mut self, code: &Code, start: Checkpoint, kind: Kind, clobbers: u16) {
        let span = code.span_since(start);
        if !span.is_empty() {
            self.segments.push(Segment { kind, span });
            self.clobbers |= clobbers;
        }
    }
    pub fn address_prefix(&self) -> impl Iterator<Item = &Segment> {
        self.segments
            .iter()
            .take_while(|segment| segment.kind.address_prefix())
    }
    pub fn body(&self) -> impl Iterator<Item = &Segment> {
        self.segments
            .iter()
            .skip_while(|segment| segment.kind.address_prefix())
    }
    pub fn checked_sp(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| segment.kind == Kind::StackAlignment)
    }
    pub fn clobbers(&self) -> u16 {
        self.clobbers
    }
    pub fn stage(&self, element: usize) -> Option<Gpr> {
        self.segments.iter().find_map(|segment| match segment.kind {
            Kind::Stage {
                element: index,
                host,
            } if index == element => Some(host),
            _ => None,
        })
    }
    pub fn result(&self, element: usize) -> Option<Gpr> {
        self.segments.iter().find_map(|segment| match segment.kind {
            Kind::Load {
                element: index,
                host,
            } if index == element => Some(host),
            _ => None,
        })
    }
    pub fn complete(&self, code: &Code) -> bool {
        let mut cursor = Code::new().checkpoint();
        for segment in &self.segments {
            if segment.span.start() != cursor {
                return false;
            }
            cursor = segment.span.end();
        }
        cursor == code.checkpoint()
    }
}
fn mask(register: Gpr) -> u16 {
    1_u16
        .checked_shl(register as u32)
        .expect("ordinary memory uses the legacy GPR bank")
}
fn mark(
    recipe: &mut Option<&mut Recipe>,
    code: &Code,
    start: Checkpoint,
    kind: Kind,
    clobbers: u16,
) {
    if let Some(recipe) = recipe {
        recipe.mark(code, start, kind, clobbers);
    }
}
#[derive(Clone, Copy)]
pub(super) struct Scalar {
    pub transfer: MemoryTransfer,
    pub bytes: u8,
    pub data: Register,
    pub address: ImmediateAddress,
}
#[derive(Clone, Copy)]
pub(super) struct Pair {
    pub transfer: MemoryTransfer,
    pub bytes: u8,
    pub data: [Register; 2],
    pub address: ImmediateAddress,
}

/// The base's host register, RAX for one in the frame, and where the access
/// starts: `[base+displacement]` is one host instruction. The checks this
/// emits leave their failures out of line. `None` for what needs the address
/// in RAX: alignment against it, a masked or translated access, and a
/// writeback of a register the access loads.
fn direct(
    code: &mut Code,
    checks: MemoryChecks,
    address: ImmediateAddress,
    unit: u8,
    loads_base: bool,
) -> Option<(Gpr, i32)> {
    let ImmediateAddress {
        base,
        displacement,
        mode,
    } = address;
    if !code.is_pinned()
        || checks.checks_every_access()
        || (checks.alignment && unit > 1)
        || (loads_base && mode != AddressMode::Offset)
    {
        return None;
    }
    let host = code.host(base).unwrap_or(Gpr::Rax);
    if host == Gpr::Rax {
        load(code, base);
    }
    if base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
        code.asm().test_imm(Size::Byte, host, 15);
        code.check_failure(super::asm::Cond::Ne);
    }
    if checks.guest_range {
        checks.range.emit_base(code, host);
    }
    let start = if mode == AddressMode::PostIndex {
        0
    } else {
        displacement
    };
    Some((host, start))
}

/// A [`direct`] access's writeback, once its faults are behind it.
fn direct_writeback(code: &mut Code, host: Gpr, address: ImmediateAddress) {
    if address.mode == AddressMode::Offset {
        return;
    }
    let mut asm = code.asm();
    asm.lea(Size::Qword, host, Mem::base(host, address.displacement));
    if host == Gpr::Rax {
        let storage = asm.guest(address.base).expect("memory base cannot be ZR");
        asm.mov_store(Size::Qword, storage, Gpr::Rax);
    }
}

/// The masked-base plan offered for the access at `address`
/// ([`super::masked_base`]), in pinned code whose every access checks its
/// masked address and outside a recipe, whose spans regions rearrange.
fn base_plan(
    code: &Code,
    checks: MemoryChecks,
    address: ImmediateAddress,
    alone: bool,
) -> Option<Plan> {
    (alone
        && code.is_pinned()
        && checks.guest_range
        && checks.every_access_masked
        && !checks.translated)
        .then(|| code.base_plan(address))
        .flatten()
}

/// The slot and displacement a [`Plan::Reuse`] access addresses directly,
/// once SP's alignment is checked. `None` for what needs the address in
/// RAX, as with [`direct`].
fn reused(
    code: &mut Code,
    checks: MemoryChecks,
    address: ImmediateAddress,
    unit: u8,
    loads_base: bool,
    alone: bool,
) -> Option<(Gpr, i32)> {
    let Some(Plan::Reuse { host, delta }) = base_plan(code, checks, address, alone) else {
        return None;
    };
    if (checks.alignment && unit > 1) || (loads_base && address.mode != AddressMode::Offset) {
        return None;
    }
    if address.base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
        let stack = code
            .host(Register::Sp)
            .expect("pinned code keeps SP in a host register");
        code.asm().test_imm(Size::Byte, stack, 15);
        code.check_failure(super::asm::Cond::Ne);
    }
    code.apply_base_plan();
    Some((host, delta))
}

/// A [`reused`] access's writeback of its base, once its faults are behind it.
fn reused_writeback(code: &mut Code, address: ImmediateAddress) {
    if address.mode == AddressMode::Offset {
        return;
    }
    match code.host(address.base) {
        Some(host) => direct_writeback(code, host, address),
        None => {
            load(code, address.base);
            direct_writeback(code, Gpr::Rax, address);
        }
    }
}

pub(super) fn address(
    code: &mut Code,
    checks: MemoryChecks,
    address: ImmediateAddress,
    unit: u8,
    access: Access,
    mut recipe: Option<&mut Recipe>,
) {
    let ImmediateAddress {
        base,
        displacement,
        mode,
    } = address;
    let plan = base_plan(code, checks, address, recipe.is_none());
    if let Some(Plan::Reuse { host, delta }) = plan {
        // The pending writeback still moves the guest's base.
        if mode != AddressMode::Offset {
            let source = code.host(base).unwrap_or_else(|| {
                load(code, base);
                Gpr::Rax
            });
            code.asm()
                .lea(Size::Qword, Gpr::Rdx, Mem::base(source, displacement));
        }
        code.asm()
            .lea(Size::Qword, Gpr::Rax, Mem::base(host, delta));
        if base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
            let stack = code
                .host(Register::Sp)
                .expect("pinned code keeps SP in a host register");
            stack_alignment_check_register(code, stack);
        }
        alignment_check(code, checks, unit);
        code.apply_base_plan();
        return;
    }
    // The checked, masked address, for later accesses to reuse.
    let keep = |code: &mut Code| {
        if let Some(Plan::Keep(host)) = plan {
            code.asm().mov(Size::Qword, host, Gpr::Rax);
            code.apply_base_plan();
        }
    };
    // Through a pinned base the address needs no copy of it.
    if let (Some(host), AddressMode::Offset) = (code.host(base), mode) {
        code.asm()
            .lea(Size::Qword, Gpr::Rax, Mem::base(host, displacement));
        if base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
            stack_alignment_check_register(code, host);
        }
        address_checks(code, checks, unit, access);
        keep(code);
        return;
    }
    let start = code.checkpoint();
    load(code, base);
    mark(&mut recipe, code, start, Kind::Base, mask(Gpr::Rax));
    if base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
        let start = code.checkpoint();
        stack_alignment_check(code);
        mark(&mut recipe, code, start, Kind::StackAlignment, 0);
    }
    let start = code.checkpoint();
    address_add(code, displacement, mode);
    mark(
        &mut recipe,
        code,
        start,
        Kind::Offset,
        mask(Gpr::Rax) | mask(Gpr::Rdx),
    );
    let start = code.checkpoint();
    address_checks(code, checks, unit, access);
    mark(
        &mut recipe,
        code,
        start,
        Kind::Checks,
        mask(Gpr::Rax) | mask(Gpr::Rcx),
    );
    keep(code);
}
const FRAME_PAIR_RESULTS: [Gpr; 2] = [Gpr::Rcx, Gpr::R8];

enum CompareInput {
    Scalars {
        first: Scalar,
        second: Scalar,
        second_host: Gpr,
    },
    Pair(Pair),
}

pub(super) struct CompareLoads {
    input: CompareInput,
    width: Width,
    left: Gpr,
    right: Gpr,
    destination: Register,
}

impl CompareLoads {
    pub(super) fn new(
        instructions: &[Instruction],
        held: super::Rax,
        checks: MemoryChecks,
    ) -> Option<Self> {
        let [first, second, compare, ..] = instructions else {
            return None;
        };
        let first_load = compare_input(&first.operation)?;
        let second_load = compare_input(&second.operation)?;
        if checks.guest_range
            || checks.alignment
            || checks.checks_every_access()
            || first.pc.0.checked_add(4) != Some(second.pc.0)
            || second.pc.0.checked_add(4) != Some(compare.pc.0)
            || first_load.data == second_load.data
            || first_load.address.base == second_load.address.base
            || first_load.data == second_load.address.base
            || held == super::Rax::Guest(first_load.address.base)
        {
            return None;
        }
        let Operation::AddSubRegister {
            width,
            subtract: true,
            flags: true,
            destination,
            left,
            right,
            amount: 0,
            ..
        } = compare.operation
        else {
            return None;
        };
        let operands = (first_load.data, second_load.data);
        let writes_back = first_load.address.mode != AddressMode::Offset
            || second_load.address.mode != AddressMode::Offset;
        if writes_back {
            // The ordinary address recipe keeps its pending writeback in
            // RDX. Both results survive only when address setup cannot
            // call a helper or borrow RCX for checks.
            if checks != MemoryChecks::DEFAULT
                || first_load.address.base == first_load.data
                || first_load.address.base == second_load.data
                || second_load.address.base == second_load.data
                || destination != Register::Zero
                    && destination != operands.0
                    && destination != operands.1
            {
                return None;
            }
        } else if destination != Register::Zero {
            return None;
        }
        let second_host = if second_load.address.mode == AddressMode::Offset {
            Gpr::Rax
        } else {
            Gpr::R8
        };
        let (left, right) = if (left, right) == operands {
            (Gpr::Rcx, second_host)
        } else if (right, left) == operands {
            (second_host, Gpr::Rcx)
        } else {
            return None;
        };
        Some(Self {
            input: CompareInput::Scalars {
                first: first_load,
                second: second_load,
                second_host,
            },
            width,
            left,
            right,
            destination,
        })
    }

    pub(super) fn from_pair(instructions: &[Instruction], checks: MemoryChecks) -> Option<Self> {
        let [load, compare, ..] = instructions else {
            return None;
        };
        let Operation::MemoryPair {
            transfer:
                transfer @ MemoryTransfer::Load {
                    signed: false,
                    width,
                },
            bytes,
            data: data @ [Register::X(_), Register::X(_)],
            base: base @ Register::X(_),
            displacement,
            mode: AddressMode::Offset,
        } = load.operation
        else {
            return None;
        };
        if checks != MemoryChecks::DEFAULT
            || load.pc.0.checked_add(4) != Some(compare.pc.0)
            || data[0] == data[1]
            || !matches!((width, bytes), (Width::W32, 4) | (Width::X64, 8))
        {
            return None;
        }
        let Operation::AddSubRegister {
            width: compare_width,
            subtract: true,
            flags: true,
            destination: Register::Zero,
            left,
            right,
            amount: 0,
            ..
        } = compare.operation
        else {
            return None;
        };
        if width != compare_width {
            return None;
        }
        let [left, right] = if [left, right] == data {
            FRAME_PAIR_RESULTS
        } else if [right, left] == data {
            [FRAME_PAIR_RESULTS[1], FRAME_PAIR_RESULTS[0]]
        } else {
            return None;
        };
        Some(Self {
            input: CompareInput::Pair(Pair {
                transfer,
                bytes,
                data,
                address: ImmediateAddress {
                    base,
                    displacement,
                    mode: AddressMode::Offset,
                },
            }),
            width,
            left,
            right,
            destination: Register::Zero,
        })
    }

    pub(super) fn compare_index(&self) -> usize {
        match self.input {
            CompareInput::Scalars { .. } => 2,
            CompareInput::Pair(_) => 1,
        }
    }

    pub(super) fn emit(
        self,
        code: &mut Code,
        source_map: &mut Vec<(GuestAddress, usize)>,
        instructions: &[Instruction],
        checks: MemoryChecks,
        live_nzcv: bool,
    ) -> super::Rax {
        debug_assert!(!code.is_pinned() && !code.constant_time());
        let compare = self.compare_index();
        match self.input {
            CompareInput::Scalars {
                first,
                second,
                second_host,
            } => {
                // Settle each scalar access before the next one.
                for (instruction, operand, result) in [
                    (&instructions[0], first, Gpr::Rcx),
                    (&instructions[1], second, second_host),
                ] {
                    source_map.push((instruction.pc, code.len()));
                    code.set_instruction(source_map.len() - 1);
                    scalar(code, checks, operand, None, Some(result));
                }
            }
            CompareInput::Pair(operand) => {
                source_map.push((instructions[0].pc, code.len()));
                code.set_instruction(source_map.len() - 1);
                // Keep the original pair's two accesses and delayed frame
                // commit. Its staged results still hold both CMP operands.
                pair(code, checks, operand, None);
            }
        }
        source_map.push((instructions[compare].pc, code.len()));
        code.set_instruction(source_map.len() - 1);
        let mut asm = code.asm();
        let destination = asm.guest(self.destination);
        let op = if destination.is_some() {
            Alu::Sub
        } else {
            Alu::Cmp
        };
        asm.alu(
            op,
            Size::of(self.width == Width::X64),
            self.left,
            self.right,
        );
        if let Some(destination) = destination {
            asm.mov_store(Size::Qword, destination, self.left);
        }
        if live_nzcv {
            super::flag_word::capture_arm_live(code, true);
            super::Rax::LiveNzcv
        } else {
            super::nzcv(code, true);
            super::Rax::Nzcv
        }
    }
}

fn compare_input(operation: &Operation) -> Option<Scalar> {
    let Operation::Memory {
        transfer: transfer @ MemoryTransfer::Load { signed: false, .. },
        bytes: bytes @ (1 | 2 | 4 | 8),
        data: data @ Register::X(_),
        base: base @ Register::X(_),
        displacement,
        mode: mode @ (AddressMode::Offset | AddressMode::PostIndex),
    } = *operation
    else {
        return None;
    };
    Some(Scalar {
        transfer,
        bytes,
        data,
        address: ImmediateAddress {
            base,
            displacement,
            mode,
        },
    })
}

pub(super) fn scalar_load(
    code: &mut Code,
    bytes: u8,
    signed: bool,
    width: Width,
    source: Mem,
    host: Gpr,
) {
    let size = Size::of(width == Width::X64);
    code.asm().guest_access(|asm| match (bytes, signed) {
        (1, false) => asm.movzx(size, host, Size::Byte, source),
        (2, false) => asm.movzx(size, host, Size::Word, source),
        (1, true) => asm.movsx(size, host, Size::Byte, source),
        (2, true) => asm.movsx(size, host, Size::Word, source),
        (4, true) => {
            debug_assert!(width == Width::X64);
            asm.movsxd(host, source);
        }
        (4 | 8, false) => asm.mov_load(size, host, source),
        _ => unreachable!("decoder validates scalar memory size"),
    });
}

pub(super) fn scalar(
    code: &mut Code,
    checks: MemoryChecks,
    operand: Scalar,
    mut recipe: Option<&mut Recipe>,
    frame_load_result: Option<Gpr>,
) {
    let Scalar {
        transfer,
        bytes,
        data,
        address: location,
    } = operand;
    let ImmediateAddress { base, mode, .. } = location;
    let access = Access::of(transfer == MemoryTransfer::Store, bytes.into());
    let loads_base = data == base && transfer != MemoryTransfer::Store;
    let reuse = reused(code, checks, location, bytes, loads_base, recipe.is_none());
    let place = reuse.or_else(|| direct(code, checks, location, bytes, loads_base));
    if place.is_none() {
        address(code, checks, location, bytes, access, recipe.as_deref_mut());
    }
    let (at, start) = place.unwrap_or((Gpr::Rax, 0));
    match transfer {
        MemoryTransfer::Store => {
            let source = match code.host(data) {
                Some(host) => memory_store::Source::Host(host),
                None => {
                    let start = code.checkpoint();
                    right_operand(code, data, Width::X64, Shift::Lsl, 0);
                    mark(
                        &mut recipe,
                        code,
                        start,
                        Kind::Stage {
                            element: 0,
                            host: Gpr::Rcx,
                        },
                        mask(Gpr::Rcx),
                    );
                    memory_store::Source::Rcx
                }
            };
            let checkpoint = code.checkpoint();
            memory_store::emit_to(code, bytes, Mem::base(at, start), source);
            mark(&mut recipe, code, checkpoint, Kind::Store, 0);
        }
        MemoryTransfer::Load { signed, width } => {
            let source = if place.is_some() {
                Mem::base(at, start)
            } else {
                accessed()
            };
            // A fault leaves a host destination as it was.
            // Offset loads have no pending writeback. Keep a direct
            // result in RAX for the next instruction. Region recipes
            // retain their separate address and result registers.
            let hold_result = code.is_pinned() || (recipe.is_none() && !code.constant_time());
            let scratch =
                frame_load_result.unwrap_or(if hold_result && mode == AddressMode::Offset {
                    Gpr::Rax
                } else {
                    Gpr::Rcx
                });
            let host = code.host(data).unwrap_or(scratch);
            let checkpoint = code.checkpoint();
            scalar_load(code, bytes, signed, width, source, host);
            mark(
                &mut recipe,
                code,
                checkpoint,
                Kind::Load { element: 0, host },
                mask(host),
            );
            // A discarded load still performs its faultable access.
            if host == scratch
                && let Some(data) = code.asm().guest(data)
            {
                let start = code.checkpoint();
                code.asm().mov_store(Size::Qword, data, host);
                mark(&mut recipe, code, start, Kind::Commit, 0);
            }
        }
    }
    // Commit writeback only after all faultable element accesses succeed.
    if reuse.is_some() {
        reused_writeback(code, location);
        return;
    }
    if let Some((host, _)) = place {
        direct_writeback(code, host, location);
        return;
    }
    let start = code.checkpoint();
    memory_writeback(code, base, mode);
    mark(&mut recipe, code, start, Kind::Writeback, 0);
}
/// Where FEAT_LSE2 makes a pair one single-copy atomic 16-byte access: an
/// LDP, LDNP, STP or STNP of X registers, 16-byte aligned (Arm DDI 0487
/// B2.2.1). Such an access is one MOVDQA, which is single-copy atomic on
/// hosts with [`crate::TargetCpu::AtomicLoad16`]; the identification
/// advertises FEAT_LSE2 only on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairAlignment {
    /// Two accesses: not an X pair, or through a checked SP at an offset
    /// that is no multiple of 16.
    Split,
    /// One 16-byte access, through a checked SP at a multiple of 16.
    Aligned,
    /// One 16-byte access where the address tests 16-byte aligned, two
    /// otherwise.
    Tested,
}

fn pair_alignment(checks: MemoryChecks, operand: Pair) -> PairAlignment {
    let Pair {
        transfer,
        bytes,
        address,
        ..
    } = operand;
    let quadwords = bytes == 8
        && match transfer {
            MemoryTransfer::Store => true,
            MemoryTransfer::Load { signed, width } => !signed && width == Width::X64,
        };
    if !quadwords {
        return PairAlignment::Split;
    }
    if address.base == Register::Sp && checks.stack_alignment {
        return match pair_start(address).rem_euclid(16) {
            0 => PairAlignment::Aligned,
            _ => PairAlignment::Split,
        };
    }
    PairAlignment::Tested
}

/// The offset of a pair's first byte from its base register.
fn pair_start(address: ImmediateAddress) -> i32 {
    match address.mode {
        AddressMode::PostIndex => 0,
        _ => address.displacement,
    }
}

/// STP of two quadwords as one 16-byte access. Clobbers XMM0 and XMM1.
fn quadword_pair_store(code: &mut Code, target: Mem, sources: [Gpr; 2]) {
    let mut asm = code.asm();
    asm.movq_to_xmm(0, sources[0]);
    asm.movq_to_xmm(1, sources[1]);
    asm.punpcklqdq(0, Rm::Xmm(1));
    asm.guest_access(|asm| asm.movdqa_store(target, 0));
}

/// The 16-byte access of an LDP of two quadwords, and the first element
/// into `host`. [`quadword_pair_second`] takes the second. Clobbers XMM0.
fn quadword_pair_load(code: &mut Code, source: Mem, host: Gpr) {
    let mut asm = code.asm();
    asm.guest_access(|asm| asm.movdqa_load(0, source));
    asm.movq_from_xmm(host, 0);
}

fn quadword_pair_second(code: &mut Code, host: Gpr) {
    let mut asm = code.asm();
    asm.punpckhqdq(0, Rm::Xmm(0));
    asm.movq_from_xmm(host, 0);
}

pub(super) fn pair(
    code: &mut Code,
    checks: MemoryChecks,
    operand: Pair,
    mut recipe: Option<&mut Recipe>,
) {
    let Pair {
        transfer,
        bytes,
        data,
        address: location,
    } = operand;
    let ImmediateAddress { base, mode, .. } = location;
    let access = Access::of(transfer == MemoryTransfer::Store, 2 * u16::from(bytes));
    let loads_base = data.contains(&base) && transfer != MemoryTransfer::Store;
    let alignment = pair_alignment(checks, operand);
    // A tested access tests its host register's alignment: one that the
    // pair starts a multiple of 16 bytes past, or RAX, which holds the
    // address.
    let tested = alignment == PairAlignment::Tested;
    let reuse = if tested {
        None
    } else {
        reused(code, checks, location, bytes, loads_base, recipe.is_none())
    };
    let place = reuse.or_else(|| {
        (!tested || pair_start(location).rem_euclid(16) == 0)
            .then(|| direct(code, checks, location, bytes, loads_base))
            .flatten()
    });
    if place.is_none() {
        address(code, checks, location, bytes, access, recipe.as_deref_mut());
    }
    let (at, displacement) = place.unwrap_or((Gpr::Rax, 0));
    // The second element stages in RDX in pinned code where no pending
    // writeback holds it, which leaves R8 to a run's locals
    // (`pinned::Span`).
    let second_stage = if code.is_pinned() && (place.is_some() || mode == AddressMode::Offset) {
        Gpr::Rdx
    } else {
        FRAME_PAIR_RESULTS[1]
    };
    match transfer {
        MemoryTransfer::Store => {
            let first = match code.host(data[0]) {
                Some(host) => memory_store::Source::Host(host),
                None => {
                    let start = code.checkpoint();
                    right_operand(code, data[0], Width::X64, Shift::Lsl, 0);
                    mark(
                        &mut recipe,
                        code,
                        start,
                        Kind::Stage {
                            element: 0,
                            host: Gpr::Rcx,
                        },
                        mask(Gpr::Rcx),
                    );
                    memory_store::Source::Rcx
                }
            };
            let second = match code.host(data[1]) {
                Some(host) => memory_store::Source::Host(host),
                None => {
                    let start = code.checkpoint();
                    match code.asm().guest(data[1]) {
                        Some(storage) => code.asm().mov_load(Size::Qword, second_stage, storage),
                        None => code
                            .asm()
                            .alu(Alu::Xor, Size::Dword, second_stage, second_stage),
                    }
                    mark(
                        &mut recipe,
                        code,
                        start,
                        Kind::Stage {
                            element: 1,
                            host: second_stage,
                        },
                        mask(second_stage),
                    );
                    memory_store::Source::Host(second_stage)
                }
            };
            let register = |source| match source {
                memory_store::Source::Host(host) => host,
                _ => Gpr::Rcx,
            };
            let sources = [register(first), register(second)];
            let start = code.checkpoint();
            if alignment == PairAlignment::Aligned {
                quadword_pair_store(code, Mem::base(at, displacement), sources);
                mark(&mut recipe, code, start, Kind::Store, 0);
            } else {
                let mut done = None;
                if tested {
                    code.asm().test_imm(Size::Byte, at, 15);
                    let split = code.asm().jcc8(Cond::Ne);
                    quadword_pair_store(code, Mem::base(at, displacement), sources);
                    done = Some(code.asm().jmp8());
                    code.asm().bind(split);
                }
                for (element, source) in [(0, first), (1, second)] {
                    let start = if element == 0 {
                        start
                    } else {
                        code.checkpoint()
                    };
                    let target = Mem::base(at, displacement + i32::from(element * bytes));
                    memory_store::emit_to(code, bytes, target, source);
                    if element == 1
                        && let Some(done) = done
                    {
                        code.asm().bind(done);
                    }
                    mark(&mut recipe, code, start, Kind::Store, 0);
                }
            }
        }
        MemoryTransfer::Load { signed, width } => {
            let size = Size::of(width == Width::X64);
            // In place where no element reads its register back: an aborted
            // load leaves its destinations UNKNOWN, but never the base.
            let host = |code: &Code, register, staged| {
                place
                    .and_then(|(at, _)| code.host(register).filter(|host| *host != at))
                    .unwrap_or(staged)
            };
            let hosts = [host(code, data[0], FRAME_PAIR_RESULTS[0]), {
                // The second element's own load is the last to need the base.
                place
                    .and_then(|_| code.host(data[1]))
                    .unwrap_or(second_stage)
            }];
            // The 16-byte access precedes the split one in the first
            // element's span, and the second element's span ends where both
            // paths join.
            let mut done = None;
            let start = code.checkpoint();
            if tested {
                code.asm().test_imm(Size::Byte, at, 15);
                let split = code.asm().jcc8(Cond::Ne);
                quadword_pair_load(code, Mem::base(at, displacement), hosts[0]);
                quadword_pair_second(code, hosts[1]);
                done = Some(code.asm().jmp8());
                code.asm().bind(split);
            }
            for (element, host, source) in [
                (0, hosts[0], Mem::base(at, displacement)),
                (1, hosts[1], Mem::base(at, displacement + i32::from(bytes))),
            ] {
                let start = if element == 0 {
                    start
                } else {
                    code.checkpoint()
                };
                if alignment == PairAlignment::Aligned {
                    if element == 0 {
                        quadword_pair_load(code, source, host);
                    } else {
                        quadword_pair_second(code, host);
                    }
                } else {
                    code.asm().guest_access(|asm| {
                        if signed {
                            debug_assert!(width == Width::X64);
                            asm.movsxd(host, source);
                        } else {
                            asm.mov_load(size, host, source);
                        }
                    });
                }
                if element == 1
                    && let Some(done) = done
                {
                    code.asm().bind(done);
                }
                let clobbers = if tested && element == 0 {
                    mask(hosts[0]) | mask(hosts[1])
                } else {
                    mask(host)
                };
                mark(
                    &mut recipe,
                    code,
                    start,
                    Kind::Load { element, host },
                    clobbers,
                );
            }
            for (register, staged) in [(data[0], hosts[0]), (data[1], hosts[1])] {
                if code.host(register) == Some(staged) {
                    continue;
                }
                if let Some(storage) = code.asm().guest(register) {
                    let start = code.checkpoint();
                    code.asm().mov_store(Size::Qword, storage, staged);
                    mark(&mut recipe, code, start, Kind::Commit, 0);
                }
            }
        }
    }
    // Commit writeback only after all faultable element accesses succeed.
    if reuse.is_some() {
        reused_writeback(code, location);
        return;
    }
    if let Some((host, _)) = place {
        direct_writeback(code, host, location);
        return;
    }
    let start = code.checkpoint();
    memory_writeback(code, base, mode);
    mark(&mut recipe, code, start, Kind::Writeback, 0);
}
pub(super) fn scalar_recipe(checks: MemoryChecks, operand: Scalar) -> (Code, Recipe) {
    let mut code = Code::new();
    let mut recipe = Recipe::default();
    scalar(&mut code, checks, operand, Some(&mut recipe), None);
    (code, recipe)
}
pub(super) fn pair_recipe(checks: MemoryChecks, operand: Pair) -> (Code, Recipe) {
    let mut code = Code::new();
    let mut recipe = Recipe::default();
    pair(&mut code, checks, operand, Some(&mut recipe));
    (code, recipe)
}

#[cfg(test)]
mod tests;
