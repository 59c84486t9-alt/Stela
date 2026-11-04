//! Shared scalar and pair memory emission with optional semantic spans.
//! Regions replace address/staging spans and copy the remaining bytes with
//! their encoder counts. Internal branches and call descriptors stay together.
use super::asm::{Alu, Checkpoint, Code, Gpr, Mem, Size, Span};
use super::{
    Access, AddressMode, ImmediateAddress, MemoryChecks, MemoryTransfer, Register, Shift, Width,
    accessed, address_add, address_checks, load, memory_store, memory_writeback, right_operand,
    stack_alignment_check, stack_alignment_check_register,
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
    // Through a pinned base the address needs no copy of it.
    if let (Some(host), AddressMode::Offset) = (code.host(base), mode) {
        code.asm()
            .lea(Size::Qword, Gpr::Rax, Mem::base(host, displacement));
        if base == Register::Sp && checks.stack_alignment && !checks.stack_checked {
            stack_alignment_check_register(code, host);
        }
        address_checks(code, checks, unit, access);
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
}
pub(super) fn scalar(
    code: &mut Code,
    checks: MemoryChecks,
    operand: Scalar,
    mut recipe: Option<&mut Recipe>,
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
    let place = direct(code, checks, location, bytes, loads_base);
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
            let size = Size::of(width == Width::X64);
            let source = if place.is_some() {
                Mem::base(at, start)
            } else {
                accessed()
            };
            // A fault leaves a host destination as it was.
            // Offset loads have no pending writeback. Keep an unpinned
            // result in RAX so the following instruction can use it
            // without reloading it from the frame.
            let scratch = if code.is_pinned() && mode == AddressMode::Offset {
                Gpr::Rax
            } else {
                Gpr::Rcx
            };
            let host = code.host(data).unwrap_or(scratch);
            let checkpoint = code.checkpoint();
            {
                let mut asm = code.asm();
                asm.guest_access(|asm| match (bytes, signed) {
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
    if let Some((host, _)) = place {
        direct_writeback(code, host, location);
        return;
    }
    let start = code.checkpoint();
    memory_writeback(code, base, mode);
    mark(&mut recipe, code, start, Kind::Writeback, 0);
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
    let place = direct(code, checks, location, bytes, loads_base);
    if place.is_none() {
        address(code, checks, location, bytes, access, recipe.as_deref_mut());
    }
    let (at, displacement) = place.unwrap_or((Gpr::Rax, 0));
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
                        Some(storage) => code.asm().mov_load(Size::Qword, Gpr::R8, storage),
                        None => code.asm().alu(Alu::Xor, Size::Dword, Gpr::R8, Gpr::R8),
                    }
                    mark(
                        &mut recipe,
                        code,
                        start,
                        Kind::Stage {
                            element: 1,
                            host: Gpr::R8,
                        },
                        mask(Gpr::R8),
                    );
                    memory_store::Source::R8
                }
            };
            for (element, source) in [(0, first), (1, second)] {
                let start = code.checkpoint();
                let target = Mem::base(at, displacement + i32::from(element * bytes));
                memory_store::emit_to(code, bytes, target, source);
                mark(&mut recipe, code, start, Kind::Store, 0);
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
            let hosts = [host(code, data[0], Gpr::Rcx), {
                // The second element's own load is the last to need the base.
                place.and_then(|_| code.host(data[1])).unwrap_or(Gpr::R8)
            }];
            for (element, host, source) in [
                (0, hosts[0], Mem::base(at, displacement)),
                (1, hosts[1], Mem::base(at, displacement + i32::from(bytes))),
            ] {
                let start = code.checkpoint();
                code.asm().guest_access(|asm| {
                    if signed {
                        debug_assert!(width == Width::X64);
                        asm.movsxd(host, source);
                    } else {
                        asm.mov_load(size, host, source);
                    }
                });
                mark(
                    &mut recipe,
                    code,
                    start,
                    Kind::Load { element, host },
                    mask(host),
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
    scalar(&mut code, checks, operand, Some(&mut recipe));
    (code, recipe)
}
pub(super) fn pair_recipe(checks: MemoryChecks, operand: Pair) -> (Code, Recipe) {
    let mut code = Code::new();
    let mut recipe = Recipe::default();
    pair(&mut code, checks, operand, Some(&mut recipe));
    (code, recipe)
}
