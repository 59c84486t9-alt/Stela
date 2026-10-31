//! Shared scalar and pair memory emission with optional semantic spans.
//! Regions replace address/staging spans and copy the remaining bytes with
//! their encoder counts. Internal branches and call descriptors stay together.
use super::asm::{Alu, Checkpoint, Code, Gpr, Mem, Size, Span};
use super::{
    Access, ImmediateAddress, MemoryChecks, MemoryTransfer, Register, Shift, Width, accessed,
    address_add, address_checks, frame, load, memory_store, memory_writeback, offset,
    right_operand, stack_alignment_check,
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
    address(code, checks, location, bytes, access, recipe.as_deref_mut());
    match transfer {
        MemoryTransfer::Store => {
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
            let start = code.checkpoint();
            memory_store::emit(code, bytes, 0, memory_store::Source::Rcx);
            mark(&mut recipe, code, start, Kind::Store, 0);
        }
        MemoryTransfer::Load { signed, width } => {
            let size = Size::of(width == Width::X64);
            let source = accessed();
            let start = code.checkpoint();
            {
                let mut asm = code.asm();
                asm.guest_access(|asm| match (bytes, signed) {
                    (1, false) => asm.movzx(size, Gpr::Rcx, Size::Byte, source),
                    (2, false) => asm.movzx(size, Gpr::Rcx, Size::Word, source),
                    (1, true) => asm.movsx(size, Gpr::Rcx, Size::Byte, source),
                    (2, true) => asm.movsx(size, Gpr::Rcx, Size::Word, source),
                    (4, true) => {
                        debug_assert!(width == Width::X64);
                        asm.movsxd(Gpr::Rcx, source);
                    }
                    (4 | 8, false) => asm.mov_load(size, Gpr::Rcx, source),
                    _ => unreachable!("decoder validates scalar memory size"),
                });
            }
            mark(
                &mut recipe,
                code,
                start,
                Kind::Load {
                    element: 0,
                    host: Gpr::Rcx,
                },
                mask(Gpr::Rcx),
            );
            // A discarded load still performs its faultable access.
            if let Some(slot) = offset(data) {
                let start = code.checkpoint();
                code.asm().mov_store(Size::Qword, frame(slot), Gpr::Rcx);
                mark(&mut recipe, code, start, Kind::Commit, 0);
            }
        }
    }
    // Commit writeback only after all faultable element accesses succeed.
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
    address(code, checks, location, bytes, access, recipe.as_deref_mut());
    match transfer {
        MemoryTransfer::Store => {
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
            let start = code.checkpoint();
            match offset(data[1]) {
                Some(slot) => code.asm().mov_load(Size::Qword, Gpr::R8, frame(slot)),
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
            for (element, source) in [
                (0, memory_store::Source::Rcx),
                (1, memory_store::Source::R8),
            ] {
                let start = code.checkpoint();
                memory_store::emit(code, bytes, element * bytes, source);
                mark(&mut recipe, code, start, Kind::Store, 0);
            }
        }
        MemoryTransfer::Load { signed, width } => {
            let size = Size::of(width == Width::X64);
            for (element, host, source) in [
                (0, Gpr::Rcx, accessed()),
                (1, Gpr::R8, Mem::base_disp8(Gpr::Rax, bytes as i8)),
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
            for (register, staged) in [(data[0], Gpr::Rcx), (data[1], Gpr::R8)] {
                if let Some(slot) = offset(register) {
                    let start = code.checkpoint();
                    code.asm().mov_store(Size::Qword, frame(slot), staged);
                    mark(&mut recipe, code, start, Kind::Commit, 0);
                }
            }
        }
    }
    // Commit writeback only after all faultable element accesses succeed.
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
