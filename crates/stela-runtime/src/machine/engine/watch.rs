//! Watchpoints on native blocks: pages holding a watched range stay out of
//! the shadow tables ([`super::Watch`]), so every access to them exits with
//! [`super::FaultCause::Watched`] before it is made. The engine then checks
//! the instruction's accesses in order (Arm `AArch64_CheckWatchpoint`) and
//! either takes the watchpoint exception or runs that one instruction with
//! its pages mapped.
//!
//! Tag checks (FEAT_MTE2) take the same path: while the current EL checks
//! the tags of untagged pointers in a half of the address space
//! ([`super::Regime::tag_checks`]), the shadow keeps that half's Tagged
//! memory out, an access to it exits with [`super::FaultCause::TagChecked`],
//! and each access's Tag Check follows its watchpoint check. Tagged
//! pointers reach [`Machine::native_check_fault`], which checks their tags
//! before the untagged retry.
use super::{
    Devices, Host, Machine, RequirementKind, Step, Stop,
    debug::{self, Access},
    tags::{TagCheck, tag_checked_form},
};
use crate::machine::{
    cpu::Exception,
    exception::Class,
    mmu::{
        self,
        alignment::{self, Kind, Shape},
    },
};
use alloc::{vec, vec::Vec};
use stela_compiler::{
    GuestAddress, Lifter,
    aarch64::{
        AddressMode, Decoder, MemoryTransfer, Operation, Register, Width, atomic, literal,
        non_temporal, ordered, register_offset::IndexExtend, simd,
    },
};

const PAGE: u64 = super::FETCH_PAGE;

/// `address` with its top byte replaced by bit 55's sign, as translation
/// regards it under TBI (Arm `AddrTop` and `AArch64_TranslateAddress`).
fn without_tag(address: u64) -> u64 {
    (((address << 8) as i64) >> 8) as u64
}

/// How an instruction's base register is untagged for a retry: the base
/// and whether the instruction loads into it. None when the retry could
/// change what the instruction does: an SP base, which exception entry
/// banks, a base the instruction also stores or swaps, or a form without
/// a base register.
fn untagging(operation: &Operation) -> Option<(Register, bool)> {
    let load = |transfer: MemoryTransfer| matches!(transfer, MemoryTransfer::Load { .. });
    let (base, data, loads): (Register, &[Register], bool) = match operation {
        Operation::Memory {
            transfer,
            data,
            base,
            ..
        } => (*base, core::slice::from_ref(data), load(*transfer)),
        Operation::MemoryPair {
            transfer,
            data,
            base,
            ..
        } => (*base, data, load(*transfer)),
        Operation::MemoryRegisterOffset(operand) => (
            operand.base,
            core::slice::from_ref(&operand.data),
            load(operand.transfer),
        ),
        Operation::MemoryUnprivileged(operand) => (
            operand.base,
            core::slice::from_ref(&operand.data),
            load(operand.transfer),
        ),
        Operation::MemoryNonTemporal(operand) => match &operand.data {
            non_temporal::Data::Integer(data) => (operand.base, data, operand.load),
            non_temporal::Data::Vector(_) => (operand.base, &[], operand.load),
        },
        Operation::Atomic(operand) => {
            let registers = match operand.kind {
                atomic::Kind::CompareExchange { compare, source } => vec![compare, source],
                atomic::Kind::CompareExchangePair { compare, source } => {
                    vec![compare[0], compare[1], source[0], source[1]]
                }
                atomic::Kind::ReadModifyWrite {
                    source,
                    destination,
                    ..
                } => vec![source, destination],
            };
            return (operand.base != Register::Sp && !registers.contains(&operand.base))
                .then_some((operand.base, false));
        }
        Operation::Ordered(ordered::Operand::Transfer {
            kind, data, base, ..
        }) => (
            *base,
            core::slice::from_ref(data),
            *kind != ordered::Kind::Release,
        ),
        Operation::Simd(
            simd::Operand::Memory { base, .. } | simd::Operand::MemoryPair { base, .. },
        ) => (*base, &[], false),
        Operation::Simd(simd::Operand::MemoryRegisterOffset(operand)) => (operand.base, &[], false),
        Operation::Simd(simd::Operand::StructureMemory(operand)) => (operand.base, &[], false),
        _ => return None,
    };
    let overlaps = data.contains(&base);
    (base != Register::Sp && !(overlaps && !loads)).then_some((base, overlaps))
}

/// The base register's value after an untagged retry that moved it by
/// `delta`: what the instruction loaded into it, or else its tagged value
/// with any writeback applied.
fn retagged(value: u64, delta: u64, loaded: bool) -> u64 {
    if loaded {
        value
    } else {
        value.wrapping_sub(delta)
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    fn index_value(&self, index: Register, extend: IndexExtend, shift: u8) -> u64 {
        let raw = self.read_register(index);
        let extended = match extend {
            IndexExtend::Uxtw => raw & 0xffff_ffff,
            IndexExtend::Sxtw => raw as u32 as i32 as i64 as u64,
            IndexExtend::Lsl | IndexExtend::Sxtx => raw,
        };
        extended << shift
    }

    /// The address an immediate-offset form accesses.
    pub(super) fn immediate_address(
        &self,
        base: Register,
        displacement: i32,
        mode: AddressMode,
    ) -> u64 {
        let base = self.read_register(base);
        match mode {
            AddressMode::PostIndex => base,
            AddressMode::Offset | AddressMode::PreIndex => {
                base.wrapping_add(displacement as i64 as u64)
            }
        }
    }

    /// The data accesses of the instruction `word` at `pc`, in Arm's order,
    /// for the forms the system-mode profile compiles, each with the shape
    /// its alignment is checked by: the bytes of each element it transfers.
    /// Prefetches make none.
    pub(super) fn data_accesses(
        &self,
        pc: u64,
        word: u32,
    ) -> Result<Vec<(Access, Shape)>, &'static str> {
        let instruction = Decoder
            .lift(GuestAddress(pc), word)
            .map_err(|_| "a data access by an instruction the decoder does not lift")?;
        let el = self.cpu.pstate.el;
        let access = |address: u64, size: u64, read: bool, write: bool| Access {
            address,
            size,
            read,
            write,
            maintenance: false,
            el,
        };
        let shape = |kind, bytes: u64| Shape {
            kind,
            bytes,
            pair: false,
        };
        let one = |address, size, load: bool| {
            vec![(access(address, size, load, !load), shape(Kind::Plain, size))]
        };
        let pair = |address: u64, size: u64, load: bool| {
            vec![
                (access(address, size, load, !load), shape(Kind::Plain, size)),
                (
                    access(address.wrapping_add(size), size, load, !load),
                    shape(Kind::Plain, size),
                ),
            ]
        };
        let load = |transfer: MemoryTransfer| matches!(transfer, MemoryTransfer::Load { .. });
        Ok(match instruction.operation {
            Operation::Memory {
                transfer,
                bytes,
                base,
                displacement,
                mode,
                ..
            } => one(
                self.immediate_address(base, displacement, mode),
                u64::from(bytes),
                load(transfer),
            ),
            Operation::MemoryPair {
                transfer,
                bytes,
                base,
                displacement,
                mode,
                ..
            } => pair(
                self.immediate_address(base, displacement, mode),
                u64::from(bytes),
                load(transfer),
            ),
            Operation::MemoryRegisterOffset(operand) => one(
                self.read_register(operand.base)
                    .wrapping_add(self.index_value(operand.index, operand.extend, operand.shift)),
                u64::from(operand.bytes),
                load(operand.transfer),
            ),
            Operation::MemoryUnprivileged(operand) => {
                // LDTR and STTR access as EL0 from EL1 (Arm
                // AccessDescriptor el).
                let address =
                    self.immediate_address(operand.base, operand.displacement, AddressMode::Offset);
                let load = load(operand.transfer);
                let bytes = u64::from(operand.bytes);
                vec![(
                    Access {
                        el: if el == 1 { 0 } else { el },
                        ..access(address, bytes, load, !load)
                    },
                    shape(Kind::Plain, bytes),
                )]
            }
            Operation::MemoryNonTemporal(operand) => pair(
                self.immediate_address(operand.base, operand.displacement, AddressMode::Offset),
                u64::from(operand.bytes),
                operand.load,
            ),
            Operation::Atomic(operand) => {
                let bytes = match operand.kind {
                    atomic::Kind::CompareExchangePair { .. } => 2 * u64::from(operand.bytes),
                    _ => u64::from(operand.bytes),
                };
                vec![(
                    access(self.read_register(operand.base), bytes, true, true),
                    shape(Kind::Atomic, bytes),
                )]
            }
            Operation::Ordered(ordered::Operand::Transfer {
                kind,
                bytes,
                base,
                displacement,
                ..
            }) => {
                let address = self
                    .read_register(base)
                    .wrapping_add(displacement as i64 as u64);
                let load = kind != ordered::Kind::Release;
                let bytes = u64::from(bytes);
                vec![(
                    access(address, bytes, load, !load),
                    shape(Kind::Ordered, bytes),
                )]
            }
            Operation::Literal(operand) => {
                let bytes = match operand.transfer {
                    literal::Transfer::Integer { signed: true, .. } => 4,
                    literal::Transfer::Integer {
                        width: Width::W32, ..
                    } => 4,
                    literal::Transfer::Integer { .. } => 8,
                    literal::Transfer::Simd { bytes, .. } => u64::from(bytes),
                };
                one(operand.address, bytes, true)
            }
            Operation::Simd(simd::Operand::Memory {
                load,
                bytes,
                base,
                displacement,
                mode,
                ..
            }) => one(
                self.immediate_address(base, displacement, mode),
                u64::from(bytes),
                load,
            ),
            Operation::Simd(simd::Operand::MemoryPair {
                load,
                bytes,
                base,
                displacement,
                mode,
                ..
            }) => pair(
                self.immediate_address(base, displacement, mode),
                u64::from(bytes),
                load,
            ),
            Operation::Simd(simd::Operand::MemoryRegisterOffset(operand)) => one(
                self.read_register(operand.base)
                    .wrapping_add(self.index_value(operand.index, operand.extend, operand.shift)),
                u64::from(operand.bytes),
                operand.load,
            ),
            Operation::Simd(simd::Operand::StructureMemory(operand)) => {
                let load = operand.direction == simd::structure_memory::Direction::Load;
                // Every element is checked; they are all aligned when the
                // first one is.
                vec![(
                    access(
                        self.read_register(operand.base),
                        u64::from(operand.transferred_bytes()),
                        load,
                        !load,
                    ),
                    shape(Kind::Plain, u64::from(operand.element_bytes)),
                )]
            }
            Operation::Prefetch(_) => Vec::new(),
            _ => return Err("a data access by an unexpected instruction class"),
        })
    }

    /// A native address check failed at `pc`. Take, in Arm's order of the
    /// instruction's accesses, the first one's Alignment fault (Arm
    /// `AArch64_UnalignedAccessFaults`, which comes before translation), or
    /// the fault its translation gives an address outside the guest's two
    /// ranges (`x86_64::RangeCheck`), which the shadow never maps.
    pub(super) fn native_check_fault(
        &mut self,
        index: usize,
        pc: u64,
        word: u32,
        fault: &super::NativeFault,
    ) -> Step {
        let accesses = self.data_accesses(pc, word).map_err(|detail| {
            self.unsupported(RequirementKind::Instruction {
                word,
                detail: alloc::format!(
                    "{detail} ({:?} at native offset {:#x} of the block at {:#x}, address {:#x})",
                    fault.cause,
                    fault.offset,
                    self.blocks[index].pc,
                    fault.address,
                ),
            })
        })?;
        let sctlr = self.cpu.regime_sctlr();
        let placement = self.host.placement();
        let in_guest_range = |address| placement.native(address);
        for (access, shape) in accesses {
            // An atomic access reads and writes: its fault is not a write
            // (Arm `NoFault`).
            let write = access.write && !access.read;
            if alignment::before_translation(sctlr, access.address, shape) {
                return self.alignment_fault(access.address, write);
            }
            if !in_guest_range(access.address) {
                let kind = if write {
                    mmu::Access::Write
                } else {
                    mmu::Access::Read
                };
                return match self.translate_data(access.address, kind) {
                    mmu::Outcome::Fault(fault) => {
                        self.data_abort(access.address, fault, write, false)
                    }
                    mmu::Outcome::Unsupported(unsupported) => {
                        Err(self.unsupported(RequirementKind::Translation(unsupported)))
                    }
                    // An untagged address the host does not map natively:
                    // the page runs in the translated variant.
                    mmu::Outcome::Mapped(_) if !in_guest_range(without_tag(access.address)) => {
                        self.run_translated(index, pc, access.address)
                    }
                    // TBI, or a 52-bit range: the shadow maps 48-bit
                    // untagged addresses only. A tagged base runs again
                    // with its tag cleared.
                    mmu::Outcome::Mapped(_) => {
                        // The retry's accesses are untagged: their
                        // watchpoints and tags are checked here first.
                        if in_guest_range(without_tag(access.address))
                            && let Some(exception) = self.access_exception(pc, word, sctlr)?
                        {
                            self.take(exception);
                            return Ok(());
                        }
                        self.tags_checked_at = Some(pc);
                        let step = self.retry_untagged(pc, word, access.address);
                        self.tags_checked_at = None;
                        if let Some(step) = step {
                            return step;
                        }
                        let mut requirement = self.requirement(RequirementKind::Native(
                            "a tagged or 52-bit data address in native code",
                        ));
                        requirement.address = Some(access.address);
                        Err(super::Stop::Unsupported(requirement))
                    }
                };
            }
        }
        Err(self.unsupported(RequirementKind::Native(
            "a native address check failed where no access faults",
        )))
    }

    /// Run the instruction at `pc`, whose access to the tagged `address`
    /// translates under TBI, once with its base register moved to the
    /// untagged address, which the shadow maps, then put the tag back on
    /// the base (Arm `AddrTop`: translation ignores the top byte, and
    /// writeback keeps it). None when the retry does not apply: the
    /// untagged address is outside the guest's ranges, or [`untagging`]
    /// refuses the base.
    fn retry_untagged(&mut self, pc: u64, word: u32, address: u64) -> Option<Step> {
        let placement = self.host.placement();
        let in_guest_range = |address| placement.native(address);
        let untagged = without_tag(address);
        if untagged == address || !in_guest_range(untagged) {
            return None;
        }
        let operation = Decoder.lift(GuestAddress(pc), word).ok()?.operation;
        let (base, loads_base) = untagging(&operation)?;
        let delta = untagged.wrapping_sub(address);
        let original = self.read_register(base);
        self.write_register(base, original.wrapping_add(delta));
        let in_range = self.data_accesses(pc, word).is_ok_and(|accesses| {
            accesses
                .iter()
                .all(|(access, _)| in_guest_range(access.address))
        });
        if !in_range {
            self.write_register(base, original);
            return None;
        }
        let el = self.cpu.pstate.el;
        let result = match self.fetch_block(pc, true) {
            Ok(super::Fetched::Block(index)) => self.execute(index, 0),
            Ok(super::Fetched::Exception(exception)) => {
                self.take(exception);
                Ok(())
            }
            Ok(super::Fetched::Checked(word)) => self.checked_instruction(pc, word),
            Err(stop) => Err(stop),
        };
        // An exception or a stop leaves the instruction unretired and its
        // base as it was.
        let retired =
            result.is_ok() && self.cpu.pc == pc + super::INSTRUCTION && self.cpu.pstate.el == el;
        let value = self.read_register(base);
        self.write_register(base, retagged(value, delta, retired && loads_base));
        Some(result)
    }

    /// A native access reached a watched page: take the watchpoint exception
    /// of the first matching access, or run the instruction with its pages
    /// mapped.
    pub(super) fn watched_access(&mut self, index: usize, pc: u64) -> Step {
        let word = self.word(index, pc)?;
        let accesses: Vec<Access> = self
            .data_accesses(pc, word)
            .map_err(|detail| self.refuse_word(word, detail))?
            .into_iter()
            .map(|(access, _)| access)
            .collect();
        if let Some(exception) = self.access_exception(pc, word, self.cpu.regime_sctlr())? {
            self.take(exception);
            return Ok(());
        }
        self.pass_watched(pc, &accesses)
    }

    /// The first exception the data accesses of `word` at `pc` take after
    /// translation, in Arm's order: each access's watchpoint, then its Tag
    /// Check for a tag-checked form ([`tag_checked_form`]), unless the
    /// tagged retry of this instruction checked its tags already. Checking
    /// stops at an access that faults before or in translation, which the
    /// instruction then takes when it runs.
    fn access_exception(
        &mut self,
        pc: u64,
        word: u32,
        sctlr: u64,
    ) -> Result<Option<Exception>, Stop> {
        let accesses = self
            .data_accesses(pc, word)
            .map_err(|detail| self.refuse_word(word, detail))?;
        let checked = self.tags_checked_at != Some(pc)
            && Decoder
                .lift(GuestAddress(pc), word)
                .is_ok_and(|instruction| tag_checked_form(&instruction.operation));
        for (access, shape) in accesses {
            if alignment::before_translation(sctlr, access.address, shape) {
                break;
            }
            if let Some(exception) = self.watchpoint_exception(&access, pc) {
                return Ok(Some(exception));
            }
            if !checked {
                continue;
            }
            // LDTR and STTR from EL1 check as EL0 (`data_accesses`).
            let mut requester = self.cpu.requester();
            requester.unprivileged = access.el != self.cpu.pstate.el;
            match self.tag_check(&access, requester, None)? {
                TagCheck::Passed => {}
                TagCheck::Untranslated => break,
                TagCheck::Failed(exception) => return Ok(Some(exception)),
            }
        }
        Ok(None)
    }

    /// The watchpoint exception `access` by the instruction at `pc` takes,
    /// if any: EC 0x34 (lower) or 0x35, CM for cache maintenance, WnR,
    /// DFSC 0b100010 and FAR at the first matching byte.
    pub(super) fn watchpoint_exception(&self, access: &Access, pc: u64) -> Option<Exception> {
        if !debug::watching(&self.cpu) {
            return None;
        }
        let hit = debug::watchpoint(&self.cpu, access)?;
        let iss = u32::from(access.maintenance) << 8 | u32::from(hit.write) << 6 | 0x22;
        let mut exception =
            self.debug_exception(Class::WatchpointLower, Class::WatchpointSame, iss, pc);
        exception.fault_address = Some(hit.address);
        Some(exception)
    }

    /// Run the instruction at `pc` once with the watched pages it touches,
    /// and those of halves whose tags are checked, mapped, then unmap them
    /// again.
    fn pass_watched(&mut self, pc: u64, accesses: &[Access]) -> Step {
        let mut pages: Vec<u64> = Vec::new();
        for access in accesses {
            let last = access.address.wrapping_add(access.size.max(1) - 1);
            for page in [access.address & !(PAGE - 1), last & !(PAGE - 1)] {
                let tag_checked = self.tag_checks[usize::from(page >> 55 & 1 != 0)];
                if (self.watch.blocks(page) || tag_checked) && !pages.contains(&page) {
                    pages.push(page);
                }
            }
        }
        if self.watch.pass.iter().any(Option::is_some) || pages.len() > 2 {
            return Err(self.unsupported(RequirementKind::Native(
                "an access touching more than two watched pages",
            )));
        }
        self.watch.pass = [pages.first().copied(), pages.get(1).copied()];
        self.sync_regime();
        let result = match self.fetch_block(pc, true) {
            Ok(super::Fetched::Block(index)) => self.execute(index, 0),
            Ok(super::Fetched::Exception(exception)) => {
                self.take(exception);
                Ok(())
            }
            Ok(super::Fetched::Checked(word)) => self.checked_instruction(pc, word),
            Err(stop) => Err(stop),
        };
        self.watch.pass = [None; 2];
        // The passed pages leave the shadow tables again.
        self.advance_translation_generation();
        self.host.invalidate_translations();
        self.sync_regime();
        result
    }

    fn refuse_word(&self, word: u32, detail: &'static str) -> super::Stop {
        self.unsupported(RequirementKind::Instruction {
            word,
            detail: detail.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(word: u32) -> Operation {
        Decoder.lift(GuestAddress(0), word).unwrap().operation
    }

    #[test]
    fn untagged_retries_keep_the_tag_on_the_base() {
        let tagged = 0x8000_0001_0425_6e90;
        assert_eq!(without_tag(tagged), 0x0000_0001_0425_6e90);
        assert_eq!(without_tag(0x5aff_fe00_0000_1000), 0xffff_fe00_0000_1000);
        let delta = without_tag(tagged).wrapping_sub(tagged);
        // STP W8, W19, [X0]: X0 keeps its tag.
        assert_eq!(
            untagging(&operation(0x2900_4c08)),
            Some((Register::X(0), false))
        );
        assert_eq!(retagged(without_tag(tagged), delta, false), tagged);
        // LDR X1, [X0, #16]! writes the tagged sum back.
        assert_eq!(
            untagging(&operation(0xf841_0c01)),
            Some((Register::X(0), false))
        );
        assert_eq!(
            retagged(without_tag(tagged) + 16, delta, false),
            tagged + 16
        );
        // LDR X0, [X0] keeps what it loads.
        assert_eq!(
            untagging(&operation(0xf940_0000)),
            Some((Register::X(0), true))
        );
        assert_eq!(retagged(0x1234, delta, true), 0x1234);
        // STR X0, [X0] would store the untagged base, and exception entry
        // banks SP.
        assert_eq!(untagging(&operation(0xf900_0000)), None);
        assert_eq!(untagging(&operation(0xf940_03e0)), None);
    }
}
