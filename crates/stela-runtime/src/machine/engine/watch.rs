//! Watchpoints on native blocks: pages holding a watched range stay out of
//! the shadow tables ([`super::Watch`]), so every access to them exits with
//! [`super::FaultCause::Watched`] before it is made. The engine then checks
//! the instruction's accesses in order (Arm `AArch64_CheckWatchpoint`) and
//! either takes the watchpoint exception or runs that one instruction with
//! its pages mapped.
use super::{
    Devices, Host, Machine, RequirementKind, Step,
    debug::{self, Access},
};
use crate::machine::{
    cpu::Exception,
    exception::Class,
    mmu::alignment::{self, Kind, Shape},
};
use alloc::{vec, vec::Vec};
use stela_compiler::{
    GuestAddress, Lifter,
    aarch64::{
        AddressMode, Decoder, MemoryTransfer, Operation, Register, Width, atomic, literal, ordered,
        register_offset::IndexExtend, simd,
    },
};

const PAGE: u64 = super::FETCH_PAGE;

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
    fn immediate_address(&self, base: Register, displacement: i32, mode: AddressMode) -> u64 {
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

    /// A native alignment check in the block at `index` failed at `pc`:
    /// take the Alignment fault of the first access that has one (Arm
    /// `AArch64_UnalignedAccessFaults`), which comes before translation.
    pub(super) fn native_alignment_fault(&mut self, pc: u64, word: u32) -> Step {
        let accesses = self
            .data_accesses(pc, word)
            .map_err(|detail| self.refuse_word(word, detail))?;
        let sctlr = self.cpu.controls(self.cpu.regime()).sctlr;
        match accesses
            .iter()
            .find(|(access, shape)| alignment::before_translation(sctlr, access.address, *shape))
        {
            // An atomic access reads and writes: its fault is not a write
            // (Arm `NoFault`).
            Some((access, _)) => self.alignment_fault(access.address, access.write && !access.read),
            None => Err(self.unsupported(RequirementKind::Native(
                "a native alignment check failed where no access faults",
            ))),
        }
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
        if let Some(exception) = accesses
            .iter()
            .find_map(|access| self.watchpoint_exception(access, pc))
        {
            self.take(exception);
            return Ok(());
        }
        self.pass_watched(pc, &accesses)
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

    /// Run the instruction at `pc` once with the watched pages it touches
    /// mapped, then unmap them again.
    fn pass_watched(&mut self, pc: u64, accesses: &[Access]) -> Step {
        let mut pages: Vec<u64> = Vec::new();
        for access in accesses {
            let last = access.address.wrapping_add(access.size.max(1) - 1);
            for page in [access.address & !(PAGE - 1), last & !(PAGE - 1)] {
                if self.watch.blocks(page) && !pages.contains(&page) {
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
            Ok(super::Fetched::Block(index)) => self.execute(index),
            Ok(super::Fetched::Exception(exception)) => {
                self.take(exception);
                Ok(())
            }
            Ok(super::Fetched::Checked(word)) => self.checked_instruction(pc, word),
            Err(stop) => Err(stop),
        };
        self.watch.pass = [None; 2];
        // The passed pages leave the shadow tables again.
        self.translation_generation += 1;
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
