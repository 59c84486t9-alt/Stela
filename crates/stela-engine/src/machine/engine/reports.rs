//! What the engine reports: events, stops, unsupported requirements, hits,
//! surveys and statistics.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// An exception taken from `from_el`, a guarded level when
    /// `from_guarded`.
    Exception {
        vector: Vector,
        from_el: u8,
        from_guarded: bool,
        syndrome: u64,
        return_address: u64,
        fault_address: Option<u64>,
    },
    /// An exception return, to a guarded level when `guarded`.
    Return { to_el: u8, guarded: bool, pc: u64 },
    /// An opt-in guarded boundary trace, emitted synchronously without a queue.
    Monitor(MonitorEvent),
    /// GENTER (`enter`) or GEXIT, and the level the PE is now at.
    Guarded {
        enter: bool,
        el: u8,
        guarded: bool,
        pc: u64,
    },
}

/// A requirement this engine does not implement, with where it was met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub pc: u64,
    pub el: u8,
    /// The link register then, which names the caller of an accessor; 0
    /// where no PE state is at hand.
    pub link: u64,
    pub kind: RequirementKind,
    /// The ESR_EL1 value the access would report if it were a guest exception.
    pub syndrome: Option<u64>,
    pub address: Option<u64>,
    /// The value a refused device write carried, which its report shows.
    pub written: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementKind {
    Instruction {
        word: u32,
        detail: String,
    },
    SystemRegister {
        word: u32,
        refusal: Refusal,
    },
    SystemInstruction {
        word: u32,
        detail: &'static str,
    },
    Translation(mmu::Unsupported),
    Fetch {
        physical: u64,
    },
    Device {
        physical: u64,
        write: bool,
        detail: String,
    },
    DeviceAdvance(String),
    IllegalReturn(IllegalReturn),
    /// Entering an EL1&0 guest of the EL2 host while the named Apple VM
    /// register (`impdef::Class::Guest`) holds state the machine does not
    /// apply to a guest.
    VmState(&'static str),
    Native(&'static str),
    ParallelAdmission(ParallelAdmissionError),
    /// Register residency cannot be recovered from the host capture.
    FaultRecovery(stela_compiler::block::FaultRecoveryError),
    /// Detailed refusal before a checked native frame was executed.
    NativePreparation(String),
}

impl fmt::Display for Requirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pc={:#x} el={} ", self.pc, self.el)?;
        if self.link != 0 {
            write!(f, "lr={:#x} ", self.link)?;
        }
        match &self.kind {
            RequirementKind::Instruction { word, detail } => {
                write!(f, "instruction {word:#010x}: {detail}")?
            }
            RequirementKind::SystemRegister { word, refusal } => {
                let access = stela_compiler::aarch64::system::registers::decode(*word);
                match access {
                    Some(access) => {
                        let e = access.encoding();
                        write!(
                            f,
                            "system register {} S{}_{}_C{}_C{}_{} ({word:#010x}): {refusal:?}",
                            if access.direction() == Direction::Read {
                                "read"
                            } else {
                                "write"
                            },
                            e.op0(),
                            e.op1(),
                            e.crn(),
                            e.crm(),
                            e.op2()
                        )?
                    }
                    None => write!(f, "system register {word:#010x}: {refusal:?}")?,
                }
            }
            RequirementKind::SystemInstruction { word, detail } => {
                write!(f, "system instruction {word:#010x}: {detail}")?
            }
            RequirementKind::Translation(unsupported) => {
                write!(f, "translation configuration {unsupported:?}")?
            }
            RequirementKind::Fetch { physical } => {
                write!(f, "instruction fetch from non-RAM PA {physical:#x}")?
            }
            RequirementKind::Device {
                physical,
                write,
                detail,
            } => {
                write!(
                    f,
                    "device {} at PA {physical:#x}: {detail}",
                    if *write { "write" } else { "read" }
                )?;
                if let Some(value) = self.written {
                    write!(f, " (value {value:#x})")?;
                }
            }
            RequirementKind::DeviceAdvance(detail) => write!(f, "device advance: {detail}")?,
            RequirementKind::IllegalReturn(reason) => write!(f, "exception return {reason:?}")?,
            RequirementKind::VmState(register) => write!(
                f,
                "entering an EL1&0 guest with nonzero Apple VM state in {register}"
            )?,
            RequirementKind::Native(detail) => write!(f, "native execution: {detail}")?,
            RequirementKind::ParallelAdmission(error) => write!(f, "parallel admission: {error}")?,
            RequirementKind::FaultRecovery(cause) => write!(f, "native fault recovery: {cause}")?,
            RequirementKind::NativePreparation(detail) => {
                write!(f, "native preparation: {detail}")?
            }
        }
        if let Some(syndrome) = self.syndrome {
            write!(f, " esr={syndrome:#x}")?;
        }
        if let Some(address) = self.address {
            write!(f, " far={address:#x}")?;
        }
        Ok(())
    }
}

/// Trace hits kept between [`Machine::take_trace_hits`] calls.
pub const TRACE_HITS: usize = 4096;

/// Watch hits kept between [`Machine::take_watch_hits`] calls.
pub const WATCH_HITS: usize = 4096;

/// A device access inside a host watch range (`Machine::set_watches`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchHit {
    pub pc: u64,
    pub pe: usize,
    pub physical: u64,
    pub bytes: u8,
    /// The value read or written; zero for a refused access.
    pub value: u64,
    pub write: bool,
    /// Whether the device completed the access.
    pub completed: bool,
    /// Further hits dropped after this one, beyond [`WATCH_HITS`].
    pub dropped: u64,
}

/// A device register's accesses ([`Machine::device_registers`]) and, under
/// step timing, the profile-clock ticks of the native faults that reached it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeviceRegister {
    pub accesses: u64,
    pub ticks: u64,
}

/// A PE reaching a host trace point (`Machine::set_traces`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceHit {
    pub pc: u64,
    pub pe: usize,
    pub el: u8,
    /// X0 to X3 and the link register.
    pub arguments: [u64; 4],
    pub lr: u64,
    /// Further hits dropped after this one, beyond [`TRACE_HITS`].
    pub dropped: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The block budget ran out.
    Budget,
    /// Every PE is off or waits in WFI or WFE with nothing able to wake it.
    Idle,
    /// Every PE is off or waits, and the run's waits reached the wait limit
    /// (`Machine::set_wait_limit`), a device has bytes for the host
    /// (`Devices::take_host_service`), or only something outside the board
    /// can end the wait (`Devices::waits_on_host`) and no limit is set. The
    /// host takes its inputs and runs the machine again to go on waiting.
    Waiting,
    /// A device carried out the guest's reset or power-off request.
    Reset(Reset),
    Unsupported(Requirement),
    /// The native implementation failed. Its owned code/capture remain held;
    /// the current frame is not a resumable architectural guest state.
    NativeFailure(Arc<NativeFailure>),
    /// An unexecuted device read kept by the canonical scheduler.
    DeviceRead(DeviceReadRequest),
    /// An unexecuted write, kept by the same canonical cohort owner.
    DeviceWrite(DeviceWriteRequest),
    /// The running PE reached a host breakpoint (`Machine::set_breakpoints`)
    /// at this PC, before executing its instruction.
    Breakpoint(u64),
}

/// A machine-wide transition a device carried out for the guest: what the
/// host must do next and the device's account of why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reset {
    pub transition: Transition,
    pub reason: String,
}

impl fmt::Display for Reset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.transition, self.reason)
    }
}

/// Where the running regime's TTBR1 tables map ([`Machine::upper_occupancy`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occupancy {
    /// The level-1 table's physical address.
    pub root: u64,
    /// First and last VA of each run of valid level-1 entries.
    pub ranges: Vec<(u64, u64)>,
    /// The first and last byte of the outermost mapped 32 MiB, where the
    /// outermost entries are tables; their whole entry otherwise.
    pub lowest: Option<u64>,
    pub highest: Option<u64>,
}

/// Where a guest thread stopped running: the PE's PC, frame pointer and
/// link register, and the physical count, when software replaced the thread
/// pointer naming it (TPIDR_EL1). While the thread stays suspended its stack
/// still holds the frame records `frame` starts, so diagnostics can walk
/// where it waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suspension {
    pub at: u64,
    pub pc: u64,
    pub frame: u64,
    pub link: u64,
}

/// The suspended threads [`Machine`] remembers at most.
pub(super) const SUSPENSIONS: usize = 1 << 14;

/// One device register a survey answered in place of its model: where it
/// was first reached, how often, the last value written to it, and the
/// device layer's reason for refusing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surveyed {
    pub physical: u64,
    pub bytes: u8,
    pub write: bool,
    pub pc: u64,
    /// The link register then, which names the caller of an accessor.
    pub link: u64,
    pub count: u64,
    pub value: u64,
    pub detail: String,
}

/// A survey's records by register and direction, and those not yet taken.
#[derive(Default)]
pub(super) struct Survey {
    pub(super) records: BTreeMap<(u64, bool), Surveyed>,
    pub(super) fresh: Vec<(u64, bool)>,
}

/// Why the engine discarded every installed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// Guest IC maintenance of every page, on this PE or broadcast by
    /// another.
    Maintenance,
    /// Low memory that releasing older code could not relieve.
    Memory,
    /// The block table could not grow.
    Table,
    /// A full code arena of one part.
    Arena,
    /// Breakpoints or traces changed, which every block embeds.
    Diagnostics,
    /// The run ended.
    Finished,
}

impl Discard {
    pub const ALL: [Self; 6] = [
        Self::Maintenance,
        Self::Memory,
        Self::Table,
        Self::Arena,
        Self::Diagnostics,
        Self::Finished,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Maintenance => "maintenance",
            Self::Memory => "memory",
            Self::Table => "table",
            Self::Arena => "arena",
            Self::Diagnostics => "diagnostics",
            Self::Finished => "finished",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "std", feature = "native-profile"),
    derive(serde::Serialize)
)]
pub struct Statistics {
    pub blocks: u64,
    /// Retirements from CPU incarnations replaced by a real PE restart.
    /// Add live/parked CPU counters through `retired_instructions`.
    pub replaced_retired: u128,
    /// Blocks entered through a chain from another, without the engine.
    pub chained: u64,
    /// Direct exits redirected into their successors.
    pub links: u64,
    /// Links undone, as the blocks they chained into went.
    pub unlinks: u64,
    /// Exits redirected through a lookup of their target (returns and
    /// direct exits out of their page), and the transfers those made.
    pub lookups: u64,
    pub lookup_hits: u64,
    /// Native runs that ended in an exit to the engine, by `ExitKind`
    /// (Fallthrough, Direct, Indirect, Call, Return, Trap, PAC, Clock,
    /// ThreadRegister, FloatingPoint, ScalableNumerical, System, AMX).
    pub exit_kinds: [u64; 13],
    /// Exits of returns, indirect branches, calls and direct exits out of
    /// their page, by why no lookup dispatcher transferred them: none was
    /// installed yet, the ITLB held no translation of the target's page in
    /// the current context, the block table no entry of the target with
    /// that page's key, the chain budget was spent, or the entry refused
    /// the BTYPE.
    pub lookup_misses: [u64; 5],
    /// Forgotten lookup contexts and ITLB entries: halves whose contexts
    /// went for an ASIDE1 or a TLBI of everything, halves a TLBI by VA
    /// reached ITLB entries of, and halves whose contexts went for any
    /// other change (an unscoped translation change, the host's fetch
    /// permissions, the upper half's first non-global fetch).
    pub lookup_forgets: [u64; 4],
    /// Fetches the engine made, by where they found their block: the block
    /// table through the ITLB's translation, there after the fetch
    /// translated the page anew, the jump cache, the block index, or
    /// nowhere, so that it was compiled or installed.
    pub fetches: [u64; 5],
    /// Pages the ITLB lacked in the context it took their translation in,
    /// and pages it held there that took a new block key (a remap, or the
    /// frame's blocks taking another variant).
    pub itlb: [u64; 2],
    pub compiled: u64,
    /// Counter ticks spent analyzing and compiling `compiled`.
    pub compile_ticks: u64,
    /// Blocks taken from the persistent translation store instead of
    /// compiled, and compiled blocks offered to it.
    pub stored: u64,
    pub offered: u64,
    /// Blocks another thread of the process (or its ahead-of-time
    /// translation) had prepared, installed instead of compiled.
    pub shared: u64,
    /// Counter ticks spent, for blocks not yet installed, reading, hashing
    /// and looking up their fetch pages; finding `shared` blocks; and
    /// installing every block.
    pub page_ticks: u64,
    pub shared_ticks: u64,
    pub install_ticks: u64,
    /// Fetch pages read again whose key a check of their bytes gave
    /// without hashing them ([`stored::page_check`]).
    pub known_keys: u64,
    /// Device transfers run because their deadline came, and the devices'
    /// interrupt lines and deadline asked anew because a cached answer
    /// expired, with the profile clock ticks each took under step timing.
    pub due_transfers: u64,
    pub transfer_ticks: u64,
    pub line_queries: u64,
    pub line_ticks: u64,
    /// Guest instructions in `compiled`.
    pub compiled_instructions: u64,
    pub exceptions: u64,
    pub interrupts: u64,
    pub system_exits: u64,
    pub device_accesses: u64,
    /// Discards of every installed block, by [`Discard`] cause.
    pub code_discards: [u64; Discard::ALL.len()],
    /// Parts of the code arena reclaimed for new code, oldest first.
    pub code_evictions: u64,
    /// Parts of the code arena released for heap pressure.
    pub code_releases: u64,
    /// Blocks another PE of the board installed first, whose own install
    /// was dropped.
    pub lost_installs: u64,
    /// Pages of compiled code an IC IVAU made stale.
    pub code_invalidations: u64,
    pub waits: u64,
    /// Changes of the running PE.
    pub switches: u64,
    /// Translation control writes that dropped every cached translation.
    pub translation_changes: u64,
    /// TLBIs, and those of them whose reach in the shadow was less than
    /// everything.
    pub tlb_maintenance: u64,
    pub scoped_maintenance: u64,
    /// TTBR0 writes, which drop the lower half's.
    pub table_base_changes: u64,
    /// Guest context changes at which the host isolated its branch
    /// predictions ([`PredictionContext`]).
    pub prediction_isolations: u64,
    /// Fetch pages whose blocks run in the translated variant, because one
    /// of their accesses reached a guest address outside the host's native
    /// ranges.
    pub translated_pages: u64,
    /// Operations answered with a degraded response; each distinct one is
    /// also reported once ([`Machine::take_unmodeled`]).
    pub degraded: u64,
    /// Counter ticks the host core halted while the PE waited, and spun
    /// while it waited for an event another core's store to its monitored
    /// granule sends.
    pub sleep_ticks: u64,
    pub spin_ticks: u64,
    /// With every PE on a core of its own: maintenance this PE broadcast,
    /// device accesses it forwarded to the home machine, and the counter
    /// ticks it spent waiting on other PEs for those or parked while the
    /// home machine served another's.
    pub broadcasts: u64,
    pub forwards: u64,
    pub sync_ticks: u64,
}

impl core::ops::AddAssign for Statistics {
    fn add_assign(&mut self, other: Self) {
        let Self {
            blocks,
            replaced_retired,
            chained,
            links,
            unlinks,
            lookups,
            lookup_hits,
            exit_kinds,
            lookup_misses,
            lookup_forgets,
            fetches,
            itlb,
            compiled,
            compile_ticks,
            stored,
            offered,
            shared,
            page_ticks,
            known_keys,
            shared_ticks,
            install_ticks,
            due_transfers,
            transfer_ticks,
            line_queries,
            line_ticks,
            compiled_instructions,
            exceptions,
            interrupts,
            system_exits,
            device_accesses,
            code_discards,
            code_evictions,
            code_releases,
            lost_installs,
            code_invalidations,
            waits,
            switches,
            translation_changes,
            tlb_maintenance,
            scoped_maintenance,
            table_base_changes,
            prediction_isolations,
            translated_pages,
            degraded,
            sleep_ticks,
            spin_ticks,
            broadcasts,
            forwards,
            sync_ticks,
        } = other;
        self.replaced_retired = self.replaced_retired.saturating_add(replaced_retired);
        for (total, count) in self.exit_kinds.iter_mut().zip(exit_kinds) {
            *total += count;
        }
        for (total, count) in self.code_discards.iter_mut().zip(code_discards) {
            *total += count;
        }
        for (total, count) in self.lookup_misses.iter_mut().zip(lookup_misses) {
            *total += count;
        }
        for (total, count) in self.lookup_forgets.iter_mut().zip(lookup_forgets) {
            *total += count;
        }
        for (total, count) in self.fetches.iter_mut().zip(fetches) {
            *total += count;
        }
        for (total, count) in self.itlb.iter_mut().zip(itlb) {
            *total += count;
        }
        for (total, count) in [
            (&mut self.blocks, blocks),
            (&mut self.chained, chained),
            (&mut self.links, links),
            (&mut self.unlinks, unlinks),
            (&mut self.lookups, lookups),
            (&mut self.lookup_hits, lookup_hits),
            (&mut self.compiled, compiled),
            (&mut self.compile_ticks, compile_ticks),
            (&mut self.stored, stored),
            (&mut self.offered, offered),
            (&mut self.shared, shared),
            (&mut self.page_ticks, page_ticks),
            (&mut self.known_keys, known_keys),
            (&mut self.shared_ticks, shared_ticks),
            (&mut self.install_ticks, install_ticks),
            (&mut self.due_transfers, due_transfers),
            (&mut self.transfer_ticks, transfer_ticks),
            (&mut self.line_queries, line_queries),
            (&mut self.line_ticks, line_ticks),
            (&mut self.compiled_instructions, compiled_instructions),
            (&mut self.exceptions, exceptions),
            (&mut self.interrupts, interrupts),
            (&mut self.system_exits, system_exits),
            (&mut self.device_accesses, device_accesses),
            (&mut self.code_evictions, code_evictions),
            (&mut self.code_releases, code_releases),
            (&mut self.lost_installs, lost_installs),
            (&mut self.code_invalidations, code_invalidations),
            (&mut self.waits, waits),
            (&mut self.switches, switches),
            (&mut self.translation_changes, translation_changes),
            (&mut self.tlb_maintenance, tlb_maintenance),
            (&mut self.scoped_maintenance, scoped_maintenance),
            (&mut self.table_base_changes, table_base_changes),
            (&mut self.prediction_isolations, prediction_isolations),
            (&mut self.translated_pages, translated_pages),
            (&mut self.degraded, degraded),
            (&mut self.sleep_ticks, sleep_ticks),
            (&mut self.spin_ticks, spin_ticks),
            (&mut self.broadcasts, broadcasts),
            (&mut self.forwards, forwards),
            (&mut self.sync_ticks, sync_ticks),
        ] {
            *total += count;
        }
    }
}

/// The heap bytes of a machine's code bookkeeping, by structure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Footprint {
    /// The block records, which hold their recovery owners; `owners` is 0
    /// since they moved there.
    pub blocks: usize,
    pub owners: usize,
    /// The live blocks' direct exit lists and recovery rows.
    pub successors: usize,
    pub rows: usize,
    /// The block index and the lookup table's index of granules.
    pub index: usize,
    pub lookup: usize,
    /// The fetch pages kept for the translation store.
    pub pages: usize,
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// What its code bookkeeping holds now: a walk of every block, for
    /// reports.
    pub fn footprint(&self) -> Footprint {
        // The walks of every block take no board lock: rows are under
        // their records' locks; only the index and table sizes need it.
        let rows = self.code.blocks.recovery().heap_bytes();
        let successors = self
            .code
            .blocks
            .iter()
            .map(|(_, block)| block.successors.len() * size_of::<super::Successor>())
            .sum();
        let cache = self.code.cache_at(super::board::LockSite::Report);
        Footprint {
            blocks: self.code.blocks.heap_bytes(),
            // Owners live in the block records, which `blocks` counts.
            owners: 0,
            successors,
            rows,
            index: cache.index.heap_bytes(),
            lookup: cache.targets.index_bytes() + self.itlb.index_bytes(),
            pages: (self.pages.len() + self.spare_pages.len()) * crate::translations::PAGE_BYTES,
        }
    }
}
