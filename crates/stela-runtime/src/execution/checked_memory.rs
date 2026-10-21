//! Immutable checked GPR blocks with a private native mapping per worker.
//!
//! This is a bounded execution boundary, not a hosted-process or machine SMP
//! scheduler. Every memory access uses the retained shared memory service;
//! direct-RAM blocks and caller-supplied native artifacts are excluded.

use super::{context::ContextLoan, floating_environment::HostFloatingEnvironment, platform};
use crate::{
    blocks::ThreadState,
    memory::{domain::MemoryThread, policy::MemoryControls},
    system::{
        events::EventEndpoint, execution::EntryBoundary,
        process_memory::FixedProcessMemoryControls, state::SystemState,
    },
};
use anyhow::{Result, ensure};
use std::{marker::PhantomData, rc::Rc};
use stela_compiler::{
    GuestAddress, Lifter, TargetCpu,
    aarch64::{Decoder, Operation},
    block::{BlockExit, BlockProfile, CheckedMemoryProfile, CompilationPlan},
    context::{ExecutionContext, memory::MemoryRequirements},
};

pub use crate::memory::domain::MemoryFault;

/// Source-bound identity. It never authorizes loading external native bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Identity {
    pub address_space: u64,
    pub entry: GuestAddress,
    pub source_sha256: String,
    pub native_sha256: String,
    pub native_bytes: usize,
    pub compiler_source_sha256: &'static str,
    pub target: TargetCpu,
    pub abi: &'static str,
    /// Distinguishes this all-writer checked contract from direct-RAM profiles.
    pub memory_model: &'static str,
}

/// One native block and its exact compiler-derived entry requirements. Create
/// this inside each worker: mappings, CPU state and contexts are not shared.
pub struct CheckedMemoryBlock {
    identity: Identity,
    source: Vec<u8>,
    source_map: Vec<(GuestAddress, usize)>,
    requirements: MemoryRequirements,
    profile: CheckedMemoryProfile,
    mapping: platform::Mapping,
    _worker: PhantomData<Rc<()>>,
}

#[derive(Debug)]
pub struct Observation {
    pub exit: BlockExit,
    pub fault: Option<MemoryFault>,
}

/// A finalization failure keeps the native observation available for diagnosis;
/// returning from native code alone does not establish successful retirement.
#[derive(Debug, Clone, Copy)]
pub struct RawMemoryObservation {
    pub version: u32,
    pub bytes: u32,
    pub status_code: u32,
    pub access_code: u32,
    pub address: u64,
    pub pc: u64,
    pub completed_bytes: u64,
}

#[derive(Debug)]
pub struct FinalizationFailure {
    pub status: stela_compiler::context::memory::MemoryStatus,
    pub observation: Option<Observation>,
    pub raw_memory: Option<RawMemoryObservation>,
}
impl core::fmt::Display for FinalizationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "checked block finalization failed: {:?}; observation: {:?}; raw memory: {:?}",
            self.status, self.observation, self.raw_memory
        )
    }
}
impl core::error::Error for FinalizationFailure {}

impl CheckedMemoryBlock {
    /// Compile one complete source block. Trailing unconsumed bytes are refused
    /// so the retained identity always describes exactly what may execute.
    pub fn compile(
        address_space: u64,
        entry: GuestAddress,
        source: Vec<u8>,
        profile: CheckedMemoryProfile,
        target: TargetCpu,
    ) -> Result<Self> {
        ensure!(
            matches!(
                profile,
                CheckedMemoryProfile::SpAlignmentEnabled
                    | CheckedMemoryProfile::SpAlignmentDisabled
            ),
            "this boundary requires the fixed checked GPR memory profile"
        );
        ensure!(
            !target.data_independent_timing(),
            "shared memory does not admit the single-agent DIT target"
        );
        ensure!(
            crate::platform::cpu::admitted(target),
            "host lacks native target requirements"
        );
        ensure!(
            !source.is_empty() && source.len() <= 4096,
            "source must be one bounded nonempty block"
        );
        ensure!(
            entry.0.checked_add(source.len() as u64).is_some(),
            "source address overflow"
        );
        let plan =
            CompilationPlan::new(&source, entry, BlockProfile::CheckedMemory(profile), target)?;
        ensure!(
            plan.source_bytes() == source.len(),
            "source contains unconsumed trailing bytes"
        );
        // The fixed memory authority establishes LSE2/EL0 memory controls, not
        // arbitrary guest instruction extensions. Reuse the existing baseline
        // register qualification; optional instructions require a CPU owner.
        for (index, bytes) in source.as_chunks::<4>().0.iter().enumerate() {
            let word = u32::from_le_bytes(*bytes);
            let instruction = Decoder
                .lift(GuestAddress(entry.0 + (index * 4) as u64), word)
                .map_err(|error| anyhow::anyhow!("source outside checked baseline: {error:?}"))?;
            ensure!(
                crate::system::fixed_execution::baseline_register_operation(
                    word,
                    &instruction.operation
                ) || matches!(
                    instruction.operation,
                    Operation::Exclusive(_)
                        | Operation::Atomic(_)
                        | Operation::Ordered(_)
                        | Operation::Literal(_)
                        | Operation::MemoryRegisterOffset(_)
                        | Operation::MemoryNonTemporal(_)
                        | Operation::MemoryUnprivileged(_)
                        | Operation::Memory { .. }
                        | Operation::MemoryPair { .. }
                ),
                "instruction requires a separate guest CPU authority"
            );
        }
        let requirements = plan.memory_requirements().expect("checked memory plan");
        let compiled = plan.compile()?;
        let identity = Identity {
            address_space,
            entry,
            source_sha256: crate::sha256(&source),
            native_sha256: crate::sha256(&compiled.native.x86_64_code),
            native_bytes: compiled.native.x86_64_code.len(),
            compiler_source_sha256: stela_compiler::SOURCE_SHA256,
            target,
            abi: profile.abi(),
            memory_model: "checked-normal-wb-all-writers-reservations-lse-ordered-memory-v2",
        };
        let mapping = platform::Mapping::new(&compiled.native.x86_64_code)?;
        Ok(Self {
            identity,
            source,
            source_map: compiled.native.source_map,
            requirements,
            profile,
            mapping,
            _worker: PhantomData,
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Enter with the existing typed CPU authority. Its controls, PE event
    /// attachment, domain and effective policy remain borrowed until the memory
    /// service finalizes. Distinct workers may hold execution loans together;
    /// mapping/protection publication still requires an exclusive service loan.
    ///
    /// # Safety
    /// The outer execution owner must qualify instruction fetch of this exact
    /// immutable source at its original PC, the guest's baseline instruction
    /// availability and source attributes, and debug/step/interrupt admission.
    /// Its CPU state and memory controls must describe this same PE and machine.
    /// All guest storage and writers must obey the retained domain's binding
    /// contract, with no external/direct-RAM writers or concurrent host rights
    /// changes. Source, state, native code, host stacks and runtime metadata
    /// must be disjoint from writable guest RAM. This method supplies checked
    /// memory invocation and PC settlement, not full PE execution authority.
    pub unsafe fn run(
        &self,
        controls: &FixedProcessMemoryControls,
        system: &SystemState,
        memory: &mut MemoryThread<MemoryControls>,
        event: &EventEndpoint,
        state: &mut ThreadState,
    ) -> Result<Observation> {
        ensure!(
            state.pc == self.identity.entry,
            "thread PC differs from checked source entry"
        );
        // The outer provider loan extends beyond the prepared invocation's own
        // loan, through finalization and exact architectural PC settlement.
        let _publication = memory
            .execution_loan()
            .map_err(|status| anyhow::anyhow!("checked publication loan refused: {status:?}"))?;
        let boundary = EntryBoundary::new(
            self.identity.address_space,
            1,
            self.identity.entry,
            self.identity.entry,
            self.source.len(),
            u32::from_le_bytes(self.source[..4].try_into().expect("complete instruction")),
        );
        let entry = controls
            .prepare(
                &boundary,
                self.requirements,
                system,
                &state.registers,
                memory,
                Some(event),
            )
            .map_err(|error| anyhow::anyhow!("checked CPU entry refused: {error:?}"))?;
        ensure!(
            entry.requirements() == self.requirements
                && entry.profile_id() == self.profile.process_memory_profile_id(),
            "checked body/authority mismatch"
        );
        let _floating = HostFloatingEnvironment::capture();
        let mut context = ExecutionContext::default();
        let mut observation = None;
        let mut raw_memory = None;
        // SAFETY: only this owner's exact compiler-produced checked mapping is
        // invoked. The typed entry retains CPU policy/storage/PE borrows, and
        // private state, context and staging cannot escape the synchronous call.
        let finalized = unsafe {
            entry.with_view(|view| {
                let mut loan = ContextLoan::memory(&mut context, view);
                let exit = self
                    .mapping
                    .call_context_block(&mut state.registers, loan.context())?;
                raw_memory = Some(RawMemoryObservation {
                    version: view.version,
                    bytes: view.bytes,
                    status_code: view.fault_kind,
                    access_code: view.fault_access,
                    address: view.fault_address,
                    pc: view.fault_pc,
                    completed_bytes: view.completed_bytes,
                });
                ensure!(
                    loan.context().has_supported_header()
                        && loan.context().memory == core::ptr::from_mut(view).cast(),
                    "checked context association changed during native call"
                );
                let status =
                    stela_compiler::context::memory::MemoryStatus::from_code(view.fault_kind)
                        .ok_or_else(|| anyhow::anyhow!("unknown checked memory status"))?;
                let access =
                    stela_compiler::context::memory::FaultAccess::from_code(view.fault_access)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "unknown checked memory fault access {}",
                                view.fault_access
                            )
                        })?;
                let fault = (status != stela_compiler::context::memory::MemoryStatus::Success)
                    .then_some(MemoryFault {
                        access,
                        status,
                        address: view.fault_address,
                        pc: view.fault_pc,
                        completed_bytes: view.completed_bytes,
                    });
                observation = Some(Observation { exit, fault });
                if let Some(fault) = observation.as_ref().and_then(|value| value.fault) {
                    ensure!(
                        self.source_map.iter().any(|(pc, _)| pc.0 == fault.pc),
                        "fault outside consumed source"
                    );
                }
                Ok::<(), anyhow::Error>(())
            })
        };
        match finalized {
            Ok(result) => result?,
            Err(status) => {
                return Err(FinalizationFailure {
                    status,
                    observation,
                    raw_memory,
                }
                .into());
            }
        }
        let observation = observation
            .ok_or_else(|| anyhow::anyhow!("checked entry returned without an observation"))?;
        state.pc = GuestAddress(
            observation
                .fault
                .map_or(observation.exit.next_pc, |fault| fault.pc),
        );
        Ok(observation)
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    //! Native two-worker qualification of the existing typed process authority.
    use super::*;
    use crate::{
        memory::{
            backing::{AccessPermissions, MemoryBacking, MemoryView},
            domain::{MappingAttributes, MemoryDomain, MemorySystem},
            policy::{LowerAddressProfile, TagCheckFaultMode},
        },
        system::{
            events::EventDomain,
            process_memory::{ProcessMemoryFeatures, SourceNormalWbDomain},
            profile::BaseSpeAbsence,
            state::El1Registers,
        },
    };
    use std::{
        alloc::{Layout, alloc_zeroed, dealloc},
        ptr::NonNull,
        sync::{Arc, Barrier},
        time::{Duration, Instant},
    };
    use stela_compiler::GuestState;
    use stela_compiler::context::memory::MemoryStatus;

    const ASID: u64 = 7;
    const PC: GuestAddress = GuestAddress(0x1000);
    const DATA: u64 = 0x4000;
    const ALIAS: u64 = 0x8000;
    const RET: u32 = 0xd65f_03c0;
    const LDXR: u32 = 0xc85f_7c01; // ldxr x1,[x0]
    const STXR: u32 = 0xc802_7c01; // stxr w2,x1,[x0]
    const ADD: u32 = 0x9100_0421; // add x1,x1,#1
    const STR: u32 = 0xf900_0001; // str x1,[x0]
    const RIGHTS: AccessPermissions = AccessPermissions {
        readable: true,
        writable: true,
        executable: false,
    };

    struct Storage {
        pointer: NonNull<u8>,
        layout: Layout,
    }
    // SAFETY: only raw storage is shared, never Rust byte references. Every access
    // participates in the one MemorySystem through checked native callbacks.
    unsafe impl Send for Storage {}
    unsafe impl Sync for Storage {}
    impl Drop for Storage {
        fn drop(&mut self) {
            unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }

    fn domain() -> Arc<MemoryDomain> {
        domain_storage().0
    }
    fn domain_storage() -> (Arc<MemoryDomain>, Arc<MemorySystem>, Arc<MemoryBacking>) {
        let layout = Layout::from_size_align(128, 64).unwrap();
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        let storage = Arc::new(Storage { pointer, layout });
        // SAFETY: the retained owner pins coherent raw RAM and rights. One backing
        // identity covers both guest aliases and no external writer exists.
        let backing = unsafe { MemoryBacking::new(pointer, 128, RIGHTS, storage) }.unwrap();
        let view = MemoryView::new(Arc::clone(&backing), DATA, 0, 128, RIGHTS).unwrap();
        let alias = MemoryView::new(Arc::clone(&backing), ALIAS, 0, 128, RIGHTS).unwrap();
        let write_only = MemoryView::new(
            Arc::clone(&backing),
            ALIAS + 0x3000,
            0,
            128,
            AccessPermissions {
                readable: false,
                ..RIGHTS
            },
        )
        .unwrap();
        let read_only = MemoryView::new(
            Arc::clone(&backing),
            ALIAS + 0x1000,
            0,
            128,
            AccessPermissions {
                writable: false,
                ..RIGHTS
            },
        )
        .unwrap();
        let attributes = MappingAttributes {
            tagged: false,
            shareable: true,
        };
        let system = MemorySystem::new(64, 8).unwrap();
        let domain = MemoryDomain::new_for_address_space(
            ASID,
            Arc::clone(&system),
            vec![
                (view, attributes),
                (alias, attributes),
                (read_only, attributes),
                (write_only, attributes),
            ],
            TargetCpu::detect(),
        )
        .unwrap();
        (domain, system, backing)
    }

    struct Worker {
        controls: FixedProcessMemoryControls,
        system: SystemState,
        memory: MemoryThread<MemoryControls>,
        event: EventEndpoint,
    }
    impl Worker {
        fn new(domain: &Arc<MemoryDomain>) -> Self {
            let features = ProcessMemoryFeatures::from_id_registers(
                0,
                1 << 32,
                0,
                0,
                BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
            )
            .unwrap();
            // SAFETY: these fixture source views are explicitly resolved untagged,
            // shareable Normal WB RAM, with physical identity/offsets and rights.
            let source =
                unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(domain)) }.unwrap();
            let controls =
                FixedProcessMemoryControls::new(features, 1 | (1 << 2), 25, 39, source).unwrap();
            let mut memory = domain.thread(MemoryControls::new(
                LowerAddressProfile::new(39, false).unwrap(),
                false,
                false,
                false,
                TagCheckFaultMode::Ignore,
                false,
            ));
            let event = EventDomain::new().register(false, None).unwrap();
            memory.bind_events(&event.producer()).unwrap();
            Self {
                controls,
                memory,
                event,
                system: SystemState::new(0, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap(),
            }
        }
        fn qualified(domain: &Arc<MemoryDomain>, lse: u64, rcpc: u64, naa: bool) -> Self {
            use crate::system::{
                identification::Register as Id, identification_snapshot::Snapshot,
            };
            let mut worker = Self::new(domain);
            let ids = Arc::new(
                Snapshot::declared(
                    "checked-shared-el0-native-qualification",
                    &[
                        (Id::IdAa64Pfr0El1, 0x11),
                        (Id::IdAa64Mmfr0El1, 0),
                        (Id::IdAa64Mmfr2El1, 1 << 32),
                        (Id::IdAa64Isar3El1, 0),
                        (Id::IdAa64Pfr1El1, 0),
                        (Id::IdAa64Dfr0El1, 0),
                        (Id::IdAa64Isar0El1, lse << 20),
                        (Id::IdAa64Isar1El1, rcpc << 20),
                    ],
                )
                .unwrap(),
            );
            // SAFETY: same resolved fixture source as `new`, with no external writer.
            let source =
                unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(domain)) }.unwrap();
            worker.controls = FixedProcessMemoryControls::new_with_identification(
                ids,
                1 | (1 << 2) | if naa { 1 << 6 } else { 0 },
                25,
                39,
                source,
            )
            .unwrap();
            worker
        }
        fn snapshot(&mut self) -> Vec<u8> {
            (0..128)
                .map(|offset| self.memory.read_scalar(DATA + offset, 1, 0, PC.0).unwrap() as u8)
                .collect()
        }
        fn run(
            &mut self,
            block: &CheckedMemoryBlock,
            state: &mut GuestState,
        ) -> Result<Observation> {
            let mut thread = crate::blocks::ThreadState {
                registers: state.clone(),
                pc: PC,
            };
            // SAFETY: closed immutable baseline EL0 fixture, no debug/IRQ state or
            // external writers; every byte access uses the retained shared domain.
            let observed = unsafe {
                block.run(
                    &self.controls,
                    &self.system,
                    &mut self.memory,
                    &self.event,
                    &mut thread,
                )
            }?;
            assert_eq!(
                thread.pc.0,
                observed
                    .fault
                    .map_or(observed.exit.next_pc, |fault| fault.pc)
            );
            *state = thread.registers;
            Ok(observed)
        }
        fn read(&mut self) -> u64 {
            self.memory.read_scalar(DATA, 8, 0, PC.0).unwrap() as u64
        }
    }
    fn block(words: &[u32]) -> CheckedMemoryBlock {
        let body = CheckedMemoryBlock::compile(
            ASID,
            PC,
            words.iter().flat_map(|word| word.to_le_bytes()).collect(),
            CheckedMemoryProfile::SpAlignmentDisabled,
            TargetCpu::detect(),
        )
        .unwrap();
        if let Some(directory) = std::env::var_os("STELA_SHARED_MEMORY_ARTIFACTS") {
            // Export setup can race across test workers compiling identical
            // source. Serialize evidence publication, outside native execution.
            static EXPORT: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _export = EXPORT.lock().unwrap();
            let directory = std::path::PathBuf::from(directory).join(&body.identity.source_sha256);
            std::fs::create_dir_all(&directory).unwrap();
            let emitted = CompilationPlan::new(
                &body.source,
                PC,
                BlockProfile::CheckedMemory(body.profile),
                body.identity.target,
            )
            .unwrap()
            .compile()
            .unwrap();
            assert_eq!(
                crate::sha256(&emitted.native.x86_64_code),
                body.identity.native_sha256
            );
            for (name, bytes) in [
                ("source.bin", body.source.as_slice()),
                ("native.bin", emitted.native.x86_64_code.as_slice()),
            ] {
                let path = directory.join(name);
                if path.exists() {
                    assert_eq!(std::fs::read(path).unwrap(), bytes);
                } else {
                    std::fs::write(path, bytes).unwrap();
                }
            }
            std::fs::write(
                directory.join("identity.json"),
                serde_json::to_vec_pretty(&body.identity).unwrap(),
            )
            .unwrap();
            std::fs::write(
                directory.join("source-map.json"),
                serde_json::to_vec_pretty(&body.source_map).unwrap(),
            )
            .unwrap();
        }
        body
    }
    fn state(address: u64) -> GuestState {
        let mut state = GuestState {
            x: std::array::from_fn(|index| 0x1234_5678_9abc_def0 ^ index as u64),
            nzcv: 0xa000_0000,
            sp: 0x12_3400,
            reserved: 0x1357_2468,
            v: std::array::from_fn(|index| [index as u64 ^ 0xaaaa_5555, !(index as u64)]),
            fpcr: 0x03c0_0000,
            fpsr: 0x0800_001f,
        };
        state.x[0] = address;
        state.x[30] = 0x9000;
        state
    }

    #[test]
    fn competing_native_llsc_workers_commit_every_increment_without_a_process_lock() {
        const INCREMENTS: usize = 2000;
        let domain = domain();
        let started = Arc::new(Barrier::new(2));
        let joins: Vec<_> = (0..2)
            .map(|index| {
                let domain = Arc::clone(&domain);
                let started = Arc::clone(&started);
                std::thread::spawn(move || {
                    let mut worker = Worker::new(&domain);
                    let increment = block(&[LDXR, ADD, STXR, RET]);
                    let mut registers = state(if index == 0 { DATA } else { ALIAS });
                    let baseline = registers.clone();
                    started.wait();
                    let mut attempts = 0;
                    for _ in 0..INCREMENTS {
                        loop {
                            let observed = worker.run(&increment, &mut registers).unwrap();
                            assert!(observed.fault.is_none());
                            assert_eq!(observed.exit.next_pc, 0x9000);
                            attempts += 1;
                            if registers.x[2] == 0 {
                                break;
                            }
                            assert!(attempts < INCREMENTS * 1000, "bounded progress");
                        }
                    }
                    let mut expected = baseline;
                    expected.x[1] = registers.x[1];
                    expected.x[2] = 0;
                    assert_eq!(
                        registers, expected,
                        "only architecturally written registers change"
                    );
                    attempts
                })
            })
            .collect();
        for join in joins {
            assert!(join.join().unwrap() >= INCREMENTS);
        }
        assert_eq!(Worker::new(&domain).read(), (2 * INCREMENTS) as u64);
    }

    #[test]
    fn native_ordinary_alias_writes_invalidate_reservations_even_after_aba() {
        let domain = domain();
        let (turn, next) = std::sync::mpsc::channel();
        let (done, completed) = std::sync::mpsc::channel();
        let writer_domain = Arc::clone(&domain);
        let writer = std::thread::spawn(move || {
            let mut worker = Worker::new(&writer_domain);
            let store = block(&[STR, RET]);
            let mut registers = state(ALIAS);
            for value in [0, 0, 1, 0] {
                next.recv_timeout(Duration::from_secs(5)).unwrap();
                registers.x[1] = value;
                assert!(worker.run(&store, &mut registers).unwrap().fault.is_none());
                done.send(()).unwrap();
            }
        });
        let mut worker = Worker::new(&domain);
        let load = block(&[LDXR, RET]);
        let store = block(&[STXR, RET]);
        let mut registers = state(DATA);
        for _ in 0..2 {
            worker.run(&load, &mut registers).unwrap();
            for _ in 0..2 {
                turn.send(()).unwrap();
                completed.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            registers.x[1] = 99;
            assert!(worker.run(&store, &mut registers).unwrap().fault.is_none());
            assert_eq!(
                registers.x[2], 1,
                "same-value/ABA writes break the global mark"
            );
        }
        writer.join().unwrap();
        assert_eq!(worker.read(), 0);
    }

    #[test]
    fn native_fault_retains_prior_effects_and_exact_source_without_later_effects() {
        let domain = domain();
        let mut worker = Worker::new(&domain);
        // str x1,[x0]; ldr x2,[x3]; ret
        let prefix = block(&[STR, 0xf940_0062, RET]);
        let mut registers = state(DATA);
        registers.x[1] = 9;
        registers.x[3] = 0xa000;
        let before = registers.clone();
        let observed = worker.run(&prefix, &mut registers).unwrap();
        let fault = observed.fault.unwrap();
        assert_eq!(fault.status, MemoryStatus::Translation);
        assert_eq!(
            (fault.address, fault.pc, fault.completed_bytes),
            (0xa000, PC.0 + 4, 0)
        );
        assert_eq!(registers, before);
        assert_eq!(worker.read(), 9);
        let store = block(&[STR, RET]);
        registers.x[0] = ALIAS + 0x1000;
        registers.x[1] = 13;
        let before = registers.clone();
        let fault = worker.run(&store, &mut registers).unwrap().fault.unwrap();
        assert_eq!(fault.status, MemoryStatus::Permission);
        assert_eq!(
            (fault.address, fault.pc, fault.completed_bytes),
            (ALIAS + 0x1000, PC.0, 0)
        );
        assert_eq!(registers, before);
        assert_eq!(worker.read(), 9);

        // A genuine architectural fault settles the local reservation before a
        // later native call; returning a fault observation must not skip cleanup.
        registers.x[0] = DATA;
        worker.run(&block(&[LDXR, RET]), &mut registers).unwrap();
        registers.x[0] = 0xa000;
        assert_eq!(
            worker
                .run(&block(&[0xf940_0001, RET]), &mut registers)
                .unwrap()
                .fault
                .unwrap()
                .status,
            MemoryStatus::Translation
        );
        registers.x[0] = DATA;
        registers.x[1] = 21;
        worker.run(&block(&[STXR, RET]), &mut registers).unwrap();
        assert_eq!(registers.x[2], 1);
        assert_eq!(worker.read(), 9);
    }

    #[test]
    fn source_profile_identity_and_existing_typed_class_refusals_are_preserved() {
        let domain = domain();
        let mut worker = Worker::new(&domain);
        let original = block(&[LDXR, RET]);
        let other = block(&[STR, RET]);
        assert_ne!(original.identity(), other.identity());
        assert_ne!(original.identity().abi, BlockProfile::SystemModeV1.abi());
        assert_eq!(
            original.identity().compiler_source_sha256,
            stela_compiler::SOURCE_SHA256
        );
        // Optional register instructions still need their separate CPU owner.
        for word in [0xdac0_2000, 0x1ac0_5000] {
            assert!(
                CheckedMemoryBlock::compile(
                    ASID,
                    PC,
                    [word, RET].into_iter().flat_map(u32::to_le_bytes).collect(),
                    CheckedMemoryProfile::SpAlignmentDisabled,
                    TargetCpu::detect()
                )
                .is_err()
            );
            assert_eq!(worker.read(), 0);
        }
        assert!(
            CheckedMemoryBlock::compile(
                ASID,
                PC,
                RET.to_le_bytes().repeat(2),
                CheckedMemoryProfile::SpAlignmentDisabled,
                TargetCpu::Baseline
            )
            .is_err()
        );
    }

    #[test]
    fn foreign_memory_or_pe_and_wrong_execution_mode_decline_before_native_effects() {
        let shared = domain();
        let mut worker = Worker::new(&shared);
        let other_pe = Worker::new(&shared);
        let other_domain = domain();
        let mut foreign = Worker::new(&other_domain);
        let load = block(&[LDXR, RET]);
        let mut registers = crate::blocks::ThreadState {
            registers: state(DATA),
            pc: PC,
        };
        let before = registers.registers.clone();
        assert!(
            unsafe {
                load.run(
                    &worker.controls,
                    &worker.system,
                    &mut worker.memory,
                    &other_pe.event,
                    &mut registers,
                )
            }
            .is_err()
        );
        assert!(
            unsafe {
                load.run(
                    &worker.controls,
                    &worker.system,
                    &mut foreign.memory,
                    &foreign.event,
                    &mut registers,
                )
            }
            .is_err()
        );
        let el1 = SystemState::new(5, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
        assert!(
            unsafe {
                load.run(
                    &worker.controls,
                    &el1,
                    &mut worker.memory,
                    &worker.event,
                    &mut registers,
                )
            }
            .is_err()
        );
        assert_eq!(registers.registers, before);
        assert_eq!(worker.read(), 0);
        assert_eq!(foreign.read(), 0);
    }

    fn write(worker: &mut Worker, address: u64, value: u64) {
        let mut registers = state(address);
        registers.x[1] = value;
        assert!(
            worker
                .run(&block(&[STR, RET]), &mut registers)
                .unwrap()
                .fault
                .is_none()
        );
    }
    fn rmw_word(size: u32, operation: u32, order: u32, destination: u32) -> u32 {
        0x3820_0000
            | (size << 30)
            | (1 << 16)
            | (operation << 12)
            | destination
            | if order & 1 != 0 { 1 << 23 } else { 0 }
            | if order & 2 != 0 { 1 << 22 } else { 0 }
    }
    #[test]
    fn native_shared_scalar_lse_matrix_preserves_complete_state_and_neighbors() {
        let domain = domain();
        let mut worker = Worker::qualified(&domain, 2, 2, false);
        for size in 0..4 {
            let bytes = 1usize << size;
            let mask = u64::MAX >> ((8 - bytes) * 8);
            for operation in 0..9 {
                for order in 0..4 {
                    for offset in [0, 7] {
                        write(&mut worker, DATA + offset, 0x80);
                        let before_memory = worker.snapshot();
                        let mut registers = state(ALIAS + offset);
                        registers.x[1] = 3;
                        let mut expected = registers.clone();
                        expected.x[2] = 0x80;
                        let word = rmw_word(size, operation, order, 2);
                        assert!(
                            worker
                                .run(&block(&[word, RET]), &mut registers)
                                .unwrap()
                                .fault
                                .is_none()
                        );
                        assert_eq!(registers, expected, "word={word:08x}");
                        let value = match operation {
                            0 => 0x83,
                            1 => 0x80,
                            2 | 3 => 0x83,
                            4 => {
                                if bytes == 1 {
                                    3
                                } else {
                                    0x80
                                }
                            }
                            5 => {
                                if bytes == 1 {
                                    0x80
                                } else {
                                    3
                                }
                            }
                            6 => 0x80,
                            7 | 8 => 3,
                            _ => unreachable!(),
                        } & mask;
                        let mut memory = before_memory;
                        memory[offset as usize..offset as usize + bytes]
                            .copy_from_slice(&value.to_le_bytes()[..bytes]);
                        assert_eq!(worker.snapshot(), memory, "word={word:08x}");
                    }
                }
            }
        }
        // The address and RMW source may alias; ZR suppresses result publication.
        write(&mut worker, DATA, 5);
        let mut registers = state(DATA);
        let mut expected = registers.clone();
        worker
            .run(&block(&[0xf820_0000, RET]), &mut registers)
            .unwrap();
        expected.x[0] = 5;
        assert_eq!(registers, expected);
        assert_eq!(worker.read(), DATA + 5);
        let before = registers.clone();
        registers.x[0] = DATA;
        registers.x[1] = 0;
        let expected = registers.clone();
        worker
            .run(&block(&[rmw_word(3, 0, 3, 31), RET]), &mut registers)
            .unwrap();
        assert_eq!(registers, expected);
        assert_eq!(before.x[0], 5);
    }
    #[test]
    fn native_shared_cas_and_casp_commit_old_registers_only_after_complete_success() {
        let domain = domain();
        let mut worker = Worker::qualified(&domain, 2, 2, false);
        for size in 0..4 {
            for matched in [false, true] {
                for order in 0..4 {
                    let bytes = 1usize << size;
                    write(&mut worker, DATA, 0x80);
                    let before_memory = worker.snapshot();
                    let mut registers = state(DATA);
                    registers.x[1] = if matched { 0x80 } else { 0x81 };
                    registers.x[2] = 3;
                    let mut expected = registers.clone();
                    expected.x[1] = 0x80;
                    let word = 0x08a0_7c02
                        | (size << 30)
                        | (1 << 16)
                        | if order & 1 != 0 { 1 << 22 } else { 0 }
                        | if order & 2 != 0 { 1 << 15 } else { 0 };
                    let observed = worker.run(&block(&[word, RET]), &mut registers).unwrap();
                    assert!(observed.fault.is_none());
                    assert_eq!(registers, expected);
                    let mut memory = before_memory;
                    if matched {
                        memory[..bytes].copy_from_slice(&3u64.to_le_bytes()[..bytes]);
                    }
                    assert_eq!(worker.snapshot(), memory);
                }
            }
        }
        for size in 0..2 {
            if size == 1 && !TargetCpu::detect().supports(TargetCpu::Cx16) {
                continue;
            }
            for matched in [false, true] {
                for order in 0..4 {
                    let bytes = 4usize << size;
                    write(&mut worker, DATA, 0x1122_3344);
                    write(&mut worker, DATA + bytes as u64, 0x5566_7788);
                    let before_memory = worker.snapshot();
                    let mut registers = state(ALIAS);
                    registers.x[2] = if matched { 0x1122_3344 } else { 0 };
                    registers.x[3] = 0x5566_7788;
                    registers.x[4] = 7;
                    registers.x[5] = 9;
                    let mut expected = registers.clone();
                    expected.x[2] = 0x1122_3344;
                    expected.x[3] = 0x5566_7788;
                    let word = 0x0820_7c04
                        | (size << 30)
                        | (2 << 16)
                        | if order & 1 != 0 { 1 << 22 } else { 0 }
                        | if order & 2 != 0 { 1 << 15 } else { 0 };
                    assert!(
                        worker
                            .run(&block(&[word, RET]), &mut registers)
                            .unwrap()
                            .fault
                            .is_none()
                    );
                    assert_eq!(registers, expected);
                    let mut memory = before_memory;
                    if matched {
                        memory[..bytes].copy_from_slice(&7u64.to_le_bytes()[..bytes]);
                        memory[bytes..2 * bytes].copy_from_slice(&9u64.to_le_bytes()[..bytes]);
                    }
                    assert_eq!(worker.snapshot(), memory);
                }
            }
        }
    }
    #[test]
    fn native_shared_atomic_fault_direction_prefix_and_failed_cas_invalidation_are_precise() {
        use stela_compiler::context::memory::FaultAccess;
        let domain = domain();
        let mut worker = Worker::qualified(&domain, 2, 2, false);
        let add = block(&[rmw_word(3, 0, 0, 2), RET]);
        for (address, status, access) in [
            (0xa000, MemoryStatus::Translation, FaultAccess::Read),
            (ALIAS + 0x3000, MemoryStatus::Permission, FaultAccess::Read),
            (ALIAS + 0x1000, MemoryStatus::Permission, FaultAccess::Write),
            (
                DATA + 15,
                MemoryStatus::Alignment,
                FaultAccess::OriginalSource,
            ),
        ] {
            let mut registers = state(address);
            let before = registers.clone();
            let memory = worker.snapshot();
            let fault = worker.run(&add, &mut registers).unwrap().fault.unwrap();
            assert_eq!(
                (
                    fault.status,
                    fault.access,
                    fault.address,
                    fault.pc,
                    fault.completed_bytes
                ),
                (status, access, address, PC.0, 0)
            );
            assert_eq!(registers, before);
            assert_eq!(worker.snapshot(), memory);
        }
        let prefix = block(&[STR, 0xf821_0062, RET]);
        let mut registers = state(DATA);
        registers.x[1] = 9;
        registers.x[3] = ALIAS + 0x1000;
        let before = registers.clone();
        let fault = worker.run(&prefix, &mut registers).unwrap().fault.unwrap();
        assert_eq!(
            (fault.pc, fault.completed_bytes, fault.access),
            (PC.0 + 4, 0, FaultAccess::Write)
        );
        assert_eq!(registers, before);
        assert_eq!(worker.read(), 9);
        let mut other = Worker::new(&domain);
        let mut reserved = state(ALIAS);
        other.run(&block(&[LDXR, RET]), &mut reserved).unwrap();
        let mut registers = state(DATA);
        registers.x[1] = 42;
        registers.x[2] = 99;
        worker
            .run(&block(&[0xc8a1_7c02, RET]), &mut registers)
            .unwrap();
        assert_eq!(registers.x[1], 9);
        assert_eq!(worker.read(), 9);
        reserved.x[1] = 11;
        other.run(&block(&[STXR, RET]), &mut reserved).unwrap();
        assert_eq!(reserved.x[2], 1);
        assert_eq!(worker.read(), 9);
    }
    #[test]
    fn native_ordered_source_features_sign_extension_and_raw_control_refusals_are_exact() {
        let domain = domain();
        let mut worker = Worker::qualified(&domain, 2, 2, false);
        write(&mut worker, DATA, 0xffff_ff80);
        for (word, expected_value) in [
            (0xc8df_fc01, 0xffff_ff80u64),        // LDAR X1,[X0]
            (0xf8bf_c001, 0xffff_ff80),           // LDAPR X1,[X0]
            (0x19c0_0001, 0xffff_ff80),           // LDAPURSB W1,[X0]
            (0x1980_0001, 0xffff_ffff_ffff_ff80), // LDAPURSB X1,[X0]
            (0x9940_0001, 0xffff_ff80),
        ] {
            // LDAPUR W1,[X0]
            let mut registers = state(DATA);
            let mut expected = registers.clone();
            expected.x[1] = expected_value;
            assert!(
                worker
                    .run(&block(&[word, RET]), &mut registers)
                    .unwrap()
                    .fault
                    .is_none()
            );
            assert_eq!(registers, expected, "word={word:08x}");
        }
        for word in [0xc89f_fc01, 0xd900_0001] {
            // STLR/STLUR X1,[X0]
            let mut registers = state(ALIAS);
            registers.x[1] = 17;
            let expected = registers.clone();
            assert!(
                worker
                    .run(&block(&[word, RET]), &mut registers)
                    .unwrap()
                    .fault
                    .is_none()
            );
            assert_eq!(registers, expected);
            assert_eq!(worker.read(), 17);
        }
        for option in 0..16 {
            let mut registers = state(DATA);
            let expected = registers.clone();
            worker
                .run(&block(&[0xd503_30bf | (option << 8), RET]), &mut registers)
                .unwrap();
            assert_eq!(registers, expected);
        }
        for (lse, rcpc, naa, word) in [
            (0, 2, false, rmw_word(3, 0, 0, 2)),
            (1, 2, false, rmw_word(3, 0, 0, 2)),
            (15, 2, false, rmw_word(3, 0, 0, 2)),
            (2, 0, false, 0xf8bf_c001),
            (2, 1, false, 0x1940_0001),
            (2, 15, false, 0xf8bf_c001),
            (2, 2, true, 0xc8df_fc01),
            (2, 2, false, 0xc8df_7c01),
        ] {
            let mut unavailable = Worker::qualified(&domain, lse, rcpc, naa);
            let mut registers = state(DATA);
            let before = registers.clone();
            let memory = worker.snapshot();
            assert!(
                unavailable
                    .run(&block(&[word, RET]), &mut registers)
                    .is_err(),
                "unexpected admission {word:08x}"
            );
            assert_eq!(registers, before);
            assert_eq!(worker.snapshot(), memory);
        }
        let mut raw = Worker::new(&domain);
        for word in [rmw_word(3, 0, 0, 2), 0xc89f_fc01, 0xd503_3fbf] {
            let mut registers = state(DATA);
            let before = registers.clone();
            assert!(raw.run(&block(&[word, RET]), &mut registers).is_err());
            assert_eq!(registers, before);
        }
        let mut naa = Worker::qualified(&domain, 2, 2, true);
        let mut registers = state(DATA);
        naa.run(&block(&[0xd503_3fbf, RET]), &mut registers)
            .unwrap();
    }
    #[test]
    fn concurrent_native_lse_and_llsc_share_alias_reservations_without_a_process_lock() {
        const INCREMENTS: usize = 2000;
        let domain = domain();
        let ready = Arc::new(Barrier::new(2));
        let joins: Vec<_> = (0..2)
            .map(|index| {
                let domain = Arc::clone(&domain);
                let ready = Arc::clone(&ready);
                std::thread::spawn(move || {
                    let mut worker = Worker::qualified(&domain, 2, 2, false);
                    let increment = block(&if index == 0 {
                        [rmw_word(3, 0, 3, 2), RET].to_vec()
                    } else {
                        vec![LDXR, ADD, STXR, RET]
                    });
                    let mut registers = state(if index == 0 { DATA } else { ALIAS });
                    let mut olds = Vec::new();
                    let mut attempts = 0;
                    ready.wait();
                    for _ in 0..INCREMENTS {
                        loop {
                            attempts += 1;
                            assert!(attempts < INCREMENTS * 100);
                            if index == 0 {
                                registers.x[1] = 1;
                            }
                            assert!(
                                worker
                                    .run(&increment, &mut registers)
                                    .unwrap()
                                    .fault
                                    .is_none()
                            );
                            if index == 0 {
                                olds.push(registers.x[2]);
                                break;
                            }
                            if registers.x[2] == 0 {
                                olds.push(registers.x[1] - 1);
                                break;
                            }
                        }
                    }
                    olds
                })
            })
            .collect();
        let mut olds: Vec<_> = joins
            .into_iter()
            .flat_map(|join| join.join().unwrap())
            .collect();
        olds.sort_unstable();
        assert_eq!(olds, (0..2 * INCREMENTS as u64).collect::<Vec<_>>());
        assert_eq!(Worker::new(&domain).read(), 2 * INCREMENTS as u64);
    }

    #[test]
    fn native_lse_failed_cas_and_host_publication_never_lose_or_tear_a_shared_write() {
        const ITERATIONS: usize = 4000;
        let (domain, system, backing) = domain_storage();
        let ready = Arc::new(Barrier::new(2));
        let producer = std::thread::spawn({
            let ready = Arc::clone(&ready);
            move || {
                ready.wait();
                for index in 0..ITERATIONS {
                    let bytes = if index % 2 == 0 { u64::MAX } else { 0 }.to_le_bytes();
                    // SAFETY: private bytes and pinned raw RAM; publication uses the
                    // exact same physical system/backing as both guest aliases.
                    unsafe { system.publish(&backing, 0, &bytes) }.unwrap();
                }
            }
        });
        let mut worker = Worker::qualified(&domain, 2, 2, false);
        let cas = block(&[0xc8a1_7c02, RET]);
        ready.wait();
        for _ in 0..ITERATIONS {
            let mut registers = state(ALIAS);
            registers.x[1] = 0x1122_3344;
            registers.x[2] = 0x55aa;
            let before = registers.clone();
            assert!(worker.run(&cas, &mut registers).unwrap().fault.is_none());
            assert!(matches!(registers.x[1], 0 | u64::MAX));
            let mut expected = before;
            expected.x[1] = registers.x[1];
            assert_eq!(registers, expected);
        }
        producer.join().unwrap();
        assert_eq!(worker.read(), 0);
    }
    #[test]
    fn concurrent_native_casp_publication_is_atomic_to_ordinary_pair_readers() {
        let target = TargetCpu::detect();
        if !target.supports(TargetCpu::Cx16) || !target.supports(TargetCpu::AtomicLoad16) {
            return;
        }
        const ITERATIONS: u64 = 3000;
        let domain = domain();
        let mut setup = Worker::new(&domain);
        write(&mut setup, DATA, 0);
        write(&mut setup, DATA + 8, u64::MAX);
        let ready = Arc::new(Barrier::new(2));
        let writer = std::thread::spawn({
            let domain = Arc::clone(&domain);
            let ready = Arc::clone(&ready);
            move || {
                let mut worker = Worker::qualified(&domain, 2, 2, false);
                let casp = block(&[0x4822_7c04, RET]);
                let mut registers = state(DATA);
                registers.x[2] = 0;
                registers.x[3] = u64::MAX;
                ready.wait();
                for value in 1..=ITERATIONS {
                    registers.x[4] = value;
                    registers.x[5] = !value;
                    worker.run(&casp, &mut registers).unwrap();
                    assert_eq!((registers.x[2], registers.x[3]), (value - 1, !(value - 1)));
                    registers.x[2] = value;
                    registers.x[3] = !value;
                }
            }
        });
        let mut reader = Worker::new(&domain);
        let load = block(&[0xa940_0c02, RET]); // LDP X2,X3,[X0]
        let mut registers = state(ALIAS);
        ready.wait();
        for _ in 0..ITERATIONS {
            reader.run(&load, &mut registers).unwrap();
            assert_eq!(registers.x[3], !registers.x[2]);
            assert!(registers.x[2] <= ITERATIONS);
        }
        writer.join().unwrap();
        assert_eq!(reader.read(), ITERATIONS);
    }
    #[test]
    fn native_lse_and_ordered_same_value_writers_invalidate_alias_exclusives_and_old_abis_refuse() {
        let domain = domain();
        let mut reserved = Worker::new(&domain);
        let mut writer = Worker::qualified(&domain, 2, 2, false);
        for word in [rmw_word(3, 0, 0, 2), 0xc89f_fc01] {
            let mut registers = state(ALIAS);
            reserved.run(&block(&[LDXR, RET]), &mut registers).unwrap();
            let mut output = state(DATA);
            output.x[1] = 0;
            writer.run(&block(&[word, RET]), &mut output).unwrap();
            registers.x[1] = 7;
            reserved.run(&block(&[STXR, RET]), &mut registers).unwrap();
            assert_eq!(registers.x[2], 1);
            assert_eq!(writer.read(), 0);
        }
        for version in [0, 1, 3, u32::MAX] {
            let mut old = block(&[rmw_word(3, 0, 0, 2), RET]);
            old.requirements.context_version = version;
            let mut registers = state(DATA);
            let before = registers.clone();
            assert!(writer.run(&old, &mut registers).is_err());
            assert_eq!(registers, before);
            assert_eq!(writer.read(), 0);
        }
    }

    #[test]
    fn native_shared_sp_fault_precedes_data_alignment_and_preserves_all_effects() {
        let domain = domain();
        let mut worker = Worker::qualified(&domain, 2, 2, false);
        let ids = Arc::clone(worker.controls.identification_snapshot_owner().unwrap());
        // SAFETY: same fully resolved fixed fixture source; no mapping changed.
        let source =
            unsafe { SourceNormalWbDomain::from_source_resolved(Arc::clone(&domain)) }.unwrap();
        worker.controls = FixedProcessMemoryControls::new_with_identification(
            ids,
            1 | (1 << 2) | (1 << 4),
            25,
            39,
            source,
        )
        .unwrap();
        for word in [
            rmw_word(3, 0, 3, 2) | (31 << 5),
            0xc8df_fc01 | (31 << 5),
            0x4822_7c04 | (31 << 5),
        ] {
            let source = [word, RET].into_iter().flat_map(u32::to_le_bytes).collect();
            let body = CheckedMemoryBlock::compile(
                ASID,
                PC,
                source,
                CheckedMemoryProfile::SpAlignmentEnabled,
                TargetCpu::detect(),
            )
            .unwrap();
            let mut registers = state(DATA);
            registers.sp = DATA + 15;
            let before = registers.clone();
            let memory = worker.snapshot();
            let fault = worker.run(&body, &mut registers).unwrap().fault.unwrap();
            assert_eq!(
                (
                    fault.status,
                    fault.access,
                    fault.address,
                    fault.pc,
                    fault.completed_bytes
                ),
                (
                    MemoryStatus::StackAlignment,
                    stela_compiler::context::memory::FaultAccess::OriginalSource,
                    DATA + 15,
                    PC.0,
                    0
                )
            );
            assert_eq!(registers, before);
            assert_eq!(worker.snapshot(), memory);
        }
    }
    #[test]
    fn native_ordered_release_acquire_publishes_ordinary_data_across_host_workers() {
        const ITERATIONS: u64 = 1000;
        let domain = domain();
        let ready = Arc::new(Barrier::new(2));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let producer = std::thread::spawn({
            let domain = Arc::clone(&domain);
            let ready = Arc::clone(&ready);
            move || {
                let mut worker = Worker::qualified(&domain, 2, 2, false);
                let poll = block(&[0xc8df_fc02, RET]);
                let publish = block(&[STR, 0xc89f_fc62, RET]);
                ready.wait();
                for value in 1..=ITERATIONS {
                    let mut registers = state(DATA);
                    loop {
                        worker.run(&poll, &mut registers).unwrap();
                        if registers.x[2] == 0 {
                            break;
                        }
                        assert!(
                            std::time::Instant::now() < deadline,
                            "bounded release/acquire handshake"
                        );
                        std::thread::yield_now();
                    }
                    registers.x[0] = DATA + 64;
                    registers.x[1] = value;
                    registers.x[2] = 1;
                    registers.x[3] = DATA;
                    worker.run(&publish, &mut registers).unwrap();
                }
            }
        });
        let mut worker = Worker::qualified(&domain, 2, 2, false);
        let observe = block(&[0xc8df_fc02, 0xf940_0061, RET]);
        let acknowledge = block(&[0xc89f_fc01, RET]);
        ready.wait();
        for value in 1..=ITERATIONS {
            let mut registers = state(ALIAS);
            registers.x[3] = ALIAS + 64;
            loop {
                worker.run(&observe, &mut registers).unwrap();
                if registers.x[2] == 1 {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "bounded release/acquire handshake"
                );
                std::thread::yield_now();
            }
            assert_eq!(registers.x[1], value);
            registers.x[1] = 0;
            worker.run(&acknowledge, &mut registers).unwrap();
        }
        producer.join().unwrap();
    }

    /// Opt-in actual native execution benchmark, never an acceptance throughput
    /// claim. Run with --release --ignored --nocapture and record host/load/source.
    #[test]
    #[ignore = "bounded native timing; run explicitly on an otherwise measured host"]
    fn benchmark_native_llsc_serialized_and_parallel() {
        benchmark_native_counters(false);
    }

    #[test]
    #[ignore = "bounded native timing; run explicitly with source/load evidence"]
    fn benchmark_native_lse_serialized_and_parallel() {
        benchmark_native_counters(true);
    }

    fn benchmark_native_counters(lse: bool) {
        let words = if lse {
            vec![rmw_word(3, 0, 3, 2), RET]
        } else {
            vec![LDXR, ADD, STXR, RET]
        };
        const ITERATIONS: usize = 20_000;
        if let Some(directory) = std::env::var_os("STELA_CONCURRENCY_ARTIFACTS") {
            use std::io::Write;
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir(&directory).expect("fresh evidence directory");
            let body = block(&words);
            let emitted = CompilationPlan::new(
                &body.source,
                PC,
                BlockProfile::CheckedMemory(body.profile),
                body.identity.target,
            )
            .unwrap()
            .compile()
            .unwrap();
            assert_eq!(
                crate::sha256(&emitted.native.x86_64_code),
                body.identity.native_sha256
            );
            for (name, bytes) in [
                ("source.bin", body.source.as_slice()),
                ("native.bin", emitted.native.x86_64_code.as_slice()),
            ] {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(directory.join(name))
                    .unwrap()
                    .write_all(bytes)
                    .unwrap();
            }
            std::fs::write(
                directory.join("identity.json"),
                serde_json::to_vec_pretty(&body.identity).unwrap(),
            )
            .unwrap();
            std::fs::write(
                directory.join("source-map.json"),
                serde_json::to_vec_pretty(&body.source_map).unwrap(),
            )
            .unwrap();
        }
        for (trial, case, parallel) in (0..5).flat_map(|trial| {
            ["contended", "disjoint"].into_iter().flat_map(move |case| {
                [trial % 2 == 0, trial % 2 != 0]
                    .into_iter()
                    .map(move |parallel| (trial, case, parallel))
            })
        }) {
            let domain = domain();
            let gate = Arc::new(std::sync::Mutex::new(()));
            let ready = Arc::new(Barrier::new(3));
            let start_workers = Arc::new(Barrier::new(3));
            let joins: Vec<_> = (0..2)
                .map(|index| {
                    let words = words.clone();
                    let domain = Arc::clone(&domain);
                    let gate = Arc::clone(&gate);
                    let ready = Arc::clone(&ready);
                    let start_workers = Arc::clone(&start_workers);
                    std::thread::spawn(move || {
                        let mut worker = if lse {
                            Worker::qualified(&domain, 2, 2, false)
                        } else {
                            Worker::new(&domain)
                        };
                        let increment = block(&words);
                        let mut thread = crate::blocks::ThreadState {
                            registers: state(
                                DATA + if case == "disjoint" { index * 64 } else { 0 },
                            ),
                            pc: PC,
                        };
                        let mut attempts = 0;
                        ready.wait();
                        start_workers.wait();
                        let cpu_start = thread_cpu_ns();
                        for _ in 0..ITERATIONS {
                            loop {
                                let _guard = (!parallel).then(|| gate.lock().unwrap());
                                thread.pc = PC;
                                if lse {
                                    thread.registers.x[1] = 1;
                                }
                                assert!(
                                    // SAFETY: same closed fixture contract as
                                    // Worker::run, with state owned by this worker.
                                    unsafe {
                                        increment.run(
                                            &worker.controls,
                                            &worker.system,
                                            &mut worker.memory,
                                            &worker.event,
                                            &mut thread,
                                        )
                                    }
                                    .unwrap()
                                    .fault
                                    .is_none()
                                );
                                attempts += 1;
                                if lse || thread.registers.x[2] == 0 {
                                    break;
                                }
                            }
                        }
                        (
                            attempts,
                            thread_cpu_ns() - cpu_start,
                            increment.identity().clone(),
                        )
                    })
                })
                .collect();
            ready.wait();
            let start = Instant::now();
            start_workers.wait();
            let results: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
            let attempts: usize = results.iter().map(|result| result.0).sum();
            let cpu_ns: u64 = results.iter().map(|result| result.1).sum();
            let elapsed = start.elapsed();
            let mut observer = Worker::new(&domain);
            assert_eq!(
                observer.read(),
                (if case == "disjoint" {
                    ITERATIONS
                } else {
                    2 * ITERATIONS
                }) as u64
            );
            if case == "disjoint" {
                assert_eq!(
                    observer.memory.read_scalar(DATA + 64, 8, 0, PC.0).unwrap(),
                    ITERATIONS as u128
                );
            }
            println!(
                "{}",
                serde_json::json!({"family":if lse {"lse"}else{"llsc"},"trial": trial, "case": case, "parallel": parallel, "workers": 2,
                "increments": 2 * ITERATIONS, "attempts": attempts, "wall_ns": elapsed.as_nanos(),
                "summed_worker_cpu_ns": cpu_ns, "identity": results[0].2})
            );
        }
    }

    fn thread_cpu_ns() -> u64 {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: initialized output belongs to this host thread. This clock counts
        // its native plus runtime/service CPU time, not exclusively guest code.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) },
            0
        );
        now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
    }
}
