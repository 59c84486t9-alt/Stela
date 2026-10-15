//! Generic hosted entry for a genuinely new, exclusively owned software EL1 PE.
//! Owned input values initialize new storage; no hardware PE or live domain is adopted.
use super::super::{ConsumerKey, software_async::SoftwareAsyncDomain};
use super::{OwnedRunOutcome, OwnedRunRequest, ProcessEntryControls, provider::M0Owner};
use crate::{
    blocks::{
        BlockRuntime, InstalledEl1Owner, InstalledM0Owner, InstalledM0Sources, RunOutcome,
        ThreadState,
    },
    memory::{
        domain::{MemoryThread, physical::PhysicalAddressSpace},
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
        source_ram::{SourceRamSystemConfig, materialize_source_ram},
        stage1,
    },
    system::{
        debug::DebugControls,
        events::{EventDomain, EventEndpoint},
        execution::owner::SystemExecutionOwner,
        profile::{BaseSpeAbsence, EntryProfile, ScalableEntryAbsence, SystemEntryFeatures},
        state::{PacmStateFeature, SystemState},
        translation_controls::{
            AsidBits, BaseEl1FeatureFacts, ControlProfile, Endianness, EvidenceBinding,
            PanFeatures, PolicyProvenance, Presence, RegisterValues, TranslationControls,
        },
    },
};
use anyhow::{Result, ensure};
use std::path::PathBuf;
use stela_compiler::{
    GuestAddress,
    block::{BlockProfile, CheckedMemoryProfile},
    context::ExecutionContext,
};

pub use crate::memory::source_ram::{
    OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration, SourceRamPermissions,
};

const INSTRUCTION_ALIGNMENT_BYTES: u64 = size_of::<u32>() as u64;
const LOWER_ADDRESS_BITS: u8 = 48;
const RESERVATION_GRANULE_BYTES: u64 = 16;
const RESERVATION_STRIPE_COUNT: usize = 8;

/// Select one existing source/compiler/consumer cohort for the whole PE lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftwareEl1Profile {
    DirectBranchV1,
    IntegerV1,
    Read64V1,
}

impl SoftwareEl1Profile {
    fn compiler(self) -> BlockProfile {
        match self {
            Self::DirectBranchV1 => BlockProfile::El1DirectBranchV1,
            Self::IntegerV1 => BlockProfile::El1M0IntegerV1,
            Self::Read64V1 => {
                BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged)
            }
        }
    }
}

/// Explicit initialization of a NEW software machine. RAM is allocated and
/// protected here; no caller-owned MemorySystem, mapping or PE is accepted.
pub struct SoftwareEl1Config {
    pub profile: SoftwareEl1Profile,
    pub cache_directory: PathBuf,
    pub ram: SourceRamDeclaration,
    pub thread: ThreadState,
    pub system: SystemState,
    pub translation: RegisterValues,
}

pub struct SoftwareEl1Request {
    pub stop_pc: Option<GuestAddress>,
    pub block_budget: usize,
}

/// Observations after the executable lifetime ends. Values are descriptive;
/// this report contains no PE, source, memory or retirement lease.
pub struct SoftwareEl1RamObservation {
    pub source_pa: u64,
    pub bytes: u64,
    pub sha256: Result<String, String>,
}

pub struct SoftwareEl1InitialRam {
    pub range: PhysicalRamRange,
    pub permissions: SourceRamPermissions,
    pub sha256: String,
}

pub struct SoftwareEl1Report {
    pub declared_capacity: Vec<PhysicalRamRange>,
    pub initialized_ram: Vec<SoftwareEl1InitialRam>,
    pub stop: String,
    pub accounting: RunOutcome,
    pub thread: ThreadState,
    pub system: SystemState,
    pub translation: Result<RegisterValues, String>,
    pub native_observation: Option<String>,
    pub memory_observation: Option<String>,
    pub register_observation: Option<String>,
    pub compiler_source_sha256: String,
    pub ram: Vec<SoftwareEl1RamObservation>,
}

enum InstalledSource {
    El1(InstalledEl1Owner),
    Read64(InstalledM0Owner),
}

/// Owns the actual original resources until its one consuming execution scope.
/// Private fields prevent caller substitution, raw entry or reset/retry.
pub struct SoftwareEl1Machine {
    profile: SoftwareEl1Profile,
    installed: InstalledSource,
    address_space: u64,
    thread: ThreadState,
    system: SystemState,
    memory: MemoryThread<MemoryControls>,
    endpoint: EventEndpoint,
    _events: EventDomain,
    execution: ProcessEntryControls,
    asynchronous: SoftwareAsyncDomain,
    context: ExecutionContext,
    observed_ranges: Vec<PhysicalRamRange>,
    declared_capacity: Vec<PhysicalRamRange>,
    initialized_ram: Vec<SoftwareEl1InitialRam>,
}

fn declared_profile() -> Result<ControlProfile> {
    // This static identity describes this factory's explicitly created base
    // software CPU. It authenticates no external hardware or incoming controls.
    const DECLARATION: &[u8] = b"stela-owned-base-el1-m0-software-v1;A64EL01;PA40;ASID8;4K16K;LittleOnly;optional-entry/debug/SPE-absent";
    let digest = stela_core::sha256(DECLARATION);
    let mut bytes = [0; 32];
    for (index, pair) in digest.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let value = std::str::from_utf8(pair)?;
        bytes[index] = u8::from_str_radix(value, 16)?;
    }
    let evidence = EvidenceBinding {
        id: "owned-base-el1-m0-software-v1",
        sha256: bytes,
    };
    ControlProfile::base_el1(
        BaseEl1FeatureFacts {
            pauth: Presence::Absent,
            pan: PanFeatures::Absent,
            ssbs: Presence::Absent,
            exs: Presence::Absent,
            asid_bits: AsidBits::Eight,
            endianness: Endianness::LittleOnly,
        },
        PolicyProvenance {
            cpu_features: evidence,
            implementation_choices: evidence,
        },
        stage1::CpuProfile {
            pa_max: stage1::PaBits::Bits40,
            asid_bits: stage1::AsidBits::Bits8,
            granules: stage1::GranuleSupport {
                kib4: true,
                kib16: true,
                kib64: false,
                lower_fallback: stage1::Granule::KiB4,
                upper_fallback: stage1::Granule::KiB4,
            },
            pauth: false,
            pan: false,
            pan3: false,
        },
    )
    .map_err(|error| anyhow::anyhow!("software EL1 control profile: {error:?}"))
}

impl SoftwareEl1Machine {
    pub fn new(config: SoftwareEl1Config) -> Result<Self> {
        let SoftwareEl1Config {
            profile,
            cache_directory,
            ram,
            thread,
            system,
            translation,
        } = config;
        ensure!(
            system.pacm_state_feature() == PacmStateFeature::Absent,
            "software EL1 foundation requires PACM-absent storage"
        );
        ensure!(
            ram.address_space != 0,
            "software EL1 address space must be nonzero"
        );
        ensure!(
            thread.pc.0.is_multiple_of(INSTRUCTION_ALIGNMENT_BYTES),
            "software EL1 initial PC is unaligned"
        );
        let address_space = ram.address_space;
        let target = ram.target;
        let materialized = materialize_source_ram(
            ram,
            SourceRamSystemConfig {
                reservation_granule_bytes: RESERVATION_GRANULE_BYTES,
                reservation_stripe_count: RESERVATION_STRIPE_COUNT,
            },
        )?;
        let (binding, immutable) = materialized.into_parts();
        let physical = PhysicalAddressSpace::from_materialized(binding)?;
        let declared_capacity = physical.layout().declared_capacity.clone();
        let initialized_ram: Vec<_> = physical
            .layout()
            .initialized
            .iter()
            .map(|extent| SoftwareEl1InitialRam {
                range: extent.range,
                permissions: extent.permissions,
                sha256: extent.source_sha256.clone(),
            })
            .collect();
        let observed_ranges = initialized_ram
            .iter()
            .filter(|extent| extent.permissions.readable)
            .map(|extent| extent.range)
            .collect();
        let policy = MemoryControls::new(
            LowerAddressProfile::new(LOWER_ADDRESS_BITS, false)
                .map_err(|error| anyhow::anyhow!("software EL1 address policy: {error:?}"))?,
            false,
            false,
            false,
            TagCheckFaultMode::Ignore,
            false,
        );
        let mut memory = physical.domain().thread(policy);
        let events = EventDomain::new();
        let endpoint = events
            .register(false, None)
            .map_err(|error| anyhow::anyhow!("software EL1 endpoint: {error:?}"))?;
        memory
            .bind_events(&endpoint.producer())
            .map_err(|error| anyhow::anyhow!("software EL1 memory endpoint: {error:?}"))?;
        let entry = EntryProfile::base(
            SystemEntryFeatures::declared_absent(),
            ScalableEntryAbsence::from_id_registers(0, 0)
                .map_err(|error| anyhow::anyhow!("software EL1 scalable declaration: {error:?}"))?,
        )
        .map_err(|error| anyhow::anyhow!("software EL1 entry declaration: {error:?}"))?;
        // SAFETY: this factory creates the actual fresh PE's declared controls;
        // all producer paths are private and owned by the retained registry.
        let execution = unsafe {
            ProcessEntryControls::fresh_software(
                entry,
                BaseSpeAbsence::from_id_aa64dfr0_el1(0)
                    .map_err(|error| anyhow::anyhow!("software EL1 SPE declaration: {error:?}"))?,
                0,
                DebugControls {
                    halted: false,
                    ignore_traps_in_debug: false,
                    halting_allowed: false,
                    edscr_tda: false,
                    os_locked: false,
                    breakpoint_count: 0,
                    watchpoint_count: 0,
                    raw_bank: 0,
                    effective_bank: 0,
                },
            )
        }?;
        let runtime = BlockRuntime::new_for_target(
            address_space,
            cache_directory,
            profile.compiler(),
            target,
        );
        // SAFETY: all physical/source storage was freshly allocated above and
        // is exclusively owned here. No raw alias, DMA, external writer or PE
        // exists. This transfers the sole Initial publication owner once.
        let installed = unsafe {
            match profile {
                SoftwareEl1Profile::DirectBranchV1 | SoftwareEl1Profile::IntegerV1 => {
                    InstalledSource::El1(InstalledEl1Owner::new(
                        runtime,
                        physical,
                        immutable,
                        entry,
                        translation,
                        declared_profile()?,
                        &system,
                        thread.pc,
                    )?)
                }
                SoftwareEl1Profile::Read64V1 => InstalledSource::Read64(InstalledM0Owner::new(
                    runtime,
                    physical,
                    immutable,
                    entry,
                    translation,
                    declared_profile()?,
                    &system,
                    thread.pc,
                )?),
            }
        };
        // SAFETY: this private registry is the complete producer universe of
        // this NEW software PE; there is no external registration/delivery API.
        let asynchronous = unsafe { SoftwareAsyncDomain::fresh_software_pe() };
        Ok(Self {
            profile,
            installed,
            address_space,
            thread,
            system,
            memory,
            endpoint,
            _events: events,
            execution,
            asynchronous,
            context: ExecutionContext::default(),
            observed_ranges,
            declared_capacity,
            initialized_ram,
        })
    }

    pub fn run_to_shutdown(self, request: SoftwareEl1Request) -> Result<SoftwareEl1Report> {
        let Self {
            profile,
            installed,
            address_space,
            mut thread,
            mut system,
            mut memory,
            endpoint,
            _events,
            execution,
            mut asynchronous,
            mut context,
            observed_ranges,
            declared_capacity,
            initialized_ram,
        } = self;
        // Stable OUTER original fields outlive the installed source scope and
        // its one backend/PE. No self-reference or mutable resources escape.
        let mut operation = |runtime: &mut BlockRuntime,
                             sources: &InstalledM0Sources,
                             controls: &TranslationControls|
         -> Result<_> {
            let outcome = {
                let pending = asynchronous.lease_no_sources().map_err(|error| {
                    anyhow::anyhow!("software EL1 complete producer lease: {error:?}")
                })?;
                // SAFETY: these are disjoint original fields of the one consumed
                // installed machine, retained until the sole PE is shut down.
                let mut backend = unsafe {
                    match profile {
                        SoftwareEl1Profile::DirectBranchV1 => M0Owner::fresh_el1_branch(
                            address_space,
                            sources,
                            controls,
                            &execution,
                            &mut memory,
                            &endpoint,
                            &mut context,
                            pending,
                        ),
                        SoftwareEl1Profile::IntegerV1 => M0Owner::fresh_el1_integer(
                            address_space,
                            sources,
                            controls,
                            &execution,
                            &mut memory,
                            &endpoint,
                            &mut context,
                            pending,
                        ),
                        SoftwareEl1Profile::Read64V1 => M0Owner::fresh_software(
                            address_space,
                            sources,
                            controls,
                            &execution,
                            &mut memory,
                            &endpoint,
                            &mut context,
                            pending,
                        ),
                    }
                }?;
                // SAFETY: one NEW actual PE over original ThreadState/System and
                // retained backend. Its complete executable lifetime is this scope.
                let mut owner =
                    unsafe { SystemExecutionOwner::new_pe(&mut thread, &mut system, &mut backend) };
                runtime.run_owned(
                    owner.loan(),
                    OwnedRunRequest {
                        stop_pc: request.stop_pc,
                        block_budget: request.block_budget,
                    },
                )
            };
            let readbacks = controls
                .snapshot()
                .map(|snapshot| snapshot.readbacks())
                .map_err(|error| format!("{error:?}"));
            let observations = match memory.observation_loan() {
                Ok(loan) => observed_ranges
                    .iter()
                    .map(|range| SoftwareEl1RamObservation {
                        source_pa: range.source_pa,
                        bytes: range.bytes,
                        sha256: usize::try_from(range.bytes)
                            .map_err(|error| error.to_string())
                            .and_then(|bytes| {
                                loan.snapshot(range.source_pa, bytes)
                                    .map(|bytes| stela_core::sha256(&bytes))
                                    .map_err(|error| format!("{error:?}"))
                            }),
                    })
                    .collect(),
                Err(error) => observed_ranges
                    .iter()
                    .map(|range| SoftwareEl1RamObservation {
                        source_pa: range.source_pa,
                        bytes: range.bytes,
                        sha256: Err(format!("{error:?}")),
                    })
                    .collect(),
            };
            Ok((outcome, readbacks, observations))
        };
        let key = ConsumerKey(());
        let (outcome, translation, ram) = match installed {
            InstalledSource::El1(owner) => owner.into_executable_scope(&key, &mut operation)??,
            InstalledSource::Read64(owner) => {
                owner.into_executable_scope(&key, &mut operation)??
            }
        };
        let OwnedRunOutcome {
            stop,
            accounting,
            last_native_observation,
            last_m0_observation,
            last_el1_register_observation,
            ..
        } = outcome;
        Ok(SoftwareEl1Report {
            declared_capacity,
            initialized_ram,
            stop: format!("{stop:?}"),
            accounting,
            thread,
            system,
            translation,
            native_observation: last_native_observation.map(|value| format!("{value:?}")),
            memory_observation: last_m0_observation.map(|value| format!("{value:?}")),
            register_observation: last_el1_register_observation.map(|value| format!("{value:?}")),
            compiler_source_sha256: crate::compiler_source_sha256().into(),
            ram,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::state::{El1Registers, PSTATE_EL1H};
    use stela_compiler::{GuestState, TargetCpu};

    #[test]
    fn full_pacm_storage_is_refused_before_ram_materialization() {
        let config = SoftwareEl1Config {
            profile: SoftwareEl1Profile::IntegerV1,
            cache_directory: PathBuf::new(),
            // Deliberately invalid RAM must not reach materialization.
            ram: SourceRamDeclaration {
                address_space: 0,
                target: TargetCpu::Baseline,
                declared_capacity: Vec::new(),
                initialized: Vec::new(),
            },
            thread: ThreadState {
                registers: GuestState::default(),
                pc: GuestAddress(0),
            },
            system: SystemState::new_with_pacm(
                PSTATE_EL1H,
                0,
                El1Registers::new(0, 0, 0, 0, 0),
                PacmStateFeature::Full,
            )
            .unwrap(),
            translation: RegisterValues {
                sctlr_el1: 0,
                tcr_el1: 0,
                ttbr0_el1: 0,
                ttbr1_el1: 0,
                mair_el1: 0,
            },
        };
        let error = SoftwareEl1Machine::new(config).err().unwrap();
        assert_eq!(
            error.to_string(),
            "software EL1 foundation requires PACM-absent storage"
        );
    }
}
