//! A new software EL1 PE with its own RAM, source and controls (hosted).
use super::super::{ConsumerKey, software_async::SoftwareAsyncDomain};
use super::{
    OwnedRunOutcome, OwnedRunRequest, ProcessEntryControls, el1_system::El1PlatformControls,
    provider::M0Owner,
};
use crate::{
    blocks::{
        BlockRuntime, InstalledEl1Owner, InstalledM0Owner, InstalledM0Sources, RunOutcome,
        ThreadState,
    },
    memory::{
        domain::{MemoryThread, physical::PhysicalAddressSpace},
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
        source_ram::{
            MaterializedSourceRam, SourceRamSystemConfig, materialize_source_ram_regions,
            materialize_source_ram_with_zeroed,
        },
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
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
use anyhow::{Result, ensure};
#[cfg(feature = "std")]
use std::path::PathBuf;
use stela_compiler::{
    GuestAddress,
    block::{BlockProfile, CheckedMemoryProfile},
    context::ExecutionContext,
};

pub use crate::memory::source_ram::{
    InitializedRamRegion, OwnedRamExtent, PhysicalRamRange, SourceRamDeclaration,
    SourceRamPermissions, ZeroedRamExtent,
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
    PlatformV1,
    Read64V1,
}

impl SoftwareEl1Profile {
    fn compiler(self) -> BlockProfile {
        match self {
            Self::DirectBranchV1 => BlockProfile::El1DirectBranchV1,
            Self::IntegerV1 => BlockProfile::El1M0IntegerV1,
            Self::PlatformV1 => BlockProfile::El1PlatformV1,
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
    #[cfg(feature = "std")]
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
    pub zero_initialized: bool,
    pub file_prefix: Option<(usize, String)>,
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
    pub memory_write_observation: Option<String>,
    pub memory_pair_read_observation: Option<String>,
    pub register_observation: Option<String>,
    pub system_observation: Option<String>,
    pub system_effect_observation: Option<String>,
    pub context_observation: Option<String>,
    pub platform_identification_sha256: Option<String>,
    pub compiler_source_sha256: String,
    /// Descriptive standard manifests still resident at shutdown. This is not
    /// an execution history, source lease, RX handle or PE admission capability.
    pub resident_artifacts: Vec<crate::Manifest>,
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
    platform: Option<El1PlatformControls>,
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

fn declared_profile(platform: Option<&El1PlatformControls>) -> Result<ControlProfile> {
    // This static identity describes this factory's explicitly created base
    // software CPU. It authenticates no external hardware or incoming controls.
    const DECLARATION: &[u8] = b"stela-owned-base-el1-m0-software-v1;A64EL01;PA40;ASID8;4K16K;LittleOnly;optional-entry/debug/SPE-absent";
    let digest = match platform {
        Some(platform) => platform
            .identification()
            .provenance()
            .input_sha256()
            .to_owned(),
        None => stela_core::sha256(DECLARATION),
    };
    let mut bytes = [0; 32];
    for (index, pair) in digest.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let value = core::str::from_utf8(pair)?;
        bytes[index] = u8::from_str_radix(value, 16)?;
    }
    let evidence = EvidenceBinding {
        id: if platform.is_some() {
            "stela-owned-base-el1-platform-v1"
        } else {
            "owned-base-el1-m0-software-v1"
        },
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
    /// Reload unchanged declared file prefixes into the original quiescent RAM.
    /// The consuming executable scope has not started; no PE is reconstructed.
    /// Tail bytes and architectural CPU/System state are retained. A platform
    /// CPU reset/entry or migration restore requires its separate real owner.
    pub fn reload_ram_file_prefixes(&mut self) -> Result<()> {
        match &mut self.installed {
            InstalledSource::El1(owner) => {
                owner.reload_ram_file_prefixes(&self.system, self.thread.pc)
            }
            InstalledSource::Read64(owner) => {
                owner.reload_ram_file_prefixes(&self.system, self.thread.pc)
            }
        }
    }

    pub fn new(config: SoftwareEl1Config) -> Result<Self> {
        Self::new_with_zeroed(config, Vec::new())
    }

    /// Explicitly initialize writable RAM through the same fresh materializer.
    /// Holes stay unavailable; zero extents cannot contain executable source.
    pub fn new_with_zeroed(
        config: SoftwareEl1Config,
        zeroed: Vec<ZeroedRamExtent>,
    ) -> Result<Self> {
        Self::new_with_regions(config, zeroed, Vec::new())
    }

    /// Explicit complete RAM regions with unchanged file prefixes and cold zero
    /// tails. Mutable instruction RAM remains the scoped single-PE/I=C=0 lane.
    pub fn new_with_regions(
        config: SoftwareEl1Config,
        zeroed: Vec<ZeroedRamExtent>,
        regions: Vec<InitializedRamRegion>,
    ) -> Result<Self> {
        let SoftwareEl1Config {
            profile,
            #[cfg(feature = "std")]
            cache_directory,
            ram,
            thread,
            system,
            translation,
        } = config;
        system.check_lower_el_storage().map_err(|error| {
            anyhow::anyhow!("software EL1 requires lower-only storage: {error:?}")
        })?;
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
        let target = ram.target;
        let materialization = SourceRamSystemConfig {
            reservation_granule_bytes: RESERVATION_GRANULE_BYTES,
            reservation_stripe_count: RESERVATION_STRIPE_COUNT,
        };
        let materialized = if regions.is_empty() {
            materialize_source_ram_with_zeroed(ram, zeroed, materialization)?
        } else {
            materialize_source_ram_regions(ram, zeroed, regions, materialization)?
        };
        Self::from_materialized(
            profile,
            #[cfg(feature = "std")]
            cache_directory,
            thread,
            system,
            translation,
            target,
            materialized,
        )
    }

    // The production path and authored ownership tests share the SAME original
    // construction body. MaterializedSourceRam has no public/caller constructor;
    // only the genuine fresh source-RAM factory can provide this storage owner.
    fn from_materialized(
        profile: SoftwareEl1Profile,
        #[cfg(feature = "std")] cache_directory: PathBuf,
        thread: ThreadState,
        system: SystemState,
        translation: RegisterValues,
        target: stela_compiler::TargetCpu,
        materialized: MaterializedSourceRam,
    ) -> Result<Self> {
        system.check_lower_el_storage().map_err(|error| {
            anyhow::anyhow!("software EL1 requires lower-only storage: {error:?}")
        })?;
        ensure!(
            system.pacm_state_feature() == PacmStateFeature::Absent,
            "software EL1 foundation requires PACM-absent storage"
        );
        let (binding, immutable) = materialized.into_parts();
        let physical = PhysicalAddressSpace::from_materialized(binding)?;
        let address_space = physical
            .domain()
            .address_space()
            .ok_or_else(|| anyhow::anyhow!("software EL1 source domain has no namespace"))?;
        ensure!(
            address_space != 0,
            "software EL1 address space must be nonzero"
        );
        ensure!(
            thread.pc.0.is_multiple_of(INSTRUCTION_ALIGNMENT_BYTES),
            "software EL1 initial PC is unaligned"
        );
        let declared_capacity = physical.layout().declared_capacity.clone();
        let initialized_ram: Vec<_> = physical
            .layout()
            .initialized
            .iter()
            .map(|extent| SoftwareEl1InitialRam {
                range: extent.range,
                permissions: extent.permissions,
                sha256: extent.source_sha256.clone(),
                zero_initialized: extent.zero_initialized,
                file_prefix: extent.file_prefix.clone(),
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
        let platform = if profile == SoftwareEl1Profile::PlatformV1 {
            Some(El1PlatformControls::declared_base()?)
        } else {
            None
        };
        let entry = match &platform {
            Some(platform) => platform.entry_profile(),
            None => EntryProfile::base(
                SystemEntryFeatures::declared_absent(),
                ScalableEntryAbsence::from_id_registers(0, 0).map_err(|error| {
                    anyhow::anyhow!("software EL1 scalable declaration: {error:?}")
                })?,
            )
            .map_err(|error| anyhow::anyhow!("software EL1 entry declaration: {error:?}"))?,
        };
        // SAFETY: this factory creates the actual fresh PE's declared controls;
        // all producer paths are private and owned by the retained registry.
        let execution = unsafe {
            ProcessEntryControls::fresh_software(
                entry,
                match &platform {
                    Some(platform) => platform.identification().base_spe_absence()?,
                    None => BaseSpeAbsence::from_id_aa64dfr0_el1(0).map_err(|error| {
                        anyhow::anyhow!("software EL1 SPE declaration: {error:?}")
                    })?,
                },
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
        #[cfg(feature = "std")]
        let runtime = BlockRuntime::new_for_target(
            address_space,
            #[cfg(feature = "std")]
            cache_directory,
            profile.compiler(),
            target,
        );
        #[cfg(not(feature = "std"))]
        let runtime =
            BlockRuntime::new_in_memory_for_target(address_space, profile.compiler(), target);
        // SAFETY: all physical/source storage was freshly allocated above and
        // is exclusively owned here. No raw alias, DMA, external writer or PE
        // exists. This transfers the sole Initial publication owner once.
        let installed = unsafe {
            match profile {
                SoftwareEl1Profile::DirectBranchV1
                | SoftwareEl1Profile::IntegerV1
                | SoftwareEl1Profile::PlatformV1 => InstalledSource::El1(InstalledEl1Owner::new(
                    runtime,
                    physical,
                    immutable,
                    entry,
                    translation,
                    declared_profile(platform.as_ref())?,
                    &system,
                    thread.pc,
                )?),
                SoftwareEl1Profile::Read64V1 => InstalledSource::Read64(InstalledM0Owner::new(
                    runtime,
                    physical,
                    immutable,
                    entry,
                    translation,
                    declared_profile(platform.as_ref())?,
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
            platform,
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
            platform,
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
        let mut operation = |runtime: &mut BlockRuntime,
                             sources: &mut InstalledM0Sources,
                             controls: &mut TranslationControls|
         -> Result<_> {
            let outcome = {
                let pending = asynchronous.lease_no_sources().map_err(|error| {
                    anyhow::anyhow!("software EL1 complete producer lease: {error:?}")
                })?;
                // SAFETY: these are disjoint fields of the one consumed machine,
                // retained until its single PE shuts down.
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
                        SoftwareEl1Profile::PlatformV1 => M0Owner::fresh_el1_platform(
                            address_space,
                            sources,
                            controls,
                            &execution,
                            &mut memory,
                            &endpoint,
                            &mut context,
                            pending,
                            platform
                                .as_ref()
                                .ok_or_else(|| anyhow::anyhow!("platform identification absent"))?,
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
                // SAFETY: one new PE over this machine's thread, system and
                // backend; its whole executable lifetime is this scope.
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
            let loan = memory
                .observation_loan()
                .map_err(|error| format!("{error:?}"));
            let observations = observed_ranges
                .iter()
                .map(|range| SoftwareEl1RamObservation {
                    source_pa: range.source_pa,
                    bytes: range.bytes,
                    sha256: loan.as_ref().map_err(Clone::clone).and_then(|loan| {
                        let bytes =
                            usize::try_from(range.bytes).map_err(|error| error.to_string())?;
                        loan.snapshot(range.source_pa, bytes)
                            .map(|bytes| stela_core::sha256(&bytes))
                            .map_err(|error| format!("{error:?}"))
                    }),
                })
                .collect();
            let artifacts = runtime
                .loaded
                .values()
                .map(|block| block.prepared.manifest.clone())
                .collect();
            Ok((outcome, readbacks, observations, artifacts))
        };
        let key = ConsumerKey(());
        let (outcome, translation, ram, resident_artifacts) = match installed {
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
            last_m0_write_observation,
            last_m0_pair_read_observation,
            last_el1_register_observation,
            last_el1_system_observation,
            last_system_effect_observation,
            last_el1_context_observation,
            ..
        } = outcome;
        let describe = |value: &dyn core::fmt::Debug| format!("{value:?}");
        Ok(SoftwareEl1Report {
            declared_capacity,
            initialized_ram,
            resident_artifacts,
            stop: format!("{stop:?}"),
            accounting,
            thread,
            system,
            translation,
            native_observation: last_native_observation.as_ref().map(|v| describe(v)),
            memory_observation: last_m0_observation.as_ref().map(|v| describe(v)),
            memory_write_observation: last_m0_write_observation.as_ref().map(|v| describe(v)),
            memory_pair_read_observation: last_m0_pair_read_observation
                .as_ref()
                .map(|v| describe(v)),
            register_observation: last_el1_register_observation.as_ref().map(|v| describe(v)),
            system_observation: last_el1_system_observation.as_ref().map(|v| describe(v)),
            system_effect_observation: last_system_effect_observation.as_ref().map(|v| describe(v)),
            context_observation: last_el1_context_observation.as_ref().map(|v| describe(v)),
            platform_identification_sha256: platform.as_ref().map(|platform| {
                platform
                    .identification()
                    .provenance()
                    .input_sha256()
                    .to_owned()
            }),
            compiler_source_sha256: crate::compiler_source_sha256().into(),
            ram,
        })
    }
}

#[cfg(test)]
mod tests;
