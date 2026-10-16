//! A new software EL1 PE with its own RAM, source and controls (hosted).
mod declaration;
pub(super) mod hosted;
pub use declaration::{SoftwareEl1Declaration, SoftwareEl1Security};

use super::super::ConsumerKey;
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
use hosted::AsyncInstallation;
pub use hosted::{HostedRamService, HostedRamServiceAttempt};
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
    HostedWaitV1,
    Read64V1,
}

impl SoftwareEl1Profile {
    fn compiler(self) -> BlockProfile {
        match self {
            Self::DirectBranchV1 => BlockProfile::El1DirectBranchV1,
            Self::IntegerV1 => BlockProfile::El1M0IntegerV1,
            Self::PlatformV1 | Self::HostedWaitV1 => BlockProfile::El1PlatformV1,
            Self::Read64V1 => {
                BlockProfile::CheckedMemory(CheckedMemoryProfile::M0DeviceRamRead64Staged)
            }
        }
    }
}

/// Initialization of a new software machine. RAM is allocated and protected
/// here.
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
    /// Wait outcome of the last native System observation (diagnostic only).
    pub wait_observation: Option<crate::system::events::Outcome>,
    pub context_observation: Option<String>,
    pub interrupt_observation: Option<String>,
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

/// Owns the machine's resources until it runs. Private fields prevent
/// substitution, raw entry or reset.
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
    asynchronous: AsyncInstallation,
    context: ExecutionContext,
    observed_ranges: Vec<PhysicalRamRange>,
    declared_capacity: Vec<PhysicalRamRange>,
    initialized_ram: Vec<SoftwareEl1InitialRam>,
}

fn declared_profile(platform: Option<&El1PlatformControls>) -> Result<ControlProfile> {
    // Identity string of the base software CPU this factory creates.
    const DECLARATION: &[u8] = b"stela-owned-base-el1-m0-software-v1;A64EL01;PA40;ASID8;4K16K;LittleOnly;optional-entry/debug/SPE-absent";
    let digest = match platform {
        Some(platform) => platform
            .identification()
            .provenance()
            .input_sha256()
            .to_owned(),
        None => crate::sha256(DECLARATION),
    };
    let mut bytes = [0; 32];
    for (index, pair) in digest.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let value = core::str::from_utf8(pair)?;
        bytes[index] = u8::from_str_radix(value, 16)?;
    }
    let evidence = EvidenceBinding {
        id: if let Some(platform) = platform {
            platform.identification().provenance().source_identity()
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
    /// Reload the unchanged file prefixes of the declared RAM before the
    /// machine runs. Tail bytes and CPU state are kept.
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
        Self::new_with_regions_and_declaration(config, zeroed, regions, None)
    }

    /// Create a platform PE whose identification registers come from
    /// `declaration`. Advertising a feature does not implement it; only the
    /// fixed platform profile accepts a custom declaration.
    pub fn new_with_declaration(
        config: SoftwareEl1Config,
        zeroed: Vec<ZeroedRamExtent>,
        declaration: SoftwareEl1Declaration,
    ) -> Result<Self> {
        ensure!(
            config.profile == SoftwareEl1Profile::PlatformV1,
            "custom declaration requires the fixed EL1 platform profile"
        );
        Self::new_with_regions_and_declaration(config, zeroed, Vec::new(), Some(declaration))
    }

    fn new_with_regions_and_declaration(
        config: SoftwareEl1Config,
        zeroed: Vec<ZeroedRamExtent>,
        regions: Vec<InitializedRamRegion>,
        declaration: Option<SoftwareEl1Declaration>,
    ) -> Result<Self> {
        #[cfg(not(feature = "std"))]
        ensure!(
            config.profile != SoftwareEl1Profile::HostedWaitV1,
            "HostedWaitV1 requires the std clock and thread parking"
        );
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
            declaration,
        )
    }

    // The production path and the tests share this construction; only the
    // source-RAM factory can provide `MaterializedSourceRam`.
    #[allow(clippy::too_many_arguments)]
    fn from_materialized(
        profile: SoftwareEl1Profile,
        #[cfg(feature = "std")] cache_directory: PathBuf,
        thread: ThreadState,
        system: SystemState,
        translation: RegisterValues,
        target: stela_compiler::TargetCpu,
        materialized: MaterializedSourceRam,
        declaration: Option<SoftwareEl1Declaration>,
    ) -> Result<Self> {
        ensure!(
            declaration.is_none() || profile == SoftwareEl1Profile::PlatformV1,
            "custom declaration requires the fixed EL1 platform profile"
        );
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
        let platform = if let Some(declaration) = declaration {
            Some(El1PlatformControls::from_declaration(declaration)?)
        } else {
            match profile {
                SoftwareEl1Profile::PlatformV1 => Some(El1PlatformControls::declared_base()?),
                SoftwareEl1Profile::HostedWaitV1 => {
                    Some(El1PlatformControls::declared_hosted_wait()?)
                }
                _ => None,
            }
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
        // SAFETY: these are the new PE's declared controls, and every producer
        // is private to its registry.
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
        // SAFETY: the physical and source storage was just allocated and is
        // owned here, with no alias, DMA or other PE. This hands over initial
        // publication once.
        let installed = unsafe {
            match profile {
                SoftwareEl1Profile::DirectBranchV1
                | SoftwareEl1Profile::IntegerV1
                | SoftwareEl1Profile::PlatformV1
                | SoftwareEl1Profile::HostedWaitV1 => InstalledSource::El1(InstalledEl1Owner::new(
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
        let asynchronous = unsafe {
            match profile {
                SoftwareEl1Profile::HostedWaitV1 => AsyncInstallation::hosted_wait()?,
                _ => AsyncInstallation::no_sources(),
            }
        };
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

    /// Take the machine's external IRQ line, once, before it runs. The
    /// producer may signal from another thread; the PE drains it into its
    /// architectural pending state.
    pub(crate) fn take_hosted_irq(&mut self) -> Result<hosted::HostedIrqProducer> {
        self.asynchronous.take_irq()
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
            mut endpoint,
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
                let mut backend = match &mut asynchronous {
                    AsyncInstallation::NoSources(domain) => {
                        let pending = domain.lease_no_sources().map_err(|error| {
                            anyhow::anyhow!("software EL1 complete producer lease: {error:?}")
                        })?;
                        // SAFETY: these are disjoint fields of the one consumed
                        // machine, retained until its single PE shuts down.
                        unsafe {
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
                                    platform.as_ref().ok_or_else(|| {
                                        anyhow::anyhow!("platform identification absent")
                                    })?,
                                ),
                                SoftwareEl1Profile::HostedWaitV1 => anyhow::bail!(
                                    "hosted machine cannot use an empty producer registry"
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
                        }?
                    }
                    AsyncInstallation::HostedWait { installation, .. } => {
                        ensure!(
                            profile == SoftwareEl1Profile::HostedWaitV1,
                            "hosted resources need the HostedWaitV1 profile"
                        );
                        let wait = installation.resources(&_events, &mut endpoint)?;
                        // SAFETY: disjoint fields of the one consumed machine and
                        // its complete hosted producer lease.
                        unsafe {
                            M0Owner::fresh_el1_hosted_wait(
                                address_space,
                                sources,
                                controls,
                                &execution,
                                &mut memory,
                                &mut context,
                                wait,
                                platform.as_ref().ok_or_else(|| {
                                    anyhow::anyhow!("hosted platform identification absent")
                                })?,
                            )?
                        }
                    }
                };
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
                            .map(|bytes| crate::sha256(&bytes))
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
            last_interrupt_observation,
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
            wait_observation: last_el1_system_observation
                .as_ref()
                .and_then(|value| value.wait_outcome),
            system_observation: last_el1_system_observation.as_ref().map(|v| describe(v)),
            system_effect_observation: last_system_effect_observation.as_ref().map(|v| describe(v)),
            context_observation: last_el1_context_observation.as_ref().map(|v| describe(v)),
            interrupt_observation: last_interrupt_observation.as_ref().map(|v| describe(v)),
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
mod tests {
    use super::*;
    use crate::system::state::{El1Registers, PSTATE_EL1H};
    use stela_compiler::{GuestState, TargetCpu};

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod barriers {
        //! DSB (including the nXS forms) and ISB after a RAM store on the platform PE.
        use super::*;
        use crate::system::{
            identification::Register,
            identification_snapshot::Snapshot,
            state::{El1Registers, PSTATE_EL1H},
        };
        use alloc::sync::Arc;
        use stela_compiler::{GuestState, TargetCpu};

        const SOURCE_PC: u64 = 0x4008_0000;
        const DATA_PA: u64 = 0x4009_0000;
        const CANARY_BYTES: usize = 32;
        const CANARY: u8 = 0xa5;
        const STP_X0_X1_X2: u32 = 0xa900_0440;
        const DSB_SY: u32 = 0xd503_3f9f;
        const DSB_NXS_BASE: u32 = 0xd503_323f;
        const DSB_NXS_SCOPE_SHIFT: u32 = 10;
        const ISB_BASE: u32 = 0xd503_30df;
        const ISB_OPTION_SHIFT: u32 = 8;
        const NOP: u32 = 0xd503_201f;
        const XS_SHIFT: u32 = 56;
        const ID_FIELD_MASK: u64 = 15;
        const IDENTIFICATION: &[Register] = &[
            Register::IdAa64Pfr0El1,
            Register::IdAa64Pfr1El1,
            Register::IdAa64Pfr2El1,
            Register::IdAa64Dfr0El1,
            Register::IdAa64Dfr1El1,
            Register::IdAa64Mmfr0El1,
            Register::IdAa64Mmfr1El1,
            Register::IdAa64Mmfr2El1,
            Register::IdAa64Isar1El1,
            Register::IdAa64Isar2El1,
            Register::IdAa64Isar3El1,
        ];

        fn source(barrier: u32) -> Vec<u8> {
            [STP_X0_X1_X2, barrier, NOP]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect()
        }

        fn config(cache: PathBuf, barrier: u32) -> SoftwareEl1Config {
            let mut registers = GuestState {
                sp: 0x1234_5000,
                nzcv: 0xa000_0000,
                reserved: 0xdec0_de00,
                ..Default::default()
            };
            for (index, value) in registers.x.iter_mut().enumerate() {
                *value = 0x1111_0000_0000_0000 | index as u64;
            }
            registers.x[2] = DATA_PA;
            SoftwareEl1Config {
                profile: SoftwareEl1Profile::PlatformV1,
                cache_directory: cache,
                ram: SourceRamDeclaration {
                    address_space: 91,
                    target: TargetCpu::Baseline,
                    declared_capacity: vec![
                        PhysicalRamRange {
                            source_pa: SOURCE_PC,
                            bytes: 0x1000,
                        },
                        PhysicalRamRange {
                            source_pa: DATA_PA,
                            bytes: CANARY_BYTES as u64,
                        },
                    ],
                    initialized: vec![
                        OwnedRamExtent {
                            source_pa: SOURCE_PC,
                            bytes: source(barrier),
                            permissions: SourceRamPermissions {
                                readable: true,
                                writable: false,
                                executable: true,
                            },
                        },
                        OwnedRamExtent {
                            source_pa: DATA_PA,
                            bytes: vec![CANARY; CANARY_BYTES],
                            permissions: SourceRamPermissions {
                                readable: true,
                                writable: true,
                                executable: false,
                            },
                        },
                    ],
                },
                thread: ThreadState {
                    pc: GuestAddress(SOURCE_PC),
                    registers,
                },
                system: SystemState::new(
                    PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
                    0x9876_5000,
                    El1Registers::new(1, 2, 3, 4, 0),
                )
                .unwrap(),
                translation: RegisterValues {
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    ttbr0_el1: 0,
                    ttbr1_el1: 0,
                    mair_el1: 0,
                },
            }
        }

        /// The base platform identification with ID_AA64ISAR1_EL1.XS replaced.
        fn declaration_with_xs(xs: u64) -> SoftwareEl1Declaration {
            let base = El1PlatformControls::declared_base().unwrap();
            let fields: Vec<_> = IDENTIFICATION
                .iter()
                .map(|&register| {
                    let value = base.identification().read(register).unwrap();
                    if register == Register::IdAa64Isar1El1 {
                        (
                            register,
                            (value & !(ID_FIELD_MASK << XS_SHIFT)) | (xs << XS_SHIFT),
                        )
                    } else {
                        (register, value)
                    }
                })
                .collect();
            let snapshot = Arc::new(Snapshot::declared("nxs-test", &fields).unwrap());
            SoftwareEl1Declaration::new(snapshot, SoftwareEl1Security::NonSecureOnly).unwrap()
        }

        fn run(machine: SoftwareEl1Machine) -> (SoftwareEl1Report, GuestState, SystemState) {
            let before = machine.thread.registers.clone();
            let system = machine.system.clone();
            let report = machine
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: Some(GuestAddress(SOURCE_PC + 2 * size_of::<u32>() as u64)),
                    block_budget: 3,
                })
                .unwrap();
            (report, before, system)
        }

        /// The store completed and nothing else in RAM or the source changed.
        fn assert_ram(report: &SoftwareEl1Report, before: &GuestState, barrier: u32) {
            let mut data = vec![CANARY; CANARY_BYTES];
            data[..8].copy_from_slice(&before.x[0].to_le_bytes());
            data[8..16].copy_from_slice(&before.x[1].to_le_bytes());
            let digest = |source_pa| {
                report
                    .ram
                    .iter()
                    .find(|range| range.source_pa == source_pa)
                    .unwrap()
                    .sha256
                    .clone()
            };
            assert_eq!(digest(DATA_PA), Ok(crate::sha256(&data)));
            assert_eq!(digest(SOURCE_PC), Ok(crate::sha256(&source(barrier))));
        }

        #[test]
        fn dsb_nxs_scopes_complete_only_when_xs_is_implemented() {
            for (scope, xs) in [
                (Some(0), Some(1)),
                (Some(1), Some(1)),
                (Some(2), Some(1)),
                (Some(3), Some(1)),
                (None, None),
                (Some(3), Some(0)),
                (Some(3), Some(ID_FIELD_MASK)),
            ] {
                let cache = tempfile::tempdir().unwrap();
                let barrier = scope.map_or(DSB_SY, |scope| {
                    DSB_NXS_BASE | (scope << DSB_NXS_SCOPE_SHIFT)
                });
                let config = config(cache.path().to_owned(), barrier);
                let machine = match xs {
                    Some(xs) => SoftwareEl1Machine::new_with_declaration(
                        config,
                        vec![],
                        declaration_with_xs(xs),
                    ),
                    None => SoftwareEl1Machine::new(config),
                }
                .unwrap();
                let (report, before, system) = run(machine);
                assert_eq!(report.thread.registers, before);
                assert_eq!(report.system, system);
                let observation = report.system_effect_observation.as_deref().unwrap();
                if xs.is_none_or(|value| value == 1) {
                    assert_eq!(report.stop, "StopAddress", "{scope:?} {xs:?}");
                    assert_eq!(report.accounting.blocks_executed, 2);
                    assert_eq!(report.thread.pc, GuestAddress(SOURCE_PC + 8));
                    assert!(observation.contains("Completed"), "{observation}");
                } else {
                    assert_ne!(report.stop, "StopAddress", "{scope:?} {xs:?}");
                    assert_eq!(report.accounting.blocks_executed, 1);
                    assert_eq!(report.thread.pc, GuestAddress(SOURCE_PC + 4));
                }
                assert_ram(&report, &before, barrier);
            }
        }

        #[test]
        fn every_isb_option_publishes_context_and_fetches_the_next_instruction() {
            for option in 0..16 {
                let cache = tempfile::tempdir().unwrap();
                let barrier = ISB_BASE | (option << ISB_OPTION_SHIFT);
                let machine =
                    SoftwareEl1Machine::new(config(cache.path().to_owned(), barrier)).unwrap();
                let (report, before, system) = run(machine);
                assert_eq!(report.stop, "StopAddress", "option {option}");
                assert_eq!(report.accounting.blocks_executed, 2);
                assert_eq!(report.thread.pc, GuestAddress(SOURCE_PC + 8));
                assert_eq!(report.thread.registers, before);
                assert_eq!(report.system, system);
                let observation = report.context_observation.as_deref().unwrap();
                assert!(
                    observation.contains(&format!(
                        "InstructionSynchronization {{ option: {option} }}"
                    )),
                    "{observation}"
                );
                assert!(observation.contains("FetchRequired"), "{observation}");
                assert!(observation.contains("failure: None"), "{observation}");
                assert_ram(&report, &before, barrier);
            }
        }
    }
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod hosted {
        //! WFx, SEVL, counters and IRQ delivery on the hosted-wait machine.
        use super::*;
        use crate::system::{
            events::{Outcome, RetireReason},
            state::{El1Registers, PSTATE_EL1H},
        };
        const SOURCE_PA: u64 = 0x100000;
        const VECTOR_BASE: u64 = 0x8000;
        const WFE: u32 = 0xd503_205f;
        const WFI: u32 = 0xd503_207f;
        const WFIT_X0: u32 = 0xd503_1020;
        const WFIT_XZR: u32 = 0xd503_103f;
        const NOP: u32 = 0xd503_201f;
        const MRS_CNTFRQ_X1: u32 = 0xd53b_e001;
        const MRS_CNTPCT_X2: u32 = 0xd53b_e022;
        const MRS_CNTVCT_X3: u32 = 0xd53b_e043;
        const MRS_CNTVCT_XZR: u32 = 0xd53b_e05f;
        const ADD_X0_X3_TIMEOUT_512_LSL12: u32 = 0x9148_0060;
        const DEADLINE_DELTA: u64 = 512 << 12;

        fn machine(cache: PathBuf, words: &[u32]) -> SoftwareEl1Machine {
            super::platform::machine_with_profile(
                cache,
                words,
                VECTOR_BASE,
                SoftwareEl1Profile::HostedWaitV1,
            )
        }
        fn request(stop_pc: u64, budget: usize) -> SoftwareEl1Request {
            SoftwareEl1Request {
                stop_pc: Some(GuestAddress(stop_pc)),
                block_budget: budget,
            }
        }

        #[test]
        fn native_wfe_factory_consumes_event_once() {
            let cache = tempfile::tempdir().unwrap();
            let machine = machine(cache.path().to_owned(), &[WFE, NOP]);
            let before = machine.thread.registers.clone();
            assert!(machine.endpoint.producer().signal_local());
            let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 4));
            assert_eq!(report.thread.registers, before);
            assert_eq!(
                report.wait_observation,
                Some(Outcome::Retired {
                    next_pc: SOURCE_PA + 4,
                    reason: RetireReason::EventConsumed,
                })
            );
            assert_eq!(report.accounting.blocks_executed, 1);
            assert!(
                report
                    .system_observation
                    .as_deref()
                    .unwrap()
                    .contains("applied: true")
            );
        }

        #[test]
        fn native_masked_wfi_uses_registered_irq_and_keeps_mask() {
            let cache = tempfile::tempdir().unwrap();
            let mut machine = machine(cache.path().to_owned(), &[WFI, NOP]);
            let before = machine.thread.registers.clone();
            let irq = machine.take_hosted_irq().unwrap();
            irq.assert().unwrap();
            assert!(machine.take_hosted_irq().is_err());
            let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 4));
            assert_eq!(report.thread.registers, before);
            assert!(crate::system::exception::irq_masked(&report.system));
            assert_eq!(
                report.wait_observation,
                Some(Outcome::Retired {
                    next_pc: SOURCE_PA + 4,
                    reason: RetireReason::InterruptPending,
                })
            );
            assert_eq!(report.accounting.blocks_executed, 1);
            assert!(report.interrupt_observation.is_none());
        }

        #[test]
        fn guest_counter_reads_supply_wfit_deadline_in_same_epoch() {
            let cache = tempfile::tempdir().unwrap();
            let machine = machine(
                cache.path().to_owned(),
                &[
                    MRS_CNTFRQ_X1,
                    MRS_CNTPCT_X2,
                    MRS_CNTVCT_X3,
                    ADD_X0_X3_TIMEOUT_512_LSL12,
                    WFIT_X0,
                    MRS_CNTVCT_XZR,
                    WFIT_XZR,
                    NOP,
                ],
            );
            let mut expected = machine.thread.registers.clone();
            let report = machine
                .run_to_shutdown(request(SOURCE_PA + 7 * 4, 7))
                .unwrap();
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 7 * 4));
            assert_eq!(
                report.thread.registers.x[1],
                crate::system::events::hosted::HOSTED_COUNTER_FREQUENCY
            );
            assert!(report.thread.registers.x[3] >= report.thread.registers.x[2]);
            assert_eq!(
                report.thread.registers.x[0],
                report.thread.registers.x[3] + DEADLINE_DELTA
            );
            expected.x[..4].copy_from_slice(&report.thread.registers.x[..4]);
            assert_eq!(report.thread.registers, expected);
            assert_eq!(
                report.wait_observation,
                Some(Outcome::Retired {
                    next_pc: SOURCE_PA + 7 * 4,
                    reason: RetireReason::DeadlineExpired,
                })
            );
            assert_eq!(report.accounting.blocks_executed, 7);
        }

        #[test]
        fn fixed_no_source_factory_refuses_wait_before_native_execution() {
            let cache = tempfile::tempdir().unwrap();
            let machine = super::platform::machine_with_profile(
                cache.path().to_owned(),
                &[WFI, NOP],
                VECTOR_BASE,
                SoftwareEl1Profile::PlatformV1,
            );
            let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
            assert!(
                report
                    .stop
                    .contains("fixed no-source platform has no hosted wait resources")
            );
            assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA));
            assert_eq!(report.accounting.blocks_executed, 0);
            assert!(report.system_observation.is_none());
        }

        #[test]
        fn daif_unmask_arbitrates_retained_irq_before_next_source_fetch() {
            // DAIFClr #2 clears only I. The IRQ stayed pending after the masked WFI,
            // so it is taken before the next instruction is fetched.
            const DAIF_CLEAR_I: u32 = 0xd503_42ff;
            const SAME_EL_SPX_IRQ_VECTOR: u64 = 0x280;
            const PSTATE_I_MASK: u64 = 1 << 7;
            let cache = tempfile::tempdir().unwrap();
            let mut machine = machine(cache.path().to_owned(), &[WFI, DAIF_CLEAR_I, NOP]);
            let before = machine.thread.registers.clone();
            let irq = machine.take_hosted_irq().unwrap();
            irq.assert().unwrap();
            let report = machine
                .run_to_shutdown(request(SAME_EL_SPX_IRQ_VECTOR, 2))
                .unwrap();
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(SAME_EL_SPX_IRQ_VECTOR));
            assert_eq!(report.thread.registers, before);
            assert_eq!(report.system.el1_registers().elr(), SOURCE_PA + 8);
            assert_eq!(report.system.el1_registers().spsr() & PSTATE_I_MASK, 0);
            assert!(crate::system::exception::irq_masked(&report.system));
            assert_eq!(report.accounting.blocks_executed, 2);
            assert!(report.interrupt_observation.is_some());
        }

        #[test]
        fn initially_unmasked_pending_irq_refuses_context_before_native() {
            const ISB_SY: u32 = 0xd503_3fdf;
            const MSR_SCTLR_X1: u32 = 0xd518_1001;
            const PSTATE_I_MASK: u64 = 1 << 7;
            for word in [ISB_SY, MSR_SCTLR_X1] {
                let cache = tempfile::tempdir().unwrap();
                let mut machine = machine(cache.path().to_owned(), &[word, NOP]);
                machine
                    .system
                    .write_daif(crate::system::pstate::DAIF_MASK & !PSTATE_I_MASK);
                machine.thread.registers.x[1] = 0;
                let before = machine.thread.registers.clone();
                let system = machine.system.clone();
                let irq = machine.take_hosted_irq().unwrap();
                irq.assert().unwrap();
                let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
                assert_eq!(
                    report.stop,
                    "EntryDeclined(\"hosted boundary: InterruptArbitrationRequired\")"
                );
                assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA));
                assert_eq!(report.thread.registers, before);
                assert_eq!(report.system, system);
                assert_eq!(report.accounting.blocks_executed, 0);
                assert!(report.context_observation.is_none());
                assert!(report.interrupt_observation.is_none());
            }
        }

        #[test]
        fn native_wfet_xzr_checks_initial_event_before_expired_deadline() {
            const WFET_XZR: u32 = 0xd503_101f;
            for (event_set, reason) in [
                (false, RetireReason::DeadlineExpired),
                (true, RetireReason::EventConsumed),
            ] {
                let cache = tempfile::tempdir().unwrap();
                let machine = machine(cache.path().to_owned(), &[WFET_XZR, NOP]);
                let before = machine.thread.registers.clone();
                if event_set {
                    assert!(machine.endpoint.producer().signal_local());
                }
                let report = machine.run_to_shutdown(request(SOURCE_PA + 4, 1)).unwrap();
                assert_eq!(report.stop, "StopAddress");
                assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 4));
                assert_eq!(report.thread.registers, before);
                assert_eq!(report.accounting.blocks_executed, 1);
                assert_eq!(
                    report.wait_observation,
                    Some(Outcome::Retired {
                        next_pc: SOURCE_PA + 4,
                        reason,
                    })
                );
            }
        }

        #[test]
        fn native_sevl_prefix_publishes_same_owner_event_before_wfe() {
            const SEVL: u32 = 0xd503_20bf;
            let cache = tempfile::tempdir().unwrap();
            let machine = machine(cache.path().to_owned(), &[SEVL, WFE, NOP]);
            let before = machine.thread.registers.clone();
            let before_system = machine.system.clone();
            let report = machine.run_to_shutdown(request(SOURCE_PA + 8, 2)).unwrap();
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 8));
            assert_eq!(report.accounting.blocks_executed, 2);
            assert_eq!(report.thread.registers, before);
            assert_eq!(report.system, before_system);
            assert!(report.interrupt_observation.is_none());
            assert_eq!(
                report.wait_observation,
                Some(Outcome::Retired {
                    next_pc: SOURCE_PA + 8,
                    reason: RetireReason::EventConsumed,
                })
            );
        }

        /// While WFIT is parked, the PE releases its domain exclusion so a host
        /// service can publish RAM and raise the IRQ that wakes it; the resumed
        /// literal load then observes the published bytes.
        #[test]
        fn wait_releases_domain_for_host_service_and_resumed_load_sees_publication() {
            const DATA_PA: u64 = 0x102000;
            const DATA_BYTES: usize = 16;
            const ONE_SECOND_TICKS: u64 = 1_000_000_000;
            const PUBLISHED: u64 = 0x0123_4567_89ab_cdef;
            const MRS_CNTVCT_X3: u32 = 0xd53b_e043;
            const MOVZ_X4_ONE_SECOND_HI: u32 = 0xd2a7_7344;
            const MOVK_X4_ONE_SECOND_LO: u32 = 0xf299_4004;
            const ADD_X0_X3_X4: u32 = 0x8b04_0060;
            const LDR_X1_DATA: u32 = 0x5800_ff61;
            // MRS, MOVZ, MOVK, ADD, WFIT and the resumed literal each run one block.
            const RETIRED: usize = 6;
            const WAIT_NEXT_PC: u64 = SOURCE_PA + 5 * size_of::<u32>() as u64;
            fn assert_send<T: Send>() {}
            assert_send::<HostedRamService>();
            let cache = tempfile::tempdir().unwrap();
            let source: Vec<_> = [
                MRS_CNTVCT_X3,
                MOVZ_X4_ONE_SECOND_HI,
                MOVK_X4_ONE_SECOND_LO,
                ADD_X0_X3_X4,
                WFIT_X0,
                LDR_X1_DATA,
                NOP,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
            let mut registers = stela_compiler::GuestState {
                sp: 0x2f0000,
                nzcv: 0xa0000000,
                reserved: 0xdec0de00,
                ..Default::default()
            };
            for (index, register) in registers.x.iter_mut().enumerate() {
                *register = 0x1111_0000_0000_0000 | index as u64;
            }
            let before = registers.clone();
            let system = SystemState::new(
                PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
                0x2e0000,
                El1Registers::new(1, 2, 3, 4, VECTOR_BASE),
            )
            .unwrap();
            let before_system = system.clone();
            let executable = SourceRamPermissions {
                readable: true,
                writable: false,
                executable: true,
            };
            let data = SourceRamPermissions {
                readable: true,
                writable: true,
                executable: false,
            };
            let mut machine = SoftwareEl1Machine::new(SoftwareEl1Config {
                profile: SoftwareEl1Profile::HostedWaitV1,
                cache_directory: cache.path().to_owned(),
                ram: SourceRamDeclaration {
                    address_space: 392,
                    target: stela_compiler::TargetCpu::Baseline,
                    declared_capacity: vec![PhysicalRamRange {
                        source_pa: SOURCE_PA,
                        bytes: 0x10000,
                    }],
                    initialized: vec![
                        OwnedRamExtent {
                            source_pa: SOURCE_PA,
                            bytes: source.clone(),
                            permissions: executable,
                        },
                        OwnedRamExtent {
                            source_pa: DATA_PA,
                            bytes: vec![0; DATA_BYTES],
                            permissions: data,
                        },
                    ],
                },
                thread: ThreadState {
                    pc: GuestAddress(SOURCE_PA),
                    registers,
                },
                system,
                translation: RegisterValues {
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    ttbr0_el1: 0,
                    ttbr1_el1: 0,
                    mair_el1: 0,
                },
            })
            .unwrap();
            let mut service = machine
                .take_hosted_ram_service(DATA_PA, DATA_BYTES)
                .unwrap();
            assert!(machine.take_hosted_irq().is_err());
            // The service can only publish while the PE holds no execution loan, so
            // it succeeds before the PE starts or once WFIT has parked. Either way
            // the IRQ is pending by the time WFIT checks it.
            let worker = std::thread::spawn(move || -> anyhow::Result<u64> {
                loop {
                    match service.try_publish_then_assert(0, &PUBLISHED.to_le_bytes())? {
                        HostedRamServiceAttempt::Published { irq_sequence } => {
                            return Ok(irq_sequence);
                        }
                        HostedRamServiceAttempt::ExecutionBusy
                        | HostedRamServiceAttempt::ServiceBusy => {
                            std::thread::sleep(core::time::Duration::from_millis(1));
                        }
                    }
                }
            });
            let report = machine
                .run_to_shutdown(request(
                    SOURCE_PA + (RETIRED * size_of::<u32>()) as u64,
                    RETIRED,
                ))
                .unwrap();
            assert_ne!(worker.join().unwrap().unwrap(), 0);
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.accounting.blocks_executed, RETIRED);
            let mut expected = before;
            expected.x[0] = report.thread.registers.x[3] + ONE_SECOND_TICKS;
            expected.x[1] = PUBLISHED;
            expected.x[3] = report.thread.registers.x[3];
            expected.x[4] = ONE_SECOND_TICKS;
            assert_eq!(report.thread.registers, expected);
            assert_eq!(report.system, before_system);
            assert!(report.interrupt_observation.is_none());
            assert_eq!(
                report.wait_observation,
                Some(Outcome::Retired {
                    next_pc: WAIT_NEXT_PC,
                    reason: RetireReason::InterruptPending,
                })
            );
            let mut expected_data = vec![0; DATA_BYTES];
            expected_data[..size_of::<u64>()].copy_from_slice(&PUBLISHED.to_le_bytes());
            let digest = |source_pa| {
                report
                    .ram
                    .iter()
                    .find(|range| range.source_pa == source_pa)
                    .unwrap()
                    .sha256
                    .clone()
            };
            assert_eq!(digest(DATA_PA), Ok(crate::sha256(&expected_data)));
            assert_eq!(digest(SOURCE_PA), Ok(crate::sha256(&source)));
        }
    }
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod mutable_source {
        //! Self-modifying code on the software EL1 PE.
        use super::*;
        use crate::system::state::{El1Registers, PSTATE_EL1H};
        use stela_compiler::{GuestState, TargetCpu};
        fn assert_ram(report: &SoftwareEl1Report, index: usize, bytes: &[u8]) {
            assert_eq!(report.ram[index].sha256, Ok(crate::sha256(bytes)));
        }
        const BASE: u64 = 0x100000;
        const STP_X0_X3_X1: u32 = 0xa9000c20;
        const ADD_X2_1: u32 = 0x91000442;
        const ADD_X2_7: u32 = 0x91001c42;
        const NOP: u32 = 0xd503201f;
        const B_BACK_12: u32 = 0x17fffffd;
        fn config(
            cache: PathBuf,
            words: &[u32],
            target: u64,
        ) -> (SoftwareEl1Config, InitializedRamRegion) {
            let mut registers = GuestState {
                sp: BASE + 0x2000,
                nzcv: 0xa0000000,
                reserved: 0xabc12300,
                fpcr: 0,
                fpsr: 0,
                ..Default::default()
            };
            for (i, value) in registers.x.iter_mut().enumerate() {
                *value = 0x1122334400000000 | i as u64;
            }
            for (i, value) in registers.v.iter_mut().enumerate() {
                *value = [0x2233445500000000 | i as u64, 0x3344556600000000 | i as u64];
            }
            registers.x[0] = u64::from(ADD_X2_7) | u64::from(NOP) << 32;
            registers.x[1] = target;
            let prefix: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            (
                SoftwareEl1Config {
                    profile: SoftwareEl1Profile::PlatformV1,
                    cache_directory: cache,
                    ram: SourceRamDeclaration {
                        address_space: 702,
                        target: TargetCpu::Baseline,
                        declared_capacity: vec![PhysicalRamRange {
                            source_pa: BASE,
                            bytes: 64,
                        }],
                        initialized: Vec::new(),
                    },
                    thread: ThreadState {
                        pc: GuestAddress(BASE),
                        registers,
                    },
                    system: SystemState::new(
                        PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
                        BASE + 0x1000,
                        El1Registers::new(1, 2, 3, 4, 0),
                    )
                    .unwrap(),
                    translation: RegisterValues {
                        sctlr_el1: 0,
                        tcr_el1: 0,
                        ttbr0_el1: 0,
                        ttbr1_el1: 0,
                        mair_el1: 0,
                    },
                },
                InitializedRamRegion {
                    range: PhysicalRamRange {
                        source_pa: BASE,
                        bytes: 64,
                    },
                    file_sha256: crate::sha256(&prefix),
                    file_prefix: prefix,
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: true,
                        executable: true,
                    },
                },
            )
        }
        #[test]
        fn revisiting_modified_cached_source_rebinds_before_any_old_instruction_executes() {
            let cache = tempfile::tempdir().unwrap();
            let (mut config, region) = config(
                cache.path().to_owned(),
                &[ADD_X2_1, NOP, STP_X0_X3_X1, B_BACK_12],
                BASE,
            );
            // The second pair member overwrites its own STP and the following branch
            // with identical words; both writes still count as source changes.
            config.thread.registers.x[3] = u64::from(STP_X0_X3_X1) | u64::from(B_BACK_12) << 32;
            let mut expected = config.thread.registers.clone();
            expected.x[2] = expected.x[2].wrapping_add(8);
            let system = config.system.clone();
            let mut expected_ram = vec![0; 64];
            expected_ram[..16].copy_from_slice(&region.file_prefix);
            expected_ram[..8].copy_from_slice(&expected.x[0].to_le_bytes());
            expected_ram[8..16].copy_from_slice(&expected.x[3].to_le_bytes());
            let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
                .unwrap()
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: None,
                    block_budget: 5,
                })
                .unwrap();
            assert_eq!(report.thread.registers, expected);
            assert_eq!(report.system, system);
            assert_eq!(report.thread.pc, GuestAddress(BASE + 4));
            assert_eq!(report.accounting.blocks_executed, 5);
            assert_ram(&report, 0, &expected_ram);
        }
        #[test]
        fn overwrite_own_source_settles_once_using_exact_preeffect_pin_and_owned_write() {
            let cache = tempfile::tempdir().unwrap();
            let (mut config, region) =
                config(cache.path().to_owned(), &[STP_X0_X3_X1, ADD_X2_1], BASE);
            config.thread.registers.x[0] = u64::from(NOP) | u64::from(ADD_X2_7) << 32;
            let mut expected = config.thread.registers.clone();
            expected.x[2] = expected.x[2].wrapping_add(7);
            let system = config.system.clone();
            let mut expected_ram = vec![0; 64];
            expected_ram[..8].copy_from_slice(&expected.x[0].to_le_bytes());
            expected_ram[8..16].copy_from_slice(&expected.x[3].to_le_bytes());
            let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
                .unwrap()
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: Some(GuestAddress(BASE + 8)),
                    block_budget: 3,
                })
                .unwrap();
            assert_eq!(report.stop, "StopAddress");
            assert_eq!(report.thread.registers, expected);
            assert_eq!(report.system, system);
            assert_eq!(report.thread.pc, GuestAddress(BASE + 8));
            assert_eq!(report.accounting.blocks_executed, 2);
            assert_ram(&report, 0, &expected_ram);
        }
        #[test]
        fn declared_region_tail_is_real_data_but_outside_region_remains_a_reached_refusal() {
            for target in [BASE + 48, BASE + 64] {
                let cache = tempfile::tempdir().unwrap();
                let (config, region) = config(cache.path().to_owned(), &[STP_X0_X3_X1], target);
                let expected = config.thread.registers.clone();
                let system = config.system.clone();
                let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
                    .unwrap()
                    .run_to_shutdown(SoftwareEl1Request {
                        stop_pc: Some(GuestAddress(BASE + 4)),
                        block_budget: 2,
                    })
                    .unwrap();
                assert_eq!(report.thread.registers, expected);
                assert_eq!(report.system, system);
                if target == BASE + 48 {
                    assert_eq!(report.stop, "StopAddress");
                    assert_eq!(report.thread.pc, GuestAddress(BASE + 4));
                    let mut ram = [0; 64];
                    ram[..4].copy_from_slice(&STP_X0_X3_X1.to_le_bytes());
                    ram[48..56].copy_from_slice(&expected.x[0].to_le_bytes());
                    ram[56..64].copy_from_slice(&expected.x[3].to_le_bytes());
                    assert_ram(&report, 0, &ram);
                } else {
                    assert_ne!(report.stop, "StopAddress");
                    assert_eq!(report.thread.pc, GuestAddress(BASE));
                    assert_eq!(report.accounting.blocks_executed, 0);
                }
            }
        }
        #[test]
        fn mutable_fetch_declines_actual_enabled_cache_controls_before_native_entry() {
            for bit in [1 << 2, 1 << 12] {
                let cache = tempfile::tempdir().unwrap();
                let (mut config, region) = config(cache.path().to_owned(), &[NOP], BASE);
                config.translation.sctlr_el1 = bit;
                assert!(
                    SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region]).is_err()
                );
            }
        }
        #[test]
        fn own_source_pair_prefix_survives_second_member_fault_without_writeback_or_retry() {
            const STP_X0_X2_X1_POST16: u32 = 0xa8810820;
            let cache = tempfile::tempdir().unwrap();
            let (config, mut region) =
                config(cache.path().to_owned(), &[STP_X0_X2_X1_POST16], BASE);
            region.range.bytes = 8; // explicit4B zero tail; remaining capacity stays absent
            let expected = config.thread.registers.clone();
            let system = config.system.clone();
            let report = SoftwareEl1Machine::new_with_regions(config, Vec::new(), vec![region])
                .unwrap()
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: None,
                    block_budget: 2,
                })
                .unwrap();
            assert!(report.stop.starts_with("Indeterminate"));
            assert_eq!(report.thread.pc, GuestAddress(BASE));
            assert_eq!(report.thread.registers, expected); // includes original X1 base
            assert_eq!(report.system, system);
            assert_eq!(report.accounting.blocks_executed, 0);
            assert_ram(&report, 0, &expected.x[0].to_le_bytes());
        }
    }
    #[cfg(target_arch = "x86_64")]
    mod platform {
        use super::*;
        use crate::system::state::{El1Registers, PSTATE_EL1H};
        const SOURCE_PA: u64 = 0x100000;
        const VECTOR_BASE: u64 = 0x8000;
        const NOP: u32 = 0xd503201f;
        fn machine(cache: PathBuf, words: &[u32], vector_base: u64) -> SoftwareEl1Machine {
            machine_with_profile(cache, words, vector_base, SoftwareEl1Profile::PlatformV1)
        }
        pub(super) fn machine_with_profile(
            cache: PathBuf,
            words: &[u32],
            vector_base: u64,
            profile: SoftwareEl1Profile,
        ) -> SoftwareEl1Machine {
            let mut registers = stela_compiler::GuestState {
                sp: 0x2f0000,
                nzcv: 0xa0000000,
                reserved: 0xdec0de00,
                ..Default::default()
            };
            for (i, value) in registers.x.iter_mut().enumerate() {
                *value = 0x1111000000000000 | i as u64;
            }
            registers.x[10] = vector_base;
            for (i, value) in registers.v.iter_mut().enumerate() {
                *value = [0x2222000000000000 | i as u64, 0x3333000000000000 | i as u64];
            }
            SoftwareEl1Machine::new(SoftwareEl1Config {
                profile,
                cache_directory: cache,
                ram: SourceRamDeclaration {
                    address_space: 91,
                    target: stela_compiler::TargetCpu::Baseline,
                    declared_capacity: vec![PhysicalRamRange {
                        source_pa: SOURCE_PA,
                        bytes: 0x10000,
                    }],
                    initialized: vec![OwnedRamExtent {
                        source_pa: SOURCE_PA,
                        bytes: words.iter().flat_map(|word| word.to_le_bytes()).collect(),
                        permissions: SourceRamPermissions {
                            readable: true,
                            writable: false,
                            executable: true,
                        },
                    }],
                },
                thread: ThreadState {
                    pc: GuestAddress(SOURCE_PA),
                    registers,
                },
                system: SystemState::new(
                    PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
                    0x2e0000,
                    El1Registers::new(1, 2, 3, 4, 0),
                )
                .unwrap(),
                translation: RegisterValues {
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    ttbr0_el1: 0,
                    ttbr1_el1: 0,
                    mair_el1: 0,
                },
            })
            .unwrap()
        }
        #[test]
        fn context_publication_rejects_other_same_profile_cache_before_fetch() {
            let machine = machine(PathBuf::new(), &[NOP], VECTOR_BASE);
            let memory = machine.memory;
            let system = machine.system;
            let InstalledSource::El1(installed) = machine.installed else {
                panic!("platform owner absent")
            };
            // Moving the installed owner keeps its cache allocation.
            installed
                .into_executable_scope(&ConsumerKey(()), |runtime, sources, controls| {
                    let outer = memory.execution_loan().unwrap();
                    let mut other = BlockRuntime::new_for_target(
                        runtime.address_space(),
                        PathBuf::new(),
                        runtime.profile(),
                        runtime.target_cpu(),
                    );
                    let before = controls.snapshot().unwrap();
                    let registered = runtime.regions.len();
                    let error = sources
                        .publication_scope(&mut other, controls, &system, &outer)
                        .err()
                        .unwrap();
                    assert_eq!(
                        error,
                        "publication runtime is not the original installed source cache"
                    );
                    assert!(other.regions.is_empty() && other.loaded.is_empty());
                    assert_eq!(runtime.regions.len(), registered);
                    let after = controls.snapshot().unwrap();
                    assert_eq!(before.generation(), after.generation());
                    assert!(before.same_pe(&after));
                    let _scope = sources
                        .publication_scope(runtime, controls, &system, &outer)
                        .unwrap();
                })
                .unwrap();
        }
    }
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod scalar_load {
        //! Scalar loads on the software EL1 PE, checked against full register banks and RAM.
        use super::*;
        use crate::system::state::{El1Registers, PSTATE_EL1H};
        use stela_compiler::{GuestState, TargetCpu};
        const CODE: u64 = 0x100000;
        const DATA: u64 = CODE + 0x100;
        fn config(cache: PathBuf, word: u32, data: Option<Vec<u8>>) -> SoftwareEl1Config {
            let mut registers = GuestState {
                sp: DATA,
                nzcv: 0xa0000000,
                reserved: 0xabc12000,
                ..Default::default()
            };
            for (index, value) in registers.x.iter_mut().enumerate() {
                *value = 0x1234567800000000 | index as u64;
            }
            for (index, value) in registers.v.iter_mut().enumerate() {
                *value = [
                    0x2233445500000000 | index as u64,
                    0x3344556600000000 | index as u64,
                ];
            }
            registers.x[1] = DATA;
            let mut initialized = vec![OwnedRamExtent {
                source_pa: CODE,
                bytes: word.to_le_bytes().to_vec(),
                permissions: SourceRamPermissions {
                    readable: true,
                    writable: false,
                    executable: true,
                },
            }];
            if let Some(bytes) = data {
                initialized.push(OwnedRamExtent {
                    source_pa: DATA,
                    bytes,
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: true,
                        executable: false,
                    },
                });
            }
            SoftwareEl1Config {
                profile: SoftwareEl1Profile::PlatformV1,
                cache_directory: cache,
                ram: SourceRamDeclaration {
                    address_space: 719,
                    target: TargetCpu::Baseline,
                    declared_capacity: vec![PhysicalRamRange {
                        source_pa: CODE,
                        bytes: 0x1000,
                    }],
                    initialized,
                },
                thread: ThreadState {
                    pc: GuestAddress(CODE),
                    registers,
                },
                system: SystemState::new(
                    PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
                    0x2f0000,
                    El1Registers::new(CODE, 0x3c5, 0, 0, 0),
                )
                .unwrap(),
                translation: RegisterValues {
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    ttbr0_el1: 0,
                    ttbr1_el1: 0,
                    mair_el1: 0,
                },
            }
        }
        fn run(config: SoftwareEl1Config) -> SoftwareEl1Report {
            SoftwareEl1Machine::new(config)
                .unwrap()
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: Some(GuestAddress(CODE + 4)),
                    block_budget: 2,
                })
                .unwrap()
        }
        #[test]
        fn widths_extensions_literals_and_zero_discard_preserve_complete_banks_and_exact_ram() {
            // Hand-written source words.
            for (word, bytes, value) in [
                (0x39400020_u32, 1, 0x80_u64),
                (0x79400020, 2, 0x8080),
                (0xb9400020, 4, 0x80808080),
                (0xf9400020, 8, 0x8080808080808080),
                (0x39c00020, 1, 0xffffff80),
                (0x39800020, 1, 0xffffffffffffff80),
                (0x79c00020, 2, 0xffff8080),
                (0x79800020, 2, 0xffffffffffff8080),
                (0xb9800020, 4, 0xffffffff80808080),
                (0x18000800, 4, 0x80808080),
                (0x58000800, 8, 0x8080808080808080),
                (0x98000800, 4, 0xffffffff80808080),
                (0xb940003f, 4, 0),
            ] {
                let cache = tempfile::tempdir().unwrap();
                let data = vec![0x80; bytes];
                let config = config(cache.path().to_owned(), word, Some(data.clone()));
                let mut expected = config.thread.registers.clone();
                if word != 0xb940003f {
                    expected.x[0] = value;
                }
                let system = config.system.clone();
                let report = run(config);
                assert_eq!(report.stop, "StopAddress", "{word:#x}");
                assert_eq!(report.thread.pc, GuestAddress(CODE + 4));
                assert_eq!(report.thread.registers, expected, "{word:#x}");
                assert_eq!(report.system, system);
                assert_eq!(report.accounting.blocks_executed, 1);
                assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&data)));
            }
        }
        #[test]
        fn immediate_register_extensions_and_pending_writeback_use_original_banks() {
            for (word, base, index, writeback) in [
                (0xb9400420_u32, DATA - 4, 0, None),   // unsigned scaled #4
                (0xb85fc020, DATA + 4, 0, None),       // LDUR W0,[X1,#-4]
                (0xf8408420, DATA, 0, Some(DATA + 8)), // post
                (0xf8408c20, DATA - 8, 0, Some(DATA)), // pre
                (0xf8626820, DATA - 8, 8, None),       // X offset
                (0xf8625820, DATA - 8, 0x1234567800000001, None), // UXTW #3
                (0xf862d820, DATA + 8, 0x12345678ffffffff, None), // SXTW #3
                (0xf8627820, DATA - 8, 1, None),
                (0xf862f820, DATA + 8, u64::MAX, None),
                (0xf87f6820, DATA, 0xdeadbeef, None), // LSL #3
            ] {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(cache.path().to_owned(), word, Some(vec![0xa5; 8]));
                config.thread.registers.x[1] = base;
                config.thread.registers.x[2] = index;
                let mut expected = config.thread.registers.clone();
                expected.x[0] = if matches!(word, 0xb85fc020 | 0xb9400420) {
                    0xa5a5a5a5
                } else {
                    0xa5a5a5a5a5a5a5a5
                };
                if let Some(base) = writeback {
                    expected.x[1] = base;
                }
                let system = config.system.clone();
                let report = run(config);
                assert_eq!(report.stop, "StopAddress", "{word:#x}");
                assert_eq!(report.thread.registers, expected, "{word:#x}");
                assert_eq!(report.system, system);
                assert_eq!(report.accounting.blocks_executed, 1);
            }
        }
        #[test]
        fn actual_sp_alignment_policy_precedes_offset_access_and_preserves_failed_writeback() {
            for sa in [false, true] {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(cache.path().to_owned(), 0xf8404fe0, Some(vec![0x5a; 8]));
                config.thread.registers.sp = DATA - 4;
                config.translation.sctlr_el1 = if sa { 1 << 3 } else { 0 };
                let mut expected = config.thread.registers.clone();
                let system = config.system.clone();
                let report = run(config);
                if sa {
                    assert!(
                        report
                            .stop
                            .contains("M0 source/control fault remains blocked")
                    );
                    let diagnostic = report.memory_observation.as_ref().unwrap();
                    assert!(diagnostic.contains("StackAlignment"));
                    assert!(diagnostic.contains(&format!("source_pc: {}", CODE)));
                    assert!(diagnostic.contains(&format!("original_sp: {}", DATA - 4)));
                    assert_eq!(report.thread.pc, GuestAddress(CODE));
                    assert_eq!(report.accounting.blocks_executed, 0);
                } else {
                    expected.sp = DATA;
                    expected.x[0] = 0x5a5a5a5a5a5a5a5a;
                    assert_eq!(report.stop, "StopAddress");
                    assert_eq!(report.accounting.blocks_executed, 1);
                }
                assert_eq!(report.thread.registers, expected);
                assert_eq!(report.system, system);
            }
        }
        #[test]
        fn reached_missing_ram_and_zr_load_refuse_without_destination_writeback_or_pc() {
            for word in [0xf8408420_u32, 0xb940003f] {
                let cache = tempfile::tempdir().unwrap();
                let config = config(cache.path().to_owned(), word, None);
                let before = config.thread.registers.clone();
                let system = config.system.clone();
                let report = run(config);
                assert_ne!(report.stop, "StopAddress");
                assert_eq!(report.thread.pc, GuestAddress(CODE));
                assert_eq!(report.thread.registers, before);
                assert_eq!(report.system, system);
                assert_eq!(report.accounting.blocks_executed, 0);
            }
        }

        #[test]
        fn aligned_sp_and_offset_destination_alias_commit_only_the_typed_register() {
            for word in [0xf94003e0_u32, 0xb9400021] {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(cache.path().to_owned(), word, Some(vec![0x3c; 8]));
                config.translation.sctlr_el1 = 1 << 3;
                let mut expected = config.thread.registers.clone();
                if word == 0xf94003e0 {
                    expected.x[0] = 0x3c3c3c3c3c3c3c3c;
                } else {
                    expected.x[1] = 0x3c3c3c3c;
                }
                let system = config.system.clone();
                let report = run(config);
                assert_eq!(report.stop, "StopAddress");
                assert_eq!(report.thread.registers, expected);
                assert_eq!(report.system, system);
                assert_eq!(report.accounting.blocks_executed, 1);
            }
        }
        #[test]
        fn device_alignment_and_unprivileged_or_constrained_shapes_decline_before_commit() {
            for word in [0xb8400820_u32, 0xf8408421] {
                let cache = tempfile::tempdir().unwrap();
                let config = config(cache.path().to_owned(), word, Some(vec![0x6b; 8]));
                assert!(SoftwareEl1Machine::new(config).is_err(), "{word:#x}");
            }
            {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(cache.path().to_owned(), 0xb9400020, Some(vec![0x6b; 8]));
                config.thread.registers.x[1] = DATA + 1;
                let before = config.thread.registers.clone();
                let system = config.system.clone();
                let report = run(config);
                assert_ne!(report.stop, "StopAddress");
                assert_eq!(report.thread.pc, GuestAddress(CODE));
                assert_eq!(report.thread.registers, before);
                assert_eq!(report.system, system);
                assert_eq!(report.accounting.blocks_executed, 0);
            }
        }
    }
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod scalar_store {
        //! Authored generic scalar-store fixtures through the original software PE.
        //! Complete bank and exact RAM comparisons; no direct native entry or fake loan.
        use super::*;
        use crate::system::state::{El1Registers, PSTATE_EL1H};
        use stela_compiler::{GuestState, TargetCpu};
        const CODE: u64 = 0x100000;
        const DATA: u64 = CODE + 0x100;
        fn config(cache: PathBuf, word: u32, data: Option<Vec<u8>>) -> SoftwareEl1Config {
            let mut registers = GuestState {
                sp: DATA,
                nzcv: 0xa0000000,
                reserved: 0xabc12000,
                ..Default::default()
            };
            for (index, value) in registers.x.iter_mut().enumerate() {
                *value = 0x1234567800000000 | index as u64;
            }
            for (index, value) in registers.v.iter_mut().enumerate() {
                *value = [
                    0x2233445500000000 | index as u64,
                    0x3344556600000000 | index as u64,
                ];
            }
            registers.x[1] = DATA;
            registers.x[0] = 0x8899aabbccddeeff;
            let mut initialized = vec![OwnedRamExtent {
                source_pa: CODE,
                bytes: word.to_le_bytes().to_vec(),
                permissions: SourceRamPermissions {
                    readable: true,
                    writable: false,
                    executable: true,
                },
            }];
            if let Some(bytes) = data {
                initialized.push(OwnedRamExtent {
                    source_pa: DATA,
                    bytes,
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: true,
                        executable: false,
                    },
                });
            }
            SoftwareEl1Config {
                profile: SoftwareEl1Profile::PlatformV1,
                cache_directory: cache,
                ram: SourceRamDeclaration {
                    address_space: 719,
                    target: TargetCpu::Baseline,
                    declared_capacity: vec![PhysicalRamRange {
                        source_pa: CODE,
                        bytes: 0x1000,
                    }],
                    initialized,
                },
                thread: ThreadState {
                    pc: GuestAddress(CODE),
                    registers,
                },
                system: SystemState::new(
                    PSTATE_EL1H | crate::system::pstate::DAIF_MASK,
                    0x2f0000,
                    El1Registers::new(CODE, 0x3c5, 0, 0, 0),
                )
                .unwrap(),
                translation: RegisterValues {
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    ttbr0_el1: 0,
                    ttbr1_el1: 0,
                    mair_el1: 0,
                },
            }
        }
        fn run(config: SoftwareEl1Config) -> SoftwareEl1Report {
            SoftwareEl1Machine::new(config)
                .unwrap()
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: Some(GuestAddress(CODE + 4)),
                    block_budget: 2,
                })
                .unwrap()
        }
        #[test]
        fn all_store_widths_and_zr_publish_only_exact_extent_and_preserve_complete_banks() {
            for (word, bytes) in [
                (0x39000020_u32, 1),
                (0x79000020, 2),
                (0xb9000020, 4),
                (0xf9000020, 8),
            ] {
                for zero in [false, true] {
                    let cache = tempfile::tempdir().unwrap();
                    let config = config(
                        cache.path().join("cache"),
                        if zero { word | 31 } else { word },
                        Some(vec![0xa5; bytes]),
                    );
                    let expected = config.thread.registers.clone();
                    let system = config.system.clone();
                    let value = if zero { 0_u64 } else { expected.x[0] };
                    let report = run(config);
                    assert_eq!(report.stop, "StopAddress");
                    assert_eq!(report.thread.pc, GuestAddress(CODE + 4));
                    assert_eq!(report.thread.registers, expected);
                    assert_eq!(report.system, system);
                    assert_eq!(report.accounting.blocks_executed, 1);
                    assert_eq!(
                        report.ram[1].sha256,
                        Ok(crate::sha256(&value.to_le_bytes()[..bytes]))
                    );
                    assert_eq!(report.ram[1].bytes, bytes as u64);
                }
            }
        }
        #[test]
        fn store_address_extensions_and_writeback_use_original_source_and_address_banks() {
            for (word, base, index, writeback) in [
                (0xb9000420_u32, DATA - 4, 0, None),
                (0xb81fc020, DATA + 4, 0, None),
                (0xf8008420, DATA, 0, Some(DATA + 8)),
                (0xf8008c20, DATA - 8, 0, Some(DATA)),
                (0xf8226820, DATA - 8, 8, None),
                (0xf8225820, DATA - 8, 0x1234567800000001, None),
                (0xf822d820, DATA + 8, 0x12345678ffffffff, None),
                (0xf8227820, DATA - 8, 1, None),
                (0xf822f820, DATA + 8, u64::MAX, None),
                (0xf83f6820, DATA, 0, None),
            ] {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(cache.path().join("cache"), word, Some(vec![0xa5; 8]));
                config.thread.registers.x[1] = base;
                config.thread.registers.x[2] = index;
                let mut expected = config.thread.registers.clone();
                let value = expected.x[0];
                if let Some(base) = writeback {
                    expected.x[1] = base;
                }
                let system = config.system.clone();
                let report = run(config);
                assert_eq!(report.stop, "StopAddress", "{word:#x}");
                assert_eq!(report.thread.registers, expected, "{word:#x}");
                assert_eq!(report.system, system);
                let bytes = if matches!(word, 0xb9000420 | 0xb81fc020) {
                    4
                } else {
                    8
                };
                let mut expected_ram = vec![0xa5; 8];
                expected_ram[..bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
                assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&expected_ram)));
            }
        }
        #[test]
        fn data_base_index_aliases_snapshot_source_before_effects_and_preserve_flags() {
            for (word, source, base, index) in [
                (0xb9000021_u32, 1, DATA, 8),
                (0xf8226822, 2, DATA - 8, 8),
                (0xf8226821, 1, DATA - 8, 8),
                (0xf90003ff, 31, DATA, 8),
            ] {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(cache.path().join("cache"), word, Some(vec![0xa5; 8]));
                config.thread.registers.x[1] = base;
                config.thread.registers.x[2] = index;
                let expected = config.thread.registers.clone();
                let system = config.system.clone();
                let value = if source == 31 { 0 } else { expected.x[source] };
                let bytes = if word == 0xb9000021 { 4 } else { 8 };
                let mut expected_ram = vec![0xa5; 8];
                expected_ram[..bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
                let report = run(config);
                assert_eq!(report.stop, "StopAddress");
                assert_eq!(report.thread.registers, expected);
                assert_eq!(report.system, system);
                assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&expected_ram)));
            }
        }
        #[test]
        fn actual_sp_alignment_precedes_store_target_and_only_success_commits_sp_writeback() {
            for sa in [false, true] {
                let cache = tempfile::tempdir().unwrap();
                let mut config =
                    config(cache.path().join("cache"), 0xf8004fe0, Some(vec![0x5a; 8]));
                config.thread.registers.sp = DATA - 4;
                config.translation.sctlr_el1 = if sa { 1 << 3 } else { 0 };
                let mut expected = config.thread.registers.clone();
                let system = config.system.clone();
                let value = expected.x[0];
                let report = run(config);
                if sa {
                    assert_ne!(report.stop, "StopAddress");
                    let diagnostic = report.memory_write_observation.as_ref().unwrap();
                    assert!(diagnostic.contains("StackAlignment"));
                    assert!(diagnostic.contains(&format!("original_sp: {}", DATA - 4)));
                    assert_eq!(report.thread.pc, GuestAddress(CODE));
                    assert_eq!(report.accounting.blocks_executed, 0);
                    assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&[0x5a; 8])));
                } else {
                    expected.sp = DATA;
                    assert_eq!(report.stop, "StopAddress");
                    assert_eq!(report.accounting.blocks_executed, 1);
                    assert_eq!(
                        report.ram[1].sha256,
                        Ok(crate::sha256(&value.to_le_bytes()))
                    );
                }
                assert_eq!(report.thread.registers, expected);
                assert_eq!(report.system, system);
            }
        }
        #[test]
        fn missing_readonly_and_misaligned_ram_refuse_before_writeback_or_any_ram_effect() {
            for kind in 0..3 {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(
                    cache.path().join("cache"),
                    0xf8008420,
                    if kind == 0 { None } else { Some(vec![0xa5; 8]) },
                );
                if kind == 1 {
                    config.ram.initialized[1].permissions.writable = false;
                }
                if kind == 2 {
                    config.thread.registers.x[1] = DATA + 1;
                }
                let expected = config.thread.registers.clone();
                let system = config.system.clone();
                let report = run(config);
                assert_ne!(report.stop, "StopAddress");
                assert_eq!(report.thread.pc, GuestAddress(CODE));
                assert_eq!(report.thread.registers, expected);
                assert_eq!(report.system, system);
                assert_eq!(report.accounting.blocks_executed, 0);
                if kind != 0 {
                    assert_eq!(report.ram[1].sha256, Ok(crate::sha256(&[0xa5; 8])));
                }
            }
            for word in [0xb8000820_u32, 0xf8008c00, 0xf8008400] {
                let cache = tempfile::tempdir().unwrap();
                let config = config(cache.path().join("cache"), word, Some(vec![0xa5; 8]));
                assert!(SoftwareEl1Machine::new(config).is_err());
            }
        }
        #[test]
        fn every_scalar_width_retires_cached_source_before_revisit_with_exact_owned_receipt() {
            for (word, bytes) in [
                (0x39000022_u32, 1),
                (0x79000022, 2),
                (0xb9000022, 4),
                (0xf9000022, 8),
            ] {
                let cache = tempfile::tempdir().unwrap();
                let mut config = config(cache.path().join("cache"), word, None);
                config.ram.initialized.clear();
                config.thread.registers.x[0] = 0;
                config.thread.registers.x[1] = CODE + 16 + if bytes == 1 { 1 } else { 0 };
                config.thread.registers.x[2] = match bytes {
                    1 => 0x1c,
                    2 | 4 => 0x91001c00,
                    8 => (0x17fffffc_u64 << 32) | 0x91001c00,
                    _ => unreachable!(),
                };
                let mut expected = config.thread.registers.clone();
                expected.x[0] = 8;
                let system = config.system.clone();
                let words = [
                    0x14000004_u32,
                    word,
                    0x14000002,
                    0xd503201f,
                    0x91000400,
                    0x17fffffc,
                ];
                let prefix = words
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>();
                let mut expected_ram = prefix.clone();
                expected_ram.resize(64, 0);
                let region = InitializedRamRegion {
                    range: PhysicalRamRange {
                        source_pa: CODE,
                        bytes: 64,
                    },
                    file_sha256: crate::sha256(&prefix),
                    file_prefix: prefix,
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: true,
                        executable: true,
                    },
                };
                let machine =
                    SoftwareEl1Machine::new_with_regions(config, vec![], vec![region]).unwrap();
                let report = machine
                    .run_to_shutdown(SoftwareEl1Request {
                        stop_pc: None,
                        block_budget: 6,
                    })
                    .unwrap();
                assert_eq!(report.accounting.blocks_executed, 6);
                assert_eq!(report.thread.pc, GuestAddress(CODE + 20));
                assert_eq!(report.thread.registers, expected);
                assert_eq!(report.system, system);
                expected_ram[16..20].copy_from_slice(&0x91001c00_u32.to_le_bytes());
                assert_eq!(report.ram[0].sha256, Ok(crate::sha256(&expected_ram)));
                assert!(
                    report
                        .memory_write_observation
                        .as_ref()
                        .unwrap()
                        .contains("modified_instruction_ram: true")
                );
            }
        }
        #[test]
        fn scalar_self_overwrite_settles_using_original_pin_before_source_rebind() {
            let cache = tempfile::tempdir().unwrap();
            let mut config = config(cache.path().join("cache"), 0xb9000022, None);
            config.ram.initialized.clear();
            config.thread.registers.x[0] = 0;
            config.thread.registers.x[1] = CODE;
            config.thread.registers.x[2] = 0x91001c00;
            let mut expected = config.thread.registers.clone();
            expected.x[0] = 7;
            let system = config.system.clone();
            let prefix = [0xb9000022_u32, 0x17ffffff]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            let mut expected_ram = prefix.clone();
            expected_ram.resize(64, 0);
            let region = InitializedRamRegion {
                range: PhysicalRamRange {
                    source_pa: CODE,
                    bytes: 64,
                },
                file_sha256: crate::sha256(&prefix),
                file_prefix: prefix,
                permissions: SourceRamPermissions {
                    readable: true,
                    writable: true,
                    executable: true,
                },
            };
            let machine =
                SoftwareEl1Machine::new_with_regions(config, vec![], vec![region]).unwrap();
            let report = machine
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: None,
                    block_budget: 3,
                })
                .unwrap();
            assert_eq!(report.accounting.blocks_executed, 3);
            assert_eq!(report.thread.pc, GuestAddress(CODE + 4));
            assert_eq!(report.thread.registers, expected);
            assert_eq!(report.system, system);
            expected_ram[..4].copy_from_slice(&0x91001c00_u32.to_le_bytes());
            assert_eq!(report.ram[0].sha256, Ok(crate::sha256(&expected_ram)));
        }
    }

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
