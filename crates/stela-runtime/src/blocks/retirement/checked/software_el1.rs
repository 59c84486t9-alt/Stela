//! Generic hosted entry for a genuinely new, exclusively owned software EL1 PE.
//! Owned input values initialize new storage; no hardware PE or live domain is adopted.
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
use anyhow::{Result, ensure};
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
    #[cfg(test)]
    pub(crate) captured_bytes: Result<Vec<u8>, String>,
}

pub struct SoftwareEl1InitialRam {
    pub range: PhysicalRamRange,
    pub permissions: SourceRamPermissions,
    pub sha256: String,
    pub zero_initialized: bool,
    pub file_prefix: Option<(usize, String)>,
}

pub struct SoftwareEl1Report {
    #[cfg(all(test, target_arch = "x86_64"))]
    system_effect_fixture_observation: Option<super::system_effects::SystemEffectObservation>,
    #[cfg(all(test, target_arch = "x86_64"))]
    exception_fixture_probe: Option<exception_fixture::ProbeObservation>,
    #[cfg(all(test, target_arch = "x86_64"))]
    context_fixture_observation: Option<super::el1_context::ContextObservation>,
    pub declared_capacity: Vec<PhysicalRamRange>,
    pub initialized_ram: Vec<SoftwareEl1InitialRam>,
    pub stop: String,
    pub accounting: RunOutcome,
    pub thread: ThreadState,
    pub system: SystemState,
    pub translation: Result<RegisterValues, String>,
    #[cfg(test)]
    pub(crate) translation_before: Result<RegisterValues, String>,
    pub native_observation: Option<String>,
    pub memory_observation: Option<String>,
    pub memory_write_observation: Option<String>,
    pub memory_pair_read_observation: Option<String>,
    #[cfg(test)]
    pub(crate) pair_read_producer_observation: Option<serde_json::Value>,
    #[cfg(test)]
    pub(crate) pair_read_progress_observation:
        Option<crate::memory::domain::m0_read::M0RamPairReadProgress>,
    #[cfg(test)]
    pub(crate) write_producer_observation: Option<serde_json::Value>,
    #[cfg(test)]
    pub(crate) write_progress_observation:
        Option<crate::memory::domain::physical::M0RamWriteProgress>,
    pub register_observation: Option<String>,
    pub system_observation: Option<String>,
    pub system_effect_observation: Option<String>,
    pub context_observation: Option<String>,
    pub platform_identification_sha256: Option<String>,
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
    #[cfg(all(
        test,
        target_arch = "x86_64",
        any(target_os = "macos", target_os = "linux")
    ))]
    pair_read_fixture: Option<super::m0::PairReadFixture>,
    #[cfg(all(
        test,
        target_arch = "x86_64",
        any(target_os = "macos", target_os = "linux")
    ))]
    hold_pair_read_order: bool,
    #[cfg(all(test, target_arch = "x86_64"))]
    exception_fixture_canary: Option<u64>,
    #[cfg(all(
        test,
        target_arch = "x86_64",
        any(target_os = "macos", target_os = "linux")
    ))]
    verify_pair_alias_monitor: bool,
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
        let value = std::str::from_utf8(pair)?;
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
        cache_directory: PathBuf,
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
            // Native fixtures retain raw execute-only source bytes through the
            // original quiescent source diagnostic, without guest Read rights.
            .filter(|extent| {
                extent.permissions.readable || cfg!(test) && extent.permissions.executable
            })
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
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            pair_read_fixture: None,
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            hold_pair_read_order: false,
            #[cfg(all(test, target_arch = "x86_64"))]
            exception_fixture_canary: None,
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            verify_pair_alias_monitor: false,
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
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            mut pair_read_fixture,
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            hold_pair_read_order,
            #[cfg(all(test, target_arch = "x86_64"))]
            exception_fixture_canary,
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            verify_pair_alias_monitor,
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
        // Stable OUTER original fields outlive the installed source scope and
        // its one backend/PE. No self-reference or mutable resources escape.
        #[cfg(test)]
        let mut translation_before = None;
        #[cfg(all(test, target_arch = "x86_64"))]
        let mut exception_fixture_probe = None;
        let mut operation = |runtime: &mut BlockRuntime,
                             sources: &mut InstalledM0Sources,
                             controls: &mut TranslationControls|
         -> Result<_> {
            #[cfg(test)]
            {
                translation_before = Some(
                    controls
                        .snapshot()
                        .map(|snapshot| snapshot.readbacks())
                        .map_err(|error| format!("{error:?}")),
                );
            }
            #[cfg(all(test, target_arch = "x86_64"))]
            let probe = if let Some(address) = exception_fixture_canary {
                let outer = memory.execution_loan().unwrap();
                let source = sources.el1_scope().map_err(anyhow::Error::msg)?;
                let probe = source
                    .physical_space()
                    .seed_exception_reservation_for_fixture(&outer, &mut memory, address)
                    .map_err(anyhow::Error::msg)?;
                let before = exception_fixture::ProbeObservation {
                    local_seeded: true,
                    event_before: endpoint.is_set(),
                    event_after: false,
                    local_after: Err("actual PE has not ended".into()),
                    generation_before: controls
                        .snapshot()
                        .map(|s| s.generation())
                        .map_err(|e| format!("{e:?}")),
                    generation_after: Err("actual PE has not ended".into()),
                };
                Some((probe, before))
            } else {
                None
            };
            // Clone only the SAME original memory-order owner, so holding its
            // fixture guard does not borrow the exclusively mutable CSE slot.
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            let fixture_order_system = if hold_pair_read_order {
                Some(std::sync::Arc::clone(
                    sources
                        .source_scope()
                        .map_err(anyhow::Error::msg)?
                        .physical_space()
                        .memory_system(),
                ))
            } else {
                None
            };
            #[cfg(all(
                test,
                target_arch = "x86_64",
                any(target_os = "macos", target_os = "linux")
            ))]
            let _fixture_order = fixture_order_system
                .as_ref()
                .map(|system| system.fixture_hold_device_ram_order())
                .transpose()?;
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
                                anyhow::anyhow!("original platform identification owner absent")
                            })?,
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
                        #[cfg(all(
                            test,
                            target_arch = "x86_64",
                            any(target_os = "macos", target_os = "linux")
                        ))]
                        pair_read_fixture: pair_read_fixture.take(),
                        #[cfg(all(
                            test,
                            target_arch = "x86_64",
                            any(target_os = "macos", target_os = "linux")
                        ))]
                        verify_pair_alias_monitor,
                        stop_pc: request.stop_pc,
                        block_budget: request.block_budget,
                    },
                )
            };
            #[cfg(all(test, target_arch = "x86_64"))]
            if let Some((probe, mut observed)) = probe {
                // Capture SAME endpoint before the destructive metadata probe.
                observed.event_after = endpoint.is_set();
                observed.local_after = probe.probe_after_pe(&mut memory);
                observed.generation_after = controls
                    .snapshot()
                    .map(|s| s.generation())
                    .map_err(|e| format!("{e:?}"));
                exception_fixture_probe = Some(observed);
            }
            let readbacks = controls
                .snapshot()
                .map(|snapshot| snapshot.readbacks())
                .map_err(|error| format!("{error:?}"));
            #[cfg(test)]
            let observations = observed_ranges
                .iter()
                .map(|range| {
                    let snapshot = usize::try_from(range.bytes)
                        .map_err(|error| error.to_string())
                        .and_then(|bytes| {
                            sources
                                .source_scope()
                                .map_err(|error| error.to_string())?
                                .physical_space()
                                .source_diagnostic_snapshot_quiescent(range.source_pa, bytes)
                                .map_err(|error| format!("{error:?}"))
                        });
                    let sha256 = snapshot
                        .as_ref()
                        .map(|bytes| stela_core::sha256(bytes))
                        .map_err(Clone::clone);
                    SoftwareEl1RamObservation {
                        source_pa: range.source_pa,
                        bytes: range.bytes,
                        sha256,
                        captured_bytes: snapshot,
                    }
                })
                .collect();
            #[cfg(not(test))]
            let observations = match memory.observation_loan() {
                Ok(loan) => observed_ranges
                    .iter()
                    .map(|range| {
                        let snapshot = usize::try_from(range.bytes)
                            .map_err(|error| error.to_string())
                            .and_then(|bytes| {
                                loan.snapshot(range.source_pa, bytes)
                                    .map_err(|error| format!("{error:?}"))
                            });
                        let sha256 = snapshot
                            .as_ref()
                            .map(|bytes| stela_core::sha256(bytes))
                            .map_err(Clone::clone);
                        SoftwareEl1RamObservation {
                            source_pa: range.source_pa,
                            bytes: range.bytes,
                            sha256,
                            #[cfg(test)]
                            captured_bytes: snapshot,
                        }
                    })
                    .collect(),
                Err(error) => observed_ranges
                    .iter()
                    .map(|range| SoftwareEl1RamObservation {
                        source_pa: range.source_pa,
                        bytes: range.bytes,
                        sha256: Err(format!("{error:?}")),
                        #[cfg(test)]
                        captured_bytes: Err(format!("{error:?}")),
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
        #[cfg(test)]
        let write_producer_observation = outcome
            .last_m0_write_observation
            .as_ref()
            .and_then(|value| value.producer_observation())
            .cloned();
        #[cfg(test)]
        let write_progress_observation = outcome
            .last_m0_write_observation
            .as_ref()
            .and_then(|value| value.progress_observation());
        #[cfg(test)]
        let pair_read_producer_observation = outcome
            .last_m0_pair_read_observation
            .as_ref()
            .and_then(|value| value.producer_observation())
            .cloned();
        #[cfg(test)]
        let pair_read_progress_observation = outcome
            .last_m0_pair_read_observation
            .as_ref()
            .and_then(|value| value.progress_observation());
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
        let system_effect_observation = last_system_effect_observation
            .as_ref()
            .map(|value| format!("{value:?}"));
        Ok(SoftwareEl1Report {
            #[cfg(all(test, target_arch = "x86_64"))]
            system_effect_fixture_observation: last_system_effect_observation,
            #[cfg(all(test, target_arch = "x86_64"))]
            exception_fixture_probe,
            declared_capacity,
            initialized_ram,
            stop: format!("{stop:?}"),
            accounting,
            thread,
            system,
            translation,
            #[cfg(test)]
            translation_before: translation_before.expect("one consumed actual installed scope"),
            native_observation: last_native_observation.map(|value| format!("{value:?}")),
            memory_observation: last_m0_observation.map(|value| format!("{value:?}")),
            memory_write_observation: last_m0_write_observation.map(|value| format!("{value:?}")),
            memory_pair_read_observation: last_m0_pair_read_observation
                .map(|value| format!("{value:?}")),
            #[cfg(test)]
            pair_read_producer_observation,
            #[cfg(test)]
            pair_read_progress_observation,
            #[cfg(test)]
            write_producer_observation,
            #[cfg(test)]
            write_progress_observation,
            register_observation: last_el1_register_observation.map(|value| format!("{value:?}")),
            system_observation: last_el1_system_observation.map(|value| format!("{value:?}")),
            system_effect_observation,
            context_observation: last_el1_context_observation
                .as_ref()
                .map(|value| format!("{value:?}")),
            #[cfg(all(test, target_arch = "x86_64"))]
            context_fixture_observation: last_el1_context_observation,
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

#[cfg(all(test, target_arch = "x86_64"))]
mod platform_tests {
    use super::*;
    use crate::system::state::{El1Registers, PSTATE_EL1H};
    const SOURCE_PA: u64 = 0x100000;
    const VECTOR_BASE: u64 = 0x8000;
    const DAIF_CLEAR_ALL: u32 = 0xd5034fff;
    const MSR_VBAR_X10: u32 = 0xd518c00a;
    const MRS_VBAR_X11: u32 = 0xd538c00b;
    const CMP_X11_X10: u32 = 0xeb0a017f;
    const B_EQ_NEXT: u32 = 0x54000040;
    const NOP: u32 = 0xd503201f;
    pub(super) fn state_bytes(state: &stela_compiler::GuestState) -> &[u8] {
        // SAFETY: stable fully initialized784-byte native ABI, observation only.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(state).cast(),
                size_of::<stela_compiler::GuestState>(),
            )
        }
    }
    pub(super) fn capture_machine_before(output: &std::path::Path, machine: &SoftwareEl1Machine) {
        // This is before the consuming run creates its one PE/outer loan.
        // The original memory owner's readonly observation service is retained;
        // it neither constructs an execution loan nor authorizes guest access.
        for range in &machine.observed_ranges {
            let snapshot = usize::try_from(range.bytes)
                .map_err(|error| error.to_string())
                .and_then(|bytes| match &machine.installed {
                    InstalledSource::El1(owner) => owner
                        .source_diagnostic_snapshot(range.source_pa, bytes)
                        .map_err(|error| format!("{error:?}")),
                    InstalledSource::Read64(_) => machine
                        .memory
                        .observation_loan()
                        .map_err(|error| format!("{error:?}"))?
                        .snapshot(range.source_pa, bytes)
                        .map_err(|error| format!("{error:?}")),
                });
            let path = output.join(format!(
                "before-ram-{:x}-{}.bin",
                range.source_pa, range.bytes
            ));
            match snapshot {
                Ok(bytes) => std::fs::write(path, bytes).unwrap(),
                Err(error) => std::fs::write(path.with_extension("error.txt"), error).unwrap(),
            }
        }
        std::fs::write(
            output.join("before-state.bin"),
            state_bytes(&machine.thread.registers),
        )
        .unwrap();
        std::fs::write(
            output.join("system-before.txt"),
            format!("{:#?}", machine.system),
        )
        .unwrap();
    }
    pub(super) fn capture_report_after(output: &std::path::Path, report: &SoftwareEl1Report) {
        // Preserve actual failure observations BEFORE unwrapping or comparing.
        // Unavailable snapshots stay explicit errors; no expected bytes fill them.
        let errors: Vec<_> = report
            .ram
            .iter()
            .map(|range| {
                format!(
                    "{:x}/{}: hash={:?}; raw_error={:?}",
                    range.source_pa,
                    range.bytes,
                    range.sha256,
                    range.captured_bytes.as_ref().err()
                )
            })
            .collect();
        std::fs::write(output.join("actual-report.txt"),format!(
            "stop={}\npc={:x}\naccounting={:?}\nnative={:?}\nwrite={:?}\npair_read={:?}\nsystem_effect={:?}\ncontrols_before={:?}\ncontrols_after={:?}\nram={:?}\n",
            report.stop,report.thread.pc.0,report.accounting,report.native_observation,
            report.memory_write_observation,report.memory_pair_read_observation,report.system_observation,
            report.translation_before,report.translation,errors)).unwrap();
        std::fs::write(
            output.join("after-state.bin"),
            state_bytes(&report.thread.registers),
        )
        .unwrap();
        std::fs::write(
            output.join("system-after.txt"),
            format!("{:#?}", report.system),
        )
        .unwrap();
        let controls = |values: &Result<RegisterValues, String>| match values {
            Ok(values) => serde_json::json!({"sctlr_el1":values.sctlr_el1,
                "tcr_el1":values.tcr_el1,"ttbr0_el1":values.ttbr0_el1,
                "ttbr1_el1":values.ttbr1_el1,"mair_el1":values.mair_el1}),
            Err(error) => serde_json::json!({"unavailable":error}),
        };
        std::fs::write(
            output.join("controls-before.json"),
            serde_json::to_vec_pretty(&controls(&report.translation_before)).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("controls-after.json"),
            serde_json::to_vec_pretty(&controls(&report.translation)).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("actual-write-progress.txt"),
            format!("{:?}", report.write_progress_observation),
        )
        .unwrap();
        std::fs::write(
            output.join("actual-producer.json"),
            serde_json::to_vec_pretty(&report.write_producer_observation).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("actual-pair-read-progress.txt"),
            format!("{:?}", report.pair_read_progress_observation),
        )
        .unwrap();
        std::fs::write(
            output.join("actual-pair-read-producer.json"),
            serde_json::to_vec_pretty(&report.pair_read_producer_observation).unwrap(),
        )
        .unwrap();
        std::fs::write(
            output.join("actual-pair-read-observation.txt"),
            format!("{:?}", report.memory_pair_read_observation),
        )
        .unwrap();
        for range in &report.ram {
            let path = output.join(format!(
                "actual-ram-{:x}-{}.bin",
                range.source_pa, range.bytes
            ));
            match &range.captured_bytes {
                Ok(bytes) => std::fs::write(path, bytes).unwrap(),
                Err(error) => std::fs::write(path.with_extension("error.txt"), error).unwrap(),
            }
        }
        std::fs::write(output.join("actual-observation.txt"), format!(
            "stop={}\npc={:x}\nblocks={}\nsystem={:?}\nwrite={:?}\nplatform_ids={:?}\ncompiler={}\n",
            report.stop,report.thread.pc.0,report.accounting.blocks_executed,
            report.system_observation,report.memory_write_observation,
            report.platform_identification_sha256,report.compiler_source_sha256)).unwrap();
    }
    fn machine(cache: PathBuf, words: &[u32], vector_base: u64) -> SoftwareEl1Machine {
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
            profile: SoftwareEl1Profile::PlatformV1,
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
            panic!("actual platform owner absent")
        };
        // Moving the installed owner retains its original cache allocation.
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

    #[test]
    #[ignore = "actual native System carriers through sole factory; requires reviewed graph and fresh ignored output"]
    fn mixed_same_owner_daif_vbar_flags_and_branch_complete() {
        let output = PathBuf::from(
            std::env::var_os("STELA_EL1_SYSTEM_NATIVE_OUTPUT").expect("fresh absolute output"),
        );
        assert!(output.is_absolute());
        std::fs::create_dir(&output).unwrap();
        let machine = machine(
            output.join("cache"),
            &[
                DAIF_CLEAR_ALL,
                MSR_VBAR_X10,
                MRS_VBAR_X11,
                CMP_X11_X10,
                B_EQ_NEXT,
                NOP,
            ],
            VECTOR_BASE,
        );
        capture_machine_before(&output, &machine);
        let mut expected = machine.thread.registers.clone();
        expected.x[11] = VECTOR_BASE;
        expected.nzcv = 0x60000000;
        let initial_ram = machine.initialized_ram[0].sha256.clone();
        let report = machine
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: Some(GuestAddress(SOURCE_PA + 24)),
                block_budget: 8,
            })
            .unwrap();
        capture_report_after(&output, &report);
        assert_eq!(report.stop, "StopAddress");
        assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA + 24));
        assert_eq!(report.thread.registers, expected);
        assert_eq!(report.system.pstate_misc(), PSTATE_EL1H);
        assert_eq!(
            *report.system.el1_registers(),
            El1Registers::new(1, 2, 3, 4, VECTOR_BASE)
        );
        assert_eq!(report.accounting.blocks_executed, 5);
        assert_eq!(report.ram[0].sha256.as_ref().unwrap(), &initial_ram);
        assert!(
            report
                .system_observation
                .as_ref()
                .unwrap()
                .contains("applied: true")
        );
        assert!(report.platform_identification_sha256.is_some());
    }
    #[test]
    #[ignore = "actual native no-effect VBAR refusal; requires reviewed graph and fresh ignored output"]
    fn mixed_misaligned_vbar_refuses_without_state_or_pc_mutation() {
        let output = PathBuf::from(
            std::env::var_os("STELA_EL1_SYSTEM_NATIVE_OUTPUT").expect("fresh absolute output"),
        );
        assert!(output.is_absolute());
        std::fs::create_dir(&output).unwrap();
        let machine = machine(output.join("cache"), &[MSR_VBAR_X10], VECTOR_BASE + 1);
        capture_machine_before(&output, &machine);
        let before = (machine.thread.registers.clone(), machine.system.clone());
        let report = machine
            .run_to_shutdown(SoftwareEl1Request {
                stop_pc: None,
                block_budget: 2,
            })
            .unwrap();
        capture_report_after(&output, &report);
        assert!(report.stop.contains("HelperRefused"));
        assert_eq!(report.thread.pc, GuestAddress(SOURCE_PA));
        assert_eq!(report.thread.registers, before.0);
        assert_eq!(report.system, before.1);
        assert_eq!(report.accounting.blocks_executed, 0);
        assert!(
            report
                .system_observation
                .as_ref()
                .unwrap()
                .contains("applied: false")
        );
    }
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    #[test]
    #[ignore = "actual native Device pair writes; reviewed current graph and fresh ignored output required"]
    fn actual_pair_native_full_state_ram_and_reached_refusals_through_same_factory() {
        use crate::memory::domain::physical::store_fixtures::{self, StoreOutcome, StoreShape};
        let output = PathBuf::from(
            std::env::var_os("STELA_EL1_STORE_NATIVE_OUTPUT").expect("fresh absolute store output"),
        );
        assert!(output.is_absolute());
        std::fs::create_dir(&output).unwrap();
        for case in store_fixtures::cases()
            .into_iter()
            .filter(|case| case.shape != StoreShape::Scalar)
        {
            let case_output = output.join(case.name);
            std::fs::create_dir(&case_output).unwrap();
            let system = SystemState::new(
                store_fixtures::PSTATE_LOW32 & !0xf000_0000,
                store_fixtures::SP_EL0,
                El1Registers::new(1, 2, 3, 4, 0),
            )
            .unwrap();
            let before_system = system.clone();
            let mut machine = SoftwareEl1Machine::from_materialized(
                SoftwareEl1Profile::PlatformV1,
                case_output.join("cache"),
                ThreadState {
                    pc: store_fixtures::SOURCE_PC,
                    registers: case.before(),
                },
                system,
                RegisterValues {
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    ttbr0_el1: 0,
                    ttbr1_el1: 0,
                    mair_el1: 0,
                },
                stela_compiler::TargetCpu::Baseline,
                case.materialize(100).unwrap(),
            )
            .unwrap();
            machine.verify_pair_alias_monitor = case.alias;
            assert_eq!(machine.thread.registers, case.before());
            capture_machine_before(&case_output, &machine);
            std::fs::write(
                case_output.join("system-before.txt"),
                format!("{:#?}", machine.system),
            )
            .unwrap();
            std::fs::write(case_output.join("source.bin"), case.source()).unwrap();
            std::fs::write(
                case_output.join("before-state.bin"),
                state_bytes(&machine.thread.registers),
            )
            .unwrap();
            let report = machine
                .run_to_shutdown(SoftwareEl1Request {
                    stop_pc: if case.outcome == StoreOutcome::Complete {
                        Some(case.expected_pc())
                    } else {
                        None
                    },
                    block_budget: 2,
                })
                .unwrap();
            capture_report_after(&case_output, &report);
            if let Some(progress) = report.write_progress_observation {
                case.assert_progress(progress);
            } else {
                assert_eq!(
                    case.completed_bytes, 0,
                    "reached publication must retain actual progress"
                );
                assert_ne!(case.outcome, StoreOutcome::Complete);
            }
            assert_eq!(
                report.thread.registers,
                case.expected_state(),
                "{}",
                case.name
            );
            assert_eq!(report.thread.pc, case.expected_pc(), "{}", case.name);
            assert_eq!(report.system, before_system, "{}", case.name);
            assert_eq!(
                report.accounting.blocks_executed,
                usize::from(case.outcome == StoreOutcome::Complete),
                "{}",
                case.name
            );
            if case.outcome == StoreOutcome::Complete {
                assert_eq!(report.stop, "StopAddress");
            } else {
                assert!(
                    report.stop.starts_with("Indeterminate"),
                    "{} {}",
                    case.name,
                    report.stop
                );
            }
            std::fs::write(
                case_output.join("system-after.txt"),
                format!("{:#?}", report.system),
            )
            .unwrap();
            std::fs::write(
                case_output.join("actual-producer.json"),
                serde_json::to_vec_pretty(&report.write_producer_observation).unwrap(),
            )
            .unwrap();
            if case.outcome == StoreOutcome::Complete || case.completed_bytes != 0 {
                let producer = report
                    .write_producer_observation
                    .as_ref()
                    .expect("reached native pair must retain its actual producer observation");
                assert_eq!(producer["same_original_outer"], true);
                assert_eq!(producer["actual_address_space"], 100);
                assert_eq!(producer["source_pc"], store_fixtures::SOURCE_PC.0);
                assert_eq!(
                    producer["source_word"],
                    u32::from_le_bytes(case.source()[..4].try_into().unwrap())
                );
            } else {
                assert!(
                    report.write_producer_observation.is_none(),
                    "pre-native refusal must not claim a native producer receipt"
                );
            }
            let before_controls = report.translation_before.as_ref().unwrap();
            std::fs::write(case_output.join("controls-before.json"), serde_json::to_vec_pretty(&serde_json::json!({
                "sctlr_el1":before_controls.sctlr_el1,"tcr_el1":before_controls.tcr_el1,
                "ttbr0_el1":before_controls.ttbr0_el1,"ttbr1_el1":before_controls.ttbr1_el1,"mair_el1":before_controls.mair_el1})).unwrap()).unwrap();
            let actual_controls = report.translation.as_ref().unwrap();
            assert_eq!(before_controls, actual_controls);
            std::fs::write(case_output.join("controls-after.json"), serde_json::to_vec_pretty(&serde_json::json!({
                "sctlr_el1":actual_controls.sctlr_el1,"tcr_el1":actual_controls.tcr_el1,
                "ttbr0_el1":actual_controls.ttbr0_el1,"ttbr1_el1":actual_controls.ttbr1_el1,"mair_el1":actual_controls.mair_el1})).unwrap()).unwrap();
            assert_eq!(
                *actual_controls,
                RegisterValues {
                    sctlr_el1: 0,
                    tcr_el1: 0,
                    ttbr0_el1: 0,
                    ttbr1_el1: 0,
                    mair_el1: 0
                }
            );
            if case.alias {
                assert!(
                    report
                        .memory_write_observation
                        .as_ref()
                        .unwrap()
                        .contains("alias_monitor_verified: true")
                );
            }
            let expected = case.expected_ram();
            for range in &report.ram {
                let actual_bytes = range.captured_bytes.as_ref().unwrap();
                std::fs::write(
                    case_output.join(format!(
                        "actual-ram-{:x}-{}.bin",
                        range.source_pa, range.bytes
                    )),
                    actual_bytes,
                )
                .unwrap();
                if range.source_pa >= store_fixtures::DATA_PA
                    && range.source_pa < store_fixtures::DATA_PA + expected.len() as u64
                {
                    let offset = (range.source_pa - store_fixtures::DATA_PA) as usize;
                    let bytes = usize::try_from(range.bytes).unwrap();
                    assert_eq!(
                        actual_bytes,
                        &expected[offset..offset + bytes],
                        "{} actual RAM",
                        case.name
                    );
                    assert_eq!(
                        range.sha256.as_ref().unwrap(),
                        &stela_core::sha256(&expected[offset..offset + bytes]),
                        "{} data range",
                        case.name
                    );
                } else if range.source_pa == store_fixtures::ALIAS_PA {
                    assert!(case.alias);
                    assert_eq!(
                        actual_bytes,
                        &expected[..size_of::<u64>()],
                        "{} actual alias",
                        case.name
                    );
                } else if range.source_pa == store_fixtures::SOURCE_PC.0 {
                    assert_eq!(actual_bytes, &case.source());
                    assert_eq!(
                        range.sha256.as_ref().unwrap(),
                        &stela_core::sha256(&case.source())
                    );
                }
            }
            std::fs::write(
                case_output.join("after-state.bin"),
                state_bytes(&report.thread.registers),
            )
            .unwrap();
            std::fs::write(case_output.join("expected-ram.bin"), expected).unwrap();
            std::fs::write(
                case_output.join("actual-observation.txt"),
                format!(
                    "stop={}\npc={:x}\nblocks={}\nwrite={:?}\ncompiler={}\n",
                    report.stop,
                    report.thread.pc.0,
                    report.accounting.blocks_executed,
                    report.memory_write_observation,
                    report.compiler_source_sha256
                ),
            )
            .unwrap();
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "el1_context/fixture.rs"]
mod exception_fixture;

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "software_el1/pair_read_tests.rs"]
mod pair_read_tests;

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "system_effects/fixture.rs"]
mod system_effect_fixture;

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "software_el1/mutable_source_tests.rs"]
mod mutable_source_tests;
