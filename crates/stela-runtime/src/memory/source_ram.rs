//! Loader RAM at fixed physical addresses. Only initialized or zeroed extents
//! are backed.
use super::{
    MAX_IMAGE_MEMORY_BYTES,
    backing::{AccessError, AccessPermissions, MemoryBacking, MemoryView},
    domain::{MappingAttributes, MemoryDomain, MemorySystem, physical::ImmutableCodeBacking},
    host_page_size,
    storage::NativeStorage,
};
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec::Vec};
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

mod region;
pub use region::InitializedRamRegion;

mod publication;
pub(crate) use publication::{SourceRamPublication, SourceRamPublisher};

const MAX_SOURCE_RAM_EXTENTS: usize = 4096;
const MAX_SOURCE_RAM_STRIPES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalRamRange {
    pub source_pa: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRamPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

pub struct OwnedRamExtent {
    pub source_pa: u64,
    pub bytes: Vec<u8>,
    pub permissions: SourceRamPermissions,
}

/// Zero-initialized RAM. Executable source must supply its bytes through
/// `OwnedRamExtent`.
pub struct ZeroedRamExtent {
    pub source_pa: u64,
    pub bytes: u64,
    pub permissions: SourceRamPermissions,
}

enum RamInitial {
    Bytes(Vec<u8>),
    Zeroed(usize),
    FilePrefix {
        prefix: Vec<u8>,
        mapped_bytes: usize,
        file_sha256: String,
    },
}

struct RamExtent {
    source_pa: u64,
    initial: RamInitial,
    permissions: SourceRamPermissions,
}

impl RamExtent {
    fn bytes(&self) -> usize {
        match &self.initial {
            RamInitial::Bytes(bytes) => bytes.len(),
            RamInitial::Zeroed(bytes) => *bytes,
            RamInitial::FilePrefix { mapped_bytes, .. } => *mapped_bytes,
        }
    }

    fn initializer(&self) -> &[u8] {
        match &self.initial {
            RamInitial::Bytes(bytes) => bytes,
            RamInitial::FilePrefix { prefix, .. } => prefix,
            // New anonymous storage provides the zeros.
            RamInitial::Zeroed(_) => &[0],
        }
    }

    fn zero_initialized(&self) -> bool {
        matches!(&self.initial, RamInitial::Zeroed(_))
    }

    fn initial_hash(&self, storage: &NativeStorage, leading: usize) -> String {
        match &self.initial {
            RamInitial::Bytes(bytes) => crate::sha256(bytes),
            RamInitial::Zeroed(bytes)
            | RamInitial::FilePrefix {
                mapped_bytes: bytes,
                ..
            } => {
                // SAFETY: the factory still owns the new zeroed storage before
                // any domain, PE or writer exists. The range is readable and
                // inside the allocation, and the temporary reference does not
                // escape the hash.
                let initial = unsafe {
                    core::slice::from_raw_parts(
                        storage.primary_base().as_ptr().add(leading),
                        *bytes,
                    )
                };
                crate::sha256(initial)
            }
        }
    }
}

pub struct SourceRamDeclaration {
    pub address_space: u64,
    pub target: TargetCpu,
    pub declared_capacity: Vec<PhysicalRamRange>,
    pub initialized: Vec<OwnedRamExtent>,
}

pub(crate) struct SourceRamSystemConfig {
    pub reservation_granule_bytes: u64,
    pub reservation_stripe_count: usize,
}

#[derive(Debug)]
pub(crate) enum SourceRamBuildError {
    Declaration(&'static str),
    AllocationLimit,
    Platform(crate::platform::memory::Error),
    Backing(AccessError),
    Domain(MemoryStatus),
    ImmutableSource(&'static str),
}
impl core::fmt::Display for SourceRamBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Declaration(reason) => write!(f, "invalid source RAM declaration: {reason}"),
            Self::AllocationLimit => write!(f, "source RAM allocation budget exceeded"),
            Self::Platform(error) => write!(f, "source RAM host allocation/protection: {error}"),
            Self::Backing(error) => write!(f, "source RAM backing: {error}"),
            Self::Domain(status) => write!(f, "source RAM domain: {status:?}"),
            Self::ImmutableSource(reason) => write!(f, "source RAM immutable code: {reason}"),
        }
    }
}
impl core::error::Error for SourceRamBuildError {}

pub(crate) struct InitializedRamLayout {
    pub range: PhysicalRamRange,
    pub permissions: SourceRamPermissions,
    pub source_sha256: String,
    pub zero_initialized: bool,
    pub file_prefix: Option<(usize, String)>,
}

#[derive(Debug)]
pub(crate) struct SourceRamLayout {
    pub declared_capacity: Vec<PhysicalRamRange>,
    pub initialized: Vec<InitializedRamLayout>,
}

/// The physical binding, created only by the materialization factory.
pub(crate) struct SourcePhysicalRamBinding {
    domain: Arc<MemoryDomain>,
    system: Arc<MemorySystem>,
    views: Vec<Arc<MemoryView>>,
    generation: u64,
    layout: SourceRamLayout,
    pub(in crate::memory) reloads: Vec<super::domain::physical::RegionReload>,
    pub(in crate::memory) reset_generation: u64,
}

impl SourcePhysicalRamBinding {
    pub(in crate::memory) fn has_mutable_instruction_sources(&self) -> bool {
        self.views.iter().any(|view| {
            view.permissions().executable && view.backing().instruction_generation().is_some()
        })
    }
    pub(in crate::memory) fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }
    pub(in crate::memory) fn system(&self) -> &Arc<MemorySystem> {
        &self.system
    }
    pub(in crate::memory) fn generation(&self) -> u64 {
        self.generation
    }
    pub(in crate::memory) fn owns_view(&self, view: &Arc<MemoryView>) -> bool {
        self.views.iter().any(|owned| Arc::ptr_eq(owned, view))
    }
    pub(in crate::memory) fn current_views(&self) -> bool {
        self.views.iter().all(|view| view.is_current())
    }
    pub(in crate::memory) fn layout(&self) -> &SourceRamLayout {
        &self.layout
    }
}

pub(crate) struct MaterializedSourceRam {
    binding: SourcePhysicalRamBinding,
    immutable_sources: Vec<ImmutableCodeBacking>,
}
impl MaterializedSourceRam {
    /// The test-created mapping, for ownership and retirement checks.
    #[cfg(test)]
    pub(crate) fn test_view(&self, source_pa: u64) -> Option<Arc<MemoryView>> {
        self.binding
            .views
            .iter()
            .find(|view| view.guest_base() == source_pa)
            .map(Arc::clone)
    }

    /// Hand the resources to the physical and source owner, once. The immutable
    /// code owners keep the same backings as the physical views.
    pub(crate) fn into_parts(self) -> (SourcePhysicalRamBinding, Vec<ImmutableCodeBacking>) {
        (self.binding, self.immutable_sources)
    }
}

fn end(range: PhysicalRamRange) -> Result<u64, SourceRamBuildError> {
    if range.bytes == 0 {
        return Err(SourceRamBuildError::Declaration("empty physical range"));
    }
    range
        .source_pa
        .checked_add(range.bytes)
        .ok_or(SourceRamBuildError::Declaration("physical range overflow"))
}

/// Create the machine's domain from initialized bytes, before any PE. Host
/// addresses are chosen by the OS and are not source physical addresses.
#[cfg(test)]
pub(crate) fn materialize_source_ram(
    declaration: SourceRamDeclaration,
    config: SourceRamSystemConfig,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    materialize_source_ram_with_zeroed(declaration, Vec::new(), config)
}

/// Materialize with additional zero-initialized RAM. The whole set is validated
/// before any storage is allocated.
pub(crate) fn materialize_source_ram_with_zeroed(
    declaration: SourceRamDeclaration,
    zeroed: Vec<ZeroedRamExtent>,
    config: SourceRamSystemConfig,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    materialize_source_ram_impl(declaration, zeroed, Vec::new(), config)
}

/// Materialize initialized regions.
pub(crate) fn materialize_source_ram_regions(
    declaration: SourceRamDeclaration,
    zeroed: Vec<ZeroedRamExtent>,
    regions: Vec<InitializedRamRegion>,
    config: SourceRamSystemConfig,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    materialize_source_ram_impl(declaration, zeroed, regions, config)
}

fn materialize_source_ram_impl(
    mut declaration: SourceRamDeclaration,
    zeroed: Vec<ZeroedRamExtent>,
    regions: Vec<InitializedRamRegion>,
    config: SourceRamSystemConfig,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    use SourceRamBuildError as E;
    if declaration.declared_capacity.is_empty()
        || declaration.initialized.is_empty() && zeroed.is_empty() && regions.is_empty()
        || declaration.declared_capacity.len() > MAX_SOURCE_RAM_EXTENTS
        || declaration
            .initialized
            .len()
            .saturating_add(zeroed.len())
            .saturating_add(regions.len())
            > MAX_SOURCE_RAM_EXTENTS
        || config.reservation_stripe_count == 0
        || config.reservation_stripe_count > MAX_SOURCE_RAM_STRIPES
    {
        return Err(E::Declaration("source RAM extent/stripe bound"));
    }
    if !crate::platform::cpu::admitted(declaration.target) {
        return Err(E::Domain(MemoryStatus::Unsupported));
    }
    let page = host_page_size()
        .map_err(|error| E::Platform(crate::platform::memory::Error::other(error.to_string())))?;
    if page < size_of::<u64>() {
        return Err(E::Platform(crate::platform::memory::Error::other(
            "host page size cannot preserve physical RAM eight-byte alignment",
        )));
    }
    declaration
        .declared_capacity
        .sort_unstable_by_key(|range| range.source_pa);
    let mut previous = None;
    for range in &declaration.declared_capacity {
        let limit = end(*range)?;
        if previous.is_some_and(|limit| limit > range.source_pa) {
            return Err(E::Declaration("overlapping physical capacity"));
        }
        previous = Some(limit);
    }
    let mut extents: Vec<_> = core::mem::take(&mut declaration.initialized)
        .into_iter()
        .map(|extent| RamExtent {
            source_pa: extent.source_pa,
            initial: RamInitial::Bytes(extent.bytes),
            permissions: extent.permissions,
        })
        .collect();
    for extent in zeroed {
        if extent.permissions.executable {
            return Err(E::Declaration(
                "zero-initialized RAM cannot be executable source",
            ));
        }
        extents.push(RamExtent {
            source_pa: extent.source_pa,
            initial: RamInitial::Zeroed(
                usize::try_from(extent.bytes).map_err(|_| E::AllocationLimit)?,
            ),
            permissions: extent.permissions,
        });
    }
    for region in regions {
        region.validate()?;
        extents.push(RamExtent {
            source_pa: region.range.source_pa,
            initial: RamInitial::FilePrefix {
                prefix: region.file_prefix,
                mapped_bytes: usize::try_from(region.range.bytes)
                    .map_err(|_| E::AllocationLimit)?,
                file_sha256: region.file_sha256,
            },
            permissions: region.permissions,
        });
    }
    extents.sort_unstable_by_key(|extent| extent.source_pa);
    let mut recipes = Vec::with_capacity(extents.len());
    let mut allocated = 0_usize;
    previous = None;
    // Every fallible check comes before allocating RAM.
    for extent in &extents {
        let range = PhysicalRamRange {
            source_pa: extent.source_pa,
            bytes: extent.bytes() as u64,
        };
        let limit = end(range)?;
        if previous.is_some_and(|limit| limit > range.source_pa) {
            return Err(E::Declaration("overlapping initialized physical RAM"));
        }
        previous = Some(limit);
        if !declaration.declared_capacity.iter().any(|capacity| {
            capacity.source_pa <= range.source_pa
                && end(*capacity).is_ok_and(|capacity_end| limit <= capacity_end)
        }) {
            return Err(E::Declaration("initialized RAM outside declared capacity"));
        }
        let permissions = extent.permissions;
        if permissions.writable
            && (!permissions.readable
                || permissions.executable
                    && !matches!(&extent.initial, RamInitial::FilePrefix { .. }))
            || !permissions.readable && !permissions.executable
        {
            return Err(E::Declaration("unsupported source RAM permissions"));
        }
        // Preserve PA/host congruence without equating their address spaces.
        let leading = (extent.source_pa & (page as u64 - 1)) as usize;
        let bytes = leading
            .checked_add(extent.bytes())
            .and_then(|bytes| bytes.checked_add(page - 1))
            .map(|bytes| bytes & !(page - 1))
            .ok_or(E::AllocationLimit)?;
        allocated = allocated.checked_add(bytes).ok_or(E::AllocationLimit)?;
        if allocated as u64 > MAX_IMAGE_MEMORY_BYTES {
            return Err(E::AllocationLimit);
        }
        recipes.push((leading, bytes));
    }
    // Never accept an existing coherence owner or infer freshness from Arc counts.
    let system = MemorySystem::new(
        config.reservation_granule_bytes,
        config.reservation_stripe_count,
    )
    .map_err(E::Domain)?;
    let mut views = Vec::with_capacity(extents.len());
    let mut immutable_sources = Vec::new();
    let mut reloads = Vec::new();
    let mut layout = Vec::with_capacity(extents.len());
    for (extent, (leading, bytes)) in extents.into_iter().zip(recipes) {
        let permissions = AccessPermissions {
            readable: extent.permissions.readable,
            writable: extent.permissions.writable,
            executable: extent.permissions.executable,
        };
        let storage = NativeStorage::initialized_ram(
            extent.initializer(),
            leading,
            bytes,
            permissions.readable || permissions.executable,
            permissions.writable,
        )
        .map_err(E::Platform)?;
        // SAFETY: the factory owns the anonymous private storage and its
        // rights. Initialization is complete, the host rights are final, no
        // references or aliases escape, and the resulting domain owns every
        // later access.
        let backing = unsafe {
            MemoryBacking::new_managed(
                storage.primary_base(),
                bytes,
                permissions,
                Arc::clone(&storage),
            )
        }
        .map_err(E::Backing)?;
        let view = MemoryView::new(
            Arc::clone(&backing),
            extent.source_pa,
            leading,
            extent.bytes(),
            permissions,
        )
        .map_err(E::Backing)?;
        if permissions.executable && !permissions.writable {
            // SAFETY: initialized_ram finalized the complete allocation host-RO;
            // this private owner created no writable alias, publisher or Rust
            // byte reference. Its retained storage keeps those rights forever.
            immutable_sources.push(
                unsafe { ImmutableCodeBacking::adopt(Arc::clone(&backing)) }
                    .map_err(E::ImmutableSource)?,
            );
        }
        let file_prefix = match &extent.initial {
            RamInitial::FilePrefix {
                prefix,
                file_sha256,
                ..
            } => {
                if permissions.executable {
                    backing
                        .enable_instruction_mutation(&system)
                        .map_err(E::Domain)?;
                }
                reloads.push(super::domain::physical::RegionReload::new(
                    Arc::clone(&backing),
                    leading,
                    prefix.clone().into_boxed_slice(),
                ));
                Some((prefix.len(), file_sha256.clone()))
            }
            _ => None,
        };
        layout.push(InitializedRamLayout {
            range: PhysicalRamRange {
                source_pa: extent.source_pa,
                bytes: extent.bytes() as u64,
            },
            permissions: extent.permissions,
            source_sha256: extent.initial_hash(&storage, leading),
            zero_initialized: extent.zero_initialized(),
            file_prefix,
        });
        views.push(view);
    }
    let domain = MemoryDomain::new_source_physical_ram(
        declaration.address_space,
        Arc::clone(&system),
        views
            .iter()
            .map(|view| {
                (
                    Arc::clone(view),
                    MappingAttributes {
                        tagged: false,
                        shareable: true,
                    },
                )
            })
            .collect(),
        declaration.target,
    )
    .map_err(E::Domain)?;
    let generation = domain.generation().map_err(E::Domain)?;
    Ok(MaterializedSourceRam {
        binding: SourcePhysicalRamBinding {
            domain,
            system,
            views,
            generation,
            reloads,
            reset_generation: 1,
            layout: SourceRamLayout {
                declared_capacity: declaration.declared_capacity,
                initialized: layout,
            },
        },
        immutable_sources,
    })
}

impl core::fmt::Debug for InitializedRamLayout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitializedRamLayout")
            .field("range", &self.range)
            .field("permissions", &self.permissions)
            .field("zero_initialized", &self.zero_initialized)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod region {
        //! RAM region storage and identity.
        use super::*;
        use crate::memory::{
            backing::AccessKind, domain::physical::PhysicalAddressSpace, stage1::PhysicalMemory,
        };
        const BASE: u64 = 0x1000;
        const ALIAS: u64 = 0x3000;
        const REGION_BYTES: u64 = 64;
        const PREFIX: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        const RWX: SourceRamPermissions = SourceRamPermissions {
            readable: true,
            writable: true,
            executable: true,
        };
        fn declaration() -> SourceRamDeclaration {
            SourceRamDeclaration {
                address_space: 701,
                target: TargetCpu::Baseline,
                declared_capacity: vec![
                    PhysicalRamRange {
                        source_pa: BASE,
                        bytes: REGION_BYTES,
                    },
                    PhysicalRamRange {
                        source_pa: ALIAS,
                        bytes: REGION_BYTES,
                    },
                ],
                initialized: Vec::new(),
            }
        }
        fn region() -> InitializedRamRegion {
            InitializedRamRegion {
                range: PhysicalRamRange {
                    source_pa: BASE,
                    bytes: REGION_BYTES,
                },
                file_prefix: PREFIX.to_vec(),
                file_sha256: crate::sha256(&PREFIX),
                permissions: RWX,
            }
        }
        fn config() -> SourceRamSystemConfig {
            SourceRamSystemConfig {
                reservation_granule_bytes: 16,
                reservation_stripe_count: 8,
            }
        }
        fn materialize() -> MaterializedSourceRam {
            materialize_source_ram_regions(declaration(), Vec::new(), vec![region()], config())
                .unwrap()
        }
        #[test]
        fn full_region_cold_contents_keep_original_file_identity_and_absent_capacity() {
            let materialized = materialize();
            let view = materialized.test_view(BASE).unwrap();
            assert_eq!(view.bytes(), REGION_BYTES as usize);
            assert!(view.resolve(BASE + 60, 4, AccessKind::Execute).is_ok());
            assert!(view.resolve(BASE + 64, 1, AccessKind::Read).is_err());
            let (binding, immutable) = materialized.into_parts();
            assert!(immutable.is_empty());
            let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
            assert_eq!(
                physical.read_descriptor(BASE).unwrap(),
                u64::from_le_bytes(PREFIX)
            );
            assert_eq!(physical.read_descriptor(BASE + 8).unwrap(), 0);
            assert_eq!(physical.read_descriptor(BASE + 56).unwrap(), 0);
            assert!(physical.read_descriptor(BASE + 64).is_err());
            assert!(physical.read_descriptor(ALIAS).is_err()); // descriptive capacity is absent
            let layout = &physical.layout().initialized[0];
            assert_eq!(layout.file_prefix, Some((8, crate::sha256(&PREFIX))));
            let mut full = vec![0; REGION_BYTES as usize];
            full[..8].copy_from_slice(&PREFIX);
            assert_eq!(layout.source_sha256, crate::sha256(&full));
            // SAFETY: intentionally rejected writable backing, no rights are changed.
            assert!(unsafe { ImmutableCodeBacking::adopt(Arc::clone(view.backing())) }.is_err());
        }
        #[test]
        fn invalid_regions_refuse_instead_of_granting_capacity_or_immutable_authority() {
            for kind in 0..5 {
                let mut input = region();
                match kind {
                    0 => input.range.bytes = 7,
                    1 => input.file_prefix.clear(),
                    2 => input.file_sha256 = "wrong".into(),
                    3 => input.range.source_pa = u64::MAX,
                    4 => input.range.source_pa = BASE + REGION_BYTES,
                    _ => unreachable!(),
                }
                assert!(
                    materialize_source_ram_regions(
                        declaration(),
                        Vec::new(),
                        vec![input],
                        config()
                    )
                    .is_err()
                );
            }
            assert!(
                materialize_source_ram_regions(
                    declaration(),
                    Vec::new(),
                    vec![region(), region()],
                    config()
                )
                .is_err()
            );
            let mut legacy = declaration();
            legacy.initialized.push(OwnedRamExtent {
                source_pa: BASE,
                bytes: PREFIX.to_vec(),
                permissions: RWX,
            });
            assert!(materialize_source_ram_with_zeroed(legacy, Vec::new(), config()).is_err());
        }
        #[test]
        fn warm_prefix_reload_preserves_tail_and_refuses_active_outer() {
            let materialized = materialize();
            let view = materialized.test_view(BASE).unwrap();
            let (binding, _) = materialized.into_parts();
            let mut physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
            {
                let _service = physical.domain().service_loan().unwrap();
                // SAFETY: the original storage and system, a quiescent service and
                // private staging.
                unsafe {
                    physical.memory_system().publish(
                        view.backing(),
                        view.backing_offset(),
                        &[0xab; 16],
                    )
                }
                .unwrap();
            }
            let generation = view.backing().instruction_generation();
            let outer = physical.initial_source_execution_loan().unwrap();
            assert!(physical.reload_original_region_prefixes().is_err());
            assert_eq!(view.backing().instruction_generation(), generation);
            drop(outer);
            let reset = physical.reload_original_region_prefixes().unwrap();
            assert_eq!(
                (
                    reset.generation,
                    reset.completed_bytes,
                    reset.completed_regions
                ),
                (2, 8, 1)
            );
            assert_eq!(
                physical.read_descriptor(BASE).unwrap(),
                u64::from_le_bytes(PREFIX)
            );
            assert_eq!(
                physical.read_descriptor(BASE + 8).unwrap(),
                u64::from_le_bytes([0xab; 8])
            );
            assert!(
                !view
                    .backing()
                    .instruction_generation_current(generation.unwrap())
            );
        }
        #[test]
        fn generation_exhaustion_precedes_byte_effect_and_unknown_attempt_fails_closed() {
            let materialized = materialize();
            let view = materialized.test_view(BASE).unwrap();
            let (binding, _) = materialized.into_parts();
            let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
            view.backing().exhaust_instruction_generation_for_test();
            let _service = physical.domain().service_loan().unwrap();
            // SAFETY: a valid owned publisher; the rejection happens before any target
            // byte changes.
            let error = unsafe {
                physical
                    .memory_system()
                    .publish(view.backing(), view.backing_offset(), &[9; 8])
            }
            .unwrap_err();
            assert_eq!(error.completed, 0);
            drop(_service);
            assert_eq!(
                physical.read_descriptor(BASE).unwrap(),
                u64::from_le_bytes(PREFIX)
            );
            let materialized = materialize();
            let view = materialized.test_view(BASE).unwrap();
            let (binding, _) = materialized.into_parts();
            let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
            let mut attempt = physical
                .memory_system()
                .prepare_source_write(view.backing(), view.backing_offset(), 8)
                .unwrap();
            attempt.attempting();
            drop(attempt); // injected unknown host-effect outcome, never a false success
            assert!(physical.check_fetch_execution().is_err());
        }

        #[test]
        fn full_file_configuration_reset_and_partial_firmware_reset_share_original_owner() {
            const CONFIG: u64 = 0x400000;
            const CONFIG_BYTES: usize = 0x10000;
            let mut template = vec![0; CONFIG_BYTES];
            template[..8].copy_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2]);
            template[CONFIG_BYTES - 8..].copy_from_slice(&[0x5a; 8]);
            let mut declared = declaration();
            declared.declared_capacity.push(PhysicalRamRange {
                source_pa: CONFIG,
                bytes: CONFIG_BYTES as u64,
            });
            let config_region = InitializedRamRegion {
                range: PhysicalRamRange {
                    source_pa: CONFIG,
                    bytes: CONFIG_BYTES as u64,
                },
                file_prefix: template.clone(),
                file_sha256: crate::sha256(&template),
                permissions: RWX,
            };
            let materialized = materialize_source_ram_regions(
                declared,
                Vec::new(),
                vec![region(), config_region],
                config(),
            )
            .unwrap();
            let firmware = materialized.test_view(BASE).unwrap();
            let configuration = materialized.test_view(CONFIG).unwrap();
            assert!(!Arc::ptr_eq(firmware.backing(), configuration.backing()));
            let (binding, _) = materialized.into_parts();
            let mut physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
            {
                let _service = physical.domain().service_loan().unwrap();
                // SAFETY: both original backings belong to this System, and original
                // quiescent service excludes execution; all staging is private.
                unsafe {
                    physical
                        .memory_system()
                        .publish(firmware.backing(), firmware.backing_offset(), &[0xab; 16])
                        .unwrap();
                    physical
                        .memory_system()
                        .publish(
                            configuration.backing(),
                            configuration.backing_offset() + 0x3ac,
                            &[0xcd; 4],
                        )
                        .unwrap();
                    physical
                        .memory_system()
                        .publish(
                            configuration.backing(),
                            configuration.backing_offset() + CONFIG_BYTES - 8,
                            &[0xef; 8],
                        )
                        .unwrap();
                }
            }
            let firmware_generation = firmware.backing().instruction_generation();
            let configuration_generation = configuration.backing().instruction_generation();
            let outer = physical.initial_source_execution_loan().unwrap();
            assert!(physical.reload_original_region_prefixes().is_err());
            assert_eq!(
                firmware.backing().instruction_generation(),
                firmware_generation
            );
            assert_eq!(
                configuration.backing().instruction_generation(),
                configuration_generation
            );
            drop(outer);
            let reset = physical.reload_original_region_prefixes().unwrap();
            assert_eq!(
                (reset.completed_bytes, reset.completed_regions),
                (8 + CONFIG_BYTES, 2)
            );
            assert_eq!(
                physical.read_descriptor(BASE).unwrap(),
                u64::from_le_bytes(PREFIX)
            );
            assert_eq!(
                physical.read_descriptor(BASE + 8).unwrap(),
                u64::from_le_bytes([0xab; 8])
            );
            for offset in (0..CONFIG_BYTES).step_by(8) {
                assert_eq!(
                    physical.read_descriptor(CONFIG + offset as u64).unwrap(),
                    u64::from_le_bytes(template[offset..offset + 8].try_into().unwrap())
                );
            }
            assert!(
                !firmware
                    .backing()
                    .instruction_generation_current(firmware_generation.unwrap())
            );
            assert!(
                !configuration
                    .backing()
                    .instruction_generation_current(configuration_generation.unwrap())
            );
            // This is a quiescent RAM reload; it grants no CPU reset or SMP authority.
        }
    }
    #[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
    mod zeroed {
        use super::*;
        use crate::memory::{domain::physical::PhysicalAddressSpace, stage1::PhysicalMemory};

        const CODE_PA: u64 = 0x1000;
        const RAM_PA: u64 = 0x2000;
        const RAM_BYTES: u64 = 24;
        const ORIGINAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        fn declaration() -> SourceRamDeclaration {
            SourceRamDeclaration {
                address_space: 51,
                target: TargetCpu::Baseline,
                declared_capacity: vec![PhysicalRamRange {
                    source_pa: CODE_PA,
                    bytes: MAX_IMAGE_MEMORY_BYTES + 0x4000,
                }],
                initialized: vec![OwnedRamExtent {
                    source_pa: CODE_PA,
                    bytes: ORIGINAL.to_vec(),
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: false,
                        executable: true,
                    },
                }],
            }
        }

        fn config() -> SourceRamSystemConfig {
            SourceRamSystemConfig {
                reservation_granule_bytes: 16,
                reservation_stripe_count: 8,
            }
        }

        fn zeroed(source_pa: u64, bytes: u64) -> ZeroedRamExtent {
            ZeroedRamExtent {
                source_pa,
                bytes,
                permissions: SourceRamPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                },
            }
        }

        #[test]
        fn explicit_zeroed_ram_preserves_original_code_and_unassigned_capacity_holes() {
            let materialized = materialize_source_ram_with_zeroed(
                declaration(),
                vec![zeroed(RAM_PA, RAM_BYTES)],
                config(),
            )
            .unwrap();
            let code = materialized.test_view(CODE_PA).unwrap();
            let ram = materialized.test_view(RAM_PA).unwrap();
            assert!(!code.permissions().writable);
            assert!(code.permissions().executable);
            assert!(ram.permissions().readable && ram.permissions().writable);
            assert!(!ram.permissions().executable);
            let (binding, original_sources) = materialized.into_parts();
            assert_eq!(original_sources.len(), 1);
            let layout = binding.layout();
            assert_eq!(layout.initialized.len(), 2);
            assert!(!layout.initialized[0].zero_initialized);
            assert_eq!(
                layout.initialized[0].source_sha256,
                crate::sha256(&ORIGINAL)
            );
            assert!(layout.initialized[1].zero_initialized);
            assert_eq!(
                layout.initialized[1].source_sha256,
                crate::sha256(&[0; RAM_BYTES as usize])
            );
            let physical = PhysicalAddressSpace::from_materialized(binding).unwrap();
            assert_eq!(
                physical.read_descriptor(CODE_PA).unwrap(),
                u64::from_le_bytes(ORIGINAL)
            );
            for offset in [0, 8, 16] {
                assert_eq!(physical.read_descriptor(RAM_PA + offset).unwrap(), 0);
            }
            assert!(physical.read_descriptor(CODE_PA + 8).is_err());
            assert!(physical.read_descriptor(RAM_PA + RAM_BYTES).is_err());
            assert!(physical.read_descriptor(0x1800).is_err());
        }

        #[test]
        fn mixed_zeroed_ranges_reject_invalid_declarations_before_materialization() {
            for extent in [
                zeroed(CODE_PA + 4, 8),
                zeroed(RAM_PA, 0),
                zeroed(u64::MAX - 7, 16),
                zeroed(RAM_PA, MAX_IMAGE_MEMORY_BYTES),
                ZeroedRamExtent {
                    permissions: SourceRamPermissions {
                        readable: true,
                        writable: false,
                        executable: true,
                    },
                    ..zeroed(RAM_PA, 8)
                },
                ZeroedRamExtent {
                    permissions: SourceRamPermissions {
                        readable: false,
                        writable: true,
                        executable: false,
                    },
                    ..zeroed(RAM_PA, 8)
                },
            ] {
                assert!(
                    materialize_source_ram_with_zeroed(declaration(), vec![extent], config())
                        .is_err()
                );
            }
            assert!(
                materialize_source_ram_with_zeroed(
                    declaration(),
                    vec![zeroed(RAM_PA, 16), zeroed(RAM_PA + 8, 16)],
                    config(),
                )
                .is_err()
            );
        }
    }
}
