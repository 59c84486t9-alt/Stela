//! Fresh loader-owned RAM with explicit source-physical placements.
//! Capacity is descriptive; only explicitly initialized/zeroed extents acquire backing.
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

#[path = "source_ram/region.rs"]
mod region;
pub use region::InitializedRamRegion;

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

/// Explicit initial zero contents, never an implicit assignment of capacity.
/// Executable source must supply original bytes through `OwnedRamExtent`.
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
            // Fresh anonymous storage supplies all remaining zeros. This is
            // explicit Zeroed metadata, not a sentinel in an original image.
            RamInitial::Zeroed(_) => &[0],
        }
    }

    fn zero_initialized(&self) -> bool {
        matches!(&self.initial, RamInitial::Zeroed(_))
    }

    fn initial_hash(&self, storage: &NativeStorage, leading: usize) -> String {
        match &self.initial {
            RamInitial::Bytes(bytes) => stela_core::sha256(bytes),
            RamInitial::Zeroed(bytes)
            | RamInitial::FilePrefix {
                mapped_bytes: bytes,
                ..
            } => {
                // SAFETY: this sole factory still owns fresh anonymous zero
                // storage before any domain/PE or writer is published. The
                // validated logical range is readable and fits this retained
                // allocation. The temporary reference cannot escape hashing.
                let initial = unsafe {
                    core::slice::from_raw_parts(
                        storage.primary_base().as_ptr().add(leading),
                        *bytes,
                    )
                };
                stela_core::sha256(initial)
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

/// Only the materialization factory can create this genuine physical binding.
/// No existing Domain/System, numeric identity or caller token is accepted.
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
    /// Actual fixture-created mapping handle, for ownership/retirement checks.
    /// No writable reference or new mapping/source authority is returned.
    #[cfg(test)]
    pub(crate) fn test_view(&self, source_pa: u64) -> Option<Arc<MemoryView>> {
        self.binding
            .views
            .iter()
            .find(|view| view.guest_base() == source_pa)
            .map(Arc::clone)
    }

    /// Supply these original resources once to the fresh physical/source owner.
    /// The immutable code owners retain the same backings as the physical views.
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

/// Create the sole machine/domain from initialized owned bytes, before any PE.
/// Host addresses are OS-selected and never interpreted as source PAs.
#[cfg(test)]
pub(crate) fn materialize_source_ram(
    declaration: SourceRamDeclaration,
    config: SourceRamSystemConfig,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    materialize_source_ram_with_zeroed(declaration, Vec::new(), config)
}

/// Extend the same sole materialization with explicit zero-initialized RAM.
/// Validate the complete mixed set before allocating any native storage.
pub(crate) fn materialize_source_ram_with_zeroed(
    declaration: SourceRamDeclaration,
    zeroed: Vec<ZeroedRamExtent>,
    config: SourceRamSystemConfig,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    materialize_source_ram_impl(declaration, zeroed, Vec::new(), config)
}

/// Materialize complete explicitly initialized regions through the original
/// factory. The existing byte/zero extent APIs retain their stricter contracts.
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
    // Every fallible declaration/budget check precedes actual RAM allocation.
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
        // SAFETY: this factory owns anonymous private storage and all rights.
        // Initialization is complete, host rights final, no byte references or
        // aliases escape, and the sole resulting domain owns every later access.
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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod zeroed_tests {
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
            stela_core::sha256(&ORIGINAL)
        );
        assert!(layout.initialized[1].zero_initialized);
        assert_eq!(
            layout.initialized[1].source_sha256,
            stela_core::sha256(&[0; RAM_BYTES as usize])
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
                materialize_source_ram_with_zeroed(declaration(), vec![extent], config()).is_err()
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

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
#[path = "source_ram/region_tests.rs"]
mod region_tests;
