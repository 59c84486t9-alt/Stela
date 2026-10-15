//! Fresh loader-owned RAM with explicit source-physical placements.
//! Capacity is descriptive; only supplied initialized extents acquire backing.
use super::{
    MAX_IMAGE_MEMORY_BYTES,
    backing::{AccessError, AccessPermissions, MemoryBacking, MemoryView},
    domain::{MappingAttributes, MemoryDomain, MemorySystem, physical::ImmutableCodeBacking},
    host_page_size,
    storage::NativeStorage,
};
use std::sync::Arc;
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

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

pub struct SourceRamDeclaration {
    pub address_space: u64,
    pub target: TargetCpu,
    pub declared_capacity: Vec<PhysicalRamRange>,
    pub initialized: Vec<OwnedRamExtent>,
}

/// Fixture-only alias of one actual initialized extent. It creates no new
/// storage and cannot be used by a production declaration or constructor.
#[cfg(test)]
pub(crate) struct SourceRamTestAlias {
    pub source_pa: u64,
    pub initialized_source_pa: u64,
    pub source_offset: usize,
    pub bytes: usize,
    pub permissions: SourceRamPermissions,
}

pub(crate) struct SourceRamSystemConfig {
    pub reservation_granule_bytes: u64,
    pub reservation_stripe_count: usize,
}

#[derive(Debug)]
pub(crate) enum SourceRamBuildError {
    Declaration(&'static str),
    AllocationLimit,
    Platform(std::io::Error),
    Backing(AccessError),
    Domain(MemoryStatus),
    ImmutableSource(&'static str),
}
impl std::fmt::Display for SourceRamBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
impl std::error::Error for SourceRamBuildError {}

pub(crate) struct InitializedRamLayout {
    pub range: PhysicalRamRange,
    pub permissions: SourceRamPermissions,
    pub source_sha256: String,
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
}

impl SourcePhysicalRamBinding {
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
pub(crate) fn materialize_source_ram(
    declaration: SourceRamDeclaration,
    config: SourceRamSystemConfig,
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    #[cfg(test)]
    {
        materialize_source_ram_impl(declaration, config, &[])
    }
    #[cfg(not(test))]
    {
        materialize_source_ram_impl(declaration, config)
    }
}

/// Existing ownership fixtures may explicitly place real backing aliases before
/// the sole physical domain exists. This API is absent from production builds.
#[cfg(test)]
pub(crate) fn materialize_source_ram_with_test_aliases(
    declaration: SourceRamDeclaration,
    config: SourceRamSystemConfig,
    aliases: &[SourceRamTestAlias],
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    materialize_source_ram_impl(declaration, config, aliases)
}

fn materialize_source_ram_impl(
    mut declaration: SourceRamDeclaration,
    config: SourceRamSystemConfig,
    #[cfg(test)] aliases: &[SourceRamTestAlias],
) -> Result<MaterializedSourceRam, SourceRamBuildError> {
    use SourceRamBuildError as E;
    if declaration.declared_capacity.is_empty()
        || declaration.initialized.is_empty()
        || declaration.declared_capacity.len() > MAX_SOURCE_RAM_EXTENTS
        || declaration.initialized.len() > MAX_SOURCE_RAM_EXTENTS
        || config.reservation_stripe_count == 0
        || config.reservation_stripe_count > MAX_SOURCE_RAM_STRIPES
    {
        return Err(E::Declaration("source RAM extent/stripe bound"));
    }
    if !declaration.target.supported() {
        return Err(E::Domain(MemoryStatus::Unsupported));
    }
    let page =
        host_page_size().map_err(|error| E::Platform(std::io::Error::other(error.to_string())))?;
    if page < size_of::<u64>() {
        return Err(E::Platform(std::io::Error::other(
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
    declaration
        .initialized
        .sort_unstable_by_key(|extent| extent.source_pa);
    let mut recipes = Vec::with_capacity(declaration.initialized.len());
    let mut allocated = 0_usize;
    previous = None;
    // Every fallible declaration/budget check precedes actual RAM allocation.
    for extent in &declaration.initialized {
        let range = PhysicalRamRange {
            source_pa: extent.source_pa,
            bytes: extent.bytes.len() as u64,
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
        if permissions.writable && (!permissions.readable || permissions.executable)
            || !permissions.readable && !permissions.executable
        {
            return Err(E::Declaration("unsupported source RAM permissions"));
        }
        // Preserve PA/host congruence without equating their address spaces.
        let leading = (extent.source_pa & (page as u64 - 1)) as usize;
        let bytes = leading
            .checked_add(extent.bytes.len())
            .and_then(|bytes| bytes.checked_add(page - 1))
            .map(|bytes| bytes & !(page - 1))
            .ok_or(E::AllocationLimit)?;
        allocated = allocated.checked_add(bytes).ok_or(E::AllocationLimit)?;
        if allocated as u64 > MAX_IMAGE_MEMORY_BYTES {
            return Err(E::AllocationLimit);
        }
        recipes.push((leading, bytes));
    }
    #[cfg(test)]
    let alias_recipes = {
        if declaration.initialized.len().saturating_add(aliases.len()) > MAX_SOURCE_RAM_EXTENTS {
            return Err(E::Declaration("source RAM fixture alias bound"));
        }
        let mut occupied: Vec<PhysicalRamRange> = declaration
            .initialized
            .iter()
            .map(|extent| PhysicalRamRange {
                source_pa: extent.source_pa,
                bytes: extent.bytes.len() as u64,
            })
            .collect();
        let mut validated = Vec::with_capacity(aliases.len());
        for alias in aliases {
            let (index, extent) = declaration
                .initialized
                .iter()
                .enumerate()
                .find(|(_, extent)| extent.source_pa == alias.initialized_source_pa)
                .ok_or(E::Declaration(
                    "fixture alias has no initialized source extent",
                ))?;
            let source_end = alias
                .source_offset
                .checked_add(alias.bytes)
                .ok_or(E::Declaration("fixture alias source offset overflow"))?;
            if source_end > extent.bytes.len() {
                return Err(E::Declaration(
                    "fixture alias exceeds initialized source bytes",
                ));
            }
            let range = PhysicalRamRange {
                source_pa: alias.source_pa,
                bytes: alias.bytes as u64,
            };
            let limit = end(range)?;
            if !declaration.declared_capacity.iter().any(|capacity| {
                capacity.source_pa <= range.source_pa
                    && end(*capacity).is_ok_and(|capacity_end| limit <= capacity_end)
            }) {
                return Err(E::Declaration("fixture alias outside declared capacity"));
            }
            if occupied.iter().any(|other| {
                other.source_pa < limit
                    && end(*other).is_ok_and(|other_end| range.source_pa < other_end)
            }) {
                return Err(E::Declaration(
                    "fixture alias overlaps physical source range",
                ));
            }
            let permissions = alias.permissions;
            let maximum = extent.permissions;
            if permissions.readable && !maximum.readable
                || permissions.writable && !maximum.writable
                || permissions.executable && !maximum.executable
                || permissions.writable && (!permissions.readable || permissions.executable)
                || !permissions.readable && !permissions.executable
            {
                return Err(E::Declaration("fixture alias exceeds source permissions"));
            }
            let original_address = extent
                .source_pa
                .checked_add(alias.source_offset as u64)
                .ok_or(E::Declaration("fixture alias source address overflow"))?;
            if alias.source_pa & 7 != original_address & 7 {
                return Err(E::Declaration(
                    "fixture alias loses physical eight-byte alignment",
                ));
            }
            occupied.push(range);
            let backing_offset = recipes[index]
                .0
                .checked_add(alias.source_offset)
                .ok_or(E::Declaration("fixture alias backing offset overflow"))?;
            let source_sha256 = stela_core::sha256(&extent.bytes[alias.source_offset..source_end]);
            validated.push((index, alias, backing_offset, source_sha256));
        }
        validated
    };
    // Never accept an existing coherence owner or infer freshness from Arc counts.
    let system = MemorySystem::new(
        config.reservation_granule_bytes,
        config.reservation_stripe_count,
    )
    .map_err(E::Domain)?;
    let mut views = Vec::with_capacity(declaration.initialized.len());
    let mut immutable_sources = Vec::new();
    let mut layout = Vec::with_capacity(declaration.initialized.len());
    for (extent, (leading, bytes)) in declaration.initialized.into_iter().zip(recipes) {
        let permissions = AccessPermissions {
            readable: extent.permissions.readable,
            writable: extent.permissions.writable,
            executable: extent.permissions.executable,
        };
        let storage = NativeStorage::initialized_ram(
            &extent.bytes,
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
            extent.bytes.len(),
            permissions,
        )
        .map_err(E::Backing)?;
        if permissions.executable {
            // SAFETY: initialized_ram finalized the complete allocation host-RO;
            // this private owner created no writable alias, publisher or Rust
            // byte reference. Its retained storage keeps those rights forever.
            immutable_sources
                .push(unsafe { ImmutableCodeBacking::adopt(backing) }.map_err(E::ImmutableSource)?);
        }
        layout.push(InitializedRamLayout {
            range: PhysicalRamRange {
                source_pa: extent.source_pa,
                bytes: extent.bytes.len() as u64,
            },
            permissions: extent.permissions,
            source_sha256: stela_core::sha256(&extent.bytes),
        });
        views.push(view);
    }
    #[cfg(test)]
    for (index, alias, offset, source_sha256) in alias_recipes {
        let source = &views[index];
        let backing = Arc::clone(source.backing());
        let permissions = AccessPermissions {
            readable: alias.permissions.readable,
            writable: alias.permissions.writable,
            executable: alias.permissions.executable,
        };
        let view = MemoryView::new(backing, alias.source_pa, offset, alias.bytes, permissions)
            .map_err(E::Backing)?;
        // A real alias retains identical original storage; no copied-byte alias
        // or host mapping is created. Immutable source backing stays host-RO.
        layout.push(InitializedRamLayout {
            range: PhysicalRamRange {
                source_pa: alias.source_pa,
                bytes: alias.bytes as u64,
            },
            permissions: alias.permissions,
            source_sha256,
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
            .finish()
    }
}
