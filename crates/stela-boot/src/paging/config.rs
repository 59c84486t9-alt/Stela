//! Configuration access under the activated standalone table owner.
//! The one native Permission keeps real firmware/root reservations. Captured
//! MCFG observations alone cannot construct this Source.
mod platform;
mod prepare;
use super::{ActivatedTables, PAGE, RootError};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt,
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};
pub(crate) use prepare::Prepared;
use stela_drivers::bus::{
    mmio::owned::{
        self, AddressSpace, Authority, CacheAttribute, PhysicalSpan, Protection, Resource,
        ResourceBacking, ResourceKind,
    },
    pci::{Address, EcamWindow, owned::OwnedConfig},
};

// A separate canonical high-half window; builder refuses any overlap.
const APERTURE: usize = 0xffff_9000_0000_0000;
const LEAVES: usize = 16;
const SLOTS: usize = LEAVES * 512;
static IRQ_DEPTH: AtomicU32 = AtomicU32::new(0);
/// HostCheck ISR entry, not inferred from an IF bit.
pub(crate) struct Interrupt;
impl Interrupt {
    pub(crate) fn enter() -> Self {
        IRQ_DEPTH.fetch_add(1, Ordering::AcqRel);
        Self
    }
}
impl Drop for Interrupt {
    fn drop(&mut self) {
        IRQ_DEPTH.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    ResourceInventory,
    ResourceConflict,
    Allocation,
    Firmware(uefi::Status),
    Mapping(owned::Error),
    Root(RootError),
    Tables(&'static str),
    Config(stela_drivers::bus::pci::owned::ConfigError),
    NotReady(Address),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceInventory => f.write_str("actual PCI resource inventory is incomplete"),
            Self::ResourceConflict => {
                f.write_str("actual PCI resources overlap retained memory or each other")
            }
            Self::Allocation => f.write_str("PCI owner allocation failed"),
            Self::Firmware(status) => write!(f, "PCI firmware inventory: {status:?}"),
            Self::Mapping(error) => write!(f, "owned PCI mapping: {error:?}"),
            Self::Root(error) => write!(f, "owned PCI root: {error}"),
            Self::Tables(error) => f.write_str(error),
            Self::Config(error) => write!(f, "owned PCI configuration: {error:?}"),
            Self::NotReady(address) => {
                write!(f, "PCI {address} returned CRS; no qualified retry clock")
            }
        }
    }
}
struct Bus {
    window: EcamWindow,
    resource: Resource,
}
pub(crate) struct Source {
    platform: Arc<platform::Platform>,
    authority: Authority,
    buses: Vec<Bus>,
    _local: PhantomData<*mut ()>,
}
struct Backing {
    platform: Arc<platform::Platform>,
    span: PhysicalSpan,
}
// SAFETY: only Source's post-EBS exclusive bus handoff mints these
// complete ECAM reservations. Original tables/resource exclusions stay pinned;
// no other config/reset writer is published for this standalone boot path.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
impl Source {
    /// # Safety
    /// Standalone/HostCheck post-EBS BSP owns all captured PCI roots,
    /// excluding firmware/SMM configuration/reset and every competing accessor.
    /// No AP, guest, root publisher or outside cache writer runs on this path.
    /// Keep the original ActivatedTables and this Source through every consumer.
    pub(crate) unsafe fn activate(
        root: &ActivatedTables,
        prepared: Prepared,
    ) -> Result<Self, Error> {
        root.check_current().map_err(Error::Root)?;
        let windows = prepared.windows.clone();
        let platform = Arc::new(platform::Platform::new(root.root.clone(), prepared)?);
        let aliases = platform.aliases()?;
        // SAFETY: single root and complete checked alias walk;
        // this mutually exclusive boot route installs the sole global registry.
        let authority = unsafe { Authority::activate(platform.clone(), platform.space, aliases) }
            .map_err(Error::Mapping)?;
        let mut buses = Vec::new();
        buses
            .try_reserve(windows.len())
            .map_err(|_| Error::Allocation)?;
        for window in windows {
            let range = window.range();
            let span =
                PhysicalSpan::new(range.start, range.end - range.start).map_err(Error::Mapping)?;
            let resource = Resource::new(Box::new(Backing {
                platform: platform.clone(),
                span,
            }));
            authority
                .register_resource(resource.clone())
                .map_err(Error::Mapping)?;
            buses.push(Bus { window, resource });
        }
        Ok(Self {
            platform,
            authority,
            buses,
            _local: PhantomData,
        })
    }
    /// Exact function access, keeping its real mapping until explicit retirement.
    pub(crate) fn config(&self, address: Address) -> Result<OwnedConfig, Error> {
        self.platform.check_bus(address)?;
        let bus = self
            .buses
            .iter()
            .find(|bus| {
                bus.window.segment == address.segment
                    && (bus.window.start_bus..=bus.window.end_bus).contains(&address.bus)
            })
            .ok_or(Error::ResourceInventory)?;
        if address.device >= 32 || address.function >= 8 {
            return Err(Error::ResourceInventory);
        }
        let physical = bus.window.base
            + (u64::from(address.bus) << 20)
            + (u64::from(address.device) << 15)
            + (u64::from(address.function) << 12);
        let start = bus.resource.physical_span().start();
        let offset = usize::try_from(
            physical
                .checked_sub(start)
                .ok_or(Error::ResourceInventory)?,
        )
        .map_err(|_| Error::ResourceInventory)?;
        let mapping = self
            .authority
            .map(
                bus.resource.clone(),
                offset,
                PAGE,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(Error::Mapping)?;
        // SAFETY: unique original bus reservation, current root and exact
        // 4K lease; no raw accessor or second writer is exposed by this Source.
        match unsafe { OwnedConfig::attach(address, bus.window, mapping) } {
            Ok(config) => Ok(config),
            Err((error, mut mapping)) => {
                // No consumer/device effect occurred. Explicitly retire this
                // rejected mapping; failure leaves its real owner quarantined.
                // SAFETY: rejected attachment made no device access and exposed no view.
                let _ = unsafe { mapping.retire() };
                Err(Error::Config(error))
            }
        }
    }
    pub(crate) fn windows(&self) -> impl Iterator<Item = EcamWindow> + '_ {
        self.buses.iter().map(|bus| bus.window)
    }
    /// Read-only bridge/ARI topology through config owners. Even
    /// absent/CRS mappings are returned to the retirement owner.
    pub(crate) fn inventory(
        &self,
        window: &EcamWindow,
    ) -> Result<Vec<stela_drivers::bus::pci::Identity>, Error> {
        use stela_drivers::bus::pci::Function;
        Function::inventory_with(
            window,
            |address| {
                let config = self.config(address)?;
                match Function::try_new(address, config) {
                    Ok(function) => Ok(Some(function)),
                    Err(config) => {
                        let vendor = config.try_read16(0).map_err(Error::Config)?;
                        let mut mapping = config.into_mapping();
                        // SAFETY: read-only inventory exposed no pointer/view and
                        // performed no device/DMA/IRQ action through this config.
                        unsafe { mapping.retire() }.map_err(Error::Mapping)?;
                        if vendor == 0xffff {
                            Ok(None)
                        } else {
                            Err(Error::NotReady(address))
                        }
                    }
                }
            },
            |function| {
                let mut mapping = function.into_config().into_mapping();
                // SAFETY: same exclusively read-only discovery scope above.
                unsafe { mapping.retire() }.map_err(Error::Mapping)
            },
        )
    }
    pub(crate) fn verify_retired(&self) -> Result<(), Error> {
        self.platform.verify_empty()?;
        let status = self.authority.status().map_err(Error::Mapping)?;
        if status.installing != 0
            || status.live != 0
            || status.uncertain != 0
            || status.quarantined != 0
        {
            return Err(Error::Mapping(owned::Error::Busy));
        }
        Ok(())
    }
    /// The private permit is minted only by post-EBS fixture binding,
    /// after its requester/controller identity and route were rechecked.
    pub(crate) fn fixture_registers(
        &self,
        permit: &crate::native_dma::diagnostic::RegisterSpan<'_>,
    ) -> Result<owned::Mapping, Error> {
        let range = permit.for_source(self).ok_or(Error::ResourceInventory)?;
        let span =
            PhysicalSpan::new(range.start, range.end - range.start).map_err(Error::Mapping)?;
        self.platform.identity_device(span)?;
        let resource = Resource::new(Box::new(Backing {
            platform: self.platform.clone(),
            span,
        }));
        self.authority
            .register_resource(resource.clone())
            .map_err(Error::Mapping)?;
        self.authority
            .map(
                resource,
                0,
                usize::try_from(span.bytes()).map_err(|_| Error::ResourceInventory)?,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(Error::Mapping)
    }
}
