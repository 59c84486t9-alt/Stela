//! Configuration access under the activated standalone table owner.
//! The one native Permission keeps real firmware/root reservations. Captured
//! MCFG observations alone cannot construct this Source.
#[cfg(feature = "diagnostics")]
mod hpet;
mod inventory;
mod platform;
mod prepare;
use super::{ActivatedTables, PAGE, RootError};
use crate::Refusal;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt,
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};
#[cfg(feature = "diagnostics")]
pub(crate) use hpet::Hpet;
pub(crate) use prepare::Prepared;
use stela_drivers::bus::{
    mmio::owned::{
        self, AddressSpace, Authority, CacheAttribute, PhysicalSpan, Protection, Resource,
        ResourceBacking, ResourceKind,
    },
    pci::{
        Address, ConfigError, EcamWindow, EnumerationError,
        assignment::{self, Assignment, OpaqueUse, PhysicalAssignment, Retention, UseKind},
    },
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
    Tables(Refusal),
    Config(ConfigError),
    Discovery(EnumerationError),
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
            Self::Tables(error) => write!(f, "{error}"),
            Self::Config(error) => write!(f, "owned PCI configuration: {error:?}"),
            Self::Discovery(error) => write!(f, "owned PCI topology: {error:?}"),
            Self::NotReady(address) => {
                write!(f, "PCI {address} returned CRS; no qualified retry clock")
            }
        }
    }
}
struct Bus {
    window: EcamWindow,
    resource: Resource,
    _assignment: Assignment<RegisterReservation>,
}
pub(crate) struct Source {
    platform: Arc<platform::Platform>,
    authority: Authority,
    buses: Vec<Bus>,
    #[cfg(feature = "diagnostics")]
    hpet_assignment: core::cell::RefCell<Option<Assignment<RegisterReservation>>>,
    #[cfg(feature = "diagnostics")]
    issued_config: core::cell::RefCell<Vec<Address>>,
    _local: PhantomData<*mut ()>,
}
struct RegisterReservation {
    platform: Arc<platform::Platform>,
    _span: PhysicalSpan,
}

// SAFETY: the exclusive post-EBS source owns the validated ECAM windows,
// separately handed off HPET page and verified diagnostic register spans. The original ActivatedTables and
// firmware exclusions remain held without a mapping or registry backedge.
unsafe impl PhysicalAssignment for RegisterReservation {
    fn parent(&self) -> Option<&assignment::Parent> {
        None
    }

    fn check_control(&self) -> Result<(), assignment::Error> {
        self.platform
            .check()
            .map_err(|_| assignment::Error::Context)
    }
}

struct RegisterBacking {
    platform: Arc<platform::Platform>,
    span: PhysicalSpan,
    retention: Retention<RegisterReservation>,
}

// SAFETY: the source gives each checked span its original retained assignment
// and keeps it across every live or quarantined mapping.
unsafe impl ResourceBacking for RegisterBacking {
    fn physical_span(&self) -> PhysicalSpan {
        self.span
    }

    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }

    fn begin_mapping(&self) -> Result<OpaqueUse, owned::Error> {
        self.platform
            .check()
            .map_err(|_| owned::Error::Unavailable)?;
        self.retention
            .begin_use(UseKind::Mapping)
            .map(|usage| usage.erase())
            .map_err(owned::Error::Assignment)
    }
}
impl Source {
    #[cfg(feature = "diagnostics")]
    fn exclude_ecam(&self, span: PhysicalSpan) -> Result<(), Error> {
        if self.buses.iter().any(|bus| {
            let ecam = bus.resource.physical_span();
            ecam.start() < span.end() && span.start() < ecam.end()
        }) {
            return Err(Error::ResourceConflict);
        }
        Ok(())
    }

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
            let assignment = Assignment::from_owned(RegisterReservation {
                platform: platform.clone(),
                _span: span,
            });
            let resource = Resource::new(Box::new(RegisterBacking {
                platform: platform.clone(),
                span,
                retention: assignment.retain(),
            }));
            buses.push(Bus {
                window,
                resource,
                _assignment: assignment,
            });
        }
        Ok(Self {
            platform,
            authority,
            buses,
            #[cfg(feature = "diagnostics")]
            hpet_assignment: core::cell::RefCell::new(None),
            #[cfg(feature = "diagnostics")]
            issued_config: core::cell::RefCell::new(Vec::new()),
            _local: PhantomData,
        })
    }
    fn config_mapping(
        &self,
        address: Address,
        protection: Protection,
    ) -> Result<(EcamWindow, owned::Mapping), Error> {
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
                protection,
            )
            .map_err(Error::Mapping)?;
        Ok((bus.window, mapping))
    }
    pub(crate) fn windows(&self) -> impl Iterator<Item = EcamWindow> + '_ {
        self.buses.iter().map(|bus| bus.window)
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
}
