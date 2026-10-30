//! Native resource services the mount supplies to [`probe`](super::probe_with_provider)
//! for drivers that attach through owned configuration space, owned register
//! mappings, per-requester DMA domains and the ACPI namespace.
use crate::bus::irq::IrqController;
use crate::bus::{
    dma::{mapping::DmaDomain, memory::PageSource},
    mmio::owned::{self, Mapping},
    pci::{
        Address, Bar, Function,
        owned::OwnedConfig,
        requester::{ClaimError, RequesterBinding, StoppedRequester},
    },
};
use alloc::sync::Arc;
use core::fmt;

/// Why a service refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// The mount has no such service, such as no ACPI namespace.
    Unavailable,
    /// The mount refuses it, such as a requester its IOMMU cannot isolate.
    Refused(&'static str),
    Mapping(owned::Error),
    Claim(ClaimError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("native resource service unavailable"),
            Self::Refused(why) => f.write_str(why),
            Self::Mapping(error) => write!(f, "native mapping: {error:?}"),
            Self::Claim(error) => write!(f, "stopped requester: {error:?}"),
        }
    }
}

/// The mount's native owners: configuration and BAR mappings from its native
/// MMIO platform, requester DMA domains from its IOMMU or the passthrough
/// domain ([`DomainKind`](crate::bus::dma::mapping::DomainKind)), kept DMA
/// pages and the ACPI namespace.
///
/// # Safety
/// Implementations transfer ownership: each claimed requester is the unique
/// owner of its function's configuration space, with its engines, DMA and
/// interrupts stopped and drained, as [`StoppedRequester::from_stopped_pci`]
/// requires. Each bridge is the unique owner of its configuration space,
/// left forwarding. Each mapping covers exactly the requested BAR, uncached and
/// read/write, with no other accessor. Each domain meets the [`DmaDomain`]
/// contract for its kind. Every
/// returned owner stays valid in every access context `probe`'s drivers use.
/// A mount that supplies the ACPI namespace also grants `probe` port I/O to
/// the i8042 at ports 0x60 and 0x64 when the namespace lists one, with IRQ1
/// and IRQ12 masked at every interrupt controller and no other user of
/// those ports.
pub unsafe trait NativeServices {
    /// Claim the function at `address` as a stopped requester through an owned
    /// mapping of its configuration space.
    fn claim_stopped(&self, address: Address) -> Result<StoppedRequester, ServiceError>;

    /// The PCI-to-PCI bridge at `address` through an owned mapping of its
    /// configuration space, left forwarding, for a driver that sets its
    /// link's upstream end as Linux's ASPM core does through `bus->self`.
    fn bridge(&self, address: Address) -> Result<Function<OwnedConfig>, ServiceError>;

    /// Map memory BAR `bar` of the function at `address` for its driver.
    fn map_bar(&self, address: Address, bar: Bar) -> Result<Mapping, ServiceError>;

    /// The mount's reservation of memory BAR `bar` of the function at
    /// `address`, for drivers that map parts of it or route child resources
    /// inside it, as Intel VMD does.
    fn bar_resource(&self, address: Address, bar: Bar) -> Result<owned::Resource, ServiceError>;

    /// The mapping permission that issues [`Self::map_bar`]'s mappings.
    fn authority(&self) -> Result<owned::Authority, ServiceError>;

    /// The DMA domain for the requester `binding` names. The domain keeps the
    /// binding, and with it the configuration epoch it keeps.
    fn domain(&self, binding: RequesterBinding) -> Result<Arc<dyn DmaDomain>, ServiceError>;

    /// Pages for driver DMA rings and buffers, for the rest of the boot.
    fn pages(&self) -> &'static dyn PageSource;

    /// An owned cryptographic source for authentication nonces. The handle
    /// outlives probe; a platform without trusted entropy reports unavailable.
    fn entropy(&self) -> Result<Arc<dyn crate::entropy::Entropy>, ServiceError> {
        Err(ServiceError::Unavailable)
    }

    /// The interrupt controller that routes MSIs to the probing CPU, for
    /// drivers that need a delivered interrupt, such as Intel's ISH.
    fn interrupts(&self) -> Result<&'static dyn IrqController, ServiceError>;

    /// The first EC installed and connected during boot's staged ACPI
    /// initialization. Probe keeps the receipt instead of installing a
    /// second operation-region handler.
    #[cfg(feature = "native-acpi")]
    fn embedded_controller(
        &self,
    ) -> Result<Option<crate::platform::ec::capability::Installed<'static>>, ServiceError> {
        Ok(None)
    }

    /// The ACPI namespace, for devices described there rather than on PCI:
    /// i8042 keyboards and mice, embedded controllers, I²C-HID devices and
    /// batteries ([`platform::acpi::Session::devices`](crate::platform::acpi::Session::devices)
    /// matches `_HID`/`_CID` and filters by `_STA`; `_CRS` decodes through
    /// [`platform::acpi::resources`](crate::platform::acpi::resources)).
    ///
    /// The session is the mount's one ACPICA instance, alive for the
    /// program. Its provider serves the ports, decode, power and global lock
    /// of the first embedded controller the ECDT or namespace names, and no
    /// other owner reaches that controller, as
    /// [`Binding::install`](crate::platform::ec::binding::Binding::install)
    /// requires.
    #[cfg(feature = "native-acpi")]
    fn acpi(&self) -> Option<&'static crate::platform::acpi::Session>;

    /// Reserve memory resource `ordinal` of `device`'s `_CRS` from the
    /// mount's native broker, for a controller the namespace describes, as
    /// [`MemoryBroker::reserve`](crate::platform::acpi::resources::MemoryBroker::reserve)
    /// reserves it.
    #[cfg(feature = "native-acpi")]
    fn acpi_memory(
        &self,
        device: &crate::platform::acpi::resources::DeviceResources<'_>,
        ordinal: usize,
    ) -> Result<owned::Resource, ServiceError>;
}

/// ACPI hardware IDs of the classes attached through [`NativeServices`].
pub mod ids {
    /// i8042 keyboards: IBM Enhanced and the compatible IDs Linux's
    /// `i8042_pnp_kbd_devids` lists.
    pub const I8042_KEYBOARD: &[&str] = &[
        "PNP0300", "PNP0301", "PNP0302", "PNP0303", "PNP0304", "PNP0305", "PNP0306", "PNP0309",
        "PNP030A", "PNP030B", "PNP0320", "PNP0343", "PNP0344", "PNP0345", "CPQA0D7",
    ];
    /// i8042 auxiliary (PS/2 mouse) ports, as Linux's `i8042_pnp_aux_devids`.
    pub const I8042_MOUSE: &[&str] = &[
        "AUI0200", "FJC6000", "FJC6001", "PNP0F03", "PNP0F0B", "PNP0F0E", "PNP0F12", "PNP0F13",
        "PNP0F19", "PNP0F1C", "SYN0801",
    ];
    /// ACPI embedded controller.
    pub const EMBEDDED_CONTROLLER: &[&str] = &["PNP0C09"];
    /// HID over I²C, by its `_CID`.
    pub const I2C_HID: &[&str] = &["PNP0C50", "ACPI0C50"];
    /// Control-method battery.
    pub const BATTERY: &[&str] = &["PNP0C0A"];
    /// Control-method lid.
    pub const LID: &[&str] = &["PNP0C0D"];
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bus::{
        dma::memory::{MemoryError, PinnedPages},
        mmio::owned::CacheAttribute,
    };
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// Services that record every request and refuse them all, as a mount
    /// without native owners would.
    #[derive(Default)]
    pub(crate) struct Refusing {
        pub(crate) requests: RefCell<Vec<Address>>,
    }

    struct NoPages;
    impl PageSource for NoPages {
        fn allocate(
            &self,
            _: usize,
            _: usize,
            _: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            Err(MemoryError::Unavailable)
        }
    }

    // SAFETY: every request is refused; no owner is transferred.
    unsafe impl NativeServices for Refusing {
        fn claim_stopped(&self, address: Address) -> Result<StoppedRequester, ServiceError> {
            self.requests.borrow_mut().push(address);
            Err(ServiceError::Unavailable)
        }
        fn bridge(&self, address: Address) -> Result<Function<OwnedConfig>, ServiceError> {
            self.requests.borrow_mut().push(address);
            Err(ServiceError::Unavailable)
        }
        fn map_bar(&self, address: Address, _: Bar) -> Result<Mapping, ServiceError> {
            self.requests.borrow_mut().push(address);
            Err(ServiceError::Unavailable)
        }
        fn bar_resource(&self, address: Address, _: Bar) -> Result<owned::Resource, ServiceError> {
            self.requests.borrow_mut().push(address);
            Err(ServiceError::Unavailable)
        }
        fn authority(&self) -> Result<owned::Authority, ServiceError> {
            Err(ServiceError::Unavailable)
        }
        fn domain(&self, _: RequesterBinding) -> Result<Arc<dyn DmaDomain>, ServiceError> {
            Err(ServiceError::Refused("requester shares an IOMMU group"))
        }
        fn interrupts(&self) -> Result<&'static dyn IrqController, ServiceError> {
            Err(ServiceError::Unavailable)
        }
        fn pages(&self) -> &'static dyn PageSource {
            &NoPages
        }
        #[cfg(feature = "native-acpi")]
        fn acpi_memory(
            &self,
            _: &crate::platform::acpi::resources::DeviceResources<'_>,
            _: usize,
        ) -> Result<owned::Resource, ServiceError> {
            Err(ServiceError::Unavailable)
        }
        #[cfg(feature = "native-acpi")]
        fn acpi(&self) -> Option<&'static crate::platform::acpi::Session> {
            None
        }
    }

    #[test]
    fn refusals_name_their_reason() {
        let services = Refusing::default();
        let address = Address {
            segment: 0,
            bus: 1,
            device: 0,
            function: 0,
        };
        assert_eq!(
            services.claim_stopped(address).err(),
            Some(ServiceError::Unavailable)
        );
        assert_eq!(*services.requests.borrow(), [address]);
        assert!(matches!(services.entropy(), Err(ServiceError::Unavailable)));

        assert_eq!(
            alloc::format!(
                "{}",
                ServiceError::Refused("requester shares an IOMMU group")
            ),
            "requester shares an IOMMU group"
        );
    }

    #[test]
    fn hardware_ids_are_unique_and_well_formed() {
        let all: Vec<&str> = [
            ids::I8042_KEYBOARD,
            ids::I8042_MOUSE,
            ids::EMBEDDED_CONTROLLER,
            ids::I2C_HID,
            ids::BATTERY,
            ids::LID,
        ]
        .concat();
        for (index, id) in all.iter().enumerate() {
            assert!(matches!(id.len(), 7 | 8), "{id}");
            assert!(
                id.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            );
            assert!(!all[index + 1..].contains(id), "{id}");
        }
    }
}
