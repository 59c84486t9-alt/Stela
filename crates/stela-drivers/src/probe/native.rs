//! PCI functions whose drivers attach through [`NativeServices`]: each takes
//! a stopped requester, its DMA domain and owned BAR mappings from the mount.
use super::{Error, NativeServices, ServiceError};
use crate::{
    Clock,
    bus::{
        dma::mapping::DmaDomain,
        mmio::owned::Mapping,
        pci::{Address, Bar, Function, owned::OwnedConfig},
    },
    net::{
        Link, LinkError, Mac,
        aqtion::{self, Aqtion, MappedRegisters},
        tg3,
    },
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::any::Any;

/// A Broadcom Tigon3 adapter over owned BAR0 and APE mappings.
pub type Tg3 = tg3::Packet<tg3::io::Mmio<OwnedConfig>, Clock>;

/// A link driver and the PCI location it was found at.
pub struct Located<L> {
    pub location: String,
    pub link: L,
}

impl<L: Link> Link for Located<L> {
    fn mac(&self) -> Mac {
        self.link.mac()
    }
    fn carrier(&mut self) -> bool {
        self.link.carrier()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.link.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.link.receive()
    }
}

/// The drivers here that attach through [`NativeServices`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Tg3,
    Aqtion,
}

impl Kind {
    pub(super) fn of(function: &Function) -> Option<Self> {
        if tg3::candidate(function.vendor, function.device, function.class) {
            Some(Self::Tg3)
        } else if aqtion::Profile::identify(function.vendor, function.device).is_some()
            && function.class == [2, 0, 0]
        {
            Some(Self::Aqtion)
        } else {
            None
        }
    }
}

/// A function claimed from the mount, before any device effect.
struct Claimed {
    function: Function<OwnedConfig>,
    domain: Arc<dyn DmaDomain>,
    bars: [Option<Bar>; 6],
}

fn claim(services: &dyn NativeServices, address: Address) -> Result<Claimed, ServiceError> {
    let requester = services.claim_stopped(address)?;
    let (requester, binding) = requester
        .into_dma_binding()
        .map_err(|(error, _)| ServiceError::Claim(error))?;
    let domain = services.domain(binding)?;
    let mut function = requester.into_function();
    let bars = function.bars();
    Ok(Claimed {
        function,
        domain,
        bars,
    })
}

fn map(
    services: &dyn NativeServices,
    address: Address,
    bars: &[Option<Bar>; 6],
    index: usize,
) -> Result<Mapping, ServiceError> {
    match bars[index] {
        Some(bar @ Bar::Memory { .. }) => services.map_bar(address, bar),
        _ => Err(ServiceError::Refused("missing memory BAR")),
    }
}

/// What a failed attach leaves: the error and any owner that must outlive
/// the device because it may hold mappings or DMA.
pub(super) type Failure = (Error, Option<Box<dyn Any>>);

/// Attach a Tigon3 adapter: BAR0 holds the MAC registers, BAR2 the APE.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, and `clock` is the
/// handoff's calibrated clock.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn tg3(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<Located<Tg3>, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let claimed = claim(services, address).map_err(refused)?;
    let mac = map(services, address, &claimed.bars, 0).map_err(refused)?;
    let ape = map(services, address, &claimed.bars, 2).map_err(refused)?;
    let window = |mapping: &Mapping| {
        let bytes = mapping.bytes()?;
        Ok((mapping.address(0, bytes)?, bytes))
    };
    let ((mac_window, mac_bytes), (ape_window, ape_bytes)) = window(&mac)
        .and_then(|mac| Ok((mac, window(&ape)?)))
        .map_err(|error| refused(ServiceError::Mapping(error)))?;
    let windows: Arc<dyn Any> = Arc::new((mac, ape));
    // SAFETY: the mount claimed the stopped function and mapped exactly its
    // BAR0 and BAR2 uncached, and `windows` keeps both mappings alive.
    let registers = unsafe {
        tg3::io::Mmio::from_owned_windows(
            claimed.function,
            mac_window,
            mac_bytes,
            ape_window,
            ape_bytes,
            windows,
        )
    }
    .map_err(|(error, function, windows)| {
        (
            Error::Tg3(error),
            Some(Box::new((function, windows)) as Box<dyn Any>),
        )
    })?;
    // SAFETY: the registers satisfy their ownership contract and `clock` is
    // the calibrated handoff clock.
    let hardware = unsafe { tg3::Hardware::new(registers, clock) };
    // SAFETY: the mount's domain isolates this requester and its pages are
    // retained; the function was stopped when claimed.
    match unsafe { tg3::Packet::attach(hardware, services.pages(), claimed.domain) } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err((error, link)) => Err((Error::Tg3(error), Some(Box::new(link)))),
    }
}

/// Attach an Aquantia AQtion adapter over its BAR0 registers.
///
/// # Safety
/// As for [`tg3`].
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn aqtion(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<Located<Aqtion>, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let claimed = claim(services, address).map_err(refused)?;
    let registers = map(services, address, &claimed.bars, 0).map_err(refused)?;
    let registers = MappedRegisters::new(registers).map_err(|(error, mapping)| {
        (
            Error::Aqtion(error),
            Some(Box::new(mapping) as Box<dyn Any>),
        )
    })?;
    // SAFETY: the mount claimed the stopped function, mapped its BAR0 and
    // supplied an isolating domain; the probe runs in process context.
    match unsafe {
        Aqtion::attach(
            claimed.function,
            registers,
            clock,
            claimed.domain,
            services.pages(),
        )
    } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err((error, link)) => Err((Error::Aqtion(error), Some(Box::new(link)))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::services::tests::Refusing;

    fn address() -> Address {
        Address {
            segment: 0,
            bus: 3,
            device: 0,
            function: 0,
        }
    }

    #[test]
    fn a_refused_claim_attaches_nothing_and_keeps_no_owner() {
        let services = Refusing::default();
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        // SAFETY: the refusing services transfer no owner.
        let tg3 = unsafe { tg3(&services, address(), clock) };
        assert!(matches!(
            tg3,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        // SAFETY: as above.
        let aqtion = unsafe { aqtion(&services, address(), clock) };
        assert!(matches!(
            aqtion,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert_eq!(*services.requests.borrow(), [address(), address()]);
    }
}
