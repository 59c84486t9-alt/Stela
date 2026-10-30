//! USB4/Thunderbolt hosts whose firmware runs the connection manager (ICM),
//! attached as Linux's `nhi_probe` and `icm_probe` attach them when ACPI
//! grants the OS no native USB4 control, which this mount never requests.
//! As Linux does with no authorizing agent, a device the firmware leaves
//! awaiting approval gets no PCIe tunnel.
use super::{Bridge, Claimed, Failure, NativeServices, ServiceError, claim, map};
use crate::{
    Clock,
    bus::{
        mmio::owned::Mapping,
        pci::{Address, ConfigSpace, Function, owned::OwnedConfig, regs},
        thunderbolt::{
            controller::{self, Controller},
            icm, ring,
        },
    },
    probe::Error,
};
use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::fmt;

/// An attached host: its ICM transport and the firmware's protocol
/// parameters, with the claimed function and BAR0 mapping it runs on.
pub struct Host {
    pub location: String,
    pub icm: icm::Host<ring::Mmio>,
    pub ready: icm::DriverReady,
    /// Firmware messages that arrived before DRIVER_READY was answered.
    pub early: Vec<icm::Event>,
    _owners: (Function<OwnedConfig>, Mapping),
}

/// Why a host was not attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The `IMR_VALID` property says the firmware image is invalid, which
    /// `nhi_imr_valid` refuses.
    InvalidFirmwareImage,
    /// Its firmware runs no connection manager; a software one is not
    /// attached yet.
    SoftwareConnectionManager,
    Clock,
    Ring(ring::Error),
    Controller(controller::Error),
    Icm(icm::Error),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFirmwareImage => f.write_str("firmware image not valid"),
            Self::SoftwareConnectionManager => {
                f.write_str("needs a software connection manager, which is not attached yet")
            }
            Self::Clock => f.write_str("uncalibrated clock"),
            Self::Ring(error) => write!(f, "NHI ring: {error:?}"),
            Self::Controller(error) => write!(f, "NHI preparation: {error:?}"),
            Self::Icm(error) => write!(f, "ICM: {error:?}"),
        }
    }
}

/// Whether the function's ACPI companion says its firmware image is
/// invalid, as `nhi_imr_valid` reads `IMR_VALID`: absent means valid.
#[cfg(feature = "native-acpi")]
fn invalid_image(services: &dyn NativeServices, address: Address, bridges: &[Bridge]) -> bool {
    use crate::platform::acpi::Value;
    services
        .acpi()
        .and_then(|session| super::companion(session, address, bridges))
        .is_some_and(|companion| {
            matches!(companion.property("IMR_VALID"), Ok(Some(Value::Integer(0))))
        })
}

#[cfg(not(feature = "native-acpi"))]
fn invalid_image(_: &dyn NativeServices, _: Address, _: &[Bridge]) -> bool {
    false
}

/// Attach the USB4 host at `address`: prepare its NHI as `nhi_probe` does,
/// enable its bus mastering, then start the ICM transport and wait for the
/// firmware's answer to DRIVER_READY.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, `clock` is the
/// handoff's calibrated clock, and `bridges` lists the segment's bridges.
#[expect(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(in crate::probe) unsafe fn attach(
    services: &dyn NativeServices,
    address: Address,
    bridges: &[Bridge],
    clock: Clock,
) -> Result<Host, Failure> {
    let refused =
        |refusal: Refusal, kept: Option<Box<dyn core::any::Any>>| (Error::Usb4(refusal), kept);
    if invalid_image(services, address, bridges) {
        return Err(refused(Refusal::InvalidFirmwareImage, None));
    }
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address).map_err(|error| (Error::Native(error), None))?;
    if icm::Family::of(function.vendor, function.device).is_none() {
        return Err(refused(
            Refusal::SoftwareConnectionManager,
            Some(Box::new((function, domain))),
        ));
    }
    let mapping = match map(services, address, &bars, 0) {
        Ok(mapping) => mapping,
        Err(error) => {
            return Err((Error::Native(error), Some(Box::new((function, domain)))));
        }
    };
    let window = mapping
        .bytes()
        .and_then(|bytes| Ok((mapping.address(0, bytes)?, bytes)));
    let (window, bytes) = match window {
        Ok(window) => window,
        Err(error) => {
            return Err((
                Error::Native(ServiceError::Mapping(error)),
                Some(Box::new((function, domain, mapping))),
            ));
        }
    };
    // SAFETY: `window` is the whole owned uncached BAR0 mapping, which the
    // host keeps with every reference to these registers.
    let registers = match unsafe { ring::Mmio::new(window, bytes) } {
        Ok(registers) => Arc::new(registers),
        Err(error) => {
            return Err(refused(
                Refusal::Ring(error),
                Some(Box::new((function, domain, mapping))),
            ));
        }
    };
    let now = || {
        clock
            .try_now_us()
            .map(|us| us / 1000)
            .map_err(|_| Refusal::Clock)
    };
    let started = (|| {
        let config = function.config();
        let command = config.read16(regs::COMMAND);
        if command & regs::COMMAND_MEMORY == 0 {
            config.write16(regs::COMMAND, command | regs::COMMAND_MEMORY);
        }
        {
            // SAFETY: the configuration and registers are the claimed
            // function's and its BAR0; this mount negotiates no native USB4
            // control, so its firmware's ICM is the connection manager, and
            // the claimed requester's DMA and interrupts are stopped.
            let mut controller = unsafe { Controller::new(&mut *config, registers.clone()) }
                .map_err(Refusal::Controller)?;
            while controller
                .poll(now()?)
                .map_err(Refusal::Controller)?
                .is_none()
            {
                core::hint::spin_loop();
            }
        }
        // `nhi_probe`'s pci_set_master, now that the domain is attached.
        let command = config.read16(regs::COMMAND);
        config.write16(regs::COMMAND, command | regs::COMMAND_MASTER);
        // SAFETY: as above; the domain is the claimed requester's own, and
        // the prepared NHI has its interrupts masked and rings idle.
        let mut host = unsafe {
            icm::Host::new(
                &*config,
                registers.clone(),
                services.pages(),
                domain.clone(),
                u64::MAX,
            )
        }
        .map_err(Refusal::Icm)?;
        host.start(now()?).map_err(Refusal::Icm)?;
        let request = host.driver_ready(now()?).map_err(Refusal::Icm)?;
        let mut early = Vec::new();
        loop {
            match host.poll(now()?).map_err(Refusal::Icm)? {
                Some(icm::Event::DriverReady {
                    request: answered,
                    parameters,
                }) if answered == request => return Ok((host, parameters, early)),
                Some(event) => early.push(event),
                None => core::hint::spin_loop(),
            }
        }
    })();
    match started {
        Ok((icm, ready, early)) => Ok(Host {
            location: alloc::format!("{address}"),
            icm,
            ready,
            early,
            _owners: (function, mapping),
        }),
        Err(refusal) => Err(refused(
            refusal,
            Some(Box::new((function, domain, mapping, registers))),
        )),
    }
}
