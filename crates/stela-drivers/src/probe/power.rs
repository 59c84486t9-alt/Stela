//! The embedded controller, batteries, AC adapter and lid the ACPI namespace
//! describes, attached through the mount's ACPI session.
use super::{Devices, PlatformError};
use crate::platform::{
    ac::AcAdapter,
    acpi::{Handle, Session},
    battery::Battery,
    ec::{
        self,
        binding::{Binding, Scope},
        discovery::{
            Ecdt,
            native::{Device, DiscoveryError},
        },
    },
    lid::Lid,
};
use alloc::{boxed::Box, string::String, vec::Vec};

/// ACPI hardware IDs, as Linux's `ec_device_ids`, `battery_device_ids`,
/// `ac_device_ids` and lid button match them.
const EC: &str = "PNP0C09";
const BATTERY: &str = "PNP0C0A";
const AC: &str = "ACPI0003";
const LID: &str = "PNP0C0D";

/// The batteries, AC adapter and lid the namespace lists, each read once
/// as it attached.
#[derive(Default)]
pub struct Power {
    pub batteries: Vec<Battery<'static>>,
    pub ac: Option<AcAdapter<'static>>,
    pub lid: Option<Lid<'static>>,
}

fn fail(devices: &mut Devices, location: String, error: PlatformError) {
    devices.platform_failures.push((location, error));
}

fn location(handle: Handle<'_>, id: &str) -> String {
    handle.path().unwrap_or_else(|_| String::from(id))
}

/// The first EC binding and discovery failures reported while selecting it.
/// A malformed ECDT may coexist with a valid DSDT fallback controller.
pub struct EmbeddedControllerInstallation {
    pub binding: Option<Binding<'static>>,
    pub failures: Vec<(String, PlatformError)>,
}

/// Install the boot EC before namespace initialization. ECDT ports take
/// precedence; DSDT discovery is the fallback, as Linux's EC probes do.
///
/// # Safety
/// The session provider owns this controller's ports, decode, power and
/// firmware global-lock services, and no other byte owner reaches it.
pub unsafe fn install_embedded_controller(
    session: &'static Session,
) -> EmbeddedControllerInstallation {
    let mut result = EmbeddedControllerInstallation {
        binding: None,
        failures: Vec::new(),
    };
    let from_ecdt = || -> Result<Option<Device<'static>>, (String, PlatformError)> {
        let Some(table) = session
            .table(b"ECDT")
            .map_err(|error| (String::from("ECDT"), PlatformError::AcpiMethod(error)))?
        else {
            return Ok(None);
        };
        let ecdt = Ecdt::parse(&table).map_err(|_| {
            (
                String::from("ECDT"),
                PlatformError::EcDiscovery(DiscoveryError::Malformed("ECDT")),
            )
        })?;
        let handle = session
            .handle(ecdt.path)
            .map_err(|error| (String::from(ecdt.path), PlatformError::AcpiMethod(error)))?;
        let fadt = session
            .table(b"FACP")
            .map_err(|error| (String::from("FACP"), PlatformError::AcpiMethod(error)))?
            .ok_or_else(|| {
                (
                    String::from("FACP"),
                    PlatformError::Refused("EC discovery requires the FADT"),
                )
            })?;
        let flags = fadt.get(112..116).ok_or_else(|| {
            (
                String::from("FACP"),
                PlatformError::Refused("FADT has no flags field"),
            )
        })?;
        let reduced = u32::from_le_bytes(flags.try_into().unwrap()) & (1 << 20) != 0;
        Device::discover_ecdt(handle, ecdt, reduced)
            .map(Some)
            .map_err(|error| (location(handle, EC), PlatformError::EcDiscovery(error)))
    };
    let device = match from_ecdt() {
        Ok(Some(device)) => Some(device),
        Ok(None) => None,
        Err(error) => {
            result.failures.push(error);
            None
        }
    };
    let device = device.or_else(|| {
        let handles = match session.devices(EC) {
            Ok(handles) => handles,
            Err(error) => {
                result
                    .failures
                    .push((String::from(EC), PlatformError::AcpiMethod(error)));
                return None;
            }
        };
        let handle = handles.into_iter().next()?;
        match Device::discover(handle) {
            Ok(device) => Some(device),
            Err(error) => {
                result
                    .failures
                    .push((location(handle, EC), PlatformError::EcDiscovery(error)));
                None
            }
        }
    });
    if let Some(device) = device {
        let at = location(device.handle, EC);
        // SAFETY: forwarded from the caller; the ECDT/DSDT selected this controller.
        match unsafe { Binding::install(device, ec::Config::default(), Scope::FirstController) } {
            Ok(binding) => result.binding = Some(binding),
            Err(error) => result.failures.push((at, PlatformError::Ec(error))),
        }
    }
    result
}

pub(super) fn attach_ec(session: &'static Session, devices: &mut Devices) {
    // SAFETY: NativeServices::acpi grants the provider/controller contract.
    let installed = unsafe { install_embedded_controller(session) };
    devices.platform_failures.extend(installed.failures);
    devices.owners.extend(
        installed
            .binding
            .map(|binding| Box::new(binding) as Box<dyn core::any::Any>),
    );
}

/// Attach every battery and the first AC adapter and lid, reading each once
/// as Linux's `acpi_battery_add`, `acpi_ac_add` and `acpi_button_add` do.
/// A device whose first reading fails stays attached with its state unknown.
pub(super) fn attach_power(session: &'static Session, devices: &mut Devices) {
    match session.devices(BATTERY) {
        Ok(handles) => {
            for handle in handles {
                let at = location(handle, BATTERY);
                match Battery::attach(handle) {
                    Ok(mut battery) => {
                        if let Err(error) = battery.refresh() {
                            fail(devices, at, PlatformError::Battery(error));
                        }
                        devices.power.batteries.push(battery);
                    }
                    Err(error) => fail(devices, at, PlatformError::Battery(error)),
                }
            }
        }
        Err(error) => fail(
            devices,
            String::from(BATTERY),
            PlatformError::AcpiMethod(error),
        ),
    }
    let first = |devices: &mut Devices, id: &str| match session.devices(id) {
        Ok(handles) => handles.into_iter().next(),
        Err(error) => {
            fail(devices, String::from(id), PlatformError::AcpiMethod(error));
            None
        }
    };
    if let Some(handle) = first(devices, AC) {
        let at = location(handle, AC);
        match AcAdapter::attach(handle) {
            Ok(mut ac) => {
                if let Err(error) = ac.refresh() {
                    fail(devices, at, PlatformError::AcpiMethod(error));
                }
                devices.power.ac = Some(ac);
            }
            Err(error) => fail(devices, at, PlatformError::AcpiMethod(error)),
        }
    }
    if let Some(handle) = first(devices, LID) {
        let at = location(handle, LID);
        match Lid::attach(handle) {
            Ok(mut lid) => {
                if let Err(error) = lid.refresh() {
                    fail(devices, at, PlatformError::AcpiMethod(error));
                }
                devices.power.lid = Some(lid);
            }
            Err(error) => fail(devices, at, PlatformError::AcpiMethod(error)),
        }
    }
}
