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

/// Install the first embedded controller's operation regions before other
/// devices' methods run, as Linux's `acpi_ec_ecdt_probe` and
/// `acpi_ec_dsdt_probe` do: the controller the ECDT names, otherwise the
/// namespace's first PNP0C09.
pub(super) fn attach_ec(session: &'static Session, devices: &mut Devices) {
    let named = match session.table(b"ECDT") {
        Ok(Some(table)) => match Ecdt::parse(&table) {
            Ok(ecdt) => match session.handle(ecdt.path) {
                Ok(handle) => Some(handle),
                Err(error) => {
                    fail(
                        devices,
                        String::from(ecdt.path),
                        PlatformError::AcpiMethod(error),
                    );
                    None
                }
            },
            Err(_) => {
                fail(
                    devices,
                    String::from("ECDT"),
                    PlatformError::EcDiscovery(DiscoveryError::Malformed("ECDT")),
                );
                None
            }
        },
        Ok(None) => None,
        Err(error) => {
            fail(
                devices,
                String::from("ECDT"),
                PlatformError::AcpiMethod(error),
            );
            None
        }
    };
    let handle = match named {
        Some(handle) => handle,
        None => match session.devices(EC) {
            Ok(handles) => match handles.into_iter().next() {
                Some(handle) => handle,
                None => return,
            },
            Err(error) => {
                fail(devices, String::from(EC), PlatformError::AcpiMethod(error));
                return;
            }
        },
    };
    let at = location(handle, EC);
    let device = match Device::discover(handle) {
        Ok(device) => device,
        Err(error) => {
            fail(devices, at, PlatformError::EcDiscovery(error));
            return;
        }
    };
    // SAFETY: [`super::NativeServices::acpi`]'s session provider serves this
    // first controller's ports, decode, power and global lock for the
    // session's life, and no other owner reaches it.
    match unsafe { Binding::install(device, ec::Config::default(), Scope::FirstController) } {
        Ok(binding) => devices.owners.push(Box::new(binding)),
        Err(error) => fail(devices, at, PlatformError::Ec(error)),
    }
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
