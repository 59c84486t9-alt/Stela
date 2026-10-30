//! The UCSI connector managers the ACPI namespace describes (PNP0CA0),
//! attached as Linux `ucsi_acpi_probe` attaches them: the `_CRS` mailbox
//! mapped as the firmware's AML maps it, Notify installed, then a PPM reset
//! and connector discovery. Their `_DEP` suppliers must be the installed
//! embedded controller, the one supplier probe holds a receipt for.
use super::{
    Devices, PlatformError,
    services::{NativeServices, ServiceError},
};
use crate::{
    Clock,
    platform::{acpi::Session, ec::capability::Installed},
    usb::typec::ucsi::acpi::{
        attachment::{self, Attachment, Mapping},
        resources::MemoryResource,
    },
};
use alloc::{string::String, vec::Vec};
use core::ptr::NonNull;

/// UCSI's ACPI hardware ID.
const UCSI: &str = "PNP0CA0";

/// A UCSI connector manager, serviced when its Notify arrives.
pub type Ucsi = Attachment<'static, Mailbox, Installed<'static>, Clock>;

/// A UCSI mailbox, through the mapping AML reaches the same firmware RAM by.
pub struct Mailbox {
    resource: MemoryResource,
    base: NonNull<u8>,
}

// SAFETY: NativeServices::firmware_memory maps exactly this firmware-owned
// range for the program, writable and coherent with AML's accesses, with no
// Rust reference to it. Drop leaves both the mapping and the RAM to firmware.
unsafe impl Mapping for Mailbox {
    fn resource(&self) -> MemoryResource {
        self.resource
    }
    fn base(&self) -> NonNull<u8> {
        self.base
    }
}

/// Attach and start every present UCSI device.
pub(super) fn attach(
    services: &dyn NativeServices,
    session: &'static Session,
    ec: Option<&Installed<'static>>,
    clock: Clock,
    devices: &mut Devices,
) {
    let discovered = match attachment::discover(session) {
        Ok(discovered) => discovered,
        Err(error) => {
            // Discovery needs the namespace's hardware mode; without UCSI
            // devices there is nothing it left unattached.
            if session
                .devices(UCSI)
                .map_or(true, |handles| !handles.is_empty())
            {
                devices
                    .platform_failures
                    .push((String::from(UCSI), PlatformError::Ucsi(error)));
            }
            return;
        }
    };
    for device in discovered {
        let device = match device {
            Ok(device) => device,
            Err(error) => {
                devices
                    .platform_failures
                    .push((String::from(UCSI), PlatformError::Ucsi(error)));
                continue;
            }
        };
        let location = device
            .handle()
            .path()
            .unwrap_or_else(|_| String::from(UCSI));
        match bind(services, ec, clock, device) {
            Ok(ucsi) => devices.power.ucsi.push(ucsi),
            Err(error) => devices.platform_failures.push((location, error)),
        }
    }
}

fn bind(
    services: &dyn NativeServices,
    ec: Option<&Installed<'static>>,
    clock: Clock,
    device: attachment::Device<'static>,
) -> Result<Ucsi, PlatformError> {
    let leases = device
        .dependencies()
        .iter()
        .map(|handle| {
            ec.filter(|ec| ec.handle() == *handle)
                .cloned()
                .ok_or(PlatformError::Native(ServiceError::Refused(
                    "UCSI _DEP names a supplier other than the installed embedded controller",
                )))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resource = device.resource();
    let base = services
        .firmware_memory(resource.physical, resource.bytes)
        .map_err(PlatformError::Native)?;
    let mut ucsi = Attachment::bind(device, Mailbox { resource, base }, leases, clock)
        .map_err(PlatformError::Ucsi)?;
    ucsi.start().map_err(PlatformError::Ucsi)?;
    Ok(ucsi)
}
