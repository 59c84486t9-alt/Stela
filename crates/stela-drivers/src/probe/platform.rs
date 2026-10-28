//! Devices the ACPI namespace describes instead of PCI, attached through
//! [`NativeServices::acpi`](super::NativeServices::acpi): the i8042 keyboard
//! and mouse ports.
use super::PlatformError;
use crate::input::ps2;
use core::ops::Range;

/// The standard i8042 data and command/status ports.
const I8042_PORTS: [Range<u64>; 2] = [0x60..0x61, 0x64..0x65];

/// The controller configuration for the i8042 ports the namespace lists.
///
/// `io` holds the I/O ranges of the first `_CRS` that lists any, the keyboard's
/// before the mouse's, as Linux's i8042 PnP probe reads them: the data port
/// first, then the command port. A `_CRS` without I/O ranges takes the
/// standard ports, as Linux does. `usb_released` says every USB host
/// controller was handed over from firmware, so no USB legacy emulation
/// traps the ports.
pub(crate) fn i8042(
    keyboard: bool,
    mouse: bool,
    io: &[Range<u64>],
    usb_released: bool,
) -> Result<Option<ps2::Config>, PlatformError> {
    if !keyboard && !mouse {
        return Ok(None);
    }
    if !usb_released {
        return Err(PlatformError::Refused(
            "i8042: a USB host controller was not handed over from firmware, so USB legacy emulation may trap its ports",
        ));
    }
    if !io.is_empty() && io.get(..2) != Some(&I8042_PORTS[..]) {
        return Err(PlatformError::Refused(
            "i8042 at ports other than 0x60 and 0x64",
        ));
    }
    Ok(Some(ps2::Config {
        keyboard,
        mouse,
        ..ps2::Config::default()
    }))
}

/// Attach the i8042 when the namespace lists a keyboard or mouse port.
#[cfg(feature = "native-acpi")]
pub(super) fn attach_i8042(
    session: &crate::platform::acpi::Session,
    clock: crate::Clock,
    usb_released: bool,
    devices: &mut super::Devices,
) {
    use super::services::ids;
    use crate::platform::acpi::resources::{self, Resource, Space};
    use alloc::vec::Vec;

    let found = |hids: &[&str]| -> Result<Vec<_>, PlatformError> {
        let mut handles = Vec::new();
        for hid in hids {
            handles.extend(
                session
                    .devices(hid)
                    .map_err(|error| PlatformError::Acpi(error.into()))?,
            );
        }
        Ok(handles)
    };
    let attempt = || -> Result<Option<ps2::Controller>, PlatformError> {
        let keyboards = found(ids::I8042_KEYBOARD)?;
        let mice = found(ids::I8042_MOUSE)?;
        let mut io = Vec::new();
        for device in keyboards.iter().chain(&mice).take(1) {
            for descriptor in resources::evaluate(*device, "_CRS").map_err(PlatformError::Acpi)? {
                if let Resource::Address(address) = descriptor.resource
                    && address.space == Space::Io
                    && address.minimum_fixed
                {
                    io.push(address.minimum..address.minimum + address.length);
                }
            }
        }
        let Some(config) = i8042(!keyboards.is_empty(), !mice.is_empty(), &io, usb_released)?
        else {
            return Ok(None);
        };
        // SAFETY: the namespace lists an i8042 at the standard ports, every
        // USB host was handed over from firmware, and the mount's NativeServices
        // contract grants those ports with IRQ1 and IRQ12 masked.
        let registers = unsafe { ps2::PortIo::claim() };
        let mut controller =
            ps2::Controller::new(registers, clock, config).map_err(PlatformError::Ps2)?;
        controller.initialize().map_err(PlatformError::Ps2)?;
        Ok(Some(controller))
    };
    match attempt() {
        Ok(controller) => devices
            .inputs
            .extend(controller.map(crate::input::InputDevice::Ps2)),
        Err(error) => devices.platform_failures.push(("i8042".into(), error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_ports_attach_the_listed_ports() {
        let config = i8042(true, false, &I8042_PORTS, true).unwrap().unwrap();
        assert!(config.keyboard && !config.mouse);
        let config = i8042(false, true, &[], true).unwrap().unwrap();
        assert!(!config.keyboard && config.mouse);
    }

    #[test]
    fn no_listed_port_attaches_nothing() {
        assert!(matches!(i8042(false, false, &[], false), Ok(None)));
    }

    #[test]
    fn other_ports_are_refused() {
        for io in [
            &[0x60..0x61, 0x60..0x61][..],
            &[0x64..0x65, 0x60..0x61],
            &[0x60..0x62, 0x64..0x65],
        ] {
            assert!(matches!(
                i8042(true, true, io, true),
                Err(PlatformError::Refused(_))
            ));
        }
    }

    #[test]
    fn a_host_still_held_by_firmware_refuses_the_ports() {
        assert!(matches!(
            i8042(true, true, &I8042_PORTS, false),
            Err(PlatformError::Refused(_))
        ));
    }
}
