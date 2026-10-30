//! Devices the ACPI namespace describes instead of PCI, attached through
//! [`NativeServices::acpi`](super::NativeServices::acpi): the i8042 keyboard
//! and mouse ports.
use super::PlatformError;
use crate::input::ps2;
use alloc::string::String;
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

/// The mouse port's firmware identifier as Linux's i8042 PnP driver forms it
/// from the device's `ids`, its `_HID` and then its `_CID`s: `PNP:` and each
/// ID in PnP form, the first of them once, with the hex digits lowercase as
/// `pnp_add_id` stores them. None when no ID is in PnP form, as `pnpacpi`
/// then adds no PnP device.
pub(crate) fn firmware_id(ids: &[String]) -> Option<String> {
    let pnp = |id: &&String| {
        let bytes = id.as_bytes();
        bytes.len() == 7
            && bytes[..3].iter().all(u8::is_ascii_uppercase)
            && bytes[3..]
                .iter()
                .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c))
    };
    let primary = ids.iter().find(pnp)?;
    let others = ids.iter().filter(pnp).filter(|id| *id != primary);
    let mut text = String::from("PNP:");
    for id in core::iter::once(primary).chain(others) {
        text.push(' ');
        text.push_str(&id[..3]);
        text.extend(id[3..].chars().map(|c| c.to_ascii_lowercase()));
    }
    Some(text)
}

/// Attach the i8042 when the namespace lists a keyboard or mouse port.
#[cfg(feature = "native-acpi")]
pub(super) fn attach_i8042(
    session: &crate::platform::acpi::Session,
    clock: crate::Clock,
    usb_released: bool,
    smbus_hosts: &[super::smbus::Host],
    devices: &mut super::Devices,
) {
    use super::{i2c::hardware_id, services::ids};
    use crate::platform::acpi::{
        Handle, Value,
        resources::{self, Resource, Space},
    };
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
    // The `_HID` and `_CID`s ACPICA reads for a device's PnP IDs.
    let pnp_ids = |device: Handle<'_>| -> Result<Vec<String>, PlatformError> {
        let acpi = |error: crate::platform::acpi::Error| PlatformError::Acpi(error.into());
        let mut ids: Vec<String> = hardware_id(device.evaluate(Some("_HID"), &[]).map_err(acpi)?)
            .into_iter()
            .collect();
        if device.child("_CID").is_ok() {
            match device.evaluate(Some("_CID"), &[]).map_err(acpi)? {
                Some(Value::Package(cids)) => {
                    ids.extend(cids.into_iter().filter_map(|cid| hardware_id(Some(cid))));
                }
                cid => ids.extend(hardware_id(cid)),
            }
        }
        Ok(ids)
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
        let firmware_id = match mice.first() {
            Some(mouse) => firmware_id(&pnp_ids(*mouse)?),
            None => None,
        };
        let mut controller =
            ps2::Controller::new_probing(registers, clock, config, firmware_id.as_deref())
                .map_err(PlatformError::Ps2)?;
        controller.initialize().map_err(PlatformError::Ps2)?;
        Ok(Some(controller))
    };
    match attempt() {
        Ok(Some(controller)) => {
            let companion = controller.smbus_companion();
            let shared = alloc::rc::Rc::new(core::cell::RefCell::new(controller));
            devices
                .inputs
                .push(crate::input::InputDevice::Ps2(shared.clone()));
            if let Some(companion) = companion {
                super::companion::attach(&shared, companion, smbus_hosts, clock, devices);
            }
        }
        Ok(None) => {}
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
    fn the_firmware_id_lists_the_pnp_ids_hid_first_in_pnp_form() {
        let ids = |ids: &[&str]| {
            ids.iter()
                .map(|id| String::from(*id))
                .collect::<alloc::vec::Vec<_>>()
        };
        assert_eq!(
            firmware_id(&ids(&["LEN0073", "PNP0F13"])).as_deref(),
            Some("PNP: LEN0073 PNP0f13")
        );
        assert_eq!(
            firmware_id(&ids(&["ACPI0003", "SYN3052", "PNP0F13", "SYN3052"])).as_deref(),
            Some("PNP: SYN3052 PNP0f13"),
            "an ID not in PnP form is skipped, and the first PnP ID listed once"
        );
        assert_eq!(firmware_id(&ids(&["MSFT0001"])), None);
    }

    #[test]
    fn a_host_still_held_by_firmware_refuses_the_ports() {
        assert!(matches!(
            i8042(true, true, &I8042_PORTS, false),
            Err(PlatformError::Refused(_))
        ));
    }
}
