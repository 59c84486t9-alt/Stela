//! The SMBus companions of PS/2 touchpads, attached as Linux
//! `psmouse_smbus_init` attaches them: once the PS/2 side is handed over, on
//! the first i801 with Host Notify that answers at the companion's address.
//! When none answers or the companion fails, the touchpad goes back to PS/2,
//! as Linux falls back to its PS/2 protocol.
use super::{Devices, PlatformError, smbus::Host};
use crate::{
    Clock,
    bus::smbus,
    input::{
        InputDevice, elan,
        hid_i2c::{self, InterruptError},
        ps2::{self, Companion},
        rmi::{
            self, AttentionError,
            transport::{self, CompanionError},
        },
        touchpad::{self, Driver, TouchpadInput},
    },
};
use alloc::{boxed::Box, format, string::String};

/// `synaptics_create_intertouch`'s `reset_delay_ms`.
const RMI_RESET_DELAY_US: u64 = 30_000;
/// The SMBus transport's settling time before its mode read, Linux's RMI
/// default reset delay.
const RMI_SMBUS_SETTLE_US: u64 = 100_000;

/// A companion's attention: its Host Notify, which the host collects. The
/// status is polled, so there is no CPU route to mask or drain.
struct HostNotify {
    host: Host,
    address: smbus::Address,
}

impl rmi::Attention for HostNotify {
    fn mask_and_drain(&mut self) -> Result<(), AttentionError> {
        Ok(())
    }
    fn pending(&mut self) -> Result<bool, AttentionError> {
        self.host
            .notified(self.address, false)
            .map_err(|_| AttentionError::Unavailable)
    }
    fn acknowledge(&mut self) -> Result<(), AttentionError> {
        self.host
            .notified(self.address, true)
            .map(drop)
            .map_err(|_| AttentionError::Unavailable)
    }
}

impl hid_i2c::Interrupt for HostNotify {
    fn mask_and_drain(&mut self) -> Result<(), InterruptError> {
        Ok(())
    }
    fn asserted(&mut self) -> Result<bool, InterruptError> {
        self.host
            .notified(self.address, true)
            .map_err(|_| InterruptError::Unavailable)
    }
}

/// The PS/2 side of an RMI4 companion, which shares the physical device.
struct Ps2Side(ps2::Shared);

impl transport::Companion for Ps2Side {
    fn reset_for_smbus(&mut self) -> Result<(), CompanionError> {
        self.0
            .borrow_mut()
            .hand_mouse_to_companion()
            .map_err(|_| CompanionError::Unavailable)
    }
    fn restore_ps2(&mut self) -> Result<(), CompanionError> {
        self.0
            .borrow_mut()
            .reclaim_mouse()
            .map_err(|_| CompanionError::Unavailable)
    }
}

/// Attach the SMBus `companion` of the touchpad on `ps2`'s mouse port.
pub(super) fn attach(
    ps2: &ps2::Shared,
    companion: Companion,
    hosts: &[Host],
    clock: Clock,
    devices: &mut Devices,
) {
    if !hosts.iter().any(Host::host_notify) {
        return;
    }
    let Ok(address) = smbus::Address::new(companion.address()) else {
        return;
    };
    if let Err(error) = ps2.borrow_mut().hand_mouse_to_companion() {
        devices.platform_failures.push((
            String::from("i8042 SMBus companion handover"),
            PlatformError::Ps2(error),
        ));
        return;
    }
    let Some(host) = hosts
        .iter()
        .find(|host| host.host_notify() && host.present(address))
    else {
        reclaim(ps2, devices);
        return;
    };
    let location = format!("{} {:#04x}", host.location(), address.get());
    let attached = match companion {
        Companion::Rmi => rmi(ps2, host, address, clock, &location, devices)
            .map(|device| (Driver::Rmi(Box::new(device)), "Synaptics RMI4")),
        Companion::Elan => {
            elan(host, address, clock).map(|device| (Driver::ElanSmbus(device), "ELAN"))
        }
    };
    match attached {
        Ok((driver, name)) => {
            devices
                .inputs
                .push(InputDevice::Touchpad(Box::new(TouchpadInput::new(
                    driver,
                    clock,
                    format!("{name} SMBus touchpad {location}"),
                ))))
        }
        Err(error) => {
            devices.platform_failures.push((
                format!("touchpad {location}"),
                PlatformError::Touchpad(error),
            ));
            reclaim(ps2, devices);
        }
    }
}

/// Synaptics InterTouch, as `rmi_smb_probe` and `rmi_driver_probe` bring it
/// up with each function engine implemented here.
fn rmi(
    ps2: &ps2::Shared,
    host: &Host,
    address: smbus::Address,
    clock: Clock,
    location: &str,
    devices: &mut Devices,
) -> Result<touchpad::RmiSmbus, touchpad::Error> {
    let failed = touchpad::Error::Rmi;
    let transport = transport::Smbus::new(
        Box::new(host.clone()) as Box<dyn smbus::Bus>,
        address,
        Box::new(Ps2Side(ps2.clone())) as Box<dyn transport::Companion>,
        clock,
        RMI_SMBUS_SETTLE_US,
    )
    .map_err(failed)?;
    let attention = Box::new(HostNotify {
        host: host.clone(),
        address,
    }) as Box<dyn rmi::Attention>;
    let configuration = rmi::Configuration {
        reset_delay_us: RMI_RESET_DELAY_US,
        ..rmi::Configuration::default()
    };
    let mut device =
        rmi::Device::new(transport, attention, clock, configuration).map_err(failed)?;
    device.initialize_control().map_err(failed)?;
    let present = |device: &touchpad::RmiSmbus, number| {
        device
            .functions()
            .iter()
            .any(|function| function.number == number)
    };
    if present(&device, 0x11) {
        device
            .initialize_f11(rmi::f11::Configuration::default())
            .map_err(failed)?;
    }
    if present(&device, 0x12) {
        device.initialize_f12(None).map_err(failed)?;
    }
    if present(&device, 0x30) {
        device.initialize_f30().map_err(failed)?;
    }
    if present(&device, 0x3a) {
        device.initialize_f3a().map_err(failed)?;
    }
    if present(&device, 0x03) {
        devices.platform_failures.push((
            format!("touchpad {location} trackstick"),
            PlatformError::Refused("RMI4 F03 PS/2 passthrough (trackstick) is not driven"),
        ));
    }
    Ok(device)
}

/// An Elantech IC's ELAN SMBus companion, as `elan_probe` brings it up.
fn elan(
    host: &Host,
    address: smbus::Address,
    clock: Clock,
) -> Result<touchpad::ElanSmbus, touchpad::Error> {
    let mut device = elan::smbus::Device::new(
        Box::new(host.clone()) as Box<dyn smbus::Bus>,
        Box::new(HostNotify {
            host: host.clone(),
            address,
        }) as Box<dyn hid_i2c::Interrupt>,
        clock,
        address,
    );
    device.initialize().map_err(touchpad::Error::Elan)?;
    Ok(device)
}

/// Give the mouse port back to PS/2.
fn reclaim(ps2: &ps2::Shared, devices: &mut Devices) {
    if let Err(error) = ps2.borrow_mut().reclaim_mouse() {
        devices.platform_failures.push((
            String::from("i8042 mouse reclaim"),
            PlatformError::Ps2(error),
        ));
    }
}
