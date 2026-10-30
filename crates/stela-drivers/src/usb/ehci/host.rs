//! The root ports of an attached EHCI controller, each high-speed device
//! brought up as Linux `hub_port_init` brings one up and its Bulk-Only mass
//! storage interface bound to [`storage`](crate::usb::storage). Full- and
//! low-speed devices go to the companion controller, which has no driver here.
use super::{Controller, DeviceId, Error};
use crate::{
    Clock,
    block::BlockError,
    bus::dma::DmaAllocator,
    usb::{
        descriptor::{
            CONFIGURATION_DESCRIPTOR, DEVICE_DESCRIPTOR, DEVICE_TO_HOST, GET_DESCRIPTOR,
            STRING_DESCRIPTOR, interfaces, setup,
        },
        storage::{self, UsbDisk, UsbStorage},
    },
};
use alloc::{format, rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;

/// An attached controller, shared by the storage transports on its roots.
pub type Shared = Rc<RefCell<Controller>>;

/// Why a root's device is left to the companion controller.
const COMPANION: &str =
    "full- or low-speed device left to the EHCI companion controller, which has no driver here";
/// Why an enumerated high-speed device is left unbound.
const NO_DRIVER: &str = "high-speed device without a Bulk-Only mass storage interface";

/// What enumeration found on one controller's roots.
#[derive(Default)]
pub struct Found {
    pub storage: Vec<UsbStorage>,
    pub disks: Vec<UsbDisk>,
    /// Devices left without a driver here, and why.
    pub unused: Vec<(String, &'static str)>,
    pub failures: Vec<(String, BlockError)>,
}

/// A root's device, reset, addressed and described.
pub(in crate::usb) struct Addressed {
    pub id: DeviceId,
    pub descriptor: [u8; 18],
}

/// Linux `hub_port_init` for a high-speed root device: reset, SET_ADDRESS to
/// the lowest free address, then the device descriptor. A failure after the
/// reset disables the root, so its address0 owner never blocks another.
pub(in crate::usb) fn address(controller: &Shared, port: u8) -> Result<Addressed, Error> {
    let mut c = controller.borrow_mut();
    let id = c.reset_port(port)?;
    let described = (|| {
        let address = c.unused_address().ok_or(Error::Exhausted)?;
        c.set_address(&id, address)?;
        let request = setup(
            DEVICE_TO_HOST,
            GET_DESCRIPTOR,
            u16::from(DEVICE_DESCRIPTOR) << 8,
            0,
            18,
        );
        let descriptor: [u8; 18] = c
            .control_in(&id, request)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        if descriptor[0] != 18 || descriptor[1] != DEVICE_DESCRIPTOR || descriptor[17] == 0 {
            return Err(Error::Invalid);
        }
        Ok(descriptor)
    })();
    match described {
        Ok(descriptor) => Ok(Addressed { id, descriptor }),
        Err(error) => {
            let _ = c.disable_port(&id);
            Err(error)
        }
    }
}

/// The configuration descriptor at `index`, whole.
pub(in crate::usb) fn configuration(
    controller: &mut Controller,
    id: &DeviceId,
    index: u8,
) -> Result<Vec<u8>, Error> {
    let value = u16::from(CONFIGURATION_DESCRIPTOR) << 8 | u16::from(index);
    let header = controller.control_in(id, setup(DEVICE_TO_HOST, GET_DESCRIPTOR, value, 0, 9))?;
    if header.len() != 9 || header[1] != CONFIGURATION_DESCRIPTOR {
        return Err(Error::Invalid);
    }
    let length = u16::from_le_bytes([header[2], header[3]]);
    let bytes =
        controller.control_in(id, setup(DEVICE_TO_HOST, GET_DESCRIPTOR, value, 0, length))?;
    if bytes.len() != usize::from(length) || bytes.get(..9) != Some(header.as_slice()) {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

/// String descriptor `index` in the device's first language, as Linux
/// `usb_string` reads it; `None` for index zero or an unreadable string.
fn string(controller: &mut Controller, id: &DeviceId, index: u8) -> Option<String> {
    if index == 0 {
        return None;
    }
    let read = |controller: &mut Controller, index: u8, language: u16| {
        let value = u16::from(STRING_DESCRIPTOR) << 8 | u16::from(index);
        controller
            .control_in(
                id,
                setup(DEVICE_TO_HOST, GET_DESCRIPTOR, value, language, 255),
            )
            .ok()
            .filter(|bytes| bytes.len() >= 2 && bytes[1] == STRING_DESCRIPTOR)
    };
    let languages = read(controller, 0, 0)?;
    let language = u16::from_le_bytes([*languages.get(2)?, *languages.get(3)?]);
    let bytes = read(controller, index, language)?;
    let length = usize::from(bytes[0]).min(bytes.len());
    let units = bytes[2..length]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit));
    let text: String = char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    (!text.is_empty()).then_some(text)
}

/// Bring up every connected root of `controller` and bind its storage.
pub fn enumerate(
    controller: &Shared,
    location: &str,
    clock: Clock,
    dma: &mut dyn DmaAllocator,
) -> Found {
    let mut found = Found::default();
    let ports = controller.borrow().ports();
    for port in 1..=ports {
        let at = format!("{location} port {port}");
        match address(controller, port) {
            Ok(addressed) => bind(controller, addressed, at, clock, dma, &mut found),
            // Nothing is connected.
            Err(Error::Stale) => {}
            Err(Error::Unsupported(
                "EHCI FS/LS companion traffic" | "EHCI companion-owned root",
            )) => found.unused.push((at, COMPANION)),
            Err(error) => found.failures.push((at, storage::ehci_error(error))),
        }
    }
    found
}

/// Bind the first Bulk-Only SCSI interface of configuration zero.
fn bind(
    controller: &Shared,
    addressed: Addressed,
    at: String,
    clock: Clock,
    dma: &mut dyn DmaAllocator,
    found: &mut Found,
) {
    let Addressed { id, descriptor } = addressed;
    let prepared = (|| {
        let mut c = controller.borrow_mut();
        let configuration = configuration(&mut c, &id, 0)?;
        let Some(setting) = interfaces(&configuration)
            .into_iter()
            .find(|i| i.alternate == 0 && storage::bulk_only(i))
        else {
            return Ok(None);
        };
        let serial = string(&mut c, &id, descriptor[16]);
        let pipes = c.configure(&id, 0)?;
        Ok(Some((setting, serial, pipes)))
    })();
    match prepared {
        Ok(Some((setting, serial, pipes))) => {
            let serial = serial.unwrap_or_else(|| at.clone());
            let io = storage::EhciBulk::new(controller.clone(), id, pipes, clock, descriptor);
            match storage::discover_ehci(io, &setting, at.clone(), serial, dma, &mut found.failures)
            {
                Ok((kept, disks)) => {
                    found.storage.push(kept);
                    found.disks.extend(disks);
                }
                Err(error) => found.failures.push((at, error)),
            }
        }
        Ok(None) => found.unused.push((at, NO_DRIVER)),
        Err(error) => found.failures.push((at, storage::ehci_error(error))),
    }
}
