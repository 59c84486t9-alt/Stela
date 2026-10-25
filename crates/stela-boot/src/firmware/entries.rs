//! The PC firmware's own boot entries for the startup menu
//! (`stela_loader::firmware_boot`): every listed entry in `BootOrder` except
//! those that start this disk. One starts by naming it in `BootNext` and
//! restarting, so the firmware boots it as from its own boot menu, whatever
//! its path holds.
use crate::output;
use alloc::{string::String, vec::Vec};
use stela_loader::firmware_boot::{self, LoadOption};
use uefi::{
    CString16, Status,
    boot::{self, OpenProtocolAttributes, OpenProtocolParams},
    cstr16,
    proto::{device_path::DevicePath, loaded_image::LoadedImage},
    runtime::{self, ResetType, VariableAttributes, VariableVendor},
};

pub(crate) struct Entry {
    pub number: u16,
    pub name: String,
}

/// The firmware's listed boot entries in its order, without Stela's own.
pub(crate) fn list() -> Vec<Entry> {
    let vendor = VariableVendor::GLOBAL_VARIABLE;
    let Ok((order, _)) = runtime::get_variable_boxed(cstr16!("BootOrder"), &vendor) else {
        return Vec::new();
    };
    let own = own_path().unwrap_or_default();
    let mut entries = Vec::new();
    for number in firmware_boot::order(&order) {
        let Ok(name) = CString16::try_from(firmware_boot::variable(number).as_str()) else {
            continue;
        };
        let Ok((bytes, _)) = runtime::get_variable_boxed(&name, &vendor) else {
            continue;
        };
        match LoadOption::parse(&bytes) {
            Ok(option) if option.listed() && !option.starts_from(&own) => entries.push(Entry {
                number,
                name: match option.description.is_empty() {
                    true => firmware_boot::variable(number),
                    false => option.description,
                },
            }),
            Ok(_) => {}
            Err(error) => output::arguments(format_args!(
                "FIRMWARE ENTRY {} skipped: {error}\n",
                firmware_boot::variable(number)
            )),
        }
    }
    entries
}

/// Restart into entry `number`; returns only when `BootNext` cannot be set.
pub(crate) fn start(number: u16) -> &'static str {
    let attributes = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::RUNTIME_ACCESS;
    let result = runtime::set_variable(
        cstr16!("BootNext"),
        &VariableVendor::GLOBAL_VARIABLE,
        attributes,
        &number.to_le_bytes(),
    );
    if result.is_err() {
        return "the firmware refused BootNext, so it cannot be asked to start that entry";
    }
    output::arguments(format_args!(
        "FIRMWARE ENTRY {} next; restarting\n",
        firmware_boot::variable(number)
    ));
    runtime::reset(ResetType::COLD, Status::SUCCESS, None)
}

/// The device path of the device `stela.efi` was loaded from.
fn own_path() -> Option<Vec<u8>> {
    let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()).ok()?;
    let device = image.device()?;
    // SAFETY: the path is only read, while no driver changes this handle.
    let path = unsafe {
        boot::open_protocol::<DevicePath>(
            OpenProtocolParams {
                handle: device,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    Some(path.as_bytes().into())
}
