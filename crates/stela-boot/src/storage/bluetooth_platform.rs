//! The live UEFI read behind [`stela_boot_core::bluetooth_dsbr`].
use stela_boot_core::bluetooth_dsbr::capture_with;
use stela_drivers::usb::bluetooth::intel::DsbrCapture;
use uefi::{
    CStr16,
    runtime::{self, VariableVendor},
};

pub(super) fn capture() -> DsbrCapture {
    capture_with(|name, vendor, bytes| {
        let mut buffer = [0; 32];
        let name =
            CStr16::from_str_with_buf(name, &mut buffer).expect("static variable name is UCS-2");
        runtime::get_variable(name, &VariableVendor(*vendor), bytes)
            .map(|(value, attributes)| (value.len(), attributes.bits()))
            .map_err(|error| (error.status().0 as u64, *error.data()))
    })
}
