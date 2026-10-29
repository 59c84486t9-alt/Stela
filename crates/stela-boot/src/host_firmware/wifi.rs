//! Read-only Intel Wi-Fi variable observations before ExitBootServices. Only
//! copied observations and immutable LOADER_DATA regions leave this module.
use crate::paging::PAGE;
use stela_boot_core::host_resources::wifi::{Capture, Read, capture_with};
use stela_drivers::net::wifi::intel::platform::Variable;
use uefi::{
    CString16, boot,
    runtime::{VariableAttributes, VariableVendor},
};

/// Preserve the EFI status and DataSize on every outcome. The safe
/// convenience wrapper discards DataSize on errors other than BUFFER_TOO_SMALL
/// and slices its buffer before the caller can validate a returned size.
fn read(variable: Variable, buffer: &mut [u8]) -> Read {
    let name = CString16::try_from(variable.name()).expect("static variable name is UCS-2");
    let vendor = VariableVendor(
        variable
            .guid()
            .parse()
            .expect("static variable GUID is valid"),
    );
    let mut bytes = buffer.len();
    let mut attributes = VariableAttributes::empty();
    let table = uefi::table::system_table_raw().expect("UEFI entry initialized the system table");
    // SAFETY: called only before EBS while the runtime table remains identity
    // mapped. All output pointers and the exclusive data buffer are valid for
    // this one call. Empty size probes pass a null data pointer.
    let status = unsafe {
        let runtime = &*table.as_ref().runtime_services;
        (runtime.get_variable)(
            name.as_ptr().cast(),
            &vendor.0,
            &mut attributes,
            &mut bytes,
            if buffer.is_empty() {
                core::ptr::null_mut()
            } else {
                buffer.as_mut_ptr().cast()
            },
        )
    };
    Read {
        status: status.0 as u64,
        bytes,
        attributes: attributes.bits(),
    }
}

pub(super) fn capture(variable: Variable) -> Result<Capture, &'static str> {
    capture_with(variable, read, |bytes| {
        let page = boot::allocate_pages(
            boot::AllocateType::AnyPages,
            boot::MemoryType::LOADER_DATA,
            bytes.div_ceil(PAGE),
        )
        .map_err(|_| "firmware has no permanent Wi-Fi observation pages")?;
        // SAFETY: fresh exclusive reserved pages, never freed or given to the
        // guest allocator. The only mutation happens before publishing Capture.
        Ok(unsafe { core::slice::from_raw_parts_mut(page.as_ptr(), bytes) })
    })
}
