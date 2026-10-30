//! A driver's I/O port window that firmware AML may also reach, arbitrated
//! as Linux `i801_acpi_probe` arbitrates the i801 SMBus window: a SystemIO
//! handler at the device's scope performs AML's port accesses there and marks
//! the window firmware-owned once AML touches it. Where no handler can be
//! installed, [`Session::io_regions_overlapping`] gives what Linux
//! `acpi_check_resource_conflict` checks.
use super::{Error, Handle, Session, Status, checked};
use alloc::boxed::Box;
use core::{
    ffi::c_void,
    ops::Range,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};

/// `ACPI_ADR_SPACE_SYSTEM_IO`.
const SYSTEM_IO: u8 = 1;
/// `ACPI_IO_MASK` and `ACPI_WRITE`.
const IO_MASK: u32 = 1;
const WRITE: u32 = 1;
/// `ACPI_REGION_DEACTIVATE`.
const DEACTIVATE: u32 = 1;

unsafe extern "C" {
    fn acpi_os_read_port(port: u64, out: *mut u32, width: u32) -> Status;
    fn acpi_os_write_port(port: u64, value: u32, width: u32) -> Status;
    fn acpi_check_address_range(space: u8, address: u64, length: usize, warn: u8) -> u32;
}

/// The window and whether AML has touched it, shared with the handler.
struct Window {
    ports: Range<u64>,
    firmware: AtomicBool,
}

/// A window under AML arbitration. Once AML accesses it, firmware owns it
/// for the rest of the boot, as Linux's i801 then inhibits its own access.
pub struct IoWindow {
    window: &'static Window,
}

impl IoWindow {
    /// Whether AML has accessed the window, so its driver must not.
    pub fn firmware_owned(&self) -> bool {
        self.window.firmware.load(Ordering::Acquire)
    }
}

impl Handle<'_> {
    /// Install a SystemIO handler at this device's scope for `ports`, as
    /// Linux `i801_acpi_probe` installs `i801_acpi_io_handler`. The handler
    /// is never removed; its window lives for the rest of the boot.
    pub fn arbitrate_io(self, ports: Range<u16>) -> Result<IoWindow, Error> {
        let window: &'static Window = Box::leak(Box::new(Window {
            ports: u64::from(ports.start)..u64::from(ports.end),
            firmware: AtomicBool::new(false),
        }));
        // SAFETY: the context is leaked, so it outlives the handler, and the
        // callbacks perform only the port accesses AML asks for.
        unsafe {
            self.install_region(
                u32::from(SYSTEM_IO),
                system_io,
                setup,
                ptr::from_ref(window).cast_mut().cast(),
            )
        }?;
        Ok(IoWindow { window })
    }
}

impl Session {
    /// How many SystemIO operation regions overlap `ports`, as ACPICA's
    /// `acpi_check_address_range` counts them without its warning.
    pub fn io_regions_overlapping(&self, ports: Range<u16>) -> Result<u32, Error> {
        let guard = self.guard()?;
        // SAFETY: the namespace guard is held; ACPICA takes its own mutex.
        let overlaps = unsafe {
            acpi_check_address_range(
                SYSTEM_IO,
                u64::from(ports.start),
                usize::from(ports.end - ports.start),
                0,
            )
        };
        guard.check()?;
        Ok(overlaps)
    }
}

/// ACPICA's `acpi_ev_default_region_setup`: the region context is the
/// handler's while the region is active.
unsafe extern "C" fn setup(
    _: *mut c_void,
    function: u32,
    context: *mut c_void,
    out: *mut *mut c_void,
) -> Status {
    if out.is_null() {
        return super::BAD_PARAMETER.0;
    }
    // SAFETY: ACPICA passes a writable region context slot.
    unsafe {
        out.write(if function == DEACTIVATE {
            ptr::null_mut()
        } else {
            context
        })
    };
    0
}

/// Linux `i801_acpi_io_handler`: AML's first access inside the window marks
/// it firmware-owned; every access is performed as ACPICA's own SystemIO
/// handler performs it.
unsafe extern "C" fn system_io(
    function: u32,
    address: u64,
    width: u32,
    value: *mut u64,
    handler: *mut c_void,
    _: *mut c_void,
) -> Status {
    if handler.is_null() || value.is_null() {
        return super::BAD_PARAMETER.0;
    }
    // SAFETY: `arbitrate_io` installed this handler with its leaked window.
    let window = unsafe { &*handler.cast::<Window>() };
    if window.ports.contains(&address) {
        window.firmware.store(true, Ordering::Release);
    }
    if function & IO_MASK == WRITE {
        // SAFETY: ACPICA passes the value to write.
        unsafe { acpi_os_write_port(address, *value as u32, width) }
    } else {
        let mut read = 0;
        // SAFETY: ACPICA's OSL fills `read`.
        let status = unsafe { acpi_os_read_port(address, &mut read, width) };
        if checked(status).is_ok() {
            // SAFETY: ACPICA passes the output slot.
            unsafe { value.write(u64::from(read)) };
        }
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::acpi::{
        Mode,
        test_support::{TEST_SERIAL, reduced_hardware_fixture},
    };
    use alloc::vec::Vec;

    fn pkg(op: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = op.to_vec();
        bytes.push(body.len() as u8 + 1);
        bytes.extend(body);
        bytes
    }

    /// `\SMB0` with a byte field of a SystemIO region at 0xefa0..0xefc0 and a
    /// method reading it, and `\OTHR` with a region at 0xefb0..0xefb8.
    fn fixture() -> Vec<u8> {
        let mut device = b"SMB0".to_vec();
        device.extend(b"\x5b\x80SMBI\x01\x0b\xa0\xef\x0a\x20");
        device.extend(pkg(b"\x5b\x81", b"SMBI\x01HSTS\x08"));
        device.extend(pkg(b"\x14", b"RDST\x00\xa4HSTS"));
        let mut aml = pkg(b"\x5b\x82", &device);
        let mut other = b"OTHR".to_vec();
        other.extend(b"\x5b\x80OTHI\x01\x0b\xb0\xef\x0a\x08");
        aml.extend(pkg(b"\x5b\x82", &other));
        aml
    }

    #[test]
    fn aml_access_inside_the_window_hands_it_to_firmware() {
        let _serial = TEST_SERIAL.lock().unwrap();
        let provider = reduced_hardware_fixture(&fixture());
        // SAFETY: authored OSL services and the native singleton are serialized.
        let session = unsafe { Session::start(provider, Mode::InterpreterOnly) }.unwrap();
        assert_eq!(session.io_regions_overlapping(0xefa0..0xefc0), Ok(2));
        assert_eq!(session.io_regions_overlapping(0xefc0..0xefe0), Ok(0));
        let device = session.handle("\\SMB0").unwrap();
        let window = device.arbitrate_io(0xefa0..0xefc0).unwrap();
        assert!(!window.firmware_owned());
        // The fixture's OSL refuses port reads, so the method fails after
        // the handler marked the window.
        assert!(device.evaluate(Some("RDST"), &[]).is_err());
        assert!(window.firmware_owned());
        session.shutdown().unwrap();
    }
}
