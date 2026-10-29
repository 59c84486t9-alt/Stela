//! Firmware-only PCI_IO observation. This supplies no native hardware grant.
//! Provenance: UEFI 2.11 chapter14, sections14.4.1/.8/.16/.18.
//! https://uefi.org/specs/UEFI/2.11/14_Protocols_PCI_Bus_Support.html
//! All callbacks and returned pool storage must end before ExitBootServices.
use alloc::vec::Vec;
use core::{
    ffi::c_void,
    mem::{offset_of, size_of},
    ptr::{self, NonNull},
};
use uefi::{Status, proto::unsafe_protocol};

// Unused slots are opaque pointer-sized fields, never invoked. They preserve
// the protocol's exact EFI_PCI_IO_PROTOCOL_ACCESS pairs and vtable ordering.
type Read = unsafe extern "efiapi" fn(*mut PciIo, u32, u32, usize, *mut c_void) -> Status;
type Location =
    unsafe extern "efiapi" fn(*mut PciIo, *mut usize, *mut usize, *mut usize, *mut usize) -> Status;
type BarAttributes =
    unsafe extern "efiapi" fn(*mut PciIo, u8, *mut u64, *mut *mut c_void) -> Status;
#[repr(C)]
#[unsafe_protocol("4cf5b200-68b8-4ca5-9eec-b23e3f50029a")]
pub struct PciIo {
    poll_mem_poll_io_mem_io: [usize; 6],
    config_read: Read,
    config_write_copy_map_unmap_alloc_free_flush: [usize; 7],
    location: Location,
    attributes: usize,
    bar_attributes: BarAttributes,
    set_bar_attributes: usize,
    rom_size: u64,
    rom_image: *mut c_void,
}
// This binary is x86-64 only; EFIAPI uses that target's actual UEFI ABI.
const _: () = {
    assert!(size_of::<usize>() == 8);
    assert!(size_of::<PciIo>() == 160);
    assert!(offset_of!(PciIo, config_read) == 48);
    assert!(offset_of!(PciIo, location) == 112);
    assert!(offset_of!(PciIo, bar_attributes) == 128);
    assert!(offset_of!(PciIo, rom_size) == 144);
};
use stela_drivers::bus::pci::Address;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Firmware(Status),
    Location,
    BarIndex,
    MissingResources,
    DescriptorTag(u8),
    DescriptorLength,
    DescriptorRange,
    Descriptor(DescriptorError),
    Checksum,
    Allocation,
    Release(Status),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Firmware(status) => write!(f, "firmware status {status:?}"),
            Self::Location => f.write_str("invalid firmware PCI location"),
            Self::BarIndex => f.write_str("invalid BAR index"),
            Self::MissingResources => f.write_str("successful BAR call returned no pool buffer"),
            Self::DescriptorTag(tag) => write!(f, "unsupported descriptor tag {tag:#x}"),
            Self::DescriptorLength => f.write_str("invalid descriptor wire length"),
            Self::DescriptorRange => f.write_str("descriptor span overflow"),
            Self::Descriptor(error) => write!(f, "resource descriptor refused: {error:?}"),
            Self::Checksum => f.write_str("resource descriptor checksum mismatch"),
            Self::Allocation => f.write_str("resource observation allocation failed"),
            Self::Release(status) => write!(f, "resource pool release failed: {status:?}"),
        }
    }
}
pub use stela_boot_core::firmware_pci::BarRegion;
use stela_boot_core::firmware_pci::{DescriptorError, decode_qword};
fn status(value: Status) -> Result<(), Error> {
    if value.is_success() {
        Ok(())
    } else {
        Err(Error::Firmware(value))
    }
}
impl PciIo {
    // Only a live ScopedProtocol obtained from actual firmware can construct a
    // usable borrow; no copy of this callback-bearing object enters a Handoff.
    pub fn address(&mut self) -> Result<Address, Error> {
        let (mut segment, mut bus, mut device, mut function) = (0, 0, 0, 0);
        // SAFETY: original scoped firmware protocol, actual EFIAPI signature,
        // writable local UINTN outputs; boot services remain active.
        status(unsafe {
            (self.location)(self, &mut segment, &mut bus, &mut device, &mut function)
        })?;
        if device >= 32 || function >= 8 {
            return Err(Error::Location);
        }
        Ok(Address {
            segment: segment.try_into().map_err(|_| Error::Location)?,
            bus: bus.try_into().map_err(|_| Error::Location)?,
            device: device as u8,
            function: function as u8,
        })
    }
    pub fn read_header(&mut self) -> Result<[u8; 64], Error> {
        let mut header = [0; 64];
        // Width0=EfiPciIoWidthUint8, count64 actual bytes; no raw ECAM access.
        // SAFETY: live boot protocol and bounded writable local output; the
        // firmware performs its own controller/configuration addressing.
        status(unsafe {
            (self.config_read)(self, 0, 0, header.len(), header.as_mut_ptr().cast())
        })?;
        Ok(header)
    }
    pub fn bar_regions(&mut self, index: u8) -> Result<Vec<BarRegion>, Error> {
        if index >= 6 {
            return Err(Error::BarIndex);
        }
        let mut raw = ptr::null_mut();
        // SAFETY: actual live EFIAPI protocol; Resources is a writable VOID**.
        // Supports is optional and unused. A successful response is a firmware
        // pool allocation containing a complete EndTag-terminated resource list.
        status(unsafe { (self.bar_attributes)(self, index, ptr::null_mut(), &mut raw) })?;
        let raw = NonNull::new(raw.cast::<u8>()).ok_or(Error::MissingResources)?;
        // SAFETY: successful protocol contract supplies the original complete
        // descriptor allocation. Only exact protocol-described records are read.
        let result = unsafe { copy_regions(raw) };
        // FreePool happens even for a refused descriptor; explicit failure is
        // returned instead of hiding release status in an infallible Drop.
        // SAFETY: original successful pool allocation, copied records own all
        // returned DATA and hold no firmware pointers. This is called once even
        // when copy_regions refuses the descriptor. On FreePool failure the
        // actual pool remains firmware-owned and caller must stop preparation.
        unsafe { uefi::boot::free_pool(raw) }.map_err(|error| Error::Release(error.status()))?;
        result
    }
}
/// # Safety
/// `base` is the original successful GetBarAttributes pool allocation and
/// contains its complete valid readable EndTag-terminated descriptor chain.
/// Firmware callback lifetime is still active. No synthetic slice length is
/// invented; malformed headers are refused before reading a descriptor body.
unsafe fn copy_regions(base: NonNull<u8>) -> Result<Vec<BarRegion>, Error> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    let mut checksum = 0u8;
    loop {
        // SAFETY: caller retains the protocol's complete descriptor chain;
        // offset advances only by checked lengths of specified descriptors.
        let tag = unsafe { base.as_ptr().add(offset).read() };
        match tag {
            0x79 => {
                let end = offset
                    .checked_add(2)
                    .filter(|n| *n <= isize::MAX as usize)
                    .ok_or(Error::DescriptorRange)?;
                // SAFETY: the actual small EndTag record has its checksum byte.
                let value = unsafe { base.as_ptr().add(end - 1).read() };
                if value != 0 && checksum.wrapping_add(tag).wrapping_add(value) != 0 {
                    return Err(Error::Checksum);
                }
                return Ok(result);
            }
            0x8a => {
                let end = offset
                    .checked_add(46)
                    .filter(|n| *n <= isize::MAX as usize)
                    .ok_or(Error::DescriptorRange)?;
                // SAFETY: the large-record header is part of the chain.
                let length = unsafe {
                    u16::from_le_bytes([
                        base.as_ptr().add(offset + 1).read(),
                        base.as_ptr().add(offset + 2).read(),
                    ])
                };
                if length != 43 {
                    return Err(Error::DescriptorLength);
                }
                let mut bytes = [0; 46];
                // SAFETY: exact standard-sized record after validated header;
                // local output is distinct and has exactly46 writable bytes.
                unsafe {
                    ptr::copy_nonoverlapping(
                        base.as_ptr().add(offset),
                        bytes.as_mut_ptr(),
                        bytes.len(),
                    );
                }
                let observed = decode_qword(&bytes).map_err(Error::Descriptor)?;
                result.try_reserve(1).map_err(|_| Error::Allocation)?;
                result.push(observed);
                checksum = bytes
                    .iter()
                    .fold(checksum, |sum, byte| sum.wrapping_add(*byte));
                offset = end;
            }
            other => return Err(Error::DescriptorTag(other)),
        }
    }
}

/// No handles/protocol pointers escape this firmware-only census. All native
/// functions (including those without a firmware handle) must still be found
/// through the later actual-root configuration factory and identity rechecked.
pub struct Census {
    pub functions: Vec<FunctionObservation>,
    pub failures: Vec<CaptureFailure>,
}
pub struct FunctionObservation {
    pub address: Address,
    pub header: [u8; 64],
    // A missing/unimplemented BAR is preserved as the actual firmware status;
    // it is not turned into an empty device or a guessed identity translation.
    pub bars: [Result<Vec<BarRegion>, Error>; 6],
}
impl FunctionObservation {
    /// Copied firmware fields, to be revalidated under a real native owner.
    pub fn identity(&self) -> stela_drivers::bus::pci::Identity {
        let word = |offset| u16::from_le_bytes([self.header[offset], self.header[offset + 1]]);
        stela_drivers::bus::pci::Identity {
            address: self.address,
            vendor: word(0),
            device: word(2),
            class: [self.header[11], self.header[10], self.header[9]],
        }
    }
}
#[derive(Debug)]
pub enum CaptureFailure {
    Enumeration(Status),
    Open(Status),
    Function(Error),
    Allocation,
}
pub fn capture() -> Result<Census, CaptureFailure> {
    use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
    let handles = boot::find_handles::<PciIo>()
        .map_err(|error| CaptureFailure::Enumeration(error.status()))?;
    let mut result = Census {
        functions: Vec::new(),
        failures: Vec::new(),
    };
    // Reserve before starting callbacks, so an allocation refusal never leaves
    // a protocol, returned pool allocation or callback-bearing token retained.
    result
        .functions
        .try_reserve_exact(handles.len())
        .map_err(|_| CaptureFailure::Allocation)?;
    result
        .failures
        .try_reserve_exact(handles.len())
        .map_err(|_| CaptureFailure::Allocation)?;
    for handle in handles {
        // SAFETY: GetProtocol is the actual firmware's scoped instance. This
        // consumer only reads header/GetLocation/GetBarAttributes; the firmware
        // retains controller driving/reset authority until actual EBS handoff.
        // All borrowed callbacks and returned pool storage end in this loop.
        let mut protocol = match unsafe {
            boot::open_protocol::<PciIo>(
                OpenProtocolParams {
                    handle,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        } {
            Ok(protocol) => protocol,
            Err(error) => {
                result.failures.push(CaptureFailure::Open(error.status()));
                continue;
            }
        };
        let address = match protocol.address() {
            Ok(address) => address,
            Err(error) => {
                result.failures.push(CaptureFailure::Function(error));
                continue;
            }
        };
        let header = match protocol.read_header() {
            Ok(header) => header,
            Err(error) => {
                result.failures.push(CaptureFailure::Function(error));
                continue;
            }
        };
        let bars = core::array::from_fn(|bar| protocol.bar_regions(bar as u8));
        // FreePool refusal cannot be followed by EBS as though reclamation had
        // succeeded. Caller stops preparation with the actual status retained.
        if let Some(status) = bars.iter().find_map(|bar| match bar {
            Err(Error::Release(status)) => Some(*status),
            _ => None,
        }) {
            return Err(CaptureFailure::Function(Error::Release(status)));
        }
        result.functions.push(FunctionObservation {
            address,
            header,
            bars,
        });
    }
    Ok(result)
}

impl core::fmt::Display for CaptureFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Enumeration(status) => write!(f, "enumerate protocol: {status:?}"),
            Self::Open(status) => write!(f, "open protocol: {status:?}"),
            Self::Function(error) => write!(f, "observe function: {error}"),
            Self::Allocation => f.write_str("protocol census allocation failed"),
        }
    }
}
