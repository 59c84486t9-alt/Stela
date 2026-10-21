//! Native NVIDIA OS hooks for PCI configuration, CPU metadata and RAM views;
//! enabling this port does not initialize a GPU or expose a Metal device.
use crate::bus::pci::ConfigSpace;
use core::{ffi::c_void, marker::PhantomData, marker::PhantomPinned, pin::Pin};

pub mod allocation;
mod memory;

const PCI_CONFIG_BYTES: u32 = 4096;

/// A native RM PCI handle borrowing one physical function's configuration space.
/// Pin before giving it to C. Its borrow excludes other Rust access until drop;
/// it is neither Send nor Sync. No allocations, registry or guest ABI is involved.
/// The device owner chooses stack or heap storage and the synchronization policy.
#[repr(C)]
pub struct PciHandle<'a> {
    context: *mut c_void,
    read: unsafe extern "C" fn(*mut c_void, u32, u32, *mut u32) -> u32,
    write: unsafe extern "C" fn(*mut c_void, u32, u32, u32) -> u32,
    _borrow: PhantomData<&'a mut ()>,
    _pin: PhantomPinned,
}

impl<'a> PciHandle<'a> {
    pub fn new<C: ConfigSpace>(config: &'a mut C) -> Self {
        Self {
            context: (config as *mut C).cast(),
            read: read::<C>,
            write: write::<C>,
            _borrow: PhantomData,
            _pin: PhantomPinned,
        }
    }

    /// Pointer accepted by the vendor's `os_pci_{read,write}_*` hooks.
    ///
    /// # Safety
    ///
    /// All C users must stop before the pinned handle is dropped. Serialize
    /// calls, including reads, and prevent callback reentry. C must not modify
    /// the handle or use this pointer for another OS hook such as reset/removal.
    pub unsafe fn as_raw(self: Pin<&mut Self>) -> *mut c_void {
        // SAFETY: obtain the pointer without moving the pinned object.
        unsafe { self.get_unchecked_mut() as *mut Self }.cast()
    }
}

fn valid_access(offset: u32, width: u32) -> bool {
    matches!(width, 1 | 2 | 4) && offset < PCI_CONFIG_BYTES && offset.is_multiple_of(width)
}

unsafe extern "C" fn read<C: ConfigSpace>(
    context: *mut c_void,
    offset: u32,
    width: u32,
    value: *mut u32,
) -> u32 {
    if !valid_access(offset, width) {
        return 0;
    }
    // SAFETY: PciHandle exclusively borrows a live C; its C caller serializes
    // callbacks and supplies a writable u32. The validated offset fits u16.
    let config = unsafe { &*context.cast::<C>() };
    let offset = offset as u16;
    let result = match width {
        1 => u32::from(config.read8(offset)),
        2 => u32::from(config.read16(offset)),
        _ => config.read32(offset),
    };
    // SAFETY: the C shim supplies its live, aligned local u32.
    unsafe { value.write(result) };
    1
}

unsafe extern "C" fn write<C: ConfigSpace>(
    context: *mut c_void,
    offset: u32,
    width: u32,
    value: u32,
) -> u32 {
    if !valid_access(offset, width) {
        return 0;
    }
    // SAFETY: PciHandle exclusively borrows a live C and the C caller serializes
    // callbacks. The validated offset fits u16; subword values are truncated.
    let config = unsafe { &mut *context.cast::<C>() };
    let offset = offset as u16;
    match width {
        1 => config.write8(offset, value as u8),
        2 => config.write16(offset, value as u16),
        _ => config.write32(offset, value),
    }
    1
}

// The native C header checks the corresponding layout. No Rust trait object
// or reference representation crosses this boundary.
const _: () = {
    assert!(core::mem::size_of::<PciHandle<'_>>() == 3 * core::mem::size_of::<usize>());
    assert!(core::mem::offset_of!(PciHandle<'_>, read) == core::mem::size_of::<usize>());
    assert!(core::mem::offset_of!(PciHandle<'_>, write) == 2 * core::mem::size_of::<usize>());
};

#[cfg(test)]
mod tests;
