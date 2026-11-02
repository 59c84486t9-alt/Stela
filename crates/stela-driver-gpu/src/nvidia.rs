//! Native NVIDIA OS hooks for PCI, CPU metadata, RAM pins/views and DMA leases;
//! enabling this port does not initialize a GPU or expose a Metal device.
use crate::bus::pci::{ConfigError, ConfigSpace};
use core::{cell::Cell, ffi::c_void, marker::PhantomData, marker::PhantomPinned, pin::Pin};

pub mod allocation;
pub mod device;
mod dma;
pub mod firmware;
mod memory;
pub mod mmio;
pub mod page_geometry;
pub mod services;

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
    // Rust-only tail; C sees the unchanged original three-word prefix.
    target: *mut c_void,
    failure: Cell<Option<ConfigError>>,
    _borrow: PhantomData<&'a mut ()>,
    _pin: PhantomPinned,
}

impl<'a> PciHandle<'a> {
    pub fn new<C: ConfigSpace>(config: &'a mut C) -> Self {
        Self {
            context: core::ptr::null_mut(),
            read: read::<C>,
            write: write::<C>,
            target: (config as *mut C).cast(),
            failure: Cell::new(None),
            _borrow: PhantomData,
            _pin: PhantomPinned,
        }
    }

    /// The first transport failure is terminal, including a failed after-write
    /// validation. Native status cannot erase its typed cause. Keep the original
    /// configuration owner until its separate retirement contract is fulfilled.
    pub fn failure(&self) -> Option<ConfigError> {
        self.failure.get()
    }

    /// Pointer accepted by the vendor's `os_pci_{read,write}_*` hooks.
    ///
    /// # Safety
    ///
    /// All C users must stop before the pinned handle is dropped. Serialize
    /// calls, including reads, and prevent callback reentry. C must not modify
    /// the handle or use this pointer for another OS hook such as reset/removal.
    /// After each native operation inspect failure() and report its exact cause;
    /// the first transport failure closes this handle permanently. In particular,
    /// WriteMayHaveApplied cannot authorize retry, rollback or owner release.
    pub unsafe fn as_raw(self: Pin<&mut Self>) -> *mut c_void {
        // SAFETY: obtain the pointer without moving the pinned object.
        let this = unsafe { self.get_unchecked_mut() };
        let pointer = this as *mut Self;
        // Standalone handles acquire their self-context only after pinning.
        // Owned-device callbacks instead keep their original Bundle context.
        if !this.target.is_null() {
            this.context = pointer.cast();
        }
        pointer.cast()
    }
}

fn valid_access(offset: u32, width: u32) -> bool {
    matches!(width, 1 | 2 | 4) && offset < PCI_CONFIG_BYTES && offset.is_multiple_of(width)
}

fn read_config<C: ConfigSpace>(config: &C, offset: u16, width: u32) -> Result<u32, ConfigError> {
    match width {
        1 => config.read8(offset).map(u32::from),
        2 => config.read16(offset).map(u32::from),
        _ => config.read32(offset),
    }
}
fn write_config<C: ConfigSpace>(
    config: &mut C,
    offset: u16,
    width: u32,
    value: u32,
) -> Result<(), ConfigError> {
    match width {
        1 => config.write8(offset, value as u8),
        2 => config.write16(offset, value as u16),
        _ => config.write32(offset, value),
    }
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
    // SAFETY: as_raw binds this exact pinned handle; exclusive C callbacks
    // serialize the live borrowed config and its disjoint terminal latch.
    let this = unsafe { &*context.cast::<PciHandle<'_>>() };
    if this.failure.get().is_some() {
        return 0;
    }
    // SAFETY: target is the same exclusively borrowed C stored by new.
    let config = unsafe { &*this.target.cast::<C>() };
    match read_config(config, offset as u16, width) {
        Ok(result) => {
            // SAFETY: the C shim supplies its live aligned u32.
            unsafe { value.write(result) };
            1
        }
        Err(error) => {
            this.failure.set(Some(error));
            0
        }
    }
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
    // SAFETY: same pinned, exclusive, serialized context as read.
    let this = unsafe { &*context.cast::<PciHandle<'_>>() };
    if this.failure.get().is_some() {
        return 0;
    }
    // SAFETY: callbacks serialize this same exclusive mutable C target.
    let config = unsafe { &mut *this.target.cast::<C>() };
    match write_config(config, offset as u16, width, value) {
        Ok(()) => 1,
        Err(error) => {
            this.failure.set(Some(error));
            0
        }
    }
}

// The native C header checks the corresponding fixed prefix. No Rust trait
// object, reference representation or Rust-only tail crosses this boundary.
const _: () = {
    // Only the fixed prefix crosses C; the Rust-only tail never does.
    assert!(core::mem::offset_of!(PciHandle<'_>, context) == 0);
    assert!(core::mem::offset_of!(PciHandle<'_>, target) == 3 * core::mem::size_of::<usize>());
    assert!(core::mem::offset_of!(PciHandle<'_>, read) == core::mem::size_of::<usize>());
    assert!(core::mem::offset_of!(PciHandle<'_>, write) == 2 * core::mem::size_of::<usize>());
};

#[cfg(test)]
mod tests;
