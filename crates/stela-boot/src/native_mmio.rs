//! Native MMIO root publication. Firmware descriptions supply permissions;
//! exclusive device ownership is acquired separately by the native dispatcher.
//! [`Source`] serves the host drivers on every host processor through a
//! preallocated uncached aperture; [`ScopedSource`] binds the same aperture
//! to one processor's root epoch for the HPET, clock and stack diagnostics.
//! WC and dynamic roots refuse.
mod capture;
mod ecam;
mod shared;
pub(crate) mod shootdown;
use ecam::RootWindow;
#[cfg(feature = "diagnostics")]
pub(crate) mod diagnostic;
mod platform;

pub(crate) use capture::{Prepared, Wire};
pub(crate) use platform::{ExclusiveHpet, HpetMapping};
#[cfg(feature = "diagnostics")]
pub(crate) use platform::{QualifiedRam, RootPublication, ScopedSource};
pub(crate) use shared::{
    IoapicRegisters, IoapicUnit, NativeExclusiveHpet, NativeHpetMapping, PROCESSORS, Source,
};

use stela_drivers::bus::mmio::owned::Error;
const PAGE: u64 = 4096;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 2;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const APERTURE_OFFSET: u64 = 0x5_0000_0000;
const ENTRIES: usize = 512;

fn failed<T>(_: T) -> Error {
    Error::Unavailable
}

/// Borrow only the reserved capture produced by this handoff.
///
/// # Safety
/// The real post-EBS main owns this handoff and native physmap. Its loader
/// allocations remain pinned, and no source bytes have been reconstructed.
pub(crate) unsafe fn captured(handoff: &crate::handoff::Handoff) -> Result<&'static Wire, Error> {
    let region = handoff.native_mmio;
    if region.physical == 0
        || !region.physical.is_multiple_of(PAGE)
        || region.bytes != size_of::<Wire>().next_multiple_of(PAGE as usize) as u64
        || region.physical.checked_add(region.bytes).is_none()
    {
        return Err(Error::Unavailable);
    }
    // SAFETY: loader reserved this exact owned region; caller keeps
    // its physmap rather than treating the numeric PA as permission.
    let wire = unsafe { &*(crate::layout::physical(region.physical) as *const Wire) };
    if !wire.valid()
        || wire.root != handoff.root
        || !(region.physical..region.physical + region.bytes)
            .step_by(PAGE as usize)
            .all(|page| wire.table_owned(page))
    {
        return Err(Error::Unavailable);
    }
    Ok(wire)
}
