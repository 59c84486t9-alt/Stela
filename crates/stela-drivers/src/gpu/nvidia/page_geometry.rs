//! Original RM global page facts from an actual canonical RAM provider.
//! This publishes metadata only, never RAM, cache policy or RM readiness.
use crate::bus::dma::memory::{MemoryError, PageGeometry, PageSource};
use core::sync::atomic::{AtomicU32, Ordering};

const EMPTY: u32 = 0;
const INSTALLING: u32 = 1;
const READY: u32 = 2;
const BASE_SHIFT_FIELD: u32 = 8;
const MAX_SHIFT_FIELD: u32 = 16;
static PROFILE: AtomicU32 = AtomicU32::new(EMPTY);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Source(MemoryError),
    InvalidGeometry,
    UnsupportedGeometry,
    Unbound,
    Busy,
    Conflict,
    Native(u32),
}

unsafe extern "C" {
    fn stela_nvidia_set_page_geometry(base: u64, max: u64, mask: u64, shift: u8) -> u32;
}

fn encoded(geometry: PageGeometry) -> u32 {
    READY
        | u32::from(geometry.base_shift()) << BASE_SHIFT_FIELD
        | u32::from(geometry.max_shift()) << MAX_SHIFT_FIELD
}

fn decode(value: u32) -> Result<PageGeometry, Error> {
    match value {
        EMPTY => Err(Error::Unbound),
        INSTALLING => Err(Error::Busy),
        _ => PageGeometry::contiguous(
            (value >> BASE_SHIFT_FIELD) as u8,
            (value >> MAX_SHIFT_FIELD) as u8,
        )
        .map_err(|_| Error::InvalidGeometry),
    }
}

fn values(geometry: PageGeometry) -> Result<(u64, u64, u64, u8), Error> {
    // The current native allocation hook accepts only the configured base
    // granule. Never publish a broader original allocation capability mask.
    if geometry.max_shift() != geometry.base_shift() {
        return Err(Error::UnsupportedGeometry);
    }
    let base = u64::try_from(geometry.base_bytes()).map_err(|_| Error::InvalidGeometry)?;
    let max = u64::try_from(geometry.max_bytes()).map_err(|_| Error::InvalidGeometry)?;
    // The original supported-mask accessor doubles max before subtracting1.
    // Keep that arithmetic representable as well as the canonical usize extent.
    max.checked_mul(2).ok_or(Error::InvalidGeometry)?;
    let low = base.checked_sub(1).ok_or(Error::InvalidGeometry)?;
    Ok((base, max, !low, geometry.base_shift()))
}

fn install_with(
    state: &AtomicU32,
    source: &dyn PageSource,
    publish: impl FnOnce(PageGeometry, (u64, u64, u64, u8)) -> Result<(), u32>,
) -> Result<PageGeometry, Error> {
    let geometry = source.page_geometry().map_err(Error::Source)?;
    let native_values = values(geometry)?;
    let expected = encoded(geometry);
    match state.compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => {}
        Err(INSTALLING) => return Err(Error::Busy),
        Err(value) if value == expected => return Ok(geometry),
        Err(_) => return Err(Error::Conflict),
    }
    if let Err(status) = publish(geometry, native_values) {
        state.store(EMPTY, Ordering::Release);
        return Err(Error::Native(status));
    }
    state.store(expected, Ordering::Release);
    Ok(geometry)
}

/// Query the original global ABI's successfully published immutable profile.
/// This is metadata, not permission to activate RM or access a device.
pub fn installed() -> Result<PageGeometry, Error> {
    decode(PROFILE.load(Ordering::Acquire))
}

/// Publish once before any original RM/native page-fact consumer runs. Matching
/// repeats query the actual source but do not write the C data again. Unknown
/// providers, concurrent installation and conflicting profiles explicitly fail.
/// Multi-granule profiles are unsupported by the current native page producer
/// and fail before publication; the actual source profile is never narrowed.
/// No reset/uninstall is provided: all native callers share these original globals.
///
/// # Safety
/// `source` must be the actual native RAM provider, with truthful immutable
/// geometry for every RM device using these facts. Exclude all original C/RM
/// callers throughout the initial installation; plain original global reads
/// must never race these writes. Keep the native profile stable for the entire
/// RM lifetime, including every allocation/mapping/retained quarantine. Calls
/// obey the provider's real process/context rules and cannot unwind or reenter
/// native RM. This does not establish a heap, physical mapping, cache policy,
/// DMA domain, IRQ context or complete RM initialization.
pub unsafe fn install(source: &dyn PageSource) -> Result<PageGeometry, Error> {
    install_with(&PROFILE, source, |_, (base, max, mask, shift)| {
        // SAFETY: install's caller excludes all original readers. The single
        // publisher owns this initial write; helper errors mutate no C data.
        let status = unsafe { stela_nvidia_set_page_geometry(base, max, mask, shift) };
        if status == 0 { Ok(()) } else { Err(status) }
    })
}

fn check_with(
    state: &AtomicU32,
    source: &dyn PageSource,
    shift: u8,
) -> Result<PageGeometry, Error> {
    let geometry = source.page_geometry().map_err(Error::Source)?;
    values(geometry)?;
    if geometry != decode(state.load(Ordering::Acquire))? || shift != geometry.base_shift() {
        return Err(Error::Conflict);
    }
    Ok(geometry)
}

pub(super) fn check_source(source: &dyn PageSource, shift: u8) -> Result<PageGeometry, Error> {
    check_with(&PROFILE, source, shift)
}

#[cfg(test)]
pub(super) mod tests;
