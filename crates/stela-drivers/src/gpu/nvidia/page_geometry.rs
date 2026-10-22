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
pub(super) mod tests {
    use super::*;
    use crate::bus::dma::memory::{CacheAttribute, PinnedPages};
    use alloc::string::ToString;
    use core::cell::Cell;
    extern crate std;

    struct Source(Result<PageGeometry, MemoryError>, Cell<usize>);
    impl PageSource for Source {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            self.1.set(self.1.get() + 1);
            self.0
        }
        fn allocate(
            &self,
            _: usize,
            _: usize,
            _: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            panic!("geometry queries must not allocate pages");
        }
    }

    /// One explicit CPU-model source profile per test process. No production
    /// default is supplied, and tests cannot reset already published original data.
    pub(crate) fn initialize_model(shift: u8) {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let source = Source(PageGeometry::base_only(shift), Cell::new(0));
            // SAFETY: this fresh hosted test process has no original RM callers;
            // only explicit RAM models use the immutable test source profile.
            unsafe { install(&source).unwrap() };
        });
        assert_eq!(
            installed().unwrap(),
            PageGeometry::base_only(shift).unwrap()
        );
    }

    /// Original 16KiB-native RAM models run unchanged in fresh processes instead of
    /// changing global native geometry while other 4KiB models retain allocations.
    pub(crate) fn separate_model_process(test: &str, shift: u8) -> bool {
        const VARIABLE: &str = "STELA_NVIDIA_PAGE_GEOMETRY_MODEL";
        if let Ok(value) = std::env::var(VARIABLE) {
            assert_eq!(value, shift.to_string());
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env(VARIABLE, shift.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && std::string::String::from_utf8_lossy(&output.stdout)
                    .contains("1 passed; 0 failed;"),
            "{}{}",
            std::string::String::from_utf8_lossy(&output.stdout),
            std::string::String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    #[test]
    fn actual_queries_precede_publication_and_unknown_sources_never_install_defaults() {
        let state = AtomicU32::new(EMPTY);
        let unknown = Source(Err(MemoryError::Unavailable), Cell::new(0));
        assert_eq!(
            install_with(&state, &unknown, |_, _| panic!("unknown provider")),
            Err(Error::Source(MemoryError::Unavailable))
        );
        assert_eq!(decode(state.load(Ordering::Acquire)), Err(Error::Unbound));
        let broad = Source(PageGeometry::contiguous(12, 14), Cell::new(0));
        assert_eq!(
            install_with(&state, &broad, |_, _| panic!("unsupported publisher")),
            Err(Error::UnsupportedGeometry)
        );
        assert_eq!(state.load(Ordering::Acquire), EMPTY);
        let source = Source(PageGeometry::base_only(12), Cell::new(0));
        assert_eq!(check_with(&state, &source, 12), Err(Error::Unbound));
        assert_eq!(
            install_with(&state, &source, |_, native| {
                assert_eq!(native, (4096, 4096, !4095, 12));
                assert_eq!(decode(state.load(Ordering::Acquire)), Err(Error::Busy));
                assert_eq!(
                    install_with(&state, &source, |_, _| panic!("reentrant publisher")),
                    Err(Error::Busy)
                );
                Ok(())
            }),
            PageGeometry::base_only(12).map_err(Error::Source)
        );
        assert_eq!(source.1.get(), 3);
        assert_eq!(check_with(&state, &source, 14), Err(Error::Conflict));
        assert_eq!(check_with(&state, &source, 12).unwrap(), source.0.unwrap());
        assert_eq!(
            install_with(&state, &source, |_, _| panic!("duplicate publication")),
            PageGeometry::base_only(12).map_err(Error::Source)
        );
        assert_eq!(
            install_with(&state, &unknown, |_, _| panic!("unknown repeat")),
            Err(Error::Source(MemoryError::Unavailable))
        );
        let conflict = Source(PageGeometry::contiguous(12, 14), Cell::new(0));
        assert_eq!(
            install_with(&state, &conflict, |_, _| panic!("conflicting publisher")),
            Err(Error::UnsupportedGeometry)
        );
        assert_eq!(
            check_with(&state, &conflict, 12),
            Err(Error::UnsupportedGeometry)
        );
        assert_eq!(
            decode(state.load(Ordering::Acquire)).unwrap(),
            source.0.unwrap()
        );
    }

    #[test]
    fn failed_native_publication_is_retryable_and_range_values_preserve_original_mask_arithmetic() {
        let state = AtomicU32::new(EMPTY);
        let source = Source(PageGeometry::base_only(14), Cell::new(0));
        assert_eq!(
            install_with(&state, &source, |_, _| Err(0x40)),
            Err(Error::Native(0x40))
        );
        assert_eq!(state.load(Ordering::Acquire), EMPTY);
        assert_eq!(
            install_with(&state, &source, |geometry, (base, max, mask, shift)| {
                assert_eq!((base, max, mask, shift), (16384, 16384, !16383, 14));
                let supported = ((max << 1) - 1) & !(base - 1);
                for candidate in 0..64 {
                    assert_eq!(
                        supported & (1u64 << candidate) != 0,
                        geometry.supports(candidate)
                    );
                }
                Ok(())
            }),
            source.0.map_err(Error::Source)
        );
        let largest = PageGeometry::base_only((usize::BITS - 2) as u8).unwrap();
        assert!(values(largest).unwrap().1.checked_mul(2).is_some());
    }
}
