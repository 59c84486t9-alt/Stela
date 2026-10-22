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
    fn allocate(&self, _: usize, _: usize, _: CacheAttribute) -> Result<PinnedPages, MemoryError> {
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
            && std::string::String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"),
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
