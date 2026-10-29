use super::*;
use crate::bus::{
    mmio::owned::Error as MappingError,
    pci::{
        ConfigSpace,
        owned::tests::{fixture, fixture_pointer},
    },
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

const ADDRESS: Address = Address {
    segment: 7,
    bus: 32,
    device: 2,
    function: 3,
};
struct Exclusion(Arc<AtomicUsize>);
impl Drop for Exclusion {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn setup() -> (
    Function<OwnedConfig>,
    Arc<super::super::owned::tests::Counters>,
    Arc<AtomicUsize>,
) {
    let (mut config, counters) = fixture(ADDRESS);
    config.write32(0, 0x1234_8086);
    config.write32(8, 0x03000012);
    config.write8(0x0e, 0x80);
    (
        Function::new(ADDRESS, config).unwrap(),
        counters,
        Arc::new(AtomicUsize::new(0)),
    )
}
fn attach(function: Function<OwnedConfig>, drops: Arc<AtomicUsize>) -> NativeFunction {
    // SAFETY: sole fixture config writer/exclusion and no device/worker.
    match unsafe { NativeFunction::attach(function, Box::new(Exclusion(drops))) } {
        Ok(owner) => owner,
        Err((error, _)) => panic!("fixture attach: {error:?}"),
    }
}

#[test]
fn observed_identity_and_native_narrow_effects_return_original_owners() {
    let (mut function, counters, drops) = setup();
    // Cached mutable discovery metadata cannot grant native device identity.
    function.vendor = 1;
    function.device = 2;
    function.class = [9; 3];
    let mut owner = attach(function, drops.clone());
    let description = owner.description().unwrap();
    assert_eq!(description.address, ADDRESS);
    assert_eq!((description.vendor, description.device), (0x8086, 0x1234));
    assert_eq!(description.class_revision, 0x03000012);
    owner.write(4, 4, 0xa5c3_0102).unwrap();
    owner.write(4, 2, 0x3344).unwrap();
    owner.write(5, 1, 0x77).unwrap();
    assert_eq!(owner.read(4, 4), Ok(0xa5c3_7744));
    assert_eq!(owner.read(6, 2), Ok(0xa5c3));
    owner.write(4095, 1, 0x56).unwrap();
    assert_eq!(owner.read(4095, 1), Ok(0x56));
    // SAFETY: isolated fixture never publishes DMA/IRQ/callbacks.
    let (function, exclusion) = match unsafe { owner.release() } {
        Ok(parts) => parts,
        Err(_) => panic!("live isolated release"),
    };
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(exclusion);
    let mut mapping = function.into_config().into_mapping();
    // SAFETY: original fixture accesses and retention are fully stopped.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
}

#[test]
fn bad_access_refuses_before_context_or_bytes_and_does_not_poison() {
    let (function, counters, drops) = setup();
    let mut owner = attach(function, drops);
    let before = counters.contexts.load(Ordering::Relaxed);
    for (offset, width) in [
        (0, 0),
        (0, 3),
        (1, 2),
        (2, 4),
        (4095, 2),
        (4096, 1),
        (u16::MAX, 4),
    ] {
        assert_eq!(
            owner.read(offset, width),
            Err(Error::Access { offset, width })
        );
        assert_eq!(
            owner.write(offset, width, 0),
            Err(Error::Access { offset, width })
        );
    }
    assert_eq!(counters.contexts.load(Ordering::Relaxed), before);
    assert_eq!(owner.failure(), None);
    assert_eq!(owner.read(0, 4), Ok(0x1234_8086));
}

#[test]
fn post_write_context_uncertainty_retains_effect_and_all_original_owners() {
    let (mut function, counters, drops) = setup();
    let pointer = fixture_pointer(function.config(), 0x40);
    let mut owner = attach(function, drops.clone());
    // The model context fails only after seeing this real CPU store;
    // it does not depend on an incidental count of preflight observations.
    counters
        .fail_after_value
        .store(0x7654_3210, Ordering::Relaxed);
    counters.fail_after_word.store(0x41, Ordering::Relaxed);
    let error = Error::Config(ConfigError::Mapping(MappingError::Unavailable));
    assert_eq!(owner.write(0x40, 4, 0x7654_3210), Err(error));
    assert_eq!(
        // SAFETY: isolated sequential fixture pointer, no device/reference aliases.
        unsafe { pointer.cast::<u32>().as_ptr().read_volatile() },
        0x7654_3210
    );
    let before = counters.contexts.load(Ordering::Relaxed);
    assert_eq!(owner.read(0, 4), Err(error));
    assert_eq!(owner.write(0x40, 4, 0), Err(error));
    // SAFETY: probe refuses release despite fixture being physically idle.
    let owner = match unsafe { owner.release() } {
        Err(owner) => owner,
        Ok(_) => panic!("uncertain release"),
    };
    assert_eq!(counters.contexts.load(Ordering::Relaxed), before);
    drop(owner);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
}

#[test]
fn identity_change_latches_and_rejection_returns_exact_original_exclusion() {
    let (function, counters, drops) = setup();
    let mut owner = attach(function, drops.clone());
    // RAM allows this identity store: model a post-effect epoch replacement.
    assert_eq!(owner.write(0, 4, 0x9999_8086), Err(Error::IdentityChanged));
    let before = counters.contexts.load(Ordering::Relaxed);
    assert_eq!(owner.read(4, 2), Err(Error::IdentityChanged));
    assert_eq!(counters.contexts.load(Ordering::Relaxed), before);
    drop(owner);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    let (mut function, _, drops) = setup();
    function.address.bus += 1;
    // SAFETY: deliberate negative metadata mismatch with isolated real owners.
    let (error, (function, exclusion)) =
        match unsafe { NativeFunction::attach(function, Box::new(Exclusion(drops.clone()))) } {
            Err(error) => error,
            Ok(_) => panic!("false address accepted"),
        };
    assert_eq!(error, Error::IdentityChanged);
    assert_eq!(function.into_config().address(), ADDRESS);
    drop(exclusion);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

struct NoPages;
impl PageSource for NoPages {
    fn allocate(
        &self,
        _: usize,
        _: usize,
        _: crate::bus::dma::memory::CacheAttribute,
    ) -> Result<crate::bus::dma::memory::PinnedPages, crate::bus::dma::memory::MemoryError> {
        panic!("root pairing must not allocate RAM")
    }
}
struct BoundDomain {
    binding: crate::bus::pci::requester::RequesterBinding,
    generation: core::sync::atomic::AtomicU64,
}
// SAFETY: this fixture exercises only canonical pairing; no map/sync operation
// succeeds or publishes an invented translation/coherence capability.
unsafe impl DmaDomain for BoundDomain {
    unsafe fn map(
        &self,
        _: &crate::bus::dma::pages::DmaPages,
        _: crate::bus::dma::mapping::Direction,
        _: u64,
    ) -> Result<crate::bus::dma::mapping::DomainMapping, DmaError> {
        Err(DmaError::IommuUnavailable)
    }
    unsafe fn unmap(&self, _: crate::bus::dma::mapping::DomainMapping) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_device(
        &self,
        _: crate::bus::dma::mapping::DomainMapping,
        _: core::ops::Range<usize>,
        _: crate::bus::dma::mapping::Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
    unsafe fn sync_for_cpu(
        &self,
        _: crate::bus::dma::mapping::DomainMapping,
        _: core::ops::Range<usize>,
        _: crate::bus::dma::mapping::Direction,
    ) -> Result<(), DmaError> {
        Err(DmaError::Unmapped)
    }
}
// SAFETY: check consumes and compares the canonical fixture binding.
unsafe impl PciDmaDomain for BoundDomain {
    fn check_configuration(&self, config: &OwnedConfig) -> Result<u64, DmaError> {
        self.binding
            .check_live()
            .map_err(|_| DmaError::MappingFailed)?;
        if !config
            .matches_binding(&self.binding)
            .map_err(|_| DmaError::MappingFailed)?
        {
            return Err(DmaError::IommuUnavailable);
        }
        Ok(self.generation.load(Ordering::Relaxed))
    }
    fn check_current_configuration(&self, config: &OwnedConfig) -> Result<u64, DmaError> {
        self.check_configuration(config)
    }
}

#[test]
fn dma_root_requires_original_binding_and_preserves_epoch_not_numeric_identity() {
    use crate::bus::pci::requester::{FunctionRole, StoppedRequester};
    let (mut function, _, drops) = setup();
    function.config().write16(4, 0x400);
    // SAFETY: isolated fixture has no engines, aliases, IRQ or workers;
    // no DMA/coherence operation is performed by this pairing-only model.
    let requester =
        match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
            Ok(value) => value,
            Err((error, _)) => panic!("stopped fixture: {error:?}"),
        };
    // SAFETY: original stopped fixture and exclusion owner, no effects.
    let (owner, binding) = match unsafe {
        NativeFunction::attach_stopped(requester, Box::new(Exclusion(drops.clone())))
    } {
        Ok(value) => value,
        Err((error, _)) => panic!("native fixture: {error:?}"),
    };
    let domain = Arc::new(BoundDomain {
        binding,
        generation: core::sync::atomic::AtomicU64::new(17),
    });
    let owner = Rc::new(RefCell::new(owner));
    let (other, _, other_drops) = setup();
    let other = Rc::new(RefCell::new(attach(other, other_drops)));
    let result = NativeDmaRoot::bind(other.clone(), domain.clone(), Arc::new(NoPages));
    assert!(matches!(
        result,
        Err((Error::Dma(DmaError::IommuUnavailable), _))
    ));
    assert_eq!(other.borrow().failure(), None);
    let root = match NativeDmaRoot::bind(owner.clone(), domain.clone(), Arc::new(NoPages)) {
        Ok(root) => root,
        Err((error, _)) => panic!("actual binding: {error:?}"),
    };
    assert_eq!(root.generation(), 17);
    assert_eq!(root.check_live(), Ok(()));
    let borrowed = owner.borrow_mut();
    assert_eq!(root.check_live(), Err(Error::Borrowed));
    drop(borrowed);
    domain.generation.store(18, Ordering::Relaxed);
    assert_eq!(root.check_live(), Err(Error::IdentityChanged));
    assert_eq!(owner.borrow().failure(), Some(Error::IdentityChanged));
    drop(root);
    drop(owner);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn registration_claim_is_unique_and_current_guard_does_no_config_observation() {
    let (mut function, counters, drops) = setup();
    let identity = fixture_pointer(function.config(), 0);
    let owner = Rc::new(RefCell::new(attach(function, drops.clone())));
    let claim = match NativeFunction::claim_registration(owner.clone()) {
        Ok(claim) => claim,
        Err(_) => panic!("first actual registration"),
    };
    assert_eq!(claim.check_current(), Ok(()));
    assert!(matches!(
        NativeFunction::claim_registration(owner.clone()),
        Err((Error::AlreadyClaimed, _))
    ));
    drop(claim);
    assert!(matches!(
        NativeFunction::claim_registration(owner.clone()),
        Err((Error::AlreadyClaimed, _))
    ));
    // SAFETY: synchronous fixture mutation models an unavailable hardware ID.
    // The pure lifetime guard MUST NOT read it or pretend to revalidate it.
    unsafe { identity.cast::<u32>().as_ptr().write_volatile(u32::MAX) };
    assert_eq!(owner.borrow().check_current(), Ok(()));
    assert_eq!(owner.borrow_mut().check_live(), Err(Error::Unavailable));
    assert_eq!(owner.borrow().check_current(), Err(Error::Unavailable));
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
    drop(owner);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn binding_escape_seals_unknown_transitions_before_effect_and_latches_degraded_readiness() {
    use crate::bus::pci::requester::{FunctionRole, StoppedRequester};
    for bind in [false, true] {
        let (mut function, _, drops) = setup();
        function.config().write32(4, 0xa5c3_0400);
        let command = fixture_pointer(function.config(), 4);
        let policy = fixture_pointer(function.config(), 0x48);
        // SAFETY: isolated stopped PF/config owner, no physical device.
        let requester =
            match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
                Ok(requester) => requester,
                Err((error, _)) => panic!("stopped fixture {error:?}"),
            };
        // SAFETY: same original stopped grant and model exclusion.
        let (owner, binding) = match unsafe {
            NativeFunction::attach_stopped(requester, Box::new(Exclusion(drops.clone())))
        } {
            Ok(pair) => pair,
            Err((error, _)) => panic!("native fixture {error:?}"),
        };
        let owner = Rc::new(RefCell::new(owner));
        let domain = Arc::new(BoundDomain {
            binding,
            generation: core::sync::atomic::AtomicU64::new(29),
        });
        let root = if bind {
            let root = match NativeDmaRoot::bind(owner.clone(), domain.clone(), Arc::new(NoPages)) {
                Ok(root) => root,
                Err((error, _)) => panic!("bound fixture {error:?}"),
            };
            assert!(matches!(
                NativeDmaRoot::bind(owner.clone(), domain.clone(), Arc::new(NoPages)),
                Err((Error::AlreadyClaimed, _))
            ));
            owner.borrow_mut().write(4, 2, 0x406).unwrap();
            assert_eq!(
                // SAFETY: observe model native-width store; Status is not
                // widened/replayed by the production Command word write.
                unsafe { command.cast::<u32>().as_ptr().read_volatile() },
                0xa5c3_0406
            );
            owner.borrow_mut().write(4, 1, 1).unwrap();
            assert_eq!(
                // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
                // nothing accesses it concurrently.
                unsafe { command.cast::<u32>().as_ptr().read_volatile() },
                0xa5c3_0401
            );
            owner.borrow_mut().write(4, 2, 0x406).unwrap();
            Some(root)
        } else {
            // An escaped binding can already be installed, but no real bound
            // context has been verified here: even BME must not be enabled.
            assert_eq!(
                owner.borrow_mut().write(4, 2, 0x406),
                Err(Error::UnsupportedPolicy)
            );
            None
        };
        for (offset, width, value) in [
            (0x48, 2, 1 << 11),  // PCIe NoSnoop (or unknown capability position)
            (0x106, 2, 1 << 15), // ATS/PASID control at any source position
            (0x104, 2, 3),       // PRI/reset-like control
            (0x180, 2, 1),       // VF/alias policy
            (0x44, 2, 3),        // PMCSR-like transition
            (0x10, 4, u32::MAX), // BAR sizing/relocation
            (0x3e, 2, 0x40),     // bridge/reset-like control
            (0x123, 1, 0xff),    // unknown vendor effects cannot be guessed safe
            (5, 1, 0),           // cannot unmask INTx without route permission
            (4, 4, 0xffff_0407), // cannot widen/replay neighboring Status
        ] {
            assert_eq!(
                owner.borrow_mut().write(offset, width, value),
                Err(Error::UnsupportedPolicy)
            );
        }
        // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and nothing
        // accesses it concurrently.
        assert_eq!(unsafe { policy.cast::<u16>().as_ptr().read_volatile() }, 0);
        assert_eq!(owner.borrow().failure(), None);
        assert_eq!(owner.borrow().check_current(), Ok(()));
        assert!(owner.borrow().denied_write_count() >= 10);
        assert_eq!(
            owner.borrow_mut().check_ready(),
            Err(Error::UnsupportedPolicy)
        );
        if let Some(root) = root {
            // An ignored unsupported transition cannot prevent original PCI
            // cleanup from clearing bus mastering/decode. It cannot
            // authorize enabling gates again or renew degraded readiness.
            owner.borrow_mut().write(4, 2, 0x400).unwrap();
            assert_eq!(
                // SAFETY: the pointer addresses live memory this test's model owns, in bounds, and
                // nothing accesses it concurrently.
                unsafe { command.cast::<u32>().as_ptr().read_volatile() },
                0xa5c3_0400
            );
            assert_eq!(
                owner.borrow_mut().write(4, 2, 0x406),
                Err(Error::UnsupportedPolicy)
            );
            assert_eq!(root.check_current(), Ok(()));
            assert_eq!(root.check_live(), Err(Error::UnsupportedPolicy));
        }
        drop(owner);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
}
