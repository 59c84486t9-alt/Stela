extern crate std;
use super::*;
use alloc::boxed::Box;
use std::{
    sync::Barrier,
    thread::{self, ThreadId},
};

/// Actual owned model allocation and execution thread. No PA/BDF/snapshot or
/// bool pretends to reserve real hardware; this is a source-free memory model.
struct OwnedAllocation {
    allocation: ManuallyDrop<Box<[u8; 4096]>>,
    owner: ThreadId,
    parent: Option<Parent>,
    releases: Arc<AtomicUsize>,
}
impl OwnedAllocation {
    fn new(parent: Option<Parent>, releases: Arc<AtomicUsize>) -> Self {
        Self {
            allocation: ManuallyDrop::new(Box::new([0; 4096])),
            owner: thread::current().id(),
            parent,
            releases,
        }
    }
    /// # Safety
    /// All model users have ended, and original custody was returned. Only this
    /// explicit model finalizer releases the original real Box allocation.
    unsafe fn finish(mut self) {
        // SAFETY: caller ended every user and consumed original custody once.
        unsafe { ManuallyDrop::drop(&mut self.allocation) };
        self.releases.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: the actual Box exclusively owns its storage, and the only parent is
// an actual retained original ancestor. No mappings/Authority/control backedge
// exists. Ordinary Drop keeps the Box; final release is explicit above. Owner
// checks use the actual creating thread, never a copied PCI/root/physical label.
unsafe impl PhysicalAssignment for OwnedAllocation {
    fn parent(&self) -> Option<&Parent> {
        self.parent.as_ref()
    }
    fn check_control(&self) -> Result<(), Error> {
        if self.owner == thread::current().id() {
            Ok(())
        } else {
            Err(Error::Context)
        }
    }
}
fn returned(owner: Assignment<OwnedAllocation>) -> OwnedAllocation {
    owner
        .into_original()
        .unwrap_or_else(|_| panic!("original physical custody refused"))
}
unsafe fn release(lease: Use<OwnedAllocation>) {
    // SAFETY: each test ends its actual model user before this explicit fence.
    unsafe { lease.release() }.unwrap_or_else(|_| panic!("original use release refused"));
}
#[test]
fn retained_original_requires_closed_admission_and_every_lease() {
    let releases = Arc::new(AtomicUsize::new(0));
    let owner = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let owner = match owner.into_original() {
        Err(Refusal {
            error: Error::Open,
            owner,
        }) => owner,
        _ => panic!("open control cannot return original custody"),
    };
    let mut owner = owner;
    let old_clone = owner.retain();
    assert!(old_clone.same_assignment(&old_clone.clone()));
    let mapping = old_clone.begin_use(UseKind::Mapping).unwrap();
    assert_eq!(mapping.kind(), UseKind::Mapping);
    assert!(matches!(owner.close(), Err(Error::Busy { uses: 1, .. })));
    assert!(matches!(
        old_clone.begin_use(UseKind::Mapping),
        Err(Error::Closed)
    ));
    // SAFETY: no real mapping was exposed; controlled model user ended.
    unsafe { release(mapping) };
    let owner = match owner.into_original() {
        Err(Refusal {
            error:
                Error::Busy {
                    uses: 0,
                    retentions: 1,
                },
            owner,
        }) => owner,
        _ => panic!("stale retained resource must prevent physical release"),
    };
    assert_eq!(releases.load(Ordering::Relaxed), 0);
    drop(old_clone);
    // SAFETY: actual use and clone are gone, same original custody returned.
    unsafe { returned(owner).finish() };
    assert_eq!(releases.load(Ordering::Relaxed), 1);
}
#[test]
fn original_bridge_custody_observes_descendant_users_and_storage() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut bridge = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let mut endpoint = Assignment::from_owned(OwnedAllocation::new(
        Some(bridge.parent()),
        releases.clone(),
    ));
    let endpoint_pin = endpoint.retain();
    let use_ = endpoint_pin.begin_use(UseKind::Dma).unwrap();
    assert_eq!(bridge.uses(), 1);
    assert!(matches!(bridge.close(), Err(Error::Busy { uses: 1, .. })));
    assert!(matches!(
        endpoint_pin.begin_use(UseKind::Interrupt),
        Err(Error::Closed)
    ));
    assert_eq!(endpoint.uses(), 1); // rejected partial acquisition rolled back
    // SAFETY: the model has no outstanding DMA/CPU access at this fence.
    unsafe { release(use_) };
    assert_eq!(bridge.uses(), 0);
    assert!(bridge.into_original().is_err()); // retains complete original graph
    // Use a separate original bridge below; the abandoned first root remains
    // retained intentionally, proving zero users is not physical release.
    endpoint.close().unwrap();
    drop(endpoint_pin);
    // SAFETY: actual child model use ended; parent remains retained separately.
    unsafe { returned(endpoint).finish() };
    assert_eq!(releases.load(Ordering::Relaxed), 1);
}
#[test]
fn bridge_returns_only_after_original_child_product_finishes() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut bridge = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let mut child = Assignment::from_owned(OwnedAllocation::new(
        Some(bridge.parent()),
        releases.clone(),
    ));
    bridge.close().unwrap();
    let bridge = match bridge.into_original() {
        Err(Refusal {
            error: Error::Busy { uses: 0, .. },
            owner,
        }) => owner,
        _ => panic!("real child reservation must retain actual bridge storage"),
    };
    child.close().unwrap();
    // SAFETY: no model users were exposed, child is closed and original.
    unsafe { returned(child).finish() };
    // SAFETY: actual child original product and every parent pin are now gone.
    unsafe { returned(bridge).finish() };
    assert_eq!(releases.load(Ordering::Relaxed), 2);
}
#[test]
fn close_racing_pending_use_cannot_release_or_reopen_assignment() {
    for _ in 0..32 {
        let releases = Arc::new(AtomicUsize::new(0));
        let mut owner = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
        let retained = owner.retain();
        let barrier = Arc::new(Barrier::new(2));
        let entered = barrier.clone();
        let pending = thread::spawn(move || {
            entered.wait();
            retained.begin_use(UseKind::Mapping)
        });
        barrier.wait();
        let closed = owner.close();
        match pending.join().unwrap() {
            Ok(use_) => {
                assert_eq!(owner.uses(), 1);
                assert!(closed.is_ok() || matches!(closed, Err(Error::Busy { uses: 1, .. })));
                // SAFETY: joined thread exposed no actual pointer/user.
                unsafe { release(use_) };
            }
            Err(error) => {
                assert_eq!(error, Error::Closed);
                assert!(closed.is_ok());
            }
        }
        assert_eq!(owner.uses(), 0);
        assert!(matches!(
            owner.retain().begin_use(UseKind::Mapping),
            Err(Error::Closed)
        ));
        // SAFETY: race is joined, all accepted uses explicitly retired.
        unsafe { returned(owner).finish() };
        assert_eq!(releases.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn foreign_release_returns_same_real_use_before_any_counter_effect() {
    let releases = Arc::new(AtomicUsize::new(0));
    let mut owner = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let use_ = owner.retain().begin_use(UseKind::Alias).unwrap();
    let use_ = thread::spawn(move || {
        // SAFETY: user ended, but original context deliberately mismatches.
        match unsafe { use_.release() } {
            Err((Error::Context, original)) => original,
            _ => panic!("foreign context cannot release original-use custody"),
        }
    })
    .join()
    .unwrap();
    assert_eq!(owner.uses(), 1);
    assert_eq!(releases.load(Ordering::Relaxed), 0);
    // SAFETY: joined foreign task returned the same actual pin, owner current.
    unsafe { release(use_) };
    owner.close().unwrap();
    // SAFETY: actual user ended and original physical custody returned.
    unsafe { returned(owner).finish() };
}
#[test]
fn abandoned_control_and_use_keep_entire_actual_allocation() {
    let releases = Arc::new(AtomicUsize::new(0));
    let before_controls = abandoned_controls();
    let before_uses = abandoned_uses();
    let mut owner = Assignment::from_owned(OwnedAllocation::new(None, releases.clone()));
    let retained = owner.retain();
    drop(retained.begin_use(UseKind::Interrupt).unwrap());
    assert_eq!(owner.uses(), 1);
    assert!(matches!(owner.close(), Err(Error::Busy { uses: 1, .. })));
    drop(owner);
    assert!(matches!(
        retained.begin_use(UseKind::Mapping),
        Err(Error::Closed)
    ));
    drop(retained);
    assert_eq!(releases.load(Ordering::Relaxed), 0);
    assert!(abandoned_controls() > before_controls);
    assert!(abandoned_uses() > before_uses);
}

mod operation;

mod close_only;
