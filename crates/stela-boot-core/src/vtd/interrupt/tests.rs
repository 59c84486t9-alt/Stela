extern crate std;
use super::*;
use core::sync::atomic::AtomicUsize;
mod model;
use model::{Pool, RegistersPeer};

const SID: u16 = 0x100;
#[derive(Default)]
struct Checks {
    fail: AtomicBool,
    context_fail: AtomicBool,
    wrong_cpu: AtomicBool,
    hard_irq: AtomicBool,
    wrong_root: AtomicBool,
    generation: AtomicU64,
    drops: AtomicUsize,
    observations: AtomicUsize,
}
// SAFETY: isolated original CPU/root context peer; atomic checks are
// nonblocking, allocation-free and never touch Unit or its register locks.
unsafe impl Context for Checks {
    fn check(&self) -> Result<(), VtdError> {
        if self.context_fail.load(Ordering::Relaxed)
            || self.wrong_cpu.load(Ordering::Relaxed)
            || self.hard_irq.load(Ordering::Relaxed)
            || self.wrong_root.load(Ordering::Relaxed)
        {
            Err(VtdError::Busy)
        } else {
            Ok(())
        }
    }
}
struct RootGrant(Arc<Checks>);
struct SourceGrant {
    checks: Arc<Checks>,
    epoch: u64,
}
// SAFETY: synchronous isolated root peer owns all symbolic interrupt sources
// and the original CPU/control epoch; no real firmware/IOAPIC users exist.
unsafe impl RootOwner for RootGrant {
    fn context(&self) -> Arc<dyn Context> {
        self.0.clone()
    }
    fn check(&self) -> Result<(), VtdError> {
        if self.0.fail.load(Ordering::Relaxed) {
            Err(VtdError::Busy)
        } else {
            Ok(())
        }
    }
    fn generation(&self) -> u64 {
        self.0.generation.load(Ordering::Relaxed)
    }
}
impl Drop for RootGrant {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: this peer retains one exact SID/configuration epoch independently
// from the root. Its epoch is fixed; explicit controls refuse changed owners.
unsafe impl ExactSourceOwner for SourceGrant {
    fn check(&self) -> Result<(), VtdError> {
        self.checks.observations.fetch_add(1, Ordering::Relaxed);
        if self.checks.fail.load(Ordering::Relaxed) {
            Err(VtdError::Busy)
        } else {
            Ok(())
        }
    }
    fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            source_id: SID,
            configuration_epoch: self.epoch,
            reset_epoch: self.epoch,
        }
    }
}
impl Drop for SourceGrant {
    fn drop(&mut self) {
        self.checks.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Fixture {
    pool: &'static Pool,
    registers: RegistersPeer,
    unit: Arc<Unit<RegistersPeer>>,
    root: Arc<Checks>,
}
impl Fixture {
    fn new(coherent: bool) -> Self {
        Self::with_cap_clear(coherent, 0)
    }
    fn with_cap_clear(coherent: bool, clear: u64) -> Self {
        let pool = Pool::new();
        let registers = RegistersPeer::new(pool, coherent);
        *registers.0.lock().unwrap().values.get_mut(&CAP).unwrap() &= !clear;
        // SAFETY: original isolated register/RAM peers with all devices stopped;
        // this test owns the entire root, its controls and exact RID inventory.
        let unit = unsafe { Unit::take_over(registers.clone(), pool, &[SID], 48, &[]) }.unwrap();
        let root = Arc::new(Checks {
            generation: AtomicU64::new(17),
            ..Checks::default()
        });
        Self {
            pool,
            registers,
            unit,
            root,
        }
    }
    fn enable(&self) {
        // SAFETY: fixture owns all symbolic sources before any route allocation.
        unsafe {
            self.unit
                .enable_interrupt_remapping(Box::new(RootGrant(self.root.clone())))
        }
        .unwrap();
    }
    fn route(&self, epoch: u64, vector: u8) -> (Route<RegistersPeer>, Arc<Checks>) {
        let checks = Arc::new(Checks::default());
        // SAFETY: exact original SID/epoch peer and exclusively allocated
        // symbolic CPU vector; no duplicate source or alternate delivery exists.
        let route = unsafe {
            self.unit.allocate_interrupt_route(
                Box::new(SourceGrant {
                    checks: checks.clone(),
                    epoch,
                }),
                RouteTarget::new(2, vector).unwrap(),
            )
        }
        .unwrap();
        (route, checks)
    }
}
fn fence(route: &mut Route<RegistersPeer>) -> Result<(), VtdError> {
    // SAFETY: fixture has stopped every symbolic source/payload/alternate route,
    // keeping the old config/DMA/callback graph through this root operation.
    unsafe { route.fence() }
}

#[test]
fn exact_sid_remapped_message_has_independent_index_and_cpu_vector() {
    let f = Fixture::new(true);
    f.enable();
    let (mut route, _) = f.route(1, 0x51);
    assert_eq!(route.identity().index, 0);
    assert_eq!(
        route.message().unwrap(),
        MsiMessage {
            address: 0xfee0_0010,
            data: 0
        }
    );
    let mut hardware = f.registers.0.lock().unwrap();
    hardware.request(SID + 1, 0);
    assert_eq!(hardware.rejected, 1);
    hardware.request(SID, 0);
    assert_eq!(hardware.fabric, [(0, 0x51)]);
    drop(hardware);
    fence(&mut route).unwrap();
    assert_eq!(f.registers.0.lock().unwrap().irr, [0x51]);
}

#[test]
fn payload_and_empty_cpu_state_cannot_complete_held_fabric_interrupt() {
    let f = Fixture::new(true);
    f.enable();
    let (mut route, source) = f.route(1, 0x52);
    {
        let mut h = f.registers.0.lock().unwrap();
        h.request(SID, 0);
        h.hold_lapic = true;
        assert!(h.irr.is_empty());
    }
    f.unit.drain_initial_requester(SID).unwrap();
    assert_eq!(fence(&mut route), Err(VtdError::Timeout));
    drop(route);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    // SAFETY: no real endpoint exists; the uncertain IRQ must still forbid root release.
    assert!(unsafe { f.unit.shut_down() }.is_err());
    drop(f.unit);
    assert_eq!(f.pool.released.load(Ordering::Relaxed), 0);
    assert_eq!(f.root.drops.load(Ordering::Relaxed), 0);
}

#[test]
fn stale_lookup_must_resolve_before_iec_and_wait_completion() {
    for withheld in [false, true] {
        let f = Fixture::new(true);
        f.enable();
        let (mut route, _) = f.route(1, 0x53);
        {
            let mut h = f.registers.0.lock().unwrap();
            h.lookup = Some((0, 0x53));
            h.hold_lookup = withheld;
            h.lookup_delay = 3;
            h.events.clear();
        }
        if withheld {
            assert_eq!(fence(&mut route), Err(VtdError::Timeout));
            let h = f.registers.0.lock().unwrap();
            assert!(!h.events.contains(&"status"));
            assert!(h.irr.is_empty());
        } else {
            fence(&mut route).unwrap();
            let h = f.registers.0.lock().unwrap();
            let at = |name| h.events.iter().position(|event| *event == name).unwrap();
            assert!(at("lookup") < at("iec"));
            assert!(at("iec") < at("lapic"));
            assert!(at("lapic") < at("status"));
        }
    }
}

#[test]
fn fenced_drop_retains_source_until_explicit_same_epoch_retirement() {
    let f = Fixture::new(true);
    f.enable();
    let (mut abandoned, abandoned_pin) = f.route(1, 0x54);
    fence(&mut abandoned).unwrap();
    drop(abandoned);
    assert_eq!(abandoned_pin.drops.load(Ordering::Relaxed), 0);
    let (mut route, source) = f.route(2, 0x55);
    fence(&mut route).unwrap();
    // SAFETY: the isolated symbolic endpoint has no CPU/work/DMA/config users;
    // this is its same current-epoch final native retirement, not just a flag.
    let ReleasedEndpoint {
        terminal,
        source: pin,
    } = unsafe { route.release_after_retirement() }.unwrap();
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    drop(pin);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    let observed = source.observations.load(Ordering::Relaxed);
    terminal.check().unwrap();
    assert_eq!(source.observations.load(Ordering::Relaxed), observed);
    drop(f.unit);
    drop(terminal);
    assert_eq!(f.pool.released.load(Ordering::Relaxed), 0);
}

#[test]
fn late_old_index_is_rejected_after_vector_reuse_and_fresh_reprobe_index() {
    let f = Fixture::new(true);
    f.enable();
    let (mut old, _) = f.route(1, 0x56);
    f.registers
        .0
        .lock()
        .unwrap()
        .upstream
        .push((SID, old.identity().index));
    fence(&mut old).unwrap();
    // SAFETY: same exact symbolic endpoint's independent retirement is complete.
    let ReleasedEndpoint {
        terminal,
        source: pin,
    } = unsafe { old.release_after_retirement() }.unwrap();
    drop(pin);
    let (new, _) = f.route(2, 0x56);
    assert_eq!(new.identity().index, 1);
    let mut h = f.registers.0.lock().unwrap();
    h.release_upstream();
    assert_eq!(h.rejected, 1);
    assert!(h.fabric.is_empty());
    assert!(h.irr.is_empty());
    h.request(SID, 1);
    assert_eq!(h.fabric, [(1, 0x56)]);
    drop(h);
    terminal.check().unwrap();
}

#[test]
fn cached_fence_rechecks_original_source_and_root_epochs() {
    for changed_source in [true, false] {
        let f = Fixture::new(true);
        f.enable();
        let (mut route, source) = f.route(1, 0x57);
        fence(&mut route).unwrap();
        if changed_source {
            source.fail.store(true, Ordering::Relaxed);
        } else {
            f.root.generation.store(18, Ordering::Relaxed);
        }
        assert!(fence(&mut route).is_err());
        drop(route);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn selective_fence_leaves_other_index_delivery_pending() {
    let f = Fixture::new(true);
    f.enable();
    let (mut a, _) = f.route(1, 0x58);
    let (b, _) = f.route(2, 0x59);
    let mut h = f.registers.0.lock().unwrap();
    h.request(SID, a.identity().index);
    h.request(SID, b.identity().index);
    drop(h);
    fence(&mut a).unwrap();
    let h = f.registers.0.lock().unwrap();
    assert_eq!(h.irr, [0x58]);
    assert_eq!(h.fabric, [(1, 0x59)]);
}

#[test]
fn queued_payload_context_and_wbf_preserve_all_persistent_controls() {
    let f = Fixture::new(false);
    f.enable();
    let (mut route, _) = f.route(1, 0x5a);
    f.registers.0.lock().unwrap().writes.clear();
    f.unit.drain_initial_requester(SID).unwrap();
    let _guard = f.unit.lock();
    f.unit.invalidate(true).unwrap();
    f.unit.invalidate_domain(7).unwrap();
    f.unit.flush_write_buffer().unwrap();
    let h = f.registers.0.lock().unwrap();
    assert!(
        !h.writes
            .iter()
            .any(|(offset, _)| *offset == CCMD || *offset == 0x108)
    );
    assert!(
        h.writes
            .iter()
            .filter(|(offset, _)| *offset == GCMD)
            .all(|(_, command)| *command as u32 & PERSISTENT
                == TRANSLATION | QUEUED_INVALIDATION | INTERRUPT_REMAP)
    );
    assert!(h.descriptors.iter().any(|d| d[0] & 15 == 1));
    assert!(
        h.descriptors
            .iter()
            .filter(|d| d[0] & 15 == 2)
            .all(|d| d[0] & 0xc0 == 0xc0)
    );
    drop(h);
    drop(_guard);
    fence(&mut route).unwrap();
}

mod failure;

mod unwind;

#[test]
fn wrong_context_checks_return_before_a_held_unit_lock_or_register_access() {
    let f = Fixture::new(true);
    f.enable();
    let (mut old, _) = f.route(1, 0x51);
    fence(&mut old).unwrap();
    // SAFETY: same exact symbolic endpoint's complete independent retirement.
    let ReleasedEndpoint {
        terminal,
        source: pin,
    } = unsafe { old.release_after_retirement() }.unwrap();
    drop(pin);
    let (live, source) = f.route(2, 0x52);
    let guard = f.unit.lock();
    let reads = f.registers.0.lock().unwrap().reads;
    let observations = source.observations.load(Ordering::Relaxed);
    for bad_context in [&f.root.wrong_cpu, &f.root.hard_irq, &f.root.wrong_root] {
        bad_context.store(true, Ordering::Relaxed);
        // No timeout or scheduling assumption: both calls return while this
        // thread still owns the non-reentrant Unit lock.
        assert_eq!(live.message(), Err(VtdError::Busy));
        assert_eq!(terminal.check(), Err(VtdError::Busy));
        bad_context.store(false, Ordering::Relaxed);
    }
    assert_eq!(f.registers.0.lock().unwrap().reads, reads);
    assert_eq!(source.observations.load(Ordering::Relaxed), observations);
    drop(guard);
    live.message().unwrap();
    terminal.check().unwrap();
}
