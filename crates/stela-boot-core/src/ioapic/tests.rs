use super::*;
extern crate std;
use core::sync::atomic::{AtomicPtr, AtomicUsize};
use std::sync::Mutex;
use stela_drivers::bus::irq::{Disposition, Handler, Registry, SharedHandlers};
struct Hardware {
    regs: [u32; 256],
    asserted: u32,
    pending: bool,
    fail_read: bool,
    refuse_mask: bool,
    broken_eoi: bool,
    tmr: Trigger,
    events: alloc::vec::Vec<&'static str>,
}
impl Hardware {
    fn service(&mut self) {
        let low = self.regs[0x22]; // GSI9, true level state, one pending vector.
        if self.asserted != 0 && low & (MASK | REMOTE_IRR) == 0 {
            assert_ne!(
                low & (1 << 15),
                0,
                "fixture must be genuinely level-triggered"
            );
            self.regs[0x22] |= REMOTE_IRR;
            self.pending = true;
            self.tmr = Trigger::Level;
            self.events.push("deliver");
        }
    }
    fn eoi(&mut self) -> Trigger {
        let observed = self.tmr;
        self.pending = false;
        self.events.push("eoi");
        if observed == Trigger::Level && !self.broken_eoi {
            self.regs[0x22] &= !REMOTE_IRR;
            self.service();
        }
        observed
    }
}
struct Board {
    hw: Mutex<Hardware>,
    ticks: AtomicU64,
    drops: AtomicUsize,
    calls: AtomicUsize,
    registry: AtomicPtr<Registry<Cpu>>,
    vector: core::sync::atomic::AtomicU8,
    domain_live: AtomicBool,
    arming_old_edge: AtomicBool,
}
impl Board {
    fn new() -> Arc<Self> {
        let mut regs = [0; 256];
        regs[1] = 0x11 | 23 << 16;
        for pin in 0..24 {
            regs[0x10 + pin * 2] = MASK;
        }
        Arc::new(Self {
            hw: Mutex::new(Hardware {
                regs,
                asserted: 0,
                pending: false,
                fail_read: false,
                refuse_mask: false,
                broken_eoi: false,
                tmr: Trigger::Edge,
                events: alloc::vec::Vec::new(),
            }),
            ticks: AtomicU64::new(0),
            drops: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
            registry: AtomicPtr::new(core::ptr::null_mut()),
            vector: core::sync::atomic::AtomicU8::new(0),
            domain_live: AtomicBool::new(true),
            arming_old_edge: AtomicBool::new(false),
        })
    }
}
struct Io(Arc<Board>);
// SAFETY: the board model is the only selector/window this test unit uses.
unsafe impl Registers for Io {
    fn read(&self, i: u8) -> u32 {
        let h = self.0.hw.lock().unwrap();
        if h.fail_read {
            u32::MAX
        } else {
            h.regs[usize::from(i)]
        }
    }
    fn write(&self, i: u8, v: u32) {
        let mut h = self.0.hw.lock().unwrap();
        let i = usize::from(i);
        if i >= 0x10 && i % 2 == 1 {
            assert_ne!(
                h.regs[i - 1] & MASK,
                0,
                "destination changed before acknowledged mask"
            );
            assert_eq!(
                h.regs[i - 1] & (REMOTE_IRR | DELIVERY),
                0,
                "live route was reprogrammed"
            );
            h.events.push("destination");
            h.regs[i] = v;
        } else if i >= 0x10 {
            let old = h.regs[i];
            if h.refuse_mask && v & MASK != 0 {
                return;
            }
            if old & CONFIG != v & CONFIG && (old ^ v) & !MASK != 0 {
                assert_ne!(old & MASK, 0, "electrical/vector changed before mask");
                if old & (1 << 15) != 0 && v & (1 << 15) == 0 {
                    assert_eq!((old ^ v) & (CONFIG & !(1 << 15)), 0);
                } else {
                    assert_eq!(old & (REMOTE_IRR | DELIVERY), 0);
                }
            }
            // Hardware does not allow software to clear RO RemoteIRR.
            h.regs[i] = (v & !(REMOTE_IRR | DELIVERY)) | old & (REMOTE_IRR | DELIVERY);
            if old & (1 << 15) != 0 && v & (1 << 15) == 0 && !h.broken_eoi {
                h.regs[i] &= !REMOTE_IRR;
                h.events.push("edge-eoi");
            }
            h.events.push(if v & MASK != 0 { "mask" } else { "unmask" });
            h.service();
        }
    }
    fn write_eoi(&self, vector: u8) {
        let mut h = self.0.hw.lock().unwrap();
        assert_eq!(h.regs[0x22] as u8, vector);
        assert!(h.regs[1] as u8 >= 0x20);
        h.events.push("direct-eoi");
        if !h.broken_eoi {
            h.regs[0x22] &= !REMOTE_IRR;
            h.service();
        }
    }
}
struct Domain(Arc<Board>);
// SAFETY: the original independent board peer owns this exact CPU/controller
// mode. Domain loss is controlled independently from RTE/pending/TMR effects.
unsafe impl NotificationDomain for Domain {
    fn check(&self) -> Result<(), posted_msi::Error> {
        if self.0.domain_live.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(posted_msi::Error::RootFailed)
        }
    }
}
struct Cpu(Arc<Board>);
// SAFETY: the board model is the single CPU this test unit runs on.
unsafe impl Platform for Cpu {
    fn check_cpu(&self) -> Result<(), IrqError> {
        Ok(())
    }
    fn check_process(&self) -> Result<(), stela_drivers::bus::irq::IrqError> {
        self.check_cpu()
    }
    fn save_and_disable(&self) -> u64 {
        0
    }
    unsafe fn restore(&self, s: u64) {
        assert_eq!(s, 0);
    }
    fn target(&self, v: u8) -> Result<Target, IrqError> {
        self.0.vector.store(v, Ordering::Relaxed);
        Ok(Target {
            destination: 3,
            vector: v,
        })
    }
    fn pending(&self, _: u8) -> Result<bool, IrqError> {
        Ok(self.0.hw.lock().unwrap().pending)
    }
    fn eoi(&self, _: u8) -> Result<Trigger, IrqError> {
        Ok(self.0.hw.lock().unwrap().eoi())
    }
    fn ticks(&self) -> u64 {
        self.0.ticks.fetch_add(1, Ordering::Relaxed)
    }
    fn timeout_ticks(&self) -> u64 {
        8
    }
    unsafe fn interrupt_window(&self) {
        // SAFETY: the fixture publishes its registry before any interrupt window and keeps it
        // alive.
        let r = unsafe { &*self.0.registry.load(Ordering::Relaxed) };
        assert!(r.dispatch(self.0.vector.load(Ordering::Relaxed)));
    }
}
struct Contributors(Arc<Board>);
// SAFETY: the board model owns the line's only contributor, which masks and quiesces in the
// model.
unsafe impl Devices for Contributors {
    fn mask(&mut self) -> Result<(), IrqError> {
        self.0.hw.lock().unwrap().events.push("device_mask");
        Ok(())
    }
    fn quiesce(&mut self) -> Result<(), IrqError> {
        let mut h = self.0.hw.lock().unwrap();
        h.asserted = 0;
        h.events.push("stopped");
        drop(h);
        if self.0.arming_old_edge.swap(false, Ordering::AcqRel) {
            {
                let mut hardware = self.0.hw.lock().unwrap();
                hardware.pending = true;
                hardware.tmr = Trigger::Edge;
                hardware.events.push("old-edge-arming");
            }
            // SAFETY: fixture publishes the original permanent Registry first.
            let registry = unsafe { &*self.0.registry.load(Ordering::Acquire) };
            assert!(registry.dispatch(self.0.vector.load(Ordering::Relaxed)));
        }
        Ok(())
    }
    unsafe fn enable(&mut self) -> Result<(), IrqError> {
        self.0.hw.lock().unwrap().events.push("device_enable");
        Ok(())
    }
}
impl Drop for Contributors {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Member(Arc<Board>, u32, bool);
impl Handler for Member {
    fn handle(&self) -> Disposition {
        let mut h = self.0.hw.lock().unwrap();
        self.0.calls.fetch_add(1, Ordering::Relaxed);
        if h.asserted & self.1 == 0 {
            return Disposition::NotMine;
        }
        if self.2 {
            h.asserted &= !self.1;
            h.events.push("cause_ack");
        }
        Disposition::Handled
    }
}
type Fixture = (
    Arc<Board>,
    Arc<Unit<Io, Cpu>>,
    &'static Registry<Cpu>,
    LineRoute,
);
fn fixture() -> Fixture {
    fixture_version(0x11)
}
fn fixture_version(version: u8) -> Fixture {
    let b = Board::new();
    b.hw.lock().unwrap().regs[1] = u32::from(version) | 23 << 16;
    let r = Box::leak(Box::new(Registry::new(Cpu(b.clone()))));
    b.registry.store(r, Ordering::Relaxed);
    // SAFETY: the model board is this unit's only selector/window owner.
    let u = unsafe {
        Unit::attach(
            Io(b.clone()),
            Cpu(b.clone()),
            Arc::new(Domain(b.clone())),
            r.identity(),
            0,
            0,
        )
    }
    .unwrap();
    (
        b,
        u,
        r,
        LineRoute {
            gsi: 9,
            polarity: Polarity::Low,
            trigger: Trigger::Level,
        },
    )
}

#[test]
fn old_edge_during_arming_gets_only_local_eoi_before_pin_programming() {
    let (board, unit, registry, line) = fixture_version(0x20);
    // SAFETY: original fixture owns this exact stopped physical source.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    board.arming_old_edge.store(true, Ordering::Release);
    let mut registration = registry
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(board.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    assert_eq!(board.calls.load(Ordering::Relaxed), 0);
    {
        let hardware = board.hw.lock().unwrap();
        assert!(!hardware.pending);
        let old = hardware
            .events
            .iter()
            .position(|event| *event == "old-edge-arming")
            .unwrap();
        let local = hardware
            .events
            .iter()
            .position(|event| *event == "eoi")
            .unwrap();
        let destination = hardware
            .events
            .iter()
            .position(|event| *event == "destination")
            .unwrap();
        assert!(old < local && local < destination);
        assert!(!hardware.events.contains(&"direct-eoi"));
        assert!(!hardware.events.contains(&"edge-eoi"));
    }
    {
        let mut hardware = board.hw.lock().unwrap();
        hardware.asserted = 1;
        hardware.service();
    }
    assert!(registry.dispatch(registration.vector()));
    assert_eq!(board.calls.load(Ordering::Relaxed), 1);
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & REMOTE_IRR, 0);
    finish(registration.retire().unwrap());
    assert_eq!(board.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn actual_registry_route_refuses_different_electrical_line_before_programming() {
    let (board, unit, registry, line) = fixture();
    // SAFETY: actual stopped fixture group owns precisely this claimed GSI.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let high = board.hw.lock().unwrap().regs[0x23];
    assert!(
        registry
            .request(stela_drivers::bus::irq::Request {
                source: Box::new(pin),
                handler: Arc::new(Member(board.clone(), 1, true)),
                routing: stela_drivers::bus::irq::RouteRequest::Line(LineRoute { gsi: 8, ..line }),
            })
            .is_err()
    );
    assert_eq!(board.hw.lock().unwrap().regs[0x23], high);
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & 255, 0);
}

#[test]
fn foreign_registry_reservation_refuses_before_any_route_programming() {
    let (board, unit, _, line) = fixture();
    let foreign = Box::leak(Box::new(Registry::new(Cpu(board.clone()))));
    // SAFETY: actual fixture owns this stopped physical source.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let high_before = board.hw.lock().unwrap().regs[0x23];
    assert!(
        foreign
            .request(stela_drivers::bus::irq::Request {
                source: Box::new(pin),
                handler: Arc::new(Member(board.clone(), 1, true)),
                routing: stela_drivers::bus::irq::RouteRequest::Line(line),
            })
            .is_err()
    );
    assert_eq!(board.hw.lock().unwrap().regs[0x23], high_before);
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & 255, 0);
}

#[test]
fn pin_domain_refuses_revoked_root_without_waiting_for_controller_lock() {
    let (board, unit, _, line) = fixture();
    // SAFETY: bounded source and genuine original board domain.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let domain = pin.notification_domain().unwrap();
    let _held = unit.lock();
    board.domain_live.store(false, Ordering::Release);
    // Independent original-root revocation is checked before any selector lock.
    assert_eq!(domain.check(), Err(posted_msi::Error::RootFailed));
    board.domain_live.store(true, Ordering::Release);
}

#[test]
fn old_edge_notification_clears_current_level_remote_irr_with_real_chip_eoi() {
    struct Deferred(Arc<ParentMask<Io, Cpu>>);
    impl Handler for Deferred {
        fn handle(&self) -> Disposition {
            stela_drivers::bus::irq::ParentMask::mask(&*self.0).unwrap();
            Disposition::Handled
        }
    }
    for version in [0x11, 0x20, 0x21] {
        for deferred in [false, true] {
            let (board, unit, registry, line) = fixture_version(version);
            // SAFETY: this exact board owns the stopped physical source group.
            let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
            let parent = Arc::new(pin.parent_mask().unwrap());
            let handler: Arc<dyn Handler> = if deferred {
                Arc::new(Deferred(parent))
            } else {
                Arc::new(Member(board.clone(), 1, true))
            };
            let mut route = registry
                .request(stela_drivers::bus::irq::Request {
                    source: Box::new(pin),
                    handler,
                    routing: stela_drivers::bus::irq::RouteRequest::Line(line),
                })
                .unwrap();
            {
                let mut h = board.hw.lock().unwrap();
                h.asserted = 1;
                h.service();
                assert_ne!(h.regs[0x22] & REMOTE_IRR, 0);
                // Independent accepted old edge notification changes CPU TMR;
                // controller RemoteIRR and current source cause remain real.
                h.tmr = Trigger::Edge;
                h.events.clear();
            }
            assert!(registry.dispatch(route.vector()));
            {
                let h = board.hw.lock().unwrap();
                assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
                assert_eq!(h.regs[0x22] & MASK != 0, deferred);
                let kind = if version < 0x20 {
                    "edge-eoi"
                } else {
                    "direct-eoi"
                };
                let local = h.events.iter().position(|event| *event == "eoi").unwrap();
                let chip = h.events.iter().position(|event| *event == kind).unwrap();
                assert!(local < chip);
            }
            finish(route.retire().unwrap());
        }
    }
}

#[test]
fn captured_chip_endpoint_remains_valid_through_retired_source_then_cannot_touch_reuse() {
    let (board, unit, _, line) = fixture_version(0x20);
    // SAFETY: same independent stopped board source and bounded programming peer.
    let mut pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let target = Target {
        destination: 3,
        vector: 0x51,
    };
    // Independent bounded hardware peer: do not invent a Registry reservation.
    // This fixture tests endpoint lifetime after the real pin state was installed.
    pin.target = Some(target);
    pin.retired = false;
    pin.lifetime.phase.store(PROGRAMMED, Ordering::Release);
    {
        let mut hardware = board.hw.lock().unwrap();
        hardware.regs[0x22] = MASK | u32::from(target.vector) | (1 << 13) | (1 << 15);
        hardware.regs[0x23] = u32::from(target.destination) << 24;
    }
    let domain = pin.notification_domain().unwrap();
    let endpoint = PinEoi {
        unit: ManuallyDrop::new(unit.clone()),
        lifetime: ManuallyDrop::new(pin.lifetime.clone()),
        pin: pin.pin,
        epoch: pin.epoch,
        target,
        line,
    };
    // SAFETY: original CPU callback/work peer is fully stopped and source masked.
    unsafe { pin.synchronize() }.unwrap();
    domain.check().unwrap();
    endpoint.after_local_eoi(Trigger::Edge).unwrap();
    drop(pin);
    assert_eq!(board.drops.load(Ordering::Relaxed), 1);
    assert_eq!(domain.check(), Err(posted_msi::Error::RootFailed));
    // SAFETY: the exact old board group has retired before this fresh claim.
    let replacement = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let writes = board.hw.lock().unwrap().events.len();
    assert_eq!(
        endpoint.after_local_eoi(Trigger::Edge),
        Err(IrqError::Unregistered)
    );
    assert_eq!(board.hw.lock().unwrap().events.len(), writes);
    drop(replacement);
}

#[test]
fn chip_eoi_fault_keeps_source_and_forbids_deferred_rearm() {
    let (board, unit, registry, line) = fixture_version(0x20);
    // SAFETY: this exact stopped board group belongs to the fixture.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let parent = pin.parent_mask().unwrap();
    let mut route = registry
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(board.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = board.hw.lock().unwrap();
        h.asserted = 1;
        h.service();
        h.tmr = Trigger::Edge;
        h.fail_read = true;
    }
    assert!(registry.dispatch(route.vector()));
    board.hw.lock().unwrap().fail_read = false;
    // SAFETY: original process peer; a failed chip acknowledgement cannot rearm.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Drain));
    assert!(route.retire().is_err());
    drop(route);
    assert_eq!(board.drops.load(Ordering::Relaxed), 0);
}
#[test]
fn real_parent_mask_contains_asserted_level_and_stale_endpoint_cannot_mask_reused_pin() {
    struct FailedDemux(Arc<ParentMask<Io, Cpu>>);
    impl Handler for FailedDemux {
        fn handle(&self) -> Disposition {
            // Callback cannot ACK its device. It must acknowledge
            // parent MASK before Registry's EOI instead of returning live.
            stela_drivers::bus::irq::ParentMask::mask(&*self.0).unwrap();
            Disposition::Handled
        }
    }
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let endpoint = Arc::new(pin.parent_mask().unwrap());
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(FailedDemux(endpoint.clone())),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = b.hw.lock().unwrap();
        h.asserted = 1;
        h.service();
    }
    assert!(r.dispatch(registration.vector()));
    {
        let h = b.hw.lock().unwrap();
        assert_eq!(
            h.asserted, 1,
            "test must retain the unacknowledged child cause"
        );
        assert_ne!(h.regs[0x22] & MASK, 0);
        assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
        assert!(!h.pending, "masked parent must not retrigger after EOI");
    }
    finish(registration.retire().unwrap());
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&*endpoint),
        Err(IrqError::Unregistered)
    );
    // SAFETY: the fixture owns the stopped line and its contributors.
    let replacement = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let replacement_mask = replacement.parent_mask().unwrap();
    let mut replacement = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(replacement),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&*endpoint),
        Err(IrqError::Unregistered)
    );
    assert_eq!(
        b.hw.lock().unwrap().regs[0x22] & MASK,
        0,
        "stale endpoint changed the new live route"
    );
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&replacement_mask),
        Ok(())
    );
    finish(replacement.retire().unwrap());
}

#[test]
fn deferred_rearm_checks_drain_epoch_and_retirement() {
    struct Deferred(Arc<ParentMask<Io, Cpu>>);
    impl Handler for Deferred {
        fn handle(&self) -> Disposition {
            stela_drivers::bus::irq::ParentMask::mask(&*self.0).unwrap();
            Disposition::Handled
        }
    }
    let (board, unit, registry, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { unit.claim(line, Box::new(Contributors(board.clone()))) }.unwrap();
    let parent = Arc::new(pin.parent_mask().unwrap());
    let mut route = registry
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Deferred(parent.clone())),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    // A still-live unmasked route cannot be rearmed as if it was drained.
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Route));
    {
        let mut hw = board.hw.lock().unwrap();
        hw.asserted = 1;
        hw.service();
    }
    assert!(registry.dispatch(route.vector()));
    {
        let mut hw = board.hw.lock().unwrap();
        hw.asserted = 0;
        hw.regs[0x22] |= REMOTE_IRR;
    }
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Drain));
    {
        let mut hw = board.hw.lock().unwrap();
        hw.regs[0x22] &= !REMOTE_IRR;
        hw.pending = true;
    }
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Drain));
    board.hw.lock().unwrap().pending = false;
    // SAFETY: the modeled child is acknowledged, EOI/IRR are drained,
    // and no deferred producer remains on this owning fixture CPU.
    unsafe { parent.rearm() }.unwrap();
    assert_eq!(board.hw.lock().unwrap().regs[0x22] & MASK, 0);
    finish(route.retire().unwrap());
    // SAFETY: the test is the parent mask's only caller, in process context.
    assert_eq!(unsafe { parent.rearm() }, Err(IrqError::Unregistered));
}

#[test]
fn parent_mask_readback_failures_are_errors_and_claim_epochs_never_wrap() {
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let endpoint = pin.parent_mask().unwrap();
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    b.hw.lock().unwrap().refuse_mask = true;
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&endpoint),
        Err(IrqError::Mask)
    );
    b.hw.lock().unwrap().fail_read = true;
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&endpoint),
        Err(IrqError::FailedRead)
    );
    {
        let mut h = b.hw.lock().unwrap();
        h.fail_read = false;
        h.refuse_mask = false;
    }
    finish(registration.retire().unwrap());
    {
        let _guard = u.lock();
        // SAFETY: the unit lock held above serializes the epoch counter.
        unsafe { *u.next_epoch.get() = u64::MAX };
    }
    assert!(matches!(
        // SAFETY: the fixture owns the stopped line and its contributors.
        unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
        Err(IrqError::Exhausted)
    ));
    assert_eq!(
        stela_drivers::bus::irq::ParentMask::mask(&endpoint),
        Err(IrqError::Unregistered)
    );
}

#[test]
fn true_level_retriggers_after_eoi_until_cause_ack_then_shared_group_retires() {
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let first: Arc<dyn Handler> = Arc::new(Member(b.clone(), 1, false));
    let second: Arc<dyn Handler> = Arc::new(Member(b.clone(), 2, true));
    let group = Arc::new(SharedHandlers::new(alloc::vec![first.clone(), second.clone()]).unwrap());
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: group.clone(),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = b.hw.lock().unwrap();
        h.asserted = 3;
        h.service();
    }
    assert!(r.dispatch(registration.vector()));
    {
        let h = b.hw.lock().unwrap();
        assert_eq!(h.asserted, 1);
        assert!(h.pending);
        assert_ne!(h.regs[0x22] & REMOTE_IRR, 0);
    }
    assert_eq!(registration.handled(), Ok(1));
    assert_eq!(Arc::strong_count(&group), 2);
    assert_eq!(Arc::strong_count(&first), 2);
    // A second delivery remains possible; removal must mask first,
    // stop every contributor, then drain CPU EOI and IOAPIC RemoteIRR.
    finish(registration.retire().unwrap());
    let h = b.hw.lock().unwrap();
    assert!(!h.pending);
    assert_eq!(h.regs[0x22] & REMOTE_IRR, 0);
    assert_ne!(h.regs[0x22] & MASK, 0);
    let mask = h.events.iter().rposition(|s| *s == "mask").unwrap();
    let stop = h.events.iter().rposition(|s| *s == "stopped").unwrap();
    assert!(mask < stop);
    assert_eq!(
        b.calls.load(Ordering::Relaxed),
        2,
        "closing delivery must never enter members"
    );
    drop(h);
    assert_eq!(b.drops.load(Ordering::Relaxed), 1);
    assert_eq!(Arc::strong_count(&group), 1);
    // SAFETY: the fixture owns the stopped line and its contributors.
    let reused = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    drop(reused);
}
#[test]
fn failed_controller_eoi_or_read_keeps_route_and_contributors_for_real_retry() {
    let (b, u, r, line) = fixture();
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    {
        let mut h = b.hw.lock().unwrap();
        h.asserted = 1;
        h.service();
        h.broken_eoi = true;
    }
    assert!(matches!(registration.retire(), Err(IrqError::Drain)));
    assert_eq!(b.drops.load(Ordering::Relaxed), 0);
    assert!(matches!(
        // SAFETY: the fixture owns the stopped line and its contributors.
        unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
        Err(IrqError::Drain)
    ));
    {
        let mut h = b.hw.lock().unwrap();
        h.fail_read = true;
    }
    assert!(matches!(registration.retire(), Err(IrqError::FailedRead)));
    {
        let mut h = b.hw.lock().unwrap();
        h.fail_read = false;
        h.broken_eoi = false;
        h.eoi();
    }
    finish(registration.retire().unwrap());
    assert_eq!(u.quarantine_count(), 0);
}
#[test]
fn electrical_route_mismatch_duplicate_claim_mask_failure_and_abandoned_pin_are_kept() {
    let (b, u, r, line) = fixture();
    assert!(matches!(
        // SAFETY: the unit lock and IRQ save serialize this selector/window pair on the owning
        // CPU.
        unsafe {
            u.claim(
                LineRoute {
                    trigger: Trigger::Edge,
                    ..line
                },
                Box::new(Contributors(b.clone())),
            )
        },
        Err(IrqError::Unsupported)
    ));
    // SAFETY: the fixture owns the stopped line and its contributors.
    let pin = unsafe { u.claim(line, Box::new(Contributors(b.clone()))) }.unwrap();
    assert!(matches!(
        // SAFETY: the fixture owns the stopped line and its contributors.
        unsafe { u.claim(line, Box::new(Contributors(b.clone()))) },
        Err(IrqError::Exhausted)
    ));
    let mut registration = r
        .request(stela_drivers::bus::irq::Request {
            source: Box::new(pin),
            handler: Arc::new(Member(b.clone(), 1, true)),
            routing: stela_drivers::bus::irq::RouteRequest::Line(line),
        })
        .unwrap();
    b.hw.lock().unwrap().refuse_mask = true;
    assert!(matches!(registration.retire(), Err(IrqError::Mask)));
    let before = b.drops.load(Ordering::Relaxed);
    drop(registration);
    assert_eq!(r.quarantine_count(), 1);
    assert_eq!(b.drops.load(Ordering::Relaxed), before);
    // Raw source owner also cannot silently free a programmed pin without
    // the unsafe completed-synchronization proof supplied by Registry.
    b.hw.lock().unwrap().refuse_mask = false;
    let other = LineRoute { gsi: 10, ..line };
    // SAFETY: the fixture owns the stopped line and its contributors.
    let mut pin = unsafe { u.claim(other, Box::new(Contributors(b.clone()))) }.unwrap();
    // Independent physical peer: hardware publication has already occurred.
    // No fabricated Registry reservation or completion receipt is constructed.
    pin.target = Some(Target {
        destination: 3,
        vector: FIRST_VECTOR + 1,
    });
    pin.retired = false;
    pin.lifetime.phase.store(PROGRAMMED, Ordering::Release);
    drop(pin);
    assert_eq!(u.quarantine_count(), 1);
}

fn finish(retired: stela_drivers::bus::irq::RetiredSource<dyn stela_drivers::bus::irq::Source>) {
    // SAFETY: this model's exact line route completed on its owner CPU.
    let (source, callback, route) =
        unsafe { retired.into_parts() }.unwrap_or_else(|_| panic!("model owner changed"));
    drop(source);
    drop(callback);
    drop(route);
}
