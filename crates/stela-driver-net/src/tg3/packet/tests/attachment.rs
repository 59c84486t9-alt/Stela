// SPDX-License-Identifier: GPL-2.0-only
//! The unique requester attachment retires after the packet owner drains RAM.
use super::*;

#[derive(Default)]
struct ControlState {
    calls: AtomicUsize,
    dropped: AtomicUsize,
    refuse: AtomicBool,
}
struct Control {
    domain: Arc<Domain>,
    state: Arc<ControlState>,
    detached: bool,
}
impl Drop for Control {
    fn drop(&mut self) {
        self.state.dropped.fetch_add(1, Ordering::Relaxed);
        if !self.detached {
            core::mem::forget(self.domain.clone());
        }
    }
}
// SAFETY: this independent synchronous RAM peer verifies its engine/BME stop,
// posted-write drain and lack of live mappings. It reaches no native device.
unsafe impl Attachment for Control {
    fn domain(&self) -> Arc<dyn DmaDomain> {
        self.domain.clone()
    }
    unsafe fn detach(&mut self) -> Result<(), DmaError> {
        self.domain.require_stopped();
        assert!(self.domain.drained.load(Ordering::Relaxed));
        assert!(self.domain.maps.lock().unwrap().is_empty());
        assert!(self.domain.posted.lock().unwrap().is_empty());
        self.state.calls.fetch_add(1, Ordering::Relaxed);
        if self.state.refuse.load(Ordering::Relaxed) {
            return Err(DmaError::InvalidationFailed);
        }
        self.detached = true;
        Ok(())
    }
}
struct Fixture {
    packet: Packet<Reg, Timer>,
    pages: Pages,
    domain: Arc<Domain>,
    peer: Arc<Mutex<Device>>,
    state: Arc<ControlState>,
}
fn attached() -> Fixture {
    let (hardware, pages, domain, peer) = parts();
    let state = Arc::new(ControlState::default());
    let attachment = Box::new(Control {
        domain: domain.clone(),
        state: state.clone(),
        detached: false,
    });
    // SAFETY: all original configuration, device/RAM, remapper and timer
    // owners belong to this isolated fixture, with no IRQ/work users.
    let packet = unsafe { Packet::attach_bound(hardware, &pages, attachment) }
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    Fixture {
        packet,
        pages,
        domain,
        peer,
        state,
    }
}

#[test]
fn detach_follows_payload_drain_and_all_ring_unmaps_before_register_release() {
    let Fixture {
        packet,
        pages,
        peer,
        state,
        ..
    } = attached();
    assert_eq!(state.calls.load(Ordering::Relaxed), 0);
    let registers = packet
        .retire()
        .unwrap_or_else(|(error, _)| panic!("{error:?}"));
    assert_eq!(state.calls.load(Ordering::Relaxed), 1);
    assert_eq!(state.dropped.load(Ordering::Relaxed), 1);
    assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
    assert_eq!(peer.lock().unwrap().drops, 0);
    drop(registers);
    assert_eq!(peer.lock().unwrap().drops, 1);
}

#[test]
fn failed_unmap_prevents_detach_until_retirement_retry() {
    let Fixture {
        packet,
        pages,
        domain,
        peer,
        state,
    } = attached();
    domain.fail_unmap.store(true, Ordering::Relaxed);
    let (error, packet) = packet.retire().err().expect("injected unmap failure");
    assert_eq!(error, Error::Dma(DmaError::InvalidationFailed));
    assert_eq!(state.calls.load(Ordering::Relaxed), 0);
    assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
    assert_eq!(peer.lock().unwrap().drops, 0);
    domain.fail_unmap.store(false, Ordering::Relaxed);
    assert!(packet.retire().is_ok());
    assert_eq!(state.calls.load(Ordering::Relaxed), 1);
}

#[test]
fn failed_detach_retains_registers_and_backing_and_cannot_restart() {
    let Fixture {
        packet,
        pages,
        domain,
        peer,
        state,
    } = attached();
    state.refuse.store(true, Ordering::Relaxed);
    let (error, mut packet) = packet.retire().err().expect("injected detach failure");
    assert_eq!(error, Error::Dma(DmaError::InvalidationFailed));
    assert!(domain.maps.lock().unwrap().is_empty());
    assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
    assert_eq!(peer.lock().unwrap().drops, 0);
    assert_eq!(state.dropped.load(Ordering::Relaxed), 0);
    assert_eq!(packet.restart(), Err(Error::Stopped));
    state.refuse.store(false, Ordering::Relaxed);
    assert!(packet.retire().is_ok());
    assert_eq!(state.calls.load(Ordering::Relaxed), 2);
    assert_eq!(state.dropped.load(Ordering::Relaxed), 1);
    assert_eq!(pages.drops.load(Ordering::Relaxed), 6);
}

#[test]
fn failed_engine_stop_keeps_attachment_and_never_attempts_detach() {
    let Fixture {
        packet,
        pages,
        peer,
        state,
        ..
    } = attached();
    peer.lock().unwrap().stop_stuck = Some(0x4c00);
    let (_, packet) = packet.retire().err().expect("injected engine failure");
    assert_eq!(state.calls.load(Ordering::Relaxed), 0);
    drop(packet);
    assert_eq!(peer.lock().unwrap().drops, 0);
    assert_eq!(pages.drops.load(Ordering::Relaxed), 0);
}
