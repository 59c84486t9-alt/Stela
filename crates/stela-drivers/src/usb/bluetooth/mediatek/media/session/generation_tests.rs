// SPDX-License-Identifier: ISC
//! Hostile cached session state around an addressed/configured native
//! transport. This fixture does not invent initialization evidence or check
//! public Session::start, radio readiness, firmware or an HCI command allowance.
use super::*;
use crate::usb::bluetooth::Host;

pub(in crate::usb::bluetooth) fn peer(hci: Hci<Host>, dma: &mut dyn DmaAllocator) -> Session<Host> {
    let bindings = Bindings::new(hci.binding()).unwrap();
    let sco = bindings.sco(voice()).unwrap();
    let mut sco_frames = framing::Framer::new(Kind::Sco);
    let mut iso_frames = framing::Framer::new(Kind::Iso);
    assert!(sco_frames.feed(&[1, 0, 4, 0xa5], 0).unwrap().is_empty());
    assert!(iso_frames.feed(&[1, 0, 4, 0, 0xb6], 0).unwrap().is_empty());
    let mut session = Session {
        hci,
        bindings,
        sco,
        sco_frames,
        iso_frames,
        pending: vec![Received::Hci(Packet::Event(vec![0xff, 1, 0x5a]))],
        lifecycle: Lifecycle::Running,
        // No invented synchronous completion or command credit.
        setup: None,
        last_reset: None,
        coredump: None,
        wideband_mtu: None,
    };
    // This already selected voice is admitted while the owner is live.
    session.set_voice(voice(), dma).unwrap();
    session
}

fn voice() -> Voice {
    Voice {
        connections: 1,
        air_mode: crate::usb::bluetooth::mediatek::media::AirMode::Cvsd,
        voice_setting: 0,
    }
}

pub(in crate::usb::bluetooth) fn hci(session: &mut Session<Host>) -> &mut Hci<Host> {
    &mut session.hci
}

pub(in crate::usb::bluetooth) fn refuse(session: &mut Session<Host>, dma: &mut dyn DmaAllocator) {
    let snapshot = |s: &Session<Host>| {
        (
            alloc::format!("{:?}", s.pending),
            s.sco_frames.snapshot(),
            s.iso_frames.snapshot(),
            s.sco,
            s.hci.state(),
            s.setup.clone(),
            s.last_reset.clone(),
        )
    };
    let before = snapshot(session);
    assert_eq!(session.lifecycle(), Lifecycle::Running);
    assert!(session.set_voice(voice(), dma).is_err()); // Same configured pair.
    assert!(session.poll().is_err()); // Queued notices and expired partial frames.
    assert!(session.submit_command(&[3, 0x0c, 0]).is_err());
    assert!(session.submit_acl(&[1, 0, 0, 0]).is_err());
    assert!(session.submit(Kind::Sco, &[1, 0, 0]).is_err());
    assert!(session.submit(Kind::Iso, &[1, 0, 0, 0]).is_err());
    assert!(session.quiesce().is_err());
    assert!(session.close().is_err());
    assert_eq!(session.lifecycle(), Lifecycle::Running);
    assert_eq!(snapshot(session), before);

    // Exercise each already-quiescent/closed wrapper branch without inventing
    // any native endpoint completion, identity, grant or initialization receipt.
    session.lifecycle = Lifecycle::Quiescent;
    assert!(session.resume().is_err());
    assert!(session.close().is_err());
    assert_eq!(session.lifecycle(), Lifecycle::Quiescent);
    assert_eq!(snapshot(session), before);
    session.lifecycle = Lifecycle::Closed;
    assert!(session.close().is_err()); // No stale idempotent-success permission.
    assert_eq!(session.lifecycle(), Lifecycle::Closed);
    assert_eq!(snapshot(session), before);
    session.lifecycle = Lifecycle::Running;
}
