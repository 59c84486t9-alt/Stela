// SPDX-License-Identifier: GPL-2.0-only
//! transport behavior tests.
use super::*;

#[test]
fn cyclic_playback_refills_without_restart() {
    for dp in [false, true] {
        for channels in [2, 4, 6, 8] {
            let mut f = Fixture::new(dp);
            let mut c = f.controller();
            let port = f.attach(&mut c);
            let (stream, period) = f.stream(&mut c, channels, 24);
            let map = c.prepare_hdmi(port, stream, 2, None).unwrap();
            for n in 0..4 {
                c.write_pcm(stream, n * period, &vec![n as u8; period])
                    .unwrap();
            }
            c.start(stream).unwrap();
            let format = c.stream_format(stream).unwrap();
            for n in 0..24 {
                f.advance(period, format);
                let next = vec![(n + 4) as u8; period];
                let done = c.refill_hdmi_period(stream, &next).unwrap().unwrap();
                assert_eq!(done.sequence, n as u64);
                assert_eq!(done.ring_offset, n % 4 * period);
            }
            {
                let h = f.hardware.lock().unwrap();
                assert_eq!(h.starts, 1);
                assert_eq!(h.stops, 0);
                for (n, chunk) in h.playback.chunks(period).enumerate() {
                    assert!(chunk.iter().all(|b| *b == n as u8));
                }
                assert_eq!(h.packet[0], 0x84);
                assert_eq!(&h.packet[1..3], if dp { &[0x1b, 0x44] } else { &[1, 10] });
                assert_eq!(h.packet[7], map.allocation());
                assert_eq!(h.digital & 0x21, 1);
                assert_eq!(h.count, channels - 1);
                // A legacy codec has no device entries to select.
                assert!(!h.commands.iter().any(|c| (c >> 8) & 0xfff == 0x735));
            }
            c.close_hdmi(port).unwrap();
            assert_eq!(c.start(stream), Err(Error::SinkUnavailable));
            c.detach_hdmi_port(port).unwrap();
            c.shutdown().unwrap();
            assert_eq!(Arc::strong_count(&f.owner), 1);
        }
    }
}

#[test]
fn invalid_port_rejected() {
    for fault in 0..6 {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        match fault {
            0 => f.hardware.lock().unwrap().vendor = 0x10de0017,
            1 => f.hardware.lock().unwrap().vendor = 0x10de00a2,
            2 => f.hardware.lock().unwrap().pin_caps = 0x10,
            3 => f.hardware.lock().unwrap().bad_eld = Some(12),
            4 => f.hardware.lock().unwrap().eld[4] = 31,
            _ => f.owner.state.lock().unwrap().observe_fault = true,
        }
        let graph = c.enumerate_codec(0).unwrap();
        // SAFETY: The controller and display owner share this fixture's locked Hardware.
        // Invalid pin/device selectors are rejected before keeping a binding.
        let attached = unsafe { c.attach_hdmi_port(&graph, 4, 0, f.owner.clone()) };
        if fault == 3 || fault == 4 {
            let port = attached.unwrap();
            let (s, _) = f.stream(&mut c, 2, 16);
            assert_eq!(c.prepare_hdmi(port, s, 2, None), Err(Error::InvalidEld));
            c.detach_hdmi_port(port).unwrap();
        } else {
            assert!(attached.is_err());
        }
        assert_eq!(f.owner.state.lock().unwrap().enable, 0);
        assert_eq!(f.hardware.lock().unwrap().pin, 0);
    }
}

#[test]
fn mst_selects_each_device_entry() {
    let mut f = Fixture::new(true);
    {
        let mut h = f.hardware.lock().unwrap();
        h.vendor = 0x10de00a8;
        h.device_list = 3;
        h.device = 2;
        h.pin_caps |= 2;
    }
    let mut c = f.controller();
    let graph = c.enumerate_codec(0).unwrap();
    // Four entries: index 4 does not exist, and the owner must agree.
    f.owner.state.lock().unwrap().device = 4;
    assert_eq!(
        // SAFETY: The controller and display owner share this fixture's locked Hardware.
        // Invalid pin/device selectors are rejected before keeping a binding.
        unsafe { c.attach_hdmi_port(&graph, 4, 4, f.owner.clone()) },
        Err(Error::InvalidHdmiPort)
    );
    assert_eq!(
        // SAFETY: The controller and display owner share this fixture's locked Hardware.
        // Invalid pin/device selectors are rejected before keeping a binding.
        unsafe { c.attach_hdmi_port(&graph, 4, 2, f.owner.clone()) },
        Err(Error::InvalidHdmiPort)
    );
    f.owner.state.lock().unwrap().device = 2;
    // SAFETY: The controller and display owner share this fixture's locked Hardware.
    // Invalid pin/device selectors are rejected before keeping a binding.
    let port = unsafe { c.attach_hdmi_port(&graph, 4, 2, f.owner.clone()) }.unwrap();
    let (stream, period) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, stream, 2, None).unwrap();
    for n in 0..4 {
        c.write_pcm(stream, n * period, &vec![n as u8; period])
            .unwrap();
    }
    c.start(stream).unwrap();
    let format = c.stream_format(stream).unwrap();
    f.advance(period, format);
    c.refill_hdmi_period(stream, &vec![4; period])
        .unwrap()
        .unwrap();
    c.close_hdmi(port).unwrap();
    c.detach_hdmi_port(port).unwrap();
    c.shutdown().unwrap();
    let h = f.hardware.lock().unwrap();
    let select = (4 << 20) | (0x735 << 8) | 2;
    assert!(h.commands.contains(&select));
    // Sense is triggered, then read for the device entry.
    assert!(h.commands.contains(&((4 << 20) | (0x709 << 8))));
    assert!(h.commands.contains(&((4 << 20) | (0xf09 << 8) | 2)));
    assert_eq!(h.packet[..3], [0x84, 0x1b, 0x44]);
    assert_eq!((h.pin, h.transmit), (0, 0));
}

#[test]
fn hotplug_reprepares_same_port() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, period) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    {
        let mut o = f.owner.state.lock().unwrap();
        o.generation += 1;
        o.connected = false;
    }
    f.hardware.lock().unwrap().sense = 0;
    assert_eq!(c.status(s).unwrap_err(), Error::SinkChanged);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
    assert_eq!(f.hardware.lock().unwrap().pin, 0);
    assert_eq!(c.start(s), Err(Error::SinkUnavailable));
    assert_eq!(Arc::strong_count(&f.owner), 2);
    {
        let mut o = f.owner.state.lock().unwrap();
        o.generation += 1;
        o.connected = true;
    }
    f.hardware.lock().unwrap().sense = 0xc0000000;
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.write_pcm(s, 0, &vec![0x7a; period * 4]).unwrap();
    c.start(s).unwrap();
    assert_eq!(f.hardware.lock().unwrap().get(0x84, 4), 0);
    c.close_hdmi(port).unwrap();
    c.detach_hdmi_port(port).unwrap();
}

#[test]
fn coalesced_ioc_preserves_frontier() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, p) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    let fmt = c.stream_format(s).unwrap();
    f.advance(p / 2, fmt);
    assert!(c.refill_hdmi_period(s, &vec![8; p]).unwrap().is_none());
    f.advance(p + p / 2, fmt);
    assert!(c.status(s).unwrap().period_completed);
    for _ in 0..2 {
        assert!(c.refill_hdmi_period(s, &vec![9; p]).unwrap().is_some());
    }
    assert!(c.refill_hdmi_period(s, &vec![10; p]).unwrap().is_none());
    c.close_hdmi(port).unwrap();
    c.detach_hdmi_port(port).unwrap();
}

#[test]
fn late_refill_stops_stream() {
    for fault in 0..3 {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, p) = f.stream(&mut c, 2, 16);
        c.prepare_hdmi(port, s, 2, None).unwrap();
        c.start(s).unwrap();
        let fmt = c.stream_format(s).unwrap();
        match fault {
            0 => {
                f.clock.0.fetch_add(100000, Ordering::SeqCst);
            }
            1 => f.advance(p * 4 - 64, fmt),
            _ => {
                f.advance(p, fmt);
                let mut h = f.hardware.lock().unwrap();
                h.late_position = Some((h.position_reads + 2, (p * 4 - 64) as u32, 32_000));
            }
        }
        assert_eq!(
            c.refill_hdmi_period(s, &vec![0x39; p]),
            Err(Error::PlaybackUnderrun)
        );
        assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
        assert_eq!(
            c.hdmi_first_error(port).unwrap(),
            Some(Error::PlaybackUnderrun)
        );
        assert_eq!(c.start(s), Err(Error::SinkUnavailable));
        c.detach_hdmi_port(port).unwrap();
    }
}

#[test]
fn enable_failure_requires_reset() {
    for fault in 0..3 {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 6, 24);
        match fault {
            0 => f.owner.state.lock().unwrap().enable_late = true,
            1 => f.hardware.lock().unwrap().reject = Some(0x72d),
            _ => f.hardware.lock().unwrap().drop_reply = Some(0x706),
        }
        let error = c.prepare_hdmi(port, s, 2, None).unwrap_err();
        assert_eq!(c.hdmi_first_error(port).unwrap(), Some(error));
        assert_eq!(Arc::strong_count(&f.owner), 2);
        assert_eq!(c.start(s), Err(Error::NeedsReset));
        f.owner.state.lock().unwrap().enable_late = false;
        {
            let mut h = f.hardware.lock().unwrap();
            h.reject = None;
            h.drop_reply = None;
        }
        c.reinitialize().unwrap();
        assert_eq!(Arc::strong_count(&f.owner), 1);
        assert_eq!(c.hdmi_first_error(port), Err(Error::InvalidHdmiPort));
    }
}
