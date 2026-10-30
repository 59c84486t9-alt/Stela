// SPDX-License-Identifier: GPL-2.0-only
//! lifecycle behavior tests.
use super::*;

#[test]
fn stop_failure_keeps_first_cause() {
    for dma_fault in [false, true] {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 2, 16);
        c.prepare_hdmi(port, s, 2, None).unwrap();
        c.start(s).unwrap();
        if dma_fault {
            f.hardware.lock().unwrap().stop_stuck = true;
        } else {
            f.owner.state.lock().unwrap().disable_fault = true;
        }
        assert!(c.close_hdmi(port).is_err());
        let first = c.hdmi_first_error(port).unwrap();
        assert!(first.is_some());
        assert_eq!(Arc::strong_count(&f.owner), 2);
        assert!(c.detach_hdmi_port(port).is_err());
        assert_eq!(c.hdmi_first_error(port).unwrap(), first);
        f.hardware.lock().unwrap().stop_stuck = false;
        f.owner.state.lock().unwrap().disable_fault = false;
        c.reinitialize().unwrap();
        assert_eq!(Arc::strong_count(&f.owner), 1);
    }
}

#[test]
fn drop_keeps_active_owner() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    drop(c);
    assert_eq!(Arc::strong_count(&f.owner), 2);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 2);
}

#[test]
fn analog_and_hdmi_streams_are_exclusive() {
    for analog_first in [false, true] {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 2, 16);
        let analog = c.enumerate_codec(1).unwrap();
        let route = analog.analog_route(Direction::Playback, 4, 2).unwrap();
        let options = crate::hda::PinOptions::Playback {
            headphone: false,
            eapd: None,
        };
        if analog_first {
            c.configure_analog_route(&analog, &route, s, 0, options)
                .unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(c.prepare_hdmi(port, s, 2, None), Err(Error::RouteInUse));
            assert_eq!(f.owner.state.lock().unwrap().enable, 0);
            assert!(
                f.hardware.lock().unwrap().commands[before..]
                    .iter()
                    .all(|command| command & (1 << 19) != 0)
            );
        } else {
            c.prepare_hdmi(port, s, 2, None).unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(
                c.configure_analog_route(&analog, &route, s, 0, options),
                Err(Error::RouteInUse)
            );
            let h = f.hardware.lock().unwrap();
            assert_eq!(h.commands.len(), before);
            assert_eq!(h.analog.binding, 0);
            assert_eq!(h.analog.pin, 0);
        }
        c.close_hdmi(port).unwrap();
        c.detach_hdmi_port(port).unwrap();
        c.shutdown().unwrap();
    }
}

#[test]
fn stopped_stream_restarts_new_epoch() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, p) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    let fmt = c.stream_format(s).unwrap();
    f.advance(p, fmt);
    c.stop(s).unwrap();
    f.clock.0.fetch_add(1_000_000, Ordering::SeqCst);
    assert!(!c.status(s).unwrap().running);
    assert_eq!(c.hdmi_first_error(port).unwrap(), None);
    assert_eq!(f.owner.state.lock().unwrap().disable, 0);
    c.write_pcm(s, 0, &vec![0x6d; p * 4]).unwrap();
    c.start(s).unwrap();
    f.hardware.lock().unwrap().playback.clear();
    f.advance(p, fmt);
    assert!(c.refill_hdmi_period(s, &vec![0x91; p]).unwrap().is_some());
    assert!(
        f.hardware
            .lock()
            .unwrap()
            .playback
            .iter()
            .all(|v| *v == 0x6d)
    );
    c.close_hdmi(port).unwrap();
    c.detach_hdmi_port(port).unwrap();
}

#[test]
fn digital_enable_preserves_status() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, p) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    for enabled in [false, true, false, true] {
        c.set_hdmi_enabled(port, enabled).unwrap();
        assert_eq!(f.hardware.lock().unwrap().digital, 0x10 | u8::from(enabled));
        assert!(c.status(s).unwrap().running);
    }
    let fmt = c.stream_format(s).unwrap();
    f.advance(p, fmt);
    assert!(c.refill_hdmi_period(s, &vec![0x53; p]).unwrap().is_some());
    assert_eq!(f.owner.state.lock().unwrap().enable, 1);
    c.close_hdmi(port).unwrap();
    assert_eq!(c.set_hdmi_enabled(port, false), Err(Error::SinkUnavailable));
    c.detach_hdmi_port(port).unwrap();
}

#[test]
fn digital_control_failure_requires_reset() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    f.hardware.lock().unwrap().reject = Some(0x70d);
    assert_eq!(c.set_hdmi_enabled(port, false), Err(Error::RouteRejected));
    assert_eq!(
        c.hdmi_first_error(port).unwrap(),
        Some(Error::RouteRejected)
    );
    assert_eq!(Arc::strong_count(&f.owner), 2);
    f.hardware.lock().unwrap().reject = None;
    c.reinitialize().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
}

#[test]
fn observation_error_precedes_stop_error() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    f.owner.state.lock().unwrap().observe_fault = true;
    f.hardware.lock().unwrap().stop_stuck = true;
    assert_eq!(c.poll_hdmi_sink(port), Err(Error::SinkUnavailable));
    assert_eq!(
        c.hdmi_first_error(port).unwrap(),
        Some(Error::SinkUnavailable)
    );
    assert_eq!(Arc::strong_count(&f.owner), 2);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 2);
    f.owner.state.lock().unwrap().observe_fault = false;
    f.hardware.lock().unwrap().stop_stuck = false;
    c.reinitialize().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
}

#[test]
fn suspend_waits_for_complete_quiescence() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    let before = f.hardware.lock().unwrap().commands.len();
    assert_eq!(c.retire_hdmi_for_pci_suspend(), Err(Error::NeedsReset));
    assert_eq!(f.hardware.lock().unwrap().commands.len(), before);
    assert_eq!(Arc::strong_count(&f.owner), 2);
    c.shutdown().unwrap();
    assert_eq!(f.hardware.lock().unwrap().pin, 0);
    assert_eq!(f.hardware.lock().unwrap().transmit, 0);
    assert_eq!(f.hardware.lock().unwrap().binding, 0);
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
    assert_eq!(f.hardware.lock().unwrap().bar[0x4c] & 2, 0);
    assert_eq!(f.hardware.lock().unwrap().bar[0x5c] & 2, 0);
    assert_eq!(Arc::strong_count(&f.owner), 2);
    c.retire_hdmi_for_pci_suspend().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
    assert_eq!(c.hdmi_first_error(port), Err(Error::InvalidHdmiPort));
    c.reinitialize().unwrap();
    assert_eq!(c.hdmi_first_error(port), Err(Error::InvalidHdmiPort));
}

#[test]
fn uncertain_gpu_stop_blocks_d3() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let port = f.attach(&mut c);
    let (s, _) = f.stream(&mut c, 2, 16);
    c.prepare_hdmi(port, s, 2, None).unwrap();
    c.start(s).unwrap();
    f.owner.state.lock().unwrap().disable_fault = true;
    assert_eq!(c.shutdown(), Err(Error::SinkUnavailable));
    assert_eq!(f.hardware.lock().unwrap().bar[0x80] & 2, 0);
    assert_eq!(c.retire_hdmi_for_pci_suspend(), Err(Error::NeedsReset));
    assert_eq!(Arc::strong_count(&f.owner), 2);
    assert_eq!(
        c.hdmi_first_error(port).unwrap(),
        Some(Error::SinkUnavailable)
    );
    f.owner.state.lock().unwrap().disable_fault = false;
    c.reinitialize().unwrap();
    assert_eq!(Arc::strong_count(&f.owner), 1);
}

#[test]
fn mmio_graph_has_no_pci_subsystem() {
    let mut f = Fixture::new(false);
    let mut c = f.controller();
    let before = f.hardware.lock().unwrap().commands.len();
    assert_eq!(c.registers.codec_pci_subsystem().unwrap(), None);
    assert_eq!(f.hardware.lock().unwrap().commands.len(), before);
    c.shutdown().unwrap();
}

#[test]
fn raw_binding_excludes_hdmi_stream() {
    for raw_first in [false, true] {
        let mut f = Fixture::new(false);
        let mut c = f.controller();
        let port = f.attach(&mut c);
        let (s, _) = f.stream(&mut c, 2, 16);
        let analog = c.enumerate_codec(1).unwrap();
        if raw_first {
            c.bind_converter(&analog, 2, s, 0).unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(c.prepare_hdmi(port, s, 2, None), Err(Error::RouteInUse));
            assert_eq!(f.owner.state.lock().unwrap().enable, 0);
            assert!(
                f.hardware.lock().unwrap().commands[before..]
                    .iter()
                    .all(|v| v & (1 << 19) != 0)
            );
        } else {
            c.prepare_hdmi(port, s, 2, None).unwrap();
            let before = f.hardware.lock().unwrap().commands.len();
            assert_eq!(c.bind_converter(&analog, 2, s, 0), Err(Error::RouteInUse));
            assert_eq!(f.hardware.lock().unwrap().commands.len(), before);
        }
        c.close_hdmi(port).unwrap();
        c.detach_hdmi_port(port).unwrap();
        c.shutdown().unwrap();
    }
}
