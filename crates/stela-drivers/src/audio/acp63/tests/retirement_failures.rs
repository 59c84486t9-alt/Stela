// SPDX-License-Identifier: GPL-2.0-only
//! Retirement failures cases.
use super::*;

#[derive(Clone, Copy, Debug)]
enum RetirePath {
    Replace,
    Suspend,
    Resume,
    Shutdown,
}

fn check_ps_retirement_failure<P: Profile>(
    (mut controller, device, source): (
        acp_pdm::Controller<Model, Time, P>,
        Arc<Mutex<Device>>,
        Source,
    ),
    path: RetirePath,
    fault: usize,
) {
    controller.initialize().unwrap();
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    controller.start().unwrap();
    device.lock().unwrap().advance(32);
    if matches!(path, RetirePath::Replace) {
        controller.stop().unwrap();
    }
    if matches!(path, RetirePath::Resume) {
        controller.suspend_retained(false).unwrap();
    }
    let capture = controller.capture.as_ref().unwrap();
    let address = capture.dma.address().unwrap();
    let cpu = capture.cpu.address(0, 4).unwrap();
    let expected = {
        let mut model = device.lock().unwrap();
        match fault {
            0 => {
                // A stale group can survive reset; an ignored write must
                // fail even when entering from kept suspension.
                model.words[0xc04 / 4] = 0x8380_0000;
                model.ignore_write = Some(0xc04);
                Error::RegisterRejected(0xc04)
            }
            1 => {
                model.fail_after_write = Some(0xc04);
                Error::RegisterUnavailable(0xc04)
            }
            2 => {
                model.reject_bme_disable = true;
                Error::PciAuthority
            }
            3 => {
                model.reset_never = true;
                Error::Timeout(Phase::ResetClear)
            }
            4 => {
                model.drain_fail = true;
                Error::Dma(DmaError::InvalidationFailed)
            }
            _ => {
                model.drain_unavailable = true;
                Error::Dma(DmaError::DrainUnavailable)
            }
        }
    };
    let result = match path {
        RetirePath::Replace => controller.prepare_capture(&source, CAPTURE_FORMAT, 8192),
        RetirePath::Suspend => controller.suspend_retained(false),
        RetirePath::Resume => controller.resume_retained(),
        RetirePath::Shutdown => controller.shutdown(),
    };
    assert_eq!(result, Err(expected), "{path:?}, fault {fault}");
    assert_eq!(controller.first_error(), Some(expected));
    assert_eq!(controller.state(), State::Faulted);
    let capture = controller.capture.as_ref().unwrap();
    assert_eq!(capture.dma.address().unwrap(), address);
    assert_eq!(capture.cpu.address(0, 4).unwrap(), cpu);
    assert!(capture.published);
    {
        let mut model = device.lock().unwrap();
        assert_eq!(model.translation.as_ref().unwrap().token.address, address);
        assert_eq!(model.maps, 1);
        assert_eq!(model.unmaps, 0);
        assert_eq!(model.atu_reads, 0);
        assert_eq!(
            model.writes.iter().filter(|(at, _)| *at == 0xc40).count(),
            1
        );
        if fault == 2 && !matches!(path, RetirePath::Replace | RetirePath::Resume) {
            assert!(
                model.master,
                "failed BME containment cannot clear ownership by assumption"
            );
        }
        model.ignore_write = None;
        model.reject_bme_disable = false;
        model.reset_never = false;
        model.drain_fail = false;
        model.drain_unavailable = false;
    }
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    controller.shutdown().unwrap();
    assert_eq!(controller.first_error(), Some(expected));
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    assert_eq!(device.lock().unwrap().unmaps, 1);
}

#[test]
fn ps_actual_reset_group_bme_and_domain_failures_retain_exact_published_owners() {
    for path in [
        RetirePath::Replace,
        RetirePath::Suspend,
        RetirePath::Resume,
        RetirePath::Shutdown,
    ] {
        for fault in 0..6 {
            check_ps_retirement_failure(fixture(0x63), path, fault);
            for revision in 0x70..=0x72 {
                check_ps_retirement_failure(fixture70(revision), path, fault);
            }
        }
    }
}
