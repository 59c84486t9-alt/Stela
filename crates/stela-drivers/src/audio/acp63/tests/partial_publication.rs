// SPDX-License-Identifier: GPL-2.0-only
//! Partial publication cases.
use super::*;

fn check_ps_partial_publication<P: Profile>(
    (mut controller, device, source): (
        acp_pdm::Controller<Model, Time, P>,
        Arc<Mutex<Device>>,
        Source,
    ),
    resume: bool,
) {
    controller.initialize().unwrap();
    if resume {
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        controller.suspend_retained(false).unwrap();
    }
    device.lock().unwrap().fail_after_write = Some(0x10004);
    let result = if resume {
        controller.resume_retained()
    } else {
        controller.prepare_capture(&source, CAPTURE_FORMAT, 4096)
    };
    assert_eq!(result, Err(Error::RegisterUnavailable(0x10004)));
    assert!(controller.capture.as_ref().unwrap().published);
    {
        let model = device.lock().unwrap();
        assert_eq!(model.unmaps, 0);
        assert_eq!(
            model.writes.iter().filter(|(at, _)| *at == 0xc40).count(),
            usize::from(resume),
            "partial PTE programming cannot issue the end-of-ring invalidate request"
        );
    }
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    controller.shutdown().unwrap();
    assert_eq!(device.lock().unwrap().unmaps, 1);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn ps_partial_setup_and_resume_publication_never_invalidate_or_release_early() {
    for resume in [false, true] {
        check_ps_partial_publication(fixture(0x63), resume);
        for revision in 0x70..=0x72 {
            check_ps_partial_publication(fixture70(revision), resume);
        }
    }
}
