// SPDX-License-Identifier: GPL-2.0-only
//! Posted payload cases.
use super::*;

fn check_ps_posted_payload<P: Profile>(
    (mut controller, device, source): (
        acp_pdm::Controller<Model, Time, P>,
        Arc<Mutex<Device>>,
        Source,
    ),
) {
    controller.initialize().unwrap();
    controller
        .prepare_capture(&source, CAPTURE_FORMAT, 4096)
        .unwrap();
    controller.start().unwrap();
    {
        let mut model = device.lock().unwrap();
        model.defer_payload = true;
        model.advance(512);
        let drains = model.drains;
        model.write(0xc40, 1);
        assert_eq!(model.posted.len(), 1024);
        assert_eq!(
            model.drains, drains,
            "cache command cannot complete posted payload"
        );
        model.drain_fail = true;
    }
    assert_eq!(
        controller.stop(),
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(
        controller.shutdown(),
        Err(Error::Dma(DmaError::InvalidationFailed))
    );
    assert_eq!(device.lock().unwrap().posted.len(), 1024);
    assert_eq!(device.lock().unwrap().cpu_syncs, 0);
    assert_eq!(device.lock().unwrap().unmaps, 0);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    {
        let mut model = device.lock().unwrap();
        model.drain_fail = false;
        model.drain_unavailable = true;
    }
    assert_eq!(
        controller.initialize(),
        Err(Error::Dma(DmaError::DrainUnavailable))
    );
    assert_eq!(device.lock().unwrap().posted.len(), 1024);
    assert_eq!(source.drops.load(Ordering::Relaxed), 0);
    device.lock().unwrap().drain_unavailable = false;
    controller.shutdown().unwrap();
    assert!(device.lock().unwrap().posted.is_empty());
    assert_eq!(device.lock().unwrap().unmaps, 1);
    assert_eq!(source.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn ps_cache_request_never_drains_payload_or_authorizes_faulted_release() {
    check_ps_posted_payload(fixture(0x63));
    for revision in 0x70..=0x72 {
        check_ps_posted_payload(fixture70(revision));
    }
}
