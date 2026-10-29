// SPDX-License-Identifier: GPL-2.0-only
//! Retirement cases.
use super::*;

#[test]
fn lost_endpoint_readiness_fences_every_published_lun_before_dma_mutation() {
    use crate::block::BlockDevice;
    use crate::usb::storage::media::{Owner, scan_uas};
    for streams in [None, Some(2)] {
        let mut memory = vec![0u64; 32 * 1024];
        let (raw, state) = target_owner(
            &mut memory,
            Target::new(vec![
                Media::disk(Lun::default(), 1),
                Media::disk(Lun::sequential(4), 4),
            ]),
            quirks::Flags::default(),
        );
        state.borrow_mut().streams = streams;
        let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
        let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
        let mut disks = scan_uas(owner.clone(), &mut Vec::new()).unwrap();
        let before = {
            let owner = owner.borrow();
            let engine = &owner.transport.engine;
            (
                engine.command.bytes().to_vec(),
                engine.status.bytes().to_vec(),
                engine.data.bytes().to_vec(),
            )
        };
        state.borrow_mut().fault = Fault::EndpointUnavailable;
        let events = state.borrow().events.len();
        assert!(disks[0].write(0, &[0xa5; 512]).is_err());
        assert!(disks[1].read(0, &mut [0; 512]).is_err());
        state.borrow_mut().fault = Fault::None;
        assert!(
            disks[0].flush().is_err(),
            "old owner revived after readiness recovered"
        );
        assert_eq!(state.borrow().events.len(), events);
        let owner = owner.borrow();
        let engine = &owner.transport.engine;
        assert!(engine.poisoned);
        assert_eq!(engine.command.bytes(), before.0);
        assert_eq!(engine.status.bytes(), before.1);
        assert_eq!(engine.data.bytes(), before.2);
    }
}

#[test]
fn failed_error_path_cancellation_retains_poison_and_actual_pending_data() {
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 512, true, Fault::CancelError);
    let state = io.state.clone();
    let mut engine = Engine::new(io, &mut dma).unwrap();
    assert!(
        engine
            .command([0; 8], &rw(true, 512), Data::In(512))
            .is_err()
    );
    assert!(engine.poisoned);
    assert!(state.borrow().active.iter().any(|t| t.pipe == Pipe::Input));
}
