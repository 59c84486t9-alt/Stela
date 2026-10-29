// SPDX-License-Identifier: GPL-2.0-only
//! Streams cases.
use super::*;

#[test]
fn streams_queue_actual_status_and_data_before_command_and_cycle_only_allocated_tags() {
    for input in [false, true] {
        for fault in [Fault::None, Fault::StatusBeforeData, Fault::CommandLast] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, input, fault);
            let state = io.state.clone();
            state.borrow_mut().streams = Some(2);
            let mut engine = Engine::new(io, &mut dma).unwrap();
            for _ in 0..4 {
                let data = vec![0x9a; 512];
                let result = engine
                    .command(
                        [0; 8],
                        &rw(input, 512),
                        if input {
                            Data::In(512)
                        } else {
                            Data::Out(&data)
                        },
                    )
                    .unwrap();
                if input {
                    assert_eq!(result, vec![0x6d; 512]);
                } else {
                    assert_eq!(state.borrow().written, data);
                }
                assert!(state.borrow().active.is_empty());
            }
            let state = state.borrow();
            let tags: Vec<_> = state
                .history
                .iter()
                .map(|iu| u16::from_be_bytes([iu[2], iu[3]]))
                .collect();
            assert_eq!(tags, vec![1, 2, 1, 2]);
            let data = if input { Pipe::Input } else { Pipe::Output };
            assert_eq!(
                &state.events[..3],
                &[
                    Event::Post(Pipe::Status),
                    Event::Post(data),
                    Event::Post(Pipe::Command)
                ]
            );
            if fault == Fault::CommandLast {
                let complete = |pipe| {
                    state
                        .events
                        .iter()
                        .position(|e| *e == Event::Complete(pipe))
                        .unwrap()
                };
                assert!(complete(data) < complete(Pipe::Status));
                assert!(complete(Pipe::Status) < complete(Pipe::Command));
            }
        }
    }
}

#[test]
fn stream_errors_drain_all_contributors_or_quarantine_without_dma_reuse() {
    for input in [false, true] {
        for fault in [
            Fault::ErrorAfterReady,
            Fault::CancelError,
            Fault::WrongReady,
            Fault::WrongTag,
            Fault::MalformedStatus,
            Fault::ShortCommand,
            Fault::Timeout,
            Fault::SubmitData,
            Fault::SubmitCommand,
            Fault::SubmitStatus,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, input, fault);
            let state = io.state.clone();
            state.borrow_mut().streams = Some(2);
            let mut engine = Engine::new(io, &mut dma).unwrap();
            let outgoing = vec![0x44; 512];
            let result = engine.command(
                [0; 8],
                &rw(input, 512),
                if input {
                    Data::In(512)
                } else {
                    Data::Out(&outgoing)
                },
            );
            assert!(result.is_err(), "{fault:?}");
            if fault == Fault::ErrorAfterReady {
                assert_eq!(
                    result,
                    Err(BlockError::Sense(Sense {
                        key: 0x02,
                        asc: 0x3a,
                        ascq: 0x00
                    }))
                );
                assert!(!engine.poisoned);
                assert!(state.borrow().active.is_empty());
            } else {
                assert!(engine.poisoned, "{fault:?}");
                let count = state.borrow().events.len();
                let data = engine.data.bytes().to_vec();
                assert!(
                    engine
                        .command([0; 8], &rw(false, 512), Data::Out(&outgoing))
                        .is_err()
                );
                assert_eq!(state.borrow().events.len(), count);
                assert_eq!(engine.data.bytes(), data);
                if fault == Fault::CancelError {
                    assert!(
                        state
                            .borrow()
                            .active
                            .iter()
                            .any(|t| matches!(t.pipe, Pipe::Input | Pipe::Output))
                    );
                } else {
                    assert!(state.borrow().active.is_empty());
                }
            }
        }
    }
}

#[test]
fn streamed_discovery_block_io_and_required_flush_use_actual_reported_lun_and_streams() {
    use crate::block::BlockDevice;
    let sparse = Lun::from_bytes([0x40, 7, 0, 3, 0, 0, 0, 0]);
    let mut target = Target::new(vec![
        Media::disk(Lun::default(), 0x10),
        Media::disk(sparse, 0x70),
    ]);
    target.reported = vec![sparse];
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 0, false, Fault::CommandLast);
    let state = io.state.clone();
    {
        let mut state = state.borrow_mut();
        state.streams = Some(2);
        state.target = Some(target);
    }
    let owner = Rc::new(RefCell::new(ScsiModel {
        engine: Engine::new(io, &mut dma).unwrap(),
        flags: quirks::Flags::from_id(0x4971, 0x8024, 0),
    }));
    let mut failures = Vec::new();
    let mut disks =
        crate::usb::storage::discover_uas_units(owner, "native", "serial", &mut failures).unwrap();
    assert_eq!(disks.len(), 2);
    assert!(failures.is_empty());
    assert_eq!(disks[1].lun, sparse);
    disks[1].write(1, &[0x55; 512]).unwrap();
    let mut bytes = [0; 512];
    disks[1].read(1, &mut bytes).unwrap();
    assert_eq!(bytes, [0x55; 512]);
    disks[1].flush().unwrap();
    let state = state.borrow();
    assert!(state.active.is_empty());
    assert_eq!(state.target.as_ref().unwrap().flushes, vec![sparse]);
    assert!(
        state
            .history
            .iter()
            .all(|iu| (1..=2).contains(&u16::from_be_bytes([iu[2], iu[3]])))
    );
}

#[test]
fn zero_allocated_streams_refuses_owner_before_submitting() {
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
    let state = io.state.clone();
    state.borrow_mut().streams = Some(0);
    assert!(Engine::new(io, &mut dma).is_err());
    assert!(state.borrow().events.is_empty());
}
