// SPDX-License-Identifier: GPL-2.0-only
//! Transport errors cases.
use super::*;

#[test]
fn invalid_ready_tag_status_or_command_length_quarantines_without_reusing_dma() {
    for fault in [
        Fault::WrongReady,
        Fault::WrongTag,
        Fault::MalformedStatus,
        Fault::ShortCommand,
        Fault::Timeout,
        Fault::SubmitStatus,
        Fault::SubmitCommand,
    ] {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 512, true, fault);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        assert!(
            engine
                .command([0; 8], &rw(true, 512), Data::In(512))
                .is_err(),
            "{fault:?}"
        );
        assert!(engine.poisoned);
        let events = state.borrow().events.len();
        let data = engine.data.bytes().to_vec();
        let status = engine.status.bytes().to_vec();
        assert!(
            engine
                .command([0; 8], &rw(false, 512), Data::Out(&vec![0xff; 512]))
                .is_err()
        );
        assert_eq!(state.borrow().events.len(), events);
        assert_eq!(engine.data.bytes(), data);
        assert_eq!(engine.status.bytes(), status);
    }
}

#[test]
fn check_condition_drains_queued_data_and_reports_actual_sense() {
    for input in [false, true] {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 512, input, Fault::ErrorAfterReady);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        let outgoing = vec![0x55; 512];
        assert_eq!(
            engine.command(
                [0; 8],
                &rw(input, 512),
                if input {
                    Data::In(512)
                } else {
                    Data::Out(&outgoing)
                }
            ),
            Err(BlockError::Sense(Sense {
                key: 0x02,
                asc: 0x3a,
                ascq: 0x00
            }))
        );
        assert!(state.borrow().active.is_empty());
        assert!(state.borrow().events.contains(&Event::Cancel(if input {
            Pipe::Input
        } else {
            Pipe::Output
        })));
        assert!(!engine.poisoned);
    }
}
