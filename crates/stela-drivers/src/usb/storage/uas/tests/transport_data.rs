// SPDX-License-Identifier: GPL-2.0-only
//! Transport data cases.
use super::*;

#[test]
fn real_ready_handshake_carries_lun_cdb_direction_and_dma_bytes() {
    for input in [false, true] {
        for length in [512, 4096, MAX_TD] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, length, input, Fault::None);
            let state = io.state.clone();
            let mut engine = Engine::new(io, &mut dma).unwrap();
            let bytes = vec![0xa7; length];
            let lun = [0x40, 7, 0, 2, 0, 0, 0, 0];
            let cdb = rw(input, length);
            let result = engine
                .command(
                    lun,
                    &cdb,
                    if input {
                        Data::In(length)
                    } else {
                        Data::Out(&bytes)
                    },
                )
                .unwrap();
            assert_eq!(
                result,
                if input {
                    vec![0x6d; length]
                } else {
                    Vec::new()
                }
            );
            let state = state.borrow();
            assert!(state.active.is_empty());
            assert_eq!(&state.command.as_ref().unwrap()[8..16], &lun);
            assert_eq!(&state.command.as_ref().unwrap()[16..26], &cdb);
            if !input {
                assert_eq!(state.written, bytes);
            }
            assert_eq!(
                &state.events[..2],
                &[Event::Post(Pipe::Status), Event::Post(Pipe::Command)]
            );
            assert!(!engine.poisoned);
        }
    }
}

#[test]
fn begun_commands_end_at_later_polls_without_waiting() {
    let length = 4096;
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, length, true, Fault::None);
    let clock = io.clock.clone();
    let mut engine = Engine::new(io, &mut dma).unwrap();
    let (lun, cdb) = ([0; 8], rw(true, length));
    engine.begin(lun, &cdb, Data::In(length)).unwrap();
    assert!(engine.active.is_some());
    assert_eq!(
        engine.begin(lun, &cdb, Data::In(length)),
        Err(BlockError::Protocol("a UAS command is already running"))
    );
    let started = clock.get();
    let mut polls = 0;
    let result = loop {
        polls += 1;
        assert!(polls < 100);
        if let Some(result) = engine.poll(None, &mut None) {
            break result;
        }
    };
    assert_eq!(result.unwrap(), vec![0x6d; length]);
    // The READY handshake, data and status took several looks, and
    // none of them waited.
    assert!(polls > 1);
    assert_eq!(clock.get(), started);
    assert!(engine.active.is_none() && !engine.poisoned);
}

#[test]
fn no_data_commands_need_real_terminal_status_and_complete_command_td() {
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
    let state = io.state.clone();
    let mut engine = Engine::new(io, &mut dma).unwrap();
    engine.command([0; 8], &[0; 6], Data::None).unwrap();
    assert!(state.borrow().active.is_empty());
    assert_eq!(
        state
            .borrow()
            .events
            .iter()
            .filter(|e| matches!(e, Event::Post(_)))
            .count(),
        2
    );
}

#[test]
fn short_write_is_an_error_and_short_read_reports_only_received_bytes() {
    for input in [false, true] {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 512, input, Fault::ShortData);
        let mut engine = Engine::new(io, &mut dma).unwrap();
        let bytes = vec![0xa5; 512];
        let result = engine.command(
            [0; 8],
            &rw(input, 512),
            if input {
                Data::In(512)
            } else {
                Data::Out(&bytes)
            },
        );
        if input {
            assert_eq!(result.unwrap(), vec![0x6d; 511]);
        } else {
            assert!(result.is_err());
        }
        assert!(!engine.poisoned);
    }
}

#[test]
fn terminal_status_before_data_completion_still_waits_for_data() {
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, 512, true, Fault::StatusBeforeData);
    let state = io.state.clone();
    let mut engine = Engine::new(io, &mut dma).unwrap();
    assert_eq!(
        engine
            .command([0; 8], &rw(true, 512), Data::In(512))
            .unwrap(),
        vec![0x6d; 512]
    );
    let state = state.borrow();
    let last_status = state
        .events
        .iter()
        .rposition(|e| *e == Event::Complete(Pipe::Status))
        .unwrap();
    let data = state
        .events
        .iter()
        .position(|e| *e == Event::Complete(Pipe::Input))
        .unwrap();
    assert!(last_status < data);
    assert!(state.active.is_empty());
}
