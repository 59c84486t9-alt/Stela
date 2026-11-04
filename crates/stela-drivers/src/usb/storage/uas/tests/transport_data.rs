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

#[test]
fn synchronous_read_exposes_only_complete_successful_data() {
    for streams in [None, Some(2)] {
        for fault in [
            Fault::StatusBeforeData,
            Fault::CommandLast,
            Fault::ShortData,
            Fault::ErrorAfterReady,
            Fault::CancelError,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, true, fault);
            let state = io.state.clone();
            state.borrow_mut().streams = streams;
            let mut engine = Engine::new(io, &mut dma).unwrap();
            let mut output = [0xa5; 512];
            let result = engine.read_into([0; 8], &rw(true, output.len()), &mut output);
            if matches!(fault, Fault::StatusBeforeData | Fault::CommandLast) {
                assert_eq!(result, Ok(()));
                assert_eq!(output, [0x6d; 512]);
            } else {
                assert!(result.is_err(), "{fault:?}");
                assert_eq!(output, [0xa5; 512]);
            }
            assert_eq!(engine.poisoned, fault == Fault::CancelError);
            assert_eq!(
                state.borrow().active.is_empty(),
                fault != Fault::CancelError
            );
        }
    }
}

#[test]
fn wide_block_reads_keep_raw_writes_and_short_results_at_the_old_boundary() {
    const WIDE: usize = 2 * MAX_TD;
    let read = rw(true, WIDE);
    for fault in [Fault::None, Fault::ShortData] {
        let mut memory = vec![0u64; 64 * 1024];
        let (io, mut dma) = model(&mut memory, WIDE, true, fault);
        let state = io.state.clone();
        state.borrow_mut().streams = Some(2);
        state.borrow_mut().read_ceiling = WIDE;
        let mut engine = Engine::new(io, &mut dma).unwrap();
        assert_eq!(engine.read_limit, WIDE);
        let flags = quirks::Flags::default();
        assert!(execute(&mut engine, flags, [0; 8], &read, Data::In(WIDE)).is_err());
        assert!(state.borrow().events.is_empty());

        assert!(admit_block_io(flags, &read, &Data::In(WIDE), WIDE).is_ok());
        assert!(
            admit_block_io(
                flags.limit_to_240_sectors(),
                &read,
                &Data::In(WIDE),
                flags.limit_to_240_sectors().transfer_ceiling(WIDE)
            )
            .is_err()
        );
        let write = rw(false, WIDE);
        let mut output = vec![0xa5; WIDE];
        assert!(admit_block_io(flags, &write, &Data::Out(&output), WIDE).is_err());
        assert!(admit_block_io(flags, &read, &Data::In(WIDE - 1), WIDE).is_err());

        let result = engine.read_into([0; 8], &read, &mut output);
        assert_eq!(state.borrow().chained_reads, [WIDE]);
        if fault == Fault::None {
            assert_eq!(result, Ok(()));
            assert!(output.iter().all(|&byte| byte == 0x6d));
            engine.begin([0; 8], &read, Data::In(WIDE)).unwrap();
            let completed = loop {
                if let Some(result) = engine.poll(None, &mut None) {
                    break result.unwrap();
                }
            };
            assert_eq!(completed, output);
            assert_eq!(state.borrow().chained_reads, [WIDE, WIDE]);
        } else {
            assert_eq!(result, Err(crate::usb::storage::SHORT_READ));
            assert!(output.iter().all(|&byte| byte == 0xa5));
        }
        assert!(state.borrow().active.is_empty());
    }
}

#[test]
fn optional_wide_dma_failure_keeps_the_original_buffer_and_limit() {
    struct LegacyOnly<'a>(&'a mut dyn DmaAllocator);
    impl DmaAllocator for LegacyOnly<'_> {
        fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
            if bytes > MAX_TD {
                return Err(BlockError::NoDmaMemory);
            }
            self.0.allocate(bytes, align)
        }
    }
    let mut memory = vec![0u64; 32 * 1024];
    let (io, mut dma) = model(&mut memory, MAX_TD, true, Fault::None);
    let state = io.state.clone();
    state.borrow_mut().streams = Some(2);
    state.borrow_mut().read_ceiling = 2 * MAX_TD;
    let mut engine = Engine::new(io, &mut LegacyOnly(&mut dma)).unwrap();
    assert_eq!(engine.read_limit, MAX_TD);
    assert_eq!(engine.data.len(), MAX_TD);
    let mut output = vec![0; MAX_TD];
    engine
        .read_into([0; 8], &rw(true, MAX_TD), &mut output)
        .unwrap();
    assert!(output.iter().all(|&byte| byte == 0x6d));
    assert!(state.borrow().chained_reads.is_empty());
}
