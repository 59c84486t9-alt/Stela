// SPDX-License-Identifier: GPL-2.0-only
//! Block zero cases.
use super::*;

#[test]
fn block_zero_probe_uses_lun_and_geometry_before_any_mode_page() {
    use crate::usb::storage::Scsi;
    for streams in [None, Some(2)] {
        for block_size in [512, 4096, MAX_TD] {
            let lun = Lun::from_bytes([0x40, 9, 0, 3, 0, 0, 0, 0]);
            let mut medium = Media::disk(lun, 0x47);
            medium.block_size = block_size as u32;
            let mut memory = vec![0u64; 32 * 1024];
            let (owner, state) = target_owner(
                &mut memory,
                Target::new(vec![medium]),
                quirks::Flags::default(),
            );
            state.borrow_mut().streams = streams;
            owner
                .borrow_mut()
                .read_before_mode_sense(lun, block_size)
                .unwrap();
            let state = state.borrow();
            assert_eq!(state.history.len(), 1);
            let command = &state.history[0];
            assert_eq!(&command[8..16], &lun.bytes());
            assert_eq!(&command[16..26], &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
            assert!(state.active.is_empty());
            assert!(state.target.as_ref().unwrap().writes.is_empty());
            assert!(state.target.as_ref().unwrap().flushes.is_empty());
        }
    }
}

#[test]
fn block_zero_failure_never_retries_or_queries_generic_mode_information() {
    for fault in [Fault::ShortData, Fault::Timeout, Fault::ErrorAfterReady] {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 512, true, fault);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        assert!(read_block_zero(&mut engine, quirks::Flags::default(), [0; 8], 512).is_err());
        let state = state.borrow();
        assert_eq!(state.history.len(), 1);
        assert_eq!(state.history[0][16], 0x28);
        assert!(state.written.is_empty());
    }
}
