// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Linux btmtk_process_coredump: a crashed MT79xx streams its memory as ACL
//! frames on the firmware dump handle. The frames are kept whole, headers
//! included, as Linux appends them to its 1,024,000-byte devcoredump.
use alloc::vec::Vec;

/// MTK_COREDUMP_SIZE.
pub const MAX_BYTES: usize = 1024 * 1000;
/// MTK_COREDUMP_NUM: the end marker counts only after this many frames.
const MIN_FRAMES: usize = 255;
/// MTK_COREDUMP_END, compared without its terminator against the start of
/// the frame's last sizeof("coredump end") bytes.
const END: &[u8; 12] = b"coredump end";
const END_LEN: usize = END.len() + 1;
/// The 5 s dump_timeout btmtk_process_coredump schedules on the first frame.
pub const TIMEOUT_US: u64 = 5_000_000;

/// Why a dump stopped collecting. Linux resets the controller for all three.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum End {
    /// The end marker arrived after at least 255 frames.
    Complete,
    /// Five seconds passed since the first frame.
    Timeout,
    /// The next frame would have exceeded the devcoredump buffer.
    Overflow,
}

/// A collected controller memory dump with the devcoredump header facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coredump {
    /// btmtk_coredump_hdr's "Controller Name": the chip's device ID.
    pub device_id: u32,
    pub firmware_version: u32,
    /// Every dump frame in arrival order, ACL headers included.
    pub data: Vec<u8>,
    pub frames: usize,
    pub end: End,
}

struct Active {
    data: Vec<u8>,
    frames: usize,
    started: u64,
}

/// The controller's dump for one attachment, identified as
/// btmtk_register_coredump records it.
pub(super) struct Collector {
    device_id: u32,
    firmware_version: u32,
    active: Option<Active>,
}

impl Collector {
    pub(super) const fn new(device_id: u32, firmware_version: u32) -> Self {
        Self {
            device_id,
            firmware_version,
            active: None,
        }
    }

    fn finish(&mut self, end: End) -> Option<Coredump> {
        self.active.take().map(|active| Coredump {
            device_id: self.device_id,
            firmware_version: self.firmware_version,
            data: active.data,
            frames: active.frames,
            end,
        })
    }

    /// One firmware dump ACL frame at `now` microseconds; the dump once it
    /// ends. A frame that would overflow the buffer ends it unappended.
    pub(super) fn feed(&mut self, frame: &[u8], now: u64) -> Option<Coredump> {
        if let Some(expired) = self.expire(now) {
            return Some(expired);
        }
        let active = self.active.get_or_insert_with(|| Active {
            data: Vec::new(),
            frames: 0,
            started: now,
        });
        let complete = active.frames >= MIN_FRAMES
            && frame.len() > END_LEN
            && frame[frame.len() - END_LEN..].starts_with(END);
        if active.data.len() + frame.len() > MAX_BYTES {
            return self.finish(End::Overflow);
        }
        active.data.extend_from_slice(frame);
        active.frames += 1;
        if complete {
            return self.finish(End::Complete);
        }
        None
    }

    /// The dump, if one has been collecting for the whole timeout.
    pub(super) fn expire(&mut self, now: u64) -> Option<Coredump> {
        let started = self.active.as_ref()?.started;
        if now.saturating_sub(started) >= TIMEOUT_US {
            return self.finish(End::Timeout);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x6f, 0xfc];
        frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn the_end_marker_completes_only_after_255_frames() {
        let mut collector = Collector::new(0x7925, 0x8a);
        let end = frame(b"xx coredump end\0");
        // An early marker is ordinary dump data.
        assert_eq!(collector.feed(&end, 0), None);
        for index in 1..255 {
            assert_eq!(collector.feed(&frame(&[index as u8; 8]), index), None);
        }
        let dump = collector.feed(&end, 300).unwrap();
        assert_eq!(dump.end, End::Complete);
        assert_eq!(dump.frames, 256);
        assert_eq!((dump.device_id, dump.firmware_version), (0x7925, 0x8a));
        assert!(dump.data.starts_with(&end));
        assert!(dump.data.ends_with(&end));
        // The marker must sit at the start of the last 13 bytes.
        let mut collector = Collector::new(0x7925, 0);
        for index in 0..255 {
            collector.feed(&frame(&[0; 4]), index);
        }
        assert_eq!(collector.feed(&frame(b"coredump end"), 300), None);
        assert_eq!(
            collector.feed(&frame(b"coredump end!"), 301).unwrap().end,
            End::Complete
        );
    }

    #[test]
    fn a_dump_times_out_five_seconds_after_its_first_frame_and_never_overflows() {
        let mut collector = Collector::new(0x7925, 0);
        assert_eq!(collector.expire(0), None);
        assert_eq!(collector.feed(&frame(&[1]), 10), None);
        assert_eq!(collector.expire(TIMEOUT_US + 9), None);
        let dump = collector.expire(TIMEOUT_US + 10).unwrap();
        assert_eq!((dump.end, dump.frames), (End::Timeout, 1));
        assert_eq!(collector.expire(u64::MAX), None);
        // A late frame first ends the expired dump.
        collector.feed(&frame(&[1]), 0);
        assert_eq!(
            collector.feed(&frame(&[2]), TIMEOUT_US).unwrap().end,
            End::Timeout
        );

        let mut collector = Collector::new(0x7925, 0);
        let chunk = frame(&[0xaa; 1020]);
        let fits = MAX_BYTES / chunk.len();
        for index in 0..fits {
            assert_eq!(collector.feed(&chunk, index as u64), None);
        }
        let dump = collector.feed(&chunk, 0).unwrap();
        assert_eq!(dump.end, End::Overflow);
        assert_eq!(dump.frames, fits);
        assert!(dump.data.len() <= MAX_BYTES);
    }
}
