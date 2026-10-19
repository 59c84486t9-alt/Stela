//! A channel's command queue and the firmware command streams it carries, as
//! the 26A434 kext builds them (docs/research/agx.md §2).
//!
//! Known (`AGXG14G`, kernel file offsets):
//! - A data-master entry names its channel by the firmware VA of the
//!   channel's `AGFIChannelState` (entry +0x08 = `AGXChannel+0x98`,
//!   `encodeAcceleratorRingCommand` 0x1b56be8). `AGXChannel::resetChannelState`
//!   (0x1b0b080) writes the state's +0x00 as the firmware VA of the channel's
//!   command-ring state (`AGXChannel+0xa0`, uncached channel memory) and +0x08
//!   as that of its command-pointer array (`AGXChannel+0xa8`, cached channel
//!   memory).
//! - The command-ring state holds the read index at +0x00, the write index at
//!   +0x40 and the ring's length at +0x50 (`resetChannelState`;
//!   `AGXChannel::writeChannelCommandPointer` 0x1b0d120, which waits while
//!   `(write + 1) % length == read`, stores an 8-byte firmware VA at
//!   `array[write]` and advances the write index modulo the length).
//! - Each pointer names a command stream `AGXSKUEncoder` built
//!   (`beginEncoding` 0x1b90088, `finishEncode` 0x1b902d0, which appends the
//!   end word `0x4000_0002` and returns the stream's firmware VA). A record
//!   starts with a 32-bit header whose low 16 bits are its type and whose high
//!   byte carries flags. The types and sizes the 26A434 encoders write:
//!   TA start 0x6 (0x9c bytes, `AGXTAChannelG14::encodeTACommandSKUStream`
//!   0x1b68168), 3D start 0x8 (0xbc, `AGX3DChannelG14::encode3DCommandSKUStream`
//!   0x1b622ec), fast blit 0xa (0x7c, `encodeFastBlitSKUStream` 0x1b61e24), CL
//!   start 0xc (0x84, `AGXCLChannelG14::encodeCLCommandSKUStream` 0x1b65ef8),
//!   0x4 (0x14, flags 0x08 or 0x88, written twice after each start), timestamp
//!   0x3 (0x4c, flag 0x80 optional, `encodeTimeStamp` 0x1b9040c), shared-event
//!   signal 0xe (0x4c, `AGXChannel::encodeSharedEventSignalCommandSKUStream`
//!   0x1b0d02c), dashboard signal 0xf (0x54,
//!   `encodeDashboardSignalCommandSKUStream` 0x1b0cf30) and the end 0x2 (4,
//!   flag 0x40).
//!
//! The firmware model reads the queue and decodes the next command's first
//! record. It executes none of them yet: a decoded record refuses by name.

use super::ring::Shared;

/// `AGFIChannelState` +0x00: the command-ring state's firmware VA.
const STATE_RING: u64 = 0x00;
/// `AGFIChannelState` +0x08: the command-pointer array's firmware VA.
const STATE_COMMANDS: u64 = 0x08;
/// Command-ring state offsets.
const RING_READ: u64 = 0x00;
const RING_WRITE: u64 = 0x40;
const RING_LENGTH: u64 = 0x50;

/// A channel's command queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Queue {
    /// Firmware VA of the command-ring state.
    pub ring: u64,
    /// Firmware VA of the command-pointer array.
    pub commands: u64,
}

impl Queue {
    /// The queue of the channel whose `AGFIChannelState` is at `state`.
    pub fn read(memory: &mut dyn Shared, state: u64) -> Result<Self, &'static str> {
        if state == 0 {
            return Err("GFX data-master entry names no channel state");
        }
        let ring = memory.read_u64(state + STATE_RING)?;
        let commands = memory.read_u64(state + STATE_COMMANDS)?;
        if ring == 0 || commands == 0 {
            return Err("GFX channel state names no command queue");
        }
        Ok(Self { ring, commands })
    }

    /// The firmware VA of the next pending command stream, if any.
    pub fn next(&self, memory: &mut dyn Shared) -> Result<Option<u64>, &'static str> {
        let read = memory.read_u32(self.ring + RING_READ)?;
        let write = memory.read_u32(self.ring + RING_WRITE)?;
        let length = memory.read_u32(self.ring + RING_LENGTH)?;
        if length == 0 || read >= length || write >= length {
            return Err("GFX channel command ring index out-of-bounds");
        }
        if read == write {
            return Ok(None);
        }
        let stream = memory.read_u64(self.commands + u64::from(read) * 8)?;
        if stream == 0 {
            return Err("GFX channel command pointer is empty");
        }
        Ok(Some(stream))
    }
}

/// A command-stream record type the 26A434 encoders write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    End,
    Timestamp,
    Record4,
    StartTa,
    Start3d,
    FastBlit,
    StartCl,
    SharedEventSignal,
    DashboardSignal,
}

impl Record {
    /// Decode a record header.
    pub fn decode(header: u32) -> Result<Self, &'static str> {
        let flags = header >> 24;
        if header & 0x00ff_0000 != 0 {
            return Err("GFX command record header has bits between its type and flags");
        }
        let record = match header & 0xffff {
            0x2 => Record::End,
            0x3 => Record::Timestamp,
            0x4 => Record::Record4,
            0x6 => Record::StartTa,
            0x8 => Record::Start3d,
            0xa => Record::FastBlit,
            0xc => Record::StartCl,
            0xe => Record::SharedEventSignal,
            0xf => Record::DashboardSignal,
            _ => return Err("GFX command record type is not one the 26A434 kext writes"),
        };
        let allowed: &[u32] = match record {
            Record::End => &[0x40],
            Record::Timestamp => &[0, 0x80],
            Record::Record4 => &[0x08, 0x88],
            _ => &[0],
        };
        if !allowed.contains(&flags) {
            return Err("GFX command record carries flags its encoder does not write");
        }
        Ok(record)
    }

    /// The record's size in bytes, header included.
    pub const fn bytes(self) -> u64 {
        match self {
            Record::End => 0x4,
            Record::Timestamp => 0x4c,
            Record::Record4 => 0x14,
            Record::StartTa => 0x9c,
            Record::Start3d => 0xbc,
            Record::FastBlit => 0x7c,
            Record::StartCl => 0x84,
            Record::SharedEventSignal => 0x4c,
            Record::DashboardSignal => 0x54,
        }
    }

    /// Why the model does not execute this record.
    pub const fn unexecuted(self) -> &'static str {
        match self {
            Record::End => "GFX command stream ends before any record the model executes",
            Record::Timestamp => "GFX timestamp record (0x3) is not executed",
            Record::Record4 => "GFX command record 0x4 is not executed",
            Record::StartTa => "GFX TA start record (0x6) is not executed",
            Record::Start3d => "GFX 3D start record (0x8) is not executed",
            Record::FastBlit => "GFX fast-blit record (0xa) is not executed",
            Record::StartCl => "GFX CL start record (0xc) is not executed",
            Record::SharedEventSignal => "GFX shared-event signal record (0xe) is not executed",
            Record::DashboardSignal => "GFX dashboard signal record (0xf) is not executed",
        }
    }
}

/// Decode the first record of the stream at `stream`.
pub fn first_record(memory: &mut dyn Shared, stream: u64) -> Result<Record, &'static str> {
    Record::decode(memory.read_u32(stream)?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::apple::agx::ring::tests::Flat;

    const BASE: u64 = 0xffff_ffa0_0000_0000;

    /// A channel state at `state` whose queue holds one command at `stream`.
    pub(crate) fn one_command(memory: &mut Flat, state: u64, stream: u64) {
        let (ring, commands) = (state + 0x1000, state + 0x2000);
        memory.put_u64(state, ring);
        memory.put_u64(state + 8, commands);
        memory.put_u32(ring + 0x50, 0x80);
        memory.put_u32(ring + 0x40, 1);
        memory.put_u64(commands, stream);
    }

    #[test]
    fn the_queue_names_the_next_command_stream() {
        let mut memory = Flat::new(BASE, 0x8000);
        one_command(&mut memory, BASE, BASE + 0x4000);
        let queue = Queue::read(&mut memory, BASE).unwrap();
        assert_eq!(queue.next(&mut memory), Ok(Some(BASE + 0x4000)));
        // Read reaching write: nothing pending.
        memory.put_u32(BASE + 0x1000, 1);
        assert_eq!(queue.next(&mut memory), Ok(None));
        // An index past the ring's length refuses.
        memory.put_u32(BASE + 0x1040, 0x80);
        assert!(queue.next(&mut memory).is_err());
        assert!(Queue::read(&mut memory, 0).is_err());
        assert!(Queue::read(&mut memory, BASE + 0x6000).is_err());
    }

    #[test]
    fn record_headers_decode_with_their_encoders_flags() {
        assert_eq!(Record::decode(0x4000_0002), Ok(Record::End));
        assert_eq!(Record::decode(0x8000_0003), Ok(Record::Timestamp));
        assert_eq!(Record::decode(3), Ok(Record::Timestamp));
        assert_eq!(Record::decode(0x8800_0004), Ok(Record::Record4));
        assert_eq!(Record::decode(0x0800_0004), Ok(Record::Record4));
        assert_eq!(Record::decode(8).map(Record::bytes), Ok(0xbc));
        assert_eq!(Record::decode(0xe).map(Record::bytes), Ok(0x4c));
        // Unwritten types, flags or middle bits refuse.
        assert!(Record::decode(0x5).is_err());
        assert!(Record::decode(0x2).is_err());
        assert!(Record::decode(0x8000_0008).is_err());
        assert!(Record::decode(0x0001_0008).is_err());
    }
}
