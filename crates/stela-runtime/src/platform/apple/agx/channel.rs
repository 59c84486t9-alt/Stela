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
//! - Each pointer is the firmware VA of an `AGFIChannelCommand*` structure
//!   whose first word is its command type (`writeChannelCommandPointer`
//!   takes the VA and the `AGFIChannelCommandType*`; the GFX firmware's
//!   `AGFAcceleratorGetStampInfoForCommand` reads `array[index]` and switches
//!   on the word, accepting the types in mask 0x1128f). The types the 26A434
//!   kext writes: TA 0 (`AGXTAChannelSKU::submitBuffer` 0x1b98b04), 3D 1 and
//!   fast blit 2 (`AGX3DChannelSKU::submitBuffer` 0x1aeb49c, which also
//!   writes barrier 4 entries), CL 3 (`AGXCLChannelSKU::submitBuffer`
//!   0x1b0fc48), remote node 7 (`submitRemoteNodeCommand` 0x1b0f3c8),
//!   shared-event signal 9 (`submitSharedEventSignal` 0x1b0b7d8) and
//!   dashboard signal 0xc (`submitDashboardSignalCommand` 0x1b0b240).
//! - Each stamped command carries its completion stamp as two firmware VAs,
//!   then the stamp value and the stamp index (the `IOGPUEvent` pair). The
//!   firmware's per-type tables (`armfw_g14g` +0x593e0 and +0x59468) place
//!   the value at TA +0x594, 3D +0x8f8, fast blit +0x5cc, CL +0x2a8, remote
//!   node and shared-event signal +0x40, dashboard signal +0x30 and the index
//!   4 bytes after it; the kext writes the addresses 0x10 and 8 bytes before
//!   the value (`submitSharedEventSignal` +0x30/+0x38,
//!   `submitDashboardSignalCommand` +0x20/+0x28, and the firmware's TA
//!   completion entry at +0x584).
//! - The command's stream is the one `AGXSKUEncoder` built (`beginEncoding`
//!   0x1b90088 writes no record; `finishEncode` 0x1b902d0 appends the end
//!   word `0x4000_0002` and returns the stream's firmware VA, which the
//!   encoder stores in the command: 3D +0x14, fast blit +0x498, CL +0x1e8,
//!   remote node and shared-event signal +0x1c, dashboard signal +0x10; the
//!   firmware's pipe handlers read the same words, `armfw_g14g` +0x1d1d0 and
//!   +0x1e3b0). A record starts with
//!   a 32-bit header whose low 16 bits are its type and whose high byte
//!   carries flags; the firmware dispatches on the low six bits. The types
//!   and sizes the 26A434 encoders write: TA start 0x6 (0x9c bytes,
//!   `AGXTAChannelG14::encodeTACommandSKUStream` 0x1b68168), 3D start 0x8
//!   (0xbc, `AGX3DChannelG14::encode3DCommandSKUStream` 0x1b622ec), fast blit
//!   0xa (0x7c, `encodeFastBlitSKUStream` 0x1b61e24), CL start 0xc (0x84,
//!   `AGXCLChannelG14::encodeCLCommandSKUStream` 0x1b65ef8), each opened by
//!   a setup record (TA 0x5 0x19c bytes, 3D 0x7 0x1b4, fast blit 0x9 0x174,
//!   CL 0xb 0x16c), 0x4 (0x14 bytes; flags the pipe in bits 4:3, TA 0, 3D
//!   and fast blit 1, CL 2, with bit 7 on the copy before the start), timestamp 0x3
//!   (0x4c, flag 0x80 optional, `encodeTimeStamp` 0x1b9040c), shared-event
//!   signal 0xe (0x4c, `AGXChannel::encodeSharedEventSignalCommandSKUStream`
//!   0x1b0d02c), remote-node stamp 0xd (0x2c, written inline by
//!   `AGXChannel::submitRemoteNodeCommand` 0x1b0f3c8), dashboard signal 0xf (0x54,
//!   `encodeDashboardSignalCommandSKUStream` 0x1b0cf30) and the end 0x2 (4,
//!   flag 0x40).
//!
//! The firmware model reads the queue and the next command; the commands that
//! need no GPU work (remote node, shared-event and dashboard signals) run in
//! [`super::signal`], every other type refuses by name.

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

    /// The (read, length) of the command ring, with the write index checked.
    fn indices(&self, memory: &mut dyn Shared) -> Result<(u32, u32, u32), &'static str> {
        let read = memory.read_u32(self.ring + RING_READ)?;
        let write = memory.read_u32(self.ring + RING_WRITE)?;
        let length = memory.read_u32(self.ring + RING_LENGTH)?;
        if length == 0 || read >= length || write >= length {
            return Err("GFX channel command ring index out-of-bounds");
        }
        Ok((read, write, length))
    }

    /// The firmware VA of the next pending command, if any.
    pub fn next(&self, memory: &mut dyn Shared) -> Result<Option<u64>, &'static str> {
        let (read, write, _) = self.indices(memory)?;
        if read == write {
            return Ok(None);
        }
        let command = memory.read_u64(self.commands + u64::from(read) * 8)?;
        if command == 0 {
            return Err("GFX channel command pointer is empty");
        }
        Ok(Some(command))
    }

    /// Retire the command at the read index: the firmware's consume, which
    /// frees the slot `writeChannelCommandPointer` waits on.
    pub fn retire(&self, memory: &mut dyn Shared) -> Result<(), &'static str> {
        let (read, write, length) = self.indices(memory)?;
        if read == write {
            return Err("GFX channel command ring has no command to retire");
        }
        memory.write(self.ring + RING_READ, &((read + 1) % length).to_le_bytes())
    }
}

/// An `AGFIChannelCommand*` type the 26A434 kext writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ta,
    ThreeD,
    FastBlit,
    Cl,
    Barrier,
    RemoteNode,
    SharedEventSignal,
    DashboardSignal,
}

impl Kind {
    /// Decode the command's type word.
    pub fn decode(word: u32) -> Result<Self, &'static str> {
        Ok(match word {
            0 => Kind::Ta,
            1 => Kind::ThreeD,
            2 => Kind::FastBlit,
            3 => Kind::Cl,
            4 => Kind::Barrier,
            7 => Kind::RemoteNode,
            9 => Kind::SharedEventSignal,
            0xc => Kind::DashboardSignal,
            _ => return Err("GFX channel command type is not one the 26A434 kext writes"),
        })
    }

    /// The stamp value's offset, from the firmware's per-type table; barriers
    /// carry no stamp.
    pub const fn stamp_value(self) -> Option<u64> {
        match self {
            Kind::Ta => Some(0x594),
            Kind::ThreeD => Some(0x8f8),
            Kind::FastBlit => Some(0x5cc),
            Kind::Cl => Some(0x2a8),
            Kind::Barrier => None,
            Kind::RemoteNode | Kind::SharedEventSignal => Some(0x40),
            Kind::DashboardSignal => Some(0x30),
        }
    }

    /// Where the encoder stores the command's stream VA, where recovered.
    pub const fn stream(self) -> Option<u64> {
        match self {
            Kind::ThreeD => Some(0x14),
            Kind::FastBlit => Some(0x498),
            Kind::Cl => Some(0x1e8),
            Kind::RemoteNode | Kind::SharedEventSignal => Some(0x1c),
            Kind::DashboardSignal => Some(0x10),
            Kind::Ta | Kind::Barrier => None,
        }
    }

    /// Why the model does not execute a command of this type.
    pub const fn unexecuted(self) -> &'static str {
        match self {
            Kind::Ta => "GFX TA command (type 0) is not executed",
            Kind::ThreeD => "GFX 3D command (type 1) is not executed",
            Kind::FastBlit => "GFX fast-blit command (type 2) is not executed",
            Kind::Cl => "GFX CL command (type 3) is not executed",
            Kind::Barrier => "GFX barrier command (type 4) is not executed",
            Kind::RemoteNode => "GFX remote-node command (type 7) is not executed",
            Kind::SharedEventSignal => "GFX shared-event signal command (type 9) is not executed",
            Kind::DashboardSignal => "GFX dashboard signal command (type 0xc) is not executed",
        }
    }
}

/// A channel command: its firmware VA and type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    pub va: u64,
    pub kind: Kind,
}

impl Command {
    pub fn read(memory: &mut dyn Shared, va: u64) -> Result<Self, &'static str> {
        Ok(Self {
            va,
            kind: Kind::decode(memory.read_u32(va)?)?,
        })
    }

    /// The firmware VA of the command's stream.
    pub fn stream(&self, memory: &mut dyn Shared) -> Result<u64, &'static str> {
        let at = self
            .kind
            .stream()
            .ok_or("GFX channel command's stream location is not recovered")?;
        match memory.read_u64(self.va + at)? {
            0 => Err("GFX channel command names no stream"),
            stream => Ok(stream),
        }
    }

    /// The command's completion stamp.
    pub fn stamp(&self, memory: &mut dyn Shared) -> Result<Stamp, &'static str> {
        let value = self
            .kind
            .stamp_value()
            .ok_or("GFX channel command carries no stamp")?;
        let stamp = Stamp {
            driver: memory.read_u64(self.va + value - 0x10)?,
            firmware: memory.read_u64(self.va + value - 0x8)?,
            value: memory.read_u32(self.va + value)?,
            index: memory.read_u32(self.va + value + 4)?,
        };
        if stamp.index >= STAMPS {
            return Err("GFX command stamp index is outside the firmware's 128 stamps");
        }
        Ok(stamp)
    }
}

/// Stamps the firmware tracks: the Flag event's 128-bit mask.
pub const STAMPS: u32 = 128;

/// A command's completion stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// The stamp the completion writes before its Flag event (the first VA).
    pub driver: u64,
    /// The stamp a signal record writes (the second VA, the record's +0x30).
    pub firmware: u64,
    pub value: u32,
    pub index: u32,
}

/// A command-stream record type the 26A434 encoders write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    End,
    Timestamp,
    /// The 0x4 record, a performance-counter sample point, with its flag
    /// byte: the pipe in bits 4:3 (TA 0, 3D and fast blit 1, CL 2), bit 7 set
    /// on the copy written before the start (`encode*SKUStream`). See
    /// [`Record::sample_point`].
    SamplePoint(u8),
    /// The record each work stream opens with, ahead of its start: TA 0x5,
    /// 3D 0x7, fast blit 0x9, CL 0xb.
    SetupTa,
    Setup3d,
    SetupFastBlit,
    SetupCl,
    StartTa,
    Start3d,
    FastBlit,
    StartCl,
    /// A remote-node command's stamp record.
    RemoteNode,
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
            0x4 => Record::SamplePoint(flags as u8),
            0x5 => Record::SetupTa,
            0x7 => Record::Setup3d,
            0x9 => Record::SetupFastBlit,
            0xb => Record::SetupCl,
            0x6 => Record::StartTa,
            0x8 => Record::Start3d,
            0xa => Record::FastBlit,
            0xc => Record::StartCl,
            0xd => Record::RemoteNode,
            0xe => Record::SharedEventSignal,
            0xf => Record::DashboardSignal,
            _ => return Err("GFX command record type is not one the 26A434 kext writes"),
        };
        let allowed: &[u32] = match record {
            Record::End => &[0x40],
            Record::Timestamp => &[0, 0x80],
            Record::SamplePoint(_) => &[0x00, 0x80, 0x08, 0x88, 0x10, 0x90],
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
            Record::SamplePoint(_) => 0x14,
            Record::SetupTa => 0x19c,
            Record::Setup3d => 0x1b4,
            Record::SetupFastBlit => 0x174,
            Record::SetupCl => 0x16c,
            Record::StartTa => 0x9c,
            Record::Start3d => 0xbc,
            Record::FastBlit => 0x7c,
            Record::StartCl => 0x84,
            Record::RemoteNode => 0x2c,
            Record::SharedEventSignal => 0x4c,
            Record::DashboardSignal => 0x54,
        }
    }

    /// What the firmware does with a sample point (record 0x4), given whether
    /// the performance-counter sampler runs.
    ///
    /// Known (`armfw_g14g`, the record dispatcher's entry 4 at +0x149cc):
    /// the handler first tests the sampler-active word (+0xf812c, written
    /// with the root's +0xb0 object's +0x4040 by the device-control sampler
    /// start, type 4, at +0x4814 and cleared by its stop, type 5, at
    /// +0x4748). While it is clear both copies are skipped whole (+0x172ec
    /// advances past the 0x14 bytes and nothing else runs). While it is set,
    /// the copy before the start reads the command its +0x0c names and writes
    /// GPU registers from that command, and the copy after it calls the
    /// per-source routine (+0x352c4) for each enabled source of the +0xb0
    /// object's sample table (+0x4060, 0x538 bytes per source) with the
    /// record's +0x04, +0x08 and +0x0c words; **Inferred** that this takes a
    /// counter sample tagged with them.
    ///
    /// The model refuses the sampler start (device control 4: counter
    /// hardware), so the sampler never runs and the record is skipped, as
    /// the firmware skips it. A caller that found the sampler running would
    /// need the counter hardware, and refuses by name.
    pub fn sample_point(self, sampler_active: bool) -> Result<(), &'static str> {
        match self {
            Record::SamplePoint(_) if !sampler_active => Ok(()),
            Record::SamplePoint(_) => {
                Err("GFX sample-point record samples counter hardware the model does not have")
            }
            _ => Err("GFX record is not a sample point"),
        }
    }

    /// Read the record header at `va`.
    pub fn read(memory: &mut dyn Shared, va: u64) -> Result<Self, &'static str> {
        Self::decode(memory.read_u32(va)?)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::apple::agx::ring::tests::Flat;

    const BASE: u64 = 0xffff_ffa0_0000_0000;

    /// A channel state at `state` whose queue holds one command at `command`.
    pub(crate) fn one_command(memory: &mut Flat, state: u64, command: u64) {
        let (ring, commands) = (state + 0x1000, state + 0x2000);
        memory.put_u64(state, ring);
        memory.put_u64(state + 8, commands);
        memory.put_u32(ring + 0x50, 0x80);
        memory.put_u32(ring + 0x40, 1);
        memory.put_u64(commands, command);
    }

    #[test]
    fn the_queue_names_the_next_command_and_retires_it() {
        let mut memory = Flat::new(BASE, 0x8000);
        one_command(&mut memory, BASE, BASE + 0x4000);
        let queue = Queue::read(&mut memory, BASE).unwrap();
        assert_eq!(queue.next(&mut memory), Ok(Some(BASE + 0x4000)));
        // Retiring advances the read index to the write index: nothing pending.
        queue.retire(&mut memory).unwrap();
        assert_eq!(memory.read_u32(BASE + 0x1000), Ok(1));
        assert_eq!(queue.next(&mut memory), Ok(None));
        assert!(queue.retire(&mut memory).is_err());
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
        assert_eq!(Record::decode(0x8800_0004), Ok(Record::SamplePoint(0x88)));
        assert_eq!(Record::decode(0x0800_0004), Ok(Record::SamplePoint(0x08)));
        // CL and TA streams carry the 0x4 record with their own pipe bits.
        assert_eq!(Record::decode(0x9000_0004), Ok(Record::SamplePoint(0x90)));
        assert_eq!(Record::decode(0x1000_0004), Ok(Record::SamplePoint(0x10)));
        assert_eq!(Record::decode(0x8000_0004), Ok(Record::SamplePoint(0x80)));
        assert_eq!(Record::decode(0x4), Ok(Record::SamplePoint(0)));
        // With the sampler idle the firmware skips both copies; a running
        // sampler needs counter hardware.
        assert_eq!(Record::SamplePoint(0x88).sample_point(false), Ok(()));
        assert!(Record::SamplePoint(0x08).sample_point(true).is_err());
        assert!(Record::End.sample_point(false).is_err());
        assert!(Record::decode(0x1800_0004).is_err());
        // Each work stream's setup record.
        assert_eq!(Record::decode(0xb).map(Record::bytes), Ok(0x16c));
        assert_eq!(Record::decode(0x5).map(Record::bytes), Ok(0x19c));
        assert_eq!(Record::decode(0x7).map(Record::bytes), Ok(0x1b4));
        assert_eq!(Record::decode(0x9).map(Record::bytes), Ok(0x174));
        assert!(Record::decode(0x8000_000b).is_err());
        assert_eq!(Record::decode(8).map(Record::bytes), Ok(0xbc));
        assert_eq!(Record::decode(0xe).map(Record::bytes), Ok(0x4c));
        assert_eq!(Record::decode(0xd).map(Record::bytes), Ok(0x2c));
        assert!(Record::decode(0x8000_000d).is_err());
        // Unwritten types, flags or middle bits refuse.
        assert!(Record::decode(0x10).is_err());
        assert!(Record::decode(0x2).is_err());
        assert!(Record::decode(0x8000_0008).is_err());
        assert!(Record::decode(0x0001_0008).is_err());
    }

    #[test]
    fn command_types_and_layouts_follow_the_kext_and_firmware_tables() {
        assert_eq!(Kind::decode(9), Ok(Kind::SharedEventSignal));
        assert_eq!(Kind::decode(0xc), Ok(Kind::DashboardSignal));
        assert_eq!(Kind::decode(3).map(Kind::stamp_value), Ok(Some(0x2a8)));
        assert_eq!(Kind::Barrier.stamp_value(), None);
        assert_eq!(Kind::Ta.stream(), None);
        assert_eq!(Kind::RemoteNode.stream(), Some(0x1c));
        // The firmware accepts 0x10, which no 26A434 writer produces.
        assert!(Kind::decode(0x10).is_err());
        assert!(Kind::decode(5).is_err());
    }

    #[test]
    fn a_signal_command_names_its_stream_and_stamp() {
        let mut memory = Flat::new(BASE, 0x1000);
        memory.put_u32(BASE, 9);
        memory.put_u64(BASE + 0x1c, BASE + 0x800);
        memory.put_u64(BASE + 0x30, BASE + 0x900);
        memory.put_u64(BASE + 0x38, BASE + 0xa00);
        memory.put_u32(BASE + 0x40, 0x300);
        memory.put_u32(BASE + 0x44, 5);
        let command = Command::read(&mut memory, BASE).unwrap();
        assert_eq!(command.kind, Kind::SharedEventSignal);
        assert_eq!(command.stream(&mut memory), Ok(BASE + 0x800));
        assert_eq!(
            command.stamp(&mut memory),
            Ok(Stamp {
                driver: BASE + 0x900,
                firmware: BASE + 0xa00,
                value: 0x300,
                index: 5,
            })
        );
        // A stamp index past the Flag mask refuses.
        memory.put_u32(BASE + 0x44, STAMPS);
        assert!(command.stamp(&mut memory).is_err());
        // So does a command with no stream.
        memory.put_u64(BASE + 0x1c, 0);
        assert!(command.stream(&mut memory).is_err());
    }
}
