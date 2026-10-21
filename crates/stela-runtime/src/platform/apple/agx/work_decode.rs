//! Original AP work-command envelopes and SKU record framing.
//!
//! The five modeled families have three distinct wire layouts. These are
//! source bindings, not pointer searches: the original `submitBuffer`,
//! `encode*CommandSKUStream`, and `finishEncode` producers fix every offset
//! below. Their firmware stamp tables independently agree (research/agx.md
//! §5.1b). In particular, a SKU stream is firmware code, not a CDM/VDM stream.
//!
//! Reading an envelope or record grants no execution/completion authority.
//! A consumer must implement the setup/start shared-memory effects, optional
//! resource and timestamp effects, GPU execution, and ordered completion.
//! Keeping a record's complete bytes prevents decoding a few engine fields
//! from silently dropping the other obligations. The cursor commits only
//! after the complete record has been read; retrying a failed read has no
//! architectural effect.

pub mod cl;
pub mod registers;
pub mod resources;
pub mod scene;
pub mod ta;

use super::channel::{Command, Kind, Record, STAMPS, Stamp};
use super::generation::{self, Family};
use super::ring::Shared;
use super::uat::CONTEXTS;
use alloc::vec;
use alloc::vec::Vec;

/// A source-qualified SKU encoding, selected from the GPU interface owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// G13G, G13X and G14G use fixed parameter blocks.
    Fixed,
    /// G14X uses a packed register program and longer setup records.
    G14X,
    /// G15G additionally changes setup payloads and start-record tails.
    G15G,
}

impl Encoding {
    pub fn for_family(family: &Family) -> Result<Self, &'static str> {
        if [generation::G13G, generation::G13X, generation::G14G]
            .iter()
            .any(|qualified| qualified == family)
        {
            Ok(Self::Fixed)
        } else if family == &generation::G14X {
            Ok(Self::G14X)
        } else if family == &generation::G15G {
            Ok(Self::G15G)
        } else {
            Err("GFX work command layout is not qualified for this GPU family")
        }
    }

    fn layout(self, kind: Kind) -> Result<Layout, &'static str> {
        let (stream, stamp) = match (self, kind) {
            (Self::Fixed, Kind::Ta) => (0x46c, 0x594),
            (Self::Fixed, Kind::ThreeD) => (0x14, 0x8f8),
            (Self::Fixed, Kind::FastBlit) => (0x498, 0x5cc),
            (Self::Fixed, Kind::Cl) => (0x1e8, 0x2a8),
            (Self::G14X, Kind::Ta) => (0x770, 0x898),
            (Self::G14X, Kind::ThreeD) => (0x14, 0xbe0),
            (Self::G14X, Kind::FastBlit) => (0x788, 0x8bc),
            (Self::G14X, Kind::Cl) => (0x760, 0x820),
            (Self::G15G, Kind::Ta) => (0x770, 0x888),
            (Self::G15G, Kind::ThreeD) => (0x14, 0xbd0),
            (Self::G15G, Kind::FastBlit) => (0x788, 0x8bc),
            (Self::G15G, Kind::Cl) => (0x760, 0x810),
            _ => return Err("GFX command is not a GPU work command"),
        };
        Ok(Layout { stream, stamp })
    }

    /// The record size includes its four-byte header. Timestamp/sample and
    /// end records retain their encoding across these interfaces.
    pub fn record_bytes(self, record: Record) -> u64 {
        match (self, record) {
            (Self::G14X, Record::SetupTa) => 0x1a4,
            (Self::G14X, Record::Setup3d) => 0x1bc,
            (Self::G14X, Record::SetupFastBlit) => 0x17c,
            (Self::G14X, Record::SetupCl) => 0x174,
            (Self::G15G, Record::SetupTa) => 0x1cc,
            (Self::G15G, Record::Setup3d) => 0x1e4,
            (Self::G15G, Record::SetupFastBlit) => 0x1a4,
            (Self::G15G, Record::SetupCl) => 0x1bc,
            (Self::G15G, Record::StartTa) => 0x94,
            (Self::G15G, Record::Start3d) => 0xb4,
            (Self::G15G, Record::FastBlit) => 0x84,
            (Self::G15G, Record::StartCl) => 0x7c,
            _ => record.bytes(),
        }
    }
}

#[derive(Clone, Copy)]
struct Layout {
    stream: u64,
    stamp: u64,
}

/// The accepted, immutable envelope of one AP work command. Packed fields
/// are intentionally read without imposing host alignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub command: Command,
    pub encoding: Encoding,
    pub counter: u64,
    pub context: u32,
    pub stamp: Stamp,
    pub stream: u64,
    /// `finishEncode` rounds the allocation's used length up to 64 bytes;
    /// the end record can precede this limit. Padding is not another record.
    pub stream_bytes: u32,
}

impl Submission {
    pub fn read(
        memory: &mut dyn Shared,
        family: &Family,
        command: Command,
    ) -> Result<Self, &'static str> {
        let encoding = Encoding::for_family(family)?;
        let layout = encoding.layout(command.kind)?;
        let mut header = [0; 16];
        memory.read(range(command.va, 0, header.len())?, &mut header)?;
        if Kind::decode(u32::from_le_bytes(header[..4].try_into().unwrap()))? != command.kind {
            return Err("GFX work command type changed before acceptance");
        }
        let counter = u64::from_le_bytes(header[4..12].try_into().unwrap());
        let context = u32::from_le_bytes(header[12..].try_into().unwrap());
        if context as usize >= CONTEXTS {
            return Err("GFX work command context is outside the UAT TTBAT");
        }
        let stream = memory.read_u64(range(command.va, layout.stream, 8)?)?;
        let stream_bytes = memory.read_u32(range(command.va, layout.stream + 8, 4)?)?;
        if stream == 0 || stream_bytes == 0 || !stream_bytes.is_multiple_of(64) {
            return Err("GFX work command has no complete 64-byte-rounded SKU allocation");
        }
        range(stream, 0, stream_bytes as usize)?;
        let mut completion = [0; 24];
        memory.read(
            range(command.va, layout.stamp - 0x10, completion.len())?,
            &mut completion,
        )?;
        let stamp = Stamp {
            driver: u64::from_le_bytes(completion[..8].try_into().unwrap()),
            firmware: u64::from_le_bytes(completion[8..16].try_into().unwrap()),
            value: u32::from_le_bytes(completion[16..20].try_into().unwrap()),
            index: u32::from_le_bytes(completion[20..].try_into().unwrap()),
        };
        if stamp.index >= STAMPS {
            return Err("GFX work stamp index is outside the firmware's 128 stamps");
        }
        Ok(Self {
            command,
            encoding,
            counter,
            context,
            stamp,
            stream,
            stream_bytes,
        })
    }

    pub fn cursor(&self) -> Cursor {
        Cursor {
            encoding: self.encoding,
            next: self.stream,
            remaining: u64::from(self.stream_bytes),
            ended: false,
        }
    }
}

/// One stock command owned by the firmware frontend. Its envelope and
/// current record cannot be redirected by AP memory changes during a later
/// DMA fault. Decoding does not complete a record or authorize GPU effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub submission: Submission,
    cursor: Cursor,
    current: Option<Frame>,
}

impl Accepted {
    pub fn read(
        memory: &mut dyn Shared,
        family: &Family,
        command: Command,
    ) -> Result<Self, &'static str> {
        let submission = Submission::read(memory, family, command)?;
        let cursor = submission.cursor();
        Ok(Self {
            submission,
            cursor,
            current: None,
        })
    }

    /// Accept one complete record before its consumer performs the first
    /// effect. A failed read retains the cursor; a later effect failure
    /// retains all original record bytes, even if the AP changes the stream.
    pub fn current(&mut self, memory: &mut dyn Shared) -> Result<&Frame, &'static str> {
        if self.current.is_none() {
            self.current = Some(
                self.cursor
                    .next(memory)?
                    .ok_or("GFX stock work has no next record before command completion")?,
            );
        }
        Ok(self.current.as_ref().unwrap())
    }

    /// Only the actual record-effect owner may release this snapshot after
    /// all native, RAM and callback phases have settled. The end record is
    /// retained until command completion, rather than treated as an empty job.
    pub fn record_completed(&mut self) -> Result<(), &'static str> {
        let record = self
            .current
            .as_ref()
            .ok_or("GFX work has no accepted record to complete")?;
        if record.record == Record::End {
            return Err("GFX work end requires actual command completion ownership");
        }
        self.current = None;
        Ok(())
    }
}

/// A SKU stream cursor. The caller retains accepted frames before applying
/// their effects; rewinding this decoder is not an execution retry protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    encoding: Encoding,
    next: u64,
    remaining: u64,
    ended: bool,
}

impl Cursor {
    pub fn next(&mut self, memory: &mut dyn Shared) -> Result<Option<Frame>, &'static str> {
        if self.ended {
            return Ok(None);
        }
        if self.remaining < 4 {
            return Err("GFX SKU allocation ended without an end record");
        }
        let record = Record::read(memory, self.next)?;
        let bytes = self.encoding.record_bytes(record);
        if bytes > self.remaining {
            return Err("GFX SKU record extends beyond its declared allocation");
        }
        let mut data = vec![0; bytes as usize];
        memory.read(range(self.next, 0, data.len())?, &mut data)?;
        // The header is part of the accepted snapshot, rather than a second
        // independent authority that can select a different record size.
        if Record::decode(u32::from_le_bytes(data[..4].try_into().unwrap()))? != record {
            return Err("GFX SKU record header changed while being read");
        }
        let frame = Frame {
            va: self.next,
            record,
            data,
        };
        let ended = record == Record::End;
        let next = if ended {
            self.next
        } else {
            self.next
                .checked_add(bytes)
                .ok_or("GFX SKU cursor wraps its address space")?
        };
        self.remaining -= bytes;
        self.ended = ended;
        self.next = next;
        Ok(Some(frame))
    }
}

/// All original bytes of an accepted record, including fields whose effects
/// still require a consumer. An unread optional field is not evidence that it is zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub va: u64,
    pub record: Record,
    data: Vec<u8>,
}

impl Frame {
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn u32(&self, offset: usize) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.field(offset, 4)?.try_into().unwrap(),
        ))
    }

    pub fn u64(&self, offset: usize) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.field(offset, 8)?.try_into().unwrap(),
        ))
    }

    fn field(&self, offset: usize, bytes: usize) -> Result<&[u8], &'static str> {
        let end = offset
            .checked_add(bytes)
            .ok_or("GFX SKU record field wraps its offset")?;
        self.data
            .get(offset..end)
            .ok_or("GFX SKU record field is outside the accepted record")
    }
}

fn range(base: u64, offset: u64, bytes: usize) -> Result<u64, &'static str> {
    let start = base
        .checked_add(offset)
        .ok_or("GFX work field wraps its address space")?;
    start
        .checked_add(bytes.saturating_sub(1) as u64)
        .ok_or("GFX work field wraps its address space")?;
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::super::ring::tests::Flat;
    use super::*;
    use crate::platform::dma::DmaError;

    const BASE: u64 = 0x1_0000_0000;
    const COMMAND: u64 = BASE;
    const STREAM: u64 = BASE + 0x2000;

    fn envelope(
        memory: &mut Flat,
        kind: Kind,
        stream_offset: u64,
        stamp_offset: u64,
        bytes: u32,
    ) -> Command {
        let word: u32 = match kind {
            Kind::Ta => 0,
            Kind::ThreeD => 1,
            Kind::FastBlit => 2,
            Kind::Cl => 3,
            _ => unreachable!(),
        };
        memory.put_u32(COMMAND, word);
        memory.put_u64(COMMAND + 4, 0x1234_5678_9abc_def0);
        memory.put_u32(COMMAND + 12, 7);
        memory.put_u64(COMMAND + stream_offset, STREAM);
        memory.put_u32(COMMAND + stream_offset + 8, bytes);
        memory.put_u64(COMMAND + stamp_offset - 16, BASE + 0x1000);
        memory.put_u64(COMMAND + stamp_offset - 8, BASE + 0x1004);
        memory.put_u32(COMMAND + stamp_offset, 0xa00);
        memory.put_u32(COMMAND + stamp_offset + 4, 127);
        Command { va: COMMAND, kind }
    }

    #[test]
    fn accepted_records_release_only_after_the_effect_owner_and_keep_end_for_completion() {
        let mut memory = Flat::new(BASE, 0x4000);
        let command = envelope(&mut memory, Kind::Cl, 0x1e8, 0x2a8, 0x200);
        memory.put_u32(STREAM, 11);
        memory.put_u64(STREAM + 4, 0x1234);
        memory.put_u32(STREAM + 0x16c, 0x4000_0002);
        let mut owned = Accepted::read(&mut memory, &generation::G14G, command).unwrap();
        assert!(owned.record_completed().is_err());
        assert_eq!(owned.current(&mut memory).unwrap().u64(4), Ok(0x1234));
        memory.put_u32(STREAM, u32::MAX);
        memory.put_u64(STREAM + 4, 0);
        assert_eq!(owned.current(&mut memory).unwrap().u64(4), Ok(0x1234));
        owned.record_completed().unwrap();
        assert_eq!(owned.current(&mut memory).unwrap().record, Record::End);
        assert_eq!(
            owned.record_completed(),
            Err("GFX work end requires actual command completion ownership")
        );
        memory.put_u32(STREAM + 0x16c, u32::MAX);
        assert_eq!(owned.current(&mut memory).unwrap().record, Record::End);
    }

    #[test]
    fn original_command_layouts_reach_the_selected_context_and_completion() {
        // Independent literal rows from the original AP encoders and the
        // seven firmware value/index tables, not the implementation table.
        for (family, rows) in [
            (
                &generation::G13G,
                [
                    (0x46c, 0x594),
                    (0x14, 0x8f8),
                    (0x498, 0x5cc),
                    (0x1e8, 0x2a8),
                ],
            ),
            (
                &generation::G13X,
                [
                    (0x46c, 0x594),
                    (0x14, 0x8f8),
                    (0x498, 0x5cc),
                    (0x1e8, 0x2a8),
                ],
            ),
            (
                &generation::G14G,
                [
                    (0x46c, 0x594),
                    (0x14, 0x8f8),
                    (0x498, 0x5cc),
                    (0x1e8, 0x2a8),
                ],
            ),
            (
                &generation::G14X,
                [
                    (0x770, 0x898),
                    (0x14, 0xbe0),
                    (0x788, 0x8bc),
                    (0x760, 0x820),
                ],
            ),
            (
                &generation::G15G,
                [
                    (0x770, 0x888),
                    (0x14, 0xbd0),
                    (0x788, 0x8bc),
                    (0x760, 0x810),
                ],
            ),
        ] {
            for (kind, (stream, stamp)) in [Kind::Ta, Kind::ThreeD, Kind::FastBlit, Kind::Cl]
                .into_iter()
                .zip(rows)
            {
                let mut memory = Flat::new(BASE, 0x4000);
                let command = envelope(&mut memory, kind, stream, stamp, 64);
                let submission = Submission::read(&mut memory, family, command).unwrap();
                assert_eq!(submission.command, command);
                assert_eq!(submission.counter, 0x1234_5678_9abc_def0);
                assert_eq!(submission.context, 7);
                assert_eq!(submission.stream, STREAM);
                assert_eq!(
                    submission.stamp,
                    Stamp {
                        driver: BASE + 0x1000,
                        firmware: BASE + 0x1004,
                        value: 0xa00,
                        index: 127,
                    }
                );
                assert_eq!(memory.read_u32(BASE + 0x1000), Ok(0));
                assert_eq!(memory.read_u32(BASE + 0x1004), Ok(0));
            }
        }
    }

    #[test]
    fn each_family_frames_all_setup_and_start_records_without_eating_the_next_header() {
        for (family, sizes) in [
            (
                &generation::G13G,
                [0x19c, 0x9c, 0x1b4, 0xbc, 0x174, 0x7c, 0x16c, 0x84],
            ),
            (
                &generation::G13X,
                [0x19c, 0x9c, 0x1b4, 0xbc, 0x174, 0x7c, 0x16c, 0x84],
            ),
            (
                &generation::G14G,
                [0x19c, 0x9c, 0x1b4, 0xbc, 0x174, 0x7c, 0x16c, 0x84],
            ),
            (
                &generation::G14X,
                [0x1a4, 0x9c, 0x1bc, 0xbc, 0x17c, 0x7c, 0x174, 0x84],
            ),
            (
                &generation::G15G,
                [0x1cc, 0x94, 0x1e4, 0xb4, 0x1a4, 0x84, 0x1bc, 0x7c],
            ),
        ] {
            for (header, bytes) in (5u32..=12).zip(sizes) {
                let mut memory = Flat::new(BASE, 0x4000);
                let mut data = vec![0xa5; bytes];
                data[..4].copy_from_slice(&header.to_le_bytes());
                memory.put(STREAM, &data);
                memory.put_u32(STREAM + bytes as u64, 0x4000_0002);
                // The rest of the allocation is arbitrary, unexecuted padding.
                memory.put_u32(STREAM + bytes as u64 + 4, 0xffff_ffff);
                let mut cursor = Cursor {
                    encoding: Encoding::for_family(family).unwrap(),
                    next: STREAM,
                    remaining: (bytes as u64 + 8).next_multiple_of(64),
                    ended: false,
                };
                let frame = cursor.next(&mut memory).unwrap().unwrap();
                assert_eq!(frame.bytes(), data);
                assert_eq!(frame.u64(4), Ok(0xa5a5_a5a5_a5a5_a5a5));
                assert_eq!(
                    cursor.next(&mut memory).unwrap().unwrap().record,
                    Record::End
                );
                assert_eq!(cursor.next(&mut memory), Ok(None));
                assert!(frame.u32(bytes - 3).is_err());
                assert!(frame.u64(usize::MAX).is_err());
            }
        }
    }

    struct FaultOnce {
        memory: Flat,
        fail_body: bool,
    }

    impl Shared for FaultOnce {
        fn read(&mut self, va: u64, data: &mut [u8]) -> Result<(), &'static str> {
            if va == STREAM && data.len() > 4 && self.fail_body {
                self.fail_body = false;
                return Err("injected complete record read failure");
            }
            self.memory.read(va, data)
        }
        fn write(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
            panic!("ingress decoding must not write")
        }
        fn gpu_read(&mut self, _: usize, _: u64, _: &mut [u8]) -> Result<(), DmaError> {
            panic!("ingress decoding must not execute GPU reads")
        }
        fn gpu_write(&mut self, _: usize, _: u64, _: &[u8]) -> Result<(), DmaError> {
            panic!("ingress decoding must not execute GPU writes")
        }
    }

    #[test]
    fn a_failed_complete_record_read_does_not_accept_or_advance_it() {
        let mut memory = Flat::new(BASE, 0x4000);
        let command = envelope(&mut memory, Kind::Cl, 0x760, 0x810, 0x200);
        memory.put_u32(STREAM, 11);
        memory.put_u64(STREAM + 0x1b0, 0x1234_5678);
        memory.put_u32(STREAM + 0x1bc, 0x4000_0002);
        let mut fault = FaultOnce {
            memory,
            fail_body: true,
        };
        let submission = Submission::read(&mut fault, &generation::G15G, command).unwrap();
        let mut cursor = submission.cursor();
        let before = cursor.clone();
        assert_eq!(
            cursor.next(&mut fault),
            Err("injected complete record read failure")
        );
        assert_eq!(cursor, before);
        let accepted = cursor.next(&mut fault).unwrap().unwrap();
        assert_eq!(accepted.u64(0x1b0), Ok(0x1234_5678));
        // Accepted bytes are not re-read when the producer's memory changes.
        fault.memory.put_u64(STREAM + 0x1b0, 0xdead);
        assert_eq!(accepted.u64(0x1b0), Ok(0x1234_5678));
        assert_eq!(
            cursor.next(&mut fault).unwrap().unwrap().record,
            Record::End
        );
    }

    #[test]
    fn malformed_envelopes_refuse_before_any_work_or_completion() {
        let mut memory = Flat::new(BASE, 0x4000);
        let command = envelope(&mut memory, Kind::Cl, 0x760, 0x810, 0x200);
        assert!(Submission::read(&mut memory, &generation::G16G, command).is_err());
        memory.put_u32(COMMAND + 12, CONTEXTS as u32);
        assert!(Submission::read(&mut memory, &generation::G15G, command).is_err());
        memory.put_u32(COMMAND + 12, 7);
        for length in [0, 4, 63, 65] {
            memory.put_u32(COMMAND + 0x768, length);
            assert!(Submission::read(&mut memory, &generation::G15G, command).is_err());
        }
        memory.put_u32(COMMAND + 0x768, 64);
        memory.put_u64(COMMAND + 0x760, u64::MAX - 31);
        assert!(Submission::read(&mut memory, &generation::G15G, command).is_err());
        memory.put_u64(COMMAND + 0x760, STREAM);
        memory.put_u32(COMMAND + 0x814, 128);
        assert!(Submission::read(&mut memory, &generation::G15G, command).is_err());
        memory.put_u32(COMMAND + 0x814, 127);
        memory.put_u32(COMMAND, 0);
        assert_eq!(
            Submission::read(&mut memory, &generation::G15G, command),
            Err("GFX work command type changed before acceptance")
        );
        assert!(
            Submission::read(
                &mut memory,
                &generation::G14G,
                Command {
                    va: u64::MAX - 8,
                    kind: Kind::Cl
                }
            )
            .is_err()
        );
    }

    #[test]
    fn a_truncated_or_unknown_record_keeps_its_original_cursor() {
        let mut memory = Flat::new(BASE, 0x4000);
        let command = envelope(&mut memory, Kind::Cl, 0x760, 0x810, 64);
        let submission = Submission::read(&mut memory, &generation::G15G, command).unwrap();
        let mut cursor = submission.cursor();
        let before = cursor.clone();
        memory.put_u32(STREAM, 11); // SetupCL cannot fit in this allocation.
        assert_eq!(
            cursor.next(&mut memory),
            Err("GFX SKU record extends beyond its declared allocation")
        );
        assert_eq!(cursor, before);
        memory.put_u32(STREAM, 0x123);
        assert!(cursor.next(&mut memory).is_err());
        assert_eq!(cursor, before);
        // Four samples fill the allocation, but none is an end record.
        cursor.remaining = 0;
        assert_eq!(
            cursor.next(&mut memory),
            Err("GFX SKU allocation ended without an end record")
        );
    }
}
