//! Opt-in observation of the GFX firmware work commands whose field layouts
//! are not recovered: the TA, 3D, CL, fast-blit, barrier, remote-node and
//! timestamp commands the matrix refuses by name (docs/research/agx.md §5.1,
//! rows FW-6..FW-9, FW-11, FW-12).
//!
//! These layouts are learned by watching what the unchanged kext submits to
//! Stela's own GFX firmware model and following each command field with the
//! engine's own decoders, not by reverse-engineering the kext or the Apple
//! firmware. With `--agx-observe` on, the firmware model records every channel
//! command a work doorbell runs ([`Observation`]): the queue it came from
//! (pipe and submission index), the channel's `AGFIChannelState`, the command
//! VA, its type and a bounded prefix of its raw bytes, and the buffers and
//! pointers it names with their sizes and first bytes where the firmware view
//! can read them.
//!
//! It then **derives** fields from observation alone ([`derive`]): a command
//! word whose value, when followed, lands on a structure the engine decodes
//! successfully is confirmed by the model's own decoding — a CDM or VDM
//! control stream that walks cleanly to its terminator, a USC word list with
//! a `Shader` and `Registers` word, a tile-size word matching the render
//! target the stream describes, or the completion stamp the driver later
//! polls. A field becomes modeled only when observation confirms it this way;
//! everything else stays refused by name.
//!
//! Observation never executes a work command and never fabricates a
//! completion: the firmware records what it sees and still refuses by name,
//! so the boot stops at the first refused command with the evidence in the
//! log. It is a diagnostic mode, off by default, and a run with it on
//! qualifies nothing beyond what it logs. Observed records belong in run
//! outputs, never in the repository; the tests here use synthetic commands
//! built from the engine's own structures.

use super::channel::{Command, Kind};
use super::ring::Shared;
use super::stream::cdm;
use super::stream::usc;
use super::stream::vdm;
use crate::platform::apple::agx::isa::machine::{Fault, Memory};
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Bytes of a command scanned for pointer and tile-size fields.
const SCAN_BYTES: u64 = 0x500;
/// The raw-byte prefix each observation logs.
const RAW_PREFIX: usize = 0x80;
/// The first bytes of each referenced buffer an observation logs.
const BUFFER_PREFIX: usize = 32;
/// Blocks a derivation walk follows before it treats the pointer as not a
/// control stream (a real stream terminates well within this).
const WALK_LIMIT: usize = 4096;
/// Lines the journal keeps before the host drains it; older ones are counted.
const JOURNAL_LINES: usize = 512;

/// The tile-size bits the 3D command carries at +0x80 (`generateRegisterList
/// For3D`: 0x1000/0x2000 for a 32-wide tile, 0x4000/0x8000 for a 32-high one;
/// docs/research/agx.md §2). A word confirming one of these matches the
/// render target the stream describes.
const TILE_SIZE_BITS: [u32; 4] = [0x1000, 0x2000, 0x4000, 0x8000];

/// What following a command field confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// A CDM control stream that walked cleanly to its terminator, with the
    /// number of launches it issued.
    ComputeStream { launches: u64 },
    /// A VDM control stream that walked cleanly to its terminator, with the
    /// number of draws it issued.
    VertexStream { draws: u64 },
    /// A USC word list with a `Shader` and a `Registers` word.
    UscList { register_halves: u32 },
    /// A tile-size word matching the render target (`0x1000`..`0x8000`).
    TileSize { bits: u32 },
    /// The command's completion stamp (two VAs, value and index): an address
    /// the driver later polls.
    Stamp { index: u32 },
}

impl Evidence {
    fn describe(self) -> String {
        match self {
            Evidence::ComputeStream { launches } => {
                format!("CDM control stream (launches={launches})")
            }
            Evidence::VertexStream { draws } => format!("VDM control stream (draws={draws})"),
            Evidence::UscList { register_halves } => {
                format!("USC word list (register_halves={register_halves})")
            }
            Evidence::TileSize { bits } => format!("tile-size word {bits:#x}"),
            Evidence::Stamp { index } => format!("completion stamp (index={index})"),
        }
    }
}

/// A field a derivation confirmed, by its offset in the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmed {
    pub offset: u64,
    pub value: u64,
    pub evidence: Evidence,
}

/// The firmware view as the engine's [`Memory`]: control-stream, USC and
/// descriptor decoders read through the firmware's UAT context, where the
/// kext allocates the command streams. A read that faults is a [`Fault`], so
/// a field whose value is not a readable structure simply fails to decode.
struct FirmwareMemory<'a>(&'a mut dyn Shared);

impl Memory for FirmwareMemory<'_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
        self.0.read(address, buffer).map_err(|_| Fault {
            address,
            write: false,
        })
    }
    fn write(&mut self, address: u64, _data: &[u8]) -> Result<(), Fault> {
        // Observation never writes; a decoder that tries to is refused.
        Err(Fault {
            address,
            write: true,
        })
    }
}

/// A pointer candidate is 8-byte aligned and nonzero; a real structure
/// pointer the kext stores is always at least page-shifted, so a small
/// integer (a count, a flag) is never followed.
fn is_pointer(word: u64) -> bool {
    word != 0 && word & 7 == 0 && word >> 14 != 0
}

/// Try `start` as a CDM stream, returning its launch count when it walks
/// cleanly to its terminator.
fn as_compute(memory: &mut dyn Memory, start: u64) -> Option<u64> {
    let mut walker = cdm::Walker::new(start);
    let mut launches = 0;
    for _ in 0..WALK_LIMIT {
        match walker.next(memory) {
            Ok(Some(cdm::Command::Launch(_))) => launches += 1,
            Ok(Some(cdm::Command::Barrier(_))) => {}
            Ok(None) => return (launches != 0).then_some(launches),
            Err(_) => return None,
        }
    }
    None
}

/// Try `start` as a VDM stream, returning its draw count when it walks
/// cleanly to its terminator.
fn as_vertex(memory: &mut dyn Memory, start: u64) -> Option<u64> {
    let mut walker = vdm::Walker::new(start);
    let mut draws = 0;
    for _ in 0..WALK_LIMIT {
        match walker.next(memory) {
            Ok(Some(vdm::Command::Draw(_))) => draws += 1,
            Ok(Some(_)) => {}
            Ok(None) => return (draws != 0).then_some(draws),
            Err(_) => return None,
        }
    }
    None
}

/// Try `start` as a USC word list, returning the register-half count when it
/// parses with a `Shader` and a `Registers` word.
fn as_usc(memory: &mut dyn Memory, start: u64) -> Option<u32> {
    let state = usc::parse(memory, 0, start).ok()?;
    match (state.code, state.register_halves) {
        (Some(_), Some(halves)) => Some(halves),
        _ => None,
    }
}

/// Derive the confirmed fields of `command`: every command word that, when
/// followed, lands on a structure the engine decodes, plus the completion
/// stamp and the tile-size words. The order is by offset.
pub fn derive(memory: &mut dyn Shared, command: &Command) -> Vec<Confirmed> {
    let mut confirmed = Vec::new();
    // The completion stamp, where the command type carries one: the pair of
    // VAs the driver and firmware poll.
    if let Ok(stamp) = command.stamp(memory)
        && let Some(value) = command.kind.stamp_value()
    {
        confirmed.push(Confirmed {
            offset: value - 0x10,
            value: stamp.driver,
            evidence: Evidence::Stamp { index: stamp.index },
        });
    }
    let mut raw = alloc::vec![0u8; SCAN_BYTES as usize];
    let readable = read_prefix(memory, command.va, &mut raw);
    // Pointer fields: follow each word with the engine's decoders. The kext
    // stores some command pointers on a 4-byte boundary (3D +0x14,
    // shared-event +0x1c), so the scan steps by four and reads the 64-bit
    // value there.
    let mut offset = 0;
    while offset + 8 <= readable {
        let word = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
        if is_pointer(word) {
            let mut view = FirmwareMemory(memory);
            let evidence = as_compute(&mut view, word)
                .map(|launches| Evidence::ComputeStream { launches })
                .or_else(|| {
                    as_vertex(&mut view, word).map(|draws| Evidence::VertexStream { draws })
                })
                .or_else(|| {
                    as_usc(&mut view, word)
                        .map(|register_halves| Evidence::UscList { register_halves })
                });
            if let Some(evidence) = evidence {
                confirmed.push(Confirmed {
                    offset: offset as u64,
                    value: word,
                    evidence,
                });
            }
        }
        offset += 4;
    }
    // Tile-size words: a 32-bit word carrying one of the render-target tile
    // bits, matching the fragment pipe's render target.
    if command.kind == Kind::ThreeD {
        let mut at = 0;
        while at + 4 <= readable {
            let word = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
            for bits in TILE_SIZE_BITS {
                if word == bits {
                    confirmed.push(Confirmed {
                        offset: at as u64,
                        value: u64::from(word),
                        evidence: Evidence::TileSize { bits },
                    });
                }
            }
            at += 4;
        }
    }
    confirmed.sort_by_key(|c| c.offset);
    confirmed.dedup();
    confirmed
}

/// Read as many bytes of `buffer` as the firmware view can, returning the
/// prefix length that read without faulting. A command structure may end
/// before [`SCAN_BYTES`]; the scan stops at the first unreadable byte.
fn read_prefix(memory: &mut dyn Shared, va: u64, buffer: &mut [u8]) -> usize {
    // Read in 8-byte steps so a short command is scanned up to its edge.
    let mut done = 0;
    while done + 8 <= buffer.len() {
        if memory
            .read(va + done as u64, &mut buffer[done..done + 8])
            .is_err()
        {
            break;
        }
        done += 8;
    }
    done
}

/// One observed channel command.
#[derive(Debug, Clone)]
pub struct Observation {
    /// The work pipe: 0 vertex (TA), 1 fragment (3D), 2 compute (CL).
    pub pipe: u8,
    /// The submission index 0..4.
    pub index: u8,
    /// The channel's `AGFIChannelState` firmware VA.
    pub channel_state: u64,
    /// The command's firmware VA.
    pub command_va: u64,
    /// The command type word, decoded where it is a kext type.
    pub kind: Option<Kind>,
    /// The raw type word, for a type the kext does not write.
    pub type_word: u32,
    /// A bounded prefix of the command's raw bytes.
    pub raw: Vec<u8>,
    /// The fields observation confirmed.
    pub confirmed: Vec<Confirmed>,
}

impl Observation {
    /// Record the command at `command_va` on the (`pipe`, `index`) queue of
    /// the channel at `channel_state`, deriving its confirmed fields.
    pub fn record(
        memory: &mut dyn Shared,
        pipe: u8,
        index: u8,
        channel_state: u64,
        command_va: u64,
    ) -> Result<Self, &'static str> {
        let type_word = memory.read_u32(command_va)?;
        let kind = Kind::decode(type_word).ok();
        let mut raw = alloc::vec![0u8; RAW_PREFIX];
        let read = read_prefix(memory, command_va, &mut raw);
        raw.truncate(read);
        let confirmed = match kind {
            Some(kind) => derive(
                memory,
                &Command {
                    va: command_va,
                    kind,
                },
            ),
            None => Vec::new(),
        };
        Ok(Self {
            pipe,
            index,
            channel_state,
            command_va,
            kind,
            type_word,
            raw,
            confirmed,
        })
    }

    /// The compact, greppable log lines for this observation: a header line
    /// and one `field` line per confirmed field. Each starts `AGX OBSERVE`.
    pub fn lines(&self) -> Vec<String> {
        let kind = match self.kind {
            Some(kind) => format!("{kind:?}"),
            None => format!("type={:#x}", self.type_word),
        };
        let mut lines = alloc::vec![format!(
            "AGX OBSERVE pipe={} index={} channel={:#x} command={:#x} {kind} raw[{}]={}",
            self.pipe,
            self.index,
            self.channel_state,
            self.command_va,
            self.raw.len(),
            hex(&self.raw),
        )];
        for field in &self.confirmed {
            lines.push(format!(
                "AGX OBSERVE field command={:#x} +{:#x} value={:#x} {}",
                self.command_va,
                field.offset,
                field.value,
                field.evidence.describe(),
            ));
        }
        lines
    }
}

/// `bytes` as lowercase hexadecimal, for a log line.
pub fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// What the firmware observed, as text lines for the boot log. Bounded: when
/// the host does not drain it, the oldest lines are dropped and counted.
#[derive(Debug, Default)]
pub struct Journal {
    lines: VecDeque<String>,
    dropped: usize,
}

impl Journal {
    /// Record one observation's lines.
    pub fn record(&mut self, observation: &Observation) {
        for line in observation.lines() {
            if self.lines.len() == JOURNAL_LINES {
                self.lines.pop_front();
                self.dropped += 1;
            }
            self.lines.push_back(line);
        }
    }

    /// The recorded lines, oldest first, preceded by a count of any dropped.
    pub fn drain(&mut self) -> Vec<String> {
        let dropped = core::mem::take(&mut self.dropped);
        let mut lines = Vec::new();
        if dropped != 0 {
            lines.push(format!("AGX OBSERVE journal dropped {dropped} older lines"));
        }
        lines.extend(self.lines.drain(..));
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::channel::Kind;
    use crate::platform::apple::agx::ring::tests::Flat;

    const BASE: u64 = 0xffff_ffa0_0000_0000;
    const COMMAND: u64 = BASE;
    const CDM_STREAM: u64 = BASE + 0x2000;
    const VDM_STREAM: u64 = BASE + 0x3000;
    const USC_LIST: u64 = BASE + 0x4000;

    /// Little-endian 32-bit words at `at`.
    fn words(memory: &mut Flat, at: u64, words: &[u32]) {
        for (i, word) in words.iter().enumerate() {
            memory.put_u32(at + 4 * i as u64, *word);
        }
    }

    /// A CDM stream of one direct launch then a terminate, built from the
    /// engine's own block encodings (`stream::cdm`).
    fn cdm_stream(memory: &mut Flat, at: u64) {
        words(
            memory,
            at,
            &[
                1 << 1, // Launch: direct, word 0 (one uniform word set)
                0,      // word 1: USC pipeline 0
                4,
                1,
                1, // global size
                4,
                1,
                1,       // local size
                2 << 29, // Stream Terminate
            ],
        );
    }

    /// A VDM stream of one index-list draw then a terminate.
    fn vdm_stream(memory: &mut Flat, at: u64) {
        words(
            memory,
            at,
            &[
                3 << 29 | 6 << 8 | 1 << 22 | 1 << 23 | 1 << 24, // Index List
                3,                                              // count
                1,                                              // instances
                0,                                              // start
                6 << 29,                                        // Stream Terminate
            ],
        );
    }

    /// A USC word list with a Registers word, a Shader word and a terminator.
    /// The Registers field 8..13 is 1, so `register_halves` is `8 * 1`.
    fn usc_list(memory: &mut Flat, at: u64) {
        let registers = 0x8d_u32 | 1 << 8;
        memory.put(at, &registers.to_le_bytes());
        memory.put(at + 4, &[0x0d, 0, 0, 0, 0, 0]); // Shader: 6 bytes, code 0
        memory.put(at + 10, &[0x88, 0]); // No preshader
    }

    #[test]
    fn a_control_stream_pointer_is_confirmed_by_a_clean_walk() {
        let mut memory = Flat::new(BASE, 0x8000);
        // A 3D command naming a VDM stream at +0x14 (channel.rs: 3D +0x14).
        memory.put_u32(COMMAND, 1);
        memory.put_u64(COMMAND + 0x14, VDM_STREAM);
        vdm_stream(&mut memory, VDM_STREAM);
        // A stamp at the 3D offset (value 0x8f8), index 3.
        memory.put_u64(COMMAND + 0x8f8 - 0x10, BASE + 0x6000);
        memory.put_u64(COMMAND + 0x8f8 - 0x8, BASE + 0x6008);
        memory.put_u32(COMMAND + 0x8f8, 0x10);
        memory.put_u32(COMMAND + 0x8f8 + 4, 3);
        let command = Command {
            va: COMMAND,
            kind: Kind::ThreeD,
        };
        let confirmed = derive(&mut memory, &command);
        // The VDM stream pointer at +0x14 is confirmed.
        assert!(confirmed.iter().any(|c| c.offset == 0x14
            && c.value == VDM_STREAM
            && matches!(c.evidence, Evidence::VertexStream { draws: 1 })));
        // The stamp field is confirmed at +0x8f8-0x10.
        assert!(confirmed.iter().any(
            |c| c.offset == 0x8f8 - 0x10 && matches!(c.evidence, Evidence::Stamp { index: 3 })
        ));
    }

    #[test]
    fn a_compute_stream_and_a_usc_list_are_each_confirmed() {
        let mut memory = Flat::new(BASE, 0x8000);
        // A CL command naming a CDM stream at +0x1e8 and a USC list at +0x20.
        memory.put_u32(COMMAND, 3);
        memory.put_u64(COMMAND + 0x1e8, CDM_STREAM);
        memory.put_u64(COMMAND + 0x20, USC_LIST);
        cdm_stream(&mut memory, CDM_STREAM);
        usc_list(&mut memory, USC_LIST);
        let command = Command {
            va: COMMAND,
            kind: Kind::Cl,
        };
        let confirmed = derive(&mut memory, &command);
        assert!(
            confirmed.iter().any(|c| c.offset == 0x1e8
                && matches!(c.evidence, Evidence::ComputeStream { launches: 1 }))
        );
        assert!(
            confirmed.iter().any(|c| c.offset == 0x20
                && matches!(c.evidence, Evidence::UscList { register_halves: 8 }))
        );
    }

    #[test]
    fn a_tile_size_word_is_confirmed_only_for_a_3d_command() {
        let mut memory = Flat::new(BASE, 0x8000);
        memory.put_u32(COMMAND, 1);
        // +0x80 carries 0x4000 (a 32-high tile).
        memory.put_u32(COMMAND + 0x80, 0x4000);
        let three_d = Command {
            va: COMMAND,
            kind: Kind::ThreeD,
        };
        let confirmed = derive(&mut memory, &three_d);
        assert!(
            confirmed
                .iter()
                .any(|c| c.offset == 0x80
                    && matches!(c.evidence, Evidence::TileSize { bits: 0x4000 }))
        );
        // A CL command's identical word is not a tile-size field.
        memory.put_u32(COMMAND, 3);
        let cl = Command {
            va: COMMAND,
            kind: Kind::Cl,
        };
        let confirmed = derive(&mut memory, &cl);
        assert!(
            !confirmed
                .iter()
                .any(|c| matches!(c.evidence, Evidence::TileSize { .. }))
        );
    }

    #[test]
    fn a_non_pointer_word_and_a_garbage_pointer_confirm_nothing() {
        let mut memory = Flat::new(BASE, 0x8000);
        memory.put_u32(COMMAND, 1);
        // A small integer at +0x10 (a count, not a pointer or a tile size).
        memory.put_u64(COMMAND + 0x10, 0x40);
        // A pointer at +0x18 whose target is not a structure (zeroed region
        // decodes as neither a stream nor a USC list).
        memory.put_u64(COMMAND + 0x18, BASE + 0x7000);
        let command = Command {
            va: COMMAND,
            kind: Kind::ThreeD,
        };
        let confirmed = derive(&mut memory, &command);
        assert!(!confirmed.iter().any(|c| c.offset == 0x10));
        assert!(!confirmed.iter().any(|c| c.offset == 0x18));
    }

    #[test]
    fn an_observation_records_its_identity_raw_bytes_and_fields() {
        let mut memory = Flat::new(BASE, 0x8000);
        memory.put_u32(COMMAND, 1);
        memory.put_u64(COMMAND + 0x14, VDM_STREAM);
        vdm_stream(&mut memory, VDM_STREAM);
        let observation = Observation::record(&mut memory, 1, 2, BASE + 0x100, COMMAND).unwrap();
        assert_eq!(observation.pipe, 1);
        assert_eq!(observation.index, 2);
        assert_eq!(observation.kind, Some(Kind::ThreeD));
        assert_eq!(observation.channel_state, BASE + 0x100);
        assert_eq!(observation.raw.len(), RAW_PREFIX);
        let lines = observation.lines();
        assert!(lines[0].starts_with("AGX OBSERVE pipe=1 index=2"));
        assert!(lines.iter().any(|l| l.contains("VDM control stream")));
        // Every line is greppable.
        assert!(lines.iter().all(|l| l.starts_with("AGX OBSERVE")));
    }

    #[test]
    fn an_unknown_command_type_records_its_word_and_derives_nothing() {
        let mut memory = Flat::new(BASE, 0x8000);
        memory.put_u32(COMMAND, 0x10); // a type no 26A434 writer produces
        let observation = Observation::record(&mut memory, 0, 0, BASE + 0x100, COMMAND).unwrap();
        assert_eq!(observation.kind, None);
        assert_eq!(observation.type_word, 0x10);
        assert!(observation.confirmed.is_empty());
        assert!(observation.lines()[0].contains("type=0x10"));
    }

    #[test]
    fn the_journal_is_bounded_and_drains_in_order() {
        let mut memory = Flat::new(BASE, 0x8000);
        memory.put_u32(COMMAND, 1);
        let observation = Observation::record(&mut memory, 1, 0, BASE, COMMAND).unwrap();
        let mut journal = Journal::default();
        for _ in 0..JOURNAL_LINES + 2 {
            journal.record(&observation);
        }
        let lines = journal.drain();
        assert!(lines[0].contains("journal dropped"));
        assert_eq!(lines.len(), JOURNAL_LINES + 1);
        assert!(journal.drain().is_empty());
    }
}
