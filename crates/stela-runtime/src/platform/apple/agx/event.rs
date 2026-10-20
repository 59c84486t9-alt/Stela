//! Firmware-to-AP events: the entries the GFX firmware posts on the firmware
//! event ring, as the 26A434 kext reads them (docs/research/agx.md §2).
//!
//! Known:
//! - The firmware posts an `AGFIFirmwareEventRingEntry` (0x48 bytes) by
//!   waiting while `write + 1 == read` (mod 256), copying the entry to
//!   `entries[write]`, advancing the write word (+0x20 of the ring state),
//!   and then sending `0x42 << 48` on endpoint 0x20 (`armfw_g14g` +0x35c88,
//!   whose ring is the directory's +0x1c0/+0x1c8 pair). The kext's
//!   `drainFirmwareEventRing` (0x1b2e5bc) reads entries from its read index
//!   to the write index (`AGXFirmwareRingValidator::fetchNextEntry`
//!   0x1b436ec) and switches on the type word at +0.
//! - Flag (type 1): a 128-bit stamp mask at +0x04 (u64, stamps 0..63) and
//!   +0x0c (u64, stamps 64..127), then a u16 count at +0x14 of trailing
//!   (u8 index, u64 value) pairs, below 6. The kext calls
//!   `IOGPUEventMachine::signalStamp(index, 0)` for each set bit. The
//!   firmware's completion path writes each completed command's value to its
//!   driver stamp, sets the stamp index's bit and posts one Flag
//!   (`armfw_g14g` +0x1ef28).
//! - Shared-event signal (type 0xa): the shared ID at +0x04 (u64, nonzero),
//!   the signalled value at +0x0c (u64) and the command's +0x50 word at
//!   +0x14; the kext calls `IOSurfaceRoot::signalEventID(id)` and, for a
//!   nonzero +0x14, sets a byte in its accelerator (`armfw_g14g` +0x182fc).
//! - CLPC I/O performance notice (type 0xe): a u64 at +0x04 the kext passes
//!   to `IOGPUFenceMachine::notifyCLPCIOPerfControl` (`armfw_g14g` +0x1817c).
//!
//! The kext's switch also reads types 0 (`handleFirmwareControllerEvent`),
//! 4 (hardware recovery: +0x04 the recovery generation, +0x0c the stamp
//! index, with the root +0xb0 recovery block and stop-state handshake;
//! `armfw_g14g` +0x6034), 7 (channel error: +0x04 kind below 5, +0x08 pipe
//! below 3, +0x0c stamp index, +0x10 value; `armfw_g14g` +0x88c4), 8
//! (scheduler notice), 0xb and 0xc. The model posts none of them: it starts
//! no recovery (what a UAT fault leaves in the firmware's recovery request
//! and what the firmware does between the stop states are unrecovered), and
//! channel errors come only from recovery aborts and from 3D-command words
//! read at 3D start (docs/research/agx.md FW-14, FW-15).

use super::initdata::Root;
use super::ring::{self, Kind, Shared};

/// Bytes of a firmware event entry.
pub const ENTRY_BYTES: usize = Kind::FirmwareEvent.entry_bytes();
/// The ring state's write word.
const WRITE: u64 = ring::WRITE;
const READ: u64 = ring::READ;

/// An event the firmware model posts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Stamps whose driver stamp was written, one bit per stamp index.
    Flag(u128),
    /// A shared event reached `value`.
    SharedSignal { id: u64, value: u64, flag: u32 },
    /// A dashboard signal's CLPC I/O performance argument.
    ClpcIoPerf(u64),
}

impl Event {
    pub fn encode(self) -> [u8; ENTRY_BYTES] {
        let mut entry = [0; ENTRY_BYTES];
        let mut put = |at: usize, bytes: &[u8]| entry[at..at + bytes.len()].copy_from_slice(bytes);
        match self {
            Event::Flag(stamps) => {
                put(0, &1u32.to_le_bytes());
                put(0x04, &(stamps as u64).to_le_bytes());
                put(0x0c, &((stamps >> 64) as u64).to_le_bytes());
                // No trailing (index, value) pairs.
                put(0x14, &0u16.to_le_bytes());
            }
            Event::SharedSignal { id, value, flag } => {
                put(0, &0xau32.to_le_bytes());
                put(0x04, &id.to_le_bytes());
                put(0x0c, &value.to_le_bytes());
                put(0x14, &flag.to_le_bytes());
            }
            Event::ClpcIoPerf(argument) => {
                put(0, &0xeu32.to_le_bytes());
                put(0x04, &argument.to_le_bytes());
            }
        }
        entry
    }
}

/// Post `event` on the root's firmware event ring. The caller sends the
/// 0x42 message for it.
pub fn post(memory: &mut dyn Shared, root: &Root, event: Event) -> Result<(), &'static str> {
    let (state, entries) = root.event_ring(memory)?;
    let read = memory.read_u32(state + READ)?;
    let write = memory.read_u32(state + WRITE)?;
    if read >= ring::ENTRIES || write >= ring::ENTRIES {
        return Err("GFX firmware event ring index out-of-bounds");
    }
    if ring::next(write) == read {
        // The firmware spins until the kext drains; the model has no later
        // step to resume from.
        return Err("GFX firmware event ring is full");
    }
    memory.write(
        entries + u64::from(write) * ENTRY_BYTES as u64,
        &event.encode(),
    )?;
    memory.write(state + WRITE, &ring::next(write).to_le_bytes())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::apple::agx::initdata::tests::{BASE, MAGIC, RINGS, ROOT, kext_root};
    use crate::platform::apple::agx::ring::tests::Flat;

    pub(crate) const EVENT_STATE: u64 = BASE + 0x14000;
    pub(crate) const EVENT_ENTRIES: u64 = BASE + 0x15000;

    /// Place the event ring at [`EVENT_STATE`]/[`EVENT_ENTRIES`].
    pub(crate) fn event_ring(memory: &mut Flat) {
        memory.put_u64(RINGS + 0x1c0, EVENT_STATE);
        memory.put_u64(RINGS + 0x1c8, EVENT_ENTRIES);
    }

    /// The `n`th posted entry.
    pub(crate) fn entry(memory: &mut Flat, n: u64) -> [u8; ENTRY_BYTES] {
        let mut bytes = [0; ENTRY_BYTES];
        memory
            .read(EVENT_ENTRIES + n * ENTRY_BYTES as u64, &mut bytes)
            .unwrap();
        bytes
    }

    #[test]
    fn entries_take_the_kexts_layouts() {
        let flag = Event::Flag(1 << 5 | 1 << 70).encode();
        assert_eq!(flag[..4], 1u32.to_le_bytes());
        assert_eq!(flag[4..0xc], (1u64 << 5).to_le_bytes());
        assert_eq!(flag[0xc..0x14], (1u64 << 6).to_le_bytes());
        assert!(flag[0x14..].iter().all(|&b| b == 0));
        let shared = Event::SharedSignal {
            id: 0x1234,
            value: 7,
            flag: 1,
        }
        .encode();
        assert_eq!(shared[..4], 0xau32.to_le_bytes());
        assert_eq!(shared[4..0xc], 0x1234u64.to_le_bytes());
        assert_eq!(shared[0xc..0x14], 7u64.to_le_bytes());
        assert_eq!(shared[0x14..0x18], 1u32.to_le_bytes());
        let clpc = Event::ClpcIoPerf(9).encode();
        assert_eq!(clpc[..4], 0xeu32.to_le_bytes());
        assert_eq!(clpc[4..0xc], 9u64.to_le_bytes());
    }

    #[test]
    fn posting_writes_at_the_write_index_and_advances_it() {
        let mut memory = Flat::new(BASE, 0x20000);
        kext_root(&mut memory);
        event_ring(&mut memory);
        let root = Root::read(&mut memory, ROOT, MAGIC).unwrap();
        memory.put_u32(EVENT_STATE + READ, 0);
        memory.put_u32(EVENT_STATE + WRITE, 0xfe);
        post(&mut memory, &root, Event::Flag(1)).unwrap();
        assert_eq!(entry(&mut memory, 0xfe), Event::Flag(1).encode());
        assert_eq!(memory.read_u32(EVENT_STATE + WRITE), Ok(0xff));
        // One more would make write reach read: the ring is full.
        assert_eq!(
            post(&mut memory, &root, Event::Flag(2)),
            Err("GFX firmware event ring is full")
        );
        memory.put_u32(EVENT_STATE + READ, 0x100);
        assert!(post(&mut memory, &root, Event::Flag(2)).is_err());
    }
}
