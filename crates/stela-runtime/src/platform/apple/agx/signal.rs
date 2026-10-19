//! The channel commands that need no GPU work: shared-event signals (command
//! type 9) and dashboard signals (0xc), as the GFX firmware runs their
//! streams (docs/research/agx.md §2).
//!
//! Known (`armfw_g14g` a000 image, firmware VAs less 0xffffff8000000000; the
//! record dispatcher at +0x13a60 switches on `header & 0x3f` through the
//! table at +0x18548):
//! - A shared-event signal command's stream is one 0xe record and the end
//!   record (`AGXChannel::encodeSharedEventSignalCommandSKUStream`
//!   0x1b0d02c). The record holds the command's +0x14 word at +0x04, the
//!   shared ID at +0x10, the value to signal at +0x18 (u64), a notify mask at
//!   +0x20, the firmware VA of the shared event's value at +0x28, then the
//!   command's firmware stamp VA at +0x30 and its stamp value at +0x38. The
//!   handler (+0x17d4c) compares the event's current u64 with the value; when
//!   it is below, it issues a request to its register window at +0x18030
//!   (`0xf0000 | word << 32`, waiting on +0x18038 bit 1), stores the value,
//!   rings two doorbells for mask bit 3 (other bits do nothing), and posts a
//!   shared-event signal event. Either way it then writes the stamp value to
//!   the firmware stamp (+0x1ab5c).
//! - A dashboard signal command's stream is one 0xf record and the end
//!   record (`encodeDashboardSignalCommandSKUStream` 0x1b0cf30). The record
//!   holds four u64 values at +0x08..+0x28 and their four u16 slot indices
//!   at +0x28..+0x30, the firmware stamp VA at +0x30, the stamp value at
//!   +0x38, a CLPC argument at +0x40, then the command's +0x48 word and the
//!   context's ID at +0x48/+0x4c. The handler (+0x17f80) issues the
//!   `0x70000` window request for that context, writes each value whose
//!   index is at most 0x9f into a firmware table, posts a CLPC event for a
//!   nonzero argument, and writes the firmware stamp.
//! - The end record completes the command (+0x18290 → +0x126dc). The
//!   firmware's completion of TA, 3D and CL work writes the stamp value to
//!   the command's driver stamp and posts a Flag event with the stamp
//!   index's bit (+0x1c684 → +0x1ef28); the model completes the signal
//!   commands the same way.
//!
//! Not modeled, explicitly: mask bit 3's doorbells (their targets are not
//! recovered) and the dashboard table (its location is not recovered) refuse
//! by name. The window requests precede every signal and completion stamp,
//! which reads as GPU cache maintenance; the model's GPU has no caches, so
//! they have nothing to act on. The firmware's out-of-order stamp buffer
//! holds nothing in a model that completes in order.

use super::channel::{Command, Kind, Record};
use super::event::Event;
use super::ring::Shared;
use alloc::vec::Vec;

/// Shared-event record fields.
const SHARED_ID: u64 = 0x10;
const SHARED_VALUE: u64 = 0x18;
const SHARED_MASK: u64 = 0x20;
const SHARED_EVENT: u64 = 0x28;
/// Both signal records: the firmware stamp's VA and value.
const STAMP_VA: u64 = 0x30;
const STAMP_VALUE: u64 = 0x38;
/// The mask bit whose doorbells the handler rings.
const MASK_DOORBELLS: u64 = 1 << 3;
/// The command word the shared-event event carries (`submitSharedEventSignal`
/// stores the descriptor's +0x44c bit there).
const COMMAND_FLAG: u64 = 0x50;
/// Dashboard record fields (the values the slots name start at +0x08).
const DASHBOARD_SLOTS: u64 = 0x28;
const DASHBOARD_CLPC: u64 = 0x40;
/// The highest dashboard slot the handler writes.
const DASHBOARD_LAST_SLOT: u16 = 0x9f;

/// Run a signal command's stream to completion, returning the events it
/// posts in order.
pub fn execute(memory: &mut dyn Shared, command: &Command) -> Result<Vec<Event>, &'static str> {
    let expected = match command.kind {
        Kind::SharedEventSignal => Record::SharedEventSignal,
        Kind::DashboardSignal => Record::DashboardSignal,
        other => return Err(other.unexecuted()),
    };
    let stamp = command.stamp(memory)?;
    let stream = command.stream(memory)?;
    if Record::read(memory, stream)? != expected {
        return Err("GFX signal command's stream does not start with its signal record");
    }
    if Record::read(memory, stream + expected.bytes())? != Record::End {
        return Err("GFX signal command's stream continues past its signal record");
    }
    let mut events = Vec::new();
    match expected {
        Record::SharedEventSignal => shared_event(memory, command, stream, &mut events)?,
        _ => dashboard(memory, stream, &mut events)?,
    }
    // The firmware stamp both records write.
    let firmware = memory.read_u64(stream + STAMP_VA)?;
    let value = memory.read_u32(stream + STAMP_VALUE)?;
    memory.write(firmware, &value.to_le_bytes())?;
    // Completion: the driver stamp, then its Flag.
    memory.write(stamp.driver, &stamp.value.to_le_bytes())?;
    events.push(Event::Flag(1 << stamp.index));
    Ok(events)
}

fn shared_event(
    memory: &mut dyn Shared,
    command: &Command,
    record: u64,
    events: &mut Vec<Event>,
) -> Result<(), &'static str> {
    let event = memory.read_u64(record + SHARED_EVENT)?;
    let value = memory.read_u64(record + SHARED_VALUE)?;
    if memory.read_u64(event)? >= value {
        return Ok(());
    }
    if memory.read_u64(record + SHARED_MASK)? & MASK_DOORBELLS != 0 {
        return Err(
            "GFX shared-event signal rings doorbells (mask bit 3) whose targets are not recovered",
        );
    }
    memory.write(event, &value.to_le_bytes())?;
    events.push(Event::SharedSignal {
        id: memory.read_u64(record + SHARED_ID)?,
        value,
        flag: memory.read_u32(command.va + COMMAND_FLAG)?,
    });
    Ok(())
}

fn dashboard(
    memory: &mut dyn Shared,
    record: u64,
    events: &mut Vec<Event>,
) -> Result<(), &'static str> {
    for n in 0..4 {
        let mut slot = [0; 2];
        memory.read(record + DASHBOARD_SLOTS + n * 2, &mut slot)?;
        if u16::from_le_bytes(slot) <= DASHBOARD_LAST_SLOT {
            return Err(
                "GFX dashboard signal writes a dashboard slot whose table is not recovered",
            );
        }
    }
    let argument = memory.read_u64(record + DASHBOARD_CLPC)?;
    if argument != 0 {
        events.push(Event::ClpcIoPerf(argument));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::ring::tests::Flat;

    const BASE: u64 = 0xffff_ffa0_0000_0000;
    const COMMAND: u64 = BASE;
    const STREAM: u64 = BASE + 0x400;
    const DRIVER: u64 = BASE + 0x800;
    const FIRMWARE: u64 = BASE + 0x808;
    const SHARED: u64 = BASE + 0x900;

    /// A shared-event signal command for stamp 3, value 0x200, signalling the
    /// event at [`SHARED`] to 5.
    fn shared_command(memory: &mut Flat) -> Command {
        memory.put_u32(COMMAND, 9);
        memory.put_u64(COMMAND + 0x1c, STREAM);
        memory.put_u64(COMMAND + 0x30, DRIVER);
        memory.put_u64(COMMAND + 0x38, FIRMWARE);
        memory.put_u32(COMMAND + 0x40, 0x200);
        memory.put_u32(COMMAND + 0x44, 3);
        memory.put_u32(COMMAND + 0x50, 1);
        memory.put_u32(STREAM, 0xe);
        memory.put_u64(STREAM + 0x10, 0xabcd);
        memory.put_u64(STREAM + 0x18, 5);
        memory.put_u64(STREAM + 0x28, SHARED);
        memory.put_u64(STREAM + 0x30, FIRMWARE);
        memory.put_u32(STREAM + 0x38, 0x200);
        memory.put_u32(STREAM + 0x4c, 0x4000_0002);
        Command::read(memory, COMMAND).unwrap()
    }

    #[test]
    fn a_shared_event_signal_raises_the_event_and_completes_its_stamp() {
        let mut memory = Flat::new(BASE, 0x1000);
        let command = shared_command(&mut memory);
        let events = execute(&mut memory, &command).unwrap();
        assert_eq!(memory.read_u64(SHARED), Ok(5));
        assert_eq!(memory.read_u32(FIRMWARE), Ok(0x200));
        assert_eq!(memory.read_u32(DRIVER), Ok(0x200));
        assert_eq!(
            events,
            [
                Event::SharedSignal {
                    id: 0xabcd,
                    value: 5,
                    flag: 1
                },
                Event::Flag(1 << 3)
            ]
        );
        // An event already at the value is not signalled again; the stamps
        // still complete.
        assert_eq!(
            execute(&mut memory, &command),
            Ok(alloc::vec![Event::Flag(1 << 3)])
        );
    }

    #[test]
    fn unrecovered_shared_event_effects_refuse_by_name() {
        let mut memory = Flat::new(BASE, 0x1000);
        let command = shared_command(&mut memory);
        memory.put_u64(STREAM + 0x20, 1 << 3);
        assert!(execute(&mut memory, &command).is_err());
        assert_eq!(memory.read_u64(SHARED), Ok(0));
        // Other mask bits do nothing in the firmware.
        memory.put_u64(STREAM + 0x20, 0x7);
        assert!(execute(&mut memory, &command).is_ok());
        // A stream that is not one signal record and the end refuses.
        memory.put_u32(STREAM + 0x4c, 0x3);
        assert!(execute(&mut memory, &command).is_err());
        memory.put_u32(STREAM, 0xf);
        assert!(execute(&mut memory, &command).is_err());
    }

    #[test]
    fn a_dashboard_signal_completes_and_passes_its_clpc_argument() {
        let mut memory = Flat::new(BASE, 0x1000);
        memory.put_u32(COMMAND, 0xc);
        memory.put_u64(COMMAND + 0x10, STREAM);
        memory.put_u64(COMMAND + 0x20, DRIVER);
        memory.put_u64(COMMAND + 0x28, FIRMWARE);
        memory.put_u32(COMMAND + 0x30, 0x300);
        memory.put_u32(COMMAND + 0x34, 70);
        memory.put_u32(STREAM, 0xf);
        memory.put_u64(STREAM + 0x28, u64::MAX);
        memory.put_u64(STREAM + 0x30, FIRMWARE);
        memory.put_u32(STREAM + 0x38, 0x300);
        memory.put_u64(STREAM + 0x40, 0x77);
        memory.put_u32(STREAM + 0x54, 0x4000_0002);
        let command = Command::read(&mut memory, COMMAND).unwrap();
        assert_eq!(
            execute(&mut memory, &command),
            Ok(alloc::vec![Event::ClpcIoPerf(0x77), Event::Flag(1 << 70)])
        );
        assert_eq!(memory.read_u32(DRIVER), Ok(0x300));
        // Indices past 0x9f are ignored; one inside the table refuses.
        memory.put_u32(STREAM + 0x28, 0x00a0_ffff);
        assert!(execute(&mut memory, &command).is_ok());
        memory.put_u32(STREAM + 0x2c, 0x0000_ffff);
        assert!(execute(&mut memory, &command).is_err());
    }

    #[test]
    fn other_commands_are_not_signals() {
        let mut memory = Flat::new(BASE, 0x1000);
        memory.put_u32(COMMAND, 1);
        let command = Command::read(&mut memory, COMMAND).unwrap();
        assert_eq!(
            execute(&mut memory, &command),
            Err("GFX 3D command (type 1) is not executed")
        );
    }
}
