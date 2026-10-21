//! The ordered KRCE register program in G14X/G15 work commands.
//!
//! Original `AGXKRCEBufferEncoderG14X::getEntry` (mac14j file 0x1b78f8c)
//! returns header bit 0, address bits 16:3, and the unaligned u64 at +4.
//! G15's getter (mac15g 0x1b3fa30) extends the address through bit 17.
//! Their encoders preserve every other header bit. Those bits and the mode
//! byte are therefore retained, not assigned an invented access width or
//! silently discarded. A register-program decoder is not its effect consumer.

use super::{Encoding, Submission, range};
use crate::platform::apple::agx::channel::Kind;
use crate::platform::apple::agx::ring::Shared;
use alloc::vec::Vec;

const ENTRY_BYTES: usize = 12;
/// The original producer puts the self pointer at array +0x700 and the
/// u16 count at +0x708. Entries cannot overlap those metadata fields.
const SELF_POINTER: u64 = 0x700;
const COUNT: usize = 8;

/// A whole original entry. Repeated addresses remain separate ordered
/// operations; neither a dictionary nor a last-value lookup replaces them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub header: u32,
    pub address: u32,
    /// The encoder's one-bit mode. Its physical effect is not yet qualified.
    pub mode: bool,
    pub value: u64,
    /// Every header bit outside the original getter's address and mode.
    pub other_bits: u32,
}

impl Entry {
    fn read(encoding: Encoding, bytes: &[u8; ENTRY_BYTES]) -> Result<Self, &'static str> {
        let address_mask = match encoding {
            Encoding::G14X => 0x1fff8,
            Encoding::G15G => 0x3fff8,
            Encoding::Fixed => return Err("GFX fixed-parameter work has no KRCE program"),
        };
        let header = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        Ok(Self {
            header,
            address: header & address_mask,
            mode: header & 1 != 0,
            value: u64::from_le_bytes(bytes[4..].try_into().unwrap()),
            other_bits: header & !(address_mask | 1),
        })
    }
}

/// An accepted program and its submitting command identity. This owns every
/// entry before a future consumer can apply the first physical effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub command: u64,
    pub base: u64,
    entries: Vec<Entry>,
}

impl Program {
    pub fn read(memory: &mut dyn Shared, submission: &Submission) -> Result<Self, &'static str> {
        if submission.encoding == Encoding::Fixed {
            return Err("GFX fixed-parameter work has no KRCE program");
        }
        // Original generateRegisterList{For3D,ForFastBlit} self-pointer
        // producers, separately checked on mac14j and mac15g (§5.1b).
        let array_offset = match submission.command.kind {
            Kind::Ta => 0x40,
            Kind::ThreeD => 0x80,
            Kind::FastBlit | Kind::Cl => 0x20,
            _ => return Err("GFX command has no work-register program"),
        };
        let base = range(submission.command.va, array_offset, 1)?;
        let mut metadata = [0; COUNT + 2];
        memory.read(range(base, SELF_POINTER, metadata.len())?, &mut metadata)?;
        let pointer = u64::from_le_bytes(metadata[..COUNT].try_into().unwrap());
        let count = u16::from_le_bytes(metadata[COUNT..].try_into().unwrap());
        if pointer != base {
            return Err("GFX KRCE program does not name its command's original array");
        }
        if usize::from(count) * ENTRY_BYTES > SELF_POINTER as usize {
            return Err("GFX KRCE entries overlap the program's own metadata");
        }
        let mut entries = Vec::with_capacity(usize::from(count));
        for index in 0..count {
            let mut bytes = [0; ENTRY_BYTES];
            memory.read(
                range(base, u64::from(index) * ENTRY_BYTES as u64, ENTRY_BYTES)?,
                &mut bytes,
            )?;
            entries.push(Entry::read(submission.encoding, &bytes)?);
        }
        Ok(Self {
            command: submission.command.va,
            base,
            entries,
        })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::channel::{Command, Stamp};
    use crate::platform::apple::agx::ring::tests::Flat;
    use crate::platform::dma::DmaError;

    const BASE: u64 = 0x1_0000_0000;

    fn submission(encoding: Encoding, kind: Kind) -> Submission {
        Submission {
            command: Command { va: BASE, kind },
            encoding,
            counter: 0x1111,
            context: 2,
            stamp: Stamp {
                driver: BASE + 0x1000,
                firmware: BASE + 0x1004,
                value: 0x100,
                index: 3,
            },
            stream: BASE + 0x2000,
            stream_bytes: 0x200,
        }
    }

    fn put_entry(memory: &mut Flat, va: u64, header: u32, value: u64) {
        memory.put_u32(va, header);
        memory.put_u64(va + 4, value);
    }

    #[test]
    fn original_getters_keep_mode_and_preserved_bits_separate_from_the_address() {
        let mut bytes = [0; 12];
        bytes[..4].copy_from_slice(&0x8083_a427_u32.to_le_bytes());
        bytes[4..].copy_from_slice(&0x1234_5678_9abc_def0_u64.to_le_bytes());
        let old = Entry::read(Encoding::G14X, &bytes).unwrap();
        assert_eq!(old.address, 0x1a420);
        assert!(old.mode);
        assert_eq!(old.other_bits, 0x8082_0006);
        assert_eq!(old.value, 0x1234_5678_9abc_def0);
        let new = Entry::read(Encoding::G15G, &bytes).unwrap();
        assert_eq!(new.address, 0x3a420);
        assert_eq!(new.other_bits, 0x8080_0006);
        assert_eq!(new.header, old.header);
        assert!(Entry::read(Encoding::Fixed, &bytes).is_err());
    }

    #[test]
    fn every_original_work_array_keeps_duplicate_writes_in_order() {
        for encoding in [Encoding::G14X, Encoding::G15G] {
            for (kind, offset) in [
                (Kind::Ta, 0x40),
                (Kind::ThreeD, 0x80),
                (Kind::FastBlit, 0x20),
                (Kind::Cl, 0x20),
            ] {
                let mut memory = Flat::new(BASE, 0x3000);
                let base = BASE + offset;
                memory.put_u64(base + 0x700, base);
                memory.put(base + 0x708, &3_u16.to_le_bytes());
                put_entry(&mut memory, base, 0x1a420, 0x1234);
                put_entry(&mut memory, base + 12, 0x10071, 0x11_0000_0000);
                put_entry(&mut memory, base + 24, 0x8001_a424, 0x5678);
                let program = Program::read(&mut memory, &submission(encoding, kind)).unwrap();
                assert_eq!(program.command, BASE);
                assert_eq!(program.base, base);
                assert_eq!(
                    program
                        .entries()
                        .iter()
                        .map(|entry| (entry.address, entry.value))
                        .collect::<Vec<_>>(),
                    [
                        (0x1a420, 0x1234),
                        (0x10070, 0x11_0000_0000),
                        (0x1a420, 0x5678)
                    ]
                );
                assert_eq!(program.entries()[2].other_bits, 0x8000_0004);
                memory.put_u64(base + 4, 0xdead);
                assert_eq!(program.entries()[0].value, 0x1234);
            }
        }
    }

    struct FaultOnce {
        memory: Flat,
        fail: bool,
    }

    impl Shared for FaultOnce {
        fn read(&mut self, va: u64, out: &mut [u8]) -> Result<(), &'static str> {
            if self.fail && va == BASE + 0x20 + 12 {
                self.fail = false;
                return Err("injected second KRCE entry read fault");
            }
            self.memory.read(va, out)
        }
        fn write(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
            panic!("no effects while accepting program");
        }
        fn gpu_read(&mut self, _: usize, _: u64, _: &mut [u8]) -> Result<(), DmaError> {
            panic!("not GPU execution");
        }
        fn gpu_write(&mut self, _: usize, _: u64, _: &[u8]) -> Result<(), DmaError> {
            panic!("not GPU execution");
        }
    }

    #[test]
    fn failed_program_reads_never_publish_a_partial_program_or_effect() {
        let mut memory = Flat::new(BASE, 0x3000);
        memory.put_u64(BASE + 0x720, BASE + 0x20);
        memory.put(BASE + 0x728, &2_u16.to_le_bytes());
        put_entry(&mut memory, BASE + 0x20, 0x1a420, 0x1234);
        put_entry(&mut memory, BASE + 0x2c, 0x10071, 0x11_0000_0000);
        let mut fault = FaultOnce { memory, fail: true };
        let submission = submission(Encoding::G14X, Kind::Cl);
        assert_eq!(
            Program::read(&mut fault, &submission),
            Err("injected second KRCE entry read fault")
        );
        let program = Program::read(&mut fault, &submission).unwrap();
        assert_eq!(program.entries().len(), 2);
        assert_eq!(program.entries()[0].value, 0x1234);
        assert_eq!(program.entries()[1].value, 0x11_0000_0000);
    }

    #[test]
    fn foreign_arrays_and_metadata_overlaps_are_not_command_bindings() {
        let mut memory = Flat::new(BASE, 0x3000);
        let command = submission(Encoding::G15G, Kind::Cl);
        memory.put_u64(BASE + 0x720, BASE + 0x30);
        assert!(Program::read(&mut memory, &command).is_err());
        memory.put_u64(BASE + 0x720, BASE + 0x20);
        memory.put(BASE + 0x728, &150_u16.to_le_bytes());
        assert_eq!(
            Program::read(&mut memory, &command),
            Err("GFX KRCE entries overlap the program's own metadata")
        );
        assert!(Program::read(&mut memory, &submission(Encoding::Fixed, Kind::Cl)).is_err());
        assert!(Program::read(&mut memory, &submission(Encoding::G14X, Kind::Barrier)).is_err());
    }
}
