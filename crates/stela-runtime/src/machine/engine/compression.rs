//! WKDMC and WKDMD (`SystemOperation::Compression`): one 16 KiB page
//! compressed or decompressed through translated guest memory, in this
//! machine's format (`stela_compiler::wkdm::codec`). The contract and its
//! evidence are in `docs/design/system.md#apple-extensions`.
//!
//! The instruction reads its whole source before it writes, and translates
//! every destination piece before writing any, so a fault leaves memory and
//! Xs unchanged and the word restarts (inference: the hardware may write a
//! prefix first, which a restart overwrites). A stage-1 or stage-2 fault is
//! the Data Abort of that access, ISV clear. Cases whose hardware behavior
//! is not established refuse by name: EL0, register field 31, overlapping
//! source and destination, Device memory, watchpoints over the transfer and
//! MTE tag checking (the 26A434 kernel disables checking around the
//! compressor).
use super::{Devices, FETCH_PAGE, Host, Machine, RequirementKind, Step, Stop, Translated};
use alloc::{format, vec, vec::Vec};
use stela_compiler::wkdm::{
    self, Instruction, Operation, PAGE_BYTES, Population, Status, UNIT_BYTES,
    codec::{self, Compressed, HEADER_BYTES},
};
use {
    crate::machine::debug, crate::machine::mmu::Access, crate::machine::mmu::MemoryType,
    stela_contracts::Chip,
};

/// What the population count field counts on `chip`. XNU names M1 (H13,
/// `xnu-8792`) uncompressed and M4 and M5 (H16, H17, `xnu-12377`)
/// compressed; M2 and M3 take M1's choice and M6 M5's (inference: the
/// macro changed once, at H16, and no H14, H15 or later header is public).
/// The kernel only compares a slot's two counts, so either choice keeps it
/// consistent.
pub(super) const fn population_source(chip: Chip) -> Population {
    match chip {
        Chip::AppleM1 | Chip::AppleM2 | Chip::AppleM3 => Population::Uncompressed,
        Chip::AppleM4 | Chip::AppleM5 | Chip::AppleM6 => Population::Compressed,
    }
}

/// Why a transfer did not complete.
enum Blocked {
    /// The exception to take; the instruction does not complete.
    Exception(crate::machine::cpu::Exception),
    Stop(Stop),
}

impl From<Stop> for Blocked {
    fn from(stop: Stop) -> Self {
        Self::Stop(stop)
    }
}

/// The register count of an Apple register field (31 is not established).
const REGISTERS: u8 = 31;

impl<H: Host, D: Devices> Machine<H, D> {
    fn refuse_compression(&self, word: u32, detail: &str) -> Stop {
        self.unsupported(RequirementKind::Instruction {
            word,
            detail: format!("WKdm: {detail}"),
        })
    }

    pub(super) fn compression(&mut self, word: u32, instruction: Instruction) -> Step {
        if self.cpu.pstate.el == 0 {
            return Err(self.refuse_compression(
                word,
                "at EL0, whether it is UNDEFINED, trapped or executed is not established",
            ));
        }
        if instruction.source >= REGISTERS || instruction.destination >= REGISTERS {
            return Err(self.refuse_compression(
                word,
                "register field 31 names neither XZR nor SP with evidence",
            ));
        }
        let (source_mask, destination_mask) = instruction.address_masks();
        let source = self.cpu.state.x[usize::from(instruction.source)] & source_mask;
        let destination = self.cpu.state.x[usize::from(instruction.destination)] & destination_mask;
        let chip = self.profile.chip;
        let outcome = match instruction.operation {
            Operation::Compress => self.compress(word, source, destination, chip),
            Operation::Decompress => self.decompress(word, source, destination, chip),
        };
        match outcome {
            Ok(result) => {
                self.cpu.state.x[usize::from(instruction.source)] = result;
                self.next()
            }
            Err(Blocked::Exception(exception)) => {
                self.take(exception);
                Ok(())
            }
            Err(Blocked::Stop(stop)) => Err(stop),
        }
    }

    fn compress(
        &mut self,
        word: u32,
        source: u64,
        destination: u64,
        chip: Chip,
    ) -> Result<u64, Blocked> {
        let mut page = vec![0; PAGE_BYTES];
        self.transfer(word, source, &mut page, false)?;
        let page: &[u8; PAGE_BYTES] = page.as_slice().try_into().expect("one page");
        let uncompressed = || wkdm::population(page);
        let counted = |written: &[u8]| match population_source(chip) {
            Population::Uncompressed => uncompressed(),
            Population::Compressed => wkdm::population(written),
        };
        Ok(match codec::compress(page) {
            Compressed::SingleValue => wkdm::result(Status::Complete, None, true, counted(&[])),
            Compressed::Incompressible => {
                wkdm::result(Status::Incompressible, None, false, counted(&[]))
            }
            Compressed::Data(mut data) => {
                self.check_disjoint(word, source, PAGE_BYTES, destination, data.len())?;
                self.transfer(word, destination, &mut data, true)?;
                let units = data.len() / UNIT_BYTES;
                wkdm::result(Status::Complete, Some(units), false, counted(&data))
            }
        })
    }

    fn decompress(
        &mut self,
        word: u32,
        source: u64,
        destination: u64,
        chip: Chip,
    ) -> Result<u64, Blocked> {
        let invalid = wkdm::result(Status::Incompressible, None, false, 0);
        let mut header = [0; HEADER_BYTES];
        self.transfer(word, source, &mut header, false)?;
        let Some(length) = codec::compressed_length(&header) else {
            return Ok(invalid);
        };
        let mut data = vec![0; length];
        self.transfer(word, source, &mut data, false)?;
        let Some(mut page) = codec::decompress(&data) else {
            return Ok(invalid);
        };
        self.check_disjoint(word, source, length, destination, PAGE_BYTES)?;
        self.transfer(word, destination, &mut page, true)?;
        let population = match population_source(chip) {
            Population::Uncompressed => wkdm::population(&page),
            Population::Compressed => wkdm::population(&data),
        };
        Ok(wkdm::result(Status::Complete, None, false, population))
    }

    /// Refuse a source and destination that overlap: the hardware's order
    /// of reads and writes within the page is not known.
    fn check_disjoint(
        &self,
        word: u32,
        source: u64,
        source_bytes: usize,
        destination: u64,
        destination_bytes: usize,
    ) -> Result<(), Blocked> {
        let end = |start: u64, bytes: usize| u128::from(start) + bytes as u128;
        if u128::from(source) < end(destination, destination_bytes)
            && u128::from(destination) < end(source, source_bytes)
        {
            return Err(self
                .refuse_compression(word, "overlapping source and destination")
                .into());
        }
        Ok(())
    }

    /// Read `data.len()` bytes at `address` into `data`, or write them from
    /// it, translating every piece first.
    fn transfer(
        &mut self,
        word: u32,
        address: u64,
        data: &mut [u8],
        write: bool,
    ) -> Result<(), Blocked> {
        let el = self.cpu.pstate.el;
        let watched = debug::Access {
            address,
            size: data.len() as u64,
            read: !write,
            write,
            maintenance: false,
            el,
        };
        let access = if write { Access::Write } else { Access::Read };
        let mut pieces = Vec::new();
        let mut done = 0;
        while done < data.len() {
            let virtual_address = address.wrapping_add(done as u64);
            let length = ((FETCH_PAGE - (virtual_address & (FETCH_PAGE - 1))) as usize)
                .min(data.len() - done);
            match self.translate_data(virtual_address, access) {
                Translated::Mapped(translation) if translation.memory == MemoryType::Device => {
                    return Err(self
                        .refuse_compression(word, "a transfer to Device memory")
                        .into());
                }
                Translated::Mapped(translation) => pieces.push((translation.physical, length)),
                Translated::Fault(fault) => {
                    return Err(Blocked::Exception(self.data_abort_exception(
                        virtual_address,
                        fault,
                        write,
                        false,
                    )));
                }
                Translated::Unsupported(unsupported) => {
                    return Err(self
                        .unsupported(RequirementKind::Translation(unsupported))
                        .into());
                }
            }
            done += length;
        }
        if self.watchpoint_exception(&watched, self.cpu.pc).is_some() {
            return Err(self
                .refuse_compression(
                    word,
                    "a watchpoint over the transfer: its report is unknown",
                )
                .into());
        }
        if self.cpu.tag_checked(el, address) {
            return Err(self
                .refuse_compression(word, "whether its accesses are tag checked is unknown")
                .into());
        }
        let mut probe = [0u8; 1];
        for &(physical, length) in &pieces {
            if !self.host.read_ram(physical, &mut probe)
                || !self.host.read_ram(physical + length as u64 - 1, &mut probe)
            {
                return Err(self
                    .unsupported(RequirementKind::Device {
                        physical,
                        write,
                        detail: "WKdm transfer outside RAM".into(),
                    })
                    .into());
            }
        }
        let mut offset = 0;
        for (physical, length) in pieces {
            let range = offset..offset + length;
            let complete = if write {
                self.host.write_ram(physical, &data[range])
            } else {
                self.host.read_ram(physical, &mut data[range])
            };
            debug_assert!(complete, "every piece was probed as RAM");
            offset += length;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::NoDevices;
    use super::super::tests::{BASE, FakeHost, machine_on, normal_memory};
    use super::*;
    use crate::machine::{exception::Class, system::Register as SystemRegister};
    use stela_compiler::wkdm::{COMPRESS_X0_X1, DECOMPRESS_X0_X1};

    const PAGE: u64 = BASE + 0x4000;
    const COMPRESSED: u64 = BASE + 0x8000;
    const RESTORED: u64 = BASE + 0xc000;
    /// Outside the test map's one 1 GiB block.
    const UNMAPPED: u64 = BASE + 0x4000_0000;

    fn machine(chip: Chip) -> Machine<FakeHost, NoDevices> {
        let mut machine = machine_on(chip, &[]);
        normal_memory(&mut machine, false);
        machine
            .cpu
            .registers
            .set(SystemRegister::VBAR_EL1, 0, BASE + 0x800);
        machine
    }

    fn page() -> Vec<u8> {
        (0..PAGE_BYTES / 4)
            .flat_map(|i| (if i % 3 == 0 { 0x1000 + i as u32 } else { 0 }).to_le_bytes())
            .collect()
    }

    fn run(machine: &mut Machine<FakeHost, NoDevices>, word: u32, source: u64, destination: u64) {
        machine.cpu.state.x[0] = source;
        machine.cpu.state.x[1] = destination;
        let instruction = wkdm::decode(word).unwrap();
        machine.compression(word, instruction).unwrap();
    }

    fn ram(machine: &mut Machine<FakeHost, NoDevices>, address: u64, bytes: usize) -> Vec<u8> {
        let mut data = vec![0; bytes];
        assert!(machine.host.read_ram(address, &mut data));
        data
    }

    #[test]
    fn compress_then_decompress_restores_the_page_with_matching_counts() {
        for chip in Chip::ALL {
            let mut machine = machine(chip);
            let original = page();
            assert!(machine.host.write_ram(PAGE, &original));
            // Unaligned low bits are ignored.
            run(&mut machine, COMPRESS_X0_X1, PAGE + 0x123, COMPRESSED + 5);
            let result = machine.cpu.state.x[0];
            assert_eq!(result >> 12 & 3, 0, "{chip:?}");
            assert_eq!(result & 0x100, 0);
            let size = ((result & 0xff) << 6) + 64;
            let codec::Compressed::Data(expected) =
                codec::compress(original.as_slice().try_into().unwrap())
            else {
                panic!("compressible");
            };
            assert_eq!(size, expected.len() as u64);
            assert_eq!(ram(&mut machine, COMPRESSED, expected.len()), expected);
            assert_eq!(machine.cpu.pc, BASE + 4);

            run(
                &mut machine,
                DECOMPRESS_X0_X1,
                COMPRESSED,
                RESTORED + 0x3fff,
            );
            let restored = machine.cpu.state.x[0];
            assert_eq!(restored & 0xffff_ffff, 0, "complete, no size");
            assert_eq!(ram(&mut machine, RESTORED, PAGE_BYTES), original);
            // The kernel compares the two counts of a slot.
            assert_eq!(restored >> 32, result >> 32);
            let counted = match population_source(chip) {
                Population::Uncompressed => wkdm::population(&original),
                Population::Compressed => wkdm::population(&expected),
            };
            assert_eq!(result >> 32, u64::from(counted));
        }
    }

    #[test]
    fn single_value_and_incompressible_pages_write_nothing() {
        let mut machine = machine(Chip::AppleM2);
        let sentinel = vec![0xa5; 64];
        assert!(machine.host.write_ram(COMPRESSED, &sentinel));
        let value: Vec<u8> = (0..PAGE_BYTES / 4)
            .flat_map(|_| 7u32.to_le_bytes())
            .collect();
        assert!(machine.host.write_ram(PAGE, &value));
        run(&mut machine, COMPRESS_X0_X1, PAGE, COMPRESSED);
        assert_eq!(
            machine.cpu.state.x[0],
            0x100 | u64::from(wkdm::population(&value)) << 32
        );
        let mut state = 0x9e37_79b9_u32;
        let noise: Vec<u8> = (0..PAGE_BYTES / 4)
            .flat_map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state.to_le_bytes()
            })
            .collect();
        assert!(machine.host.write_ram(PAGE, &noise));
        run(&mut machine, COMPRESS_X0_X1, PAGE, COMPRESSED);
        assert_eq!(machine.cpu.state.x[0] & 0xffff_ffff, 2 << 12);
        assert_eq!(ram(&mut machine, COMPRESSED, 64), sentinel);
    }

    #[test]
    fn invalid_compressed_data_fails_without_writing() {
        let mut machine = machine(Chip::AppleM4);
        let before = ram(&mut machine, RESTORED, PAGE_BYTES);
        assert!(machine.host.write_ram(COMPRESSED, &[0xff; 64]));
        run(&mut machine, DECOMPRESS_X0_X1, COMPRESSED, RESTORED);
        assert_eq!(machine.cpu.state.x[0], 2 << 12);
        assert_eq!(ram(&mut machine, RESTORED, PAGE_BYTES), before);
        assert_eq!(machine.cpu.pc, BASE + 4);
    }

    #[test]
    fn faults_take_the_data_abort_and_leave_state_unchanged() {
        for (word, source, destination, write) in [
            (COMPRESS_X0_X1, UNMAPPED, COMPRESSED, false),
            (COMPRESS_X0_X1, PAGE, UNMAPPED, true),
            (DECOMPRESS_X0_X1, UNMAPPED, RESTORED, false),
        ] {
            let mut machine = machine(Chip::AppleM2);
            assert!(machine.host.write_ram(PAGE, &page()));
            if word == DECOMPRESS_X0_X1 {
                run(&mut machine, COMPRESS_X0_X1, PAGE, COMPRESSED);
                machine.cpu.pc = BASE;
            }
            let before = ram(&mut machine, COMPRESSED, 0x4000);
            run(&mut machine, word, source, destination);
            let esr = machine.cpu.read(SystemRegister::ESR_EL1);
            assert_eq!(esr >> 26, Class::DataAbortSame as u64, "{word:#x}");
            assert_eq!(esr >> 6 & 1, u64::from(write), "WnR");
            assert_eq!(esr >> 24 & 1, 0, "ISV");
            assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), UNMAPPED);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
            assert_eq!(machine.cpu.state.x[0], source, "Xs is unchanged");
            assert_eq!(ram(&mut machine, COMPRESSED, 0x4000), before);
        }
    }

    #[test]
    fn unestablished_cases_refuse() {
        let mut machine = machine(Chip::AppleM2);
        assert!(machine.host.write_ram(PAGE, &page()));
        machine.cpu.state.x[0] = PAGE;
        machine.cpu.state.x[1] = PAGE + 0x100;
        let compress = wkdm::decode(COMPRESS_X0_X1).unwrap();
        assert!(
            machine.compression(COMPRESS_X0_X1, compress).is_err(),
            "overlap"
        );
        let xzr = wkdm::decode(0x0020_0be0).unwrap();
        assert!(machine.compression(0x0020_0be0, xzr).is_err(), "field 31");
        machine.cpu.pstate.el = 0;
        machine.cpu.state.x[1] = COMPRESSED;
        assert!(
            machine.compression(COMPRESS_X0_X1, compress).is_err(),
            "EL0"
        );
    }

    #[test]
    fn system_mode_exits_complete_through_the_engine() {
        let mut machine = machine(Chip::AppleM3);
        assert!(machine.host.write_ram(PAGE, &page()));
        machine.cpu.state.x[0] = PAGE;
        machine.cpu.state.x[1] = COMPRESSED;
        machine.system_instruction(COMPRESS_X0_X1).unwrap();
        assert_eq!(machine.cpu.state.x[0] >> 12 & 3, 0);
        assert_eq!(machine.cpu.pc, BASE + 4);
    }
}
