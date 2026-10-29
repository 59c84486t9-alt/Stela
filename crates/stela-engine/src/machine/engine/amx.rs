//! AMX block exits: one Apple AMX instruction against the PE's AMX unit and
//! translated guest memory, with the reference model of
//! `stela_compiler::amx::model`. The ABI and its evidence are in
//! `docs/design/system.md#apple-extensions` and `machine::amx`.
use super::{Devices, FETCH_PAGE, Host, Machine, RequirementKind, Step};
use crate::machine::{
    amx,
    cpu::Exception,
    exception::Class,
    mmu::{self, Access, Outcome as Translated},
};
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, vec::Vec};
use stela_compiler::{
    GuestAddress,
    amx::{
        AmxOperand, AmxOperation, AmxRegisters, decode,
        model::{self, AmxError, AmxMemory, MemoryFault},
    },
};

/// ISS of the exception for an AMX instruction while `AMX_CTL_EL1` bit 63 is
/// clear: ESR 0xfe000003 (Asahi Linux, "Apple Instructions"). 26A434 XNU's
/// handler for this class and subtype enables AMX on a faulting `set` and
/// retries it (`0xfffffe000bd778b4`).
pub const DISABLED_ISS: u32 = 3;

/// Why a transfer stopped, beyond the address the model reports.
enum Failure {
    Fault(mmu::Fault),
    Translation(mmu::Unsupported),
    Device { physical: u64 },
}

/// Guest virtual memory for the model. Each call translates every 4 KiB
/// piece first and touches memory only when all are mapped RAM.
struct Translate<'a, H: Host, D: Devices> {
    machine: &'a mut Machine<H, D>,
    failure: Option<Failure>,
}

impl<H: Host, D: Devices> Translate<'_, H, D> {
    /// (physical, length) pieces of `address..address+bytes`.
    fn pieces(
        &mut self,
        address: u64,
        bytes: usize,
        write: bool,
    ) -> Result<Vec<(u64, usize)>, MemoryFault> {
        let access = if write { Access::Write } else { Access::Read };
        let mut pieces = Vec::new();
        let mut done = 0;
        while done < bytes {
            let virtual_address = address.wrapping_add(done as u64);
            let page_left = (FETCH_PAGE - (virtual_address & (FETCH_PAGE - 1))) as usize;
            let length = page_left.min(bytes - done);
            match self.machine.translate_data(virtual_address, access) {
                Translated::Mapped(translation) => pieces.push((translation.physical, length)),
                Translated::Fault(fault) => {
                    self.failure = Some(Failure::Fault(fault));
                    return Err(MemoryFault {
                        address: virtual_address,
                        write,
                    });
                }
                Translated::Unsupported(unsupported) => {
                    self.failure = Some(Failure::Translation(unsupported));
                    return Err(MemoryFault {
                        address: virtual_address,
                        write,
                    });
                }
            }
            done += length;
        }
        Ok(pieces)
    }

    fn device(&mut self, physical: u64, address: u64, write: bool) -> MemoryFault {
        self.failure = Some(Failure::Device { physical });
        MemoryFault { address, write }
    }
}

impl<H: Host, D: Devices> AmxMemory for Translate<'_, H, D> {
    fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), MemoryFault> {
        let pieces = self.pieces(address, destination.len(), false)?;
        let mut offset = 0;
        for (physical, length) in pieces {
            let range = offset..offset + length;
            if !self
                .machine
                .host
                .read_ram(physical, &mut destination[range])
            {
                return Err(self.device(physical, address.wrapping_add(offset as u64), false));
            }
            offset += length;
        }
        Ok(())
    }

    fn write(&mut self, address: u64, source: &[u8]) -> Result<(), MemoryFault> {
        let pieces = self.pieces(address, source.len(), true)?;
        // Probe every piece so that nothing is written unless all are RAM.
        let mut offset = 0;
        let mut probe = [0u8; 1];
        for &(physical, length) in &pieces {
            if !self.machine.host.read_ram(physical, &mut probe)
                || !self
                    .machine
                    .host
                    .read_ram(physical + length as u64 - 1, &mut probe)
            {
                return Err(self.device(physical, address.wrapping_add(offset as u64), true));
            }
            offset += length;
        }
        let mut offset = 0;
        for (physical, length) in pieces {
            if !self
                .machine
                .host
                .write_ram(physical, &source[offset..offset + length])
            {
                return Err(self.device(physical, address.wrapping_add(offset as u64), true));
            }
            offset += length;
        }
        Ok(())
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Refuse an AMX case whose hardware behavior is not established.
    fn refuse_amx(&self, word: u32, detail: &str) -> Step {
        Err(self.unsupported(RequirementKind::Instruction {
            word,
            detail: format!("AMX: {detail}"),
        }))
    }

    /// Execute the AMX word at the PC.
    pub(super) fn amx(&mut self, word: u32) -> Step {
        let pc = self.cpu.pc;
        let instruction = match decode(GuestAddress(pc), word) {
            Ok(Some(instruction)) => instruction,
            Ok(None) => {
                return Err(self.unsupported(RequirementKind::Native(
                    "AMX exit at a word outside the AMX space",
                )));
            }
            Err(error) => return self.refuse_amx(word, &error.to_string()),
        };
        if let Some(step) = self.hacr_guest(word, crate::machine::hacr::Operation::Amx) {
            return step;
        }
        let operation = instruction.operation;
        let Some(generation) = self.cpu.amx.generation() else {
            return self.refuse_amx(word, amx::UNQUALIFIED_GENERATION);
        };
        if !self.cpu.amx.enabled(amx::governing(
            if self.cpu.regime() == crate::machine::cpu::TranslationRegime::El20 {
                2
            } else {
                1
            },
        )) {
            if operation == AmxOperation::Unallocated {
                return self.refuse_amx(
                    word,
                    "unallocated operation while AMX_CTL_EL1 is clear: which exception wins is unknown",
                );
            }
            self.take(Exception::synchronous(
                Class::ImplementationDefined,
                DISABLED_ISS,
                pc,
            ));
            return Ok(());
        }
        let live = self.cpu.amx.live();
        match operation {
            AmxOperation::Unallocated => return self.undefined(),
            AmxOperation::Set if live => {
                return self.refuse_amx(word, "set while state is live: syndrome unknown");
            }
            AmxOperation::Set => {
                self.cpu.amx.registers = Some(Box::new(AmxRegisters::zeroed()));
                return self.next();
            }
            AmxOperation::Clear if live => {
                self.cpu.amx.registers = None;
                return self.next();
            }
            AmxOperation::Clear => {
                return self.refuse_amx(word, "clr without live state: behavior unknown");
            }
            _ if !live => {
                return self.refuse_amx(word, "operation without live state: behavior unknown");
            }
            _ => {}
        }
        let operand = match instruction.operand {
            AmxOperand::Register(index) if index < 31 => self.cpu.state.x[usize::from(index)],
            AmxOperand::Register(_) | AmxOperand::None => 0,
        };
        let mut registers = self.cpu.amx.registers.take().expect("live above");
        let mut memory = Translate {
            machine: self,
            failure: None,
        };
        let result =
            model::execute_for(generation, &mut registers, operation, operand, &mut memory);
        let failure = memory.failure.take();
        self.cpu.amx.registers = Some(registers);
        match result {
            Ok(()) => self.next(),
            Err(AmxError::Alignment { address, write, .. }) => self.alignment_fault(address, write),
            Err(AmxError::Memory(MemoryFault { address, write })) => match failure {
                Some(Failure::Fault(fault)) => self.data_abort(address, fault, write, false),
                Some(Failure::Translation(unsupported)) => {
                    Err(self.unsupported(RequirementKind::Translation(unsupported)))
                }
                Some(Failure::Device { physical }) => {
                    Err(self.unsupported(RequirementKind::Device {
                        physical,
                        write,
                        detail: "AMX transfer outside RAM".into(),
                    }))
                }
                None => unreachable!("every memory fault records its failure"),
            },
            Err(AmxError::Unsupported { detail }) => self.refuse_amx(word, detail),
            Err(AmxError::Enablement | AmxError::Undefined) => {
                unreachable!("set, clr and unallocated operations are handled above")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{BASE, machine_on};
    use super::*;
    use crate::machine::system::Register as SystemRegister;
    use crate::machine::{
        amx::{AMX_CTL_EL1, AMX_STATE_T, AmxView},
        exception::syndrome,
    };
    use stela_contracts::Chip;

    fn machine(words: &[u32]) -> Machine<super::super::tests::FakeHost, super::super::NoDevices> {
        machine_on(Chip::AppleM2, words)
    }

    const LDX: u32 = 0x0020_1000;
    const STZ: u32 = 0x0020_10a0;
    const FMA32: u32 = 0x0020_1180;
    const SET: u32 = 0x0020_1220;
    const CLR: u32 = 0x0020_1221;
    const DATA: u64 = BASE + 0x8000;

    fn msr(encoding: stela_compiler::aarch64::system::registers::Encoding, rt: u32) -> u32 {
        0xd510_0000
            | u32::from(encoding.op0() & 1) << 19
            | u32::from(encoding.op1()) << 16
            | u32::from(encoding.crn()) << 12
            | u32::from(encoding.crm()) << 8
            | u32::from(encoding.op2()) << 5
            | rt
    }

    fn mrs(encoding: stela_compiler::aarch64::system::registers::Encoding, rt: u32) -> u32 {
        msr(encoding, rt) | 1 << 21
    }

    #[test]
    fn disabled_amx_raises_the_implementation_defined_class() {
        for chip in [Chip::AppleM1, Chip::AppleM2, Chip::AppleM3, Chip::AppleM4] {
            let mut machine = machine_on(chip, &[]);
            machine
                .cpu
                .registers
                .set(SystemRegister::VBAR_EL1, 0, BASE + 0x4000);
            machine.amx(LDX).unwrap();
            assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xfe00_0003);
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1),
                syndrome(Class::ImplementationDefined, DISABLED_ISS)
            );
            assert_eq!(
                machine.cpu.read(SystemRegister::ELR_EL1),
                BASE,
                "the PC stays on the word"
            );
            assert_eq!(machine.cpu.pc, BASE + 0x4200);
            assert!(
                machine.amx(0x0020_12e0).is_err(),
                "unallocated while disabled"
            );
        }
    }

    #[test]
    fn kernel_style_enable_set_compute_save_and_clear() {
        let mut machine = machine(&[]);
        machine.cpu.state.x[1] = 1 << 63 | 0x100;
        machine.system_instruction(msr(AMX_CTL_EL1, 1)).unwrap();
        assert!(machine.cpu.amx.enabled(AmxView::El1));
        machine.system_instruction(mrs(AMX_STATE_T, 2)).unwrap();
        assert_eq!(machine.cpu.state.x[2], 0);

        machine.amx(SET).unwrap();
        assert!(machine.cpu.amx.live());
        assert!(machine.amx(SET).is_err(), "set while live is refused");
        machine.system_instruction(mrs(AMX_STATE_T, 2)).unwrap();
        assert_eq!(machine.cpu.state.x[2], 1);

        // X0 = 1.0f32 lanes at DATA, loaded into X[0] and Y[0].
        let ones: Vec<u8> = (0..16).flat_map(|_| 1.0f32.to_le_bytes()).collect();
        assert!(machine.host.write_ram(DATA, &ones));
        machine.cpu.state.x[3] = DATA;
        machine.amx(LDX | 3).unwrap();
        machine.amx(0x0020_1020 | 3).unwrap(); // ldy
        machine.cpu.state.x[4] = 0;
        machine.amx(FMA32 | 4).unwrap();
        // stz row 0 to DATA + 0x100 crossing no page; then a store across one.
        machine.cpu.state.x[5] = DATA + 0x100;
        machine.amx(STZ | 5).unwrap();
        let mut row = [0u8; 64];
        assert!(machine.host.read_ram(DATA + 0x100, &mut row));
        assert_eq!(&row[..4], &1.0f32.to_le_bytes());
        machine.cpu.state.x[5] = DATA + 0x1000 - 32;
        machine.amx(STZ | 5).unwrap();
        assert!(machine.host.read_ram(DATA + 0x1000 - 32, &mut row));
        assert_eq!(&row[..4], &1.0f32.to_le_bytes());
        // msr, mrs, set, mrs, ldx, ldy, fma32, stz, stz.
        assert_eq!(machine.cpu.pc, BASE + 9 * 4, "each completed word advances");

        machine.amx(CLR).unwrap();
        assert!(!machine.cpu.amx.live());
        assert!(machine.amx(CLR).is_err(), "clr without live state");
        assert!(machine.amx(LDX | 3).is_err(), "no live state");
    }

    #[test]
    fn chip_generation_drives_id_and_transfer_semantics() {
        for (chip, id, rows) in [
            (Chip::AppleM1, 1, 2),
            (Chip::AppleM2, 2, 4),
            (Chip::AppleM3, 4, 4),
            (Chip::AppleM4, 8, 4),
        ] {
            let mut machine = machine_on(chip, &[]);
            machine
                .system_instruction(mrs(crate::machine::amx::AMXIDR_EL1, 2))
                .unwrap();
            assert_eq!(machine.cpu.state.x[2], id);
            machine.cpu.state.x[1] = (1 << 63) | 0x100;
            machine.system_instruction(msr(AMX_CTL_EL1, 1)).unwrap();
            machine.amx(SET).unwrap();
            for row in 0..4 {
                assert!(
                    machine
                        .host
                        .write_ram(DATA + row * 64, &[row as u8 + 1; 64])
                );
            }
            // Bit60 selects four rows on M2–M4; M3/M4 bit61 distributes
            // them every other row. All destinations wrap after X7.
            machine.cpu.state.x[3] = (1 << 62) | (1 << 61) | (1 << 60) | (7 << 56) | DATA;
            machine.amx(LDX | 3).unwrap();
            let registers = machine.cpu.amx.registers.as_ref().unwrap();
            assert_eq!(registers.x[7], [1; 64]);
            if matches!(chip, Chip::AppleM3 | Chip::AppleM4) {
                assert_eq!(registers.x[1], [2; 64]);
                assert_eq!(registers.x[3], [3; 64]);
                assert_eq!(registers.x[5], [4; 64]);
                assert_eq!(registers.x[0], [0; 64]);
            } else {
                assert_eq!(registers.x[0], [2; 64]);
                assert_eq!(registers.x[1], [if rows == 4 { 3 } else { 0 }; 64]);
                assert_eq!(registers.x[2], [if rows == 4 { 4 } else { 0 }; 64]);
            }
            machine.amx(CLR).unwrap();
            assert!(!machine.cpu.amx.live());
        }
    }

    #[test]
    fn unqualified_generation_refuses_before_enablement_or_state_effects() {
        for chip in [Chip::AppleM5, Chip::AppleM6] {
            let mut machine = machine_on(chip, &[]);
            let ram = machine.host.ram.clone();
            let esr = machine.cpu.read(SystemRegister::ESR_EL1);
            for word in [SET, LDX, FMA32, CLR] {
                let error = machine.amx(word).unwrap_err();
                assert!(format!("{error:?}").contains(amx::UNQUALIFIED_GENERATION));
                assert_eq!(machine.cpu.pc, BASE);
                assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
                assert!(!machine.cpu.amx.live());
                assert_eq!(machine.host.ram, ram);
            }
        }
    }

    #[test]
    fn a_vhe_host_kernel_is_governed_by_the_el2_copy() {
        let mut machine = machine(&[]);
        machine.cpu.pstate = crate::machine::exception::Pstate::reset(2);
        *machine.cpu.amx.control(AmxView::El1) = 1 << 63;
        assert!(machine.amx(SET).is_ok());
        assert!(!machine.cpu.amx.live(), "the EL1 copy does not enable");
        machine.cpu.pc = BASE;
        machine.cpu.state.x[1] = 1 << 63;
        machine.system_instruction(msr(AMX_CTL_EL1, 1)).unwrap();
        machine.amx(SET).unwrap();
        assert!(machine.cpu.amx.live());
    }

    #[test]
    fn unallocated_operations_are_undefined_when_enabled() {
        let mut machine = machine(&[]);
        *machine.cpu.amx.control(AmxView::El1) = 1 << 63;
        machine.amx(0x0020_13ff).unwrap();
        assert_eq!(
            machine.cpu.read(SystemRegister::ESR_EL1),
            syndrome(Class::Unknown, 0)
        );
    }

    #[test]
    fn translated_transfers_cross_pages_and_fault_without_partial_effects() {
        for chip in [Chip::AppleM1, Chip::AppleM2, Chip::AppleM3, Chip::AppleM4] {
            let mut machine = machine_on(chip, &[]);
            // 4 KiB granule, 39-bit low half: L1, L2 and L3 tables in RAM. VA
            // page 0 is writable, page 1 read-only and page 2 unmapped.
            let (l1, l2, l3) = (BASE + 0xa000, BASE + 0xb000, BASE + 0xc000);
            let page =
                |pa: u64, read_only: bool| pa | 0b11 | 1 << 10 | 1 << 2 | u64::from(read_only) << 7;
            for (slot, descriptor) in [
                (l1, l2 | 0b11),
                (l2, l3 | 0b11),
                (l3, page(BASE, false)),
                (l3 + 8, page(BASE + 0x1000, true)),
            ] {
                assert!(machine.host.write_ram(slot, &descriptor.to_le_bytes()));
            }
            for (register, value) in [
                (SystemRegister::SCTLR_EL1, mmu::SCTLR_M),
                // T0SZ 25, EPD1, 48-bit IPS.
                (SystemRegister::TCR_EL1, 25 | 1 << 23 | 5 << 32),
                (SystemRegister::TTBR0_EL1, l1),
                (SystemRegister::MAIR_EL1, 0xff00),
            ] {
                machine.cpu.registers.set(register, 0, value);
            }
            machine.cpu.registers.set(SystemRegister::VBAR_EL1, 0, 0x0);
            let bytes: Vec<u8> = (0..512).map(|i| (i * 7) as u8).collect();
            assert!(machine.host.write_ram(BASE + 0xf00, &bytes));
            *machine.cpu.amx.control(AmxView::El1) = 1 << 63;
            machine.amx(SET).unwrap();

            machine.cpu.state.x[3] = 0xfe0;
            machine.amx(LDX | 3).unwrap();
            let registers = machine.cpu.amx.registers.as_deref().unwrap();
            assert_eq!(registers.x[0][..], bytes[0xe0..0xe0 + 64]);

            // A store into page 1 is a permission fault at its first byte there.
            let mut before = [0u8; 64];
            assert!(machine.host.read_ram(BASE + 0xfe0, &mut before));
            machine.cpu.pc = 0x40;
            machine.amx(STZ | 3).unwrap();
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1),
                syndrome(Class::DataAbortSame, 0b00_1111 | 1 << 6)
            );
            assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), 0x1000);
            assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), 0x40);
            let mut after = [0u8; 64];
            assert!(machine.host.read_ram(BASE + 0xfe0, &mut after));
            assert_eq!(after, before, "nothing written");

            // A load reaching page 2 is a level 3 translation fault.
            machine.cpu.state.x[3] = 0x1fe0;
            machine.amx(LDX | 3).unwrap();
            assert_eq!(
                machine.cpu.read(SystemRegister::ESR_EL1),
                syndrome(Class::DataAbortSame, 0b00_0111)
            );
            assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), 0x2000);
            let registers = machine.cpu.amx.registers.as_deref().unwrap();
            assert_eq!(registers.x[0][..], bytes[0xe0..0xe0 + 64], "unchanged");
        }
    }

    #[test]
    fn m1_pair_alignment_reports_native_iss_and_far_before_translation() {
        for el in [0, 1] {
            for operation in [0, 1, 2, 3, 4, 5] {
                for offset in [1, 63, 64, 127] {
                    let mut machine = machine_on(Chip::AppleM1, &[]);
                    *machine.cpu.amx.control(AmxView::El1) = 1 << 63;
                    machine.amx(SET).unwrap();
                    machine.cpu.amx.registers.as_mut().unwrap().x[7] = [0x37; 64];
                    machine.cpu.amx.registers.as_mut().unwrap().z[63] = [0xb1; 64];
                    let before = machine.cpu.amx.registers.clone();
                    let ram = machine.host.ram.clone();
                    machine.cpu.pc = BASE;
                    machine.cpu.pstate = crate::machine::exception::Pstate::reset(el);
                    // No translation table exists at TTBR0=0: a walk would
                    // fail. Alignment must win without any memory service.
                    machine
                        .cpu
                        .registers
                        .set(SystemRegister::SCTLR_EL1, 0, mmu::SCTLR_M);
                    machine
                        .cpu
                        .registers
                        .set(SystemRegister::TCR_EL1, 0, 25 | 5 << 32);
                    machine.cpu.registers.set(SystemRegister::TTBR0_EL1, 0, 0);
                    machine
                        .cpu
                        .registers
                        .set(SystemRegister::VBAR_EL1, 0, BASE + 0x4000);
                    let address = 0x100_0000 | offset;
                    machine.cpu.state.x[3] = (0xff << 56) | address;
                    let write = matches!(operation, 2 | 3 | 5);
                    machine
                        .completing(BASE, |machine| machine.amx(LDX | (operation << 5) | 3))
                        .unwrap();
                    let class = if el == 0 {
                        Class::DataAbortLower
                    } else {
                        Class::DataAbortSame
                    };
                    assert_eq!(
                        machine.cpu.read(SystemRegister::ESR_EL1),
                        syndrome(class, 0x21 | u32::from(write) << 6),
                        "ISV is zero, including the 128-byte transfer width"
                    );
                    assert_eq!(machine.cpu.read(SystemRegister::FAR_EL1), address);
                    assert_eq!(machine.cpu.read(SystemRegister::ELR_EL1), BASE);
                    assert_eq!(machine.cpu.retired, 0, "faulting word never retires");
                    assert!(machine.cpu.amx.registers == before);
                    assert_eq!(machine.host.ram, ram);
                }
            }
        }
    }

    #[test]
    fn alignment_qualification_does_not_change_live_or_hacr_admission() {
        let mut machine = machine_on(Chip::AppleM1, &[]);
        machine.cpu.state.x[3] = (1 << 62) | (DATA + 64);
        machine.amx(LDX | 3).unwrap();
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0xfe00_0003);

        *machine.cpu.amx.control(AmxView::El1) = 1 << 63;
        machine.cpu.pc = BASE;
        assert!(
            machine.amx(LDX | 3).is_err(),
            "no live state remains unqualified"
        );
        machine.amx(SET).unwrap();
        machine.cpu.pc = BASE;
        let before = machine.cpu.amx.registers.clone();
        machine
            .cpu
            .registers
            .set(SystemRegister::HACR_EL2, 0, 1 << 10);
        let error = machine.amx(LDX | 3).unwrap_err();
        assert!(format!("{error:?}").contains("bit 10"));
        assert_eq!(machine.cpu.pc, BASE);
        assert!(machine.cpu.amx.registers == before);
    }

    #[test]
    fn later_chips_keep_refusing_unqualified_pair_alignment() {
        for chip in [Chip::AppleM2, Chip::AppleM3, Chip::AppleM4] {
            let mut machine = machine_on(chip, &[]);
            *machine.cpu.amx.control(AmxView::El1) = 1 << 63;
            machine.amx(SET).unwrap();
            machine.cpu.pc = BASE;
            machine.cpu.state.x[3] = (1 << 62) | (DATA + 64);
            let before = machine.cpu.amx.registers.clone();
            let esr = machine.cpu.read(SystemRegister::ESR_EL1);
            for word in [LDX, STZ] {
                assert!(machine.amx(word | 3).is_err());
                assert_eq!(machine.cpu.pc, BASE);
                assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), esr);
                assert!(machine.cpu.amx.registers == before);
            }
        }
    }

    #[test]
    fn transfers_outside_ram_stop_without_effects() {
        let mut machine = machine(&[]);
        *machine.cpu.amx.control(AmxView::El1) = 1 << 63;
        machine.amx(SET).unwrap();
        machine.cpu.state.x[3] = 1 << 40;
        let stop = machine.amx(LDX | 3).unwrap_err();
        assert!(format!("{stop:?}").contains("Device"), "{stop:?}");
        assert_eq!(
            machine.cpu.amx.registers.as_deref(),
            Some(&AmxRegisters::zeroed())
        );
    }
}
