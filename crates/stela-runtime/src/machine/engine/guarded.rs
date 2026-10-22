//! Apple GXF instruction exits (`block::system::GuardedOperation`): GENTER
//! and GEXIT. The contracts and their evidence are in `docs/design/system.md`
//! (GXF).
use super::{Devices, Event, Host, Machine, RequirementKind, Step};
use crate::machine::{cpu::ASPSR_GUARDED, hacr};
use stela_compiler::block::system::GuardedOperation;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Execute the GXF instruction `word` at the PC.
    pub(super) fn guarded(&mut self, word: u32, operation: GuardedOperation) -> Step {
        let enter = matches!(operation, GuardedOperation::Enter { .. });
        if let Some(step) = self.hacr_guest(word, hacr::Operation::Guarded { enter }) {
            return step;
        }
        match operation {
            GuardedOperation::Enter { immediate } => self.guarded_enter(word, immediate),
            GuardedOperation::Exit => self.guarded_exit(),
        }
    }

    /// GENTER (`Cpu::guarded_enter`). At GL0 no source or 26A434 code shows
    /// its effect: it stays UNDEFINED, as at EL0, once reported.
    fn guarded_enter(&mut self, word: u32, immediate: u8) -> Step {
        if self.cpu.pstate.guarded && self.cpu.pstate.el == 0 {
            let requirement = self.requirement(RequirementKind::SystemInstruction {
                word,
                detail: "GENTER at GL0 has no established effect; it is taken as UNDEFINED",
            });
            self.degrade(requirement)?;
        }
        if self.cpu.guarded_enter(immediate).is_err() {
            return self.undefined();
        }
        self.host.report(&Event::Guarded {
            enter: true,
            el: self.cpu.pstate.el,
            guarded: true,
            pc: self.cpu.pc,
        });
        self.sync_regime();
        Ok(())
    }

    /// GEXIT (`Cpu::guarded_exit`).
    fn guarded_exit(&mut self) -> Step {
        if self.cpu.pstate.guarded && self.cpu.pstate.el != 0 {
            let bank = &self.cpu.apple.guarded[usize::from(self.cpu.pstate.el) - 1];
            self.guest_entry(bank.spsr, bank.aspsr & ASPSR_GUARDED != 0)?;
        }
        match self.cpu.guarded_exit() {
            Err(_) => self.undefined(),
            Ok(Err(reason)) => Err(self.unsupported(RequirementKind::IllegalReturn(reason))),
            Ok(Ok(())) => {
                self.pacm_written = true;
                self.host.report(&Event::Guarded {
                    enter: false,
                    el: self.cpu.pstate.el,
                    guarded: self.cpu.pstate.guarded,
                    pc: self.cpu.pc,
                });
                self.sync_regime();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::tests::{BASE, FakeHost, machine_on};
    use super::super::{NoDevices, Stop};
    use super::*;
    use crate::machine::{Chip, system::Register as SystemRegister};

    const GENTER: u32 = 0x0020_1420;
    const GEXIT: u32 = 0x0020_1400;
    const ENTER: u64 = BASE + 0x9000;
    pub(in super::super) const VECTORS: u64 = BASE + 0xa000;
    pub(in super::super) const UNDEFINED: u64 = 0x0200_0000;

    /// A machine on `chip` at EL1 with SPRR and EL1's GXF enabled and
    /// GXF_ENTER_EL1 at [`ENTER`].
    pub(in super::super) fn gxf(chip: Chip) -> Machine<FakeHost, NoDevices> {
        let mut machine = machine_on(chip, &[]);
        machine.cpu.state.x[0] = 1;
        machine.cpu.state.x[1] = ENTER;
        for word in [
            0xd51e_f100, // msr SPRR_CONFIG_EL1, x0
            0xd51e_f140, // msr GXF_CONFIG_EL1, x0
            0xd51e_f821, // msr GXF_ENTER_EL1, x1
        ] {
            machine.system_instruction(word).unwrap();
        }
        machine
    }

    /// [`gxf`] after GENTER, at GL1 with VBAR_GL1 at [`VECTORS`].
    pub(in super::super) fn gl1(chip: Chip) -> Machine<FakeHost, NoDevices> {
        let mut machine = gxf(chip);
        machine.system_instruction(GENTER).unwrap();
        machine.cpu.state.x[2] = VECTORS;
        machine.system_instruction(0xd51e_fa42).unwrap(); // msr VBAR_GL1, x2
        machine
    }

    #[test]
    fn genter_records_its_immediate_and_from_a_gl_returns_there() {
        let mut machine = gxf(Chip::AppleM2);
        machine.cpu.state.sp = 0x7000;
        let first = machine.cpu.pc;
        machine.system_instruction(GENTER | 3).unwrap();
        let bank = &machine.cpu.apple.guarded[0];
        assert_eq!(
            (bank.elr, bank.esr, bank.aspsr),
            (first + 4, 0xfe01_0003, 0)
        );
        assert_eq!(machine.cpu.pc, ENTER);
        // At GL1, on SP_EL0 with interrupts unmasked: GENTER #8 stays at GL1,
        // on SP_GL1 with DAIF set, and records the guarded return.
        machine.cpu.state.sp = 0x8000;
        machine.system_instruction(0xd500_40bf).unwrap(); // msr SPSel, #0
        machine.cpu.state.sp = 0x6000;
        machine.system_instruction(0xd503_43ff).unwrap(); // msr DAIFClr, #3
        let second = machine.cpu.pc;
        machine.system_instruction(GENTER | 8).unwrap();
        assert!(machine.cpu.pstate.guarded && machine.cpu.pstate.sp);
        assert_eq!(machine.cpu.pstate.el, 1);
        assert_eq!(machine.cpu.pstate.daif, crate::machine::exception::DAIF_ALL);
        assert_eq!((machine.cpu.pc, machine.cpu.state.sp), (ENTER, 0x8000));
        let bank = &machine.cpu.apple.guarded[0];
        assert_eq!(
            (bank.elr, bank.esr, bank.aspsr),
            (second + 4, 0xfe01_0008, 1)
        );
        // GEXIT resumes GL1 where it was, on SP_EL0 again.
        machine.system_instruction(GEXIT).unwrap();
        assert!(machine.cpu.pstate.guarded && !machine.cpu.pstate.sp);
        assert_eq!((machine.cpu.pc, machine.cpu.state.sp), (second + 4, 0x6000));
        assert_eq!(machine.cpu.read(SystemRegister::ESR_EL1), 0);
    }

    #[test]
    fn genter_at_gl0_stops_strictly_or_is_undefined_once_reported() {
        let mut machine = gl1(Chip::AppleM2);
        machine.cpu.state.x[3] = 0x3c0;
        machine.cpu.state.x[4] = BASE + 0xb000;
        for word in [
            0xd51e_fa63, // msr SPSR_GL1, x3 (EL0t, DAIF masked)
            0xd51e_fac4, // msr ELR_GL1, x4
            0xd69f_03e0, // eret
        ] {
            machine.system_instruction(word).unwrap();
        }
        assert_eq!(
            (machine.cpu.pstate.el, machine.cpu.pstate.guarded),
            (0, true)
        );
        machine.set_strict(true);
        assert!(matches!(
            machine.system_instruction(GENTER),
            Err(Stop::Unsupported(_))
        ));
        machine.set_strict(false);
        machine.system_instruction(GENTER).unwrap();
        assert_eq!(machine.cpu.pc, VECTORS + 0x400);
        assert_eq!(machine.cpu.apple.guarded[0].esr, UNDEFINED);
        assert_eq!(machine.take_unmodeled().len(), 1);
    }
}
