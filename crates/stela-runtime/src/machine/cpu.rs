//! The architectural state of one PE: `GuestState` for the registers native
//! blocks use, plus PC, PSTATE, banked stack pointers and the EL1 system
//! registers that only the engine touches.
use super::{
    exception::{self, Class, IllegalReturn, Pstate, Vector},
    mmu::{self, Controls},
    timer::Timer,
};
use stela_compiler::GuestState;

/// Pointer-authentication key registers, in APIA, APIB, APDA, APDB, APGA
/// order, each as (low, high).
pub type PointerKeys = [[u64; 2]; 5];

#[derive(Debug, Clone, Default)]
pub struct SystemRegisters {
    /// SP_EL0 when it is not the current stack pointer.
    pub sp_el0: u64,
    /// SP_EL1 when it is not the current stack pointer.
    pub sp_el1: u64,
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
    pub far: u64,
    pub vbar: u64,
    pub translation: Controls,
    pub actlr: u64,
    pub amair: u64,
    pub afsr0: u64,
    pub afsr1: u64,
    pub contextidr: u64,
    pub cpacr: u64,
    pub cntkctl: u64,
    pub csselr: u64,
    pub mdscr: u64,
    pub oslsr_locked: bool,
    pub osdlr: u64,
    pub par: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub tpidr_el1: u64,
    pub keys: PointerKeys,
    pub physical_timer: Timer,
    pub virtual_timer: Timer,
    /// The local event register (WFE/SEV).
    pub event: bool,
}

#[derive(Debug, Clone)]
pub struct Cpu {
    pub state: GuestState,
    pub pc: u64,
    pub pstate: Pstate,
    pub system: SystemRegisters,
}

/// What an exception entry needs beyond the vector kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exception {
    pub vector: Vector,
    pub syndrome: u64,
    pub fault_address: Option<u64>,
    /// ELR_EL1: the preferred return address.
    pub return_address: u64,
}

impl Exception {
    pub fn synchronous(class: Class, iss: u32, return_address: u64) -> Self {
        Self {
            vector: Vector::Synchronous,
            syndrome: exception::syndrome(class, iss),
            fault_address: None,
            return_address,
        }
    }

    pub fn undefined(pc: u64) -> Self {
        Self::synchronous(Class::Unknown, 0, pc)
    }
}

impl Cpu {
    pub fn new(pc: u64, pstate: Pstate) -> Self {
        Self {
            state: GuestState::default(),
            pc,
            pstate,
            system: SystemRegisters {
                oslsr_locked: true,
                ..SystemRegisters::default()
            },
        }
    }

    fn uses_sp_el1(pstate: Pstate) -> bool {
        pstate.el == 1 && pstate.sp_el1
    }

    /// Switch PSTATE, moving the current stack pointer to its bank and
    /// loading the newly selected one.
    pub fn set_pstate(&mut self, next: Pstate) {
        let was = Self::uses_sp_el1(self.pstate);
        let will = Self::uses_sp_el1(next);
        if was != will {
            if was {
                self.system.sp_el1 = self.state.sp;
                self.state.sp = self.system.sp_el0;
            } else {
                self.system.sp_el0 = self.state.sp;
                self.state.sp = self.system.sp_el1;
            }
        }
        self.pstate = next;
    }

    /// SP_EL0 regardless of which stack pointer is current.
    pub fn sp_el0(&self) -> u64 {
        if Self::uses_sp_el1(self.pstate) {
            self.system.sp_el0
        } else {
            self.state.sp
        }
    }

    pub fn set_sp_el0(&mut self, value: u64) {
        if Self::uses_sp_el1(self.pstate) {
            self.system.sp_el0 = value;
        } else {
            self.state.sp = value;
        }
    }

    pub fn requester(&self) -> mmu::Requester {
        mmu::Requester {
            el: self.pstate.el,
            pan: self.pstate.pan,
            unprivileged: false,
        }
    }

    /// Take an exception to EL1 and continue at its vector.
    pub fn take(&mut self, exception: Exception) {
        let from = self.pstate;
        self.system.spsr = from.to_spsr(self.state.nzcv);
        self.system.elr = exception.return_address;
        if exception.vector == Vector::Synchronous {
            self.system.esr = exception.syndrome;
        }
        if let Some(address) = exception.fault_address {
            self.system.far = address;
        }
        self.set_pstate(exception::entry_pstate(from, self.system.translation.sctlr));
        self.pc = self
            .system
            .vbar
            .wrapping_add(exception::vector_offset(from, exception.vector));
    }

    /// ERET from EL1. EL0 ERET is undefined and must not reach here.
    pub fn exception_return(&mut self) -> Result<(), IllegalReturn> {
        let (next, nzcv) = exception::from_spsr(self.system.spsr)?;
        self.state.nzcv = nzcv;
        self.set_pstate(next);
        self.pc = self.system.elr;
        // ERET clears the local exclusive monitor and sets the event register.
        self.system.event = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::exception::{DAIF_ALL, DAIF_I};

    #[test]
    fn exception_entry_and_return_bank_stack_pointers() {
        let user = Pstate {
            el: 0,
            sp_el1: false,
            daif: 0,
            ..Pstate::RESET_EL1
        };
        let mut cpu = Cpu::new(0x4000, user);
        cpu.state.sp = 0x7000;
        cpu.state.nzcv = 0x6000_0000;
        cpu.system.sp_el1 = 0xffff_0000;
        cpu.system.vbar = 0xffff_8000;
        cpu.take(Exception::synchronous(Class::SupervisorCall, 7, 0x4004));
        assert_eq!(cpu.pc, 0xffff_8400);
        assert_eq!(cpu.state.sp, 0xffff_0000);
        assert_eq!(cpu.sp_el0(), 0x7000);
        assert_eq!(cpu.system.elr, 0x4004);
        assert_eq!(cpu.system.spsr, 0x6000_0000);
        assert_eq!(cpu.system.esr, 0x5600_0007);
        assert_eq!(cpu.pstate.daif, DAIF_ALL);
        assert!(cpu.pstate.pan);
        cpu.state.sp = 0xffff_0100;
        cpu.system.spsr = DAIF_I as u64 * 64; // EL0t with IRQs masked
        cpu.exception_return().unwrap();
        assert_eq!(
            (cpu.pc, cpu.state.sp, cpu.system.sp_el1),
            (0x4004, 0x7000, 0xffff_0100)
        );
        assert_eq!(cpu.pstate.el, 0);
        assert_eq!(cpu.pstate.daif, DAIF_I);
        assert_eq!(cpu.state.nzcv, 0);
        cpu.system.spsr = 0x9;
        assert_eq!(cpu.exception_return(), Err(IllegalReturn::Mode(9)));
    }

    #[test]
    fn interrupts_from_el1h_use_the_current_el_spx_group() {
        let mut cpu = Cpu::new(0x8000, Pstate::RESET_EL1);
        cpu.system.vbar = 0x1_0000;
        cpu.system.esr = 0x1234;
        cpu.take(Exception {
            vector: Vector::Fiq,
            syndrome: 0,
            fault_address: None,
            return_address: 0x8000,
        });
        assert_eq!(cpu.pc, 0x1_0300);
        assert_eq!(cpu.system.esr, 0x1234, "interrupts leave ESR unchanged");
    }
}
