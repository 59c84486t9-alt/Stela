//! The architectural state of one PE: `GuestState` for the registers native
//! blocks use, plus PC, PSTATE, banked stack pointers and the kernel level's
//! system registers that only the engine touches.
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
    pub guarded: GuardedRegisters,
    /// Apple PAC controls (XNU `xnu-6153.141.1` `arm64_common.h`).
    pub apctl: u64,
    /// KERNELKEYLO/HI_EL1.
    pub kernel_key: [u64; 2],
    /// Implementation-defined registers without architectural effect here.
    pub impdef: super::impdef::Registers,
    /// HCR_EL2 when the profile has EL2. Only VHE is modeled, so E2H stays
    /// set; TGE selects the host configuration.
    pub hcr: u64,
    /// TPIDR_EL2 when the profile has EL2.
    pub tpidr_el2: u64,
    /// Apple VMSA_LOCK_EL1: locks of the kernel level's translation
    /// registers.
    pub vmsa_lock: u64,
    /// Registers of levels that never execute under a VHE host: EL1 and GL1
    /// copies reached through `*_EL12`, `*_EL02` and `*_GL12` encodings, and
    /// EL2 virtualization controls that only act on guests. Values are kept;
    /// UNKNOWN reset values read as 0.
    pub inactive: alloc::collections::BTreeMap<u16, u64>,
}

pub const HCR_FMO: u64 = 1 << 3;
pub const HCR_IMO: u64 = 1 << 4;
pub const HCR_TGE: u64 = 1 << 27;
pub const HCR_HCD: u64 = 1 << 29;
pub const HCR_E2H: u64 = 1 << 34;

/// Apple GXF state: configuration, entry points and the GL1 bank
/// (Asahi Linux "SPRR and GXF"; m1n1 `cpu_regs.h` and `gxf_asm.S`).
#[derive(Debug, Clone, Default)]
pub struct GuardedRegisters {
    /// GXF_CONFIG_EL1; bit 0 enables GENTER.
    pub config: u64,
    /// GXF_ENTER_EL1: where GENTER continues.
    pub enter: u64,
    /// GXF_ABORT_EL1.
    pub abort: u64,
    /// SP_GL1 when it is not the current stack pointer.
    pub sp: u64,
    pub tpidr: u64,
    pub vbar: u64,
    pub spsr: u64,
    /// ASPSR_GL1; bit 0 makes GEXIT return to the guarded level.
    pub aspsr: u64,
    pub esr: u64,
    pub elr: u64,
    pub far: u64,
}

pub const GXF_CONFIG_EN: u64 = 1;
pub const ASPSR_GUARDED: u64 = 1;

/// Which stack pointer a PSTATE selects: SP_EL0, the kernel level's own
/// (SP_EL1, or SP_EL2 for a VHE host), or the guarded level's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stack {
    El0,
    Kernel,
    Guarded,
}

fn stack(pstate: Pstate) -> Stack {
    match (pstate.el, pstate.sp_el1, pstate.guarded) {
        (0, _, _) | (_, false, _) => Stack::El0,
        (_, true, true) => Stack::Guarded,
        (_, true, false) => Stack::Kernel,
    }
}

/// Why a GXF instruction cannot run here; each is UNDEFINED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedRefusal {
    /// GENTER outside the kernel level, at the guarded level, or with GXF or
    /// SPRR disabled.
    Enter,
    /// GEXIT outside the guarded level.
    Exit,
}

#[derive(Debug, Clone)]
pub struct Cpu {
    pub state: GuestState,
    pub pc: u64,
    pub pstate: Pstate,
    pub system: SystemRegisters,
    /// The EL exceptions are taken to: 1, or 2 when the profile has EL2 and
    /// runs as a VHE host. The `system` registers belong to this level; the
    /// guarded level beside it is GL1 or GL2.
    pub kernel_el: u8,
    /// The PE's Apple AMX unit (`machine::amx`).
    pub amx: super::amx::Unit,
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
            kernel_el: pstate.el.max(1),
            amx: super::amx::Unit::default(),
        }
    }

    fn bank(&mut self, which: Stack) -> &mut u64 {
        match which {
            Stack::El0 => &mut self.system.sp_el0,
            Stack::Kernel => &mut self.system.sp_el1,
            Stack::Guarded => &mut self.system.guarded.sp,
        }
    }

    /// Switch PSTATE, moving the current stack pointer to its bank and
    /// loading the newly selected one.
    pub fn set_pstate(&mut self, next: Pstate) {
        let (was, will) = (stack(self.pstate), stack(next));
        if was != will {
            let current = self.state.sp;
            *self.bank(was) = current;
            self.state.sp = *self.bank(will);
        }
        self.pstate = next;
    }

    /// SP_EL0 regardless of which stack pointer is current.
    pub fn sp_el0(&self) -> u64 {
        if stack(self.pstate) == Stack::El0 {
            self.state.sp
        } else {
            self.system.sp_el0
        }
    }

    pub fn set_sp_el0(&mut self, value: u64) {
        if stack(self.pstate) == Stack::El0 {
            self.state.sp = value;
        } else {
            self.system.sp_el0 = value;
        }
    }

    /// GXF is usable when both SPRR and GXF are enabled (m1n1 `gxf.c`
    /// `gxf_enabled`).
    pub fn guarded_enabled(&self) -> bool {
        self.system.translation.sprr.enabled() && self.system.guarded.config & GXF_CONFIG_EN != 0
    }

    /// GENTER at EL1: bank the return state in the GL1 registers and
    /// continue at GXF_ENTER_EL1 on the GL1 stack with every exception masked.
    /// Masking follows exception entry; it is an inference, as is the
    /// SP_GL1 selection (m1n1 sets `sp` after GENTER).
    pub fn guarded_enter(&mut self) -> Result<(), GuardedRefusal> {
        if self.pstate.el != self.kernel_el || self.pstate.guarded || !self.guarded_enabled() {
            return Err(GuardedRefusal::Enter);
        }
        let from = self.pstate;
        self.system.guarded.spsr = from.to_spsr(self.state.nzcv);
        self.system.guarded.elr = self.pc.wrapping_add(4);
        self.system.guarded.aspsr = 0;
        self.set_pstate(Pstate {
            sp_el1: true,
            daif: exception::DAIF_ALL,
            guarded: true,
            ..from
        });
        self.pc = self.system.guarded.enter;
        Ok(())
    }

    /// GEXIT at the guarded level: restore PSTATE from SPSR_GL1 and continue
    /// at ELR_GL1, at GL1 when ASPSR_GL1 says so.
    pub fn guarded_exit(&mut self) -> Result<Result<(), IllegalReturn>, GuardedRefusal> {
        if !self.pstate.guarded {
            return Err(GuardedRefusal::Exit);
        }
        let (mut next, nzcv) = match exception::from_spsr(self.system.guarded.spsr, self.kernel_el)
        {
            Ok(value) => value,
            Err(illegal) => return Ok(Err(illegal)),
        };
        next.guarded = self.system.guarded.aspsr & ASPSR_GUARDED != 0;
        if next.guarded && next.el != self.kernel_el {
            return Ok(Err(IllegalReturn::Mode(0)));
        }
        if let Err(illegal) = self.host_regime(next) {
            return Ok(Err(illegal));
        }
        self.state.nzcv = nzcv;
        self.set_pstate(next);
        self.pc = self.system.guarded.elr;
        Ok(Ok(()))
    }

    /// EL0 under an EL2 kernel runs in the host's EL2&0 regime only while
    /// HCR_EL2.TGE is set.
    fn host_regime(&self, next: Pstate) -> Result<(), IllegalReturn> {
        if self.kernel_el == 2 && next.el == 0 && self.system.hcr & HCR_TGE == 0 {
            return Err(IllegalReturn::GuestRegime);
        }
        Ok(())
    }

    pub fn requester(&self) -> mmu::Requester {
        mmu::Requester {
            el: self.pstate.el,
            pan: self.pstate.pan,
            unprivileged: false,
            guarded: self.pstate.guarded,
        }
    }

    /// Take an exception to the kernel level and continue at its vector. At
    /// the guarded level it is taken to that GL through VBAR_GLx and the GL
    /// bank instead.
    pub fn take(&mut self, exception: Exception) {
        let from = self.pstate;
        if from.guarded {
            let bank = &mut self.system.guarded;
            bank.spsr = from.to_spsr(self.state.nzcv);
            bank.elr = exception.return_address;
            bank.aspsr = ASPSR_GUARDED;
            if exception.vector == Vector::Synchronous {
                bank.esr = exception.syndrome;
            }
            if let Some(address) = exception.fault_address {
                bank.far = address;
            }
            let vbar = bank.vbar;
            self.set_pstate(exception::entry_pstate(
                from,
                self.system.translation.sctlr,
                self.kernel_el,
            ));
            self.pc = vbar.wrapping_add(exception::vector_offset(from, exception.vector));
            return;
        }
        self.system.spsr = from.to_spsr(self.state.nzcv);
        self.system.elr = exception.return_address;
        if exception.vector == Vector::Synchronous {
            self.system.esr = exception.syndrome;
        }
        if let Some(address) = exception.fault_address {
            self.system.far = address;
        }
        self.set_pstate(exception::entry_pstate(
            from,
            self.system.translation.sctlr,
            self.kernel_el,
        ));
        self.pc = self
            .system
            .vbar
            .wrapping_add(exception::vector_offset(from, exception.vector));
    }

    /// ERET from the kernel level. EL0 ERET is undefined and must not reach
    /// here.
    pub fn exception_return(&mut self) -> Result<(), IllegalReturn> {
        let (next, nzcv) = exception::from_spsr(self.system.spsr, self.kernel_el)?;
        self.host_regime(next)?;
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

    #[test]
    fn an_el2_kernel_takes_exceptions_to_el2_and_returns_to_el0_only_with_tge() {
        let mut cpu = Cpu::new(0x8000, Pstate::reset(2));
        assert_eq!(cpu.kernel_el, 2);
        cpu.system.hcr = HCR_E2H;
        cpu.system.vbar = 0x1_0000;
        cpu.system.sp_el1 = 0xa000;
        cpu.state.sp = 0xa000;
        cpu.take(Exception::synchronous(Class::HypervisorCall, 3, 0x8004));
        assert_eq!((cpu.pc, cpu.pstate.el), (0x1_0200, 2));
        assert_eq!(cpu.system.spsr & 0xf, 0b1001, "EL2h");
        assert_eq!(cpu.system.esr, 0x5a00_0003);
        cpu.exception_return().unwrap();
        assert_eq!((cpu.pc, cpu.pstate.el), (0x8004, 2));
        // EL0 would run in the guest's EL1&0 regime without TGE.
        cpu.system.spsr = 0;
        assert_eq!(cpu.exception_return(), Err(IllegalReturn::GuestRegime));
        cpu.system.hcr |= HCR_TGE;
        cpu.exception_return().unwrap();
        assert_eq!(cpu.pstate.el, 0);
        // EL1 does not run under a VHE host.
        cpu.take(Exception::synchronous(Class::SupervisorCall, 0, 0x8008));
        assert_eq!((cpu.pc, cpu.pstate.el), (0x1_0400, 2));
        cpu.system.spsr = 0b0101;
        assert_eq!(cpu.exception_return(), Err(IllegalReturn::Mode(5)));
    }
}
