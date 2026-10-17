//! The architectural state of one PE: `GuestState` for the registers native
//! blocks use, plus PC, PSTATE, the System register file and Apple's state.
//!
//! EL0, EL1 and EL2 exist; EL2 is a VHE host (HCR_EL2.E2H is RES1). Every
//! exception is routed to its target EL as Arm's pseudocode routes it, and
//! entry and return use that EL's ELR, SPSR, ESR, FAR, VBAR and SP (Arm
//! `AArch64_TakeException`, `AArch64_ExceptionReturn`).
use super::{
    exception::{self, Class, IllegalReturn, Pstate, Vector},
    mmu::{self, Controls, Sprr},
    system::{
        Feature, File, Register,
        helpers::{bits, effective_nvx},
    },
};
use stela_compiler::GuestState;

pub const HCR_VM: u32 = 0;
pub const HCR_FMO: u32 = 3;
pub const HCR_IMO: u32 = 4;
pub const HCR_AMO: u32 = 5;
pub const HCR_VF: u32 = 6;
pub const HCR_VI: u32 = 7;
pub const HCR_VSE: u32 = 8;
pub const HCR_TSC: u32 = 19;
pub const HCR_TGE: u32 = 27;
pub const HCR_HCD: u32 = 29;
pub const HCR_TEA: u32 = 37;
pub const HCR_API: u32 = 41;

/// Apple GXF state of one guarded level: GL1 beside EL1, GL2 beside EL2
/// (Asahi Linux "SPRR and GXF"; m1n1 `cpu_regs.h`, `gxf.c` and `gxf_asm.S`).
#[derive(Debug, Clone, Default)]
pub struct GuardedBank {
    /// GXF_ENTER_ELx: where GENTER continues.
    pub enter: u64,
    /// GXF_ABORT_ELx.
    pub abort: u64,
    /// SP_GLx when it is not the current stack pointer.
    pub sp: u64,
    pub tpidr: u64,
    pub vbar: u64,
    pub spsr: u64,
    /// ASPSR_GLx; bit 0 makes GEXIT return to the guarded level.
    pub aspsr: u64,
    pub esr: u64,
    pub elr: u64,
    pub far: u64,
}

pub const GXF_CONFIG_EN: u64 = 1;
pub const ASPSR_GUARDED: u64 = 1;

/// Apple's implementation-defined state (machine::registers dispatches its
/// encodings).
#[derive(Debug, Clone)]
pub struct AppleState {
    /// SPRR_CONFIG_EL1.
    pub sprr_config: u64,
    /// SPRR permissions: EL0 of the EL1&0 regime, EL1, EL0 of the EL2&0
    /// regime, EL2.
    pub sprr_perm: [u64; 4],
    /// `S3_6_C15_C3_0` and `S3_6_C15_C3_1` (`mmu::Sprr::fields`).
    pub sprr_fields: [u64; 2],
    /// GXF_CONFIG_EL1.
    pub gxf_config: u64,
    /// GL1 and GL2.
    pub guarded: [GuardedBank; 2],
    /// APCTL_EL1 and APCTL_EL2.
    pub apctl: [u64; 2],
    /// KERNELKEYLO/HI_EL1.
    pub kernel_key: [u64; 2],
    /// VMSA_LOCK_EL1 and the EL whose translation registers it locks.
    pub vmsa_lock: u64,
    pub vmsa_lock_el: u8,
    /// VM_TMR_FIQ_ENA_EL2: bit 0 lets the EL1 virtual timer, bit 1 the EL1
    /// physical timer, signal FIQ.
    pub vm_timer_fiq: u64,
    /// Implementation-defined registers without architectural effect here.
    pub impdef: super::impdef::Registers,
}

/// SPRR_PERM indexes into [`AppleState::sprr_perm`].
pub const PERM_EL0_10: usize = 0;
pub const PERM_EL1: usize = 1;
pub const PERM_EL0_20: usize = 2;
pub const PERM_EL2: usize = 3;
pub const VM_TIMER_FIQ_VIRTUAL: u64 = 1;
pub const VM_TIMER_FIQ_PHYSICAL: u64 = 2;

impl Default for AppleState {
    fn default() -> Self {
        Self {
            sprr_config: 0,
            sprr_perm: [0; 4],
            sprr_fields: [0; 2],
            gxf_config: 0,
            guarded: [GuardedBank::default(), GuardedBank::default()],
            apctl: [0; 2],
            kernel_key: [0; 2],
            vmsa_lock: 0,
            vmsa_lock_el: 1,
            // Both EL1 timers signal FIQ until EL2 software says otherwise
            // (inference: m1n1 and SPTM program it explicitly).
            vm_timer_fiq: VM_TIMER_FIQ_VIRTUAL | VM_TIMER_FIQ_PHYSICAL,
            impdef: super::impdef::Registers::default(),
        }
    }
}

/// A translation regime of the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationRegime {
    /// EL1&0, through stage 1 and, with HCR_EL2.VM, stage 2.
    El10,
    /// EL2&0, the VHE host.
    El20,
}

/// Which stack pointer a PSTATE selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stack {
    El0,
    El1,
    El2,
    /// SP_GL1 or SP_GL2.
    Guarded(usize),
}

fn stack(pstate: Pstate) -> Stack {
    match (pstate.el, pstate.sp, pstate.guarded) {
        (0, _, _) | (_, false, _) => Stack::El0,
        (el, true, true) => Stack::Guarded(usize::from(el) - 1),
        (1, true, false) => Stack::El1,
        (_, true, false) => Stack::El2,
    }
}

/// Why a GXF instruction cannot run here; each is UNDEFINED.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardedRefusal {
    /// GENTER at EL0, at the guarded level, or with GXF or SPRR disabled.
    Enter,
    /// GEXIT outside the guarded level.
    Exit,
}

#[derive(Debug, Clone)]
pub struct Cpu {
    pub state: GuestState,
    pub pc: u64,
    pub pstate: Pstate,
    /// The architectural System registers.
    pub registers: File,
    pub apple: AppleState,
    /// The local event register (WFE/SEV).
    pub event: bool,
    /// Arm `ShouldAdvanceSS`: the instruction being stepped advances the
    /// software step state machine when it completes; ERET cancels that.
    pub step_advance: bool,
    /// The debug communications channel.
    pub dcc: super::debug::Dcc,
    /// The claim tags (DBGCLAIMSET_EL1, DBGCLAIMCLR_EL1), clear at reset.
    pub claim: u8,
    /// The Exclusives monitor: the physical reservation granule an exclusive
    /// load marked (`engine::exclusive`).
    pub monitor: Option<u64>,
    /// The PE's Apple AMX unit (`machine::amx`).
    pub amx: super::amx::Unit,
}

/// What an exception entry needs beyond the vector kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exception {
    pub vector: Vector,
    pub syndrome: u64,
    pub fault_address: Option<u64>,
    /// ELR_ELx: the preferred return address.
    pub return_address: u64,
    /// The EL it is taken to; `None` routes it as an exception that targets
    /// EL1 by default (to EL2 from EL2, or from EL0 with HCR_EL2.TGE).
    pub target: Option<u8>,
}

impl Exception {
    pub fn synchronous(class: Class, iss: u32, return_address: u64) -> Self {
        Self {
            vector: Vector::Synchronous,
            syndrome: exception::syndrome(class, iss),
            fault_address: None,
            return_address,
            target: None,
        }
    }

    pub fn undefined(pc: u64) -> Self {
        Self::synchronous(Class::Unknown, 0, pc)
    }

    pub fn to(self, el: u8) -> Self {
        Self {
            target: Some(el),
            ..self
        }
    }
}

/// The banked exception registers of one EL.
struct Bank {
    elr: Register,
    spsr: Register,
    esr: Register,
    far: Register,
    vbar: Register,
    sctlr: Register,
}

fn bank(el: u8) -> Bank {
    if el == 2 {
        Bank {
            elr: Register::ELR_EL2,
            spsr: Register::SPSR_EL2,
            esr: Register::ESR_EL2,
            far: Register::FAR_EL2,
            vbar: Register::VBAR_EL2,
            sctlr: Register::SCTLR_EL2,
        }
    } else {
        Bank {
            elr: Register::ELR_EL1,
            spsr: Register::SPSR_EL1,
            esr: Register::ESR_EL1,
            far: Register::FAR_EL1,
            vbar: Register::VBAR_EL1,
            sctlr: Register::SCTLR_EL1,
        }
    }
}

impl Cpu {
    /// A PE of the default chip.
    pub fn new(pc: u64, pstate: Pstate) -> Self {
        Self::of(super::Chip::DEFAULT, pc, pstate)
    }

    /// A PE of `chip`, its registers at their Cold reset values under the
    /// chip's profile.
    pub fn of(chip: super::Chip, pc: u64, pstate: Pstate) -> Self {
        let mut registers = File::new(chip);
        // OSLSR_EL1.OSLM = 0b10 (bits 3 and 0): the OS lock is implemented.
        // OSLK, set at Cold reset, comes with the reset value.
        let oslsr = registers.get(Register::OSLSR_EL1, 0);
        registers.set_raw(Register::OSLSR_EL1, 0, oslsr | 0b1000);
        Self {
            state: GuestState::default(),
            pc,
            pstate,
            registers,
            apple: AppleState::default(),
            event: false,
            step_advance: false,
            dcc: super::debug::Dcc::default(),
            claim: 0,
            monitor: None,
            amx: super::amx::Unit::default(),
        }
    }

    pub fn read(&self, register: Register) -> u64 {
        self.registers.get(register, 0)
    }

    pub fn field(&self, register: Register, low: u32, width: u32) -> u64 {
        bits(self.read(register), u64::from(low), u64::from(width))
    }

    pub fn hcr(&self, bit: u32) -> bool {
        self.field(Register::HCR_EL2, bit, 1) == 1
    }

    /// Arm `EffectiveHCR_EL2_NVx` (`helpers::effective_nvx`): '000' on a chip
    /// without FEAT_NV.
    pub fn nested(&self) -> u64 {
        let chip = self.registers.chip();
        effective_nvx(
            self.read(Register::HCR_EL2),
            Feature::FEAT_NV.on(chip),
            Feature::FEAT_NV2.on(chip),
        )
    }

    fn bank_sp(&mut self, which: Stack) -> &mut u64 {
        match which {
            Stack::Guarded(level) => &mut self.apple.guarded[level].sp,
            Stack::El0 | Stack::El1 | Stack::El2 => unreachable!("SP_ELx live in the file"),
        }
    }

    fn sp_register(which: Stack) -> Option<Register> {
        match which {
            Stack::El0 => Some(Register::SP_EL0),
            Stack::El1 => Some(Register::SP_EL1),
            Stack::El2 => Some(Register::SP_EL2),
            Stack::Guarded(_) => None,
        }
    }

    fn store_sp(&mut self, which: Stack, value: u64) {
        match Self::sp_register(which) {
            Some(register) => self.registers.set_raw(register, 0, value),
            None => *self.bank_sp(which) = value,
        }
    }

    fn load_sp(&mut self, which: Stack) -> u64 {
        match Self::sp_register(which) {
            Some(register) => self.registers.get(register, 0),
            None => *self.bank_sp(which),
        }
    }

    /// Switch PSTATE, moving the current stack pointer to its bank and
    /// loading the newly selected one.
    pub fn set_pstate(&mut self, next: Pstate) {
        let (was, will) = (stack(self.pstate), stack(next));
        if was != will {
            let current = self.state.sp;
            self.store_sp(was, current);
            self.state.sp = self.load_sp(will);
        }
        self.pstate = next;
    }

    /// A banked stack pointer, current or not.
    pub fn sp(&self, el: u8) -> u64 {
        let which = match el {
            0 => Stack::El0,
            1 => Stack::El1,
            _ => Stack::El2,
        };
        if stack(self.pstate) == which {
            self.state.sp
        } else {
            Self::sp_register(which).map_or(0, |register| self.registers.get(register, 0))
        }
    }

    pub fn set_sp(&mut self, el: u8, value: u64) {
        let which = match el {
            0 => Stack::El0,
            1 => Stack::El1,
            _ => Stack::El2,
        };
        if stack(self.pstate) == which {
            self.state.sp = value;
        } else {
            self.store_sp(which, value);
        }
    }

    /// HCR_EL2.TGE: EL0 runs in the EL2&0 host regime.
    pub fn in_host(&self) -> bool {
        self.hcr(HCR_TGE)
    }

    /// The regime the current PSTATE translates in.
    pub fn regime(&self) -> TranslationRegime {
        if self.pstate.el == 2 || (self.pstate.el == 0 && self.in_host()) {
            TranslationRegime::El20
        } else {
            TranslationRegime::El10
        }
    }

    /// Translation controls of a regime: its stage-1 registers and, for
    /// EL1&0, the stage-2 registers that `mmu` applies under HCR_EL2.VM or DC.
    pub fn controls(&self, regime: TranslationRegime) -> Controls {
        let (sctlr, tcr, ttbr0, ttbr1, mair, kernel, user) = match regime {
            TranslationRegime::El10 => (
                Register::SCTLR_EL1,
                Register::TCR_EL1,
                Register::TTBR0_EL1,
                Register::TTBR1_EL1,
                Register::MAIR_EL1,
                PERM_EL1,
                PERM_EL0_10,
            ),
            TranslationRegime::El20 => (
                Register::SCTLR_EL2,
                Register::TCR_EL2,
                Register::TTBR0_EL2,
                Register::TTBR1_EL2,
                Register::MAIR_EL2,
                PERM_EL2,
                PERM_EL0_20,
            ),
        };
        Controls {
            sctlr: self.read(sctlr),
            tcr: self.read(tcr),
            ttbr0: self.read(ttbr0),
            ttbr1: self.read(ttbr1),
            mair: self.read(mair),
            xs: Feature::FEAT_XS.on(self.registers.chip()),
            sprr: Sprr {
                config: self.apple.sprr_config,
                el1: self.apple.sprr_perm[kernel],
                el0: self.apple.sprr_perm[user],
                fields: self.apple.sprr_fields,
            },
            stage2: self.stage2(regime),
            second_stage: (regime == TranslationRegime::El10).then(|| mmu::Stage2 {
                hcr: self.read(Register::HCR_EL2),
                vtcr: self.read(Register::VTCR_EL2),
                vttbr: self.read(Register::VTTBR_EL2),
                xs: Feature::FEAT_XS.on(self.registers.chip()),
            }),
            regime: match regime {
                TranslationRegime::El10 => mmu::Regime::El10,
                TranslationRegime::El20 => mmu::Regime::El20,
            },
        }
    }

    /// Whether the EL1&0 regime translates through stage 2.
    pub fn stage2(&self, regime: TranslationRegime) -> bool {
        regime == TranslationRegime::El10 && self.hcr(HCR_VM)
    }

    /// GXF is usable when both SPRR and GXF are enabled (m1n1 `gxf.c`
    /// `gxf_enabled`).
    pub fn guarded_enabled(&self) -> bool {
        self.apple.sprr_config & mmu::SPRR_CONFIG_EN != 0
            && self.apple.gxf_config & GXF_CONFIG_EN != 0
    }

    /// GENTER at EL1 or EL2: bank the return state in that GL's registers and
    /// continue at GXF_ENTER_ELx on the GL stack with every exception masked.
    /// Masking follows exception entry; it is an inference, as is the stack
    /// selection (m1n1 sets `sp` after GENTER).
    pub fn guarded_enter(&mut self) -> Result<(), GuardedRefusal> {
        if self.pstate.el == 0 || self.pstate.guarded || !self.guarded_enabled() {
            return Err(GuardedRefusal::Enter);
        }
        // GENTER completes, returning to the next instruction, so the saved
        // state and the guarded level both start with BTYPE clear.
        let from = Pstate {
            btype: 0,
            ..self.pstate
        };
        let level = usize::from(from.el) - 1;
        let spsr = from.to_spsr(self.state.nzcv);
        let bank = &mut self.apple.guarded[level];
        bank.spsr = spsr;
        bank.elr = self.pc.wrapping_add(4);
        bank.aspsr = 0;
        let enter = bank.enter;
        self.set_pstate(Pstate {
            sp: true,
            daif: exception::DAIF_ALL,
            guarded: true,
            ..from
        });
        self.pc = enter;
        Ok(())
    }

    /// GEXIT at the guarded level: restore PSTATE from SPSR_GLx and continue
    /// at ELR_GLx, at the guarded level when ASPSR_GLx says so.
    pub fn guarded_exit(&mut self) -> Result<Result<(), IllegalReturn>, GuardedRefusal> {
        if !self.pstate.guarded {
            return Err(GuardedRefusal::Exit);
        }
        let level = usize::from(self.pstate.el) - 1;
        let bank = &self.apple.guarded[level];
        let (spsr, elr, aspsr) = (bank.spsr, bank.elr, bank.aspsr);
        if let Some(illegal) = self.illegal_return(spsr) {
            return Ok(Err(illegal));
        }
        let (mut next, nzcv) = exception::restore(self.pstate, spsr, false);
        next.guarded = aspsr & ASPSR_GUARDED != 0;
        if next.guarded && next.el != self.pstate.el {
            return Ok(Err(IllegalReturn::Mode(0)));
        }
        self.state.nzcv = nzcv;
        self.set_pstate(next);
        self.pc = elr;
        Ok(Ok(()))
    }

    pub fn requester(&self) -> mmu::Requester {
        mmu::Requester {
            el: self.pstate.el,
            pan: self.pstate.pan,
            unprivileged: false,
            guarded: self.pstate.guarded,
        }
    }

    /// The EL an exception targeting EL1 by default is taken to.
    pub fn route(&self) -> u8 {
        match self.pstate.el {
            2 => 2,
            0 if self.in_host() => 2,
            _ => 1,
        }
    }

    /// The EL a physical interrupt is routed to (Arm
    /// `AArch64_TakePhysicalIRQException` and FIQ): EL2 from EL2, or from EL0
    /// and EL1 with HCR_EL2.TGE or the IMO/FMO routing bit.
    pub fn interrupt_target(&self, vector: Vector) -> u8 {
        let routing = match vector {
            Vector::Irq => HCR_IMO,
            Vector::Fiq => HCR_FMO,
            _ => HCR_AMO,
        };
        if self.pstate.el == 2 || self.in_host() || self.hcr(routing) {
            2
        } else {
            1
        }
    }

    /// Take an exception and continue at its vector. At the guarded level it
    /// stays there, through VBAR_GLx and the GL bank.
    pub fn take(&mut self, exception: Exception) {
        let from = self.pstate;
        let target = exception.target.unwrap_or_else(|| self.route());
        if from.guarded && target == from.el {
            let level = usize::from(from.el) - 1;
            let spsr = from.to_spsr(self.state.nzcv);
            let bank = &mut self.apple.guarded[level];
            bank.spsr = spsr;
            bank.elr = exception.return_address;
            bank.aspsr = ASPSR_GUARDED;
            if exception.vector == Vector::Synchronous {
                bank.esr = exception.syndrome;
            }
            if let Some(address) = exception.fault_address {
                bank.far = address;
            }
            let vbar = bank.vbar;
            let sctlr = self.read(bank_sctlr(from.el));
            let entry = exception::entry_pstate(from, sctlr, from.el, self.in_host());
            self.set_pstate(Pstate {
                guarded: true,
                ..entry
            });
            self.pc = vbar.wrapping_add(exception::vector_offset(from, target, exception.vector));
            return;
        }
        let bank = bank(target);
        let mut spsr = from.to_spsr(self.state.nzcv);
        // From EL1 to EL1 under HCR_EL2.NV (with NV1 RAZ, NVx 'x01'),
        // SPSR_EL1.M[3:2] records EL2, the level the guest hypervisor
        // believes it runs at (Arm `AArch64_TakeException`).
        if from.el == 1 && target == 1 && self.nested() & 0b011 == 0b001 {
            spsr = spsr & !0b1100 | 0b1000;
        }
        self.registers.set_raw(bank.spsr, 0, spsr);
        self.registers
            .set_raw(bank.elr, 0, exception.return_address);
        if exception.vector == Vector::Synchronous || exception.vector == Vector::SError {
            self.registers.set_raw(bank.esr, 0, exception.syndrome);
        }
        if let Some(address) = exception.fault_address {
            self.registers.set_raw(bank.far, 0, address);
        }
        let sctlr = self.read(bank.sctlr);
        self.set_pstate(Pstate {
            guarded: false,
            ..exception::entry_pstate(from, sctlr, target, self.in_host())
        });
        let vbar = self.read(bank.vbar) & !0x7ff;
        self.pc = vbar.wrapping_add(exception::vector_offset(from, target, exception.vector));
    }

    /// Why a return from the current EL to `spsr` is illegal, if it is
    /// (Arm `IllegalExceptionReturn`): an invalid or AArch32 mode, a higher
    /// EL, or EL1 while HCR_EL2.TGE is set.
    pub fn illegal_return(&self, spsr: u64) -> Option<IllegalReturn> {
        match exception::spsr_target(spsr) {
            Err(illegal) => Some(illegal),
            Ok((el, _)) if el > self.pstate.el => Some(IllegalReturn::Mode(el << 2)),
            Ok((1, _)) if self.hcr(HCR_TGE) => Some(IllegalReturn::Host),
            Ok(_) => None,
        }
    }

    /// ELR_ELx of the current EL.
    pub fn exception_link(&self) -> u64 {
        self.read(bank(self.pstate.el).elr)
    }

    /// An instruction address with its tag removed for the current EL (Arm
    /// `AArch64_BranchAddr`): with TBI and not TBID for the half that bit 55
    /// selects, bits 63:56 copy bit 55. Every EL here uses two VA ranges
    /// (EL1&0, or EL2&0 because HCR_EL2.E2H is RES1), so the address is sign
    /// extended.
    pub fn branch_address(&self, address: u64) -> u64 {
        let tcr = self.controls(self.regime()).tcr;
        let (tbi, tbid) = if address & (1 << 55) != 0 {
            (38, 52)
        } else {
            (37, 51)
        };
        if tcr & (1 << tbi) != 0 && tcr & (1 << tbid) == 0 {
            exception::sign_extend_55(address)
        } else {
            address
        }
    }

    /// ERET, ERETAA or ERETAB from EL1 or EL2 to `target`, the current ELR
    /// after any authentication (Arm `AArch64_ExceptionReturn`). An illegal
    /// return sets PSTATE.IL instead of changing EL; after one to AArch32 the
    /// ARBITRARY PC bits 63:32 and 1:0 read 0. EL0 ERET is UNDEFINED and must
    /// not reach here.
    pub fn exception_return(&mut self, target: u64) {
        let spsr = self.read(bank(self.pstate.el).spsr);
        let illegal = self.illegal_return(spsr).is_some();
        let destination = match exception::spsr_target(spsr) {
            Ok((el, _)) if !illegal => el,
            _ => self.pstate.el,
        };
        let ss = super::debug::return_ss(self, spsr, destination);
        let (mut next, nzcv) = exception::restore(self.pstate, spsr, illegal);
        next.ss = ss;
        self.step_advance = false;
        self.state.nzcv = nzcv;
        self.set_pstate(next);
        self.pc = if illegal && spsr & (1 << 4) != 0 {
            target & 0xffff_fffc
        } else {
            self.branch_address(target)
        };
        // ERET clears the local exclusive monitor and sets the event register.
        self.monitor = None;
        self.event = true;
    }
}

fn bank_sctlr(el: u8) -> Register {
    bank(el).sctlr
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::exception::{DAIF_ALL, DAIF_I};

    const HCR_E2H_TGE: u64 = 1 << 34 | 1 << 27;

    #[test]
    fn exception_entry_and_return_bank_stack_pointers() {
        let user = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ..Pstate::reset(1)
        };
        let mut cpu = Cpu::new(0x4000, user);
        cpu.state.sp = 0x7000;
        cpu.state.nzcv = 0x6000_0000;
        cpu.registers.set_raw(Register::SP_EL1, 0, 0xffff_0000);
        cpu.registers.set(Register::VBAR_EL1, 0, 0xffff_8000);
        cpu.take(Exception::synchronous(Class::SupervisorCall, 7, 0x4004));
        assert_eq!(cpu.pc, 0xffff_8400);
        assert_eq!(cpu.state.sp, 0xffff_0000);
        assert_eq!(cpu.sp(0), 0x7000);
        assert_eq!(cpu.read(Register::ELR_EL1), 0x4004);
        assert_eq!(cpu.read(Register::SPSR_EL1), 0x6000_0000);
        assert_eq!(cpu.read(Register::ESR_EL1), 0x5600_0007);
        assert_eq!(cpu.pstate.daif, DAIF_ALL);
        assert!(cpu.pstate.pan);
        cpu.state.sp = 0xffff_0100;
        cpu.registers.set(Register::SPSR_EL1, 0, DAIF_I as u64 * 64); // EL0t with IRQs masked
        cpu.exception_return(cpu.exception_link());
        assert_eq!(
            (cpu.pc, cpu.state.sp, cpu.sp(1)),
            (0x4004, 0x7000, 0xffff_0100)
        );
        assert_eq!(cpu.pstate.el, 0);
        assert_eq!(cpu.pstate.daif, DAIF_I);
        assert_eq!(cpu.state.nzcv, 0);
    }

    #[test]
    fn interrupts_from_el1h_use_the_current_el_spx_group() {
        let mut cpu = Cpu::new(0x8000, Pstate::reset(1));
        cpu.registers.set(Register::VBAR_EL1, 0, 0x1_0000);
        cpu.registers.set(Register::ESR_EL1, 0, 0x1234);
        cpu.take(Exception {
            vector: Vector::Fiq,
            syndrome: 0,
            fault_address: None,
            return_address: 0x8000,
            target: Some(1),
        });
        assert_eq!(cpu.pc, 0x1_0300);
        assert_eq!(
            cpu.read(Register::ESR_EL1),
            0x1234,
            "interrupts leave ESR unchanged"
        );
    }

    #[test]
    fn routing_follows_tge_and_el2_uses_its_own_registers() {
        let mut cpu = Cpu::new(0x8000, Pstate::reset(2));
        cpu.registers.set(Register::HCR_EL2, 0, HCR_E2H_TGE);
        cpu.registers.set(Register::VBAR_EL2, 0, 0x1_0000);
        cpu.state.sp = 0xa000;
        cpu.take(Exception::synchronous(Class::HypervisorCall, 3, 0x8004).to(2));
        assert_eq!((cpu.pc, cpu.pstate.el), (0x1_0200, 2));
        assert_eq!(cpu.read(Register::SPSR_EL2) & 0xf, 0b1001, "EL2h");
        assert_eq!(cpu.read(Register::ESR_EL2), 0x5a00_0003);
        cpu.exception_return(cpu.exception_link());
        assert_eq!((cpu.pc, cpu.pstate.el), (0x8004, 2));
        // EL0 in the host: exceptions go to EL2.
        cpu.registers.set(Register::SPSR_EL2, 0, 0);
        cpu.exception_return(cpu.exception_link());
        assert_eq!((cpu.pstate.el, cpu.regime()), (0, TranslationRegime::El20));
        cpu.take(Exception::synchronous(Class::SupervisorCall, 0, 0x8008));
        assert_eq!((cpu.pc, cpu.pstate.el), (0x1_0400, 2));
        // A return to EL1 under TGE is illegal: EL2 stays and sets IL.
        cpu.registers.set(Register::SPSR_EL2, 0, 0b0101);
        assert_eq!(cpu.illegal_return(0b0101), Some(IllegalReturn::Host));
        cpu.exception_return(0x9000);
        assert_eq!((cpu.pc, cpu.pstate.el, cpu.pstate.il), (0x9000, 2, true));
        // Without TGE it enters a guest.
        cpu.registers.set(Register::HCR_EL2, 0, 0);
        cpu.exception_return(cpu.exception_link());
        assert!(!cpu.pstate.il);
        assert_eq!((cpu.pstate.el, cpu.regime()), (1, TranslationRegime::El10));
        assert_eq!(cpu.route(), 1);
        assert_eq!(cpu.interrupt_target(Vector::Irq), 1);
        cpu.registers.set(Register::HCR_EL2, 0, 1 << HCR_IMO);
        assert_eq!(cpu.interrupt_target(Vector::Irq), 2);
    }
}
