//! AArch64 PSTATE, SPSR and exception vectors for EL0, EL1 and EL2. Sources:
//! Arm ARM DDI0487 (June 2026) D1.3 (exception entry), D1.4 (exception return,
//! illegal returns), D17.2.37 (ESR_ELx) and C5.2 (SPSR and PSTATE fields), and
//! Arm `AArch64_TakeException`, `ELFromSPSR` and `SetPSTATEFromPSR`.

/// The parts of PSTATE the engine owns outside `GuestState` (which holds NZCV
/// and the current SP value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pstate {
    pub el: u8,
    /// SPSel: true selects SP_ELx at EL1 and EL2.
    pub sp: bool,
    /// D, A, I, F as SPSR bits 9:6 (D=bit 3 of this value).
    pub daif: u8,
    pub pan: bool,
    pub uao: bool,
    pub dit: bool,
    pub ssbs: bool,
    pub tco: bool,
    /// The Illegal Execution state bit: the next instruction takes EC 0x0E.
    pub il: bool,
    /// FEAT_BTI's branch type, which the next instruction is checked against
    /// in a guarded page.
    pub btype: u8,
    /// The software step bit: set while the step state machine is
    /// active-not-pending (`machine::debug::Step`).
    pub ss: bool,
    /// FEAT_PAuth_LR's PAC modifier: set by PACM, it makes the next
    /// instruction's PAC*SP, AUT*SP, RETA* or *1716 form take a second
    /// modifier.
    pub pacm: bool,
    /// Apple GXF: executing at the guarded level beside `el` (GL1 or GL2).
    /// SPSR does not encode it; the GL bank's ASPSR does.
    pub guarded: bool,
}

pub const DAIF_D: u8 = 8;
pub const DAIF_A: u8 = 4;
pub const DAIF_I: u8 = 2;
pub const DAIF_F: u8 = 1;
pub const DAIF_ALL: u8 = 15;

const SPSR_M_AARCH32: u64 = 1 << 4;
const SPSR_DAIF_SHIFT: u32 = 6;
const SPSR_PAN: u64 = 1 << 22;
const SPSR_UAO: u64 = 1 << 23;
const SPSR_DIT: u64 = 1 << 24;
const SPSR_TCO: u64 = 1 << 25;
const SPSR_SSBS: u64 = 1 << 12;
const SPSR_IL: u64 = 1 << 20;
const SPSR_BTYPE_SHIFT: u32 = 10;
const SPSR_SS: u64 = 1 << 21;
const SPSR_PACM: u64 = 1 << 35;
const NZCV_MASK: u64 = 0xf000_0000;

impl Pstate {
    /// The reset state at `el`h with every exception masked.
    pub const fn reset(el: u8) -> Self {
        Self {
            el,
            sp: true,
            daif: DAIF_ALL,
            pan: false,
            uao: false,
            dit: false,
            ssbs: false,
            tco: false,
            il: false,
            btype: 0,
            ss: false,
            pacm: false,
            guarded: false,
        }
    }

    /// SPSR_ELx for an exception taken from this state.
    pub fn to_spsr(self, nzcv: u32) -> u64 {
        let mode = (u64::from(self.el) << 2) | u64::from(self.el != 0 && self.sp);
        (u64::from(nzcv) & NZCV_MASK)
            | mode
            | (u64::from(self.daif) << SPSR_DAIF_SHIFT)
            | if self.pan { SPSR_PAN } else { 0 }
            | if self.uao { SPSR_UAO } else { 0 }
            | if self.dit { SPSR_DIT } else { 0 }
            | if self.tco { SPSR_TCO } else { 0 }
            | if self.ssbs { SPSR_SSBS } else { 0 }
            | if self.il { SPSR_IL } else { 0 }
            | u64::from(self.btype) << SPSR_BTYPE_SHIFT
            | if self.ss { SPSR_SS } else { 0 }
            | if self.pacm { SPSR_PACM } else { 0 }
    }
}

/// Why an exception return is illegal (Arm `IllegalExceptionReturn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IllegalReturn {
    /// SPSR.M names AArch32, which this CPU profile does not implement.
    Aarch32,
    /// SPSR.M names EL3, an EL above the current one, or a reserved mode.
    Mode(u8),
    /// A return to EL1 while HCR_EL2.TGE is set.
    Host,
}

/// The AArch64 EL and SPSel an SPSR names, if this PE implements them (Arm
/// `ELFromSPSR`): not AArch32, not EL3, M[1] clear, and M[0] clear for EL0.
pub fn spsr_target(spsr: u64) -> Result<(u8, bool), IllegalReturn> {
    if spsr & SPSR_M_AARCH32 != 0 {
        return Err(IllegalReturn::Aarch32);
    }
    let mode = (spsr & 0xf) as u8;
    let (el, sp) = (mode >> 2, mode & 1 != 0);
    if mode & 0b10 != 0 || el > 2 || (el == 0 && sp) {
        return Err(IllegalReturn::Mode(mode));
    }
    Ok((el, sp))
}

/// PSTATE and NZCV after an exception return to `spsr` from `current` (Arm
/// `SetPSTATEFromPSR`). A legal return restores EL, SPSel, IL, UAO, DIT,
/// SSBS, BTYPE and PACM. An illegal one keeps EL and SPSel and sets IL; UAO,
/// DIT, SSBS, BTYPE and PACM are then ARBITRARY and Stela takes them from
/// SPSR. Both restore NZCV, PAN and DAIF. PSTATE.SS is 0 here: the caller
/// sets it (Arm `DebugExceptionReturnSS`, `machine::debug::return_ss`), and
/// the caller clears PACM where IsPACMEnabled is false at the new EL. TCO is
/// untouched because the profile has no MTE.
pub fn restore(current: Pstate, spsr: u64, illegal: bool) -> (Pstate, u32) {
    let (el, sp, il) = match spsr_target(spsr) {
        Ok((el, sp)) if !illegal => (el, sp, spsr & SPSR_IL != 0),
        _ => (current.el, current.sp, true),
    };
    (
        Pstate {
            el,
            sp,
            daif: ((spsr >> SPSR_DAIF_SHIFT) & 15) as u8,
            pan: spsr & SPSR_PAN != 0,
            uao: spsr & SPSR_UAO != 0,
            dit: spsr & SPSR_DIT != 0,
            ssbs: spsr & SPSR_SSBS != 0,
            tco: current.tco,
            il,
            btype: ((spsr >> SPSR_BTYPE_SHIFT) & 3) as u8,
            ss: false,
            pacm: spsr & SPSR_PACM != 0,
            guarded: illegal && current.guarded,
        },
        (spsr & NZCV_MASK) as u32,
    )
}

/// Bits 63:56 replaced by bit 55.
pub fn sign_extend_55(address: u64) -> u64 {
    (((address << 8) as i64) >> 8) as u64
}

/// Exception classes the engine raises (ESR_ELx.EC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    Unknown = 0x00,
    WaitTrap = 0x01,
    FloatingPointAccess = 0x07,
    PointerAuthenticationTrap = 0x09,
    BranchTarget = 0x0d,
    IllegalExecution = 0x0e,
    SupervisorCall = 0x15,
    HypervisorCall = 0x16,
    MonitorCall = 0x17,
    SystemRegister = 0x18,
    ExceptionReturnTrap = 0x1a,
    PointerAuthenticationFailure = 0x1c,
    InstructionAbortLower = 0x20,
    InstructionAbortSame = 0x21,
    PcAlignment = 0x22,
    DataAbortLower = 0x24,
    DataAbortSame = 0x25,
    SpAlignment = 0x26,
    SError = 0x2f,
    /// Breakpoint, software step and watchpoint exceptions from a lower EL;
    /// the same EL's class is one more.
    BreakpointLower = 0x30,
    BreakpointSame = 0x31,
    StepLower = 0x32,
    StepSame = 0x33,
    WatchpointLower = 0x34,
    WatchpointSame = 0x35,
    /// BRK.
    Breakpoint = 0x3c,
    /// Apple's implementation-defined class (XNU "private exception"); its
    /// ISS selects the cause, as for AMX use while disabled (`machine::amx`).
    ImplementationDefined = 0x3f,
}

/// The kind of vector an exception uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vector {
    Synchronous = 0x000,
    Irq = 0x080,
    Fiq = 0x100,
    SError = 0x180,
}

const IL: u32 = 1 << 25;

/// ESR_ELx for a synchronous exception from a 32-bit instruction, or an
/// SError: IL is always set for AArch64 (Arm `AArch64_ExceptionClass`).
pub fn syndrome(class: Class, iss: u32) -> u64 {
    u64::from(((class as u32) << 26) | IL | (iss & 0x01ff_ffff))
}

/// ISS for a data abort without instruction syndrome (ISV=0). WnR marks a
/// write; FnV stays clear because FAR is always valid here.
pub fn data_abort_iss(status: u32, write: bool) -> u32 {
    status | if write { 1 << 6 } else { 0 }
}

/// The vector offset from the target EL's VBAR for an exception taken from
/// `from`: a lower AArch64 EL, or the current EL with SP_EL0 or SP_ELx.
pub fn vector_offset(from: Pstate, target: u8, vector: Vector) -> u64 {
    let group = if target > from.el {
        0x400
    } else if from.sp {
        0x200
    } else {
        0x000
    };
    group + vector as u64
}

const SCTLR_SPAN: u64 = 1 << 23;
const SCTLR_DSSBS: u64 = 1 << 44;

/// PSTATE after taking an exception to `target` (Arm
/// `AArch64_TakeException`): IL, UAO, BTYPE and PACM clear, the target's SCTLR.SPAN clear sets PAN at EL1,
/// and at EL2 while EL0 runs in the host (HCR_EL2.TGE); DSSBS gives SSBS.
/// TCO is untouched because the profile has no MTE. An exception taken at
/// the guarded level stays there (m1n1 `gxf_asm.S` handles GL exceptions at
/// VBAR_GLx and returns with GEXIT); the caller keeps `guarded`.
pub fn entry_pstate(from: Pstate, sctlr: u64, target: u8, in_host: bool) -> Pstate {
    let span = sctlr & SCTLR_SPAN == 0 && (target == 1 || in_host);
    Pstate {
        el: target,
        sp: true,
        daif: DAIF_ALL,
        pan: from.pan || span,
        uao: false,
        dit: from.dit,
        ssbs: sctlr & SCTLR_DSSBS != 0,
        tco: from.tco,
        il: false,
        btype: 0,
        ss: false,
        pacm: false,
        guarded: from.guarded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsr_round_trips_every_legal_aarch64_mode() {
        for (el, sp) in [(0, false), (1, false), (1, true), (2, false), (2, true)] {
            for daif in 0..=15 {
                let state = Pstate {
                    el,
                    sp,
                    daif,
                    pan: daif & 1 != 0,
                    uao: daif & 8 != 0,
                    dit: daif & 2 != 0,
                    ssbs: daif & 4 != 0,
                    il: daif == 5,
                    btype: daif & 3,
                    pacm: daif & 8 == 0,
                    ..Pstate::reset(2)
                };
                let spsr = state.to_spsr(0xa000_0000);
                assert_eq!(restore(Pstate::reset(2), spsr, false), (state, 0xa000_0000));
            }
        }
        assert_eq!(Pstate::reset(1).to_spsr(0), 0x3c5);
        assert_eq!(spsr_target(0x3c9), Ok((2, true)));
        assert_eq!(spsr_target(0x3cd), Err(IllegalReturn::Mode(0xd)));
        assert_eq!(spsr_target(0x3c6), Err(IllegalReturn::Mode(6)));
        assert_eq!(spsr_target(0x3c1), Err(IllegalReturn::Mode(1)), "EL0h");
        assert_eq!(spsr_target(0x10), Err(IllegalReturn::Aarch32));
    }

    #[test]
    fn an_illegal_return_keeps_the_el_and_sets_il() {
        let current = Pstate {
            el: 1,
            sp: false,
            ..Pstate::reset(1)
        };
        // To EL2h with D, PAN and NZCV set: only the always-restored fields
        // change.
        let spsr = 0x6000_0000 | SPSR_PAN | 0x209;
        let (next, nzcv) = restore(current, spsr, true);
        assert_eq!((next.el, next.sp, next.il), (1, false, true));
        assert_eq!((next.daif, next.pan, nzcv), (DAIF_D, true, 0x6000_0000));
        // An invalid mode is illegal whatever the caller decided.
        assert!(restore(current, 0x10, false).0.il);
        assert!(!entry_pstate(next, 0, 1, false).il);
        assert_eq!(next.to_spsr(0) & SPSR_IL, SPSR_IL);
    }

    #[test]
    fn vectors_syndromes_and_entry_state() {
        let user = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ..Pstate::reset(1)
        };
        assert_eq!(vector_offset(user, 1, Vector::Synchronous), 0x400);
        assert_eq!(vector_offset(user, 2, Vector::Irq), 0x480);
        assert_eq!(vector_offset(Pstate::reset(1), 1, Vector::Fiq), 0x300);
        assert_eq!(vector_offset(Pstate::reset(1), 2, Vector::Fiq), 0x500);
        let el1t = Pstate {
            sp: false,
            ..Pstate::reset(1)
        };
        assert_eq!(vector_offset(el1t, 1, Vector::Irq), 0x080);
        assert_eq!(syndrome(Class::SupervisorCall, 0x1234), 0x5600_1234);
        assert_eq!(syndrome(Class::SError, 0x1_0000), 0xbe01_0000);
        assert_eq!(
            syndrome(Class::DataAbortSame, data_abort_iss(0b000111, true)),
            0x9600_0047
        );
        let entered = entry_pstate(user, 0, 1, false);
        assert!(entered.pan && entered.sp && entered.el == 1);
        assert_eq!(entered.daif, DAIF_ALL);
        assert!(!entered.ssbs);
        let entered = entry_pstate(user, SCTLR_SPAN | SCTLR_DSSBS, 1, false);
        assert!(!entered.pan && entered.ssbs);
        // At EL2, SPAN only applies while EL0 is in the host.
        assert!(!entry_pstate(user, 0, 2, false).pan);
        assert!(entry_pstate(user, 0, 2, true).pan);
        // BTYPE is saved in SPSR and clear in the handler.
        let branched = Pstate {
            btype: 0b10,
            ..user
        };
        assert_eq!((branched.to_spsr(0) >> 10) & 3, 0b10);
        assert_eq!(entry_pstate(branched, 0, 1, false).btype, 0);
    }
}
