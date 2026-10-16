//! AArch64 exception entry and return with EL1 as the only exception level
//! above EL0. Sources: Arm ARM DDI0487 (June 2026) D1.3 (exception entry),
//! D1.4 (exception return, illegal returns), D17.2.37 (ESR_ELx) and C5.2 (SPSR
//! and PSTATE fields).

/// The parts of PSTATE the engine owns outside `GuestState` (which holds NZCV
/// and the current SP value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pstate {
    pub el: u8,
    /// SPSel: at EL1, true selects SP_EL1.
    pub sp_el1: bool,
    /// D, A, I, F as SPSR bits 9:6 (D=bit 3 of this value).
    pub daif: u8,
    pub pan: bool,
    pub uao: bool,
    pub dit: bool,
    pub ssbs: bool,
    pub tco: bool,
    /// Apple GXF: executing at the guarded level beside `el` (GL1). SPSR
    /// does not encode it; the GL bank's ASPSR does.
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
const SPSR_SS: u64 = 1 << 21;
const NZCV_MASK: u64 = 0xf000_0000;

impl Pstate {
    /// The reset state at EL1h with every exception masked.
    pub const RESET_EL1: Self = Self {
        el: 1,
        sp_el1: true,
        daif: DAIF_ALL,
        pan: false,
        uao: false,
        dit: false,
        ssbs: false,
        tco: false,
        guarded: false,
    };

    /// SPSR_EL1 for an exception taken from this state.
    pub fn to_spsr(self, nzcv: u32) -> u64 {
        let mode = (u64::from(self.el) << 2) | u64::from(self.el != 0 && self.sp_el1);
        (u64::from(nzcv) & NZCV_MASK)
            | mode
            | (u64::from(self.daif) << SPSR_DAIF_SHIFT)
            | if self.pan { SPSR_PAN } else { 0 }
            | if self.uao { SPSR_UAO } else { 0 }
            | if self.dit { SPSR_DIT } else { 0 }
            | if self.tco { SPSR_TCO } else { 0 }
            | if self.ssbs { SPSR_SSBS } else { 0 }
    }
}

/// Why an ERET cannot restore the saved state on this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IllegalReturn {
    /// SPSR.M names AArch32, which this CPU profile does not implement.
    Aarch32,
    /// SPSR.M names EL2 or EL3, which do not exist, or an invalid mode.
    Mode(u8),
    /// Software step or an illegal-state bit is set; debug state is absent.
    DebugState,
}

/// Decode SPSR_EL1 for ERET. Returns the new PSTATE and NZCV.
pub fn from_spsr(spsr: u64) -> Result<(Pstate, u32), IllegalReturn> {
    if spsr & SPSR_M_AARCH32 != 0 {
        return Err(IllegalReturn::Aarch32);
    }
    let mode = (spsr & 0xf) as u8;
    let (el, sp_el1) = match mode {
        0b0000 => (0, false),
        0b0100 => (1, false),
        0b0101 => (1, true),
        _ => return Err(IllegalReturn::Mode(mode)),
    };
    if spsr & (SPSR_IL | SPSR_SS) != 0 {
        return Err(IllegalReturn::DebugState);
    }
    Ok((
        Pstate {
            el,
            sp_el1,
            daif: ((spsr >> SPSR_DAIF_SHIFT) & 15) as u8,
            pan: spsr & SPSR_PAN != 0,
            uao: spsr & SPSR_UAO != 0,
            dit: spsr & SPSR_DIT != 0,
            ssbs: spsr & SPSR_SSBS != 0,
            tco: spsr & SPSR_TCO != 0,
            guarded: false,
        },
        (spsr & NZCV_MASK) as u32,
    ))
}

/// Exception classes the engine raises (ESR_ELx.EC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    Unknown = 0x00,
    WaitTrap = 0x01,
    FloatingPointAccess = 0x07,
    IllegalExecution = 0x0e,
    SupervisorCall = 0x15,
    SystemRegister = 0x18,
    InstructionAbortLower = 0x20,
    InstructionAbortSame = 0x21,
    PcAlignment = 0x22,
    DataAbortLower = 0x24,
    DataAbortSame = 0x25,
    SpAlignment = 0x26,
    Breakpoint = 0x3c,
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

/// ESR_EL1 for a synchronous exception from a 32-bit instruction.
pub fn syndrome(class: Class, iss: u32) -> u64 {
    u64::from(((class as u32) << 26) | IL | (iss & 0x01ff_ffff))
}

/// ISS for a data abort without instruction syndrome (ISV=0). WnR marks a
/// write; FnV stays clear because FAR is always valid here.
pub fn data_abort_iss(status: u32, write: bool) -> u32 {
    status | if write { 1 << 6 } else { 0 }
}

/// The vector offset from VBAR_EL1 for an exception taken from `from` to EL1.
pub fn vector_offset(from: Pstate, vector: Vector) -> u64 {
    let group = match (from.el, from.sp_el1) {
        (1, false) => 0x000,
        (1, true) => 0x200,
        _ => 0x400,
    };
    group + vector as u64
}

const SCTLR_SPAN: u64 = 1 << 23;
const SCTLR_DSSBS: u64 = 1 << 44;

/// PSTATE after taking an exception to EL1: SCTLR_EL1.SPAN clear sets PAN and
/// DSSBS gives SSBS. TCO is untouched because the profile has no MTE. An
/// exception taken at the guarded level stays there (m1n1 `gxf_asm.S` handles
/// GL exceptions at VBAR_GL1 and returns with GEXIT).
pub fn entry_pstate(from: Pstate, sctlr: u64) -> Pstate {
    Pstate {
        el: 1,
        sp_el1: true,
        daif: DAIF_ALL,
        pan: from.pan || sctlr & SCTLR_SPAN == 0,
        uao: false,
        dit: from.dit,
        ssbs: sctlr & SCTLR_DSSBS != 0,
        tco: from.tco,
        guarded: from.guarded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsr_round_trips_every_legal_aarch64_mode() {
        for (el, sp_el1) in [(0, false), (1, false), (1, true)] {
            for daif in 0..=15 {
                let state = Pstate {
                    el,
                    sp_el1,
                    daif,
                    pan: daif & 1 != 0,
                    uao: false,
                    dit: daif & 2 != 0,
                    ssbs: daif & 4 != 0,
                    tco: daif & 8 != 0,
                    guarded: false,
                };
                let spsr = state.to_spsr(0xa000_0000);
                assert_eq!(from_spsr(spsr), Ok((state, 0xa000_0000)));
            }
        }
        assert_eq!(Pstate::RESET_EL1.to_spsr(0), 0x3c5);
        assert_eq!(from_spsr(0x3c9), Err(IllegalReturn::Mode(9)));
        assert_eq!(from_spsr(0x10), Err(IllegalReturn::Aarch32));
        assert_eq!(from_spsr(SPSR_IL | 5), Err(IllegalReturn::DebugState));
    }

    #[test]
    fn vectors_syndromes_and_entry_state() {
        let user = Pstate {
            el: 0,
            sp_el1: false,
            daif: 0,
            ..Pstate::RESET_EL1
        };
        assert_eq!(vector_offset(user, Vector::Synchronous), 0x400);
        assert_eq!(vector_offset(Pstate::RESET_EL1, Vector::Fiq), 0x300);
        let el1t = Pstate {
            sp_el1: false,
            ..Pstate::RESET_EL1
        };
        assert_eq!(vector_offset(el1t, Vector::Irq), 0x080);
        assert_eq!(syndrome(Class::SupervisorCall, 0x1234), 0x5600_1234);
        assert_eq!(
            syndrome(Class::DataAbortSame, data_abort_iss(0b000111, true)),
            0x9600_0047
        );
        let entered = entry_pstate(user, 0);
        assert!(entered.pan && entered.sp_el1 && entered.el == 1);
        assert_eq!(entered.daif, DAIF_ALL);
        assert!(!entered.ssbs);
        let entered = entry_pstate(user, SCTLR_SPAN | SCTLR_DSSBS);
        assert!(!entered.pan && entered.ssbs);
    }
}
