//! MRS, MSR and MSR (immediate) over the engine's register file.
//!
//! Every encoding either has modeled behavior here or is refused with its
//! fields; nothing reads as an unimplemented zero. EL0 accesses follow the
//! Arm ARM DDI0487 (June 2026) D19 access tables for a PE without EL2/EL3:
//! registers EL0 may not reach are UNDEFINED, and the ones EL1 controls trap
//! with EC 0x18 when disabled.
use super::{
    cpu::Cpu,
    exception::{DAIF_ALL, Pstate},
    impdef,
};
use alloc::vec::Vec;
use stela_compiler::aarch64::system::registers::{Direction, Encoding, RegisterAccess};

/// Identification and fixed registers of one declared CPU profile. A register
/// without a value refuses: profile values need evidence.
#[derive(Debug, Clone)]
pub struct CpuProfile {
    pub name: &'static str,
    pub counter_frequency: u64,
    pub fixed: Vec<(Encoding, u64)>,
}

impl CpuProfile {
    fn fixed(&self, encoding: Encoding) -> Option<u64> {
        self.fixed
            .iter()
            .find(|(candidate, _)| *candidate == encoding)
            .map(|(_, value)| *value)
    }
}

/// Encodings named by the Arm ARM; Apple IMPDEF registers keep raw fields.
pub mod encodings {
    use super::Encoding;
    macro_rules! registers {
        ($($name:ident = $op0:literal, $op1:literal, $crn:literal, $crm:literal, $op2:literal;)*) => {
            $(pub const $name: Encoding = Encoding::new($op0, $op1, $crn, $crm, $op2);)*
        };
    }
    registers! {
        MIDR_EL1 = 3, 0, 0, 0, 0;
        MPIDR_EL1 = 3, 0, 0, 0, 5;
        REVIDR_EL1 = 3, 0, 0, 0, 6;
        ID_AA64PFR0_EL1 = 3, 0, 0, 4, 0;
        ID_AA64PFR1_EL1 = 3, 0, 0, 4, 1;
        ID_AA64ZFR0_EL1 = 3, 0, 0, 4, 4;
        ID_AA64SMFR0_EL1 = 3, 0, 0, 4, 5;
        ID_AA64DFR0_EL1 = 3, 0, 0, 5, 0;
        ID_AA64DFR1_EL1 = 3, 0, 0, 5, 1;
        ID_AA64AFR0_EL1 = 3, 0, 0, 5, 4;
        ID_AA64AFR1_EL1 = 3, 0, 0, 5, 5;
        ID_AA64ISAR0_EL1 = 3, 0, 0, 6, 0;
        ID_AA64ISAR1_EL1 = 3, 0, 0, 6, 1;
        ID_AA64ISAR2_EL1 = 3, 0, 0, 6, 2;
        ID_AA64MMFR0_EL1 = 3, 0, 0, 7, 0;
        ID_AA64MMFR1_EL1 = 3, 0, 0, 7, 1;
        ID_AA64MMFR2_EL1 = 3, 0, 0, 7, 2;
        CCSIDR_EL1 = 3, 1, 0, 0, 0;
        CLIDR_EL1 = 3, 1, 0, 0, 1;
        AIDR_EL1 = 3, 1, 0, 0, 7;
        CSSELR_EL1 = 3, 2, 0, 0, 0;
        CTR_EL0 = 3, 3, 0, 0, 1;
        DCZID_EL0 = 3, 3, 0, 0, 7;
        SCTLR_EL1 = 3, 0, 1, 0, 0;
        ACTLR_EL1 = 3, 0, 1, 0, 1;
        CPACR_EL1 = 3, 0, 1, 0, 2;
        TTBR0_EL1 = 3, 0, 2, 0, 0;
        TTBR1_EL1 = 3, 0, 2, 0, 1;
        TCR_EL1 = 3, 0, 2, 0, 2;
        APIAKEYLO_EL1 = 3, 0, 2, 1, 0;
        APIAKEYHI_EL1 = 3, 0, 2, 1, 1;
        APIBKEYLO_EL1 = 3, 0, 2, 1, 2;
        APIBKEYHI_EL1 = 3, 0, 2, 1, 3;
        APDAKEYLO_EL1 = 3, 0, 2, 2, 0;
        APDAKEYHI_EL1 = 3, 0, 2, 2, 1;
        APDBKEYLO_EL1 = 3, 0, 2, 2, 2;
        APDBKEYHI_EL1 = 3, 0, 2, 2, 3;
        APGAKEYLO_EL1 = 3, 0, 2, 3, 0;
        APGAKEYHI_EL1 = 3, 0, 2, 3, 1;
        SPSR_EL1 = 3, 0, 4, 0, 0;
        ELR_EL1 = 3, 0, 4, 0, 1;
        SP_EL0 = 3, 0, 4, 1, 0;
        SPSEL = 3, 0, 4, 2, 0;
        CURRENTEL = 3, 0, 4, 2, 2;
        PAN = 3, 0, 4, 2, 3;
        UAO = 3, 0, 4, 2, 4;
        NZCV = 3, 3, 4, 2, 0;
        DAIF = 3, 3, 4, 2, 1;
        DIT = 3, 3, 4, 2, 5;
        SSBS = 3, 3, 4, 2, 6;
        FPCR = 3, 3, 4, 4, 0;
        FPSR = 3, 3, 4, 4, 1;
        AFSR0_EL1 = 3, 0, 5, 1, 0;
        AFSR1_EL1 = 3, 0, 5, 1, 1;
        ESR_EL1 = 3, 0, 5, 2, 0;
        FAR_EL1 = 3, 0, 6, 0, 0;
        PAR_EL1 = 3, 0, 7, 4, 0;
        MAIR_EL1 = 3, 0, 10, 2, 0;
        AMAIR_EL1 = 3, 0, 10, 3, 0;
        VBAR_EL1 = 3, 0, 12, 0, 0;
        ISR_EL1 = 3, 0, 12, 1, 0;
        CONTEXTIDR_EL1 = 3, 0, 13, 0, 1;
        TPIDR_EL1 = 3, 0, 13, 0, 4;
        TPIDR_EL0 = 3, 3, 13, 0, 2;
        TPIDRRO_EL0 = 3, 3, 13, 0, 3;
        CNTKCTL_EL1 = 3, 0, 14, 1, 0;
        CNTFRQ_EL0 = 3, 3, 14, 0, 0;
        CNTPCT_EL0 = 3, 3, 14, 0, 1;
        CNTVCT_EL0 = 3, 3, 14, 0, 2;
        CNTPCTSS_EL0 = 3, 3, 14, 0, 5;
        CNTVCTSS_EL0 = 3, 3, 14, 0, 6;
        CNTP_TVAL_EL0 = 3, 3, 14, 2, 0;
        CNTP_CTL_EL0 = 3, 3, 14, 2, 1;
        CNTP_CVAL_EL0 = 3, 3, 14, 2, 2;
        CNTV_TVAL_EL0 = 3, 3, 14, 3, 0;
        CNTV_CTL_EL0 = 3, 3, 14, 3, 1;
        CNTV_CVAL_EL0 = 3, 3, 14, 3, 2;
        MDCCINT_EL1 = 2, 0, 0, 2, 0;
        MDSCR_EL1 = 2, 0, 0, 2, 2;
        OSLAR_EL1 = 2, 0, 1, 0, 4;
        OSLSR_EL1 = 2, 0, 1, 1, 4;
        OSDLR_EL1 = 2, 0, 1, 3, 4;
        // Apple SPRR and GXF (m1n1 `cpu_regs.h`; Asahi "SPRR and GXF").
        SPRR_CONFIG_EL1 = 3, 6, 15, 1, 0;
        GXF_CONFIG_EL1 = 3, 6, 15, 1, 2;
        SPRR_PERM_EL0 = 3, 6, 15, 1, 5;
        SPRR_PERM_EL1 = 3, 6, 15, 1, 6;
        SPRR_PERM_EL12 = 3, 6, 15, 15, 7;
        SPRR_PERM_EL02 = 3, 4, 15, 5, 2;
        GXF_STATUS_EL1 = 3, 6, 15, 8, 0;
        GXF_ENTER_EL1 = 3, 6, 15, 8, 1;
        GXF_ABORT_EL1 = 3, 6, 15, 8, 2;
        GXF_ENTER_EL12 = 3, 6, 15, 15, 2;
        GXF_ABORT_EL12 = 3, 6, 15, 15, 3;
        SP_GL12 = 3, 6, 15, 10, 0;
        TPIDR_GL1 = 3, 6, 15, 10, 1;
        VBAR_GL1 = 3, 6, 15, 10, 2;
        SPSR_GL1 = 3, 6, 15, 10, 3;
        ASPSR_GL1 = 3, 6, 15, 10, 4;
        ESR_GL1 = 3, 6, 15, 10, 5;
        ELR_GL1 = 3, 6, 15, 10, 6;
        FAR_GL1 = 3, 6, 15, 10, 7;
        // Apple PAC (XNU `xnu-6153.141.1` `pexpert/pexpert/arm64/arm64_common.h`).
        APCTL_EL1 = 3, 4, 15, 0, 4;
        APSTS_EL1 = 3, 6, 15, 12, 4;
        KERNELKEYLO_EL1 = 3, 4, 15, 1, 0;
        KERNELKEYHI_EL1 = 3, 4, 15, 1, 1;
        // Apple's non-speculative virtual count (XNU `machine_routines.c`
        // KERNEL_CNTVCTSS_EL0: "S3_4_C15_C10_6 and ACNTVCT_EL0 have identical
        // encodings"; m1n1 CNTVCT_ALIAS_EL0).
        CNTVCT_ALIAS_EL0 = 3, 4, 15, 10, 6;
    }
}
use encodings::*;

/// Which engine state a write changed, so the engine can resynchronize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changes {
    /// SCTLR, TCR, TTBRn or MAIR: translations and shadow roots.
    pub translation: bool,
    /// EL, PAN or SPSel: which shadow root and stack apply.
    pub regime: bool,
    /// DAIF or a timer: interrupt delivery must be re-evaluated.
    pub interrupts: bool,
    /// CPACR: FP/SIMD access.
    pub floating_point: bool,
}

/// Why an access cannot complete on this machine (not a guest exception).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No modeled behavior for this encoding.
    Unimplemented,
    /// An identification register the CPU profile has no value for.
    NoProfileValue,
    /// A modeled register written with a setting this engine cannot honor.
    UnsupportedSetting(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Read(u64),
    Written(Changes),
    /// UNDEFINED at the current EL (EC 0).
    Undefined,
    /// Trapped to EL1 by an EL1 control (EC 0x18).
    Trapped,
    Refused(Refusal),
}

/// ISS for EC 0x18 (MSR, MRS or System instruction trap).
pub fn trap_iss(access: RegisterAccess) -> u32 {
    let encoding = access.encoding();
    (u32::from(encoding.op0()) << 20)
        | (u32::from(encoding.op2()) << 17)
        | (u32::from(encoding.op1()) << 14)
        | (u32::from(encoding.crn()) << 10)
        | (u32::from(access.rt()) << 5)
        | (u32::from(encoding.crm()) << 1)
        | u32::from(access.direction() == Direction::Read)
}

const SCTLR_UMA: u64 = 1 << 9;
const SCTLR_DZE: u64 = 1 << 14;
const SCTLR_UCT: u64 = 1 << 15;
/// Bits of SCTLR_EL1 the engine accepts: everything below bit 32 except
/// alignment checking (A) and big-endian data (E0E, EE), plus DSSBS.
/// BT0/BT1 (bits 35/36) are accepted because the engine refuses to execute
/// pages whose descriptors set GP, so no BTI check can be skipped.
const SCTLR_SUPPORTED: u64 = 0x0000_1018_fcff_fffd;
/// APSTS_EL1.MKEYVld: the hardware master key is ready. This machine has no
/// key-generation delay, so the bit always reads as set.
const APSTS_MKEYVLD: u64 = 1;
/// The GL12 aliases and the EL12/EL02 SPRR and GXF views exist only for EL2.
const EL2_ONLY: [Encoding; 5] = [
    SPRR_PERM_EL12,
    SPRR_PERM_EL02,
    GXF_ENTER_EL12,
    GXF_ABORT_EL12,
    SP_GL12,
];
const CNTKCTL_EL0PCTEN: u64 = 1 << 0;
const CNTKCTL_EL0VCTEN: u64 = 1 << 1;
const CNTKCTL_EL0VTEN: u64 = 1 << 8;
const CNTKCTL_EL0PTEN: u64 = 1 << 9;
const ISR_I: u64 = 1 << 7;
const ISR_F: u64 = 1 << 6;

/// Pending interrupt lines, for ISR_EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lines {
    pub irq: bool,
    pub fiq: bool,
}

/// Inputs an access may observe besides the register file.
pub struct Environment<'a> {
    pub profile: &'a CpuProfile,
    pub now: u64,
    pub lines: Lines,
}

impl Cpu {
    /// Perform MRS or MSR. `Read` results are not yet written to Rt.
    pub fn access_register(
        &mut self,
        access: RegisterAccess,
        environment: &Environment,
    ) -> Outcome {
        let encoding = access.encoding();
        if self.pstate.el == 0
            && let Some(outcome) = self.el0_gate(encoding, access.direction())
        {
            return outcome;
        }
        match access.direction() {
            Direction::Read => self.read(encoding, environment),
            Direction::Write => {
                let value = if access.rt() == 31 {
                    0
                } else {
                    self.state.x[usize::from(access.rt())]
                };
                self.write(encoding, value, environment.now)
            }
        }
    }

    /// EL0 permission for registers EL0 can name; `None` lets the access run.
    fn el0_gate(&self, encoding: Encoding, direction: Direction) -> Option<Outcome> {
        let sctlr = self.system.translation.sctlr;
        let cntkctl = self.system.cntkctl;
        let allowed = |enabled: bool| (!enabled).then_some(Outcome::Trapped);
        let read_only = direction == Direction::Write;
        match encoding {
            NZCV | FPCR | FPSR | DIT | SSBS | TPIDR_EL0 => None,
            // The user JIT toggle (Sven Peter, "Apple Silicon Hardware
            // Secrets: SPRR and Guarded Exception Levels").
            SPRR_PERM_EL0 => None,
            TPIDRRO_EL0 | DCZID_EL0 if read_only => Some(Outcome::Undefined),
            TPIDRRO_EL0 | DCZID_EL0 => None,
            DAIF => allowed(sctlr & SCTLR_UMA != 0),
            CTR_EL0 if read_only => Some(Outcome::Undefined),
            CTR_EL0 => allowed(sctlr & SCTLR_UCT != 0),
            CNTFRQ_EL0 if read_only => Some(Outcome::Undefined),
            CNTFRQ_EL0 => allowed(cntkctl & (CNTKCTL_EL0PCTEN | CNTKCTL_EL0VCTEN) != 0),
            CNTPCT_EL0 | CNTPCTSS_EL0 if read_only => Some(Outcome::Undefined),
            CNTPCT_EL0 | CNTPCTSS_EL0 => allowed(cntkctl & CNTKCTL_EL0PCTEN != 0),
            CNTVCT_EL0 | CNTVCTSS_EL0 | CNTVCT_ALIAS_EL0 if read_only => Some(Outcome::Undefined),
            CNTVCT_EL0 | CNTVCTSS_EL0 | CNTVCT_ALIAS_EL0 => {
                allowed(cntkctl & CNTKCTL_EL0VCTEN != 0)
            }
            CNTP_TVAL_EL0 | CNTP_CTL_EL0 | CNTP_CVAL_EL0 => allowed(cntkctl & CNTKCTL_EL0PTEN != 0),
            CNTV_TVAL_EL0 | CNTV_CTL_EL0 | CNTV_CVAL_EL0 => allowed(cntkctl & CNTKCTL_EL0VTEN != 0),
            _ => Some(Outcome::Undefined),
        }
    }

    fn read(&mut self, encoding: Encoding, environment: &Environment) -> Outcome {
        let system = &self.system;
        let now = environment.now;
        let value = match encoding {
            SCTLR_EL1 => system.translation.sctlr,
            TCR_EL1 => system.translation.tcr,
            TTBR0_EL1 => system.translation.ttbr0,
            TTBR1_EL1 => system.translation.ttbr1,
            MAIR_EL1 => system.translation.mair,
            AMAIR_EL1 => system.amair,
            ACTLR_EL1 => system.actlr,
            CPACR_EL1 => system.cpacr,
            SPSR_EL1 => system.spsr,
            ELR_EL1 => system.elr,
            SP_EL0 if !self.pstate.sp_el1 => return Outcome::Undefined,
            SP_EL0 => self.sp_el0(),
            SPSEL => u64::from(self.pstate.sp_el1),
            CURRENTEL => u64::from(self.pstate.el) << 2,
            PAN => u64::from(self.pstate.pan) << 22,
            UAO => u64::from(self.pstate.uao) << 23,
            NZCV => u64::from(self.state.nzcv & 0xf000_0000),
            DAIF => u64::from(self.pstate.daif) << 6,
            DIT => u64::from(self.pstate.dit) << 24,
            SSBS => u64::from(self.pstate.ssbs) << 12,
            FPCR => u64::from(self.state.fpcr),
            FPSR => u64::from(self.state.fpsr),
            AFSR0_EL1 => system.afsr0,
            AFSR1_EL1 => system.afsr1,
            ESR_EL1 => system.esr,
            FAR_EL1 => system.far,
            PAR_EL1 => system.par,
            VBAR_EL1 => system.vbar,
            ISR_EL1 => {
                (if environment.lines.irq { ISR_I } else { 0 })
                    | if environment.lines.fiq { ISR_F } else { 0 }
            }
            CONTEXTIDR_EL1 => system.contextidr,
            TPIDR_EL1 => system.tpidr_el1,
            TPIDR_EL0 => system.tpidr_el0,
            TPIDRRO_EL0 => system.tpidrro_el0,
            CNTKCTL_EL1 => system.cntkctl,
            CNTFRQ_EL0 => environment.profile.counter_frequency,
            CNTPCT_EL0 | CNTVCT_EL0 | CNTPCTSS_EL0 | CNTVCTSS_EL0 | CNTVCT_ALIAS_EL0 => now,
            CNTP_TVAL_EL0 => system.physical_timer.read_value(now),
            CNTP_CTL_EL0 => system.physical_timer.read_control(now),
            CNTP_CVAL_EL0 => system.physical_timer.compare(),
            CNTV_TVAL_EL0 => system.virtual_timer.read_value(now),
            CNTV_CTL_EL0 => system.virtual_timer.read_control(now),
            CNTV_CVAL_EL0 => system.virtual_timer.compare(),
            CSSELR_EL1 => system.csselr,
            MDSCR_EL1 => system.mdscr,
            OSLSR_EL1 => 0b1000 | (u64::from(system.oslsr_locked) << 1),
            OSDLR_EL1 => system.osdlr,
            APIAKEYLO_EL1 => system.keys[0][0],
            APIAKEYHI_EL1 => system.keys[0][1],
            APIBKEYLO_EL1 => system.keys[1][0],
            APIBKEYHI_EL1 => system.keys[1][1],
            APDAKEYLO_EL1 => system.keys[2][0],
            APDAKEYHI_EL1 => system.keys[2][1],
            APDBKEYLO_EL1 => system.keys[3][0],
            APDBKEYHI_EL1 => system.keys[3][1],
            APGAKEYLO_EL1 => system.keys[4][0],
            APGAKEYHI_EL1 => system.keys[4][1],
            encoding if self.apple(encoding).is_some() => {
                return self.apple(encoding).expect("checked").read(self);
            }
            encoding if impdef::lookup(encoding).is_some() => {
                let entry = impdef::lookup(encoding).expect("checked");
                return match self.system.impdef.read(entry) {
                    Some(value) => Outcome::Read(value),
                    None => Outcome::Refused(Refusal::UnsupportedSetting(
                        "read of an implementation-defined storage register before its first write",
                    )),
                };
            }
            _ => {
                return match environment.profile.fixed(encoding) {
                    Some(value) => Outcome::Read(value),
                    None if is_identification(encoding) => {
                        Outcome::Refused(Refusal::NoProfileValue)
                    }
                    None => Outcome::Refused(Refusal::Unimplemented),
                };
            }
        };
        Outcome::Read(value)
    }

    fn write(&mut self, encoding: Encoding, value: u64, now: u64) -> Outcome {
        let mut changes = Changes::default();
        let pstate = self.pstate;
        let system = &mut self.system;
        match encoding {
            SCTLR_EL1 => {
                if value & !SCTLR_SUPPORTED != 0 {
                    return Outcome::Refused(Refusal::UnsupportedSetting(
                        "SCTLR_EL1 bit outside the implemented set",
                    ));
                }
                system.translation.sctlr = value;
                changes.translation = true;
            }
            TCR_EL1 => {
                system.translation.tcr = value;
                changes.translation = true;
            }
            TTBR0_EL1 => {
                system.translation.ttbr0 = value;
                changes.translation = true;
            }
            TTBR1_EL1 => {
                system.translation.ttbr1 = value;
                changes.translation = true;
            }
            MAIR_EL1 => {
                system.translation.mair = value;
                changes.translation = true;
            }
            AMAIR_EL1 => system.amair = value,
            ACTLR_EL1 => system.actlr = value,
            CPACR_EL1 => {
                system.cpacr = value;
                changes.floating_point = true;
            }
            SPSR_EL1 => system.spsr = value,
            ELR_EL1 => system.elr = value,
            SP_EL0 if !pstate.sp_el1 => return Outcome::Undefined,
            SP_EL0 => self.set_sp_el0(value),
            SPSEL => {
                self.set_pstate(Pstate {
                    sp_el1: value & 1 != 0,
                    ..pstate
                });
                changes.regime = true;
            }
            PAN => {
                self.pstate.pan = value & (1 << 22) != 0;
                changes.regime = true;
            }
            UAO => self.pstate.uao = value & (1 << 23) != 0,
            NZCV => self.state.nzcv = (value & 0xf000_0000) as u32,
            DAIF => {
                self.pstate.daif = ((value >> 6) & u64::from(DAIF_ALL)) as u8;
                changes.interrupts = true;
            }
            DIT => self.pstate.dit = value & (1 << 24) != 0,
            SSBS => self.pstate.ssbs = value & (1 << 12) != 0,
            FPCR => self.state.fpcr = value as u32,
            FPSR => self.state.fpsr = value as u32,
            AFSR0_EL1 => system.afsr0 = value,
            AFSR1_EL1 => system.afsr1 = value,
            ESR_EL1 => system.esr = value,
            FAR_EL1 => system.far = value,
            PAR_EL1 => system.par = value,
            VBAR_EL1 => system.vbar = value & !0x7ff,
            CONTEXTIDR_EL1 => system.contextidr = value & 0xffff_ffff,
            TPIDR_EL1 => system.tpidr_el1 = value,
            TPIDR_EL0 => system.tpidr_el0 = value,
            TPIDRRO_EL0 => system.tpidrro_el0 = value,
            CNTKCTL_EL1 => system.cntkctl = value,
            CNTP_TVAL_EL0 => {
                system.physical_timer.write_value(now, value);
                changes.interrupts = true;
            }
            CNTP_CTL_EL0 => {
                system.physical_timer.write_control(value);
                changes.interrupts = true;
            }
            CNTP_CVAL_EL0 => {
                system.physical_timer.write_compare(value);
                changes.interrupts = true;
            }
            CNTV_TVAL_EL0 => {
                system.virtual_timer.write_value(now, value);
                changes.interrupts = true;
            }
            CNTV_CTL_EL0 => {
                system.virtual_timer.write_control(value);
                changes.interrupts = true;
            }
            CNTV_CVAL_EL0 => {
                system.virtual_timer.write_compare(value);
                changes.interrupts = true;
            }
            CSSELR_EL1 => system.csselr = value & 0xf,
            MDSCR_EL1 => {
                // Software step and debug exceptions need a debug model.
                if value & ((1 << 0) | (1 << 13) | (1 << 15)) != 0 {
                    return Outcome::Refused(Refusal::UnsupportedSetting(
                        "MDSCR_EL1 software step or debug exceptions",
                    ));
                }
                system.mdscr = value;
            }
            OSLAR_EL1 => system.oslsr_locked = value & 1 != 0,
            OSDLR_EL1 => system.osdlr = value & 1,
            MDCCINT_EL1 if value == 0 => {}
            APIAKEYLO_EL1 => system.keys[0][0] = value,
            APIAKEYHI_EL1 => system.keys[0][1] = value,
            APIBKEYLO_EL1 => system.keys[1][0] = value,
            APIBKEYHI_EL1 => system.keys[1][1] = value,
            APDAKEYLO_EL1 => system.keys[2][0] = value,
            APDAKEYHI_EL1 => system.keys[2][1] = value,
            APDBKEYLO_EL1 => system.keys[3][0] = value,
            APDBKEYHI_EL1 => system.keys[3][1] = value,
            APGAKEYLO_EL1 => system.keys[4][0] = value,
            APGAKEYHI_EL1 => system.keys[4][1] = value,
            encoding if self.apple(encoding).is_some() => {
                return self.apple(encoding).expect("checked").write(self, value);
            }
            encoding if impdef::lookup(encoding).is_some() => {
                let entry = impdef::lookup(encoding).expect("checked");
                self.system.impdef.write(entry, value);
            }
            CNTPCT_EL0 | CNTVCT_EL0 | CNTPCTSS_EL0 | CNTVCTSS_EL0 | CNTVCT_ALIAS_EL0 => {
                return Outcome::Undefined;
            }
            _ if is_identification(encoding) => return Outcome::Undefined,
            _ => return Outcome::Refused(Refusal::Unimplemented),
        }
        Outcome::Written(changes)
    }

    /// MSR (immediate). `encoding` is the decoded op1/CRm/op2 form.
    pub fn write_pstate_field(&mut self, encoding: Encoding) -> Outcome {
        let immediate = encoding.crm();
        let mut changes = Changes::default();
        match (encoding.op1(), encoding.op2()) {
            (3, 6) | (3, 7) => {
                if self.pstate.el == 0 && self.system.translation.sctlr & SCTLR_UMA == 0 {
                    return Outcome::Trapped;
                }
                if encoding.op2() == 6 {
                    self.pstate.daif |= immediate;
                } else {
                    self.pstate.daif &= !immediate;
                }
                changes.interrupts = true;
            }
            _ if self.pstate.el == 0 => match (encoding.op1(), encoding.op2()) {
                (3, 2) => self.pstate.dit = immediate & 1 != 0,
                (3, 1) => self.pstate.ssbs = immediate & 1 != 0,
                _ => return Outcome::Undefined,
            },
            (0, 5) => {
                self.set_pstate(Pstate {
                    sp_el1: immediate & 1 != 0,
                    ..self.pstate
                });
                changes.regime = true;
            }
            (0, 4) => {
                self.pstate.pan = immediate & 1 != 0;
                changes.regime = true;
            }
            (0, 3) => self.pstate.uao = immediate & 1 != 0,
            (3, 2) => self.pstate.dit = immediate & 1 != 0,
            (3, 1) => self.pstate.ssbs = immediate & 1 != 0,
            _ => return Outcome::Refused(Refusal::Unimplemented),
        }
        Outcome::Written(changes)
    }

    /// DC ZVA is permitted at EL0 only with SCTLR_EL1.DZE.
    pub fn zva_permitted(&self) -> bool {
        self.pstate.el == 1 || self.system.translation.sctlr & SCTLR_DZE != 0
    }
}

/// Apple implementation-defined registers with modeled behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Apple {
    SprrConfig,
    SprrPermEl1,
    SprrPermEl0,
    GxfConfig,
    GxfStatus,
    GxfEnter,
    GxfAbort,
    /// A GL1 bank register, only reachable at the guarded level.
    Guarded(Encoding),
    El2Only,
    ApStatus,
    ApControl,
    KernelKey(usize),
}

impl Apple {
    fn read(self, cpu: &Cpu) -> Outcome {
        let sprr = cpu.system.translation.sprr;
        let gl = &cpu.system.guarded;
        Outcome::Read(match self {
            Self::SprrConfig => sprr.config,
            Self::SprrPermEl1 | Self::SprrPermEl0 if !sprr.enabled() => {
                return Outcome::Undefined;
            }
            Self::SprrPermEl1 => sprr.el1,
            Self::SprrPermEl0 => sprr.el0,
            Self::GxfConfig => gl.config,
            Self::GxfStatus => u64::from(cpu.pstate.guarded),
            Self::GxfEnter => gl.enter,
            Self::GxfAbort => gl.abort,
            Self::Guarded(_) if !cpu.pstate.guarded => {
                return Outcome::Refused(Refusal::UnsupportedSetting(
                    "GL1 bank register outside the guarded level",
                ));
            }
            Self::Guarded(encoding) => match encoding {
                TPIDR_GL1 => gl.tpidr,
                VBAR_GL1 => gl.vbar,
                SPSR_GL1 => gl.spsr,
                ASPSR_GL1 => gl.aspsr,
                ESR_GL1 => gl.esr,
                ELR_GL1 => gl.elr,
                _ => gl.far,
            },
            Self::El2Only => return Outcome::Undefined,
            Self::ApStatus => APSTS_MKEYVLD,
            Self::ApControl => cpu.system.apctl,
            Self::KernelKey(index) => cpu.system.kernel_key[index],
        })
    }

    fn write(self, cpu: &mut Cpu, value: u64) -> Outcome {
        use super::mmu::{
            SPRR_CONFIG_EN, SPRR_CONFIG_LOCK_CONFIG, SPRR_CONFIG_LOCK_PERM_EL0,
            SPRR_CONFIG_LOCK_PERM_EL1,
        };
        let mut changes = Changes::default();
        let sprr = &mut cpu.system.translation.sprr;
        let refuse = |reason| Outcome::Refused(Refusal::UnsupportedSetting(reason));
        match self {
            Self::SprrConfig => {
                if sprr.config & SPRR_CONFIG_LOCK_CONFIG != 0 {
                    return refuse("SPRR_CONFIG_EL1 write after LOCK_CONFIG");
                }
                let known = SPRR_CONFIG_EN
                    | SPRR_CONFIG_LOCK_CONFIG
                    | SPRR_CONFIG_LOCK_PERM_EL0
                    | SPRR_CONFIG_LOCK_PERM_EL1;
                if value & !known != 0 {
                    return refuse("SPRR_CONFIG_EL1 bit without documented meaning");
                }
                sprr.config = value;
                changes.translation = true;
            }
            Self::SprrPermEl1 | Self::SprrPermEl0 if !sprr.enabled() => {
                return Outcome::Undefined;
            }
            Self::SprrPermEl1 => {
                if sprr.config & SPRR_CONFIG_LOCK_PERM_EL1 != 0 {
                    return refuse("SPRR_PERM_EL1 write after LOCK_KERNEL_PERM");
                }
                sprr.el1 = value;
                changes.translation = true;
            }
            Self::SprrPermEl0 => {
                if sprr.config & SPRR_CONFIG_LOCK_PERM_EL0 != 0 {
                    return refuse("SPRR_PERM_EL0 write after LOCK_PERM");
                }
                sprr.el0 = value;
                changes.translation = true;
            }
            Self::GxfConfig => {
                if value & !super::cpu::GXF_CONFIG_EN != 0 {
                    return refuse("GXF_CONFIG_EL1 bit without documented meaning");
                }
                cpu.system.guarded.config = value;
            }
            Self::GxfStatus | Self::ApStatus => return Outcome::Undefined,
            Self::GxfEnter => cpu.system.guarded.enter = value,
            Self::GxfAbort => cpu.system.guarded.abort = value,
            Self::Guarded(_) if !cpu.pstate.guarded => {
                return refuse("GL1 bank register outside the guarded level");
            }
            Self::Guarded(encoding) => {
                let gl = &mut cpu.system.guarded;
                match encoding {
                    TPIDR_GL1 => gl.tpidr = value,
                    VBAR_GL1 => gl.vbar = value & !0x7ff,
                    SPSR_GL1 => gl.spsr = value,
                    ASPSR_GL1 => gl.aspsr = value,
                    ESR_GL1 => gl.esr = value,
                    ELR_GL1 => gl.elr = value,
                    _ => gl.far = value,
                }
            }
            Self::El2Only => return Outcome::Undefined,
            Self::ApControl => cpu.system.apctl = value,
            Self::KernelKey(index) => cpu.system.kernel_key[index] = value,
        }
        Outcome::Written(changes)
    }
}

impl Cpu {
    fn apple(&self, encoding: Encoding) -> Option<Apple> {
        Some(match encoding {
            SPRR_CONFIG_EL1 => Apple::SprrConfig,
            SPRR_PERM_EL1 => Apple::SprrPermEl1,
            SPRR_PERM_EL0 => Apple::SprrPermEl0,
            GXF_CONFIG_EL1 => Apple::GxfConfig,
            GXF_STATUS_EL1 => Apple::GxfStatus,
            GXF_ENTER_EL1 => Apple::GxfEnter,
            GXF_ABORT_EL1 => Apple::GxfAbort,
            TPIDR_GL1 | VBAR_GL1 | SPSR_GL1 | ASPSR_GL1 | ESR_GL1 | ELR_GL1 | FAR_GL1 => {
                Apple::Guarded(encoding)
            }
            APSTS_EL1 => Apple::ApStatus,
            APCTL_EL1 => Apple::ApControl,
            KERNELKEYLO_EL1 => Apple::KernelKey(0),
            KERNELKEYHI_EL1 => Apple::KernelKey(1),
            encoding if EL2_ONLY.contains(&encoding) => Apple::El2Only,
            _ => return None,
        })
    }
}

/// The read-only identification space: op0=3, op1 in {0,1,3}, CRn=0.
fn is_identification(encoding: Encoding) -> bool {
    encoding.op0() == 3 && encoding.crn() == 0 && matches!(encoding.op1(), 0 | 1 | 3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::exception::{DAIF_F, DAIF_I};
    use stela_compiler::aarch64::system::registers::{decode, decode_pstate_immediate};

    fn profile() -> CpuProfile {
        CpuProfile {
            name: "test",
            counter_frequency: 24_000_000,
            fixed: vec![(MIDR_EL1, 0x611f_0320)],
        }
    }

    fn mrs(rt: u8, encoding: Encoding) -> RegisterAccess {
        decode(
            0xd530_0000
                | (u32::from(encoding.op0() & 1) << 19)
                | (u32::from(encoding.op1()) << 16)
                | (u32::from(encoding.crn()) << 12)
                | (u32::from(encoding.crm()) << 8)
                | (u32::from(encoding.op2()) << 5)
                | u32::from(rt),
        )
        .unwrap()
    }

    fn msr(rt: u8, encoding: Encoding) -> RegisterAccess {
        let read = mrs(rt, encoding);
        decode(0xd510_0000 | (trap_bits(read) & 0x000f_ffff)).unwrap()
    }

    fn trap_bits(access: RegisterAccess) -> u32 {
        let encoding = access.encoding();
        (u32::from(encoding.op0() & 1) << 19)
            | (u32::from(encoding.op1()) << 16)
            | (u32::from(encoding.crn()) << 12)
            | (u32::from(encoding.crm()) << 8)
            | (u32::from(encoding.op2()) << 5)
            | u32::from(access.rt())
    }

    #[test]
    fn el1_registers_banking_timers_and_refusals() {
        let profile = profile();
        let environment = Environment {
            profile: &profile,
            now: 1000,
            lines: Lines {
                irq: false,
                fiq: true,
            },
        };
        let mut cpu = Cpu::new(0, Pstate::RESET_EL1);
        cpu.state.x[3] = 0xffff_0000_1234_0000;
        assert_eq!(
            cpu.access_register(msr(3, TTBR1_EL1), &environment),
            Outcome::Written(Changes {
                translation: true,
                ..Changes::default()
            })
        );
        assert_eq!(cpu.system.translation.ttbr1, 0xffff_0000_1234_0000);
        assert_eq!(
            cpu.access_register(mrs(0, MIDR_EL1), &environment),
            Outcome::Read(0x611f_0320)
        );
        assert_eq!(
            cpu.access_register(mrs(0, ID_AA64MMFR0_EL1), &environment),
            Outcome::Refused(Refusal::NoProfileValue)
        );
        assert_eq!(
            cpu.access_register(mrs(0, Encoding::new(3, 0, 15, 0, 0)), &environment),
            Outcome::Refused(Refusal::Unimplemented)
        );
        assert_eq!(
            cpu.access_register(mrs(0, CURRENTEL), &environment),
            Outcome::Read(4)
        );
        assert_eq!(
            cpu.access_register(mrs(0, ISR_EL1), &environment),
            Outcome::Read(1 << 6)
        );
        cpu.state.x[1] = 500;
        cpu.access_register(msr(1, CNTV_TVAL_EL0), &environment);
        assert_eq!(cpu.system.virtual_timer.compare(), 1500);
        // SP_EL0 is reachable at EL1h, and SPSel moves the stacks.
        cpu.state.sp = 0x9000;
        cpu.state.x[2] = 0x5000;
        cpu.access_register(msr(2, SP_EL0), &environment);
        cpu.access_register(msr(31, SPSEL), &environment);
        assert_eq!((cpu.state.sp, cpu.system.sp_el1), (0x5000, 0x9000));
        assert_eq!(
            cpu.access_register(mrs(0, SP_EL0), &environment),
            Outcome::Undefined
        );
        let daifclr = decode_pstate_immediate(0xd503_47ff & !(0xf << 8) | (3 << 8)).unwrap();
        cpu.write_pstate_field(daifclr);
        assert_eq!(cpu.pstate.daif, DAIF_ALL & !(DAIF_I | DAIF_F));
    }

    #[test]
    fn el0_access_rules() {
        let profile = profile();
        let environment = Environment {
            profile: &profile,
            now: 7,
            lines: Lines::default(),
        };
        let mut cpu = Cpu::new(
            0,
            Pstate {
                el: 0,
                sp_el1: false,
                daif: 0,
                ..Pstate::RESET_EL1
            },
        );
        assert_eq!(
            cpu.access_register(mrs(0, TPIDR_EL1), &environment),
            Outcome::Undefined
        );
        assert_eq!(
            cpu.access_register(mrs(0, CNTVCT_EL0), &environment),
            Outcome::Trapped
        );
        cpu.system.cntkctl = CNTKCTL_EL0VCTEN;
        assert_eq!(
            cpu.access_register(mrs(0, CNTVCT_EL0), &environment),
            Outcome::Read(7)
        );
        assert_eq!(
            cpu.access_register(msr(0, TPIDRRO_EL0), &environment),
            Outcome::Undefined
        );
        assert!(matches!(
            cpu.access_register(msr(0, TPIDR_EL0), &environment),
            Outcome::Written(_)
        ));
        assert_eq!(
            cpu.access_register(mrs(0, DAIF), &environment),
            Outcome::Trapped
        );
        let access = mrs(4, CNTVCT_EL0);
        assert_eq!(trap_iss(access), 0x0034_f881);
    }
}
