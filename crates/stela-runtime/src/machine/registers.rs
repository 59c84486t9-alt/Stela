//! Apple's IMPLEMENTATION DEFINED System registers and MSR (immediate).
//!
//! Architectural System registers and System instructions go through the
//! generated AARCHMRS accessors (`machine::system`). This module handles the
//! op0=3 CRn=15 space Apple uses: SPRR, GXF, the Apple PAC controls,
//! VMSA_LOCK_EL1, the VM timer FIQ enables, AMX, the performance monitor
//! (`machine::pmu`) and the `machine::impdef` table. Every other encoding in that space refuses with its fields.
//!
//! With EL2 present and HCR_EL2.E2H RES1, Apple's registers follow the VHE
//! pattern their names show (m1n1 `cpu_regs.h`): at EL2 the `*_EL1` and
//! `*_GL1` encodings reach the EL2 and GL2 state and the `*_EL12`, `*_EL02`
//! and `*_GL12` encodings reach the EL1 and GL1 state (inference from the
//! names and from m1n1 `gxf_asm.S`). HCR_EL2.TIDCP traps the whole
//! IMPLEMENTATION DEFINED space from EL1 to EL2.
use super::{
    cpu::{
        Cpu, GXF_CONFIG_EL1_LOCK, GXF_CONFIG_EN, GXF_CONFIG_LOCKS, GuardedBank, PERM_EL0_10,
        PERM_EL0_20, PERM_EL1, PERM_EL2, TranslationRegime, VM_TIMER_FIQ_PHYSICAL,
        VM_TIMER_FIQ_VIRTUAL,
    },
    exception::Pstate,
    impdef,
    pmu::Pmu,
    system::Register,
};
use alloc::vec::Vec;
use stela_compiler::aarch64::system::registers::{Direction, Encoding, RegisterAccess};

/// Identification and fixed registers of one declared CPU profile. A register
/// without a value refuses: profile values need evidence.
#[derive(Debug, Clone)]
pub struct CpuProfile {
    pub name: &'static str,
    /// The Apple CPU every PE of the profile is.
    pub chip: super::Chip,
    pub counter_frequency: u64,
    pub fixed: Vec<(Encoding, u64)>,
    /// The board's PEs, numbered as the devices number them, each with the
    /// values that differ between PEs. Empty for a uniprocessor described by
    /// `fixed` alone.
    pub processors: Vec<Identity>,
}

/// The identification values one PE does not share with the others; they
/// replace `fixed` entries of the same registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub midr: u64,
    pub mpidr: u64,
    /// The core clock in Hz, where the SoC row has evidence of it; it paces
    /// the cycle counter of Apple's performance monitor (`machine::pmu`).
    pub clock: Option<u64>,
}

/// Encodings named by the Arm ARM and by m1n1 `cpu_regs.h`.
pub mod encodings {
    pub use stela_compiler::aarch64::system::registers::Encoding;
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
        ID_AA64MMFR3_EL1 = 3, 0, 0, 7, 3;
        ID_AA64MMFR4_EL1 = 3, 0, 0, 7, 4;
        ID_AA64PFR2_EL1 = 3, 0, 0, 4, 2;
        ID_AA64FPFR0_EL1 = 3, 0, 0, 4, 7;
        ID_AA64DFR2_EL1 = 3, 0, 0, 5, 2;
        ID_AA64ISAR3_EL1 = 3, 0, 0, 6, 3;
        LORID_EL1 = 3, 0, 10, 4, 7;
        MPAMIDR_EL1 = 3, 0, 10, 4, 4;
        ERRIDR_EL1 = 3, 0, 5, 3, 0;
        MDRAR_EL1 = 2, 0, 1, 0, 0;
        DBGAUTHSTATUS_EL1 = 2, 0, 7, 14, 6;
        CCSIDR_EL1 = 3, 1, 0, 0, 0;
        CLIDR_EL1 = 3, 1, 0, 0, 1;
        AIDR_EL1 = 3, 1, 0, 0, 7;
        CTR_EL0 = 3, 3, 0, 0, 1;
        DCZID_EL0 = 3, 3, 0, 0, 7;
        FPCR = 3, 3, 4, 4, 0;
        FPSR = 3, 3, 4, 4, 1;
        // Apple SPRR and GXF (m1n1 `cpu_regs.h`; Asahi "SPRR and GXF").
        SPRR_CONFIG_EL1 = 3, 6, 15, 1, 0;
        GXF_CONFIG_EL1 = 3, 6, 15, 1, 2;
        SPRR_PERM_EL0 = 3, 6, 15, 1, 5;
        SPRR_PERM_EL1 = 3, 6, 15, 1, 6;
        SPRR_PERM_EL12 = 3, 6, 15, 15, 7;
        SPRR_PERM_EL02 = 3, 4, 15, 5, 2;
        // No public name; see `mmu::Sprr::fields`.
        SPRR_FIELDS_0 = 3, 6, 15, 3, 0;
        SPRR_FIELDS_1 = 3, 6, 15, 3, 1;
        GXF_STATUS_EL1 = 3, 6, 15, 8, 0;
        GXF_ENTER_EL1 = 3, 6, 15, 8, 1;
        GXF_ABORT_EL1 = 3, 6, 15, 8, 2;
        GXF_ENTER_EL12 = 3, 6, 15, 15, 2;
        GXF_ABORT_EL12 = 3, 6, 15, 15, 3;
        // No public name: EL1's GXF_CONFIG from EL2. SPTM 26A434 clears it
        // with GXF_ENTER_EL12 and GXF_ABORT_EL12 (`__text+0xbf8c`) and later
        // clears its bit 0 alone (`__text+0x59e7c`); the kernel saves and
        // restores it with a VM's GL12 registers (0xfffffe000bda2b5c).
        GXF_CONFIG_EL12 = 3, 6, 15, 15, 1;
        SP_GL12 = 3, 6, 15, 10, 0;
        TPIDR_GL1 = 3, 6, 15, 10, 1;
        VBAR_GL1 = 3, 6, 15, 10, 2;
        SPSR_GL1 = 3, 6, 15, 10, 3;
        ASPSR_GL1 = 3, 6, 15, 10, 4;
        ESR_GL1 = 3, 6, 15, 10, 5;
        ELR_GL1 = 3, 6, 15, 10, 6;
        FAR_GL1 = 3, 6, 15, 10, 7;
        TPIDR_GL2 = 3, 6, 15, 11, 1;
        VBAR_GL12 = 3, 6, 15, 9, 2;
        SPSR_GL12 = 3, 6, 15, 9, 3;
        ASPSR_GL12 = 3, 6, 15, 9, 4;
        ESR_GL12 = 3, 6, 15, 9, 5;
        ELR_GL12 = 3, 6, 15, 9, 6;
        // Apple PAC (XNU `xnu-6153.141.1` `pexpert/pexpert/arm64/arm64_common.h`).
        APCTL_EL1 = 3, 4, 15, 0, 4;
        APCTL_EL2 = 3, 6, 15, 12, 2;
        APCTL_EL12 = 3, 6, 15, 15, 0;
        APSTS_EL1 = 3, 6, 15, 12, 4;
        KERNELKEYLO_EL1 = 3, 4, 15, 1, 0;
        KERNELKEYHI_EL1 = 3, 4, 15, 1, 1;
        // XNU `xnu-6153.141.1` `arm64_common.h` (HAS_VMSA_LOCK).
        VMSA_LOCK_EL1 = 3, 4, 15, 1, 2;
        // FIQ enables of the EL1 virtual (bit 0) and physical (bit 1) timers
        // (m1n1 `cpu_regs.h` VM_TMR_FIQ_ENA_EL2).
        VM_TMR_FIQ_ENA_EL2 = 3, 5, 15, 1, 3;
        // Apple's non-speculative virtual count (XNU `machine_routines.c`
        // KERNEL_CNTVCTSS_EL0: "S3_4_C15_C10_6 and ACNTVCT_EL0 have identical
        // encodings"; m1n1 CNTVCT_ALIAS_EL0).
        CNTVCT_ALIAS_EL0 = 3, 4, 15, 10, 6;
        // m1n1 `cpu_regs.h` "Lockdown registers"; the commit register has no
        // public name (see `Apple::SprLockdown`).
        SPR_LOCKDOWN_EL2 = 3, 4, 15, 0, 5;
        SPR_LOCKDOWN_COMMIT = 3, 4, 15, 12, 5;
    }
}
use encodings::*;

/// Which engine state a write changed, so the engine can resynchronize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changes {
    /// Translation controls or SPRR: shadow roots and fetch translations.
    pub translation: bool,
    /// EL, PAN or SPSel: which shadow root and stack apply.
    pub regime: bool,
    /// DAIF or a timer: interrupt delivery must be re-evaluated.
    pub interrupts: bool,
    /// FP/SIMD access.
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
    /// Trapped with EC 0x18, to the given EL or routed by default.
    Trapped(Option<u8>),
    /// An SME access trap (EC 0x1D, SMTC 0) to the given EL.
    SmeTrapped(u8),
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

/// Pending interrupt lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lines {
    pub irq: bool,
    pub fiq: bool,
}

const HCR_TIDCP: u32 = 20;
const SCTLR_UMA: u64 = 1 << 9;
/// APSTS_EL1.MKEYVld: the hardware master key is ready. This machine has no
/// key-generation delay, so the bit always reads as set.
const APSTS_MKEYVLD: u64 = 1;
/// CNTKCTL_EL1.EL0VCTEN, at the same bit in CNTHCTL_EL2 with E2H set.
const EL0VCTEN: u32 = 1;

/// VMSA_LOCK_EL1 bits (XNU `xnu-6153.141.1` `arm64_common.h`): each locks
/// one translation register, and bit 63 locks SCTLR.M.
const VMSA_LOCK_VBAR: u64 = 1 << 0;
const VMSA_LOCK_SCTLR: u64 = 1 << 1;
const VMSA_LOCK_TCR: u64 = 1 << 2;
const VMSA_LOCK_TTBR0: u64 = 1 << 3;
const VMSA_LOCK_TTBR1: u64 = 1 << 4;
const VMSA_LOCK_SCTLR_M: u64 = 1 << 63;
const VMSA_LOCK_KNOWN: u64 = 0x1f | VMSA_LOCK_SCTLR_M;

/// A write VMSA_LOCK_EL1 forbids. The lock covers the translation registers
/// of the EL that wrote it (inference: SPTM sets it at EL2 for its own
/// registers). What hardware does with the write is not documented (XNU
/// checks the lock in software and panics), so it stops.
pub(crate) fn vmsa_locked(cpu: &Cpu, register: Register, value: u64) -> Option<&'static str> {
    let lock = cpu.apple.vmsa_lock;
    if lock == 0 {
        return None;
    }
    let el2 = cpu.apple.vmsa_lock_el == 2;
    let pick = |el1: Register, el2_register: Register| if el2 { el2_register } else { el1 };
    let locked = |bit: u64| lock & bit != 0;
    let sctlr = pick(Register::SCTLR_EL1, Register::SCTLR_EL2);
    if register == pick(Register::VBAR_EL1, Register::VBAR_EL2) && locked(VMSA_LOCK_VBAR) {
        return Some("VBAR write under VMSA_LOCK_EL1");
    }
    if register == sctlr && locked(VMSA_LOCK_SCTLR) {
        return Some("SCTLR write under VMSA_LOCK_EL1");
    }
    if register == sctlr && locked(VMSA_LOCK_SCTLR_M) && (value ^ cpu.read(sctlr)) & 1 != 0 {
        return Some("SCTLR.M change under VMSA_LOCK_EL1");
    }
    if register == pick(Register::TCR_EL1, Register::TCR_EL2) && locked(VMSA_LOCK_TCR) {
        return Some("TCR write under VMSA_LOCK_EL1");
    }
    if register == pick(Register::TTBR0_EL1, Register::TTBR0_EL2) && locked(VMSA_LOCK_TTBR0) {
        return Some("TTBR0 write under VMSA_LOCK_EL1");
    }
    if register == pick(Register::TTBR1_EL1, Register::TTBR1_EL2) && locked(VMSA_LOCK_TTBR1) {
        return Some("TTBR1 write under VMSA_LOCK_EL1");
    }
    None
}

/// Apple registers with modeled behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Apple {
    SprrConfig,
    /// One of `AppleState::sprr_perm`.
    SprrPerm(usize),
    /// `S3_6_C15_C3_0` (0) and `S3_6_C15_C3_1` (1).
    SprrFields(usize),
    /// GXF_CONFIG of EL1 (0) or EL2 (1).
    GxfConfig(usize),
    GxfStatus,
    /// GXF_ENTER (true) or GXF_ABORT of a guarded level.
    GxfEntry(usize, bool),
    /// A GL bank register of the current guarded level.
    Guarded(usize, Encoding),
    /// A GL1 bank register reached from EL2 through its GL12 name.
    GuardedOne(Encoding),
    TpidrGl(usize),
    ApStatus,
    ApControl(usize),
    KernelKey(usize),
    VmsaLock,
    VmTimerFiq,
    CountAlias,
    /// SPR_LOCKDOWN_EL2 (`false`) and `S3_4_C15_C12_5` (`true`). SPTM 26A434
    /// writes SPR_LOCKDOWN_EL2 once per PE, with every bit except 4, 27 and
    /// 63, after its MMIO lockdown (`__text+0x181a4`), then writes 1 to
    /// `S3_4_C15_C12_5` (`__text+0x181bc`); neither is read. Inferred from
    /// that order: the first selects what is locked and bit 0 of the second
    /// commits it. Once committed, a write that changes either stops. What
    /// each bit protects is not documented, so the commit makes no other
    /// register read-only here (docs/design/system.md records the gap).
    SprLockdown(bool),
}

fn bank_read(bank: &GuardedBank, encoding: Encoding) -> u64 {
    match encoding {
        VBAR_GL1 | VBAR_GL12 => bank.vbar,
        SPSR_GL1 | SPSR_GL12 => bank.spsr,
        ASPSR_GL1 | ASPSR_GL12 => bank.aspsr,
        ESR_GL1 | ESR_GL12 => bank.esr,
        ELR_GL1 | ELR_GL12 => bank.elr,
        SP_GL12 => bank.sp,
        _ => bank.far,
    }
}

fn bank_write(bank: &mut GuardedBank, encoding: Encoding, value: u64) {
    match encoding {
        VBAR_GL1 | VBAR_GL12 => bank.vbar = value & !0x7ff,
        SPSR_GL1 | SPSR_GL12 => bank.spsr = value,
        ASPSR_GL1 | ASPSR_GL12 => bank.aspsr = value,
        ESR_GL1 | ESR_GL12 => bank.esr = value,
        ELR_GL1 | ELR_GL12 => bank.elr = value,
        SP_GL12 => bank.sp = value,
        _ => bank.far = value,
    }
}

/// CNTVCT_ALIAS_EL0 reads the virtual count of the current regime: the
/// physical count, minus CNTVOFF_EL2 outside the EL2&0 host.
fn count_alias(cpu: &Cpu, physical: u64) -> u64 {
    if cpu.regime() == TranslationRegime::El20 {
        physical
    } else {
        physical.wrapping_sub(cpu.read(Register::CNTVOFF_EL2))
    }
}

impl Cpu {
    /// Which Apple register an encoding reaches at the current EL; an EL2
    /// name below EL2 is UNDEFINED.
    fn apple(&self, encoding: Encoding) -> Option<Result<Apple, Outcome>> {
        let at_el2 = self.pstate.el == 2;
        let level = usize::from(self.pstate.el.max(1)) - 1;
        let el2 = |register: Apple| {
            Some(if at_el2 {
                Ok(register)
            } else {
                Err(Outcome::Undefined)
            })
        };
        Some(Ok(match encoding {
            SPRR_CONFIG_EL1 => Apple::SprrConfig,
            SPRR_PERM_EL1 => Apple::SprrPerm(if at_el2 { PERM_EL2 } else { PERM_EL1 }),
            SPRR_PERM_EL12 => return el2(Apple::SprrPerm(PERM_EL1)),
            SPRR_PERM_EL0 => Apple::SprrPerm(if self.regime() == TranslationRegime::El20 {
                PERM_EL0_20
            } else {
                PERM_EL0_10
            }),
            SPRR_PERM_EL02 => return el2(Apple::SprrPerm(PERM_EL0_10)),
            SPRR_FIELDS_0 => Apple::SprrFields(0),
            SPRR_FIELDS_1 => Apple::SprrFields(1),
            GXF_CONFIG_EL1 => Apple::GxfConfig(level),
            GXF_CONFIG_EL12 => return el2(Apple::GxfConfig(0)),
            GXF_STATUS_EL1 => Apple::GxfStatus,
            GXF_ENTER_EL1 => Apple::GxfEntry(level, true),
            GXF_ABORT_EL1 => Apple::GxfEntry(level, false),
            GXF_ENTER_EL12 => return el2(Apple::GxfEntry(0, true)),
            GXF_ABORT_EL12 => return el2(Apple::GxfEntry(0, false)),
            VBAR_GL1 | SPSR_GL1 | ASPSR_GL1 | ESR_GL1 | ELR_GL1 | FAR_GL1 => {
                Apple::Guarded(level, encoding)
            }
            TPIDR_GL1 => Apple::TpidrGl(0),
            TPIDR_GL2 => return el2(Apple::TpidrGl(1)),
            VBAR_GL12 | SPSR_GL12 | ASPSR_GL12 | ESR_GL12 | ELR_GL12 | SP_GL12 => {
                return el2(Apple::GuardedOne(encoding));
            }
            APSTS_EL1 => Apple::ApStatus,
            APCTL_EL1 => Apple::ApControl(level),
            APCTL_EL2 => return el2(Apple::ApControl(1)),
            APCTL_EL12 => return el2(Apple::ApControl(0)),
            KERNELKEYLO_EL1 => Apple::KernelKey(0),
            KERNELKEYHI_EL1 => Apple::KernelKey(1),
            VMSA_LOCK_EL1 => Apple::VmsaLock,
            VM_TMR_FIQ_ENA_EL2 => return el2(Apple::VmTimerFiq),
            CNTVCT_ALIAS_EL0 => Apple::CountAlias,
            SPR_LOCKDOWN_EL2 => return el2(Apple::SprLockdown(false)),
            SPR_LOCKDOWN_COMMIT => return el2(Apple::SprLockdown(true)),
            _ => return None,
        }))
    }

    /// MRS or MSR to an encoding without an architectural accessor: Apple's
    /// IMPLEMENTATION DEFINED space, or UNDEFINED. `physical` is the system
    /// counter, for the count alias. `Read` results are not yet written to
    /// Rt.
    /// A reserved encoding of the feature ID space (op0 3, op1 0, CRn 0, CRm
    /// 1-7) without an architectural register. Such an encoding is RES0 from
    /// EL1 and EL2 (Arm's registers since allocated there were "unnamed and
    /// reserved, RES0 from EL1, EL2, and EL3"), HCR_EL2.TID3 traps EL1 reads
    /// of CRm 2-7 to EL2 under FEAT_FGT, EL0 reads trap with EC 0x18 under
    /// FEAT_IDST, and writes are UNDEFINED.
    fn reserved_id(&self, access: RegisterAccess) -> Option<Outcome> {
        const HCR_TID3: u32 = 18;
        let encoding = access.encoding();
        if (encoding.op0(), encoding.op1(), encoding.crn()) != (3, 0, 0)
            || !(1..=7).contains(&encoding.crm())
        {
            return None;
        }
        Some(if access.direction() != Direction::Read {
            Outcome::Undefined
        } else if self.pstate.el == 0 {
            Outcome::Trapped(None)
        } else if self.pstate.el == 1 && encoding.crm() >= 2 && self.hcr(HCR_TID3) {
            Outcome::Trapped(Some(2))
        } else {
            Outcome::Read(0)
        })
    }

    pub fn apple_access(&mut self, access: RegisterAccess, physical: u64) -> Outcome {
        let encoding = access.encoding();
        if let Some(outcome) = self.reserved_id(access) {
            return outcome;
        }
        if encoding.op0() != 3 || !matches!(encoding.crn(), 11 | 15) {
            // Unallocated architectural encodings.
            return Outcome::Undefined;
        }
        let read = access.direction() == Direction::Read;
        let value = if access.rt() == 31 {
            0
        } else {
            self.state.x[usize::from(access.rt())]
        };
        if self.pstate.el == 0 {
            return self.apple_el0(encoding, read, value, physical);
        }
        if self.pstate.el == 1 && !self.in_host() && self.hcr(HCR_TIDCP) {
            return Outcome::Trapped(Some(2));
        }
        if encoding.crn() == 11 {
            return Outcome::Refused(Refusal::UnsupportedSetting(
                "CRn=11 IMPLEMENTATION DEFINED register (CTRR, paused)",
            ));
        }
        if super::amx::Unit::owns(encoding) {
            let el = if self.regime() == TranslationRegime::El20 {
                2
            } else {
                1
            };
            return if read {
                self.amx.read(encoding, el).expect("checked")
            } else {
                self.amx.write(encoding, el, value).expect("checked")
            };
        }
        if let Some(pmu) = self.pmu.as_mut().filter(|_| Pmu::owns(encoding)) {
            let context = super::pmu::Context {
                el: self.pstate.el,
                waiting: false,
            };
            let retired = self.retired;
            let outcome = if read {
                pmu.read(encoding, physical, retired, context)
                    .map(Outcome::Read)
            } else {
                pmu.write(encoding, value, physical, retired, context)
                    .map(|()| {
                        Outcome::Written(Changes {
                            interrupts: true,
                            ..Changes::default()
                        })
                    })
            };
            return outcome
                .unwrap_or_else(|reason| Outcome::Refused(Refusal::UnsupportedSetting(reason)));
        }
        if let Some(entry) = impdef::lookup(encoding) {
            return if read {
                match self.apple.impdef.read(entry) {
                    Some(value) => Outcome::Read(value),
                    None => Outcome::Refused(Refusal::UnsupportedSetting(
                        "read of an implementation-defined storage register before its first write",
                    )),
                }
            } else {
                self.apple.impdef.write(entry, value);
                Outcome::Written(Changes::default())
            };
        }
        match self.apple(encoding) {
            Some(Ok(Apple::CountAlias)) if read => Outcome::Read(count_alias(self, physical)),
            Some(Ok(register)) if read => register.read(self),
            Some(Ok(register)) => register.write(self, value),
            Some(Err(outcome)) => outcome,
            None => Outcome::Refused(Refusal::Unimplemented),
        }
    }

    /// EL0 reaches only SPRR_PERM_EL0 (the user JIT toggle; Sven Peter,
    /// "Apple Silicon Hardware Secrets") and the counter alias, under the
    /// same enable as CNTVCT_EL0.
    fn apple_el0(&mut self, encoding: Encoding, read: bool, value: u64, physical: u64) -> Outcome {
        let register = Apple::SprrPerm(if self.in_host() {
            PERM_EL0_20
        } else {
            PERM_EL0_10
        });
        match encoding {
            SPRR_PERM_EL0 if read => register.read(self),
            SPRR_PERM_EL0 => register.write(self, value),
            CNTVCT_ALIAS_EL0 if !read => Outcome::Undefined,
            CNTVCT_ALIAS_EL0 => {
                let control = if self.in_host() {
                    Register::CNTHCTL_EL2
                } else {
                    Register::CNTKCTL_EL1
                };
                if self.field(control, EL0VCTEN, 1) == 0 {
                    Outcome::Trapped(None)
                } else {
                    Outcome::Read(count_alias(self, physical))
                }
            }
            _ => Outcome::Undefined,
        }
    }

    /// MSR (immediate), following Arm's `MSR (immediate)` decode for the
    /// profile: SPSel, PAN and UAO from EL1, DAIFSet, DAIFClr, DIT and SSBS
    /// from EL0, and with FEAT_SME SVCRSM, SVCRZA and SVCRSMZA (SMSTART and
    /// SMSTOP) from EL0 after `CheckSMEAccess`. Every other PSTATE field
    /// encoding is UNDEFINED, including those of features outside the
    /// profile (NMI, MTE and the EBEP family) and the EL2, EL3 and Secure
    /// op1 values. DAIFSet and DAIFClr
    /// at EL0 trap in the host or while SCTLR_EL1.UMA is clear, to EL2 under
    /// HCR_EL2.TGE (Arm `AArch64_CheckDAIFAccess`).
    pub fn write_pstate_field(&mut self, encoding: Encoding) -> Outcome {
        let immediate = encoding.crm();
        let bit = immediate & 1 != 0;
        let mut changes = Changes::default();
        let minimum = match (encoding.op1(), encoding.op2()) {
            (0, 3..=5) => 1,
            (3, 1 | 2 | 6 | 7) => 0,
            // CRm<3:1> selects SM, ZA or both; 0b000 and 0b1xx are
            // unallocated.
            (3, 3) if self.scalable.is_some() && matches!(immediate >> 1, 1..=3) => 0,
            _ => return Outcome::Undefined,
        };
        if self.pstate.el < minimum {
            return Outcome::Undefined;
        }
        match (encoding.op1(), encoding.op2()) {
            (3, op2 @ (6 | 7)) => {
                if self.pstate.el == 0
                    && (self.in_host()
                        || self.registers.get(Register::SCTLR_EL1, 0) & SCTLR_UMA == 0)
                {
                    return Outcome::Trapped(Some(if self.hcr(super::cpu::HCR_TGE) {
                        2
                    } else {
                        1
                    }));
                }
                if op2 == 6 {
                    self.pstate.daif |= immediate;
                } else {
                    self.pstate.daif &= !immediate;
                }
                changes.interrupts = true;
            }
            (0, 5) => {
                self.set_pstate(Pstate {
                    sp: bit,
                    ..self.pstate
                });
                changes.regime = true;
            }
            (0, 4) => {
                self.pstate.pan = bit;
                changes.regime = true;
            }
            (3, 3) => {
                if let Some(el) = self.sme_access_trap() {
                    return Outcome::SmeTrapped(el);
                }
                let svcr = self.svcr();
                let (streaming, za) = (svcr & 1 != 0, svcr & 2 != 0);
                let streaming = if immediate & 0b0010 != 0 {
                    bit
                } else {
                    streaming
                };
                let za = if immediate & 0b0100 != 0 { bit } else { za };
                if let Err(reason) = self.set_svcr(streaming, za) {
                    return Outcome::Refused(Refusal::UnsupportedSetting(reason));
                }
            }
            (0, 3) => self.pstate.uao = bit,
            (3, 2) => self.pstate.dit = bit,
            _ => self.pstate.ssbs = bit,
        }
        Outcome::Written(changes)
    }
}

/// ESR ISS of a trapped MSR, MRS, SYS or SYSL word (Arm
/// `AArch64_SystemAccessTrapSyndrome`, EC 0x18): Op0, Op2, Op1, CRn, Rt, CRm
/// and the direction straight from the instruction. MSR (immediate) reports
/// Op0 0 and Rt 31.
pub fn word_trap_iss(word: u32) -> u32 {
    let field = |shift: u32, bits: u32| (word >> shift) & ((1 << bits) - 1);
    field(19, 2) << 20
        | field(5, 3) << 17
        | field(16, 3) << 14
        | field(12, 4) << 10
        | field(0, 5) << 5
        | field(8, 4) << 1
        | field(21, 1)
}

impl Apple {
    fn read(self, cpu: &Cpu) -> Outcome {
        let apple = &cpu.apple;
        let sprr_enabled = apple.sprr_config & super::mmu::SPRR_CONFIG_EN != 0;
        Outcome::Read(match self {
            Self::SprrConfig => apple.sprr_config,
            Self::SprrPerm(_) if !sprr_enabled => return Outcome::Undefined,
            Self::SprrPerm(index) => apple.sprr_perm[index],
            Self::SprrFields(which) => apple.sprr_fields[which],
            Self::GxfConfig(level) => apple.gxf_config[level],
            Self::GxfStatus => u64::from(cpu.pstate.guarded),
            Self::GxfEntry(level, true) => apple.guarded[level].enter,
            Self::GxfEntry(level, false) => apple.guarded[level].abort,
            Self::Guarded(..) if !cpu.pstate.guarded => {
                return Outcome::Refused(Refusal::UnsupportedSetting(
                    "GL bank register outside the guarded level",
                ));
            }
            Self::Guarded(level, encoding) => bank_read(&apple.guarded[level], encoding),
            Self::GuardedOne(encoding) => bank_read(&apple.guarded[0], encoding),
            Self::TpidrGl(level) => apple.guarded[level].tpidr,
            Self::ApStatus => APSTS_MKEYVLD,
            Self::ApControl(level) => apple.apctl[level],
            Self::KernelKey(index) => apple.kernel_key[index],
            Self::VmsaLock => apple.vmsa_lock,
            Self::VmTimerFiq => apple.vm_timer_fiq,
            Self::CountAlias => unreachable!("the caller completes the count alias"),
            Self::SprLockdown(_) => {
                return Outcome::Refused(Refusal::UnsupportedSetting(
                    "read of a lockdown register no software reads",
                ));
            }
        })
    }

    fn write(self, cpu: &mut Cpu, value: u64) -> Outcome {
        use super::mmu::{
            SPRR_CONFIG_EN, SPRR_CONFIG_LOCK_CONFIG, SPRR_CONFIG_LOCK_PERM_EL0,
            SPRR_CONFIG_LOCK_PERM_EL1, SPRR_CONFIG_UNDOCUMENTED,
        };
        let mut changes = Changes::default();
        // The SPRR locks bind outside the guarded level only: SPTM 26A434
        // rewrites SPRR_CONFIG_EL1 and SPRR_PERM_EL1 from GL2 after setting
        // every lock (inference from that use).
        let guarded = cpu.pstate.guarded;
        let writer = cpu.pstate.el.max(1);
        let apple = &mut cpu.apple;
        let config = apple.sprr_config;
        let locked = |bit: u64| !guarded && config & bit != 0;
        let refuse = |reason| Outcome::Refused(Refusal::UnsupportedSetting(reason));
        if matches!(self, Self::SprrPerm(_) | Self::SprrFields(_))
            && locked(SPRR_CONFIG_UNDOCUMENTED)
        {
            return refuse("SPRR register write after an undocumented SPRR_CONFIG lock bit");
        }
        if matches!(self, Self::GxfConfig(1) | Self::GxfEntry(1, _))
            && !guarded
            && apple.gxf_config[1] & GXF_CONFIG_LOCKS != 0
        {
            return refuse("EL2 GXF register write after an undocumented GXF_CONFIG lock bit");
        }
        match self {
            Self::SprrConfig => {
                if locked(SPRR_CONFIG_LOCK_CONFIG) {
                    return refuse("SPRR_CONFIG_EL1 write after LOCK_CONFIG");
                }
                if value & !0xff != 0 {
                    return refuse("SPRR_CONFIG_EL1 bit without documented meaning");
                }
                apple.sprr_config = value;
                changes.translation = true;
            }
            Self::SprrPerm(_) if config & SPRR_CONFIG_EN == 0 => return Outcome::Undefined,
            Self::SprrPerm(index) => {
                let lock = if index == PERM_EL0_10 || index == PERM_EL0_20 {
                    SPRR_CONFIG_LOCK_PERM_EL0
                } else {
                    SPRR_CONFIG_LOCK_PERM_EL1
                };
                if locked(lock) {
                    return refuse("SPRR_PERM write after its lock");
                }
                apple.sprr_perm[index] = value;
                changes.translation = true;
            }
            Self::SprrFields(which) => {
                apple.sprr_fields[which] = value;
                changes.translation = true;
            }
            Self::GxfConfig(level) => {
                if value & !(GXF_CONFIG_EN | GXF_CONFIG_LOCKS | GXF_CONFIG_EL1_LOCK) != 0 {
                    return refuse("GXF_CONFIG bit without documented or observed meaning");
                }
                if level == 0
                    && !guarded
                    && value & GXF_CONFIG_EN != 0
                    && apple.gxf_config[1] & GXF_CONFIG_EL1_LOCK != 0
                {
                    return refuse("EL1 GXF enable after GXF_CONFIG bit 6");
                }
                apple.gxf_config[level] = value;
            }
            Self::GxfStatus | Self::ApStatus | Self::CountAlias => return Outcome::Undefined,
            Self::GxfEntry(level, true) => apple.guarded[level].enter = value,
            Self::GxfEntry(level, false) => apple.guarded[level].abort = value,
            Self::Guarded(..) if !guarded => {
                return refuse("GL bank register outside the guarded level");
            }
            Self::Guarded(level, encoding) => {
                bank_write(&mut apple.guarded[level], encoding, value)
            }
            Self::GuardedOne(encoding) => bank_write(&mut apple.guarded[0], encoding, value),
            Self::TpidrGl(level) => apple.guarded[level].tpidr = value,
            Self::ApControl(level) => apple.apctl[level] = value,
            Self::KernelKey(index) => apple.kernel_key[index] = value,
            Self::VmsaLock => {
                if value & !VMSA_LOCK_KNOWN != 0 {
                    return refuse("VMSA_LOCK_EL1 bit without documented meaning");
                }
                // A lock is not documented to be releasable.
                if apple.vmsa_lock & !value != 0 {
                    return refuse("VMSA_LOCK_EL1 write clearing a lock bit");
                }
                apple.vmsa_lock = value;
                apple.vmsa_lock_el = writer;
            }
            Self::VmTimerFiq => {
                if value & !(VM_TIMER_FIQ_VIRTUAL | VM_TIMER_FIQ_PHYSICAL) != 0 {
                    return refuse("VM_TMR_FIQ_ENA_EL2 bit without documented meaning");
                }
                apple.vm_timer_fiq = value;
                changes.interrupts = true;
            }
            Self::SprLockdown(false) => {
                if apple.spr_locked && apple.spr_lockdown != Some(value) {
                    return refuse("SPR_LOCKDOWN_EL2 change after its commit");
                }
                apple.spr_lockdown = Some(value);
            }
            Self::SprLockdown(true) => {
                if value & !1 != 0 {
                    return refuse("S3_4_C15_C12_5 bit without documented meaning");
                }
                if apple.spr_locked && value == 0 {
                    return refuse("S3_4_C15_C12_5 write releasing the SPR lockdown");
                }
                apple.spr_locked = value == 1;
            }
        }
        Outcome::Written(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::cpu::HCR_TGE;
    use stela_compiler::aarch64::system::registers::decode;

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
        decode(
            0xd510_0000
                | (u32::from(encoding.op0() & 1) << 19)
                | (u32::from(encoding.op1()) << 16)
                | (u32::from(encoding.crn()) << 12)
                | (u32::from(encoding.crm()) << 8)
                | (u32::from(encoding.op2()) << 5)
                | u32::from(read.rt()),
        )
        .unwrap()
    }

    #[test]
    fn sptms_gxf_finalization_locks_el2s_gxf_and_el1s_enable() {
        let mut cpu = Cpu::new(0, Pstate::reset(2));
        let write = |cpu: &mut Cpu, encoding, value| {
            cpu.state.x[5] = value;
            cpu.apple_access(msr(5, encoding), 0)
        };
        let written = |outcome| matches!(outcome, Outcome::Written(_));
        let refused = |outcome| matches!(outcome, Outcome::Refused(_));
        // SPTM enables GXF at EL2 and enters GL2.
        assert!(written(write(&mut cpu, SPRR_CONFIG_EL1, 1)));
        assert!(written(write(&mut cpu, GXF_CONFIG_EL1, 1)));
        assert!(cpu.guarded_enabled());
        cpu.pstate.guarded = true;
        // At GL2 it clears EL1's GXF and sets the undocumented bits.
        for encoding in [GXF_CONFIG_EL12, GXF_ENTER_EL12, GXF_ABORT_EL12] {
            assert!(written(write(&mut cpu, encoding, 0)));
        }
        assert!(written(write(&mut cpu, GXF_CONFIG_EL1, 0x6f)));
        assert_eq!(cpu.apple.gxf_config, [0, 0x6f]);
        assert_eq!(
            cpu.apple_access(mrs(0, GXF_CONFIG_EL1), 0),
            Outcome::Read(0x6f)
        );
        // Outside GL2, EL2's GXF registers and EL1's enable are locked, but
        // EL1's entry points are not.
        cpu.pstate.guarded = false;
        assert!(refused(write(&mut cpu, GXF_ENTER_EL1, 0x1000)));
        assert!(refused(write(&mut cpu, GXF_CONFIG_EL1, 0x6f)));
        assert!(refused(write(&mut cpu, GXF_CONFIG_EL12, 1)));
        assert!(written(write(&mut cpu, GXF_ENTER_EL12, 0x2000)));
        // Bits nobody sets refuse; EL1 reaches only its own configuration.
        let mut fresh = Cpu::new(0, Pstate::reset(2));
        assert!(refused(write(&mut fresh, GXF_CONFIG_EL1, 1 << 7)));
        let mut el1 = Cpu::new(0, Pstate::reset(1));
        assert_eq!(write(&mut el1, GXF_CONFIG_EL12, 0), Outcome::Undefined);
        assert!(written(write(&mut el1, GXF_CONFIG_EL1, 1)));
        assert_eq!(el1.apple.gxf_config, [1, 0]);
    }

    #[test]
    fn sptms_spr_lockdown_commits_at_el2_and_then_holds() {
        let mut cpu = Cpu::new(0, Pstate::reset(2));
        let write = |cpu: &mut Cpu, encoding, value| {
            cpu.state.x[5] = value;
            cpu.apple_access(msr(5, encoding), 0)
        };
        let written = |outcome| matches!(outcome, Outcome::Written(_));
        const MASK: u64 = 0x7fff_f7ff_ffff_ffef;
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_EL2, MASK)));
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_COMMIT, 1)));
        assert_eq!(
            (cpu.apple.spr_lockdown, cpu.apple.spr_locked),
            (Some(MASK), true)
        );
        // The same values again complete; a change or a release stops.
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_EL2, MASK)));
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_COMMIT, 1)));
        for (encoding, value) in [(SPR_LOCKDOWN_EL2, u64::MAX), (SPR_LOCKDOWN_COMMIT, 0)] {
            assert!(matches!(
                write(&mut cpu, encoding, value),
                Outcome::Refused(_)
            ));
        }
        // Undocumented bits and reads refuse; both are UNDEFINED below EL2.
        let mut fresh = Cpu::new(0, Pstate::reset(2));
        assert!(matches!(
            write(&mut fresh, SPR_LOCKDOWN_COMMIT, 2),
            Outcome::Refused(_)
        ));
        assert!(matches!(
            fresh.apple_access(mrs(0, SPR_LOCKDOWN_EL2), 0),
            Outcome::Refused(_)
        ));
        let mut el1 = Cpu::new(0, Pstate::reset(1));
        assert_eq!(write(&mut el1, SPR_LOCKDOWN_EL2, MASK), Outcome::Undefined);
    }

    #[test]
    fn apple_registers_follow_the_vhe_names_and_tidcp() {
        let mut cpu = Cpu::new(0, Pstate::reset(2));
        let write = |cpu: &mut Cpu, encoding, value| {
            cpu.state.x[5] = value;
            cpu.apple_access(msr(5, encoding), 0)
        };
        // At EL2, APCTL_EL1 names APCTL_EL2 and APCTL_EL12 names EL1's.
        write(&mut cpu, APCTL_EL1, 2);
        write(&mut cpu, APCTL_EL12, 1);
        assert_eq!(cpu.apple.apctl, [1, 2]);
        // GXF entry points per level.
        write(&mut cpu, GXF_ENTER_EL1, 0x2000);
        write(&mut cpu, GXF_ENTER_EL12, 0x1000);
        assert_eq!(
            (cpu.apple.guarded[0].enter, cpu.apple.guarded[1].enter),
            (0x1000, 0x2000)
        );
        // GL12 names reach GL1's bank from EL2; TPIDR_GL2 is GL2's.
        write(&mut cpu, VBAR_GL12, 0x8800);
        write(&mut cpu, TPIDR_GL2, 7);
        assert_eq!(cpu.apple.guarded[0].vbar, 0x8800);
        assert_eq!(cpu.apple.guarded[1].tpidr, 7);
        // SPRR permissions per regime.
        write(&mut cpu, SPRR_CONFIG_EL1, 1);
        write(&mut cpu, SPRR_PERM_EL1, 0x22);
        write(&mut cpu, SPRR_PERM_EL12, 0x11);
        assert_eq!(
            (cpu.apple.sprr_perm[PERM_EL1], cpu.apple.sprr_perm[PERM_EL2]),
            (0x11, 0x22)
        );
        // EL2 names are UNDEFINED at EL1, and TIDCP traps the space to EL2.
        let mut el1 = Cpu::new(0, Pstate::reset(1));
        assert_eq!(el1.apple_access(mrs(0, APCTL_EL12), 0), Outcome::Undefined);
        el1.registers.set(Register::HCR_EL2, 0, 1 << HCR_TIDCP);
        assert_eq!(
            el1.apple_access(mrs(0, APCTL_EL1), 0),
            Outcome::Trapped(Some(2))
        );
        // TGE puts EL0 in the host.
        el1.registers.set(Register::HCR_EL2, 0, 1 << HCR_TGE);
        assert_eq!(el1.regime(), TranslationRegime::El10);
        // VMSA_LOCK_EL1 locks the writer's TTBR1 and is not released.
        assert!(matches!(
            write(&mut cpu, VMSA_LOCK_EL1, VMSA_LOCK_TTBR1),
            Outcome::Written(_)
        ));
        assert!(vmsa_locked(&cpu, Register::TTBR1_EL2, 0).is_some());
        assert!(vmsa_locked(&cpu, Register::TTBR1_EL1, 0).is_none());
        assert!(matches!(
            write(&mut cpu, VMSA_LOCK_EL1, 0),
            Outcome::Refused(_)
        ));
        // Undefined architectural encodings outside CRn 11/15.
        assert_eq!(
            cpu.apple_access(mrs(0, Encoding::new(3, 0, 13, 7, 7)), 0),
            Outcome::Undefined
        );
    }

    #[test]
    fn sprr_locks_bind_outside_the_guarded_level() {
        let mut cpu = Cpu::new(0, Pstate::reset(2));
        let write = |cpu: &mut Cpu, encoding, value| {
            cpu.state.x[5] = value;
            cpu.apple_access(msr(5, encoding), 0)
        };
        write(&mut cpu, SPRR_CONFIG_EL1, 0xfb);
        assert!(matches!(
            write(&mut cpu, SPRR_PERM_EL1, 1),
            Outcome::Refused(_)
        ));
        assert!(matches!(
            write(&mut cpu, SPRR_FIELDS_0, 1),
            Outcome::Refused(_)
        ));
        cpu.pstate.guarded = true;
        assert!(matches!(
            write(&mut cpu, SPRR_PERM_EL1, 1),
            Outcome::Written(_)
        ));
        assert!(matches!(
            write(&mut cpu, SPRR_CONFIG_EL1, 0xff),
            Outcome::Written(_)
        ));
        assert!(matches!(
            write(&mut cpu, SPRR_FIELDS_0, 1 << 18),
            Outcome::Written(_)
        ));
        assert_eq!(cpu.apple.sprr_fields[0], 1 << 18);
    }
}
