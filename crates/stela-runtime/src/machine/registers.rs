//! Apple's IMPLEMENTATION DEFINED System registers and MSR (immediate).
//!
//! Architectural System registers and System instructions go through the
//! generated AARCHMRS accessors (`machine::system`). This module handles the
//! op0=3 CRn=15 space Apple uses: SPRR, GXF, the Apple PAC controls,
//! VMSA_LOCK_EL1, the VM timer FIQ enables, the Apple generic timer
//! (`machine::timer::agt`), AMX, the performance monitor (`machine::pmu`)
//! and the `machine::impdef` table. Every other encoding in
//! that space (CRn 11 and 15) that the chip's censused components access
//! refuses with its fields; one they never access is UNDEFINED.
//!
//! With EL2 present and HCR_EL2.E2H RES1, Apple's registers follow the VHE
//! pattern their names show (m1n1 `cpu_regs.h`): at EL2 the `*_EL1` and
//! `*_GL1` encodings reach the EL2 and GL2 state and the `*_EL12`, `*_EL02`
//! and `*_GL12` encodings reach the EL1 and GL1 state (inference from the
//! names and from m1n1 `gxf_asm.S`). HCR_EL2.TIDCP traps the whole
//! IMPLEMENTATION DEFINED space from EL1 to EL2.
use super::{
    cpu::{
        Cpu, GXF_CONFIG_EL1_LOCK, GXF_CONFIG_EN, GXF_CONFIG_LOCKS, GuardedBank, HCR_VM,
        PERM_EL0_10, PERM_EL0_20, PERM_EL1, PERM_EL2, TranslationRegime, VM_TIMER_FIQ_PHYSICAL,
        VM_TIMER_FIQ_VIRTUAL,
    },
    exception::Pstate,
    impdef,
    pmu::Pmu,
    system::{Feature, Register},
    timer::agt,
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
    /// The PE's caches, where the SoC row and DeviceTree describe them;
    /// without them CLIDR_EL1 and CCSIDR_EL1 take the profile's values.
    pub caches: Option<super::caches::Caches>,
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
        AMCFGR_EL0 = 3, 3, 13, 2, 1;
        AMCGCR_EL0 = 3, 3, 13, 2, 2;
        AMCG1IDR_EL0 = 3, 3, 13, 2, 6;
        CCSIDR_EL1 = 3, 1, 0, 0, 0;
        CLIDR_EL1 = 3, 1, 0, 0, 1;
        AIDR_EL1 = 3, 1, 0, 0, 7;
        CTR_EL0 = 3, 3, 0, 0, 1;
        DCZID_EL0 = 3, 3, 0, 0, 7;
        GMID_EL1 = 3, 1, 0, 0, 4;
        FPCR = 3, 3, 4, 4, 0;
        FPSR = 3, 3, 4, 4, 1;
        TPIDR_EL0 = 3, 3, 13, 0, 2;
        TPIDRRO_EL0 = 3, 3, 13, 0, 3;
        TPIDR_EL1 = 3, 0, 13, 0, 4;
        TPIDR_EL2 = 3, 4, 13, 0, 2;
        DAIF = 3, 3, 4, 2, 1;
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
        // No public name: GL1's FAR from EL2, where FAR_GL1's encoding
        // (C10_7) follows ELR_GL1's (C10_6) as C9_7 follows ELR_GL12's;
        // 26A434 XNU's hypervisor saves and restores it with the other GL12
        // registers (0xfffffe000bd9edbc, 0xfffffe000bda2b94; inference).
        FAR_GL12 = 3, 6, 15, 9, 7;
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
        // m1n1 apple_regs.json ACNTPCT_EL0, physical timer counter
        // (pre-spec CNTPCTSS_EL0); matching original LLB/iBoot read it
        // beside CNTP_TVAL/CTL and CNTFRQ. Source-qualified here at EL2.
        ACNTPCT_EL0 = 3, 4, 15, 10, 5;
        // m1n1 `cpu_regs.h` "Lockdown registers"; the commit register has no
        // public name (see `Apple::SprLockdown`).
        SPR_LOCKDOWN_EL2 = 3, 4, 15, 0, 5;
        SPR_LOCKDOWN_EL1 = 3, 4, 15, 0, 6;
        SPR_LOCKDOWN_COMMIT = 3, 4, 15, 12, 5;
        CYC_OVRD = 3, 5, 15, 5, 0;
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
    /// The write took a value whose effect this machine does not model
    /// (`impdef::Entry::unmodeled_effect`): what is missing, which the
    /// engine reports once, or stops at in strict mode.
    pub unmodeled: Option<&'static str>,
    /// SIQ_CFG_EL1 now refuses (`true`) or accepts the AIC's IRQs for this
    /// PE ([`SIQ_CFG_NO_IRQ`]).
    pub irq_steering: Option<bool>,
}

/// SIQ_CFG_EL1's mode, bits 1:0, of which 3 keeps the AICv2 from sending
/// the core IRQs, while FIQs, part of the core complex, are unaffected
/// (Asahi `hw/cpu/system-registers.md`, "s3_4_c15_c10_4 (labeled
/// SIQ_CFG_EL1 in m1n1)"); m1n1 writes 2 (`chickens.c`). 26A434 XNU sets
/// the mode per thread at context switch, 3 for a thread its
/// `siq_realtime_thread_mode` selects unless the CPU runs its idle thread
/// (kernelcache.release.mac14g 0xfffffe000bd7c388..0xfffffe000bd7c3d0).
pub const SIQ_CFG_MODE: u64 = 0b11;
pub const SIQ_CFG_NO_IRQ: u64 = 0b11;

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
    /// A view of the architectural register at this encoding in this
    /// timer bank (`timer::agt`): the engine runs its generated accessor on
    /// the bank, and a trap reports the encoding the instruction names.
    View(Encoding, agt::Bank),
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

pub(crate) const HCR_TIDCP: u32 = 20;
const SCTLR_UMA: u64 = 1 << 9;
/// APSTS_EL1.MKEYVld: the hardware master key is ready. This machine has no
/// key-generation delay, so the bit always reads as set.
const APSTS_MKEYVLD: u64 = 1;
/// CNTKCTL_EL1.EL0VCTEN, at the same bit in CNTHCTL_EL2 with E2H set.
const EL0VCTEN: u32 = 1;

/// CYC_OVRD fields (m1n1 `cpu_regs.h` `CYC_OVRD_*`; XNU `xnu-6153.141.1`
/// `arm64_common.h` `ARM64_REG_CYC_OVRD_*`): the FIQ and IRQ modes, of which
/// XNU uses 0 and 2 (`fiq_disable`, `irq_disable`, set before powering the
/// core down "to avoid spurious wakeups"); the WFI mode, 2 forcing WFI to
/// clock gating (`ok2pwrdn_force_up`) and 3 letting it power the core down
/// (`ok2pwrdn_force_down`); and `disWfiRetn`, which forbids the retention
/// state. Bits 30 and 31 keep the core from fetching the timebase
/// (`dsblSnoopTime`) and stop, as does every unnamed bit or mode.
const CYC_OVRD_RETENTION_DISABLE: u64 = 1;
const CYC_OVRD_FIQ_SHIFT: u32 = 20;
const CYC_OVRD_IRQ_SHIFT: u32 = 22;
const CYC_OVRD_WFI_SHIFT: u32 = 24;
const CYC_OVRD_DISABLE: u64 = 2;
const CYC_OVRD_WFI_CLOCK_GATE: u64 = 2;
pub const CYC_OVRD_WFI_POWER_DOWN: u64 = 3;
const CYC_OVRD_KNOWN: u64 = CYC_OVRD_RETENTION_DISABLE | 0b11_1111 << CYC_OVRD_FIQ_SHIFT;

/// A two-bit CYC_OVRD field.
const fn cyc_ovrd_field(value: u64, shift: u32) -> u64 {
    value >> shift & 0b11
}

impl Cpu {
    /// CYC_OVRD's WFI mode.
    pub fn wfi_mode(&self) -> u64 {
        cyc_ovrd_field(self.apple.cyc_ovrd, CYC_OVRD_WFI_SHIFT)
    }

    /// The interrupt lines this core takes and wakes for: the device lines
    /// with the vGIC maintenance interrupt on IRQ (`machine::vgic`), which
    /// CYC_OVRD's FIQ and IRQ disable modes keep the core from seeing.
    pub fn core_lines(&self, lines: Lines) -> Lines {
        self.enabled_lines(Lines {
            irq: lines.irq || self.vgic.maintenance_asserted(),
            fiq: lines.fiq,
        })
    }

    /// Whether device `lines` wake this core from CYC_OVRD's power-down
    /// mode: a line its FIQ or IRQ mode does not disable asserts.
    pub fn wakes_for(&self, lines: Lines) -> bool {
        let lines = self.enabled_lines(lines);
        lines.irq || lines.fiq
    }

    fn enabled_lines(&self, lines: Lines) -> Lines {
        let enabled = |shift| cyc_ovrd_field(self.apple.cyc_ovrd, shift) != CYC_OVRD_DISABLE;
        Lines {
            irq: lines.irq && enabled(CYC_OVRD_IRQ_SHIFT),
            fiq: lines.fiq && enabled(CYC_OVRD_FIQ_SHIFT),
        }
    }
}

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
    PointerKey(super::pointer_keys::Register),
    VmsaLock,
    VmTimerFiq,
    CountAlias,
    PhysicalCountAlias,
    /// AGTCNTRDIR of the EL1&0 (0) or EL2&0 (1) regime.
    TimerRedirect(usize),
    /// SPR_LOCKDOWN_EL2 (0) or SPR_LOCKDOWN_EL1 (1), XNU's `MSR_RO_CTL`
    /// ([`SPR_LOCK_GROUPS`]), each committed by its bit of
    /// [`Apple::SprCommit`].
    SprLockdown(usize),
    /// `S3_4_C15_C12_5`, XNU's `MSR_LOCK` (`MSR_LOCK_VAL` bit 0 commits).
    SprCommit,
    CycleOverride,
}

/// The SPR lockdown (XNU `xnu-7195.141.2` `pexpert/pexpert/arm64/spr_locks.h`,
/// `HAS_TWO_STAGE_SPR_LOCK`: "SPR locks are split into RO_CTL and LOCK
/// registers"). Bit n of `MSR_RO_CTL` makes register group n read-only once
/// bit 0 of `MSR_LOCK` commits it. XNU's value leaves bits 4 (HID4), 27
/// (CYC_OVRD) and 47 (ACC_OVRD) writable, and every 26A434 SPTM of the M1 to
/// M3 families writes it to SPR_LOCKDOWN_EL2 (`S3_4_C15_C0_5`, m1n1) as
/// 0xffff_7fff_f7ff_ffef, or on some M3 parts with bit 47 also set
/// (sptm.t8122 file 0xbbf44..0xbbf70). The M3 SPTMs then write all ones to
/// SPR_LOCKDOWN_EL1 (`S3_4_C15_C0_6`) and commit with 3 instead of 1
/// (file 0xbbf74..0xbbf80): bit 1 commits that second bank (inferred from
/// the pairing; which registers it guards is not established, so none is
/// read-only through it). No SPTM reads either bank. XNU's lock test writes
/// a locked HID8 and expects a synchronous abort that `sleh.c` takes as
/// `ESR_EC_UNCATEGORIZED` with ISS 0, and HID8 unchanged
/// (`osfmk/arm64/platform_tests.c` `arm64_spr_lock_test`): so a committed
/// group's write is UNDEFINED, at every EL. Both banks read what was
/// written, 0 from reset (Asahi `hw/cpu/system-register-dumps.md`: 0 under
/// m1n1, and the written value under Darwin 20.3, less bits the M1 does not
/// implement, which this model keeps). The M4 and later SPTMs write
/// neither, and the M4-and-later AppleProcessorTrace `defeatureCore`
/// clears bits 1, 53 and 54 of SPR_LOCKDOWN_EL2 before writing HID1 or
/// EHID1 (kernelcache.release.mac16g 0xfffffe0009cb46a8..0xfffffe0009cb4708).
/// A change of a committed bank or commit bit has no documented outcome and
/// stops.
const SPR_LOCK_COMMIT_BITS: u64 = 0b11;

/// The registers whose SPR lockdown group is established: HID1 and HID4 by
/// XNU's `MSR_RO_CTL_HID1` and `MSR_RO_CTL_HID4`, EHID1 by `defeatureCore`
/// clearing bit 1 to write it, CYC_OVRD and ACC_OVRD by XNU's names, and
/// EHID4 with HID4 (inference: 26A434 XNU writes it on E cores after the
/// lockdown). HID8, which XNU's test shows locked, is UNDEFINED here
/// already: no 26A434 component accesses it. Other registers' groups are not
/// public, so the lockdown leaves them writable (docs/design/system.md).
const SPR_LOCK_GROUPS: [(Encoding, u32); 6] = [
    (impdef::HID1, 1),
    (impdef::EHID1, 1),
    (impdef::HID4, 4),
    (impdef::EHID4, 4),
    (CYC_OVRD, 27),
    (impdef::ACC_OVRD, 47),
];

impl Cpu {
    /// Whether SPR_LOCKDOWN_EL2's committed groups make `encoding` read-only.
    fn spr_read_only(&self, encoding: Encoding) -> bool {
        self.apple.spr_commit & 1 != 0
            && SPR_LOCK_GROUPS.iter().any(|&(locked, group)| {
                locked == encoding && self.apple.spr_lockdown[0] >> group & 1 != 0
            })
    }
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
        if let Some(name) = agt::decode(encoding, self.registers.chip()) {
            let apple = |architectural| Some(Err(Outcome::View(architectural, agt::Bank::Apple)));
            return match name {
                agt::Name::View(architectural) => apple(architectural),
                agt::Name::Redirect { el12: true } => el2(Apple::TimerRedirect(0)),
                agt::Name::Redirect { el12: false } => Some(Ok(Apple::TimerRedirect(level))),
                agt::Name::NoRedirectControl => apple(agt::no_redirect_control(self.pstate.el)),
            };
        }
        if let Some(register) = super::pointer_keys::Register::decode(encoding) {
            return Some(if at_el2 {
                Ok(Apple::PointerKey(register))
            } else {
                Err(Outcome::Refused(Refusal::UnsupportedSetting(
                    "Apple EL2 PAC key access below EL2 lacks permission qualification",
                )))
            });
        }
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
            VBAR_GL12 | SPSR_GL12 | ASPSR_GL12 | ESR_GL12 | ELR_GL12 | FAR_GL12 | SP_GL12 => {
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
            ACNTPCT_EL0 if !at_el2 => {
                return Some(Err(Outcome::Refused(Refusal::UnsupportedSetting(
                    "ACNTPCT_EL0 access below EL2 lacks permission qualification",
                ))));
            }
            ACNTPCT_EL0 => Apple::PhysicalCountAlias,
            SPR_LOCKDOWN_EL2 => return el2(Apple::SprLockdown(0)),
            SPR_LOCKDOWN_EL1 => return el2(Apple::SprLockdown(1)),
            SPR_LOCKDOWN_COMMIT => return el2(Apple::SprCommit),
            CYC_OVRD => Apple::CycleOverride,
            _ => return None,
        }))
    }

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

    /// An access to a CTRR register (`machine::ctrr`) at EL1 or EL2.
    fn ctrr_access(&mut self, register: super::ctrr::Register, read: bool, value: u64) -> Outcome {
        use super::ctrr::{Holder, Register as Ctrr};
        let el = self.pstate.el;
        let mut cluster = self.ctrr.borrow_mut();
        let written = |result: Result<Option<&'static str>, &'static str>| match result {
            Ok(unmodeled) => Outcome::Written(Changes {
                translation: true,
                unmodeled,
                ..Changes::default()
            }),
            Err(reason) => Outcome::Refused(Refusal::UnsupportedSetting(reason)),
        };
        let el2_only = matches!(
            register,
            Ctrr::A { level: 1, .. } | Ctrr::Legacy { cluster: true, .. }
        );
        if el2_only && el != 2 {
            return Outcome::Undefined;
        }
        match register {
            Ctrr::A { level, field } if read => Outcome::Read(cluster.read(level, field)),
            Ctrr::A { level, field } => written(cluster.write(level, field, value).map(|()| None)),
            Ctrr::Legacy {
                cluster: per_cluster,
                index,
            } => {
                let bank = if per_cluster {
                    &mut cluster.copies
                } else {
                    &mut self.ctrr_core.el1
                };
                if read {
                    Outcome::Read(bank.legacy[index])
                } else {
                    written(bank.write_legacy(index, value).map(|()| None))
                }
            }
            Ctrr::Region {
                view,
                region,
                field,
            } => {
                let Some(holder) = view.holder(el) else {
                    return Outcome::Undefined;
                };
                let bank = match holder {
                    Holder::Cluster => &mut cluster.copies,
                    core => self.ctrr_core.bank(core).expect("a per-core copy"),
                };
                if read {
                    Outcome::Read(bank.read(region, field))
                } else {
                    written(bank.write(region, field, value))
                }
            }
        }
    }

    /// TAG_OFFSET_EL2 (`machine::tag_storage`): the value iBoot locked, the
    /// same on every PE. Software after the handoff only reads it; a write
    /// changing a locked value refuses, and one to an unprogrammed register
    /// (no handoff) is not modeled.
    fn tag_offset_access(&self, read: bool, value: u64) -> Outcome {
        let current = self.core_locks.tag_offset;
        if self.pstate.el != 2 {
            Outcome::Undefined
        } else if read {
            Outcome::Read(current)
        } else if current & super::tag_storage::LOCK == 0 {
            Outcome::Refused(Refusal::UnsupportedSetting(
                "TAG_OFFSET_EL2 write without the boot firmware's locked value",
            ))
        } else if value == current {
            Outcome::Written(Changes::default())
        } else {
            Outcome::Refused(Refusal::UnsupportedSetting(
                "TAG_OFFSET_EL2 change after its lock",
            ))
        }
    }

    /// MRS or MSR to an encoding without an architectural accessor: Apple's
    /// IMPLEMENTATION DEFINED space, or UNDEFINED. `physical` is the system
    /// counter, for the count alias. `Read` results are not yet written to
    /// Rt.
    ///
    /// In the IMPLEMENTATION DEFINED space (CRn 11 and 15), an encoding with
    /// no model that the chip's censused components access
    /// ([`impdef::consumed`]) refuses by name: its consumer expects an
    /// effect no source defines. One no censused component accesses is
    /// UNDEFINED, as Arm makes an unallocated encoding: an inference from
    /// the census, which an M2 enumeration of the space could overturn.
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
        if !read && self.spr_read_only(encoding) {
            return Outcome::Undefined;
        }
        if let Some(register) = super::ctrr::decode(self.registers.chip(), encoding) {
            return self.ctrr_access(register, read, value);
        }
        if super::tag_storage::owns(self.registers.chip(), encoding) {
            return self.tag_offset_access(read, value);
        }
        if Pmu::owns_on(self.registers.chip(), encoding) {
            let Some(pmu) = self.pmu.as_mut() else {
                return Outcome::Refused(Refusal::UnsupportedSetting(
                    "CPMU access requires an explicit PE clock in the CPU profile",
                ));
            };
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
        let consumed = impdef::consumed(encoding, self.registers.chip());
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
        if let Some(entry) = impdef::lookup(encoding, self.registers.chip()) {
            if entry.el2 && self.pstate.el != 2 {
                return Outcome::Undefined;
            }
            // The guarded level's HPFAR would hold a stage-2 fault's IPA,
            // which can arise only while stage 2 is enabled.
            if entry.encoding == impdef::GUARDED_HPFAR && self.hcr(HCR_VM) {
                return Outcome::Refused(Refusal::UnsupportedSetting(
                    "the guarded level's HPFAR while HCR_EL2.VM enables stage 2",
                ));
            }
            if entry.class == impdef::Class::Energy {
                return if read {
                    let activity = impdef::Activity {
                        count: physical,
                        frequency: super::timer::system_frequency(self),
                        mpidr: self.read(Register::MPIDR_EL1),
                    };
                    match self.apple.impdef.energy(entry, activity) {
                        Ok(value) => Outcome::Read(value),
                        Err(reason) => Outcome::Refused(Refusal::UnsupportedSetting(reason)),
                    }
                } else {
                    match self.apple.impdef.write(entry, value) {
                        Ok(()) => Outcome::Written(Changes::default()),
                        Err(reason) => Outcome::Refused(Refusal::UnsupportedSetting(reason)),
                    }
                };
            }
            return self.impdef_access(entry, read, value);
        }
        if encoding.crn() == 11 {
            return if consumed {
                Outcome::Refused(Refusal::UnsupportedSetting(
                    "CRn=11 IMPLEMENTATION DEFINED register without a model",
                ))
            } else {
                Outcome::Undefined
            };
        }
        match self.apple(encoding) {
            Some(Ok(Apple::CountAlias)) if read => Outcome::Read(count_alias(self, physical)),
            Some(Ok(Apple::PhysicalCountAlias)) if read => Outcome::Read(physical),
            Some(Ok(register)) if read => register.read(self),
            Some(Ok(register)) => register.write(self, value),
            Some(Err(outcome)) => outcome,
            None if consumed => Outcome::Refused(Refusal::Unimplemented),
            None => Outcome::Undefined,
        }
    }

    /// A read or write of a `machine::impdef` entry.
    fn impdef_access(&mut self, entry: &'static impdef::Entry, read: bool, value: u64) -> Outcome {
        if read {
            return match self.apple.impdef.read(entry) {
                Ok(value) => Outcome::Read(value),
                Err(reason) => Outcome::Refused(Refusal::UnsupportedSetting(reason)),
            };
        }
        match self.apple.impdef.write(entry, value) {
            Ok(()) => Outcome::Written(Changes {
                unmodeled: entry.unmodeled_effect(value),
                irq_steering: (entry.encoding == impdef::SIQ_CFG_EL1)
                    .then_some(value & SIQ_CFG_MODE == SIQ_CFG_NO_IRQ),
                ..Changes::default()
            }),
            Err(reason) => Outcome::Refused(Refusal::UnsupportedSetting(reason)),
        }
    }

    /// EL0 reaches only SPRR_PERM_EL0 (the user JIT toggle; Sven Peter,
    /// "Apple Silicon Hardware Secrets"), the counter alias, under the same
    /// enable as CNTVCT_EL0, the Apple generic timer's views of EL0
    /// registers, under their architectural registers' enables, and
    /// JCTL_EL0 on the chips whose components use it. XNU's user MSR test
    /// (`xnu-12377.121.6` `tests/user_msrs.c`) skips JCTL_EL0 and TPIDR_EL0
    /// alone as registers EL0 is meant to write, which the kernel context
    /// switches; every other implementation-defined register it probes must
    /// fault at EL0 or not hold a value across a switch. So the others stay
    /// UNDEFINED: AFPCR_EL0 is EL0 by name only, and `S3_5_C15_C10_1`, which
    /// the kernel clears at every context switch and qemu-t8030 gives EL0
    /// access on the A13, is unestablished on these chips.
    fn apple_el0(&mut self, encoding: Encoding, read: bool, value: u64, physical: u64) -> Outcome {
        if let Some(agt::Name::View(architectural)) = agt::decode(encoding, self.registers.chip()) {
            return Outcome::View(architectural, agt::Bank::Apple);
        }
        if super::pointer_keys::Register::decode(encoding).is_some() {
            return Outcome::Refused(Refusal::UnsupportedSetting(
                "Apple EL2 PAC key access below EL2 lacks permission qualification",
            ));
        }
        let register = Apple::SprrPerm(if self.in_host() {
            PERM_EL0_20
        } else {
            PERM_EL0_10
        });
        match encoding {
            SPRR_PERM_EL0 if read => register.read(self),
            SPRR_PERM_EL0 => register.write(self, value),
            ACNTPCT_EL0 => Outcome::Refused(Refusal::UnsupportedSetting(
                "ACNTPCT_EL0 access below EL2 lacks permission qualification",
            )),
            impdef::JCTL_EL0 => match impdef::lookup(encoding, self.registers.chip()) {
                Some(entry) => self.impdef_access(entry, read, value),
                None => Outcome::Undefined,
            },
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
    /// from EL0, with FEAT_MTE TCO from EL0, and with FEAT_SME SVCRSM, SVCRZA
    /// and SVCRSMZA (SMSTART and SMSTOP) from EL0 after `CheckSMEAccess`.
    /// Every other PSTATE field encoding is UNDEFINED, including those of
    /// features outside the profile (NMI and the EBEP family) and the EL2,
    /// EL3 and Secure op1 values. DAIFSet and DAIFClr
    /// at EL0 trap in the host or while SCTLR_EL1.UMA is clear, to EL2 under
    /// HCR_EL2.TGE (Arm `AArch64_CheckDAIFAccess`).
    pub fn write_pstate_field(&mut self, encoding: Encoding) -> Outcome {
        let immediate = encoding.crm();
        let bit = immediate & 1 != 0;
        let mut changes = Changes::default();
        let minimum = match (encoding.op1(), encoding.op2()) {
            (0, 3..=5) => 1,
            (3, 1 | 2 | 6 | 7) => 0,
            (3, 4) => match self.registers.implemented(Feature::FEAT_MTE) {
                Ok(true) => 0,
                Ok(false) => return Outcome::Undefined,
                Err(reason) => return Outcome::Refused(Refusal::UnsupportedSetting(reason)),
            },
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
            // PSTATE.TCO decides which accesses are tag checked.
            (3, 4) => {
                self.pstate.tco = bit;
                changes.regime = true;
            }
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
            Self::PointerKey(_) => {
                return Outcome::Refused(Refusal::UnsupportedSetting(
                    "Apple EL2 PAC key read permission is unqualified",
                ));
            }
            Self::VmsaLock => apple.vmsa_lock,
            Self::VmTimerFiq => apple.vm_timer_fiq,
            Self::TimerRedirect(regime) => apple.generic_timer.redirect(regime),
            Self::CountAlias | Self::PhysicalCountAlias => {
                unreachable!("the caller completes the count alias")
            }
            Self::SprLockdown(bank) => apple.spr_lockdown[bank],
            Self::SprCommit => apple.spr_commit,
            Self::CycleOverride => apple.cyc_ovrd,
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
        if matches!(self, Self::SprrFields(_)) && locked(SPRR_CONFIG_UNDOCUMENTED) {
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
                let user = index == PERM_EL0_10 || index == PERM_EL0_20;
                let (lock, fields) = if user {
                    (SPRR_CONFIG_LOCK_PERM_EL0, apple.sprr_fields[0])
                } else {
                    (SPRR_CONFIG_LOCK_PERM_EL1, apple.sprr_fields[1])
                };
                let changed = apple.sprr_perm[index] ^ value;
                if (locked(lock) || locked(SPRR_CONFIG_UNDOCUMENTED))
                    && changed & !super::mmu::sprr_unlocked(fields) != 0
                {
                    return refuse(
                        "SPRR_PERM change outside its unlocked EL fields after its lock",
                    );
                }
                apple.sprr_perm[index] = value;
                changes.translation = true;
            }
            Self::SprrFields(which) => apple.sprr_fields[which] = value,
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
            Self::GxfStatus | Self::ApStatus | Self::CountAlias | Self::PhysicalCountAlias => {
                return Outcome::Undefined;
            }
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
            Self::PointerKey(register) => apple.pointer_keys.write(register, value),
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
            Self::TimerRedirect(regime) => {
                changes.unmodeled = apple.generic_timer.set_redirect(regime, value);
            }
            Self::SprLockdown(bank) => {
                if apple.spr_commit >> bank & 1 != 0 && apple.spr_lockdown[bank] != value {
                    return refuse("SPR lockdown bank change after its commit");
                }
                apple.spr_lockdown[bank] = value;
            }
            Self::SprCommit => {
                if value & !SPR_LOCK_COMMIT_BITS != 0 {
                    return refuse("S3_4_C15_C12_5 bit without documented or observed meaning");
                }
                if apple.spr_commit & !value != 0 {
                    return refuse("S3_4_C15_C12_5 write releasing an SPR lockdown commit");
                }
                apple.spr_commit = value;
            }
            Self::CycleOverride => {
                let mode = |shift| cyc_ovrd_field(value, shift);
                if value & !CYC_OVRD_KNOWN != 0 {
                    return refuse("CYC_OVRD bit without public description");
                }
                if [CYC_OVRD_FIQ_SHIFT, CYC_OVRD_IRQ_SHIFT]
                    .into_iter()
                    .any(|shift| !matches!(mode(shift), 0 | CYC_OVRD_DISABLE))
                {
                    return refuse("CYC_OVRD FIQ or IRQ mode without public description");
                }
                if !matches!(
                    mode(CYC_OVRD_WFI_SHIFT),
                    0 | CYC_OVRD_WFI_CLOCK_GATE | CYC_OVRD_WFI_POWER_DOWN
                ) {
                    return refuse("CYC_OVRD WFI mode without public description");
                }
                apple.cyc_ovrd = value;
                changes.interrupts = true;
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
    fn physical_count_alias_uses_actual_supplied_time_without_virtual_offset_or_tuning_coupling() {
        for chip in super::super::Chip::ALL {
            let mut cpu = Cpu::of(chip, 0, Pstate::reset(2));
            cpu.registers.set(Register::CNTVOFF_EL2, 0, 0x1234);
            // SIQ_CFG is a separate retained tuning word, not a count reset.
            let siq = impdef::SIQ_CFG_EL1;
            for tuning in [0, 2, 0] {
                cpu.state.x[5] = tuning;
                assert!(matches!(
                    cpu.apple_access(msr(5, siq), 0),
                    Outcome::Written(_)
                ));
                for physical in [0, 0x9876_5432_1234_5678, u64::MAX] {
                    assert_eq!(
                        cpu.apple_access(mrs(0, ACNTPCT_EL0), physical),
                        Outcome::Read(physical)
                    );
                    assert_eq!(cpu.read(Register::CNTVOFF_EL2), 0x1234);
                }
            }
            assert_eq!(
                cpu.apple_access(msr(5, ACNTPCT_EL0), 99),
                Outcome::Undefined
            );
            assert_eq!(
                cpu.apple_access(mrs(0, ACNTPCT_EL0), 100),
                Outcome::Read(100)
            );
        }
    }

    #[test]
    fn unqualified_lower_el_physical_alias_permissions_remain_named_for_both_directions() {
        for el in [0, 1] {
            let mut cpu = Cpu::new(0, Pstate::reset(el));
            for control in [0, u64::MAX] {
                cpu.registers.set(Register::CNTKCTL_EL1, 0, control);
                cpu.registers.set(Register::CNTHCTL_EL2, 0, control);
                for access in [mrs(0, ACNTPCT_EL0), msr(0, ACNTPCT_EL0)] {
                    assert_eq!(
                        cpu.apple_access(access, 123),
                        Outcome::Refused(Refusal::UnsupportedSetting(
                            "ACNTPCT_EL0 access below EL2 lacks permission qualification"
                        ))
                    );
                }
            }
        }
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
    fn cyc_ovrd_takes_xnus_sleep_and_restart_settings() {
        let mut cpu = Cpu::new(0, Pstate::reset(2));
        let mut write = |value| {
            cpu.state.x[5] = value;
            cpu.apple_access(msr(5, CYC_OVRD), 0)
        };
        let written = |outcome| matches!(outcome, Outcome::Written(_));
        // `ml_arm_sleep`: IRQ and FIQ disabled, then power-down with
        // retention disabled.
        assert!(written(write(0xa0_0000)));
        assert!(written(write(0x3a0_0001)));
        for value in [1 << 30, 1 << 20, 3 << 22, 1 << 24, 1 << 5] {
            assert!(matches!(write(value), Outcome::Refused(_)), "{value:#x}");
        }
        assert_eq!(
            cpu.apple_access(mrs(0, CYC_OVRD), 0),
            Outcome::Read(0x3a0_0001)
        );
        assert_eq!(cpu.wfi_mode(), CYC_OVRD_WFI_POWER_DOWN);
        let both = Lines {
            irq: true,
            fiq: true,
        };
        assert_eq!(cpu.core_lines(both), Lines::default());
        // The restart path clears both modes; `arm64_force_wfi_clock_gate`.
        cpu.state.x[5] = 0x200_0000;
        assert!(written(cpu.apple_access(msr(5, CYC_OVRD), 0)));
        assert_eq!(cpu.core_lines(both), both);
        assert_eq!(cpu.wfi_mode(), CYC_OVRD_WFI_CLOCK_GATE);
    }

    #[test]
    fn sptms_spr_lockdown_commits_at_el2_and_then_holds() {
        use super::super::Chip;
        let write = |cpu: &mut Cpu, encoding, value| {
            cpu.state.x[5] = value;
            cpu.apple_access(msr(5, encoding), 0)
        };
        let written = |outcome| matches!(outcome, Outcome::Written(_));
        // XNU's MSR_RO_CTL_VAL, which the M1 and M2 SPTMs write: every
        // bit but 4, 27 and 47.
        const RO_CTL: u64 = 0xffff_7fff_f7ff_ffef;
        let mut cpu = Cpu::of(Chip::AppleM2, 0, Pstate::reset(2));
        assert_eq!(
            cpu.apple_access(mrs(0, SPR_LOCKDOWN_EL2), 0),
            Outcome::Read(0)
        );
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_EL2, RO_CTL)));
        // Before the commit every group is writable.
        assert!(written(write(&mut cpu, impdef::HID1, 0)));
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_COMMIT, 1)));
        assert_eq!(
            cpu.apple_access(mrs(0, SPR_LOCKDOWN_EL2), 0),
            Outcome::Read(RO_CTL)
        );
        assert_eq!(
            cpu.apple_access(mrs(0, SPR_LOCKDOWN_COMMIT), 0),
            Outcome::Read(1)
        );
        // A committed group's write is UNDEFINED and changes nothing; reads
        // and the groups XNU leaves writable complete.
        cpu.state.x[5] = 0x55;
        assert_eq!(
            cpu.apple_access(msr(5, impdef::HID1), 0),
            Outcome::Undefined
        );
        assert_eq!(cpu.apple_access(mrs(0, impdef::HID1), 0), Outcome::Read(0));
        for encoding in [impdef::HID4, CYC_OVRD, impdef::ACC_OVRD] {
            assert!(written(write(&mut cpu, encoding, 0)), "{encoding:?}");
        }
        cpu.pstate.el = 1;
        assert_eq!(write(&mut cpu, impdef::HID1, 1), Outcome::Undefined);
        cpu.pstate.el = 2;
        // The same values again complete; a change or a release stops.
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_EL2, RO_CTL)));
        assert!(written(write(&mut cpu, SPR_LOCKDOWN_COMMIT, 1)));
        for (encoding, value) in [(SPR_LOCKDOWN_EL2, u64::MAX), (SPR_LOCKDOWN_COMMIT, 0)] {
            assert!(matches!(
                write(&mut cpu, encoding, value),
                Outcome::Refused(_)
            ));
        }
        // The M3 SPTMs add SPR_LOCKDOWN_EL1, all ones, and commit both banks
        // with 3 (sptm.t8122 file 0xbbf70..0xbbf80); bit 2 has no meaning.
        let mut m3 = Cpu::of(Chip::AppleM3, 0, Pstate::reset(2));
        assert!(written(write(&mut m3, SPR_LOCKDOWN_EL2, RO_CTL)));
        assert!(written(write(&mut m3, SPR_LOCKDOWN_EL1, u64::MAX)));
        assert!(written(write(&mut m3, SPR_LOCKDOWN_COMMIT, 3)));
        assert_eq!(m3.apple.spr_lockdown, [RO_CTL, u64::MAX]);
        assert!(matches!(
            write(&mut m3, SPR_LOCKDOWN_EL1, 0),
            Outcome::Refused(_)
        ));
        assert!(matches!(
            write(&mut m3, SPR_LOCKDOWN_COMMIT, 7),
            Outcome::Refused(_)
        ));
        // The M4-and-later `defeatureCore` loosens an uncommitted bank.
        let mut m4 = Cpu::of(Chip::AppleM4, 0, Pstate::reset(2));
        assert!(written(write(&mut m4, SPR_LOCKDOWN_EL2, 0)));
        assert_eq!(
            m4.apple_access(mrs(0, SPR_LOCKDOWN_EL2), 0),
            Outcome::Read(0)
        );
        // Every lockdown register is UNDEFINED below EL2.
        let mut el1 = Cpu::new(0, Pstate::reset(1));
        for encoding in [SPR_LOCKDOWN_EL2, SPR_LOCKDOWN_EL1, SPR_LOCKDOWN_COMMIT] {
            assert_eq!(write(&mut el1, encoding, 0), Outcome::Undefined);
        }
    }

    /// A SIQ_CFG_EL1 write tells the board whether the PE now refuses the
    /// AIC's IRQs: mode 3 refuses, XNU's 0 and 2 accept.
    #[test]
    fn siq_cfg_steers_the_aics_irqs() {
        let mut cpu = Cpu::new(0, Pstate::reset(2));
        for (value, refuses) in [(3, true), (2, false), (0x7, true), (0, false)] {
            cpu.state.x[5] = value;
            assert!(matches!(
                cpu.apple_access(msr(5, impdef::SIQ_CFG_EL1), 0),
                Outcome::Written(Changes {
                    irq_steering: Some(steering),
                    ..
                }) if steering == refuses
            ));
        }
    }

    /// EL0 programs JCTL_EL0, the per-thread register XNU's user MSR test
    /// leaves user-writable, on the chips whose components use it (M2 on);
    /// other implementation-defined registers stay UNDEFINED at EL0.
    #[test]
    fn el0_reaches_jctl_on_the_chips_that_use_it() {
        use super::super::Chip;
        let mut m2 = Cpu::of(Chip::AppleM2, 0, Pstate::reset(0));
        m2.state.x[5] = 0x4000;
        assert!(matches!(
            m2.apple_access(msr(5, impdef::JCTL_EL0), 0),
            Outcome::Written(Changes {
                unmodeled: Some(_),
                ..
            })
        ));
        assert_eq!(
            m2.apple_access(mrs(0, impdef::JCTL_EL0), 0),
            Outcome::Read(0x4000)
        );
        for encoding in [impdef::AFPCR_EL0, impdef::TRACE_CLEARED, impdef::HID4] {
            assert_eq!(m2.apple_access(mrs(0, encoding), 0), Outcome::Undefined);
        }
        let mut m1 = Cpu::of(Chip::AppleM1, 0, Pstate::reset(0));
        assert_eq!(
            m1.apple_access(mrs(0, impdef::JCTL_EL0), 0),
            Outcome::Undefined
        );
    }

    /// CRn 11 reaches `machine::impdef` where an entry owns it, and stays
    /// UNDEFINED on a chip whose components never access it.
    #[test]
    fn crn_11_encodings_reach_their_impdef_entries() {
        use super::super::Chip;
        let mut m5 = Cpu::of(Chip::AppleM5, 0, Pstate::reset(2));
        assert_eq!(
            m5.apple_access(mrs(0, impdef::PL2_ERR_STS), 0),
            Outcome::Read(0)
        );
        m5.state.x[5] = 0x57f;
        assert!(matches!(
            m5.apple_access(msr(5, impdef::PL2_ERR_STS), 0),
            Outcome::Written(_)
        ));
        let mut m2 = Cpu::of(Chip::AppleM2, 0, Pstate::reset(2));
        assert_eq!(
            m2.apple_access(mrs(0, impdef::PL2_ERR_STS), 0),
            Outcome::Undefined
        );
    }

    /// Exercise decoded MRS/MSR, including privilege routing before validation:
    /// no rejected access can corrupt the PE's predictor configuration.
    #[test]
    fn objc_prediction_accesses_preserve_state_and_trap_before_writing() {
        use crate::machine::Chip;
        use impdef::{BP_OBJC_ADR_EL1, BP_OBJC_CTL_EL1};

        for chip in Chip::ALL {
            let mut cpu = Cpu::of(chip, 0, Pstate::reset(1));
            for (encoding, value, unknown) in [
                (BP_OBJC_ADR_EL1, 0x00ab_cdef_1234_5678, 1 << 56),
                (BP_OBJC_CTL_EL1, 0x001a_bcde_f83b_107f, 1 << 22),
            ] {
                cpu.state.x[5] = value;
                if chip == Chip::AppleM1 {
                    assert_eq!(cpu.apple_access(msr(5, encoding), 0), Outcome::Undefined);
                    assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Undefined);
                    assert_eq!(cpu.apple.impdef.used().count(), 0);
                    continue;
                }
                assert_eq!(
                    cpu.apple_access(msr(5, encoding), 0),
                    Outcome::Written(Changes::default())
                );
                assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Read(value));
                let writes = cpu.apple.impdef.writes.clone();
                cpu.state.x[5] = value | unknown;
                assert!(matches!(
                    cpu.apple_access(msr(5, encoding), 0),
                    Outcome::Refused(Refusal::UnsupportedSetting(_))
                ));
                assert_eq!(cpu.apple.impdef.writes, writes);
                assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Read(value));

                cpu.registers.set(Register::HCR_EL2, 0, 1 << HCR_TIDCP);
                assert_eq!(
                    cpu.apple_access(msr(5, encoding), 0),
                    Outcome::Trapped(Some(2))
                );
                assert_eq!(
                    cpu.apple_access(mrs(0, encoding), 0),
                    Outcome::Trapped(Some(2))
                );
                assert_eq!(cpu.apple.impdef.writes, writes);
                cpu.registers.set(Register::HCR_EL2, 0, 0);
                cpu.pstate.el = 0;
                assert_eq!(cpu.apple_access(msr(5, encoding), 0), Outcome::Undefined);
                assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Undefined);
                assert_eq!(cpu.apple.impdef.writes, writes);
                // EL2's SPTM uses the same physical PE state. Writing XZR
                // clears it, even though X5 still contains an invalid value.
                cpu.pstate.el = 2;
                assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Read(value));
                assert_eq!(
                    cpu.apple_access(msr(31, encoding), 0),
                    Outcome::Written(Changes::default())
                );
                assert_eq!(cpu.apple_access(mrs(31, encoding), 0), Outcome::Read(0));
                cpu.pstate.el = 1;
            }
        }
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
        // SPTM's lockdown: fields 2 and 9 of S3_6_C15_C3_1 keep those EL
        // fields of SPRR_PERM_EL1 writable outside GL.
        write(&mut cpu, SPRR_FIELDS_1, 0x40010);
        write(&mut cpu, SPRR_PERM_EL1, 0x2020_a52a_302a_bae6);
        cpu.pstate.guarded = false;
        for (value, allowed) in [
            (0x2020_a52a_302a_bbe6, true),  // index 2: EL r-- to rw-
            (0x2020_a53a_302a_bbe6, true),  // index 9: EL r-- to rw-
            (0x2020_a53a_302a_bfe6, false), // index 2's GL field
            (0x2020_a53a_302a_bbe7, false), // index 0
        ] {
            assert_eq!(
                matches!(write(&mut cpu, SPRR_PERM_EL1, value), Outcome::Written(_)),
                allowed,
                "{value:#x}"
            );
        }
        // SPRR_PERM_EL0 follows S3_6_C15_C3_0, here field 9 only.
        assert!(matches!(
            write(&mut cpu, SPRR_PERM_EL0, 3 << 36),
            Outcome::Written(_)
        ));
        assert!(matches!(
            write(&mut cpu, SPRR_PERM_EL0, 3 << 36 | 1),
            Outcome::Refused(_)
        ));
        // A field of 2 (SPTM's restore-mode field 5) unlocks only the GL
        // half of its index.
        cpu.pstate.guarded = true;
        write(&mut cpu, SPRR_FIELDS_0, 2 << 10 | 1 << 18);
        cpu.pstate.guarded = false;
        assert!(matches!(
            write(&mut cpu, SPRR_PERM_EL0, 3 << 36 | 0xc << 20),
            Outcome::Written(_)
        ));
        assert!(matches!(
            write(&mut cpu, SPRR_PERM_EL0, 3 << 36 | 0xf << 20),
            Outcome::Refused(_)
        ));
    }

    #[test]
    fn qualified_pmu_registers_trap_before_mutation_and_stay_undefined_at_el0() {
        for chip in super::super::Chip::ALL {
            let mut cpu = Cpu::of(chip, 0, Pstate::reset(2));
            cpu.pmu = Pmu::for_chip(chip, 1_000_000_000, 24_000_000);
            let mut encodings = alloc::vec![super::super::pmu::PMC[1]];
            if chip == super::super::Chip::AppleM6 {
                encodings.push(Encoding::new(3, 0, 11, 13, 2));
            }
            for encoding in encodings {
                cpu.pstate.el = 2;
                cpu.state.x[5] = 123;
                assert!(matches!(
                    cpu.apple_access(msr(5, encoding), 0),
                    Outcome::Written(_)
                ));
                cpu.pstate.el = 1;
                cpu.registers.set(Register::HCR_EL2, 0, 1 << HCR_TIDCP);
                cpu.state.x[5] = 456;
                assert_eq!(
                    cpu.apple_access(msr(5, encoding), 0),
                    Outcome::Trapped(Some(2))
                );
                assert_eq!(
                    cpu.apple_access(mrs(0, encoding), 0),
                    Outcome::Trapped(Some(2))
                );
                cpu.pstate.el = 0;
                assert_eq!(cpu.apple_access(msr(5, encoding), 0), Outcome::Undefined);
                assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Undefined);
                cpu.pstate.el = 2;
                assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Read(123));
            }
        }
    }

    #[test]
    fn m4_ctrr_names_reach_the_vhe_copies_and_iboots_controls() {
        use super::super::{Chip, ctrr};
        let crn11 = |crm, op2| Encoding::new(3, 0, 11, crm, op2);
        let (lower_el1, lower_el12, lower_el2) = (crn11(0, 0), crn11(0, 4), crn11(1, 0));
        let handoff = ctrr::Handoff {
            locked: alloc::vec![ctrr::Locked {
                region: ctrr::Region::CtrrC,
                first: 0x100_06fb_8000,
                last: 0x100_0710_bfff,
            }],
            legacy_locked: true,
            tag_offset: 0,
        };
        let mut cpu = Cpu::of(Chip::AppleM4, 0, Pstate::reset(2));
        cpu.ctrr.replace(ctrr::Cluster::handed_off(&handoff));
        cpu.ctrr_core = ctrr::Core::handed_off(&handoff);
        let write = |cpu: &mut Cpu, encoding, value| {
            cpu.state.x[5] = value;
            cpu.apple_access(msr(5, encoding), 0)
        };
        // SPTM's EL1-name write at EL2 lands in EL2's copy, which the kernel
        // reads by its EL2 name; EL1's copy stays clear.
        assert!(matches!(
            write(&mut cpu, lower_el1, 0x100_06fb_8000),
            Outcome::Written(Changes {
                translation: true,
                unmodeled: None,
                ..
            })
        ));
        assert_eq!(
            cpu.apple_access(mrs(0, lower_el2), 0),
            Outcome::Read(0x100_06fb_8000)
        );
        assert_eq!(cpu.apple_access(mrs(0, lower_el12), 0), Outcome::Read(0));
        // iBoot's locked per-cluster copy and CTRR-A/B controls.
        assert_eq!(
            cpu.apple_access(mrs(0, crn11(6, 7)), 0),
            Outcome::Read(0x100_0710_b000)
        );
        assert_eq!(
            cpu.apple_access(mrs(0, crn11(8, 2)), 0),
            Outcome::Read(ctrr::CTRR_HANDOFF)
        );
        let ctrr_a = Encoding::new(3, 4, 15, 2, 5);
        assert_eq!(
            cpu.apple_access(mrs(0, ctrr_a), 0),
            Outcome::Read(ctrr::CTRR_HANDOFF)
        );
        assert!(matches!(write(&mut cpu, ctrr_a, 0), Outcome::Refused(_)));
        // A CTXR enable completes with its effect reported.
        assert!(matches!(
            write(&mut cpu, crn11(5, 2), ctrr::CTXR_HANDOFF[0]),
            Outcome::Written(Changes {
                unmodeled: Some(_),
                ..
            })
        ));
        // At EL1 the EL1 name reaches EL1's copy; the EL12, EL2 and
        // per-cluster names are UNDEFINED.
        cpu.pstate.el = 1;
        assert_eq!(cpu.apple_access(mrs(0, lower_el1), 0), Outcome::Read(0));
        for encoding in [
            lower_el12,
            lower_el2,
            crn11(6, 6),
            Encoding::new(3, 4, 15, 11, 4),
        ] {
            assert_eq!(cpu.apple_access(mrs(0, encoding), 0), Outcome::Undefined);
        }
    }

    #[test]
    fn tag_offset_reads_iboots_locked_value_at_el2() {
        use super::super::{Chip, ctrr, identification, tag_storage::TAG_OFFSET_EL2};
        const LOCKED: u64 = 0x8000_0101_e000_0000;
        for chip in Chip::ALL {
            let mut cpu = Cpu::of(chip, 0, Pstate::reset(2));
            cpu.core_locks = alloc::rc::Rc::new(ctrr::Handoff {
                tag_offset: LOCKED,
                ..ctrr::Handoff::default()
            });
            let outcome = cpu.apple_access(mrs(0, TAG_OFFSET_EL2), 0);
            if !identification::memory_tagging(chip) {
                // The census rules the other chips' encoding.
                assert_ne!(outcome, Outcome::Read(LOCKED), "{}", chip.name());
                continue;
            }
            assert_eq!(outcome, Outcome::Read(LOCKED));
            cpu.state.x[5] = LOCKED;
            assert!(matches!(
                cpu.apple_access(msr(5, TAG_OFFSET_EL2), 0),
                Outcome::Written(_)
            ));
            cpu.state.x[5] = 0;
            assert!(matches!(
                cpu.apple_access(msr(5, TAG_OFFSET_EL2), 0),
                Outcome::Refused(_)
            ));
            cpu.pstate.el = 1;
            assert_eq!(
                cpu.apple_access(mrs(0, TAG_OFFSET_EL2), 0),
                Outcome::Undefined
            );
        }
    }

    #[test]
    fn every_crn11_encoding_the_m4_to_m6_sptms_and_kernels_access_reaches_ctrr() {
        use super::super::{Chip, ctrr};
        for chip in [Chip::AppleM4, Chip::AppleM5, Chip::AppleM6] {
            for crm in 0..16 {
                for op2 in 0..8 {
                    let encoding = Encoding::new(3, 0, 11, crm, op2);
                    // CRm 9 up holds TAG_OFFSET_EL2 (`machine::tag_storage`)
                    // and the M6 kernel's other registers.
                    if !impdef::consumed(encoding, chip) || crm >= 9 {
                        continue;
                    }
                    assert!(
                        ctrr::decode(chip, encoding).is_some(),
                        "{} {encoding:?}",
                        chip.name()
                    );
                }
            }
        }
    }

    /// The M3-and-later encodings whose owners are being written outside
    /// `machine::impdef`: the M5 kpc state S3_1_C15_C5_1, which
    /// `machine::pmu` owns on the M6 only (mac17g save 0xfffffe000be64104,
    /// restore 0xfffffe000beb56b0). Each family leaves this list when its
    /// owner lands.
    fn pending_owner(encoding: Encoding) -> bool {
        const KPC: (u8, u8, u8) = (1, 5, 1);
        let key = (encoding.op1(), encoding.crm(), encoding.op2());
        encoding.crn() == 15 && key == KPC
    }

    /// Every IMPLEMENTATION DEFINED encoding a chip's censused components
    /// access has an owner: a modeled register here, CTRR, AMX, the core
    /// PMU, the board's fast IPIs, the Apple generic timer or a
    /// `machine::impdef` entry with a class other than `Unsupported`
    /// ([`pending_owner`] aside on the later chips).
    #[test]
    fn every_encoding_the_components_access_has_a_model() {
        use crate::platform::apple::ipi;
        for chip in super::super::Chip::ALL {
            let mut owned = 0;
            for crn in [11, 15] {
                for selector in 0u16..1 << 10 {
                    let field = |shift: u16, mask: u16| ((selector >> shift) & mask) as u8;
                    let (op1, crm, op2) = (field(7, 7), field(3, 0xf), field(0, 7));
                    let encoding = Encoding::new(3, op1, crn, crm, op2);
                    if !impdef::consumed(encoding, chip)
                        || Pmu::owns_on(chip, encoding)
                        || ipi::Register::decode(encoding).is_some()
                        || super::super::timer::agt::decode(encoding, chip).is_some()
                        || pending_owner(encoding)
                    {
                        continue;
                    }
                    owned += 1;
                    let entry = impdef::lookup(encoding, chip);
                    assert!(
                        entry.is_none_or(|entry| entry.class != impdef::Class::Unsupported),
                        "{} {encoding:?}",
                        chip.name()
                    );
                    // A modeled register may be UNDEFINED in this state
                    // (SPRR's permissions while SPRR is disabled), but none
                    // lacks a model.
                    let mut cpu = Cpu::of(chip, 0, Pstate::reset(2));
                    let outcome = cpu.apple_access(mrs(0, encoding), 0);
                    assert!(
                        !matches!(
                            outcome,
                            Outcome::Refused(Refusal::Unimplemented)
                                | Outcome::Refused(Refusal::UnsupportedSetting(
                                    "CRn=11 IMPLEMENTATION DEFINED register without a model"
                                ))
                        ),
                        "{} {encoding:?}",
                        chip.name()
                    );
                }
            }
            assert!(owned > 150, "{}: {owned}", chip.name());
        }
    }
}
