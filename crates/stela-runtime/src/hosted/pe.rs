//! The hosted PE: one core of the modeled SoC running the guest thread at EL0t under
//! the EL1&0 regime with the controls XNU arm64 gives user threads, and
//! every exception from EL0 taken to an EL1 vector the host intercepts.
//!
//! Controls follow XNU `osfmk/arm64/proc_reg.h` (`SCTLR_EL1_DEFAULT`,
//! `TCR_EL1_BASE` with TBI0 and TBID0 for data-only top-byte ignore) and
//! `machine_routines.c` (`CNTKCTL_EL1` EL0 counter access and the event
//! stream). The translation granule is the identity map's
//! ([`super::tables`]). HCR_EL2 leaves PAC untrapped (API, APK) with TGE
//! clear, so EL0 exceptions reach EL1.
use super::hardware::{CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, Hardware};
use super::tables::{T0SZ, Tables};
use stela_compiler::TargetCpu;
use {
    crate::machine::Cpu, crate::machine::CpuProfile, crate::machine::exception::Pstate,
    crate::machine::registers::encodings::DCZID_EL0,
    crate::machine::registers::encodings::ID_AA64PFR1_EL1,
    crate::machine::registers::encodings::ID_AA64SMFR0_EL1, crate::machine::soc,
    crate::machine::system::Register, stela_contracts::Chip,
};

/// EL1's vector base. Nothing executes there: the host stops at each entry
/// (`Machine::set_breakpoints`) and returns with `return_from_exception`.
/// Inside the 64 GiB commpage nesting region, which no user mapping uses.
pub const VECTOR_BASE: u64 = 0xf_ffff_0000;
/// Arm vector offsets for exceptions from a lower EL using AArch64.
pub const LOWER_SYNCHRONOUS: u64 = VECTOR_BASE + 0x400;
pub const LOWER_IRQ: u64 = VECTOR_BASE + 0x480;
pub const LOWER_FIQ: u64 = VECTOR_BASE + 0x500;
pub const LOWER_SERROR: u64 = VECTOR_BASE + 0x580;
/// Same-EL vectors, which a correct host never reaches.
pub const CURRENT_SYNCHRONOUS: u64 = VECTOR_BASE + 0x200;

const SCTLR_M: u64 = 1 << 0;
const SCTLR_C: u64 = 1 << 2;
const SCTLR_SA: u64 = 1 << 3;
const SCTLR_SA0: u64 = 1 << 4;
const SCTLR_CP15BEN: u64 = 1 << 5;
const SCTLR_EOS: u64 = 1 << 11;
const SCTLR_I: u64 = 1 << 12;
const SCTLR_EN_DB: u64 = 1 << 13;
const SCTLR_DZE: u64 = 1 << 14;
const SCTLR_UCT: u64 = 1 << 15;
const SCTLR_NTWI: u64 = 1 << 16;
const SCTLR_NTWE: u64 = 1 << 18;
const SCTLR_EIS: u64 = 1 << 22;
const SCTLR_SPAN: u64 = 1 << 23;
const SCTLR_UCI: u64 = 1 << 26;
const SCTLR_EN_DA: u64 = 1 << 27;
const SCTLR_EN_IB: u64 = 1 << 30;
const SCTLR_EN_IA: u64 = 1 << 31;
/// `SCTLR_EL1_DEFAULT` for an ARMv8.6 Apple core with Apple PAC, without
/// BTI enforcement or SME: the user-visible enables (UCI, UCT, DZE, nTWE,
/// nTWI), stack alignment, caches, the MMU and all four PAC keys.
pub const SCTLR_EL1: u64 = SCTLR_M
    | SCTLR_C
    | SCTLR_SA
    | SCTLR_SA0
    | SCTLR_CP15BEN
    | SCTLR_EOS
    | SCTLR_I
    | SCTLR_EN_DB
    | SCTLR_DZE
    | SCTLR_UCT
    | SCTLR_NTWI
    | SCTLR_NTWE
    | SCTLR_EIS
    | SCTLR_SPAN
    | SCTLR_UCI
    | SCTLR_EN_DA
    | SCTLR_EN_IB
    | SCTLR_EN_IA;
/// The keys a process whose user JOP is disabled runs without: all four.
/// xnu-7195 cleared only `SCTLR_JOP_KEYS_ENABLED` (IA, DA and DB) and kept
/// IB for return addresses, but the 26A434 shared cache's libunwind
/// (`UnwindCursor::step`) authenticates every frame's saved return address
/// with IB and traps on failure, and an arm64 image saves its return
/// addresses unsigned: such a process unwinds through its own frames only
/// with IB's PAC and AUT returning their input too. The SPTM-era kernels
/// keep how they disable the keys (`SPTM_ROOT_PT_FLAG_JOP`,
/// `ml_non_arm64e_user_jop_pid`) out of the published sources.
pub const SCTLR_USER_JOP_KEYS: u64 = SCTLR_EN_IA | SCTLR_EN_IB | SCTLR_EN_DA | SCTLR_EN_DB;

/// Whether a process's pointer authentication keys are enabled. Exec
/// disables them for an image whose CPU subtype does not use pointer
/// authentication (`IMGPF_NOJOP`, `arm64_cpusubtype_uses_ptrauth`): its
/// PAC and AUT instructions return their input
/// ([`SCTLR_USER_JOP_KEYS`]), and the kernel signs nothing for it (the
/// shared region's slide, the dyld pager and `bsdthread_register`'s entry
/// points).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserJop {
    Enabled,
    Disabled,
}

impl UserJop {
    /// `CPU_SUBTYPE_ARM64_PTR_AUTH_VERSION` and the macOS
    /// `CPU_SUBTYPE_ARM64_PTR_AUTH_MAX_PREFERRED_VERSION` (1).
    const PTR_AUTH_VERSION_SHIFT: u32 = 24;
    const PTR_AUTH_VERSION_MASK: u32 = 0xf;
    const PTR_AUTH_MAX_PREFERRED_VERSION: u32 = 1;

    /// `arm64_cpusubtype_uses_ptrauth` of an arm64 image's CPU subtype.
    pub fn of_subtype(subtype: u32) -> Self {
        let version = (subtype >> Self::PTR_AUTH_VERSION_SHIFT) & Self::PTR_AUTH_VERSION_MASK;
        if subtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E
            && version <= Self::PTR_AUTH_MAX_PREFERRED_VERSION
        {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }

    /// SCTLR_EL1 as the thread returns to EL0.
    pub fn sctlr(self) -> u64 {
        match self {
            Self::Enabled => SCTLR_EL1,
            Self::Disabled => SCTLR_EL1 & !SCTLR_USER_JOP_KEYS,
        }
    }
}

const TCR_IRGN0_WRITEBACK: u64 = 1 << 8;
const TCR_ORGN0_WRITEBACK: u64 = 1 << 10;
const TCR_SH0_INNER: u64 = 3 << 12;
/// TG0 = 0b00: the 4 KiB granule of the identity map.
const TCR_TG0_4KB: u64 = 0;
/// EPD1: no TTBR1 walks; user threads never touch the upper range.
const TCR_EPD1: u64 = 1 << 23;
/// IPS = 0b101: 48-bit output, covering every host user address.
const TCR_IPS_48BITS: u64 = 5 << 32;
const TCR_TBI0: u64 = 1 << 37;
/// TBID0: top-byte ignore for data only, so instruction pointers keep their
/// PAC field (`TCR_TBID0_TBI_DATA_ONLY`).
const TCR_TBID0: u64 = 1 << 51;
pub const TCR_EL1: u64 = T0SZ
    | TCR_IRGN0_WRITEBACK
    | TCR_ORGN0_WRITEBACK
    | TCR_SH0_INNER
    | TCR_TG0_4KB
    | TCR_EPD1
    | TCR_IPS_48BITS
    | TCR_TBI0
    | TCR_TBID0;
/// Attribute 0: Normal, Inner and Outer Write-Back non-transient.
const MAIR_EL1: u64 = 0xff;
/// FPEN = 0b11: FP/SIMD untrapped at EL0 and EL1.
const CPACR_FPEN: u64 = 3 << 20;
/// EL0PCTEN, EL0VCTEN and the event stream (`_enable_timebase_event_stream`).
const CNTKCTL_EL0PCTEN: u64 = 1 << 0;
const CNTKCTL_EL0VCTEN: u64 = 1 << 1;
const CNTKCTL_EVNTEN: u64 = 1 << 2;
const CNTKCTL_EVNTDIR: u64 = 1 << 3;
const CNTKCTL_EVNTI_SHIFT: u32 = 4;
/// XNU `wfe_timeout_configure`'s bit for a 1 µs event period at 24 MHz:
/// 24 ticks round up to 2^5, less one for the falling edge.
const EVENT_STREAM_BIT: u64 = 4;
const CNTKCTL_EL1: u64 = CNTKCTL_EL0PCTEN
    | CNTKCTL_EL0VCTEN
    | CNTKCTL_EVNTEN
    | CNTKCTL_EVNTDIR
    | EVENT_STREAM_BIT << CNTKCTL_EVNTI_SHIFT;
/// HCR_EL2: RW (EL1 is AArch64), API and APK (PAC instructions and key
/// registers untrapped), E2H as the profile's RES1, TGE clear.
const HCR_RW: u64 = 1 << 31;
const HCR_E2H: u64 = 1 << 34;
const HCR_APK: u64 = 1 << 40;
const HCR_API: u64 = 1 << 41;
const HCR_EL2: u64 = HCR_RW | HCR_E2H | HCR_APK | HCR_API;
/// CNTHCTL_EL2 with E2H: EL1PCTEN and EL1PTEN, the physical counter and
/// timer untrapped below EL2.
const CNTHCTL_EL2: u64 = 1 << 10 | 1 << 11;
/// DCZID_EL0: 64-byte DC ZVA blocks (BS = 4), enabled, as Apple cores report.
const DCZID_BLOCK_64: u64 = 4;
/// TPIDR_EL0's CPU number and cluster fields (`machine_machdep.h`): this
/// thread runs on CPU 0 of cluster 0.
pub const TPIDR_EL0_CPU: u64 = 0;

/// The PAC keys of one process: IA and DA are also the shared region's, as
/// XNU's user JOP key is per shared region; IB, DB and GA are per process.
#[derive(Debug, Clone, Copy)]
pub struct Keys {
    pub ia: [u64; 2],
    pub ib: [u64; 2],
    pub da: [u64; 2],
    pub db: [u64; 2],
    pub ga: [u64; 2],
}

impl Keys {
    /// Fresh keys from the host's entropy source.
    pub fn random() -> anyhow::Result<Self> {
        let mut words = [0u64; 10];
        let bytes = words.len() * 8;
        // SAFETY: getentropy fills at most 256 bytes of the buffer.
        let status = unsafe { libc::getentropy(words.as_mut_ptr().cast(), bytes) };
        anyhow::ensure!(status == 0, "getentropy failed");
        Ok(Self {
            ia: [words[0], words[1]],
            ib: [words[2], words[3]],
            da: [words[4], words[5]],
            db: [words[6], words[7]],
            ga: [words[8], words[9]],
        })
    }
}

/// Hosted memory tagging is not implemented: guest memory is the host's,
/// mapped by 1 GiB identity blocks of one Normal attribute, and nothing
/// keeps its Allocation Tags, enables tag access at EL0 (SCTLR_EL1.ATA0)
/// or checks them in translated code. Presenting it also makes the hosted
/// kernel's tagging answers (tag storage, remote pointer tags) read the
/// tags kept.
const HOSTED_MEMORY_TAGGING: bool = false;

/// ID_AA64PFR1_EL1.MTE and MTE_frac.
const PFR1_MTE_FIELDS: u64 = 0xf << 8 | 0xf << 40;

/// Whether the hosted machine presents memory tagging, given whether the
/// chip has it (`Hardware::memory_tagging`): not until hosted memory
/// tagging exists, so a tagging chip's hosted process sees a machine
/// without it (no FEAT_MTE in its identification, sysctls and commpage,
/// and a kernel that ignores `VM_FLAGS_MTE` as non-MTE kernels do) rather
/// than one whose tag stores silently keep nothing.
pub const fn memory_tagging(chip: bool) -> bool {
    chip && HOSTED_MEMORY_TAGGING
}

/// The hosted limit exec reports once for a chip with memory tagging.
pub const MEMORY_TAGGING_LIMIT: &str = "the chip's memory tagging (FEAT_MTE2) is not presented \
     to hosted processes: hosted memory keeps no Allocation Tags, so the process runs as on a \
     chip without it";

/// Hosted streaming execution is not implemented: the hosted kernel has no
/// SME access trap (XNU enables SME for a thread at its first use,
/// `arm_sme_trap`), no SME or ZA thread states, signal contexts or
/// `hw.optional.arm.sme_max_svl_b`, and no cluster shared resource for
/// `bsdthread_get_max_parallelism`.
const HOSTED_STREAMING: bool = false;

/// ID_AA64PFR1_EL1.SME.
const PFR1_SME_FIELD: u64 = 0xf << 24;

/// Whether the hosted machine presents the Scalable Matrix Extension, given
/// whether the chip has it (`identification::streaming`): not until hosted
/// streaming execution exists, so an SME chip's hosted process sees a
/// machine without it (no FEAT_SME in its identification, sysctls and
/// commpage, and SMSTART UNDEFINED) rather than one whose first SME
/// instruction faults.
pub const fn streaming(chip: bool) -> bool {
    chip && HOSTED_STREAMING
}

/// The hosted limit exec reports once for a chip with SME.
pub const STREAMING_LIMIT: &str = "the chip's Scalable Matrix Extension (FEAT_SME) is not \
     presented to hosted processes: the hosted kernel keeps no streaming or ZA state, so the \
     process runs as on a chip without it";

/// The hosted limits exec reports once for `chip`: each feature the chip
/// has that the hosted machine does not present.
pub fn limits(chip: Chip) -> Vec<&'static str> {
    let tagging = crate::machine::identification::memory_tagging(chip);
    let sme = crate::machine::identification::streaming(chip);
    [
        (tagging && !memory_tagging(tagging), MEMORY_TAGGING_LIMIT),
        (sme && !streaming(sme), STREAMING_LIMIT),
    ]
    .into_iter()
    .filter_map(|(withheld, limit)| withheld.then_some(limit))
    .collect()
}

/// The chip profile of the hosted PE: identification the engine implements
/// on this host, capped at the SoC's chip, with the M2's 24 MHz counter
/// and without memory tagging or SME unless the hosted machine presents
/// them ([`memory_tagging`], [`streaming`]). Its one PE is the core the
/// thread reports running on (CPU 0, [`TPIDR_EL0_CPU`]), identified from
/// the SoC's row as the system engine identifies it (`soc::cpus`): the
/// MIDR_EL1 part of its cluster type, which gives the commpage's and
/// sysctls' CPU family ([`Hardware`]), and its caches. It has no core
/// clock: the hosted PE keeps no Apple performance monitor. The process is
/// one guest context, so its speculation guarantees are the host OS's
/// process isolation (`Speculation::HOSTED`).
pub fn profile(hardware: &Hardware, target: TargetCpu) -> anyhow::Result<CpuProfile> {
    let chip = hardware.chip;
    let mut fixed = crate::machine::identification::derive(
        chip,
        target,
        true,
        crate::machine::identification::Speculation::HOSTED,
    );
    let tagging = memory_tagging(hardware.memory_tagging);
    let sme = streaming(crate::machine::identification::streaming(chip));
    for (register, value) in &mut fixed {
        match *register {
            ID_AA64PFR1_EL1 => {
                if !tagging {
                    *value &= !PFR1_MTE_FIELDS;
                }
                if !sme {
                    *value &= !PFR1_SME_FIELD;
                }
            }
            ID_AA64SMFR0_EL1 if !sme => *value = 0,
            _ => {}
        }
    }
    fixed.push((DCZID_EL0, DCZID_BLOCK_64));
    let mut cpus = soc::cpus(
        hardware.chip_id,
        hardware.brand,
        &[hardware.boot_processor()],
    )
    .map_err(anyhow::Error::msg)?;
    for processor in &mut cpus.processors {
        processor.clock = None;
    }
    Ok(CpuProfile {
        name: hardware.brand,
        chip,
        counter_frequency: super::host::COUNTER_HZ,
        fixed,
        processors: cpus.processors,
    })
}

/// A new user thread's PSTATE, XNU's `PSR64_USER64_DEFAULT`: EL0t in
/// AArch64 with every flag and mask clear.
fn user_pstate() -> Pstate {
    Pstate {
        el: 0,
        sp: false,
        daif: 0,
        ..Pstate::reset(0)
    }
}

/// The SPSR_EL1 an exception return to a fresh user state takes, as the
/// kernel sets it for a workqueue thread's upcall (`thread_set_wq_state64`).
pub fn user_spsr() -> u64 {
    user_pstate().to_spsr(0)
}

/// A PE of `chip` at EL0t, entering at `pc` with the process's keys and
/// user JOP state, its identity stage 1 and EL1's intercepted vectors.
pub fn user_thread(chip: Chip, pc: u64, tables: &Tables, keys: &Keys, jop: UserJop) -> Cpu {
    let mut cpu = Cpu::of(chip, pc, user_pstate());
    let registers = &mut cpu.registers;
    for (register, value) in [
        (Register::SCTLR_EL1, jop.sctlr()),
        (Register::TCR_EL1, TCR_EL1),
        (Register::MAIR_EL1, MAIR_EL1),
        (Register::TTBR0_EL1, tables.root()),
        (Register::CPACR_EL1, CPACR_FPEN),
        (Register::CNTKCTL_EL1, CNTKCTL_EL1),
        (Register::VBAR_EL1, VECTOR_BASE),
        (Register::HCR_EL2, HCR_EL2),
        (Register::CNTHCTL_EL2, CNTHCTL_EL2),
        (Register::TPIDR_EL0, TPIDR_EL0_CPU),
        (Register::TPIDRRO_EL0, 0),
        (Register::APIAKeyLo_EL1, keys.ia[0]),
        (Register::APIAKeyHi_EL1, keys.ia[1]),
        (Register::APIBKeyLo_EL1, keys.ib[0]),
        (Register::APIBKeyHi_EL1, keys.ib[1]),
        (Register::APDAKeyLo_EL1, keys.da[0]),
        (Register::APDAKeyHi_EL1, keys.da[1]),
        (Register::APDBKeyLo_EL1, keys.db[0]),
        (Register::APDBKeyHi_EL1, keys.db[1]),
        (Register::APGAKeyLo_EL1, keys.ga[0]),
        (Register::APGAKeyHi_EL1, keys.ga[1]),
    ] {
        registers.set_raw(register, 0, value);
    }
    // From the M3 on, the thread's counter reads reach the Apple generic
    // timer's bank (`timer::agt`), whose controls XNU sets alike.
    for (register, value) in [
        (Register::CNTKCTL_EL1, CNTKCTL_EL1),
        (Register::CNTHCTL_EL2, CNTHCTL_EL2),
    ] {
        cpu.apple.generic_timer.set(register, value);
    }
    cpu
}

/// The vectors the host stops at.
pub const fn vectors() -> [u64; 5] {
    [
        CURRENT_SYNCHRONOUS,
        LOWER_SYNCHRONOUS,
        LOWER_IRQ,
        LOWER_FIQ,
        LOWER_SERROR,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::system::registers::Encoding;

    #[test]
    fn user_controls_match_xnu_user_threads() {
        assert_eq!(TCR_EL1 & 0x3f, 17);
        assert_ne!(SCTLR_EL1 & SCTLR_SA0, 0);
        assert_eq!(
            SCTLR_EL1 & (SCTLR_EN_IA | SCTLR_EN_IB | SCTLR_EN_DA | SCTLR_EN_DB),
            SCTLR_EN_IA | SCTLR_EN_IB | SCTLR_EN_DA | SCTLR_EN_DB
        );
        let tables = Tables::new().unwrap();
        let keys = Keys::random().unwrap();
        let cpu = user_thread(Chip::AppleM2, 0x1000, &tables, &keys, UserJop::Enabled);
        assert_eq!(cpu.pstate.el, 0);
        assert_eq!(cpu.read(Register::SCTLR_EL1), SCTLR_EL1);
        assert_eq!(cpu.read(Register::TTBR0_EL1), tables.root());
        assert_eq!(cpu.read(Register::APIBKeyHi_EL1), keys.ib[1]);
        assert_eq!(VECTOR_BASE & 0x7ff, 0);
    }

    fn hosted_profile(chip_id: u32) -> CpuProfile {
        let hardware = Hardware::of_soc(chip_id, 1 << 34).unwrap();
        profile(&hardware, TargetCpu::detect()).unwrap()
    }

    fn fixed(profile: &CpuProfile, encoding: Encoding) -> u64 {
        profile
            .fixed
            .iter()
            .find(|(register, _)| *register == encoding)
            .map_or(0, |(_, value)| *value)
    }

    #[test]
    fn a_tagging_chip_presents_no_memory_tagging_to_hosted_processes() {
        assert!(crate::machine::identification::memory_tagging(
            Chip::AppleM5
        ));
        assert!(!memory_tagging(true));
        let m5 = hosted_profile(0x8142);
        assert_eq!(fixed(&m5, ID_AA64PFR1_EL1) & PFR1_MTE_FIELDS, 0);
        // The register's other features stay.
        assert_ne!(fixed(&m5, ID_AA64PFR1_EL1), 0);
        assert!(limits(Chip::AppleM5).contains(&MEMORY_TAGGING_LIMIT));
        assert!(!limits(Chip::AppleM2).contains(&MEMORY_TAGGING_LIMIT));
    }

    /// An SME chip's hosted PE presents no SME, and exec reports the limit.
    #[test]
    fn an_sme_chip_presents_no_streaming_to_hosted_processes() {
        assert!(crate::machine::identification::streaming(Chip::AppleM4));
        assert!(!streaming(true));
        let m4 = hosted_profile(0x8132);
        assert_eq!(fixed(&m4, ID_AA64PFR1_EL1) & PFR1_SME_FIELD, 0);
        assert_eq!(fixed(&m4, ID_AA64SMFR0_EL1), 0);
        assert_eq!(limits(Chip::AppleM4), [STREAMING_LIMIT]);
        assert!(limits(Chip::AppleM2).is_empty());
    }

    /// Each SoC's hosted PE is its CPU 0 as the SoC row identifies it: a Pro,
    /// Max or Ultra presents its own MIDR_EL1 part, the one its CPU family
    /// comes from, not its base chip's.
    #[test]
    fn the_hosted_pe_is_the_socs_cpu_0() {
        for model in super::super::hardware::models() {
            let hardware = Hardware::of_model(model, 1 << 34).unwrap();
            let profile = profile(&hardware, TargetCpu::detect()).unwrap();
            let [identity] = profile.processors[..] else {
                panic!("{model} has {} hosted PEs", profile.processors.len());
            };
            let part = soc::midr_part(hardware.chip_id, hardware.boot_processor().cluster_type);
            assert_eq!(Some((identity.midr >> 4 & 0xfff) as u16), part, "{model}");
            assert_eq!(identity.clock, None, "{model}");
            assert_eq!(profile.chip, hardware.chip, "{model}");
        }
        let m2 = hosted_profile(0x8112).processors[0].midr;
        let m2_max = hosted_profile(0x6021).processors[0].midr;
        assert_ne!(m2, m2_max);
    }

    #[test]
    fn only_ptrauth_subtypes_keep_user_jop() {
        // arm64e (ABI version 0 and the stable PTRAUTH_ABI bit), its
        // macOS-preferred version 1, a later version, arm64 and arm64.v8.
        assert_eq!(UserJop::of_subtype(2), UserJop::Enabled);
        assert_eq!(UserJop::of_subtype(0x8000_0002), UserJop::Enabled);
        assert_eq!(UserJop::of_subtype(0x8100_0002), UserJop::Enabled);
        assert_eq!(UserJop::of_subtype(0x8200_0002), UserJop::Disabled);
        assert_eq!(UserJop::of_subtype(0), UserJop::Disabled);
        assert_eq!(UserJop::of_subtype(1), UserJop::Disabled);
        let tables = Tables::new().unwrap();
        let keys = Keys::random().unwrap();
        let cpu = user_thread(Chip::AppleM2, 0x1000, &tables, &keys, UserJop::Disabled);
        let sctlr = cpu.read(Register::SCTLR_EL1);
        assert_eq!(sctlr & SCTLR_USER_JOP_KEYS, 0);
        assert_eq!(sctlr | SCTLR_USER_JOP_KEYS, SCTLR_EL1);
    }
}
