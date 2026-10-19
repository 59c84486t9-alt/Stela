//! The hosted PE: one Apple M2 core running the guest thread at EL0t under
//! the EL1&0 regime with the controls XNU arm64 gives user threads, and
//! every exception from EL0 taken to an EL1 vector the host intercepts.
//!
//! Controls follow XNU `osfmk/arm64/proc_reg.h` (`SCTLR_EL1_DEFAULT`,
//! `TCR_EL1_BASE` with TBI0 and TBID0 for data-only top-byte ignore) and
//! `machine_routines.c` (`CNTKCTL_EL1` EL0 counter access and the event
//! stream). The translation granule is the identity map's
//! ([`super::tables`]). HCR_EL2 leaves PAC untrapped (API, APK) with TGE
//! clear, so EL0 exceptions reach EL1.
use super::tables::{T0SZ, Tables};
use crate::machine::{
    Chip, Cpu, CpuProfile, exception::Pstate, registers::encodings::DCZID_EL0, system::Register,
};
use stela_compiler::TargetCpu;

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

/// The chip profile of the hosted PE: identification the engine implements
/// on this host, capped at the chip, with the M2's 24 MHz counter.
pub fn profile(chip: Chip, target: TargetCpu) -> CpuProfile {
    let mut fixed = crate::machine::identification::derive(chip, target, true);
    fixed.push((DCZID_EL0, DCZID_BLOCK_64));
    CpuProfile {
        name: chip.name(),
        chip,
        counter_frequency: super::host::COUNTER_HZ,
        fixed,
        processors: Vec::new(),
    }
}

/// A PE of `chip` at EL0t, entering at `pc` with the process's keys, its
/// identity stage 1 and EL1's intercepted vectors.
pub fn user_thread(chip: Chip, pc: u64, tables: &Tables, keys: &Keys) -> Cpu {
    let user = Pstate {
        el: 0,
        sp: false,
        daif: 0,
        ..Pstate::reset(0)
    };
    let mut cpu = Cpu::of(chip, pc, user);
    let registers = &mut cpu.registers;
    for (register, value) in [
        (Register::SCTLR_EL1, SCTLR_EL1),
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
        let cpu = user_thread(Chip::AppleM2, 0x1000, &tables, &keys);
        assert_eq!(cpu.pstate.el, 0);
        assert_eq!(cpu.read(Register::TTBR0_EL1), tables.root());
        assert_eq!(cpu.read(Register::APIBKeyHi_EL1), keys.ib[1]);
        assert_eq!(VECTOR_BASE & 0x7ff, 0);
    }
}
