//! The host processor's own performance request. After ExitBootServices no
//! operating system asks the CPU for speed, so a core runs at whatever its
//! firmware left: with hardware-controlled P-states (Intel HWP, AMD CPPC)
//! not enabled, or enabled with a balanced energy preference, a busy core
//! may stay below its highest clock. Each processor that runs a PE asks
//! for full performance as Linux's `performance` policy does in active
//! mode, on that processor itself:
//!
//! - Intel HWP (intel_pstate `intel_pstate_hwp_enable`,
//!   `intel_pstate_hwp_set`): HWP notifications off, HWP on, minimum and
//!   maximum both the highest level, desired level 0 (the hardware picks)
//!   and energy preference 0 where the EPP field exists. Like
//!   `intel_pstate_init`, HWP that firmware left off is not turned on
//!   without EPP (Linux also accepts the DEC bit of the model-specific
//!   POWER_CTL, which this does not read).
//! - AMD CPPC through MSRs (amd-pstate `msr_cppc_enable`,
//!   `amd_pstate_update_min_max_limit`, `amd_pstate_epp_update_limit`):
//!   CPPC on, maximum the core's highest level, minimum the firmware's
//!   minimum where the request holds nothing else and else the nominal
//!   level, desired 0 and energy preference 0. Zen parts without the MSR
//!   interface use ACPI shared-memory CPPC; they are left as firmware set
//!   them.
//!
//! Every access is gated by the vendor and the CPUID bit that enumerates
//! the register, so a processor (or a hypervisor) without the interface is
//! never touched and only counts as `legacy`. Bits the request does not
//! own (Intel's activity window, package control and valid bits; reserved
//! bits) keep their values. Both enables are one-way until reset. Idle
//! waits are unchanged, and processors parked in their idle loop keep the
//! firmware's request, as Linux leaves an offline AMD CPU's.
//!
//! Registers: Intel SDM Vol. 3B 15.4 (CPUID.06H:EAX[7] HWP, [8] HWP
//! notification, [10] EPP; IA32_PM_ENABLE 770H, IA32_HWP_CAPABILITIES 771H,
//! IA32_HWP_INTERRUPT 773H, IA32_HWP_REQUEST 774H); AMD PPR (CPUID
//! 8000_0008H:EBX[27] CPPC; CPPC_CAP1 C001_02B0H, CPPC_ENABLE C001_02B1H,
//! CPPC_REQ C001_02B3H).
use crate::msr::{AMD_VENDOR, Bit, Gate, Msr, Register};
use alloc::{format, string::String};
use core::arch::x86_64::__cpuid;
use core::sync::atomic::{AtomicU32, Ordering};

const HWP_BIT: Bit = Bit::new(6, Register::Eax, 7);
const HWP_NOTIFY_BIT: Bit = Bit::new(6, Register::Eax, 8);
const HWP_EPP_BIT: Bit = Bit::new(6, Register::Eax, 10);
const AMD_CPPC_BIT: Bit = Bit::new(0x8000_0008, Register::Ebx, 27);

pub const PM_ENABLE: Msr = Msr::new(0x770, Gate::Cpuid(HWP_BIT));
pub const HWP_CAPABILITIES: Msr = Msr::new(0x771, Gate::Cpuid(HWP_BIT));
pub const HWP_INTERRUPT: Msr = Msr::new(0x773, Gate::Cpuid(HWP_NOTIFY_BIT));
pub const HWP_REQUEST: Msr = Msr::new(0x774, Gate::Cpuid(HWP_BIT));
pub const AMD_CPPC_CAP1: Msr = Msr::new(0xc001_02b0, Gate::Cpuid(AMD_CPPC_BIT));
pub const AMD_CPPC_ENABLE: Msr = Msr::new(0xc001_02b1, Gate::Cpuid(AMD_CPPC_BIT));
pub const AMD_CPPC_REQ: Msr = Msr::new(0xc001_02b3, Gate::Cpuid(AMD_CPPC_BIT));

const INTEL_VENDOR: [u32; 3] = [
    u32::from_le_bytes(*b"Genu"),
    u32::from_le_bytes(*b"ineI"),
    u32::from_le_bytes(*b"ntel"),
];

/// IA32_HWP_REQUEST bit 42: the package request (IA32_HWP_REQUEST_PKG)
/// governs this processor instead of its own fields.
const HWP_PACKAGE_CONTROL: u64 = 1 << 42;

/// What CPUID says about this processor's performance interfaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    pub intel: bool,
    pub amd: bool,
    pub hwp: bool,
    pub hwp_notify: bool,
    pub hwp_epp: bool,
    pub cppc: bool,
}

impl Features {
    /// This processor's enumeration. The vendor gates each interface as
    /// Linux's drivers do (intel_pstate loads on Intel only, amd-pstate on
    /// AMD only).
    pub fn read() -> Self {
        let identity = __cpuid(0);
        let vendor = [identity.ebx, identity.edx, identity.ecx];
        let intel = vendor == INTEL_VENDOR;
        let amd = vendor == AMD_VENDOR;
        Self {
            intel,
            amd,
            hwp: intel && HWP_BIT.present(),
            hwp_notify: intel && HWP_NOTIFY_BIT.present(),
            hwp_epp: intel && HWP_EPP_BIT.present(),
            cppc: amd && AMD_CPPC_BIT.present(),
        }
    }
}

/// The performance levels a processor publishes, on its own 8-bit scale.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Levels {
    pub highest: u8,
    /// Intel's guaranteed level; AMD's nominal level.
    pub sustained: u8,
    pub lowest: u8,
}

impl Levels {
    /// IA32_HWP_CAPABILITIES: highest 7:0, guaranteed 15:8, most efficient
    /// 23:16, lowest 31:24.
    pub fn intel(capabilities: u64) -> Self {
        Self {
            highest: capabilities as u8,
            sustained: (capabilities >> 8) as u8,
            lowest: (capabilities >> 24) as u8,
        }
    }

    /// CPPC_CAP1: lowest 7:0, lowest nonlinear 15:8, nominal 23:16,
    /// highest 31:24.
    pub fn amd(capabilities: u64) -> Self {
        Self {
            highest: (capabilities >> 24) as u8,
            sustained: (capabilities >> 16) as u8,
            lowest: capabilities as u8,
        }
    }

    /// Published levels that order, or none (an unprogrammed capability
    /// register), so the firmware's request stays.
    fn ordered(self) -> Option<Self> {
        (self.highest != 0 && self.lowest <= self.highest).then_some(self)
    }
}

/// A request's minimum and maximum levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub minimum: u8,
    pub maximum: u8,
}

/// The IA32_HWP_REQUEST value for `capabilities`, or none to keep the
/// firmware's request: minimum 7:0 and maximum 15:8 both the highest level
/// (intel_pstate `intel_pstate_hwp_set`: `min = max` under the performance
/// policy), desired 23:16 = 0, and with `epp` the energy preference 31:24 =
/// 0. Bits 63:32 stay.
pub fn intel_request(capabilities: u64, current: u64, epp: bool) -> Option<(u64, Bounds)> {
    let levels = Levels::intel(capabilities).ordered()?;
    let kept = if epp { !0xffff_ffff } else { !0x00ff_ffff };
    let highest = u64::from(levels.highest);
    let value = (current & kept) | highest | highest << 8;
    Some((
        value,
        Bounds {
            minimum: levels.highest,
            maximum: levels.highest,
        },
    ))
}

/// The CPPC_REQ value for `capabilities`, or none to keep the firmware's
/// request: maximum 7:0 the highest level, minimum 15:8 the firmware's
/// minimum when the request holds nothing else (amd-pstate's
/// `bios_min_perf`, `msr_init_perf`) and else the nominal level, never
/// above the maximum nor below the lowest level; desired 23:16 = 0 and
/// energy preference 31:24 = 0. Bits 63:32 stay.
pub fn amd_request(capabilities: u64, current: u64) -> Option<(u64, Bounds)> {
    const MINIMUM: u64 = 0xff << 8;
    let levels = Levels::amd(capabilities).ordered()?;
    let firmware_minimum = (current & !MINIMUM == 0).then_some((current >> 8) as u8);
    let minimum = firmware_minimum
        .filter(|&minimum| minimum != 0)
        .unwrap_or(levels.sustained)
        .clamp(levels.lowest, levels.highest);
    let value = (current & !0xffff_ffff) | u64::from(levels.highest) | u64::from(minimum) << 8;
    Some((
        value,
        Bounds {
            minimum,
            maximum: levels.highest,
        },
    ))
}

/// What this processor's performance request became.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Intel HWP asks for `bounds`; `package` when the package request
    /// governs this processor instead (request bit 42, firmware's choice).
    Hwp {
        levels: Levels,
        bounds: Bounds,
        epp: bool,
        package: bool,
    },
    /// AMD CPPC asks for `bounds`.
    Cppc { levels: Levels, bounds: Bounds },
    /// HWP without EPP that firmware left off: left off, as Linux does.
    HwpWithoutEpp,
    /// The capability register published no usable levels; the
    /// firmware's request stays.
    Unpublished,
    /// Neither interface is enumerated (legacy P-states, AMD shared-memory
    /// CPPC, or a hypervisor that hides them); nothing was touched.
    Legacy,
}

/// The model-specific registers [`request_with`] uses, so that tests can
/// see each access.
pub trait Registers {
    /// # Safety
    /// As [`Msr::read`].
    unsafe fn read(&mut self, msr: Msr) -> u64;
    /// # Safety
    /// As [`Msr::write`].
    unsafe fn write(&mut self, msr: Msr, value: u64);
}

/// This processor's registers.
pub struct Hardware;

impl Registers for Hardware {
    unsafe fn read(&mut self, msr: Msr) -> u64 {
        // SAFETY: the caller's contract.
        unsafe { msr.read() }
    }

    unsafe fn write(&mut self, msr: Msr, value: u64) {
        // SAFETY: the caller's contract.
        unsafe { msr.write(value) }
    }
}

/// Ask for full performance (module documentation) through `registers`,
/// touching only the registers `features` enumerates.
///
/// # Safety
/// CPL0 on the processor `features` describes, whose registers `registers`
/// reaches, with interrupts disabled and before guest code runs on it;
/// nothing else on this processor owns its P-state registers.
pub unsafe fn request_with(features: Features, registers: &mut impl Registers) -> Outcome {
    if features.hwp {
        // SAFETY: CPUID.06H:EAX[7] on an Intel CPU enumerates IA32_PM_ENABLE,
        // IA32_HWP_CAPABILITIES and IA32_HWP_REQUEST, and [8]
        // IA32_HWP_INTERRUPT. The request is written only with HWP on: it
        // faults while HWP is off. Each value keeps the bits it does not own.
        unsafe {
            let enabled = registers.read(PM_ENABLE) & 1 != 0;
            if !enabled && !features.hwp_epp {
                return Outcome::HwpWithoutEpp;
            }
            if features.hwp_notify {
                registers.write(HWP_INTERRUPT, 0);
            }
            if !enabled {
                registers.write(PM_ENABLE, 1);
            }
            let capabilities = registers.read(HWP_CAPABILITIES);
            let current = registers.read(HWP_REQUEST);
            let Some((value, bounds)) = intel_request(capabilities, current, features.hwp_epp)
            else {
                return Outcome::Unpublished;
            };
            registers.write(HWP_REQUEST, value);
            return Outcome::Hwp {
                levels: Levels::intel(capabilities),
                bounds,
                epp: features.hwp_epp,
                package: value & HWP_PACKAGE_CONTROL != 0,
            };
        }
    }
    if features.cppc {
        // SAFETY: CPUID 8000_0008H:EBX[27] on an AMD CPU enumerates the CPPC
        // registers; the enable precedes the request as amd-pstate orders
        // them. The request keeps its upper bits.
        unsafe {
            if registers.read(AMD_CPPC_ENABLE) & 1 == 0 {
                registers.write(AMD_CPPC_ENABLE, 1);
            }
            let capabilities = registers.read(AMD_CPPC_CAP1);
            let current = registers.read(AMD_CPPC_REQ);
            let Some((value, bounds)) = amd_request(capabilities, current) else {
                return Outcome::Unpublished;
            };
            registers.write(AMD_CPPC_REQ, value);
            return Outcome::Cppc {
                levels: Levels::amd(capabilities),
                bounds,
            };
        }
    }
    Outcome::Legacy
}

/// Ask this processor for full performance and count the outcome.
///
/// # Safety
/// As [`request_with`], on the calling processor.
pub unsafe fn request_full_performance() -> Outcome {
    // SAFETY: the caller's contract; `Features::read` describes this CPU.
    let outcome = unsafe { request_with(Features::read(), &mut Hardware) };
    TALLY.record(outcome);
    outcome
}

/// Processors per outcome and the range of published and requested
/// levels, for one report after the processors start.
pub struct Tally {
    outcomes: [AtomicU32; 5],
    package: AtomicU32,
    /// Lowest and highest of each processor's highest level, and of its
    /// requested minimum: the cores of a hybrid or preferred-core part
    /// publish different levels.
    highest: [AtomicU32; 2],
    minimum: [AtomicU32; 2],
}

impl Tally {
    pub const fn new() -> Self {
        Self {
            outcomes: [const { AtomicU32::new(0) }; 5],
            package: AtomicU32::new(0),
            highest: [AtomicU32::new(u32::MAX), AtomicU32::new(0)],
            minimum: [AtomicU32::new(u32::MAX), AtomicU32::new(0)],
        }
    }

    /// Count one processor's outcome.
    pub fn record(&self, outcome: Outcome) {
        let index = match outcome {
            Outcome::Hwp { .. } => 0,
            Outcome::Cppc { .. } => 1,
            Outcome::HwpWithoutEpp => 2,
            Outcome::Unpublished => 3,
            Outcome::Legacy => 4,
        };
        self.outcomes[index].fetch_add(1, Ordering::Relaxed);
        let (levels, bounds) = match outcome {
            Outcome::Hwp {
                levels,
                bounds,
                package,
                ..
            } => {
                self.package
                    .fetch_add(u32::from(package), Ordering::Relaxed);
                (levels, bounds)
            }
            Outcome::Cppc { levels, bounds } => (levels, bounds),
            _ => return,
        };
        self.highest[0].fetch_min(levels.highest.into(), Ordering::Relaxed);
        self.highest[1].fetch_max(levels.highest.into(), Ordering::Relaxed);
        self.minimum[0].fetch_min(bounds.minimum.into(), Ordering::Relaxed);
        self.minimum[1].fetch_max(bounds.minimum.into(), Ordering::Relaxed);
    }

    /// The outcomes as one report line.
    pub fn summary(&self) -> String {
        let count = |index: usize| self.outcomes[index].load(Ordering::Relaxed);
        let range = |pair: &[AtomicU32; 2]| {
            let (low, high) = (
                pair[0].load(Ordering::Relaxed),
                pair[1].load(Ordering::Relaxed),
            );
            match (low, high) {
                (u32::MAX, _) => String::from("none"),
                (low, high) if low == high => format!("{low}"),
                (low, high) => format!("{low}-{high}"),
            }
        };
        format!(
            "HOST PERFORMANCE hwp={} cppc={} hwp_without_epp={} unpublished={} legacy={} \
             package_controlled={} highest={} requested_minimum={} preference=performance\n",
            count(0),
            count(1),
            count(2),
            count(3),
            count(4),
            self.package.load(Ordering::Relaxed),
            range(&self.highest),
            range(&self.minimum),
        )
    }
}

impl Default for Tally {
    fn default() -> Self {
        Self::new()
    }
}

static TALLY: Tally = Tally::new();

/// The outcomes of every [`request_full_performance`] as one report line.
pub fn summary() -> String {
    TALLY.summary()
}

#[cfg(test)]
mod tests;
