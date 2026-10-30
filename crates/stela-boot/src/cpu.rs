//! The host CPU from CPUID (Intel SDM Vol. 2A "CPUID"; AMD APM Vol. 3
//! appendix E): its identity and features for the host check's report, and
//! the floor Stela needs, x86-64-v2 (SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT,
//! CMPXCHG16B, LAHF/SAHF in 64-bit mode) and NX for its page tables.
pub use stela_boot_core::msr;

#[cfg(feature = "diagnostics")]
use Register::{Eax, Ebx};
use Register::{Ecx, Edx};
#[cfg(feature = "diagnostics")]
mod report;
use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};
#[cfg(feature = "diagnostics")]
pub use report::*;

const EXTENDED: u32 = 0x8000_0000;
#[derive(Clone, Copy)]
enum Register {
    #[cfg(feature = "diagnostics")]
    Eax,
    #[cfg(feature = "diagnostics")]
    Ebx,
    Ecx,
    Edx,
}

/// One CPUID feature bit.
#[derive(Clone, Copy)]
pub struct Feature {
    #[cfg(feature = "diagnostics")]
    pub name: &'static str,
    leaf: u32,
    subleaf: u32,
    register: Register,
    bit: u32,
}

const fn bit(_name: &'static str, leaf: u32, register: Register, bit: u32) -> Feature {
    Feature {
        #[cfg(feature = "diagnostics")]
        name: _name,
        leaf,
        subleaf: 0,
        register,
        bit,
    }
}

/// CPUID `leaf`.`subleaf`, or `None` beyond the CPU's highest leaf of
/// that range.
fn leaf(leaf: u32, subleaf: u32) -> Option<CpuidResult> {
    (leaf <= __cpuid(leaf & EXTENDED).eax).then(|| __cpuid_count(leaf, subleaf))
}

impl Feature {
    pub fn present(&self) -> bool {
        leaf(self.leaf, self.subleaf).is_some_and(|result| {
            let value = match self.register {
                #[cfg(feature = "diagnostics")]
                Register::Eax => result.eax,
                #[cfg(feature = "diagnostics")]
                Register::Ebx => result.ebx,
                Register::Ecx => result.ecx,
                Register::Edx => result.edx,
            };
            value & (1 << self.bit) != 0
        })
    }
}

pub const LA57: Feature = bit("LA57", 7, Ecx, 16);

pub const INVARIANT_TSC: Feature = bit("invariant-TSC", 0x8000_0007, Edx, 8);
