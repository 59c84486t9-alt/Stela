// SPDX-License-Identifier: GPL-2.0-only
//! Pure native-time policy and calibration arithmetic. Rules follow pinned Linux
//! 8d0a987907fe264b5688fa9c76e25b533c31a3dd arch/x86/kernel/{tsc,tsc_sync,hpet}.c
//! and arch/x86/include/asm/tsc.h. These values grant no CPU, clock, register,
//! mapping, lifecycle, synchronization or interrupt permission. Native admission
//! must observe the real retained owner/controls, reliability and progress.
mod calibration;
mod features;
pub use calibration::{RateWindow, RationalRate, ReferenceScale, Sample, wrapped_delta};
pub use features::{
    CounterPolicy, Deadline, HpetPowerConstraint, RateRequirement, Reliability, Serialization,
    counter_policy, hpet_power_constraint,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MalformedCapture,
    MissingCpuid(u32),
    DuplicateCpuid(u32),
    MissingMsr(u32),
    DuplicateMsr(u32),
    TscUnavailable,
    InvariantUnavailable,
    HypervisorContractRequired,
    InvalidPackageCount,
    Pc10StopsHpet,
    InvalidRate,
    InvalidMask,
    NoProgress,
    Backwards,
    Disturbed,
    Overflow,
    InconsistentRate,
}
#[cfg(test)]
mod tests;
