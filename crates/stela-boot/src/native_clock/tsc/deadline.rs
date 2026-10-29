// SPDX-License-Identifier: GPL-2.0-only
//! Actual LAPIC idle/rate eligibility, including Linux init_amd family rules.
use super::super::WorkError;
use core::arch::x86_64::__cpuid_count;
use stela_boot_core::{
    topology::{Cpuid, Snapshot},
    tsc::{self, Deadline},
};

pub(in crate::native_clock) struct Control {
    identity: [u32; 4],
    basic: [u32; 4],
    thermal: Option<[u32; 4]>,
}
fn query(leaf: u32) -> [u32; 4] {
    let value = __cpuid_count(leaf, 0);
    [value.eax, value.ebx, value.ecx, value.edx]
}
fn record(leaf: u32, value: [u32; 4]) -> Cpuid {
    Cpuid {
        leaf,
        subleaf: 0,
        eax: value[0],
        ebx: value[1],
        ecx: value[2],
        edx: value[3],
    }
}
impl Control {
    pub(in crate::native_clock) fn capture() -> Result<Self, WorkError> {
        let identity = query(0);
        if identity[0] < 1 {
            return Err(WorkError::Unavailable);
        }
        let basic = query(1);
        let thermal = (identity[0] >= 6).then(|| query(6));
        let mut snapshot = Snapshot::default();
        snapshot.records[0] = record(0, identity);
        snapshot.records[1] = record(1, basic);
        snapshot.count = 2;
        if let Some(value) = thermal {
            snapshot.records[2] = record(6, value);
            snapshot.count = 3;
        }
        if tsc::deadline_policy(&snapshot).map_err(|_| WorkError::Unavailable)? != Deadline::Arat {
            return Err(WorkError::Unavailable);
        }
        Ok(Self {
            identity,
            basic,
            thermal,
        })
    }
    pub(in crate::native_clock) fn max_cpuid(&self) -> u32 {
        self.identity[0]
    }
    pub(in crate::native_clock) fn thermal_eax(&self) -> u32 {
        self.thermal.map_or(0, |value| value[0])
    }
    pub(in crate::native_clock) fn check(&self) -> Result<(), WorkError> {
        if query(0) != self.identity
            || query(1) != self.basic
            || self.thermal.is_some_and(|value| query(6) != value)
        {
            return Err(WorkError::CorruptContext);
        }
        Ok(())
    }
}
