// SPDX-License-Identifier: GPL-2.0-only
//! Native HPET power validation and private CPU TSC calibration.
//! TSC remains a candidate: no Cpu/Clock/Idle implementation,
//! Prepared variant or service grant can be constructed from this observation.
//! Absent ADJUST remains an explicit owned-watchdog requirement; a temporary
//! HPET active-spin reference is not that persistent watchdog or PC10 proof.
mod deadline;
pub(super) use deadline::Control as DeadlineControl;
mod hpet_power;
use super::{HpetCounter, WorkError};
use crate::{engine::host::RootIdentity, handoff::Handoff, native_smp::firmware};
use alloc::sync::Arc;
use core::{
    arch::{asm, x86_64::__cpuid_count},
    marker::PhantomData,
};
pub(super) use hpet_power::PowerControl;
use stela_boot_core::{
    topology::Snapshot,
    tsc::{self, Calibration, CounterPolicy, RateRequirement, Sample},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Work(WorkError),
    Policy(tsc::Error),
    Inventory,
    ChangedControl,
}
impl From<WorkError> for Error {
    fn from(value: WorkError) -> Self {
        Self::Work(value)
    }
}
impl From<tsc::Error> for Error {
    fn from(value: tsc::Error) -> Self {
        Self::Policy(value)
    }
}
#[derive(Debug)]
pub(crate) struct Observation<'a> {
    pub policy: CounterPolicy,
    pub calibration: &'a Calibration,
    pub reference_table: [u8; 32],
    pub reference_period_fs: u32,
}
pub(crate) struct Candidate {
    identity: Arc<RootIdentity>,
    captured: Snapshot,
    packages: u32,
    policy: CounterPolicy,
    calibration: Calibration,
    reference_table: [u8; 32],
    reference_period_fs: u32,
    previous: u64,
    failure: Option<Error>,
    _local: PhantomData<*mut ()>,
}
// Baseline CPUID is serializing on admitted x86-64. Do not presume
// AMD LFENCE ordering or use unchecked RDTSCP/TSC_AUX as an affinity lease.
pub(super) fn ordered() -> u64 {
    let _ = __cpuid_count(0, 0);
    let (low, high): (u32, u32);
    // SAFETY: only called after kept-CPU TSC feature admission.
    // Default memory clobber and both CPUIDs enclose the exact ordered sample.
    unsafe {
        asm!("rdtsc",out("eax")low,out("edx")high,options(nostack,preserves_flags));
    }
    let result = (u64::from(high) << 32) | u64::from(low);
    let _ = __cpuid_count(0, 0);
    result
}
fn live_policy(
    identity: &RootIdentity,
    captured: &Snapshot,
    packages: u32,
) -> Result<CounterPolicy, Error> {
    identity.check_dispatch()?;
    let mut live = *captured;
    let records = live
        .records
        .get_mut(..live.count as usize)
        .ok_or(tsc::Error::MalformedCapture)?;
    for record in records {
        if matches!(
            record.leaf,
            0 | 1 | 6 | 7 | 0xb | 0x15 | 0x1f | 0x8000_0000 | 0x8000_0001 | 0x8000_0007
        ) {
            let value = __cpuid_count(record.leaf, record.subleaf);
            (record.eax, record.ebx, record.ecx, record.edx) =
                (value.eax, value.ebx, value.ecx, value.edx);
        }
    }
    // Never probe an absent control: only the live ADJUST feature gates
    // this privileged read. Missing/changed records remain explicit failures.
    if live.get(7, 0).is_some_and(|leaf| leaf.ebx & (1 << 1) != 0) {
        let records = live
            .msrs
            .get_mut(..live.msr_count as usize)
            .ok_or(tsc::Error::MalformedCapture)?;
        for record in records.iter_mut().filter(|record| record.index == 0x3b) {
            // SAFETY: CPL0 kept CPU, live CPUID gates TSC_ADJUST.
            record.value = unsafe { crate::cpu::msr::TSC_ADJUST.read() };
        }
    }
    Ok(tsc::counter_policy(&live, packages)?)
}
impl Candidate {
    /// # Safety
    /// Original post-EBS handoff/capture/HostOwner identity and native
    /// HPET exclusive handoff are held, not reconstructed records. IF0 on
    /// that BSP, no migration/suspend/reset/control writer or reference wrap;
    /// no native/helper frame, external HPET route or overlapping source user.
    /// Reference is bounded active-spin only; retire it before any later HLT.
    pub(crate) unsafe fn observe(
        handoff: &Handoff,
        identity: Arc<RootIdentity>,
        reference: &HpetCounter,
    ) -> Result<Self, Error> {
        identity.check_dispatch()?;
        // SAFETY: caller keeps the sealed loader record and physmap.
        let capture = unsafe { firmware::captured(handoff.native_processors) }
            .map_err(|_| Error::Inventory)?;
        let bsp = capture
            .processors
            .get(capture.selected[0] as usize)
            .ok_or(Error::Inventory)?;
        let captured = identity.processor_snapshot()?;
        if captured.apic_id().map(u64::from) != Some(bsp.apic_id) {
            return Err(Error::Inventory);
        }
        let mut packages = 0u32;
        for (index, processor) in capture.processors.iter().enumerate() {
            if !capture.processors[..index]
                .iter()
                .any(|prior| prior.location.package == processor.location.package)
            {
                packages = packages.checked_add(1).ok_or(Error::Inventory)?;
            }
        }
        let original = tsc::counter_policy(&capture.snapshots[0], packages)?;
        let policy = tsc::counter_policy(&captured, packages)?;
        if original != policy || live_policy(&identity, &captured, packages)? != policy {
            return Err(Error::ChangedControl);
        }
        // Reference authenticity before any raw access, but not from a numeric
        // base/table digest alone. The method checks native owner/Arc.
        reference.calibration_sample(&identity)?;
        let period = reference.period_fs();
        let calibration = tsc::calibrate_hpet::<Error>(period, || {
            if live_policy(&identity, &captured, packages)? != policy {
                return Err(Error::ChangedControl);
            }
            let tsc_before = ordered();
            let reference_value = reference.calibration_sample(&identity)?;
            let tsc_after = ordered();
            if live_policy(&identity, &captured, packages)? != policy {
                return Err(Error::ChangedControl);
            }
            Ok(Sample {
                tsc_before,
                reference: reference_value,
                tsc_after,
            })
        })?;
        if let RateRequirement::HardwareCrystalRatio(rate) = policy.rate
            && !calibration.rate_window().contains_rate(rate)
        {
            return Err(tsc::Error::InconsistentRate.into());
        }
        let previous = ordered();
        Ok(Self {
            identity,
            captured,
            packages,
            policy,
            calibration,
            reference_table: reference.descriptor().table_sha256(),
            reference_period_fs: period,
            previous,
            failure: None,
            _local: PhantomData,
        })
    }
    /// Reobserve control/rate/affinity and monotonicity; first failure is
    /// permanent. This is calibration evidence, never a continuous-time grant.
    pub(crate) fn recheck(&mut self) -> Result<u64, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = (|| {
            if live_policy(&self.identity, &self.captured, self.packages)? != self.policy {
                return Err(Error::ChangedControl);
            }
            let raw = ordered();
            if raw < self.previous {
                return Err(tsc::Error::Backwards.into());
            }
            if live_policy(&self.identity, &self.captured, self.packages)? != self.policy {
                return Err(Error::ChangedControl);
            }
            Ok(raw)
        })();
        match result {
            Ok(raw) => {
                self.previous = raw;
                Ok(raw)
            }
            Err(error) => {
                self.failure = Some(error);
                Err(error)
            }
        }
    }
    pub(crate) fn observation(&self) -> Result<Observation<'_>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(Observation {
            policy: self.policy,
            calibration: &self.calibration,
            reference_table: self.reference_table,
            reference_period_fs: self.reference_period_fs,
        })
    }
}
