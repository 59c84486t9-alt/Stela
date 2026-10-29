use super::{Error, RationalRate};
use crate::topology::{Cpuid, Snapshot};
const ADJUST: u32 = 0x3b;
const PACKAGE_LIMIT: u32 = 0xe2;
const INTEL: [u32; 3] = [
    u32::from_le_bytes(*b"Genu"),
    u32::from_le_bytes(*b"ineI"),
    u32::from_le_bytes(*b"ntel"),
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Serialization {
    Rdtscp,
    SerializingCpuid,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deadline {
    Arat,
    RequiresOwnedBroadcast,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reliability {
    /// Actual adjustment observation; native code still checks instability,
    /// retained controls/epoch and changes, not just this feature combination.
    AdjustmentMonitored {
        observed: u64,
    },
    RequiresOwnedReferenceWatchdog,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RateRequirement {
    HardwareCrystalRatio(RationalRate),
    RequiresObservedCalibration,
}
/// Policy data only, never an admitted continuous counter or synchronized SMP
/// timebase. Safe model construction cannot supply a native capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterPolicy {
    pub apic_id: u32,
    pub serialization: Serialization,
    pub reliability: Reliability,
    pub deadline: Deadline,
    pub rate: RateRequirement,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpetPowerConstraint {
    NoPc10Indication,
    /// Preserve this actual power/control lease; a later limit change requires
    /// requalification/source transition, not disabling deep idle as a workaround.
    RequiresStablePackageLimit {
        observed: u64,
    },
}
fn leaf(snapshot: &Snapshot, index: u32) -> Result<Cpuid, Error> {
    let records = snapshot
        .records
        .get(..snapshot.count as usize)
        .ok_or(Error::MalformedCapture)?;
    let mut matching = records.iter().filter(|r| r.leaf == index && r.subleaf == 0);
    let value = matching.next().copied().ok_or(Error::MissingCpuid(index))?;
    if matching.next().is_some() {
        return Err(Error::DuplicateCpuid(index));
    }
    Ok(value)
}
fn msr(snapshot: &Snapshot, index: u32) -> Result<u64, Error> {
    let records = snapshot
        .msrs
        .get(..snapshot.msr_count as usize)
        .ok_or(Error::MalformedCapture)?;
    let mut matching = records.iter().filter(|r| r.index == index);
    let value = matching
        .next()
        .map(|r| r.value)
        .ok_or(Error::MissingMsr(index))?;
    if matching.next().is_some() {
        return Err(Error::DuplicateMsr(index));
    }
    Ok(value)
}
/// Linux cc9de5d4 init_amd derives the always-running LAPIC timer for
/// family0x12 onward even when CPUID6 does not expose the Intel ARAT bit.
pub fn deadline_policy(snapshot: &Snapshot) -> Result<Deadline, Error> {
    let identity = leaf(snapshot, 0)?;
    let basic = leaf(snapshot, 1)?;
    let amd = [identity.ebx, identity.edx, identity.ecx]
        == [
            u32::from_le_bytes(*b"Auth"),
            u32::from_le_bytes(*b"enti"),
            u32::from_le_bytes(*b"cAMD"),
        ];
    let base = basic.eax >> 8 & 15;
    let family = if base == 15 {
        base + (basic.eax >> 20 & 255)
    } else {
        base
    };
    if amd && family > 0x11 {
        return Ok(Deadline::Arat);
    }
    if identity.eax >= 6 && leaf(snapshot, 6)?.eax & (1 << 2) != 0 {
        Ok(Deadline::Arat)
    } else {
        Ok(Deadline::RequiresOwnedBroadcast)
    }
}

fn intel(identity: Cpuid) -> bool {
    [identity.ebx, identity.edx, identity.ecx] == INTEL
}
/// Classify actual observations or authored model input. Caller/package data is
/// not trusted native ownership; native admission independently binds it to the
/// current CPU, original capture, resource/control owner and reliability policy.
pub fn counter_policy(snapshot: &Snapshot, packages: u32) -> Result<CounterPolicy, Error> {
    if packages == 0 {
        return Err(Error::InvalidPackageCount);
    }
    let identity = leaf(snapshot, 0)?;
    if identity.eax < 1 {
        return Err(Error::TscUnavailable);
    }
    let basic = leaf(snapshot, 1)?;
    if basic.edx & (1 << 4) == 0 {
        return Err(Error::TscUnavailable);
    }
    if basic.ecx & (1 << 31) != 0 {
        return Err(Error::HypervisorContractRequired);
    }
    if leaf(snapshot, 0x8000_0000)?.eax < 0x8000_0007 {
        return Err(Error::InvariantUnavailable);
    }
    if leaf(snapshot, 0x8000_0007)?.edx & (1 << 8) == 0 {
        return Err(Error::InvariantUnavailable);
    }
    let serialization = if leaf(snapshot, 0x8000_0001)?.edx & (1 << 27) != 0 {
        Serialization::Rdtscp
    } else {
        Serialization::SerializingCpuid
    };
    let adjust = if identity.eax >= 7 && leaf(snapshot, 7)?.ebx & (1 << 1) != 0 {
        Some(msr(snapshot, ADJUST)?)
    } else {
        None
    };
    let reliability = match adjust {
        Some(observed) if packages <= 4 => Reliability::AdjustmentMonitored { observed },
        _ => Reliability::RequiresOwnedReferenceWatchdog,
    };
    let deadline = deadline_policy(snapshot)?;
    let rate = if intel(identity) && identity.eax >= 0x15 {
        let ratio = leaf(snapshot, 0x15)?;
        if ratio.eax != 0 && ratio.ebx != 0 && ratio.ecx != 0 {
            RateRequirement::HardwareCrystalRatio(RationalRate::new(
                u64::from(ratio.ecx) * u64::from(ratio.ebx),
                u64::from(ratio.eax),
            )?)
        } else {
            RateRequirement::RequiresObservedCalibration
        }
    } else {
        RateRequirement::RequiresObservedCalibration
    };
    Ok(CounterPolicy {
        apic_id: snapshot.apic_id().ok_or(Error::MalformedCapture)?,
        serialization,
        reliability,
        deadline,
        rate,
    })
}
/// Pinned Linux hpet.c mwait_pc10_supported/hpet_is_pc10_damaged policy.
/// Absence of this one known problem is not proof of controller continuity.
pub fn hpet_power_constraint(snapshot: &Snapshot) -> Result<HpetPowerConstraint, Error> {
    let identity = leaf(snapshot, 0)?;
    if !intel(identity) || identity.eax < 5 || leaf(snapshot, 1)?.ecx & (1 << 3) == 0 {
        return Ok(HpetPowerConstraint::NoPc10Indication);
    }
    let mwait = leaf(snapshot, 5)?;
    if mwait.ecx & 3 != 3 || mwait.edx & (0xf << 28) == 0 {
        return Ok(HpetPowerConstraint::NoPc10Indication);
    }
    let observed = msr(snapshot, PACKAGE_LIMIT)?;
    if observed & 0xf >= 8 {
        return Err(Error::Pc10StopsHpet);
    }
    Ok(HpetPowerConstraint::RequiresStablePackageLimit { observed })
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    fn observed(family: u32, amd: bool, arat: bool) -> Snapshot {
        let mut snapshot = Snapshot::default();
        let vendor = if amd {
            [*b"Auth", *b"enti", *b"cAMD"]
        } else {
            [*b"Genu", *b"ineI", *b"ntel"]
        };
        snapshot.records[0] = Cpuid {
            leaf: 0,
            eax: 6,
            ebx: u32::from_le_bytes(vendor[0]),
            edx: u32::from_le_bytes(vendor[1]),
            ecx: u32::from_le_bytes(vendor[2]),
            ..Cpuid::default()
        };
        snapshot.records[1] = Cpuid {
            leaf: 1,
            eax: (15 << 8) | ((family - 15) << 20),
            ..Cpuid::default()
        };
        snapshot.records[2] = Cpuid {
            leaf: 6,
            eax: if arat { 1 << 2 } else { 0 },
            ..Cpuid::default()
        };
        snapshot.count = 3;
        snapshot
    }
    #[test]
    fn amd_deep_idle_timer_support_does_not_require_the_intel_feature_bit() {
        assert_eq!(
            deadline_policy(&observed(0x19, true, false)),
            Ok(Deadline::Arat)
        );
        assert_eq!(
            deadline_policy(&observed(0x12, true, false)),
            Ok(Deadline::Arat)
        );
        assert_eq!(
            deadline_policy(&observed(0x11, true, false)),
            Ok(Deadline::RequiresOwnedBroadcast)
        );
    }
    #[test]
    fn other_vendors_need_their_observed_arat_bit() {
        assert_eq!(
            deadline_policy(&observed(0x19, false, false)),
            Ok(Deadline::RequiresOwnedBroadcast)
        );
        assert_eq!(
            deadline_policy(&observed(0x19, false, true)),
            Ok(Deadline::Arat)
        );
    }
}
