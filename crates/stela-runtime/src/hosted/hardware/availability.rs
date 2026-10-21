//! Native Darwin CPU availability, not exclusive CPU ownership. One
//! HOST_BASIC_INFO reply owns every observation (kern/host.c). Later
//! fields of the old five-word reply remain explicitly unknown.
use anyhow::{Context as _, Result, ensure};

const HOST_BASIC_INFO: i32 = 1;
const HOST_BASIC_INFO_COUNT: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DarwinAvailability {
    pub maximum_slots: u32,
    pub available_slots: u32,
    pub physical_active: Option<u32>,
    pub physical_maximum: Option<u32>,
    pub logical_active: Option<u32>,
    pub logical_maximum: Option<u32>,
}

impl DarwinAvailability {
    /// The actual host's one snapshot. These are OS-observed counts; the
    /// Darwin scheduler supplies no exclusive physical binding here.
    pub fn observe() -> Result<Self> {
        unsafe extern "C" {
            fn host_info(host: u32, flavor: i32, words: *mut u32, count: *mut u32) -> i32;
            fn mach_port_deallocate(task: u32, name: u32) -> i32;
        }
        let mut words = [0u32; HOST_BASIC_INFO_COUNT];
        let mut count = HOST_BASIC_INFO_COUNT as u32;
        // SAFETY: the host right is owned until deallocation, and the
        // native output capacity is exactly count integer_t words.
        let status = unsafe {
            let host = super::super::darwin::mach_host_self();
            let status = host_info(host, HOST_BASIC_INFO, words.as_mut_ptr(), &raw mut count);
            mach_port_deallocate(super::super::host::task(), host);
            status
        };
        ensure!(status == 0, "native HOST_BASIC_INFO failed: {status:#x}");
        ensure!(
            count as usize <= words.len(),
            "native HOST_BASIC_INFO exceeded its capacity"
        );
        Self::from_words(&words[..count as usize])
    }

    /// Keep the source's distinction between old and current replies;
    /// unsigned storage must not turn a negative integer_t into capacity.
    fn from_words(words: &[u32]) -> Result<Self> {
        let field = |index: usize| -> Result<Option<u32>> {
            words
                .get(index)
                .map(|&value| {
                    ensure!(
                        value != 0 && value <= i32::MAX as u32,
                        "native HOST_BASIC_INFO word {index} is not a positive CPU count"
                    );
                    Ok(value)
                })
                .transpose()
        };
        ensure!(
            matches!(words.len(), 5 | HOST_BASIC_INFO_COUNT),
            "native HOST_BASIC_INFO has an unqualified {}-word layout",
            words.len()
        );
        let snapshot = Self {
            maximum_slots: field(0)?.context("HOST_BASIC_INFO lacks max_cpus")?,
            available_slots: field(1)?.context("HOST_BASIC_INFO lacks avail_cpus")?,
            physical_active: field(6)?,
            physical_maximum: field(7)?,
            logical_active: field(8)?,
            logical_maximum: field(9)?,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(self) -> Result<()> {
        ensure!(
            self.maximum_slots > 0
                && self.maximum_slots <= i32::MAX as u32
                && self.available_slots > 0
                && self.available_slots <= self.maximum_slots,
            "native available CPUs exceed maximum slots"
        );
        for (active, maximum, kind) in [
            (self.physical_active, self.physical_maximum, "physical"),
            (self.logical_active, self.logical_maximum, "logical"),
        ] {
            if let (Some(active), Some(maximum)) = (active, maximum) {
                ensure!(
                    active != 0 && active <= maximum && maximum <= i32::MAX as u32,
                    "native {kind} active/maximum CPU counts are inconsistent"
                );
            }
        }
        if let (Some(physical), Some(logical)) = (self.physical_active, self.logical_active) {
            ensure!(
                physical <= logical && logical == self.available_slots,
                "native active physical/logical/available CPU counts are inconsistent"
            );
        }
        if let (Some(physical), Some(logical)) = (self.physical_maximum, self.logical_maximum) {
            ensure!(
                physical <= logical && logical <= self.maximum_slots,
                "native maximum physical/logical/slot CPU counts are inconsistent"
            );
        }
        Ok(())
    }

    /// One logical guest CPU per observed physical core. This is a shared
    /// scheduler capacity budget, never a claim of exclusive assignment.
    pub(super) fn budget(self) -> Result<(u8, u8)> {
        self.validate()?;
        let active = self
            .physical_active
            .context("native physical active CPU count is unknown")?;
        let maximum = self
            .physical_maximum
            .context("native physical maximum CPU count is unknown")?;
        ensure!(
            self.logical_active.is_some() && self.logical_maximum.is_some(),
            "native logical CPU observations are unknown"
        );
        let active = u8::try_from(active)
            .context("physical active count exceeds the guest commpage width")?;
        let maximum = u8::try_from(maximum)
            .context("physical maximum count exceeds the guest commpage width")?;
        Ok((active, maximum))
    }
}

/// One configured guest execution group, owned by the hosted process's
/// shared ExecutionLock and identical CPU0 semantics. Native logical
/// observations remain separate; no affinity or native cache mapping is
/// implied by this configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SharedScheduler {
    pub observed: DarwinAvailability,
    pub active: u8,
    pub maximum: u8,
}

impl SharedScheduler {
    pub fn new(observed: DarwinAvailability) -> Result<Self> {
        let (active, maximum) = observed.budget()?;
        Ok(Self {
            observed,
            active,
            maximum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words() -> [u32; HOST_BASIC_INFO_COUNT] {
        [16, 12, 0, 0, 0, 0, 6, 8, 12, 16, 0, 0]
    }

    #[test]
    fn native_smt_observations_do_not_double_guest_capacity() {
        let observed = DarwinAvailability::from_words(&words()).unwrap();
        let plan = SharedScheduler::new(observed).unwrap();
        assert_eq!((plan.active, plan.maximum), (6, 8));
        assert_eq!(
            (plan.observed.logical_active, plan.observed.logical_maximum),
            (Some(12), Some(16))
        );
        let old = DarwinAvailability::from_words(&words()[..5]).unwrap();
        assert_eq!(old.physical_active, None);
        assert!(old.budget().is_err());
    }

    #[test]
    fn malformed_widths_counts_and_relationships_cannot_become_capacity() {
        for count in 0..HOST_BASIC_INFO_COUNT {
            if count != 5 {
                assert!(DarwinAvailability::from_words(&words()[..count]).is_err());
            }
        }
        for (index, value) in [
            (0, 0),
            (1, u32::MAX),
            (6, 0),
            (6, 9),
            (7, 17),
            (8, 11),
            (9, 17),
        ] {
            let mut words = words();
            words[index] = value;
            assert!(
                DarwinAvailability::from_words(&words).is_err(),
                "{index}={value}"
            );
        }
        let mut too_wide = words();
        for index in [0, 1, 6, 7, 8, 9] {
            too_wide[index] = 256;
        }
        assert!(
            DarwinAvailability::from_words(&too_wide)
                .unwrap()
                .budget()
                .is_err()
        );
    }

    #[test]
    fn the_native_snapshot_has_source_qualified_cpu_counts() {
        let observed = DarwinAvailability::observe().unwrap();
        eprintln!("native CPU availability: {observed:?}; shared scheduler, no exclusive binding");
        let (active, maximum) = observed.budget().unwrap();
        assert!(active > 0 && active <= maximum);
    }
}
