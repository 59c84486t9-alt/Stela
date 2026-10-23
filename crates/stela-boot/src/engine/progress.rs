//! Read-only boot observations, never an estimate of total boot completion.
extern crate alloc;

use alloc::{format, string::String, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Component {
    SecureMonitor,
    TrustedMonitor,
    Kernel,
}

impl Component {
    fn region(name: &str) -> Option<Self> {
        let (image, segment) = name.rsplit_once('-')?;
        if !matches!(segment, "rx" | "bx") {
            return None;
        }
        // These are boot-bundle component/segment roles, not source addresses,
        // application identities or assumptions about a particular build.
        match image {
            "SPTM" => Some(Self::SecureMonitor),
            "TXM" => Some(Self::TrustedMonitor),
            "BootKC" => Some(Self::Kernel),
            _ => None,
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::SecureMonitor => "Secure monitor (SPTM)",
            Self::TrustedMonitor => "Trusted execution monitor (TXM)",
            Self::Kernel => "macOS kernel",
        }
    }
}

struct CodeRange {
    component: Component,
    start: u64,
    end: u64,
}

#[derive(Default)]
pub(super) struct BootProgress {
    ranges: Vec<CodeRange>,
    sampled: Option<(u64, u64)>,
    reported: u8,
    installer: Option<String>,
}

pub(super) struct Update {
    pub detail: String,
    pub first_component: Option<Component>,
}

impl BootProgress {
    pub(super) fn new<'a>(regions: impl Iterator<Item = (&'a str, u64, u64)>) -> Self {
        let ranges = regions
            .filter_map(|(name, start, bytes)| {
                Some(CodeRange {
                    component: Component::region(name)?,
                    start,
                    end: start.checked_add(bytes).filter(|end| *end > start)?,
                })
            })
            .collect();
        Self {
            ranges,
            ..Self::default()
        }
    }

    pub(super) fn start(&mut self, ticks: u64, blocks: u64) {
        self.sampled = Some((ticks, blocks));
    }

    pub(super) fn installer(&mut self, step: String) {
        self.installer = Some(step);
    }

    pub(super) fn due(&self, ticks: u64, hz: u64) -> bool {
        self.sampled
            .is_some_and(|(last, _)| ticks.wrapping_sub(last) >= hz.max(1))
    }

    /// Called at a stopped host-service boundary, at most once per second.
    /// The physical instruction address comes from a read-only current-regime
    /// walk. Failure or an unclassified address never invents a component.
    pub(super) fn sample(
        &mut self,
        physical: Option<u64>,
        ticks: u64,
        hz: u64,
        blocks: u64,
    ) -> Option<Update> {
        if !self.due(ticks, hz) {
            return None;
        }
        let (last, previous) = self.sampled.replace((ticks, blocks))?;
        let elapsed = ticks.wrapping_sub(last);
        let rate =
            u128::from(blocks.saturating_sub(previous)) * u128::from(hz) / u128::from(elapsed);
        let component = physical.and_then(|physical| {
            let mut matches = self
                .ranges
                .iter()
                .filter(|range| (range.start..range.end).contains(&physical));
            let first = matches.next()?.component;
            // Ambiguous metadata must not assert which image is executing.
            matches
                .all(|range| range.component == first)
                .then_some(first)
        });
        let first_component = component.filter(|component| {
            let bit = 1 << (*component as u8);
            let first = self.reported & bit == 0;
            self.reported |= bit;
            first
        });
        let stage = self
            .installer
            .as_deref()
            .unwrap_or_else(|| component.map_or("Boot execution", |component| component.name()));
        Some(Update {
            detail: format!("{stage} | {blocks} blocks executed, {rate}/s"),
            first_component,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_follow_current_source_ranges_without_a_boot_percentage() {
        let mut progress = BootProgress::new(
            [("SPTM-rx", 0x1000, 0x100), ("BootKC-bx", 0x2000, 0x100)].into_iter(),
        );
        progress.start(10, 0);
        assert!(progress.sample(Some(0x1000), 109, 100, 99).is_none());
        let first = progress.sample(Some(0x10ff), 110, 100, 100).unwrap();
        assert_eq!(first.first_component, Some(Component::SecureMonitor));
        assert!(first.detail.contains("100 blocks executed, 100/s"));
        assert!(!first.detail.contains('%'));
        let unknown = progress.sample(Some(0x1100), 210, 100, 100).unwrap();
        assert!(unknown.detail.starts_with("Boot execution"));
        assert!(unknown.detail.ends_with("0/s"));
        let kernel = progress.sample(Some(0x2000), 310, 100, 200).unwrap();
        assert_eq!(kernel.first_component, Some(Component::Kernel));
        let monitor = progress.sample(Some(0x1000), 410, 100, 250).unwrap();
        assert_eq!(monitor.first_component, None);
        assert!(monitor.detail.starts_with("Secure monitor (SPTM)"));
    }

    #[test]
    fn unknown_or_ambiguous_source_never_reports_a_component() {
        let mut progress = BootProgress::new(
            [
                ("SPTM-rw", 0x1000, 0x100),
                ("TXM-rx", u64::MAX, 2),
                ("SPTM-rx", 0x2000, 0x100),
                ("BootKC-rx", 0x2000, 0x100),
            ]
            .into_iter(),
        );
        progress.start(0, 0);
        for (ticks, physical) in [(1, Some(0x1000)), (2, Some(0x2000)), (3, None)] {
            let update = progress.sample(physical, ticks, 1, ticks).unwrap();
            assert_eq!(update.first_component, None);
            assert!(update.detail.starts_with("Boot execution"));
        }
        progress.installer(String::from("installer: restoring system"));
        assert!(
            progress
                .sample(None, 4, 1, 4)
                .unwrap()
                .detail
                .starts_with("installer:")
        );
    }
}
