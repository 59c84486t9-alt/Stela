//! Pure geometry for original captured ECAM/RootBridge descriptions.
//! This module creates no Resource, mapping, device exclusion or root authority.
use alloc::vec::Vec;
use core::ops::RangeInclusive;
use stela_drivers::bus::{
    mmio::owned::{Error, PhysicalSpan},
    pci::EcamWindow,
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(super) struct RootWindow {
    pub segment: u32,
    pub bridge: u32,
    pub flags: u8,
    pub specific: u8,
    pub space: u8,
    pub reserved: u8,
    pub minimum: u64,
    pub maximum: u64,
    pub translation: u64,
    pub length: u64,
}

fn physical(window: EcamWindow, bits: u8) -> Result<PhysicalSpan, Error> {
    if !(32..=52).contains(&bits) || window.start_bus > window.end_bus {
        return Err(Error::InvalidRange);
    }
    let start = window
        .base
        .checked_add(u64::from(window.start_bus) << 20)
        .ok_or(Error::InvalidRange)?;
    let end = window
        .base
        .checked_add((u64::from(window.end_bus) + 1) << 20)
        .ok_or(Error::InvalidRange)?;
    if end > 1u64 << bits {
        return Err(Error::InvalidRange);
    }
    PhysicalSpan::new(start, end - start)
}

/// Borrowed immutable descriptions whose COMPLETE original MCFG windows were
/// checked before any subset is selected. This remains descriptive metadata;
/// only Source joins its actual captured bytes/owner and mints a reservation.
pub(super) struct EcamInventory<'a> {
    windows: &'a [EcamWindow],
    bits: u8,
}
impl<'a> EcamInventory<'a> {
    pub(super) fn validate(windows: &'a [EcamWindow], bits: u8) -> Result<Self, Error> {
        let mut spans: Vec<PhysicalSpan> = Vec::new();
        spans
            .try_reserve_exact(windows.len())
            .map_err(|_| Error::Unavailable)?;
        for (at, window) in windows.iter().enumerate() {
            let span = physical(*window, bits)?;
            if windows[..at]
                .iter()
                .zip(&spans)
                .any(|(previous, physical)| {
                    (previous.segment == window.segment
                        && previous.start_bus <= window.end_bus
                        && window.start_bus <= previous.end_bus)
                        || (physical.start() < span.end() && span.start() < physical.end())
                })
            {
                return Err(Error::ResourceConflict);
            }
            spans.push(span);
        }
        Ok(Self { windows, bits })
    }

    pub(super) fn subset(
        &self,
        index: usize,
        buses: RangeInclusive<u8>,
        roots: &[RootWindow],
    ) -> Result<(EcamWindow, PhysicalSpan), Error> {
        if buses.is_empty() {
            return Err(Error::OutsideResource);
        }
        let mut window = *self.windows.get(index).ok_or(Error::OutsideResource)?;
        let (first, last) = (*buses.start(), *buses.end());
        if first > last || first < window.start_bus || last > window.end_bus {
            return Err(Error::OutsideResource);
        }
        let mut matching = roots.iter().filter(|root| {
            root.segment == u32::from(window.segment)
                && root.space == 2
                && root.translation == 0
                && root.flags & !0x0f == 0
                && root.flags & 2 == 0
                && root.minimum <= u64::from(first)
                && u64::from(last) <= root.maximum
                && root.maximum <= 255
                && root
                    .maximum
                    .checked_sub(root.minimum)
                    .and_then(|bytes| bytes.checked_add(1))
                    == Some(root.length)
        });
        matching.next().ok_or(Error::OutsideResource)?;
        if matching.next().is_some() {
            return Err(Error::ResourceConflict);
        }
        window.start_bus = first;
        window.end_bus = last;
        Ok((window, physical(window, self.bits)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(base: u64, segment: u16, first: u8, last: u8) -> EcamWindow {
        EcamWindow {
            base,
            segment,
            start_bus: first,
            end_bus: last,
        }
    }
    fn parent(first: u8, last: u8) -> RootWindow {
        RootWindow {
            bridge: 1,
            space: 2,
            minimum: u64::from(first),
            maximum: u64::from(last),
            length: u64::from(last) - u64::from(first) + 1,
            ..RootWindow::default()
        }
    }

    #[test]
    fn captured_bus_zero_parent_issues_only_requested_bus_zero() {
        let original = [window(0xe000_0000, 0, 0, 255)];
        let inventory = EcamInventory::validate(&original, 48).unwrap();
        let roots = [parent(0, 0)];
        let (selected, span) = inventory.subset(0, 0..=0, &roots).unwrap();
        assert_eq!(selected, window(0xe000_0000, 0, 0, 0));
        assert_eq!(span, PhysicalSpan::new(0xe000_0000, 1 << 20).unwrap());
        assert_eq!(
            inventory.subset(0, 0..=1, &roots),
            Err(Error::OutsideResource)
        );
        assert_eq!(
            inventory.subset(0, 0..=255, &roots),
            Err(Error::OutsideResource)
        );
        let mut exhausted = 0..=0;
        assert_eq!(exhausted.next(), Some(0));
        assert!(exhausted.is_empty());
        assert_eq!(
            inventory.subset(0, exhausted, &roots),
            Err(Error::OutsideResource)
        );
    }

    #[test]
    fn request_must_be_inside_original_mcfg_and_uses_original_bus_offset() {
        let original = [window(0xc000_0000, 0, 32, 63)];
        let inventory = EcamInventory::validate(&original, 48).unwrap();
        let roots = [parent(0, 255)];
        let (selected, span) = inventory.subset(0, 32..=33, &roots).unwrap();
        assert_eq!(selected, window(0xc000_0000, 0, 32, 33));
        assert_eq!(span, PhysicalSpan::new(0xc200_0000, 2 << 20).unwrap());
        assert_eq!(
            inventory.subset(0, 31..=32, &roots),
            Err(Error::OutsideResource)
        );
        assert_eq!(
            inventory.subset(0, 63..=64, &roots),
            Err(Error::OutsideResource)
        );
        assert_eq!(
            inventory.subset(0, 33..=32, &roots),
            Err(Error::OutsideResource)
        );
        assert_eq!(
            inventory.subset(1, 32..=32, &roots),
            Err(Error::OutsideResource)
        );
    }

    #[test]
    fn parent_requires_unique_positive_untranslated_same_segment_description() {
        let original = [window(0xe000_0000, 0, 0, 255)];
        let inventory = EcamInventory::validate(&original, 48).unwrap();
        let root = parent(0, 0);
        assert_eq!(
            inventory.subset(0, 0..=0, &[root, root]),
            Err(Error::ResourceConflict)
        );
        for invalid in [
            RootWindow { flags: 2, ..root },
            RootWindow {
                flags: 0x10,
                ..root
            },
            RootWindow {
                translation: 1,
                ..root
            },
            RootWindow { segment: 1, ..root },
            RootWindow { length: 0, ..root },
            RootWindow {
                maximum: 256,
                length: 257,
                ..root
            },
        ] {
            assert_eq!(
                inventory.subset(0, 0..=0, &[invalid]),
                Err(Error::OutsideResource)
            );
        }
    }

    #[test]
    fn subset_cannot_hide_full_original_physical_or_bus_overlap() {
        let physical_overlap = [window(0xe000_0000, 0, 0, 255), window(0xe800_0000, 1, 0, 0)];
        assert!(matches!(
            EcamInventory::validate(&physical_overlap, 48),
            Err(Error::ResourceConflict)
        ));
        let bus_overlap = [
            window(0xc000_0000, 0, 0, 127),
            window(0xe000_0000, 0, 64, 255),
        ];
        assert!(matches!(
            EcamInventory::validate(&bus_overlap, 48),
            Err(Error::ResourceConflict)
        ));
    }

    #[test]
    fn physical_width_and_arithmetic_are_checked_before_subsets() {
        let overflow = [window(u64::MAX & !0xfffff, 0, 1, 1)];
        assert!(matches!(
            EcamInventory::validate(&overflow, 52),
            Err(Error::InvalidRange)
        ));
        let outside_width = [window(1 << 32, 0, 0, 0)];
        assert!(matches!(
            EcamInventory::validate(&outside_width, 32),
            Err(Error::InvalidRange)
        ));
        let exact_end = [window(0xf000_0000, 0, 0, 255)];
        assert!(EcamInventory::validate(&exact_end, 32).is_ok());
    }
}
