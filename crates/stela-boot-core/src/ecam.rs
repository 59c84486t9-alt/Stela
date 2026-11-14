//! Pure geometry for original captured ECAM/RootBridge descriptions.
//! This module creates no Resource, mapping, device exclusion or root permission.
pub mod census;
pub mod memory;
pub mod topology;
use alloc::vec::Vec;
use core::ops::RangeInclusive;
use stela_drivers::bus::{
    mmio::owned::{Error, PhysicalSpan},
    pci::{Address, EcamWindow},
};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RootWindow {
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

/// How a root bridge window the firmware describes is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// As described.
    Kept,
    /// The maximum lies below the minimum but the length is set: the
    /// window ends at `minimum + length - 1`. The UEFI root bridge
    /// configuration leaves the maximum unused, and some firmware puts the
    /// alignment mask there.
    Derived,
    /// No length, or a maximum below the minimum with no length to end
    /// it: an unset window, left out as Linux leaves it out.
    Empty,
}

impl RootWindow {
    /// Read this window as Linux reads an address space descriptor: a
    /// window without length is unset and left out, the rest are used.
    pub fn normalize(&mut self) -> Reading {
        if self.length == 0 {
            return Reading::Empty;
        }
        if self.maximum >= self.minimum {
            return Reading::Kept;
        }
        match self.minimum.checked_add(self.length - 1) {
            Some(maximum) => {
                self.maximum = maximum;
                Reading::Derived
            }
            None => Reading::Empty,
        }
    }

    fn buses(&self) -> Option<RangeInclusive<u8>> {
        (self.space == 2
            && self.translation == 0
            && self.flags & !0x0f == 0
            && self.flags & 2 == 0
            && self.maximum <= 255
            && self.maximum.checked_sub(self.minimum)?.checked_add(1)? == self.length)
            .then_some(self.minimum as u8..=self.maximum as u8)
    }
}

fn physical(window: EcamWindow, bits: u8) -> Result<PhysicalSpan, Error> {
    if !(32..=52).contains(&bits)
        || window.start_bus > window.end_bus
        || !window.base.is_multiple_of(1 << 20)
    {
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

/// Whether a root bridge forwards configuration requests for `bus` of
/// `segment`. A request for any other bus of an MCFG window ends at the
/// root complex, which completes it with all ones.
pub fn root_decodes(roots: &[RootWindow], segment: u16, bus: u8) -> bool {
    roots.iter().any(|root| {
        root.segment == u32::from(segment) && root.buses().is_some_and(|buses| buses.contains(&bus))
    })
}

/// Whether a configuration read of `offset` at `address` ends at the root
/// complex, which completes it with all ones: no root bridge forwards the
/// bus, and the request still leaves the processor. That is the case for a
/// bus of an MCFG window, and, on segment 0 below register 0x100, for any
/// bus, which the type 1 mechanism reaches without ECAM. Linux reads such a
/// register through `raw_pci_read` that way. A segment no root bridge
/// describes says nothing about the decode, so outside the MCFG windows its
/// reads are not answered.
pub fn ends_at_root_complex(
    windows: &[EcamWindow],
    roots: &[RootWindow],
    address: Address,
    offset: u16,
) -> bool {
    if root_decodes(roots, address.segment, address.bus) {
        return false;
    }
    let windowed = windows.iter().any(|window| {
        window.segment == address.segment
            && (window.start_bus..=window.end_bus).contains(&address.bus)
    });
    let type1 = address.segment == 0
        && offset < 0x100
        && roots
            .iter()
            .any(|root| root.segment == 0 && root.buses().is_some());
    windowed || type1
}

/// A bus of an ECAM window whose configuration space a memory map entry
/// that is not left to devices overlaps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryConflict {
    pub bus: u8,
    /// The bus's configuration space.
    pub span: PhysicalSpan,
    /// The entry, as (start, end, kind).
    pub entry: (u64, u64, u32),
}

/// The first bus of `window` whose configuration space overlaps a memory
/// map entry (start, end, kind) that is not reserved or MMIO
/// (`firmware_map::leaves_to_devices`). Only the window's own buses count,
/// as Linux sizes an MCFG window from its bus range; a range no entry
/// covers is no conflict.
pub fn memory_conflict(
    window: EcamWindow,
    bits: u8,
    entries: impl IntoIterator<Item = (u64, u64, u32)> + Clone,
) -> Result<Option<MemoryConflict>, Error> {
    for bus in window.start_bus..=window.end_bus {
        let span = physical(
            EcamWindow {
                start_bus: bus,
                end_bus: bus,
                ..window
            },
            bits,
        )?;
        if let Some(entry) =
            crate::firmware_map::first_conflict(entries.clone(), span.start(), span.end())
        {
            return Ok(Some(MemoryConflict { bus, span, entry }));
        }
    }
    Ok(None)
}

/// Borrowed immutable descriptions whose COMPLETE original MCFG windows were
/// checked before any subset is selected. This remains descriptive metadata;
/// only Source joins its captured bytes/owner and mints a reservation.
pub struct EcamInventory<'a> {
    windows: &'a [EcamWindow],
    bits: u8,
}
impl<'a> EcamInventory<'a> {
    pub fn validate(windows: &'a [EcamWindow], bits: u8) -> Result<Self, Error> {
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

    /// Select every bus granted by the captured root bridges. MCFG can
    /// describe a wider decode aperture than the firmware assigned to roots.
    /// Every granted bus must be accounted for by one original MCFG window.
    pub fn root_windows(&self, roots: &[RootWindow]) -> Result<Vec<EcamWindow>, Error> {
        for descriptor in roots {
            if !roots.iter().any(|root| {
                root.bridge == descriptor.bridge
                    && root.segment == descriptor.segment
                    && root.space == 2
            }) {
                return Err(Error::OutsideResource);
            }
        }
        let mut selected = Vec::new();
        for root in roots.iter().filter(|root| root.space == 2) {
            let buses = root.buses().ok_or(Error::InvalidRange)?;
            let mut first = *buses.start();
            loop {
                let index = self.window_for_bus(root.segment, first)?;
                let last = self.windows[index].end_bus.min(*buses.end());
                let (window, _) = self.subset(index, first..=last, roots)?;
                selected.try_reserve(1).map_err(|_| Error::Exhausted)?;
                selected.push(window);
                if last == *buses.end() {
                    break;
                }
                first = last + 1;
            }
        }
        if selected.is_empty() {
            return Err(Error::OutsideResource);
        }
        // Also reject partially overlapping grants. A wider grant can contain
        // an entire subset while another root claims only part of that subset.
        EcamInventory::validate(&selected, self.bits)?;
        Ok(selected)
    }

    /// Check that an observed bridge cannot route outside its own root grant.
    pub fn check_bridge(
        &self,
        roots: &[RootWindow],
        address: Address,
        downstream: RangeInclusive<u8>,
    ) -> Result<(), Error> {
        let segment = u32::from(address.segment);
        let mut matching = roots.iter().filter_map(|root| {
            (root.segment == segment)
                .then(|| root.buses())
                .flatten()
                .filter(|buses| buses.contains(&address.bus))
        });
        let root = matching.next().ok_or(Error::OutsideResource)?;
        if matching.next().is_some() {
            return Err(Error::ResourceConflict);
        }
        if downstream.is_empty()
            || !root.contains(downstream.start())
            || !root.contains(downstream.end())
        {
            return Err(Error::OutsideResource);
        }
        for bus in downstream {
            self.window_for_bus(segment, bus)?;
        }
        Ok(())
    }

    fn window_for_bus(&self, segment: u32, bus: u8) -> Result<usize, Error> {
        self.windows
            .iter()
            .position(|window| {
                u32::from(window.segment) == segment
                    && (window.start_bus..=window.end_bus).contains(&bus)
            })
            .ok_or(Error::OutsideResource)
    }

    /// Select one original function's exact 4 KiB configuration extent.
    pub fn function(
        &self,
        address: Address,
        roots: &[RootWindow],
    ) -> Result<(EcamWindow, PhysicalSpan), Error> {
        if address.device >= 32 || address.function >= 8 {
            return Err(Error::InvalidRange);
        }
        let index = self.window_for_bus(u32::from(address.segment), address.bus)?;
        let (window, bus) = self.subset(index, address.bus..=address.bus, roots)?;
        let offset = (u64::from(address.device) << 15) | (u64::from(address.function) << 12);
        let start = bus.start().checked_add(offset).ok_or(Error::InvalidRange)?;
        Ok((window, PhysicalSpan::new(start, 4096)?))
    }

    pub fn subset(
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
                && root
                    .buses()
                    .is_some_and(|buses| buses.contains(&first) && buses.contains(&last))
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
    fn unset_windows_are_left_out_and_inverted_ones_end_at_their_length() {
        let memory = |minimum, maximum, length| RootWindow {
            minimum,
            maximum,
            length,
            ..RootWindow::default()
        };
        let mut kept = memory(0xe000_0000, 0xefff_ffff, 0x1000_0000);
        assert_eq!(kept.normalize(), Reading::Kept);
        assert_eq!(kept.maximum, 0xefff_ffff);
        // The alignment mask in the maximum, as one firmware reports it.
        let mut derived = memory(0xf600_0000, 0xff_ffff, 0x1a0_0000);
        assert_eq!(derived.normalize(), Reading::Derived);
        assert_eq!(derived.maximum, 0xf79f_ffff);
        for mut empty in [
            memory(0x1_0000_0000, 0, 0),
            memory(0xe000_0000, 0xefff_ffff, 0),
            memory(u64::MAX, 0, 2),
        ] {
            assert_eq!(empty.normalize(), Reading::Empty);
        }
        let mut bus = RootWindow {
            space: 2,
            ..memory(0x10, 0, 0x10)
        };
        assert_eq!(bus.normalize(), Reading::Derived);
        assert_eq!(bus.buses(), Some(0x10..=0x1f));
    }

    #[test]
    fn only_root_bridge_buses_are_decoded() {
        let root = |segment: u32, first: u64, last: u64| RootWindow {
            segment,
            bridge: 1,
            space: 2,
            minimum: first,
            maximum: last,
            length: last - first + 1,
            ..RootWindow::default()
        };
        let roots = [root(0, 0, 0x3f), root(1, 0x10, 0x10)];
        assert!(root_decodes(&roots, 0, 0));
        assert!(root_decodes(&roots, 0, 0x3f));
        assert!(!root_decodes(&roots, 0, 0x40));
        assert!(root_decodes(&roots, 1, 0x10));
        assert!(!root_decodes(&roots, 1, 0x11));
        assert!(!root_decodes(&roots, 2, 0));
        // A memory window is no bus grant.
        let memory = RootWindow {
            space: 0,
            ..root(0, 0x40, 0x7f)
        };
        assert!(!root_decodes(&[memory], 0, 0x40));
    }

    #[test]
    fn a_bus_no_root_bridge_forwards_reads_all_ones_where_the_request_leaves_the_processor() {
        let at = |segment, bus| Address {
            segment,
            bus,
            device: 0,
            function: 0,
        };
        // MCFG names buses 0-0x7f; the root bridge forwards 0-0x7e.
        let windows = [window(0xe000_0000, 0, 0, 0x7f)];
        let roots = [parent(0, 0x7e)];
        assert!(!ends_at_root_complex(&windows, &roots, at(0, 0), 0x19));
        assert!(ends_at_root_complex(&windows, &roots, at(0, 0x7f), 0x100));
        // Bus 0xff is in no window: the type 1 mechanism reaches its
        // header, extended registers need ECAM.
        assert!(ends_at_root_complex(&windows, &roots, at(0, 0xff), 0x19));
        assert!(ends_at_root_complex(&windows, &roots, at(0, 0xff), 0xff));
        assert!(!ends_at_root_complex(&windows, &roots, at(0, 0xff), 0x100));
        // No type 1 mechanism beyond segment 0, and no answer without a
        // root bridge on the segment.
        assert!(!ends_at_root_complex(&windows, &roots, at(1, 0xff), 0x19));
        assert!(!ends_at_root_complex(&windows, &[], at(0, 0xff), 0x19));
    }

    #[test]
    fn an_ecam_window_needs_reserved_mmio_or_unlisted_memory_under_each_bus() {
        use crate::firmware_map::{MMIO, RESERVED};
        const RAM: u32 = 7;
        let full = window(0xe000_0000, 0, 0, 0xff);
        let end = 0xf000_0000;
        // The firmware's map leaves the window out: a hole.
        let hole = [(0, 0x8000_0000, RAM), (0x1_0000_0000, 0x2_0000_0000, RAM)];
        assert_eq!(memory_conflict(full, 48, hole), Ok(None));
        // An MMIO or a reserved entry over the window.
        for kind in [MMIO, RESERVED] {
            assert_eq!(
                memory_conflict(full, 48, [(0xe000_0000, end, kind)]),
                Ok(None)
            );
        }
        // RAM over bus 0x80 refuses at that bus.
        let ram = [(0xe000_0000, 0xe800_0000, MMIO), (0xe800_0000, end, RAM)];
        assert_eq!(
            memory_conflict(full, 48, ram),
            Ok(Some(MemoryConflict {
                bus: 0x80,
                span: PhysicalSpan::new(0xe800_0000, 1 << 20).unwrap(),
                entry: (0xe800_0000, end, RAM),
            }))
        );
        // A window of 64 buses ends at 0xe400_0000: RAM right after it is
        // no conflict, RAM in its last bus is.
        let short = window(0xe000_0000, 0, 0, 0x3f);
        assert_eq!(
            memory_conflict(short, 48, [(0xe400_0000, end, RAM)]),
            Ok(None)
        );
        assert_eq!(
            memory_conflict(short, 48, [(0xe3ff_f000, end, RAM)])
                .unwrap()
                .map(|conflict| conflict.bus),
            Some(0x3f)
        );
        // A window that starts at bus 0x10 begins 16 MiB above its base.
        let late = window(0xe000_0000, 0, 0x10, 0x1f);
        assert_eq!(
            memory_conflict(late, 48, [(0xe000_0000, 0xe100_0000, RAM)]),
            Ok(None)
        );
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
    fn census_uses_the_root_grants_and_refuses_uncovered_or_overlapping_buses() {
        let original = [
            window(0xe000_0000, 0, 0, 63),
            window(0xe000_0000, 0, 64, 255),
        ];
        let inventory = EcamInventory::validate(&original, 48).unwrap();
        assert_eq!(
            inventory
                .root_windows(&[parent(0, 0), parent(60, 65)])
                .unwrap(),
            [
                window(0xe000_0000, 0, 0, 0),
                window(0xe000_0000, 0, 60, 63),
                window(0xe000_0000, 0, 64, 65)
            ]
        );
        assert_eq!(
            inventory.root_windows(&[parent(0, 63), parent(31, 65)]),
            Err(Error::ResourceConflict)
        );
        assert_eq!(
            inventory.root_windows(&[RootWindow {
                segment: 1,
                ..parent(0, 0)
            }]),
            Err(Error::OutsideResource)
        );
        let root_bridge = Address {
            segment: 0,
            bus: 60,
            device: 0,
            function: 0,
        };
        let roots = [parent(0, 59), parent(60, 65), parent(66, 255)];
        assert_eq!(inventory.check_bridge(&roots, root_bridge, 61..=65), Ok(()));
        assert_eq!(
            inventory.check_bridge(&roots, root_bridge, 61..=66),
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
            inventory.subset(0, core::ops::RangeInclusive::new(33, 32), &roots),
            Err(Error::OutsideResource)
        );
        assert_eq!(
            inventory.subset(1, 32..=32, &roots),
            Err(Error::OutsideResource)
        );
    }

    #[test]
    fn functions_on_the_same_nonzero_bus_get_disjoint_original_pages() {
        let original = [window(0x8000_0000, 0, 32, 63)];
        let inventory = EcamInventory::validate(&original, 48).unwrap();
        let roots = [parent(32, 32)];
        let address = Address {
            segment: 0,
            bus: 32,
            device: 31,
            function: 6,
        };
        let (window, first) = inventory.function(address, &roots).unwrap();
        let (_, last) = inventory
            .function(
                Address {
                    function: 7,
                    ..address
                },
                &roots,
            )
            .unwrap();
        assert_eq!(window.start_bus, 32);
        assert_eq!(window.end_bus, 32);
        assert_eq!(first.start(), 0x820f_e000);
        assert_eq!(first.end(), last.start());
        assert_eq!(last.end(), 0x8210_0000);
        assert_eq!(
            inventory.function(
                Address {
                    device: 32,
                    ..address
                },
                &roots
            ),
            Err(Error::InvalidRange)
        );
        assert_eq!(
            inventory.function(
                Address {
                    function: 8,
                    ..address
                },
                &roots
            ),
            Err(Error::InvalidRange)
        );
        assert_eq!(
            inventory.function(Address { bus: 33, ..address }, &roots),
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
        let overflow = [window(!0xfffff_u64, 0, 1, 1)];
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
