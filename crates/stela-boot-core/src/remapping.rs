//! Which DMA remapping units the mount takes over, and which requesters
//! each one isolates: the PCI functions present behind the root buses, the
//! units' device scopes resolved against them, and the policy that leaves a
//! unit untranslated when taking it would cut off DMA nothing re-maps.
//!
//! A unit is left untranslated when its scope holds a display controller no
//! driver claims (an integrated GPU's scanout reaches its stolen memory
//! through the unit, with the firmware's reserved regions mapped one to
//! one), or when a reserved region (DMAR RMRR, IVRS IVMD) names a requester
//! other than a USB host controller, whose reserved region serves only the
//! firmware's legacy USB emulation until the xHCI BIOS handoff (Linux's
//! `device_rmrr_is_relaxable`). A display driver that maps those regions
//! itself passes its function in `claimed_displays`, and the unit is taken.
use alloc::vec::Vec;
use core::ops::Range;

/// The 4 KiB page span a DMA window needs, within the host's supported
/// physical-address width. This describes geometry, not permission to map it.
pub fn window_range(range: &Range<u64>, physical_bits: u8) -> Option<Range<u64>> {
    if !(32..=52).contains(&physical_bits) || range.start >= range.end {
        return None;
    }
    let end = range.end.checked_next_multiple_of(4096)?;
    if end > 1u64 << physical_bits {
        return None;
    }
    Some((range.start & !4095)..end)
}

/// One present PCI function: its requester ID, class code and, for a
/// PCI-to-PCI bridge, its secondary and subordinate buses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Present {
    pub rid: u16,
    /// Base class, subclass and programming interface.
    pub class: [u8; 3],
    pub bridge: Option<(u8, u8)>,
}

impl Present {
    pub fn display(&self) -> bool {
        self.class[0] == 0x03
    }
    pub fn usb(&self) -> bool {
        self.class[0] == 0x0c && self.class[1] == 0x03
    }
}

const VENDOR: u16 = 0x00;
const CLASS: u16 = 0x08;
const HEADER: u16 = 0x0c;
const BUSES: u16 = 0x18;

/// Every function behind `roots`, found as Linux's `pci_scan_child_bus`
/// finds them: each root bus, then each bus a bridge leads to. `read32`
/// reads a configuration dword of a requester, `None` where nothing
/// answers.
pub fn enumerate(roots: &[u8], mut read32: impl FnMut(u16, u16) -> Option<u32>) -> Vec<Present> {
    let mut found = Vec::new();
    let mut seen = [false; 256];
    let mut pending: Vec<u8> = roots.to_vec();
    while let Some(bus) = pending.pop() {
        if core::mem::replace(&mut seen[usize::from(bus)], true) {
            continue;
        }
        for device in 0..32u16 {
            let first = u16::from(bus) << 8 | device << 3;
            let Some(header) = read32(first, VENDOR)
                .filter(|id| *id as u16 != 0xffff)
                .and_then(|_| read32(first, HEADER))
            else {
                continue;
            };
            let functions = if header >> 16 & 0x80 != 0 { 8 } else { 1 };
            for function in 0..functions {
                let rid = first | function;
                if read32(rid, VENDOR).is_none_or(|id| id as u16 == 0xffff) {
                    continue;
                }
                let class = read32(rid, CLASS).unwrap_or(0);
                let kind = read32(rid, HEADER).unwrap_or(0) >> 16 & 0x7f;
                let bridge = (kind == 1)
                    .then(|| read32(rid, BUSES))
                    .flatten()
                    .map(|buses| ((buses >> 8) as u8, (buses >> 16) as u8))
                    .filter(|&(secondary, subordinate)| {
                        secondary > bus && subordinate >= secondary
                    });
                if let Some((secondary, _)) = bridge {
                    pending.push(secondary);
                }
                found.push(Present {
                    rid,
                    class: [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
                    bridge,
                });
            }
        }
    }
    found.sort_unstable_by_key(|function| function.rid);
    found
}

/// A device scope: an endpoint, or a bridge and every function behind it,
/// named by its start bus and (device, function) path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub bridge: bool,
    pub bus: u8,
    pub path: Vec<(u8, u8)>,
}

impl Scope {
    /// The present requesters the scope names: none when its path does not
    /// lead to a present function.
    pub fn resolve(&self, present: &[Present]) -> Vec<u16> {
        let find = |rid: u16| present.iter().find(|function| function.rid == rid);
        let mut bus = self.bus;
        let mut target = None;
        for (index, &(device, function)) in self.path.iter().enumerate() {
            let rid = u16::from(bus) << 8 | u16::from(device) << 3 | u16::from(function);
            let Some(found) = find(rid) else {
                return Vec::new();
            };
            if index + 1 == self.path.len() {
                target = Some(found);
            } else if let Some((secondary, _)) = found.bridge {
                bus = secondary;
            } else {
                return Vec::new();
            }
        }
        match target {
            None => Vec::new(),
            Some(found) if !self.bridge => alloc::vec![found.rid],
            Some(found) => {
                let Some((secondary, subordinate)) = found.bridge else {
                    return alloc::vec![found.rid];
                };
                present
                    .iter()
                    .filter(|function| {
                        function.rid == found.rid
                            || (secondary..=subordinate).contains(&((function.rid >> 8) as u8))
                    })
                    .map(|function| function.rid)
                    .collect()
            }
        }
    }
}

/// Why a unit is left untranslated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leave {
    /// No present requester sits in its scope.
    Empty,
    /// This display controller sits in its scope, and no driver maps the
    /// unit's reserved regions for it.
    Display(u16),
    /// A reserved region names this requester, which is not a USB host
    /// controller.
    Reserved(u16),
}

/// The requesters a unit covers, sorted, when the policy takes it.
pub fn decide(
    covered: &[u16],
    reserved: &[u16],
    present: &[Present],
    claimed_displays: &[u16],
) -> Result<Vec<u16>, Leave> {
    let mut covered = covered.to_vec();
    covered.sort_unstable();
    covered.dedup();
    if covered.is_empty() {
        return Err(Leave::Empty);
    }
    let function = |rid: u16| present.iter().find(|function| function.rid == rid);
    if let Some(&display) = covered.iter().find(|&&rid| {
        function(rid).is_some_and(Present::display) && !claimed_displays.contains(&rid)
    }) {
        return Err(Leave::Display(display));
    }
    if let Some(&held) = reserved
        .iter()
        .find(|&&rid| covered.contains(&rid) && !function(rid).is_some_and(Present::usb))
    {
        return Err(Leave::Reserved(held));
    }
    Ok(covered)
}

/// The present requesters an include-all unit covers: those no other unit
/// on its segment lists.
pub fn remainder(present: &[Present], listed: &[u16]) -> Vec<u16> {
    present
        .iter()
        .map(|function| function.rid)
        .filter(|rid| !listed.contains(rid))
        .collect()
}

/// What the policy does with each unit of `remapping` on `segment`, by its
/// index in `remapping.units`: listed units first, then include-all units
/// over what the listed ones leave.
pub fn plan(
    remapping: &crate::dmar::Remapping,
    segment: u16,
    present: &[Present],
    claimed_displays: &[u16],
) -> Vec<(usize, Result<Vec<u16>, Leave>)> {
    let reserved: Vec<u16> = remapping
        .reserved
        .iter()
        .filter(|region| region.segment == segment)
        .flat_map(|region| {
            region
                .scopes
                .iter()
                .flat_map(|scope| scope.resolve(present))
        })
        .collect();
    let on_segment = || {
        remapping
            .units
            .iter()
            .enumerate()
            .filter(|(_, unit)| unit.segment == segment)
    };
    let mut listed = Vec::new();
    let mut decisions = Vec::new();
    for (index, unit) in on_segment().filter(|(_, unit)| !unit.include_all) {
        let covered: Vec<u16> = unit
            .scopes
            .iter()
            .flat_map(|scope| scope.resolve(present))
            .collect();
        listed.extend_from_slice(&covered);
        decisions.push((
            index,
            decide(&covered, &reserved, present, claimed_displays),
        ));
    }
    for (index, _) in on_segment().filter(|(_, unit)| unit.include_all) {
        let covered = remainder(present, &listed);
        decisions.push((
            index,
            decide(&covered, &reserved, present, claimed_displays),
        ));
    }
    decisions
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec};

    /// A function's requester, class, multifunction bit and bridge buses.
    type Function = (u16, [u8; 3], bool, Option<(u8, u8)>);

    /// A config space of `(rid, offset) -> dword`.
    fn space(functions: &[Function]) -> BTreeMap<(u16, u16), u32> {
        let mut space = BTreeMap::new();
        for &(rid, class, multi, bridge) in functions {
            space.insert((rid, VENDOR), 0x1234_8086);
            space.insert(
                (rid, CLASS),
                u32::from(class[0]) << 24 | u32::from(class[1]) << 16 | u32::from(class[2]) << 8,
            );
            let kind = u32::from(bridge.is_some()) | if multi { 0x80 } else { 0 };
            space.insert((rid, HEADER), kind << 16);
            if let Some((secondary, subordinate)) = bridge {
                space.insert(
                    (rid, BUSES),
                    u32::from(secondary) << 8 | u32::from(subordinate) << 16,
                );
            }
        }
        space
    }

    fn inventory() -> Vec<Present> {
        let space = space(&[
            (0x0000, [6, 0, 0], false, None),
            (0x0010, [3, 0, 0], false, None),
            (0x00a0, [0x0c, 3, 0x30], true, None),
            (0x00a1, [5, 0, 0], true, None),
            (0x00e0, [6, 4, 0], false, Some((1, 2))),
            (0x0100, [6, 4, 0], false, Some((2, 2))),
            (0x0200, [1, 8, 2], false, None),
        ]);
        enumerate(&[0], |rid, offset| space.get(&(rid, offset)).copied())
    }

    #[test]
    fn window_geometry_rejects_empty_overflow_and_out_of_width_ranges() {
        assert_eq!(
            window_range(&(0x12345..0x12346), 48),
            Some(0x12000..0x13000)
        );
        let limit = 1u64 << 52;
        assert_eq!(
            window_range(&(limit - 1..limit), 52),
            Some(limit - 4096..limit)
        );
        for range in [
            0..0,
            0x1000..0x1000,
            0..u64::MAX,
            u64::MAX - 4096..u64::MAX,
            limit..limit + 1,
        ] {
            assert_eq!(window_range(&range, 52), None);
        }
        for bits in [0, 31, 53, 64] {
            assert_eq!(window_range(&(0x1000..0x2000), bits), None);
        }
    }

    #[test]
    fn enumeration_follows_bridges_and_multifunction_devices() {
        let found = inventory();
        let rids: Vec<u16> = found.iter().map(|function| function.rid).collect();
        assert_eq!(
            rids,
            [0x0000, 0x0010, 0x00a0, 0x00a1, 0x00e0, 0x0100, 0x0200]
        );
        assert!(found[1].display());
        assert!(found[2].usb());
        assert_eq!(found[4].bridge, Some((1, 2)));
    }

    #[test]
    fn scopes_resolve_endpoints_paths_and_bridge_subtrees() {
        let present = inventory();
        let endpoint = Scope {
            bridge: false,
            bus: 0,
            path: vec![(0x1c, 0), (0, 0), (0, 0)],
        };
        assert_eq!(endpoint.resolve(&present), [0x0200]);
        let bridge = Scope {
            bridge: true,
            bus: 0,
            path: vec![(0x1c, 0)],
        };
        assert_eq!(bridge.resolve(&present), [0x00e0, 0x0100, 0x0200]);
        let absent = Scope {
            bridge: false,
            bus: 0,
            path: vec![(5, 0)],
        };
        assert!(absent.resolve(&present).is_empty());
    }

    #[test]
    fn an_include_all_unit_covers_what_listed_units_leave() {
        use crate::dmar::{Drhd, Remapping, Rmrr};
        let present = inventory();
        let unit = |include_all, scopes| Drhd {
            base: 0xfed9_0000,
            bytes: 4096,
            segment: 0,
            include_all,
            scopes,
        };
        let graphics = Scope {
            bridge: false,
            bus: 0,
            path: vec![(2, 0)],
        };
        let mut remapping = Remapping {
            physical_bits: 39,
            units: vec![unit(true, vec![]), unit(false, vec![graphics])],
            reserved: vec![Rmrr {
                segment: 0,
                base: 0x7d00_0000,
                limit: 0x7d01_ffff,
                scopes: vec![Scope {
                    bridge: false,
                    bus: 0,
                    path: vec![(0x14, 0)],
                }],
            }],
        };
        let decisions = plan(&remapping, 0, &present, &[]);
        assert_eq!(decisions[0], (1, Err(Leave::Display(0x0010))));
        assert_eq!(
            decisions[1],
            (0, Ok(vec![0x0000, 0x00a0, 0x00a1, 0x00e0, 0x0100, 0x0200]))
        );
        assert!(plan(&remapping, 1, &present, &[]).is_empty());
        remapping.reserved[0].scopes[0].path = vec![(0x1c, 0), (0, 0), (0, 0)];
        assert_eq!(
            plan(&remapping, 0, &present, &[])[1],
            (0, Err(Leave::Reserved(0x0200)))
        );
    }

    #[test]
    fn displays_and_non_usb_reservations_leave_a_unit_untranslated() {
        let present = inventory();
        let all = remainder(&present, &[]);
        assert_eq!(
            decide(&all, &[], &present, &[]),
            Err(Leave::Display(0x0010))
        );
        assert_eq!(decide(&all, &[], &present, &[0x0010]), Ok(all.clone()));
        let rest = remainder(&present, &[0x0010]);
        assert_eq!(decide(&rest, &[0x00a0], &present, &[]), Ok(rest.clone()));
        assert_eq!(
            decide(&rest, &[0x0200], &present, &[]),
            Err(Leave::Reserved(0x0200))
        );
        // A reservation for a requester another unit covers does not count.
        assert_eq!(
            decide(&[0x0200], &[0x0010], &present, &[]),
            Ok(vec![0x0200])
        );
        assert_eq!(decide(&[], &[], &present, &[]), Err(Leave::Empty));
    }
}
