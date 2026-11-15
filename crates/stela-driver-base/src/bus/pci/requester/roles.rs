// SPDX-License-Identifier: GPL-2.0-only
// VF requester arithmetic follows Linux drivers/pci/iov.c, Copyright (C)
// 2009 Intel Corporation, Yu Zhao <yu.zhao@intel.com>, and register fields
// follow include/uapi/linux/pci_regs.h at cc9de5d4b5ab6459f5774946aa3195ad51236fa8.
//! PF/VF classification across a complete, stable PCI configuration inventory.
//! These observations grant no configuration, reset or DMA ownership.
use super::{Address, CapabilityError, FunctionRole};
use crate::bus::pci::capability::{ExtendedCapabilities, Transport};
use alloc::{collections::BTreeMap, vec::Vec};
const SRIOV: u16 = 0x10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Issue {
    Config {
        address: Address,
        error: crate::bus::pci::ConfigError,
    },
    Read {
        address: Address,
        offset: u16,
    },
    Capability {
        address: Address,
        error: CapabilityError,
    },
    Sriov(Address),
    Collision(Address),
    Topology(Address),
}
impl Issue {
    fn address(&self) -> Address {
        match *self {
            Self::Config { address, .. } => address,
            Self::Read { address, .. }
            | Self::Capability { address, .. }
            | Self::Sriov(address)
            | Self::Collision(address)
            | Self::Topology(address) => address,
        }
    }
}

#[derive(Default)]
pub struct Inventory {
    present: Vec<Address>,
    virtuals: BTreeMap<Address, Address>,
    sources: Vec<Address>,
    issues: Vec<Issue>,
}
impl Inventory {
    pub const fn empty() -> Self {
        Self {
            present: Vec::new(),
            virtuals: BTreeMap::new(),
            sources: Vec::new(),
            issues: Vec::new(),
        }
    }

    /// `functions` is the complete present-function inventory for the admitted
    /// buses/segments. Configuration, reset, removal and SR-IOV writers must
    /// remain excluded throughout capture and use. An incomplete input cannot
    /// establish Physical: the caller's platform grant must supply completeness.
    pub fn capture(
        functions: &[Address],
        mut read32: impl FnMut(Address, u16) -> Result<Option<u32>, crate::bus::pci::ConfigError>,
    ) -> Result<Self, crate::bus::pci::ConfigError> {
        let mut inventory = Self {
            present: functions.to_vec(),
            ..Self::default()
        };
        inventory.present.sort_unstable();
        inventory.present.dedup();
        let mut virtuals = BTreeMap::new();
        let mut sources = Vec::new();
        // Every function is examined, whatever an earlier one showed: an
        // issue refuses only what it reaches ([`Inventory::refusal`]), and
        // each PF's VFs must be known for the functions it does not reach.
        for &address in &inventory.present {
            match function(address, &mut read32) {
                Err(Issue::Config { error, .. }) => return Err(error),
                Err(issue) => inventory.issues.push(issue),
                Ok(None) => {}
                Ok(Some(vfs)) => {
                    sources.push(address);
                    for vf in vfs {
                        if virtuals.insert(vf, address).is_some() {
                            inventory.issues.push(Issue::Collision(vf));
                        }
                    }
                }
            }
        }
        for &source in &sources {
            if virtuals.contains_key(&source) {
                inventory.issues.push(Issue::Sriov(source));
            }
        }
        inventory.virtuals = virtuals;
        inventory.sources = sources;
        Ok(inventory)
    }
    /// Add a complete newly adopted subtree while the previous configuration
    /// and SR-IOV epoch remains unchanged. Present but unclaimed functions may
    /// occur in both inventories; an existing PF's VF assignment cannot change.
    /// This joins observations and grants no access to either subtree.
    pub fn extend(&mut self, fresh: Self) {
        for &source in &self.sources {
            if fresh.present.contains(&source)
                && (!fresh.sources.contains(&source)
                    || self
                        .virtuals
                        .iter()
                        .filter(|(_, owner)| **owner == source)
                        .ne(fresh.virtuals.iter().filter(|(_, owner)| **owner == source)))
            {
                self.issues.push(Issue::Sriov(source));
            }
        }
        for (&vf, &source) in &fresh.virtuals {
            if self.virtuals.get(&vf).is_some_and(|owner| *owner != source)
                || (self.present.contains(&vf) && !self.virtuals.contains_key(&vf))
            {
                self.issues.push(Issue::Collision(vf));
            }
        }
        for &source in &fresh.sources {
            if self.virtuals.contains_key(&source)
                || (self.present.contains(&source) && !self.sources.contains(&source))
            {
                self.issues.push(Issue::Sriov(source));
            }
        }
        for &source in &self.sources {
            if fresh.virtuals.contains_key(&source) {
                self.issues.push(Issue::Sriov(source));
            }
        }
        self.present.extend(fresh.present);
        self.present.sort_unstable();
        self.present.dedup();
        self.sources.extend(fresh.sources);
        self.sources.sort_unstable();
        self.sources.dedup();
        self.virtuals.extend(fresh.virtuals);
        self.issues.extend(fresh.issues);
    }
    /// Refuse the subtree of `address`, a bridge, after its owned topology
    /// observation failed; the whole segment where its buses are unknown.
    pub fn invalidate_topology(&mut self, address: Address) {
        self.issues.push(Issue::Topology(address));
    }
    /// The function's role, given the bridges of the present topology.
    pub fn role(&self, address: Address, bridges: &[Bridge]) -> FunctionRole {
        if self.refusal(address, bridges).is_some() {
            FunctionRole::Unverified
        } else if self.virtuals.contains_key(&address) {
            FunctionRole::Virtual
        } else if self.present.binary_search(&address).is_ok() {
            FunctionRole::Physical
        } else {
            FunctionRole::Unverified
        }
    }
    /// The first issue that reaches the function at `address`, which then
    /// stays unverified. An issue concerns one function, whose own role and
    /// SR-IOV state it leaves unknown: that function, and every function
    /// that could be one of its VFs, which by the SR-IOV routing rules have
    /// a higher requester ID and a bus that configuration requests route to
    /// the same link as the function's own ([`Routes`]); a collision, every
    /// function there; a failed bridge observation, the bridge's subtree.
    /// Where the bridges do not form one tree of nested bus ranges, any
    /// issue reaches its whole segment, as before.
    pub fn refusal(&self, address: Address, bridges: &[Bridge]) -> Option<Issue> {
        let routes = Routes::of(address.segment, bridges);
        self.issues.iter().copied().find(|issue| {
            reaches(*issue, address, routes.as_ref(), bridges)
                // An issue at a VF puts its PF's SR-IOV state in doubt too.
                || self.virtuals.get(&issue.address()).is_some_and(|&pf| {
                    reaches(Issue::Sriov(pf), address, routes.as_ref(), bridges)
                })
        })
    }
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }
}

/// A PCI-to-PCI bridge of the present topology and the buses it routes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bridge {
    pub address: Address,
    pub secondary: u8,
    pub subordinate: u8,
}
impl Bridge {
    fn routes(&self, bus: u8) -> bool {
        (self.secondary..=self.subordinate).contains(&bus)
    }
    fn width(&self) -> u8 {
        self.subordinate - self.secondary
    }
}

/// Where a segment's configuration requests go: each bus to the innermost
/// bridge whose range holds it, or to the root complex. Two functions whose
/// buses go to the same place share a link: a PF's VFs, whose requester IDs
/// are the PF's plus its First VF Offset and strides, can only be on buses
/// that route to the PF's own link, or configuration could not reach them.
struct Routes<'a> {
    bridges: alloc::vec::Vec<&'a Bridge>,
}
impl<'a> Routes<'a> {
    /// The segment's routes, or None where its bridges do not form a tree:
    /// a range that holds its own bridge's bus, ranges that overlap without
    /// nesting, or a range outside the one its bridge's bus is in.
    fn of(segment: u16, bridges: &'a [Bridge]) -> Option<Self> {
        let routes = Self {
            bridges: bridges
                .iter()
                .filter(|bridge| bridge.address.segment == segment)
                .collect(),
        };
        for (index, bridge) in routes.bridges.iter().enumerate() {
            if bridge.subordinate < bridge.secondary || bridge.routes(bridge.address.bus) {
                return None;
            }
            for other in &routes.bridges[index + 1..] {
                let disjoint =
                    bridge.subordinate < other.secondary || other.subordinate < bridge.secondary;
                let nested = (bridge.routes(other.secondary) && bridge.routes(other.subordinate))
                    || (other.routes(bridge.secondary) && other.routes(bridge.subordinate));
                if !disjoint && (!nested || bridge.width() == other.width()) {
                    return None;
                }
            }
            if let Some(parent) = routes.link(bridge.address.bus)
                && !(parent.routes(bridge.secondary) && parent.routes(bridge.subordinate))
            {
                return None;
            }
        }
        Some(routes)
    }
    /// The innermost bridge that routes `bus`, None for the root complex.
    fn link(&self, bus: u8) -> Option<&'a Bridge> {
        self.bridges
            .iter()
            .copied()
            .filter(|bridge| bridge.routes(bus))
            .min_by_key(|bridge| bridge.width())
    }
    fn same_link(&self, a: u8, b: u8) -> bool {
        self.link(a).map(|bridge| bridge.address) == self.link(b).map(|bridge| bridge.address)
    }
}

fn rid(address: Address) -> u16 {
    u16::from(address.bus) << 8 | u16::from(address.device) << 3 | u16::from(address.function)
}

/// Whether the function at `address` could be a VF of the one at `pf`.
fn follows(pf: Address, address: Address, routes: &Routes<'_>) -> bool {
    rid(address) > rid(pf) && routes.same_link(pf.bus, address.bus)
}

/// Whether `issue` leaves the function at `address` unverified
/// ([`Inventory::refusal`]); `routes` None refuses the whole segment.
fn reaches(
    issue: Issue,
    address: Address,
    routes: Option<&Routes<'_>>,
    bridges: &[Bridge],
) -> bool {
    let at = issue.address();
    if at.segment != address.segment {
        return false;
    }
    if at == address {
        return true;
    }
    let Some(routes) = routes else {
        return true;
    };
    match issue {
        Issue::Topology(bridge) => match bridges.iter().find(|known| known.address == bridge) {
            Some(known) => known.routes(address.bus),
            None => true,
        },
        // Two PFs claim one VF: either one's VFs, and both PFs, are on its
        // link, and which function is whose is unknown.
        Issue::Collision(vf) => routes.same_link(vf.bus, address.bus),
        // The function's own SR-IOV state is unknown or refused: any VF it
        // has follows it on its link.
        Issue::Config { .. } | Issue::Read { .. } | Issue::Capability { .. } | Issue::Sriov(_) => {
            follows(at, address, routes)
        }
    }
}

fn read(
    read32: &mut impl FnMut(Address, u16) -> Result<Option<u32>, crate::bus::pci::ConfigError>,
    address: Address,
    offset: u16,
) -> Result<u32, Issue> {
    read32(address, offset)
        .map_err(|error| Issue::Config { address, error })?
        .filter(|value| *value != u32::MAX)
        .ok_or(Issue::Read { address, offset })
}
fn fields(
    read32: &mut impl FnMut(Address, u16) -> Result<Option<u32>, crate::bus::pci::ConfigError>,
    address: Address,
    at: u16,
) -> Result<[u16; 5], Issue> {
    let control = read(read32, address, at + 8)? as u16;
    let total = (read(read32, address, at + 12)? >> 16) as u16;
    let count = read(read32, address, at + 16)? as u16;
    let geometry = read(read32, address, at + 20)?;
    Ok([
        control,
        total,
        count,
        geometry as u16,
        (geometry >> 16) as u16,
    ])
}
fn function(
    address: Address,
    read32: &mut impl FnMut(Address, u16) -> Result<Option<u32>, crate::bus::pci::ConfigError>,
) -> Result<Option<Vec<Address>>, Issue> {
    let identity = read(read32, address, 0)?;
    if matches!(identity as u16, 0 | 1 | u16::MAX) || address.device >= 32 || address.function >= 8
    {
        return Err(Issue::Sriov(address));
    }
    // An all-ones first extended header denotes no extended configuration,
    // including conventional PCI. Classification still examines every PF,
    // rather than inferring this function's role from that local absence.
    let first = read32(address, 0x100)
        .map_err(|error| Issue::Config { address, error })?
        .ok_or(Issue::Read {
            address,
            offset: 0x100,
        })?;
    let mut sriov = None;
    if first != u32::MAX {
        let transport = Transport(|offset: u16, bytes: u8| {
            let value = read32(address, offset & !3)
                .map_err(|error| CapabilityError::Config { offset, error })?
                .ok_or(CapabilityError::FailedRead { offset })?;
            Ok::<_, CapabilityError>(match bytes {
                1 => value >> ((offset & 3) * 8) & 0xff,
                2 => value >> ((offset & 2) * 8) & 0xffff,
                _ => value,
            })
        });
        for entry in ExtendedCapabilities::census(transport) {
            let entry = entry.map_err(|error| match error {
                CapabilityError::Config { error, .. } => Issue::Config { address, error },
                error => Issue::Capability { address, error },
            })?;
            if entry.id == SRIOV && (entry.version != 1 || sriov.replace(entry.offset).is_some()) {
                return Err(Issue::Sriov(address));
            }
        }
    }
    let virtuals = if let Some(at) = sriov {
        if read(read32, address, 0x0c)? >> 16 & 0x7f != 0 {
            return Err(Issue::Sriov(address));
        }
        let snapshot @ [control, total, count, offset, stride] = fields(read32, address, at)?;
        let mut vfs = Vec::new();
        if control & 1 != 0 {
            if count == 0 || count > total || offset == 0 || (count > 1 && stride == 0) {
                return Err(Issue::Sriov(address));
            }
            let rid = u16::from(address.bus) << 8
                | u16::from(address.device) << 3
                | u16::from(address.function);
            for index in 0..count {
                let vf = u32::from(rid) + u32::from(offset) + u32::from(stride) * u32::from(index);
                let vf = u16::try_from(vf).map_err(|_| Issue::Sriov(address))?;
                vfs.push(Address {
                    segment: address.segment,
                    bus: (vf >> 8) as u8,
                    device: ((vf >> 3) & 31) as u8,
                    function: (vf & 7) as u8,
                });
            }
        }
        if fields(read32, address, at)? != snapshot {
            return Err(Issue::Sriov(address));
        }
        Some(vfs)
    } else {
        None
    };
    if read(read32, address, 0)? != identity
        || read32(address, 0x100).map_err(|error| Issue::Config { address, error })? != Some(first)
    {
        return Err(Issue::Sriov(address));
    }
    Ok(virtuals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    const PF: Address = Address {
        segment: 0,
        bus: 0,
        device: 31,
        function: 0,
    };
    fn at(segment: u16, rid: u16) -> Address {
        Address {
            segment,
            bus: (rid >> 8) as u8,
            device: ((rid >> 3) & 31) as u8,
            function: (rid & 7) as u8,
        }
    }
    fn plain() -> [u32; 1024] {
        let mut words = [0; 1024];
        words[0] = 0x12348086;
        words
    }
    fn pf(count: u16, offset: u16, stride: u16) -> [u32; 1024] {
        let mut words = plain();
        // PCI Express, which alone has the extended list SR-IOV is in.
        words[1] |= 1 << 20;
        words[0x34 / 4] = 0x40;
        words[0x40 / 4] = 0x0002_0010;
        words[0x100 / 4] = 0x10010;
        words[0x108 / 4] = 1;
        words[0x10c / 4] = 16 << 16;
        words[0x110 / 4] = u32::from(count);
        words[0x114 / 4] = u32::from(offset) | u32::from(stride) << 16;
        words
    }
    fn capture(spaces: &BTreeMap<Address, [u32; 1024]>) -> Inventory {
        let functions: Vec<_> = spaces.keys().copied().collect();
        Inventory::capture(&functions, |address, offset| {
            Ok(spaces
                .get(&address)
                .map(|words| words[usize::from(offset) / 4]))
        })
        .unwrap()
    }
    #[test]
    fn transport_denial_aborts_without_absence_or_a_physical_role() {
        use crate::bus::pci::{ConfigError, ConfigFailure, assignment};
        let words = pf(2, 8, 1);
        let mut accesses = 0;
        Inventory::capture(&[PF], |_, offset| {
            accesses += 1;
            Ok(Some(words[usize::from(offset) / 4]))
        })
        .unwrap();
        for fault in 1..=accesses {
            let mut observed = 0;
            let denied =
                ConfigError::before_effect(ConfigFailure::Ownership(assignment::Error::Closed));
            let result = Inventory::capture(&[PF], |_, offset| {
                observed += 1;
                if observed == fault {
                    Err(denied)
                } else {
                    Ok(Some(words[usize::from(offset) / 4]))
                }
            });
            assert_eq!(result.err(), Some(denied));
            assert_eq!(observed, fault, "no read after denied original permission");
        }
    }
    #[test]
    fn vfs_without_local_capabilities_are_classified_from_their_pf_across_a_bus_boundary() {
        let spaces = BTreeMap::from([
            (PF, pf(2, 8, 2)),
            (at(0, 0x100), plain()),
            (at(0, 0x101), plain()),
            (at(0, 0x102), plain()),
            (at(3, 0x100), plain()),
        ]);
        let inventory = capture(&spaces);
        assert!(inventory.issues().is_empty());
        assert_eq!(inventory.role(PF, &[]), FunctionRole::Physical);
        for rid in [0x100, 0x102] {
            assert_eq!(inventory.role(at(0, rid), &[]), FunctionRole::Virtual);
        }
        assert_eq!(inventory.role(at(0, 0x101), &[]), FunctionRole::Physical);
        assert_eq!(inventory.role(at(3, 0x100), &[]), FunctionRole::Physical);
        assert_eq!(inventory.role(at(0, 0x200), &[]), FunctionRole::Unverified);
    }
    /// Linux `pci_cfg_space_size`: a conventional function has no extended
    /// space. An Intel PCH SMBus read at 0x100 through ECAM answers with its
    /// first bytes again, whose next pointer is no list: the segment, and
    /// the GPU in it, are still classified.
    #[test]
    fn a_conventional_function_aliasing_its_extended_space_leaves_the_segment_classified() {
        let mut smbus = plain();
        smbus[0] = 0x7aa3_8086;
        // Power management alone, which is no PCI Express.
        smbus[1] |= 1 << 20;
        smbus[0x34 / 4] = 0x50;
        smbus[0x50 / 4] = 0x0003_0001;
        for at in 0..64 {
            smbus[0x100 / 4 + at] = smbus[at];
        }
        // A PCI Express function, with SR-IOV and no VF enabled.
        let gpu = at(0, 0x100);
        let mut express = pf(2, 8, 1);
        express[0x108 / 4] = 0;
        let spaces = BTreeMap::from([(PF, smbus), (gpu, express)]);
        let inventory = capture(&spaces);
        assert!(inventory.issues().is_empty(), "{:?}", inventory.issues());
        assert_eq!(inventory.role(PF, &[]), FunctionRole::Physical);
        assert_eq!(inventory.role(gpu, &[]), FunctionRole::Physical);
    }
    #[test]
    fn disabled_vfs_do_not_reclassify_an_ordinary_present_function() {
        let mut source = pf(2, 8, 2);
        source[0x108 / 4] = 0;
        let spaces = BTreeMap::from([(PF, source), (at(0, 0x100), plain())]);
        assert_eq!(
            capture(&spaces).role(at(0, 0x100), &[]),
            FunctionRole::Physical
        );
    }
    #[test]
    fn malformed_or_overflowing_enabled_vf_geometry_refuses_what_could_be_its_vfs() {
        for (source, words) in [
            (PF, pf(0, 8, 1)),
            (PF, pf(17, 8, 1)),
            (PF, pf(2, 0, 1)),
            (PF, pf(2, 8, 0)),
            (at(0, 0xff00), pf(2, 0x100, 1)),
        ] {
            let spaces = BTreeMap::from([
                (source, words),
                (at(0, 0x100), plain()),
                (at(0, 0xff08), plain()),
                (at(1, 0x100), plain()),
            ]);
            let inventory = capture(&spaces);
            assert!(!inventory.issues().is_empty());
            assert_eq!(inventory.role(source, &[]), FunctionRole::Unverified);
            assert_eq!(inventory.role(at(0, 0xff08), &[]), FunctionRole::Unverified);
            assert_eq!(inventory.role(at(1, 0x100), &[]), FunctionRole::Physical);
            // A VF's requester ID is its PF's plus the offset and strides.
            let before = if source == PF {
                FunctionRole::Unverified
            } else {
                FunctionRole::Physical
            };
            assert_eq!(inventory.role(at(0, 0x100), &[]), before);
        }
    }
    #[test]
    fn failed_pf_reads_prevent_a_local_capability_absence_from_becoming_a_physical_grant() {
        let spaces = BTreeMap::from([(PF, pf(2, 8, 1)), (at(0, 0x100), plain())]);
        let functions: Vec<_> = spaces.keys().copied().collect();
        let inventory = Inventory::capture(&functions, |address, offset| {
            if address == PF && offset == 0x100 {
                Ok(None)
            } else {
                Ok(Some(spaces[&address][usize::from(offset) / 4]))
            }
        })
        .unwrap();
        assert_eq!(inventory.role(at(0, 0x100), &[]), FunctionRole::Unverified);
    }
    #[test]
    fn overlapping_pf_vf_ranges_and_nested_pf_capabilities_are_refused() {
        let spaces = BTreeMap::from([(at(0, 0), pf(2, 0x100, 1)), (PF, pf(2, 8, 1))]);
        assert!(
            capture(&spaces)
                .issues()
                .iter()
                .any(|issue| matches!(issue, Issue::Collision(_)))
        );
        let spaces = BTreeMap::from([(PF, pf(1, 8, 1)), (at(0, 0x100), pf(1, 8, 1))]);
        assert_eq!(capture(&spaces).role(PF, &[]), FunctionRole::Unverified);
    }
    #[test]
    fn changing_numvfs_during_capture_refuses_the_pf() {
        let words = pf(2, 8, 1);
        let mut samples = 0;
        let inventory = Inventory::capture(&[PF], |_, offset| {
            if offset == 0x110 {
                samples += 1;
                return Ok(Some(if samples == 1 { 2 } else { 1 }));
            }
            Ok(Some(words[usize::from(offset) / 4]))
        })
        .unwrap();
        assert_eq!(inventory.role(PF, &[]), FunctionRole::Unverified);
    }
    #[test]
    fn duplicate_and_unsupported_sriov_refuse_classification() {
        let mut duplicate = pf(2, 8, 1);
        duplicate[0x100 / 4] |= 0x140 << 20;
        duplicate[0x140 / 4] = 0x10010;
        let mut unknown = pf(2, 8, 1);
        unknown[0x100 / 4] = 0x20010;
        for words in [duplicate, unknown] {
            assert_eq!(
                capture(&BTreeMap::from([(PF, words)])).role(PF, &[]),
                FunctionRole::Unverified
            );
        }
        let mut conventional = plain();
        conventional[0x100 / 4] = u32::MAX;
        assert_eq!(
            capture(&BTreeMap::from([(PF, conventional)])).role(PF, &[]),
            FunctionRole::Physical
        );
    }

    /// Linux `pci_find_next_ext_capability`: a loop, a pointer with its low
    /// bits set or a vendor entry whose length cannot be read ends or passes
    /// the walk, and the PF is still classified.
    #[test]
    fn an_odd_extended_list_still_classifies_the_pf() {
        let mut cycle = pf(2, 8, 1);
        cycle[0x100 / 4] |= 0x100 << 20;
        let mut unaligned = pf(2, 8, 1);
        unaligned[0x100 / 4] |= 0x142 << 20;
        let mut vendor = pf(2, 8, 1);
        vendor[0x100 / 4] |= 0x200 << 20;
        vendor[0x200 / 4] = 0x1000b;
        for words in [cycle, unaligned, vendor] {
            let inventory = capture(&BTreeMap::from([(PF, words)]));
            assert!(inventory.issues().is_empty());
            assert_eq!(inventory.role(PF, &[]), FunctionRole::Physical);
        }
    }

    #[test]
    fn an_arriving_vf_keeps_the_initial_pf_classification_and_other_segments_stay_independent() {
        let mut inventory = capture(&BTreeMap::from([(PF, pf(2, 8, 2))]));
        inventory.extend(capture(&BTreeMap::from([
            (at(0, 0x100), plain()),
            (at(0, 0x102), plain()),
            (at(3, 0x100), plain()),
        ])));
        assert!(inventory.issues().is_empty());
        assert_eq!(inventory.role(at(0, 0x100), &[]), FunctionRole::Virtual);
        assert_eq!(inventory.role(at(0, 0x102), &[]), FunctionRole::Virtual);
        assert_eq!(inventory.role(at(3, 0x100), &[]), FunctionRole::Physical);
        assert_eq!(inventory.role(PF, &[]), FunctionRole::Physical);
    }
    #[test]
    fn repeated_unclaimed_observations_preserve_the_same_pf_epoch() {
        let spaces = BTreeMap::from([(PF, pf(2, 8, 2)), (at(0, 0x100), plain())]);
        let mut inventory = capture(&spaces);
        inventory.extend(capture(&spaces));
        assert!(inventory.issues().is_empty());
        assert_eq!(inventory.role(PF, &[]), FunctionRole::Physical);
        assert_eq!(inventory.role(at(0, 0x100), &[]), FunctionRole::Virtual);
    }
    #[test]
    fn arrival_cannot_change_an_existing_pf_or_reclassify_an_owned_physical_function() {
        for fresh in [
            BTreeMap::from([(PF, pf(1, 8, 1))]),
            BTreeMap::from([(PF, plain())]),
            BTreeMap::from([(at(0, 0), pf(1, 0xf8, 1))]),
            BTreeMap::from([(at(0, 0x100), pf(1, 8, 1))]),
        ] {
            let mut inventory = capture(&BTreeMap::from([(PF, pf(2, 8, 2))]));
            inventory.extend(capture(&fresh));
            assert!(!inventory.issues().is_empty());
            assert_eq!(inventory.role(PF, &[]), FunctionRole::Unverified);
        }
        let mut inventory = capture(&BTreeMap::from([(at(0, 0x100), plain())]));
        inventory.extend(capture(&BTreeMap::from([(PF, pf(1, 8, 1))])));
        assert_eq!(inventory.role(at(0, 0x100), &[]), FunctionRole::Unverified);
    }

    #[test]
    fn an_unready_pf_refuses_the_functions_after_it_on_its_link() {
        for vendor in [0, 1, u16::MAX] {
            let mut words = plain();
            words[0] = u32::from(vendor);
            let inventory = capture(&BTreeMap::from([(PF, words), (at(0, 0x100), plain())]));
            assert_eq!(inventory.role(at(0, 0x100), &[]), FunctionRole::Unverified);
        }
    }

    fn bridge(rid: u16, secondary: u8, subordinate: u8) -> Bridge {
        Bridge {
            address: at(0, rid),
            secondary,
            subordinate,
        }
    }

    /// A refused SR-IOV capability on a root-complex function (as on a PCH
    /// xHCI at 00:14.0) leaves the GPU behind a root port, the integrated
    /// graphics before it and every other link verified: only what could be
    /// its VFs is refused.
    #[test]
    fn a_defect_on_one_function_refuses_only_what_could_be_its_vfs() {
        let mut xhci = pf(2, 8, 1);
        xhci[0x100 / 4] |= 0x140 << 20;
        xhci[0x140 / 4] = 0x10010;
        let xhci_at = at(0, 0xa0);
        let gpu = at(0, 0x100);
        let mut gpu_space = pf(2, 8, 1);
        gpu_space[0x108 / 4] = 0;
        let spaces = BTreeMap::from([
            (at(0, 0x10), plain()),
            (xhci_at, xhci),
            (at(0, 0xfb), plain()),
            (gpu, gpu_space),
            (at(0, 0x101), plain()),
            (at(0, 0x200), plain()),
        ]);
        let inventory = capture(&spaces);
        assert!(
            inventory.issues() == [Issue::Sriov(xhci_at)],
            "{:?}",
            inventory.issues()
        );
        let bridges = [bridge(0x08, 1, 1), bridge(0xe0, 2, 2)];
        assert_eq!(inventory.role(xhci_at, &bridges), FunctionRole::Unverified);
        assert_eq!(
            inventory.refusal(xhci_at, &bridges),
            Some(Issue::Sriov(xhci_at))
        );
        // On the root complex's link after the xHCI: a VF of it could be there.
        assert_eq!(
            inventory.role(at(0, 0xfb), &bridges),
            FunctionRole::Unverified
        );
        // Before it on the same link, and on other links: never its VFs.
        assert_eq!(
            inventory.role(at(0, 0x10), &bridges),
            FunctionRole::Physical
        );
        assert_eq!(inventory.role(gpu, &bridges), FunctionRole::Physical);
        assert_eq!(inventory.refusal(gpu, &bridges), None);
        assert_eq!(
            inventory.role(at(0, 0x101), &bridges),
            FunctionRole::Physical
        );
        assert_eq!(
            inventory.role(at(0, 0x200), &bridges),
            FunctionRole::Physical
        );
        // Without the bridges' routes the whole root link is in doubt.
        assert_eq!(inventory.role(gpu, &[]), FunctionRole::Unverified);
    }

    /// A defect behind a root port stays on that port's link; a PF examined
    /// after it still has its VFs classified.
    #[test]
    fn a_defect_behind_a_bridge_stays_on_its_link_and_later_pfs_are_still_classified() {
        let mut unready = plain();
        unready[0] = 0xffff_0000 | 1;
        let spaces = BTreeMap::from([
            (at(0, 0x100), unready),
            (at(0, 0x101), plain()),
            (at(0, 0x200), pf(2, 8, 2)),
            (at(0, 0x208), plain()),
            (at(0, 0x20a), plain()),
            (at(0, 0x300), plain()),
            (PF, plain()),
        ]);
        let inventory = capture(&spaces);
        let bridges = [bridge(0x08, 1, 1), bridge(0xe0, 2, 3)];
        assert_eq!(
            inventory.role(at(0, 0x100), &bridges),
            FunctionRole::Unverified
        );
        assert_eq!(
            inventory.role(at(0, 0x101), &bridges),
            FunctionRole::Unverified
        );
        assert_eq!(
            inventory.role(at(0, 0x200), &bridges),
            FunctionRole::Physical
        );
        assert_eq!(
            inventory.role(at(0, 0x208), &bridges),
            FunctionRole::Virtual
        );
        assert_eq!(
            inventory.role(at(0, 0x20a), &bridges),
            FunctionRole::Virtual
        );
        assert_eq!(
            inventory.role(at(0, 0x300), &bridges),
            FunctionRole::Physical
        );
        assert_eq!(inventory.role(PF, &bridges), FunctionRole::Physical);
    }

    /// Bridges whose ranges do not nest cannot say where a VF could be:
    /// any issue then refuses its whole segment.
    #[test]
    fn bridges_that_do_not_form_a_tree_refuse_the_whole_segment() {
        let mut unready = plain();
        unready[0] = 0xffff_0000 | 1;
        let spaces = BTreeMap::from([
            (at(0, 0x100), unready),
            (at(0, 0x300), plain()),
            (at(1, 0x300), plain()),
        ]);
        let inventory = capture(&spaces);
        let good = [bridge(0x08, 1, 1), bridge(0x10, 2, 4)];
        assert_eq!(inventory.role(at(0, 0x300), &good), FunctionRole::Physical);
        for bad in [
            // Overlapping without nesting.
            [bridge(0x08, 1, 3), bridge(0x10, 2, 4)],
            // A range holding its own bridge's bus.
            [bridge(0x08, 1, 1), bridge(0x10, 0, 4)],
            // A bridge on bus 1 routing buses outside its parent's range.
            [bridge(0x08, 1, 1), bridge(0x108, 3, 4)],
            // Two bridges routing the same buses.
            [bridge(0x08, 1, 4), bridge(0x10, 1, 4)],
        ] {
            assert_eq!(inventory.role(at(0, 0x300), &bad), FunctionRole::Unverified);
            assert_eq!(inventory.role(at(1, 0x300), &bad), FunctionRole::Physical);
        }
    }

    #[test]
    fn a_failed_bridge_observation_refuses_its_subtree_or_the_segment_when_unknown() {
        let spaces = BTreeMap::from([
            (at(0, 0x10), plain()),
            (at(0, 0x100), plain()),
            (at(0, 0x200), plain()),
            (at(0, 0x300), plain()),
        ]);
        let mut inventory = capture(&spaces);
        let bridges = [bridge(0x08, 1, 2), bridge(0x108, 2, 2), bridge(0xe0, 3, 3)];
        inventory.invalidate_topology(at(0, 0x08));
        assert_eq!(
            inventory.role(at(0, 0x100), &bridges),
            FunctionRole::Unverified
        );
        assert_eq!(
            inventory.role(at(0, 0x200), &bridges),
            FunctionRole::Unverified
        );
        assert_eq!(
            inventory.role(at(0, 0x10), &bridges),
            FunctionRole::Physical
        );
        assert_eq!(
            inventory.role(at(0, 0x300), &bridges),
            FunctionRole::Physical
        );
        assert_eq!(
            inventory.refusal(at(0, 0x200), &bridges),
            Some(Issue::Topology(at(0, 0x08)))
        );
        inventory.invalidate_topology(at(0, 0x30));
        assert_eq!(
            inventory.role(at(0, 0x300), &bridges),
            FunctionRole::Unverified
        );
    }

    #[test]
    fn a_collision_refuses_its_link_both_ways_and_a_nested_pf_refuses_its_owner() {
        let spaces = BTreeMap::from([
            (at(0, 0x200), pf(2, 0x10, 1)),
            (at(0, 0x208), pf(2, 0x8, 1)),
            (at(0, 0x100), plain()),
        ]);
        let inventory = capture(&spaces);
        assert!(
            inventory
                .issues()
                .iter()
                .any(|issue| matches!(issue, Issue::Collision(_)))
        );
        let bridges = [bridge(0x08, 1, 1), bridge(0xe0, 2, 2)];
        assert_eq!(
            inventory.role(at(0, 0x200), &bridges),
            FunctionRole::Unverified
        );
        assert_eq!(
            inventory.role(at(0, 0x208), &bridges),
            FunctionRole::Unverified
        );
        assert_eq!(
            inventory.role(at(0, 0x100), &bridges),
            FunctionRole::Physical
        );
        // A VF that states SR-IOV of its own puts its PF in doubt, which is
        // before it.
        let spaces = BTreeMap::from([(at(0, 0x200), pf(1, 8, 1)), (at(0, 0x208), pf(1, 8, 1))]);
        let inventory = capture(&spaces);
        assert_eq!(
            inventory.role(at(0, 0x200), &bridges),
            FunctionRole::Unverified
        );
    }
}
