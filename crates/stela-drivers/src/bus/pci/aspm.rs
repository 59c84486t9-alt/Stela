// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (C) 2007 Intel
// Copyright (C) Zhang Yanmin (yanmin.zhang@intel.com)
// Copyright (C) Shaohua Li (shaohua.li@intel.com)
// Copyright (c) 2026 Stela contributors
//! PCIe ASPM errata handling, shared by physical-device drivers.
//!
//! The 82574 workaround follows Linux `e1000e/netdev.c`'s
//! `__e1000e_disable_aspm` at commit
//! `a804c5742bff224d4cb4d25dd383554d598be32b`: disable L0s/L1 on the
//! downstream component before its upstream bridge. Register/topology access
//! and validation here are Stela's own implementation.
pub mod native;

use super::{CapabilityError, ConfigSpace, EcamWindow, Function};
use crate::{Handoff, block::BlockError};
use alloc::vec::Vec;

const CAPABILITY_PCIE: u8 = 0x10;
const PCIE_FLAGS: u16 = 0x02;
const PCIE_LINK_CONTROL: u16 = 0x10;
const PCIE_ASPM: u16 = 3;
const BRIDGE_BUSES: u16 = 0x18;
const EXT_CAPABILITY_L1SS: u16 = 0x1e;
const L1SS_CONTROL1: u16 = 8;
const ASPM_L1_2: u32 = 1 << 2;

/// Disable only ASPM L1.2 at the actual downstream/upstream link components.
/// PCI-PM L1.2, L1.1, timing parameters and conventional Link Control remain
/// unchanged. Both capability chains and control snapshots are validated before
/// the downstream-first writes. An error may leave the downstream disabled;
/// it never rolls back by re-enabling an unsafe state or enables the device.
///
/// # Safety
/// The `disable_aspm_link` ownership/mapping requirements apply. In addition,
/// the host must own firmware/ACPI ASPM policy for this link; no firmware/AML
/// or other driver may restore L1.2 while this policy is in force.
pub unsafe fn disable_aspm_l1_2_link(
    function: &mut Function,
    handoff: &Handoff,
) -> Result<(), BlockError> {
    let windows = segment_windows(function, handoff)?;
    let mut functions = Vec::new();
    for window in windows {
        // SAFETY: qualified exclusive segment ownership and complete ECAM
        // mappings; no second PCI or firmware owner may race this operation.
        functions.extend(unsafe { Function::enumerate(&window) });
    }
    disable_l1_2_with(function, &mut functions)
}

fn l1ss_control<C: ConfigSpace>(function: &Function<C>) -> Result<Option<(u16, u32)>, BlockError> {
    // Validate a real conventional PCIe function before accessing its extended
    // configuration space. Keep malformed chains distinct from absent L1SS.
    link_control(function)?;
    let first = function.config.read32(0x100);
    if first == u32::MAX {
        return Err(BlockError::Device { status: first });
    }
    let mut found = None;
    for entry in function.config.extended_capabilities() {
        let entry = entry.map_err(|error| match error {
            CapabilityError::FailedRead { .. } => BlockError::Device { status: u32::MAX },
            CapabilityError::Cycle { .. } => {
                BlockError::Unsupported("looping PCI extended capabilities")
            }
            CapabilityError::Overlap { .. } => {
                BlockError::Unsupported("overlapping PCI extended capabilities")
            }
            _ => BlockError::Unsupported("invalid PCI extended capability offset"),
        })?;
        if entry.id != EXT_CAPABILITY_L1SS {
            continue;
        }
        if found.is_some() || entry.version != 1 {
            return Err(BlockError::Unsupported(
                "invalid or duplicate PCI L1SS capability",
            ));
        }
        let capability = function.config.read32(entry.offset + 4);
        let control = function.config.read32(entry.offset + L1SS_CONTROL1);
        if capability == u32::MAX || control == u32::MAX {
            return Err(BlockError::Device { status: u32::MAX });
        }
        if capability & (1 << 4) == 0 || (control & ASPM_L1_2 != 0 && capability & ASPM_L1_2 == 0) {
            return Err(BlockError::Unsupported(
                "inconsistent PCI L1SS support/control",
            ));
        }
        found = Some((entry.offset + L1SS_CONTROL1, control));
    }
    Ok(found)
}

fn clear_l1_2<C: ConfigSpace>(
    function: &mut Function<C>,
    snapshot: (u16, u32),
) -> Result<(), BlockError> {
    let (offset, original) = snapshot;
    let wanted = original & !ASPM_L1_2;
    if original != wanted {
        // Linux notes some devices require DWORD access to L1SS. CTL1 is a
        // full control register, unlike Link Control's adjacent W1C status.
        function.config.write32(offset, wanted);
    }
    let observed = function.config.read32(offset);
    if observed != wanted {
        return Err(BlockError::Device { status: observed });
    }
    Ok(())
}

fn disable_l1_2_with<C: ConfigSpace>(
    function: &mut Function<C>,
    functions: &mut [Function<C>],
) -> Result<(), BlockError> {
    let parent = upstream(function, functions)?;
    let child_control = l1ss_control(function)?;
    let parent_control = parent
        .map(|index| l1ss_control(&functions[index]))
        .transpose()?
        .flatten();
    // An older peer without L1SS cannot form L1.2. Do not refuse a working
    // endpoint or invent a missing control; disable every advertised side.
    if let Some(child) = child_control {
        clear_l1_2(function, child)?;
    }
    if let Some((parent, control)) = parent.zip(parent_control) {
        clear_l1_2(&mut functions[parent], control)?;
    }
    Ok(())
}

/// Disable both ASPM states on a PCIe function and its immediate upstream
/// bridge, before enabling the device's MMIO or bus mastering. Both ends
/// are read back; a refused setting is an error. Bus topology comes from
/// type-1 headers, not from bus-number arithmetic. An endpoint directly on
/// a root bus has no parent bridge and only its own control is changed.
///
/// # Safety
///
/// `handoff` must describe valid identity-mapped ECAM windows after
/// ExitBootServices. The caller must exclusively own PCI configuration
/// access throughout the function's segment for this operation; no other
/// firmware, thread or driver may access those configuration registers.
/// `function` must be the unique active owner of its addressed function.
pub unsafe fn disable_aspm_link(
    function: &mut Function,
    handoff: &Handoff,
) -> Result<(), BlockError> {
    let windows = segment_windows(function, handoff)?;
    let mut functions = Vec::new();
    for window in windows {
        // SAFETY: the caller owns configuration access; segment_windows
        // checked every window's entire mapping and disjoint bus numbers.
        functions.extend(unsafe { Function::enumerate(&window) });
    }
    disable_aspm_with(function, &mut functions)
}

fn segment_windows<C: ConfigSpace>(
    function: &Function<C>,
    handoff: &Handoff,
) -> Result<Vec<EcamWindow>, BlockError> {
    let windows: Vec<_> = handoff
        .ecam
        .iter()
        .filter(|window| window.segment == function.address.segment)
        .copied()
        .collect();
    let mapped = windows
        .iter()
        .all(|window| window.start_bus <= window.end_bus && handoff.is_mapped(&window.range()));
    let contains = windows
        .iter()
        .any(|window| (window.start_bus..=window.end_bus).contains(&function.address.bus));
    if !mapped || !contains {
        // Skipping an unmapped range could hide the actual upstream bridge.
        return Err(BlockError::Unsupported(
            "unmapped PCI configuration for ASPM",
        ));
    }
    for (index, window) in windows.iter().enumerate() {
        if windows[index + 1..]
            .iter()
            .any(|other| window.start_bus <= other.end_bus && other.start_bus <= window.end_bus)
        {
            return Err(BlockError::Unsupported(
                "overlapping PCI configuration windows",
            ));
        }
    }
    Ok(windows)
}

fn link_control<C: ConfigSpace>(function: &Function<C>) -> Result<u16, BlockError> {
    let mut express = None;
    for entry in function.config.capabilities() {
        let entry =
            entry.map_err(|_| BlockError::Unsupported("malformed PCI capabilities for ASPM"))?;
        if entry.id == CAPABILITY_PCIE && express.replace(entry.offset).is_some() {
            return Err(BlockError::Unsupported("multiple PCIe capabilities"));
        }
    }
    let capability = express.ok_or(BlockError::Unsupported("ASPM requires a PCIe capability"))?;
    // This is a conventional capability, entirely in the first 256 bytes.
    if capability + PCIE_LINK_CONTROL + 2 > 0x100 {
        return Err(BlockError::Unsupported(
            "PCIe link control outside capability space",
        ));
    }
    let flags = function.config.read16(capability + PCIE_FLAGS);
    let port_type = (flags >> 4) & 0xf;
    // Root-complex integrated endpoints/event collectors have no Link Control.
    if flags & 0xf == 0 || !matches!(port_type, 0 | 1 | 4 | 5 | 6 | 7 | 8) {
        return Err(BlockError::Unsupported("PCIe function has no link control"));
    }
    Ok(capability + PCIE_LINK_CONTROL)
}

fn upstream<C: ConfigSpace>(
    function: &Function<C>,
    functions: &[Function<C>],
) -> Result<Option<usize>, BlockError> {
    let mut found = None;
    for (index, candidate) in functions.iter().enumerate() {
        if candidate.address.segment != function.address.segment
            || candidate.address == function.address
            || candidate.class[..2] != [6, 4]
            || candidate.header_type() != 1
        {
            continue;
        }
        let buses = candidate.config.read32(BRIDGE_BUSES);
        let primary = buses as u8;
        let secondary = (buses >> 8) as u8;
        let subordinate = (buses >> 16) as u8;
        // Firmware leaves unused bridges with secondary bus zero. They do
        // not make every root-bus endpoint their downstream child.
        if secondary == 0 || secondary != function.address.bus {
            continue;
        }
        if primary != candidate.address.bus || secondary == primary || subordinate < secondary {
            return Err(BlockError::Unsupported(
                "invalid upstream PCI bridge routing",
            ));
        }
        if found.replace(index).is_some() {
            return Err(BlockError::Unsupported("ambiguous upstream PCI bridge"));
        }
    }
    Ok(found)
}

fn clear_aspm<C: ConfigSpace>(function: &mut Function<C>, control: u16) -> Result<(), BlockError> {
    let value = function.config.read16(control);
    if value & PCIE_ASPM != 0 {
        // Narrow access is essential: Link Status shares this DWORD and
        // includes W1C fields that must not be acknowledged by this write.
        function.config.write16(control, value & !PCIE_ASPM);
    }
    let status = function.config.read16(control);
    if status & PCIE_ASPM != 0 {
        return Err(BlockError::Device {
            status: u32::from(status),
        });
    }
    Ok(())
}

fn disable_aspm_with<C: ConfigSpace>(
    function: &mut Function<C>,
    functions: &mut [Function<C>],
) -> Result<(), BlockError> {
    let upstream = upstream(function, functions)?;
    let downstream_control = link_control(function)?;
    // Validate both capabilities before changing either end of the link.
    let upstream_control = upstream
        .map(|index| link_control(&functions[index]))
        .transpose()?;
    clear_aspm(function, downstream_control)?;
    if let Some((index, control)) = upstream.zip(upstream_control) {
        clear_aspm(&mut functions[index], control)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Clock,
        bus::pci::{Address, EcamConfig},
    };
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;

    type Writes = Rc<RefCell<Vec<(Address, u16, u32)>>>;

    struct Config {
        words: [u32; 1024],
        address: Address,
        writes: Writes,
        refuses_aspm: bool,
        refuses_l1ss: bool,
        failed_read: Option<u16>,
    }

    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            if self.failed_read == Some(offset) {
                return u32::MAX;
            }
            self.words[usize::from(offset / 4)]
        }
        fn write32(&mut self, offset: u16, value: u32) {
            assert!(
                offset >= 0x100,
                "ASPM must not write a DWORD containing W1C Link Status"
            );
            self.writes.borrow_mut().push((self.address, offset, value));
            self.words[usize::from(offset / 4)] =
                value | if self.refuses_l1ss { ASPM_L1_2 } else { 0 };
        }
        fn write16(&mut self, offset: u16, value: u16) {
            self.writes
                .borrow_mut()
                .push((self.address, offset, u32::from(value)));
            let shift = (offset & 2) * 8;
            let value = if self.refuses_aspm {
                value | PCIE_ASPM
            } else {
                value
            };
            let word = &mut self.words[usize::from(offset / 4)];
            *word = (*word & !(0xffff << shift)) | (u32::from(value) << shift);
        }
    }

    fn address(segment: u16, bus: u8, device: u8) -> Address {
        Address {
            segment,
            bus,
            device,
            function: 0,
        }
    }

    fn device(at: Address, bridge: Option<(u8, u8)>, writes: &Writes) -> Function<Config> {
        let mut config = Config {
            words: [0; 1024],
            address: at,
            writes: Rc::clone(writes),
            refuses_aspm: false,
            refuses_l1ss: false,
            failed_read: None,
        };
        config.words[0] = 0x10d3_8086;
        config.words[1] = 1 << 20; // status capability-list flag
        config.words[2] = if bridge.is_some() {
            0x0604_0000
        } else {
            0x0200_0000
        };
        config.words[13] = 0x40;
        config.words[16] =
            (1 | if bridge.is_some() { 4 << 4 } else { 0 }) << 16 | u32::from(CAPABILITY_PCIE);
        // Preserve all unrelated Link Control bits and W1C Link Status.
        config.words[20] = 0xc000_a5a3;
        if let Some((secondary, subordinate)) = bridge {
            config.words[3] = 1 << 16;
            config.words[6] =
                u32::from(at.bus) | u32::from(secondary) << 8 | u32::from(subordinate) << 16;
        }
        Function::new(at, config).unwrap()
    }

    #[test]
    fn disables_the_exact_link_downstream_first_with_narrow_writes() {
        let writes = Writes::default();
        let mut endpoint = device(address(3, 8, 0), None, &writes);
        let parent_address = address(3, 4, 2);
        let mut functions = vec![
            device(address(3, 0, 1), Some((4, 12)), &writes), // ancestor, not parent
            device(address(0, 4, 2), Some((8, 8)), &writes),  // different segment
            device(parent_address, Some((8, 12)), &writes),
            device(address(3, 4, 3), Some((9, 10)), &writes), // sibling link
        ];
        disable_aspm_with(&mut endpoint, &mut functions).unwrap();
        assert_eq!(
            *writes.borrow(),
            [
                (endpoint.address, 0x50, 0xa5a0),
                (parent_address, 0x50, 0xa5a0)
            ]
        );
        assert_eq!(endpoint.config.words[20], 0xc000_a5a0);
        assert_eq!(functions[2].config.words[20], 0xc000_a5a0);
        assert_eq!(functions[0].config.words[20], 0xc000_a5a3);
        assert_eq!(functions[1].config.words[20], 0xc000_a5a3);
        assert_eq!(functions[3].config.words[20], 0xc000_a5a3);
    }

    #[test]
    fn a_root_bus_endpoint_disables_its_own_link_control() {
        let writes = Writes::default();
        let mut endpoint = device(address(0, 0, 3), None, &writes);
        let mut disabled = device(address(0, 0, 1), Some((0, 0)), &writes);
        disable_aspm_with(&mut endpoint, core::slice::from_mut(&mut disabled)).unwrap();
        assert_eq!(*writes.borrow(), [(endpoint.address, 0x50, 0xa5a0)]);
        assert_eq!(disabled.config.words[20], 0xc000_a5a3);
        writes.borrow_mut().clear();
        disable_aspm_with(&mut endpoint, &mut []).unwrap();
        assert!(writes.borrow().is_empty());
    }

    #[test]
    fn both_capabilities_must_be_valid_before_any_register_is_changed() {
        let writes = Writes::default();
        let mut endpoint = device(address(0, 8, 0), None, &writes);
        let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
        parent.config.words[16] = 0; // no PCIe capability
        assert!(disable_aspm_with(&mut endpoint, &mut [parent]).is_err());
        assert!(writes.borrow().is_empty());
        endpoint.config.words[16] = 0x0091_0010; // RC-integrated endpoint, no link control
        assert!(disable_aspm_with(&mut endpoint, &mut []).is_err());
        assert!(writes.borrow().is_empty());
    }

    #[test]
    fn duplicate_parents_invalid_bus_routing_and_capability_loops_fail() {
        let writes = Writes::default();
        let mut endpoint = device(address(0, 8, 0), None, &writes);
        let mut parents = [
            device(address(0, 4, 1), Some((8, 8)), &writes),
            device(address(0, 4, 2), Some((8, 8)), &writes),
        ];
        assert!(disable_aspm_with(&mut endpoint, &mut parents).is_err());
        parents[0].config.words[6] ^= 1; // primary bus disagrees with address
        assert!(disable_aspm_with(&mut endpoint, &mut parents[..1]).is_err());
        endpoint.config.words[16] |= 0x4000; // self-referential capability chain
        assert!(disable_aspm_with(&mut endpoint, &mut []).is_err());
        assert!(writes.borrow().is_empty());
    }

    #[test]
    fn a_refused_aspm_change_is_reported() {
        let writes = Writes::default();
        let mut endpoint = device(address(0, 0, 3), None, &writes);
        endpoint.config.refuses_aspm = true;
        assert!(matches!(
            disable_aspm_with(&mut endpoint, &mut []),
            Err(BlockError::Device { .. })
        ));
    }

    #[test]
    fn ecam_halfword_store_does_not_replace_the_adjacent_halfword() {
        let mut words = [0xc000_a5a3u32; 64];
        // SAFETY: the fixture owns this exact stable ECAM backing.
        let mut config = unsafe { EcamConfig::raw(words.as_mut_ptr() as u64) };
        config.write16(0x50, 0xa5a0);
        assert_eq!(words[20], 0xc000_a5a0);
        config.write16(0x52, 0x1234);
        assert_eq!(words[20], 0x1234_a5a0);
    }

    #[test]
    fn unmapped_or_overlapping_segment_windows_are_not_scanned() {
        let writes = Writes::default();
        let endpoint = device(address(1, 2, 0), None, &writes);
        let window = EcamWindow {
            base: 0x8000_0000,
            segment: 1,
            start_bus: 0,
            end_bus: 3,
        };
        let mut handoff = Handoff {
            firmware: None,
            bluetooth_platform: Default::default(),
            wifi_platform: Default::default(),
            completion: None,
            ecam: vec![window],
            mapped: vec![window.range()],
            dma: 0..0,
            clock: Clock {
                ticks_per_microsecond: 1,
            },
        };
        assert_eq!(segment_windows(&endpoint, &handoff).unwrap(), [window]);
        handoff.mapped.clear();
        assert!(segment_windows(&endpoint, &handoff).is_err());
        handoff.mapped.push(window.range());
        handoff.ecam.push(window);
        assert!(segment_windows(&endpoint, &handoff).is_err());
        handoff.ecam = vec![EcamWindow {
            segment: 0,
            ..window
        }];
        assert!(segment_windows(&endpoint, &handoff).is_err());
    }

    fn add_l1ss(function: &mut Function<Config>, at: u16, control: u32) {
        function.config.words[0x100 / 4] = u32::from(at) << 20 | 0x0001_0001;
        function.config.words[usize::from(at / 4)] = 0x0001_001e;
        function.config.words[usize::from((at + 4) / 4)] = 0x1f;
        function.config.words[usize::from((at + 8) / 4)] = control;
    }

    #[test]
    fn l1_2_changes_only_aspm_bit_downstream_before_parent_with_dword_access() {
        let writes = Writes::default();
        let mut endpoint = device(address(0, 8, 0), None, &writes);
        let mut parent = device(address(0, 4, 1), Some((8, 12)), &writes);
        add_l1ss(&mut endpoint, 0x180, 0x5abca50f);
        add_l1ss(&mut parent, 0x240, 0xabcdff0f);
        let parent_address = parent.address;
        disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
        assert_eq!(
            *writes.borrow(),
            [
                (endpoint.address, 0x188, 0x5abca50b),
                (parent_address, 0x248, 0xabcdff0b)
            ]
        );
        assert_eq!(endpoint.config.words[20], 0xc000_a5a3);
        assert_eq!(parent.config.words[20], 0xc000_a5a3);
        assert_eq!(endpoint.config.words[0x188 / 4], 0x5abca50b);
        assert_eq!(parent.config.words[0x248 / 4], 0xabcdff0b);
        writes.borrow_mut().clear();
        disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
        assert!(
            writes.borrow().is_empty(),
            "already-disabled controls need no write"
        );
    }

    #[test]
    fn l1ss_absence_skips_missing_controls_and_malformed_capabilities_still_refuse() {
        let writes = Writes::default();
        let mut endpoint = device(address(0, 8, 0), None, &writes);
        let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
        disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
        add_l1ss(&mut endpoint, 0x180, 0xf);
        disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).unwrap();
        assert_eq!(*writes.borrow(), [(endpoint.address, 0x188, 0xb)]);
        writes.borrow_mut().clear();
        disable_l1_2_with(&mut endpoint, &mut []).unwrap();
        assert!(writes.borrow().is_empty());
        add_l1ss(&mut parent, 0x180, 0xf);
        let mut older_endpoint = device(address(0, 8, 0), None, &writes);
        disable_l1_2_with(&mut older_endpoint, core::slice::from_mut(&mut parent)).unwrap();
        assert_eq!(*writes.borrow(), [(parent.address, 0x188, 0xb)]);
        writes.borrow_mut().clear();
        for invalid in 0..8 {
            let mut broken = device(address(0, 4, 1), Some((8, 8)), &writes);
            add_l1ss(&mut broken, 0x180, 0xf);
            match invalid {
                0 => broken.config.words[0x180 / 4] |= 0x180 << 20, // loop
                1 => broken.config.words[0x180 / 4] |= 0x183 << 20, // misalignment
                2 => broken.config.words[0x180 / 4] |= 0x080 << 20, // below extended space
                3 => broken.config.words[0x180 / 4] = 0x0002_001e,  // unknown L1SS version
                4 => {
                    broken.config.words[0x180 / 4] |= 0x200 << 20;
                    broken.config.words[0x200 / 4] = 0x0001_001e;
                }
                5 => broken.config.words[0x184 / 4] = 0, // support absent
                6 => {
                    broken.config.words[0x184 / 4] = 0x10;
                } // enabled unsupported L1.2
                _ => {
                    broken.config.words[0x100 / 4] = 0xff4 << 20 | 0x10001;
                    broken.config.words[0xff4 / 4] = 0x1001e;
                }
            }
            assert!(
                disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut broken)).is_err(),
                "invalid {invalid}"
            );
            assert!(writes.borrow().is_empty());
        }
    }

    #[test]
    fn l1ss_failed_reads_and_refused_changes_leave_observable_partial_state() {
        let writes = Writes::default();
        for failed in [0x100, 0x180, 0x184, 0x188] {
            let mut endpoint = device(address(0, 8, 0), None, &writes);
            let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
            add_l1ss(&mut endpoint, 0x180, 0xf);
            add_l1ss(&mut parent, 0x180, 0xf);
            parent.config.failed_read = Some(failed);
            assert_eq!(
                disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)),
                Err(BlockError::Device { status: u32::MAX })
            );
            assert!(writes.borrow().is_empty());
        }
        let mut endpoint = device(address(0, 8, 0), None, &writes);
        let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
        add_l1ss(&mut endpoint, 0x180, 0xf);
        add_l1ss(&mut parent, 0x180, 0xf);
        endpoint.config.refuses_l1ss = true;
        assert!(disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).is_err());
        assert_eq!(writes.borrow().len(), 1);
        writes.borrow_mut().clear();
        endpoint.config.refuses_l1ss = false;
        parent.config.refuses_l1ss = true;
        assert!(disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent)).is_err());
        assert_eq!(writes.borrow().len(), 2);
        assert_eq!(endpoint.config.words[0x188 / 4], 0xb);
        assert_eq!(parent.config.words[0x188 / 4], 0xf);
    }

    #[test]
    fn extended_headers_cannot_alias_l1ss_bodies_in_either_traversal_direction() {
        for body in [0x184u16, 0x188, 0x18c] {
            for reverse in [false, true] {
                for broken_parent in [false, true] {
                    let writes = Writes::default();
                    let mut endpoint = device(address(0, 8, 0), None, &writes);
                    let mut parent = device(address(0, 4, 1), Some((8, 8)), &writes);
                    add_l1ss(&mut endpoint, 0x180, 0x0001_0005);
                    add_l1ss(&mut parent, 0x180, 0x0001_0005);
                    let broken = if broken_parent {
                        &mut parent
                    } else {
                        &mut endpoint
                    };
                    let unknown_header = if body == 0x184 {
                        0x0001_001f
                    } else {
                        0x0001_0005
                    };
                    if reverse {
                        broken.config.words[0x100 / 4] = u32::from(body) << 20 | 0x0001_0001;
                        broken.config.words[usize::from(body / 4)] = 0x180 << 20 | unknown_header;
                    } else {
                        broken.config.words[0x180 / 4] |= u32::from(body) << 20;
                        broken.config.words[usize::from(body / 4)] = unknown_header;
                    }
                    let endpoint_before = endpoint.config.words;
                    let parent_before = parent.config.words;
                    assert!(
                        disable_l1_2_with(&mut endpoint, core::slice::from_mut(&mut parent))
                            .is_err(),
                        "body {body:x} reverse {reverse} parent {broken_parent}"
                    );
                    assert!(writes.borrow().is_empty());
                    assert_eq!(endpoint.config.words, endpoint_before);
                    assert_eq!(parent.config.words, parent_before);
                }
            }
        }
    }
}
