// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 1999 - 2018 Intel Corporation.
// Copyright (c) 2026 Stela contributors
//! PCIe ASPM errata handling, shared by physical-device drivers.
//!
//! The 82574 workaround follows Linux `e1000e/netdev.c`'s
//! `__e1000e_disable_aspm` at commit
//! `a804c5742bff224d4cb4d25dd383554d598be32b`: disable L0s/L1 on the
//! downstream component before its upstream bridge. Register/topology access
//! and validation here are Stela's own implementation.
use super::{ConfigSpace, EcamWindow, Function};
use crate::{Handoff, block::BlockError};
use alloc::vec::Vec;

const CAPABILITY_PCIE: u8 = 0x10;
const PCIE_FLAGS: u16 = 0x02;
const PCIE_LINK_CONTROL: u16 = 0x10;
const PCIE_ASPM: u16 = 3;
const BRIDGE_BUSES: u16 = 0x18;

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
    let mut seen = [false; 64];
    for (offset, id) in function.capabilities() {
        if core::mem::replace(&mut seen[usize::from(offset / 4)], true) {
            return Err(BlockError::Unsupported("looping PCI capabilities for ASPM"));
        }
        if id == CAPABILITY_PCIE && express.replace(u16::from(offset)).is_some() {
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
        bus::pci::{Address, EcamConfig, Mmio},
    };
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;

    type Writes = Rc<RefCell<Vec<(Address, u16, u16)>>>;

    struct Config {
        words: [u32; 64],
        address: Address,
        writes: Writes,
        refuses_aspm: bool,
    }

    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            self.words[usize::from(offset / 4)]
        }
        fn write32(&mut self, _: u16, _: u32) {
            panic!("ASPM must not write a DWORD containing W1C Link Status");
        }
        fn write16(&mut self, offset: u16, value: u16) {
            self.writes.borrow_mut().push((self.address, offset, value));
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
            words: [0; 64],
            address: at,
            writes: Rc::clone(writes),
            refuses_aspm: false,
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
        let mut config = EcamConfig {
            // SAFETY: this test owns the complete aligned register backing.
            registers: unsafe { Mmio::new(words.as_mut_ptr() as u64) },
        };
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
}
