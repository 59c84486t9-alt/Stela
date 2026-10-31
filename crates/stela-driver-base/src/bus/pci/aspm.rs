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

/// Disable only ASPM L1.2 at the downstream/upstream link components.
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
        // SAFETY: checked exclusive segment ownership and complete ECAM
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
        // Skipping an unmapped range could hide the upstream bridge.
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

/// The ASPM Control field of the function's PCIe Link Control: zero
/// without a link, as `pcie_capability_read_word` reads a missing register.
pub fn aspm_control<C: ConfigSpace>(function: &Function<C>) -> u16 {
    link_control(function).map_or(0, |at| function.config.read16(at) & PCIE_ASPM)
}

/// The Current Link Speed field of the function's PCIe Link Status: zero
/// without a link, as `pcie_capability_read_word` reads a missing register.
pub fn link_speed<C: ConfigSpace>(function: &Function<C>) -> u8 {
    link_control(function).map_or(0, |at| (function.config.read16(at + 2) & 0xf) as u8)
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
mod tests;
