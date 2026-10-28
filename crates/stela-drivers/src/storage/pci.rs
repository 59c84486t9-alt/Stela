// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict native PCI admission shared by polled storage controllers.
use crate::{
    block::BlockError,
    bus::pci::{ConfigSpace, Function, Layout, capability},
};
use alloc::vec::Vec;

const PCI_COMMAND: u16 = 0x04;
const PCI_MEMORY: u16 = 1 << 1;
const PCI_BUS_MASTER: u16 = 1 << 2;
const PCI_INTX_DISABLE: u16 = 1 << 10;
const PCI_CAP_CONTROL: u16 = 2;
const PCI_HEADER_TYPE: u16 = 0x0e;
const PCI_PM: u8 = 0x01;
const PCI_VPD: u8 = 0x03;
const PCI_VENDOR: u8 = 0x09;
const PCI_SSVID: u8 = 0x0d;
const PCI_EXPRESS: u8 = 0x10;
const PCI_EXP_TYPE: u16 = 0x00f0;
const PCI_EXP_SLOT: u16 = 0x0100;
const PCI_EXP_ENDPOINT: u16 = 0;
const PCI_EXP_LEGACY_ENDPOINT: u16 = 1;
const PCI_EXP_RC_ENDPOINT: u16 = 9;
const PCI_MSI: u8 = 0x05;
const PCI_MSIX: u8 = 0x11;
const PCI_MSI_ENABLE: u16 = 1;
const PCI_MSIX_ENABLE: u16 = 1 << 15;

/// Return a capability only after validating the entire supported chain,
/// including the real version-specific body of every admitted capability.
pub(super) fn capability<C: ConfigSpace>(config: &C, id: u8) -> Result<Option<u16>, BlockError> {
    Ok(checked_capabilities(config, Some(id))?.1)
}

pub(super) fn quiesce_pio<C: ConfigSpace>(function: &mut Function<C>) -> Result<(), BlockError> {
    let identity = u32::from(function.vendor) | u32::from(function.device) << 16;
    if function.config().read32(0) != identity {
        return Err(BlockError::Unsupported(
            "storage PCI identity changed before PIO ownership",
        ));
    }
    let [msi, msix] = checked_capabilities(function.config(), None)?.0;
    set_pio_command(function, false)?;
    if let Some(at) = msi {
        let value = function.config().read16(at) & !PCI_MSI_ENABLE;
        function.config().write16(at, value);
        if function.config().read16(at) & PCI_MSI_ENABLE != 0 {
            return Err(BlockError::Unsupported(
                "storage PIO MSI disable did not acknowledge",
            ));
        }
    }
    if let Some(at) = msix {
        let value = function.config().read16(at) & !PCI_MSIX_ENABLE;
        function.config().write16(at, value);
        if function.config().read16(at) & PCI_MSIX_ENABLE != 0 {
            return Err(BlockError::Unsupported(
                "storage PIO MSI-X disable did not acknowledge",
            ));
        }
    }
    Ok(())
}

// The shared inventory is deliberately tolerant for discovery. Hardware ownership
// instead requires a complete, unambiguous chain before any power/BAR/MMIO work.
fn checked_capabilities<C: ConfigSpace>(
    config: &C,
    target: Option<u8>,
) -> Result<([Option<u16>; 2], Option<u16>), BlockError> {
    let malformed = BlockError::Unsupported("storage malformed PCI capability chain");
    if config.read8(PCI_HEADER_TYPE) & 0x7f != 0 {
        return Err(malformed);
    }
    let mut controls = [None; 2];
    let mut found = None;
    let mut singletons = [false; 256];
    for entry in config.capabilities() {
        let entry = entry.map_err(|_| malformed.clone())?;
        let (at, id) = (entry.offset, entry.id);
        if id == 0 {
            return Err(malformed);
        }
        if id != PCI_VENDOR {
            if singletons[usize::from(id)] {
                return Err(malformed);
            }
            singletons[usize::from(id)] = true;
        }
        if target == Some(id) {
            found = Some(at);
        }
        // Every admitted body must be measured. Otherwise a next pointer can
        // name PM/MSI controls inside a different capability's real registers.
        match id {
            PCI_PM | PCI_VPD | PCI_SSVID | PCI_VENDOR => {}
            PCI_EXPRESS => {
                let flags = config.read16(at + PCI_CAP_CONTROL);
                let kind = (flags & PCI_EXP_TYPE) >> 4;
                if flags & PCI_EXP_SLOT != 0 {
                    return Err(BlockError::Unsupported(
                        "storage unqualified PCIe slot capability",
                    ));
                }
                if !matches!(
                    kind,
                    PCI_EXP_ENDPOINT | PCI_EXP_LEGACY_ENDPOINT | PCI_EXP_RC_ENDPOINT
                ) || entry.layout != Layout::Sized
                {
                    return Err(BlockError::Unsupported(
                        "storage unqualified PCIe capability extent",
                    ));
                }
            }
            PCI_MSI | PCI_MSIX => {
                controls[usize::from(id == PCI_MSIX)] = Some(at + PCI_CAP_CONTROL);
            }
            _ => {
                return Err(BlockError::Unsupported(
                    "storage unsupported PCI capability extent",
                ));
            }
        }
    }
    Ok((controls, found))
}

/// The offset of extended capability `target`, after every entry is
/// measured: endpoint AER without prefix or completion-timeout logging, serial
/// number, power budgeting, vendor-specific, LTR, L1 PM substates and PTM, each
/// once except vendor-specific. A header in another body grants nothing; any
/// other capability or layout is `invalid`.
pub(super) fn measured_extended<C: ConfigSpace + ?Sized>(
    config: &C,
    target: u16,
    invalid: BlockError,
) -> Result<Option<u16>, BlockError> {
    if config.read32(0x100) == u32::MAX {
        return Err(invalid);
    }
    let entries = capability::extended_capabilities(config)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid.clone())?;
    let mut singletons = 0u32;
    let mut found = None;
    for entry in &entries {
        let (at, id) = (entry.offset, entry.id);
        if entry.version != 1 && !(id == 1 && entry.version == 2) {
            return Err(invalid);
        }
        match id {
            // Conventional (non-Flit) endpoint AER through the four DWORD log.
            1 => {
                if at + 0x2c > 0x1000
                    || capability::overlap(entries.iter().map(|e| e.span()), at, 0x2c).is_some()
                    || config.read32(at + 0x18) & (1 << 11 | 1 << 12 | 1 << 18) != 0
                {
                    return Err(invalid);
                }
            }
            3 | 4 | 0x0b | 0x18 | 0x1e | 0x1f => {}
            _ => return Err(invalid),
        }
        if id != 0x0b {
            let bit = 1 << id;
            if singletons & bit != 0 {
                return Err(invalid);
            }
            singletons |= bit;
        }
        if id == target {
            found = Some(at);
        }
    }
    Ok(found)
}

pub(super) fn set_pio_command<C: ConfigSpace>(
    function: &mut Function<C>,
    grant_memory: bool,
) -> Result<(), BlockError> {
    let command = (function.config().read16(PCI_COMMAND) & !(PCI_BUS_MASTER | PCI_MEMORY))
        | PCI_INTX_DISABLE
        | if grant_memory { PCI_MEMORY } else { 0 };
    // Clear DMA ownership before power-up/BAR probing; grant memory only after
    // every register mapping has been validated. Neither phase grants DMA.
    function.config().write16(PCI_COMMAND, command);
    let mask = PCI_BUS_MASTER | PCI_MEMORY | PCI_INTX_DISABLE;
    if function.config().read16(PCI_COMMAND) & mask != command & mask {
        return Err(BlockError::Unsupported(
            "storage PIO PCI command did not acknowledge",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Clock;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::RefCell;
    #[test]
    fn owned_pio_activation_never_grants_dma_or_writes_adjacent_pci_status() {
        #[derive(Clone)]
        struct Config {
            bytes: Rc<RefCell<Vec<u8>>>,
            writes: Rc<RefCell<Vec<(u16, usize, u32)>>>,
        }
        impl ConfigSpace for Config {
            fn read8(&self, at: u16) -> u8 {
                self.bytes.borrow()[usize::from(at)]
            }
            fn read16(&self, at: u16) -> u16 {
                let at = usize::from(at);
                u16::from_le_bytes(self.bytes.borrow()[at..at + 2].try_into().unwrap())
            }
            fn read32(&self, at: u16) -> u32 {
                let at = usize::from(at);
                u32::from_le_bytes(self.bytes.borrow()[at..at + 4].try_into().unwrap())
            }
            fn write8(&mut self, _: u16, _: u8) {
                panic!("PIO activation must use actual word stores");
            }
            fn write32(&mut self, _: u16, _: u32) {
                panic!("PCI status/control RMW would clear adjacent W1C status");
            }
            fn write16(&mut self, at: u16, value: u16) {
                assert!(matches!(at, 0x04 | 0x52 | 0x62 | 0x92 | 0xa2));
                if at == 0x04 {
                    assert_eq!(value & PCI_BUS_MASTER, 0, "transient DMA grant");
                }
                self.writes.borrow_mut().push((at, 2, u32::from(value)));
                let at = usize::from(at);
                self.bytes.borrow_mut()[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
        }
        let bytes = Rc::new(RefCell::new(vec![0; 256]));
        let writes = Rc::new(RefCell::new(Vec::new()));
        {
            let mut b = bytes.borrow_mut();
            b[..4].copy_from_slice(&0x8220_1217u32.to_le_bytes());
            b[4..6].copy_from_slice(&7u16.to_le_bytes());
            b[6..8].copy_from_slice(&0xa010u16.to_le_bytes());
            b[8..12].copy_from_slice(&0x0805_0100u32.to_le_bytes());
            b[0x34] = 0x50;
            b[0x50] = 5;
            b[0x51] = 0x60;
            b[0x52..0x54].copy_from_slice(&0x81u16.to_le_bytes());
            b[0x60] = 0x11;
            b[0x62..0x64].copy_from_slice(&0x8001u16.to_le_bytes());
        }
        let valid = bytes.borrow().clone();
        let mut function = Function::new(
            crate::bus::pci::Address {
                segment: 0,
                bus: 0,
                device: 1,
                function: 0,
            },
            Config {
                bytes: bytes.clone(),
                writes: writes.clone(),
            },
        )
        .unwrap();
        quiesce_pio(&mut function).unwrap();
        assert_eq!(function.config().read16(4), 0x401);
        set_pio_command(&mut function, true).unwrap();
        let c = function.config();
        assert_eq!(c.read16(4), 0x403);
        assert_eq!(c.read16(6), 0xa010);
        assert_eq!(c.read16(0x52), 0x80);
        assert_eq!(c.read16(0x62), 1);
        assert_eq!(
            &*writes.borrow(),
            &[(4, 2, 0x401), (0x52, 2, 0x80), (0x62, 2, 1), (4, 2, 0x403)]
        );
        // Refuse malformed inventories without even a PCI command write: otherwise
        // the tolerant shared inventory could hide a still-enabled interrupt route.
        for (name, changes) in [
            ("below capability range", vec![(0x34, 0x3c)]),
            ("unaligned head", vec![(0x34, 0x51)]),
            ("unaligned next", vec![(0x51, 0x63)]),
            ("self loop", vec![(0x51, 0x50)]),
            ("multi-node loop", vec![(0x61, 0x50)]),
            ("duplicate MSI", vec![(0x60, 5)]),
            ("duplicate MSI-X", vec![(0x50, 0x11)]),
            ("all-ones ID", vec![(0x60, 0xff)]),
            ("reserved ID", vec![(0x60, 0)]),
            (
                "PM body beyond standard config",
                vec![(0x34, 0xfc), (0xfc, 1)],
            ),
            (
                "PMCSR overlaps MSI header",
                vec![(0x34, 0x40), (0x40, 1), (0x41, 0x44), (0x44, 5)],
            ),
            (
                "duplicate PM",
                vec![(0x34, 0x40), (0x40, 1), (0x41, 0x48), (0x48, 1)],
            ),
            (
                "MSI-X body beyond standard config",
                vec![(0x34, 0xfc), (0xfc, 0x11)],
            ),
            (
                "MSI body beyond standard config",
                vec![(0x34, 0xf8), (0xf8, 5)],
            ),
            (
                "capability overlaps MSI control",
                vec![(0x51, 0x54), (0x54, 1)],
            ),
            (
                "PCIe v1 body hides PM",
                vec![
                    (0x34, 0x40),
                    (0x40, 0x10),
                    (0x41, 0x44),
                    (0x42, 1),
                    (0x44, 1),
                    (0x48, 1), // real PCIe Device Control, not a PMCSR
                ],
            ),
            (
                "PCIe v1 body hides MSI",
                vec![(0x34, 0x40), (0x40, 0x10), (0x41, 0x50), (0x42, 1)],
            ),
            (
                "PCIe v2 tail hides PM",
                vec![
                    (0x34, 0x40),
                    (0x40, 0x10),
                    (0x41, 0x70),
                    (0x42, 2),
                    (0x70, 1),
                ],
            ),
            (
                "PCIe v2 tail hides MSI",
                vec![
                    (0x34, 0x40),
                    (0x40, 0x10),
                    (0x41, 0x70),
                    (0x42, 2),
                    (0x70, 5),
                ],
            ),
            (
                "VPD body hides PM",
                vec![(0x34, 0x40), (0x40, 3), (0x41, 0x44), (0x44, 1)],
            ),
            (
                "VPD body hides MSI",
                vec![(0x34, 0x40), (0x40, 3), (0x41, 0x44), (0x44, 5)],
            ),
            (
                "vendor body hides PM",
                vec![(0x34, 0x40), (0x40, 9), (0x41, 0x44), (0x42, 16), (0x44, 1)],
            ),
            (
                "vendor body hides MSI",
                vec![(0x34, 0x40), (0x40, 9), (0x41, 0x44), (0x42, 16), (0x44, 5)],
            ),
            (
                "subsystem body hides MSI",
                vec![(0x34, 0x40), (0x40, 0x0d), (0x41, 0x44), (0x44, 5)],
            ),
            (
                "PCIe unknown version",
                vec![(0x34, 0x40), (0x40, 0x10), (0x41, 0), (0x42, 3)],
            ),
            (
                "PCIe unqualified port type",
                vec![(0x34, 0x40), (0x40, 0x10), (0x41, 0), (0x42, 0x42)],
            ),
            (
                "PCIe endpoint with slot",
                vec![(0x34, 0x40), (0x40, 0x10), (0x41, 0), (0x42, 2), (0x43, 1)],
            ),
            (
                "PCIe truncated v2 body",
                vec![(0x34, 0xe0), (0xe0, 0x10), (0xe2, 2)],
            ),
            ("vendor missing length", vec![(0x34, 0x40), (0x40, 9)]),
            (
                "vendor short header",
                vec![(0x34, 0x40), (0x40, 9), (0x42, 2)],
            ),
            ("vendor overflow", vec![(0x34, 0xfc), (0xfc, 9), (0xfe, 5)]),
            ("unknown extent", vec![(0x34, 0x40), (0x40, 0x7f)]),
            ("unsupported known extent", vec![(0x34, 0x40), (0x40, 7)]),
            (
                "duplicate PCIe",
                vec![
                    (0x34, 0x40),
                    (0x40, 0x10),
                    (0x41, 0x80),
                    (0x42, 1),
                    (0x80, 0x10),
                    (0x82, 1),
                ],
            ),
            (
                "duplicate VPD",
                vec![(0x34, 0x40), (0x40, 3), (0x41, 0x48), (0x48, 3)],
            ),
            (
                "duplicate subsystem capability",
                vec![(0x34, 0x40), (0x40, 0x0d), (0x41, 0x48), (0x48, 0x0d)],
            ),
            ("non-endpoint header", vec![(0x0e, 1)]),
        ] {
            let mut corrupt = valid.clone();
            for (at, value) in changes {
                corrupt[at] = value;
            }
            let writes = Rc::new(RefCell::new(Vec::new()));
            let mut function = Function::new(
                function.address,
                Config {
                    bytes: Rc::new(RefCell::new(corrupt)),
                    writes: writes.clone(),
                },
            )
            .unwrap();
            assert!(quiesce_pio(&mut function).is_err(), "{name}");
            assert!(
                writes.borrow().is_empty(),
                "{name}: refused before hardware attachment"
            );
        }
        // A valid PM capability before MSI is admitted without treating PMCSR as
        // another header; the later power-up sees a real, disjoint PMCSR in D0.
        let mut with_pm = valid.clone();
        with_pm[0x34] = 0x40;
        with_pm[0x40] = 1;
        with_pm[0x41] = 0x50;
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut function = Function::new(
            function.address,
            Config {
                bytes: Rc::new(RefCell::new(with_pm)),
                writes: writes.clone(),
            },
        )
        .unwrap();
        quiesce_pio(&mut function).unwrap();
        function
            .power_up(&Clock {
                ticks_per_microsecond: 1000,
            })
            .unwrap();
        assert_eq!(
            &*writes.borrow(),
            &[(4, 2, 0x401), (0x52, 2, 0x80), (0x62, 2, 1)]
        );
        // Exact source endpoint lengths differ by version and link presence.
        // All headers following these real bodies remain separate from PMCSR
        // and interrupt controls, even when body bytes resemble header IDs.
        for flags in [0x01u16, 0x02, 0x11, 0x12, 0x91, 0x92] {
            let mut mixed = valid.clone();
            mixed[0x34] = 0x40;
            mixed[0x40] = 0x10;
            mixed[0x41] = 0x80;
            mixed[0x42..0x44].copy_from_slice(&flags.to_le_bytes());
            mixed[0x80] = 1;
            mixed[0x81] = 0x90;
            mixed[0x82] = 3;
            mixed[0x90] = 5;
            mixed[0x91] = 0xa0;
            mixed[0x92..0x94].copy_from_slice(&1u16.to_le_bytes());
            mixed[0xa0] = 0x11;
            mixed[0xa1] = 0xb0;
            mixed[0xa2..0xa4].copy_from_slice(&0x8001u16.to_le_bytes());
            mixed[0xb0] = 3;
            mixed[0xb1] = 0xb8;
            mixed[0xb8] = 9;
            mixed[0xb9] = 0xc0;
            mixed[0xba] = 8;
            mixed[0xc0] = 0x0d;
            let writes = Rc::new(RefCell::new(Vec::new()));
            let mut function = Function::new(
                function.address,
                Config {
                    bytes: Rc::new(RefCell::new(mixed)),
                    writes: writes.clone(),
                },
            )
            .unwrap();
            quiesce_pio(&mut function).unwrap();
            function
                .power_up(&Clock {
                    ticks_per_microsecond: 1000,
                })
                .unwrap();
            assert_eq!(
                &*writes.borrow(),
                &[(4, 2, 0x401), (0x92, 2, 0), (0xa2, 2, 1)],
                "flags={flags:x}"
            );
        }
        // Exact endpoint bodies and vendor lengths may end at byte255. These
        // are genuine boundary profiles, not headers admitted by truncation.
        for (start, id, extra) in [
            (0xec, 0x10, 0x01u8),
            (0xcc, 0x10, 0x02),
            (0xf4, 0x10, 0x91),
            (0xd4, 0x10, 0x92),
            (0xfc, 9, 3),
            (0x40, 9, 0xc0),
        ] {
            let mut boundary = valid.clone();
            boundary[0x34] = start as u8;
            boundary[start] = id;
            boundary[start + 1] = 0;
            boundary[start + 2] = extra;
            if id == 0x10 {
                boundary[start + 3] = 0;
            }
            let writes = Rc::new(RefCell::new(Vec::new()));
            let mut function = Function::new(
                function.address,
                Config {
                    bytes: Rc::new(RefCell::new(boundary)),
                    writes: writes.clone(),
                },
            )
            .unwrap();
            quiesce_pio(&mut function).unwrap();
            assert_eq!(
                &*writes.borrow(),
                &[(4, 2, 0x401)],
                "start={start:x}, extra={extra:x}"
            );
        }
        // A complete maximum-length list of four-byte vendor capabilities
        // terminates normally without a forgiving iteration cutoff.
        let mut complete = valid;
        complete[0x34] = 0x40;
        for at in (0x40..=0xfc).step_by(4) {
            complete[at] = 9;
            complete[at + 2] = 4; // native vendor-capability byte length
            complete[at + 1] = if at == 0xfc { 0 } else { (at + 4) as u8 };
        }
        let writes = Rc::new(RefCell::new(Vec::new()));
        let mut function = Function::new(
            function.address,
            Config {
                bytes: Rc::new(RefCell::new(complete)),
                writes: writes.clone(),
            },
        )
        .unwrap();
        quiesce_pio(&mut function).unwrap();
        assert_eq!(&*writes.borrow(), &[(4, 2, 0x401)]);
    }
}
