// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict native PCI admission shared by polled storage controllers.
use crate::{
    block::BlockError,
    bus::pci::{ConfigSpace, Function},
};

const PCI_COMMAND: u16 = 0x04;
const PCI_MEMORY: u16 = 1 << 1;
const PCI_BUS_MASTER: u16 = 1 << 2;
const PCI_INTX_DISABLE: u16 = 1 << 10;
const PCI_CAP_CONTROL: u16 = 2;
const PCI_STATUS: u16 = 0x06;
const PCI_CAP_PRESENT: u16 = 1 << 4;
const PCI_CAP_POINTER: u16 = 0x34;
const PCI_HEADER_TYPE: u16 = 0x0e;
const PCI_PM: u8 = 0x01;
const PCI_PM_BYTES: usize = 8;
const PCI_MSI: u8 = 0x05;
const PCI_MSIX: u8 = 0x11;
const PCI_MSI_ENABLE: u16 = 1;
const PCI_MSIX_ENABLE: u16 = 1 << 15;

pub(super) fn quiesce_pio<C: ConfigSpace>(function: &mut Function<C>) -> Result<(), BlockError> {
    let identity = u32::from(function.vendor) | u32::from(function.device) << 16;
    if function.config().read32(0) != identity {
        return Err(BlockError::Unsupported(
            "storage PCI identity changed before PIO ownership",
        ));
    }
    let ([msi, msix], _) = checked_capabilities(function.config(), None)?;
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
/// Validate a source-used capability's full register body before reading it.
pub(super) fn capability<C: ConfigSpace>(
    config: &C,
    id: u8,
    bytes: usize,
) -> Result<Option<u16>, BlockError> {
    Ok(checked_capabilities(config, Some((id, bytes)))?.1)
}

fn checked_capabilities<C: ConfigSpace>(
    config: &C,
    required: Option<(u8, usize)>,
) -> Result<([Option<u16>; 2], Option<u16>), BlockError> {
    let malformed = BlockError::Unsupported("storage malformed PCI capability chain");
    if config.read8(PCI_HEADER_TYPE) & 0x7f != 0 {
        return Err(malformed);
    }
    let mut controls = [None; 2];
    let mut found = None;
    let mut power_management = false;
    if config.read16(PCI_STATUS) & PCI_CAP_PRESENT == 0 {
        return Ok((controls, found));
    }
    let mut at = u16::from(config.read8(PCI_CAP_POINTER));
    let mut occupied = [false; 256];
    while at != 0 {
        if !(0x40..=0xfc).contains(&at) || at & 3 != 0 || occupied[usize::from(at)] {
            return Err(malformed);
        }
        let header = config.read16(at);
        let id = header as u8;
        if id == 0 || id == 0xff {
            return Err(malformed);
        }
        let requested = if let Some((target, bytes)) = required {
            if id == target {
                if found.is_some() {
                    return Err(malformed);
                }
                found = Some(at);
                bytes
            } else {
                2
            }
        } else {
            2
        };
        let bytes = if id == PCI_PM {
            // prepare_slots subsequently calls power_up, including PMCSR+4.
            if power_management {
                return Err(malformed);
            }
            power_management = true;
            PCI_PM_BYTES
        } else if id == PCI_MSI || id == PCI_MSIX {
            let index = usize::from(id == PCI_MSIX);
            if controls[index].is_some() {
                return Err(malformed);
            }
            controls[index] = Some(at + PCI_CAP_CONTROL);
            let control = config.read16(at + PCI_CAP_CONTROL);
            if id == PCI_MSIX {
                12
            } else {
                // MSI: header/control, address, optional upper address, data,
                // and optional per-vector mask/pending dwords (with padding).
                let wide = control & (1 << 7) != 0;
                let masking = control & (1 << 8) != 0;
                if masking {
                    if wide { 24 } else { 20 }
                } else if wide {
                    14
                } else {
                    10
                }
            }
        } else {
            2
        };
        let end = usize::from(at) + bytes.max(requested);
        if end > occupied.len() || occupied[usize::from(at)..end].iter().any(|used| *used) {
            return Err(malformed);
        }
        occupied[usize::from(at)..end].fill(true);
        at = header >> 8;
    }
    Ok((controls, found))
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
                assert!(matches!(at, 0x04 | 0x52 | 0x62));
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
