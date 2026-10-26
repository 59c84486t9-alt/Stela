// SPDX-License-Identifier: GPL-2.0-only
// Native adaptation of sdhci-pci-core.c, Copyright 2005-2008 Pierre Ossman.
//! Exact PCI identities select source-required host operating sequences.
use super::{BlockError, Box, Rc, RefCell, registers::Registers};
use crate::bus::pci::{ConfigSpace, Function};
mod o2micro;
pub(super) use o2micro::stabilize as o2_stabilize;

const ENE: u16 = 0x1524;
const CB712_SD: u16 = 0x0550;
const CB712_SD_2: u16 = 0x0551;
const CB714_SD: u16 = 0x0750;
const CB714_SD_2: u16 = 0x0751;
const INTEL: u16 = 0x8086;
const O2: u16 = 0x1217;
const O2_8220: u16 = 0x8220;
const O2_8221: u16 = 0x8221;
const O2_8320: u16 = 0x8320;
const O2_8321: u16 = 0x8321;
const QRK_SD: u16 = 0x08a7;
const MRST_SD0: u16 = 0x0807;
const MRST_SD1: u16 = 0x0808;
const MRST_SD2: u16 = 0x084f;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Profile {
    Standard,
    Ene712,
    Ene714,
    IntelQuark,
    IntelMrst0,
    IntelMrstOther,
    O2Legacy,
    Gli9750,
    Gli9755,
    Gli9767,
    Gli9763e,
}
impl Profile {
    pub fn select(vendor: u16, device: u16) -> Self {
        match (vendor, device) {
            (ENE, CB712_SD | CB712_SD_2) => Self::Ene712,
            (ENE, CB714_SD | CB714_SD_2) => Self::Ene714,
            (INTEL, QRK_SD) => Self::IntelQuark,
            (INTEL, MRST_SD0) => Self::IntelMrst0,
            (INTEL, MRST_SD1 | MRST_SD2) => Self::IntelMrstOther,
            (O2, O2_8220 | O2_8221 | O2_8320 | O2_8321) => Self::O2Legacy,
            (0x17a0, 0x9750) => Self::Gli9750,
            (0x17a0, 0x9755) => Self::Gli9755,
            (0x17a0, 0x9767) => Self::Gli9767,
            (0x17a0, 0xe763) => Self::Gli9763e,
            _ => Self::Standard,
        }
    }
    pub fn single_power_write(self) -> bool {
        matches!(self, Self::Ene712 | Self::Ene714)
    }
    pub fn disable_adma(self) -> bool {
        matches!(
            self,
            Self::Ene712 | Self::Ene714 | Self::IntelMrst0 | Self::IntelMrstOther | Self::O2Legacy
        )
    }
    pub fn reset_after_ios(self) -> bool {
        self == Self::Ene714
    }
    pub fn no_high_speed_bit(self) -> bool {
        matches!(
            self,
            Self::IntelQuark | Self::IntelMrst0 | Self::IntelMrstOther
        )
    }
    pub fn slots(self, reported: u8) -> u8 {
        // MRST HC1/2 expose unused, broken SDIO3/5 slot entries.
        if self == Self::IntelMrstOther {
            1
        } else {
            reported
        }
    }
    pub fn mmc_width(self) -> u8 {
        // mrst_hc_probe_slot declares this platform's eight physical pins.
        // Controller CAP_8BIT alone is never wiring authority.
        if matches!(self, Self::IntelMrst0 | Self::Gli9763e) {
            8
        } else {
            4
        }
    }
    pub fn retained_config(self) -> bool {
        self == Self::O2Legacy
    }
    pub fn gli(self) -> bool {
        matches!(
            self,
            Self::Gli9750 | Self::Gli9755 | Self::Gli9767 | Self::Gli9763e
        )
    }
    pub fn nonremovable(self) -> bool {
        self == Self::Gli9763e
    }
    pub fn register_bytes(self) -> u64 {
        if self == Self::Gli9750 {
            0x900
        } else if matches!(self, Self::Gli9767 | Self::Gli9763e) {
            0x600
        } else if self.retained_config() {
            0x200
        } else {
            0x100
        }
    }
}

/// The actual enumerated function remains owned here for every later clock and
/// power operation. Slots share this authority; no second ECAM view is created.
pub(super) type Control = Rc<RefCell<Controller>>;
pub(super) struct Controller {
    registers: Box<dyn Registers>,
    identity: u32,
    fault: Option<BlockError>,
}
impl Controller {
    pub fn new(function: Function) -> Control {
        let identity = u32::from(function.vendor) | u32::from(function.device) << 16;
        Rc::new(RefCell::new(Self {
            registers: Box::new(OwnedFunction(function)),
            identity,
            fault: None,
        }))
    }
    #[cfg(test)]
    pub fn model(registers: Box<dyn Registers>, identity: u32) -> Control {
        Rc::new(RefCell::new(Self {
            registers,
            identity,
            fault: None,
        }))
    }
    pub fn healthy(&self) -> Result<(), BlockError> {
        self.fault.clone().map_or(Ok(()), Err)
    }
    pub fn fail(&mut self, error: BlockError) {
        self.fault = Some(error);
    }
    fn operation(
        &mut self,
        operation: impl FnOnce(&mut dyn Registers) -> Result<(), BlockError>,
    ) -> Result<(), BlockError> {
        self.healthy()?;
        let result = (|| {
            if self.registers.read32(0) != self.identity {
                return Err(BlockError::Unsupported(
                    "SDHCI owned PCI function identity changed",
                ));
            }
            operation(self.registers.as_mut())?;
            if self.registers.read32(0) != self.identity {
                return Err(BlockError::Unsupported(
                    "SDHCI owned PCI function identity changed",
                ));
            }
            Ok(())
        })();
        if let Err(error) = &result {
            self.fail(error.clone());
        }
        result
    }
    pub fn prepare(&mut self) -> Result<(), BlockError> {
        self.operation(o2micro::prepare)
    }
    pub fn before_clock(&mut self) -> Result<(), BlockError> {
        self.operation(o2micro::before_clock)
    }
    pub fn power_off(&mut self) -> Result<(), BlockError> {
        self.operation(o2micro::power_off)
    }
}
struct OwnedFunction(Function);
impl Registers for OwnedFunction {
    fn read8(&mut self, at: usize) -> u8 {
        self.0.config().read8(at as u16)
    }
    fn read16(&mut self, at: usize) -> u16 {
        self.0.config().read16(at as u16)
    }
    fn read32(&mut self, at: usize) -> u32 {
        self.0.config().read32(at as u16)
    }
    fn write8(&mut self, at: usize, value: u8) {
        self.0.config().write8(at as u16, value);
    }
    fn write16(&mut self, at: usize, value: u16) {
        self.0.config().write16(at as u16, value);
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.0.config().write32(at as u16, value);
    }
}
