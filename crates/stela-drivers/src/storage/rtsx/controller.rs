// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of rtsx_pcr.c and rts5227.c, Copyright 2009-2013 Realtek.
//! Owned PCI profile, actual HAIMR/PHY access, standard clocks and socket power.
use super::*;

const PCI_EXP: u8 = 0x10;
const EXP_LINK_CONTROL: u16 = 0x10;
const EXP_DEVICE_CONTROL2: u16 = 0x28;
const EXP_LTR_ENABLE: u16 = 1 << 10;
const L1SS: u16 = 0x1e;
const VENDOR_SETTING1: u16 = 0x724;
const VENDOR_SETTING2: u16 = 0x814;
const CLOCK_REQUEST_CONFIG: u16 = 0x70f;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Admission { pcie: u16, version: u8, l1ss: Option<u16> }

pub(super) fn admission<C: ConfigSpace>(function: &mut Function<C>) -> Result<Admission, BlockError> {
    let config = function.config();
    let pcie = super::super::pci::capability(config, PCI_EXP, 0x14)?
        .ok_or(BlockError::Unsupported("RTSX requires an actual PCIe endpoint capability"))?;
    let flags = config.read16(pcie + 2);
    let version = (flags & 15) as u8;
    if !matches!(version, 1 | 2) || flags & 0xf0 != 0 {
        return Err(BlockError::Unsupported("RTSX unqualified PCIe capability version/type"));
    }
    if version == 2 {
        // Include the complete endpoint v2 body through Link Status2, so a
        // capability header cannot hide inside source-used controls.
        super::super::pci::capability(config, PCI_EXP, 0x34)?;
    }
    let mut used = [false; 1024];
    let mut at = 0x100u16;
    let mut l1ss = None;
    loop {
        if !(0x100..=0xffc).contains(&at) || at & 3 != 0 || used[usize::from(at / 4)] {
            return Err(BlockError::Unsupported("RTSX malformed extended PCIe capability chain"));
        }
        let header = config.read32(at);
        if header == 0 { break; }
        let id = header as u16;
        if id == 0 || id == u16::MAX {
            return Err(BlockError::Unsupported("RTSX invalid extended PCIe capability header"));
        }
        let words = if id == L1SS {
            if l1ss.is_some() || at > 0xff4 {
                return Err(BlockError::Unsupported("RTSX ambiguous/truncated L1 substates"));
            }
            l1ss = Some(at);
            3
        } else { 1 };
        let first = usize::from(at / 4);
        if used[first..first + words].iter().any(|used| *used) {
            return Err(BlockError::Unsupported("RTSX overlapping extended PCIe capability"));
        }
        used[first..first + words].fill(true);
        let next = (header >> 20) as u16;
        if next == 0 { break; }
        at = next;
    }
    Ok(Admission { pcie, version, l1ss })
}

pub(super) struct Configuration {
    pcie: u16,
    ltr: bool,
    ltr_active: bool,
    force_clock_request: bool,
    card_drive: u8,
    drive: usize,
    reverse_socket: bool,
    reverse_cd: bool,
    reverse_wp: bool,
    pub no_mmc: bool,
    pub vendor_valid: bool,
}
impl Configuration {
    pub fn capture<C: ConfigSpace>(function: &mut Function<C>, expected: Admission) -> Result<Self, BlockError> {
        let actual = admission(function)?;
        if actual != expected {
            return Err(BlockError::Unsupported("RTSX PCIe capabilities changed across D0 activation"));
        }
        let pci = function.config();
        let ltr = actual.version == 2 && pci.read16(actual.pcie + EXP_DEVICE_CONTROL2) & EXP_LTR_ENABLE != 0;
        let force_clock_request = actual.l1ss.is_none_or(|at| pci.read32(at + 8) & 15 == 0);
        let setting1 = pci.read32(VENDOR_SETTING1);
        let mut config = Self { pcie: actual.pcie, ltr, ltr_active: ltr && actual.l1ss.is_some(),
            force_clock_request, card_drive: 0x41, drive: 3, reverse_socket: false,
            reverse_cd: false, reverse_wp: false, no_mmc: false,
            vendor_valid: setting1 & 0x0100_0000 == 0 };
        if config.vendor_valid {
            let setting2 = pci.read32(VENDOR_SETTING2);
            config.card_drive = (config.card_drive & 0x3f) | (((setting1 >> 25) as u8 & 1) << 6);
            config.drive = ((setting2 >> 5) & 3) as usize;
            config.reverse_socket = setting2 & 0x4000 != 0;
            config.reverse_cd = setting2 & 0x0080_0000 != 0;
            config.reverse_wp = setting2 & 0x0040_0000 != 0;
            config.no_mmc = setting2 & 0x10 != 0;
        }
        Ok(config)
    }
}

impl Engine {
    pub(super) fn new(pci: Box<dyn Pci>, registers: Box<dyn Registers>, config: Configuration,
        clock: Clock, location: String) -> Result<Self, BlockError> {
        let mut engine = Self { pci, registers, config, clock, location, rca: 0,
            scratch: [0; 512], medium: None, fault: None };
        engine.healthy()?;
        engine.registers.write32(BIER, 0);
        if engine.registers.read32(BIER) != 0 {
            return engine.failed(BlockError::Unsupported("RTSX interrupt mask did not acknowledge"));
        }
        engine.registers.write32(HCBCTLR, STOP_CMD);
        engine.registers.write32(HDBCTLR, STOP_DMA);
        let deadline = clock.deadline(100_000);
        while engine.registers.read32(HCBCTLR) & HAIMR_TRANS_START != 0
            || engine.registers.read32(HDBCTLR) & HAIMR_TRANS_START != 0 {
            if deadline.passed() { return engine.failed(BlockError::Timeout); }
        }
        engine.write_reg(DMACTL, 0x80, 0x80)?;
        engine.write_reg(RBCTL, 0x80, 0x80)?;
        engine.initialize()?;
        engine.power_off()?;
        Ok(engine)
    }
    pub(super) fn failed<T>(&mut self, error: BlockError) -> Result<T, BlockError> {
        self.medium = None;
        self.fault = Some(error.clone());
        Err(error)
    }
    pub(super) fn read_reg(&mut self, at: u16) -> Result<u8, BlockError> {
        if let Some(error) = &self.fault { return Err(error.clone()); }
        self.registers.write32(HAIMR, HAIMR_READ_START | u32::from(at & 0x3fff) << 16);
        for _ in 0..1024 {
            let result = self.registers.read32(HAIMR);
            if result & HAIMR_TRANS_START == 0 { return Ok(result as u8); }
        }
        self.failed(BlockError::Timeout)
    }
    pub(super) fn write_reg(&mut self, at: u16, mask: u8, value: u8) -> Result<(), BlockError> {
        if let Some(error) = &self.fault { return Err(error.clone()); }
        self.registers.write32(HAIMR, HAIMR_WRITE_START | u32::from(at & 0x3fff) << 16
            | u32::from(mask) << 8 | u32::from(value));
        for _ in 0..1024 {
            let result = self.registers.read32(HAIMR);
            if result & HAIMR_TRANS_START == 0 {
                if result as u8 != value {
                    return self.failed(BlockError::Unsupported("RTSX register write did not acknowledge"));
                }
                return Ok(());
            }
        }
        self.failed(BlockError::Timeout)
    }
    fn phy(&mut self, address: u8, value: u16) -> Result<(), BlockError> {
        self.write_reg(PHYDATA0, 0xff, value as u8)?;
        self.write_reg(PHYDATA1, 0xff, (value >> 8) as u8)?;
        self.write_reg(PHYADDR, 0xff, address)?;
        self.write_reg(PHYRWCTL, 0xff, 0x81)?;
        for _ in 0..100_000 {
            if self.read_reg(PHYRWCTL)? & 0x80 == 0 { return Ok(()); }
        }
        self.failed(BlockError::Timeout)
    }
    fn initialize(&mut self) -> Result<(), BlockError> {
        self.write_reg(FPDCTL, SSC_POWER_DOWN, 0)?;
        self.clock.delay(200);
        let link_at = self.config.pcie + EXP_LINK_CONTROL;
        let old = self.pci.read16(link_at);
        self.pci.write16(link_at, old & !3);
        if self.pci.read16(link_at) & 3 != 0 {
            return self.failed(BlockError::Unsupported("RTSX ASPM disable did not acknowledge"));
        }
        if old & 2 != 0 { self.clock.delay(10_000); }
        self.write_reg(PM_CTRL3, D3_DELINK_MODE_EN, 0)?;
        self.phy(0, 0xba42)?;
        for (at, mask, value) in [
            (CLK_DIV, 7, 7), (HOST_SLEEP_STATE, 3, 0), (CARD_CLK_EN, 0x1e, 0),
            (CHANGE_LINK_STATE, 0x0a, 0), (CARD_DRIVE_SEL, 0xff, self.config.card_drive),
            (SSC_CTL1, 0xff, SSC_8X_EN | SSC_SEL_4M), (SSC_CTL2, 0xff, 0x12),
            (CHANGE_LINK_STATE, 0x16, 0x10), (IRQSTAT0, LINK_RDY_INT, LINK_RDY_INT),
            (PERST_GLITCH_WIDTH, 0xff, 0x80), (RCCTL, 1, 0), (NFTS_TX_CTRL, 2, 0),
        ] { self.write_reg(at, mask, value)?; }
        let link = self.pci.read16(link_at) | (1 << 8);
        self.pci.write16(link_at, link);
        if self.pci.read16(link_at) != link {
            return self.failed(BlockError::Unsupported("RTSX clock-request PCI control did not acknowledge"));
        }
        self.pci.write8(CLOCK_REQUEST_CONFIG, 0x5b);
        if self.pci.read8(CLOCK_REQUEST_CONFIG) != 0x5b {
            return self.failed(BlockError::Unsupported("RTSX clock-request setup did not acknowledge"));
        }
        for (at, mask, value) in [
            (GPIO_CTL, 2, 2), (ASPM_FORCE_CTL, 0x3f, 0), (LDO_PWR_SEL, 3, 0),
            (LDO_PWR_SEL, 3, 1), (OLT_LED_CTL, 0x0f, 2), (OBFF_CFG, 3, 3),
        ] { self.write_reg(at, mask, value)?; }
        if self.config.ltr { self.write_reg(LTR_CTL, 0xff, 0xa3)?; }
        self.driving()?;
        if self.config.reverse_socket { self.write_reg(PETXCFG, 0x30, 0x30)?; }
        else {
            self.write_reg(PETXCFG, 0x20, u8::from(self.config.reverse_cd) << 5)?;
            self.write_reg(PETXCFG, 0x10, u8::from(self.config.reverse_wp) << 4)?;
        }
        self.write_reg(PME_FORCE_CTL, 0xff, 0x30)?;
        self.write_reg(PM_CTRL3, 1, 0)?;
        let request = if self.config.force_clock_request { FORCE_CLKREQ_LOW } else { FORCE_CLKREQ_HIGH };
        self.write_reg(PETXCFG, FORCE_CLKREQ_DELINK_MASK, request)?;
        self.write_reg(PM_CTRL3, 0x10, 0)?;
        Ok(())
    }
    fn driving(&mut self) -> Result<(), BlockError> {
        let value = [0x13, 0x96, 0x7f, 0x96][self.config.drive];
        for at in [SD30_CLK_DRIVE_SEL, SD30_CMD_DRIVE_SEL, SD30_DAT_DRIVE_SEL] {
            self.write_reg(at, 0xff, value)?;
        }
        Ok(())
    }
    pub(super) fn power_off(&mut self) -> Result<(), BlockError> {
        self.medium = None;
        self.write_reg(CARD_CLK_EN, SD_CLK_EN, 0)?;
        self.write_reg(CARD_OE, SD_OUTPUT_EN | MS_OUTPUT_EN, 0)?;
        self.write_reg(CARD_PWR_CTL, SD_POWER_MASK | PMOS_STRG_MASK, SD_POWER_OFF | PMOS_STRG_400mA)?;
        self.write_reg(PWR_GATE_CTRL, LDO3318_PWR_MASK, 0)?;
        self.write_reg(CARD_PULL_CTL2, 0xff, 0x55)?;
        self.write_reg(CARD_PULL_CTL3, 0xff, 0xd5)?;
        Ok(())
    }
    pub(super) fn configure_card(&mut self) -> Result<(), BlockError> {
        self.power_off()?;
        self.clock.delay(100_000);
        self.phy(8, 0x4fe4)?;
        self.driving()?;
        self.write_reg(CARD_SELECT, 7, SD_MOD_SEL)?;
        self.write_reg(CARD_SHARE_MODE, CARD_SHARE_MASK, CARD_SHARE_48_SD)?;
        self.write_reg(CARD_CLK_EN, SD_CLK_EN, SD_CLK_EN)?;
        self.write_reg(CARD_PULL_CTL2, 0xff, 0xaa)?;
        self.write_reg(CARD_PULL_CTL3, 0xff, 0xe9)?;
        self.write_reg(CARD_PWR_CTL, SD_POWER_MASK, SD_PARTIAL_POWER_ON)?;
        self.write_reg(PWR_GATE_CTRL, LDO3318_PWR_MASK, 2)?;
        self.clock.delay(20_000);
        self.write_reg(CARD_PWR_CTL, SD_POWER_MASK, SD_POWER_ON)?;
        self.write_reg(PWR_GATE_CTRL, LDO3318_PWR_MASK, 6)?;
        self.write_reg(CARD_OE, SD_OUTPUT_EN | MS_OUTPUT_EN, SD_OUTPUT_EN | MS_OUTPUT_EN)?;
        self.clock.delay(1_000);
        self.write_reg(CARD_OE, SD_OUTPUT_EN, SD_OUTPUT_EN)?;
        self.timing(false)?;
        self.write_reg(SD_CFG1, 3, SD_BUS_WIDTH_1BIT)?;
        self.set_clock(400_000)?;
        self.write_reg(SD_BUS_STAT, SD_CLK_TOGGLE_EN | SD_CLK_FORCE_STOP, SD_CLK_TOGGLE_EN)?;
        self.clock.delay(1_000);
        self.write_reg(SD_BUS_STAT, SD_CLK_TOGGLE_EN, 0)?;
        self.rca = 0;
        Ok(())
    }
    pub(super) fn timing(&mut self, high_speed: bool) -> Result<(), BlockError> {
        self.write_reg(SD_CFG1, 0x0c, 0)?;
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, CLK_LOW_FREQ)?;
        self.write_reg(CARD_CLK_SOURCE, 0xff, 0x24)?;
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, 0)?;
        self.write_reg(SD_PUSH_POINT_CTL, if high_speed { SD20_TX_SEL_MASK } else { 0xff },
            if high_speed { SD20_TX_14_AHEAD } else { 0 })?;
        self.write_reg(SD_SAMPLE_POINT_CTL, SD20_RX_SEL_MASK,
            if high_speed { SD20_RX_14_DELAY } else { SD20_RX_POS_EDGE })
    }
    pub(super) fn set_clock(&mut self, requested: u32) -> Result<u32, BlockError> {
        let initial = requested <= 1_000_000;
        let internal = if initial { 30 } else { requested / 1_000_000 * 2 };
        if internal <= 2 || internal > 210 {
            return Err(BlockError::Unsupported("RTSX unsupported standard clock"));
        }
        let mut n = internal - 2;
        let mut div = 1u8;
        while n < 80 && div < 4 { n = (n + 2) * 2 - 2; div += 1; }
        if n > 208 { return Err(BlockError::Unsupported("RTSX SSC divider overflow")); }
        let count = (125 / internal + 3).min(15) as u8;
        // Source double-CLK compensation followed by revision for the selected divider.
        let depth = (SSC_DEPTH_500K - 1).checked_sub(div - 1).filter(|depth| *depth != 0)
            .unwrap_or(SSC_DEPTH_4M);
        self.write_reg(SD_CFG1, SD_CLK_DIVIDE_MASK, if initial { SD_CLK_DIVIDE_128 } else { SD_CLK_DIVIDE_0 })?;
        for (at, mask, value) in [
            (CLK_CTL, CLK_LOW_FREQ, CLK_LOW_FREQ), (CLK_DIV, 0xff, div << 4 | count),
            (SSC_CTL1, SSC_RSTB, 0), (SSC_CTL2, SSC_DEPTH_MASK, depth),
            (SSC_DIV_N_0, 0xff, n as u8), (SSC_CTL1, SSC_RSTB, SSC_RSTB),
        ] { self.write_reg(at, mask, value)?; }
        self.clock.delay(130);
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, 0)?;
        Ok(if initial { 30_000_000 / 128 } else { internal * 1_000_000 / 2 })
    }
}
