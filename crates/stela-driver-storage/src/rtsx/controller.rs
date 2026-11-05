// SPDX-License-Identifier: GPL-2.0-or-later
// Native adaptation of rtsx_pcr.c and rts5227.c, Copyright 2009-2013 Realtek.
//! Owned PCI profile, HAIMR/PHY access, standard clocks and socket power.
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
pub(super) struct Admission {
    pcie: u16,
    version: u8,
    l1ss: Option<u16>,
}

pub(super) fn admission<C: ConfigSpace>(
    function: &mut Function<C>,
) -> Result<Admission, BlockError> {
    let config = function.config();
    let pcie = super::super::pci::capability(config, PCI_EXP)?.ok_or(BlockError::Unsupported(
        "RTSX requires an actual PCIe endpoint capability",
    ))?;
    let flags = config.read16(pcie + 2)?;
    let version = (flags & 15) as u8;
    if !matches!(version, 1 | 2) || flags & 0xf0 != 0 {
        return Err(BlockError::Unsupported(
            "RTSX unqualified PCIe capability version/type",
        ));
    }
    let l1ss = extended_capabilities(config)?;
    Ok(Admission {
        pcie,
        version,
        l1ss,
    })
}

// A header inside an unknown/variable body's payload must never become L1SS
// permission. Unknown generations/layouts are refused before ownership effects.
fn extended_capabilities<C: ConfigSpace>(config: &C) -> Result<Option<u16>, BlockError> {
    super::super::pci::measured_extended(
        config,
        L1SS,
        BlockError::Unsupported("RTSX unqualified extended PCIe capability chain"),
    )
}

pub(super) struct Configuration {
    pub profile: ChipProfile,
    pcie: u16,
    l1ss_control: u8,
    rtd3: bool,
    ltr: bool,
    ltr_active: bool,
    force_clock_request: bool,
    card_drive: u8,
    drive: usize,
    drive_1v8: usize,
    reverse_socket: bool,
    reverse_cd: bool,
    reverse_wp: bool,
    pub no_mmc: bool,
    pub vendor_valid: bool,
    aspm: u8,
}
impl Configuration {
    pub(super) fn rts5229_drive(&self, voltage180: bool) -> u8 {
        [1, 2, 5, 3][if voltage180 {
            self.drive_1v8
        } else {
            self.drive
        }]
    }
    pub(super) fn drive_1v8(&self) -> u8 {
        [0x99, 0xaa, 0xfe, 0xb3][self.drive_1v8]
    }
    pub fn capture<C: ConfigSpace>(
        function: &mut Function<C>,
        expected: Admission,
    ) -> Result<Self, BlockError> {
        let profile = ChipProfile::select(function.device).ok_or(BlockError::Unsupported(
            "RTSX device has no native chip profile",
        ))?;
        let actual = admission(function)?;
        if actual != expected {
            return Err(BlockError::Unsupported(
                "RTSX PCIe capabilities changed across D0 activation",
            ));
        }
        let pci = function.config();
        let ltr = actual.version == 2
            && pci.read16(actual.pcie + EXP_DEVICE_CONTROL2)? & EXP_LTR_ENABLE != 0;
        let l1ss_control = match actual.l1ss {
            Some(at) => pci.read32(at + 8)? as u8 & 15,
            None => 0,
        };
        let force_clock_request = l1ss_control == 0;
        let setting1 = pci.read32(VENDOR_SETTING1)?;
        let mut config = Self {
            profile,
            l1ss_control,
            rtd3: false,
            pcie: actual.pcie,
            ltr,
            ltr_active: ltr && actual.l1ss.is_some(),
            force_clock_request,
            card_drive: 0x41,
            drive: if profile == ChipProfile::Rts5229 {
                0
            } else {
                3
            },
            drive_1v8: 3,
            reverse_socket: false,
            reverse_cd: false,
            reverse_wp: false,
            no_mmc: false,
            vendor_valid: setting1 & 0x0100_0000 == 0,
            aspm: 2,
        };
        if config.vendor_valid {
            let setting2 = pci.read32(VENDOR_SETTING2)?;
            config.card_drive = (config.card_drive & 0x3f) | (((setting1 >> 25) as u8 & 1) << 6);
            config.drive = ((setting2 >> 5) & 3) as usize;
            config.drive_1v8 = ((setting1 >> 26) & 3) as usize;
            config.aspm = ((setting1 >> 28) & 3) as u8;
            if profile != ChipProfile::Rts5229 {
                config.reverse_socket = setting2 & 0x4000 != 0;
                config.reverse_cd = setting2 & 0x0080_0000 != 0;
                config.reverse_wp = setting2 & 0x0040_0000 != 0;
                config.no_mmc = setting2 & 0x10 != 0;
                config.rtd3 = profile == ChipProfile::Rts522a && setting2 & 2 != 0;
            }
        }
        Ok(config)
    }
}

impl Host {
    #[expect(
        clippy::result_large_err,
        reason = "Return the same affine device, mapping and timer graph without a fallible failure-path allocation."
    )]
    pub(super) fn new(
        pci: Box<dyn Pci>,
        registers: Box<dyn Registers>,
        config: Configuration,
        clock: Clock,
        minimum: Rc<dyn crate::bus::pci::power::Timer>,
        location: String,
    ) -> Result<Self, HostFailure> {
        let inputs = crate::Retained::new(EnginePreparation {
            pci,
            registers,
            config,
            clock,
            minimum,
            location,
        });
        if let Err(error) = inputs
            .minimum
            .check()
            .map_err(BlockError::PciPower)
            .and_then(|()| validate_clock(inputs.clock))
        {
            return Err(HostFailure {
                error,
                owner: crate::Retained::new(FailedHost::Preparation(inputs.into_inner())),
            });
        }
        let EnginePreparation {
            pci,
            registers,
            config,
            clock,
            minimum,
            location,
        } = inputs.into_inner();
        let mut engine = core::mem::ManuallyDrop::new(Engine {
            pci,
            registers,
            config,
            clock,
            minimum,
            minimum_in_progress: false,
            operation_in_progress: false,
            location,
            rca: 0,
            scratch: [0; 512],
            medium: None,
            fault: None,
            last_failure: None,
            request_deadline: None,
            restoration_failure: None,
            failure_finalized: false,
            ocp_status: None,
            timing_mode: Timing::Legacy,
            signal_voltage: SignalVoltage::V3_3,
            tuning_rejection_observed: false,
            silicon_version: 0,
        });
        let result = (|| {
            engine.healthy()?;
            engine.registers.write32(BIER, 0);
            if engine.registers.read32(BIER) != 0 {
                return engine.failed(BlockError::Unsupported(
                    "RTSX interrupt mask did not acknowledge",
                ));
            }
            let budget = Budget::new(&engine, 100_000);
            budget.check()?;
            engine.registers.write32(HCBCTLR, STOP_CMD);
            budget.check()?;
            engine.registers.write32(HDBCTLR, STOP_DMA);
            budget.check()?;
            loop {
                budget.check()?;
                let command = engine.registers.read32(HCBCTLR);
                budget.check()?;
                let data = engine.registers.read32(HDBCTLR);
                budget.check()?;
                if command & HAIMR_TRANS_START == 0 && data & HAIMR_TRANS_START == 0 {
                    break;
                }
            }
            // Source init_params observes the revision before PHY/extra
            // initialization; a failed read grants no electrical profile effects.
            if engine.config.profile == ChipProfile::Rts5229 {
                engine.silicon_version = engine.read_reg(DUMMY_REG_RESET_0)? & 15;
            }
            engine.write_reg(DMACTL, 0x80, 0x80)?;
            engine.write_reg(RBCTL, 0x80, 0x80)?;
            engine.initialize()?;
            engine.power_off()
        })();
        let host = Host {
            inner: Rc::new(RefCell::new(engine)),
        };
        if let Err(error) = result {
            {
                let mut engine = host.inner.borrow_mut();
                engine.medium = None;
                engine.fault.get_or_insert_with(|| error.clone());
            }
            return Err(HostFailure {
                error,
                owner: crate::Retained::new(FailedHost::Host(host)),
            });
        }
        Ok(host)
    }
}
impl Engine {
    pub(super) fn quiet(&mut self, microseconds: u64) -> Result<(), BlockError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        self.minimum_in_progress = true;
        let result = self.minimum.wait_us(microseconds);
        self.minimum_in_progress = false;
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.failed(BlockError::PciPower(error)),
        }
    }
    pub(super) fn failed<T>(&mut self, error: BlockError) -> Result<T, BlockError> {
        self.medium = None;
        self.fault.get_or_insert_with(|| error.clone());
        Err(error)
    }
    pub(super) fn read_reg(&mut self, at: u16) -> Result<u8, BlockError> {
        self.read_reg_before(at, None)
    }
    pub(super) fn read_reg_before(
        &mut self,
        at: u16,
        budget: Option<Budget>,
    ) -> Result<u8, BlockError> {
        let (value, late) = self.observe_reg_before(at, budget)?;
        if late {
            Err(BlockError::Timeout)
        } else {
            Ok(value)
        }
    }
    // A terminal value remains available for error decoding even if the
    // same completed observation was late. It never authorizes late success.
    pub(super) fn observe_reg_before(
        &mut self,
        at: u16,
        budget: Option<Budget>,
    ) -> Result<(u8, bool), BlockError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        self.registers
            .write32(HAIMR, HAIMR_READ_START | u32::from(at & 0x3fff) << 16);
        for _ in 0..1024 {
            if budget.is_some_and(Budget::expired) {
                return self.failed(BlockError::Timeout);
            }
            let result = self.registers.read32(HAIMR);
            if result & HAIMR_TRANS_START == 0 {
                return Ok((result as u8, budget.is_some_and(Budget::expired)));
            }
            if budget.is_some_and(Budget::expired) {
                return self.failed(BlockError::Timeout);
            }
        }
        self.failed(BlockError::Timeout)
    }
    pub(super) fn write_reg(&mut self, at: u16, mask: u8, value: u8) -> Result<(), BlockError> {
        self.write_reg_before(at, mask, value, None)
    }
    pub(super) fn write_reg_before(
        &mut self,
        at: u16,
        mask: u8,
        value: u8,
        budget: Option<Budget>,
    ) -> Result<(), BlockError> {
        if let Some(error) = &self.fault {
            return Err(error.clone());
        }
        if let Some(budget) = budget {
            budget.check()?;
        }
        self.registers.write32(
            HAIMR,
            HAIMR_WRITE_START
                | u32::from(at & 0x3fff) << 16
                | u32::from(mask) << 8
                | u32::from(value),
        );
        for _ in 0..1024 {
            if budget.is_some_and(Budget::expired) {
                return self.failed(BlockError::Timeout);
            }
            let result = self.registers.read32(HAIMR);
            if result & HAIMR_TRANS_START == 0 {
                if result as u8 != value {
                    return self.failed(BlockError::Unsupported(
                        "RTSX register write did not acknowledge",
                    ));
                }
                if let Some(budget) = budget {
                    budget.check()?;
                }
                return Ok(());
            }
            if budget.is_some_and(Budget::expired) {
                return self.failed(BlockError::Timeout);
            }
        }
        self.failed(BlockError::Timeout)
    }
    pub(super) fn phy(&mut self, address: u8, value: u16) -> Result<(), BlockError> {
        self.write_reg(PHYDATA0, 0xff, value as u8)?;
        self.write_reg(PHYDATA1, 0xff, (value >> 8) as u8)?;
        self.write_reg(PHYADDR, 0xff, address)?;
        self.write_reg(PHYRWCTL, 0xff, 0x81)?;
        for _ in 0..100_000 {
            if self.read_reg(PHYRWCTL)? & 0x80 == 0 {
                return Ok(());
            }
        }
        self.failed(BlockError::Timeout)
    }
    fn initialize(&mut self) -> Result<(), BlockError> {
        self.write_reg(FPDCTL, SSC_POWER_DOWN, 0)?;
        self.quiet(200)?;
        let link_at = self.config.pcie + EXP_LINK_CONTROL;
        if self.config.profile == ChipProfile::Rts522a {
            self.rts522a_disable_aspm()?;
            self.rts522a_optimize_phy()?;
        } else {
            let old = self
                .pci
                .read16(link_at)
                .map_err(|error| self.configuration_failed(error))?;
            self.pci
                .write16(link_at, old & !3)
                .map_err(|error| self.configuration_failed(error))?;
            if self
                .pci
                .read16(link_at)
                .map_err(|error| self.configuration_failed(error))?
                & 3
                != 0
            {
                return self.failed(BlockError::Unsupported(
                    "RTSX ASPM disable did not acknowledge",
                ));
            }
            if old & 2 != 0
                || self.config.profile == ChipProfile::Rts5229 && self.config.aspm & 2 != 0
            {
                self.quiet(10_000)?;
            }
            if self.config.profile != ChipProfile::Rts5229 {
                self.write_reg(PM_CTRL3, D3_DELINK_MODE_EN, 0)?;
            }
            self.phy(0, 0xba42)?;
        }
        for (at, mask, value) in [
            (CLK_DIV, 7, 7),
            (HOST_SLEEP_STATE, 3, 0),
            (CARD_CLK_EN, 0x1e, 0),
            (CHANGE_LINK_STATE, 0x0a, 0),
            (CARD_DRIVE_SEL, 0xff, self.config.card_drive),
            (SSC_CTL1, 0xff, SSC_8X_EN | SSC_SEL_4M),
            (SSC_CTL2, 0xff, 0x12),
            (CHANGE_LINK_STATE, 0x16, 0x10),
            (IRQSTAT0, LINK_RDY_INT, LINK_RDY_INT),
            (PERST_GLITCH_WIDTH, 0xff, 0x80),
            (RCCTL, 1, 0),
            (NFTS_TX_CTRL, 2, 0),
        ] {
            self.write_reg(at, mask, value)?;
        }
        if self.config.profile == ChipProfile::Rts522a {
            self.rts522a_init_ocp()?;
            self.rts522a_oobs(self.config.l1ss_control != 0)?;
        }
        let link = self
            .pci
            .read16(link_at)
            .map_err(|error| self.configuration_failed(error))?
            | (1 << 8);
        self.pci
            .write16(link_at, link)
            .map_err(|error| self.configuration_failed(error))?;
        if self
            .pci
            .read16(link_at)
            .map_err(|error| self.configuration_failed(error))?
            != link
        {
            return self.failed(BlockError::Unsupported(
                "RTSX clock-request PCI control did not acknowledge",
            ));
        }
        self.pci
            .write8(CLOCK_REQUEST_CONFIG, 0x5b)
            .map_err(|error| self.configuration_failed(error))?;
        if self
            .pci
            .read8(CLOCK_REQUEST_CONFIG)
            .map_err(|error| self.configuration_failed(error))?
            != 0x5b
        {
            return self.failed(BlockError::Unsupported(
                "RTSX clock-request setup did not acknowledge",
            ));
        }
        if self.config.profile == ChipProfile::Rts5229 {
            self.rts5229_initialize()?;
            self.quiet(1_000)?;
            return self.active_ltr();
        }
        for (at, mask, value) in [
            (GPIO_CTL, 2, 2),
            (ASPM_FORCE_CTL, 0x3f, 0),
            (LDO_PWR_SEL, 3, 0),
            (LDO_PWR_SEL, 3, 1),
            (OLT_LED_CTL, 0x0f, 2),
        ] {
            self.write_reg(at, mask, value)?;
        }
        if self.config.ltr {
            self.write_reg(LTR_CTL, 0xff, 0xa3)?;
        }
        self.write_reg(OBFF_CFG, 3, 3)?;
        self.driving()?;
        if self.config.reverse_socket {
            self.write_reg(PETXCFG, 0x30, 0x30)?;
        } else {
            self.write_reg(PETXCFG, 0x20, u8::from(self.config.reverse_cd) << 5)?;
            self.write_reg(PETXCFG, 0x10, u8::from(self.config.reverse_wp) << 4)?;
        }
        let pm_ctrl3 = if self.config.profile == ChipProfile::Rts522a {
            self.rts522a_extra(self.config.rtd3)?;
            RTS522A_PM_CTRL3
        } else {
            self.write_reg(PME_FORCE_CTL, 0xff, 0x30)?;
            self.write_reg(PM_CTRL3, 1, 0)?;
            PM_CTRL3
        };
        let request = if self.config.force_clock_request {
            FORCE_CLKREQ_LOW
        } else {
            FORCE_CLKREQ_HIGH
        };
        self.write_reg(PETXCFG, FORCE_CLKREQ_DELINK_MASK, request)?;
        self.write_reg(pm_ctrl3, 0x10, 0)?;
        if self.config.profile == ChipProfile::Rts522a {
            self.rts522a_disable_aspm()?;
        }
        // Native full-on ordering: ASPM disabled before active LTR. RTS5227's
        // zero-initialized active latency is zero; later chips set other values.
        self.quiet(1_000)?;
        self.active_ltr()?;
        if self.config.profile == ChipProfile::Rts522a {
            self.write_reg(
                L1SUB_CONFIG3,
                0xff,
                if self.config.l1ss_control & 8 != 0 {
                    0x78
                } else {
                    0
                },
            )?;
        }
        Ok(())
    }
    fn active_ltr(&mut self) -> Result<(), BlockError> {
        if self.config.ltr_active {
            let latency = if self.config.profile == ChipProfile::Rts522a {
                0x883cu32
            } else {
                0
            };
            for (index, value) in latency.to_le_bytes().into_iter().enumerate() {
                self.write_reg(MSGTXDATA0 + index as u16, 0xff, value)?;
            }
            self.write_reg(
                LTR_CTL,
                LTR_TX_EN_MASK | LTR_LATENCY_MODE_MASK,
                LTR_TX_EN_1 | LTR_LATENCY_MODE_SW,
            )?;
        }
        Ok(())
    }
    pub(super) fn driving(&mut self) -> Result<(), BlockError> {
        if self.config.profile == ChipProfile::Rts5229 {
            return self.rts5229_drive(false);
        }
        let value = [0x13, 0x96, 0x7f, 0x96][self.config.drive];
        for at in [SD30_CLK_DRIVE_SEL, SD30_CMD_DRIVE_SEL, SD30_DAT_DRIVE_SEL] {
            self.write_reg(at, 0xff, value)?;
        }
        Ok(())
    }
    pub(super) fn power_off(&mut self) -> Result<(), BlockError> {
        self.medium = None;
        let budget = Budget::retirement(self);
        self.write_reg_before(CARD_CLK_EN, SD_CLK_EN, 0, Some(budget))?;
        self.write_reg_before(CARD_OE, SD_OUTPUT_EN | MS_OUTPUT_EN, 0, Some(budget))?;
        if self.config.profile == ChipProfile::Rts522a {
            self.rts522a_disable_ocp(budget)?;
        }
        self.write_reg_before(
            CARD_PWR_CTL,
            SD_POWER_MASK | PMOS_STRG_MASK,
            SD_POWER_OFF | PMOS_STRG_400MA,
            Some(budget),
        )?;
        self.write_reg_before(PWR_GATE_CTRL, LDO3318_PWR_MASK, 0, Some(budget))?;
        self.write_reg_before(CARD_PULL_CTL2, 0xff, 0x55, Some(budget))?;
        let pull = if self.config.profile == ChipProfile::Rts5229 && self.silicon_version == 2 {
            0xe5
        } else {
            0xd5
        };
        self.write_reg_before(CARD_PULL_CTL3, 0xff, pull, Some(budget))?;
        if self.config.profile == ChipProfile::Rts522a {
            self.rts522a_clear_ocp(budget)?;
        }
        Ok(())
    }
    pub(super) fn configure_card(&mut self) -> Result<(), BlockError> {
        self.power_off()?;
        self.quiet(100_000)?;
        if self.config.profile == ChipProfile::Rts5229 {
            self.rts5229_voltage(false)?;
        } else {
            self.phy(
                8,
                if self.config.profile == ChipProfile::Rts522a {
                    0x57e4
                } else {
                    0x4fe4
                },
            )?;
            self.driving()?;
        }
        self.signal_voltage = SignalVoltage::V3_3;
        self.write_reg(CARD_SELECT, 7, SD_MOD_SEL)?;
        self.write_reg(CARD_SHARE_MODE, CARD_SHARE_MASK, CARD_SHARE_48_SD)?;
        self.write_reg(CARD_CLK_EN, SD_CLK_EN, SD_CLK_EN)?;
        self.write_reg(CARD_PULL_CTL2, 0xff, 0xaa)?;
        let pull = if self.config.profile == ChipProfile::Rts5229 && self.silicon_version == 2 {
            0xd9
        } else {
            0xe9
        };
        self.write_reg(CARD_PULL_CTL3, 0xff, pull)?;
        if self.config.profile == ChipProfile::Rts522a {
            self.rts522a_enable_ocp()?;
        }
        self.write_reg(CARD_PWR_CTL, SD_POWER_MASK, SD_PARTIAL_POWER_ON)?;
        self.write_reg(PWR_GATE_CTRL, LDO3318_PWR_MASK, 2)?;
        self.quiet(if self.config.profile == ChipProfile::Rts5229 {
            150
        } else {
            20_000
        })?;
        self.write_reg(CARD_PWR_CTL, SD_POWER_MASK, SD_POWER_ON)?;
        self.write_reg(PWR_GATE_CTRL, LDO3318_PWR_MASK, 6)?;
        if self.config.profile != ChipProfile::Rts5229 {
            self.write_reg(CARD_OE, SD_OUTPUT_EN, SD_OUTPUT_EN)?;
            self.write_reg(CARD_OE, MS_OUTPUT_EN, MS_OUTPUT_EN)?;
        }
        self.quiet(1_000)?;
        self.write_reg(CARD_OE, SD_OUTPUT_EN, SD_OUTPUT_EN)?;
        self.timing(false)?;
        self.write_reg(SD_CFG1, 3, SD_BUS_WIDTH_1BIT)?;
        self.set_clock(400_000)?;
        self.write_reg(
            SD_BUS_STAT,
            SD_CLK_TOGGLE_EN | SD_CLK_FORCE_STOP,
            SD_CLK_TOGGLE_EN,
        )?;
        self.quiet(1_000)?;
        self.write_reg(SD_BUS_STAT, SD_CLK_TOGGLE_EN, 0)?;
        self.rca = 0;
        Ok(())
    }
    pub(super) fn timing(&mut self, high_speed: bool) -> Result<(), BlockError> {
        self.timing_mode = if high_speed {
            Timing::HighSpeed
        } else {
            Timing::Legacy
        };
        self.write_reg(SD_CFG1, 0x0c, 0)?;
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, CLK_LOW_FREQ)?;
        self.write_reg(CARD_CLK_SOURCE, 0xff, 0x24)?;
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, 0)?;
        self.write_reg(
            SD_PUSH_POINT_CTL,
            if high_speed { SD20_TX_SEL_MASK } else { 0xff },
            if high_speed { SD20_TX_14_AHEAD } else { 0 },
        )?;
        self.write_reg(
            SD_SAMPLE_POINT_CTL,
            SD20_RX_SEL_MASK,
            if high_speed {
                SD20_RX_14_DELAY
            } else {
                SD20_RX_POS_EDGE
            },
        )
    }
    pub(super) fn set_clock(&mut self, requested: u32) -> Result<u32, BlockError> {
        if requested < 30_000_000 / 128 {
            return Err(BlockError::Unsupported(
                "RTSX requested clock below qualified initial rate",
            ));
        }
        let initial = requested <= 1_000_000;
        let variable_phase = matches!(self.timing_mode, Timing::Sdr50 | Timing::Sdr104);
        let double_clock = !variable_phase;
        let internal = if initial {
            30
        } else {
            requested / 1_000_000 * if double_clock { 2 } else { 1 }
        };
        if internal <= 2 || internal > 210 {
            return Err(BlockError::Unsupported("RTSX unsupported standard clock"));
        }
        let mut n = internal - 2;
        let mut div = 1u8;
        while n < 80 && div < 4 {
            n = (n + 2) * 2 - 2;
            div += 1;
        }
        if n > 208 {
            return Err(BlockError::Unsupported("RTSX SSC divider overflow"));
        }
        let count = (125 / internal + 3).min(15) as u8;
        // Source double-CLK compensation followed by revision for the selected divider.
        let depth = match self.timing_mode {
            Timing::Sdr50 | Timing::Sdr104 => SSC_DEPTH_2M,
            Timing::Sdr25 => SSC_DEPTH_1M,
            _ => SSC_DEPTH_500K,
        };
        let depth = (depth - u8::from(double_clock))
            .checked_sub(div - 1)
            .filter(|depth| *depth != 0)
            .unwrap_or(SSC_DEPTH_4M);
        self.write_reg(
            SD_CFG1,
            SD_CLK_DIVIDE_MASK,
            if initial {
                SD_CLK_DIVIDE_128
            } else {
                SD_CLK_DIVIDE_0
            },
        )?;
        for (at, mask, value) in [
            (CLK_CTL, CLK_LOW_FREQ, CLK_LOW_FREQ),
            (CLK_DIV, 0xff, div << 4 | count),
            (SSC_CTL1, SSC_RSTB, 0),
            (SSC_CTL2, SSC_DEPTH_MASK, depth),
            (SSC_DIV_N_0, 0xff, n as u8),
            (SSC_CTL1, SSC_RSTB, SSC_RSTB),
        ] {
            self.write_reg(at, mask, value)?;
        }
        if variable_phase {
            self.write_reg(SD_VPTX_CTL, PHASE_NOT_RESET, 0)?;
            self.write_reg(SD_VPTX_CTL, PHASE_NOT_RESET, PHASE_NOT_RESET)?;
        }
        self.quiet(130)?;
        self.write_reg(CLK_CTL, CLK_LOW_FREQ, 0)?;
        Ok(if initial {
            30_000_000 / 128
        } else {
            internal * 1_000_000 / if double_clock { 2 } else { 1 }
        })
    }
}
