// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! rtl8152_apply_firmware and MAC/PHY block executors from pinned r8152.c.
//! Upload is preparation, never proof that the device PHY/MAC is initialized.
use super::super::firmware::{Bank, Block, Firmware, Fixup, Mac as MacPatch, PhyNc, PhyUnion};
use super::*;

impl<C: Control> Chip<C> {
    /// Execute a completely validated image against its exact observed chip.
    /// `power_cut` may be true only when the revision-specific caller observed
    /// PHY_STAT_PWRDN/EXT_INIT, matching the donor's no-wait patch handshake.
    /// A failed upload poisons this chip until whole-device reset/reattachment.
    /// No unfinished revision becomes carrier-ready through this method.
    pub fn upload_firmware(
        &mut self,
        image: &Firmware<'_>,
        power_cut: bool,
    ) -> Result<(), BlockError> {
        if image.revision() != self.revision || self.initialized || self.enabled || !self.accessible
        {
            return Err(BlockError::Unsupported(
                "RTL815x firmware upload requires exact unstarted chip",
            ));
        }
        if image
            .blocks()
            .iter()
            .any(|block| matches!(block, Block::Mac(patch) if patch.breakpoints().next().is_none()))
        {
            return Err(BlockError::Unsupported(
                "RTL815x firmware has no active MAC breakpoints",
            ));
        }
        if image.blocks().iter().any(|block| match block {
            Block::PhyNc(patch) => usize::from(patch.register()) + patch.payload().len() > 0x10000,
            Block::PhyUnion(patch) => {
                usize::from(patch.register()) + patch.payload().len() > 0x10000
            }
            _ => false,
        }) {
            return Err(BlockError::Unsupported(
                "RTL815x PHY firmware would wrap SRAM address space",
            ));
        }
        let result = self.upload(image, !power_cut);
        self.base = None;
        if result.is_err() {
            self.accessible = false;
        }
        result
    }

    fn write_block(&mut self, bank: u16, address: u32, data: &[u8]) -> Result<(), BlockError> {
        if data.is_empty()
            || !address.is_multiple_of(4)
            || !data.len().is_multiple_of(4)
            || address
                .checked_add(data.len() as u32)
                .is_none_or(|end| end > 0xffff)
        {
            return Err(BlockError::Unsupported(
                "RTL815x firmware OCP range/alignment",
            ));
        }
        for (index, chunk) in data.chunks(512).enumerate() {
            let at = address + index as u32 * 512;
            let request = super::super::super::xhci::setup(
                0x40,
                5,
                at as u16,
                bank | 0xff,
                chunk.len() as u16,
            );
            self.transaction(request, chunk)?;
        }
        Ok(())
    }

    pub(super) fn sram_write(&mut self, address: u16, value: u16) -> Result<(), BlockError> {
        self.phy_write(OCP_SRAM_ADDR, u32::from(address))?;
        self.phy_write(OCP_SRAM_DATA, u32::from(value))
    }

    pub(super) fn sram_read(&mut self, address: u16) -> Result<u16, BlockError> {
        self.phy_write(OCP_SRAM_ADDR, u32::from(address))?;
        let mapped = self.phy_address(OCP_SRAM_DATA)?;
        Ok(self.read(PLA, mapped, 2)? as u16)
    }

    fn phy_stream(&mut self, address: u16, data: &[u8]) -> Result<(), BlockError> {
        self.phy_write(OCP_SRAM_ADDR, u32::from(address))?;
        for word in data.as_chunks::<2>().0 {
            self.phy_write(OCP_SRAM_DATA, u32::from(u16::from_le_bytes(*word)))?;
        }
        Ok(())
    }

    pub(super) fn patch_request(&mut self, request: bool, wait: bool) -> Result<(), BlockError> {
        self.phy_modify(
            OCP_PHY_PATCH_CMD,
            PATCH_REQUEST,
            if request { PATCH_REQUEST } else { 0 },
        )?;
        if wait {
            self.io.delay_us(1000);
            let mapped = self.phy_address(OCP_PHY_PATCH_STAT)?;
            // The hardware changes PATCH_READY asynchronously. Even release
            // must acknowledge it clearing before normal PHY accesses resume.
            if let Err(error) = self.poll(
                PLA,
                mapped,
                2,
                PATCH_READY,
                if request { PATCH_READY } else { 0 },
                (5000, 1000),
            ) {
                if request && self.accessible {
                    // Bounded best-effort request withdrawal on a live bus.
                    self.phy_modify(OCP_PHY_PATCH_CMD, PATCH_REQUEST, 0)?;
                }
                return Err(error);
            }
        }
        Ok(())
    }

    fn patch_key(&mut self, register: u16, key: u16) -> Result<(), BlockError> {
        if register == 0 {
            return Err(BlockError::Unsupported(
                "RTL815x missing PHY patch key register",
            ));
        }
        if key != 0 {
            self.sram_write(register, key)?;
            self.sram_write(SRAM_PHY_LOCK as u16, PHY_PATCH_LOCK as u16)
        } else {
            self.sram_write(0, 0)?;
            self.phy_modify(OCP_PHY_LOCK, PATCH_LOCK, 0)?;
            self.sram_write(register, 0)
        }
    }

    fn clear_breakpoints(&mut self, bank: u16) -> Result<(), BlockError> {
        let extended = self.revision.0 == 0x6400
            || (bank == USB && matches!(self.revision.0, 0x6010 | 0x7030 | 0x7410 | 0x7420));
        if extended {
            self.write(bank, USB_BP2_EN, 2, 0)?;
        } else {
            self.write(bank, PLA_BP_EN, 1, 0)?;
        }
        self.write_block(bank, PLA_BP_0, if extended { &[0; 32] } else { &[0; 16] })?;
        self.io.delay_us(3000);
        self.write(bank, PLA_BP_BA, 2, 0)
    }

    fn upload_mac(&mut self, patch: &MacPatch<'_>) -> Result<(), BlockError> {
        let bank = match patch.bank() {
            Bank::Pla => PLA,
            Bank::Usb => USB,
        };
        let (version_reg, version) = patch.version_register();
        if version_reg != 0 && self.read(USB, u32::from(version_reg), 1)? >= u32::from(version) {
            return Ok(());
        }
        self.clear_breakpoints(bank)?;
        // RTL8153A revision 04 requires MACDBG backup/restore before PLA code.
        if self.revision.0 == 0x5c10
            && bank == PLA
            && self.read(PLA, PLA_MACDBG_POST, 2)? & DEBUG_OE == 0
        {
            self.write(PLA, PLA_MACDBG_PRE, 2, DEBUG_LTSSM)?;
            self.write(PLA, PLA_MACDBG_POST, 2, DEBUG_LTSSM)?;
        }
        self.write_block(bank, u32::from(patch.register()), patch.payload())?;
        let (base_reg, base) = patch.breakpoint_base();
        self.write(bank, u32::from(base_reg), 2, u32::from(base))?;
        let mut breakpoints = [0u8; 32];
        let mut count: usize = 0;
        for (index, value) in patch.breakpoints().enumerate() {
            breakpoints[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
            count += 2;
        }
        // The donor calls generic_ocp_write even for zero breakpoints; that
        // call explicitly rejects zero length rather than silently doing nothing.
        if count == 0 {
            return Err(BlockError::Unsupported(
                "RTL815x firmware has no active MAC breakpoints",
            ));
        }
        self.write_block(
            bank,
            u32::from(patch.breakpoint_start()),
            &breakpoints[..count.next_multiple_of(4)],
        )?;
        let (enable_reg, enable) = patch.breakpoint_enable();
        if enable_reg != 0 {
            self.write(bank, u32::from(enable_reg), 2, u32::from(enable))?;
        }
        if version_reg != 0 {
            self.write(USB, u32::from(version_reg), 1, u32::from(version))?;
        }
        Ok(())
    }

    fn upload_nc(&mut self, patch: &PhyNc<'_>) -> Result<(), BlockError> {
        self.base = None;
        let (mode, before, after) = patch.mode();
        self.sram_write(mode, before)?;
        let (base, value) = patch.base();
        self.sram_write(base, value)?;
        self.phy_stream(patch.register(), patch.payload())?;
        let (enable, value) = patch.patch_enable();
        self.sram_write(enable, value)?;
        for (index, value) in patch.breakpoints().enumerate() {
            self.sram_write(patch.breakpoint_start() + index as u16 * 2, value)?;
        }
        self.sram_write(mode, after)
    }

    fn upload_union(&mut self, patch: &PhyUnion<'_>) -> Result<(), BlockError> {
        self.base = None;
        for (register, value) in patch.presets() {
            self.sram_write(register, value)?;
        }
        self.phy_stream(patch.register(), patch.payload())?;
        for (register, value) in patch.breakpoints() {
            self.sram_write(register, value)?;
        }
        if let Some((register, value)) = patch.breakpoint_enable() {
            self.sram_write(register, value)?;
        }
        Ok(())
    }

    fn upload_speedup(
        &mut self,
        register: u16,
        version: u16,
        data: &[u8],
        wait: bool,
    ) -> Result<(), BlockError> {
        self.base = None;
        if self.sram_read(SRAM_GPHY_FW_VER as u16)? >= version {
            return Ok(());
        }
        self.patch_request(true, wait)?;
        let transferred = (|| {
            for chunk in data.chunks(2048) {
                self.modify(USB, USB_GPHY_CTRL, 2, 0, GPHY_PATCH_DONE | BACKUP_RESTRORE)?;
                self.write_block(USB, u32::from(register), chunk)?;
                self.modify(PLA, PLA_POL_GPIO_CTRL, 2, 0, POL_GPHY_PATCH)?;
                self.poll(PLA, PLA_POL_GPIO_CTRL, 2, POL_GPHY_PATCH, 0, (1000, 0))?;
            }
            Ok(())
        })();
        self.base = None;
        // The donor exits the chunk loop then releases the patch request even
        // after a GPIO deadline. A failed USB access forbids further register
        // writes; a still-accessible device must acknowledge request release.
        if self.accessible {
            self.patch_request(false, wait)?;
        }
        transferred?;
        if self.sram_read(SRAM_GPHY_FW_VER as u16)? != version {
            return Err(BlockError::Unsupported(
                "RTL815x PHY firmware version did not acknowledge upload",
            ));
        }
        Ok(())
    }

    fn upload(&mut self, image: &Firmware<'_>, wait: bool) -> Result<(), BlockError> {
        self.pre_firmware()?;
        let mut patch_phy = true;
        let mut key_register = None;
        for block in image.blocks() {
            match block {
                Block::Mac(patch) => self.upload_mac(patch)?,
                Block::PhyStart {
                    key_register: register,
                    key,
                } if patch_phy => {
                    self.patch_request(true, wait)?;
                    self.patch_key(*register, *key)?;
                    key_register = Some(*register);
                }
                Block::PhyStop if patch_phy => {
                    self.patch_key(
                        key_register.ok_or(BlockError::Unsupported(
                            "RTL815x missing active PHY patch key",
                        ))?,
                        0,
                    )?;
                    self.patch_request(false, wait)?;
                }
                Block::PhyNc(patch) => self.upload_nc(patch)?,
                Block::PhyUnion(patch) if patch_phy => self.upload_union(patch)?,
                Block::PhyFixup {
                    register,
                    value,
                    operation,
                } if patch_phy => {
                    self.base = None;
                    let mapped = self.phy_address(u32::from(*register))?;
                    let old = self.read(PLA, mapped, 2)? as u16;
                    let new = match operation {
                        Fixup::And => old & value,
                        Fixup::Or => old | value,
                        Fixup::Clear => old & !value,
                        Fixup::Xor => old ^ value,
                    };
                    self.write(PLA, mapped, 2, u32::from(new))?;
                }
                Block::PhySpeedUp {
                    register,
                    version,
                    payload,
                } => self.upload_speedup(*register, *version, payload, wait)?,
                Block::PhyVersion { register, version } => {
                    self.base = None;
                    patch_phy = self.sram_read(*register)? < *version;
                    if patch_phy {
                        self.sram_write(*register, *version)?;
                    }
                }
                Block::PhyStart { .. }
                | Block::PhyStop
                | Block::PhyUnion(_)
                | Block::PhyFixup { .. } => {}
            }
        }
        self.post_firmware()
    }

    fn pre_firmware(&mut self) -> Result<(), BlockError> {
        match self.revision.0 {
            0x5c10 | 0x5c20 => {
                self.poll(USB, USB_WDT1_CTRL, 1, WTD1_EN, 0, (104, 1000))?;
                if self.revision.0 == 0x5c20 {
                    self.modify(USB, USB_FW_FIX_EN0, 2, FW_FIX_SUSPEND, 0)?;
                }
            }
            0x6010 | 0x6400 => self.write(USB, USB_FC_TIMER, 2, CTRL_TIMER_EN | (1000 / 8))?,
            _ => {}
        }
        Ok(())
    }

    fn post_firmware(&mut self) -> Result<(), BlockError> {
        match self.revision.0 {
            0x5c10 => {
                if self.read(USB, USB_CSTMR, 1)? & FORCE_SUPER != 0 {
                    self.write(USB, PLA_BP_4, 2, BP4_SUPER_ONLY)?;
                }
                self.write(PLA, PLA_UPHY_TIMER, 2, 36000 / 16)?;
            }
            0x5c20 => {
                if self.read(USB, USB_CSTMR, 1)? & FORCE_SUPER != 0 {
                    self.modify(PLA, PLA_BP_EN, 2, 0, 1)?;
                }
                self.write(PLA, PLA_UPHY_TIMER, 2, 36000 / 16)?;
                self.write(PLA, PLA_EXTRA_STATUS, 2, U3P3_CHECK_EN | 4)?;
                self.modify(USB, USB_FW_FIX_EN0, 2, 0, FW_FIX_SUSPEND)?;
                self.modify(USB, USB_USB2PHY, 1, 0, USB2PHY_L1 | USB2PHY_SUSPEND)?;
            }
            0x5c30 => {
                self.modify(USB, USB_USB2PHY, 1, 0, USB2PHY_L1 | USB2PHY_SUSPEND)?;
                self.modify(USB, USB_FW_FIX_EN1, 2, 0, FW_IP_RESET_EN)?;
            }
            0x6010 => {
                if self.read(USB, USB_MISC_1, 1)? & BND_MASK != 0 {
                    self.modify(PLA, PLA_BP_EN, 2, 0, 1)?;
                }
                self.modify(USB, USB_FW_CTRL, 2, 0, FLOW_CTRL_PATCH_OPT)?;
                self.modify(USB, USB_FW_TASK, 2, 0, FC_PATCH_TASK)?;
                self.modify(USB, USB_FW_FIX_EN1, 2, 0, FW_IP_RESET_EN)?;
            }
            0x6400 => {
                self.modify(USB, USB_FW_CTRL, 2, 0, FLOW_CTRL_PATCH_2)?;
                self.modify(USB, USB_FW_TASK, 2, 0, FC_PATCH_TASK)?;
            }
            0x7030 => {
                self.modify(USB, USB_FW_FIX_EN1, 2, 0, FW_IP_RESET_EN)?;
                self.write(USB, USB_UPHY3_MDCMDIO, 4, 0x4026_840e)?;
                self.write(USB, USB_UPHY3_MDCMDIO, 4, 0x4001_acc9)?;
            }
            0x7410 | 0x7420 => {}
            _ => {
                return Err(BlockError::Unsupported(
                    "RTL815x firmware hooks for revision not implemented",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::usb::ethernet::{firmware::tests::synthetic_upload, rtl815x::tests::Model};
    use alloc::{collections::BTreeMap, rc::Rc};
    use core::cell::RefCell;

    /// Stateful PHY/MCU model independent of the uploader: SRAM auto-increment,
    /// asynchronous patch-ready, staged 2 KiB USB RAM download ownership and
    /// firmware version changes occur only after complete, ordered payloads.
    pub(crate) struct Hardware {
        pub(crate) core: Model,
        pub(crate) sram: BTreeMap<u16, u16>,
        pub(crate) sram2: BTreeMap<u16, u16>,
        pointer2: u16,
        pub(crate) mdi: [u16; 4],
        pointer: u16,
        patch_pending: Option<(bool, usize)>,
        speed_expected: Vec<u8>,
        speed_received: Vec<u8>,
        speed_version: u16,
        staged: usize,
        speed_pending: usize,
        pub(crate) stuck_patch: bool,
        stuck_speed: bool,
        wrong_version: bool,
        pub(crate) efuse: u32,
        pub(crate) phy_states: alloc::collections::VecDeque<u32>,
        pub(crate) ups_exit_power_cut: bool,
    }

    impl Hardware {
        pub(crate) fn new(revision: u16, bytes: &[u8]) -> Self {
            let mut hardware = Self {
                core: Model::new(revision),
                sram: BTreeMap::new(),
                sram2: BTreeMap::new(),
                pointer2: 0,
                mdi: [0; 4],
                pointer: 0,
                patch_pending: None,
                speed_expected: Vec::new(),
                speed_received: Vec::new(),
                speed_version: 0,
                staged: 0,
                speed_pending: 0,
                stuck_patch: false,
                stuck_speed: false,
                wrong_version: false,
                efuse: 0x1ffff,
                phy_states: Default::default(),
                ups_exit_power_cut: false,
            };
            // Independent raw wire inventory of a speed-up block: do not read
            // expectations back from the production parser/uploader objects.
            let mut at = 64;
            while at + 8 <= bytes.len() {
                let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                let length = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()) as usize;
                if kind == 0 {
                    break;
                }
                if kind == 13 {
                    let offset = usize::from(u16::from_le_bytes(
                        bytes[at + 8..at + 10].try_into().unwrap(),
                    ));
                    hardware.speed_version =
                        u16::from_le_bytes(bytes[at + 10..at + 12].try_into().unwrap());
                    hardware.speed_expected = bytes[at + offset..at + length].to_vec();
                }
                at += length.next_multiple_of(8);
            }
            hardware
        }

        pub(crate) fn request(
            &mut self,
            request: [u8; 8],
            output: &[u8],
        ) -> Result<Vec<u8>, BlockError> {
            let address = u32::from(u16::from_le_bytes([request[2], request[3]]));
            let bank = u16::from_le_bytes([request[4], request[5]]) & 0xff00;
            let mapped = if bank == PLA && address & 0xf000 == 0xb000 {
                (address & 0xfff) | self.core.base
            } else {
                address
            };
            let lanes = request[4] & 0xf;
            let target = mapped
                + match lanes {
                    2 => 1,
                    4 | 12 => 2,
                    8 => 3,
                    _ => 0,
                };
            let read = request[0] == 0xc0;
            if read && bank == PLA {
                // SRAM2 data is the upper half of the aligned four-byte read.
                if mapped == OCP_SRAM2_ADDR {
                    self.core.set(
                        PLA,
                        OCP_SRAM2_DATA,
                        2,
                        u32::from(*self.sram2.get(&self.pointer2).unwrap_or(&0)),
                    );
                }
                if mapped == 0xd068 {
                    let port = (self.core.get(PLA, 0xd068, 2) >> 3 & 3) as usize;
                    self.core.set(PLA, 0xd06a, 2, u32::from(self.mdi[port]));
                }

                if target == OCP_PHY_STATUS
                    && let Some(state) = self.phy_states.pop_front()
                {
                    self.core.set(PLA, OCP_PHY_STATUS, 2, state);
                }
                if address == PLA_EFUSE_DATA {
                    let command = self.core.get(PLA, PLA_EFUSE_CMD, 2);
                    self.core.set(PLA, PLA_EFUSE_DATA, 2, self.efuse & 0xffff);
                    self.core.set(
                        PLA,
                        PLA_EFUSE_CMD,
                        2,
                        (command & !EFUSE_DATA_BIT16)
                            | if self.efuse & 0x10000 != 0 {
                                EFUSE_DATA_BIT16
                            } else {
                                0
                            },
                    );
                }
                if target == OCP_SRAM_DATA {
                    self.core.set(
                        PLA,
                        OCP_SRAM_DATA,
                        2,
                        u32::from(*self.sram.get(&self.pointer).unwrap_or(&0)),
                    );
                }
                if target == OCP_PHY_PATCH_STAT
                    && !self.stuck_patch
                    && let Some((ready, count)) = &mut self.patch_pending
                {
                    *count -= 1;
                    if *count == 0 {
                        self.core.set(
                            PLA,
                            OCP_PHY_PATCH_STAT,
                            2,
                            if *ready { PATCH_READY } else { 0 },
                        );
                        self.patch_pending = None;
                    }
                }
                if target == PLA_POL_GPIO_CTRL && self.speed_pending != 0 && !self.stuck_speed {
                    self.speed_pending -= 1;
                    if self.speed_pending == 0 {
                        self.core.set(PLA, PLA_POL_GPIO_CTRL, 2, 0);
                        if self.speed_received.len() == self.speed_expected.len()
                            && !self.wrong_version
                        {
                            self.sram
                                .insert(SRAM_GPHY_FW_VER as u16, self.speed_version);
                        }
                    }
                }
            }
            let reply = self.core.request(request, output)?;
            if !read && bank == USB && target == USB_MISC_2 && self.ups_exit_power_cut {
                self.ups_exit_power_cut = false;
                self.core.set(USB, USB_MISC_0, 2, PCUT_STATUS);
            }
            if !read && bank == PLA {
                if target == OCP_SRAM2_ADDR {
                    self.pointer2 = self.core.get(PLA, OCP_SRAM2_ADDR, 2) as u16;
                }
                if target == OCP_SRAM2_DATA {
                    self.sram2
                        .insert(self.pointer2, self.core.get(PLA, OCP_SRAM2_DATA, 2) as u16);
                    self.pointer2 = self.pointer2.wrapping_add(2);
                }
                if target == 0xd06a {
                    let port = (self.core.get(PLA, 0xd068, 2) >> 3 & 3) as usize;
                    self.mdi[port] = self.core.get(PLA, 0xd06a, 2) as u16;
                }

                if target == OCP_SRAM_ADDR {
                    self.pointer = self.core.get(PLA, OCP_SRAM_ADDR, 2) as u16;
                }
                if target == OCP_SRAM_DATA {
                    self.sram
                        .insert(self.pointer, self.core.get(PLA, OCP_SRAM_DATA, 2) as u16);
                    self.pointer = self.pointer.wrapping_add(2);
                }
                if target == OCP_PHY_PATCH_CMD {
                    self.patch_pending = Some((
                        self.core.get(PLA, OCP_PHY_PATCH_CMD, 2) & PATCH_REQUEST != 0,
                        3,
                    ));
                }
                if target == PLA_POL_GPIO_CTRL
                    && self.core.get(PLA, PLA_POL_GPIO_CTRL, 2) & POL_GPHY_PATCH != 0
                {
                    assert_eq!(
                        self.core.get(USB, USB_GPHY_CTRL, 2) & (GPHY_PATCH_DONE | BACKUP_RESTRORE),
                        GPHY_PATCH_DONE | BACKUP_RESTRORE
                    );
                    assert!(self.staged > 0 && self.staged <= 2048);
                    let start = self.speed_received.len();
                    let chunk: Vec<u8> = (0..self.staged)
                        .map(|i| self.core.get(USB, 0x9a00 + i as u32, 1) as u8)
                        .collect();
                    assert_eq!(chunk, self.speed_expected[start..start + self.staged]);
                    self.speed_received.extend(chunk);
                    self.staged = 0;
                    self.speed_pending = 3;
                }
            }
            if !read && bank == USB && (0x9a00..0xa200).contains(&address) {
                assert_eq!(address as usize - 0x9a00, self.staged);
                self.staged += output.len();
            }
            Ok(reply)
        }
    }
    pub(crate) struct Io(pub(crate) Rc<RefCell<Hardware>>);
    impl Control for Io {
        fn control(&mut self, request: [u8; 8], output: &[u8]) -> Result<Vec<u8>, BlockError> {
            self.0.borrow_mut().request(request, output)
        }
        fn delay_us(&mut self, us: u64) {
            self.0.borrow_mut().core.delays.push(us);
        }
    }

    fn execute(bytes: &[u8], revision: u16) -> (Chip<Io>, Rc<RefCell<Hardware>>) {
        let model = Rc::new(RefCell::new(Hardware::new(revision, bytes)));
        let mut chip = Chip::probe(Io(model.clone()), Revision(revision)).unwrap();
        chip.upload_firmware(&Firmware::parse(bytes, Revision(revision)).unwrap(), false)
            .unwrap();
        assert!(!chip.initialized);
        assert!(chip.carrier().is_err());
        assert_eq!(chip.base, None);
        (chip, model)
    }

    #[test]
    fn mac_phy_and_speedup_effects_require_completion_and_never_claim_carrier_ready() {
        for revision in [
            0x5c10, 0x5c20, 0x5c30, 0x6010, 0x6400, 0x7030, 0x7410, 0x7420,
        ] {
            let bytes = synthetic_upload(revision);
            let (mut chip, model) = execute(&bytes, revision);
            {
                let state = model.borrow();
                let core = &state.core;
                assert_eq!(core.get(USB, 0xcfd7, 1), 4);
                assert_eq!(core.get(USB, 0xcfd6, 1), 6);
                assert_eq!(core.get(PLA, 0xf800, 4), 0x5a5a_5a5a);
                if matches!(revision, 0x7410 | 0x7420) {
                    assert_eq!(state.speed_received.len(), 4224);
                    assert_eq!(state.sram[&(SRAM_GPHY_FW_VER as u16)], 0x21);
                }
            }
            let before = model.borrow().core.trace.len();
            chip.upload_firmware(&Firmware::parse(&bytes, Revision(revision)).unwrap(), false)
                .unwrap();
            let model = model.borrow();
            assert!(
                !model.core.trace[before..]
                    .iter()
                    .any(|(request, data)| request[0] == 0x40
                        && u16::from_le_bytes([request[2], request[3]]) == 0xf800
                        && data.len() > 4)
            );
        }
    }

    #[test]
    fn failures_at_every_mac_upload_request_poison_and_forbid_retries() {
        let bytes = synthetic_upload(0x6010);
        let (_, model) = execute(&bytes, 0x6010);
        let count = model.borrow().core.trace.len();
        for at in 1..count {
            let model = Rc::new(RefCell::new(Hardware::new(0x6010, &bytes)));
            let mut chip = Chip::probe(Io(model.clone()), Revision(0x6010)).unwrap();
            model.borrow_mut().core.fail_at = Some(at);
            let firmware = Firmware::parse(&bytes, Revision(0x6010)).unwrap();
            assert!(chip.upload_firmware(&firmware, false).is_err());
            assert!(!chip.accessible);
            assert_eq!(model.borrow().core.trace.len(), at + 1);
            assert!(chip.upload_firmware(&firmware, false).is_err());
            assert_eq!(model.borrow().core.trace.len(), at + 1);
        }
    }

    #[test]
    fn patch_ready_speedup_and_final_version_failures_remain_explicit() {
        for case in 0..3 {
            let revision = if case == 0 { 0x5c10 } else { 0x7410 };
            let bytes = synthetic_upload(revision);
            let model = Rc::new(RefCell::new(Hardware::new(revision, &bytes)));
            match case {
                0 => model.borrow_mut().stuck_patch = true,
                1 => model.borrow_mut().stuck_speed = true,
                _ => model.borrow_mut().wrong_version = true,
            }
            let mut chip = Chip::probe(Io(model.clone()), Revision(revision)).unwrap();
            let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
            assert!(chip.upload_firmware(&firmware, false).is_err());
            assert!(!chip.accessible);
            assert!(!chip.initialized);
            if case == 1 {
                assert_eq!(
                    model.borrow().core.get(PLA, OCP_PHY_PATCH_CMD, 2) & PATCH_REQUEST,
                    0
                );
            }
            let count = model.borrow().core.trace.len();
            assert!(chip.upload_firmware(&firmware, false).is_err());
            assert_eq!(model.borrow().core.trace.len(), count);
        }
    }

    #[test]
    #[ignore = "requires pinned real RTL8153/8156 firmware fixtures; see THIRD_PARTY.md"]
    fn real_firmware_uploads_preserve_payloads_order_and_final_version() {
        extern crate std;
        use sha2::{Digest, Sha256};
        let directory = std::env::var("STELA_RTL815X_FIRMWARE").unwrap();
        for (name, revision, _, hash) in crate::usb::ethernet::firmware::tests::FIXTURES {
            let bytes = std::fs::read(std::path::Path::new(&directory).join(name)).unwrap();
            assert_eq!(alloc::format!("{:x}", Sha256::digest(&bytes)), hash);
            execute(&bytes, revision);
        }
    }
}
