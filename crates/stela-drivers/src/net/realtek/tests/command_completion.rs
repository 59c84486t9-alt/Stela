// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Completion timing and command-port effects for the shared model.
use super::*;

impl Model {
    pub(super) fn complete(&self, s: &mut State) {
        if s.ep_ready_at.is_some_and(|at| self.time.now() >= at) {
            *s.oob.entry(0x124).or_default() |= 1;
            s.ep_ready_at = None;
        }
        if s.cmac_ready_at.is_some_and(|at| self.time.now() >= at) {
            s.bytes[IBISR0] |= 0x20;
            s.cmac_ready_at = None;
        }
        if let Some((at, reg)) = s.dp_ready_at
            && self.time.now() >= at
        {
            *s.dp_ocp.entry(reg).or_default() |= 1 << 11;
            s.dp_ready_at = None;
        }
        if s.shared_ready_at.is_some_and(|at| self.time.now() >= at) {
            s.bytes[MCU] |= 2;
            s.shared_ready_at = None;
        }
        if s.reset_phy_at.is_some_and(|t| self.time.now() >= t) && !self.stuck_phy_reset {
            s.phy.entry((0, 0)).and_modify(|v| *v &= !PHY_RESET);
            s.phy_ocp
                .entry(OCP_PHY_BASE)
                .and_modify(|v| *v &= !PHY_RESET);
            s.reset_phy_at = None;
        }
        if s.reset_mac_at.is_some_and(|t| self.time.now() >= t) && !self.stuck_reset {
            s.bytes[COMMAND] &= !RESET;
            s.reset_mac_at = None;
        }
        let Some((port, command, when)) = s.pending else {
            return;
        };
        if self.time.now() < when
            || self.fault == Some(port)
            || (port == PHY_ACCESS && s.mdio_commands >= self.fail_phy_at)
            || (port == ERI_ADDRESS && s.eri_commands >= self.fail_eri_at)
            || (port == CSI_ADDRESS && s.csi_commands >= self.fail_csi_at)
            || (port == DP_OCP_ACCESS && s.dp_commands >= self.fail_dp_at)
            || (port == PHY_OCP && s.phy_ocp_commands >= self.fail_phy_ocp_at)
        {
            return;
        }
        s.pending = None;
        let write = command & ACCESS != 0;
        let value = match port {
            PHY_ACCESS => {
                let reg = ((command >> 16) & 31) as u16;
                if write {
                    if reg == PHY_PAGE {
                        s.page = command as u16;
                    } else {
                        s.phy.insert((s.page, reg), command as u16);
                        if s.page == 5 && reg == 5 {
                            s.parameter = command as u16;
                        } else if s.page == 5 && reg == 6 {
                            s.parameters.insert(s.parameter, command as u16);
                        }
                        if s.page == 7 {
                            if reg == 0x1e {
                                s.extended_page = command as u16;
                            } else {
                                s.extended.insert((s.extended_page, reg), command as u16);
                            }
                        }
                        if s.page == 0 && reg == 0 && command as u16 & PHY_RESET != 0 {
                            s.reset_phy_at = Some(self.time.now() + 100);
                        }
                    }
                    command & !ACCESS
                } else {
                    let value = if reg == PHY_PAGE {
                        s.page
                    } else if s.page == 5 && reg == 6 {
                        *s.parameters.get(&s.parameter).unwrap_or(&0)
                    } else if s.page == 7 && reg != 0x1e {
                        *s.extended.get(&(s.extended_page, reg)).unwrap_or(&0)
                    } else {
                        *s.phy.get(&(s.page, reg)).unwrap_or(&0)
                    };
                    (command & !0xffff) | ACCESS | u32::from(value)
                }
            }
            EFUSE_ACCESS => command | ACCESS | u32::from(s.efuse),
            EPHY_ACCESS => {
                let reg = ((command >> 16) & 31) as usize;
                if write {
                    s.ephy[reg] = command as u16;
                    command & !ACCESS
                } else {
                    command | ACCESS | u32::from(s.ephy[reg])
                }
            }
            ERI_ADDRESS => {
                let reg = (command & 0xfff) as u16;
                let oob = command & 0x30000 == 0x20000;
                if oob {
                    assert_eq!(
                        command & 0x7ffc_0000,
                        if self.ep_mode == Some(52) {
                            0x3dc0_0000
                        } else {
                            0
                        }
                    );
                }
                if write {
                    let mut value = *(if oob { &s.oob } else { &s.eri }).get(&reg).unwrap_or(&0);
                    let data = Self::raw32(s, ERI_DATA);
                    for byte in 0..4 {
                        if command & (1 << (12 + byte)) != 0 {
                            value = (value & !(0xff << (byte * 8))) | (data & (0xff << (byte * 8)));
                        }
                    }
                    if oob {
                        s.oob.insert(reg, value);
                        if reg == 0x30
                            && value & 1 != 0
                            && s.oob.get(&0x180).is_some_and(|v| *v & 0xff == 5)
                            && s.oob[&0x128] & 1 != 0
                        {
                            s.ep_ready_at =
                                self.ep_ready_delay.map(|delay| self.time.now() + delay);
                        }
                    } else {
                        s.eri.insert(reg, value);
                    }
                    command & !ACCESS
                } else {
                    Self::store32(
                        s,
                        ERI_DATA,
                        *(if oob { &s.oob } else { &s.eri }).get(&reg).unwrap_or(&0),
                    );
                    command | ACCESS
                }
            }
            CSI_ADDRESS => {
                let key = (((command >> 16) & 7) as u8, (command & 0xfff) as u16);
                if write {
                    let value = Self::raw32(s, CSI_DATA);
                    s.csi.insert(key, value);
                    command & !ACCESS
                } else {
                    let value = *s.csi.get(&key).unwrap_or(&0x1278_5634);
                    Self::store32(s, CSI_DATA, value);
                    command | ACCESS
                }
            }
            DP_OCP_ACCESS => {
                let address = (command & 0xfff) as u16;
                if write {
                    let data = Self::raw32(s, DP_OCP_DATA);
                    let mut value = *s.dp_ocp.get(&address).unwrap_or(&0);
                    for byte in 0..4 {
                        if command & (1 << (12 + byte)) != 0 {
                            let mask = 0xff << (8 * byte);
                            value = (value & !mask) | (data & mask);
                        }
                    }
                    s.dp_ocp.insert(address, value);
                    if address == 0x30 && data == 1 {
                        let reg = if s.dp_ocp.contains_key(&0xb8) {
                            0xb8
                        } else {
                            0x10
                        };
                        if s.eri[&0xe8] & 0xff == 5 && s.dp_ocp[&reg] & (1 << 15) != 0 {
                            s.dp_ready_at = self
                                .dp_ready_delay
                                .map(|delay| (self.time.now() + delay, reg));
                        }
                    }
                    command & !ACCESS
                } else {
                    Self::store32(s, DP_OCP_DATA, *s.dp_ocp.get(&address).unwrap_or(&0));
                    command | ACCESS
                }
            }
            PHY_OCP => {
                // Address bit0 is always zero. Data bit15 occupies the
                // same command bit15 and must not contaminate the address.
                let address = ((command >> 15) as u16) & !1;
                if write {
                    // Pinned realtek_main.c: internal NBASE C22 MMD
                    // access has no effect and its data reads always zero.
                    // The driver uses it only to detect internal versus
                    // external MMD access, never to claim a successful MMD write.
                    if !(self.internal_nbase && matches!(address, 0xa41a | 0xa41c)) {
                        s.phy_ocp.insert(address, command as u16);
                    }
                    if address == 0xa436 {
                        s.g_parameter = command as u16;
                    } else if address == 0xa438 {
                        s.g_parameters.insert(s.g_parameter, command as u16);
                    } else if address == 0xb87c {
                        s.n_parameter = command as u16;
                    } else if address == 0xb87e {
                        s.n_parameters.insert(s.n_parameter, command as u16);
                    }
                    if address == OCP_PHY_BASE && command as u16 & PHY_RESET != 0 {
                        s.reset_phy_at = Some(self.time.now() + 100);
                    }
                    command & !ACCESS
                } else {
                    let value = if address == 0xa402 && s.bmsr_latch_low_once {
                        s.bmsr_latch_low_once = false;
                        *s.phy_ocp.get(&address).unwrap_or(&0) & !4
                    } else if self.internal_nbase && address == 0xa41c {
                        0
                    } else if address == 0xb87e {
                        *s.n_parameters.get(&s.n_parameter).unwrap_or(&0)
                    } else if address == 0xa438 {
                        *s.g_parameters.get(&s.g_parameter).unwrap_or(&0)
                    } else {
                        *s.phy_ocp.get(&address).unwrap_or(&0)
                    };
                    command | ACCESS | u32::from(value)
                }
            }
            _ => panic!("unmodeled command port"),
        };
        Self::store32(s, port, value);
    }
}
