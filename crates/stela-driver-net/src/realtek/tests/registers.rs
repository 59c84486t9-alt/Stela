// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Register reads and writes for the shared protocol model.
use super::*;

impl Registers for Model {
    fn read8(&self, o: usize) -> u8 {
        if self.failed_read == Some(o) {
            return u8::MAX;
        }
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        if o == COMMAND
            && self.fail_mac_address.is_some_and(|address| {
                s.writes
                    .iter()
                    .rfind(|(r, _, _)| *r == MAC_OCP)
                    .is_some_and(|(_, v, _)| *v & ACCESS != 0 && (*v >> 15) as u16 & !1 == address)
            })
        {
            return u8::MAX;
        }
        if o == COMMAND && s.bytes[o] == ENABLE {
            return self.command_readback.unwrap_or(s.bytes[o]);
        }
        s.bytes[o]
    }
    fn read16(&self, o: usize) -> u16 {
        if self.failed_read == Some(o) {
            return u16::MAX;
        }
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        u16::from_le_bytes(s.bytes[o..o + 2].try_into().unwrap())
    }
    fn read32(&self, o: usize) -> u32 {
        if self.failed_read == Some(o) {
            return u32::MAX;
        }
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        Self::raw32(&s, o)
    }
    fn write8(&self, o: usize, v: u8) {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        s.writes.push((o, u32::from(v), 1));
        if self.ep_mode.is_some() && o == IBISR0 {
            s.bytes[o] &= !v; // W1C management status.
            return;
        }
        s.bytes[o] = v;
        if self.ep_mode.is_some() && o == IBCR2 && v & 1 == 0 {
            s.cmac_ready_at = self.cmac_ready_delay.map(|delay| self.time.now() + delay);
        }
        if o == COMMAND && v & RESET != 0 {
            s.reset_mac_at = Some(self.time.now() + 300);
        }
    }
    fn write16(&self, o: usize, v: u16) {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        s.writes.push((o, u32::from(v), 2));
        s.bytes[o..o + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn write32(&self, o: usize, v: u32) {
        let mut s = self.state.borrow_mut();
        self.complete(&mut s);
        s.writes.push((o, v, 4));
        if matches!(
            o,
            PHY_ACCESS
                | EPHY_ACCESS
                | ERI_ADDRESS
                | CSI_ADDRESS
                | PHY_OCP
                | EFUSE_ACCESS
                | DP_OCP_ACCESS
        ) {
            if o == PHY_ACCESS {
                if self.dp_mode {
                    assert_eq!(Model::raw32(&s, DP_MDIO_GATE) & DP_MDIO_GATED, 0);
                }
                s.mdio_commands += 1;
            } else if o == ERI_ADDRESS {
                s.eri_commands += 1;
            } else if o == CSI_ADDRESS {
                s.csi_commands += 1;
            } else if o == DP_OCP_ACCESS {
                s.dp_commands += 1;
            } else if o == PHY_OCP {
                s.phy_ocp_commands += 1;
            }
            s.pending = Some((o, v, self.time.now() + 15));
        }
        if o == MAC_OCP && !self.dp_mode {
            let reg = (((v & !ACCESS) >> 15) as u16) & !1;
            if v & ACCESS != 0 {
                s.mac.insert(reg, v as u16);
                if reg == 0xe8de || (self.internal_nbase && reg == 0xc01e) {
                    s.bytes[MCU] &= !2;
                    s.shared_ready_at =
                        self.shared_ready_delay.map(|delay| self.time.now() + delay);
                }
            } else {
                let data = u32::from(match (self.h_adc, reg) {
                    (Some((a, _)), 0xdd02) => a,
                    (Some((_, b)), 0xdd00) => b,
                    _ => *s.mac.get(&reg).unwrap_or(&0),
                });
                Self::store32(&mut s, o, data);
                return;
            }
        }
        Self::store32(&mut s, o, v);
    }
}
