// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//! Routers from before USB4, behind a USB4 host: Linux lc.c, the EEPROM half
//! of eeprom.c and what switch.c does for routers without USB4 registers.
use super::{Cm, Error, regs::*, router::Kind};
use crate::bus::thunderbolt::config::Space;
use alloc::vec::Vec;

const INTEL: u16 = 0x8086;
const LIGHT_RIDGE: u16 = 0x1513;
const EAGLE_RIDGE: u16 = 0x151a;
const LIGHT_PEAK: u16 = 0x151b;
const CACTUS_RIDGE_4C: u16 = 0x1547;
const CACTUS_RIDGE_2C: u16 = 0x1548;
const PORT_RIDGE: u16 = 0x1549;
const REDWOOD_RIDGE_2C: u16 = 0x1567;
const REDWOOD_RIDGE_4C: u16 = 0x1569;
const FALCON_RIDGE_2C: u16 = 0x156b;
const FALCON_RIDGE_4C: u16 = 0x156d;
const WIN_RIDGE_2C: u16 = 0x157e;
const ALPINE_RIDGE_2C: u16 = 0x1576;
const ALPINE_RIDGE_4C: u16 = 0x1578;
const ALPINE_RIDGE_LP: u16 = 0x15c0;
const ALPINE_RIDGE_C_4C: u16 = 0x15d3;
const ALPINE_RIDGE_C_2C: u16 = 0x15da;
const TITAN_RIDGE_2C: u16 = 0x15e7;
const TITAN_RIDGE_4C: u16 = 0x15ea;
const TITAN_RIDGE_DD: u16 = 0x15ef;

/// Which of Intel's controllers a router's identity names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Controller {
    LightRidge,
    EagleRidge,
    /// Thunderbolt 1 otherwise, also what an unknown router counts as.
    First,
    Second,
    AlpineRidge,
    TitanRidge,
}

impl Controller {
    pub(super) fn of(vendor: u16, device: u16) -> Self {
        if vendor != INTEL {
            return Self::First;
        }
        match device {
            LIGHT_RIDGE => Self::LightRidge,
            EAGLE_RIDGE => Self::EagleRidge,
            LIGHT_PEAK | CACTUS_RIDGE_2C | CACTUS_RIDGE_4C | PORT_RIDGE | REDWOOD_RIDGE_2C
            | REDWOOD_RIDGE_4C => Self::First,
            WIN_RIDGE_2C | FALCON_RIDGE_2C | FALCON_RIDGE_4C => Self::Second,
            ALPINE_RIDGE_2C | ALPINE_RIDGE_4C | ALPINE_RIDGE_LP | ALPINE_RIDGE_C_2C
            | ALPINE_RIDGE_C_4C => Self::AlpineRidge,
            TITAN_RIDGE_2C | TITAN_RIDGE_4C | TITAN_RIDGE_DD => Self::TitanRidge,
            _ => Self::First,
        }
    }
    /// `tb_switch_get_generation`.
    pub(super) fn generation(self) -> u8 {
        match self {
            Self::LightRidge | Self::EagleRidge | Self::First => 1,
            Self::Second => 2,
            Self::AlpineRidge | Self::TitanRidge => 3,
        }
    }
    /// The router register that lets `tb_port_find_cap` walk an adapter.
    pub(super) fn tmu_access(self) -> Option<u16> {
        match self {
            Self::LightRidge => Some(0x26),
            Self::EagleRidge => Some(0x2a),
            _ => None,
        }
    }
}

/// Vendor-specific router capabilities of a router from before USB4.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Vendor {
    pub plug_events: Option<u16>,
    pub time: Option<u16>,
    pub link_controller: Option<u16>,
}

impl Cm {
    /// `tb_switch_alloc`'s look at the vendor capabilities.
    pub(super) async fn find_vendor_capabilities(&mut self, route: u64) -> Result<(), Error> {
        let vendor = Vendor {
            plug_events: self.vendor_capability(route, VSE_PLUG_EVENTS).await?,
            time: self.vendor_capability(route, VSE_TIME).await?,
            link_controller: self.vendor_capability(route, VSE_LINK_CONTROLLER).await?,
        };
        self.router_mut(route)?.vendor_capabilities = vendor;
        Ok(())
    }

    /// `tb_plug_events_active`.
    pub(super) async fn enable_plug_events(&mut self, route: u64) -> Result<(), Error> {
        let router = self.router(route)?;
        let capability = router
            .vendor_capabilities
            .plug_events
            .ok_or(Error::Legacy)?;
        // Alpine Ridge needs its USB events for the internal xHCI.
        let disable_usb = !matches!(router.device(), LIGHT_RIDGE | EAGLE_RIDGE | PORT_RIDGE)
            && router.controller() != Controller::AlpineRidge;
        let value = if disable_usb {
            PLUG_EVENTS_USB_DISABLE
        } else {
            0
        };
        self.router_modify(route, capability + 1, PLUG_EVENTS_DISABLE, value)
            .await
    }

    /// `find_port_lc_cap`: the link controller registers of a lane.
    async fn lane_controller(&mut self, route: u64, number: u8) -> Result<Option<u16>, Error> {
        let Some(capability) = self.router(route)?.vendor_capabilities.link_controller else {
            return Ok(None);
        };
        let description = self.router_read(route, capability + LC_DESC).await?;
        let start = (description >> LC_DESC_SIZE_SHIFT) & 0xff;
        let size = (description >> LC_DESC_PORT_SIZE_SHIFT) & 0xfff;
        let physical = u32::from(number.saturating_sub(1)) / 2;
        Ok(Some(capability + (start + physical * size) as u16))
    }

    /// `tb_lc_set_port_configured`.
    pub(super) async fn lc_set_configured(
        &mut self,
        route: u64,
        number: u8,
        configured: bool,
    ) -> Result<(), Error> {
        let router = self.router(route)?;
        let upstream = router.upstream == number;
        if router.generation() < 2 {
            return Ok(());
        }
        let Some(capability) = self.lane_controller(route, number).await? else {
            return Ok(());
        };
        let lane = if !number.is_multiple_of(2) {
            LC_SX_CTRL_L1C
        } else {
            LC_SX_CTRL_L2C
        };
        let bits = lane | if upstream { LC_SX_CTRL_UPSTREAM } else { 0 };
        let value = if configured { bits } else { 0 };
        self.router_modify(route, capability + LC_SX_CTRL, bits, value)
            .await
    }

    /// `tb_lc_lane_bonding_possible`.
    pub(super) async fn lc_bonding_possible(&mut self, route: u64) -> Result<bool, Error> {
        let router = self.router(route)?;
        let up = router.upstream;
        if router.generation() < 2 {
            return Ok(false);
        }
        let Some(capability) = self.lane_controller(route, up).await? else {
            return Ok(false);
        };
        let attributes = self.router_read(route, capability + LC_PORT_ATTR).await?;
        Ok(attributes & LC_PORT_ATTR_BE != 0)
    }

    /// `tb_switch_set_uuid`: newer controllers have one in fuses.
    pub(super) async fn read_fused_uuid(&mut self, route: u64) -> Result<(), Error> {
        let Some(capability) = self.router(route)?.vendor_capabilities.link_controller else {
            return Ok(());
        };
        let words = self
            .read(route, 0, Space::Router, capability + LC_FUSE, 4)
            .await?;
        let mut uuid = [0; 4];
        uuid.copy_from_slice(&words);
        self.router_mut(route)?.fused_uuid = Some(uuid);
        Ok(())
    }

    /// `tb_lc_xhci_connect`.
    async fn lc_connect_xhci(&mut self, route: u64, number: u8) -> Result<(), Error> {
        let Some(capability) = self.lane_controller(route, number).await? else {
            return Ok(());
        };
        self.router_modify(
            route,
            capability + LC_LINK_REQ,
            LC_LINK_REQ_XHCI_CONNECT,
            LC_LINK_REQ_XHCI_CONNECT,
        )
        .await
    }

    /// `tb_lc_is_usb_plugged`, and that the xHCI is not there yet.
    async fn lc_wants_xhci(&mut self, route: u64, number: u8) -> Result<bool, Error> {
        let Some(capability) = self.lane_controller(route, number).await? else {
            return Ok(false);
        };
        let plugged = self.router_read(route, capability + LC_CS_42).await?;
        let requests = self.router_read(route, capability + LC_LINK_REQ).await?;
        Ok(plugged & LC_CS_42_USB_PLUGGED != 0 && requests & LC_LINK_REQ_XHCI_CONNECT == 0)
    }

    /// Bring the router's internal xHCI up for whatever is on its Type-C
    /// ports, once it has its PCIe tunnel: `tb_switch_xhci_connect`.
    pub(super) async fn connect_xhci(&mut self, route: u64) -> Result<(), Error> {
        match self.router(route)?.controller() {
            Controller::AlpineRidge => {
                for number in [1, 3] {
                    if self.lc_wants_xhci(route, number).await? {
                        self.lc_connect_xhci(route, number).await?;
                    }
                }
                Ok(())
            }
            Controller::TitanRidge => {
                self.lc_connect_xhci(route, 1).await?;
                self.lc_connect_xhci(route, 3).await
            }
            _ => Ok(()),
        }
    }

    /// The bits of `input`'s sink in `TB_LC_SNK_ALLOCATION`, the mask's
    /// lowest first: `tb_lc_dp_sink_from_port`.
    fn lc_sink(&self, input: (u64, u8)) -> Result<u32, Error> {
        let first = self
            .router(input.0)?
            .find(Kind::DpIn)
            .ok_or(Error::Topology)?
            .number;
        Ok(if first == input.1 {
            0
        } else {
            LC_SNK_ALLOCATION_SNK1_SHIFT
        })
    }

    /// `tb_lc_dp_sink_available`: a sink free or already the CM's.
    async fn lc_sink_allocation(&mut self, input: (u64, u8)) -> Result<Option<u32>, Error> {
        let capability = self
            .router(input.0)?
            .vendor_capabilities
            .link_controller
            .ok_or(Error::Topology)?;
        let shift = self.lc_sink(input)?;
        let word = self
            .router_read(input.0, capability + LC_SNK_ALLOCATION)
            .await?;
        let owner = (word >> shift) & LC_SNK_ALLOCATION_MASK;
        Ok((owner == 0 || owner == LC_SNK_ALLOCATION_CM).then_some(word))
    }

    /// `tb_lc_dp_sink_query`.
    pub(super) async fn lc_sink_free(&mut self, input: (u64, u8)) -> Result<bool, Error> {
        if self.router(input.0)?.generation() < 3 {
            return Ok(true);
        }
        Ok(self.lc_sink_allocation(input).await?.is_some())
    }

    /// `tb_lc_dp_sink_alloc` and `tb_lc_dp_sink_dealloc`.
    pub(super) async fn lc_set_sink(
        &mut self,
        input: (u64, u8),
        allocated: bool,
    ) -> Result<(), Error> {
        if self.router(input.0)?.generation() < 3 {
            return Ok(());
        }
        let word = self.lc_sink_allocation(input).await?.ok_or(Error::Busy)?;
        let shift = self.lc_sink(input)?;
        let capability = self
            .router(input.0)?
            .vendor_capabilities
            .link_controller
            .ok_or(Error::Topology)?;
        let owner = if allocated { LC_SNK_ALLOCATION_CM } else { 0 };
        let updated = (word & !(LC_SNK_ALLOCATION_MASK << shift)) | owner << shift;
        self.router_write(input.0, capability + LC_SNK_ALLOCATION, updated)
            .await
    }

    async fn eeprom_control(&mut self, route: u64, capability: u16) -> Result<u32, Error> {
        self.router_read(route, capability + EEPROM_CTL).await
    }

    /// `tb_eeprom_active`.
    async fn eeprom_active(
        &mut self,
        route: u64,
        capability: u16,
        active: bool,
    ) -> Result<(), Error> {
        let offset = capability + EEPROM_CTL;
        let mut word = self.eeprom_control(route, capability).await?;
        if active {
            word |= EEPROM_ENABLE;
            self.router_write(route, offset, word).await?;
            self.router_write(route, offset, word & !EEPROM_CS).await
        } else {
            word |= EEPROM_CS;
            self.router_write(route, offset, word).await?;
            self.router_write(route, offset, word & !EEPROM_ENABLE)
                .await
        }
    }

    /// `tb_eeprom_out`.
    async fn eeprom_out(&mut self, route: u64, capability: u16, byte: u8) -> Result<(), Error> {
        let offset = capability + EEPROM_CTL;
        let mut word = self.eeprom_control(route, capability).await?;
        for bit in (0..8).rev() {
            word = (word & !EEPROM_DI) | if byte >> bit & 1 != 0 { EEPROM_DI } else { 0 };
            self.router_write(route, offset, word).await?;
            self.router_write(route, offset, word | EEPROM_SK).await?;
            self.router_write(route, offset, word).await?;
        }
        Ok(())
    }

    /// `tb_eeprom_in`.
    async fn eeprom_in(&mut self, route: u64, capability: u16) -> Result<u8, Error> {
        let offset = capability + EEPROM_CTL;
        let word = self.eeprom_control(route, capability).await?;
        let mut byte = 0;
        for _ in 0..8 {
            self.router_write(route, offset, word | EEPROM_SK).await?;
            let read = self.router_read(route, offset).await?;
            self.router_write(route, offset, read & !EEPROM_SK).await?;
            byte = byte << 1 | u8::from(read & EEPROM_DO != 0);
        }
        Ok(byte)
    }

    async fn eeprom_transfer(
        &mut self,
        route: u64,
        capability: u16,
        address: u16,
        count: usize,
    ) -> Result<Vec<u8>, Error> {
        for byte in [3, (address >> 8) as u8, address as u8] {
            self.eeprom_out(route, capability, byte).await?;
        }
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            bytes.push(self.eeprom_in(route, capability).await?);
        }
        Ok(bytes)
    }

    /// `tb_eeprom_read_n`: the access is ended whatever happens, as the
    /// router cannot be probed again otherwise.
    pub(super) async fn eeprom_read(
        &mut self,
        route: u64,
        offset: u16,
        count: usize,
    ) -> Result<Vec<u8>, Error> {
        let capability = self
            .router(route)?
            .vendor_capabilities
            .plug_events
            .ok_or(Error::Unsupported)?;
        let control = self.eeprom_control(route, capability).await?;
        if control & EEPROM_PRESENT == 0 || control & EEPROM_NOT_PRESENT != 0 {
            return Err(Error::Unsupported);
        }
        let base = self.router_read(route, capability + DROM_OFFSET).await?;
        let base = u16::try_from(base).map_err(|_| Error::Unsupported)?;
        self.eeprom_active(route, capability, true).await?;
        let bytes = self
            .eeprom_transfer(route, capability, base.wrapping_add(offset), count)
            .await;
        let ended = self.eeprom_active(route, capability, false).await;
        let bytes = bytes?;
        ended.map(|()| bytes)
    }
}
