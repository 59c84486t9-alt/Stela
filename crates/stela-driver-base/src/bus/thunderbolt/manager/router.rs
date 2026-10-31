// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Routers and their adapters: Linux switch.c, usb4.c and cap.c.
use super::{
    Cm, Error,
    legacy::{Controller, Vendor},
    regs::*,
    tmu::Tmu,
};
use crate::bus::thunderbolt::{
    config::Space,
    drom::{self, Image},
};
use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    vec::Vec,
};

/// HopIDs below this are reserved: Linux's `TB_PATH_MIN_HOPID`.
pub(super) const MIN_HOP: u16 = 8;
/// A USB4 domain is at most this deep.
const MAX_DEPTH: u32 = 5;

/// A route's depth: `tb_route_length`.
pub(super) fn depth(route: u64) -> u32 {
    (u64::BITS - route.leading_zeros()).div_ceil(8)
}
/// The route of the router above `route`.
pub(super) fn parent(route: u64) -> u64 {
    route & ((1u64 << ((depth(route) - 1) * 8)) - 1)
}
/// The downstream port that the router at `level` uses towards `route`.
pub(super) fn port_at(route: u64, level: u32) -> u8 {
    (route >> (level * 8)) as u8
}
/// The route below `port` of the router at `route`.
pub(super) fn downstream(route: u64, port: u8) -> u64 {
    route | u64::from(port) << (depth(route) * 8)
}
/// Whether `route` lies at or below `ancestor`.
pub(super) fn beneath(route: u64, ancestor: u64) -> bool {
    let level = depth(ancestor);
    depth(route) >= level && (level == 0 || route & ((1u64 << (level * 8)) - 1) == ancestor)
}

/// An adapter's protocol: `enum tb_port_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Inactive,
    Lane,
    Nhi,
    DpIn,
    DpOut,
    PcieDown,
    PcieUp,
    Usb3Down,
    Usb3Up,
    Other,
}

impl Kind {
    fn of(raw: u32) -> Self {
        match raw & 0x00ff_ffff {
            0 => Self::Inactive,
            1 => Self::Lane,
            2 => Self::Nhi,
            0x0e_0101 => Self::DpIn,
            0x0e_0102 => Self::DpOut,
            0x10_0101 => Self::PcieDown,
            0x10_0102 => Self::PcieUp,
            0x20_0101 => Self::Usb3Down,
            0x20_0102 => Self::Usb3Up,
            _ => Self::Other,
        }
    }
    pub(super) fn is_dp(self) -> bool {
        matches!(self, Self::DpIn | Self::DpOut)
    }
}

/// The HopIDs in use on one direction of an adapter.
#[derive(Debug, Default)]
pub(super) struct HopIds {
    limit: u16,
    used: BTreeSet<u16>,
}

impl HopIds {
    /// Reserve `wanted`, or the lowest free HopID: `tb_port_alloc_hopid`.
    pub(super) fn take(&mut self, wanted: Option<u16>) -> Option<u16> {
        let id = match wanted {
            Some(id) => (MIN_HOP..=self.limit)
                .contains(&id)
                .then_some(id)
                .filter(|id| !self.used.contains(id))?,
            None => (MIN_HOP..=self.limit).find(|id| !self.used.contains(id))?,
        };
        self.used.insert(id);
        Some(id)
    }
    pub(super) fn release(&mut self, id: u16) {
        self.used.remove(&id);
    }
    pub(super) fn limit(&self) -> u16 {
        self.limit
    }
    fn limit_to(&mut self, limit: u16) {
        self.limit = limit;
    }
}

/// One adapter of a router.
#[derive(Debug)]
pub(super) struct Port {
    pub number: u8,
    pub kind: Kind,
    /// Its configuration space does not exist.
    pub disabled: bool,
    pub cap_phy: Option<u16>,
    pub cap_usb4: Option<u16>,
    pub cap_adapter: Option<u16>,
    pub cap_time: Option<u16>,
    /// The other lane adapter of the same USB4 port, and which lane this is.
    pub dual: Option<u8>,
    pub lane: u8,
    pub bonded: bool,
    /// The lane adapter at the far end of this lane's link.
    pub remote: Option<(u64, u8)>,
    /// `ADP_CS_4` as last read or written.
    pub buffers: u32,
    pub total_credits: u32,
    pub control_credits: u32,
    pub hops_in: HopIds,
    pub hops_out: HopIds,
}

impl Port {
    fn absent(number: u8) -> Self {
        Self {
            number,
            kind: Kind::Inactive,
            disabled: false,
            cap_phy: None,
            cap_usb4: None,
            cap_adapter: None,
            cap_time: None,
            dual: None,
            lane: 0,
            bonded: false,
            remote: None,
            buffers: 0,
            total_credits: 0,
            control_credits: 0,
            hops_in: HopIds::default(),
            hops_out: HopIds::default(),
        }
    }
    pub(super) fn nfc_credits(&self) -> u32 {
        self.buffers & ADP_CS_4_NFC_BUFFERS
    }
    /// `tb_usable_credits`.
    pub(super) fn usable_credits(&self) -> u32 {
        self.total_credits.saturating_sub(self.control_credits)
    }
}

/// The router's preferred buffer allocation: `usb4_switch_credits_init`.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Credits {
    pub allocation: bool,
    pub max_usb3: u32,
    pub min_dp_aux: u32,
    pub min_dp_main: u32,
    pub max_pcie: u32,
}

/// A router in the domain.
#[derive(Debug)]
pub(super) struct Router {
    pub route: u64,
    /// `ROUTER_CS_0..=4`.
    pub header: [u32; 5],
    pub upstream: u8,
    pub ports: Vec<Port>,
    pub link_usb4: bool,
    pub link_speed: u32,
    pub link_width: u32,
    pub credits: Credits,
    pub uid: u64,
    /// The UUID a link controller holds in fuses.
    pub fused_uuid: Option<[u32; 4]>,
    /// The vendor and device names of its DROM.
    pub name: Option<String>,
    pub vendor_capabilities: Vendor,
    pub tmu: Tmu,
    pub authorized: bool,
    pub unplugged: bool,
}

impl Router {
    pub(super) fn vendor(&self) -> u16 {
        self.header[0] as u16
    }
    pub(super) fn device(&self) -> u16 {
        (self.header[0] >> 16) as u16
    }
    pub(super) fn usb4_version(&self) -> u8 {
        (self.header[4] >> 29) as u8
    }
    /// `tb_switch_is_usb4`.
    pub(super) fn is_usb4(&self) -> bool {
        self.usb4_version() != 0
    }
    pub(super) fn controller(&self) -> Controller {
        Controller::of(self.vendor(), self.device())
    }
    /// `tb_switch_get_generation`.
    pub(super) fn generation(&self) -> u8 {
        if self.is_usb4() {
            4
        } else {
            self.controller().generation()
        }
    }
    /// `tb_dp_is_usb4`.
    pub(super) fn dp_is_usb4(&self) -> bool {
        self.is_usb4() || self.controller() == Controller::TitanRidge
    }
    pub(super) fn first_capability(&self) -> u16 {
        (self.header[1] & 0xff) as u16
    }
    pub(super) fn max_port(&self) -> u8 {
        ((self.header[1] >> 14) & 63) as u8
    }
    pub(super) fn port(&self, number: u8) -> Result<&Port, Error> {
        self.ports.get(usize::from(number)).ok_or(Error::Topology)
    }
    pub(super) fn port_mut(&mut self, number: u8) -> Result<&mut Port, Error> {
        self.ports
            .get_mut(usize::from(number))
            .ok_or(Error::Topology)
    }
    pub(super) fn find(&self, kind: Kind) -> Option<&Port> {
        self.ports.iter().find(|port| port.kind == kind)
    }
    /// The lanes' USB4 ports apart from the upstream one, in order, primary
    /// lanes only: the numbering `usb4_port_index` gives them.
    pub(super) fn usb4_index(&self, number: u8) -> usize {
        self.ports
            .iter()
            .filter(|port| {
                port.kind == Kind::Lane && port.number != self.upstream && port.lane == 0
            })
            .take_while(|port| port.number != number)
            .count()
    }
    /// The `kind` adapter that USB4 port `number` extends:
    /// `usb4_switch_map_pcie_down` and `usb4_switch_map_usb3_down`.
    pub(super) fn mapped(&self, number: u8, kind: Kind) -> Option<u8> {
        self.ports
            .iter()
            .filter(|port| port.kind == kind)
            .nth(self.usb4_index(number))
            .map(|port| port.number)
    }
    /// The UUID from `tb_switch_set_uuid`: fused, or the UID filled up with
    /// ones.
    pub(super) fn uuid(&self) -> [u32; 4] {
        self.fused_uuid
            .unwrap_or([self.uid as u32, (self.uid >> 32) as u32, !0, !0])
    }
}

impl Cm {
    pub(super) fn router(&self, route: u64) -> Result<&Router, Error> {
        self.routers.get(&route).ok_or(Error::Topology)
    }
    pub(super) fn router_mut(&mut self, route: u64) -> Result<&mut Router, Error> {
        self.routers.get_mut(&route).ok_or(Error::Topology)
    }
    pub(super) fn adapter(&self, route: u64, number: u8) -> Result<&Port, Error> {
        self.router(route)?.port(number)
    }
    pub(super) fn adapter_mut(&mut self, route: u64, number: u8) -> Result<&mut Port, Error> {
        self.router_mut(route)?.port_mut(number)
    }
    /// The capability of `port` at the offset in the adapter's registers.
    pub(super) fn capability(
        &self,
        route: u64,
        number: u8,
        select: fn(&Port) -> Option<u16>,
    ) -> Result<u16, Error> {
        select(self.adapter(route, number)?).ok_or(Error::Topology)
    }

    /// Find capability `id` on adapter `port`: `tb_port_find_cap`.
    async fn port_capability(
        &mut self,
        route: u64,
        port: u8,
        first: u16,
        id: u8,
    ) -> Result<Option<u16>, Error> {
        let mut offset = first;
        for _ in 0..64 {
            if offset == 0 {
                break;
            }
            let word = self.port_read(route, port, offset).await?;
            if (word >> 8) as u8 == id {
                return Ok(Some(offset));
            }
            offset = (word & 0xff) as u16;
        }
        Ok(None)
    }

    /// Find capability `id` on adapter `port` of any router: `tb_port_find_cap`.
    async fn find_port_capability(
        &mut self,
        route: u64,
        port: u8,
        first: u16,
        id: u8,
    ) -> Result<Option<u16>, Error> {
        let router = self.router(route)?;
        let controller = router.controller();
        let Some(access) = controller.tmu_access().filter(|_| !router.is_usb4()) else {
            return self.port_capability(route, port, first, id).await;
        };
        self.router_modify(route, access, 0, TMU_ACCESS_ENABLE)
            .await?;
        let found = self.port_capability(route, port, first, id).await;
        // Light Ridge repeats the next pointer on the following read.
        if controller == Controller::LightRidge {
            self.port_read(route, port, 0).await?;
        }
        self.router_modify(route, access, TMU_ACCESS_ENABLE, 0)
            .await?;
        found
    }

    /// Find capability `id` of the router: `tb_switch_find_cap`.
    pub(super) async fn router_capability(
        &mut self,
        route: u64,
        id: u8,
    ) -> Result<Option<u16>, Error> {
        self.walk_capabilities(route, |word| (word >> 8) as u8 == id)
            .await
    }

    /// Find vendor capability `id` of the router: `tb_switch_find_vse_cap`.
    pub(super) async fn vendor_capability(
        &mut self,
        route: u64,
        id: u8,
    ) -> Result<Option<u16>, Error> {
        self.walk_capabilities(route, |word| {
            (word >> 8) as u8 == CAP_VENDOR && (word >> 16) as u8 == id
        })
        .await
    }

    async fn walk_capabilities(
        &mut self,
        route: u64,
        wanted: impl Fn(u32) -> bool,
    ) -> Result<Option<u16>, Error> {
        let mut offset = self.router(route)?.first_capability();
        for _ in 0..64 {
            if offset == 0 {
                break;
            }
            let words = self.read(route, 0, Space::Router, offset, 2).await?;
            if wanted(words[0]) {
                return Ok(Some(offset));
            }
            offset = match (words[0] >> 8) as u8 {
                CAP_VENDOR if words[0] >> 24 == 0 => (words[1] & 0xffff) as u16,
                CAP_VENDOR | CAP_TIME => (words[0] & 0xff) as u16,
                _ => return Ok(None),
            };
        }
        Ok(None)
    }

    /// Identify the router at `route` and enumerate it: `tb_switch_alloc`,
    /// `tb_switch_configure` and `tb_switch_add`. It joins the domain only
    /// once it can be used.
    pub(super) async fn add_router(&mut self, route: u64) -> Result<(), Error> {
        if route != 0 {
            self.unlock(parent(route), port_at(route, depth(route) - 1))
                .await?;
        }
        let upstream = self.upstream_port(route).await?;
        let words = self.read(route, 0, Space::Router, 0, 5).await?;
        let mut header = [0; 5];
        header.copy_from_slice(&words);
        if depth(route) > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let mut router = Router {
            route,
            header,
            upstream,
            ports: Vec::new(),
            link_usb4: false,
            link_speed: 0,
            link_width: 0,
            credits: Credits::default(),
            uid: 0,
            fused_uuid: None,
            name: None,
            vendor_capabilities: Vendor::default(),
            tmu: Tmu::default(),
            authorized: route == 0,
            unplugged: false,
        };
        // A host router from before USB4 has its firmware's connection manager.
        if route == 0 && !router.is_usb4() {
            return Err(Error::Legacy);
        }
        router.ports = (0..=router.max_port()).map(Port::absent).collect();
        self.routers.insert(route, router);
        let added = self.bring_up(route).await;
        if added.is_err() {
            self.routers.remove(&route);
        }
        added
    }

    async fn bring_up(&mut self, route: u64) -> Result<(), Error> {
        let usb4 = self.router(route)?.is_usb4();
        if !usb4 {
            self.find_vendor_capabilities(route).await?;
        }
        self.configure(route).await?;
        let mut preferences = None;
        if usb4 {
            preferences = self.credit_preferences(route).await;
            let uid = self.read(route, 0, Space::Router, ROUTER_CS_7, 2).await?;
            self.router_mut(route)?.uid = u64::from(uid[0]) | u64::from(uid[1]) << 32;
        }
        for number in 1..=self.router(route)?.max_port() {
            self.init_port(route, number).await?;
        }
        let result = self.read_drom(route).await;
        self.note(route, "reading the DROM", result)?;
        if !usb4 {
            self.read_fused_uuid(route).await?;
        }
        self.link_default_ports(route)?;
        self.adopt_credits(route, preferences)?;
        self.update_link_attributes(route).await?;
        self.init_link(route).await?;
        self.init_tmu(route).await?;
        // `tb_switch_port_hotplug_enable`.
        for number in 1..=self.router(route)?.max_port() {
            if self.adapter(route, number)?.cap_usb4.is_some() {
                self.port_modify(route, number, ADP_CS_5, ADP_CS_5_DHP, 0)
                    .await?;
            }
        }
        Ok(())
    }

    /// Enumerate the router and set up what it may tunnel: `tb_switch_configure`.
    async fn configure(&mut self, route: u64) -> Result<(), Error> {
        let router = self.router_mut(route)?;
        let upstream = router.upstream;
        let usb4 = router.is_usb4();
        if !usb4 && router.vendor_capabilities.plug_events.is_none() {
            return Err(Error::Legacy);
        }
        let cmuv = match router.usb4_version() {
            0 => (router.header[4] >> 8) & 0xff,
            1 => CMUV_V1,
            _ => CMUV_V2,
        };
        let header = &mut router.header;
        header[1] =
            (header[1] & !((63 << 8) | (7 << 20))) | u32::from(upstream) << 8 | depth(route) << 20;
        header[2] = route as u32;
        header[3] = (route >> 32) as u32 | ROUTER_CS_3_V;
        // A 255 ms notification timeout on every router.
        header[4] = (header[4] & !0xffff) | cmuv << 8 | 0xff;
        let words = [header[1], header[2], header[3], header[4]];
        self.write(route, 0, Space::Router, ROUTER_CS_1, &words)
            .await?;
        if route == 0 {
            return Ok(());
        }
        if usb4 {
            self.setup_usb4(route).await
        } else {
            self.enable_plug_events(route).await
        }
    }

    /// Read the router's DROM, for the name it goes by and the ports it says
    /// are not there: `tb_drom_read`. A router has one if it can say so.
    async fn read_drom(&mut self, route: u64) -> Result<(), Error> {
        let (bytes, uid, usb4) = {
            let usb4 = self.router(route)?.is_usb4();
            let header = match self.drom_bytes(route, usb4, 14, 2).await {
                Ok(header) => header,
                Err(Error::Unsupported) => return Ok(()),
                Err(error) => return Err(error),
            };
            let mask = if usb4 { 0xfff } else { 0x3ff };
            let size = usize::from(u16::from_le_bytes([header[0], header[1]]) & mask);
            let bytes = self
                .drom_bytes(route, usb4, 0, size + drom::DATA_START)
                .await?;
            (bytes, self.router(route)?.uid, usb4)
        };
        let router = self.router_mut(route)?;
        let lanes: Vec<bool> = router
            .ports
            .iter()
            .map(|port| port.kind == Kind::Lane)
            .collect();
        let image = Image::parse(bytes, uid, router.max_port(), |port| {
            lanes.get(usize::from(port)).copied().unwrap_or(false)
        })
        .map_err(Error::Drom)?;
        if !usb4 {
            router.uid = image.uid;
        }
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).to_string();
        router.name = match (image.vendor_name(), image.device_name()) {
            (Some(vendor), Some(device)) => Some(format!("{} {}", text(vendor), text(device))),
            (vendor, device) => vendor.or(device).map(text),
        };
        for number in 1..=router.max_port() {
            let Some(found) = image.port(number) else {
                continue;
            };
            let port = router.port_mut(number)?;
            port.disabled |= found.disabled;
            if let Some(lane) = found.lane {
                port.lane = lane.link_number;
                port.dual = lane.dual_port;
            }
        }
        Ok(())
    }

    /// `count` bytes of the DROM at `offset`.
    async fn drom_bytes(
        &mut self,
        route: u64,
        usb4: bool,
        offset: usize,
        count: usize,
    ) -> Result<Vec<u8>, Error> {
        if !usb4 {
            let offset = u16::try_from(offset).map_err(|_| Error::Reply)?;
            return self.eeprom_read(route, offset, count).await;
        }
        let end = offset + count;
        let mut bytes = Vec::with_capacity(count + 3);
        let mut address = offset & !3;
        while address < end {
            let words = (end - address).div_ceil(4).min(OP_DATA_WORDS);
            let mut data = [0; OP_DATA_WORDS];
            self.drom_block(route, address, &mut data[..words]).await?;
            bytes.extend(data[..words].iter().flat_map(|word| word.to_le_bytes()));
            address += words * 4;
        }
        bytes.drain(..offset & 3);
        bytes.truncate(count);
        Ok(bytes)
    }

    /// `usb4_switch_drom_read_block`, with `tb_nvm_read_data`'s retries.
    async fn drom_block(
        &mut self,
        route: u64,
        address: usize,
        data: &mut [u32],
    ) -> Result<(), Error> {
        for _ in 0..DROM_RETRIES {
            let mut metadata = (data.len() as u32) << DROM_SIZE_SHIFT
                | ((address / 4) as u32) << DROM_ADDRESS_SHIFT;
            if self
                .router_operation(route, OP_DROM_READ, &mut metadata, data)
                .await?
                == 0
            {
                return Ok(());
            }
        }
        Err(Error::Reply)
    }

    /// `usb4_switch_setup`: PCIe tunnels are offered whatever the approval
    /// policy, which decides on the tunnels themselves.
    async fn setup_usb4(&mut self, route: u64) -> Result<(), Error> {
        let status = self.router_read(route, ROUTER_CS_6).await?;
        let above = parent(route);
        let down = port_at(route, depth(route) - 1);
        let parent_router = self.router(above)?;
        let usb3 = parent_router.find(Kind::Usb3Down).is_some();
        let pcie = parent_router.find(Kind::PcieDown).is_some();
        let usb4 = match parent_router.port(down)?.cap_usb4 {
            Some(cap) => self.port_read(above, down, cap + PORT_CS_18).await? & PORT_CS_18_TCM == 0,
            None => false,
        };
        self.router_mut(route)?.link_usb4 = usb4;
        let mut xhci = status & ROUTER_CS_6_HCI != 0;
        let mut value = self.router_read(route, ROUTER_CS_5).await?;
        if usb4 && usb3 {
            value |= ROUTER_CS_5_UTO;
            xhci = false;
        }
        if pcie {
            value |= ROUTER_CS_5_PTO;
            if xhci {
                value |= ROUTER_CS_5_HCO;
            }
        }
        value &= !ROUTER_CS_5_CNS;
        self.router_write(route, ROUTER_CS_5, value).await?;
        self.router_wait(route, ROUTER_CS_6, ROUTER_CS_6_RR, ROUTER_CS_6_RR, 500)
            .await
    }

    /// `usb4_switch_configuration_valid`.
    pub(super) async fn configuration_valid(&mut self, route: u64) -> Result<(), Error> {
        if route == 0 || !self.router(route)?.is_usb4() {
            return Ok(());
        }
        self.router_modify(route, ROUTER_CS_5, 0, ROUTER_CS_5_CV)
            .await?;
        self.router_wait(route, ROUTER_CS_6, ROUTER_CS_6_CR, ROUTER_CS_6_CR, 500)
            .await
    }

    /// The router's preferred buffer allocation, indexed by `BA_*`, if it
    /// has one: `usb4_switch_credits_init`.
    async fn credit_preferences(&mut self, route: u64) -> Option<[Option<u32>; 6]> {
        let mut metadata = 0;
        let mut data = [0; OP_DATA_WORDS];
        let status = self
            .router_operation(route, OP_BUFFER_ALLOC, &mut metadata, &mut data)
            .await;
        let length = (metadata & 0xff) as usize;
        if !matches!(status, Ok(0)) || length > data.len() {
            return None;
        }
        let mut values = [None; 6];
        for word in &data[..length] {
            if let Some(slot) = values.get_mut(usize::from(*word as u16)) {
                *slot = Some(word >> 16);
            }
        }
        Some(values)
    }

    /// Use the preferences if they cover the router's adapters, or the
    /// fixed defaults.
    fn adopt_credits(
        &mut self,
        route: u64,
        preferences: Option<[Option<u32>; 6]>,
    ) -> Result<(), Error> {
        let Some(values) = preferences else {
            return Ok(());
        };
        let value = |index: u16| values[usize::from(index)];
        let router = self.router_mut(route)?;
        let any = |kinds: &[Kind]| router.ports.iter().any(|port| kinds.contains(&port.kind));
        let lanes = router
            .ports
            .iter()
            .filter(|port| port.kind == Kind::Lane)
            .count();
        let (aux, main) = (value(BA_MIN_DP_AUX), value(BA_MIN_DP_MAIN));
        let incomplete = (route == 0 && value(BA_MAX_HI).is_none())
            || (lanes > 2 && (aux.is_none() || main.is_none()))
            || (any(&[Kind::DpOut]) && main.is_none())
            || (any(&[Kind::DpIn, Kind::DpOut]) && aux.is_none())
            || (any(&[Kind::Usb3Down, Kind::Usb3Up]) && value(BA_MAX_USB3).is_none())
            || (any(&[Kind::PcieDown, Kind::PcieUp]) && value(BA_MAX_PCIE).is_none());
        if !incomplete {
            router.credits = Credits {
                allocation: true,
                max_usb3: value(BA_MAX_USB3).unwrap_or(0),
                min_dp_aux: aux.unwrap_or(0),
                min_dp_main: main.unwrap_or(0),
                max_pcie: value(BA_MAX_PCIE).unwrap_or(0),
            };
        }
        Ok(())
    }

    /// `tb_init_port`.
    async fn init_port(&mut self, route: u64, number: u8) -> Result<(), Error> {
        let words = match self.read(route, number, Space::Port, 0, 8).await {
            Ok(words) => words,
            Err(Error::NotImplemented) => {
                self.adapter_mut(route, number)?.disabled = true;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let kind = Kind::of(words[2]);
        let first = (words[1] & 0xff) as u16;
        let (mut phy, mut usb4, mut adapter) = (None, None, None);
        let mut control = 0;
        if kind == Kind::Lane {
            phy = self
                .find_port_capability(route, number, first, CAP_PHY)
                .await?;
            usb4 = self
                .find_port_capability(route, number, first, CAP_USB4)
                .await?;
            if usb4.is_some()
                && let Ok(hop) = self.read(route, number, Space::Hops, 0, 2).await
            {
                control = (hop[0] >> HOP_INITIAL_CREDITS_SHIFT) & 0x7f;
            }
            if control == 0 {
                control = 2;
            }
        } else {
            adapter = self
                .find_port_capability(route, number, first, CAP_ADAPTER)
                .await?;
        }
        let time = self
            .find_port_capability(route, number, first, CAP_TIME)
            .await?;
        let port = self.adapter_mut(route, number)?;
        port.kind = kind;
        port.cap_phy = phy;
        port.cap_usb4 = usb4;
        port.cap_adapter = adapter;
        port.cap_time = time;
        port.control_credits = control;
        port.buffers = words[4];
        port.total_credits = (words[4] & ADP_CS_4_TOTAL_BUFFERS) >> ADP_CS_4_TOTAL_SHIFT;
        port.hops_in.limit_to((words[5] & 0x7ff) as u16);
        port.hops_out.limit_to(((words[5] >> 11) & 0x7ff) as u16);
        Ok(())
    }

    /// Pair adjacent lane adapters into USB4 ports:
    /// `tb_switch_default_link_ports`.
    fn link_default_ports(&mut self, route: u64) -> Result<(), Error> {
        let router = self.router_mut(route)?;
        for number in 1..usize::from(router.max_port()) {
            if router.ports[number].kind == Kind::Lane
                && router.ports[number + 1].kind == Kind::Lane
                && router.ports[number].dual.is_none()
                && router.ports[number + 1].dual.is_none()
            {
                router.ports[number].dual = Some(number as u8 + 1);
                router.ports[number + 1].dual = Some(number as u8);
                router.ports[number + 1].lane = 1;
            }
        }
        Ok(())
    }

    /// `tb_port_get_link_speed`, in Gb/s.
    pub(super) async fn link_speed(&mut self, route: u64, port: u8) -> Result<u32, Error> {
        let phy = self.capability(route, port, |port| port.cap_phy)?;
        let word = self.port_read(route, port, phy + LANE_ADP_CS_1).await?;
        Ok(match (word >> LANE_ADP_CS_1_SPEED_SHIFT) & 15 {
            LANE_ADP_CS_1_GEN4 => 40,
            LANE_ADP_CS_1_GEN3 => 20,
            _ => 10,
        })
    }

    /// `tb_port_get_link_width`.
    pub(super) async fn link_width(&mut self, route: u64, port: u8) -> Result<u32, Error> {
        let phy = self.capability(route, port, |port| port.cap_phy)?;
        let word = self.port_read(route, port, phy + LANE_ADP_CS_1).await?;
        Ok((word >> LANE_ADP_CS_1_WIDTH_SHIFT) & 63)
    }

    /// `tb_switch_update_link_attributes`.
    async fn update_link_attributes(&mut self, route: u64) -> Result<(), Error> {
        if route == 0 {
            return Ok(());
        }
        let up = self.router(route)?.upstream;
        let speed = self.link_speed(route, up).await?;
        let width = self.link_width(route, up).await?;
        let router = self.router_mut(route)?;
        router.link_speed = speed;
        router.link_width = width;
        Ok(())
    }

    /// `tb_port_update_credits`.
    async fn update_credits(&mut self, route: u64, number: u8) -> Result<(), Error> {
        let dual = self.adapter(route, number)?.dual;
        for number in core::iter::once(number).chain(dual) {
            let buffers = self.port_read(route, number, ADP_CS_4).await?;
            let port = self.adapter_mut(route, number)?;
            port.buffers = buffers;
            port.total_credits = (buffers & ADP_CS_4_TOTAL_BUFFERS) >> ADP_CS_4_TOTAL_SHIFT;
        }
        Ok(())
    }

    fn set_bonded(&mut self, route: u64, number: u8, bonded: bool) -> Result<(), Error> {
        let port = self.adapter_mut(route, number)?;
        port.bonded = bonded;
        if let Some(dual) = port.dual {
            self.adapter_mut(route, dual)?.bonded = bonded;
        }
        Ok(())
    }

    /// `tb_switch_link_init`: links can come up bonded.
    async fn init_link(&mut self, route: u64) -> Result<(), Error> {
        if route == 0 {
            return Ok(());
        }
        let router = self.router(route)?;
        let (up, bonded) = (router.upstream, router.link_width >= WIDTH_DUAL);
        let (above, down) = (parent(route), port_at(route, depth(route) - 1));
        self.set_bonded(route, up, bonded)?;
        self.update_credits(route, up).await?;
        self.set_bonded(above, down, bonded)?;
        self.update_credits(above, down).await
    }

    /// `tb_port_lane_bonding_enable`.
    async fn bond_port(&mut self, route: u64, number: u8, upstream: bool) -> Result<(), Error> {
        let phy = self.capability(route, number, |port| port.cap_phy)?;
        let dual = self.adapter(route, number)?.dual.ok_or(Error::Topology)?;
        let dual_phy = self.capability(route, dual, |port| port.cap_phy)?;
        let width = |word: u32| (word >> LANE_ADP_CS_1_WIDTH_SHIFT) & 63;
        for (number, phy) in [(number, phy), (dual, dual_phy)] {
            let word = self.port_read(route, number, phy + LANE_ADP_CS_1).await?;
            if width(word) == WIDTH_SINGLE {
                self.port_write(
                    route,
                    number,
                    phy + LANE_ADP_CS_1,
                    (word & !LANE_ADP_CS_1_TARGET_WIDTH) | LANE_ADP_CS_1_TARGET_DUAL,
                )
                .await?;
            }
        }
        let second = self
            .port_read(route, dual, dual_phy + LANE_ADP_CS_1)
            .await?;
        if width(second) == WIDTH_SINGLE && !upstream {
            self.port_modify(route, number, phy + LANE_ADP_CS_1, 0, LANE_ADP_CS_1_LB)
                .await?;
        }
        self.set_bonded(route, number, true)
    }

    /// `tb_port_width_supported`.
    async fn width_supported(&mut self, route: u64, port: u8, width: u32) -> bool {
        let Ok(phy) = self.capability(route, port, |port| port.cap_phy) else {
            return false;
        };
        self.port_read(route, port, phy + LANE_ADP_CS_0)
            .await
            .is_ok_and(|word| (word >> LANE_ADP_CS_0_WIDTH_SHIFT) & 63 & width != 0)
    }

    /// Bond the router's link to its parent if both ends can:
    /// `tb_switch_lane_bonding_enable` through `tb_switch_set_link_width`.
    async fn bond_link(&mut self, route: u64) -> Result<(), Error> {
        let router = self.router(route)?;
        let up = router.upstream;
        let (above, down) = (parent(route), port_at(route, depth(route) - 1));
        let (up_cap, usb4) = (router.port(up)?.cap_usb4, router.is_usb4());
        let up_dual = router.port(up)?.dual;
        let down_dual = self.adapter(above, down)?.dual;
        let (Some(_), Some(down_dual)) = (up_dual, down_dual) else {
            return Ok(());
        };
        let possible = match up_cap {
            Some(cap) => self.port_read(route, up, cap + PORT_CS_18).await? & PORT_CS_18_BE != 0,
            None => !usb4 && self.lc_bonding_possible(route).await?,
        };
        if !possible
            || !self.width_supported(route, up, WIDTH_DUAL).await
            || !self.width_supported(above, down, WIDTH_DUAL).await
            || !self.wait_for_port(above, down_dual).await?
        {
            return Ok(());
        }
        self.bond_port(route, up, true).await?;
        self.bond_port(above, down, false).await?;
        let phy = self.capability(above, down, |port| port.cap_phy)?;
        let bonded = (WIDTH_DUAL | WIDTH_ASYM_TX | WIDTH_ASYM_RX) << LANE_ADP_CS_1_WIDTH_SHIFT;
        let deadline = self.platform.now_ms() + 100;
        loop {
            match self.port_read(above, down, phy + LANE_ADP_CS_1).await {
                Ok(word) if word & bonded != 0 => break,
                // The lanes report themselves locked while they bond.
                Ok(_) | Err(Error::Locked) => {}
                Err(error) => return Err(error),
            }
            if self.platform.now_ms() >= deadline {
                return Err(Error::Timeout);
            }
        }
        self.update_credits(above, down).await?;
        self.update_credits(route, up).await?;
        self.update_link_attributes(route).await
    }

    /// Tie the router to its parent, bond the link and mark both ends
    /// configured: `tb_configure_link`.
    pub(super) async fn configure_link(&mut self, route: u64) -> Result<(), Error> {
        let up = self.router(route)?.upstream;
        let (above, down) = (parent(route), port_at(route, depth(route) - 1));
        let up_dual = self.adapter(route, up)?.dual;
        let down_dual = self.adapter(above, down)?.dual;
        self.adapter_mut(above, down)?.remote = Some((route, up));
        self.adapter_mut(route, up)?.remote = Some((above, down));
        if let (Some(up_dual), Some(down_dual)) = (up_dual, down_dual) {
            self.adapter_mut(above, down_dual)?.remote = Some((route, up_dual));
            self.adapter_mut(route, up_dual)?.remote = Some((above, down_dual));
        }
        if self.router(route)?.link_width < WIDTH_DUAL {
            // A link that stays single lane still carries tunnels.
            if let Err(error @ Error::Channel(_)) = self.bond_link(route).await {
                return Err(error);
            }
        }
        for (route, port) in [(route, up), (above, down)] {
            self.mark_configured(route, port, true).await?;
        }
        Ok(())
    }

    /// `usb4_port_configure` or `tb_lc_configure_port`, and their opposites.
    async fn mark_configured(
        &mut self,
        route: u64,
        port: u8,
        configured: bool,
    ) -> Result<(), Error> {
        let Some(cap) = self.adapter(route, port)?.cap_usb4 else {
            return self.lc_set_configured(route, port, configured).await;
        };
        let value = if configured { PORT_CS_19_PC } else { 0 };
        self.port_modify(route, port, cap + PORT_CS_19, PORT_CS_19_PC, value)
            .await
    }

    /// The upstream router's half of `tb_switch_unconfigure_link`, after an unplug.
    pub(super) async fn unconfigure_link(&mut self, route: u64, port: u8) -> Result<(), Error> {
        self.mark_configured(route, port, false).await
    }

    /// `usb4_port_unlock`: make the router below `port` reachable.
    async fn unlock(&mut self, route: u64, port: u8) -> Result<(), Error> {
        if !self.router(route)?.is_usb4() {
            return Ok(());
        }
        self.port_modify(route, port, ADP_CS_4, ADP_CS_4_LCK, 0)
            .await
    }

    /// Wait for the lane to come up, as `tb_wait_for_port` does: whether a
    /// link is up.
    pub(super) async fn wait_for_port(&mut self, route: u64, port: u8) -> Result<bool, Error> {
        let phy = self.capability(route, port, |port| port.cap_phy)?;
        for _ in 0..10 {
            let words = self.read(route, port, Space::Port, phy, 2).await?;
            // `struct tb_cap_phy`: 16 + 16 + 14 + 1 + 11 bits before the state.
            let state = (words[1] >> 26) & 15;
            match state {
                PORT_STATE_DISABLED | PORT_STATE_UNPLUGGED => return Ok(false),
                PORT_STATE_UP..=PORT_STATE_CL2 => return Ok(true),
                _ => self.sleep(100).await?,
            }
        }
        Ok(false)
    }

    /// Issue a downstream port reset: `usb4_port_reset`.
    pub(super) async fn reset_port(&mut self, route: u64, port: u8) -> Result<(), Error> {
        let cap = self.capability(route, port, |port| port.cap_usb4)?;
        self.port_modify(route, port, cap + PORT_CS_19, 0, PORT_CS_19_DPR)
            .await?;
        self.sleep(10).await?;
        self.port_modify(route, port, cap + PORT_CS_19, PORT_CS_19_DPR, 0)
            .await
    }

    /// Clear what boot firmware left behind in the host router:
    /// `tb_switch_reset_host`.
    pub(super) async fn reset_host(&mut self) -> Result<(), Error> {
        for number in 1..=self.router(0)?.max_port() {
            let port = self.adapter(0, number)?;
            let (kind, lane, limit) = (port.kind, port.lane, port.hops_in.limit());
            match kind {
                Kind::Lane if number == self.router(0)?.upstream => continue,
                Kind::Lane if port.cap_usb4.is_some() => self.reset_port(0, number).await?,
                Kind::Lane => {}
                Kind::Usb3Down | Kind::Usb3Up => self.enable_usb3_adapter(0, number, false).await?,
                Kind::DpIn | Kind::DpOut => self.enable_dp_adapter(0, number, false).await?,
                Kind::PcieDown | Kind::PcieUp => self.enable_pcie_adapter(0, number, false).await?,
                _ => continue,
            }
            // Lane 1 adapters have no path configuration space on USB4.
            if kind == Kind::Lane && lane != 0 {
                continue;
            }
            for hop in MIN_HOP..=limit {
                self.deactivate_hop(0, number, hop, true).await?;
            }
        }
        Ok(())
    }
}
