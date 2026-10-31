// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! PCIe, USB3 and DisplayPort tunnels: Linux tunnel.c and the adapter
//! operations of switch.c and usb4.c.
use super::{
    Cm, Error,
    legacy::Controller,
    path::{ALL, Adapter, INTERNAL, Path, SOURCE},
    regs::*,
    router::{Kind, depth},
};
use crate::bus::thunderbolt::config::Space;
use alloc::vec::Vec;

const PCIE_HOP: u16 = 8;
const PCIE_PRIORITY: u32 = 3;
const PCIE_WEIGHT: u32 = 1;
const MIN_PCIE_CREDITS: u32 = 6;
const USB3_HOP: u16 = 8;
const USB3_PRIORITY: u32 = 3;
const USB3_WEIGHT: u32 = 2;
const DP_AUX_HOP: u16 = 8;
const DP_VIDEO_HOP: u16 = 9;
const DP_AUX_PRIORITY: u32 = 2;
const DP_AUX_WEIGHT: u32 = 1;
const DP_VIDEO_PRIORITY: u32 = 1;
const DP_VIDEO_WEIGHT: u32 = 1;
/// The VESA spec gives DPRX negotiation 5 s; graphics drivers poll for new
/// connections every 10 s.
const DPRX_MS: u64 = 12_000;
/// A USB4 v2 link keeps this much for PCIe and USB3 bulk traffic.
pub(super) const V2_PCIE_MINIMUM: u32 = 1500 * PCIE_WEIGHT;
const V2_USB3_MINIMUM: u32 = 1500 * USB3_WEIGHT;

/// What a tunnel carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Pcie,
    Usb3,
    DisplayPort,
}

/// Bandwidth in Mb/s, upstream and downstream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Bandwidth {
    pub up: u32,
    pub down: u32,
}

#[derive(Debug)]
pub(super) struct Tunnel {
    pub protocol: Protocol,
    pub source: Adapter,
    pub destination: Adapter,
    pub paths: Vec<Path>,
    /// A USB3 tunnel from the host router: what it is allocated.
    pub allocated: Bandwidth,
    /// A DisplayPort tunnel: the bandwidth it may use.
    pub limit: Bandwidth,
    /// A DisplayPort tunnel: when DPRX has to be done by, while it is not.
    pub dprx: Option<u64>,
}

impl Tunnel {
    pub(super) fn on_port(&self, adapter: Adapter) -> bool {
        self.paths.iter().any(|path| path.on_port(adapter))
    }
    pub(super) fn downstream(&self) -> bool {
        depth(self.source.0) < depth(self.destination.0)
    }
}

/// `tb_dp_bandwidth`: tunneling removes the 8b/10b encoding.
fn dp_bandwidth(rate: u32, lanes: u32) -> u32 {
    rate * lanes * 8 / 10
}

/// A capability's maximum rate, in Mb/s per lane: `tb_dp_cap_get_rate`.
fn dp_rate(cap: u32) -> u32 {
    match (cap & DP_CAP_RATE) >> DP_CAP_RATE_SHIFT {
        1 => 2700,
        2 => 5400,
        3 => 8100,
        _ => 1620,
    }
}

/// `tb_dp_cap_get_lanes`.
fn dp_lanes(cap: u32) -> u32 {
    match (cap & DP_CAP_LANES) >> DP_CAP_LANES_SHIFT {
        1 => 2,
        2 => 4,
        _ => 1,
    }
}

/// A capability limited to `rate` and `lanes`: `tb_dp_cap_set_rate` and
/// `tb_dp_cap_set_lanes`.
fn dp_limit(cap: u32, rate: u32, lanes: u32) -> u32 {
    let rate = match rate {
        2700 => 1,
        5400 => 2,
        8100 => 3,
        _ => 0,
    };
    let lanes = match lanes {
        2 => 1,
        4 => 2,
        _ => 0,
    };
    (cap & !(DP_CAP_RATE | DP_CAP_LANES)) | rate << DP_CAP_RATE_SHIFT | lanes << DP_CAP_LANES_SHIFT
}

/// The largest rate and lane count that fits `limit` Mb/s:
/// `tb_dp_reduce_bandwidth`.
fn dp_reduce(limit: u32, input: u32, output: u32) -> Option<(u32, u32)> {
    const MODES: [(u32, u32); 12] = [
        (8100, 4),
        (5400, 4),
        (8100, 2),
        (2700, 4),
        (5400, 2),
        (8100, 1),
        (1620, 4),
        (5400, 1),
        (2700, 2),
        (1620, 2),
        (2700, 1),
        (1620, 1),
    ];
    MODES.into_iter().find(|&(rate, lanes)| {
        rate <= dp_rate(output)
            && lanes <= dp_lanes(output)
            && rate <= dp_rate(input)
            && lanes <= dp_lanes(input)
            && dp_bandwidth(rate, lanes) <= limit
    })
}

/// `usb3_bw_to_mbps`.
fn usb3_mbps(value: u32, scale: u32) -> u32 {
    ((u64::from(value) * (512 << scale) * 8000 + 500_000) / 1_000_000) as u32
}

/// `mbps_to_usb3_bw`.
fn usb3_units(mbps: u32, scale: u32) -> u32 {
    (u64::from(mbps) * 1_000_000 / 8000).div_ceil(512 << scale) as u32
}

impl Cm {
    /// `tb_available_credits`: what PCIe can have of the lane adapter once
    /// USB3 and as many DP streams as fit have their share, and that stream
    /// count.
    fn available_credits(&self, adapter: Adapter) -> Result<(u32, u32), Error> {
        let router = self.router(adapter.0)?;
        let credits = router.credits;
        let usable = router.port(adapter.1)?.usable_credits();
        let stream = credits.min_dp_aux + credits.min_dp_main;
        let streams = (usable.saturating_sub(credits.max_usb3 + credits.max_pcie))
            .checked_div(stream)
            .unwrap_or(0);
        let left = usable
            .saturating_sub(streams * stream)
            .saturating_sub(credits.max_usb3);
        Ok((left, streams))
    }

    /// `tb_pci_init_credits` and `tb_usb3_init_credits`.
    fn bulk_credits(&self, adapter: Adapter, protocol: Protocol) -> Result<u32, Error> {
        let router = self.router(adapter.0)?;
        let port = router.port(adapter.1)?;
        if port.kind == Kind::Lane && router.credits.allocation {
            return match protocol {
                Protocol::Usb3 => Ok(router.credits.max_usb3),
                _ => {
                    let (available, _) = self.available_credits(adapter)?;
                    let credits = router.credits.max_pcie.min(available);
                    if credits < MIN_PCIE_CREDITS {
                        Err(Error::NoCredits)
                    } else {
                        Ok(credits)
                    }
                }
            };
        }
        Ok(match (port.kind == Kind::Lane, port.bonded) {
            (true, true) => 32,
            (true, false) => 16,
            (false, _) => 7,
        })
    }

    fn init_bulk_path(&self, path: &mut Path, protocol: Protocol) -> Result<(), Error> {
        path.egress_flow = SOURCE | INTERNAL;
        path.ingress_flow = ALL;
        (path.priority, path.weight) = match protocol {
            Protocol::Usb3 => (USB3_PRIORITY, USB3_WEIGHT),
            _ => (PCIE_PRIORITY, PCIE_WEIGHT),
        };
        for hop in &mut path.hops {
            hop.initial_credits = self.bulk_credits((hop.route, hop.input), protocol)?;
        }
        Ok(())
    }

    /// Reserve `count` paths with `init` and return them, or none of them.
    fn allocate_paths(
        &mut self,
        wanted: &[(Adapter, u16, Adapter, u16)],
        link: u8,
        init: impl Fn(&Self, usize, &mut Path) -> Result<(), Error>,
    ) -> Result<Vec<Path>, Error> {
        let mut paths = Vec::with_capacity(wanted.len());
        for (index, &(source, source_hop, destination, destination_hop)) in
            wanted.iter().enumerate()
        {
            let allocated = self
                .allocate_path(source, source_hop, destination, destination_hop, link)
                .and_then(|mut path| match init(self, index, &mut path) {
                    Ok(()) => Ok(path),
                    Err(error) => {
                        self.free_path(&path);
                        Err(error)
                    }
                });
            match allocated {
                Ok(path) => paths.push(path),
                Err(error) => {
                    for path in &paths {
                        self.free_path(path);
                    }
                    return Err(error);
                }
            }
        }
        Ok(paths)
    }

    async fn activate_paths(&mut self, tunnel: &mut Tunnel) -> Result<(), Error> {
        for path in &mut tunnel.paths {
            self.activate_path(path).await?;
        }
        Ok(())
    }

    /// Stop what `tunnel` has started, adapters first: `tb_tunnel_deactivate`.
    pub(super) async fn deactivate_tunnel(&mut self, tunnel: &mut Tunnel) -> Result<(), Error> {
        let stopped = match tunnel.protocol {
            Protocol::Pcie => self.stop_pcie(tunnel).await,
            Protocol::Usb3 => self.stop_usb3(tunnel).await,
            Protocol::DisplayPort => self.stop_dp(tunnel).await,
        };
        let mut result = stopped;
        for path in &mut tunnel.paths {
            if path.active {
                let done = self.deactivate_path(path).await;
                result = result.and(done);
            }
        }
        result
    }

    /// Free the paths of a tunnel that will not run.
    pub(super) fn free_tunnel(&mut self, tunnel: &Tunnel) {
        for path in &tunnel.paths {
            self.free_path(path);
        }
    }

    fn is_present(&self, adapter: Adapter) -> bool {
        self.routers
            .get(&adapter.0)
            .is_some_and(|router| !router.unplugged)
    }

    /// Whether an adapter carries a tunnel: `tb_port_is_enabled`.
    pub(super) async fn adapter_enabled(&mut self, adapter: Adapter) -> Result<bool, Error> {
        let (route, number) = adapter;
        let port = self.adapter(route, number)?;
        let Some(cap) = port.cap_adapter else {
            return Ok(false);
        };
        let word = self.port_read(route, number, cap).await?;
        Ok(match self.adapter(route, number)?.kind {
            Kind::PcieDown | Kind::PcieUp => word & ADP_PCIE_CS_0_PE != 0,
            Kind::Usb3Down | Kind::Usb3Up => word & ADP_USB3_CS_0_PE != 0,
            Kind::DpIn | Kind::DpOut => word & (ADP_DP_CS_0_VE | ADP_DP_CS_0_AE) != 0,
            _ => false,
        })
    }

    /// `tb_pci_port_enable`.
    pub(super) async fn enable_pcie_adapter(
        &mut self,
        route: u64,
        port: u8,
        enable: bool,
    ) -> Result<(), Error> {
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let word = if enable { ADP_PCIE_CS_0_PE } else { 0 };
        self.port_write(route, port, cap + ADP_PCIE_CS_0, word)
            .await
    }

    /// `tb_usb3_port_enable`.
    pub(super) async fn enable_usb3_adapter(
        &mut self,
        route: u64,
        port: u8,
        enable: bool,
    ) -> Result<(), Error> {
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let word = if enable {
            ADP_USB3_CS_0_PE | ADP_USB3_CS_0_V
        } else {
            0
        };
        self.port_write(route, port, cap + ADP_USB3_CS_0, word)
            .await
    }

    /// `tb_dp_port_enable`.
    pub(super) async fn enable_dp_adapter(
        &mut self,
        route: u64,
        port: u8,
        enable: bool,
    ) -> Result<(), Error> {
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let both = ADP_DP_CS_0_VE | ADP_DP_CS_0_AE;
        let value = if enable { both } else { 0 };
        self.port_modify(route, port, cap + ADP_DP_CS_0, both, value)
            .await
    }

    /// `tb_dp_port_hpd_is_active`.
    pub(super) async fn dp_hot_plugged(&mut self, route: u64, port: u8) -> Result<bool, Error> {
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        Ok(self.port_read(route, port, cap + ADP_DP_CS_2).await? & ADP_DP_CS_2_HPD != 0)
    }

    /// Set a DP adapter's HopIDs: `tb_dp_port_set_hops`.
    async fn set_dp_hops(
        &mut self,
        adapter: Adapter,
        video: u16,
        aux_tx: u16,
        aux_rx: u16,
    ) -> Result<(), Error> {
        let (route, port) = adapter;
        if self.router(route)?.is_usb4() {
            return Ok(());
        }
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let mut words = self
            .read(route, port, Space::Port, cap + ADP_DP_CS_0, 2)
            .await?;
        words[0] = (words[0] & !ADP_DP_CS_0_VIDEO) | u32::from(video) << ADP_DP_CS_0_VIDEO_SHIFT;
        words[1] = (words[1] & !(ADP_DP_CS_1_AUX_TX | ADP_DP_CS_1_AUX_RX))
            | u32::from(aux_tx)
            | u32::from(aux_rx) << ADP_DP_CS_1_AUX_RX_SHIFT;
        self.write(route, port, Space::Port, cap + ADP_DP_CS_0, &words)
            .await
    }

    /// Wait for the PCIe adapter's LTSSM to be in Detect:
    /// `tb_pci_port_ltssm_state_detect`.
    async fn pcie_detect(&mut self, adapter: Adapter) -> Result<(), Error> {
        let (route, port) = adapter;
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        self.port_wait(
            route,
            port,
            cap + ADP_PCIE_CS_0,
            ADP_PCIE_CS_0_LTSSM,
            0,
            500,
        )
        .await
    }

    /// Set up PCIe tunnel from `down` to `up`: `tb_tunnel_alloc_pci` and
    /// `tb_tunnel_activate`.
    pub(super) async fn start_pcie(&mut self, up: Adapter, down: Adapter) -> Result<(), Error> {
        let paths = self.allocate_paths(
            &[
                (down, PCIE_HOP, up, PCIE_HOP),
                (up, PCIE_HOP, down, PCIE_HOP),
            ],
            0,
            |cm, _, path| cm.init_bulk_path(path, Protocol::Pcie),
        )?;
        let mut tunnel = Tunnel {
            protocol: Protocol::Pcie,
            source: down,
            destination: up,
            paths,
            allocated: Bandwidth::default(),
            limit: Bandwidth::default(),
            dprx: None,
        };
        let started = self.activate_pcie(&mut tunnel).await;
        self.finish_activation(tunnel, started).await
    }

    async fn activate_pcie(&mut self, tunnel: &mut Tunnel) -> Result<(), Error> {
        let (down, up) = (tunnel.source, tunnel.destination);
        self.pcie_detect(down).await?;
        self.pcie_detect(up).await?;
        self.activate_paths(tunnel).await?;
        self.set_pcie_encapsulation(tunnel, true).await?;
        self.enable_pcie_adapter(up.0, up.1, true).await?;
        self.enable_pcie_adapter(down.0, down.1, true).await
    }

    /// `tb_pci_set_ext_encapsulation`.
    async fn set_pcie_encapsulation(&mut self, tunnel: &Tunnel, enable: bool) -> Result<(), Error> {
        let (down, up) = (tunnel.source, tunnel.destination);
        if self.router(down.0)?.usb4_version() < 2 || self.router(up.0)?.usb4_version() < 2 {
            return Ok(());
        }
        let lane = self.router(up.0)?.upstream;
        if enable && self.link_speed(up.0, lane).await? < 40 {
            return Ok(());
        }
        let value = if enable { ADP_PCIE_CS_1_EE } else { 0 };
        for (route, port) in [down, up] {
            if !self.is_present((route, port)) {
                continue;
            }
            let cap = self.capability(route, port, |port| port.cap_adapter)?;
            self.port_modify(route, port, cap + ADP_PCIE_CS_1, ADP_PCIE_CS_1_EE, value)
                .await?;
        }
        Ok(())
    }

    async fn stop_pcie(&mut self, tunnel: &Tunnel) -> Result<(), Error> {
        let (down, up) = (tunnel.source, tunnel.destination);
        if self.is_present(down) {
            self.enable_pcie_adapter(down.0, down.1, false).await?;
        }
        if self.is_present(up) {
            // The router below can be gone.
            self.enable_pcie_adapter(up.0, up.1, false).await.ok();
        }
        if self.is_present(down) {
            self.set_pcie_encapsulation(tunnel, false).await?;
        }
        Ok(())
    }

    /// `usb4_usb3_port_cm_request`.
    async fn usb3_request(&mut self, adapter: Adapter, request: bool) -> Result<(), Error> {
        let (route, port) = adapter;
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let value = if request { ADP_USB3_CS_2_CMR } else { 0 };
        self.port_modify(route, port, cap + ADP_USB3_CS_2, ADP_USB3_CS_2_CMR, value)
            .await?;
        self.port_wait(
            route,
            port,
            cap + ADP_USB3_CS_1,
            ADP_USB3_CS_1_HCA,
            if request { ADP_USB3_CS_1_HCA } else { 0 },
            1500,
        )
        .await
    }

    /// `usb4_usb3_port_read_consumed_bandwidth`.
    async fn usb3_consumed(&mut self, adapter: Adapter) -> Result<Bandwidth, Error> {
        let (route, port) = adapter;
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let word = self.port_read(route, port, cap + ADP_USB3_CS_1).await?;
        let scale = self.port_read(route, port, cap + ADP_USB3_CS_3).await? & ADP_USB3_CS_3_SCALE;
        Ok(Bandwidth {
            up: usb3_mbps(word & ADP_USB3_CS_1_CUBW, scale),
            down: usb3_mbps((word >> ADP_USB3_CS_1_CDBW_SHIFT) & 0xfff, scale),
        })
    }

    /// `usb4_usb3_port_write_allocated_bandwidth`.
    async fn usb3_write_allocated(
        &mut self,
        adapter: Adapter,
        bandwidth: Bandwidth,
    ) -> Result<(), Error> {
        let (route, port) = adapter;
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let most = bandwidth.up.max(bandwidth.down);
        let scale = (0..64)
            .find(|&scale| usb3_units(most, scale) < 4096)
            .ok_or(Error::NoBandwidth)?;
        self.port_write(route, port, cap + ADP_USB3_CS_3, scale)
            .await?;
        self.port_modify(
            route,
            port,
            cap + ADP_USB3_CS_2,
            ADP_USB3_CS_2_AUBW | ADP_USB3_CS_2_ADBW,
            usb3_units(bandwidth.up, scale)
                | usb3_units(bandwidth.down, scale) << ADP_USB3_CS_2_ADBW_SHIFT,
        )
        .await
    }

    /// `usb4_usb3_port_allocate_bandwidth`: never below what is consumed.
    async fn usb3_allocate(
        &mut self,
        adapter: Adapter,
        wanted: Bandwidth,
    ) -> Result<Bandwidth, Error> {
        self.usb3_request(adapter, true).await?;
        let allocated: Result<_, Error> = async {
            let consumed = self.usb3_consumed(adapter).await?;
            let bandwidth = Bandwidth {
                up: wanted.up.max(consumed.up),
                down: wanted.down.max(consumed.down),
            };
            self.usb3_write_allocated(adapter, bandwidth).await?;
            Ok(bandwidth)
        }
        .await;
        let cleared = self.usb3_request(adapter, false).await;
        let bandwidth = allocated?;
        cleared.map(|()| bandwidth)
    }

    /// `usb4_usb3_port_release_bandwidth`: 900 Mb/s stays for isochronous
    /// traffic.
    async fn usb3_release(&mut self, adapter: Adapter) -> Result<Bandwidth, Error> {
        self.usb3_request(adapter, true).await?;
        let released: Result<_, Error> = async {
            let consumed = self.usb3_consumed(adapter).await?;
            let bandwidth = Bandwidth {
                up: consumed.up.max(900),
                down: consumed.down.max(900),
            };
            self.usb3_write_allocated(adapter, bandwidth).await?;
            Ok(bandwidth)
        }
        .await;
        let cleared = self.usb3_request(adapter, false).await;
        let bandwidth = released?;
        cleared.map(|()| bandwidth)
    }

    /// `usb4_usb3_port_max_link_rate`.
    async fn usb3_rate(&mut self, adapter: Adapter) -> Result<u32, Error> {
        let (route, port) = adapter;
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        let word = self.port_read(route, port, cap + ADP_USB3_CS_4).await?;
        Ok(
            if (word & ADP_USB3_CS_4_MSLR) >> ADP_USB3_CS_4_MSLR_SHIFT == ADP_USB3_CS_4_MSLR_20G {
                20_000
            } else {
                10_000
            },
        )
    }

    /// 90% of the slower adapter's link rate may be isochronous:
    /// `tb_usb3_max_link_rate`.
    async fn usb3_limit(&mut self, up: Adapter, down: Adapter) -> Result<u32, Error> {
        let rate = self.usb3_rate(up).await?.min(self.usb3_rate(down).await?);
        Ok(rate * 90 / 100)
    }

    /// `tb_tunnel_alloc_usb3` and `tb_tunnel_activate`. A tunnel from the
    /// host router holds the bandwidth of everything behind it.
    pub(super) async fn start_usb3(
        &mut self,
        up: Adapter,
        down: Adapter,
        available: Bandwidth,
    ) -> Result<(), Error> {
        let first = down.0 == 0;
        let limit = if first {
            self.usb3_limit(up, down).await?
        } else {
            0
        };
        let paths = self.allocate_paths(
            &[
                (down, USB3_HOP, up, USB3_HOP),
                (up, USB3_HOP, down, USB3_HOP),
            ],
            0,
            |cm, _, path| cm.init_bulk_path(path, Protocol::Usb3),
        )?;
        let mut tunnel = Tunnel {
            protocol: Protocol::Usb3,
            source: down,
            destination: up,
            paths,
            allocated: Bandwidth {
                up: limit.min(available.up),
                down: limit.min(available.down),
            },
            limit: Bandwidth::default(),
            dprx: None,
        };
        let started = self.activate_usb3(&mut tunnel).await;
        self.finish_activation(tunnel, started).await
    }

    async fn activate_usb3(&mut self, tunnel: &mut Tunnel) -> Result<(), Error> {
        let (down, up) = (tunnel.source, tunnel.destination);
        if down.0 == 0 {
            tunnel.allocated = self.usb3_allocate(down, tunnel.allocated).await?;
        }
        self.activate_paths(tunnel).await?;
        self.enable_usb3_adapter(down.0, down.1, true).await?;
        self.enable_usb3_adapter(up.0, up.1, true).await
    }

    async fn stop_usb3(&mut self, tunnel: &Tunnel) -> Result<(), Error> {
        let (down, up) = (tunnel.source, tunnel.destination);
        if self.is_present(down) {
            self.enable_usb3_adapter(down.0, down.1, false).await?;
        }
        if self.is_present(up) {
            self.enable_usb3_adapter(up.0, up.1, false).await.ok();
        }
        Ok(())
    }

    /// `tb_usb3_consumed_bandwidth`: PCIe shares what USB3 leaves, by weight.
    pub(super) async fn usb3_tunnel_consumed(&mut self, index: usize) -> Result<Bandwidth, Error> {
        let tunnel = &self.tunnels[index];
        let allocated = tunnel.allocated;
        let lane = (
            tunnel.destination.0,
            self.router(tunnel.destination.0)?.upstream,
        );
        let grow = |value: u32| value * (USB3_WEIGHT + PCIE_WEIGHT) / USB3_WEIGHT;
        let minimum = if self.link_speed(lane.0, lane.1).await? >= 40 {
            V2_USB3_MINIMUM
        } else {
            0
        };
        Ok(Bandwidth {
            up: grow(allocated.up).max(minimum),
            down: grow(allocated.down).max(minimum),
        })
    }

    /// `tb_usb3_release_unused_bandwidth`.
    pub(super) async fn usb3_release_unused(&mut self, index: usize) -> Result<(), Error> {
        let down = self.tunnels[index].source;
        self.tunnels[index].allocated = self.usb3_release(down).await?;
        Ok(())
    }

    /// `tb_usb3_reclaim_available_bandwidth`.
    pub(super) async fn usb3_reclaim(
        &mut self,
        index: usize,
        available: Bandwidth,
    ) -> Result<(), Error> {
        let tunnel = &self.tunnels[index];
        let (down, up, allocated) = (tunnel.source, tunnel.destination, tunnel.allocated);
        let limit = self.usb3_limit(up, down).await?;
        if allocated.up >= limit && allocated.down >= limit {
            return Ok(());
        }
        let wanted = Bandwidth {
            up: limit.min(available.up).max(allocated.up),
            down: limit.min(available.down).max(allocated.down),
        };
        if wanted != allocated {
            self.tunnels[index].allocated = self.usb3_allocate(down, wanted).await?;
        }
        Ok(())
    }

    /// `tb_dp_init_video_credits` for one hop.
    fn video_credits(&self, adapter: Adapter) -> Result<u32, Error> {
        let router = self.router(adapter.0)?;
        let port = router.port(adapter.1)?;
        if port.kind == Kind::Lane && router.credits.allocation {
            let (_, streams) = self.available_credits(adapter)?;
            if router.credits.min_dp_main == 0
                || port.nfc_credits() / router.credits.min_dp_main > streams
            {
                return Err(Error::NoCredits);
            }
            return Ok(router.credits.min_dp_main);
        }
        Ok(port.total_credits.saturating_sub(2).min(12))
    }

    fn init_dp_path(&self, path: &mut Path, video: bool) -> Result<(), Error> {
        path.egress_flow = if video { 0 } else { SOURCE | INTERNAL };
        path.ingress_flow = if video { 0 } else { ALL };
        (path.priority, path.weight) = if video {
            (DP_VIDEO_PRIORITY, DP_VIDEO_WEIGHT)
        } else {
            (DP_AUX_PRIORITY, DP_AUX_WEIGHT)
        };
        let v2 = self
            .router(path.hops.first().ok_or(Error::Topology)?.route)?
            .usb4_version()
            >= 2;
        for index in 0..path.hops.len() {
            let hop = path.hops[index];
            let router = self.router(hop.route)?;
            let adapter = (hop.route, hop.input);
            let lanes = router.port(hop.input)?.kind == Kind::Lane
                && router.port(hop.output)?.kind == Kind::Lane;
            let hop = &mut path.hops[index];
            hop.power_managed = v2 && lanes && router.usb4_version() >= 2;
            if video {
                hop.nfc_credits = self.video_credits(adapter)?;
            } else if router.port(adapter.1)?.kind == Kind::Lane && router.credits.allocation {
                hop.initial_credits = router.credits.min_dp_aux;
            } else {
                hop.initial_credits = 1;
            }
        }
        Ok(())
    }

    /// `tb_dp_cm_handshake`.
    async fn dp_handshake(&mut self, out: Adapter) -> Result<(), Error> {
        let (route, port) = out;
        let cap = self.capability(route, port, |port| port.cap_adapter)?;
        self.port_modify(
            route,
            port,
            cap + DP_STATUS_CTRL,
            0,
            DP_STATUS_CTRL_UF | DP_STATUS_CTRL_CMHS,
        )
        .await?;
        self.port_wait(
            route,
            port,
            cap + DP_STATUS_CTRL,
            DP_STATUS_CTRL_CMHS,
            0,
            3000,
        )
        .await
    }

    /// `tb_dp_xchg_caps`.
    async fn dp_exchange_capabilities(&mut self, tunnel: &Tunnel) -> Result<(), Error> {
        let (input, output) = (tunnel.source, tunnel.destination);
        let (from, to) = (self.router(input.0)?, self.router(output.0)?);
        if from.generation() < 2 || to.generation() < 2 {
            return Ok(());
        }
        // Titan Ridge leaves its AUX timers on for LTTPR.
        let no_lttpr = output.0 != 0 && to.controller() == Controller::TitanRidge;
        if from.dp_is_usb4() && to.dp_is_usb4() {
            self.dp_handshake(output).await?;
        }
        let in_cap = self.capability(input.0, input.1, |port| port.cap_adapter)?;
        let out_cap = self.capability(output.0, output.1, |port| port.cap_adapter)?;
        let local_in = self
            .port_read(input.0, input.1, in_cap + DP_LOCAL_CAP)
            .await?;
        let mut local_out = self
            .port_read(output.0, output.1, out_cap + DP_LOCAL_CAP)
            .await?;
        self.port_write(output.0, output.1, out_cap + DP_REMOTE_CAP, local_in)
            .await?;
        let limit = if tunnel.downstream() {
            tunnel.limit.down
        } else {
            tunnel.limit.up
        };
        if limit != 0 && dp_bandwidth(dp_rate(local_out), dp_lanes(local_out)) > limit {
            let (rate, lanes) = dp_reduce(limit, local_in, local_out).ok_or(Error::NoBandwidth)?;
            local_out = dp_limit(local_out, rate, lanes);
        }
        if no_lttpr {
            local_out |= DP_COMMON_CAP_LTTPR_NS;
        }
        self.port_write(input.0, input.1, in_cap + DP_REMOTE_CAP, local_out)
            .await
    }

    /// Set up a DP tunnel: `tb_tunnel_alloc_dp` and `tb_tunnel_activate`.
    /// The tunnel counts as up once DPRX is done, which [`Cm::poll_dprx`] sees.
    pub(super) async fn start_dp(
        &mut self,
        input: Adapter,
        output: Adapter,
        link: u8,
        limit: Bandwidth,
    ) -> Result<(), Error> {
        let paths = self.allocate_paths(
            &[
                (input, DP_VIDEO_HOP, output, DP_VIDEO_HOP),
                (input, DP_AUX_HOP, output, DP_AUX_HOP),
                (output, DP_AUX_HOP, input, DP_AUX_HOP),
            ],
            link,
            |cm, index, path| cm.init_dp_path(path, index == 0),
        )?;
        let mut tunnel = Tunnel {
            protocol: Protocol::DisplayPort,
            source: input,
            destination: output,
            paths,
            allocated: Bandwidth::default(),
            limit,
            dprx: self
                .router(input.0)?
                .dp_is_usb4()
                .then(|| self.platform.now_ms() + DPRX_MS),
        };
        let started = self.activate_dp(&mut tunnel).await;
        self.finish_activation(tunnel, started).await
    }

    async fn activate_dp(&mut self, tunnel: &mut Tunnel) -> Result<(), Error> {
        self.dp_exchange_capabilities(tunnel).await?;
        self.activate_paths(tunnel).await?;
        let last = |path: &Path| path.hops.last().map_or(0, |hop| hop.output_hop);
        let first = |path: &Path| path.hops.first().map_or(0, |hop| hop.input_hop);
        let [video, aux_out, aux_in] = tunnel.paths.as_slice() else {
            return Err(Error::Topology);
        };
        let (at_input, at_output) = (
            (first(video), first(aux_out), last(aux_in)),
            (last(video), first(aux_in), last(aux_out)),
        );
        let (input, output) = (tunnel.source, tunnel.destination);
        self.set_dp_hops(input, at_input.0, at_input.1, at_input.2)
            .await?;
        self.set_dp_hops(output, at_output.0, at_output.1, at_output.2)
            .await?;
        self.enable_dp_adapter(input.0, input.1, true).await?;
        self.enable_dp_adapter(output.0, output.1, true).await
    }

    async fn stop_dp(&mut self, tunnel: &Tunnel) -> Result<(), Error> {
        let (input, output) = (tunnel.source, tunnel.destination);
        if self.is_present(input) {
            let cap = self.capability(input.0, input.1, |port| port.cap_adapter)?;
            self.port_modify(input.0, input.1, cap + ADP_DP_CS_3, 0, ADP_DP_CS_3_HPDC)
                .await?;
            self.set_dp_hops(input, 0, 0, 0).await?;
            self.enable_dp_adapter(input.0, input.1, false).await?;
        }
        if self.is_present(output) {
            self.set_dp_hops(output, 0, 0, 0).await.ok();
            self.enable_dp_adapter(output.0, output.1, false).await.ok();
        }
        Ok(())
    }

    /// Whether DPRX negotiation of the tunnel's DP IN is done.
    pub(super) async fn dprx_done(&mut self, input: Adapter) -> Result<bool, Error> {
        let cap = self.capability(input.0, input.1, |port| port.cap_adapter)?;
        let word = self
            .port_read(input.0, input.1, cap + DP_COMMON_CAP)
            .await?;
        Ok(word & DP_COMMON_CAP_DPRX_DONE != 0)
    }

    /// `tb_dp_consumed_bandwidth`: what DPRX agreed, or what was reserved
    /// while it negotiates.
    pub(super) async fn dp_consumed(&mut self, index: usize) -> Result<Bandwidth, Error> {
        let tunnel = &self.tunnels[index];
        let (input, down) = (tunnel.source, tunnel.downstream());
        let router = self.router(input.0)?;
        // Thunderbolt 1 has no bandwidth management.
        if router.generation() < 2 {
            return Ok(Bandwidth::default());
        }
        let modern = router.dp_is_usb4();
        let cap = self.capability(input.0, input.1, |port| port.cap_adapter)?;
        let register = if modern && self.dprx_done(input).await? {
            DP_COMMON_CAP
        } else {
            DP_REMOTE_CAP
        };
        let word = self.port_read(input.0, input.1, cap + register).await?;
        let bandwidth = dp_bandwidth(dp_rate(word), dp_lanes(word));
        Ok(if down {
            Bandwidth {
                up: 0,
                down: bandwidth,
            }
        } else {
            Bandwidth {
                up: bandwidth,
                down: 0,
            }
        })
    }

    /// Keep a started tunnel, or undo what its activation did and report why not.
    async fn finish_activation(
        &mut self,
        mut tunnel: Tunnel,
        started: Result<(), Error>,
    ) -> Result<(), Error> {
        match started {
            Ok(()) => {
                self.tunnels.push(tunnel);
                Ok(())
            }
            Err(error @ Error::Channel(_)) => Err(error),
            Err(error) => {
                self.deactivate_tunnel(&mut tunnel).await.ok();
                self.free_tunnel(&tunnel);
                Err(error)
            }
        }
    }
}

/// The bandwidth a USB4 v2 link keeps in reserve for PCIe, if `pcie` adapters
/// are at both its ends: `tb_tunnel_reserved_pci`.
pub(super) fn reserved_pcie(speed: u32, pcie: bool) -> Bandwidth {
    if speed >= 40 && pcie {
        Bandwidth {
            up: V2_PCIE_MINIMUM,
            down: V2_PCIE_MINIMUM,
        }
    } else {
        Bandwidth::default()
    }
}
