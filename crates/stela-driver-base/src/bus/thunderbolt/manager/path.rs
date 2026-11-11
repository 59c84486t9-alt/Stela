// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! Protocol paths across the domain's routers: Linux path.c.
use super::{
    Cm, Error,
    regs::*,
    router::{Kind, depth, parent, port_at},
};
use crate::bus::thunderbolt::config::Space;
use alloc::vec::Vec;

/// `enum tb_path_port`.
pub(super) const SOURCE: u8 = 1;
pub(super) const INTERNAL: u8 = 2;
pub(super) const DESTINATION: u8 = 4;
pub(super) const ALL: u8 = SOURCE | INTERNAL | DESTINATION;

/// An adapter: its router's route and its number.
pub(super) type Adapter = (u64, u8);

/// One router's forwarding entry on a path.
#[derive(Clone, Copy, Debug)]
pub(super) struct Hop {
    pub route: u64,
    pub input: u8,
    pub input_hop: u16,
    pub output: u8,
    pub output_hop: u16,
    pub initial_credits: u32,
    pub nfc_credits: u32,
    pub power_managed: bool,
}

/// `struct tb_path`, reserved in the domain's HopID allocators from
/// [`Cm::allocate_path`] until [`Cm::free_path`].
#[derive(Debug)]
pub(super) struct Path {
    pub hops: Vec<Hop>,
    pub egress_flow: u8,
    pub ingress_flow: u8,
    pub priority: u32,
    pub weight: u32,
    pub clear_flow: bool,
    pub active: bool,
}

impl Path {
    pub(super) fn on_port(&self, adapter: Adapter) -> bool {
        self.hops.iter().any(|hop| {
            hop.route == adapter.0 && (hop.input == adapter.1 || hop.output == adapter.1)
        })
    }
}

impl Cm {
    /// The ports a path uses through each router from `source` to
    /// `destination`, primary lanes only: `tb_next_port_on_path`.
    pub(super) fn walk(
        &self,
        source: Adapter,
        destination: Adapter,
    ) -> Result<Vec<(u64, u8, u8)>, Error> {
        let (mut up, mut down) = (source.0, destination.0);
        let mut climb = Vec::new();
        let mut descend = Vec::new();
        while up != down {
            if depth(up) >= depth(down) {
                climb.push(up);
                up = parent(up);
            } else {
                descend.push(down);
                down = parent(down);
            }
        }
        climb.push(up);
        climb.extend(descend.iter().rev());
        let mut steps = Vec::with_capacity(climb.len());
        let mut input = source.1;
        for (index, &route) in climb.iter().enumerate() {
            let Some(&next) = climb.get(index + 1) else {
                steps.push((route, input, destination.1));
                break;
            };
            let (output, next_input) = if depth(next) < depth(route) {
                (self.router(route)?.upstream, port_at(route, depth(next)))
            } else {
                (port_at(next, depth(route)), self.router(next)?.upstream)
            };
            steps.push((route, input, output));
            input = next_input;
        }
        Ok(steps)
    }

    /// Reserve HopIDs for a path: `tb_path_alloc`. `link` is the lane
    /// preferred on links that are not bonded.
    pub(super) fn allocate_path(
        &mut self,
        source: Adapter,
        source_hop: u16,
        destination: Adapter,
        destination_hop: u16,
        link: u8,
    ) -> Result<Path, Error> {
        let steps = self.walk(source, destination)?;
        let mut path = Path {
            hops: Vec::with_capacity(steps.len()),
            egress_flow: 0,
            ingress_flow: 0,
            priority: 0,
            weight: 0,
            clear_flow: false,
            active: false,
        };
        let mut input_hop = source_hop;
        for (index, &(route, input, output)) in steps.iter().enumerate() {
            let last = index + 1 == steps.len();
            let reserved = self.reserve_hop(route, input, input_hop, output, link, {
                if last { Some(destination_hop) } else { None }
            });
            match reserved {
                Ok(hop) => {
                    input_hop = hop.output_hop;
                    path.hops.push(hop);
                }
                Err(error) => {
                    self.free_path(&path);
                    return Err(error);
                }
            }
        }
        Ok(path)
    }

    fn reserve_hop(
        &mut self,
        route: u64,
        input: u8,
        input_hop: u16,
        output: u8,
        link: u8,
        output_hop: Option<u16>,
    ) -> Result<Hop, Error> {
        let choose = |port: &super::router::Port, other: bool| match port.dual {
            Some(dual) if other => dual,
            _ => port.number,
        };
        let router = self.router(route)?;
        let port = router.port(input)?;
        let input = choose(port, !port.bonded && port.lane != link);
        let bonded_input = router.port(input)?.bonded;
        let port = router.port(output)?;
        let output = choose(
            port,
            (!bonded_input && port.bonded && port.lane != 0) || (!port.bonded && port.lane != link),
        );
        let router = self.router_mut(route)?;
        let input_hop = router
            .port_mut(input)?
            .hops_in
            .take(Some(input_hop))
            .ok_or(Error::NoHopId)?;
        let Some(output_hop) = router.port_mut(output)?.hops_out.take(output_hop) else {
            router.port_mut(input)?.hops_in.release(input_hop);
            return Err(Error::NoHopId);
        };
        Ok(Hop {
            route,
            input,
            input_hop,
            output,
            output_hop,
            initial_credits: 0,
            nfc_credits: 0,
            power_managed: false,
        })
    }

    /// Return the path's HopIDs: `tb_path_free`. Routers that left the
    /// domain took theirs with them.
    pub(super) fn free_path(&mut self, path: &Path) {
        for hop in &path.hops {
            if let Ok(router) = self.router_mut(hop.route) {
                if let Ok(port) = router.port_mut(hop.input) {
                    port.hops_in.release(hop.input_hop);
                }
                if let Ok(port) = router.port_mut(hop.output) {
                    port.hops_out.release(hop.output_hop);
                }
            }
        }
    }

    /// Whether the router can still be spoken to.
    fn present(&self, route: u64) -> bool {
        self.routers
            .get(&route)
            .is_some_and(|router| !router.unplugged)
    }

    /// `tb_port_add_nfc_credits`: only lane adapters have them on USB4.
    async fn add_nfc_credits(&mut self, hop: Hop, credits: i32) -> Result<(), Error> {
        // USB4 keeps NFC buffers to lane adapters.
        if credits == 0
            || !self.present(hop.route)
            || (self.router(hop.route)?.is_usb4()
                && self.adapter(hop.route, hop.input)?.kind != Kind::Lane)
        {
            return Ok(());
        }
        let port = self.adapter_mut(hop.route, hop.input)?;
        let current = port.nfc_credits() as i32;
        let updated = (current + credits.max(-current)) as u32;
        let buffers = (port.buffers & !ADP_CS_4_NFC_BUFFERS) | updated;
        port.buffers = buffers;
        self.port_write(hop.route, hop.input, ADP_CS_4, buffers)
            .await
    }

    /// `__tb_path_deactivate_hop`: an idle entry stays as it is.
    pub(super) async fn deactivate_hop(
        &mut self,
        route: u64,
        port: u8,
        hop: u16,
        clear_flow: bool,
    ) -> Result<(), Error> {
        let offset = 2 * hop;
        let mut words = self.read(route, port, Space::Hops, offset, 2).await?;
        if words[0] & HOP_ENABLE == 0 {
            return Ok(());
        }
        words[0] &= !HOP_ENABLE;
        self.write(route, port, Space::Hops, offset, &words).await?;
        let deadline = self.platform.now_ms() + 500;
        loop {
            let mut words = self.read(route, port, Space::Hops, offset, 2).await?;
            if words[1] & HOP_PENDING == 0 {
                if !clear_flow {
                    return Ok(());
                }
                if self.adapter(route, port)?.kind == Kind::Lane {
                    words[1] &= !(HOP_INGRESS_FC | HOP_INGRESS_SHARED);
                }
                words[1] &= !(HOP_EGRESS_FC | HOP_EGRESS_SHARED);
                return self.write(route, port, Space::Hops, offset, &words).await;
            }
            if self.platform.now_ms() >= deadline {
                return Err(Error::Timeout);
            }
        }
    }

    /// Stop the path's hops from `first` on, keeping going past a failure
    /// so that one gone router does not leave the rest of the path running.
    async fn deactivate_hops(&mut self, path: &Path, first: usize) -> Result<(), Error> {
        let mut result = Ok(());
        for hop in &path.hops[first..] {
            if !self.present(hop.route) {
                continue;
            }
            let done = self
                .deactivate_hop(hop.route, hop.input, hop.input_hop, path.clear_flow)
                .await;
            if let (Err(error), Ok(())) = (done, &result) {
                if matches!(error, Error::Channel(_)) {
                    return Err(error);
                }
                if !error.gone() {
                    result = Err(error);
                }
            }
        }
        result
    }

    async fn deallocate_nfc(&mut self, path: &Path, first: usize) -> Result<(), Error> {
        for hop in &path.hops[first..] {
            self.add_nfc_credits(*hop, -(hop.nfc_credits as i32))
                .await?;
        }
        Ok(())
    }

    /// `tb_path_deactivate`.
    pub(super) async fn deactivate_path(&mut self, path: &mut Path) -> Result<(), Error> {
        let stopped = self.deactivate_hops(path, 0).await;
        let released = self.deallocate_nfc(path, 0).await;
        path.active = false;
        stopped.and(released)
    }

    /// `tb_path_activate`: NFC credits last hop first, then the hops from
    /// the source on.
    pub(super) async fn activate_path(&mut self, path: &mut Path) -> Result<(), Error> {
        for index in (0..path.hops.len()).rev() {
            let hop = path.hops[index];
            if let Err(error) = self.add_nfc_credits(hop, hop.nfc_credits as i32).await {
                self.deallocate_nfc(path, index + 1).await.ok();
                return Err(error);
            }
        }
        for index in 0..path.hops.len() {
            if let Err(error) = self.program_hop(path, index).await {
                if matches!(error, Error::Channel(_)) {
                    return Err(error);
                }
                self.deactivate_hops(path, 0).await.ok();
                self.deallocate_nfc(path, 0).await.ok();
                return Err(error);
            }
        }
        path.active = true;
        Ok(())
    }

    async fn program_hop(&mut self, path: &Path, index: usize) -> Result<(), Error> {
        let hop = path.hops[index];
        let offset = 2 * hop.input_hop;
        // Left active by someone else.
        self.deactivate_hop(hop.route, hop.input, hop.input_hop, path.clear_flow)
            .await
            .ok();
        // USB4 routers need the entry read before it is written.
        let words = self
            .read(hop.route, hop.input, Space::Hops, offset, 2)
            .await?;
        let out_mask = if index + 1 == path.hops.len() {
            DESTINATION
        } else {
            INTERNAL
        };
        let in_mask = if index == 0 { SOURCE } else { INTERNAL };
        let mut first = u32::from(hop.output_hop)
            | u32::from(hop.output) << 11
            | u32::from(hop.power_managed) << 24
            | HOP_ENABLE;
        // A counter index of all ones with its enable clear: no counter.
        let mut second = path.weight | path.priority << 8 | 0x7ff << 12;
        if path.egress_flow & out_mask != 0 {
            second |= HOP_EGRESS_FC;
        }
        // Credits and input flow control of a protocol adapter are vendor
        // defined on USB4, and stay as they read.
        if self.adapter(hop.route, hop.input)?.kind == Kind::Lane
            || !self.router(hop.route)?.is_usb4()
        {
            first |= hop.initial_credits << HOP_INITIAL_CREDITS_SHIFT;
            if path.ingress_flow & in_mask != 0 {
                second |= HOP_INGRESS_FC;
            }
        } else {
            first |= words[0] & (0x7f << HOP_INITIAL_CREDITS_SHIFT);
            second |= words[1] & (HOP_INGRESS_FC | HOP_INGRESS_SHARED);
        }
        self.write(hop.route, hop.input, Space::Hops, offset, &[first, second])
            .await
    }
}
