// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019 Intel Corporation
// Authors: Mika Westerberg <mika.westerberg@linux.intel.com>
//          Rajmohan Mani <rajmohan.mani@intel.com>
//! Time synchronization across the domain: Linux tmu.c, for the modes a
//! domain without CL states uses. The host router runs LowRes, each link
//! between two USB4 v2 routers enhanced uni-directional, any other link
//! bi-directional HiFi.
use super::{
    Cm, Error,
    regs::*,
    router::{depth, parent, port_at},
};
use crate::bus::thunderbolt::config::Space;

/// `TS_PACKET_INTERVAL` of each mode, in microseconds: `tmu_rates`.
const LOW_RESOLUTION_RATE: u32 = 1000;
const HIGH_FIDELITY_RATE: u32 = 16;
/// `tmu_params` of the enhanced uni-directional mode.
const ENHANCED_WINDOW: u32 = 800;
const ENHANCED_AVERAGE: u32 = 4;
const ENHANCED_REPLICA_TIMEOUT: u32 = 3125;
const ENHANCED_REPLICA_THRESHOLD: u32 = 25;
const ENHANCED_REPLICA_N: u32 = 128;
const ENHANCED_DIRECTION_SWITCH_N: u32 = 255;

/// What the router's time management unit runs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Mode {
    #[default]
    Off,
    LowResolution,
    HighFidelity,
    EnhancedUnidirectional,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Tmu {
    pub capability: Option<u16>,
    pub mode: Mode,
    /// `has_ucap`: its adapters have a uni-directional mode to leave.
    pub unidirectional: bool,
}

impl Cm {
    /// `tb_switch_tmu_init`, for what `tmu_mode_init` tells of a router
    /// enumerated from reset: a nonzero rate means firmware left it running.
    pub(super) async fn init_tmu(&mut self, route: u64) -> Result<(), Error> {
        let capability = self.router_capability(route, CAP_TIME).await?;
        let mode = match capability {
            Some(cap) if self.tmu_rate(route, cap).await? != 0 => Mode::HighFidelity,
            _ => Mode::Off,
        };
        let unidirectional = match capability {
            Some(cap) => {
                self.router_read(route, cap + TMU_RTR_CS_0).await? & TMU_RTR_CS_0_UCAP != 0
            }
            None => false,
        };
        self.router_mut(route)?.tmu = Tmu {
            capability,
            mode,
            unidirectional,
        };
        Ok(())
    }

    async fn tmu_rate(&mut self, route: u64, capability: u16) -> Result<u32, Error> {
        let word = self.router_read(route, capability + TMU_RTR_CS_3).await?;
        Ok(word >> TMU_RTR_CS_3_INTERVAL_SHIFT)
    }

    async fn set_tmu_rate(&mut self, route: u64, capability: u16, rate: u32) -> Result<(), Error> {
        self.router_modify(
            route,
            capability + TMU_RTR_CS_3,
            TMU_RTR_CS_3_INTERVAL,
            rate << TMU_RTR_CS_3_INTERVAL_SHIFT,
        )
        .await
    }

    async fn set_time_disruption(
        &mut self,
        route: u64,
        capability: u16,
        disrupted: bool,
    ) -> Result<(), Error> {
        let router = self.router(route)?;
        let (offset, bit) = if router.is_usb4() {
            (capability + TMU_RTR_CS_0, TMU_RTR_CS_0_TD)
        } else if let Some(time) = router.vendor_capabilities.time {
            (time + TIME_VSEC_CS_26, TIME_VSEC_CS_26_TD)
        } else {
            return Ok(());
        };
        let value = if disrupted { bit } else { 0 };
        self.router_modify(route, offset, bit, value).await
    }

    /// `tb_port_tmu_time_sync`: the bit disables synchronization.
    async fn enable_time_sync(&mut self, route: u64, port: u8) -> Result<(), Error> {
        let Some(cap) = self.adapter(route, port)?.cap_time else {
            return Ok(());
        };
        self.port_modify(route, port, cap + TMU_ADP_CS_6, TMU_ADP_CS_6_DTS, 0)
            .await
    }

    /// Point the new router at the grandmaster's time: `tb_switch_tmu_post_time`.
    async fn post_time(&mut self, route: u64, capability: u16) -> Result<(), Error> {
        let Some(host) = self.router(0)?.tmu.capability else {
            return Ok(());
        };
        let local = self
            .read(0, 0, Space::Router, host + TMU_RTR_CS_1, 3)
            .await?;
        let time = u64::from(local[2] & TMU_RTR_CS_3_LOCAL_TIME) << 48
            | u64::from(local[1]) << 16
            | u64::from(local[0] >> TMU_RTR_CS_1_LOCAL_TIME_SHIFT);
        self.set_time_disruption(route, capability, true).await?;
        let posted = self.post_local_time(route, capability, time).await;
        let cleared = self.set_time_disruption(route, capability, false).await;
        posted.and(cleared)
    }

    async fn post_local_time(
        &mut self,
        route: u64,
        capability: u16,
        time: u64,
    ) -> Result<(), Error> {
        self.write(
            route,
            0,
            Space::Router,
            capability + TMU_RTR_CS_22,
            &[time as u32, (time >> 32) as u32],
        )
        .await?;
        let post = capability + TMU_RTR_CS_24;
        self.write(route, 0, Space::Router, post, &[1, !0]).await?;
        self.router_write(route, capability + TMU_RTR_CS_25, 0)
            .await?;
        for _ in 0..100 {
            let words = self.read(route, 0, Space::Router, post, 2).await?;
            if words == [0, 0] {
                return Ok(());
            }
        }
        Err(Error::Timeout)
    }

    /// The host router's half: `tb_switch_tmu_configure` with LowRes and
    /// `tb_switch_tmu_enable`.
    pub(super) async fn enable_host_tmu(&mut self) -> Result<(), Error> {
        let Some(capability) = self.router(0)?.tmu.capability else {
            return Ok(());
        };
        self.set_time_disruption(0, capability, true).await?;
        let enabled = self.set_tmu_rate(0, capability, LOW_RESOLUTION_RATE).await;
        let cleared = self.set_time_disruption(0, capability, false).await;
        enabled.and(cleared)?;
        self.router_mut(0)?.tmu.mode = Mode::LowResolution;
        Ok(())
    }

    /// Synchronize a device router to its parent: `tb_enable_tmu`.
    pub(super) async fn enable_tmu(&mut self, route: u64) -> Result<(), Error> {
        let Some(capability) = self.router(route)?.tmu.capability else {
            return Ok(());
        };
        let above = parent(route);
        let enhanced =
            self.router(route)?.usb4_version() > 1 && self.router(above)?.usb4_version() > 1;
        let wanted = if enhanced {
            Mode::EnhancedUnidirectional
        } else {
            Mode::HighFidelity
        };
        if self.router(route)?.tmu.mode == wanted {
            return Ok(());
        }
        if self.router(route)?.is_usb4() {
            self.post_time(route, capability).await?;
        }
        self.set_time_disruption(route, capability, true).await?;
        let enabled = if enhanced {
            self.enable_enhanced(route, capability).await
        } else {
            self.enable_bidirectional(route, capability).await
        };
        let cleared = self.set_time_disruption(route, capability, false).await;
        enabled.and(cleared)?;
        self.router_mut(route)?.tmu.mode = wanted;
        Ok(())
    }

    /// `tb_switch_tmu_enable_bidirectional`.
    async fn enable_bidirectional(&mut self, route: u64, capability: u16) -> Result<(), Error> {
        let up = self.router(route)?.upstream;
        let (above, down) = (parent(route), port_at(route, depth(route) - 1));
        if self.router(route)?.tmu.unidirectional {
            for (route, port) in [(route, up), (above, down)] {
                let Some(cap) = self.adapter(route, port)?.cap_time else {
                    continue;
                };
                self.port_modify(route, port, cap + TMU_ADP_CS_3, TMU_ADP_CS_3_UDM, 0)
                    .await?;
            }
        }
        self.set_tmu_rate(route, capability, HIGH_FIDELITY_RATE)
            .await?;
        self.enable_time_sync(route, up).await?;
        self.enable_time_sync(above, down).await
    }

    /// `tb_switch_tmu_enable_enhanced`.
    async fn enable_enhanced(&mut self, route: u64, capability: u16) -> Result<(), Error> {
        self.router_modify(
            route,
            capability + TMU_RTR_CS_0,
            TMU_RTR_CS_0_FREQ_WIND,
            ENHANCED_WINDOW << TMU_RTR_CS_0_FREQ_WIND_SHIFT,
        )
        .await?;
        let average = (0..4).fold(0, |word, field| word | ENHANCED_AVERAGE << (6 * field));
        self.router_modify(
            route,
            capability + TMU_RTR_CS_15,
            TMU_RTR_CS_15_AVERAGES,
            average,
        )
        .await?;
        self.router_modify(
            route,
            capability + TMU_RTR_CS_18,
            TMU_RTR_CS_18_DELTA_AVG,
            0,
        )
        .await?;
        let up = self.router(route)?.upstream;
        let (above, down) = (parent(route), port_at(route, depth(route) - 1));
        for (route, port) in [(route, up), (above, down)] {
            let cap = self.capability(route, port, |port| port.cap_time)?;
            self.port_modify(
                route,
                port,
                cap + TMU_ADP_CS_8,
                TMU_ADP_CS_8_REPL_TIMEOUT | TMU_ADP_CS_8_REPL_THRESHOLD,
                ENHANCED_REPLICA_TIMEOUT
                    | ENHANCED_REPLICA_THRESHOLD << TMU_ADP_CS_8_REPL_THRESHOLD_SHIFT,
            )
            .await?;
            self.port_modify(
                route,
                port,
                cap + TMU_ADP_CS_9,
                TMU_ADP_CS_9_REPL_N | TMU_ADP_CS_9_DIRSWITCH | TMU_ADP_CS_9_INTERVAL,
                ENHANCED_REPLICA_N
                    | ENHANCED_DIRECTION_SWITCH_N << TMU_ADP_CS_9_DIRSWITCH_SHIFT
                    | HIGH_FIDELITY_RATE << TMU_ADP_CS_9_INTERVAL_SHIFT,
            )
            .await?;
            self.port_modify(route, port, cap + TMU_ADP_CS_8, 0, TMU_ADP_CS_8_EUDM)
                .await?;
        }
        Ok(())
    }
}
