// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Actual source BB/MAC/RF channel sequence. No calibrated radio/TX admission.
use super::channel_power::{self, Geometry, Plan, Programmed, Width};
use super::{Attempt, Error, Io, Path, PhyInitialized, Report, rf};

/// Actual source channel stores and IGI latch completed. This retains the same
/// physical PHY state; it is not readback/calibration/OS-policy authority.
#[derive(Debug)]
pub struct ChannelSet {
    phy: PhyInitialized,
    geometry: Geometry,
    primary_index: u8,
    initial_igi: u8,
    programmed_rf18: u32,
}
impl ChannelSet {
    pub fn phy(&self) -> &PhyInitialized {
        &self.phy
    }
    pub fn geometry(&self) -> Geometry {
        self.geometry
    }
    pub fn primary_index(&self) -> u8 {
        self.primary_index
    }
    pub fn initial_igi(&self) -> u8 {
        self.initial_igi
    }
    /// Source computed RF18 value written to both paths, not readback.
    pub fn programmed_rf18(&self) -> u32 {
        self.programmed_rf18
    }
    /// Apply the next source power phase for this exact requested geometry.
    ///
    /// # Safety
    /// All actual same-owner/reset/firmware/board, held native→OS authority,
    /// current power inputs, quiesced work, queued-air drain and qualification
    /// requirements of PhyInitialized::program_channel_power apply. Required
    /// genuine coexistence band notification must already complete, preserving
    /// the source channel → coexistence → power order. ChannelSet
    /// stores are not proof that the radio tuned/calibrated or can transmit.
    pub unsafe fn program_channel_power<I: Io>(
        self,
        io: &mut I,
        report: &Report,
        plan: Plan,
    ) -> Result<Programmed, Error> {
        if self.geometry != plan.geometry() {
            return Err(Error::ChannelPower(channel_power::Error::Geometry));
        }
        // SAFETY: caller retains the same actual native and policy guards;
        // immutable plan geometry is additionally bound to this source phase.
        unsafe { self.phy.program_channel_power(io, report, plan) }
    }
}
impl PhyInitialized {
    /// Set source baseband, MAC and both RF paths then latch actual current IGI.
    ///
    /// # Safety
    /// Same actual retained requester, control owner, reset/firmware/board epoch
    /// as this PHY state, Report and Io, not equal fingerprints alone. Retain
    /// actual claims/queues/pins/full BAR and qualified native clock; genuine
    /// prior MAC/HCI/PHY initialization remains valid. Invalidate old applied
    /// policy and actually stop/enforce/drain queued air traffic first. Hold
    /// native control authority followed by genuine OS/location authority for
    /// this exact channel/width through the complete sequence; no reverse waits.
    /// Operational TX (including autonomous ACK/beacon/retry), RX and competing
    /// reset/IRQ/PHY/RF/coexistence/power work remain genuinely quiesced. A
    /// parsed channel, scan result or caller numeric geometry is not authority.
    /// Caller performs required coexistence notification, per-channel power,
    /// RFK/IQK/DPK, EDCCA and actual tuning/readback qualification before any
    /// shared RX/TX admission. This does not claim DMA stop or air completion.
    pub unsafe fn set_channel<I: Io>(
        self,
        io: &mut I,
        report: &Report,
        geometry: Geometry,
    ) -> Result<ChannelSet, Error> {
        let profile = self.factory_power().profile();
        if io.profile() != profile || report.profile() != profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(Error::UnsupportedRfLayout);
        }
        let index = primary_index(geometry);
        let mut a = Attempt {
            io,
            profile,
            done: false,
        };
        a.domain()?;
        let (initial_igi, programmed_rf18) = set(&mut a, report, geometry, index)?;
        a.domain()?;
        a.done = true;
        Ok(ChannelSet {
            phy: self,
            geometry,
            primary_index: index,
            initial_igi,
            programmed_rf18,
        })
    }
}
fn center(g: Geometry) -> u8 {
    g.centers()[g.width() as usize].expect("validated geometry")
}
pub(super) fn primary_index(g: Geometry) -> u8 {
    match g.width() {
        Width::Mhz20 => 0,
        Width::Mhz40 => {
            if g.primary() > center(g) {
                1
            } else {
                2
            }
        }
        Width::Mhz80 => match i16::from(g.primary()) - i16::from(center(g)) {
            2 => 1,
            -2 => 2,
            6 => 3,
            -6 => 4,
            _ => unreachable!("validated geometry"),
        },
    }
}
pub(super) fn set<I: Io>(
    a: &mut Attempt<'_, I>,
    report: &Report,
    g: Geometry,
    index: u8,
) -> Result<(u8, u32), Error> {
    bb(a, g, index)?;
    mac(a, g, index)?;
    let rf18 = rf_channel(a, report, g)?;
    let igi = (a.io.read32(0x1d70)? & 127) as u8;
    for (mask, value) in [
        (0x7f, igi.wrapping_sub(2)),
        (0x7f00, igi.wrapping_sub(2)),
        (0x7f, igi),
        (0x7f00, igi),
    ] {
        a.modify32(0x1d70, mask, u32::from(value))?;
    }
    Ok((igi, rf18))
}
fn bb<I: Io>(a: &mut Attempt<'_, I>, g: Geometry, index: u8) -> Result<(), Error> {
    let ch = center(g);
    if ch <= 14 {
        a.modify32(0x1a14, 0x300, 0)?;
        a.modify32(0x1a9c, 1 << 20, 1)?;
        a.modify32(0x454, 1 << 7, 0)?;
        a.modify32(0x1a80, 1 << 18, 0)?;
        a.modify32(0x1c80, 0x3f000000, 0xf)?;
        let (cck, ofdm) = if g.width() == Width::Mhz20 {
            (5, 6)
        } else {
            (4, 0)
        };
        for (reg, mask, value) in [
            (0x18ac, 0xf000, cck),
            (0x41ac, 0xf000, cck),
            (0x18ac, 0x1f0, ofdm),
            (0x41ac, 0x1f0, ofdm),
        ] {
            a.modify32(reg, mask, value)?;
        }
        a.modify32(
            0xc30,
            0xfff,
            match ch {
                13 | 14 => 0x969,
                11 | 12 => 0x96a,
                _ => 0x9aa,
            },
        )?;
        let values = if ch == 14 {
            [
                0x3da0, 0x4962c931, 0x6aa3, 0xaa7b, 0xf3d7, 0, 0xff012455, 0xffff,
            ]
        } else {
            [
                0x5284, 0x3e18fec8, 0xa88, 0xacc4, 0xc8b2, 0x00faf0de, 0x00122344, 0x0fffffff,
            ]
        };
        for ((reg, mask), value) in [
            (0x1a20, 0xffff0000),
            (0x1a24, u32::MAX),
            (0x1a28, 0xffff),
            (0x1a98, 0xffff0000),
            (0x1a9c, 0xffff),
            (0x1aa0, u32::MAX),
            (0x1aac, u32::MAX),
            (0x1ab0, u32::MAX),
        ]
        .into_iter()
        .zip(values)
        {
            a.modify32(reg, mask, value)?;
        }
        a.modify32(0x808, 0x70, if ch == 13 { 3 } else { 1 })?;
    } else {
        a.modify32(0x1a80, 1 << 18, 1)?;
        a.modify32(0x454, 1 << 7, 1)?;
        a.modify32(0x1a14, 0x300, 3)?;
        a.modify32(0x1a9c, 1 << 20, 0)?;
        a.modify32(0x1c80, 0x3f000000, 0x22)?;
        a.modify32(0x808, 0x70, 3)?;
        let agc = if ch <= 64 {
            1
        } else if ch <= 144 {
            2
        } else {
            3
        };
        for reg in [0x18ac, 0x41ac] {
            a.modify32(reg, 0x1f0, agc)?;
        }
        let sco = match ch {
            36..=51 => 0x494,
            52..=55 => 0x493,
            56..=111 => 0x453,
            112..=119 => 0x452,
            120..=172 => 0x412,
            173..=177 => 0x411,
            _ => unreachable!("validated geometry"),
        };
        a.modify32(0xc30, 0xfff, sco)?;
    }
    match g.width() {
        Width::Mhz20 => {
            for (reg, mask, value) in [
                (0x810, 0x3ff0, 0x19b),
                (0x9b0, 0xf, 0),
                (0x9b0, 0xffc0, 0),
                (0x9b4, 0x700, 7),
                (0x9b4, 0x700000, 6),
                (0x1abc, 1 << 30, 0),
                (0x88c, 0xf000, 1),
                (0xcbc, 1 << 21, 0),
            ] {
                a.modify32(reg, mask, value)?;
            }
        }
        Width::Mhz40 => {
            a.modify32(0x1a00, 1 << 4, u32::from(index == 1))?;
            for (reg, mask, value) in [
                (0x9b0, 0xf, 5),
                (0x9b0, 0xc0, 0),
                (0x9b0, 0xff00, u32::from(index | (index << 4))),
                (0x1abc, 1 << 30, 1),
                (0x88c, 0xf000, 1),
                (0xcbc, 1 << 21, 1),
            ] {
                a.modify32(reg, mask, value)?;
            }
        }
        Width::Mhz80 => {
            for (reg, mask, value) in [
                (0x9b0, 0xf, 10),
                (0x9b0, 0xc0, 0),
                (0x9b0, 0xff00, u32::from(index | (index << 4))),
                (0x88c, 0xf000, 6),
                (0xcbc, 1 << 21, 1),
            ] {
                a.modify32(reg, mask, value)?;
            }
        }
    }
    Ok(())
}
fn mac<I: Io>(a: &mut Attempt<'_, I>, g: Geometry, index: u8) -> Result<(), Error> {
    let sub40 = if g.width() == Width::Mhz80 {
        if index == 1 || index == 3 { 9 } else { 10 }
    } else {
        0
    };
    a.io.write8(0x483, index | (sub40 << 4))?;
    let old = a.io.read32(0x668)?;
    let mode = match g.width() {
        Width::Mhz20 => 0,
        Width::Mhz40 => 1 << 7,
        Width::Mhz80 => 1 << 8,
    };
    a.io.write32(0x668, (old & !0x180) | mode)?;
    a.modify32(0x24, 0x300000, 0)?;
    a.io.write8(0x55c, 80)?;
    a.io.write8(0x638, 80)?;
    let old = a.io.read8(0x454)?;
    a.io.write8(0x454, (old & !0x80) | if center(g) > 14 { 0x80 } else { 0 })?;
    Ok(())
}
fn rstb<I: Io>(a: &mut Attempt<'_, I>, on: bool) -> Result<(), Error> {
    a.modify32(0x1c90, 1 << 8, u32::from(on))?;
    if on {
        for reg in [0x1830, 0x4130] {
            a.modify32(reg, 1 << 29, 1)?;
        }
    }
    Ok(())
}
fn rf_channel<I: Io>(a: &mut Attempt<'_, I>, report: &Report, g: Geometry) -> Result<u32, Error> {
    // SAFETY: public consumed transition holds the actual same serialized
    // requester and uninterrupted PHY/firmware epoch with full native domains.
    let old = unsafe { rf::Registers::new(a.io, report) }?.read(Path::A, 0x18, 0xfffff)?;
    let ch = center(g);
    let band = if ch <= 14 { 0 } else { (1 << 16) | (1 << 8) };
    let rfsi = if ch >= 149 {
        1 << 18
    } else if ch >= 100 {
        1 << 17
    } else {
        0
    };
    let (width, rxbb) = match g.width() {
        Width::Mhz20 => (0x3000, 0x18),
        Width::Mhz40 => (0x2000, 0x10),
        Width::Mhz80 => (0x1000, 8),
    };
    let value = (old & !((1 << 16) | (1 << 9) | (1 << 8) | 0xff | (1 << 18) | (1 << 17) | 0x3000))
        | band
        | rfsi
        | u32::from(ch)
        | width;
    rstb(a, false)?;
    {
        // SAFETY: same retained guarded control owner; no competing worker
        // can reset/revoke the RF domain through this serialized native borrow.
        let mut rf = unsafe { rf::Registers::new(a.io, report) }?;
        for path in [Path::A, Path::B] {
            rf.write(path, 0xee, 4, 1)?;
            rf.write(path, 0x33, 0x1f, 0x12)?;
            rf.write(path, 0x3f, 0xfffff, rxbb)?;
            rf.write(path, 0xee, 4, 0)?;
        }
        for path in [Path::A, Path::B] {
            rf.write(path, 0x18, 0xfffff, value)?;
        }
    }
    rstb(a, true)?;
    Ok(value)
}
