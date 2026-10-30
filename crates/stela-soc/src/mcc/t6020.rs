//! T602x AP memory-controller requests, independently of T6000's cache owner.
//!
//! Original 26A434 mac14j KC SHA256 ef4712e54102b35c11665c46fa7543a3fafc0c419723f583cb0ac891016f531a:
//! start file2ecb674 counts reg entries minus two, with four DCS channels each;
//! readCacheSize2ecce34 reads100020; cache mode2ecd9e8 writes1c1c00;
//! ways wait2ecd710 reads plane*40000+1c04, data13:9/tag8:4;
//! DCS flush2ece46c selects200a40+channel*200000 and preserves high16.
//! These are request/consumer facts, not evidence that a write powers a cache,
//! programs DRAM or produces an event counter. Unknown effects stay pending.
use crate::Result;
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

use stela_soc_data::mcc::t6020::{
    CACHE_MODE, CACHE_SIZE, CACHE_STATUS, CHANNELS, DCS_BASE, DCS_GATING, DCS_STRIDE, DRAIN,
    DRAM_CONFIGURATION, Layout, MCC_GATING, PLANE_STRIDE, PLANES, WAYS_STATUS,
};
const NAME: &str = "t6020-mcc";
const DCS_GATE_FIELDS: u32 = 0x1100;
const MCC_GATE_FIELDS: u32 = 0x30000000;

/// Explicit newly owned software control words, never Apple reset readings.
/// No capacity, healthy status, counter value or cache grant is initialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelImage {
    pub dram: u32,
    pub gating: u32,
    pub drain_high: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    pub channels: Vec<ChannelImage>,
    pub mcc_gating: Vec<u32>,
}
impl Configuration {
    pub fn clear_software_controls(layout: Layout) -> Self {
        Self {
            channels: (0..layout.channels())
                .map(|_| ChannelImage {
                    dram: 0,
                    gating: 0,
                    drain_high: 0,
                })
                .collect(),
            mcc_gating: alloc::vec![0; layout.apertures()],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Register {
    CacheMode,
    MccGating,
    Dram(u8),
    DcsGating(u8),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub serial: u64,
    pub aperture: u8,
    pub register: Register,
    pub previous: Option<u32>,
    pub written: u32,
    pub at: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReceipt {
    pub serial: u64,
    pub aperture: u8,
    pub channel: u8,
    pub written: u32,
    pub at: u64,
}
struct State {
    layout: Layout,
    configuration: Configuration,
    lifecycle: LifecycleState,
    pending: BTreeMap<(u8, Register), Request>,
    drains: BTreeMap<(u8, u8), DrainReceipt>,
    serial: u64,
}
impl State {
    fn accessible(&self) -> Result<()> {
        if self.lifecycle.reset || !self.lifecycle.retention {
            return Err(refuse!(
                "T602x memory reset or state loss has no qualified owner"
            ));
        }
        if !self.lifecycle.powered || !self.lifecycle.clocked || self.lifecycle.quiesced {
            return Err(refuse!(
                "T602x memory frontend is paused by its actual owner"
            ));
        }
        Ok(())
    }
    fn channel(&self, aperture: u8, lane: u8) -> &ChannelImage {
        &self.configuration.channels[usize::from(aperture) * CHANNELS + usize::from(lane)]
    }
    fn control(&self, aperture: u8, register: Register) -> Result<u32> {
        if self.pending.contains_key(&(aperture, register)) {
            return Err(refuse!(
                "T602x control awaits an actual DRAM/clock/power backend effect"
            ));
        }
        match register {
            Register::CacheMode => Err(refuse!(
                "T602x cache state requires its actual PMP/cache owner"
            )),
            Register::MccGating => Ok(self.configuration.mcc_gating[usize::from(aperture)]),
            Register::Dram(lane) => Ok(self.channel(aperture, lane).dram),
            Register::DcsGating(lane) => Ok(self.channel(aperture, lane).gating),
        }
    }
}

/// Clones and aperture aliases keep one control/request/lifecycle owner.
/// There is no public completion setter or copied readiness bit.
#[derive(Clone)]
pub struct Controller(Rc<RefCell<State>>);
impl Controller {
    pub fn initialized(
        layout: Layout,
        configuration: Configuration,
        lifecycle: LifecycleState,
    ) -> Result<Self> {
        if configuration.channels.len() != layout.channels()
            || configuration.mcc_gating.len() != layout.apertures()
        {
            return Err(refuse!(
                "T602x initial image must cover every actual aperture and channel"
            ));
        }
        if lifecycle.reset || !lifecycle.retention {
            return Err(refuse!("T602x initial physical reset/loss is unqualified"));
        }
        Ok(Self(Rc::new(RefCell::new(State {
            layout,
            configuration,
            lifecycle,
            pending: BTreeMap::new(),
            drains: BTreeMap::new(),
            serial: 0,
        }))))
    }
    pub fn layout(&self) -> Layout {
        self.0.borrow().layout
    }
    pub fn view(&self, aperture: usize) -> Result<View> {
        if aperture >= self.layout().apertures() {
            return Err(refuse!("T602x aperture is outside its actual owner"));
        }
        Ok(View {
            owner: self.clone(),
            aperture: aperture as u8,
        })
    }
    pub fn requests(&self) -> Vec<Request> {
        self.0.borrow().pending.values().copied().collect()
    }
    pub fn drain_receipts(&self) -> Vec<DrainReceipt> {
        self.0.borrow().drains.values().copied().collect()
    }
    pub fn lifecycle_state(&self) -> LifecycleState {
        self.0.borrow().lifecycle
    }
    /// The complete AP read/write footprint recovered here. Unlisted offsets
    /// and unsupported effects still refuse; this is not a placement grant.
    pub fn register_offsets(&self) -> Vec<u64> {
        let mut offsets = alloc::vec![MCC_GATING, CACHE_SIZE, CACHE_MODE];
        for plane in 0..PLANES {
            offsets.extend(
                [CACHE_STATUS, WAYS_STATUS].map(|offset| offset + u64::from(plane) * PLANE_STRIDE),
            );
        }
        for lane in 0..CHANNELS {
            let base = DCS_BASE + lane as u64 * DCS_STRIDE;
            offsets.extend([base + DRAIN, base + DRAM_CONFIGURATION, base + DCS_GATING]);
        }
        offsets
    }
    pub fn requires_ram_read(&self, offset: u64, width: Width) -> bool {
        width == Width::Word && drain_lane(offset).is_some()
    }
    pub(crate) fn drain_control(&self, aperture: usize, offset: u64) -> Result<u32> {
        let lane =
            drain_lane(offset).ok_or(refuse!("T602x access is not a source DCS drain word"))?;
        let state = self
            .0
            .try_borrow()
            .map_err(|_| refuse!("T602x control owner is borrowed"))?;
        state.accessible()?;
        if aperture >= state.layout.apertures() {
            return Err(refuse!("T602x drain aperture is outside its actual owner"));
        }
        if !state.pending.is_empty() {
            return Err(refuse!(
                "canonical RAM exclusion cannot settle a pending T602x controller request"
            ));
        }
        Ok(u32::from(state.channel(aperture as u8, lane).drain_high) << 16)
    }
    /// Only the enclosing canonical resource may call this, after checking its
    /// RAM identity, live generation and the closed producer cohort.
    pub(crate) fn record_ram_drain(
        &self,
        aperture: usize,
        offset: u64,
        written: u32,
        at: u64,
    ) -> Result<()> {
        if written != self.drain_control(aperture, offset)? {
            return Err(refuse!(
                "T602x DCS flush must preserve high16 and clear both low bytes"
            ));
        }
        let lane = drain_lane(offset).ok_or(refuse!("T602x drain word is absent"))?;
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| refuse!("T602x control owner is borrowed"))?;
        let serial = state
            .serial
            .checked_add(1)
            .ok_or(refuse!("T602x request serial exhausted"))?;
        state.drains.insert(
            (aperture as u8, lane),
            DrainReceipt {
                serial,
                aperture: aperture as u8,
                channel: lane,
                written,
                at,
            },
        );
        state.serial = serial;
        Ok(())
    }
}

fn channel_register(offset: u64, register: u64) -> Option<u8> {
    let delta = offset.checked_sub(DCS_BASE + register)?;
    (delta.is_multiple_of(DCS_STRIDE) && delta / DCS_STRIDE < CHANNELS as u64)
        .then_some((delta / DCS_STRIDE) as u8)
}
fn drain_lane(offset: u64) -> Option<u8> {
    channel_register(offset, DRAIN)
}
fn control_register(offset: u64) -> Option<Register> {
    match offset {
        CACHE_MODE => Some(Register::CacheMode),
        MCC_GATING => Some(Register::MccGating),
        _ => channel_register(offset, DRAM_CONFIGURATION)
            .map(Register::Dram)
            .or_else(|| channel_register(offset, DCS_GATING).map(Register::DcsGating)),
    }
}

pub struct View {
    owner: Controller,
    aperture: u8,
}
impl Lifecycle for View {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        let state = self
            .owner
            .0
            .try_borrow_mut()
            .map_err(|_| refuse!("T602x control owner is borrowed"))?;
        if proposed.reset || !proposed.retention {
            return Err(refuse!(
                "T602x reset, state loss and request cancellation are unqualified"
            ));
        }
        if proposed != state.lifecycle && !state.pending.is_empty() {
            return Err(refuse!(
                "T602x lifecycle cannot retire an unsettled controller request"
            ));
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.owner.0.borrow_mut().lifecycle = proposed;
    }
}
impl MmioDevice for View {
    fn name(&self) -> &'static str {
        NAME
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Read, reason);
        let state = self
            .owner
            .0
            .try_borrow()
            .map_err(|_| fail(refuse!("T602x control owner is borrowed")))?;
        state.accessible().map_err(fail)?;
        if width != Width::Word {
            return Err(fail(refuse!("T602x AP register requires a 32-bit access")));
        }
        if let Some(register) = control_register(offset) {
            return state
                .control(self.aperture, register)
                .map(u64::from)
                .map_err(fail);
        }
        let reason = if drain_lane(offset).is_some() {
            "T602x DCS drain requires the same actual live canonical RAM service"
        } else if offset == CACHE_SIZE
            || (0..PLANES).any(|p| {
                offset
                    .checked_sub(u64::from(p) * PLANE_STRIDE)
                    .is_some_and(|within| [CACHE_STATUS, WAYS_STATUS].contains(&within))
            })
        {
            "T602x cache capacity/way state has no actual qualified PMP/cache producer"
        } else {
            "T602x register, thermal, performance or quota effect is unqualified"
        };
        Err(fail(reason.into()))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Write, reason);
        let mut state = self
            .owner
            .0
            .try_borrow_mut()
            .map_err(|_| fail(refuse!("T602x control owner is borrowed")))?;
        state.accessible().map_err(fail)?;
        if width != Width::Word || value > u64::from(u32::MAX) {
            return Err(fail(refuse!(
                "T602x AP register requires an exact 32-bit value/access"
            )));
        }
        let register = control_register(offset).ok_or_else(|| {
            fail(refuse!(
                "T602x write requires an unqualified effect or a live RAM drain"
            ))
        })?;
        let previous = if register == Register::CacheMode {
            if value > 1 {
                return Err(fail(refuse!(
                    "T602x cache mode has an unrecovered encoding"
                )));
            }
            None
        } else {
            Some(state.control(self.aperture, register).map_err(fail)?)
        };
        if state.pending.contains_key(&(self.aperture, register)) {
            return Err(fail(refuse!(
                "T602x controller request replacement/cancellation is unqualified"
            )));
        }
        let written = value as u32;
        let fields = match register {
            Register::MccGating => Some(MCC_GATE_FIELDS),
            Register::DcsGating(_) => Some(DCS_GATE_FIELDS),
            _ => None,
        };
        if let (Some(fields), Some(previous)) = (fields, previous)
            && written & !fields != previous & !fields
        {
            return Err(fail(refuse!(
                "T602x gating write changes opaque source-preserved fields"
            )));
        }
        if matches!(register, Register::MccGating) && written & MCC_GATE_FIELDS == 0x20000000
            || matches!(register, Register::DcsGating(_)) && written & DCS_GATE_FIELDS == 0x1000
        {
            return Err(fail(refuse!(
                "T602x gating request has an unrecovered two-field encoding"
            )));
        }
        let serial = state
            .serial
            .checked_add(1)
            .ok_or_else(|| fail(refuse!("T602x request serial exhausted")))?;
        state.pending.insert(
            (self.aperture, register),
            Request {
                serial,
                aperture: self.aperture,
                register,
                previous,
                written,
                at: access.now,
            },
        );
        state.serial = serial;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    fn running() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }
    fn owner(apertures: usize) -> Controller {
        let layout = Layout::new(apertures).unwrap();
        Controller::initialized(
            layout,
            Configuration::clear_software_controls(layout),
            running(),
        )
        .unwrap()
    }
    #[test]
    fn source_channel_order_covers_pro_max_and_both_ultra_dies() {
        for apertures in [4, 8, 16] {
            let layout = Layout::new(apertures).unwrap();
            for channel in 0..apertures * CHANNELS {
                assert_eq!(
                    layout.channel(channel),
                    Ok((
                        (channel >> 2) as u8,
                        DCS_BASE + (channel & 3) as u64 * DCS_STRIDE
                    ))
                );
            }
            assert!(layout.channel(apertures * CHANNELS).is_err());
        }
        assert!(Layout::new(0).is_err());
        assert!(Layout::new(17).is_err());
    }
    #[test]
    fn requests_are_shared_but_never_become_healthy_readback_or_completion() {
        let owner = owner(4);
        let mut a = owner.view(0).unwrap();
        let mut alias = owner.view(0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 9, &mut latch);
        let dram = DCS_BASE + DRAM_CONFIGURATION;
        assert_eq!(a.read(dram, Width::Word, &mut access), Ok(0));
        a.write(dram, Width::Word, 0x133, &mut access).unwrap();
        assert!(alias.read(dram, Width::Word, &mut access).is_err());
        assert!(alias.write(dram, Width::Word, 0x133, &mut access).is_err());
        assert_eq!(owner.requests().len(), 1);
        assert!(owner.drain_control(0, DCS_BASE + DRAIN).is_err());
        let paused = LifecycleState {
            quiesced: true,
            ..running()
        };
        assert!(alias.check_lifecycle(paused).is_err());
        for offset in [CACHE_SIZE, WAYS_STATUS, CACHE_MODE] {
            assert!(alias.read(offset, Width::Word, &mut access).is_err());
        }
        for offset in [0, 4, u64::MAX] {
            assert!(alias.read(offset, Width::Word, &mut access).is_err());
        }
        assert!(
            owner
                .view(1)
                .unwrap()
                .read(dram, Width::Word, &mut access)
                .is_ok()
        );
    }
    #[test]
    fn exact_source_masks_preserve_opaque_controls_and_refuse_before_mutation() {
        let layout = Layout::new(4).unwrap();
        let mut configuration = Configuration::clear_software_controls(layout);
        configuration.channels[0].gating = 0x80000007;
        let owner = Controller::initialized(layout, configuration, running()).unwrap();
        let mut view = owner.view(0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 4, &mut latch);
        for (width, value) in [
            (Width::Double, 0),
            (Width::Word, 1u64 << 32),
            (Width::Word, 0x1100),
        ] {
            assert!(
                view.write(DCS_BASE + DCS_GATING, width, value, &mut access)
                    .is_err()
            );
        }
        assert!(owner.requests().is_empty());
        view.write(DCS_BASE + DCS_GATING, Width::Word, 0x80001107, &mut access)
            .unwrap();
        assert_eq!(owner.requests()[0].previous, Some(0x80000007));
        assert_eq!(owner.requests()[0].written, 0x80001107);
    }
    #[test]
    fn live_drain_keeps_high_control_and_never_leaves_a_saved_ready_word() {
        let layout = Layout::new(16).unwrap();
        let mut configuration = Configuration::clear_software_controls(layout);
        configuration.channels[63].drain_high = 0x91ab;
        let owner = Controller::initialized(layout, configuration, running()).unwrap();
        let offset = DCS_BASE + 3 * DCS_STRIDE + DRAIN;
        assert_eq!(owner.drain_control(15, offset), Ok(0x91ab0000));
        for value in [0, 0x91aa0000, 0x91ab0001, 0x91ab0100] {
            assert!(owner.record_ram_drain(15, offset, value, 1).is_err());
        }
        assert!(owner.drain_receipts().is_empty());
        owner.record_ram_drain(15, offset, 0x91ab0000, 7).unwrap();
        assert_eq!(
            owner.drain_receipts()[0],
            DrainReceipt {
                serial: 1,
                aperture: 15,
                channel: 3,
                written: 0x91ab0000,
                at: 7
            }
        );
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 8, &mut latch);
        assert!(
            owner
                .view(15)
                .unwrap()
                .read(offset, Width::Word, &mut access)
                .is_err()
        );
    }
}
