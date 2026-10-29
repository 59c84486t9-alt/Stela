//! Source-checked T8112 channels and live synchronous memory drainage.
//!
//! 26A434 J473 KC SHA256 06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d:
//! start saves +ed0/+ec8 at file2efac98..2efacf0, stride400000;
//! _dcsWriteQueueFlush file2efde44..2efdf14 clears low16 of +a40, keeps
//! high16, delays330us and executes the final barrier. No ordinary read or
//! saved ready bit establishes completion of the synchronous frontend.
//!
//! `handleDCSOdtsEvent` reads each channel's +41c once a second: the latest
//! LPDDR mode register 4 refresh rate of its two ranks in bits 4:0 and 9:5,
//! retrying while either reads 0xd. The model's DRAM is at nominal
//! temperature, where LPDDR5 refreshes at the 1x rate, code 0xa (Intel 12th
//! Generation Core datasheet volume 2, `MR4_RANK_TEMPERATURE`).
//!
//! `_enablePerfCtrl` and `_writePerfCtrl` program the performance counter
//! control and event selection words +580..+640, which hold their full32
//! writes from a zero handoff. In the driver's `AMCPerfCounterConfig` table
//! (`SR duration(usec)`, `PD duration(usec)`), +588 bits 0 and 4 enable the
//! self-refresh and power-down duration counters and bits 8 and 12 clear
//! them; `_enablePerfCtrl` panics unless a clear bit reads clear within
//! 20 us, and a clear completes at once. The counters at +4000 count DRAM
//! events, which no producer supplies, so their reads refuse.
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

const NAME: &str = "dcs";
pub const CHANNEL_STRIDE: u64 = 0x400000;
pub const CHANNELS: usize = 8;
const GATING: u64 = 0x18;
const GATING_FIELDS: u32 = 0x1100;
const REFRESH: u64 = 0x41c;
const DRAIN: u64 = 0xa40;
const CONFIG_EC8: u64 = 0xec8;
const CONFIG_ED0: u64 = 0xed0;
const PERF: core::ops::Range<u64> = 0x580..0x640;
const DURATION: u64 = 0x588;
const DURATION_CLEAR: u32 = 1 << 8 | 1 << 12;
/// The LPDDR5 1x refresh-rate code in both ranks' fields.
const NOMINAL_REFRESH: u64 = 0xa | 0xa << 5;
const PERF_WORDS: usize = ((PERF.end - PERF.start) / 4) as usize;

/// Caller-declared software backing, not physical reset/DRAM observations.
/// Initial configuration is held as opaque full32 words; drain high16 is
/// a separately declared controller image, never derived from an empty queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelConfiguration {
    pub ec8: u32,
    pub ed0: u32,
    pub gating: u32,
    pub drain_high: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Configuration { offset: u64, value: u32 },
    Drain { preserved_high: u16 },
}

/// A reached native input. Configuration requests remain pending: publishing
/// this record neither applies host DRAM programming nor authorizes a PMP ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub serial: u64,
    pub channel: usize,
    pub at: u64,
    pub effect: Effect,
}

/// Fixed-size per-channel progress, not an ever-growing event queue. Completed
/// drainage is represented by an exact count and latest completion; pending
/// configuration keeps its complete request until a backend exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelProgress {
    pub pending_configuration: Option<Request>,
    pub latest_drain: Option<Request>,
    pub completed_drains: u64,
}

struct Channel {
    configuration: ChannelConfiguration,
    progress: ChannelProgress,
    perf: [u32; PERF_WORDS],
}
struct State {
    channels: Vec<Channel>,
    lifecycle: LifecycleState,
    serial: u64,
}
impl State {
    fn accessible(&self) -> Result<(), &'static str> {
        let state = self.lifecycle;
        if !state.powered || !state.clocked || state.quiesced || state.reset {
            return Err("native DCS resource is paused by its actual lifecycle owner");
        }
        Ok(())
    }
    fn request(
        &mut self,
        channel: usize,
        at: u64,
        effect: Effect,
    ) -> Result<Request, &'static str> {
        let serial = self
            .serial
            .checked_add(1)
            .ok_or("DCS request serial exhausted")?;
        let request = Request {
            serial,
            channel,
            at,
            effect,
        };
        self.serial = serial;
        Ok(request)
    }
}

/// One eight-channel frontend. Clones share control, lifecycle,
/// pending effects and bounded completed progress; they are not copies.
#[derive(Clone)]
pub struct Controller {
    state: Rc<RefCell<State>>,
}
impl Controller {
    pub fn initialized(
        configuration: Vec<ChannelConfiguration>,
        lifecycle: LifecycleState,
    ) -> Result<Self, &'static str> {
        if configuration.len() != CHANNELS || lifecycle.reset || !lifecycle.retention {
            return Err("native T8112 DCS requires all eight retained initialized channels");
        }
        if configuration
            .iter()
            .any(|channel| channel.gating & GATING_FIELDS == 0x1000)
        {
            return Err("native DCS initial gating selector is outside the original protocol");
        }
        Ok(Self {
            state: Rc::new(RefCell::new(State {
                channels: configuration
                    .into_iter()
                    .map(|configuration| Channel {
                        configuration,
                        progress: ChannelProgress::default(),
                        perf: [0; PERF_WORDS],
                    })
                    .collect(),
                lifecycle,
                serial: 0,
            })),
        })
    }
    pub fn progress(&self) -> [ChannelProgress; CHANNELS] {
        let state = self.state.borrow();
        core::array::from_fn(|channel| state.channels[channel].progress)
    }
    pub fn requires_ram_access(&self, offset: u64, width: Width) -> bool {
        locate(offset, width).is_ok_and(|(_, register)| register == DRAIN)
    }
    pub(crate) fn drain_control(
        &self,
        offset: u64,
        width: Width,
    ) -> Result<(usize, u16), &'static str> {
        let (channel, register) = locate(offset, width)?;
        if register != DRAIN {
            return Err("native DCS service is not its original drain word");
        }
        let state = self
            .state
            .try_borrow()
            .map_err(|_| "native DCS owner is already borrowed")?;
        state.accessible()?;
        if state
            .channels
            .iter()
            .any(|channel| channel.progress.pending_configuration.is_some())
        {
            return Err(
                "native DCS drain cannot settle an outstanding channel configuration request",
            );
        }
        Ok((channel, state.channels[channel].configuration.drain_high))
    }
    pub(crate) fn record_ram_drain(
        &self,
        offset: u64,
        width: Width,
        value: u64,
        at: u64,
    ) -> Result<(), &'static str> {
        let (channel, high) = self.drain_control(offset, width)?;
        if value != u64::from(high) << 16 {
            return Err("native DCS flush must retain high16 and clear both low bytes");
        }
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| "native DCS owner is already borrowed")?;
        let completed = state.channels[channel]
            .progress
            .completed_drains
            .checked_add(1)
            .ok_or("DCS completed drain count exhausted")?;
        let request = state.request(
            channel,
            at,
            Effect::Drain {
                preserved_high: high,
            },
        )?;
        state.channels[channel].progress.latest_drain = Some(request);
        state.channels[channel].progress.completed_drains = completed;
        Ok(())
    }
}

fn locate(offset: u64, width: Width) -> Result<(usize, u64), &'static str> {
    if width != Width::Word
        || !offset.is_multiple_of(4)
        || offset / CHANNEL_STRIDE >= CHANNELS as u64
    {
        return Err("native DCS access is outside the original aligned full32 channel geometry");
    }
    Ok(((offset / CHANNEL_STRIDE) as usize, offset % CHANNEL_STRIDE))
}
impl Lifecycle for Controller {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        let state = self
            .state
            .try_borrow()
            .map_err(|_| "native DCS owner is already borrowed")?;
        if proposed.reset || !proposed.retention {
            return Err("native DCS destructive reset/power loss is not source-qualified");
        }
        if state
            .channels
            .iter()
            .any(|channel| channel.progress.pending_configuration.is_some())
            && proposed != state.lifecycle
        {
            return Err(
                "native DCS lifecycle cannot discard pending channel configuration effects",
            );
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.state.borrow_mut().lifecycle = proposed;
    }
}
impl MmioDevice for Controller {
    fn name(&self) -> &'static str {
        NAME
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |why| refuse(NAME, offset, width, Direction::Read, why);
        let (channel, register) = locate(offset, width).map_err(fail)?;
        let state = self
            .state
            .try_borrow()
            .map_err(|_| fail("native DCS owner is already borrowed"))?;
        state.accessible().map_err(fail)?;
        if state.channels[channel]
            .progress
            .pending_configuration
            .is_some()
        {
            return Err(fail(
                "native DCS configuration has no completed actual backend effect",
            ));
        }
        let configuration = state.channels[channel].configuration;
        if PERF.contains(&register) {
            return Ok(u64::from(
                state.channels[channel].perf[((register - PERF.start) / 4) as usize],
            ));
        }
        match register {
            CONFIG_EC8 => Ok(u64::from(configuration.ec8)),
            CONFIG_ED0 => Ok(u64::from(configuration.ed0)),
            GATING => Ok(u64::from(configuration.gating)),
            DRAIN => Err(fail(
                "native DCS drain requires the actual canonical all-writer memory service",
            )),
            REFRESH => Ok(NOMINAL_REFRESH),
            _ => Err(fail(
                "native DCS register/event accounting is not source-qualified",
            )),
        }
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |why| refuse(NAME, offset, width, Direction::Write, why);
        let (channel, register) = locate(offset, width).map_err(fail)?;
        let mut state = self
            .state
            .try_borrow_mut()
            .map_err(|_| fail("native DCS owner is already borrowed"))?;
        state.accessible().map_err(fail)?;
        if PERF.contains(&register) && value <= u64::from(u32::MAX) {
            let value = value as u32;
            let clear = if register == DURATION {
                DURATION_CLEAR
            } else {
                0
            };
            state.channels[channel].perf[((register - PERF.start) / 4) as usize] = value & !clear;
            return Ok(());
        }
        if !matches!(register, CONFIG_EC8 | CONFIG_ED0 | GATING) || value > u64::from(u32::MAX) {
            return Err(fail(
                "native DCS write has no qualified full32 configuration or memory service",
            ));
        }
        if state.channels[channel]
            .progress
            .pending_configuration
            .is_some()
        {
            return Err(fail(
                "native DCS channel still owns an incomplete configuration effect",
            ));
        }
        if register == GATING {
            let previous = state.channels[channel].configuration.gating;
            if ((value as u32 ^ previous) & !GATING_FIELDS) != 0
                || value as u32 & GATING_FIELDS == 0x1000
            {
                return Err(fail(
                    "native DCS gating request changes opaque fields or uses an absent source selector",
                ));
            }
        }
        let request = state
            .request(
                channel,
                access.now,
                Effect::Configuration {
                    offset: register,
                    value: value as u32,
                },
            )
            .map_err(fail)?;
        state.channels[channel].progress.pending_configuration = Some(request);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_reads_nominal_and_perf_control_holds_with_clears_completing() {
        let live = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        };
        let configuration = ChannelConfiguration {
            ec8: 0,
            ed0: 0,
            gating: 0,
            drain_high: 0,
        };
        let mut owner =
            Controller::initialized(alloc::vec![configuration; CHANNELS], live).unwrap();
        let mut latch = stela_contracts::interrupt::InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let base = 3 * CHANNEL_STRIDE;
        assert_eq!(
            owner.read(base + REFRESH, Width::Word, &mut access),
            Ok(0x14a)
        );
        assert_eq!(owner.read(base + 0x58c, Width::Word, &mut access), Ok(0));
        owner
            .write(base + 0x58c, Width::Word, 0x3ff_001a, &mut access)
            .unwrap();
        assert_eq!(
            owner.read(base + 0x58c, Width::Word, &mut access),
            Ok(0x3ff_001a)
        );
        owner
            .write(base + DURATION, Width::Word, 0x1111, &mut access)
            .unwrap();
        assert_eq!(
            owner.read(base + DURATION, Width::Word, &mut access),
            Ok(0x11)
        );
        // Other channels keep their own words; the counters refuse.
        assert_eq!(owner.read(0x58c, Width::Word, &mut access), Ok(0));
        assert!(owner.read(base + 0x4000, Width::Word, &mut access).is_err());
    }

    #[test]
    fn completed_drain_progress_is_bounded_and_exhaustion_preserves_pending_effects() {
        let live = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        };
        let owner = Controller::initialized(alloc::vec![ChannelConfiguration { ec8: 1, ed0: 2, gating: 0, drain_high: 0xa123 }; CHANNELS], live).unwrap();
        for serial in 1..=10000 {
            owner
                .record_ram_drain(DRAIN, Width::Word, 0xa1230000, serial)
                .unwrap();
        }
        let progress = owner.progress();
        assert_eq!(progress.len(), CHANNELS);
        assert_eq!(progress[0].completed_drains, 10000);
        assert_eq!(progress[0].latest_drain.unwrap().serial, 10000);
        assert!(progress[0].pending_configuration.is_none());
        owner.state.borrow_mut().channels[0]
            .progress
            .completed_drains = u64::MAX;
        let previous = owner.progress();
        assert!(
            owner
                .record_ram_drain(DRAIN, Width::Word, 0xa1230000, 10001)
                .is_err()
        );
        assert_eq!(owner.progress(), previous);
        assert_eq!(owner.state.borrow().serial, 10000);
        owner.state.borrow_mut().serial = u64::MAX;
        let previous = owner.progress();
        assert!(
            owner
                .record_ram_drain(CHANNEL_STRIDE + DRAIN, Width::Word, 0xa1230000, 10002)
                .is_err()
        );
        assert_eq!(owner.progress(), previous);
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_MCC_J473_KERNELCACHE"]
    fn original_drain_and_gating_consumers_keep_their_pinned_source_contract() {
        use sha2::{Digest, Sha256};
        let data =
            std::fs::read(std::env::var("STELA_TEST_MCC_J473_KERNELCACHE").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        for (start, end, expected) in [
            (
                0x2efde44,
                0x2efdf14,
                "db786464147a73c61e701aac43ade3025b859f723b8565f4f485fb7f223ae40d",
            ),
            (
                0x2efd5b0,
                0x2efd710,
                "982b9f14788762fdb21934443c3ff4a6dd40cdda2388035844116c2a459b39f1",
            ),
            (
                0x2efdd34,
                0x2efde38,
                "3f078bb32f6fab369fd634713e01a297e777f6b186e84c80db39b989f81389a2",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&data[start..end])), expected);
        }
    }
}
