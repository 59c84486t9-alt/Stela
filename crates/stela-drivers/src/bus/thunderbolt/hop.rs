// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2019 Intel Corporation
//! Hop disable, bounded pending drain and flow-control clear.
//!
//! Adapted from Linux path.c::__tb_path_deactivate_hop. This is one CM
//! primitive, not a tunnel allocator or an endpoint/IOMMU DMA drain receipt.
use super::{
    channel::{self, Channel},
    config::{self, Address, Reply, Route, Space},
    ring::Registers,
    topology::{AdapterKind, Path},
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
const ENABLE: u32 = 1 << 31;
const PENDING: u32 = 1 << 28;
const INGRESS: u32 = (1 << 24) | (1 << 26);
const EGRESS: u32 = (1 << 25) | (1 << 27);
const DRAIN_MS: u64 = 500;
static QUARANTINED: AtomicU64 = AtomicU64::new(0);
pub fn quarantined_hops() -> u64 {
    QUARANTINED.load(Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub route: Route,
    pub port: u8,
    pub hop: u16,
    pub kind: AdapterKind,
    pub usb4: bool,
    pub clear_flow_control: bool,
}
impl Target {
    fn validate(self) -> Result<(), Error> {
        if self.port == 0
            || self.port >= 64
            || self.hop >= 2048
            || self.hop < if self.kind == AdapterKind::Nhi { 1 } else { 8 }
            || matches!(self.kind, AdapterKind::Inactive | AdapterKind::Unknown(_))
            || Path::new(self.route).is_err()
        {
            return Err(Error::Target);
        }
        Ok(())
    }
    fn address(self) -> Address {
        Address {
            port: self.port,
            space: Space::Hops,
            offset: self.hop * 2,
            words: 2,
        }
    }
    fn clear_mask(self) -> u32 {
        EGRESS
            | if self.kind == AdapterKind::Lane || !self.usb4 {
                INGRESS
            } else {
                0
            }
    }
}
/// Exact CM hop allocation, router lifetime and power reservation.
///
/// # Safety
/// The implementation owns this exact target exclusively until its last Arc
/// ends, including quarantine retention; its metadata comes from real router/
/// adapter inventory and link configuration. No other CM/firmware actor writes
/// the hop, changes its route or releases its allocation. Dropping this object
/// can release this hop ID/router reservation only; it must never substitute
/// local path-PENDING clearance for endpoint posted-DMA/IRQ/IOMMU teardown.
pub unsafe trait Owner: Send + Sync {
    fn target(&self) -> Target;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Words {
    pub raw: [u32; 2],
}
impl Words {
    pub fn enabled(self) -> bool {
        self.raw[0] & ENABLE != 0
    }
    pub fn pending(self) -> bool {
        self.raw[1] & PENDING != 0
    }
    fn disabled(self) -> Self {
        Self {
            raw: [self.raw[0] & !ENABLE, self.raw[1]],
        }
    }
    fn cleared(self, target: Target) -> Self {
        Self {
            raw: [self.raw[0], self.raw[1] & !target.clear_mask()],
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub target: Target,
    pub before: Words,
    pub after: Words,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Target,
    ClockOverflow,
    Timeout,
    Stopped,
    Poisoned,
    UnexpectedReceipt,
    Readback,
    Controller {
        route: Route,
        port: u8,
        code: u8,
        raw: u32,
    },
    Hotplug(config::PlugEvent),
    Notification(config::NotificationError),
    Channel(channel::Error),
}
impl From<channel::Error> for Error {
    fn from(value: channel::Error) -> Self {
        Self::Channel(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Drained(Receipt),
    Discarded(config::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Initial,
    Disable(Words),
    Drain,
    Clear(Words),
    Verify,
    Done,
    Fault,
}
/// Owns its channel while a single native hop is being disabled. Clock values
/// use monotonic milliseconds, matching the containing Channel's clock.
/// Uncertain failure permanently poisons that channel and keeps the Owner.
pub struct Teardown<R: Registers> {
    channel: Option<Channel<R>>,
    owner: Arc<dyn Owner>,
    target: Target,
    stage: Stage,
    expected: Option<u64>,
    deadline: u64,
    before: Option<Words>,
}
impl<R: Registers> Teardown<R> {
    /// Transfer this native CM hop reservation into teardown.
    ///
    /// # Safety
    /// `owner` and `channel` refer to the same live physical NHI/requester
    /// and platform ownership/reset epoch. The owner's target route, adapter,
    /// HopID and observed USB4/lane metadata belong to that channel's
    /// topology and have not been recycled or changed since reservation. The
    /// channel is exclusively idle; no other engine owns a pending request.
    /// The caller keeps all independent endpoint/DMA/IOMMU ownership until
    /// its own teardown, regardless of this local hop's receipt.
    ///
    /// Safe code cannot pair two independently obtained physical capabilities:
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use stela_drivers::bus::thunderbolt::{
    ///     channel::Channel, hop::{Owner, Teardown}, ring::Registers,
    /// };
    /// fn pair<R: Registers>(channel: Channel<R>, owner: Arc<dyn Owner>) {
    ///     let _teardown = Teardown::new(channel, owner, 0);
    /// }
    /// ```
    pub unsafe fn new(
        channel: Channel<R>,
        owner: Arc<dyn Owner>,
        now_ms: u64,
    ) -> Result<Self, Error> {
        let target = owner.target();
        let result = target
            .validate()
            .and_then(|_| now_ms.checked_add(DRAIN_MS).ok_or(Error::ClockOverflow));
        let deadline = match result {
            Ok(deadline) => deadline,
            Err(error) => {
                Self::quarantine(&owner);
                return Err(error);
            }
        };
        Ok(Self {
            channel: Some(channel),
            owner,
            target,
            stage: Stage::Initial,
            expected: None,
            deadline,
            before: None,
        })
    }
    fn quarantine(owner: &Arc<dyn Owner>) {
        let _ = QUARANTINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(1))
        });
        core::mem::forget(owner.clone());
    }
    fn channel(&mut self) -> &mut Channel<R> {
        self.channel.as_mut().expect("owned channel")
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stage = Stage::Fault;
        let _ = self.channel().cancel();
        Err(error)
    }
    /// The returned channel remains poisoned after an uncertain failure. The
    /// unresolved hop owner is quarantined by Drop even when the channel moves.
    pub fn into_channel(mut self) -> Channel<R> {
        self.channel.take().expect("owned channel")
    }
    fn submit(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.expected.is_some() {
            return Ok(());
        }
        let target = self.target;
        let deadline = self.deadline;
        let result = match self.stage {
            Stage::Initial | Stage::Drain | Stage::Verify => {
                self.channel()
                    .read(target.route, target.address(), now_ms, deadline)
            }
            Stage::Disable(words) | Stage::Clear(words) => {
                self.channel()
                    .write(target.route, target.address(), &words.raw, now_ms, deadline)
            }
            _ => return Err(Error::Stopped),
        };
        match result {
            Ok(id) => {
                self.expected = Some(id);
                Ok(())
            }
            Err(channel::Error::Ring(super::ring::Error::Full) | channel::Error::Busy) => Ok(()),
            Err(error) => self.fail(error.into()),
        }
    }
    fn receipt(&mut self, after: Words) -> Result<Option<Event>, Error> {
        let before = self.before.ok_or(Error::UnexpectedReceipt)?;
        self.stage = Stage::Done;
        Ok(Some(Event::Drained(Receipt {
            target: self.target,
            before,
            after,
        })))
    }
    fn complete(&mut self, reply: Reply) -> Result<Option<Event>, Error> {
        let data = match reply {
            Reply::Configuration { data, .. } => data,
            Reply::ControllerError {
                route,
                port,
                code,
                raw,
                ..
            } => {
                return self.fail(Error::Controller {
                    route,
                    port,
                    code,
                    raw,
                });
            }
            Reply::Reset => return self.fail(Error::UnexpectedReceipt),
        };
        match self.stage {
            Stage::Initial | Stage::Drain | Stage::Verify => {
                let Ok(raw) = data.as_slice().try_into() else {
                    return self.fail(Error::UnexpectedReceipt);
                };
                let words = Words { raw };
                match self.stage {
                    Stage::Initial => {
                        self.before = Some(words);
                        if words.enabled() {
                            self.stage = Stage::Disable(words.disabled());
                        } else if words.pending() {
                            self.stage = Stage::Drain;
                        } else {
                            return self.receipt(words);
                        }
                    }
                    Stage::Drain => {
                        if words.enabled() {
                            return self.fail(Error::Readback);
                        }
                        if !words.pending() {
                            if self.target.clear_flow_control
                                && self.before.is_some_and(|before| before.enabled())
                            {
                                self.stage = Stage::Clear(words.cleared(self.target));
                            } else {
                                return self.receipt(words);
                            }
                        }
                    }
                    Stage::Verify => {
                        if words.enabled()
                            || words.pending()
                            || words.raw[1] & self.target.clear_mask() != 0
                        {
                            return self.fail(Error::Readback);
                        }
                        return self.receipt(words);
                    }
                    _ => unreachable!(),
                }
            }
            Stage::Disable(_) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.stage = Stage::Drain;
            }
            Stage::Clear(_) => {
                if !data.is_empty() {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.stage = Stage::Verify;
            }
            _ => return self.fail(Error::UnexpectedReceipt),
        }
        Ok(None)
    }
    pub fn poll(&mut self, now_ms: u64) -> Result<Option<Event>, Error> {
        match self.stage {
            Stage::Fault => return Err(Error::Poisoned),
            Stage::Done => return Err(Error::Stopped),
            _ => {}
        }
        if now_ms >= self.deadline {
            return self.fail(Error::Timeout);
        }
        match self.channel().poll(now_ms) {
            Err(error) => return self.fail(error.into()),
            Ok(Some(channel::Event::Completed { request, reply })) => {
                if self.expected != Some(request) {
                    return self.fail(Error::UnexpectedReceipt);
                }
                self.expected = None;
                if let Some(event) = self.complete(reply)? {
                    return Ok(Some(event));
                }
            }
            Ok(Some(channel::Event::Plug(event))) => return self.fail(Error::Hotplug(event)),
            Ok(Some(channel::Event::Notification(event))) => {
                return self.fail(Error::Notification(event));
            }
            Ok(Some(channel::Event::Discarded(error))) => return Ok(Some(Event::Discarded(error))),
            Ok(None) => {}
        }
        self.submit(now_ms)?;
        Ok(None)
    }
}
impl<R: Registers> Drop for Teardown<R> {
    fn drop(&mut self) {
        if self.stage != Stage::Done {
            Self::quarantine(&self.owner);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use crate::bus::thunderbolt::ring::{Direction, TX_DESCRIPTOR, model::*};
    use alloc::vec::Vec;

    use core::sync::atomic::AtomicUsize;

    #[test]
    fn owned_hop_bounds_keep_control_and_reserved_protocol_paths_explicit() {
        let mut target = Target {
            route: Route::new(0).unwrap(),
            port: 1,
            hop: 8,
            kind: AdapterKind::Lane,
            usb4: true,
            clear_flow_control: true,
        };
        assert_eq!(target.validate(), Ok(()));
        for hop in [0, 1, 7, 2048, u16::MAX] {
            target.hop = hop;
            assert_eq!(target.validate(), Err(Error::Target));
        }
        target.kind = AdapterKind::Nhi;
        target.hop = 1;
        assert_eq!(target.validate(), Ok(()));
        target.hop = 2047;
        assert_eq!(target.address().offset, 4094);
        assert_eq!(target.validate(), Ok(()));
        target.port = 0;
        assert_eq!(target.validate(), Err(Error::Target));
        target.port = 64;
        assert_eq!(target.validate(), Err(Error::Target));
        target.port = 1;
        target.kind = AdapterKind::Unknown(0xabcdef);
        assert_eq!(target.validate(), Err(Error::Target));
    }
    #[test]
    #[ignore = "oracle: STELA_THUNDERBOLT_HOP_ORACLE"]
    fn unchanged_linux_hop_deactivation_register_effects_match() {
        extern crate std;
        use std::{env, fs};
        let trace =
            fs::read_to_string(env::var("STELA_THUNDERBOLT_HOP_ORACLE").expect("set hop trace"))
                .unwrap();
        let mut count = 0;
        for line in trace.lines() {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert_eq!(fields[0], "H");
            let v: Vec<u32> = fields[1..]
                .iter()
                .map(|field| field.parse().unwrap())
                .collect();
            assert_eq!(v.len(), 12);
            let target = Target {
                route: Route::new(0).unwrap(),
                port: 1,
                hop: 8,
                kind: if v[1] != 0 {
                    AdapterKind::Lane
                } else {
                    AdapterKind::PcieDown
                },
                usb4: v[0] != 0,
                clear_flow_control: v[2] != 0,
            };
            let before = Words { raw: [v[3], v[4]] };
            let disabled = before.disabled();
            assert_eq!(disabled.raw, [v[8], v[9]]);
            let drained = Words {
                raw: [disabled.raw[0], disabled.raw[1] & !PENDING],
            };
            let after = if target.clear_flow_control {
                drained.cleared(target)
            } else {
                drained
            };
            assert_eq!(after.raw, [v[5], v[6]]);
            assert_eq!(v[7], if target.clear_flow_control { 2 } else { 1 });
            assert_eq!(
                [v[10], v[11]],
                if target.clear_flow_control {
                    after.raw
                } else {
                    [0, 0]
                }
            );
            count += 1;
        }
        assert_eq!(count, 8192);
    }

    #[test]
    fn hop_disable_pending_drain_and_flow_clear_preserve_usb4_vendor_ingress() {
        use super::super::{
            config::Route,
            hop::{Event, Target, Teardown, Words},
            topology::AdapterKind,
        };
        for (usb4, kind) in [
            (true, AdapterKind::Lane),
            (true, AdapterKind::PcieDown),
            (false, AdapterKind::PcieDown),
        ] {
            for clear_flow_control in [false, true] {
                let (_source, domain, model, mut channel) = channel();
                channel.start(0).unwrap();
                let dropped = Arc::new(AtomicUsize::new(0));
                let target = Target {
                    route: Route::new(0).unwrap(),
                    port: 1,
                    hop: 8,
                    kind,
                    usb4,
                    clear_flow_control,
                };
                let owner = Arc::new(HopOwner {
                    target,
                    dropped: dropped.clone(),
                });
                // SAFETY: this synthetic Owner and Channel share the same
                // exclusive NHI/model requester, reservation and reset epoch;
                // its observed adapter metadata is unchanged and channel idle.
                let mut teardown = unsafe { Teardown::new(channel, owner.clone(), 0) }.unwrap();
                assert_eq!(teardown.poll(0).unwrap(), None);
                let initial = [0x81012345, 0x1f5abcde];
                let disabled = [initial[0] & !(1 << 31), initial[1]];
                let drained = [disabled[0], disabled[1] & !(1 << 28)];
                let clear_mask = (1 << 25)
                    | (1 << 27)
                    | if kind == AdapterKind::Lane || !usb4 {
                        (1 << 24) | (1 << 26)
                    } else {
                        0
                    };
                let cleared = [drained[0], drained[1] & !clear_mask];
                let mut result = None;
                let steps = if clear_flow_control { 6 } else { 4 };
                for index in 0..steps {
                    let sent = domain.data(
                        model.frame_address(Direction::Tx, index),
                        if index == 1 || index == 4 { 24 } else { 16 },
                    );
                    if index == 1 || index == 4 {
                        let expected = if index == 1 { disabled } else { cleared };
                        let actual: Vec<_> = sent[12..20]
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|raw| u32::from_be_bytes(*raw))
                            .collect();
                        assert_eq!(actual, expected);
                    }
                    let data: &[u32] = match index {
                        0 => &initial,
                        1 | 4 => &[],
                        2 => &disabled,
                        3 => &drained,
                        5 => &cleared,
                        _ => unreachable!(),
                    };
                    let reply = hop_response(&domain, &model, index, data);
                    model.finish(Direction::Tx, index, &[], None);
                    finish_rx(&model, index, &reply);
                    result = teardown.poll(index as u64 + 1).unwrap();
                    if index < steps - 1 {
                        assert_eq!(result, None);
                    }
                }
                let Some(Event::Drained(receipt)) = result else {
                    panic!("drain receipt")
                };
                assert_eq!(receipt.before, Words { raw: initial });
                assert_eq!(
                    receipt.after,
                    Words {
                        raw: if clear_flow_control { cleared } else { drained }
                    }
                );
                assert_eq!(teardown.poll(20), Err(super::super::hop::Error::Stopped));
                let mut channel = teardown.into_channel();
                drop(owner);
                assert_eq!(dropped.load(Ordering::Relaxed), 1);
                channel_release(&mut channel);
            }
        }
    }

    #[test]
    fn uncertain_hop_pending_or_rejected_disable_keeps_allocation_and_poisoned_channel() {
        use super::super::{
            channel::Error as ChannelError,
            config::Route,
            hop::{Error as HopError, Target, Teardown},
            topology::AdapterKind,
        };
        for reject in [false, true] {
            let (_source, domain, model, mut channel) = channel();
            channel.start(0).unwrap();
            let dropped = Arc::new(AtomicUsize::new(0));
            let target = Target {
                route: Route::new(0).unwrap(),
                port: 1,
                hop: 8,
                kind: AdapterKind::Lane,
                usb4: true,
                clear_flow_control: true,
            };
            let owner = Arc::new(HopOwner {
                target,
                dropped: dropped.clone(),
            });
            let before = super::super::hop::quarantined_hops();
            // SAFETY: this synthetic Owner and Channel share the same
            // exclusive NHI/model requester, reservation and reset epoch;
            // its observed adapter metadata is unchanged and channel idle.
            let mut teardown = unsafe { Teardown::new(channel, owner.clone(), 0) }.unwrap();
            teardown.poll(0).unwrap();
            let initial = [1 << 31, 0x1f000000];
            for index in 0..2 {
                let reply = hop_response(
                    &domain,
                    &model,
                    index,
                    if index == 0 { &initial } else { &[] },
                );
                model.finish(Direction::Tx, index, &[], None);
                finish_rx(&model, index, &reply);
                assert_eq!(teardown.poll(index as u64 + 1).unwrap(), None);
            }
            let response = if reject { initial } else { [0, 1 << 28] };
            let reply = hop_response(&domain, &model, 2, &response);
            model.finish(Direction::Tx, 2, &[], None);
            finish_rx(&model, 2, &reply);
            if reject {
                assert_eq!(teardown.poll(3), Err(HopError::Readback));
            } else {
                assert_eq!(teardown.poll(3).unwrap(), None);
                assert_eq!(teardown.poll(500), Err(HopError::Timeout));
            }
            let writes = model.state.lock().unwrap().writes.len();
            assert_eq!(teardown.poll(501), Err(HopError::Poisoned));
            let mut channel = teardown.into_channel();
            assert!(super::super::hop::quarantined_hops() > before);
            drop(owner);
            assert_eq!(dropped.load(Ordering::Relaxed), 0);
            assert_eq!(
                channel.read(Route::new(0).unwrap(), cfg_address(), 501, 600),
                Err(ChannelError::Poisoned)
            );
            assert_eq!(writes, model.state.lock().unwrap().writes.len());
            channel_release(&mut channel);
        }
    }

    #[test]
    fn already_disabled_hop_is_observed_without_invented_flow_control_writes() {
        use super::super::{
            config::Route,
            hop::{Event, Target, Teardown},
            topology::AdapterKind,
        };
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let dropped = Arc::new(AtomicUsize::new(0));
        let target = Target {
            route: Route::new(0).unwrap(),
            port: 1,
            hop: 8,
            kind: AdapterKind::Lane,
            usb4: true,
            clear_flow_control: true,
        };
        let owner = Arc::new(HopOwner {
            target,
            dropped: dropped.clone(),
        });
        // SAFETY: this synthetic Owner and Channel share the same
        // exclusive NHI/model requester, reservation and reset epoch;
        // its observed adapter metadata is unchanged and channel idle.
        let mut teardown = unsafe { Teardown::new(channel, owner.clone(), 0) }.unwrap();
        teardown.poll(0).unwrap();
        let words = [0x12345, 0x0f0abcde];
        let reply = hop_response(&domain, &model, 0, &words);
        model.finish(Direction::Tx, 0, &[], None);
        finish_rx(&model, 0, &reply);
        assert!(
            matches!(teardown.poll(1).unwrap(),Some(Event::Drained(receipt)) if receipt.before.raw==words && receipt.after.raw==words)
        );
        assert_eq!(model.read32(TX_DESCRIPTOR + 8) >> 16, 1);
        let mut channel = teardown.into_channel();
        drop(owner);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        channel_release(&mut channel);
    }
}
