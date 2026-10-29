// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Serialized configuration requests on the hop-zero NHI rings.
//!
//! Linux ctl.c serializes control work and dispatches asynchronous events apart
//! from replies. This bounded engine owns one request for the whole channel,
//! since an error has no address/sequence and may come from an upstream router.
//! Timeouts/cancellation permanently refuse new requests until the platform
//! destroys/drains/resets the containing channel; late packets cannot be reused.
use super::{config, ring};
use crate::bus::dma::{mapping::DmaDomain, memory::PageSource};
use alloc::sync::Arc;

const RING_ENTRIES: u16 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Config(config::Error),
    Ring(ring::Error),
    Busy,
    Stopped,
    Poisoned,
    InvalidDeadline,
    ClockRegressed,
    IdentityExhausted,
    Timeout { request: u64 },
}
impl From<config::Error> for Error {
    fn from(value: config::Error) -> Self {
        Self::Config(value)
    }
}
impl From<ring::Error> for Error {
    fn from(value: ring::Error) -> Self {
        Self::Ring(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Completed {
        request: u64,
        reply: config::Reply,
    },
    Plug(config::PlugEvent),
    Notification(config::NotificationError),
    /// Bad CRC/markers/header or a late/unrelated reply was dropped. The active
    /// request remains active; a malformed packet never supplies its result.
    Discarded(config::Error),
}
struct Active {
    id: u64,
    deadline: u64,
    request: config::Request,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Running,
    Poisoned,
    Disabled,
    Released,
}

/// A caller-serialized, polled native NHI configuration channel. Ring IRQs must
/// remain masked. Each public clock observation is from one monotonic source in
/// caller-defined units; the driver does not invent a timer or execute waits.
pub struct Channel<R: ring::Registers> {
    tx: ring::Ring<R>,
    rx: ring::Ring<R>,
    phase: Phase,
    active: Option<Active>,
    pending_event: Option<(config::Encoded, Event)>,
    next_sequence: u8,
    next_id: u64,
    last_now: u64,
    tx_released: bool,
    rx_released: bool,
}
impl<R: ring::Registers> Channel<R> {
    /// Allocate the raw TX/RX hop-zero rings without publishing DMA.
    ///
    /// # Safety
    /// All physical NHI ownership/power/coherence/IOMMU/interrupt prerequisites
    /// of `Ring::new` hold for both exclusive hop-zero rings. The native
    /// platform has positively granted software configuration-channel ownership
    /// (there is no firmware ICM owner using these rings). The same kept
    /// mapping/domain describes this live requester for both directions.
    pub unsafe fn new(
        registers: Arc<R>,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        address_limit: u64,
    ) -> Result<Self, Error> {
        let config = |direction| ring::RingConfig {
            direction,
            hop: 0,
            entries: RING_ENTRIES,
            address_limit,
        };
        // SAFETY: caller establishes both exclusive raw hop-zero resources.
        let tx = unsafe {
            ring::Ring::new(
                registers.clone(),
                source,
                domain.clone(),
                config(ring::Direction::Tx),
            )?
        };
        // SAFETY: same physical ownership; TX allocation has not published DMA.
        let rx =
            unsafe { ring::Ring::new(registers, source, domain, config(ring::Direction::Rx))? };
        Ok(Self {
            tx,
            rx,
            phase: Phase::New,
            active: None,
            pending_event: None,
            next_sequence: 0,
            next_id: 0,
            last_now: 0,
            tx_released: false,
            rx_released: false,
        })
    }
    fn poison<T>(&mut self, error: Error) -> Result<T, Error> {
        self.phase = Phase::Poisoned;
        self.active = None;
        Err(error)
    }
    fn running(&self) -> Result<(), Error> {
        match self.phase {
            Phase::Running => Ok(()),
            Phase::Poisoned => Err(Error::Poisoned),
            _ => Err(Error::Stopped),
        }
    }
    fn observe(&mut self, now: u64) -> Result<(), Error> {
        self.running()?;
        if now < self.last_now {
            return self.poison(Error::ClockRegressed);
        }
        self.last_now = now;
        if let Some(active) = self.active.as_ref()
            && now >= active.deadline
        {
            return self.poison(Error::Timeout { request: active.id });
        }
        Ok(())
    }
    /// Enable/prime RX before enabling TX so a request cannot outrun reception.
    pub fn start(&mut self, now: u64) -> Result<(), Error> {
        if self.phase != Phase::New {
            return Err(Error::Busy);
        }
        let result = (|| {
            self.rx.start()?;
            for _ in 1..RING_ENTRIES {
                self.rx.receive()?;
            }
            self.tx.start()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.last_now = now;
                self.phase = Phase::Running;
                Ok(())
            }
            Err(error) => self.poison(error),
        }
    }
    fn issue(&mut self, request: config::Request, now: u64, deadline: u64) -> Result<u64, Error> {
        self.observe(now)?;
        if self.active.is_some() || self.pending_event.is_some() {
            return Err(Error::Busy);
        }
        if deadline <= now {
            return Err(Error::InvalidDeadline);
        }
        let id = self
            .next_id
            .checked_add(1)
            .ok_or(Error::IdentityExhausted)?;
        if let Err(error) = self.tx.transmit(request.frame()) {
            return if error == ring::Error::Full {
                Err(Error::Ring(error))
            } else {
                self.poison(error.into())
            };
        }
        self.active = Some(Active {
            id,
            deadline,
            request,
        });
        self.next_id = id;
        self.next_sequence = (self.next_sequence + 1) & 3;
        Ok(id)
    }
    pub fn read(
        &mut self,
        route: config::Route,
        address: config::Address,
        now: u64,
        deadline: u64,
    ) -> Result<u64, Error> {
        let request = config::Request::read(route, address, self.next_sequence)?;
        self.issue(request, now, deadline)
    }
    pub fn write(
        &mut self,
        route: config::Route,
        address: config::Address,
        data: &[u32],
        now: u64,
        deadline: u64,
    ) -> Result<u64, Error> {
        let request = config::Request::write(route, address, self.next_sequence, data)?;
        self.issue(request, now, deadline)
    }
    pub fn reset(&mut self, route: config::Route, now: u64, deadline: u64) -> Result<u64, Error> {
        self.issue(config::Request::reset(route), now, deadline)
    }
    /// Cancellation has no protocol receipt. Keep published leases and refuse
    /// later requests; only a containing drain/reset can end ambiguity.
    pub fn cancel(&mut self) -> Result<Option<u64>, Error> {
        self.running()?;
        let id = self.active.take().map(|a| a.id);
        self.phase = Phase::Poisoned;
        Ok(id)
    }
    fn acknowledge(&mut self) -> Result<Option<Event>, Error> {
        let Some((frame, _)) = self.pending_event.as_ref() else {
            return Ok(None);
        };
        match self.tx.transmit(frame) {
            Ok(_) => Ok(self.pending_event.take().map(|(_, event)| event)),
            Err(ring::Error::Full) => Ok(None),
            Err(error) => self.poison(error.into()),
        }
    }
    /// Progress completions and at most one receive packet. Hotplug/notification
    /// events are returned only after their real ACK has been published. A full
    /// TX ring keeps that exact event and defers further RX consumption.
    pub fn poll(&mut self, now: u64) -> Result<Option<Event>, Error> {
        self.observe(now)?;
        for _ in 0..RING_ENTRIES {
            match self.tx.poll() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => return self.poison(error.into()),
            }
        }
        if self.pending_event.is_some() {
            return self.acknowledge();
        }
        let completion = match self.rx.poll() {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(None),
            Err(error) => return self.poison(error.into()),
        };
        let event = (|| {
            let received = completion.received()?;
            match received.kind {
                config::PacketType::Event => {
                    let plug = received.event()?;
                    self.pending_event = Some((plug.acknowledgement()?, Event::Plug(plug)));
                    Ok(None)
                }
                config::PacketType::Error if received.notification_error()?.is_some() => {
                    let notice = received
                        .notification_error()?
                        .expect("checked notification");
                    self.pending_event =
                        Some((notice.acknowledgement()?, Event::Notification(notice)));
                    Ok(None)
                }
                _ => {
                    let Some(active) = self.active.as_ref() else {
                        return Err(config::Error::UnexpectedReply);
                    };
                    let reply = active.request.reply(&received)?;
                    let request = active.id;
                    self.active = None;
                    Ok(Some(Event::Completed { request, reply }))
                }
            }
        })();
        // CPU ownership of this exact completed slot was proven by ring.poll.
        // Replenish it even when the packet was malformed or unrelated.
        if let Err(error) = self.rx.receive() {
            return self.poison(error.into());
        }
        match event {
            Err(error) => Ok(Some(Event::Discarded(error))),
            Ok(Some(event)) => Ok(Some(event)),
            Ok(None) => self.acknowledge(),
        }
    }
    /// Attempt both disables even if either fails; no DMA lease is reclaimed.
    pub fn disable(&mut self) -> Result<(), Error> {
        if self.phase == Phase::Released {
            return Err(Error::Stopped);
        }
        self.active = None;
        let tx = if self.tx_released {
            Ok(())
        } else {
            self.tx.disable()
        };
        let rx = if self.rx_released {
            Ok(())
        } else {
            self.rx.disable()
        };
        match tx.and(rx) {
            Ok(()) => {
                self.phase = Phase::Disabled;
                Ok(())
            }
            Err(error) => self.poison(error.into()),
        }
    }
    /// # Safety
    /// Both rings have acknowledged final posted-DMA/IRQ/worker drain,
    /// exactly as required by `Ring::release`. Execute in process/deferred
    /// context. A failed invalidation keeps its leases and supports retry.
    pub unsafe fn release(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Disabled {
            return Err(Error::Busy);
        }
        // SAFETY: the caller proves final drain of both rings.
        unsafe {
            ring::release_pair(
                (&mut self.tx, &mut self.tx_released),
                (&mut self.rx, &mut self.rx_released),
            )?;
        }
        self.phase = Phase::Released;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::bus::dma::mapping::DmaError;

    use crate::bus::thunderbolt::config::PacketType;
    use crate::bus::thunderbolt::ring::{
        self, COMPLETED, Direction, ENABLE, RAW, RX_OPTIONS, TX_OPTIONS, model::*,
    };

    use core::sync::atomic::Ordering;

    #[test]
    fn configuration_channel_owns_ring_dma_and_wraps_sequence_and_rings() {
        use super::super::{
            channel::{Error as ChannelError, Event},
            config::{Reply, Route},
        };
        let (source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let writes = &model.state.lock().unwrap().writes.clone();
        let rx_enable = writes
            .iter()
            .position(|(offset, value)| *offset == RX_OPTIONS && *value == ENABLE | RAW)
            .unwrap();
        let tx_enable = writes
            .iter()
            .position(|(offset, value)| *offset == TX_OPTIONS && *value == ENABLE | RAW)
            .unwrap();
        assert!(rx_enable < tx_enable);
        for cycle in 0..24u32 {
            let now = u64::from(cycle);
            let id = channel
                .read(Route::new(19).unwrap(), cfg_address(), now, now + 100)
                .unwrap();
            assert_eq!(id, now + 1);
            let before = model.state.lock().unwrap().writes.len();
            assert_eq!(
                channel.read(Route::new(20).unwrap(), cfg_address(), now, now + 100),
                Err(ChannelError::Busy)
            );
            assert_eq!(before, model.state.lock().unwrap().writes.len());
            let transmitted = domain.data(
                model.frame_address(Direction::Tx, (cycle % 10) as usize),
                16,
            );
            let address = u32::from_be_bytes(transmitted[8..12].try_into().unwrap());
            assert_eq!((address >> 27) & 3, cycle & 3);
            assert_eq!(&transmitted[..8], &[0, 0, 0, 0, 0, 0, 0, 19]);
            model.finish(Direction::Tx, (cycle % 10) as usize, &[], None);
            let reply = incoming(PacketType::Read, &[1 << 31, 19, address, cycle]);
            finish_rx(&model, (cycle % 10) as usize, &reply);
            assert_eq!(
                channel.poll(now).unwrap(),
                Some(Event::Completed {
                    request: id,
                    reply: Reply::Configuration {
                        upstream_port: 2,
                        data: vec![cycle]
                    }
                })
            );
        }
        channel_release(&mut channel);
        drop(channel);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(
            source.allocated.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn unrelated_corrupt_and_asynchronous_packets_do_not_finish_outstanding_request() {
        use super::super::{
            channel::{Error as ChannelError, Event},
            config::{Reply, Route},
        };
        let (_source, domain, model, mut channel) = channel();
        channel.start(1).unwrap();
        let id = channel
            .read(Route::new(19).unwrap(), cfg_address(), 1, 100)
            .unwrap();
        let transmitted = domain.data(model.frame_address(Direction::Tx, 0), 16);
        let address = u32::from_be_bytes(transmitted[8..12].try_into().unwrap());
        let wrong = incoming(PacketType::Read, &[1 << 31, 19, address ^ (1 << 27), 55]);
        finish_rx(&model, 0, &wrong);
        assert_eq!(
            channel.poll(2).unwrap(),
            Some(Event::Discarded(
                super::super::config::Error::UnexpectedReply
            ))
        );
        let mut corrupt = incoming(PacketType::Read, &[1 << 31, 19, address, 55]);
        corrupt.bytes[12] ^= 1;
        finish_rx(&model, 1, &corrupt);
        assert_eq!(
            channel.poll(3).unwrap(),
            Some(Event::Discarded(super::super::config::Error::Checksum))
        );
        let plug = incoming(PacketType::Event, &[0, 7, 6]);
        finish_rx(&model, 2, &plug);
        assert!(
            matches!(channel.poll(4).unwrap(),Some(Event::Plug(event)) if event.route.raw()==7 && event.port==6)
        );
        let plug_ack = domain.data(model.frame_address(Direction::Tx, 1), 16);
        assert_eq!(&plug_ack[..12], &[0, 0, 0, 0, 0, 0, 0, 7, 0x80, 0, 6, 7]);
        let notice = incoming(PacketType::Error, &[0, 8, 35 | (4 << 8)]);
        finish_rx(&model, 3, &notice);
        assert!(
            matches!(channel.poll(5).unwrap(),Some(Event::Notification(event)) if event.route.raw()==8 && event.code==35)
        );
        let notification_ack = domain.data(model.frame_address(Direction::Tx, 2), 12);
        assert_eq!(&notification_ack[..8], &[0, 0, 0, 0, 0, 0, 0, 8]);
        let before = model.state.lock().unwrap().writes.len();
        assert_eq!(
            channel.read(Route::new(1).unwrap(), cfg_address(), 6, 50),
            Err(ChannelError::Busy)
        );
        assert_eq!(before, model.state.lock().unwrap().writes.len());
        let upstream_error = incoming(PacketType::Error, &[1 << 31, 0, 15 | (9 << 8)]);
        finish_rx(&model, 4, &upstream_error);
        assert!(
            matches!(channel.poll(6).unwrap(),Some(Event::Completed { request,reply:Reply::ControllerError { route,port:9,code:15,.. } }) if request==id && route.raw()==0)
        );
        channel_release(&mut channel);
    }

    #[test]
    fn channel_timeout_cancel_and_clock_regression_never_reuse_ambiguous_dma() {
        use super::super::{channel::Error as ChannelError, config::Route};
        for case in 0..3 {
            let (_source, _domain, model, mut channel) = channel();
            channel.start(5).unwrap();
            let id = channel
                .read(Route::new(0).unwrap(), cfg_address(), 5, 10)
                .unwrap();
            let writes = model.state.lock().unwrap().writes.len();
            match case {
                0 => assert_eq!(channel.poll(10), Err(ChannelError::Timeout { request: id })),
                1 => assert_eq!(channel.cancel(), Ok(Some(id))),
                _ => assert_eq!(channel.poll(4), Err(ChannelError::ClockRegressed)),
            }
            assert_eq!(
                channel.read(Route::new(0).unwrap(), cfg_address(), 11, 30),
                Err(ChannelError::Poisoned)
            );
            assert_eq!(channel.poll(11), Err(ChannelError::Poisoned));
            assert_eq!(model.state.lock().unwrap().writes.len(), writes);
            channel_release(&mut channel);
        }
    }

    #[test]
    fn full_ack_ring_keeps_event_and_defers_rx_until_tx_completion() {
        use super::super::{channel::Event, config::Route};
        let (_source, domain, model, mut channel) = channel();
        channel.start(0).unwrap();
        let id = channel
            .read(Route::new(19).unwrap(), cfg_address(), 0, 100)
            .unwrap();
        let sent = domain.data(model.frame_address(Direction::Tx, 0), 16);
        let address = u32::from_be_bytes(sent[8..12].try_into().unwrap());
        for index in 0..9 {
            let plug = incoming(PacketType::Event, &[0, 7, index as u32]);
            finish_rx(&model, index, &plug);
            let result = channel.poll(1).unwrap();
            if index < 8 {
                assert!(matches!(result, Some(Event::Plug(_))));
            } else {
                assert_eq!(result, None);
            }
        }
        let reply = incoming(PacketType::Read, &[1 << 31, 19, address, 77]);
        finish_rx(&model, 9, &reply);
        let before = model.state.lock().unwrap().writes.len();
        assert_eq!(channel.poll(2).unwrap(), None);
        assert_eq!(model.state.lock().unwrap().writes.len(), before);
        model.finish(Direction::Tx, 0, &[], None);
        assert!(matches!(channel.poll(3).unwrap(),Some(Event::Plug(event)) if event.port==8));
        assert!(
            matches!(channel.poll(4).unwrap(),Some(Event::Completed { request,.. }) if request==id)
        );
        channel_release(&mut channel);
    }

    #[test]
    fn channel_partial_final_invalidation_can_retry_after_one_ring_is_released() {
        let (source, domain, _model, mut channel) = channel();
        channel.start(0).unwrap();
        channel.disable().unwrap();
        domain.fail_unmap_at.store(12, Ordering::Relaxed);
        assert_eq!(
            // SAFETY: no synthetic activity survives the containing final drain.
            unsafe { channel.release() },
            Err(super::super::channel::Error::Ring(ring::Error::Dma(
                DmaError::InvalidationFailed
            )))
        );
        // Repeating disable cannot touch an already-released TX ring or lose
        // the RX invalidation retry; both outcomes previously succeeded.
        channel.disable().unwrap();
        // SAFETY: the same acknowledged final synthetic drain still applies.
        unsafe { channel.release() }.unwrap();
        drop(channel);
        assert!(domain.state.lock().unwrap().maps.is_empty());
        assert_eq!(
            source.allocated.load(Ordering::Relaxed),
            source.released.load(Ordering::Relaxed)
        );
    }

    #[test]
    fn raw_rx_preserves_posted_and_frame_mode_aliases_in_completed_descriptors() {
        for flags in 0..16u16 {
            let (_source, _domain, model, mut ring) = self::ring(Direction::Rx, 4);
            ring.start().unwrap();
            ring.receive().unwrap();
            model.finish(
                Direction::Rx,
                0,
                &[0x45; 16],
                Some((u32::from(flags | COMPLETED) << 20) | (1 << 12) | 16),
            );
            let completed = ring.poll().unwrap().unwrap();
            assert_eq!(completed.flags, flags | COMPLETED);
            assert_eq!(completed.data, vec![0x45; 16]);
            release(&mut ring);
        }
    }
}
