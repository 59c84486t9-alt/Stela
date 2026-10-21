// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Andreas Noever <andreas.noever@gmail.com>
// Copyright (C) 2018 Intel Corporation
//! Serialized configuration requests on the actual hop-zero NHI rings.
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
    /// Allocate the actual raw TX/RX hop-zero rings without publishing DMA.
    ///
    /// # Safety
    /// All physical NHI ownership/power/coherence/IOMMU/interrupt prerequisites
    /// of `Ring::new` hold for both exclusive hop-zero rings. The native
    /// platform has positively granted software configuration-channel ownership
    /// (there is no firmware ICM owner using these rings). The same retained
    /// mapping/domain describes this exact live requester for both directions.
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
    /// later requests; only an actual containing drain/reset can end ambiguity.
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
    /// TX ring retains that exact event and defers further RX consumption.
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
    /// Both rings have actual acknowledged final posted-DMA/IRQ/worker drain,
    /// exactly as required by `Ring::release`. Execute in process/deferred
    /// context. A failed invalidation keeps its leases and supports retry.
    pub unsafe fn release(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Disabled {
            return Err(Error::Busy);
        }
        if !self.tx_released {
            // SAFETY: caller establishes actual final drain for both rings.
            unsafe {
                self.tx.release()?;
            }
            self.tx_released = true;
        }
        if !self.rx_released {
            // SAFETY: as above; successful TX release does not authorize RX.
            unsafe {
                self.rx.release()?;
            }
            self.rx_released = true;
        }
        self.phase = Phase::Released;
        Ok(())
    }
}
