// SPDX-License-Identifier: GPL-2.0-only
//! Retained single-queue BCM5720 copper Ethernet backend.
use super::{Delay, Error, Hardware, Registers};
use crate::{
    bus::dma::{
        mapping::DmaDomain,
        memory::{MemoryError, PageSource},
    },
    net::{HEADER, Link, LinkError, MAX_FRAME, MIN_FRAME, Mac, check_frame},
};
use alloc::{format, sync::Arc, vec::Vec};
mod memory;
use memory::{Memory, RET, RX, TX};

const SD_STATUS_ERROR: u32 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Building,
    Running,
    Faulted,
    Stopped,
}
/// Actual PCI/config/MMIO ownership, isolated requester domain and pinned rings
/// form one lifetime. An uncertain epoch retains all of them. No IRQs or worker
/// callbacks are registered by this polled backend.
pub struct Packet<R: Registers, D: Delay> {
    hardware: Hardware<R, D>,
    memory: Option<Memory>,
    domain: Arc<dyn DmaDomain>,
    mac: Mac,
    board: Option<super::transport::board::Board>,
    carrier_up: bool,
    state: State,
    failure: Option<Error>,
    mbuf_low_water_events: u64,
    tx_producer: usize,
    tx_consumer: usize,
    rx_producer: usize,
    rx_consumer: usize,
    /// True only after all preconditions for attempted device containment have
    /// been observed; arbitrary unsupported hardware is never stopped here.
    identified: bool,
}
impl<R: Registers, D: Delay> Packet<R, D> {
    /// Attach an actual exclusively owned stopped requester, with real NVM
    /// bootcode already present. Errors return the whole retained epoch.
    ///
    /// # Safety
    /// `hardware` owns the actual BCM5720 function/config/UC MAC/APE resources
    /// described by `Registers`, powered in PCI D0. `domain` is the actual
    /// isolated requester domain for that function/aliases; it retains its root
    /// and performs real invalidation, coherence and payload write drain.
    /// `pages` supplies retained pins, never synthetic physical addresses.
    /// Inherited DMA is stopped/drained, BusMaster clear, MSI/MSI-X disabled and
    /// posted messages/CPU vectors/workers drained before this call. Those
    /// original interrupt exclusions remain retained in the actual register
    /// owner through retirement; no other provider may re-enable them.
    /// All calls/releases run in the original provider's qualified context.
    /// A numeric BDF, arbitrary Arc or fake domain cannot grant this authority.
    pub unsafe fn attach(
        hardware: Hardware<R, D>,
        pages: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, (Error, Self)> {
        let mut value = Self {
            hardware,
            memory: None,
            domain,
            mac: Mac::default(),
            board: None,
            carrier_up: false,
            state: State::Building,
            failure: None,
            mbuf_low_water_events: 0,
            tx_producer: 0,
            tx_consumer: 0,
            rx_producer: RX - 1,
            rx_consumer: 0,
            identified: false,
        };
        let result = (|| {
            let board = value.hardware.packet_prepare()?;
            value.identified = true;
            value.mac = board.mac;
            value.board = Some(board);
            value.hardware.packet_reset(board)?;
            match Memory::new(pages, value.domain.clone()) {
                Ok(memory) => value.memory = Some(memory),
                Err((error, memory)) => {
                    value.memory = Some(memory);
                    return Err(error);
                }
            }
            let addresses = value.memory.as_ref().unwrap().addresses()?;
            value.hardware.packet_start(board, addresses)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                value.state = State::Running;
                Ok(value)
            }
            Err(error) => {
                value.fault(error);
                Err((error, value))
            }
        }
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    /// Successfully handled BCM5720 A0 MBUF low-water discard indications,
    /// acknowledged through the real W1C register. Multiple drops can coalesce
    /// into one event; this is not an exact packet-loss counter. Faulted cause
    /// or acknowledgement observations remain in `failure`. Saturates at u64::MAX.
    pub fn mbuf_low_water_events(&self) -> u64 {
        self.mbuf_low_water_events
    }
    fn fault(&mut self, error: Error) -> Error {
        self.failure.get_or_insert(error);
        self.state = State::Faulted;
        error
    }
    fn check(&self) -> Result<(), Error> {
        if self.state == State::Running {
            Ok(())
        } else {
            Err(Error::Stopped)
        }
    }
    fn poll(&mut self) -> Result<usize, Error> {
        self.check()?;
        self.hardware.request_status()?;
        let (flags, tx, rx) = self.memory.as_ref().unwrap().status()?;
        if flags & SD_STATUS_ERROR != 0 && self.hardware.packet_attention()? {
            self.mbuf_low_water_events = self.mbuf_low_water_events.saturating_add(1);
        }
        if tx >= TX || rx >= RET {
            return Err(Error::RingCorrupt);
        }
        let done = (tx + TX - self.tx_consumer) % TX;
        let pending = (self.tx_producer + TX - self.tx_consumer) % TX;
        if done > pending {
            return Err(Error::RingCorrupt);
        }
        for _ in 0..done {
            self.memory
                .as_ref()
                .unwrap()
                .complete_tx(self.tx_consumer)?;
            self.tx_consumer = (self.tx_consumer + 1) % TX;
        }
        Ok(rx)
    }
    /// Stop MAC/DMA engines, observe BusMaster clear and complete the original
    /// remapper's posted payload drain. A failed attempt remains retryable only
    /// for containment; it can never resume submission or invent completion.
    pub fn stop(&mut self) -> Result<(), Error> {
        if self.state == State::Stopped {
            return Ok(());
        }
        self.state = State::Faulted;
        if !self.identified {
            return Err(self.failure.unwrap_or(Error::NotIdentified));
        }
        let result = (|| {
            self.hardware.packet_stop()?;
            // SAFETY: real engines acknowledged stopped, original BME clear;
            // retained isolated domain and every packet/status target remain.
            unsafe {
                self.domain.drain_posted_writes()?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.state = State::Stopped;
                Ok(())
            }
            Err(error) => Err(self.fault(error)),
        }
    }
    /// Release only after stop/drain and acknowledged removal of every real
    /// mapping. An unmap error returns this same epoch with original owners.
    pub fn retire(mut self) -> Result<R, (Error, Self)> {
        let result = self.stop().and_then(|()| {
            if let Some(memory) = &mut self.memory {
                memory.retire()?;
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                self.memory.take();
                Ok(self.hardware.release_registers())
            }
            Err(error) => {
                self.failure.get_or_insert(error);
                Err((error, self))
            }
        }
    }
    fn restart_after_link_loss(&mut self) -> Result<(), Error> {
        self.hardware.packet_stop()?;
        // SAFETY: actual acknowledged engine stop and BME clear above; every
        // target, original requester domain and interrupt exclusion is retained.
        unsafe {
            self.domain.drain_posted_writes()?;
        }
        let board = self.board.ok_or(Error::NotIdentified)?;
        self.hardware.packet_reset(board)?;
        // SAFETY: the old epoch is fully stopped/drained and the chip reset;
        // the same real mappings remain, with no intervening new DMA source.
        unsafe {
            self.memory.as_mut().unwrap().reset_after_drain()?;
        }
        let addresses = self.memory.as_ref().unwrap().addresses()?;
        self.hardware.packet_start(board, addresses)?;
        self.tx_producer = 0;
        self.tx_consumer = 0;
        self.rx_producer = RX - 1;
        self.rx_consumer = 0;
        Ok(())
    }
    fn transmit_inner(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.poll()?;
        if (self.tx_producer + 1) % TX == self.tx_consumer {
            return Err(Error::RingFull);
        }
        self.memory.as_ref().unwrap().tx(self.tx_producer, frame)?;
        self.tx_producer = (self.tx_producer + 1) % TX;
        self.hardware.tx_producer(self.tx_producer)
    }
    fn receive_inner(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let producer = self.poll()?;
        // A finite pass drops damaged frames without blocking on new traffic.
        for _ in 0..RET {
            if self.rx_consumer == producer {
                return Ok(None);
            }
            let (_, frame) = self.memory.as_mut().unwrap().receive(self.rx_consumer)?;
            // The next spare producer slot must really be CPU-owned; the
            // memory layer refuses an out-of-order return which violates it.
            self.memory.as_mut().unwrap().offer(self.rx_producer)?;
            self.rx_producer = (self.rx_producer + 1) % RX;
            self.hardware.rx_producer(self.rx_producer)?;
            self.rx_consumer = (self.rx_consumer + 1) % RET;
            self.hardware.rx_consumer(self.rx_consumer)?;
            if frame.is_some() {
                return Ok(frame);
            }
        }
        Err(Error::RingCorrupt)
    }
}
impl<R: Registers, D: Delay> Link for Packet<R, D> {
    fn mac(&self) -> Mac {
        self.mac
    }
    fn carrier(&mut self) -> bool {
        if self.check().is_err() {
            return false;
        }
        match self.hardware.packet_carrier() {
            Ok(carrier) => {
                if !carrier && self.carrier_up {
                    self.carrier_up = false;
                    if let Err(error) = self.restart_after_link_loss() {
                        self.fault(error);
                        return false;
                    }
                }
                self.carrier_up = carrier;
                carrier
            }
            Err(error) => {
                self.fault(error);
                false
            }
        }
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        check_frame(frame)?;
        if !self.carrier() {
            return if let Some(error) = self.failure {
                Err(LinkError::Adapter(format!("tg3: {error:?}")))
            } else {
                Err(LinkError::NoCarrier)
            };
        }
        match self.transmit_inner(frame) {
            Ok(()) => Ok(()),
            Err(Error::RingFull) => Err(LinkError::Adapter("tg3 transmit ring full".into())),
            Err(error) => {
                self.fault(error);
                Err(LinkError::Adapter(format!("tg3: {error:?}")))
            }
        }
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        if !self.carrier() {
            return if let Some(error) = self.failure {
                Err(LinkError::Adapter(format!("tg3: {error:?}")))
            } else {
                Ok(None)
            };
        }
        match self.receive_inner() {
            Ok(frame) => Ok(frame),
            Err(error) => {
                self.fault(error);
                Err(LinkError::Adapter(format!("tg3: {error:?}")))
            }
        }
    }
}
#[cfg(test)]
mod tests;
