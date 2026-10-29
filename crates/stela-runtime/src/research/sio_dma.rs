//! SIO firmware DMA channel ownership at the recovered 26A434 AP boundary.
//!
//! `AppleSmartIODMAController::bufferForHandle` (KC file 0x2e660e4)
//! addresses 12-byte pool slots; `segmentForHandle` (0x2e66124) skips
//! six slots. `_startDMACommand` (0x2e66764) writes flags/count at +56/+60;
//! `_segmentFunction` (0x2e67538) emits {u64 IOVA,u32 size} entries at +72.
//! `deliverMessage` (0x2e677e0) consumes terminal REPORT 0x68, bit31 set,
//! with the original tag and progress in bits63:32. SIO firmware TX
//! progress (VA0x17f8) excludes bytes still owned by its shim FIFO.
//!
//! This implements real DMA into a bounded peripheral FIFO, not sample
//! playback or a successful SIO firmware handshake. Callers must provide the
//! DART stream and consume FIFO data explicitly; no data is discarded
//! to manufacture progress. Full SIO setup/control, mailbox dispatch, receive
//! channels and DPA physical reset ownership remain separate requirements.
//! Consequently this boundary is not yet registered as complete PMGR coverage.
pub mod setup;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use stela_contracts::bus::LifecycleState;
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};

const SLOT_BYTES: u64 = 12;
/// The original 26A434 controller allocates 0x7ff8 bytes and sends 0xaaa slots.
const MAX_POOL_SLOTS: u32 = 0xaaa;
/// AppleSmartIO::endpointForHandle (0x2e5fd1c) validates identities through 0xe5.
const MAX_CHANNEL: u8 = 0xe5;
const HEADER_BYTES: usize = 72;
const FLAGS_OFFSET: usize = 56;
const COUNT_OFFSET: usize = 60;
const SEGMENT_BYTES: usize = 12;
const REPORT: u64 = 0x68 << 16;
const REPORT_TERMINAL: u64 = 1 << 31;

/// The recovered pool geometry is explicit. Other firmware ABIs, including
/// the public older 48-byte descriptor, must select their own checked layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorLayout {
    ScatterGather72,
}

/// One host-owned SIO descriptor pool. Its size is in 12-byte slots, as the
/// original controller sends parameter2 (0xaaa in 26A434), not a byte count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pool {
    pub iova: u64,
    pub slots: u32,
    pub layout: DescriptorLayout,
}

/// A terminal descriptor report, including an explicit short transfer after
/// software termination. Its count is the bytes consumed by the
/// peripheral, not copied into the shim FIFO or audibly played.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub channel: u8,
    pub tag: u8,
    pub bytes: u32,
}
impl Completion {
    /// Original terminal REPORT payload. The caller owns mailbox delivery;
    /// taking it cannot synthesize an ACK for an unperformed DMA request.
    pub fn report(self) -> u64 {
        u64::from(self.channel)
            | u64::from(self.tag) << 8
            | REPORT
            | REPORT_TERMINAL
            | u64::from(self.bytes) << 32
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported(&'static str),
    Dma(DmaError),
}
impl From<DmaError> for Error {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

/// Six configuration words written by `_configureDMA` at KC 0x2e673b8..
/// 0x2e673f0. The five known fields agree with the independently recovered
/// SIO configuration; the additional original word is supported only as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Configuration {
    pub word_bytes: u8,
    pub fifo_bytes: u32,
    pub threshold: u32,
    pub limit: u32,
}

impl Pool {
    fn address(self, slot: u32, bytes: u64) -> Result<u64, Error> {
        if self.slots == 0 || self.slots > MAX_POOL_SLOTS || self.iova & 0xfff != 0 {
            return Err(Error::Unsupported(
                "SIO descriptor pool geometry is not qualified",
            ));
        }
        let pool_bytes = u64::from(self.slots) * SLOT_BYTES;
        self.iova
            .checked_add(pool_bytes)
            .ok_or(Error::Unsupported("SIO descriptor pool exceeds I/O space"))?;
        let offset = u64::from(slot) * SLOT_BYTES;
        if offset.checked_add(bytes).is_none_or(|end| end > pool_bytes) {
            return Err(Error::Unsupported("SIO descriptor exceeds its pool"));
        }
        Ok(self.iova + offset)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Segment {
    iova: u64,
    bytes: u32,
}

#[derive(Debug)]
struct Transfer {
    tag: u8,
    segments: Vec<Segment>,
    segment: usize,
    offset: u32,
    transferred: u32,
    delivered: u32,
    total: u32,
}

/// A real transmit channel's FIFO and descriptor continuation. Channel numbers
/// are protocol identities, not ADMAC register indices or PMGR device IDs.
/// The SIO provider/board must prove which physical port owns each instance.
pub struct Channel {
    number: u8,
    capacity: usize,
    configuration: Option<Configuration>,
    fifo: VecDeque<u8>,
    transfer: Option<Transfer>,
    completions: VecDeque<Completion>,
    state: LifecycleState,
    stopped: bool,
}

impl Channel {
    pub fn transmit(number: u8, fifo_bytes: usize) -> Result<Self, Error> {
        if number > MAX_CHANNEL
            || number & 1 != 0
            || fifo_bytes == 0
            || fifo_bytes > u16::MAX as usize
        {
            return Err(Error::Unsupported(
                "SIO transmit channel geometry is not qualified",
            ));
        }
        Ok(Self {
            number,
            capacity: fifo_bytes,
            configuration: None,
            fifo: VecDeque::new(),
            transfer: None,
            completions: VecDeque::new(),
            stopped: false,
            state: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
        })
    }

    fn available(&self) -> bool {
        self.state.powered && self.state.clocked && !self.state.quiesced && !self.state.reset
    }

    fn active(&self) -> bool {
        self.available() && !self.stopped
    }

    pub fn pending_bytes(&self) -> usize {
        self.fifo.len()
    }

    /// DMA bytes not yet copied into the shim FIFO. A zero remainder does
    /// not complete a transmit while the peripheral still owns FIFO bytes.
    pub fn remaining_bytes(&self) -> Option<u32> {
        self.transfer
            .as_ref()
            .map(|transfer| transfer.total - transfer.transferred)
    }

    pub fn remaining_delivery_bytes(&self) -> Option<u32> {
        self.transfer
            .as_ref()
            .map(|transfer| transfer.total - transfer.delivered)
    }

    pub fn configuration(&self) -> Option<Configuration> {
        self.configuration
    }

    /// Apply the original shared-memory configuration, without ACKing an
    /// unsupported timeout, shape or additional header effect. The entire
    /// command is checked before replacing configuration.
    pub fn configure(
        &mut self,
        pool: Pool,
        slot: u32,
        port: &mut Port<'_, '_>,
    ) -> Result<(), Error> {
        if !self.available()
            || self.transfer.is_some()
            || !self.fifo.is_empty()
            || !self.completions.is_empty()
        {
            return Err(Error::Unsupported(
                "SIO configuration still has suspended or owned channel work",
            ));
        }
        let address = pool.address(slot, HEADER_BYTES as u64)?;
        let mut data = [0; HEADER_BYTES];
        port.read(address, &mut data)?;
        let words: [u32; 6] = core::array::from_fn(|index| {
            u32::from_le_bytes(data[index * 4..index * 4 + 4].try_into().unwrap())
        });
        let [shape, timeout, fifo, threshold, limit, additional] = words;
        if shape > 2
            || timeout != 0
            || additional != 0
            || data[24..].iter().any(|byte| *byte != 0)
            || fifo as usize != self.capacity
            || limit != fifo
            || threshold != fifo
        {
            return Err(Error::Unsupported(
                "SIO DMA configuration fields are not qualified",
            ));
        }
        self.stopped = false;
        self.configuration = Some(Configuration {
            word_bytes: 1 << shape,
            fifo_bytes: fifo,
            threshold,
            limit,
        });
        Ok(())
    }

    /// Recovered per-channel CONFIGURE(5)/ISSUE(6)/TERMINATE(8) request. The ACK denotes
    /// configuration or descriptor ownership; REPORT is separate and
    /// appears only after peripheral delivery or explicit termination.
    /// Global SIO initialization is not faked.
    pub fn command(
        &mut self,
        pool: Pool,
        payload: u64,
        port: &mut Port<'_, '_>,
    ) -> Result<u64, Error> {
        if payload as u8 != self.number || payload >> 24 & 0xff != 0 {
            return Err(Error::Unsupported(
                "SIO request channel or parameter is not qualified",
            ));
        }
        let tag = (payload >> 8) as u8;
        let kind = (payload >> 16) as u8;
        let slot = (payload >> 32) as u32;
        match kind {
            5 => self.configure(pool, slot, port)?,
            6 if self.configuration.is_some() => self.submit(pool, slot, tag, port)?,
            6 => {
                return Err(Error::Unsupported(
                    "SIO channel has no committed DMA configuration",
                ));
            }
            8 if slot == 0 => self.terminate()?,
            _ => {
                return Err(Error::Unsupported(
                    "SIO control or cancellation command is not qualified",
                ));
            }
        }
        Ok(u64::from(self.number) | u64::from(tag) << 8 | 0x65 << 16 | u64::from(kind) << 32)
    }

    /// Software TERMINATE is distinct from physical DPA reset. Original
    /// `_stopDMA` (0x2e66f64) sends kind8/data0 and, after its ACK, waits for
    /// original command ownership to finish. `deliverMessage` turns a short
    /// terminal byte count into an explicit underrun. Firmware VA0x17f8
    /// subtracts current TX FIFO occupancy from progress; stop VA0x31c0..31d4
    /// samples that value. Keep committed but undelivered bytes, inhibit
    /// further FIFO consumption and report delivery exactly once.
    pub fn terminate(&mut self) -> Result<(), Error> {
        if !self.available() {
            return Err(Error::Unsupported(
                "SIO termination while the channel is suspended is not qualified",
            ));
        }
        self.stopped = true;
        if let Some(transfer) = self.transfer.take() {
            self.completions.push_back(Completion {
                channel: self.number,
                tag: transfer.tag,
                bytes: transfer.delivered,
            });
        }
        Ok(())
    }

    /// Acquire one descriptor only after validating its complete SG snapshot.
    /// A refused acquisition changes no channel/continuation/FIFO ownership;
    /// the IOMMU still reports any real descriptor-table fault it encountered.
    pub fn submit(
        &mut self,
        pool: Pool,
        slot: u32,
        tag: u8,
        port: &mut Port<'_, '_>,
    ) -> Result<(), Error> {
        if !self.active() {
            return Err(Error::Unsupported("SIO DMA channel is suspended"));
        }
        if self.transfer.is_some()
            || !self.fifo.is_empty()
            || self.completions.iter().any(|entry| entry.tag == tag)
        {
            return Err(Error::Unsupported(
                "SIO DMA command, FIFO or completion still owns channel work",
            ));
        }
        let address = pool.address(slot, HEADER_BYTES as u64)?;
        let offset = address - pool.iova;
        let pool_bytes = u64::from(pool.slots) * SLOT_BYTES;
        let mut header = [0; HEADER_BYTES];
        port.read(address, &mut header)?;
        let flags = u32::from_le_bytes(header[FLAGS_OFFSET..FLAGS_OFFSET + 4].try_into().unwrap());
        let count = u32::from_le_bytes(header[COUNT_OFFSET..COUNT_OFFSET + 4].try_into().unwrap());
        if flags != 0
            || count == 0
            || header[..FLAGS_OFFSET]
                .iter()
                .chain(&header[COUNT_OFFSET + 4..])
                .any(|byte| *byte != 0)
        {
            return Err(Error::Unsupported(
                "SIO descriptor header fields or empty transfer are not qualified",
            ));
        }
        let end = offset
            .checked_add(HEADER_BYTES as u64)
            .and_then(|start| start.checked_add(u64::from(count) * SEGMENT_BYTES as u64))
            .filter(|end| *end <= pool_bytes)
            .ok_or(Error::Unsupported(
                "SIO scatter/gather list exceeds its pool",
            ))?;
        // Pool bounds cap allocations; never allocate from an unchecked guest count.
        let mut segments = Vec::with_capacity(count as usize);
        let mut next = offset + HEADER_BYTES as u64;
        let mut total = 0u32;
        while next < end {
            let mut bytes = [0; SEGMENT_BYTES];
            port.read(pool.iova + next, &mut bytes)?;
            let segment = Segment {
                iova: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                bytes: u32::from_le_bytes(bytes[8..].try_into().unwrap()),
            };
            if segment.bytes == 0
                || segment.iova.checked_add(u64::from(segment.bytes)).is_none()
                || self.configuration.is_some_and(|configuration| {
                    !segment
                        .bytes
                        .is_multiple_of(u32::from(configuration.word_bytes))
                        || !segment
                            .iova
                            .is_multiple_of(u64::from(configuration.word_bytes))
                })
            {
                return Err(Error::Unsupported("SIO segment range is not qualified"));
            }
            total = total.checked_add(segment.bytes).ok_or(Error::Unsupported(
                "SIO completion byte count exceeds the recovered wire field",
            ))?;
            segments.push(segment);
            next += SEGMENT_BYTES as u64;
        }
        self.transfer = Some(Transfer {
            tag,
            segments,
            segment: 0,
            offset: 0,
            transferred: 0,
            delivered: 0,
            total,
        });
        Ok(())
    }

    /// Transfer until FIFO backpressure or a real DMA fault. Each successful
    /// page-sized chunk is committed once, so retry cannot duplicate bytes or
    /// re-read a guest-edited SG list after taking ownership.
    pub fn advance(&mut self, port: &mut Port<'_, '_>) -> Result<usize, Error> {
        if !self.active() {
            return Ok(0);
        }
        let mut moved = 0;
        while self.fifo.len() < self.capacity {
            let Some(transfer) = self.transfer.as_mut() else {
                break;
            };
            if transfer.segment == transfer.segments.len() {
                break;
            }
            let segment = transfer.segments[transfer.segment];
            let address = segment.iova + u64::from(transfer.offset);
            let page = port.iommu.page();
            if page == 0 {
                return Err(Error::Unsupported("SIO DMA translation page is zero"));
            }
            let bytes = (self.capacity - self.fifo.len())
                .min((segment.bytes - transfer.offset) as usize)
                .min((page - address % page) as usize);
            let mut data = alloc::vec![0; bytes];
            port.read(address, &mut data)?;
            self.fifo.extend(data);
            transfer.offset += bytes as u32;
            transfer.transferred += bytes as u32;
            moved += bytes;
            if transfer.offset == segment.bytes {
                transfer.segment += 1;
                transfer.offset = 0;
            }
        }
        Ok(moved)
    }

    /// Peripheral consumption. Supply/clock pauses keep samples and
    /// make no forward progress; no timer silently discards buffered output.
    pub fn consume(&mut self, output: &mut [u8]) -> usize {
        if !self.active() {
            return 0;
        }
        let bytes = output.len().min(self.fifo.len());
        for destination in &mut output[..bytes] {
            *destination = self.fifo.pop_front().expect("bounded FIFO count");
        }
        if let Some(transfer) = self.transfer.as_mut() {
            transfer.delivered += bytes as u32;
            if transfer.delivered == transfer.total {
                self.completions.push_back(Completion {
                    channel: self.number,
                    tag: transfer.tag,
                    bytes: transfer.delivered,
                });
                self.transfer = None;
            }
        }
        bytes
    }

    /// Transfer completion remains owned until the transport commits delivery.
    pub fn completion(&self) -> Option<Completion> {
        self.completions.front().copied()
    }

    pub fn acknowledge_completion(&mut self, expected: Completion) -> Result<(), Error> {
        if self.completions.front() != Some(&expected) {
            return Err(Error::Unsupported(
                "SIO completion delivery does not match its owner",
            ));
        }
        self.completions.pop_front();
        Ok(())
    }

    /// Suspension is real, but a PMGR shim reset must not discard
    /// SIO firmware-owned commands, report delivery or FIFO samples. Until
    /// physical reset/cancellation is recovered, destructive edges refuse.
    pub fn check_lifecycle(&self, state: LifecycleState) -> Result<(), Error> {
        if state.reset || !state.powered && !state.retention {
            return Err(Error::Unsupported(
                "SIO/DPA physical reset and memory-loss cancellation remain unqualified",
            ));
        }
        Ok(())
    }

    /// Apply only a state previously checked by the owner before PMGR commit.
    pub fn set_lifecycle(&mut self, state: LifecycleState) {
        self.state = state;
    }
}

#[cfg(test)]
mod tests;
