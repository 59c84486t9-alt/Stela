//! SIO firmware DMA channel ownership at the recovered 26A434 AP boundary.
//!
//! `AppleSmartIODMAController::bufferForHandle` (KC file 0x2e660e4)
//! addresses 12-byte pool slots; `segmentForHandle` (0x2e66124) skips
//! six slots. `_startDMACommand` (0x2e66764) writes flags/count at +56/+60;
//! `_segmentFunction` (0x2e67538) emits {u64 IOVA,u32 size} entries at +72.
//! `deliverMessage` (0x2e677e0) consumes terminal REPORT 0x68, bit31 set,
//! with the original tag and actual progress in bits63:32. SIO firmware TX
//! progress (VA0x17f8) excludes bytes still owned by its shim FIFO.
//!
//! This implements real DMA into a bounded peripheral FIFO, not sample
//! playback or a successful SIO firmware handshake. Callers must provide the
//! actual DART stream and consume FIFO data explicitly; no data is discarded
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
/// the public older 48-byte descriptor, must select their own qualified layout.
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
/// software termination. Its count is the bytes actually consumed by the
/// peripheral, not merely copied into the shim FIFO or audibly played.
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
    /// actual configuration or descriptor ownership; REPORT is separate and
    /// appears only after actual peripheral delivery or explicit termination.
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
    /// samples that value. Retain committed but undelivered bytes, inhibit
    /// further FIFO consumption and report actual delivery exactly once.
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

    /// Actual peripheral consumption. Supply/clock pauses retain samples and
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

    /// Retained suspension is real, but a PMGR shim reset must not discard
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
mod tests {
    use super::*;
    use {
        stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram,
        stela_contracts::interrupt::InterruptLatch,
    };

    const RAM: u64 = 0x8000;
    const BUFFER: u64 = RAM + 0x2000;

    fn descriptor(ram: &mut Ram, slot: u32, segments: &[(u64, u32)]) {
        let start = slot as usize * SLOT_BYTES as usize;
        ram.bytes[start + COUNT_OFFSET..start + COUNT_OFFSET + 4]
            .copy_from_slice(&(segments.len() as u32).to_le_bytes());
        for (index, &(address, bytes)) in segments.iter().enumerate() {
            let start = start + HEADER_BYTES + index * SEGMENT_BYTES;
            ram.bytes[start..start + 8].copy_from_slice(&address.to_le_bytes());
            ram.bytes[start + 8..start + 12].copy_from_slice(&bytes.to_le_bytes());
        }
    }

    fn pool() -> Pool {
        Pool {
            iova: RAM,
            slots: 0xaaa,
            layout: DescriptorLayout::ScatterGather72,
        }
    }

    #[test]
    fn original_scatter_gather_reports_only_after_actual_peripheral_delivery() {
        let mut ram = Ram::new(RAM, 0x8000);
        ram.bytes[0x2000..0x2008].copy_from_slice(b"abcdefgh");
        descriptor(&mut ram, 8, &[(BUFFER, 3), (BUFFER + 3, 5)]);
        let mut channel = Channel::transmit(100, 4).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut physical = Physical;
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        channel.submit(pool(), 8, 0x82, &mut port).unwrap();
        assert_eq!(channel.advance(&mut port), Ok(4));
        assert_eq!(channel.remaining_bytes(), Some(4));
        assert_eq!(channel.completion(), None);
        assert_eq!(channel.advance(&mut port), Ok(0));
        let mut samples = [0; 8];
        assert_eq!(channel.consume(&mut samples[..4]), 4);
        assert_eq!(channel.advance(&mut port), Ok(4));
        assert_eq!(channel.remaining_bytes(), Some(0));
        assert_eq!(channel.remaining_delivery_bytes(), Some(4));
        assert_eq!(channel.completion(), None);
        assert_eq!(channel.consume(&mut samples[4..]), 4);
        assert_eq!(&samples, b"abcdefgh");
        let completion = channel.completion().unwrap();
        assert_eq!(
            completion,
            Completion {
                channel: 100,
                tag: 0x82,
                bytes: 8
            }
        );
        assert_eq!(completion.report(), 0x0000000880688264);
        assert!(channel.submit(pool(), 8, 0x82, &mut port).is_err());
        assert!(
            channel
                .acknowledge_completion(Completion {
                    tag: 0x83,
                    ..completion
                })
                .is_err()
        );
        assert_eq!(channel.completion(), Some(completion));
        channel.acknowledge_completion(completion).unwrap();
        assert_eq!(channel.completion(), None);
    }

    #[test]
    fn retained_clock_and_quiesce_pause_actual_dma_and_fifo_without_completing_work() {
        let mut ram = Ram::new(RAM, 0x8000);
        ram.bytes[0x2000..0x2004].copy_from_slice(b"data");
        descriptor(&mut ram, 1, &[(BUFFER, 4)]);
        let mut channel = Channel::transmit(102, 2).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut physical = Physical;
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        channel.submit(pool(), 1, 1, &mut port).unwrap();
        channel.advance(&mut port).unwrap();
        let initial = channel.state;
        for state in [
            LifecycleState {
                clocked: false,
                ..initial
            },
            LifecycleState {
                quiesced: true,
                ..initial
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..initial
            },
        ] {
            channel.check_lifecycle(state).unwrap();
            channel.set_lifecycle(state);
            assert_eq!(channel.advance(&mut port), Ok(0));
            assert_eq!(channel.consume(&mut [0; 2]), 0);
            assert_eq!(channel.pending_bytes(), 2);
            assert_eq!(channel.remaining_bytes(), Some(2));
            assert_eq!(channel.completion(), None);
        }
        for state in [
            LifecycleState {
                reset: true,
                ..initial
            },
            LifecycleState {
                powered: false,
                ..initial
            },
        ] {
            assert!(channel.check_lifecycle(state).is_err());
            assert_eq!(channel.remaining_bytes(), Some(2));
            assert_eq!(channel.pending_bytes(), 2);
        }
        channel.set_lifecycle(initial);
        let mut samples = [0; 4];
        assert_eq!(channel.consume(&mut samples[..2]), 2);
        assert_eq!(channel.advance(&mut port), Ok(2));
        assert_eq!(channel.consume(&mut samples[2..]), 2);
        assert_eq!(&samples, b"data");
        assert_eq!(channel.completion().unwrap().bytes, 4);
    }

    #[test]
    fn later_dma_fault_preserves_committed_chunks_and_pinned_scatter_gather_ownership() {
        let mut ram = Ram::new(RAM, 0x3000);
        ram.bytes[0x2000..0x2004].copy_from_slice(b"once");
        descriptor(&mut ram, 1, &[(BUFFER, 4), (RAM + 0x3000, 4)]);
        let mut channel = Channel::transmit(100, 8).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut physical = Physical;
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        channel.submit(pool(), 1, 7, &mut port).unwrap();
        assert_eq!(
            channel.advance(&mut port),
            Err(Error::Dma(DmaError::Memory))
        );
        assert_eq!(channel.pending_bytes(), 4);
        assert_eq!(channel.remaining_bytes(), Some(4));
        assert_eq!(channel.completion(), None);
        // Alter the guest table after acquisition, then make only the original
        // second segment available. Retry must not duplicate or redirect it.
        descriptor(&mut ram, 1, &[(BUFFER + 100, 4)]);
        ram.bytes.resize(0x4000, 0);
        ram.bytes[0x3000..0x3004].copy_from_slice(b"next");
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(channel.advance(&mut port), Ok(4));
        let mut samples = [0; 8];
        assert_eq!(channel.consume(&mut samples), 8);
        assert_eq!(&samples, b"oncenext");
        assert_eq!(channel.completion().unwrap().bytes, 8);
    }

    #[test]
    fn configure_and_issue_ack_real_effects_and_unknown_controls_never_ack() {
        let mut ram = Ram::new(RAM, 0x8000);
        ram.bytes[0x2000..0x2004].copy_from_slice(b"word");
        descriptor(&mut ram, 8, &[(BUFFER, 4)]);
        let mut channel = Channel::transmit(100, 8).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut physical = Physical;
        let configure = 100 | 7 << 8 | 5 << 16;
        let issue = 100 | 9 << 8 | 6 << 16 | 8 << 32;
        {
            let mut port = Port {
                iommu: &mut physical,
                stream: 2,
                memory: &mut ram,
                access: &mut access,
            };
            assert!(channel.command(pool(), issue, &mut port).is_err());
        }
        for (index, word) in [2u32, 0, 8, 8, 8, 0].into_iter().enumerate() {
            ram.bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        {
            let mut port = Port {
                iommu: &mut physical,
                stream: 2,
                memory: &mut ram,
                access: &mut access,
            };
            assert_eq!(
                channel.command(pool(), configure, &mut port),
                Ok(100 | 7 << 8 | 0x65 << 16 | 5 << 32)
            );
            assert_eq!(channel.configuration().unwrap().word_bytes, 4);
            for unsupported in [
                100 | 2 << 16,
                100 | 3 << 16,
                100 | 8 << 16 | 1 << 32,
                issue | 1 << 24,
                issue ^ 1,
            ] {
                assert!(channel.command(pool(), unsupported, &mut port).is_err());
                assert_eq!(channel.remaining_bytes(), None);
            }
            assert_eq!(
                channel.command(pool(), issue, &mut port),
                Ok(100 | 9 << 8 | 0x65 << 16 | 6 << 32)
            );
            assert_eq!(channel.completion(), None);
            assert!(channel.command(pool(), configure, &mut port).is_err());
            assert_eq!(channel.advance(&mut port), Ok(4));
        }
        let mut samples = [0; 4];
        assert_eq!(channel.consume(&mut samples), 4);
        assert_eq!(&samples, b"word");
        let completion = channel.completion().unwrap();
        channel.acknowledge_completion(completion).unwrap();
        let before = channel.configuration();
        // A nonzero extra original word must not disappear behind an ACK.
        ram.bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(channel.command(pool(), configure, &mut port).is_err());
        assert_eq!(channel.configuration(), before);
        assert_eq!(channel.remaining_bytes(), None);
    }

    #[test]
    fn software_termination_reports_peripheral_delivery_and_retains_undelivered_fifo_ownership() {
        let mut ram = Ram::new(RAM, 0x8000);
        ram.bytes[0x2000..0x2008].copy_from_slice(b"keeprest");
        descriptor(&mut ram, 1, &[(BUFFER, 8)]);
        let mut channel = Channel::transmit(100, 4).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut physical = Physical;
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        channel.submit(pool(), 1, 17, &mut port).unwrap();
        channel.advance(&mut port).unwrap();
        let mut consumed = [0; 2];
        assert_eq!(channel.consume(&mut consumed), 2);
        assert_eq!(&consumed, b"ke");
        assert_eq!(channel.remaining_delivery_bytes(), Some(6));
        assert_eq!(
            channel.command(pool(), 100 | 99 << 8 | 8 << 16, &mut port),
            Ok(100 | 99 << 8 | 0x65 << 16 | 8 << 32)
        );
        let report = Completion {
            channel: 100,
            tag: 17,
            bytes: 2,
        };
        assert_eq!(channel.completion(), Some(report));
        assert_eq!(channel.remaining_bytes(), None);
        assert_eq!(channel.advance(&mut port), Ok(0));
        assert_eq!(channel.pending_bytes(), 2);
        assert_eq!(channel.fifo.iter().copied().collect::<Vec<_>>(), b"ep");
        assert_eq!(channel.consume(&mut [0; 8]), 0);
        assert!(channel.submit(pool(), 1, 17, &mut port).is_err());
        channel.terminate().unwrap();
        assert_eq!(channel.completions.len(), 1);
        channel.acknowledge_completion(report).unwrap();
        assert_eq!(channel.completion(), None);
        // Clock/power resume cannot undo a software stop or discard its FIFO.
        let initial = channel.state;
        for paused in [
            LifecycleState {
                clocked: false,
                ..initial
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..initial
            },
            LifecycleState {
                quiesced: true,
                ..initial
            },
        ] {
            channel.check_lifecycle(paused).unwrap();
            channel.set_lifecycle(paused);
            channel.set_lifecycle(initial);
            assert_eq!(channel.consume(&mut [0; 8]), 0);
            assert_eq!(channel.advance(&mut port), Ok(0));
            assert_eq!(channel.pending_bytes(), 2);
            assert!(channel.submit(pool(), 1, 18, &mut port).is_err());
        }
        // A distinct command canceled before any delivery reports zero,
        // even when all its DMA bytes already reached the FIFO.
        let mut channel = Channel::transmit(100, 8).unwrap();
        channel.submit(pool(), 1, 17, &mut port).unwrap();
        channel.advance(&mut port).unwrap();
        assert_eq!(channel.remaining_bytes(), Some(0));
        assert_eq!(channel.completion(), None);
        channel.terminate().unwrap();
        assert_eq!(channel.completion().unwrap().bytes, 0);
        assert_eq!(channel.pending_bytes(), 8);
    }

    #[test]
    fn actual_dart_clock_and_stream_faults_cannot_be_substituted_for_dma_success() {
        use {
            crate::platform::apple::dart::Dart, stela_contracts::bus::Access,
            stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
        };
        let mut ram = Ram::new(RAM, 0x8000);
        ram.bytes[0x2000..0x2004].copy_from_slice(b"real");
        descriptor(&mut ram, 1, &[(BUFFER, 4)]);
        let mut channel = Channel::transmit(100, 4).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut dart = Dart::new(16, None);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: 2,
                memory: &mut ram,
                access: &mut access,
            };
            assert!(matches!(
                channel.submit(pool(), 1, 9, &mut port),
                Err(Error::Dma(DmaError::Fault(_)))
            ));
            assert_eq!(channel.remaining_bytes(), None);
            assert_eq!(channel.completion(), None);
        }
        dart.write(0xc00, Width::Word, 4, &mut access).unwrap();
        dart.write(0x1008, Width::Word, 6, &mut access).unwrap();
        let mut port = Port {
            iommu: &mut dart,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        channel.submit(pool(), 1, 9, &mut port).unwrap();
        dart.set_clock(false);
        let mut port = Port {
            iommu: &mut dart,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(matches!(
            channel.advance(&mut port),
            Err(Error::Dma(DmaError::Unsupported(_)))
        ));
        assert_eq!(channel.pending_bytes(), 0);
        assert_eq!(channel.remaining_bytes(), Some(4));
        assert_eq!(channel.completion(), None);
        dart.set_clock(true);
        let mut port = Port {
            iommu: &mut dart,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(channel.advance(&mut port), Ok(4));
        let mut samples = [0; 4];
        assert_eq!(channel.consume(&mut samples), 4);
        assert_eq!(&samples, b"real");
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_SIO_KERNELCACHE"]
    fn original_controller_proves_pool_header_segments_and_terminal_report_layout() {
        use sha2::{Digest, Sha256};
        let path =
            std::env::var("STELA_TEST_SIO_KERNELCACHE").expect("pinned original kernelcache path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        // Exact original instructions are source-integrity evidence for this
        // ABI. Production dispatch never consults offsets or input hashes.
        for (offset, opcode) in [
            (0x2e660f4, 0x52800189),
            (0x2e66134, 0x11001829),
            (0x2e66a84, 0x2907201f),
            (0x2e67568, 0xf9000161),
            (0x2e67584, 0xb9000162),
            (0x2e66a98, 0x528000c8),
            (0x2e67804, 0x7101a11f),
            (0x2e67810, 0x36f803c8),
            (0x2e650f0, 0x52815542),
            (0x2e64f7c, 0x528fff02),
            (0x2e673e8, 0xb9001409),
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original SIO driver at {offset:#x}"
            );
        }
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_SIO_FIRMWARE"]
    fn original_firmware_excludes_undelivered_fifo_bytes_from_tx_stop_report() {
        use sha2::{Digest, Sha256};
        let path =
            std::env::var("STELA_TEST_SIO_FIRMWARE").expect("pinned original SIO firmware path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "356dbeba0e7f5d0a36e3db2eddce66dca6869e8629aa322f4da1addf0a9780cc"
        );
        // Original PRELOAD __TEXT VA0 has file offset0x1000. The stop path
        // queries progress adjusted for TX FIFO occupancy before REPORT.
        // These bounded source-integrity checks never affect production.
        for (address, opcode) in [
            (0x17f8, 0xf9410809),
            (0x1804, 0xb9402120),
            (0x1828, 0x11007108),
            (0x182c, 0xb8684928),
            (0x1830, 0x12003908),
            (0x1834, 0x4b080148),
            (0x1838, 0x4b282000),
            (0x31c4, 0x97fff99f),
            (0x31cc, 0x97fff98b),
            (0x31d4, 0x36f81840),
            (0x3e14, 0x52900d08),
            (0x3e28, 0x3940c029),
            (0x3e2c, 0xb940142a),
            (0x3e3c, 0xb9000fea),
            (0x3e4c, 0x3d800000),
            (0x45b8, 0x39400823),
            (0x45d4, 0xaa03814a),
        ] {
            let offset = address + 0x1000;
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original SIO firmware at VA{address:#x}"
            );
        }
    }

    #[test]
    fn malformed_or_out_of_pool_descriptors_refuse_before_command_ownership() {
        let mut ram = Ram::new(RAM, 0x8000);
        let mut channel = Channel::transmit(100, 8).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = super::super::bus::Access::new(0, 0, &mut latch);
        let mut physical = Physical;
        for segments in [
            vec![],
            vec![(u64::MAX - 1, 4)],
            vec![(BUFFER, 0)],
            vec![(BUFFER, u32::MAX), (BUFFER, 1)],
        ] {
            descriptor(&mut ram, 1, &segments);
            let mut port = Port {
                iommu: &mut physical,
                stream: 2,
                memory: &mut ram,
                access: &mut access,
            };
            assert!(channel.submit(pool(), 1, 1, &mut port).is_err());
            assert_eq!(channel.remaining_bytes(), None);
            assert_eq!(channel.pending_bytes(), 0);
        }
        let mut port = Port {
            iommu: &mut physical,
            stream: 2,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(channel.submit(pool(), 0xaaa, 1, &mut port).is_err());
        for invalid in [
            Pool {
                slots: u32::MAX,
                ..pool()
            },
            Pool {
                iova: u64::MAX - 0xfff,
                ..pool()
            },
            Pool {
                iova: RAM + 1,
                ..pool()
            },
        ] {
            assert!(channel.submit(invalid, 1, 1, &mut port).is_err());
            assert_eq!(channel.remaining_bytes(), None);
        }
        assert!(Channel::transmit(101, 8).is_err());
        assert!(Channel::transmit(0xe6, 8).is_err());
    }
}
