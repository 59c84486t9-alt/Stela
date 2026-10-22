// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name>
// Copyright (C) 2020-2023 MediaTek Inc.
//! Ordinary PCIe data TX: one 64-byte TXWI fetched by WFDMA, with independent
//! firmware-owned TXP payloads. Descriptor consumption alone cannot free them.
use super::{Allocation, DESC_BYTES, DONE, LAST, QueueIo, retain_queue};
use crate::bus::dma::{
    mapping::{Direction, DmaDomain},
    memory::PageSource,
};
use crate::net::wifi::mediatek::{identity::Chip, tx_free, txp, txwi};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{Ordering, fence};

const TOKENS: usize = 8192;
const MAX_COUNT: usize = 2048;
const MAX_SEGMENT: usize = 4095;
static NEXT_EPOCH: crate::net::wifi::Identities = crate::net::wifi::Identities::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Ring(super::Error),
    Txwi(txwi::Error),
    Txp(txp::Error),
    Free(tx_free::Error),
    InvalidFrame,
    PublicationRefused,
    Full,
    WrongEpoch,
    EpochExhausted,
    UnknownToken(u16),
    DuplicateFree(u16),
    WrongStation(u16),
}
impl From<super::Error> for Error {
    fn from(e: super::Error) -> Self {
        Self::Ring(e)
    }
}
impl From<txwi::Error> for Error {
    fn from(e: txwi::Error) -> Self {
        Self::Txwi(e)
    }
}
impl From<txp::Error> for Error {
    fn from(e: txp::Error) -> Self {
        Self::Txp(e)
    }
}
impl From<tx_free::Error> for Error {
    fn from(e: tx_free::Error) -> Self {
        Self::Free(e)
    }
}
impl From<crate::bus::dma::mapping::DmaError> for Error {
    fn from(e: crate::bus::dma::mapping::DmaError) -> Self {
        Self::Ring(e.into())
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek data TX: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Host ownership epoch, not an extra field invented in firmware packets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch(u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub epoch: Epoch,
    pub serial: u64,
    pub token: u16,
    pub descriptor: u16,
    pub wcid: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreeEvidence {
    pub header: [u32; 2],
    pub wcid: Option<u16>,
    pub pair_word: Option<u32>,
    pub accounting: Option<tx_free::Accounting>,
    pub accounting_word: Option<u32>,
    pub release_word: u32,
}
/// Mapping removal completed after both hardware receipts. No air ACK or TXS
/// status is synthesized. The caller still owns any separate PID/TXS context.
pub struct Released<C> {
    pub receipt: Receipt,
    pub evidence: FreeEvidence,
    pub context: C,
}
struct Packet<C> {
    txwi: Allocation,
    payload: Vec<Allocation>,
    context: Option<C>,
    receipt: Receipt,
    consumed: bool,
    free: Option<FreeEvidence>,
}

/// One actual data queue and the requester's sole ordinary 8192-token table.
/// `C` retains the caller's real association/key-generation context. Completion
/// returns it only after DMA removal; uncertain Drop retains it with the claim.
pub struct DataRing<Q: QueueIo, C: 'static> {
    io: Option<Q>,
    descriptors: Allocation,
    slots: Vec<Option<Receipt>>,
    tokens: Vec<Option<Packet<C>>>,
    ready: VecDeque<u16>,
    domain: Arc<dyn DmaDomain>,
    epoch: Epoch,
    chip: Chip,
    serial: u64,
    next_token: usize,
    head: usize,
    tail: usize,
    queued: usize,
    outstanding: usize,
    poisoned: bool,
    released: bool,
}
impl<Q: QueueIo, C: 'static> DataRing<Q, C> {
    /// # Safety
    /// All `super::TxRing::install` requester/coherent-WB/NoSnoop/ATS/idle
    /// qualifications apply. This owns the actual data queue and the complete
    /// token namespace; no other data submit/free/reset owner may exist. It is
    /// a fresh firmware/token epoch: prior TX, RX, IRQ/deferred work and late
    /// firmware completions are actually drained/reset, not merely forgotten.
    /// The caller serializes station/key retirement with submission and retains
    /// any other users (including TXS) independently. Process/deferred context
    /// is required for canonical allocation, sync, unmap and final Drop.
    pub unsafe fn install(
        io: Q,
        source: &dyn PageSource,
        domain: Arc<dyn DmaDomain>,
        count: usize,
        chip: Chip,
    ) -> Result<Self, Error> {
        if !(4..=MAX_COUNT).contains(&count) || !count.is_power_of_two() {
            return Err(super::Error::InvalidSize.into());
        }
        let epoch = Epoch(NEXT_EPOCH.next().ok_or(Error::EpochExhausted)?);
        let descriptors = Allocation::new(
            source,
            domain.clone(),
            count * DESC_BYTES,
            Direction::Bidirectional,
        )?;
        for i in 0..count {
            descriptors.write32(i * DESC_BYTES + 4, DONE)?;
        }
        descriptors.dma.sync_for_device(0..count * DESC_BYTES)?;
        let base = descriptors.address()?;
        let mut ring = Self {
            io: Some(io),
            descriptors,
            slots: (0..count).map(|_| None).collect(),
            tokens: (0..TOKENS).map(|_| None).collect(),
            ready: VecDeque::new(),
            domain,
            epoch,
            chip,
            serial: 0,
            next_token: 0,
            head: 0,
            tail: 0,
            queued: 0,
            outstanding: 0,
            poisoned: true,
            released: false,
        };
        // Guard the first possible queue-base publication, including failed MMIO.
        ring.descriptors.published = true;
        ring.io
            .as_mut()
            .expect("retained queue")
            .configure(base, count as u16)?;
        if ring.io.as_mut().expect("retained queue").device_index()? != 0 {
            return Err(super::Error::InvalidDeviceIndex.into());
        }
        ring.poisoned = false;
        Ok(ring)
    }
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn pending_descriptors(&self) -> usize {
        self.queued
    }
    pub fn outstanding_tokens(&self) -> usize {
        self.outstanding
    }
    /// Serialized native lifecycle view of actual retained packet contexts.
    /// False does not establish requester-wide or unrelated deferred quiescence.
    pub(in crate::net::wifi::mediatek) fn has_pending_context(
        &self,
        mut matches: impl FnMut(&C) -> bool,
    ) -> bool {
        self.tokens
            .iter()
            .flatten()
            .any(|p| p.context.as_ref().is_some_and(&mut matches))
    }
    fn live(&self) -> Result<(), Error> {
        if self.poisoned || self.released {
            Err(super::Error::Poisoned.into())
        } else {
            Ok(())
        }
    }
    /// Copies an already validated ordinary MPDU into owned canonical mappings.
    /// Config must describe those bytes and the actual acknowledged firmware
    /// station/key/rate tables; encoding cannot validate that shared state.
    /// `context` must retain that generation through completion/quarantine.
    /// Success means queued; an error after publication poisons and retains all
    /// hardware-reachable mappings and context until actual quiescence.
    pub fn submit(
        &mut self,
        source: &dyn PageSource,
        config: txwi::Config,
        bytes: &[u8],
        context: C,
    ) -> Result<Receipt, Error> {
        self.submit_if(source, config, bytes, context, || true)
    }
    /// Recheck a time-sensitive native admission after all payload/TXWI
    /// allocation, mapping and visibility work, immediately before the first
    /// hardware-reachable descriptor address/context publication. Refusal has
    /// published nothing and does not consume a token or poison this ring.
    /// The real owner must still serialize policy/key/radio revocation through
    /// publication; this callback does not manufacture an atomic hardware gate.
    pub(in crate::net::wifi::mediatek) fn submit_if(
        &mut self,
        source: &dyn PageSource,
        config: txwi::Config,
        bytes: &[u8],
        context: C,
        admit: impl FnOnce() -> bool,
    ) -> Result<Receipt, Error> {
        self.live()?;
        if config.chip != self.chip
            || config.frame.bytes != bytes.len()
            || bytes.len() <= 14
            || bytes.len() > MAX_SEGMENT * 4
            || matches!(config.queue, txwi::Queue::Beacon | txwi::Queue::Discovery)
        {
            return Err(Error::InvalidFrame);
        }
        let txd = txwi::encode_mpdu(config, bytes)?;
        if self.queued + 1 >= self.slots.len() - 1 || self.outstanding == TOKENS {
            return Err(Error::Full);
        }
        let token = (0..TOKENS)
            .map(|n| (self.next_token + n) % TOKENS)
            .find(|&i| self.tokens[i].is_none())
            .ok_or(Error::Full)?;
        let serial = self.serial.checked_add(1).ok_or(Error::EpochExhausted)?;
        let receipt = Receipt {
            epoch: self.epoch,
            serial,
            token: token as u16,
            descriptor: self.head as u16,
            wcid: config.wcid,
        };
        // No address has been published yet. Failures here safely unmap fresh RAM.
        let mut payload = Vec::with_capacity(bytes.len().div_ceil(MAX_SEGMENT));
        for chunk in bytes.chunks(MAX_SEGMENT) {
            let data = Allocation::new(
                source,
                self.domain.clone(),
                chunk.len(),
                Direction::ToDevice,
            )?;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    data.pointer(0, chunk.len())?,
                    chunk.len(),
                );
            }
            data.dma.sync_for_device(0..chunk.len())?;
            payload.push(data);
        }
        let txwi = Allocation::new(
            source,
            self.domain.clone(),
            txp::TXWI_BYTES,
            Direction::ToDevice,
        )?;
        let spans = payload
            .iter()
            .zip(bytes.chunks(MAX_SEGMENT))
            .map(|(p, chunk)| txp::Span::new(&p.dma, 0, chunk.len()))
            .collect::<Result<Vec<_>, _>>()?;
        let txp = txp::Encoded::new(token as u16, &spans)?;
        unsafe {
            core::ptr::copy_nonoverlapping(txd.as_ptr(), txwi.pointer(0, 32)?, 32);
            core::ptr::copy_nonoverlapping(txp.bytes().as_ptr(), txwi.pointer(32, 32)?, 32);
        }
        txwi.dma.sync_for_device(0..txp::TXWI_BYTES)?;
        drop(txp);
        drop(spans);
        let address = txwi.address()?;
        if !admit() {
            return Err(Error::PublicationRefused);
        }
        self.tokens[token] = Some(Packet {
            txwi,
            payload,
            context: Some(context),
            receipt,
            consumed: false,
            free: None,
        });
        self.next_token = (token + 1) % TOKENS;
        self.serial = serial;
        self.outstanding += 1;
        // Retain context before the first prefetchable descriptor address store.
        let packet = self.tokens[token].as_mut().expect("inserted token");
        packet.txwi.published = true;
        for data in &mut packet.payload {
            data.published = true;
        }
        self.slots[self.head] = Some(receipt);
        let result = self.publish(address);
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        Ok(receipt)
    }
    fn publish(&mut self, address: u32) -> Result<(), Error> {
        let at = self.head * DESC_BYTES;
        self.descriptors.write32(at, address)?;
        self.descriptors.write32(at + 8, 0)?;
        self.descriptors.write32(at + 12, 0)?;
        self.descriptors
            .write32(at + 4, LAST | ((txp::TXWI_BYTES as u32) << 16))?;
        self.descriptors.dma.sync_for_device(at..at + DESC_BYTES)?;
        self.head = (self.head + 1) % self.slots.len();
        self.queued += 1;
        fence(Ordering::SeqCst);
        self.io
            .as_mut()
            .expect("retained queue")
            .publish(self.head as u16)?;
        Ok(())
    }
    /// Observe one actual WFDMA index advancement. This permits slot reuse,
    /// never payload/TXWI removal or a successful air status by itself.
    pub fn poll_consumed(&mut self) -> Result<Option<Receipt>, Error> {
        self.live()?;
        let result = self.poll_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn poll_inner(&mut self) -> Result<Option<Receipt>, Error> {
        let count = self.slots.len();
        let actual = usize::from(self.io.as_mut().expect("retained queue").device_index()?);
        if actual >= count || (actual + count - self.tail) % count > self.queued {
            return Err(super::Error::InvalidDeviceIndex.into());
        }
        if actual == self.tail {
            return Ok(None);
        }
        fence(Ordering::SeqCst);
        let at = self.tail * DESC_BYTES;
        // SAFETY: actual requester index passed this exact descriptor slot.
        unsafe {
            self.descriptors.dma.sync_for_cpu(at..at + DESC_BYTES)?;
        }
        let receipt = self.slots[self.tail].ok_or(super::Error::OwnershipMismatch)?;
        let packet = self.tokens[usize::from(receipt.token)]
            .as_mut()
            .ok_or(Error::UnknownToken(receipt.token))?;
        if packet.receipt != receipt || packet.consumed {
            return Err(super::Error::OwnershipMismatch.into());
        }
        packet.consumed = true;
        if packet.free.is_some() {
            self.ready.push_back(receipt.token);
        }
        self.slots[self.tail] = None;
        self.tail = (self.tail + 1) % count;
        self.queued -= 1;
        Ok(Some(receipt))
    }
    /// Apply a whole decoded firmware release batch only after every token and
    /// optional WCID has been validated. A bad batch mutates no packet state.
    ///
    /// # Safety
    /// Bytes must be an actual complete, non-dropped type-6 firmware packet from
    /// this requester's owned completed RX queue, in this exact fresh firmware
    /// epoch, delivered once by the serialized RX owner. They must never come
    /// from a network MPDU, fabricated frame or old queue/worker/reset epoch.
    /// Firmware must obey its source token-release contract: all references to
    /// each released TXWI/MSDU have ended and no delayed duplicate release can
    /// follow token reuse. The wire has no generation field; a host cookie or
    /// epoch cannot detect such a stale duplicate after a token is reallocated.
    pub unsafe fn apply_tx_free(&mut self, epoch: Epoch, bytes: &[u8]) -> Result<usize, Error> {
        self.live()?;
        let result = self.free_inner(epoch, bytes);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn free_inner(&mut self, epoch: Epoch, bytes: &[u8]) -> Result<usize, Error> {
        if epoch != self.epoch {
            return Err(Error::WrongEpoch);
        }
        let notification = tx_free::parse(self.chip, bytes)?;
        for event in &notification.events {
            if let tx_free::Event::Release { wcid, token, .. } = *event {
                let packet = self
                    .tokens
                    .get(usize::from(token))
                    .and_then(Option::as_ref)
                    .ok_or(Error::UnknownToken(token))?;
                if packet.free.is_some() {
                    return Err(Error::DuplicateFree(token));
                }
                if wcid.is_some_and(|w| w != packet.receipt.wcid) {
                    return Err(Error::WrongStation(token));
                }
            }
        }
        let mut pair_word = None;
        let mut accounting = None;
        let mut accounting_word = None;
        for event in notification.events {
            match event {
                tx_free::Event::Pair { raw, .. } => {
                    pair_word = Some(raw);
                    accounting = None;
                    accounting_word = None;
                }
                tx_free::Event::Accounting { value, raw, .. } => {
                    accounting = Some(value);
                    accounting_word = Some(raw);
                }
                tx_free::Event::Release {
                    wcid,
                    token,
                    accounting: local,
                    raw,
                } => {
                    let packet = self.tokens[usize::from(token)]
                        .as_mut()
                        .expect("whole batch validated");
                    packet.free = Some(FreeEvidence {
                        header: notification.header,
                        wcid,
                        pair_word,
                        accounting: local.or(accounting),
                        accounting_word,
                        release_word: raw,
                    });
                    if packet.consumed {
                        self.ready.push_back(token);
                    }
                }
            }
        }
        Ok(usize::from(notification.declared_tokens))
    }
    /// Remove mappings only after both actual receipts. Every mapping and
    /// context stays owned if a sync/unmap fails; the epoch then fails closed.
    pub fn take_released(&mut self) -> Result<Option<Released<C>>, Error> {
        self.live()?;
        let result = self.release_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn release_inner(&mut self) -> Result<Option<Released<C>>, Error> {
        let Some(&token) = self.ready.front() else {
            return Ok(None);
        };
        let packet = self.tokens[usize::from(token)]
            .as_mut()
            .ok_or(Error::UnknownToken(token))?;
        let evidence = packet.free.ok_or(super::Error::OwnershipMismatch)?;
        if !packet.consumed {
            return Err(super::Error::OwnershipMismatch.into());
        }
        // SAFETY: observed index consumption AND actual firmware TX-free ended
        // all hardware references. Serialized exclusive owner has no other users.
        unsafe {
            packet.txwi.dma.sync_for_cpu(0..txp::TXWI_BYTES)?;
            for data in &packet.payload {
                data.dma.sync_for_cpu(0..data.dma.bytes())?;
            }
            for data in &mut packet.payload {
                data.release()?;
            }
            packet.txwi.release()?;
        }
        let mut packet = self.tokens[usize::from(token)]
            .take()
            .expect("retained token");
        self.ready.pop_front();
        self.outstanding -= 1;
        Ok(Some(Released {
            receipt: packet.receipt,
            evidence,
            context: packet.context.take().expect("retained context"),
        }))
    }
    /// # Safety
    /// Full hardware/firmware and CPU-worker fence as for raw ring teardown,
    /// including firmware TXP payload accesses and all prior token completions.
    /// A DMA-engine idle bit alone is insufficient. Failed removal retains all
    /// contexts; retry requires this proof still to hold.
    pub unsafe fn release_after_quiesce(&mut self) -> Result<Vec<C>, Error> {
        self.poisoned = true;
        for packet in self.tokens.iter_mut().flatten() {
            for data in &mut packet.payload {
                unsafe {
                    data.release()?;
                }
            }
            unsafe {
                packet.txwi.release()?;
            }
        }
        unsafe {
            self.descriptors.release()?;
        }
        self.released = true;
        let contexts = self
            .tokens
            .iter_mut()
            .filter_map(Option::take)
            .filter_map(|mut p| p.context.take())
            .collect();
        self.slots.fill(None);
        self.ready.clear();
        self.queued = 0;
        self.outstanding = 0;
        Ok(contexts)
    }
}
impl<Q: QueueIo, C: 'static> Drop for DataRing<Q, C> {
    fn drop(&mut self) {
        if self.descriptors.published && !self.released {
            retain_queue(self.io.take());
            // DMA leases quarantine their pins/domain; keep actual station/key
            // context too, including partial successful unmaps before failure.
            for packet in self.tokens.iter_mut().flatten() {
                if let Some(context) = packet.context.take() {
                    core::mem::forget(context);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{
        rx::{Assembly, RxRing},
        tests::{Domain, Io, Memory, Source, State},
    };
    use super::*;
    use core::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    struct Context(Arc<AtomicUsize>, u64);
    impl Drop for Context {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Model {
        tx: Arc<Mutex<State>>,
        rx: Arc<Mutex<State>>,
        memory: Arc<Mutex<Memory>>,
        rx_ring: RxRing<Io>,
        assembly: Assembly,
        drops: Arc<AtomicUsize>,
    }
    fn setup(chip: Chip, count: usize) -> (DataRing<Io, Context>, Model) {
        let memory = Arc::new(Mutex::new(Memory::default()));
        let tx = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let rx = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let domain: Arc<dyn DmaDomain> = Arc::new(Domain(memory.clone()));
        // SAFETY: one fresh, stopped modeled requester; both queues resolve DMA
        // through its one actual mapping registry. No physical claim is made.
        let ring =
            unsafe { DataRing::install(Io(tx.clone()), &Source, domain.clone(), count, chip) }
                .unwrap();
        let rx_ring = unsafe { RxRing::install(Io(rx.clone()), &Source, domain, 8) }.unwrap();
        (
            ring,
            Model {
                tx,
                rx,
                memory,
                rx_ring,
                assembly: Assembly::default(),
                drops: Arc::new(AtomicUsize::new(0)),
            },
        )
    }
    fn config(chip: Chip, bytes: usize) -> txwi::Config {
        txwi::Config {
            chip,
            wcid: 7,
            vif: Some(txwi::Vif {
                omac: 2,
                wmm: 1,
                band: 0,
                mld: false,
            }),
            phy_band_one: false,
            queue: txwi::Queue::Data { access_category: 0 },
            pid: 1,
            frame: txwi::Frame {
                bytes,
                header_bytes: 26,
                kind: txwi::Kind::Data,
                subtype: 8,
                tid: 5,
                multicast: false,
                fragment: txwi::Fragment::None,
                sequence: txwi::Sequence::Hardware,
                minimum_rate: false,
            },
            protect: true,
            no_ack: false,
            hardware_amsdu: false,
            fixed_rate: None,
        }
    }
    fn pointer(memory: &Memory, address: u64, bytes: usize) -> *const u8 {
        let (&base, (pages, pointer, direction)) = memory
            .mappings
            .range(..=address)
            .next_back()
            .expect("actual mapped IOVA");
        let offset = usize::try_from(address - base).unwrap();
        assert!(offset + bytes <= pages.bytes());
        assert_ne!(*direction, Direction::FromDevice);
        assert_ne!(address, (*pointer + offset) as u64);
        (*pointer + offset) as *const u8
    }
    struct DevicePacket {
        address: u64,
        token: u16,
        wcid: u16,
        segments: Vec<(u64, usize)>,
    }
    fn fetch(model: &Model, expected_txd: [u8; 32]) -> DevicePacket {
        let mut tx = model.tx.lock().unwrap();
        assert_ne!(tx.index, tx.head);
        let memory = model.memory.lock().unwrap();
        let descriptor = unsafe {
            core::slice::from_raw_parts(
                pointer(&memory, tx.base + u64::from(tx.index) * 16, 16).cast::<u32>(),
                4,
            )
        };
        assert_eq!(u32::from_le(descriptor[1]), LAST | (64 << 16));
        assert_eq!(descriptor[2..], [0, 0]);
        let address = u64::from(u32::from_le(descriptor[0]));
        let txwi = unsafe { core::slice::from_raw_parts(pointer(&memory, address, 64), 64) };
        assert_eq!(&txwi[..32], expected_txd);
        assert_eq!(
            u16::from_le_bytes(txwi[32..34].try_into().unwrap()) & 0x8000,
            0x8000
        );
        let token = u16::from_le_bytes(txwi[32..34].try_into().unwrap()) & 0x7fff;
        assert!(token < 8192);
        assert_eq!(&txwi[34..40], &[0; 6]);
        let mut segments = Vec::new();
        for i in 0..4 {
            let at = 40 + i / 2 * 12;
            let (address_at, length_at) = if i % 2 == 0 {
                (at, at + 4)
            } else {
                (at + 8, at + 6)
            };
            let addr = u64::from(u32::from_le_bytes(
                txwi[address_at..address_at + 4].try_into().unwrap(),
            ));
            let len = u16::from_le_bytes(txwi[length_at..length_at + 2].try_into().unwrap());
            assert!((1..=4095).contains(&(len & 0x7fff)));
            assert_eq!(len & 0x7000, 0);
            segments.push((addr, usize::from(len & 0xfff)));
            if len & 0x8000 != 0 {
                break;
            }
        }
        let wcid = u32::from_le_bytes(txwi[4..8].try_into().unwrap()) as u16 & 0x3ff;
        // Only WFDMA's TXWI fetch has completed. Firmware may read both TXWI
        // and all referenced MSDUs later, after this index is visible to host.
        tx.index = (tx.index + 1) % tx.count;
        DevicePacket {
            address,
            token,
            wcid,
            segments,
        }
    }
    fn finish(model: &Model, packet: &DevicePacket) -> Vec<u8> {
        let memory = model.memory.lock().unwrap();
        let txwi = unsafe { core::slice::from_raw_parts(pointer(&memory, packet.address, 64), 64) };
        assert_eq!(
            u16::from_le_bytes(txwi[32..34].try_into().unwrap()) & 0x7fff,
            packet.token
        );
        let mut payload = Vec::new();
        for &(address, bytes) in &packet.segments {
            payload.extend_from_slice(unsafe {
                core::slice::from_raw_parts(pointer(&memory, address, bytes), bytes)
            });
        }
        payload
    }
    fn notification(chip: Chip, tokens: &[u16], wcid: u16) -> Vec<u8> {
        let mut words = vec![
            (6 << 27) | ((tokens.len() as u32) << 16),
            if chip == Chip::Mt7925 { 4 << 16 } else { 0 },
        ];
        words.push((1 << 31) | (u32::from(wcid) << if chip == Chip::Mt7925 { 12 } else { 14 }));
        if chip == Chip::Mt7925 {
            words.push((1 << 30) | (3 << 24));
            for pair in tokens.chunks(2) {
                words.push(u32::from(pair[0]) | (u32::from(*pair.get(1).unwrap_or(&0x7fff)) << 15));
            }
        } else {
            for &token in tokens {
                words.push((u32::from(token) << 16) | 3);
            }
        }
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
    fn deliver(model: &mut Model, bytes: &[u8]) -> Vec<u8> {
        super::super::rx::tests::device_receive(&model.rx, bytes, true, 0);
        let fragment = model.rx_ring.poll().unwrap().expect("actual DDONE");
        let frame = model
            .assembly
            .push(fragment)
            .unwrap()
            .expect("complete packet");
        assert!(!frame.drop);
        frame.bytes
    }
    fn quiesce(ring: &mut DataRing<Io, Context>, model: &mut Model) -> Vec<Context> {
        // SAFETY: modeled requester no longer accesses any queue/token buffer.
        let contexts = unsafe { ring.release_after_quiesce() }.unwrap();
        unsafe { model.rx_ring.release_after_quiesce() }.unwrap();
        assert!(model.memory.lock().unwrap().mappings.is_empty());
        contexts
    }
    #[test]
    fn refused_final_admission_changes_no_descriptor_token_or_context_owner() {
        let (mut ring, mut model) = setup(Chip::Mt7925, 8);
        let before = model.memory.lock().unwrap().mappings.len();
        let descriptor = ring.descriptors.read32(0).unwrap();
        let bytes = vec![0x5a; 100];
        let calls = AtomicUsize::new(0);
        let result = ring.submit_if(
            &Source,
            config(Chip::Mt7925, bytes.len()),
            &bytes,
            Context(model.drops.clone(), 1),
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                // Both actual payload and TXWI are mapped before the gate.
                assert_eq!(model.memory.lock().unwrap().mappings.len(), before + 2);
                false
            },
        );
        assert_eq!(result, Err(Error::PublicationRefused));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(model.memory.lock().unwrap().mappings.len(), before);
        assert_eq!(ring.descriptors.read32(0).unwrap(), descriptor);
        assert_eq!(ring.descriptors.read32(4).unwrap(), DONE);
        assert_eq!(model.tx.lock().unwrap().head, 0);
        assert_eq!(ring.pending_descriptors(), 0);
        assert_eq!(ring.outstanding_tokens(), 0);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        assert!(!ring.is_poisoned());
        let receipt = ring
            .submit(
                &Source,
                config(Chip::Mt7925, bytes.len()),
                &bytes,
                Context(model.drops.clone(), 2),
            )
            .unwrap();
        assert_eq!(
            (receipt.serial, receipt.token, receipt.descriptor),
            (1, 0, 0)
        );
        drop(quiesce(&mut ring, &mut model));
        assert_eq!(model.drops.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn actual_requester_reads_txwi_then_late_payload_until_both_completions_through_wrap_and_reuse()
    {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let (mut ring, mut model) = setup(chip, if chip == Chip::Mt7925 { 2048 } else { 8 });
            let baseline = model.memory.lock().unwrap().mappings.len();
            for n in 0..8201u64 {
                let bytes = vec![n as u8; [26, 4095, 4096, 8190, 16380][n as usize % 5]];
                let c = config(chip, bytes.len());
                let receipt = ring
                    .submit(&Source, c, &bytes, Context(model.drops.clone(), n))
                    .unwrap();
                assert_eq!(receipt.token, (n % 8192) as u16);
                assert!(ring.poll_consumed().unwrap().is_none());
                let packet = fetch(&model, txwi::encode(c).unwrap());
                assert_eq!(packet.token, receipt.token);
                if n % 2 == 0 {
                    assert_eq!(ring.poll_consumed().unwrap(), Some(receipt));
                    assert!(ring.take_released().unwrap().is_none());
                    assert!(model.memory.lock().unwrap().mappings.len() > baseline);
                }
                assert_eq!(finish(&model, &packet), bytes);
                let wire = notification(chip, &[packet.token], packet.wcid);
                let complete = deliver(&mut model, &wire);
                // SAFETY: actual modeled firmware finished all TXP reads and
                // delivered this once through this requester's completed RX.
                unsafe { ring.apply_tx_free(ring.epoch(), &complete) }.unwrap();
                if n % 2 == 1 {
                    assert!(ring.take_released().unwrap().is_none());
                    assert_eq!(ring.poll_consumed().unwrap(), Some(receipt));
                }
                let released = ring.take_released().unwrap().expect("both receipts");
                assert_eq!(released.receipt, receipt);
                assert_eq!(released.context.1, n);
                assert_eq!(released.evidence.accounting.unwrap().attempts, 3);
                assert_eq!(released.evidence.accounting.unwrap().status, 0);
                assert_eq!(model.drops.load(Ordering::Relaxed), n as usize);
                drop(released);
                assert_eq!(model.memory.lock().unwrap().mappings.len(), baseline);
                assert_eq!(ring.outstanding_tokens(), 0);
            }
            assert!(quiesce(&mut ring, &mut model).is_empty());
            assert_eq!(model.drops.load(Ordering::Relaxed), 8201);
        }
    }
    #[test]
    fn whole_free_batch_is_validated_before_any_token_changes() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            for case in 0..5 {
                let (mut ring, mut model) = setup(chip, 8);
                let a = ring
                    .submit(
                        &Source,
                        config(chip, 30),
                        &[7; 30],
                        Context(model.drops.clone(), 1),
                    )
                    .unwrap();
                let b = ring
                    .submit(
                        &Source,
                        config(chip, 30),
                        &[8; 30],
                        Context(model.drops.clone(), 2),
                    )
                    .unwrap();
                let tokens = match case {
                    0 => vec![a.token, 8192],
                    1 => vec![a.token, a.token],
                    _ => vec![a.token, b.token],
                };
                let wire = notification(chip, &tokens, if case == 2 { 8 } else { 7 });
                let epoch = if case == 3 {
                    Epoch(ring.epoch.0 + 1)
                } else {
                    ring.epoch()
                };
                if case == 4 {
                    let one = notification(chip, &[b.token], 7);
                    unsafe { ring.apply_tx_free(epoch, &one) }.unwrap();
                }
                let before: Vec<_> = ring.tokens.iter().flatten().map(|p| p.free).collect();
                assert!(unsafe { ring.apply_tx_free(epoch, &wire) }.is_err());
                assert!(ring.is_poisoned());
                assert_eq!(
                    ring.tokens
                        .iter()
                        .flatten()
                        .map(|p| p.free)
                        .collect::<Vec<_>>(),
                    before
                );
                assert_eq!(ring.outstanding_tokens(), 2);
                assert_eq!(model.drops.load(Ordering::Relaxed), 0);
                drop(quiesce(&mut ring, &mut model));
                assert_eq!(model.drops.load(Ordering::Relaxed), 2);
            }
        }
    }
    #[test]
    fn ring_and_token_pressure_are_separate_and_bad_submissions_publish_nothing() {
        let chip = Chip::Mt7925;
        let (mut ring, mut model) = setup(chip, 4);
        for n in 0..8192 {
            ring.submit(
                &Source,
                config(chip, 30),
                &[n as u8; 30],
                Context(model.drops.clone(), n),
            )
            .unwrap();
            fetch(&model, txwi::encode(config(chip, 30)).unwrap());
            assert!(ring.poll_consumed().unwrap().is_some());
        }
        let before = model.memory.lock().unwrap().mappings.len();
        assert_eq!(
            ring.submit(
                &Source,
                config(chip, 30),
                &[0; 30],
                Context(model.drops.clone(), 9999)
            ),
            Err(Error::Full)
        );
        assert_eq!(ring.outstanding_tokens(), 8192);
        assert_eq!(ring.pending_descriptors(), 0);
        assert_eq!(model.memory.lock().unwrap().mappings.len(), before);
        assert!(!ring.is_poisoned());
        drop(quiesce(&mut ring, &mut model));
        assert_eq!(model.drops.load(Ordering::Relaxed), 8193);

        let (mut ring, mut model) = setup(chip, 4);
        for n in 0..2 {
            ring.submit(
                &Source,
                config(chip, 30),
                &[0; 30],
                Context(model.drops.clone(), n),
            )
            .unwrap();
        }
        assert_eq!(
            ring.submit(
                &Source,
                config(chip, 30),
                &[0; 30],
                Context(model.drops.clone(), 2)
            ),
            Err(Error::Full)
        );
        assert_eq!(ring.pending_descriptors(), 2);
        assert_eq!(
            ring.submit(
                &Source,
                config(Chip::Mt7921, 30),
                &[0; 30],
                Context(model.drops.clone(), 3)
            ),
            Err(Error::InvalidFrame)
        );
        assert_eq!(
            ring.submit(
                &Source,
                config(chip, 31),
                &[0; 30],
                Context(model.drops.clone(), 4)
            ),
            Err(Error::InvalidFrame)
        );
        drop(quiesce(&mut ring, &mut model));
        assert_eq!(model.drops.load(Ordering::Relaxed), 5);
    }
    #[test]
    fn uncertain_publication_drop_retains_real_queue_pins_and_context() {
        for failure in [false, true] {
            let chip = Chip::Mt7925;
            let (mut ring, mut model) = setup(chip, 8);
            model.tx.lock().unwrap().fail_publish = failure;
            let result = ring.submit(
                &Source,
                config(chip, 5000),
                &[0; 5000],
                Context(model.drops.clone(), 1),
            );
            assert_eq!(result.is_err(), failure);
            let before = model.memory.lock().unwrap().mappings.len();
            drop(ring);
            assert_eq!(model.tx.lock().unwrap().queue_drops, 0);
            assert_eq!(model.drops.load(Ordering::Relaxed), 0);
            assert_eq!(model.memory.lock().unwrap().mappings.len(), before);
            unsafe { model.rx_ring.release_after_quiesce() }.unwrap();
            assert_eq!(model.rx.lock().unwrap().queue_drops, 0);
            drop(model.rx_ring);
            assert_eq!(model.rx.lock().unwrap().queue_drops, 1);
        }
    }
    #[test]
    fn unmap_and_completion_visibility_failures_retain_context_until_quiescent_retry() {
        for failure in 0..6 {
            let chip = Chip::Mt7925;
            let (mut ring, mut model) = setup(chip, 8);
            ring.submit(
                &Source,
                config(chip, 5000),
                &[0; 5000],
                Context(model.drops.clone(), 1),
            )
            .unwrap();
            let packet = fetch(&model, txwi::encode(config(chip, 5000)).unwrap());
            assert_eq!(finish(&model, &packet), [0; 5000]);
            let complete = deliver(&mut model, &notification(chip, &[packet.token], 7));
            unsafe { ring.apply_tx_free(ring.epoch(), &complete) }.unwrap();
            assert!(ring.poll_consumed().unwrap().is_some());
            {
                let mut memory = model.memory.lock().unwrap();
                if failure < 3 {
                    memory.fail_sync_at = Some(memory.syncs.len() + failure + 1);
                } else {
                    memory.fail_unmap_at = Some(memory.unmaps + failure - 2);
                }
            }
            assert!(ring.take_released().is_err());
            assert!(ring.is_poisoned());
            assert_eq!(ring.outstanding_tokens(), 1);
            assert_eq!(model.drops.load(Ordering::Relaxed), 0);
            assert_eq!(model.tx.lock().unwrap().queue_drops, 0);
            {
                let mut memory = model.memory.lock().unwrap();
                memory.fail_sync_at = None;
                memory.fail_unmap_at = None;
            }
            drop(quiesce(&mut ring, &mut model));
            assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn every_submission_visibility_failure_distinguishes_unpublished_from_reachable_context() {
        for fail in 1..=5 {
            let chip = Chip::Mt7921;
            let (mut ring, mut model) = setup(chip, 8);
            let baseline = model.memory.lock().unwrap().mappings.len();
            {
                let mut memory = model.memory.lock().unwrap();
                memory.fail_sync_at = Some(memory.syncs.len() + fail);
            }
            assert!(
                ring.submit(
                    &Source,
                    config(chip, 10000),
                    &[0; 10000],
                    Context(model.drops.clone(), 1)
                )
                .is_err()
            );
            if fail < 5 {
                assert!(!ring.is_poisoned());
                assert_eq!(ring.outstanding_tokens(), 0);
                assert_eq!(model.memory.lock().unwrap().mappings.len(), baseline);
                assert_eq!(model.drops.load(Ordering::Relaxed), 1);
            } else {
                assert!(ring.is_poisoned());
                assert_eq!(ring.outstanding_tokens(), 1);
                assert!(model.memory.lock().unwrap().mappings.len() > baseline);
                assert_eq!(model.drops.load(Ordering::Relaxed), 0);
            }
            model.memory.lock().unwrap().fail_sync_at = None;
            drop(quiesce(&mut ring, &mut model));
            assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn invalid_actual_indices_and_uncertain_constructor_keep_actual_owner() {
        for actual in [1, u16::MAX] {
            let (mut ring, mut model) = setup(Chip::Mt7921, 8);
            model.tx.lock().unwrap().index = actual;
            assert_eq!(
                ring.poll_consumed(),
                Err(Error::Ring(super::super::Error::InvalidDeviceIndex))
            );
            assert!(ring.is_poisoned());
            quiesce(&mut ring, &mut model);
        }
        let memory = Arc::new(Mutex::new(Memory::default()));
        let state = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            fail_configure: true,
            ..State::default()
        }));
        let domain: Arc<dyn DmaDomain> = Arc::new(Domain(memory.clone()));
        let result = unsafe {
            DataRing::<_, Context>::install(Io(state.clone()), &Source, domain, 2048, Chip::Mt7925)
        };
        assert!(matches!(
            result,
            Err(Error::Ring(super::super::Error::RegisterFailure))
        ));
        assert_eq!(state.lock().unwrap().queue_drops, 0);
        assert_eq!(memory.lock().unwrap().mappings.len(), 1);
    }

    #[test]
    fn failed_partial_quiescent_unmap_drop_retains_context_with_remaining_mappings() {
        let (mut ring, mut model) = setup(Chip::Mt7925, 8);
        ring.submit(
            &Source,
            config(Chip::Mt7925, 10000),
            &[0; 10000],
            Context(model.drops.clone(), 1),
        )
        .unwrap();
        {
            let mut memory = model.memory.lock().unwrap();
            memory.fail_unmap_at = Some(memory.unmaps + 2);
        }
        assert!(unsafe { ring.release_after_quiesce() }.is_err());
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        let remaining = model.memory.lock().unwrap().mappings.len();
        drop(ring);
        assert_eq!(model.memory.lock().unwrap().mappings.len(), remaining);
        assert_eq!(model.tx.lock().unwrap().queue_drops, 0);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        model.memory.lock().unwrap().fail_unmap_at = None;
        unsafe { model.rx_ring.release_after_quiesce() }.unwrap();
    }

    #[test]
    #[ignore = "requires freshly built unchanged Linux descriptor oracle"]
    fn unchanged_dma_add_buf_matches_actual_owned_queue_descriptors() {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };
        let directory =
            std::env::var_os("STELA_MT792X_DATA_ORACLE").expect("STELA_MT792X_DATA_ORACLE");
        for count in [4, 8, 2048] {
            let chip = Chip::Mt7925;
            let (mut ring, mut model) = setup(chip, count);
            let mut input = Vec::new();
            let mut expected = Vec::new();
            for n in 0..100u64 {
                let head = ring.head;
                let queued = ring.queued;
                ring.submit(
                    &Source,
                    config(chip, 100),
                    &[n as u8; 100],
                    Context(model.drops.clone(), n),
                )
                .unwrap();
                let memory = model.memory.lock().unwrap();
                let descriptor = ring.descriptors.pointer(head * 16, 16).unwrap();
                let bytes = unsafe { core::slice::from_raw_parts(descriptor, 16) };
                expected.extend_from_slice(bytes);
                for value in [
                    ring.head as u32,
                    ring.queued as u32,
                    head as u32,
                    1,
                    1,
                    0xffff,
                ] {
                    expected.extend_from_slice(&value.to_le_bytes());
                }
                let address = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                assert!(memory.mappings.contains_key(&u64::from(address)));
                for value in [address, count as u32, head as u32, queued as u32] {
                    input.extend_from_slice(&value.to_le_bytes());
                }
                drop(memory);
                fetch(&model, txwi::encode(config(chip, 100)).unwrap());
                ring.poll_consumed().unwrap().unwrap();
            }
            let mut child = Command::new(std::path::Path::new(&directory).join("data"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(&input).unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                std::string::String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.stdout, expected, "actual owned queue count {count}");
            drop(quiesce(&mut ring, &mut model));
            assert_eq!(model.drops.load(Ordering::Relaxed), 100);
        }
    }
}
