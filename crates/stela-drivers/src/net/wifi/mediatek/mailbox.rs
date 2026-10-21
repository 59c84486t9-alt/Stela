// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
// Copyright (C) 2019 Lorenzo Bianconi <lorenzo.bianconi83@gmail.com>
//! Serialized polling boot mailbox over actual WFDMA TX/RX queues. Firmware
//! scatter needs real TX-DMA completion; acknowledged commands need both DMA
//! completion and an actual correctly sequenced MCU event. Timeout poisons the
//! complete mailbox epoch and retains owned queues/pins until controller reset.
use super::{
    download::{FailureKind, PortState, Transport, TransportFailure},
    firmware::{Prepared, Requests},
    identity::Identity,
    mcu::{self, Command, Encoder, Event, Queue},
    ring::{
        self, QueueIo, TxRing,
        rx::{Assembly, Frame, RxRing},
    },
};
use alloc::vec::Vec;

const TIMEOUT_US: u64 = 3_000_000;
const MAX_EVENTS: usize = 64;
const MAX_EVENT_BYTES: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cause {
    PendingTransmit,
    ClockUnavailable,
    Ring(ring::Error),
    Message(mcu::Error),
    Timeout,
    EventLimit,
    CoreDump,
    CookieMismatch,
    Poisoned,
    FirmwareTarget,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    pub command: Command,
    pub sequence: u8,
    pub dma_released: bool,
    pub cause: Cause,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reply {
    pub command: Command,
    pub sequence: u8,
    pub result: u32,
    pub dma_released: bool,
    pub frame: Frame,
}

pub struct Mailbox<W: QueueIo, F: QueueIo, R: QueueIo> {
    identity: Identity,
    wm: TxRing<W>,
    fwdl: TxRing<F>,
    rx: RxRing<R>,
    assembly: Assembly,
    encoder: Encoder,
    clock: crate::Clock,
    cookie: u64,
    poisoned: bool,
    last_failure: Option<Failure>,
    events: Vec<Frame>,
    event_bytes: usize,
    replies: Vec<Reply>,
}
impl<W: QueueIo, F: QueueIo, R: QueueIo> Mailbox<W, F, R> {
    /// # Safety
    /// All three actual queues must belong exclusively to this one actually
    /// observed identity/requester and the same coherent native DMA attachment.
    /// They must be the chip's WM/FWDL TX and WM event RX queues, configured by
    /// the owning controller with engines enabled, device IRQ sources masked,
    /// no competing command/NAPI/reset owners, and the actual calibrated Clock.
    /// Successful construction also requires an actual reset/fresh firmware
    /// command-sequencing epoch: every old command-processing path, old RX
    /// response, IRQ and deferred worker has drained, and no late response from
    /// a previous epoch can arrive. Empty TX queues alone cannot prove this.
    /// This constructor neither admits PCI ownership nor starts/resets hardware.
    pub unsafe fn from_rings(
        identity: Identity,
        wm: TxRing<W>,
        fwdl: TxRing<F>,
        rx: RxRing<R>,
        clock: crate::Clock,
    ) -> Result<Self, Cause> {
        if wm.pending() != 0 || fwdl.pending() != 0 {
            return Err(Cause::PendingTransmit);
        }
        if clock.ticks_per_microsecond == 0 {
            return Err(Cause::ClockUnavailable);
        }
        Ok(Self {
            identity,
            wm,
            fwdl,
            rx,
            assembly: Assembly::default(),
            encoder: Encoder::default(),
            clock,
            cookie: 0,
            poisoned: false,
            last_failure: None,
            events: Vec::new(),
            event_bytes: 0,
            replies: Vec::new(),
        })
    }
    pub fn last_failure(&self) -> Option<Failure> {
        self.last_failure
    }
    /// Unexpected/unsolicited frames are retained under explicit resource bounds.
    /// The caller dispatches them before radio/MLME continuation; none is silently
    /// consumed as an acknowledgement or dropped from a successful boot result.
    pub fn events(&self) -> &[Frame] {
        &self.events
    }
    pub fn replies(&self) -> &[Reply] {
        &self.replies
    }
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn failure(
        &mut self,
        command: Command,
        sequence: u8,
        dma_released: bool,
        cause: Cause,
    ) -> TransportFailure {
        self.poisoned = true;
        if self.last_failure.is_none() {
            self.last_failure = Some(Failure {
                command,
                sequence,
                dma_released,
                cause,
            });
        }
        TransportFailure {
            kind: if cause == Cause::Timeout {
                FailureKind::Timeout
            } else {
                FailureKind::InvalidResponse
            },
            port: PortState::Uncertain,
        }
    }
    fn retain(&mut self, frame: Frame) -> Result<(), Cause> {
        if self.events.len() == MAX_EVENTS || self.event_bytes + frame.bytes.len() > MAX_EVENT_BYTES
        {
            return Err(Cause::EventLimit);
        }
        self.event_bytes += frame.bytes.len();
        self.events.push(frame);
        Ok(())
    }
    fn next_frame(&mut self) -> Result<Option<Frame>, ring::Error> {
        let Some(fragment) = self.rx.poll()? else {
            return Ok(None);
        };
        self.assembly.push(fragment)
    }
    fn transfer(&mut self, command: Command, payload: &[u8]) -> Result<u32, TransportFailure> {
        self.transfer_timed(command, payload, TIMEOUT_US)
    }
    fn transfer_timed(
        &mut self,
        command: Command,
        payload: &[u8],
        timeout_us: u64,
    ) -> Result<u32, TransportFailure> {
        if self.poisoned {
            return Err(self.failure(command, 0, false, Cause::Poisoned));
        }
        let packet = self
            .encoder
            .encode(self.identity.chip, command, payload)
            .map_err(|_| TransportFailure {
                kind: FailureKind::InvalidResponse,
                port: PortState::Usable,
            })?;
        let sequence = packet.sequence;
        let Some(cookie) = self.cookie.checked_add(1) else {
            return Err(self.failure(command, sequence, false, Cause::CookieMismatch));
        };
        self.cookie = cookie;
        let submit = match packet.queue {
            Queue::Wm => self.wm.submit(cookie, &packet.bytes),
            Queue::FirmwareDownload => self.fwdl.submit(cookie, &packet.bytes),
        };
        submit.map_err(|e| self.failure(command, sequence, false, Cause::Ring(e)))?;
        let deadline = self.clock.deadline(timeout_us);
        let mut dma_released = false;
        let mut reply: Option<(u32, usize)> = None;
        loop {
            if !dma_released {
                let completion = match packet.queue {
                    Queue::Wm => self.wm.poll(),
                    Queue::FirmwareDownload => self.fwdl.poll(),
                }
                .map_err(|e| self.failure(command, sequence, false, Cause::Ring(e)))?;
                if let Some(completion) = completion {
                    if completion.cookie != cookie || completion.bytes != packet.bytes.len() {
                        return Err(self.failure(command, sequence, false, Cause::CookieMismatch));
                    }
                    dma_released = true;
                    if let Some((_, index)) = reply {
                        self.replies[index].dma_released = true;
                    }
                }
            }
            if let Some(frame) = self
                .next_frame()
                .map_err(|e| self.failure(command, sequence, dma_released, Cause::Ring(e)))?
            {
                if frame.drop {
                    self.retain(frame)
                        .map_err(|e| self.failure(command, sequence, dma_released, e))?;
                    return Err(self.failure(
                        command,
                        sequence,
                        dma_released,
                        Cause::Message(mcu::Error::NotResponse),
                    ));
                }
                let event = Event::parse(self.identity.chip, &frame.bytes);
                match event {
                    Ok(event)
                        if event.event_id == 0xf0
                            || (event.option & 2 != 0 && event.event_id == 0x0a) =>
                    {
                        self.retain(frame)
                            .map_err(|e| self.failure(command, sequence, dma_released, e))?;
                        return Err(self.failure(command, sequence, dma_released, Cause::CoreDump));
                    }
                    Ok(event) => match event.boot_result(&packet) {
                        Ok(result) if reply.is_none() => {
                            if self.replies.len() == 1024 {
                                return Err(self.failure(
                                    command,
                                    sequence,
                                    dma_released,
                                    Cause::EventLimit,
                                ));
                            }
                            let index = self.replies.len();
                            self.replies.push(Reply {
                                command,
                                sequence,
                                result,
                                dma_released,
                                frame,
                            });
                            reply = Some((result, index));
                        }
                        _ => self
                            .retain(frame)
                            .map_err(|e| self.failure(command, sequence, dma_released, e))?,
                    },
                    Err(_) => self
                        .retain(frame)
                        .map_err(|e| self.failure(command, sequence, dma_released, e))?,
                }
            }
            if dma_released && (!packet.expects_response() || reply.is_some()) {
                if let Some((result, index)) = reply {
                    self.replies[index].dma_released = true;
                    return Ok(result);
                }
                return Ok(0);
            }
            if deadline.passed() {
                return Err(self.failure(command, sequence, dma_released, Cause::Timeout));
            }
            core::hint::spin_loop();
        }
    }
    /// # Safety
    /// The actual controller has acknowledged WFDMA idle/reset and drained every
    /// submission/IRQ/worker, including timed-out command processing, before any
    /// queue mapping is removed. A software timeout is never this proof.
    pub unsafe fn release_after_quiesce(&mut self) -> Result<(), ring::Error> {
        self.poisoned = true;
        unsafe {
            self.wm.release_after_quiesce()?;
            self.fwdl.release_after_quiesce()?;
            self.rx.release_after_quiesce()?
        };
        Ok(())
    }
}
impl<W: QueueIo, F: QueueIo, R: QueueIo> Transport for Mailbox<W, F, R> {
    fn validate_firmware(&self, prepared: &Prepared<'_>) -> Result<(), TransportFailure> {
        if *prepared.requests() != Requests::new(&self.identity) {
            return Err(TransportFailure {
                kind: FailureKind::FirmwareTarget,
                port: PortState::Usable,
            });
        }
        Ok(())
    }
    fn command(&mut self, command: u8, payload: &[u8]) -> Result<u32, TransportFailure> {
        let command = Command::try_from(command).map_err(|_| TransportFailure {
            kind: FailureKind::InvalidResponse,
            port: PortState::Usable,
        })?;
        if command == Command::Scatter {
            return Err(TransportFailure {
                kind: FailureKind::InvalidResponse,
                port: PortState::Usable,
            });
        }
        self.transfer(command, payload)
    }
    fn scatter(&mut self, payload: &[u8]) -> Result<(), TransportFailure> {
        self.transfer(Command::Scatter, payload).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        firmware::tests::{catalog, patch_bytes, ram_bytes},
        identity::{Chip, PciIdentity},
        ring::{
            rx::tests::device_receive,
            tests::{Domain, Io, Memory, Source, State, device_complete_one},
        },
    };
    use super::*;
    extern crate std;
    use alloc::sync::Arc;
    use std::sync::Mutex;
    struct DeviceIo {
        io: Io,
        rx: Arc<Mutex<State>>,
        chip: Chip,
        reply: bool,
        wrong_seq: bool,
        delay: usize,
        polls: usize,
        pending_index: Option<u16>,
        fwdl: bool,
    }
    // SAFETY: one serialized model requester; actual model IOVA memory is read
    // before TX-index completion and actual RX IOVA bytes written before DDONE.
    unsafe impl QueueIo for DeviceIo {
        fn configure(&mut self, address: u32, count: u16) -> Result<(), ring::Error> {
            self.io.configure(address, count)
        }
        fn device_index(&mut self) -> Result<u16, ring::Error> {
            self.polls += 1;
            if self.polls >= self.delay
                && let Some(index) = self.pending_index.take()
            {
                self.io.0.lock().unwrap().index = index;
            }
            self.io.device_index()
        }
        fn publish(&mut self, head: u16) -> Result<(), ring::Error> {
            self.io.publish(head)?;
            let old = self.io.0.lock().unwrap().index;
            device_complete_one(&self.io.0);
            let packet = self.io.0.lock().unwrap().completed.last().unwrap().clone();
            if self.delay != 0 {
                self.pending_index = Some(self.io.0.lock().unwrap().index);
                self.io.0.lock().unwrap().index = old;
                self.polls = 0;
            }
            if !self.fwdl && self.reply {
                let command = packet[36];
                let seq = packet[39];
                let base = if self.chip == Chip::Mt7925 { 32 } else { 24 };
                let mut response = vec![0u8; base + 12];
                response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                response[base..base + 2].copy_from_slice(&12u16.to_le_bytes());
                response[base + 4] = if command == 0x10 { 4 } else { 1 };
                response[base + 5] = if self.wrong_seq { seq % 15 + 1 } else { seq };
                response[base + 8] = if command == 0x10 {
                    if packet[64] == 1 { 2 } else { 3 }
                } else {
                    0
                };
                device_receive(&self.rx, &response, true, 0);
            }
            Ok(())
        }
    }
    fn identity(chip: Chip) -> Identity {
        let id = match chip {
            Chip::Mt7921 => 0x7961,
            Chip::Mt7922 => 0x7922,
            Chip::Mt7925 => 0x7925,
        };
        Identity::observed(
            PciIdentity {
                vendor: 0x14c3,
                device: id,
                subsystem_vendor: 0x1234,
                subsystem_device: 0xabcd,
                revision: 3,
                class: [2, 0x80, 0],
            },
            u32::from(id),
            0x12340010,
            Some(0),
        )
        .unwrap()
    }
    type TestMailbox = Mailbox<DeviceIo, DeviceIo, Io>;
    type ModelState = Arc<Mutex<State>>;
    fn setup(
        chip: Chip,
        reply: bool,
        wrong_seq: bool,
        delay: usize,
    ) -> (TestMailbox, ModelState, ModelState, ModelState) {
        // One real modeled requester/domain has one shared IOVA namespace.
        // Queue register states remain independent; all device DMA resolves
        // through this same registry and allocator.
        let memory = Arc::new(Mutex::new(Memory::default()));
        let domain: Arc<dyn crate::bus::dma::mapping::DmaDomain> = Arc::new(Domain(memory.clone()));
        let wm = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let fwdl = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let rx = Arc::new(Mutex::new(State {
            memory: memory.clone(),
            ..State::default()
        }));
        let alloc_tx = |state: Arc<Mutex<State>>, is_fwdl| {
            unsafe {
                TxRing::install(
                    DeviceIo {
                        io: Io(state.clone()),
                        rx: rx.clone(),
                        chip,
                        reply,
                        wrong_seq,
                        delay,
                        polls: 0,
                        pending_index: None,
                        fwdl: is_fwdl,
                    },
                    &Source,
                    domain.clone(),
                    8,
                )
            }
            .unwrap()
        };
        let wmring = alloc_tx(wm.clone(), false);
        let fwring = alloc_tx(fwdl.clone(), true);
        let rxring =
            unsafe { RxRing::install(Io(rx.clone()), &Source, domain.clone(), 8) }.unwrap();
        {
            let bases = [
                wm.lock().unwrap().base,
                fwdl.lock().unwrap().base,
                rx.lock().unwrap().base,
            ];
            let memory = memory.lock().unwrap();
            assert_eq!(memory.mappings.len(), 27);
            let mut last_end = 0;
            let mut cpu = alloc::collections::BTreeSet::new();
            for (&address, (pins, pointer, _direction)) in &memory.mappings {
                assert!(address >= last_end);
                last_end = address + pins.bytes() as u64;
                assert!(cpu.insert(*pointer));
            }
            assert_ne!(bases[0], bases[1]);
            assert_ne!(bases[0], bases[2]);
            assert_ne!(bases[1], bases[2]);
        }
        // SAFETY: all queues are exclusively owned parts of this one modeled chip;
        // clock is a live RDTSC test boundary and all firmware events use real IOVAs.
        let m = unsafe {
            Mailbox::from_rings(
                identity(chip),
                wmring,
                fwring,
                rxring,
                crate::Clock {
                    ticks_per_microsecond: 1,
                },
            )
        }
        .unwrap();
        (m, wm, fwdl, rx)
    }
    #[test]
    fn full_prepared_download_uses_real_tx_and_rx_iova_memory_for_every_chip() {
        use super::super::download::{Downloader, PatchState, ReleaseState};
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let (mailbox, wm, fwdl, rx) = setup(chip, true, false, 0);
            let requests = Requests::new(&identity(chip));
            let provider = catalog(&requests, patch_bytes(), ram_bytes());
            let prepared = requests.load(&provider).unwrap();
            let mut engine = Downloader::new(mailbox);
            let report = engine.download(&prepared).unwrap();
            assert_eq!(report.patch, PatchState::Uploaded);
            assert_eq!(report.release, ReleaseState::Released);
            assert!(report.firmware_start_acknowledged);
            assert_eq!(wm.lock().unwrap().completed.len(), 6);
            assert_eq!(fwdl.lock().unwrap().completed.len(), 2);
            assert_eq!(engine.transport().replies().len(), 6);
            if chip == Chip::Mt7922 {
                let mut mailbox = engine.into_transport();
                // SAFETY: actual modeled controller is stopped before teardown.
                unsafe { mailbox.release_after_quiesce() }.unwrap();
                drop(mailbox);
                assert!(
                    wm.lock()
                        .unwrap()
                        .memory
                        .lock()
                        .unwrap()
                        .mappings
                        .is_empty()
                );
                assert!(
                    fwdl.lock()
                        .unwrap()
                        .memory
                        .lock()
                        .unwrap()
                        .mappings
                        .is_empty()
                );
                assert!(
                    rx.lock()
                        .unwrap()
                        .memory
                        .lock()
                        .unwrap()
                        .mappings
                        .is_empty()
                );
            } else {
                // Owned domains/pins remain live if the composed downloader
                // is dropped before acknowledged controller quiescence.
                drop(engine);
                assert!(wm.lock().unwrap().memory.lock().unwrap().mappings.len() >= 2);
                assert!(rx.lock().unwrap().memory.lock().unwrap().mappings.len() >= 2);
            }
        }
    }
    #[test]
    fn actual_ack_does_not_release_tx_memory_before_hardware_dma_index() {
        let (mut m, wm, _, _) = setup(Chip::Mt7925, true, false, 3);
        assert_eq!(m.command(0x10, &1u32.to_le_bytes()), Ok(2));
        assert_eq!(wm.lock().unwrap().index, 1);
        assert_eq!(m.replies().len(), 1);
        assert!(m.replies()[0].dma_released);
        assert_eq!(m.wm.pending(), 0);
        assert_eq!(
            wm.lock()
                .unwrap()
                .memory
                .lock()
                .unwrap()
                .syncs
                .iter()
                .filter(|v| v.0)
                .count(),
            4
        );
        // SAFETY: explicit model stop covers every live TX/RX queue.
        unsafe { m.release_after_quiesce() }.unwrap();
    }
    #[test]
    fn missing_or_stale_reply_poison_epoch_and_keep_first_failure_after_late_completion() {
        for (reply, wrong, delay) in [
            (false, false, 0),
            (true, true, 0),
            (true, false, usize::MAX),
        ] {
            let (mut m, wm, _, _) = setup(Chip::Mt7921, reply, wrong, delay);
            let err = m
                .transfer_timed(Command::PatchSemaphore, &1u32.to_le_bytes(), 0)
                .unwrap_err();
            assert_eq!(err.kind, FailureKind::Timeout);
            assert_eq!(err.port, PortState::Uncertain);
            assert!(m.is_poisoned());
            let original = m.last_failure().unwrap();
            let count = wm.lock().unwrap().completed.len();
            if wrong {
                assert_eq!(m.events().len(), 1);
            }
            if delay == usize::MAX {
                assert_eq!(m.replies().len(), 1);
                assert!(!m.replies()[0].dma_released);
            }
            // A late actual DMA-index completion never opens a poisoned mailbox epoch.
            wm.lock().unwrap().index = 1;
            assert!(m.command(0x10, &[0; 4]).is_err());
            assert_eq!(m.last_failure(), Some(original));
            assert_eq!(wm.lock().unwrap().completed.len(), count);
            // SAFETY: controller reset owner explicitly stopped all model DMA now.
            unsafe { m.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    fn exact_firmware_target_is_checked_before_the_first_mcu_command() {
        use super::super::download::{Downloader, Stage};
        let (m, wm, fwdl, _) = setup(Chip::Mt7922, true, false, 0);
        let wrong = Requests::new(&identity(Chip::Mt7921));
        let provider = catalog(&wrong, patch_bytes(), ram_bytes());
        let prepared = wrong.load(&provider).unwrap();
        let mut downloader = Downloader::new(m);
        let error = downloader.download(&prepared).unwrap_err();
        assert_eq!(error.stage, Stage::FirmwareTarget);
        assert_eq!(error.failure.kind, FailureKind::FirmwareTarget);
        assert_eq!(error.failure.port, PortState::Usable);
        assert!(wm.lock().unwrap().completed.is_empty());
        assert!(fwdl.lock().unwrap().completed.is_empty());
    }
    #[test]
    fn actual_core_dump_event_is_retained_and_refuses_even_a_later_valid_ack() {
        for (eid, option) in [(0xf0, 0), (0x0a, 6)] {
            let (mut m, _, _, rx) = setup(Chip::Mt7925, true, false, 0);
            let mut event = vec![0u8; 44];
            event[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
            event[32..34].copy_from_slice(&12u16.to_le_bytes());
            event[36] = eid;
            event[37] = 1;
            event[38] = option;
            device_receive(&rx, &event, true, 0);
            assert!(m.command(0x10, &1u32.to_le_bytes()).is_err());
            assert_eq!(m.last_failure().unwrap().cause, Cause::CoreDump);
            assert_eq!(m.events()[0].bytes, event);
            assert!(m.replies().is_empty());
            // SAFETY: explicit controller stop/reset covers pending later ACK.
            unsafe { m.release_after_quiesce() }.unwrap();
        }
    }
    #[test]
    #[ignore = "requires pinned firmware and unchanged donor download trace fixtures"]
    fn actual_pinned_download_crosses_owned_dma_and_actual_mcu_event_path() {
        use super::super::download::Downloader;
        use sha2::{Digest, Sha256};
        let images = std::path::PathBuf::from(std::env::var("STELA_MT792X_FIRMWARE").unwrap());
        let oracle = std::path::PathBuf::from(std::env::var("STELA_MT792X_ORACLE").unwrap());
        for (chip, number, hash) in [
            (
                Chip::Mt7921,
                7921,
                "3d6d7aaa078980259c08e04467ac500ca57735887ffd2a66d60d3da1f28bb458",
            ),
            (
                Chip::Mt7922,
                7922,
                "a7796d0533de77419ee5925ad4c0060f3dbbd58ae02086ac106af9f56c8015aa",
            ),
            (
                Chip::Mt7925,
                7925,
                "1903493fa3e5b5fb058924b0529f35b5cd646e036486275cde074fade4d78146",
            ),
        ] {
            let expected = std::fs::read(oracle.join(alloc::format!("{number}.trace"))).unwrap();
            assert_eq!(alloc::format!("{:x}", Sha256::digest(&expected)), hash);
            let (m, wm, fwdl, rx) = setup(chip, true, false, 0);
            let requests = Requests::new(&identity(chip));
            let provider = catalog(
                &requests,
                std::fs::read(images.join(chip.patch_name())).unwrap(),
                std::fs::read(images.join(chip.ram_name())).unwrap(),
            );
            let prepared = requests.load(&provider).unwrap();
            let mut downloader = Downloader::new(m);
            assert!(
                downloader
                    .download(&prepared)
                    .unwrap()
                    .firmware_start_acknowledged
            );
            let wm = wm.lock().unwrap();
            let fw = fwdl.lock().unwrap();
            let (mut at, mut wi, mut fi, mut operation) = (0usize, 0usize, 0usize, 0usize);
            while at < expected.len() {
                let cmd = expected[at];
                let n = u32::from_le_bytes(expected[at + 2..at + 6].try_into().unwrap()) as usize;
                let bytes = &expected[at + 6..at + 6 + n];
                if cmd == 0xee {
                    assert_eq!(fw.completed[fi], bytes);
                    fi += 1;
                } else {
                    let packet = &wm.completed[wi];
                    wi += 1;
                    assert_eq!(packet[36], cmd);
                    assert_eq!(packet[39], (operation % 15 + 1) as u8);
                    assert_eq!(&packet[64..], bytes);
                }
                operation += 1;
                at += 6 + n;
            }
            assert_eq!(wi, wm.completed.len());
            assert_eq!(fi, fw.completed.len());
            drop(wm);
            drop(fw);
            assert!(
                rx.lock()
                    .unwrap()
                    .memory
                    .lock()
                    .unwrap()
                    .syncs
                    .iter()
                    .any(|v| v.0)
            );
        }
    }
    #[test]
    fn pending_old_request_and_same_sequence_ack_refuse_new_mailbox_epoch() {
        for old_fwdl in [false, true] {
            let (m, wm_state, fwdl_state, rx_state) = setup(Chip::Mt7921, true, false, 0);
            let Mailbox {
                identity,
                mut wm,
                mut fwdl,
                rx,
                clock,
                ..
            } = m;
            let old = Encoder::default()
                .encode(Chip::Mt7921, Command::PatchSemaphore, &1u32.to_le_bytes())
                .unwrap();
            if old_fwdl {
                fwdl.submit(1, &old.bytes).unwrap();
            } else {
                wm.submit(1, &old.bytes).unwrap();
            }
            // Simulate old RX sequence1 even when the pending queue is FWDL.
            if old_fwdl {
                let mut response = vec![0u8; 36];
                response[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
                response[29] = 1;
                response[32] = 2;
                device_receive(&rx_state, &response, true, 0);
            }
            // This constructor must reject known pending TX before assuming
            // the caller's otherwise-required fresh firmware-epoch proof.
            let result = unsafe { Mailbox::from_rings(identity, wm, fwdl, rx, clock) };
            assert!(matches!(result, Err(Cause::PendingTransmit)));
            assert_eq!(
                wm_state.lock().unwrap().completed.len(),
                usize::from(!old_fwdl)
            );
            assert_eq!(
                fwdl_state.lock().unwrap().completed.len(),
                usize::from(old_fwdl)
            );
            assert_eq!(wm_state.lock().unwrap().queue_drops, 0);
            assert_eq!(rx_state.lock().unwrap().queue_drops, 0);
        }
    }
}
