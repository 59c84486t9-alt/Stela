// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Native DMA glue for MT7925 media and initialized Realtek USB2 SCO. Common xHCI owns schedule,
//! cancellation, terminal TD classification and endpoint-context retirement.
use super::Host;
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, DmaBuffer},
    usb::{
        bluetooth::{
            Hci, Io,
            mediatek::media::{self, Bindings, Kind, Loss, MediaIo, Pair, Read, Session},
        },
        xhci::{self, IsoStatus, IsoTransfer, TransferTicket},
    },
};
use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{Ordering, fence};
const BUFFER: usize = 4096;
const DEPTH: usize = 32;
const SEND_US: u64 = 5_000_000;
struct Buffer {
    dma: DmaBuffer,
    queued: Option<IsoTransfer>,
}
struct QueuedOutput {
    sequence: u64,
    slots: Vec<usize>,
    lengths: Vec<usize>,
    retired: usize,
    packet_bytes: usize,
    deadline: crate::Deadline,
}
/// All buffers remain reserved for the boot, even on a failed stop/dequeue.
/// No Drop/free can return an uncertain physical range to another driver.
pub(super) struct Native {
    bindings: Bindings,
    iso: Option<Pair>,
    sco: Option<Pair>,
    iso_input: DmaBuffer,
    iso_output: DmaBuffer,
    iso_receive: Option<TransferTicket>,
    iso_send: bool,
    input: Vec<Buffer>,
    output: Vec<Buffer>,
    next_input: usize,
    running: bool,
    retired: bool,
    poisoned: bool,
    output_sequence: u64,
    queued_output: VecDeque<QueuedOutput>,
    output_receipts: VecDeque<media::OutputReceipt>,
    alt6_packet_flow: bool,
}
impl Hci<Host> {
    /// Owned SCO/queued wideband for an actually initialized source QCA profile.
    pub fn into_qca_media(
        mut self,
        dma: &mut dyn DmaAllocator,
    ) -> media::Result<crate::usb::bluetooth::qca::media::Session<Host>> {
        self.io.validate()?;
        let bindings = Bindings::qca_sco(self.binding())?;
        self.io.media = Some(Native::new(bindings, dma)?);
        crate::usb::bluetooth::qca::media::Session::start(self)
    }
    /// Open USB2 CVSD SCO on this already initialized exact Realtek function.
    /// The host stack supplies actual voice state and owns HCI command credits.
    pub fn into_realtek_sco(
        mut self,
        dma: &mut dyn DmaAllocator,
    ) -> media::Result<crate::usb::bluetooth::realtek::media::Session<Host>> {
        self.io.validate()?;
        let bindings = Bindings::realtek_sco(self.binding())?;
        self.io.media = Some(Native::new(bindings, dma)?);
        crate::usb::bluetooth::realtek::media::Session::start(self)
    }
    /// Enable this PC's MT7925 media extension with retained live initialization
    /// evidence and an actual current HCI command allowance. This must precede
    /// concurrent host/guest stack ownership; it neither performs nor permits a
    /// shared Wi-Fi/Bluetooth reset. All DMA comes from this attachment's owner.
    pub fn into_mt7925_media(
        mut self,
        dma: &mut dyn DmaAllocator,
        command_credits: u8,
    ) -> media::Result<Session<Host>> {
        self.io.validate()?;
        let bindings = Bindings::new(self.binding())?;
        self.io.media = Some(Native::new(bindings, dma)?);
        Session::start(self, dma, command_credits)
    }
}
impl Native {
    fn new(bindings: Bindings, dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        let iso_input = dma.allocate(BUFFER, BUFFER)?;
        let iso_output = dma.allocate(BUFFER, BUFFER)?;
        let mut input = Vec::new();
        let mut output = Vec::new();
        for _ in 0..DEPTH {
            input.push(Buffer {
                dma: dma.allocate(BUFFER, BUFFER)?,
                queued: None,
            });
            output.push(Buffer {
                dma: dma.allocate(BUFFER, BUFFER)?,
                queued: None,
            });
        }
        let running = !bindings.has_iso();
        Ok(Self {
            bindings,
            iso: None,
            sco: None,
            iso_input,
            iso_output,
            iso_receive: None,
            iso_send: false,
            input,
            output,
            next_input: 0,
            running,
            retired: false,
            poisoned: false,
            output_sequence: 1,
            queued_output: VecDeque::new(),
            output_receipts: VecDeque::new(),
            alt6_packet_flow: false,
        })
    }
    fn active(&self) -> Result<(), BlockError> {
        if self.retired || self.poisoned || !self.running {
            return Err(BlockError::Unsupported(
                "MT7925 native media inactive or quarantined",
            ));
        }
        Ok(())
    }
    fn select(host: &mut Host, interface: u8, alternate: u8) -> Result<(), BlockError> {
        // Genuine standard SET_INTERFACE completion, never just a local plan.
        host.control(
            xhci::setup(1, 11, u16::from(alternate), u16::from(interface), 0),
            &[],
        )
    }
    fn start(
        &mut self,
        host: &mut Host,
        pair: Pair,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        host.validate()?;
        if !self.bindings.has_iso()
            || self.iso.is_some()
            || self.retired
            || self.poisoned
            || pair != self.bindings.iso()
        {
            return Err(BlockError::Unsupported(
                "MT7925 exact fresh interrupt interface plan",
            ));
        }
        host.controller
            .borrow_mut()
            .device(host.id)?
            .preflight_endpoints(&pair.endpoints())?;
        Self::select(host, pair.interface, pair.alternate)?;
        // Record before Configure Endpoint: a failing command can leave hardware
        // ownership unresolved; cleanup must still attempt the exact contexts.
        self.iso = Some(pair);
        host.controller
            .borrow_mut()
            .device(host.id)?
            .configure(&pair.endpoints(), None, dma)?;
        self.running = true;
        self.post_interrupt(host)?;
        Ok(())
    }
    fn post_interrupt(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.validate()?;
        let pair = self
            .iso
            .ok_or(BlockError::Unsupported("MT7925 interrupt interface absent"))?;
        if self.iso_receive.is_none() {
            self.iso_receive = Some(
                host.controller
                    .borrow_mut()
                    .device(host.id)?
                    .submit_ticket(
                        pair.input.dci(),
                        self.iso_input.physical(),
                        media::service_bytes(pair.input),
                    )?,
            );
        }
        Ok(())
    }
    fn post_sco(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.validate()?;
        let Some(pair) = self.sco else {
            return Ok(());
        };
        let len = media::service_bytes(pair.input);
        let mut controller_owner = host.controller.borrow_mut();
        let mut controller = controller_owner.device(host.id)?;
        for entry in &mut self.input {
            if entry.queued.is_none() {
                entry.queued =
                    Some(controller.submit_iso(pair.input.dci(), entry.dma.physical(), len)?);
            }
        }
        Ok(())
    }
    fn replace(
        &mut self,
        host: &mut Host,
        previous: Option<Pair>,
        next: Option<Pair>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        host.validate()?;
        self.active()?;
        if self.sco != previous || next.is_some_and(|p| !self.bindings.accepts_sco(p)) {
            return Err(BlockError::Unsupported(
                "MT7925 exact retained SCO alternate plan",
            ));
        }
        if let Some(old) = previous {
            host.controller
                .borrow_mut()
                .device(host.id)?
                .deconfigure(&old.endpoints())?;
            for buffer in self.input.iter_mut().chain(&mut self.output) {
                buffer.queued = None;
            }
            self.sco = None;
            self.retire_queued_output();
        }
        if let Some(pair) = next {
            host.controller
                .borrow_mut()
                .device(host.id)?
                .preflight_endpoints(&pair.endpoints())?;
        }
        Self::select(host, 1, next.map_or(0, |p| p.alternate))?;
        self.next_input = 0;
        if let Some(pair) = next {
            self.sco = Some(pair);
            host.controller.borrow_mut().device(host.id)?.configure(
                &pair.endpoints(),
                None,
                dma,
            )?;
            self.post_sco(host)?;
        }
        Ok(())
    }
    fn read(&mut self, host: &mut Host, kind: Kind) -> Result<Option<Read>, BlockError> {
        host.validate()?;
        self.active()?;
        match kind {
            Kind::Iso => {
                self.post_interrupt(host)?;
                let pair = self
                    .iso
                    .ok_or(BlockError::Unsupported("HCI ISO interface absent"))?;
                let length = media::service_bytes(pair.input);
                let result = host
                    .controller
                    .borrow_mut()
                    .device(host.id)?
                    .completed_ticket(self.iso_receive.as_ref().unwrap());
                match result {
                    Some(Ok(bytes)) if bytes <= length => {
                        self.iso_receive = None;
                        fence(Ordering::Acquire);
                        let data = self.iso_input.bytes()[..bytes].to_vec();
                        self.post_interrupt(host)?;
                        Ok(Some(Read::Data(data)))
                    }
                    Some(Ok(_)) => Err(BlockError::Unsupported(
                        "MT7925 interrupt completion length",
                    )),
                    Some(Err(error)) => Err(error), // Keep ticket/buffer pending.
                    None => Ok(None),
                }
            }
            Kind::Sco => {
                let pair = self
                    .sco
                    .ok_or(BlockError::Unsupported("MT7925 SCO alternate inactive"))?;
                self.post_sco(host)?;
                let index = self.next_input;
                let result = host
                    .controller
                    .borrow_mut()
                    .device(host.id)?
                    .completed_iso(self.input[index].queued.as_ref().unwrap());
                let Some(result) = result else {
                    return Ok(None);
                };
                let done = result?; // Err never releases or clears a ticket.
                if done.bytes > media::service_bytes(pair.input) {
                    return Err(BlockError::Unsupported("MT7925 SCO completion length"));
                }
                self.input[index].queued = None;
                if done.status == IsoStatus::MissedService {
                    // xHCI requires cancellation of all remaining scheduled TDs
                    // after this terminal status before restarting the schedule.
                    host.controller
                        .borrow_mut()
                        .device(host.id)?
                        .cancel(pair.input.dci())?;
                    for b in &mut self.input {
                        b.queued = None;
                    }
                    self.next_input = 0;
                } else {
                    self.next_input = (index + 1) % DEPTH;
                }
                fence(Ordering::Acquire);
                let read = match done.status {
                    IsoStatus::Success | IsoStatus::Short => {
                        Read::Data(self.input[index].dma.bytes()[..done.bytes].to_vec())
                    }
                    status => Read::Loss(loss(status)),
                };
                self.post_sco(host)?;
                Ok(Some(read))
            }
        }
    }
    fn write(&mut self, host: &mut Host, kind: Kind, bytes: &[u8]) -> media::Result<()> {
        host.validate()?;
        let deadline = host
            .clock
            .try_deadline(SEND_US)
            .map_err(|_| BlockError::Unsupported(super::CLOCK_REQUIREMENT))?;
        self.active()?;
        match kind {
            Kind::Iso => {
                let pair = self
                    .iso
                    .ok_or(BlockError::Unsupported("HCI ISO interface absent"))?;
                if bytes.len() != 264 || self.iso_send {
                    return Err(media::Error::Unsupported(
                        "MT7925 padded interrupt output ownership",
                    ));
                }
                host.controller
                    .borrow_mut()
                    .device(host.id)?
                    .endpoint_ready(pair.output.dci())?;
                if deadline.passed() {
                    return Err(BlockError::Timeout.into());
                }
                self.iso_output.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
                fence(Ordering::Release);
                if deadline.passed() {
                    return Err(BlockError::Timeout.into());
                }
                let trb = host
                    .controller
                    .borrow_mut()
                    .device(host.id)?
                    .submit_ticket(pair.output.dci(), self.iso_output.physical(), bytes.len())?;
                self.iso_send = true;
                loop {
                    if let Some(result) = host
                        .controller
                        .borrow_mut()
                        .device(host.id)?
                        .completed_ticket(&trb)
                    {
                        let done = result?;
                        if done != bytes.len() {
                            return Err(media::Error::OutputCompletion {
                                kind,
                                status: IsoStatus::Short,
                                expected: bytes.len(),
                                actual: done,
                            });
                        }
                        self.iso_send = false;
                        return Ok(());
                    }
                    if deadline.passed() {
                        return Err(BlockError::Timeout.into());
                    }
                    crate::waiting();
                    core::hint::spin_loop();
                }
            }
            Kind::Sco => {
                if !self.queued_output.is_empty() {
                    return Err(media::Error::Unsupported(
                        "queued SCO output owns native buffers",
                    ));
                }
                let pair = self
                    .sco
                    .ok_or(BlockError::Unsupported("MT7925 SCO alternate inactive"))?;
                let lengths = self.sco_lengths(pair, bytes.len())?;
                if lengths.len() > DEPTH || self.output.iter().any(|b| b.queued.is_some()) {
                    return Err(media::Error::Unsupported(
                        "bounded SCO output queue ownership",
                    ));
                }
                if pair.alternate == 6 {
                    self.alt6_packet_flow = !self.alt6_packet_flow;
                }
                // Separate buffers for all services; none is overwritten before
                // its actual terminal completion or acknowledged cancellation.
                let mut offset = 0;
                for (b, &length) in self.output.iter_mut().zip(&lengths) {
                    if deadline.passed() {
                        return Err(BlockError::Timeout.into());
                    }
                    b.dma.bytes_mut()[..length].copy_from_slice(&bytes[offset..offset + length]);
                    offset += length;
                    fence(Ordering::Release);
                    if deadline.passed() {
                        return Err(BlockError::Timeout.into());
                    }
                    b.queued = Some(host.controller.borrow_mut().device(host.id)?.submit_iso(
                        pair.output.dci(),
                        b.dma.physical(),
                        length,
                    )?);
                }
                for (b, &length) in self.output.iter_mut().zip(&lengths) {
                    loop {
                        if let Some(result) = host
                            .controller
                            .borrow_mut()
                            .device(host.id)?
                            .completed_iso(b.queued.as_ref().unwrap())
                        {
                            let done = result?;
                            b.queued = None;
                            if done.status != IsoStatus::Success || done.bytes != length {
                                // Even a terminal loss cannot credit successful
                                // HCI delivery; caller closes and drains the rest.
                                return Err(media::Error::OutputCompletion {
                                    kind,
                                    status: done.status,
                                    expected: length,
                                    actual: done.bytes,
                                });
                            }
                            break;
                        }
                        if deadline.passed() {
                            return Err(BlockError::Timeout.into());
                        }
                        crate::waiting();
                        core::hint::spin_loop();
                    }
                }
                Ok(())
            }
        }
    }
    /// One HCI packet's isochronous services. `btusb_isoc_tx` paces every
    /// alternate-6 URB (`__fill_isoc_descriptor_msbc`): six or seven empty
    /// services, alternately, then the packet, for its 7.5 ms interval.
    fn sco_lengths(&self, pair: Pair, packet: usize) -> media::Result<Vec<usize>> {
        let flow = (pair.alternate == 6).then_some(self.alt6_packet_flow);
        crate::usb::bluetooth::realtek::media::output_lengths(
            packet,
            media::service_bytes(pair.output),
            flow,
        )
    }
    fn queue_sco(&mut self, host: &mut Host, bytes: &[u8]) -> media::Result<Option<u64>> {
        host.validate()?;
        self.active()?;
        let pair = self
            .sco
            .ok_or(BlockError::Unsupported("queued SCO alternate inactive"))?;
        let lengths = self.sco_lengths(pair, bytes.len())?;
        let count = lengths.len();
        // Backpressure precedes sequence, pacing, buffer or hardware mutation.
        let slots: Vec<_> = self
            .output
            .iter()
            .enumerate()
            .filter(|(_, b)| b.queued.is_none())
            .map(|(i, _)| i)
            .take(count)
            .collect();
        if slots.len() != count || self.queued_output.len() + self.output_receipts.len() >= DEPTH {
            return Ok(None);
        }
        let next = self
            .output_sequence
            .checked_add(1)
            .ok_or(BlockError::Unsupported("queued SCO sequence exhausted"))?;
        let deadline = host
            .clock
            .try_deadline(SEND_US)
            .map_err(|_| BlockError::Unsupported(super::CLOCK_REQUIREMENT))?;
        let schedules = host
            .controller
            .borrow_mut()
            .device(host.id)?
            .iso_schedule_list(pair.output.dci(), xhci::IsoSchedule::Asap, count)?;
        if deadline.passed() {
            return Err(BlockError::Timeout.into());
        }
        let sequence = self.output_sequence;
        self.output_sequence = next;
        if pair.alternate == 6 {
            self.alt6_packet_flow = !self.alt6_packet_flow;
        }
        // Retain the intended packet before its first publication. Any later
        // failure closes/quarantines all previously published service owners.
        self.queued_output.push_back(QueuedOutput {
            sequence,
            slots: slots.clone(),
            lengths: lengths.clone(),
            retired: 0,
            packet_bytes: bytes.len(),
            deadline,
        });
        let result: media::Result<()> = (|| {
            let mut offset = 0;
            for ((slot, length), schedule) in slots.into_iter().zip(lengths).zip(schedules) {
                if self.queued_output.back().unwrap().deadline.passed() {
                    return Err(BlockError::Timeout.into());
                }
                let buffer = &mut self.output[slot];
                buffer.dma.bytes_mut()[..length].copy_from_slice(&bytes[offset..offset + length]);
                offset += length;
                fence(Ordering::Release);
                if self.queued_output.back().unwrap().deadline.passed() {
                    return Err(BlockError::Timeout.into());
                }
                buffer.queued = Some(
                    host.controller
                        .borrow_mut()
                        .device(host.id)?
                        .submit_iso_scheduled(
                            pair.output.dci(),
                            buffer.dma.physical(),
                            length,
                            schedule,
                        )?,
                );
            }
            Ok(())
        })();
        result.map_err(|cause| media::Error::QueuedOutput {
            sequence,
            cause: alloc::boxed::Box::new(cause),
        })?;
        Ok(Some(sequence))
    }
    fn poll_sco_output(&mut self, host: &mut Host) -> media::Result<Option<media::OutputReceipt>> {
        host.validate()?;
        if self.poisoned || self.retired {
            return Err(BlockError::Unsupported("queued SCO owner quarantined or closed").into());
        }
        if let Some(receipt) = self.output_receipts.pop_front() {
            return Ok(Some(receipt));
        }
        let Some(packet) = self.queued_output.front_mut() else {
            return Ok(None);
        };
        if packet.deadline.passed() {
            return Err(media::Error::QueuedOutput {
                sequence: packet.sequence,
                cause: alloc::boxed::Box::new(BlockError::Timeout.into()),
            });
        }
        while packet.retired < packet.slots.len() {
            let index = packet.retired;
            let buffer = &mut self.output[packet.slots[index]];
            let ticket = buffer
                .queued
                .as_ref()
                .ok_or(BlockError::Unsupported("queued SCO publication incomplete"))?;
            let Some(done) = host
                .controller
                .borrow_mut()
                .device(host.id)?
                .completed_iso(ticket)
            else {
                return Ok(None);
            };
            let done = done?;
            if packet.deadline.passed() {
                return Err(media::Error::QueuedOutput {
                    sequence: packet.sequence,
                    cause: alloc::boxed::Box::new(BlockError::Timeout.into()),
                });
            }
            buffer.queued = None; // Only an actual terminal service releases DMA.
            packet.retired += 1;
            if done.status != IsoStatus::Success || done.bytes != packet.lengths[index] {
                return Err(media::Error::QueuedOutput {
                    sequence: packet.sequence,
                    cause: alloc::boxed::Box::new(media::Error::OutputCompletion {
                        kind: Kind::Sco,
                        status: done.status,
                        expected: packet.lengths[index],
                        actual: done.bytes,
                    }),
                });
            }
        }
        let packet = self.queued_output.pop_front().unwrap();
        Ok(Some(media::OutputReceipt {
            sequence: packet.sequence,
            packet_bytes: packet.packet_bytes,
            disposition: media::OutputDisposition::Completed,
        }))
    }
    fn retire_queued_output(&mut self) {
        for packet in self.queued_output.drain(..) {
            self.output_receipts.push_back(media::OutputReceipt {
                sequence: packet.sequence,
                packet_bytes: packet.packet_bytes,
                disposition: media::OutputDisposition::RetiredUnconfirmed,
            });
        }
    }
    fn quiesce(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.validate()?;
        self.active()?;
        self.running = false;
        let mut failure = None;
        let mut controller_owner = host.controller.borrow_mut();
        let mut controller = controller_owner.device(host.id)?;
        if let Some(pair) = self.iso {
            if let Some(ticket) = &self.iso_receive
                && let Err(e) = controller.cancel_ticket(ticket)
            {
                failure.get_or_insert(e);
            }
            if self.iso_send
                && let Err(e) = controller.cancel(pair.output.dci())
            {
                failure.get_or_insert(e);
            }
        }
        if let Some(pair) = self.sco {
            // An idle completed ISO output still owns Queue.next. Always
            // acknowledge retirement of both schedules, not just live payloads.
            for ep in pair.endpoints() {
                if let Err(e) = controller.cancel(ep.dci()) {
                    failure.get_or_insert(e);
                }
            }
        }
        if let Some(error) = failure {
            self.poisoned = true;
            return Err(error);
        }
        self.iso_receive = None;
        self.iso_send = false;
        for b in self.input.iter_mut().chain(&mut self.output) {
            b.queued = None;
        }
        self.retire_queued_output();
        self.next_input = 0;
        Ok(())
    }
    fn reset_epoch(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.validate()?;
        self.quiesce(host)?;
        if let Some(pair) = self.sco {
            host.controller
                .borrow_mut()
                .device(host.id)?
                .deconfigure(&pair.endpoints())?;
            self.sco = None;
            Self::select(host, pair.interface, 0)?;
        }
        Ok(())
    }
    fn resume(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.validate()?;
        if self.running
            || self.retired
            || self.poisoned
            || (self.bindings.has_iso() && self.iso.is_none())
        {
            return Err(BlockError::Unsupported(
                "MT7925 media resume requires known stopped streams",
            ));
        }
        self.running = true;
        if self.bindings.has_iso() {
            self.post_interrupt(host)?;
        }
        self.post_sco(host)
    }
    pub(super) fn close(&mut self, host: &mut Host) -> Result<(), BlockError> {
        host.validate()?;
        if self.retired {
            return if self.poisoned {
                Err(BlockError::Unsupported(
                    "MT7925 media permanently quarantined",
                ))
            } else {
                Ok(())
            };
        }
        let mut failure = if self.running {
            self.quiesce(host).err()
        } else {
            None
        };
        self.retired = true;
        // Deconfigure also cancels/drains every queued TD; it refuses poisoned
        // endpoint states. Do not select a new alternate after any uncertainty.
        let mut controller_owner = host.controller.borrow_mut();
        {
            let mut controller = controller_owner.device(host.id)?;
            for pair in [self.sco, self.iso].into_iter().flatten() {
                if let Err(e) = controller.deconfigure(&pair.endpoints()) {
                    failure.get_or_insert(e);
                }
            }
        }
        drop(controller_owner);
        if failure.is_none() {
            if let Some(pair) = self.sco
                && let Err(e) = Self::select(host, pair.interface, 0)
            {
                failure.get_or_insert(e);
            }
            if let Some(pair) = self.iso
                && let Err(e) = Self::select(host, pair.interface, 0)
            {
                failure.get_or_insert(e);
            }
        }
        if let Some(error) = failure {
            self.poisoned = true;
            Err(error)
        } else {
            Ok(())
        }
    }
}
fn loss(status: IsoStatus) -> Loss {
    match status {
        IsoStatus::MissedService => Loss::MissedService,
        IsoStatus::Transaction => Loss::Transaction,
        IsoStatus::Babble => Loss::Babble,
        IsoStatus::Bandwidth => Loss::Bandwidth,
        IsoStatus::BufferOverrun => Loss::BufferOverrun,
        IsoStatus::Success | IsoStatus::Short => unreachable!(),
    }
}
impl Host {
    fn with_media<T, E: From<BlockError>>(
        &mut self,
        f: impl FnOnce(&mut Native, &mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        self.open()?;
        let mut media = self
            .media
            .take()
            .ok_or(BlockError::Unsupported("native MT7925 media not prepared"))?;
        let result = f(&mut media, self);
        if result.is_err() {
            media.poisoned = true;
        }
        self.media = Some(media);
        result
    }
}
impl MediaIo for Host {
    fn queue_sco(&mut self, bytes: &[u8]) -> media::Result<Option<u64>> {
        self.with_media(|m, h| m.queue_sco(h, bytes))
    }
    fn poll_sco_output(&mut self) -> media::Result<Option<media::OutputReceipt>> {
        self.with_media(|m, h| m.poll_sco_output(h))
    }
    fn start_iso(&mut self, pair: Pair, dma: &mut dyn DmaAllocator) -> Result<(), BlockError> {
        self.with_media(|m, h| m.start(h, pair, dma))
    }
    fn replace_sco(
        &mut self,
        previous: Option<Pair>,
        next: Option<Pair>,
        dma: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        self.with_media(|m, h| m.replace(h, previous, next, dma))
    }
    fn read_media(&mut self, kind: Kind) -> Result<Option<Read>, BlockError> {
        self.with_media(|m, h| m.read(h, kind))
    }
    fn write_media(&mut self, kind: Kind, bytes: &[u8]) -> media::Result<()> {
        self.with_media(|m, h| m.write(h, kind, bytes))
    }
    fn quiesce_media(&mut self) -> Result<(), BlockError> {
        self.with_media(|m, h| m.quiesce(h))
    }
    fn reset_media_epoch(&mut self) -> Result<(), BlockError> {
        self.with_media(|m, h| m.reset_epoch(h))
    }
    fn resume_media(&mut self) -> Result<(), BlockError> {
        self.with_media(|m, h| m.resume(h))
    }
    fn close_media(&mut self) -> Result<(), BlockError> {
        self.validate()?;
        let Some(mut media) = self.media.take() else {
            return Ok(());
        };
        let result = media.close(self);
        self.media = Some(media);
        result
    }
}

#[cfg(test)]
pub(super) fn generation_prepare(
    host: &mut Host,
    binding: &crate::usb::bluetooth::Binding,
    dma: &mut dyn DmaAllocator,
) {
    let mut native = Native::new(Bindings::new(binding).unwrap(), dma).unwrap();
    let pair = native.bindings.iso();
    native.start(host, pair, dma).unwrap();
    let sco = native
        .bindings
        .sco(media::Voice {
            connections: 1,
            air_mode: media::AirMode::Cvsd,
            voice_setting: 0,
        })
        .unwrap();
    native.replace(host, None, sco, dma).unwrap();
    assert!(native.iso_receive.is_some());
    assert!(native.input.iter().all(|b| b.queued.is_some()));
    host.media = Some(native);
}

#[cfg(test)]
pub(super) fn generation_refuse(host: &mut Host, dma: &mut dyn DmaAllocator) {
    let native = host.media.as_ref().unwrap();
    let iso = native.iso.unwrap();
    let sco = native.sco;
    let before = (
        native.running,
        native.retired,
        native.poisoned,
        native.next_input,
        native.iso_receive.is_some(),
        native.input.iter().filter(|b| b.queued.is_some()).count(),
    );
    assert!(host.start_iso(iso, dma).is_err());
    assert!(host.replace_sco(sco, None, dma).is_err());
    assert!(host.read_media(Kind::Iso).is_err());
    assert!(host.read_media(Kind::Sco).is_err());
    assert!(host.write_media(Kind::Iso, &[0x7a; 264]).is_err());
    assert!(host.write_media(Kind::Sco, &[0x7a; 48]).is_err());
    assert!(host.quiesce_media().is_err());
    assert!(host.reset_media_epoch().is_err());
    assert!(host.resume_media().is_err());
    assert!(host.close_media().is_err());
    let native = host.media.as_ref().unwrap();
    assert_eq!(
        (
            native.running,
            native.retired,
            native.poisoned,
            native.next_input,
            native.iso_receive.is_some(),
            native.input.iter().filter(|b| b.queued.is_some()).count()
        ),
        before
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bus::dma::RegionAllocator,
        usb::bluetooth::{State, mediatek::media::tests::binding},
    };
    #[test]
    fn native_media_buffers_remain_unchanged_after_failed_stop_or_halted_dequeue() {
        for halted in [false, true] {
            let mut backing = vec![0u64; 256 * 1024];
            let base = backing.as_mut_ptr() as u64;
            // SAFETY: synthetic RAM remains exclusive/live through all owners.
            let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
            let binding = binding();
            let mut native = Native::new(Bindings::new(&binding).unwrap(), &mut dma).unwrap();
            let (controller, ticket) = xhci::model::controller_with_unresolved_ticket(
                &mut dma,
                native.iso_input.physical(),
                512,
                5,
                halted,
            );
            let mut device = binding.device().clone();
            device.id = controller.borrow().test_device_id(device.slot).unwrap();
            let binding = crate::usb::bluetooth::Binding::new(
                &device,
                &xhci::interfaces(&device.configuration)[0],
            )
            .unwrap();
            let mut hci = Hci::attach(controller, &device, binding, &mut dma).unwrap();
            // This is the shared fixture's real submitted interrupt/bulk TD,
            // not a fabricated completion. The endpoint plan is local test data.
            let mut pair = native.bindings.iso();
            pair.input.address = 0x82;
            pair.output.address = 2;
            native.iso = Some(pair);
            native.iso_receive = Some(ticket);
            native.running = true;
            native.iso_input.bytes_mut()[..512].fill(0xa5);
            hci.io.media = Some(native);
            let before = backing.clone();
            assert!(hci.io.close_media().is_err());
            let native = hci.io.media.as_ref().unwrap();
            assert!(native.retired && native.poisoned);
            assert!(native.iso_receive.is_some());
            assert!(hci.io.resume_media().is_err());
            assert!(hci.io.write_media(Kind::Iso, &[0; 264]).is_err());
            assert_eq!(backing, before);
            // Base close cannot turn the failed media retirement into success.
            assert!(hci.close().is_err());
            assert_eq!(hci.state(), State::Failed);
            assert_eq!(backing, before);
        }
    }
    #[test]
    fn native_quiesce_retires_idle_sco_output_schedule_before_repost_after_long_pause() {
        idle_sco_output_schedule(false);
    }
    #[test]
    fn native_realtek_sco_without_iso_resumes_actual_retired_schedule_after_long_pause() {
        idle_sco_output_schedule(true);
    }
    fn idle_sco_output_schedule(realtek: bool) {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive synthetic RAM outlives model, rings and class owner.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let fixture = xhci::model::iso_class_fixture(&mut dma, xhci::HIGH_SPEED);
        let controller = fixture.controller();
        let binding = binding();
        let mut device = binding.device().clone();
        if realtek {
            device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x71, 0x87]);
        }
        device.id = controller.borrow().test_device_id(device.slot).unwrap();
        let binding = crate::usb::bluetooth::Binding::new(
            &device,
            &xhci::interfaces(&device.configuration)[0],
        )
        .unwrap();
        let bindings = if realtek {
            Bindings::realtek_sco(&binding)
        } else {
            Bindings::new(&binding)
        }
        .unwrap();
        let mut native = Native::new(bindings, &mut dma).unwrap();
        if realtek {
            assert!(native.running && native.iso.is_none());
        }
        let pair = native
            .bindings
            .sco(media::Voice {
                connections: 1,
                air_mode: media::AirMode::Cvsd,
                voice_setting: 0,
            })
            .unwrap()
            .unwrap();
        controller
            .borrow_mut()
            .configure(1, &pair.endpoints(), None, &mut dma)
            .unwrap();
        let mut hci = Hci::attach(controller.clone(), &device, binding, &mut dma).unwrap();
        native.sco = Some(pair);
        native.running = true;
        let dci = pair.output.dci();
        let length = media::service_bytes(pair.output);
        let ticket = controller
            .borrow_mut()
            .submit_iso(1, dci, native.output[0].dma.physical(), length)
            .unwrap();
        fixture.complete(dci, 1, 0);
        let done = controller
            .borrow_mut()
            .completed_iso(&ticket)
            .unwrap()
            .unwrap();
        assert_eq!(done.status, IsoStatus::Success);
        assert_eq!(done.bytes, length);
        assert!(native.output.iter().all(|b| b.queued.is_none())); // Payload done; schedule still retained.
        native.quiesce(&mut hci.io).unwrap();
        assert!(fixture.commands().contains(&(15, dci))); // Actual Stop Endpoint ACK.
        assert!(fixture.commands().contains(&(16, dci))); // Actual Set Dequeue ACK resets Queue.next.
        fixture.set_mfindex(8192); // Old FrameID is outside the actual scheduling window.
        // Reuse the exact SCO repost operation from Native::resume. This opaque
        // fixture models ISO rings only, not ordinary interrupt/HCI enumeration.
        if realtek {
            native.resume(&mut hci.io).unwrap();
            assert!(native.iso_receive.is_none());
        } else {
            native.post_sco(&mut hci.io).unwrap();
        }
        let fresh = controller
            .borrow_mut()
            .submit_iso(1, dci, native.output[0].dma.physical(), length)
            .unwrap();
        fixture.complete(dci, 1, 0);
        assert_eq!(
            controller
                .borrow_mut()
                .completed_iso(&fresh)
                .unwrap()
                .unwrap()
                .status,
            IsoStatus::Success
        );
        controller.borrow_mut().cancel(1, pair.input.dci()).unwrap();
    }
    #[test]
    fn mt7925_wideband_sco_paces_alternate_6_like_btusb_isoc_tx() {
        let mut backing = vec![0u64; 64 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive synthetic RAM outlives the class owner.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let mut native = Native::new(Bindings::new(&binding()).unwrap(), &mut dma).unwrap();
        assert!(native.bindings.has_iso());
        let pair = native
            .bindings
            .sco(media::Voice {
                connections: 1,
                air_mode: media::AirMode::Transparent,
                voice_setting: 0,
            })
            .unwrap()
            .unwrap();
        assert_eq!(pair.alternate, 6);
        let service = media::service_bytes(pair.output);
        let paced = |idle| [vec![0; idle], vec![service]].concat();
        assert_eq!(native.sco_lengths(pair, service).unwrap(), paced(6));
        native.alt6_packet_flow = true;
        assert_eq!(native.sco_lengths(pair, service).unwrap(), paced(7));
        // A packet goes in one frame; one larger than a service cannot.
        assert!(native.sco_lengths(pair, service + 1).is_err());
    }

    #[test]
    fn native_realtek_alt6_queues_actual_zero_services_and_payloads_with_bounded_receipts() {
        for speed in [xhci::FULL_SPEED, xhci::HIGH_SPEED] {
            queued_wideband_services(speed);
        }
    }
    fn queued_wideband_services(speed: u8) {
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive fixture memory outlives every retained native TD.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let fixture = xhci::model::iso_class_fixture(&mut dma, speed);
        let controller = fixture.controller();
        let mut device = binding().device().clone();
        device.speed = speed;
        device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x71, 0x87]);
        let mut at = 0;
        let mut alt6 = false;
        while at < device.configuration.len() {
            let len = usize::from(device.configuration[at]);
            if device.configuration[at + 1] == 4 {
                alt6 = device.configuration[at + 2..at + 4] == [1, 6];
            }
            if alt6 && device.configuration[at + 1] == 5 {
                device.configuration[at + 4..at + 7].copy_from_slice(&[
                    63,
                    0,
                    if speed == xhci::FULL_SPEED { 1 } else { 4 },
                ]);
            } else if speed == xhci::FULL_SPEED
                && device.configuration[at + 1] == 5
                && matches!(device.configuration[at + 3] & 3, 2 | 3)
            {
                device.configuration[at + 4..at + 6].copy_from_slice(&64u16.to_le_bytes());
            }
            at += len;
        }
        device.id = controller.borrow().test_device_id(device.slot).unwrap();
        let binding = crate::usb::bluetooth::Binding::new(
            &device,
            &xhci::interfaces(&device.configuration)[0],
        )
        .unwrap();
        let bindings = Bindings::realtek_sco(&binding).unwrap();
        let pair = bindings.wideband_sco(1, 60).unwrap().unwrap();
        assert_eq!(pair.alternate, 6);
        let mut native = Native::new(bindings, &mut dma).unwrap();
        // Native ring fixture supplies real endpoint contexts, but does not
        // simulate HCI firmware setup or SET_INTERFACE. Those are separate models.
        controller
            .borrow_mut()
            .configure(1, &pair.endpoints(), None, &mut dma)
            .unwrap();
        let mut hci = Hci::attach(controller.clone(), &device, binding, &mut dma).unwrap();
        native.sco = Some(pair);
        let mut packet = vec![0x6a; 63];
        // A generous real TSC budget keeps this DMA/scheduling proof independent
        // of host test-runner latency. Modeled MFINDEX supplies service timing.
        hci.io.clock.ticks_per_microsecond = 1000;
        packet[..3].copy_from_slice(&[1, 0, 60]);
        for sequence in 1..=4 {
            assert_eq!(
                native.queue_sco(&mut hci.io, &packet).unwrap(),
                Some(sequence)
            );
        }
        let geometry: Vec<_> = native
            .output
            .iter()
            .map(|b| b.dma.bytes().to_vec())
            .collect();
        assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), None);
        assert_eq!(native.output_sequence, 5);
        assert!(!native.alt6_packet_flow);
        assert_eq!(
            native
                .output
                .iter()
                .map(|b| b.dma.bytes().to_vec())
                .collect::<Vec<_>>(),
            geometry
        );
        let mut previous = None;
        let mut service_times = Vec::new();
        for (n, queued) in native.queued_output.iter().enumerate() {
            assert_eq!(queued.slots.len(), if n % 2 == 0 { 7 } else { 8 });
            for (i, slot) in queued.slots.iter().enumerate() {
                assert_eq!(
                    queued.lengths[i],
                    if i + 1 == queued.slots.len() { 63 } else { 0 }
                );
                let xhci::IsoSchedule::AtMicroframe(now) =
                    native.output[*slot].queued.as_ref().unwrap().schedule()
                else {
                    panic!("fixture requires actual FrameID schedule");
                };
                if let Some(last) = previous {
                    assert_eq!(now, (last + 8) % 16384);
                }
                previous = Some(now);
                service_times.push(now);
            }
        }
        assert_eq!(native.poll_sco_output(&mut hci.io).unwrap(), None);
        // Complete the actual 30 ring TDs. The hardware model reads native TRB
        // lengths: an empty interval cannot masquerade as the 63-byte payload.
        assert_eq!(service_times.len(), 30);
        assert_eq!(service_times[14] - service_times[6], 64); // actual 8ms between payloads
        assert_eq!(service_times[21] - service_times[14], 56); // actual 7ms between payloads
        assert_eq!(service_times[29] - service_times[21], 64);
        for now in service_times {
            fixture.service_at(pair.output.dci(), u32::from(now), 1);
        }
        for sequence in 1..=4 {
            assert_eq!(
                native.poll_sco_output(&mut hci.io).unwrap(),
                Some(media::OutputReceipt {
                    sequence,
                    packet_bytes: 63,
                    disposition: media::OutputDisposition::Completed,
                })
            );
        }
        assert!(native.output.iter().all(|b| b.queued.is_none()));
        assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(5));
        assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(6));
        native.quiesce(&mut hci.io).unwrap();
        assert!(fixture.commands().contains(&(15, pair.output.dci())));
        assert!(fixture.commands().contains(&(16, pair.output.dci())));
        for sequence in 5..=6 {
            assert_eq!(
                native.poll_sco_output(&mut hci.io).unwrap(),
                Some(media::OutputReceipt {
                    sequence,
                    packet_bytes: 63,
                    disposition: media::OutputDisposition::RetiredUnconfirmed,
                })
            );
        }
        assert_eq!(native.poll_sco_output(&mut hci.io).unwrap(), None);
        fixture.set_mfindex(8192);
        native.resume(&mut hci.io).unwrap();
        assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(7));
        for _ in 0..7 {
            fixture.complete(pair.output.dci(), 1, 0);
        }
        assert_eq!(
            native
                .poll_sco_output(&mut hci.io)
                .unwrap()
                .unwrap()
                .disposition,
            media::OutputDisposition::Completed
        );
        native.quiesce(&mut hci.io).unwrap();
        native.resume(&mut hci.io).unwrap();
        assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(8));
        let retained: Vec<_> = native
            .output
            .iter()
            .map(|b| b.dma.bytes().to_vec())
            .collect();
        // Deterministically inject an already expired real raw-clock deadline
        // after actual publication. This does not claim five physical seconds
        // elapsed or change calibration to invent a timeout.
        native.queued_output.front_mut().unwrap().deadline = hci.io.clock.try_deadline(0).unwrap();
        assert!(
            matches!(native.poll_sco_output(&mut hci.io),Err(media::Error::QueuedOutput {sequence:8,cause})
            if matches!(*cause,media::Error::Transport(BlockError::Timeout)))
        );
        assert_eq!(native.queued_output.front().unwrap().sequence, 8);
        assert_eq!(
            native.output.iter().filter(|b| b.queued.is_some()).count(),
            8
        );
        assert_eq!(
            native
                .output
                .iter()
                .map(|b| b.dma.bytes().to_vec())
                .collect::<Vec<_>>(),
            retained
        );
        native.quiesce(&mut hci.io).unwrap(); // actual retirement, never local timeout credit
        assert_eq!(
            native
                .poll_sco_output(&mut hci.io)
                .unwrap()
                .unwrap()
                .disposition,
            media::OutputDisposition::RetiredUnconfirmed
        );
    }
}
