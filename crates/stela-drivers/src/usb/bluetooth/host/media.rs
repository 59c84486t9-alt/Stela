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
    /// Owned SCO/queued wideband for an initialized source QCA profile.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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
    /// The host stack supplies voice state and owns HCI command credits.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub fn into_realtek_sco(
        mut self,
        dma: &mut dyn DmaAllocator,
    ) -> media::Result<crate::usb::bluetooth::realtek::media::Session<Host>> {
        self.io.validate()?;
        let bindings = Bindings::realtek_sco(self.binding())?;
        self.io.media = Some(Native::new(bindings, dma)?);
        crate::usb::bluetooth::realtek::media::Session::start(self)
    }
    /// Enable this PC's MT7925 media extension with kept live initialization
    /// evidence and a current HCI command allowance. This must precede
    /// concurrent host/guest stack ownership; it neither performs nor permits a
    /// shared Wi-Fi/Bluetooth reset. All DMA comes from this attachment's owner.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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
        // Standard SET_INTERFACE completion, never just a local plan.
        host.control(
            crate::usb::descriptor::setup(1, 11, u16::from(alternate), u16::from(interface), 0),
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
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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
                // its terminal completion or acknowledged cancellation.
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
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn sco_lengths(&self, pair: Pair, packet: usize) -> media::Result<Vec<usize>> {
        let flow = (pair.alternate == 6).then_some(self.alt6_packet_flow);
        crate::usb::bluetooth::realtek::media::output_lengths(
            packet,
            media::service_bytes(pair.output),
            flow,
        )
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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
        // Keep the intended packet before its first publication. Any later
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
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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
            buffer.queued = None; // Only a terminal service releases DMA.
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
    /// A clean close left both interfaces at alternate 0 and retired every
    /// TD, so the next power-on may claim them again. The mSBC flow persists,
    /// as btusb keeps `usb_alt6_packet_flow` for the device's life.
    fn reopen(&mut self) -> Result<(), BlockError> {
        if !self.retired
            || self.poisoned
            || self.iso_receive.is_some()
            || self.iso_send
            || !self.queued_output.is_empty()
            || self
                .input
                .iter()
                .chain(&self.output)
                .any(|b| b.queued.is_some())
        {
            return Err(BlockError::Unsupported(
                "MT7925 media did not close cleanly",
            ));
        }
        self.iso = None;
        self.sco = None;
        self.next_input = 0;
        self.running = !self.bindings.has_iso();
        self.retired = false;
        Ok(())
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
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    fn queue_sco(&mut self, bytes: &[u8]) -> media::Result<Option<u64>> {
        self.with_media(|m, h| m.queue_sco(h, bytes))
    }
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
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
    fn reopen_media(&mut self) -> Result<(), BlockError> {
        self.open()?;
        self.media
            .as_mut()
            .ok_or(BlockError::Unsupported("native MT7925 media not prepared"))?
            .reopen()
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
mod tests;
