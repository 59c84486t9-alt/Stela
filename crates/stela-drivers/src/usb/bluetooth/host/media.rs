// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Native DMA glue for the exact MT7925 class plan. Common xHCI owns schedule,
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
        xhci::{self, IsoStatus, IsoTransfer},
    },
};
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};
const BUFFER: usize = 4096;
const DEPTH: usize = 32;
const SEND_US: u64 = 5_000_000;
struct Buffer {
    dma: DmaBuffer,
    queued: Option<IsoTransfer>,
}
/// All buffers remain reserved for the boot, even on a failed stop/dequeue.
/// No Drop/free can return an uncertain physical range to another driver.
pub(super) struct Native {
    bindings: Bindings,
    iso: Option<Pair>,
    sco: Option<Pair>,
    iso_input: DmaBuffer,
    iso_output: DmaBuffer,
    iso_receive: Option<u64>,
    iso_send: bool,
    input: Vec<Buffer>,
    output: Vec<Buffer>,
    next_input: usize,
    running: bool,
    retired: bool,
    poisoned: bool,
}
impl Hci<Host> {
    /// Enable this PC's MT7925 media extension with retained live initialization
    /// evidence and an actual current HCI command allowance. This must precede
    /// concurrent host/guest stack ownership; it neither performs nor permits a
    /// shared Wi-Fi/Bluetooth reset. All DMA comes from this attachment's owner.
    pub fn into_mt7925_media(
        mut self,
        dma: &mut dyn DmaAllocator,
        command_credits: u8,
    ) -> media::Result<Session<Host>> {
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
            running: false,
            retired: false,
            poisoned: false,
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
        if self.iso.is_some() || self.retired || self.poisoned || pair != self.bindings.iso() {
            return Err(BlockError::Unsupported(
                "MT7925 exact fresh interrupt interface plan",
            ));
        }
        host.controller
            .borrow_mut()
            .preflight_endpoints(host.slot, &pair.endpoints())?;
        Self::select(host, pair.interface, pair.alternate)?;
        // Record before Configure Endpoint: a failing command can leave hardware
        // ownership unresolved; cleanup must still attempt the exact contexts.
        self.iso = Some(pair);
        host.controller
            .borrow_mut()
            .configure(host.slot, &pair.endpoints(), None, dma)?;
        self.running = true;
        self.post_interrupt(host)?;
        Ok(())
    }
    fn post_interrupt(&mut self, host: &mut Host) -> Result<(), BlockError> {
        let pair = self
            .iso
            .ok_or(BlockError::Unsupported("MT7925 interrupt interface absent"))?;
        if self.iso_receive.is_none() {
            self.iso_receive = Some(host.controller.borrow_mut().submit(
                host.slot,
                pair.input.dci(),
                self.iso_input.physical(),
                media::service_bytes(pair.input),
            )?);
        }
        Ok(())
    }
    fn post_sco(&mut self, host: &mut Host) -> Result<(), BlockError> {
        let Some(pair) = self.sco else {
            return Ok(());
        };
        let len = media::service_bytes(pair.input);
        let mut controller = host.controller.borrow_mut();
        for entry in &mut self.input {
            if entry.queued.is_none() {
                entry.queued = Some(controller.submit_iso(
                    host.slot,
                    pair.input.dci(),
                    entry.dma.physical(),
                    len,
                )?);
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
        self.active()?;
        if self.sco != previous || next.is_some_and(|p| !self.bindings.accepts_sco(p)) {
            return Err(BlockError::Unsupported(
                "MT7925 exact retained SCO alternate plan",
            ));
        }
        if let Some(old) = previous {
            host.controller
                .borrow_mut()
                .deconfigure(host.slot, &old.endpoints())?;
            for buffer in self.input.iter_mut().chain(&mut self.output) {
                buffer.queued = None;
            }
            self.sco = None;
        }
        if let Some(pair) = next {
            host.controller
                .borrow_mut()
                .preflight_endpoints(host.slot, &pair.endpoints())?;
        }
        Self::select(host, 1, next.map_or(0, |p| p.alternate))?;
        self.next_input = 0;
        if let Some(pair) = next {
            self.sco = Some(pair);
            host.controller
                .borrow_mut()
                .configure(host.slot, &pair.endpoints(), None, dma)?;
            self.post_sco(host)?;
        }
        Ok(())
    }
    fn read(&mut self, host: &mut Host, kind: Kind) -> Result<Option<Read>, BlockError> {
        self.active()?;
        match kind {
            Kind::Iso => {
                self.post_interrupt(host)?;
                let pair = self.iso.unwrap();
                let length = media::service_bytes(pair.input);
                let result = host.controller.borrow_mut().completed(
                    host.slot,
                    pair.input.dci(),
                    self.iso_receive.unwrap(),
                    length,
                );
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
                        .cancel(host.slot, pair.input.dci())?;
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
        self.active()?;
        match kind {
            Kind::Iso => {
                let pair = self.iso.unwrap();
                if bytes.len() != 264 || self.iso_send {
                    return Err(media::Error::Unsupported(
                        "MT7925 padded interrupt output ownership",
                    ));
                }
                host.controller
                    .borrow_mut()
                    .endpoint_ready(host.slot, pair.output.dci())?;
                self.iso_output.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
                fence(Ordering::Release);
                let trb = host.controller.borrow_mut().submit(
                    host.slot,
                    pair.output.dci(),
                    self.iso_output.physical(),
                    bytes.len(),
                )?;
                self.iso_send = true;
                let deadline = host.clock.deadline(SEND_US);
                loop {
                    if let Some(result) = host.controller.borrow_mut().completed(
                        host.slot,
                        pair.output.dci(),
                        trb,
                        bytes.len(),
                    ) {
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
                let pair = self
                    .sco
                    .ok_or(BlockError::Unsupported("MT7925 SCO alternate inactive"))?;
                let service = media::service_bytes(pair.output);
                let count = bytes.len().div_ceil(service);
                if count > DEPTH || self.output.iter().any(|b| b.queued.is_some()) {
                    return Err(media::Error::Unsupported(
                        "bounded SCO output queue ownership",
                    ));
                }
                // Separate buffers for all services; none is overwritten before
                // its actual terminal completion or acknowledged cancellation.
                for (b, chunk) in self.output.iter_mut().zip(bytes.chunks(service)) {
                    b.dma.bytes_mut()[..chunk.len()].copy_from_slice(chunk);
                    fence(Ordering::Release);
                    b.queued = Some(host.controller.borrow_mut().submit_iso(
                        host.slot,
                        pair.output.dci(),
                        b.dma.physical(),
                        chunk.len(),
                    )?);
                }
                let deadline = host.clock.deadline(SEND_US);
                for (b, chunk) in self.output.iter_mut().zip(bytes.chunks(service)) {
                    loop {
                        if let Some(result) = host
                            .controller
                            .borrow_mut()
                            .completed_iso(b.queued.as_ref().unwrap())
                        {
                            let done = result?;
                            b.queued = None;
                            if done.status != IsoStatus::Success || done.bytes != chunk.len() {
                                // Even a terminal loss cannot credit successful
                                // HCI delivery; caller closes and drains the rest.
                                return Err(media::Error::OutputCompletion {
                                    kind,
                                    status: done.status,
                                    expected: chunk.len(),
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
    fn quiesce(&mut self, host: &mut Host) -> Result<(), BlockError> {
        self.active()?;
        self.running = false;
        let mut failure = None;
        let mut controller = host.controller.borrow_mut();
        if let Some(pair) = self.iso {
            for (pending, ep) in [
                (self.iso_receive.is_some(), pair.input),
                (self.iso_send, pair.output),
            ] {
                if pending && let Err(e) = controller.cancel(host.slot, ep.dci()) {
                    failure.get_or_insert(e);
                }
            }
        }
        if let Some(pair) = self.sco {
            // An idle completed ISO output still owns Queue.next. Always
            // acknowledge retirement of both schedules, not just live payloads.
            for ep in pair.endpoints() {
                if let Err(e) = controller.cancel(host.slot, ep.dci()) {
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
        self.next_input = 0;
        Ok(())
    }
    fn reset_epoch(&mut self, host: &mut Host) -> Result<(), BlockError> {
        self.quiesce(host)?;
        if let Some(pair) = self.sco {
            host.controller
                .borrow_mut()
                .deconfigure(host.slot, &pair.endpoints())?;
            self.sco = None;
            Self::select(host, pair.interface, 0)?;
        }
        Ok(())
    }
    fn resume(&mut self, host: &mut Host) -> Result<(), BlockError> {
        if self.running || self.retired || self.poisoned || self.iso.is_none() {
            return Err(BlockError::Unsupported(
                "MT7925 media resume requires known stopped streams",
            ));
        }
        self.running = true;
        self.post_interrupt(host)?;
        self.post_sco(host)
    }
    pub(super) fn close(&mut self, host: &mut Host) -> Result<(), BlockError> {
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
        let mut controller = host.controller.borrow_mut();
        for pair in [self.sco, self.iso].into_iter().flatten() {
            if let Err(e) = controller.deconfigure(host.slot, &pair.endpoints()) {
                failure.get_or_insert(e);
            }
        }
        drop(controller);
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
        let Some(mut media) = self.media.take() else {
            return Ok(());
        };
        let result = media.close(self);
        self.media = Some(media);
        result
    }
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
            let controller = xhci::tests::controller_with_unresolved_td(
                &mut dma,
                native.iso_input.physical(),
                512,
                5,
                halted,
            );
            let device = binding.device().clone();
            let mut hci = Hci::attach(controller, &device, binding, &mut dma).unwrap();
            // This is the shared fixture's real submitted interrupt/bulk TD,
            // not a fabricated completion. The endpoint plan is local test data.
            let mut pair = native.bindings.iso();
            pair.input.address = 0x82;
            pair.output.address = 2;
            native.iso = Some(pair);
            native.iso_receive = Some(1);
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
        let mut backing = vec![0u64; 256 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusive synthetic RAM outlives model, rings and class owner.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let fixture = xhci::iso_class_fixture(&mut dma, xhci::HIGH_SPEED);
        let controller = fixture.controller();
        let binding = binding();
        let device = binding.device().clone();
        let mut native = Native::new(Bindings::new(&binding).unwrap(), &mut dma).unwrap();
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
        native.post_sco(&mut hci.io).unwrap();
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
}
