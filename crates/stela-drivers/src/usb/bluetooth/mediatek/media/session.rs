// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Shared MT7925 media and Realtek CVSD SCO owner. Stream retirement never authorizes a shared
//! connectivity reset, power transition or Wi-Fi sibling retirement.
use super::{Bindings, Error, Kind, Pair, Result, Voice, framing};
use crate::usb::bluetooth::mediatek::{
    coredump::Collector,
    packet::DUMP_HANDLE,
    wmt::{self, WmtEvent},
};
use crate::{
    block::BlockError,
    bus::dma::DmaAllocator,
    usb::bluetooth::{Hci, InitializationReport, Io, Packet, State},
};
use alloc::vec::Vec;

/// The MediaTek dump collector for a validated MediaTek initialization.
fn collector<B: Io>(hci: &Hci<B>) -> Option<Collector> {
    match hci.initialization() {
        Some(Ok(InitializationReport::MediaTek(report))) => Some(Collector::new(
            report.identity.device_id,
            report.identity.firmware_version,
        )),
        _ => None,
    }
}

/// HCI_INIT_TIMEOUT, btmtk_usb_hci_wmt_sync's wait for the WMT event.
const WMT_TIMEOUT_US: u64 = 10_000_000;
/// btmtk_usb_submit_wmt_recv_urb's vendor EP0 IN for HCI_WMT_MAX_EVENT_SIZE.
const WMT_EVENT: [u8; 8] = [0xc0, 1, 0x30, 0, 0, 0, 64, 0];

/// What btusb_mtk_shutdown observed before the function retired.
#[derive(Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    /// The WMT function-off event; Linux requires only its operation.
    pub function_off: WmtEvent,
    /// Interrupt-pipe observations in wire order while it was awaited,
    /// including the 0xfc6f command's own flow-control event.
    pub asynchronous: Vec<Received>,
}

/// One completed media USB observation. Loss is explicit, never a successful
/// empty packet; the backend may reuse DMA only after a terminal completion.
pub enum Read {
    Data(Vec<u8>),
    Loss(Loss),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Loss {
    MissedService,
    Transaction,
    Babble,
    Bandwidth,
    BufferOverrun,
}
/// Completion authority for one accepted queued SCO packet. Retirement after
/// cancellation cannot establish whether an unobserved radio delivery occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputDisposition {
    Completed,
    RetiredUnconfirmed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputReceipt {
    pub sequence: u64,
    pub packet_bytes: usize,
    pub disposition: OutputDisposition,
}
/// Physical media boundary for this same exclusively owned HCI function.
/// Implementations retain all uncertain DMA, including on failed cancellation.
/// Replace must cancel/drain and drop old endpoint contexts before SET_INTERFACE
/// and fresh configuration. Successful quiesce permits only stream restart;
/// it is no physical suspend/resume or shared-radio reset authority.
pub trait MediaIo: Io {
    /// Some(sequence) means accepted, never delivered. None is bounded
    /// backpressure with no publication or ownership change.
    fn queue_sco(&mut self, _bytes: &[u8]) -> Result<Option<u64>> {
        Err(Error::Unsupported("queued SCO transport"))
    }
    fn poll_sco_output(&mut self) -> Result<Option<OutputReceipt>> {
        Err(Error::Unsupported("queued SCO completion transport"))
    }
    fn start_iso(
        &mut self,
        pair: Pair,
        dma: &mut dyn DmaAllocator,
    ) -> core::result::Result<(), BlockError>;
    fn replace_sco(
        &mut self,
        previous: Option<Pair>,
        next: Option<Pair>,
        dma: &mut dyn DmaAllocator,
    ) -> core::result::Result<(), BlockError>;
    fn read_media(&mut self, kind: Kind) -> core::result::Result<Option<Read>, BlockError>;
    fn write_media(&mut self, kind: Kind, bytes: &[u8]) -> Result<()>;
    fn quiesce_media(&mut self) -> core::result::Result<(), BlockError>;
    /// Drain media, remove the old SCO voice/alternate, retaining the configured
    /// third interrupt interface for ordinary HCI Reset. No shared reset.
    fn reset_media_epoch(&mut self) -> core::result::Result<(), BlockError>;
    fn resume_media(&mut self) -> core::result::Result<(), BlockError>;
    fn close_media(&mut self) -> core::result::Result<(), BlockError>;
}
#[derive(Debug, Eq, PartialEq)]
pub enum Received {
    Hci(Packet),
    Sco(Vec<u8>),
    Iso(Vec<u8>),
    Loss(Kind, Loss),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lifecycle {
    Running,
    Quiescent,
    Closed,
    Failed,
}
/// Actual synchronous command completion and returned command allowance. These
/// credits belong to the caller's HCI stack after setup, not this USB transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupReport {
    pub completion: Vec<u8>,
    pub command_credits: u8,
}

pub struct Session<B: MediaIo> {
    pub(in crate::usb::bluetooth) hci: Hci<B>,
    bindings: Bindings,
    sco: Option<Pair>,
    sco_frames: framing::Framer,
    iso_frames: framing::Framer,
    pending: Vec<Received>,
    /// MediaTek firmware dump assembly; other vendors have none.
    coredump: Option<Collector>,
    lifecycle: Lifecycle,
    setup: Option<SetupReport>,
    last_reset: Option<SetupReport>,
    wideband_mtu: Option<u16>,
}
impl<B: MediaIo> Session<B> {
    /// Consume one initialized exact-device transport before handing it to a
    /// Bluetooth stack. `command_credits` is the caller's actual current HCI
    /// allowance; no other command may be outstanding or concurrently submitted.
    /// USB identity alone cannot pass the retained live MT7925 initialization
    /// check. Failure closes the entire function and requires a fresh rebind.
    pub fn start(mut hci: Hci<B>, dma: &mut dyn DmaAllocator, command_credits: u8) -> Result<Self> {
        let result = Self::prepare(&mut hci, dma, command_credits);
        match result {
            Ok((bindings, setup, pending)) => Ok(Self {
                coredump: collector(&hci),
                hci,
                bindings,
                setup: Some(setup),
                last_reset: None,
                wideband_mtu: None,
                pending,
                sco: None,
                sco_frames: framing::Framer::new(Kind::Sco),
                iso_frames: framing::Framer::new(Kind::Iso),
                lifecycle: Lifecycle::Running,
            }),
            Err(error) => {
                let media = hci.io.close_media().err();
                let base = hci.close().err();
                Err(Error::Cleanup {
                    cause: alloc::boxed::Box::new(error),
                    media,
                    base,
                })
            }
        }
    }
    pub(in crate::usb::bluetooth) fn start_realtek(hci: Hci<B>) -> Result<Self> {
        Self::start_standard(hci, true)
    }
    pub(in crate::usb::bluetooth) fn start_qca(hci: Hci<B>) -> Result<Self> {
        Self::start_standard(hci, false)
    }
    fn start_standard(mut hci: Hci<B>, realtek: bool) -> Result<Self> {
        let result = (|| {
            hci.open().map_err(Error::Hci)?;
            let bindings = if realtek {
                Bindings::realtek_sco(hci.binding())
            } else {
                Bindings::qca_sco(hci.binding())
            }?;
            let d = &hci.binding().device().descriptor;
            let usb = crate::usb::bluetooth::realtek::UsbIdentity {
                vendor: u16::from_le_bytes([d[8], d[9]]),
                product: u16::from_le_bytes([d[10], d[11]]),
                revision: u16::from_le_bytes([d[12], d[13]]),
            };
            let ready = match hci.initialization() {
                Some(Ok(InitializationReport::Realtek(report))) if realtek => {
                    report.before.usb == usb
                }
                Some(Ok(InitializationReport::Qualcomm(report))) if !realtek => {
                    (report.usb.vendor, report.usb.product, report.usb.revision)
                        == (usb.vendor, usb.product, usb.revision)
                }
                _ => false,
            };
            if !ready {
                return Err(Error::Unsupported(
                    "retained matching live USB vendor initialization required",
                ));
            }
            Ok(bindings)
        })();
        match result {
            Ok(bindings) => Ok(Self {
                coredump: None,
                hci,
                bindings,
                sco: None,
                sco_frames: framing::Framer::new(Kind::Sco),
                iso_frames: framing::Framer::new(Kind::Iso),
                pending: Vec::new(),
                lifecycle: Lifecycle::Running,
                setup: None,
                last_reset: None,
                wideband_mtu: None,
            }),
            Err(cause) => Err(Error::Cleanup {
                cause: alloc::boxed::Box::new(cause),
                media: hci.io.close_media().err(),
                base: hci.close().err(),
            }),
        }
    }
    fn prepare(
        hci: &mut Hci<B>,
        dma: &mut dyn DmaAllocator,
        credits: u8,
    ) -> Result<(Bindings, SetupReport, Vec<Received>)> {
        hci.open().map_err(Error::Hci)?;
        let bindings = Bindings::new(hci.binding())?;
        let ready = matches!(hci.initialization(), Some(Ok(InitializationReport::MediaTek(report)))
            if report.identity.chip == super::super::Chip::Mt7925
                && report.identity.usb == super::super::UsbIdentity { vendor: 0x13d3, product: 0x3602, revision: 0x100 });
        if !ready {
            return Err(Error::Unsupported(
                "retained live MT7925 initialization required",
            ));
        }
        if credits == 0 {
            return Err(Error::Packet(
                "actual available HCI command credit required",
            ));
        }
        hci.io.start_iso(bindings.iso(), dma)?;
        // Source btmtk_usb_isointf_init: receive is posted before this genuine
        // synchronous vendor command. A Command Status is not its completion.
        let mut pending = Vec::new();
        let setup = Self::command(hci, &[0x98, 0xfd, 2, 8, 1], &mut pending, false)?;
        Ok((bindings, setup, pending))
    }
    fn command(
        hci: &mut Hci<B>,
        packet: &[u8],
        pending: &mut Vec<Received>,
        forward_completion: bool,
    ) -> Result<SetupReport> {
        let opcode = u16::from_le_bytes([packet[0], packet[1]]);
        hci.submit_command(packet).map_err(Error::Hci)?;
        let deadline = hci.io.now_us().saturating_add(5_000_000);
        let mut bytes: usize = pending
            .iter()
            .map(|p| match p {
                Received::Hci(Packet::Event(b) | Packet::Acl(b) | Packet::Diagnostic(b))
                | Received::Sco(b)
                | Received::Iso(b) => b.len(),
                Received::Loss(_, _) => 0,
            })
            .sum();
        let mut completion = None;
        while completion.is_none() {
            for packet in hci.poll().map_err(Error::Hci)? {
                let matched = match &packet {
                    Packet::Event(event)
                        if event.len() >= 5
                            && event[0] == 0x0e
                            && event[3..5] == opcode.to_le_bytes() =>
                    {
                        if completion.is_some()
                            || event.len() < 6
                            || (opcode == 0x0c03 && event.len() != 6)
                        {
                            return Err(Error::Packet(
                                "one complete synchronous HCI Command Complete",
                            ));
                        }
                        if event[5] != 0 {
                            return Err(Error::Controller {
                                status: event[5],
                                event: event.clone(),
                            });
                        }
                        completion = Some(SetupReport {
                            completion: event.clone(),
                            command_credits: event[2],
                        });
                        !forward_completion
                    }
                    Packet::Event(event)
                        if event.len() == 6
                            && event[0] == 0x0f
                            && event[4..6] == opcode.to_le_bytes() =>
                    {
                        if event[2] != 0 {
                            return Err(Error::Controller {
                                status: event[2],
                                event: event.clone(),
                            });
                        }
                        false // Preserve successful Status for the stack too.
                    }
                    _ => false,
                };
                if !matched {
                    bytes += match &packet {
                        Packet::Event(b) | Packet::Acl(b) | Packet::Diagnostic(b) => b.len(),
                    };
                    if bytes > 32768 || pending.len() >= 64 {
                        return Err(Error::Packet(
                            "bounded synchronous HCI asynchronous packets",
                        ));
                    }
                    pending.push(Received::Hci(packet));
                }
            }
            if hci.io.now_us() >= deadline {
                return Err(Error::Transport(BlockError::Timeout));
            }
            if completion.is_none() {
                crate::waiting();
                core::hint::spin_loop();
            }
        }
        Ok(completion.unwrap())
    }
    /// Last observed lifecycle; active operations validate the retained native
    /// device generation independently before using session-owned state.
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }
    pub fn setup_report(&self) -> &SetupReport {
        self.setup.as_ref().expect("MT7925 setup completion")
    }
    /// Latest ordinary HCI Reset completion, distinct from the historical vendor
    /// setup and any physical/shared reset authority. Its CC is also queued for
    /// the caller's HCI stack, in observed order with asynchronous packets.
    pub fn last_reset(&self) -> Option<&SetupReport> {
        self.last_reset.as_ref()
    }
    /// Move already observed historical packets at a completed command boundary.
    /// This performs no live poll or ownership grant and cannot discard earlier
    /// observations if a subsequent native read/retirement operation fails.
    pub(in crate::usb::bluetooth) fn take_pending_observations(&mut self) -> Vec<Received> {
        core::mem::take(&mut self.pending)
    }
    /// Historical initialization evidence for this retained owner, never proof
    /// that a later physical reset/power loss preserved radio state. Such a
    /// transition invalidates the owner and requires a fresh attachment.
    pub fn initialization(&self) -> &super::super::OwnedReport {
        match self.hci.initialization().unwrap().unwrap() {
            InitializationReport::MediaTek(r) => r,
            _ => unreachable!(),
        }
    }
    fn running(&self) -> Result<()> {
        self.hci.io.validate()?;
        if self.lifecycle != Lifecycle::Running || self.hci.state() != State::Open {
            return Err(Error::Unsupported("media session is not running"));
        }
        Ok(())
    }
    fn fail(&mut self, cause: Error) -> Error {
        self.lifecycle = Lifecycle::Failed;
        Error::Cleanup {
            cause: alloc::boxed::Box::new(cause),
            media: self.hci.io.close_media().err(),
            base: self.hci.close().err(),
        }
    }
    pub fn submit_command(&mut self, packet: &[u8]) -> Result<()> {
        self.running()?;
        if packet.len() >= 2 && packet[..2] == [3, 0x0c] {
            if packet != [3, 0x0c, 0] {
                return Err(Error::Packet("ordinary HCI Reset has no parameters"));
            }
            return self.reset();
        }
        let reinitializes = if packet.len() >= 2 {
            let opcode = u16::from_le_bytes([packet[0], packet[1]]);
            match self.hci.initialization() {
                Some(Ok(InitializationReport::MediaTek(_))) => matches!(opcode, 0xfc6f | 0xfd98),
                Some(Ok(InitializationReport::Realtek(_))) => opcode == 0xfc20,
                _ => false,
            }
        } else {
            false
        };
        if reinitializes {
            return Err(Error::Unsupported(
                "WMT/media setup requires retirement and fresh initialization",
            ));
        }
        self.hci
            .submit_command(packet)
            .map_err(|e| self.fail(Error::Hci(e)))
    }
    /// Ordinary controller HCI Reset, as source hci_dev_init_sync performs after
    /// vendor setup. Caller owns actual HCI command credits/no pending command.
    /// Retire the old voice/partial media epoch, await genuine CC, then repost
    /// third-interface RX without reapplying fd98. This is no USB/subsystem or
    /// Wi-Fi reset, and failed completion cannot resume the media owner.
    fn reset(&mut self) -> Result<()> {
        self.hci
            .io
            .reset_media_epoch()
            .map_err(|e| self.fail(e.into()))?;
        self.lifecycle = Lifecycle::Quiescent;
        self.sco = None;
        self.sco_frames.reset();
        self.iso_frames.reset();
        self.last_reset = None;
        self.wideband_mtu = None;
        let report = Self::command(&mut self.hci, &[3, 0x0c, 0], &mut self.pending, true)
            .map_err(|e| self.fail(e))?;
        self.last_reset = Some(report);
        self.hci
            .io
            .resume_media()
            .map_err(|e| self.fail(e.into()))?;
        self.lifecycle = Lifecycle::Running;
        Ok(())
    }
    pub fn submit_acl(&mut self, packet: &[u8]) -> Result<()> {
        self.running()?;
        self.hci
            .submit_acl(packet)
            .map_err(|e| self.fail(Error::Hci(e)))
    }
    pub fn set_voice(&mut self, voice: Voice, dma: &mut dyn DmaAllocator) -> Result<()> {
        self.running()?;
        let next = self.bindings.sco(voice)?;
        if next == self.sco {
            self.wideband_mtu = None;
            return Ok(());
        }
        self.hci
            .io
            .replace_sco(self.sco, next, dma)
            .map_err(|e| self.fail(e.into()))?;
        self.sco = next;
        self.wideband_mtu = None;
        self.sco_frames.reset();
        Ok(())
    }
    pub(in crate::usb::bluetooth) fn set_wideband_voice(
        &mut self,
        connections: u8,
        mtu: u16,
        dma: &mut dyn DmaAllocator,
    ) -> Result<()> {
        self.running()?;
        let capable = match self.hci.initialization() {
            Some(Ok(InitializationReport::Realtek(r))) => {
                r.before.project == crate::usb::bluetooth::realtek::Project::Rtl8852Bu
                    || matches!(
                        (r.before.usb.vendor, r.before.usb.product),
                        (0x0bda, 0x8771) | (0x0b05, 0x190e)
                    )
            }
            Some(Ok(InitializationReport::Qualcomm(r))) => r.policy.wideband_speech,
            _ => false,
        };
        if !capable {
            return Err(Error::Unsupported(
                "source initialized USB wideband capability",
            ));
        }
        let next = self.bindings.wideband_sco(connections, mtu)?;
        if next != self.sco {
            self.hci
                .io
                .replace_sco(self.sco, next, dma)
                .map_err(|e| self.fail(e.into()))?;
            self.sco = next;
            self.sco_frames.reset();
        }
        self.wideband_mtu = next.map(|_| mtu);
        Ok(())
    }
    pub(in crate::usb::bluetooth) fn queue_sco(&mut self, packet: &[u8]) -> Result<Option<u64>> {
        self.running()?;
        framing::validate(Kind::Sco, packet)?;
        let pair = self
            .sco
            .ok_or(Error::Unsupported("queued SCO requires active voice"))?;
        if self
            .wideband_mtu
            .is_some_and(|mtu| usize::from(packet[2]) > usize::from(mtu))
            || (self.wideband_mtu.is_some() && pair.alternate == 6 && packet.len() > 63)
        {
            return Err(Error::Packet("wideband packet exceeds actual MTU/service"));
        }
        self.hci.io.queue_sco(packet).map_err(|e| self.fail(e))
    }
    pub(in crate::usb::bluetooth) fn poll_sco_output(&mut self) -> Result<Option<OutputReceipt>> {
        self.hci.io.validate()?;
        if !matches!(self.lifecycle, Lifecycle::Running | Lifecycle::Quiescent) {
            return Err(Error::Unsupported("queued output owner is terminal"));
        }
        self.hci.io.poll_sco_output().map_err(|e| self.fail(e))
    }
    pub fn submit(&mut self, kind: Kind, packet: &[u8]) -> Result<()> {
        self.running()?;
        if kind == Kind::Iso && !self.bindings.has_iso() {
            return Err(Error::Unsupported(
                "SCO-only USB transport has no HCI ISO interface",
            ));
        }
        framing::validate(kind, packet)?;
        if kind == Kind::Sco && self.wideband_mtu.is_some() {
            return Err(Error::Unsupported(
                "wideband SCO requires queued output and completion polling",
            ));
        }
        if kind == Kind::Sco && self.sco.is_none() {
            return Err(Error::Unsupported(
                "SCO has no selected active voice alternate",
            ));
        }
        let result = if kind == Kind::Iso {
            self.hci.io.write_media(kind, &framing::iso_output(packet)?)
        } else {
            self.hci.io.write_media(kind, packet)
        };
        result.map_err(|e| self.fail(e))
    }
    pub fn poll(&mut self) -> Result<Vec<Received>> {
        self.running()?;
        let mut output = core::mem::take(&mut self.pending);
        output.extend(
            self.hci
                .poll()
                .map_err(|e| self.fail(Error::Hci(e)))?
                .into_iter()
                .map(Received::Hci),
        );
        // btmtk_usb_recv_acl forwards each dump frame as a diagnostic and
        // also feeds btmtk_process_coredump.
        if let Some(collector) = self.coredump.as_mut() {
            let now = self.hci.io.now_us();
            let mut ended = collector.expire(now);
            for received in &output {
                if let Received::Hci(Packet::Diagnostic(frame)) = received
                    && frame.len() >= 2
                    && u16::from_le_bytes([frame[0], frame[1]]) == DUMP_HANDLE
                    && ended.is_none()
                {
                    ended = collector.feed(frame, now);
                }
            }
            if let Some(dump) = ended {
                return Err(self.fail(Error::ControllerDump(alloc::boxed::Box::new(dump))));
            }
        }
        for kind in [Kind::Iso, Kind::Sco] {
            if kind == Kind::Iso && !self.bindings.has_iso() {
                continue;
            }
            if kind == Kind::Sco && self.sco.is_none() {
                continue;
            }
            let read = self
                .hci
                .io
                .read_media(kind)
                .map_err(|e| self.fail(e.into()))?;
            let now = self.hci.io.now_us();
            let framer = match kind {
                Kind::Sco => &mut self.sco_frames,
                Kind::Iso => &mut self.iso_frames,
            };
            let data = match read {
                Some(Read::Loss(loss)) => {
                    framer.reset();
                    output.push(Received::Loss(kind, loss));
                    continue;
                }
                Some(Read::Data(bytes)) if bytes.len() <= 4096 => bytes,
                Some(Read::Data(_)) => {
                    return Err(self.fail(Error::Packet("bounded media USB receive")));
                }
                None => Vec::new(),
            };
            let frames = framer.feed(&data, now).map_err(|e| self.fail(e))?;
            output.extend(frames.into_iter().map(|f| match kind {
                Kind::Sco => Received::Sco(f),
                Kind::Iso => Received::Iso(f),
            }));
        }
        Ok(output)
    }
    /// Cancel and drain only media endpoints. Base command/event/ACL ownership
    /// remains live; no USB power suspend, shared reset or reinitialization.
    pub fn quiesce(&mut self) -> Result<()> {
        self.running()?;
        self.hci
            .io
            .quiesce_media()
            .map_err(|e| self.fail(e.into()))?;
        for framer in [&mut self.sco_frames, &mut self.iso_frames] {
            if framer.partial() {
                framer.reset();
            }
        }
        self.lifecycle = Lifecycle::Quiescent;
        Ok(())
    }
    pub fn resume(&mut self) -> Result<()> {
        self.hci.io.validate()?;
        if self.lifecycle != Lifecycle::Quiescent {
            return Err(Error::Unsupported(
                "media resume requires acknowledged quiescence",
            ));
        }
        self.hci
            .io
            .resume_media()
            .map_err(|e| self.fail(e.into()))?;
        self.lifecycle = Lifecycle::Running;
        Ok(())
    }
    /// btusb_mtk_shutdown: WMT function control off, then the ISO interface
    /// and transport retire. `command_credits` is the caller's actual HCI
    /// allowance; zero refuses without effects. MediaTek only; any failure
    /// is terminal.
    pub fn shutdown(&mut self, command_credits: u8) -> Result<ShutdownReport> {
        self.hci.io.validate()?;
        if !matches!(self.lifecycle, Lifecycle::Running | Lifecycle::Quiescent)
            || self.hci.state() != State::Open
        {
            return Err(Error::Unsupported("media session is not open"));
        }
        if !matches!(
            self.hci.initialization(),
            Some(Ok(InitializationReport::MediaTek(_)))
        ) {
            return Err(Error::Unsupported("WMT shutdown is MediaTek-only"));
        }
        if command_credits == 0 {
            return Err(Error::Packet(
                "actual available shutdown HCI credit required",
            ));
        }
        let report = self.function_off().map_err(|e| self.fail(e))?;
        self.close()?;
        Ok(report)
    }
    fn function_off(&mut self) -> Result<ShutdownReport> {
        let command = wmt::command(wmt::FUNCTION, 0, &[0])
            .map_err(|_| Error::Packet("WMT function control command"))?;
        self.hci.submit_command(&command).map_err(Error::Hci)?;
        let deadline = self.hci.io.now_us().saturating_add(WMT_TIMEOUT_US);
        let mut asynchronous = core::mem::take(&mut self.pending);
        loop {
            for packet in self.hci.poll().map_err(Error::Hci)? {
                if asynchronous.len() >= 64 {
                    return Err(Error::Packet("bounded shutdown asynchronous packets"));
                }
                asynchronous.push(Received::Hci(packet));
            }
            let bytes = self.hci.io.control_read(WMT_EVENT)?;
            if !bytes.is_empty() {
                let function_off = WmtEvent::parse(bytes, wmt::FUNCTION)
                    .map_err(|_| Error::Packet("WMT function control event"))?;
                return Ok(ShutdownReport {
                    function_off,
                    asynchronous,
                });
            }
            let now = self.hci.io.now_us();
            if now >= deadline {
                return Err(Error::Transport(BlockError::Timeout));
            }
            // btmtk_usb_wmt_recv relaxes 500 us before resubmitting an empty IN.
            while self.hci.io.now_us() < now.saturating_add(500) {
                crate::waiting();
                core::hint::spin_loop();
            }
        }
    }
    pub fn close(&mut self) -> Result<()> {
        self.hci.io.validate()?;
        if self.lifecycle == Lifecycle::Closed {
            return Ok(());
        }
        if self.lifecycle == Lifecycle::Failed {
            return Err(Error::Unsupported(
                "failed media session requires fresh rebind",
            ));
        }
        let media = self.hci.io.close_media().err();
        let base = self.hci.close().err();
        self.lifecycle = if media.is_none() && base.is_none() {
            Lifecycle::Closed
        } else {
            Lifecycle::Failed
        };
        if media.is_some() || base.is_some() {
            return Err(Error::Cleanup {
                cause: alloc::boxed::Box::new(Error::Unsupported("media close failed")),
                media,
                base,
            });
        }
        Ok(())
    }
}
impl<B: MediaIo> Drop for Session<B> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
pub(in crate::usb::bluetooth) mod generation_tests;
