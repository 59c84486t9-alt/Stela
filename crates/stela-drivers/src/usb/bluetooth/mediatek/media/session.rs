// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! Owned MT7925 media session. Stream retirement never authorizes a shared
//! connectivity reset, power transition or Wi-Fi sibling retirement.
use super::{Bindings, Error, Kind, Pair, Result, Voice, framing};
use crate::{
    block::BlockError,
    bus::dma::DmaAllocator,
    usb::bluetooth::{Hci, InitializationReport, Io, Packet, State},
};
use alloc::vec::Vec;

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
/// Physical media boundary for this same exclusively owned HCI function.
/// Implementations retain all uncertain DMA, including on failed cancellation.
/// Replace must cancel/drain and drop old endpoint contexts before SET_INTERFACE
/// and fresh configuration. Successful quiesce permits only stream restart;
/// it is no physical suspend/resume or shared-radio reset authority.
pub trait MediaIo: Io {
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
    pub(super) hci: Hci<B>,
    bindings: Bindings,
    sco: Option<Pair>,
    sco_frames: framing::Framer,
    iso_frames: framing::Framer,
    pending: Vec<Received>,
    lifecycle: Lifecycle,
    setup: SetupReport,
    last_reset: Option<SetupReport>,
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
                hci,
                bindings,
                setup,
                last_reset: None,
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
    pub fn lifecycle(&self) -> Lifecycle {
        self.lifecycle
    }
    pub fn setup_report(&self) -> &SetupReport {
        &self.setup
    }
    /// Latest ordinary HCI Reset completion, distinct from the historical vendor
    /// setup and any physical/shared reset authority. Its CC is also queued for
    /// the caller's HCI stack, in observed order with asynchronous packets.
    pub fn last_reset(&self) -> Option<&SetupReport> {
        self.last_reset.as_ref()
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
        if packet.len() >= 2
            && matches!(u16::from_le_bytes([packet[0], packet[1]]), 0xfc6f | 0xfd98)
        {
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
            return Ok(());
        }
        self.hci
            .io
            .replace_sco(self.sco, next, dma)
            .map_err(|e| self.fail(e.into()))?;
        self.sco = next;
        self.sco_frames.reset();
        Ok(())
    }
    pub fn submit(&mut self, kind: Kind, packet: &[u8]) -> Result<()> {
        self.running()?;
        framing::validate(kind, packet)?;
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
        for kind in [Kind::Iso, Kind::Sco] {
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
    pub fn close(&mut self) -> Result<()> {
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
