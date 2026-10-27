//! Serialized SCSI-transparent Bulk-Only Transport for all LUNs of one interface.
// SPDX-License-Identifier: GPL-2.0-only AND GPL-2.0-or-later
// Hardware protocol reference: Linux drivers/usb/storage/transport.c,
// Copyright 1999-2002 Matthew Dharm; 2000 David L. Brown, Jr.;
// 2000 Stephen J. Gowdy; 2002 Alan Stern; 1999 Michael Gee.
// Block-zero ordering: Linux sd.c, Drew Eckhardt 1992; Eric Youngdale
// 1993-1995, 1999. Retained lifecycle uses Stela's shared xHCI authority.
use super::super::xhci::{DEVICE_TO_HOST, Device, Interface, RECIPIENT_INTERFACE, TYPE_CLASS};
use super::{Data, Endpoint, MAX_TD, Shared, scsi, setup};
mod quirks;
use crate::{
    block::{BlockError, Sense},
    bus::dma::{DmaAllocator, DmaBuffer},
};
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

const RESET: u8 = 0xff;
const GET_MAX_LUN: u8 = 0xfe;
const CBW_SIGNATURE: u32 = 0x4342_5355;
const CSW_SIGNATURE: u32 = 0x5342_5355;
/// bCSWStatus: Command Failed (BOT 5.2).
const CSW_FAILED: u8 = 1;
const COMMAND_US: u64 = 30_000_000;
const RESET_RECOVERY_US: u64 = 6_000_000;
const MAX_LUN: u8 = 15;
/// xHCI completion code 22: the slot must be retired, not cancelled.
const INCOMPATIBLE_DEVICE: u32 = 22;
const PROTOCOL_ERROR: BlockError = BlockError::Protocol("malformed Bulk-Only wrapper or transfer");
const SHORT_WRITE: BlockError = BlockError::Protocol("short Bulk-Only write");

pub(super) fn supported(device: &Device) -> Result<(), &'static str> {
    quirks::Flags::from_device(device).map(|_| ())
}

/// Private seam: every native transfer returns only after completion or actual
/// xHCI cancellation. An error may leave poison; ready must expose it before
/// the CPU touches either DMA buffer again. No hosted USB API is used.
pub(super) trait Io {
    fn ready(&mut self) -> Result<(), BlockError>;
    fn control(&mut self, request: [u8; 8]) -> Result<Vec<u8>, BlockError>;
    fn clear(&mut self, endpoint: Endpoint) -> Result<(), BlockError>;
    fn bulk(&mut self, endpoint: Endpoint, buffer: u64, length: usize)
    -> Result<usize, BlockError>;
    fn delay(&self, micros: u64);
    /// The transport's clock, in microseconds.
    fn now_us(&self) -> u64;
    /// Submit a bulk transfer and return; [`Self::reap`] gives its length
    /// once complete. By default it runs at once.
    fn submit(
        &mut self,
        endpoint: Endpoint,
        buffer: u64,
        length: usize,
    ) -> Result<Pending, BlockError> {
        Ok(Pending::Done(self.bulk(endpoint, buffer, length)))
    }
    /// A submitted transfer's length once complete; never waits. A failed
    /// or timed-out one has had its endpoint's queue cancelled, as a
    /// failed [`Self::bulk`] has.
    fn reap(&mut self, pending: &Pending) -> Option<Result<usize, BlockError>> {
        match pending {
            Pending::Done(result) => Some(result.clone()),
            Pending::Ticket { .. } => Some(Err(BlockError::Protocol(
                "a BOT transfer ticket on a transport without tickets",
            ))),
        }
    }
}

/// A submitted bulk transfer ([`Io::submit`]).
pub(super) enum Pending {
    Done(Result<usize, BlockError>),
    Ticket {
        ticket: super::super::xhci::TransferTicket,
        dci: u8,
        deadline: crate::Deadline,
    },
}

pub(super) struct Native {
    pub controller: Shared,
    pub id: super::super::xhci::SlotId,
    pub endpoints: [Endpoint; 2],
}
impl Io for Native {
    fn ready(&mut self) -> Result<(), BlockError> {
        let mut controller = self.controller.borrow_mut();
        let mut device = controller.device(self.id)?;
        for dci in [1, self.endpoints[0].dci(), self.endpoints[1].dci()] {
            device.endpoint_ready(dci)?;
        }
        Ok(())
    }
    fn control(&mut self, request: [u8; 8]) -> Result<Vec<u8>, BlockError> {
        self.controller
            .borrow_mut()
            .device(self.id)?
            .control(request, &[])
    }
    fn clear(&mut self, endpoint: Endpoint) -> Result<(), BlockError> {
        self.controller
            .borrow_mut()
            .device(self.id)?
            .clear(&endpoint)
    }
    fn bulk(
        &mut self,
        endpoint: Endpoint,
        buffer: u64,
        length: usize,
    ) -> Result<usize, BlockError> {
        self.controller.borrow_mut().device(self.id)?.transfer(
            endpoint.dci(),
            buffer,
            length,
            COMMAND_US,
        )
    }
    fn delay(&self, micros: u64) {
        let clock = self.controller.borrow().clock;
        clock.delay(micros);
    }
    fn now_us(&self) -> u64 {
        self.controller.borrow().clock.now_us()
    }
    fn submit(
        &mut self,
        endpoint: Endpoint,
        buffer: u64,
        length: usize,
    ) -> Result<Pending, BlockError> {
        let mut controller = self.controller.borrow_mut();
        let deadline = controller
            .clock
            .try_deadline(COMMAND_US)
            .map_err(|_| BlockError::Unsupported("xHCI transfer timeout clock unavailable"))?;
        let dci = endpoint.dci();
        let ticket = controller
            .device(self.id)?
            .submit_ticket(dci, buffer, length)?;
        Ok(Pending::Ticket {
            ticket,
            dci,
            deadline,
        })
    }
    /// As the xHCI's own waited transfer: a failure or a timeout cancels
    /// the endpoint's queue before the buffer returns to the CPU.
    fn reap(&mut self, pending: &Pending) -> Option<Result<usize, BlockError>> {
        let Pending::Ticket {
            ticket,
            dci,
            deadline,
        } = pending
        else {
            let Pending::Done(result) = pending else {
                unreachable!()
            };
            return Some(result.clone());
        };
        let mut controller = self.controller.borrow_mut();
        let mut device = match controller.device(self.id) {
            Ok(device) => device,
            Err(error) => return Some(Err(error)),
        };
        match device.completed_ticket(ticket) {
            Some(Ok(length)) => Some(Ok(length)),
            Some(Err(error)) => {
                let incompatible = matches!(
                    error,
                    BlockError::Device {
                        status: INCOMPATIBLE_DEVICE
                    }
                );
                if !incompatible && let Err(cancel) = device.cancel(*dci) {
                    return Some(Err(cancel));
                }
                Some(Err(error))
            }
            None if deadline.passed() => Some(device.cancel(*dci).and(Err(BlockError::Timeout))),
            None => None,
        }
    }
}

/// The unique owner can move to a fresh transport only after actual whole-device
/// retirement and successful native reconstruction. Retained old media aliases
/// keep their poisoned Bot, whose buffer slots are then permanently empty.
/// This never manufactures another DmaBuffer or rewinds its allocator.
struct TransportBuffer(Option<DmaBuffer>);
impl TransportBuffer {
    fn new(buffer: DmaBuffer) -> Self {
        Self(Some(buffer))
    }
    fn present(&self) -> bool {
        self.0.is_some()
    }
    fn transfer(&mut self) -> Self {
        Self(Some(self.0.take().expect("retained BOT DMA owner")))
    }
}
impl Deref for TransportBuffer {
    type Target = DmaBuffer;
    fn deref(&self) -> &DmaBuffer {
        self.0.as_ref().expect("retained BOT DMA owner")
    }
}
impl DerefMut for TransportBuffer {
    fn deref_mut(&mut self) -> &mut DmaBuffer {
        self.0.as_mut().expect("retained BOT DMA owner")
    }
}

pub(super) struct Bot<I: Io> {
    pub io: I,
    interface: u8,
    endpoints: [Endpoint; 2],
    buffer: TransportBuffer,
    wrapper: TransportBuffer,
    tag: u32,
    max_lun: u8,
    poisoned: bool,
    flags: quirks::Flags,
    initial_read: bool,
    attachment: Option<(Device, Interface)>,
    reset_generation: u64,
    /// The clock time a reset recovery's settling ends ([`Self::recover`]).
    settling: Option<u64>,
    /// The command begun and not yet ended ([`Self::begin`]).
    begun: Option<Begun>,
}

/// A command between its wrapper and its status, one transfer at a time,
/// none waited for ([`Bot::begin`]).
struct Begun {
    lun: u8,
    cdb: Vec<u8>,
    is_in: bool,
    length: usize,
    out: Option<Vec<u8>>,
    received: Vec<u8>,
    moved: usize,
    /// The status stage met a zero-length packet, or a stall.
    zero: bool,
    stalled: bool,
    stage: Stage,
    /// The command is the REQUEST SENSE that answers another's result.
    sensing: Option<Sensing>,
}

/// What a REQUEST SENSE answers (Linux `usb_stor_invoke_transport`).
#[derive(Clone, Copy)]
enum Sensing {
    /// The command reported CHECK CONDITION: its auto-sense.
    Failed,
    /// A SYNCHRONIZE CACHE the device's quirk leaves without status.
    Synchronized,
}

enum Stage {
    /// The CBW, of this many bytes.
    Wrapper(Pending, usize),
    /// A data transfer of this many bytes.
    Data(Pending, usize),
    Status(Pending),
}

/// What a step of a begun command left.
enum Next {
    Wait,
    Stage(Stage),
    Done(Result<Vec<u8>, BlockError>),
}

impl<I: Io> Bot<I> {
    #[cfg(test)]
    pub fn new(
        io: I,
        interface: u8,
        endpoints: [Endpoint; 2],
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        Self::with_flags(io, interface, endpoints, dma, quirks::Flags::default())
    }
    fn with_flags(
        mut io: I,
        interface: u8,
        endpoints: [Endpoint; 2],
        dma: &mut dyn DmaAllocator,
        flags: quirks::Flags,
    ) -> Result<Self, BlockError> {
        let max_lun = Self::startup(&mut io, interface, flags)?;
        Ok(Self::with_buffers(
            io,
            interface,
            endpoints,
            TransportBuffer::new(dma.allocate(MAX_TD, MAX_TD)?),
            TransportBuffer::new(dma.allocate(64, 64)?),
            flags,
            max_lun,
        ))
    }
    /// Perform actual transport admission before committing any moved buffers.
    fn startup(io: &mut I, interface: u8, flags: quirks::Flags) -> Result<u8, BlockError> {
        io.ready()?;
        let request = setup(
            DEVICE_TO_HOST | TYPE_CLASS | RECIPIENT_INTERFACE,
            GET_MAX_LUN,
            0,
            u16::from(interface),
            1,
        );
        Ok(if flags.single_lun() {
            0
        } else {
            match io.control(request) {
                Ok(bytes) if bytes.len() == 1 && bytes[0] <= MAX_LUN => bytes[0],
                // Linux `usb_stor_Bulk_max_lun`: devices stall this request, send
                // nothing, time out or answer nonsense; all mean one LUN. EP0
                // must still be usable afterwards.
                _ => {
                    io.ready()?;
                    0
                }
            }
        })
    }
    fn with_buffers(
        io: I,
        interface: u8,
        endpoints: [Endpoint; 2],
        buffer: TransportBuffer,
        wrapper: TransportBuffer,
        flags: quirks::Flags,
        max_lun: u8,
    ) -> Self {
        Self {
            io,
            interface,
            endpoints,
            buffer,
            wrapper,
            tag: 0,
            max_lun,
            poisoned: false,
            flags,
            initial_read: flags.initial_read(),
            attachment: None,
            reset_generation: 0,
            settling: None,
            begun: None,
        }
    }
    pub fn max_lun(&self) -> u8 {
        self.max_lun
    }
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }
    pub fn delay(&self, micros: u64) {
        self.io.delay(micros);
    }

    pub fn generation(&self) -> u64 {
        self.reset_generation
    }
    pub fn write_protect(&self) -> bool {
        self.flags.write_protect()
    }
    pub fn write_cache(&self) -> bool {
        self.flags.write_cache()
    }
    pub fn capacity16_first(&self) -> bool {
        self.flags.capacity16_first()
    }
    pub fn capacity(&self, blocks: u64) -> Option<u64> {
        self.flags.capacity(blocks)
    }
    pub fn max_transfer_bytes(&self) -> usize {
        self.flags.max_transfer_bytes()
    }
    pub fn read_before_mode_sense(&mut self, lun: u8, block_size: usize) -> Result<(), BlockError> {
        let mut cdb = [0; 10];
        cdb[0] = scsi::READ_10;
        cdb[8] = 1;
        if self.initial_read {
            // Linux INITIAL_READ10 discards the first result. This workaround
            // runs only while probing metadata before publication, never on a
            // caller's data command or after an observed media change.
            self.initial_read = false;
            match self.command(lun, &cdb, Data::In(block_size)) {
                Err(BlockError::Sense(sense)) if super::media::changed(&sense) => {
                    return Err(BlockError::Sense(sense));
                }
                Err(error) if self.poisoned => return Err(error),
                _ => {}
            }
        }
        let bytes = self.command(lun, &cdb, Data::In(block_size))?;
        if bytes.len() != block_size {
            return Err(BlockError::Protocol("short USB block-zero read"));
        }
        Ok(())
    }

    fn ready(&mut self) -> Result<(), BlockError> {
        if self.poisoned || !self.buffer.present() || !self.wrapper.present() {
            return Err(BlockError::Unsupported(
                "USB storage interface requires rebind",
            ));
        }
        if let Err(error) = self.io.ready() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }
    /// Reset and halt clearing affect *every* LUN. All acknowledgements must
    /// succeed to reuse the shared transport. Unresolved DMA stays in permanent
    /// boot allocations, and the entire interface remains quarantined.
    ///
    /// Acknowledged class reset is not device-side recovery completion: as
    /// usb_stor_reset_common, the device settles for HZ*6 before either
    /// CLEAR_FEATURE, which controller readiness alone cannot replace. No
    /// caller waits for it; the transport takes no command until it has
    /// passed ([`Self::recovering`]).
    fn recover(&mut self) {
        let reset = (|| {
            self.io.ready()?;
            self.io.control(setup(
                TYPE_CLASS | RECIPIENT_INTERFACE,
                RESET,
                0,
                u16::from(self.interface),
                0,
            ))
        })();
        match reset {
            // The acknowledged reset ends every published unit's media.
            Ok(_) => {
                self.settling = Some(self.io.now_us().saturating_add(RESET_RECOVERY_US));
                self.reset_generation = self.reset_generation.wrapping_add(1);
            }
            Err(_) => self.poisoned = true,
        }
    }

    /// Whether a reset recovery still settles. Once it has settled, both
    /// halts are cleared and the transport takes commands again.
    fn recovering(&mut self) -> bool {
        let Some(settled) = self.settling else {
            return false;
        };
        if self.io.now_us() < settled {
            return true;
        }
        self.settling = None;
        let result = (|| {
            self.io.ready()?;
            let input = self.io.clear(self.endpoints[0]);
            let output = self.io.clear(self.endpoints[1]);
            input?;
            output?;
            self.io.ready()
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        false
    }
    fn failed<T>(&mut self, error: BlockError) -> Result<T, BlockError> {
        self.recover();
        Err(error)
    }

    /// Run `cdb` on `lun`, the caller waiting, for a reset recovery's
    /// settling first.
    pub fn command(&mut self, lun: u8, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        if let Some(settled) = self.settling {
            let now = self.io.now_us();
            if now < settled {
                self.io.delay(settled - now);
            }
        }
        self.begin(lun, cdb, data)?;
        self.wait()
    }

    /// The begun command's result, the caller waiting for its transfers.
    fn wait(&mut self) -> Result<Vec<u8>, BlockError> {
        loop {
            if let Some(result) = self.end() {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Whether a begun command has not ended, or a reset recovery settles.
    pub fn busy(&mut self) -> bool {
        self.begun.is_some() || self.recovering()
    }

    /// Begin `cdb` on `lun` with its data stage and return once its CBW is
    /// submitted; [`Self::end`] gives the result.
    pub fn begin(&mut self, lun: u8, cdb: &[u8], data: Data<'_>) -> Result<(), BlockError> {
        if self.begun.is_some() || self.recovering() {
            return Err(BlockError::Protocol(
                "BOT runs one command at a time, none while its reset settles",
            ));
        }
        if lun > self.max_lun || cdb.is_empty() || cdb.len() > 16 || !self.flags.permits(cdb) {
            return Err(BlockError::Unsupported(
                "invalid USB storage LUN or command",
            ));
        }
        let (length, is_in, out) = match data {
            Data::None => (0, false, None),
            Data::In(n) => (n, true, None),
            Data::Out(b) => (b.len(), false, Some(b.to_vec())),
        };
        if length > self.max_transfer_bytes() {
            return Err(BlockError::Unsupported(
                "USB storage transfer above device bound",
            ));
        }
        self.ready()?;
        self.tag = self.tag.wrapping_add(1);
        let wrapper = cbw(self.tag, lun, cdb, length, is_in);
        self.wrapper.bytes_mut()[..31].copy_from_slice(&wrapper);
        // BULK32 pads the actual native transfer; stale wrapper bytes cannot
        // leak through the extra donor-defined byte.
        let cbw_length = self.flags.cbw_len();
        self.wrapper.bytes_mut()[31] = 0;
        let pending = match self
            .io
            .submit(self.endpoints[1], self.wrapper.physical(), cbw_length)
        {
            Ok(pending) => pending,
            Err(error) => return self.failed(error),
        };
        self.begun = Some(Begun {
            lun,
            cdb: cdb.to_vec(),
            is_in,
            length,
            out,
            received: Vec::new(),
            moved: 0,
            zero: false,
            stalled: false,
            stage: Stage::Wrapper(pending, cbw_length),
            sensing: None,
        });
        Ok(())
    }

    /// The begun command's data once its status arrived, with same-LUN
    /// auto-sense after a failure, which runs as the command did; never
    /// waits for a transfer.
    pub fn end(&mut self) -> Option<Result<Vec<u8>, BlockError>> {
        let mut begun = self.begun.take()?;
        let result = loop {
            match self.advance(&mut begun) {
                Next::Wait => {
                    self.begun = Some(begun);
                    return None;
                }
                Next::Stage(stage) => begun.stage = stage,
                Next::Done(result) => break result,
            }
        };
        match begun.sensing {
            Some(Sensing::Failed) => {
                let sense = result.ok().and_then(|bytes| Sense::parse(&bytes));
                return Some(Err(
                    sense.map_or(BlockError::CheckCondition, BlockError::Sense)
                ));
            }
            Some(Sensing::Synchronized) => {
                return Some(result.and_then(|bytes| {
                    let sense = Sense::parse(&bytes).ok_or(PROTOCOL_ERROR)?;
                    if sense.key != 0 {
                        return Err(BlockError::Sense(sense));
                    }
                    Ok(Vec::new())
                }));
            }
            None => {}
        }
        let (lun, cdb) = (begun.lun, &begun.cdb);
        // SCSI auto-sense must use the failing command's LUN, and cannot race
        // a different unit's command while the interface is borrowed.
        let sensing = if result == Err(BlockError::CheckCondition) {
            (cdb[0] != scsi::REQUEST_SENSE).then_some(Sensing::Failed)
        } else {
            (result.is_ok()
                && cdb.first() == Some(&scsi::SYNCHRONIZE_CACHE_10)
                && self.flags.sense_after_sync())
            .then_some(Sensing::Synchronized)
        };
        let Some(sensing) = sensing else {
            return Some(result);
        };
        if let Err(error) = self.begin(lun, &scsi::request_sense(), Data::In(scsi::SENSE_BYTES)) {
            return Some(Err(match sensing {
                Sensing::Failed => BlockError::CheckCondition,
                Sensing::Synchronized => error,
            }));
        }
        self.begun.as_mut().unwrap().sensing = Some(sensing);
        self.end()
    }

    /// Move the begun command on as far as its completed transfers allow.
    fn advance(&mut self, begun: &mut Begun) -> Next {
        match &begun.stage {
            Stage::Wrapper(pending, cbw_length) => {
                let cbw_length = *cbw_length;
                let Some(result) = self.io.reap(pending) else {
                    return Next::Wait;
                };
                match result {
                    Ok(n) if n == cbw_length => {}
                    Ok(_) => return Next::Done(self.failed(PROTOCOL_ERROR)),
                    Err(error) => return Next::Done(self.failed(error)),
                }
                if self.flags.go_slow() {
                    self.io.delay(125);
                }
                self.data_or_status(begun)
            }
            Stage::Data(pending, piece) => {
                let piece = *piece;
                let Some(result) = self.io.reap(pending) else {
                    return Next::Wait;
                };
                let endpoint = self.endpoints[usize::from(!begun.is_in)];
                match result {
                    Ok(n) if n <= piece => {
                        if begun.is_in {
                            begun.received.extend_from_slice(&self.buffer.bytes()[..n]);
                        }
                        begun.moved += n;
                        if n < piece {
                            return self.status(begun);
                        }
                        self.data_or_status(begun)
                    }
                    Ok(_) => Next::Done(self.failed(PROTOCOL_ERROR)),
                    Err(BlockError::Device {
                        status: super::STALL,
                    }) => {
                        if let Err(error) = self.io.clear(endpoint) {
                            return Next::Done(self.failed(error));
                        }
                        self.status(begun)
                    }
                    Err(error) => Next::Done(self.failed(error)),
                }
            }
            Stage::Status(pending) => {
                let Some(result) = self.io.reap(pending) else {
                    return Next::Wait;
                };
                match result {
                    Ok(13) => Next::Done(self.conclude(begun)),
                    Ok(0) if !begun.zero && !begun.stalled => {
                        begun.zero = true;
                        self.submit_status()
                    }
                    Err(BlockError::Device {
                        status: super::STALL,
                    }) if !begun.stalled => {
                        begun.stalled = true;
                        if let Err(error) = self.io.clear(self.endpoints[0]) {
                            return Next::Done(self.failed(error));
                        }
                        self.submit_status()
                    }
                    Ok(_) => Next::Done(self.failed(PROTOCOL_ERROR)),
                    Err(error) => Next::Done(self.failed(error)),
                }
            }
        }
    }

    /// A data stage longer than one transfer descriptor moves as
    /// consecutive ones of `MAX_TD` bytes, each a whole number of packets,
    /// as Linux's scatter-gather list does, until the device ends it short
    /// or stalls.
    fn data_or_status(&mut self, begun: &mut Begun) -> Next {
        if begun.moved >= begun.length {
            return self.status(begun);
        }
        let piece = (begun.length - begun.moved).min(MAX_TD);
        // No uncertain CBW transfer can be followed by a CPU data write.
        if let Some(bytes) = &begun.out {
            self.buffer.bytes_mut()[..piece]
                .copy_from_slice(&bytes[begun.moved..begun.moved + piece]);
        }
        let endpoint = self.endpoints[usize::from(!begun.is_in)];
        match self.io.submit(endpoint, self.buffer.physical(), piece) {
            Ok(pending) => Next::Stage(Stage::Data(pending, piece)),
            Err(error) => Next::Done(self.failed(error)),
        }
    }

    /// Some bridges skip the data phase and send the CSW directly. Keep
    /// status bytes out of returned media and do not wait for a second CSW.
    fn status(&mut self, begun: &mut Begun) -> Next {
        let skipped = begun.is_in
            && begun.moved == 13
            && begun.length > 13
            && u32::from_le_bytes(begun.received[..4].try_into().unwrap()) == CSW_SIGNATURE;
        if skipped {
            self.wrapper.bytes_mut()[..13].copy_from_slice(&begun.received[..13]);
            begun.moved = 0;
            return Next::Done(self.conclude(begun));
        }
        self.submit_status()
    }

    fn submit_status(&mut self) -> Next {
        match self
            .io
            .submit(self.endpoints[0], self.wrapper.physical(), 13)
        {
            Ok(pending) => Next::Stage(Stage::Status(pending)),
            Err(error) => Next::Done(self.failed(error)),
        }
    }

    /// The command's result from its CSW.
    fn conclude(&mut self, begun: &mut Begun) -> Result<Vec<u8>, BlockError> {
        let (cdb, is_in, length, moved) = (&begun.cdb, begun.is_in, begun.length, begun.moved);
        let mut received = core::mem::take(&mut begun.received);
        let bytes = &self.wrapper.bytes()[..13];
        let residue = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let status = bytes[12];
        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != CSW_SIGNATURE
            || (!self.flags.ignore_tag()
                && u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != self.tag)
            || status > 1
        {
            return self.failed(PROTOCOL_ERROR);
        }
        if status == CSW_FAILED {
            return Err(BlockError::CheckCondition);
        }
        // transport.c detects bogus residue only from completely received,
        // successful fixed-size identification replies; no bytes are invented.
        if is_in
            && moved == length
            && residue != 0
            && ((cdb[0] == scsi::INQUIRY && length == 36)
                || (cdb[0] == scsi::READ_CAPACITY_10 && length == 8))
        {
            self.flags.learn_residue();
        }
        if !self.flags.ignore_residue() && residue > length {
            return self.failed(PROTOCOL_ERROR);
        }
        let residue = if self.flags.ignore_residue() {
            0
        } else {
            residue
        };
        // A successful CSW does not turn a partial block write into success.
        if !is_in && (moved != length || residue != 0) {
            return Err(SHORT_WRITE);
        }
        received.truncate(moved.min(length - residue));
        Ok(received)
    }
}

impl Bot<Native> {
    pub fn native(
        io: Native,
        device: &Device,
        setting: &Interface,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        let flags = quirks::Flags::from_device(device).map_err(BlockError::Unsupported)?;
        let endpoints = io.endpoints;
        let mut bot = Self::with_flags(io, setting.number, endpoints, dma, flags)?;
        bot.attachment = Some((device.clone(), setting.clone()));
        Ok(bot)
    }
    pub fn device(&self) -> &Device {
        &self.attachment.as_ref().expect("native BOT attachment").0
    }
    pub fn interface(&self) -> u8 {
        self.interface
    }
    pub fn quarantine(&mut self) {
        self.poisoned = true;
        let mut controller = self.io.controller.borrow_mut();
        if let Ok(mut device) = controller.device(self.io.id) {
            device.quarantine();
        }
    }
    /// Reconstruct the genuine attachment while retaining its two transport
    /// allocations. Root-leaf reset also reuses the controller's retired
    /// resources; downstream reset retains the existing allocation behavior.
    /// Every fallible reconstruction step precedes moving either buffer owner.
    pub fn reset_and_rebind(
        &mut self,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, (alloc::string::String, BlockError)> {
        self.poisoned = true;
        let fail = |why| {
            (
                alloc::string::String::from("BOT reset/rebind"),
                BlockError::Unsupported(why),
            )
        };
        if !self.buffer.present() || !self.wrapper.present() {
            return Err(fail("BOT transport DMA owners already transferred"));
        }
        let (old, old_setting) = self
            .attachment
            .as_ref()
            .ok_or_else(|| fail("BOT has no retained native attachment"))?;
        let interfaces = super::super::xhci::interfaces(&old.configuration);
        if old.configuration.get(4) != Some(&1)
            || interfaces.is_empty()
            || interfaces.iter().any(|i| i.number != self.interface)
        {
            return Err(fail(
                "BOT reset requires exclusive ownership of a single-interface device",
            ));
        }
        let controller = self.io.controller.clone();
        // SAFETY: this sole interface owns both bulk endpoints and was
        // permanently poisoned before retiring the complete physical device.
        let mut fresh = unsafe {
            controller
                .borrow_mut()
                .reset_and_reuse_root(old, &self.endpoints, dma)?
        };
        let id = fresh.id;
        let result = (|| {
            if fresh.descriptor != old.descriptor
                || fresh.configurations != old.configurations
                || fresh.serial != old.serial
                || fresh.speed != old.speed
            {
                return Err(fail("USB device identity/descriptors changed across reset"));
            }
            fresh.configuration = fresh
                .configurations
                .iter()
                .find(|bytes| bytes.get(5) == Some(&old.configuration_value()))
                .cloned()
                .ok_or_else(|| fail("USB reset lost the selected configuration"))?;
            let setting = super::super::xhci::interfaces(&fresh.configuration)
                .into_iter()
                .find(|i| {
                    i.number == self.interface
                        && i.alternate == old_setting.alternate
                        && i.class == super::CLASS
                        && i.subclass == super::SCSI
                        && i.protocol == super::BULK_ONLY
                })
                .ok_or_else(|| fail("USB reset lost the selected BOT alternate"))?;
            controller
                .borrow_mut()
                .device(id)
                .and_then(|mut device| device.set_configuration(fresh.configuration_value()))
                .map_err(|e| {
                    (
                        alloc::string::String::from("BOT reset restore configuration"),
                        e,
                    )
                })?;
            if setting.alternate != 0 {
                controller
                    .borrow_mut()
                    .device(id)
                    .and_then(|mut device| {
                        device.control(
                            setup(
                                1,
                                super::super::xhci::SET_INTERFACE,
                                u16::from(setting.alternate),
                                u16::from(setting.number),
                                0,
                            ),
                            &[],
                        )
                    })
                    .map_err(|e| {
                        (
                            alloc::string::String::from("BOT reset restore alternate"),
                            e,
                        )
                    })?;
            }
            controller
                .borrow_mut()
                .device(id)
                .and_then(|mut device| device.configure(&self.endpoints, None, dma))
                .map_err(|e| {
                    (
                        alloc::string::String::from("BOT reset reconstruct endpoints"),
                        e,
                    )
                })?;
            let flags = quirks::Flags::from_device(&fresh).map_err(fail)?;
            let mut io = Native {
                controller: controller.clone(),
                id,
                endpoints: self.endpoints,
            };
            let max_lun = Self::startup(&mut io, setting.number, flags).map_err(|e| {
                (
                    alloc::string::String::from("BOT reset reconstruct transport"),
                    e,
                )
            })?;
            io.ready().map_err(|e| {
                (
                    alloc::string::String::from("BOT reset final transport readiness"),
                    e,
                )
            })?;
            // Every fallible operation has completed. Whole-device retirement
            // acknowledged all old endpoint DMA, and fresh configuration and
            // endpoint commands have acknowledged the replacement. No request
            // in the new transport refers to either application buffer yet.
            // Move the actual unique owners; old aliases stay poisoned and
            // cannot inspect or submit these addresses again.
            let mut buffer = self.buffer.transfer();
            let mut wrapper = self.wrapper.transfer();
            buffer.bytes_mut().fill(0);
            wrapper.bytes_mut().fill(0);
            let mut bot = Self::with_buffers(
                io,
                setting.number,
                self.endpoints,
                buffer,
                wrapper,
                flags,
                max_lun,
            );
            bot.attachment = Some((fresh, setting));
            Ok(bot)
        })();
        if result.is_err()
            && let Ok(mut device) = controller.borrow_mut().device(id)
        {
            device.quarantine();
        }
        result
    }
}

fn cbw(tag: u32, lun: u8, cdb: &[u8], length: usize, is_in: bool) -> [u8; 31] {
    let mut bytes = [0; 31];
    bytes[..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
    bytes[4..8].copy_from_slice(&tag.to_le_bytes());
    bytes[8..12].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[12] = if is_in { 0x80 } else { 0 };
    bytes[13] = lun;
    bytes[14] = cdb.len() as u8;
    bytes[15..15 + cdb.len()].copy_from_slice(cdb);
    bytes
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::{rc::Rc, vec};
    use core::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        None,
        ShortCbw,
        ShortData,
        DataStall,
        CswStall,
        CswZero,
        CswZeroThenStall,
        SkippedData,
        WrongTag,
        BadSignature,
        BadResidue,
        Phase,
        Timeout,
        Reset,
        ClearInput,
        ClearOutput,
    }
    #[derive(Clone)]
    struct Unit {
        media: Vec<u8>,
        sense: u32,
        readonly: bool,
        attention: bool,
        huge: bool,
        descriptor_sense: bool,
        /// Spun down until START STOP UNIT starts it.
        stopped: bool,
    }
    struct Command {
        lun: u8,
        cdb: Vec<u8>,
        tag: u32,
        length: usize,
        input: bool,
        payload: Vec<u8>,
        status: u8,
        data_done: bool,
        /// Data bytes moved so far, over one transfer or several.
        moved: usize,
    }
    #[derive(Debug, PartialEq, Eq)]
    enum Order {
        Reset,
        Delay(u64),
        Clear(u8),
        Cbw(u8),
    }
    struct State {
        range: core::ops::Range<u64>,
        max: Result<Vec<u8>, BlockError>,
        units: Vec<Option<Unit>>,
        command: Option<Command>,
        history: Vec<(u8, u32, Vec<u8>)>,
        controls: Vec<[u8; 8]>,
        wrappers: Vec<usize>,
        clears: Vec<u8>,
        fault: Fault,
        override_payload: Vec<(u8, Vec<u8>)>,
        poisoned: bool,
        transfers: usize,
        delays: usize,
        now: u64,
        reset_ready: Option<u64>,
        order: Vec<Order>,
    }
    #[derive(Clone)]
    struct Model(Rc<RefCell<State>>);
    impl Io for Model {
        fn ready(&mut self) -> Result<(), BlockError> {
            if self.0.borrow().poisoned {
                Err(BlockError::Unsupported("model unacknowledged cancellation"))
            } else {
                Ok(())
            }
        }
        fn control(&mut self, request: [u8; 8]) -> Result<Vec<u8>, BlockError> {
            let mut s = self.0.borrow_mut();
            s.controls.push(request);
            match request[1] {
                GET_MAX_LUN => {
                    assert_eq!(request, setup(0xa1, GET_MAX_LUN, 0, 3, 1));
                    s.max.clone()
                }
                RESET => {
                    assert_eq!(request, setup(0x21, RESET, 0, 3, 0));
                    if s.fault == Fault::Reset {
                        Err(BlockError::Timeout)
                    } else {
                        s.command = None;
                        s.reset_ready = Some(s.now + RESET_RECOVERY_US);
                        s.order.push(Order::Reset);
                        Ok(Vec::new())
                    }
                }
                _ => panic!("unexpected control"),
            }
        }
        fn clear(&mut self, endpoint: Endpoint) -> Result<(), BlockError> {
            let mut s = self.0.borrow_mut();
            assert!(
                s.reset_ready.is_none_or(|at| s.now >= at),
                "halt clear before reset settled"
            );
            s.order.push(Order::Clear(endpoint.address));
            s.clears.push(endpoint.address);
            if (s.fault == Fault::ClearInput && endpoint.address == 0x82)
                || (s.fault == Fault::ClearOutput && endpoint.address == 0x02)
            {
                Err(BlockError::Timeout)
            } else {
                Ok(())
            }
        }
        fn delay(&self, micros: u64) {
            assert!(matches!(micros, 125 | 100_000 | RESET_RECOVERY_US));
            let mut s = self.0.borrow_mut();
            s.now += micros;
            s.order.push(Order::Delay(micros));
            if micros == 100_000 {
                s.delays += 1;
            }
        }
        fn now_us(&self) -> u64 {
            self.0.borrow().now
        }
        fn bulk(
            &mut self,
            endpoint: Endpoint,
            address: u64,
            length: usize,
        ) -> Result<usize, BlockError> {
            let mut s = self.0.borrow_mut();
            s.transfers += 1;
            assert!(
                address >= s.range.start
                    && address.checked_add(length as u64).unwrap() <= s.range.end
            );
            // SAFETY: the test's private DMA allocation is live, within range,
            // and only this synchronous model accesses it during a transfer.
            let bytes = unsafe { core::slice::from_raw_parts_mut(address as *mut u8, length) };
            if s.command.is_none() {
                assert!(!endpoint.is_in());
                assert!(matches!(length, 31 | 32));
                if length == 32 {
                    assert_eq!(bytes[31], 0);
                }
                s.wrappers.push(length);
                assert_eq!(
                    u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                    CBW_SIGNATURE
                );
                assert_eq!(bytes[12] & 0x7f, 0);
                assert_eq!(bytes[13] & 0xf0, 0);
                assert!((1..=16).contains(&bytes[14]));
                let lun = bytes[13];
                assert!(
                    s.reset_ready.is_none_or(|at| s.now >= at),
                    "CBW before reset settled"
                );
                s.order.push(Order::Cbw(lun));
                let tag = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let cdb = bytes[15..15 + usize::from(bytes[14])].to_vec();
                let requested = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
                let input = bytes[12] & 0x80 != 0;
                s.history.push((lun, tag, cdb.clone()));
                let mut payload = Vec::new();
                let mut status = 0;
                let unit = s.units.get_mut(usize::from(lun)).and_then(Option::as_mut);
                if let Some(u) = unit {
                    match cdb[0] {
                        0x12 => {
                            payload = vec![0; 36];
                            payload[1] = 0x80;
                            payload[4] = 31;
                            payload[8..16].copy_from_slice(b"STELA   ");
                            payload[16..32].copy_from_slice(b"MULTI LUN MODEL ");
                        }
                        op if u.attention && !matches!(op, 0x12 | 0x03) => {
                            u.attention = false;
                            u.sense = 0x062900;
                            status = 1;
                        }
                        0x00 if u.stopped => {
                            // NOT READY: initializing command required.
                            u.sense = 0x020402;
                            status = 1;
                        }
                        0x00 => {}
                        0x1b => u.stopped = cdb[4] & 1 == 0,
                        0x03 => {
                            payload = vec![0; 18];
                            if u.descriptor_sense {
                                payload[0] = 0x72;
                                payload[1] = (u.sense >> 16) as u8;
                                payload[2] = (u.sense >> 8) as u8;
                                payload[3] = u.sense as u8;
                            } else {
                                payload[0] = 0x70;
                                payload[2] = (u.sense >> 16) as u8;
                                payload[7] = 10;
                                payload[12] = (u.sense >> 8) as u8;
                                payload[13] = u.sense as u8;
                            }
                        }
                        0x25 => {
                            payload = vec![0; 8];
                            let last = if u.huge {
                                u32::MAX
                            } else {
                                (u.media.len() / 512 - 1) as u32
                            };
                            payload[..4].copy_from_slice(&last.to_be_bytes());
                            payload[4..8].copy_from_slice(&512u32.to_be_bytes());
                        }
                        0x9e => {
                            payload = vec![0; 32];
                            payload[..8].copy_from_slice(&((1u64 << 32) + 7).to_be_bytes());
                            payload[8..12].copy_from_slice(&4096u32.to_be_bytes());
                        }
                        0x1a => {
                            payload = vec![3, 0, if u.readonly { 0x80 } else { 0 }, 0];
                        }
                        0x28 | 0x88 => {
                            let lba = if cdb[0] == 0x28 {
                                u64::from(u32::from_be_bytes(cdb[2..6].try_into().unwrap()))
                            } else {
                                u64::from_be_bytes(cdb[2..10].try_into().unwrap())
                            };
                            let at = lba as usize * 512;
                            payload = u.media[at..at + requested].to_vec();
                        }
                        0x2a | 0x8a | 0x35 => {}
                        _ => {
                            u.sense = 0x052000;
                            status = 1;
                        }
                    }
                } else {
                    status = 1;
                    if cdb[0] == 0x12 {
                        // Empty reader slots identify normally, but TUR fails.
                        payload = vec![0; 36];
                        payload[1] = 0x80;
                        payload[4] = 31;
                        status = 0;
                    } else if cdb[0] == 3 {
                        payload = vec![0; 18];
                        payload[0] = 0x70;
                        payload[2] = 2;
                        payload[7] = 10;
                        payload[12] = 0x3a;
                        status = 0;
                    }
                }
                if let Some((_, bytes)) = s.override_payload.iter().find(|(op, _)| *op == cdb[0]) {
                    payload = bytes.clone();
                }
                s.command = Some(Command {
                    lun,
                    cdb,
                    tag,
                    length: requested,
                    input,
                    payload,
                    status,
                    data_done: requested == 0,
                    moved: 0,
                });
                if s.fault == Fault::ShortCbw {
                    return Ok(30);
                }
                return Ok(length);
            }
            if s.fault == Fault::Timeout {
                s.poisoned = true;
                return Err(BlockError::Timeout);
            }
            let mut command = s.command.take().unwrap();
            if !command.data_done {
                assert_eq!(command.input, endpoint.is_in());
                // A data stage moves in transfers of whole packets but its
                // last, up to the command's length.
                let remaining = command.length - command.moved;
                assert!(length == remaining || length < remaining && length.is_multiple_of(512));
                command.data_done = true;
                if s.fault == Fault::SkippedData {
                    assert!(command.input && length > 13);
                    bytes[..13].fill(0);
                    bytes[..4].copy_from_slice(&CSW_SIGNATURE.to_le_bytes());
                    bytes[4..8].copy_from_slice(&command.tag.to_le_bytes());
                    bytes[8..12].copy_from_slice(&(command.length as u32).to_le_bytes());
                    s.fault = Fault::None;
                    return Ok(13);
                }
                if s.fault == Fault::DataStall {
                    s.command = Some(command);
                    return Err(BlockError::Device {
                        status: super::super::STALL,
                    });
                }
                let count = if s.fault == Fault::ShortData {
                    length - 1
                } else if command.input {
                    length.min(command.payload.len().saturating_sub(command.moved))
                } else {
                    length
                };
                let moved = command.moved;
                if command.input {
                    bytes[..count].copy_from_slice(&command.payload[moved..moved + count]);
                } else if command.status == 0 && matches!(command.cdb[0], 0x2a | 0x8a) {
                    let at = moved
                        + if command.cdb[0] == 0x2a {
                            u32::from_be_bytes(command.cdb[2..6].try_into().unwrap()) as usize * 512
                        } else {
                            u64::from_be_bytes(command.cdb[2..10].try_into().unwrap()) as usize
                                * 512
                        };
                    s.units[usize::from(command.lun)].as_mut().unwrap().media[at..at + count]
                        .copy_from_slice(&bytes[..count]);
                }
                command.moved += count;
                // A short transfer ends the stage early.
                command.data_done = command.moved == command.length || count < length;
                s.command = Some(command);
                return Ok(count);
            }
            assert!(endpoint.is_in());
            assert_eq!(length, 13);
            if matches!(
                s.fault,
                Fault::CswStall | Fault::CswZero | Fault::CswZeroThenStall
            ) {
                let fault = s.fault;
                s.fault = if fault == Fault::CswZeroThenStall {
                    Fault::CswStall
                } else {
                    Fault::None
                };
                s.command = Some(command);
                return if matches!(fault, Fault::CswZero | Fault::CswZeroThenStall) {
                    Ok(0)
                } else {
                    Err(BlockError::Device {
                        status: super::super::STALL,
                    })
                };
            }
            bytes.fill(0);
            bytes[..4].copy_from_slice(
                &if s.fault == Fault::BadSignature {
                    0
                } else {
                    CSW_SIGNATURE
                }
                .to_le_bytes(),
            );
            bytes[4..8].copy_from_slice(
                &(command.tag + u32::from(s.fault == Fault::WrongTag)).to_le_bytes(),
            );
            bytes[8..12].copy_from_slice(
                &if s.fault == Fault::BadResidue {
                    command.length as u32 + 1
                } else {
                    0
                }
                .to_le_bytes(),
            );
            bytes[12] = if s.fault == Fault::Phase
                || matches!(
                    s.fault,
                    Fault::Reset | Fault::ClearInput | Fault::ClearOutput
                ) {
                2
            } else {
                command.status
            };
            Ok(13)
        }
    }
    fn endpoints() -> [Endpoint; 2] {
        [0x82, 0x02].map(|address| Endpoint {
            address,
            attributes: 2,
            max_packet: 64,
            interval: 0,
            companion: None,
        })
    }
    fn unit(byte: u8) -> Option<Unit> {
        Some(Unit {
            media: vec![byte; 8192],
            sense: 0,
            readonly: false,
            attention: false,
            huge: false,
            descriptor_sense: false,
            stopped: false,
        })
    }
    fn model(start: u64, end: u64, units: Vec<Option<Unit>>) -> Model {
        Model(Rc::new(RefCell::new(State {
            range: start..end,
            max: Ok(vec![(units.len() - 1) as u8]),
            units,
            command: None,
            history: Vec::new(),
            controls: Vec::new(),
            wrappers: Vec::new(),
            clears: Vec::new(),
            fault: Fault::None,
            override_payload: Vec::new(),
            poisoned: false,
            transfers: 0,
            delays: 0,
            now: 0,
            reset_ready: None,
            order: Vec::new(),
        })))
    }
    fn dma(backing: &mut [u64]) -> RegionAllocator {
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: each caller keeps the exclusive backing alive until all Bot
        // owners and the synchronous private model are dropped.
        unsafe { RegionAllocator::new(start..start + core::mem::size_of_val(backing) as u64) }
    }
    struct NativeFixture {
        storage: super::super::UsbStorage,
        disk: super::super::UsbDisk,
        hardware: Rc<RefCell<crate::usb::xhci::model::ResetHardware>>,
        dma: RegionAllocator,
    }
    fn native_fixture(
        memory: &mut [u64],
        speed: u8,
        context: usize,
        write_cache: bool,
    ) -> NativeFixture {
        let (controller, device, hardware, mut dma) =
            crate::usb::xhci::model::reset_bot_fixture(memory, speed, context, 3, write_cache);
        let identity = &device.descriptor[8..12];
        assert_eq!(
            identity,
            if write_cache {
                &[0xc2, 0x0b, 0x00, 0x23]
            } else {
                &[0xf4, 0x46, 0x03, 0x00]
            },
        );
        assert_eq!(
            quirks::Flags::from_device(&device).unwrap().write_cache(),
            write_cache
        );
        let interface = crate::usb::xhci::interfaces(&device.configuration).remove(0);
        let endpoints = [true, false].map(|input| {
            *interface
                .endpoints
                .iter()
                .find(|endpoint| endpoint.is_in() == input)
                .unwrap()
        });
        controller
            .borrow_mut()
            .device(device.id)
            .unwrap()
            .configure(&endpoints, None, &mut dma)
            .unwrap();
        let mut failures = Vec::new();
        let (storage, mut disks) = super::super::discover_retained(
            controller,
            &device,
            &interface,
            endpoints,
            &mut dma,
            &mut failures,
        )
        .unwrap();
        assert!(failures.is_empty());
        assert_eq!(disks.len(), 1);
        let super::super::UsbTransport::Bot(disk) = &disks[0].disk else {
            panic!("native BOT fixture published another transport")
        };
        assert_eq!(disk.identity.features.write_cache, write_cache);
        NativeFixture {
            storage,
            disk: disks.remove(0),
            hardware,
            dma,
        }
    }
    #[test]
    fn native_root_bot_reuses_original_transport_buffers_across_96_resets_and_real_io() {
        use crate::block::BlockDevice;
        use crate::usb::xhci::{HIGH_SPEED, SUPER_SPEED};
        // The unquirked profile intentionally has no flush command. The pinned
        // WRITE_CACHE identity requires a real acknowledged 0x35 every epoch.
        for write_cache in [false, true] {
            for speed in [HIGH_SPEED, SUPER_SPEED] {
                for context in [32, 64] {
                    let mut memory = vec![0u64; 512 * 1024];
                    let NativeFixture {
                        mut storage,
                        mut disk,
                        hardware,
                        mut dma,
                    } = native_fixture(&mut memory, speed, context, write_cache);
                    let super::super::media::TransportOwner::Bot(owner) = &storage.owner else {
                        panic!("native BOT fixture published another transport")
                    };
                    let original = {
                        let owner = owner.borrow();
                        (
                            owner.transport.buffer.physical(),
                            owner.transport.buffer.len(),
                            owner.transport.wrapper.physical(),
                            owner.transport.wrapper.len(),
                        )
                    };
                    assert_eq!(original.1, MAX_TD);
                    assert_eq!(original.3, 64);
                    let remaining = dma.remaining();
                    let mut retired = Vec::new();
                    for epoch in 1..=96 {
                        let old_owner = match &storage.owner {
                            super::super::media::TransportOwner::Bot(owner) => owner.clone(),
                            _ => panic!("native BOT recovery changed transport"),
                        };
                        let mut failures = Vec::new();
                        let mut fresh = storage.reset_and_rebind(&mut dma, &mut failures).unwrap();
                        assert!(failures.is_empty());
                        assert_eq!(fresh.len(), 1);
                        assert_eq!(dma.remaining(), remaining, "reset allocated new DMA");
                        assert_eq!(hardware.borrow().resets, epoch);
                        {
                            let old = old_owner.borrow();
                            assert!(old.transport.poisoned());
                            assert!(!old.transport.buffer.present());
                            assert!(!old.transport.wrapper.present());
                        }
                        let super::super::media::TransportOwner::Bot(owner) = &storage.owner else {
                            panic!("native BOT recovery changed transport")
                        };
                        {
                            let owner = owner.borrow();
                            assert_eq!(
                                (
                                    owner.transport.buffer.physical(),
                                    owner.transport.buffer.len(),
                                    owner.transport.wrapper.physical(),
                                    owner.transport.wrapper.len(),
                                ),
                                original,
                            );
                        }
                        let current_bytes = {
                            let owner = owner.borrow();
                            (
                                owner.transport.buffer.bytes().to_vec(),
                                owner.transport.wrapper.bytes().to_vec(),
                            )
                        };
                        retired.push((disk, old_owner));
                        let accesses = hardware.borrow().accesses;
                        for (old_disk, old_owner) in &mut retired {
                            let mut poison = [0xb7; 512];
                            assert!(old_disk.read(7, &mut poison).is_err());
                            assert_eq!(poison, [0xb7; 512]);
                            assert!(old_disk.write(7, &[0xee; 512]).is_err());
                            assert!(old_disk.flush_cache().is_err());
                            let mut old = old_owner.borrow_mut();
                            assert!(old.transport.io.ready().is_err());
                            assert!(
                                old.transport
                                    .command(0, &scsi::inquiry(), Data::In(36))
                                    .is_err()
                            );
                            assert!(old.transport.reset_and_rebind(&mut dma).is_err());
                        }
                        assert_eq!(hardware.borrow().accesses, accesses);
                        assert_eq!(dma.remaining(), remaining);
                        {
                            let owner = owner.borrow();
                            assert_eq!(owner.transport.buffer.bytes(), current_bytes.0);
                            assert_eq!(owner.transport.wrapper.bytes(), current_bytes.1);
                        }
                        disk = fresh.remove(0);
                        let byte = epoch as u8;
                        disk.write(7, &[byte; 512]).unwrap();
                        disk.flush().unwrap();
                        let mut actual = [0; 512];
                        disk.read(7, &mut actual).unwrap();
                        assert_eq!(actual, [byte; 512]);
                        for opcode in [scsi::READ_10, scsi::WRITE_10] {
                            assert!(
                                hardware.borrow().scsi.contains(&(epoch, opcode)),
                                "missing CDB {opcode:#x}: cache={write_cache}, speed={speed}, context={context}, epoch={epoch}",
                            );
                        }
                        assert_eq!(
                            hardware
                                .borrow()
                                .scsi
                                .iter()
                                .filter(|&&(seen_epoch, opcode)| {
                                    seen_epoch == epoch && opcode == scsi::SYNCHRONIZE_CACHE_10
                                })
                                .count(),
                            usize::from(write_cache),
                            "flush CDB: cache={write_cache}, speed={speed}, context={context}, epoch={epoch}",
                        );
                        assert_eq!(dma.remaining(), remaining);
                    }
                    assert_eq!(retired.len(), 96);
                }
            }
        }
    }
    #[test]
    fn native_bot_failed_reset_keeps_both_original_buffer_owners_and_bytes() {
        use crate::block::BlockDevice;
        use crate::usb::xhci::{HIGH_SPEED, SUPER_SPEED, model::ResetFault};
        for speed in [HIGH_SPEED, SUPER_SPEED] {
            for context in [32, 64] {
                for fault in [
                    ResetFault::Stop(2),
                    ResetFault::Disable,
                    ResetFault::NoResetChange,
                    ResetFault::Identity,
                    ResetFault::ConfigureAfterReset,
                    ResetFault::FatalAfterReset,
                    ResetFault::ChangeAfterReset,
                ] {
                    let mut memory = vec![0u64; 512 * 1024];
                    let NativeFixture {
                        mut storage,
                        mut disk,
                        hardware,
                        mut dma,
                    } = native_fixture(&mut memory, speed, context, false);
                    let owner = match &storage.owner {
                        super::super::media::TransportOwner::Bot(owner) => owner.clone(),
                        _ => panic!("native BOT fixture published another transport"),
                    };
                    let before = {
                        let mut owner = owner.borrow_mut();
                        owner.transport.buffer.bytes_mut().fill(0xa5);
                        owner.transport.wrapper.bytes_mut().fill(0x5a);
                        (
                            owner.transport.buffer.physical(),
                            owner.transport.buffer.bytes().to_vec(),
                            owner.transport.wrapper.physical(),
                            owner.transport.wrapper.bytes().to_vec(),
                        )
                    };
                    hardware.borrow_mut().fault = fault;
                    let mut failures = Vec::new();
                    assert!(storage.reset_and_rebind(&mut dma, &mut failures).is_err());
                    assert!(!failures.is_empty());
                    {
                        let owner = owner.borrow();
                        assert!(owner.transport.poisoned());
                        assert!(owner.transport.buffer.present());
                        assert!(owner.transport.wrapper.present());
                        assert_eq!(owner.transport.buffer.physical(), before.0);
                        assert_eq!(owner.transport.buffer.bytes(), before.1);
                        assert_eq!(owner.transport.wrapper.physical(), before.2);
                        assert_eq!(owner.transport.wrapper.bytes(), before.3);
                    }
                    let accesses = hardware.borrow().accesses;
                    let mut poison = [0xc3; 512];
                    assert!(disk.read(0, &mut poison).is_err());
                    assert_eq!(poison, [0xc3; 512]);
                    assert!(disk.write(0, &[0x11; 512]).is_err());
                    assert!(disk.flush_cache().is_err());
                    assert!(
                        owner
                            .borrow_mut()
                            .transport
                            .command(0, &scsi::inquiry(), Data::In(36))
                            .is_err()
                    );
                    assert_eq!(hardware.borrow().accesses, accesses);
                    let owner = owner.borrow();
                    assert_eq!(owner.transport.buffer.bytes(), before.1);
                    assert_eq!(owner.transport.wrapper.bytes(), before.3);
                }
            }
        }
    }
    #[test]
    fn all_sixteen_luns_have_independent_media_sense_and_shared_tags() {
        let mut memory = vec![0u64; 32 * 1024];
        let mut dma = dma(&mut memory);
        let start = memory.as_mut_ptr() as u64;
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            (0..16).map(unit).collect(),
        );
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        for lun in 0..=bot.max_lun() {
            let identity = super::super::probe(&mut bot, lun, "slot", "serial").unwrap();
            assert_eq!(identity.blocks, 16);
            assert_eq!(
                identity.serial,
                if lun == 0 {
                    "serial".into()
                } else {
                    alloc::format!("serial:lun{lun}")
                }
            );
            let read = bot
                .command(lun, &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0], Data::In(512))
                .unwrap();
            assert_eq!(read, vec![lun; 512]);
            let bytes = vec![lun.wrapping_add(40); 512];
            bot.command(lun, &[0x2a, 0, 0, 0, 0, 1, 0, 0, 1, 0], Data::Out(&bytes))
                .unwrap();
            assert_eq!(
                &state.borrow().units[usize::from(lun)]
                    .as_ref()
                    .unwrap()
                    .media[512..1024],
                &bytes
            );
            bot.command(lun, &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None)
                .unwrap();
        }
        let state = state.borrow();
        assert!(state.history.windows(2).all(|w| w[1].1 == w[0].1 + 1));
        // Probe reads block zero before MODE SENSE. Check every actual CDB,
        // rather than only a total that could hide a missing read or a command
        // sent to the wrong LUN after the shared transport's tags advance.
        let expected: [&[u8]; 8] = [
            &[0x12, 0, 0, 0, 36, 0],
            &[0x00, 0, 0, 0, 0, 0],
            &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0],
            &[0x1a, 0, 0x3f, 0, 192, 0],
            &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0],
            &[0x2a, 0, 0, 0, 0, 1, 0, 0, 1, 0],
            &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        assert_eq!(state.history.len(), 16 * expected.len());
        for (lun, commands) in state.history.chunks_exact(expected.len()).enumerate() {
            for ((actual_lun, _, cdb), expected_cdb) in commands.iter().zip(expected) {
                assert_eq!(usize::from(*actual_lun), lun);
                assert_eq!(cdb.as_slice(), expected_cdb);
            }
        }
    }
    #[test]
    fn empty_slot_does_not_hide_later_ready_media_and_auto_sense_keeps_lun() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![None, unit(1), None, unit(3)],
        );
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        for lun in 0..4 {
            let result = super::super::probe(&mut bot, lun, "slot", "serial");
            assert_eq!(result.is_ok(), lun == 1 || lun == 3);
            assert!(!bot.poisoned());
        }
        let state = state.borrow();
        for w in state.history.windows(2) {
            if w[1].2[0] == 3 {
                assert_eq!(w[0].0, w[1].0);
            }
        }
    }
    #[test]
    fn attention_descriptor_sense_capacity16_and_write_protection_are_real() {
        for descriptor in [false, true] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let mut u = unit(7).unwrap();
            u.attention = true;
            u.descriptor_sense = descriptor;
            u.huge = true;
            u.media.resize(4096, 7);
            u.readonly = true;
            let io = model(start, start + memory.len() as u64 * 8, vec![Some(u)]);
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            let identity = super::super::probe(&mut bot, 0, "slot", "serial").unwrap();
            assert_eq!(identity.blocks, (1 << 32) + 8);
            assert_eq!(identity.block_size, 4096);
            assert!(identity.read_only);
            assert_eq!(state.borrow().delays, 1);
        }
    }
    #[test]
    fn a_stopped_unit_is_started_once_and_then_identified() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let mut stopped = unit(0x11).unwrap();
        stopped.stopped = true;
        let io = model(start, start + memory.len() as u64 * 8, vec![Some(stopped)]);
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        super::super::probe(&mut bot, 0, "slot", "serial").unwrap();
        assert!(!state.borrow().units[0].as_ref().unwrap().stopped);
    }

    #[test]
    fn get_max_lun_takes_one_bounded_byte_and_otherwise_one_unit() {
        for (response, max_lun) in [
            (Ok(vec![0]), 0),
            (Ok(vec![15]), 15),
            (Ok(vec![]), 0),
            (Ok(vec![16]), 0),
            (Ok(vec![0, 1]), 0),
            (
                Err(BlockError::Device {
                    status: super::super::STALL,
                }),
                0,
            ),
            (Err(BlockError::Timeout), 0),
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
            io.0.borrow_mut().max = response;
            assert_eq!(
                Bot::new(io, 3, endpoints(), &mut dma).unwrap().max_lun(),
                max_lun
            );
        }
    }
    #[test]
    fn short_cbw_phase_csw_and_residue_errors_require_interface_reset() {
        for fault in [
            Fault::ShortCbw,
            Fault::WrongTag,
            Fault::BadSignature,
            Fault::BadResidue,
            Fault::Phase,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            state.borrow_mut().fault = fault;
            assert!(bot.command(0, &[0; 6], Data::None).is_err());
            state.borrow_mut().now += RESET_RECOVERY_US;
            assert!(!bot.busy());
            let state = state.borrow();
            assert_eq!(state.controls.last().unwrap()[1], RESET);
            assert_eq!(state.clears, vec![0x82, 0x02]);
            assert!(!bot.poisoned());
        }
    }
    #[test]
    fn data_stall_reads_csw_and_csw_stall_or_zero_gets_one_retry() {
        for fault in [Fault::DataStall, Fault::CswStall, Fault::CswZero] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            state.borrow_mut().fault = fault;
            let result = bot
                .command(0, &[0x12, 0, 0, 0, 36, 0], Data::In(36))
                .unwrap();
            assert_eq!(result.len(), if fault == Fault::DataStall { 0 } else { 36 });
            assert!(!bot.poisoned());
        }
    }
    #[test]
    fn short_out_cannot_be_reported_as_successful_write() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        state.borrow_mut().fault = Fault::ShortData;
        assert_eq!(
            bot.command(
                0,
                &[0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0],
                Data::Out(&vec![2; 512])
            ),
            Err(SHORT_WRITE)
        );
    }
    #[test]
    fn failed_reset_clear_or_cancellation_quarantines_every_lun_without_dma_rewrite() {
        for fault in [
            Fault::Reset,
            Fault::ClearInput,
            Fault::ClearOutput,
            Fault::Timeout,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(
                start,
                start + memory.len() as u64 * 8,
                vec![unit(0), unit(1)],
            );
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            state.borrow_mut().fault = fault;
            assert!(
                bot.command(0, &[0x12, 0, 0, 0, 36, 0], Data::In(36))
                    .is_err()
            );
            // A failed halt clear shows once the reset has settled.
            state.borrow_mut().now += RESET_RECOVERY_US;
            assert!(!bot.busy());
            assert!(bot.poisoned());
            let wrapper = bot.wrapper.bytes().to_vec();
            let buffer = bot.buffer.bytes().to_vec();
            let transfers = state.borrow().transfers;
            assert!(
                bot.command(
                    1,
                    &[0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0],
                    Data::Out(&vec![0xa5; 512])
                )
                .is_err()
            );
            assert_eq!(state.borrow().transfers, transfers);
            assert_eq!(bot.wrapper.bytes(), wrapper);
            assert_eq!(bot.buffer.bytes(), buffer);
        }
    }
    #[test]
    fn invalid_lun_cdb_and_lengths_are_rejected_without_touching_dma() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(start, start + memory.len() as u64 * 8, vec![unit(0)]);
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        for (lun, cdb, length) in [
            (1, vec![0; 6], 0),
            (0, vec![], 0),
            (0, vec![0; 17], 0),
            (0, vec![0; 6], bot.max_transfer_bytes() + 1),
        ] {
            assert!(bot.command(lun, &cdb, Data::In(length)).is_err());
        }
        assert_eq!(state.borrow().transfers, 0);
        assert_eq!(bot.tag, 0);
    }
    #[test]
    fn native_poison_preflight_preserves_all_buffers() {
        for (dci, halted) in [1, 4, 5]
            .into_iter()
            .flat_map(|dci| [false, true].map(move |halted| (dci, halted)))
        {
            let mut memory = vec![0u64; 64 * 1024];
            let mut dma = dma(&mut memory);
            let mut wrapper = dma.allocate(64, 64).unwrap();
            wrapper.bytes_mut().fill(0xa5);
            let mut buffer = dma.allocate(512, 512).unwrap();
            buffer.bytes_mut().fill(0x5a);
            let controller = super::super::super::xhci::model::controller_with_unresolved_td(
                &mut dma,
                wrapper.physical(),
                wrapper.len(),
                dci,
                halted,
            );
            let id = controller.borrow().test_device_id(1).unwrap();
            let mut bot = Bot {
                io: Native {
                    controller,
                    id,
                    endpoints: endpoints(),
                },
                interface: 3,
                endpoints: endpoints(),
                buffer: TransportBuffer::new(buffer),
                wrapper: TransportBuffer::new(wrapper),
                tag: 7,
                max_lun: 1,
                poisoned: false,
                flags: quirks::Flags::default(),
                initial_read: false,
                attachment: None,
                reset_generation: 0,
                settling: None,
                begun: None,
            };
            assert!(
                bot.command(1, &[0x2a, 0, 0, 0, 0, 0, 0, 0, 1, 0], Data::Out(&[1, 2, 3]))
                    .is_err()
            );
            assert_eq!(bot.tag, 7);
            assert!(bot.wrapper.bytes().iter().all(|b| *b == 0xa5));
            assert!(bot.buffer.bytes().iter().all(|b| *b == 0x5a));
        }
    }
    #[test]
    fn retained_reader_discovers_inserted_media_and_never_revives_removed_aliases() {
        use super::super::media::{Owner, scan_bot};
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let io = model(start, start + memory.len() as u64 * 8, vec![None, None]);
        let state = io.0.clone();
        let mut dma = dma(&mut memory);
        let owner = Rc::new(RefCell::new(Owner::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
            "reader".into(),
            "serial".into(),
        )));
        let mut failures = Vec::new();
        assert!(scan_bot(owner.clone(), &mut failures).unwrap().is_empty());
        assert!(
            state
                .borrow()
                .history
                .iter()
                .all(|(_, _, cdb)| !matches!(cdb[0], 0x25 | 0x1a))
        );
        state.borrow_mut().units[0] = unit(0x31);
        let mut disks = scan_bot(owner.clone(), &mut failures).unwrap();
        assert_eq!(disks.len(), 1);
        let mut same = scan_bot(owner.clone(), &mut failures).unwrap();
        assert!(Rc::ptr_eq(&disks[0].media, &same[0].media));
        disks[0].write(0, &[0x72; 512]).unwrap();
        disks[0].flush().unwrap();
        let mut data = [0; 512];
        same[0].read(0, &mut data).unwrap();
        assert_eq!(data, [0x72; 512]);
        // A real failed data command returns UA. The target does not commit
        // its payload; the caller must never silently retry it on new media.
        state.borrow_mut().units[0].as_mut().unwrap().attention = true;
        let before = state.borrow().history.len();
        assert_eq!(
            disks[0].write(0, &[0xa4; 512]),
            Err(BlockError::Sense(Sense {
                key: 0x06,
                asc: 0x29,
                ascq: 0x00
            }))
        );
        assert_eq!(
            state.borrow().history[before..]
                .iter()
                .filter(|(_, _, c)| c[0] == 0x2a)
                .count(),
            1
        );
        let before = state.borrow().transfers;
        assert!(same[0].read(0, &mut data).is_err());
        assert!(same[0].read(0, &mut []).is_err());
        assert!(same[0].write(0, &[0; 512]).is_err());
        assert!(same[0].flush_cache().is_err());
        assert!(same[0].command(&[0; 6], super::super::Data::None).is_err());
        assert_eq!(state.borrow().transfers, before);
        let mut current = scan_bot(owner.clone(), &mut failures).unwrap();
        assert!(!Rc::ptr_eq(&current[0].media, &disks[0].media));
        current[0].read(0, &mut data).unwrap();
        assert_eq!(data, [0x72; 512], "failed write was replayed");
        state.borrow_mut().units[0] = None;
        data.fill(0x5a);
        assert_eq!(
            current[0].read(0, &mut data),
            Err(BlockError::Sense(Sense {
                key: 0x02,
                asc: 0x3a,
                ascq: 0x00
            }))
        );
        assert_eq!(data, [0x5a; 512]);
        assert!(scan_bot(owner.clone(), &mut failures).unwrap().is_empty());
        state.borrow_mut().units[0] = unit(0x99);
        let mut inserted = scan_bot(owner, &mut failures).unwrap();
        inserted[0].read(0, &mut data).unwrap();
        assert_eq!(data, [0x99; 512]);
        let before = state.borrow().transfers;
        assert!(current[0].read(0, &mut data).is_err());
        assert!(disks[0].flush_cache().is_err());
        assert_eq!(state.borrow().transfers, before);
        assert_eq!(
            state
                .borrow()
                .controls
                .iter()
                .filter(|c| c[1] == GET_MAX_LUN)
                .count(),
            1
        );
    }

    #[test]
    fn rescan_revalidates_geometry_protection_and_quarantines_all_on_transport_poison() {
        use super::super::media::{Owner, scan_bot};
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(0x11), unit(0x22)],
        );
        let state = io.0.clone();
        let mut dma = dma(&mut memory);
        let owner = Rc::new(RefCell::new(Owner::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
            "reader".into(),
            "serial".into(),
        )));
        let mut failures = Vec::new();
        let mut old = scan_bot(owner.clone(), &mut failures).unwrap();
        state.borrow_mut().units[0]
            .as_mut()
            .unwrap()
            .media
            .resize(4096, 0x33);
        let mut fresh = scan_bot(owner.clone(), &mut failures).unwrap();
        assert_eq!(fresh[0].identity().blocks, 8);
        assert!(old[0].flush_cache().is_err());
        old[1].read(0, &mut [0; 512]).unwrap();
        state.borrow_mut().units[0].as_mut().unwrap().readonly = true;
        let protected = scan_bot(owner.clone(), &mut failures).unwrap();
        assert!(protected[0].identity().read_only);
        assert!(fresh[0].flush_cache().is_err());
        // Failed revalidation cannot preserve an older apparently usable view.
        state.borrow_mut().override_payload.push((0x25, vec![0; 7]));
        assert!(scan_bot(owner.clone(), &mut failures).unwrap().is_empty());
        assert!(old[1].flush_cache().is_err());
        state.borrow_mut().override_payload.clear();
        let mut ready = scan_bot(owner.clone(), &mut failures).unwrap();
        state.borrow_mut().fault = Fault::Timeout;
        assert!(ready[0].read(0, &mut [0; 512]).is_err());
        let before = state.borrow().transfers;
        assert!(ready[1].flush_cache().is_err());
        assert_eq!(state.borrow().transfers, before);
        assert!(scan_bot(owner, &mut failures).is_err());
    }

    #[test]
    fn real_block_api_chunks_units_checks_bounds_and_never_copies_short_reads() {
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let mut first = unit(0x22).unwrap();
        first.media = vec![0x22; MAX_TD * 3];
        let mut second = unit(0x44).unwrap();
        second.readonly = true;
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![Some(first), Some(second)],
        );
        let state = io.0.clone();
        let bot = Rc::new(RefCell::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
        ));
        let mut disks = Vec::new();
        for lun in 0..2 {
            let identity =
                super::super::probe(&mut *bot.borrow_mut(), lun, "slot", "serial").unwrap();
            disks.push(super::super::Disk {
                bot: bot.clone(),
                lun,
                identity: crate::block::Identity {
                    features: crate::block::Features {
                        write_cache: true,
                        ..identity.features
                    },
                    ..identity
                },
                media: Rc::new(core::cell::Cell::new(true)),
                running: None,
                next_tag: 0,
            });
        }
        let mut bytes = vec![0; MAX_TD * 2 + 512];
        disks[0].read(0, &mut bytes).unwrap();
        assert!(bytes.iter().all(|b| *b == 0x22));
        disks[0].write(1, &vec![0x66; MAX_TD + 512]).unwrap();
        disks[0].flush().unwrap();
        let before = state.borrow().transfers;
        assert_eq!(disks[1].write(0, &[0; 512]), Err(BlockError::ReadOnly));
        assert!(disks[0].read(u64::MAX, &mut [0; 512]).is_err());
        assert!(disks[0].read(0, &mut [0; 511]).is_err());
        assert_eq!(state.borrow().transfers, before);
        state.borrow_mut().fault = Fault::ShortData;
        let mut untouched = [0xa5; 512];
        assert!(disks[0].read(0, &mut untouched).is_err());
        assert_eq!(untouched, [0xa5; 512]);
        assert_eq!(disks[0].cdb(false, false, u32::MAX as u64, 1)[0], 0x28);
        assert_eq!(disks[0].cdb(false, false, u32::MAX as u64, 2)[0], 0x88);
        assert_eq!(disks[0].cdb(true, false, 1u64 << 32, 1)[0], 0x8a);
    }

    #[test]
    #[ignore = "requires pinned unchanged Linux CBW builder trace"]
    fn unchanged_linux_cbw_builder_matches_all_luns_and_transfer_profiles() {
        extern crate std;
        let path = std::env::var("STELA_USB_BOT_CBW_ORACLE").expect("oracle trace path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(&bytes[..8], b"BOTCBW01");
        let records = &bytes[8..];
        assert_eq!(records.len() % 58, 0);
        assert_eq!(records.len() / 58, 6144);
        for record in records.as_chunks::<58>().0 {
            let tag = u32::from_le_bytes(record[..4].try_into().unwrap());
            let lun = record[4];
            let n = usize::from(record[5]);
            let input = record[6] != 0;
            let length = u32::from_le_bytes(record[7..11].try_into().unwrap()) as usize;
            assert_eq!(
                cbw(tag, lun, &record[11..11 + n], length, input).as_slice(),
                &record[27..58]
            );
        }
    }
    #[test]
    fn discovery_reports_empty_slots_and_publishes_only_actual_ready_units() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![None, unit(1), None, unit(3)],
        );
        let bot = Rc::new(RefCell::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
        ));
        let mut failures = Vec::new();
        let disks =
            super::super::discover_units(bot, "reader interface 3", "reader-serial", &mut failures)
                .unwrap();
        assert_eq!(disks.iter().map(|d| d.lun).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(
            failures,
            vec![
                (
                    "reader interface 3 LUN 0".into(),
                    BlockError::Sense(Sense {
                        key: 0x02,
                        asc: 0x3a,
                        ascq: 0x00
                    })
                ),
                (
                    "reader interface 3 LUN 2".into(),
                    BlockError::Sense(Sense {
                        key: 0x02,
                        asc: 0x3a,
                        ascq: 0x00
                    })
                )
            ]
        );
    }
    #[test]
    fn invalid_identification_capacity_and_mode_never_publish_a_block_device() {
        let mut short_capacity = vec![0; 7];
        short_capacity[0] = 1;
        let mut overflow = vec![0; 32];
        overflow[..8].fill(255);
        overflow[8..12].copy_from_slice(&512u32.to_be_bytes());
        let mut bad_block = vec![0; 8];
        bad_block[4..8].copy_from_slice(&513u32.to_be_bytes());
        for (opcode, payload) in [
            (0x12, vec![0; 35]),
            (0x12, vec![0x20; 36]),
            (0x25, short_capacity),
            (0x25, bad_block),
            (0x9e, overflow),
            (0x1a, vec![0; 4]),
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let mut u = unit(0).unwrap();
            u.huge = opcode == 0x9e;
            let io = model(start, start + memory.len() as u64 * 8, vec![Some(u)]);
            io.0.borrow_mut().override_payload.push((opcode, payload));
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            assert!(super::super::probe(&mut bot, 0, "slot", "serial").is_err());
        }
    }
    #[test]
    fn malformed_sense_never_fabricates_a_ready_unit() {
        for bytes in [
            vec![],
            vec![0x70; 13],
            vec![0x72; 7],
            vec![0x71; 8],
            vec![0x75; 18],
        ] {
            assert_eq!(Sense::parse(&bytes), None);
        }
        let mut fixed = vec![0; 18];
        fixed[0] = 0x71;
        fixed[2] = 6;
        fixed[7] = 5;
        assert_eq!(Sense::parse(&fixed), None);
        fixed[7] = 6;
        fixed[12] = 0x29;
        assert_eq!(
            Sense::parse(&fixed),
            Some(Sense {
                key: Sense::UNIT_ATTENTION,
                asc: Sense::RESET_OCCURRED,
                ascq: 0
            })
        );
    }
    #[test]
    fn late_discovery_transport_poison_discards_already_probed_units() {
        struct FailSecond(Model);
        impl Io for FailSecond {
            fn ready(&mut self) -> Result<(), BlockError> {
                self.0.ready()
            }
            fn control(&mut self, r: [u8; 8]) -> Result<Vec<u8>, BlockError> {
                self.0.control(r)
            }
            fn clear(&mut self, e: Endpoint) -> Result<(), BlockError> {
                self.0.clear(e)
            }
            fn delay(&self, m: u64) {
                self.0.delay(m);
            }
            fn now_us(&self) -> u64 {
                self.0.now_us()
            }
            fn bulk(&mut self, e: Endpoint, p: u64, n: usize) -> Result<usize, BlockError> {
                if !e.is_in() && n == 31 {
                    let range = self.0.0.borrow().range.clone();
                    assert!(p >= range.start && p + 31 <= range.end);
                    // SAFETY: same live private DMA range as Model::bulk.
                    if unsafe { (p as *const u8).add(13).read() } == 1 {
                        self.0.0.borrow_mut().fault = Fault::Timeout;
                    }
                }
                self.0.bulk(e, p, n)
            }
        }
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(0), unit(1), unit(2)],
        );
        let state = io.0.clone();
        let bot = Rc::new(RefCell::new(
            Bot::new(FailSecond(io), 3, endpoints(), &mut dma).unwrap(),
        ));
        let mut failures = Vec::new();
        assert!(
            super::super::discover_units(bot.clone(), "reader", "serial", &mut failures).is_err()
        );
        assert!(bot.borrow().poisoned());
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, "reader LUN 1");
        assert!(!state.borrow().history.iter().any(|(lun, _, _)| *lun == 2));
    }
    /// No caller waits for a reset to settle: the transport refuses
    /// commands until it has, then clears both halts.
    #[test]
    fn a_settling_reset_holds_commands_without_waiting() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(0), unit(1)],
        );
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        state.borrow_mut().fault = Fault::Phase;
        bot.begin(0, &[0; 6], Data::None).unwrap();
        assert!(bot.end().unwrap().is_err());
        state.borrow_mut().fault = Fault::None;
        assert!(bot.busy());
        assert!(bot.begin(1, &[0; 6], Data::None).is_err());
        assert!(!state.borrow().order.contains(&Order::Clear(0x82)));
        state.borrow_mut().now += RESET_RECOVERY_US;
        assert!(!bot.busy());
        assert_eq!(bot.generation(), 1);
        bot.command(1, &[0; 6], Data::None).unwrap();
        assert!(
            !state
                .borrow()
                .order
                .iter()
                .any(|order| matches!(order, Order::Delay(_)))
        );
    }

    #[test]
    fn recovery_waits_for_real_reset_settle_before_clears_and_next_lun() {
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(0), unit(1)],
        );
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        state.borrow_mut().fault = Fault::Phase;
        assert!(bot.command(0, &[0; 6], Data::None).is_err());
        assert!(!bot.poisoned());
        assert!(bot.busy(), "the reset settles");
        state.borrow_mut().fault = Fault::None;
        bot.command(1, &[0; 6], Data::None).unwrap();
        assert_eq!(
            state.borrow().order,
            vec![
                Order::Cbw(0),
                Order::Reset,
                Order::Delay(RESET_RECOVERY_US),
                Order::Clear(0x82),
                Order::Clear(0x02),
                Order::Cbw(1)
            ]
        );
    }
    #[test]
    fn source_bridge_profiles_change_actual_wire_transfers_and_probes() {
        // Two retained 64-KiB-aligned owners plus wrappers can require
        // 262207 bytes from an arbitrary base, exceeding a 256-KiB fixture.
        let mut memory = vec![0u64; 33 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(3), unit(7)],
        );
        let state = io.0.clone();
        // Kobian Mercury Binocam uses an actual 32-byte wrapper.
        let flags = quirks::Flags::from_id(0x04fc, 0x80c2, 0x0100, true).unwrap();
        let mut bot = Bot::with_flags(io, 3, endpoints(), &mut dma, flags).unwrap();
        bot.command(0, &scsi::inquiry(), Data::In(36)).unwrap();
        assert_eq!(state.borrow().wrappers, vec![32]);
        assert_eq!(bot.wrapper.bytes()[31], 0);
        // Genesis high-speed IDE bridge requires the command/data delay.
        bot.flags = quirks::Flags::from_id(0x05e3, 0x0702, 0x0010, true).unwrap();
        bot.command(0, &scsi::inquiry(), Data::In(36)).unwrap();
        assert!(state.borrow().order.contains(&Order::Delay(125)));
        let before = state.borrow().controls.len();
        let flags = quirks::Flags::from_id(0x054c, 0x0010, 0x0106, true).unwrap();
        let mut single = Bot::with_flags(bot.io.clone(), 3, endpoints(), &mut dma, flags).unwrap();
        assert_eq!(single.max_lun(), 0);
        assert_eq!(state.borrow().controls.len(), before);
        assert!(single.command(1, &scsi::inquiry(), Data::In(36)).is_err());
        single.flags = quirks::Flags::from_id(0x04e8, 0x5122, 0, true).unwrap();
        state.borrow_mut().fault = Fault::WrongTag;
        assert_eq!(
            single
                .command(0, &scsi::inquiry(), Data::In(36))
                .unwrap()
                .len(),
            36
        );
        assert!(!state.borrow().controls.iter().any(|r| r[1] == RESET));
    }

    #[test]
    fn source_residue_learning_skipped_data_and_chained_csw_retry_use_real_status() {
        for fault in [
            Fault::BadResidue,
            Fault::SkippedData,
            Fault::CswZeroThenStall,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let start = memory.as_mut_ptr() as u64;
            let mut dma = dma(&mut memory);
            let io = model(start, start + memory.len() as u64 * 8, vec![unit(4)]);
            let state = io.0.clone();
            let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
            state.borrow_mut().fault = fault;
            let bytes = bot.command(0, &scsi::inquiry(), Data::In(36)).unwrap();
            assert_eq!(
                bytes.len(),
                if fault == Fault::SkippedData { 0 } else { 36 }
            );
            assert!(!state.borrow().controls.iter().any(|r| r[1] == RESET));
            if fault == Fault::BadResidue {
                assert!(bot.flags.ignore_residue());
            }
            if fault == Fault::CswZeroThenStall {
                assert_eq!(state.borrow().clears, vec![0x82]);
            }
        }
    }

    #[test]
    fn metadata_warmup_limits_and_last_sector_split_reach_actual_block_commands() {
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let mut u = unit(0x55).unwrap();
        u.media.resize(128 * 1024, 0x55);
        let io = model(start, start + memory.len() as u64 * 8, vec![Some(u)]);
        let state = io.0.clone();
        let mut bot = Bot::new(io, 3, endpoints(), &mut dma).unwrap();
        // Samsung YP-CP3: 64-sector ceiling and incorrect CSW tags.
        bot.flags = quirks::Flags::from_id(0x04e8, 0x5122, 0x0000, true).unwrap();
        let identity = super::super::probe(&mut bot, 0, "slot", "serial").unwrap();
        {
            let state = state.borrow();
            let read = state
                .history
                .iter()
                .position(|(_, _, c)| c[0] == scsi::READ_10)
                .unwrap();
            let mode = state
                .history
                .iter()
                .position(|(_, _, c)| c[0] == scsi::MODE_SENSE_6)
                .unwrap();
            assert!(read < mode);
        }
        let maximum = bot.max_transfer_bytes();
        assert_eq!(maximum, 32768);
        let shared = Rc::new(RefCell::new(bot));
        let mut disk = super::super::Disk {
            bot: shared,
            lun: 0,
            identity,
            media: Rc::new(core::cell::Cell::new(true)),
            running: None,
            next_tag: 0,
        };
        let before = state.borrow().history.len();
        let mut data = vec![0; 128 * 1024];
        disk.read(0, &mut data).unwrap();
        assert!(data.iter().all(|&b| b == 0x55));
        let state = state.borrow();
        let reads: Vec<_> = state.history[before..]
            .iter()
            .filter(|(_, _, c)| c[0] == scsi::READ_10)
            .collect();
        assert!(
            reads
                .iter()
                .all(|(_, _, c)| usize::from(u16::from_be_bytes([c[7], c[8]])) * 512 <= maximum)
        );
        assert_eq!(&reads.last().unwrap().2[7..9], &[0, 1]);
    }

    #[test]
    fn acknowledged_class_reset_permanently_invalidates_all_published_luns() {
        use super::super::media::{Owner, scan_bot};
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let start = memory.as_mut_ptr() as u64;
        let mut dma = dma(&mut memory);
        let io = model(
            start,
            start + memory.len() as u64 * 8,
            vec![unit(1), unit(2)],
        );
        let state = io.0.clone();
        let owner = Rc::new(RefCell::new(Owner::new(
            Bot::new(io, 3, endpoints(), &mut dma).unwrap(),
            "reader".into(),
            "serial".into(),
        )));
        let mut failures = Vec::new();
        let mut old = scan_bot(owner.clone(), &mut failures).unwrap();
        state.borrow_mut().fault = Fault::Phase;
        assert!(old[0].command(&[0; 6], Data::None).is_err());
        let before = state.borrow().transfers;
        assert!(old[1].read(0, &mut [0; 512]).is_err());
        assert!(old[0].flush_cache().is_err());
        assert_eq!(state.borrow().transfers, before);
        state.borrow_mut().fault = Fault::None;
        assert_eq!(scan_bot(owner, &mut failures).unwrap().len(), 2);
        assert!(old[1].flush_cache().is_err());
    }
}
