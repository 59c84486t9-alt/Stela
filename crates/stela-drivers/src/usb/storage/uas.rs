//! Native USB Attached SCSI command/data/status transport.
//!
//! USB2 uses actual READ/WRITE_READY handshakes; SuperSpeed uses the canonical
//! xHCI primary stream service and opaque transfer tickets. The same serialized
//! CDB owner retains every contributor until completion or acknowledged drain.
// SPDX-License-Identifier: GPL-2.0-only
// Linux uas.c reference: Hans de Goede/Red Hat 2013-2016;
// Matthew Wilcox/Intel Corp 2010; Sarah Sharp/Intel Corp 2010.
use super::{Data, Device, DmaAllocator, Endpoint, MAX_TD, Shared};
use crate::{
    block::{BlockError, Sense},
    bus::dma::DmaBuffer,
};
use alloc::vec::Vec;

mod binding;
mod quirks;
pub use binding::Binding;

/// Shared with alternate selection; readiness still requires actual allocation.
pub const REQUESTED_STREAMS: u16 = 2;

const COMMAND_IU: u8 = 1;
const STATUS_IU: u8 = 3;
const RESPONSE_IU: u8 = 4;
const READ_READY_IU: u8 = 6;
const WRITE_READY_IU: u8 = 7;
const TIMEOUT_US: u64 = 30_000_000;
const IU_BUFFER_BYTES: usize = 512;
const MAX_CDB: usize = 260;
const PROTOCOL_ERROR: BlockError = BlockError::Protocol("malformed UAS information unit");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pipe {
    Command,
    Status,
    Input,
    Output,
}
impl Pipe {
    fn index(self) -> usize {
        self as usize
    }
}

/// Opaque eight-byte SCSI logical-unit address, retained exactly as reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lun([u8; 8]);
impl Lun {
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
    pub(super) fn sequential(number: u16) -> Self {
        let mut bytes = [0; 8];
        bytes[0..2].copy_from_slice(&number.to_be_bytes());
        Self(bytes)
    }
    pub fn bytes(self) -> [u8; 8] {
        self.0
    }
}
impl core::fmt::Display for Lun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The class owner keeps buffers allocated for the entire boot, including
/// uncertain DMA. A failed command quarantines this complete interface; host
/// TD cancellation alone cannot establish that the device retired its UAS tag.
pub struct Host {
    engine: Engine<Native>,
    flags: quirks::Flags,
    device: Device,
    binding: Binding,
}
impl Host {
    /// # Safety
    /// `device`, binding and controller must name the same physical attachment
    /// and configuration/reset epoch. The caller owns the interface exclusively
    /// and has not configured or submitted to any of these endpoint contexts.
    /// This constructor owns SET_INTERFACE and actual endpoint/stream setup.
    /// No firmware/other class owner may drive the interface.
    pub unsafe fn new(
        controller: Shared,
        device: &Device,
        binding: Binding,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, BlockError> {
        use super::super::xhci::{FULL_SPEED, HIGH_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS};
        if !matches!(
            device.speed,
            FULL_SPEED | HIGH_SPEED | SUPER_SPEED | SUPER_SPEED_PLUS
        ) {
            return Err(BlockError::Unsupported("UAS device speed"));
        }
        if controller
            .borrow_mut()
            .device(device.id)?
            .current_configuration()?
            != Some(binding.configuration_value())
        {
            return Err(BlockError::Unsupported(
                "UAS configuration is not acknowledged",
            ));
        }
        if binding.alternate() != 0 {
            controller.borrow_mut().device(device.id)?.control(
                super::setup(
                    0x01,
                    super::super::xhci::SET_INTERFACE,
                    u16::from(binding.alternate()),
                    u16::from(binding.interface()),
                    0,
                ),
                &[],
            )?;
        }
        let endpoints = binding.endpoints();
        let streams = if matches!(device.speed, SUPER_SPEED | SUPER_SPEED_PLUS) {
            // This is the real allocation/configuration ACK, not a capability
            // advertisement or a caller-supplied claim that streams exist.
            Some(
                controller
                    .borrow_mut()
                    .device(device.id)?
                    .configure_streams(
                        &endpoints,
                        &binding.stream_endpoints(),
                        REQUESTED_STREAMS,
                        dma,
                    )?,
            )
        } else {
            controller
                .borrow_mut()
                .device(device.id)?
                .configure(&endpoints, None, dma)?;
            None
        };
        let engine = Engine::new(
            Native {
                controller,
                id: device.id,
                endpoints,
                streams,
            },
            dma,
        )?;
        Ok(Self {
            engine,
            flags: binding.flags,
            device: device.clone(),
            binding,
        })
    }
    /// Permanently retire this owner and construct a new owner after an actual
    /// whole-device USB reset. Existing Rc disk aliases never become usable.
    pub(super) fn reset_and_rebind(
        &mut self,
        dma: &mut dyn DmaAllocator,
    ) -> Result<Self, (alloc::string::String, BlockError)> {
        self.engine.poisoned = true;
        let fail = |why| {
            (
                alloc::string::String::from("UAS reset/rebind"),
                BlockError::Unsupported(why),
            )
        };
        let interfaces = super::super::xhci::interfaces(&self.device.configuration);
        if self.device.configuration.get(4) != Some(&1)
            || interfaces.is_empty()
            || interfaces
                .iter()
                .any(|interface| interface.number != self.binding.interface())
        {
            return Err(fail(
                "UAS reset requires exclusive ownership of a single-interface device",
            ));
        }
        let controller = self.engine.io.controller.clone();
        // SAFETY: this sole interface owns exactly all configured class DCIs,
        // and its shared owner was permanently poisoned before retirement.
        let mut fresh = unsafe {
            controller.borrow_mut().reset_and_identify(
                &self.device,
                &self.binding.endpoints(),
                dma,
            )?
        };
        let id = fresh.id;
        let result = (|| {
            if fresh.descriptor != self.device.descriptor
                || fresh.configurations != self.device.configurations
                || fresh.serial != self.device.serial
                || fresh.speed != self.device.speed
            {
                return Err(fail("USB device identity/descriptors changed across reset"));
            }
            fresh.configuration = fresh
                .configurations
                .iter()
                .find(|bytes| bytes.get(5) == Some(&self.binding.configuration_value()))
                .cloned()
                .ok_or_else(|| fail("USB reset lost the selected configuration"))?;
            let interface = super::super::xhci::interfaces(&fresh.configuration)
                .into_iter()
                .find(|interface| {
                    interface.number == self.binding.interface()
                        && interface.alternate == self.binding.alternate()
                })
                .ok_or_else(|| fail("USB reset lost the selected UAS alternate"))?;
            let binding = Binding::new(&fresh, &interface).map_err(fail)?;
            controller
                .borrow_mut()
                .device(id)
                .and_then(|mut device| device.set_configuration(fresh.configuration_value()))
                .map_err(|error| {
                    (
                        alloc::string::String::from("UAS reset restore configuration"),
                        error,
                    )
                })?;
            // SAFETY: the fresh physical attachment/verified configuration is
            // exclusive, and no endpoint other than EP0 has been configured.
            unsafe { Self::new(controller.clone(), &fresh, binding, dma) }.map_err(|error| {
                (
                    alloc::string::String::from("UAS reset reconstruct endpoints"),
                    error,
                )
            })
        })();
        if result.is_err()
            && let Ok(mut device) = controller.borrow_mut().device(id)
        {
            device.quarantine();
        }
        result
    }
    pub(super) fn device(&self) -> &Device {
        &self.device
    }
    pub(super) fn interface(&self) -> u8 {
        self.binding.interface()
    }
    pub(super) fn quarantine(&mut self) {
        self.engine.poisoned = true;
        let mut controller = self.engine.io.controller.borrow_mut();
        if let Ok(mut device) = controller.device(self.engine.io.id) {
            device.quarantine();
        }
    }

    /// Execute a CDB against an actual eight-byte SCSI LUN address. A check
    /// condition uses the returned Sense IU, not an invented REQUEST SENSE.
    pub fn command(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        data: Data<'_>,
    ) -> Result<Vec<u8>, BlockError> {
        execute(&mut self.engine, self.flags, lun, cdb, data)
    }

    pub(super) fn delay(&self, micros: u64) {
        let clock = self.engine.io.controller.borrow().clock;
        clock.delay(micros);
    }
    /// Linux `uas_sdev_configure`: an ALWAYS_SYNC enclosure skips both mode
    /// pages and is assumed writable with its write cache on.
    pub(super) fn write_protect_page(&self) -> Option<u8> {
        (!self.flags.always_sync()).then_some(super::scsi::ALL_PAGES)
    }
    pub(super) fn caching(&self) -> super::Caching {
        match self.flags.always_sync() {
            true => super::Caching::WriteBack,
            false => super::Caching::Query,
        }
    }
    /// `uas_sdev_configure` sets `read_before_ms` for every UAS unit. Some
    /// bridges otherwise return generic write-protect/cache mode information.
    /// This metadata read is never a retry of a caller's failed block command.
    pub(super) fn read_before_mode_sense(
        &mut self,
        lun: [u8; 8],
        block_size: usize,
    ) -> Result<(), BlockError> {
        read_block_zero(&mut self.engine, self.flags, lun, block_size)
    }
    pub(super) fn max_transfer_bytes(&self) -> usize {
        self.flags.max_transfer_bytes()
    }
    pub(super) fn report_luns_permitted(&self) -> bool {
        self.flags.report_luns_permitted()
    }
    pub fn requires_rebind(&self) -> bool {
        self.engine.poisoned
    }
}

fn execute<I: Io>(
    engine: &mut Engine<I>,
    flags: quirks::Flags,
    lun: [u8; 8],
    cdb: &[u8],
    data: Data<'_>,
) -> Result<Vec<u8>, BlockError> {
    if !flags.permits(cdb) {
        return Err(BlockError::Unsupported(
            "CDB requires an unsupported enclosure operation",
        ));
    }
    let length = match &data {
        Data::None => 0,
        Data::In(bytes) => *bytes,
        Data::Out(bytes) => bytes.len(),
    };
    if length > flags.max_transfer_bytes() {
        return Err(BlockError::Unsupported("UAS enclosure transfer limit"));
    }
    engine.command(lun, cdb, data)
}

/// Linux `sd_read_block_zero` uses READ(10) when the ordinary block path uses
/// ten-byte CDBs. Stela propagates failure rather than querying mode pages after
/// uncertain transport/media change. No retry, write, or data publication occurs.
fn read_block_zero<I: Io>(
    engine: &mut Engine<I>,
    flags: quirks::Flags,
    lun: [u8; 8],
    block_size: usize,
) -> Result<(), BlockError> {
    if block_size < 512 || !block_size.is_power_of_two() || block_size > MAX_TD {
        return Err(BlockError::Unsupported("UAS block-zero probe geometry"));
    }
    let mut cdb = [0; 10];
    cdb[0] = super::scsi::READ_10;
    cdb[8] = 1;
    let bytes = execute(engine, flags, lun, &cdb, Data::In(block_size))?;
    if bytes.len() != block_size {
        return Err(BlockError::Protocol("short UAS block-zero probe"));
    }
    Ok(())
}

trait Io {
    type Ticket;
    fn ready(&mut self) -> Result<(), BlockError>;
    fn streams(&self) -> Option<u16> {
        None
    }
    fn submit(
        &mut self,
        pipe: Pipe,
        tag: u16,
        address: u64,
        length: usize,
    ) -> Result<Self::Ticket, BlockError>;
    fn completed(&mut self, ticket: &Self::Ticket) -> Option<Result<usize, BlockError>>;
    fn cancel(&mut self, pipe: Pipe) -> Result<(), BlockError>;
    fn now(&self) -> u64;
    fn pause(&self);
}
struct Native {
    controller: Shared,
    id: super::super::xhci::SlotId,
    endpoints: [Endpoint; 4],
    streams: Option<u16>,
}
enum NativeTicket {
    Ordinary { pipe: Pipe, trb: u64, length: usize },
    Stream(super::super::xhci::StreamTransfer),
}
impl Io for Native {
    type Ticket = NativeTicket;
    fn ready(&mut self) -> Result<(), BlockError> {
        let mut controller = self.controller.borrow_mut();
        let mut device = controller.device(self.id)?;
        device.endpoint_ready(1)?;
        for endpoint in self.endpoints {
            device.endpoint_ready(endpoint.dci())?;
        }
        Ok(())
    }
    fn streams(&self) -> Option<u16> {
        self.streams
    }
    fn submit(
        &mut self,
        pipe: Pipe,
        tag: u16,
        address: u64,
        length: usize,
    ) -> Result<NativeTicket, BlockError> {
        let dci = self.endpoints[pipe.index()].dci();
        let mut controller = self.controller.borrow_mut();
        let mut device = controller.device(self.id)?;
        if self.streams.is_some() && pipe != Pipe::Command {
            device
                .submit_stream(dci, tag, address, length)
                .map(NativeTicket::Stream)
        } else {
            device
                .submit(dci, address, length)
                .map(|trb| NativeTicket::Ordinary { pipe, trb, length })
        }
    }
    fn completed(&mut self, ticket: &NativeTicket) -> Option<Result<usize, BlockError>> {
        let mut controller = self.controller.borrow_mut();
        let mut device = match controller.device(self.id) {
            Ok(device) => device,
            Err(error) => return Some(Err(error)),
        };
        match ticket {
            NativeTicket::Stream(ticket) => device.completed_stream(ticket),
            NativeTicket::Ordinary { pipe, trb, length } => {
                device.completed(self.endpoints[pipe.index()].dci(), *trb, *length)
            }
        }
    }
    fn cancel(&mut self, pipe: Pipe) -> Result<(), BlockError> {
        self.controller
            .borrow_mut()
            .device(self.id)?
            .cancel(self.endpoints[pipe.index()].dci())
    }
    fn now(&self) -> u64 {
        self.controller.borrow().clock.now_us()
    }
    fn pause(&self) {
        let clock = self.controller.borrow().clock;
        clock.delay(1);
    }
}

struct Engine<I: Io> {
    io: I,
    command: DmaBuffer,
    status: DmaBuffer,
    data: DmaBuffer,
    pending: [Option<I::Ticket>; 4],
    touched: [bool; 4],
    tag: u16,
    poisoned: bool,
}
impl<I: Io> Engine<I> {
    fn new(mut io: I, dma: &mut dyn DmaAllocator) -> Result<Self, BlockError> {
        if io.streams() == Some(0) {
            return Err(BlockError::Unsupported("UAS has no usable stream IDs"));
        }
        io.ready()?;
        Ok(Self {
            io,
            command: dma.allocate(IU_BUFFER_BYTES, IU_BUFFER_BYTES)?,
            status: dma.allocate(IU_BUFFER_BYTES, IU_BUFFER_BYTES)?,
            data: dma.allocate(MAX_TD, MAX_TD)?,
            pending: core::array::from_fn(|_| None),
            touched: [false; 4],
            tag: 0,
            poisoned: false,
        })
    }
    fn post(&mut self, pipe: Pipe, address: u64, length: usize) -> Result<(), BlockError> {
        let index = pipe.index();
        if self.pending[index].is_some() {
            return Err(BlockError::Unsupported(
                "UAS pipe already has a pending transfer",
            ));
        }
        // A failed submit may have published a TD before losing its receipt.
        // Include it in terminal cancellation even without a returned ticket.
        self.touched[index] = true;
        self.pending[index] = Some(self.io.submit(pipe, self.tag, address, length)?);
        Ok(())
    }
    fn failure<T>(&mut self, error: BlockError) -> Result<T, BlockError> {
        self.poisoned = true;
        for pipe in [Pipe::Command, Pipe::Status, Pipe::Input, Pipe::Output] {
            if self.touched[pipe.index()] {
                // Retain the owner and all allocations even on cancellation
                // failure. There is no successful-looking tag reuse afterward.
                let _ = self.io.cancel(pipe);
            }
        }
        Err(error)
    }
    fn command(&mut self, lun: [u8; 8], cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
        if self.poisoned {
            return Err(BlockError::Unsupported("UAS interface requires rebind"));
        }
        let (length, input) = match &data {
            Data::None => (0, false),
            Data::In(n) => (*n, true),
            Data::Out(b) => (b.len(), false),
        };
        if cdb.is_empty() || cdb.len() > MAX_CDB || length > MAX_TD {
            return Err(BlockError::Unsupported("UAS CDB or transfer length"));
        }
        // Readiness can fail because topology retirement, a controller fault,
        // or an earlier endpoint error invalidated this attachment. Fence the
        // entire class owner before media code observes the failure. No DMA
        // buffer may be rewritten and no later command may reuse this epoch.
        self.touched = [false; 4];
        if let Err(error) = self.io.ready() {
            return self.failure(error);
        }
        let streams = self.io.streams();
        let maximum = streams.unwrap_or(u16::MAX);
        self.tag = if self.tag >= maximum { 1 } else { self.tag + 1 };
        let command = command_iu(self.tag, lun, cdb);
        self.command.bytes_mut()[..command.len()].copy_from_slice(&command);
        self.status.bytes_mut().fill(0);
        if let Data::Out(bytes) = data {
            self.data.bytes_mut()[..length].copy_from_slice(bytes);
        }
        self.touched = [false; 4];
        if let Err(error) = self.post(Pipe::Status, self.status.physical(), IU_BUFFER_BYTES) {
            return self.failure(error);
        }
        // USB3 has no READY handshake. Queue the actual stream-owned status
        // and data requests before publishing the ordinary command IU.
        if streams.is_some()
            && length != 0
            && let Err(error) = self.post(
                if input { Pipe::Input } else { Pipe::Output },
                self.data.physical(),
                length,
            )
        {
            return self.failure(error);
        }
        if let Err(error) = self.post(Pipe::Command, self.command.physical(), command.len()) {
            return self.failure(error);
        }
        let started = self.io.now();
        let mut ready = false;
        let mut moved = if length == 0 { Some(0) } else { None };
        let mut terminal: Option<Status> = None;
        loop {
            for pipe in [Pipe::Command, Pipe::Status, Pipe::Input, Pipe::Output] {
                let index = pipe.index();
                let completion = self.pending[index]
                    .as_ref()
                    .and_then(|ticket| self.io.completed(ticket));
                let Some(completion) = completion else {
                    continue;
                };
                self.pending[index] = None;
                let count = match completion {
                    Ok(count) => count,
                    Err(error) => return self.failure(error),
                };
                match pipe {
                    Pipe::Command if count != command.len() => {
                        return self.failure(PROTOCOL_ERROR);
                    }
                    Pipe::Command => {}
                    Pipe::Input | Pipe::Output if count <= length => moved = Some(count),
                    Pipe::Input | Pipe::Output => {
                        return self.failure(PROTOCOL_ERROR);
                    }
                    Pipe::Status => {
                        let frame = match self
                            .status
                            .bytes()
                            .get(..count)
                            .and_then(|bytes| status_iu(bytes, self.tag))
                        {
                            Some(frame) => frame,
                            None => {
                                return self.failure(PROTOCOL_ERROR);
                            }
                        };
                        match frame {
                            Frame::Ready(direction)
                                if streams.is_none()
                                    && !ready
                                    && length != 0
                                    && direction == input =>
                            {
                                ready = true;
                                // Repost the status request before data; a fast
                                // device may finish its CDB as soon as data ends.
                                if let Err(error) =
                                    self.post(Pipe::Status, self.status.physical(), IU_BUFFER_BYTES)
                                {
                                    return self.failure(error);
                                }
                                if let Err(error) = self.post(
                                    if input { Pipe::Input } else { Pipe::Output },
                                    self.data.physical(),
                                    length,
                                ) {
                                    return self.failure(error);
                                }
                            }
                            Frame::Ready(_) => {
                                return self.failure(PROTOCOL_ERROR);
                            }
                            Frame::Done(status) => terminal = Some(status),
                        }
                    }
                }
            }
            if let Some(status) = &terminal {
                if status.code != 0 {
                    // Device-terminal error may precede host data completion.
                    // Drain each actual outstanding contributor before any CPU
                    // buffer access or later command is permitted.
                    for pipe in [Pipe::Command, Pipe::Input, Pipe::Output] {
                        if self.pending[pipe.index()].is_some() {
                            if let Err(error) = self.io.cancel(pipe) {
                                return self.failure(error);
                            }
                            self.pending[pipe.index()] = None;
                        }
                    }
                    return Err(match status.response {
                        Some(_) => BlockError::Protocol("UAS Response IU refused the command"),
                        None => Sense::parse(&status.sense)
                            .map_or(BlockError::CheckCondition, BlockError::Sense),
                    });
                }
                if self.pending.iter().all(Option::is_none) {
                    let Some(moved) = moved else {
                        return self.failure(PROTOCOL_ERROR);
                    };
                    if !input && moved != length {
                        return Err(BlockError::Protocol("short UAS write"));
                    }
                    return Ok(if input {
                        self.data.bytes()[..moved].to_vec()
                    } else {
                        Vec::new()
                    });
                }
            }
            if self.io.now().wrapping_sub(started) >= TIMEOUT_US {
                return self.failure(BlockError::Timeout);
            }
            self.io.pause();
        }
    }
}

fn command_iu(tag: u16, lun: [u8; 8], cdb: &[u8]) -> Vec<u8> {
    let extra = cdb.len().saturating_sub(16).next_multiple_of(4);
    let mut bytes = vec![0; 32 + extra];
    bytes[0] = COMMAND_IU;
    bytes[2..4].copy_from_slice(&tag.to_be_bytes());
    bytes[6] = extra as u8;
    bytes[8..16].copy_from_slice(&lun);
    bytes[16..16 + cdb.len()].copy_from_slice(cdb);
    bytes
}
struct Status {
    code: u8,
    sense: Vec<u8>,
    response: Option<u8>,
}
enum Frame {
    Ready(bool),
    Done(Status),
}
fn status_iu(bytes: &[u8], tag: u16) -> Option<Frame> {
    if bytes.len() < 4 || u16::from_be_bytes(bytes[2..4].try_into().ok()?) != tag {
        return None;
    }
    match bytes[0] {
        READ_READY_IU if bytes.len() == 4 => Some(Frame::Ready(true)),
        WRITE_READY_IU if bytes.len() == 4 => Some(Frame::Ready(false)),
        STATUS_IU if bytes.len() >= 16 => {
            // Like Linux uas_sense, a sense length that disagrees with the
            // transfer is clamped to the bytes that actually arrived.
            let length = usize::from(u16::from_be_bytes(bytes[14..16].try_into().ok()?));
            let end = bytes.len().min(16 + length);
            Some(Frame::Done(Status {
                code: bytes[6],
                sense: bytes[16..end].to_vec(),
                response: None,
            }))
        }
        RESPONSE_IU if bytes.len() == 8 => Some(Frame::Done(Status {
            code: if bytes[7] == 8 { 0 } else { 0xff },
            sense: Vec::new(),
            response: Some(bytes[7]),
        })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::RegionAllocator;
    use alloc::{rc::Rc, vec};
    use core::cell::{Cell, RefCell};
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Fault {
        None,
        WrongReady,
        WrongTag,
        MalformedStatus,
        ShortCommand,
        ShortData,
        Timeout,
        SubmitStatus,
        SubmitCommand,
        ErrorAfterReady,
        CancelError,
        StatusBeforeData,
        FlushError,
        CommandLast,
        SubmitData,
        EndpointUnavailable,
    }
    #[derive(Clone, Copy)]
    struct Ticket {
        pipe: Pipe,
        id: u64,
        address: u64,
        length: usize,
        stream: u16,
    }
    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Post(Pipe),
        Complete(Pipe),
        Cancel(Pipe),
    }
    struct State {
        range: core::ops::Range<u64>,
        events: Vec<Event>,
        active: Vec<Ticket>,
        next: u64,
        command: Option<Vec<u8>>,
        history: Vec<Vec<u8>>,
        tag: u16,
        requested: usize,
        input: bool,
        ready: bool,
        data_done: bool,
        terminal_sent: bool,
        fault: Fault,
        written: Vec<u8>,
        target: Option<Target>,
        reply: Option<Reply>,
        streams: Option<u16>,
    }
    #[derive(Clone)]
    struct Model {
        state: Rc<RefCell<State>>,
        clock: Rc<Cell<u64>>,
    }
    impl Model {
        fn bytes(s: &State, t: &Ticket) -> Vec<u8> {
            assert!(t.address >= s.range.start && t.address + t.length as u64 <= s.range.end);
            // SAFETY: one test owns this live DMA range, and only its synchronous
            // completion model accesses it until the ticket is retired.
            unsafe { core::slice::from_raw_parts(t.address as *const u8, t.length) }.to_vec()
        }
        fn write(s: &State, t: &Ticket, bytes: &[u8]) {
            assert!(
                bytes.len() <= t.length
                    && t.address >= s.range.start
                    && t.address + t.length as u64 <= s.range.end
            );
            // SAFETY: as bytes(); every write is within this ticket's allocation.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), t.address as *mut u8, bytes.len());
            }
        }
    }
    impl Io for Model {
        type Ticket = Ticket;
        fn ready(&mut self) -> Result<(), BlockError> {
            if self.state.borrow().fault == Fault::EndpointUnavailable {
                Err(BlockError::Unsupported("model attachment retired"))
            } else {
                Ok(())
            }
        }
        fn streams(&self) -> Option<u16> {
            self.state.borrow().streams
        }
        fn now(&self) -> u64 {
            self.clock.get()
        }
        fn pause(&self) {
            self.clock.set(self.clock.get() + 1_000_000);
        }
        fn submit(
            &mut self,
            pipe: Pipe,
            tag: u16,
            address: u64,
            length: usize,
        ) -> Result<Ticket, BlockError> {
            let mut s = self.state.borrow_mut();
            assert!(!s.active.iter().any(|t| t.pipe == pipe));
            s.next += 1;
            let t = Ticket {
                pipe,
                id: s.next,
                address,
                length,
                stream: if pipe != Pipe::Command && s.streams.is_some() {
                    tag
                } else {
                    0
                },
            };
            if let Some(count) = s.streams {
                assert!((1..=count).contains(&tag));
            }
            s.events.push(Event::Post(pipe));
            s.active.push(t);
            match pipe {
                Pipe::Command => {
                    assert!(s.active.iter().any(|t| t.pipe == Pipe::Status));
                    let bytes = Self::bytes(&s, &t);
                    assert_eq!(bytes[0], COMMAND_IU);
                    assert_eq!(bytes.len(), 32 + usize::from(bytes[6]));
                    s.tag = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
                    assert_ne!(s.tag, 0);
                    if let Some(target) = &mut s.target {
                        let reply = target.prepare(&bytes);
                        s.requested = reply.requested;
                        s.input = reply.input;
                        s.reply = Some(reply);
                    } else {
                        match bytes[16] {
                            0x35 => s.requested = 0,
                            0x28 | 0x2a | 0x2e => {
                                s.input = bytes[16] == 0x28;
                                s.requested = usize::from(u16::from_be_bytes(
                                    bytes[23..25].try_into().unwrap(),
                                )) * 512;
                            }
                            0xaa | 0xae => {
                                s.input = false;
                                s.requested = u32::from_be_bytes(bytes[22..26].try_into().unwrap())
                                    as usize
                                    * 512;
                            }
                            0x8a | 0x8e => {
                                s.input = false;
                                s.requested = u32::from_be_bytes(bytes[26..30].try_into().unwrap())
                                    as usize
                                    * 512;
                            }
                            0x9c => {
                                s.input = false;
                                s.requested = usize::from(u16::from_be_bytes(
                                    bytes[28..30].try_into().unwrap(),
                                )) * 512;
                            }
                            0x7f => {
                                s.input = false;
                                assert!(matches!(
                                    u16::from_be_bytes(bytes[24..26].try_into().unwrap()),
                                    0x0b..=0x0d
                                ));
                                s.requested = u32::from_be_bytes(bytes[44..48].try_into().unwrap())
                                    as usize
                                    * 512;
                            }
                            0 => assert_eq!(s.requested, 0),
                            other => panic!("unmodeled actual CDB {other:#x}"),
                        }
                    }
                    s.history.push(bytes.clone());
                    s.command = Some(bytes);
                    if s.streams.is_some() {
                        for active in &s.active {
                            if active.pipe != Pipe::Command {
                                assert_eq!(active.stream, s.tag);
                            }
                        }
                        if s.requested != 0 {
                            let direction = if s.input { Pipe::Input } else { Pipe::Output };
                            let data = s
                                .active
                                .iter()
                                .find(|t| t.pipe == direction)
                                .expect("stream data must precede command");
                            assert_eq!(data.length, s.requested);
                        }
                    }
                    s.ready = s.streams.is_some();
                    s.data_done = false;
                    s.terminal_sent = false;
                }
                Pipe::Input | Pipe::Output => {
                    if s.streams.is_some() {
                        assert!(
                            !s.active.iter().any(|t| t.pipe == Pipe::Command),
                            "stream data posted after command"
                        );
                    } else {
                        assert!(s.ready);
                        assert_eq!(pipe == Pipe::Input, s.input);
                        assert_eq!(length, s.requested);
                    }
                    assert!(s.active.iter().any(|t| t.pipe == Pipe::Status));
                }
                _ => {}
            }
            if (s.fault == Fault::SubmitStatus && pipe == Pipe::Status)
                || (s.fault == Fault::SubmitCommand && pipe == Pipe::Command)
                || (s.fault == Fault::SubmitData && matches!(pipe, Pipe::Input | Pipe::Output))
            {
                return Err(BlockError::Timeout);
            }
            Ok(t)
        }
        fn completed(&mut self, t: &Ticket) -> Option<Result<usize, BlockError>> {
            let mut s = self.state.borrow_mut();
            assert!(s.active.iter().any(|current| current.id == t.id));
            if s.fault == Fault::Timeout {
                return None;
            }
            let result = match t.pipe {
                Pipe::Command
                    if s.fault == Fault::CommandLast
                        && (!s.terminal_sent || s.requested != 0 && !s.data_done) =>
                {
                    None
                }
                Pipe::Command => Some(Ok(if s.fault == Fault::ShortCommand {
                    t.length - 1
                } else {
                    t.length
                })),
                Pipe::Status => {
                    s.command.as_ref()?;
                    let mut bytes = vec![0; 16];
                    bytes[0] = STATUS_IU;
                    bytes[2..4].copy_from_slice(&s.tag.to_be_bytes());
                    if s.streams.is_some() && s.fault == Fault::WrongReady {
                        bytes.truncate(4);
                        bytes[0] = READ_READY_IU;
                    } else if let Some(sense) = s.reply.as_ref().and_then(|reply| reply.sense) {
                        bytes[6] = 2;
                        bytes[14..16].copy_from_slice(&18u16.to_be_bytes());
                        bytes.resize(34, 0);
                        bytes[16] = 0x70;
                        bytes[18] = (sense >> 16) as u8;
                        bytes[23] = 10;
                        bytes[28] = (sense >> 8) as u8;
                        bytes[29] = sense as u8;
                    } else if s.requested != 0 && !s.ready {
                        bytes.truncate(4);
                        bytes[0] = if s.input ^ (s.fault == Fault::WrongReady) {
                            READ_READY_IU
                        } else {
                            WRITE_READY_IU
                        };
                        s.ready = true;
                    } else if s.requested != 0
                        && !s.data_done
                        && !matches!(
                            s.fault,
                            Fault::ErrorAfterReady | Fault::CancelError | Fault::StatusBeforeData
                        )
                    {
                        return None;
                    } else if matches!(s.fault, Fault::ErrorAfterReady | Fault::CancelError)
                        || s.fault == Fault::FlushError && s.command.as_ref().unwrap()[16] == 0x35
                    {
                        bytes[6] = 2;
                        bytes[14..16].copy_from_slice(&18u16.to_be_bytes());
                        bytes.resize(34, 0);
                        bytes[16] = 0x70;
                        bytes[18] = 2;
                        bytes[23] = 10;
                        bytes[28] = 0x3a;
                    }
                    if s.fault == Fault::WrongTag
                        || s.reply.as_ref().is_some_and(|reply| reply.wrong_tag)
                    {
                        bytes[2..4].copy_from_slice(&s.tag.wrapping_add(1).to_be_bytes());
                    }
                    if s.fault == Fault::MalformedStatus {
                        // An IU ID Linux uas_stat_cmplt logs as bogus.
                        bytes[0] = 0x7f;
                    }
                    if bytes[0] == STATUS_IU {
                        s.terminal_sent = true;
                    }
                    Self::write(&s, t, &bytes);
                    Some(Ok(bytes.len()))
                }
                Pipe::Input | Pipe::Output => {
                    if s.fault == Fault::StatusBeforeData && !s.terminal_sent {
                        return None;
                    }
                    if matches!(s.fault, Fault::ErrorAfterReady | Fault::CancelError) {
                        return None;
                    }
                    let count = if let Some(reply) = &s.reply {
                        if t.pipe == Pipe::Input {
                            reply.data.len().min(t.length)
                        } else {
                            t.length
                        }
                    } else if s.fault == Fault::ShortData {
                        t.length - 1
                    } else {
                        t.length
                    };
                    if t.pipe == Pipe::Input {
                        let data = s.reply.as_ref().map_or_else(
                            || vec![0x6d; count],
                            |reply| reply.data[..count].to_vec(),
                        );
                        Self::write(&s, t, &data);
                    } else {
                        s.written = Self::bytes(&s, t)[..count].to_vec();
                        let command = s.command.clone().unwrap();
                        let written = s.written.clone();
                        if let Some(target) = &mut s.target {
                            target.write(&command, written);
                        }
                    }
                    s.data_done = true;
                    Some(Ok(count))
                }
            };
            if result.is_some() {
                s.active.retain(|current| current.id != t.id);
                s.events.push(Event::Complete(t.pipe));
            }
            result
        }
        fn cancel(&mut self, pipe: Pipe) -> Result<(), BlockError> {
            let mut s = self.state.borrow_mut();
            s.events.push(Event::Cancel(pipe));
            if s.fault == Fault::CancelError && matches!(pipe, Pipe::Input | Pipe::Output) {
                return Err(BlockError::Timeout);
            }
            s.active.retain(|current| current.pipe != pipe);
            Ok(())
        }
    }
    fn model(
        memory: &mut [u64],
        length: usize,
        input: bool,
        fault: Fault,
    ) -> (Model, RegionAllocator) {
        let start = memory.as_mut_ptr() as u64;
        let range = start..start + core::mem::size_of_val(memory) as u64;
        let io = Model {
            state: Rc::new(RefCell::new(State {
                range: range.clone(),
                events: Vec::new(),
                active: Vec::new(),
                next: 0,
                command: None,
                history: Vec::new(),
                tag: 0,
                requested: length,
                input,
                ready: false,
                data_done: false,
                terminal_sent: false,
                fault,
                written: Vec::new(),
                target: None,
                reply: None,
                streams: None,
            })),
            clock: Rc::new(Cell::new(0)),
        };
        // SAFETY: each test keeps memory exclusive/live until all IO owners drop.
        (io, unsafe { RegionAllocator::new(range) })
    }
    #[derive(Clone)]
    struct Media {
        lun: Lun,
        blocks: u64,
        block_size: u32,
        read_only: bool,
        empty: bool,
        marker: u8,
        version: u8,
    }
    impl Media {
        fn disk(lun: Lun, marker: u8) -> Self {
            Self {
                lun,
                blocks: 4096,
                block_size: 512,
                read_only: false,
                empty: false,
                marker,
                version: 6,
            }
        }
    }
    struct Reply {
        requested: usize,
        input: bool,
        data: Vec<u8>,
        sense: Option<u32>,
        wrong_tag: bool,
    }
    enum CacheReply {
        Replace {
            sense: u32,
            blocks: u64,
            read_only: bool,
        },
        Sense(u32),
        Data(Vec<u8>),
    }
    struct Target {
        media: Vec<Media>,
        reported: Vec<Lun>,
        report_override: Option<Vec<u8>>,
        report_attention: usize,
        unit_attention: Option<u32>,
        report_change_blocks: Option<u64>,
        block_zero_change: Option<(Lun, u64)>,
        cache_reply: Option<CacheReply>,
        report_illegal: bool,
        poison_lun: Option<Lun>,
        writes: Vec<(Lun, u64, Vec<u8>)>,
        flushes: Vec<Lun>,
    }
    impl Target {
        fn new(media: Vec<Media>) -> Self {
            Self {
                reported: media.iter().map(|m| m.lun).collect(),
                media,
                report_override: None,
                report_attention: 0,
                unit_attention: None,
                report_change_blocks: None,
                block_zero_change: None,
                cache_reply: None,
                report_illegal: false,
                poison_lun: None,
                writes: Vec::new(),
                flushes: Vec::new(),
            }
        }
        fn prepare(&mut self, iu: &[u8]) -> Reply {
            let lun = Lun::from_bytes(iu[8..16].try_into().unwrap());
            let cdb = &iu[16..];
            if cdb[0] == super::super::scsi::MODE_SENSE_6
                && cdb[2] == super::super::scsi::CACHING_PAGE
                && let Some(cache) = self.cache_reply.take()
            {
                let (sense, data) = match cache {
                    CacheReply::Replace {
                        sense,
                        blocks,
                        read_only,
                    } => {
                        let media = self
                            .media
                            .iter_mut()
                            .find(|media| media.lun == lun)
                            .unwrap();
                        media.blocks = blocks;
                        media.read_only = read_only;
                        media.empty = (sense >> 8) & 0xff == 0x3a;
                        (Some(sense), Vec::new())
                    }
                    CacheReply::Sense(sense) => (Some(sense), Vec::new()),
                    CacheReply::Data(data) => (None, data),
                };
                return Reply {
                    requested: usize::from(cdb[4]),
                    input: true,
                    data,
                    sense,
                    wrong_tag: false,
                };
            }
            if cdb[..10] == [0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]
                && let Some((unit, blocks)) = self.block_zero_change
                && unit == lun
            {
                self.block_zero_change = None;
                self.media[0].blocks = blocks;
                return Reply {
                    requested: 0,
                    input: true,
                    data: Vec::new(),
                    sense: Some(0x063f0e),
                    wrong_tag: false,
                };
            }
            let media = self.media.iter().find(|media| media.lun == lun);
            let mut reply = Reply {
                requested: 0,
                input: true,
                data: Vec::new(),
                sense: None,
                wrong_tag: self.poison_lun == Some(lun),
            };
            if cdb[0] == 0
                && let Some(sense) = self.unit_attention.take()
            {
                reply.sense = Some(sense);
                return reply;
            }
            match cdb[0] {
                0x12 => {
                    assert_eq!(&cdb[..6], &[0x12, 0, 0, 0, 36, 0]);
                    reply.requested = 36;
                    reply.data = vec![0; 36];
                    reply.data[2] = media.map_or(6, |media| media.version);
                    reply.data[4] = 31;
                    reply.data[8..16].copy_from_slice(b"STELAUSB");
                    reply.data[16..32].copy_from_slice(b"UAS TARGET MODEL");
                    if media.is_none() {
                        reply.data[0] = 0x7f;
                    }
                }
                0xa0 => {
                    assert_eq!(&cdb[1..6], &[0; 5]);
                    assert_eq!(&cdb[10..12], &[0; 2]);
                    reply.requested = u32::from_be_bytes(cdb[6..10].try_into().unwrap()) as usize;
                    if self.report_attention > 0 {
                        self.report_attention -= 1;
                        if let Some(blocks) = self.report_change_blocks.take() {
                            self.media[0].blocks = blocks;
                        }
                        reply.sense = Some(0x063f0e);
                    } else if self.report_illegal {
                        reply.sense = Some(0x052000);
                    } else if let Some(bytes) = &self.report_override {
                        reply.data = bytes.clone();
                    } else {
                        reply.data = vec![0; 8];
                        reply.data[..4]
                            .copy_from_slice(&((self.reported.len() * 8) as u32).to_be_bytes());
                        for lun in &self.reported {
                            reply.data.extend_from_slice(&lun.bytes());
                        }
                    }
                    reply.data.truncate(reply.requested);
                }
                _ => {
                    let Some(media) = media else {
                        reply.sense = Some(0x052500);
                        return reply;
                    };
                    match cdb[0] {
                        0 => {
                            assert_eq!(&cdb[..6], &[0; 6]);
                            if media.empty {
                                reply.sense = Some(0x023a00);
                            }
                        }
                        0x25 => {
                            reply.requested = 8;
                            let last = u32::try_from(media.blocks - 1).unwrap_or(u32::MAX);
                            reply.data.extend_from_slice(&last.to_be_bytes());
                            reply
                                .data
                                .extend_from_slice(&media.block_size.to_be_bytes());
                        }
                        0x9e => {
                            assert_eq!(cdb[1], 0x10);
                            assert_eq!(cdb[13], 32);
                            reply.requested = 32;
                            reply.data = vec![0; 32];
                            reply.data[..8].copy_from_slice(&(media.blocks - 1).to_be_bytes());
                            reply.data[8..12].copy_from_slice(&media.block_size.to_be_bytes());
                        }
                        0x1a => {
                            assert!(matches!(cdb[2], 0x08 | 0x3f));
                            assert_eq!(usize::from(cdb[4]), super::super::scsi::MODE_SENSE_BYTES);
                            let protect = if media.read_only { 0x80 } else { 0 };
                            // A write-back Caching page follows the header.
                            reply.data = vec![7, 0, protect, 0, 0x08, 0x12, 0x04, 0];
                            reply.requested = usize::from(cdb[4]);
                        }
                        0x28 | 0x2a | 0x88 | 0x8a => {
                            let (lba, count) = Self::range(cdb);
                            assert!(
                                lba.checked_add(u64::from(count))
                                    .is_some_and(|end| end <= media.blocks)
                            );
                            reply.requested = count as usize * media.block_size as usize;
                            reply.input = matches!(cdb[0], 0x28 | 0x88);
                            if reply.input {
                                reply.data = self
                                    .writes
                                    .iter()
                                    .rev()
                                    .find(|(unit, at, bytes)| {
                                        *unit == lun && *at == lba && bytes.len() == reply.requested
                                    })
                                    .map_or_else(
                                        || vec![media.marker; reply.requested],
                                        |(_, _, bytes)| bytes.clone(),
                                    );
                            } else {
                                assert!(!media.read_only, "write reached protected medium");
                            }
                        }
                        0x35 => {
                            assert_eq!(&cdb[..10], &[0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                            self.flushes.push(lun);
                        }
                        op => panic!("unmodeled discovery/block opcode {op:#x}"),
                    }
                }
            }
            reply
        }
        fn range(cdb: &[u8]) -> (u64, u32) {
            if matches!(cdb[0], 0x28 | 0x2a) {
                (
                    u64::from(u32::from_be_bytes(cdb[2..6].try_into().unwrap())),
                    u32::from(u16::from_be_bytes(cdb[7..9].try_into().unwrap())),
                )
            } else {
                (
                    u64::from_be_bytes(cdb[2..10].try_into().unwrap()),
                    u32::from_be_bytes(cdb[10..14].try_into().unwrap()),
                )
            }
        }
        fn write(&mut self, iu: &[u8], bytes: Vec<u8>) {
            let lun = Lun::from_bytes(iu[8..16].try_into().unwrap());
            let cdb = &iu[16..];
            assert!(matches!(cdb[0], 0x2a | 0x8a));
            let (lba, _) = Self::range(cdb);
            self.writes.push((lun, lba, bytes));
        }
    }
    struct ScsiModel {
        engine: Engine<Model>,
        flags: quirks::Flags,
    }
    impl super::super::Scsi for ScsiModel {
        type Lun = Lun;
        fn command(&mut self, lun: Lun, cdb: &[u8], data: Data<'_>) -> Result<Vec<u8>, BlockError> {
            execute(&mut self.engine, self.flags, lun.bytes(), cdb, data)
        }
        fn delay(&self, micros: u64) {
            self.engine
                .io
                .clock
                .set(self.engine.io.clock.get() + micros);
        }
        fn poisoned(&self) -> bool {
            self.engine.poisoned
        }
        fn write_protect_page(&self) -> Option<u8> {
            (!self.flags.always_sync()).then_some(super::super::scsi::ALL_PAGES)
        }
        fn caching(&self) -> super::super::Caching {
            match self.flags.always_sync() {
                true => super::super::Caching::WriteBack,
                false => super::super::Caching::Query,
            }
        }
        fn report_luns_permitted(&self) -> bool {
            self.flags.report_luns_permitted()
        }
        fn read_before_mode_sense(
            &mut self,
            lun: Lun,
            block_size: usize,
        ) -> Result<(), BlockError> {
            read_block_zero(&mut self.engine, self.flags, lun.bytes(), block_size)
        }
        fn max_transfer_bytes(&self) -> usize {
            self.flags.max_transfer_bytes()
        }
    }
    fn target_owner(
        memory: &mut [u64],
        target: Target,
        flags: quirks::Flags,
    ) -> (Rc<RefCell<ScsiModel>>, Rc<RefCell<State>>) {
        let (io, mut dma) = model(memory, 0, false, Fault::None);
        let state = io.state.clone();
        state.borrow_mut().target = Some(target);
        (
            Rc::new(RefCell::new(ScsiModel {
                engine: Engine::new(io, &mut dma).unwrap(),
                flags,
            })),
            state,
        )
    }

    #[test]
    fn reported_sparse_hierarchical_units_publish_real_blocks_and_keep_identity() {
        use crate::block::BlockDevice;
        let sparse = Lun::from_bytes([0x40, 7, 0, 2, 0, 0, 0, 0]);
        let mut empty = Media::disk(Lun::default(), 0);
        empty.empty = true;
        let mut protected = Media::disk(Lun::sequential(3), 0x33);
        protected.read_only = true;
        let mut big = Media::disk(sparse, 0x77);
        big.blocks = u64::from(u32::MAX) + 4096;
        let mut target = Target::new(vec![empty, protected, big]);
        target.report_attention = 2;
        let mut memory = vec![0u64; 32 * 1024];
        let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
        let mut failures = Vec::new();
        let mut disks =
            super::super::discover_uas_units(owner, "native", "serial", &mut failures).unwrap();
        assert_eq!(disks.len(), 2);
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0].1,
            BlockError::Sense(Sense {
                key: 0x02,
                asc: 0x3a,
                ascq: 0x00
            })
        );
        assert!(disks[0].identity().read_only);
        assert!(disks[0].write(0, &[0; 512]).is_err());
        assert_eq!(disks[1].identity().blocks, u64::from(u32::MAX) + 4096);
        assert!(disks[1].identity().location.ends_with("4007000200000000"));
        assert!(disks[1].identity().serial.ends_with(":lun4007000200000000"));
        let lba = u64::from(u32::MAX) + 1;
        let bytes = vec![0xab; MAX_TD + 512];
        disks[1].write(lba, &bytes).unwrap();
        disks[1].flush().unwrap();
        let mut actual = vec![0; bytes.len()];
        disks[1].read(lba, &mut actual).unwrap();
        assert_eq!(actual, bytes);
        let state = state.borrow();
        assert!(state.active.is_empty());
        let target = state.target.as_ref().unwrap();
        assert_eq!(target.writes.len(), 2);
        assert_eq!(target.flushes, vec![sparse]);
        assert!(target.writes.iter().all(|(lun, _, _)| *lun == sparse));
        assert_eq!(state.history.iter().filter(|iu| iu[16] == 0xa0).count(), 3);
    }
    #[test]
    fn spc6_version_keeps_sparse_reported_units_beyond_first_absent_sequential_unit() {
        let mut zero = Media::disk(Lun::default(), 0x10);
        zero.version = 8;
        let sparse = Lun::sequential(7);
        let target = Target::new(vec![zero, Media::disk(sparse, 0x70)]);
        let mut memory = vec![0u64; 32 * 1024];
        let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
        let mut failures = Vec::new();
        let disks = super::super::discover_uas_units(owner, "native", "id", &mut failures).unwrap();
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[1].lun, sparse);
        assert!(failures.is_empty());
        let state = state.borrow();
        assert!(state.history.iter().any(|iu| iu[16] == 0xa0));
        assert!(
            state
                .history
                .iter()
                .filter(|iu| iu[16] == 0x12)
                .all(|iu| iu[8..16] != Lun::sequential(1).bytes())
        );
        assert!(state.active.is_empty());
    }
    #[test]
    fn actual_initial_zero_survives_omission_but_absent_zero_is_never_invented() {
        use crate::block::BlockDevice;
        for case in 0..5 {
            let zero = Lun::default();
            let sparse = Lun::sequential(7);
            let mut media = if case == 2 {
                Vec::new()
            } else {
                vec![Media::disk(zero, 0x10)]
            };
            if case != 0 {
                media.push(Media::disk(sparse, 0x70));
            }
            let mut target = Target::new(media);
            target.reported = if case == 0 {
                Vec::new()
            } else if case == 4 {
                vec![zero, sparse]
            } else {
                vec![sparse]
            };
            if case == 3 {
                target.poison_lun = Some(sparse);
            }
            let mut memory = vec![0u64; 32 * 1024];
            let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
            let mut failures = Vec::new();
            let result =
                super::super::discover_uas_units(owner.clone(), "native", "id", &mut failures);
            if case == 3 {
                assert!(result.is_err());
                assert!(owner.borrow().engine.poisoned);
            } else {
                let mut disks = result.unwrap();
                assert!(failures.is_empty());
                let expected = if matches!(case, 0 | 2) { 1 } else { 2 };
                assert_eq!(disks.len(), expected);
                assert_eq!(disks[0].lun, if case == 2 { sparse } else { zero });
                let mut bytes = [0; 512];
                disks[0].read(0, &mut bytes).unwrap();
                assert_eq!(bytes, [if case == 2 { 0x70 } else { 0x10 }; 512]);
            }
            let state = state.borrow();
            assert!(state.active.is_empty());
            assert_eq!(
                state
                    .history
                    .iter()
                    .filter(|iu| iu[16] == 0x12 && iu[8..16] == zero.bytes())
                    .count(),
                1
            );
            assert_eq!(
                state
                    .history
                    .iter()
                    .filter(|iu| iu[16] == 0x25 && iu[8..16] == zero.bytes())
                    .count(),
                usize::from(case != 2)
            );
        }
    }
    #[test]
    fn source_no_report_fallback_scans_past_empty_slot_and_stops_at_actual_absence() {
        let mut empty = Media::disk(Lun::default(), 0);
        empty.empty = true;
        let target = Target::new(vec![empty, Media::disk(Lun::sequential(1), 0x11)]);
        let mut memory = vec![0u64; 32 * 1024];
        let flags = quirks::Flags::from_id(0x0bc2, 0x331a, 0);
        let (owner, state) = target_owner(&mut memory, target, flags);
        let mut failures = Vec::new();
        let disks =
            super::super::discover_uas_units(owner, "card reader", "id", &mut failures).unwrap();
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].lun, Lun::sequential(1));
        assert_eq!(failures.len(), 1);
        let state = state.borrow();
        assert!(state.history.iter().all(|iu| iu[16] != 0xa0));
        let inquiries: Vec<_> = state
            .history
            .iter()
            .filter(|iu| iu[16] == 0x12)
            .map(|iu| Lun::from_bytes(iu[8..16].try_into().unwrap()))
            .collect();
        assert_eq!(
            inquiries,
            vec![Lun::default(), Lun::sequential(1), Lun::sequential(2)]
        );
    }
    #[test]
    fn reported_transfer_uncertainty_discards_previously_initialized_units() {
        let mut target = Target::new(vec![
            Media::disk(Lun::default(), 1),
            Media::disk(Lun::sequential(7), 7),
        ]);
        target.poison_lun = Some(Lun::sequential(7));
        let mut memory = vec![0u64; 32 * 1024];
        let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
        let mut failures = Vec::new();
        assert!(
            super::super::discover_uas_units(owner.clone(), "native", "id", &mut failures).is_err()
        );
        assert!(owner.borrow().engine.poisoned);
        assert_eq!(failures.len(), 1);
        assert!(state.borrow().active.is_empty());
    }
    #[test]
    fn report_list_grows_from_real_header_and_never_accepts_partial_or_duplicate_lists() {
        for case in 0..5 {
            let mut target = Target::new(vec![Media::disk(Lun::default(), 1)]);
            target.reported = (0..600).map(Lun::sequential).collect();
            match case {
                1 => target.report_override = Some(vec![0, 0, 0, 9, 0, 0, 0, 0]),
                2 => target.report_override = Some(vec![0, 1, 0, 0, 0, 0, 0, 0]),
                3 => target.report_override = Some(vec![0, 0, 0, 8, 0, 0, 0, 0]),
                4 => target.reported = vec![Lun::default(), Lun::default()],
                _ => {}
            }
            let mut memory = vec![0u64; 32 * 1024];
            let (owner, state) = target_owner(&mut memory, target, quirks::Flags::default());
            let result = super::super::report_luns(&mut *owner.borrow_mut());
            if case == 0 {
                assert_eq!(result.unwrap().unwrap().len(), 600);
                assert_eq!(state.borrow().history.len(), 2);
            } else {
                assert!(result.is_err(), "case{case}");
            }
            assert!(state.borrow().active.is_empty());
            assert!(!owner.borrow().engine.poisoned);
        }
    }
    #[test]
    fn illegal_report_falls_back_and_always_sync_uses_only_safe_mode_page() {
        use crate::block::BlockDevice;
        let mut target = Target::new(vec![Media::disk(Lun::default(), 0x11)]);
        target.report_illegal = true;
        let mut memory = vec![0u64; 32 * 1024];
        let flags = quirks::Flags::from_id(0x4971, 0x8024, 0);
        let (owner, state) = target_owner(&mut memory, target, flags);
        let mut failures = Vec::new();
        let mut disks =
            super::super::discover_uas_units(owner, "native", "id", &mut failures).unwrap();
        assert_eq!(disks.len(), 1);
        assert!(failures.is_empty());
        disks[0].write(1, &[0x88; 512]).unwrap();
        assert!(state.borrow().target.as_ref().unwrap().flushes.is_empty());
        // ALWAYS_SYNC reads no mode page and flushes its assumed write cache.
        disks[0].flush().unwrap();
        let state = state.borrow();
        assert!(!state.history.iter().any(|iu| iu[16] == 0x1a));
        assert_eq!(state.target.as_ref().unwrap().flushes, vec![Lun::default()]);
        assert!(state.active.is_empty());
    }

    #[test]
    fn streams_queue_actual_status_and_data_before_command_and_cycle_only_allocated_tags() {
        for input in [false, true] {
            for fault in [Fault::None, Fault::StatusBeforeData, Fault::CommandLast] {
                let mut memory = vec![0u64; 32 * 1024];
                let (io, mut dma) = model(&mut memory, 512, input, fault);
                let state = io.state.clone();
                state.borrow_mut().streams = Some(2);
                let mut engine = Engine::new(io, &mut dma).unwrap();
                for _ in 0..4 {
                    let data = vec![0x9a; 512];
                    let result = engine
                        .command(
                            [0; 8],
                            &rw(input, 512),
                            if input {
                                Data::In(512)
                            } else {
                                Data::Out(&data)
                            },
                        )
                        .unwrap();
                    if input {
                        assert_eq!(result, vec![0x6d; 512]);
                    } else {
                        assert_eq!(state.borrow().written, data);
                    }
                    assert!(state.borrow().active.is_empty());
                }
                let state = state.borrow();
                let tags: Vec<_> = state
                    .history
                    .iter()
                    .map(|iu| u16::from_be_bytes([iu[2], iu[3]]))
                    .collect();
                assert_eq!(tags, vec![1, 2, 1, 2]);
                let data = if input { Pipe::Input } else { Pipe::Output };
                assert_eq!(
                    &state.events[..3],
                    &[
                        Event::Post(Pipe::Status),
                        Event::Post(data),
                        Event::Post(Pipe::Command)
                    ]
                );
                if fault == Fault::CommandLast {
                    let complete = |pipe| {
                        state
                            .events
                            .iter()
                            .position(|e| *e == Event::Complete(pipe))
                            .unwrap()
                    };
                    assert!(complete(data) < complete(Pipe::Status));
                    assert!(complete(Pipe::Status) < complete(Pipe::Command));
                }
            }
        }
    }
    #[test]
    fn stream_errors_drain_all_contributors_or_quarantine_without_dma_reuse() {
        for input in [false, true] {
            for fault in [
                Fault::ErrorAfterReady,
                Fault::CancelError,
                Fault::WrongReady,
                Fault::WrongTag,
                Fault::MalformedStatus,
                Fault::ShortCommand,
                Fault::Timeout,
                Fault::SubmitData,
                Fault::SubmitCommand,
                Fault::SubmitStatus,
            ] {
                let mut memory = vec![0u64; 32 * 1024];
                let (io, mut dma) = model(&mut memory, 512, input, fault);
                let state = io.state.clone();
                state.borrow_mut().streams = Some(2);
                let mut engine = Engine::new(io, &mut dma).unwrap();
                let outgoing = vec![0x44; 512];
                let result = engine.command(
                    [0; 8],
                    &rw(input, 512),
                    if input {
                        Data::In(512)
                    } else {
                        Data::Out(&outgoing)
                    },
                );
                assert!(result.is_err(), "{fault:?}");
                if fault == Fault::ErrorAfterReady {
                    assert_eq!(
                        result,
                        Err(BlockError::Sense(Sense {
                            key: 0x02,
                            asc: 0x3a,
                            ascq: 0x00
                        }))
                    );
                    assert!(!engine.poisoned);
                    assert!(state.borrow().active.is_empty());
                } else {
                    assert!(engine.poisoned, "{fault:?}");
                    let count = state.borrow().events.len();
                    let data = engine.data.bytes().to_vec();
                    assert!(
                        engine
                            .command([0; 8], &rw(false, 512), Data::Out(&outgoing))
                            .is_err()
                    );
                    assert_eq!(state.borrow().events.len(), count);
                    assert_eq!(engine.data.bytes(), data);
                    if fault == Fault::CancelError {
                        assert!(
                            state
                                .borrow()
                                .active
                                .iter()
                                .any(|t| matches!(t.pipe, Pipe::Input | Pipe::Output))
                        );
                    } else {
                        assert!(state.borrow().active.is_empty());
                    }
                }
            }
        }
    }
    #[test]
    fn streamed_discovery_block_io_and_required_flush_use_actual_reported_lun_and_streams() {
        use crate::block::BlockDevice;
        let sparse = Lun::from_bytes([0x40, 7, 0, 3, 0, 0, 0, 0]);
        let mut target = Target::new(vec![
            Media::disk(Lun::default(), 0x10),
            Media::disk(sparse, 0x70),
        ]);
        target.reported = vec![sparse];
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 0, false, Fault::CommandLast);
        let state = io.state.clone();
        {
            let mut state = state.borrow_mut();
            state.streams = Some(2);
            state.target = Some(target);
        }
        let owner = Rc::new(RefCell::new(ScsiModel {
            engine: Engine::new(io, &mut dma).unwrap(),
            flags: quirks::Flags::from_id(0x4971, 0x8024, 0),
        }));
        let mut failures = Vec::new();
        let mut disks =
            super::super::discover_uas_units(owner, "native", "serial", &mut failures).unwrap();
        assert_eq!(disks.len(), 2);
        assert!(failures.is_empty());
        assert_eq!(disks[1].lun, sparse);
        disks[1].write(1, &[0x55; 512]).unwrap();
        let mut bytes = [0; 512];
        disks[1].read(1, &mut bytes).unwrap();
        assert_eq!(bytes, [0x55; 512]);
        disks[1].flush().unwrap();
        let state = state.borrow();
        assert!(state.active.is_empty());
        assert_eq!(state.target.as_ref().unwrap().flushes, vec![sparse]);
        assert!(
            state
                .history
                .iter()
                .all(|iu| (1..=2).contains(&u16::from_be_bytes([iu[2], iu[3]])))
        );
    }
    #[test]
    fn zero_allocated_streams_refuses_owner_before_submitting() {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
        let state = io.state.clone();
        state.borrow_mut().streams = Some(0);
        assert!(Engine::new(io, &mut dma).is_err());
        assert!(state.borrow().events.is_empty());
    }

    #[test]
    fn native_uas_admission_rejects_foreign_generation_before_configuration_or_dma() {
        use crate::usb::xhci::{self, HIGH_SPEED, SUPER_SPEED};
        for speed in [HIGH_SPEED, SUPER_SPEED] {
            let mut first_memory = vec![0u64; 512 * 1024];
            let mut second_memory = vec![0u64; 512 * 1024];
            let (first, first_device, first_hardware, mut first_dma) =
                xhci::model::reset_fixture(&mut first_memory, speed, 32, 3);
            let (_second, second_device, second_hardware, _second_dma) =
                xhci::model::reset_fixture(&mut second_memory, speed, 32, 3);
            assert_eq!(first_device.slot, second_device.slot);
            assert_ne!(first_device.id, second_device.id);
            let binding = Binding::new(
                &second_device,
                &xhci::interfaces(&second_device.configuration)[0],
            )
            .unwrap();
            let first_accesses = first_hardware.borrow().accesses;
            let second_accesses = second_hardware.borrow().accesses;
            let remaining = first_dma.remaining();
            // Deliberately mismatch the actual enumerated identity and host.
            // Generation validation must refuse before the unsafe ownership
            // promise could publish class effects on this unrelated attachment.
            assert!(
                unsafe { Host::new(first.clone(), &second_device, binding, &mut first_dma) }
                    .is_err()
            );
            assert_eq!(first_hardware.borrow().accesses, first_accesses);
            assert_eq!(second_hardware.borrow().accesses, second_accesses);
            assert_eq!(first_dma.remaining(), remaining);
        }
    }

    #[test]
    fn native_empty_owner_rescans_change_and_reset_without_retargeting_old_disks() {
        use crate::block::BlockDevice;
        use crate::usb::xhci::{self, HIGH_SPEED, SUPER_SPEED};
        for speed in [HIGH_SPEED, SUPER_SPEED] {
            let mut memory = vec![0u64; 512 * 1024];
            let (controller, device, hardware, mut dma) =
                xhci::model::reset_fixture(&mut memory, speed, 32, 3);
            hardware.borrow_mut().empty_media = true;
            let binding =
                Binding::new(&device, &xhci::interfaces(&device.configuration)[0]).unwrap();
            let mut failures = Vec::new();
            let (storage, disks) = unsafe {
                super::super::discover_uas_retained(
                    controller,
                    &device,
                    binding,
                    &mut dma,
                    &mut failures,
                )
            }
            .unwrap();
            assert!(disks.is_empty());
            assert!(
                hardware
                    .borrow()
                    .scsi
                    .iter()
                    .all(|(_, op)| !matches!(*op, 0x25 | 0x1a))
            );
            // Mirror normal Found/probe retention after typed disks are drained.
            let mut found = xhci::Found::default();
            found.storage.push(storage);
            let mut probed = crate::probe::Disks::default();
            probed.usb_storage.extend(found.storage);
            let mut storage = probed.usb_storage.remove(0);
            hardware.borrow_mut().empty_media = false;
            let mut disks = storage.rescan(&mut failures).unwrap();
            assert_eq!(disks.len(), 1);
            disks[0].write(1, &[0x44; 512]).unwrap();
            disks[0].flush().unwrap();
            let mut same = storage.rescan(&mut failures).unwrap();
            same[0].read(1, &mut [0; 512]).unwrap();
            // UA while INQUIRY is being retried still invalidates the previous
            // publication even with identical fresh capacity and identifiers.
            hardware.borrow_mut().sense_once = Some((0x12, 0x062800));
            let mut changed = storage.rescan(&mut failures).unwrap();
            assert_eq!(changed.len(), 1);
            let before = hardware.borrow().accesses;
            assert!(disks[0].read(0, &mut [0; 512]).is_err());
            assert!(same[0].flush().is_err());
            assert_eq!(hardware.borrow().accesses, before);
            // CHECK CONDITION can arrive before USB2 READY or before SS data
            // completes. The native contributor cancellation must finish, and
            // neither the failed write nor an old alias may be replayed.
            hardware.borrow_mut().sense_once = Some((0x2a, 0x062800));
            let before_commands = hardware.borrow().scsi.len();
            assert_eq!(
                changed[0].write(1, &[0x55; 512]),
                Err(BlockError::Sense(Sense {
                    key: 0x06,
                    asc: 0x28,
                    ascq: 0x00
                }))
            );
            assert_eq!(
                hardware.borrow().scsi[before_commands..]
                    .iter()
                    .filter(|(_, op)| *op == 0x2a)
                    .count(),
                1
            );
            let mut ready = storage.rescan(&mut failures).unwrap();
            let mut preserved = [0; 512];
            ready[0].read(1, &mut preserved).unwrap();
            assert_eq!(preserved, [0x44; 512], "failed native write was replayed");
            hardware.borrow_mut().sense_once = Some((0, 0x063a00));
            let before_commands = hardware.borrow().scsi.len();
            assert!(storage.rescan(&mut failures).unwrap().is_empty());
            assert!(
                hardware.borrow().scsi[before_commands..]
                    .iter()
                    .all(|(_, op)| !matches!(*op, 0x25 | 0x1a))
            );
            hardware.borrow_mut().empty_media = true;
            assert!(storage.rescan(&mut failures).unwrap().is_empty());
            let before = hardware.borrow().accesses;
            assert!(changed[0].write(0, &[0; 512]).is_err());
            assert_eq!(hardware.borrow().accesses, before);
            hardware.borrow_mut().empty_media = false;
            let mut inserted = storage.rescan(&mut failures).unwrap();
            // The retained reset variant must return a usable owner even when
            // physical reset succeeds with no media. Old owners stay poisoned.
            hardware.borrow_mut().empty_media = true;
            let (mut rebound, empty) = inserted[0]
                .reset_and_rebind_retained(&mut dma, &mut failures)
                .unwrap();
            assert!(empty.is_empty());
            let before = hardware.borrow().accesses;
            assert!(inserted[0].flush().is_err());
            assert_eq!(hardware.borrow().accesses, before);
            assert!(storage.rescan(&mut failures).is_err());
            hardware.borrow_mut().empty_media = false;
            let mut fresh = rebound.rescan(&mut failures).unwrap();
            assert_eq!(fresh[0].identity().blocks, 2048);
            fresh[0].write(1500, &[0x88; 512]).unwrap();
            fresh[0].flush().unwrap();
            let mut bytes = [0; 512];
            fresh[0].read(1500, &mut bytes).unwrap();
            assert_eq!(bytes, [0x88; 512]);
        }
    }

    #[test]
    fn late_target_change_discards_earlier_probe_and_revalidates_before_publication() {
        use super::super::media::{Owner, scan_uas};
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let mut initial = Media::disk(Lun::default(), 1);
        initial.blocks = 1024;
        let (raw, state) = target_owner(
            &mut memory,
            Target::new(vec![initial]),
            quirks::Flags::default(),
        );
        let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
        let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
        let mut failures = Vec::new();
        let mut old = scan_uas(owner.clone(), &mut failures).unwrap();
        {
            let mut state = state.borrow_mut();
            let target = state.target.as_mut().unwrap();
            target.report_attention = 1;
            target.report_change_blocks = Some(4096);
        }
        let mut fresh = scan_uas(owner.clone(), &mut failures).unwrap();
        assert_eq!(
            fresh[0].identity().blocks,
            4096,
            "earlier capacity survived late target change"
        );
        fresh[0].read(3000, &mut [0; 512]).unwrap();
        let before = state.borrow().events.len();
        assert!(old[0].flush().is_err());
        assert_eq!(state.borrow().events.len(), before);
        // Every REPORT now changes the target: no provisional view is usable.
        state.borrow_mut().target.as_mut().unwrap().report_attention = usize::MAX;
        assert_eq!(
            scan_uas(owner, &mut failures).err(),
            Some(BlockError::Unsupported(
                "USB media changed repeatedly during rescan"
            ))
        );
        let before = state.borrow().events.len();
        assert!(fresh[0].flush().is_err());
        assert_eq!(state.borrow().events.len(), before);
    }

    #[test]
    fn block_zero_target_change_restarts_earlier_lun_metadata_before_publication() {
        use super::super::media::{Owner, scan_uas};
        use crate::block::BlockDevice;
        for streams in [None, Some(2)] {
            let mut memory = vec![0u64; 32 * 1024];
            let later = Lun::sequential(4);
            let (raw, state) = target_owner(
                &mut memory,
                Target::new(vec![Media::disk(Lun::default(), 1), Media::disk(later, 4)]),
                quirks::Flags::default(),
            );
            state.borrow_mut().streams = streams;
            let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
            let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
            let mut old = scan_uas(owner.clone(), &mut Vec::new()).unwrap();
            assert_eq!(old.len(), 2);
            state
                .borrow_mut()
                .target
                .as_mut()
                .unwrap()
                .block_zero_change = Some((later, 8192));
            let mut failures = Vec::new();
            let fresh = scan_uas(owner, &mut failures).unwrap();
            assert_eq!(fresh.len(), 2);
            assert_eq!(
                fresh[0].identity().blocks,
                8192,
                "earlier provisional geometry survived a later block-zero target-change UA"
            );
            assert!(failures.iter().any(|(_, error)| *error
                == BlockError::Sense(Sense {
                    key: 6,
                    asc: 0x3f,
                    ascq: 0x0e,
                })));
            let before = state.borrow().events.len();
            assert!(old[0].read(0, &mut [0; 512]).is_err());
            assert!(old[1].flush().is_err());
            assert_eq!(state.borrow().events.len(), before);
        }
    }

    #[test]
    fn first_lun_cache_change_restarts_geometry_and_protection_before_publication() {
        use super::super::media::{Owner, scan_uas};
        use crate::block::BlockDevice;
        for streams in [None, Some(2)] {
            for sense in [0x062800, 0x063f0e] {
                let mut memory = vec![0u64; 32 * 1024];
                let mut initial = Media::disk(Lun::default(), 0x51);
                initial.blocks = 1024;
                initial.read_only = true;
                let mut target = Target::new(vec![initial]);
                target.cache_reply = Some(CacheReply::Replace {
                    sense,
                    blocks: 8192,
                    read_only: false,
                });
                let (raw, state) = target_owner(&mut memory, target, quirks::Flags::default());
                state.borrow_mut().streams = streams;
                let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
                let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
                let mut failures = Vec::new();
                let mut fresh = scan_uas(owner, &mut failures).unwrap();
                assert_eq!(fresh.len(), 1);
                assert_eq!(
                    fresh[0].identity().blocks,
                    8192,
                    "final cache query published earlier geometry"
                );
                assert!(
                    !fresh[0].identity().read_only,
                    "final cache query published earlier protection"
                );
                assert!(failures.iter().any(|(_, error)| *error
                    == BlockError::Sense(Sense {
                        key: (sense >> 16) as u8,
                        asc: (sense >> 8) as u8,
                        ascq: sense as u8
                    })));
                assert_eq!(
                    state
                        .borrow()
                        .history
                        .iter()
                        .filter(|iu| iu[16] == 0x25)
                        .count(),
                    2
                );
                fresh[0].write(7000, &[0x62; 512]).unwrap();
                fresh[0].flush().unwrap();
                assert_eq!(
                    state.borrow().target.as_ref().unwrap().flushes,
                    vec![Lun::default()],
                    "write-back flush suppressed after cache change"
                );
            }
        }
    }

    #[test]
    fn first_lun_final_cache_no_media_never_publishes_previous_metadata() {
        use super::super::media::{Owner, scan_uas};
        for streams in [None, Some(2)] {
            for sense in [0x023a00, 0x063a00] {
                let mut memory = vec![0u64; 32 * 1024];
                let mut target = Target::new(vec![Media::disk(Lun::default(), 0x31)]);
                target.cache_reply = Some(CacheReply::Replace {
                    sense,
                    blocks: 8192,
                    read_only: false,
                });
                let (raw, state) = target_owner(&mut memory, target, quirks::Flags::default());
                state.borrow_mut().streams = streams;
                let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
                let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
                let mut failures = Vec::new();
                assert!(scan_uas(owner.clone(), &mut failures).unwrap().is_empty());
                assert!(failures.iter().any(|(_, error)| *error
                    == BlockError::Sense(Sense {
                        key: (sense >> 16) as u8,
                        asc: (sense >> 8) as u8,
                        ascq: sense as u8
                    })));
                // The reader remains retained. A later actual insertion is
                // freshly probed and keeps the target's real cache policy.
                state.borrow_mut().target.as_mut().unwrap().media[0].empty = false;
                let mut fresh = scan_uas(owner, &mut failures).unwrap();
                assert_eq!(fresh.len(), 1);
                assert_eq!(fresh[0].identity.blocks, 8192);
                use crate::block::BlockDevice;
                fresh[0].flush().unwrap();
                assert_eq!(
                    state.borrow().target.as_ref().unwrap().flushes,
                    vec![Lun::default()]
                );
            }
        }
    }

    #[test]
    fn stable_cache_policy_and_explicit_unsupported_page_preserve_flush_semantics() {
        use super::super::media::{Owner, scan_uas};
        use crate::block::BlockDevice;
        for (reply, write_back) in [
            (CacheReply::Data(vec![7, 0, 0, 0, 8, 0x12, 4, 0]), true),
            (CacheReply::Data(vec![7, 0, 0, 0, 8, 0x12, 0, 0]), false),
            (CacheReply::Data(vec![3, 0, 0, 0]), false),
            (CacheReply::Sense(0x052400), false),
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let mut target = Target::new(vec![Media::disk(Lun::default(), 0x11)]);
            target.cache_reply = Some(reply);
            let (raw, state) = target_owner(&mut memory, target, quirks::Flags::default());
            let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
            let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
            let mut failures = Vec::new();
            let mut disks = scan_uas(owner, &mut failures).unwrap();
            assert_eq!(disks.len(), 1);
            assert!(failures.is_empty());
            assert_eq!(disks[0].write_cache, write_back);
            disks[0].write(1, &[0x91; 512]).unwrap();
            disks[0].flush().unwrap();
            assert_eq!(
                state.borrow().target.as_ref().unwrap().flushes.len(),
                usize::from(write_back)
            );
            assert_eq!(
                state
                    .borrow()
                    .history
                    .iter()
                    .filter(|iu| iu[16] == 0x25)
                    .count(),
                1
            );
        }
        for (reply, error) in [
            (
                CacheReply::Sense(0x052000),
                BlockError::Sense(Sense {
                    key: 5,
                    asc: 0x20,
                    ascq: 0,
                }),
            ),
            (
                CacheReply::Data(vec![0; 4]),
                BlockError::Protocol("malformed USB mode parameter header"),
            ),
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let mut target = Target::new(vec![Media::disk(Lun::default(), 0x11)]);
            target.cache_reply = Some(reply);
            let (raw, _) = target_owner(&mut memory, target, quirks::Flags::default());
            let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
            let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
            let mut failures = Vec::new();
            assert!(scan_uas(owner, &mut failures).unwrap().is_empty());
            assert_eq!(failures.len(), 1);
            assert_eq!(failures[0].1, error);
        }
    }

    #[test]
    fn report_lun_removal_and_rescan_poison_permanently_invalidate_real_uas_aliases() {
        use super::super::media::{Owner, scan_uas};
        use crate::block::BlockDevice;
        let mut memory = vec![0u64; 32 * 1024];
        let sparse = Lun::from_bytes([0x40, 7, 0, 2, 0, 0, 0, 0]);
        let (raw, state) = target_owner(
            &mut memory,
            Target::new(vec![Media::disk(Lun::default(), 1), Media::disk(sparse, 7)]),
            quirks::Flags::default(),
        );
        let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
        let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
        let mut failures = Vec::new();
        let mut old = scan_uas(owner.clone(), &mut failures).unwrap();
        state
            .borrow_mut()
            .target
            .as_mut()
            .unwrap()
            .reported
            .retain(|lun| *lun != sparse);
        let mut current = scan_uas(owner.clone(), &mut failures).unwrap();
        assert_eq!(current.len(), 1);
        let before = state.borrow().events.len();
        assert!(old[1].read(0, &mut [0; 512]).is_err());
        assert_eq!(state.borrow().events.len(), before);
        old[0].read(0, &mut [0; 512]).unwrap();
        state
            .borrow_mut()
            .target
            .as_mut()
            .unwrap()
            .reported
            .push(sparse);
        let mut inserted = scan_uas(owner.clone(), &mut failures).unwrap();
        inserted[1].read(0, &mut [0; 512]).unwrap();
        assert!(old[1].flush().is_err());
        state.borrow_mut().target.as_mut().unwrap().unit_attention = Some(0x063f0e);
        assert_eq!(
            inserted[0].command(&[0; 6], Data::None),
            Err(BlockError::Sense(Sense {
                key: 0x06,
                asc: 0x3f,
                ascq: 0x0e
            }))
        );
        let before = state.borrow().events.len();
        assert!(inserted[1].read(0, &mut [0; 512]).is_err());
        assert_eq!(
            state.borrow().events.len(),
            before,
            "target LUN remapping allowed old disk I/O"
        );
        let mut restored = scan_uas(owner.clone(), &mut failures).unwrap();
        state.borrow_mut().target.as_mut().unwrap().poison_lun = Some(sparse);
        assert!(scan_uas(owner, &mut failures).is_err());
        let before = state.borrow().events.len();
        assert!(current[0].flush().is_err());
        assert!(restored[0].flush().is_err());
        assert!(restored[1].write(0, &[0; 512]).is_err());
        assert_eq!(state.borrow().events.len(), before);
    }

    #[test]
    fn native_root_reset_rebind_preserves_old_alias_quarantine_and_reprobes_geometry() {
        use crate::block::BlockDevice;
        for speed in [
            super::super::super::xhci::HIGH_SPEED,
            super::super::super::xhci::SUPER_SPEED,
        ] {
            let mut memory = vec![0u64; 512 * 1024];
            let (controller, device, hardware, mut dma) =
                crate::usb::xhci::model::reset_fixture(&mut memory, speed, 32, 3);
            let interface = crate::usb::xhci::interfaces(&device.configuration).remove(0);
            let binding = Binding::new(&device, &interface).unwrap();
            let mut failures = Vec::new();
            let mut disks = unsafe {
                super::super::discover_uas(
                    controller.clone(),
                    &device,
                    binding,
                    &mut dma,
                    &mut failures,
                )
            }
            .unwrap();
            assert_eq!(disks.len(), 1);
            assert_eq!(disks[0].identity().blocks, 1024);
            let super::super::UsbTransport::Uas(unit) = &disks[0].disk else {
                panic!()
            };
            let owner = unit.bot.clone();
            let mut alias = super::super::UsbDisk {
                disk: super::super::UsbTransport::Uas(super::super::Disk {
                    bot: owner.clone(),
                    lun: unit.lun,
                    identity: unit.identity.clone(),
                    media: unit.media.clone(),
                    write_cache: unit.write_cache,
                }),
            };
            let commands_before_fault = hardware.borrow().scsi.len();
            hardware.borrow_mut().hang_next = true;
            let mut old_read = [0x91; 512];
            assert_eq!(disks[0].read(1, &mut old_read), Err(BlockError::Timeout));
            assert_eq!(old_read, [0x91; 512]);
            assert!(
                hardware.borrow().device_task,
                "endpoint cancellation retired firmware task"
            );
            let before = {
                let host = owner.borrow();
                (
                    host.transport.engine.command.bytes().to_vec(),
                    host.transport.engine.status.bytes().to_vec(),
                    host.transport.engine.data.bytes().to_vec(),
                )
            };
            let mut fresh = disks[0].reset_and_rebind(&mut dma, &mut failures).unwrap();
            assert_eq!(fresh.len(), 1);
            assert_eq!(fresh[0].identity().blocks, 2048);
            assert!(failures.is_empty());
            assert_eq!(hardware.borrow().enables, vec![1, 1, 2]);
            assert_eq!(hardware.borrow().resets, 1);
            assert!(!hardware.borrow().device_task);
            let access = hardware.borrow().accesses;
            assert!(alias.read(0, &mut [0; 512]).is_err());
            assert!(disks[0].write(0, &[0; 512]).is_err());
            assert_eq!(hardware.borrow().accesses, access);
            {
                let host = owner.borrow();
                assert!(host.transport.requires_rebind());
                assert_eq!(host.transport.engine.command.bytes(), before.0);
                assert_eq!(host.transport.engine.status.bytes(), before.1);
                assert_eq!(host.transport.engine.data.bytes(), before.2);
            }
            fresh[0].write(1500, &[0xa7; 512]).unwrap();
            fresh[0].flush().unwrap();
            let mut bytes = [0; 512];
            fresh[0].read(1500, &mut bytes).unwrap();
            assert_eq!(bytes, [0xa7; 512]);
            let hardware = hardware.borrow();
            assert_eq!(
                hardware.scsi[commands_before_fault..]
                    .iter()
                    .filter(|(epoch, op)| *epoch == 0 && *op == 0x28)
                    .count(),
                1,
                "timed-out read replayed"
            );
            assert!(
                hardware
                    .scsi
                    .iter()
                    .any(|(epoch, op)| *epoch == 1 && *op == 0x12)
            );
            assert!(
                hardware
                    .scsi
                    .iter()
                    .any(|(epoch, op)| *epoch == 1 && *op == 0x25)
            );
            assert!(
                hardware
                    .scsi
                    .iter()
                    .any(|(epoch, op)| *epoch == 1 && *op == 0x1a)
            );
        }
    }
    #[test]
    fn native_reset_identity_or_reconstruction_failure_quarantines_both_epochs() {
        use crate::block::BlockDevice;
        for changed in [false, true] {
            let mut memory = vec![0u64; 512 * 1024];
            let (controller, device, hardware, mut dma) = crate::usb::xhci::model::reset_fixture(
                &mut memory,
                crate::usb::xhci::SUPER_SPEED,
                32,
                3,
            );
            let interface = crate::usb::xhci::interfaces(&device.configuration).remove(0);
            let mut failures = Vec::new();
            let mut disks = unsafe {
                super::super::discover_uas(
                    controller.clone(),
                    &device,
                    Binding::new(&device, &interface).unwrap(),
                    &mut dma,
                    &mut failures,
                )
            }
            .unwrap();
            struct RebuildFailure<'a> {
                inner: &'a mut dyn DmaAllocator,
                hardware: alloc::rc::Rc<RefCell<crate::usb::xhci::model::ResetHardware>>,
            }
            impl DmaAllocator for RebuildFailure<'_> {
                fn allocate(
                    &mut self,
                    bytes: usize,
                    align: usize,
                ) -> Result<DmaBuffer, BlockError> {
                    if self.hardware.borrow().reconstructed() {
                        Err(BlockError::NoDmaMemory)
                    } else {
                        self.inner.allocate(bytes, align)
                    }
                }
            }
            if changed {
                hardware.borrow_mut().fault = crate::usb::xhci::model::ResetFault::Identity;
            }
            let result = if changed {
                disks[0].reset_and_rebind(&mut dma, &mut failures)
            } else {
                disks[0].reset_and_rebind(
                    &mut RebuildFailure {
                        inner: &mut dma,
                        hardware: hardware.clone(),
                    },
                    &mut failures,
                )
            };
            assert!(result.is_err());
            assert!(!failures.is_empty());
            assert!(
                controller
                    .borrow_mut()
                    .endpoint_ready(device.slot, 1)
                    .is_err()
            );
            assert!(controller.borrow_mut().endpoint_ready(2, 1).is_err());
            let access = hardware.borrow().accesses;
            assert!(disks[0].read(0, &mut [0; 512]).is_err());
            assert_eq!(hardware.borrow().accesses, access);
        }
    }

    #[test]
    fn block_zero_probe_uses_actual_lun_and_geometry_before_any_mode_page() {
        use super::super::Scsi;
        for streams in [None, Some(2)] {
            for block_size in [512, 4096, MAX_TD] {
                let lun = Lun::from_bytes([0x40, 9, 0, 3, 0, 0, 0, 0]);
                let mut medium = Media::disk(lun, 0x47);
                medium.block_size = block_size as u32;
                let mut memory = vec![0u64; 32 * 1024];
                let (owner, state) = target_owner(
                    &mut memory,
                    Target::new(vec![medium]),
                    quirks::Flags::default(),
                );
                state.borrow_mut().streams = streams;
                owner
                    .borrow_mut()
                    .read_before_mode_sense(lun, block_size)
                    .unwrap();
                let state = state.borrow();
                assert_eq!(state.history.len(), 1);
                let command = &state.history[0];
                assert_eq!(&command[8..16], &lun.bytes());
                assert_eq!(&command[16..26], &[0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
                assert!(state.active.is_empty());
                assert!(state.target.as_ref().unwrap().writes.is_empty());
                assert!(state.target.as_ref().unwrap().flushes.is_empty());
            }
        }
    }
    #[test]
    fn block_zero_failure_never_retries_or_queries_generic_mode_information() {
        for fault in [Fault::ShortData, Fault::Timeout, Fault::ErrorAfterReady] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, true, fault);
            let state = io.state.clone();
            let mut engine = Engine::new(io, &mut dma).unwrap();
            assert!(read_block_zero(&mut engine, quirks::Flags::default(), [0; 8], 512).is_err());
            let state = state.borrow();
            assert_eq!(state.history.len(), 1);
            assert_eq!(state.history[0][16], 0x28);
            assert!(state.written.is_empty());
        }
    }
    #[test]
    fn lost_endpoint_readiness_fences_every_published_lun_before_dma_mutation() {
        use super::super::media::{Owner, scan_uas};
        use crate::block::BlockDevice;
        for streams in [None, Some(2)] {
            let mut memory = vec![0u64; 32 * 1024];
            let (raw, state) = target_owner(
                &mut memory,
                Target::new(vec![
                    Media::disk(Lun::default(), 1),
                    Media::disk(Lun::sequential(4), 4),
                ]),
                quirks::Flags::default(),
            );
            state.borrow_mut().streams = streams;
            let raw = Rc::try_unwrap(raw).ok().unwrap().into_inner();
            let owner = Rc::new(RefCell::new(Owner::new(raw, "uas".into(), "serial".into())));
            let mut disks = scan_uas(owner.clone(), &mut Vec::new()).unwrap();
            let before = {
                let owner = owner.borrow();
                let engine = &owner.transport.engine;
                (
                    engine.command.bytes().to_vec(),
                    engine.status.bytes().to_vec(),
                    engine.data.bytes().to_vec(),
                )
            };
            state.borrow_mut().fault = Fault::EndpointUnavailable;
            let events = state.borrow().events.len();
            assert!(disks[0].write(0, &[0xa5; 512]).is_err());
            assert!(disks[1].read(0, &mut [0; 512]).is_err());
            state.borrow_mut().fault = Fault::None;
            assert!(
                disks[0].flush().is_err(),
                "old owner revived after readiness recovered"
            );
            assert_eq!(state.borrow().events.len(), events);
            let owner = owner.borrow();
            let engine = &owner.transport.engine;
            assert!(engine.poisoned);
            assert_eq!(engine.command.bytes(), before.0);
            assert_eq!(engine.status.bytes(), before.1);
            assert_eq!(engine.data.bytes(), before.2);
        }
    }

    fn rw(input: bool, length: usize) -> [u8; 10] {
        let mut cdb = [0; 10];
        cdb[0] = if input { 0x28 } else { 0x2a };
        cdb[5] = 1;
        cdb[7..9].copy_from_slice(&((length / 512) as u16).to_be_bytes());
        cdb
    }
    #[test]
    fn real_ready_handshake_carries_lun_cdb_direction_and_actual_dma_bytes() {
        for input in [false, true] {
            for length in [512, 4096, MAX_TD] {
                let mut memory = vec![0u64; 32 * 1024];
                let (io, mut dma) = model(&mut memory, length, input, Fault::None);
                let state = io.state.clone();
                let mut engine = Engine::new(io, &mut dma).unwrap();
                let bytes = vec![0xa7; length];
                let lun = [0x40, 7, 0, 2, 0, 0, 0, 0];
                let cdb = rw(input, length);
                let result = engine
                    .command(
                        lun,
                        &cdb,
                        if input {
                            Data::In(length)
                        } else {
                            Data::Out(&bytes)
                        },
                    )
                    .unwrap();
                assert_eq!(
                    result,
                    if input {
                        vec![0x6d; length]
                    } else {
                        Vec::new()
                    }
                );
                let state = state.borrow();
                assert!(state.active.is_empty());
                assert_eq!(&state.command.as_ref().unwrap()[8..16], &lun);
                assert_eq!(&state.command.as_ref().unwrap()[16..26], &cdb);
                if !input {
                    assert_eq!(state.written, bytes);
                }
                assert_eq!(
                    &state.events[..2],
                    &[Event::Post(Pipe::Status), Event::Post(Pipe::Command)]
                );
                assert!(!engine.poisoned);
            }
        }
    }
    #[test]
    fn no_data_commands_need_real_terminal_status_and_complete_command_td() {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        engine.command([0; 8], &[0; 6], Data::None).unwrap();
        assert!(state.borrow().active.is_empty());
        assert_eq!(
            state
                .borrow()
                .events
                .iter()
                .filter(|e| matches!(e, Event::Post(_)))
                .count(),
            2
        );
    }
    #[test]
    fn invalid_ready_tag_status_or_command_length_quarantines_without_reusing_dma() {
        for fault in [
            Fault::WrongReady,
            Fault::WrongTag,
            Fault::MalformedStatus,
            Fault::ShortCommand,
            Fault::Timeout,
            Fault::SubmitStatus,
            Fault::SubmitCommand,
        ] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, true, fault);
            let state = io.state.clone();
            let mut engine = Engine::new(io, &mut dma).unwrap();
            assert!(
                engine
                    .command([0; 8], &rw(true, 512), Data::In(512))
                    .is_err(),
                "{fault:?}"
            );
            assert!(engine.poisoned);
            let events = state.borrow().events.len();
            let data = engine.data.bytes().to_vec();
            let status = engine.status.bytes().to_vec();
            assert!(
                engine
                    .command([0; 8], &rw(false, 512), Data::Out(&vec![0xff; 512]))
                    .is_err()
            );
            assert_eq!(state.borrow().events.len(), events);
            assert_eq!(engine.data.bytes(), data);
            assert_eq!(engine.status.bytes(), status);
        }
    }
    #[test]
    fn check_condition_drains_queued_data_and_reports_actual_sense() {
        for input in [false, true] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, input, Fault::ErrorAfterReady);
            let state = io.state.clone();
            let mut engine = Engine::new(io, &mut dma).unwrap();
            let outgoing = vec![0x55; 512];
            assert_eq!(
                engine.command(
                    [0; 8],
                    &rw(input, 512),
                    if input {
                        Data::In(512)
                    } else {
                        Data::Out(&outgoing)
                    }
                ),
                Err(BlockError::Sense(Sense {
                    key: 0x02,
                    asc: 0x3a,
                    ascq: 0x00
                }))
            );
            assert!(state.borrow().active.is_empty());
            assert!(state.borrow().events.contains(&Event::Cancel(if input {
                Pipe::Input
            } else {
                Pipe::Output
            })));
            assert!(!engine.poisoned);
        }
    }
    #[test]
    fn failed_error_path_cancellation_retains_poison_and_actual_pending_data() {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 512, true, Fault::CancelError);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        assert!(
            engine
                .command([0; 8], &rw(true, 512), Data::In(512))
                .is_err()
        );
        assert!(engine.poisoned);
        assert!(state.borrow().active.iter().any(|t| t.pipe == Pipe::Input));
    }
    #[test]
    fn short_write_is_an_error_and_short_read_reports_only_received_bytes() {
        for input in [false, true] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, input, Fault::ShortData);
            let mut engine = Engine::new(io, &mut dma).unwrap();
            let bytes = vec![0xa5; 512];
            let result = engine.command(
                [0; 8],
                &rw(input, 512),
                if input {
                    Data::In(512)
                } else {
                    Data::Out(&bytes)
                },
            );
            if input {
                assert_eq!(result.unwrap(), vec![0x6d; 511]);
            } else {
                assert!(result.is_err());
            }
            assert!(!engine.poisoned);
        }
    }
    #[test]
    fn zero_empty_and_oversized_cdb_or_data_never_submit_work() {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        for (cdb, n) in [(vec![], 0), (vec![0; 261], 0), (vec![0; 6], MAX_TD + 1)] {
            assert!(engine.command([0; 8], &cdb, Data::In(n)).is_err());
        }
        assert!(state.borrow().events.is_empty());
    }
    #[test]
    fn command_extension_padding_and_status_lengths_are_bounded() {
        for length in [1, 6, 10, 16, 17, 31, 32, 255, 260] {
            let bytes = command_iu(0x1234, [0xa5; 8], &vec![0x6d; length]);
            let extra = length.saturating_sub(16).next_multiple_of(4);
            assert_eq!(bytes.len(), 32 + extra);
            assert_eq!(usize::from(bytes[6]), extra);
            assert!(bytes[16 + length..].iter().all(|b| *b == 0));
        }
        for bytes in [
            vec![],
            vec![STATUS_IU, 0, 0],
            vec![STATUS_IU, 0, 0, 1],
            vec![READ_READY_IU, 0, 0, 2],
            vec![STATUS_IU; 16],
        ] {
            assert!(status_iu(&bytes, 1).is_none());
        }
        let response = [RESPONSE_IU, 0, 0, 1, 0, 0, 0, 8];
        let Frame::Done(status) = status_iu(&response, 1).unwrap() else {
            panic!()
        };
        assert_eq!(status.code, 0);
        assert_eq!(status.response, Some(8));
        // Disagreeing sense lengths clamp to the transfer, as Linux uas_sense does.
        let mut sense = vec![STATUS_IU, 0, 0, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 40];
        sense.extend([0x70, 0, 6]);
        let Frame::Done(status) = status_iu(&sense, 1).unwrap() else {
            panic!()
        };
        assert_eq!(
            (status.code, status.sense.as_slice()),
            (2, &[0x70, 0, 6][..])
        );
        sense[15] = 1;
        let Frame::Done(status) = status_iu(&sense, 1).unwrap() else {
            panic!()
        };
        assert_eq!(status.sense, [0x70]);
    }
    #[test]
    fn terminal_status_before_data_completion_still_waits_for_actual_data() {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 512, true, Fault::StatusBeforeData);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        assert_eq!(
            engine
                .command([0; 8], &rw(true, 512), Data::In(512))
                .unwrap(),
            vec![0x6d; 512]
        );
        let state = state.borrow();
        let last_status = state
            .events
            .iter()
            .rposition(|e| *e == Event::Complete(Pipe::Status))
            .unwrap();
        let data = state
            .events
            .iter()
            .position(|e| *e == Event::Complete(Pipe::Input))
            .unwrap();
        assert!(last_status < data);
        assert!(state.active.is_empty());
    }
    #[test]
    fn always_sync_writes_are_not_followed_by_a_cache_flush_like_linux() {
        for (op, action) in [(0x2a, None), (0x8a, None), (0x7f, Some(0x0b))] {
            let mut memory = vec![0u64; 32 * 1024];
            let (io, mut dma) = model(&mut memory, 512, false, Fault::None);
            let state = io.state.clone();
            let mut engine = Engine::new(io, &mut dma).unwrap();
            execute(
                &mut engine,
                quirks::Flags::from_id(0x4971, 0x8024, 0),
                [0; 8],
                &write_form(op, action, false),
                Data::Out(&[0xa5; 512]),
            )
            .unwrap();
            let state = state.borrow();
            assert_eq!(state.history.len(), 1);
            assert_eq!(state.written, vec![0xa5; 512]);
        }
    }
    #[test]
    fn enclosure_restrictions_fail_before_dma_or_native_submission() {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        assert!(
            execute(
                &mut engine,
                quirks::Flags::from_id(0x0bc2, 0, 0),
                [0; 8],
                &[0x85; 16],
                Data::None
            )
            .is_err()
        );
        assert!(state.borrow().events.is_empty());
        assert_eq!(engine.tag, 0);
    }
    #[test]
    #[ignore = "requires STELA_USB_UAS_RECOVERY_ORACLE from pinned uas.c and sd.c"]
    fn unchanged_linux_uas_reset_order_and_block_zero_cdb_match() {
        extern crate std;
        let trace = std::fs::read(
            std::env::var("STELA_USB_UAS_RECOVERY_ORACLE").expect("UAS recovery oracle trace"),
        )
        .unwrap();
        assert_eq!(&trace[..8], b"UASRCV01");
        let mut at = 8;
        for lock_failure in [0, 1] {
            for reset_failure in [0, 1] {
                let header = &trace[at..at + 4];
                at += 4;
                assert_eq!(&header[..2], &[lock_failure, reset_failure]);
                assert_eq!(header[2], u8::from(lock_failure != 0 || reset_failure != 0));
                let events = &trace[at..at + usize::from(header[3])];
                at += events.len();
                assert_eq!(
                    events,
                    if lock_failure != 0 {
                        &b"L"[..]
                    } else {
                        &b"LCSDZRU"[..]
                    }
                );
            }
        }
        for block_size in [512usize, 4096, MAX_TD] {
            for long_cdb in [false, true] {
                let bytes = u32::from_le_bytes(trace[at..at + 4].try_into().unwrap()) as usize;
                assert_eq!(bytes, block_size);
                assert_eq!(trace[at + 4], u8::from(long_cdb));
                let cdb = &trace[at + 5..at + 21];
                at += 21;
                if long_cdb {
                    // The ordinary Stela block-zero path selects READ(10).
                    // Retain the donor's alternative bytes without claiming a
                    // production use_16_for_rw quirk that is not selected.
                    assert_eq!(cdb[0], 0x88);
                    assert_eq!(&cdb[10..14], &1u32.to_be_bytes());
                    continue;
                }
                let mut medium = Media::disk(Lun::default(), 0x7a);
                medium.block_size = block_size as u32;
                let mut memory = vec![0u64; 32 * 1024];
                let (owner, state) = target_owner(
                    &mut memory,
                    Target::new(vec![medium]),
                    quirks::Flags::default(),
                );
                let mut owner = owner.borrow_mut();
                read_block_zero(
                    &mut owner.engine,
                    quirks::Flags::default(),
                    [0; 8],
                    block_size,
                )
                .unwrap();
                assert_eq!(&state.borrow().history[0][16..32], cdb);
            }
        }
        assert_eq!(at, trace.len());
    }

    #[test]
    #[ignore = "requires pinned unchanged UAS builders and enclosure table"]
    fn unchanged_linux_uas_builders_and_enclosure_rows_match() {
        extern crate std;
        fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> &'a [u8] {
            let result = &bytes[*at..*at + n];
            *at += n;
            result
        }
        fn u16le(bytes: &[u8], at: &mut usize) -> u16 {
            u16::from_le_bytes(take(bytes, at, 2).try_into().unwrap())
        }
        let bytes =
            std::fs::read(std::env::var("STELA_USB_UAS_ORACLE").expect("UAS oracle trace path"))
                .unwrap();
        let mut at = 0;
        assert_eq!(take(&bytes, &mut at, 8), b"UASRAW01");
        for _ in 0..288 {
            let tag = u16le(&bytes, &mut at);
            let length = usize::from(u16le(&bytes, &mut at));
            let lun = take(&bytes, &mut at, 8).try_into().unwrap();
            let wire = usize::from(u16le(&bytes, &mut at));
            let cdb = take(&bytes, &mut at, length);
            let expected = take(&bytes, &mut at, wire);
            assert_eq!(command_iu(tag, lun, cdb), expected);
        }
        assert_eq!(take(&bytes, &mut at, 8), b"POLICY24");
        for _ in 0..24 {
            let vendor = u16le(&bytes, &mut at);
            let product = u16le(&bytes, &mut at);
            let lo = u16le(&bytes, &mut at);
            let hi = u16le(&bytes, &mut at);
            let bits = take(&bytes, &mut at, 1)[0];
            for revision in [lo, hi] {
                assert_eq!(
                    quirks::Flags::from_id(vendor, product, revision).bits(),
                    bits | if vendor == 0x0bc2 { 16 } else { 0 }
                );
            }
        }
        assert_eq!(at, bytes.len());
    }
    fn write_form(op: u8, action: Option<u16>, fua: bool) -> Vec<u8> {
        let length = match op {
            0x2a | 0x2e => 10,
            0xaa | 0xae => 12,
            0x7f => 32,
            _ => 16,
        };
        let mut cdb = vec![0; length];
        cdb[0] = op;
        if op == 0x7f {
            cdb[7] = 24;
            cdb[8..10].copy_from_slice(&action.unwrap().to_be_bytes());
            cdb[10] = if fua { 8 } else { 0 };
            cdb[28..32].copy_from_slice(&1u32.to_be_bytes());
        } else {
            cdb[1] = if fua { 8 } else { 0 };
            match op {
                0x2a | 0x2e => cdb[7..9].copy_from_slice(&1u16.to_be_bytes()),
                0xaa | 0xae => cdb[6..10].copy_from_slice(&1u32.to_be_bytes()),
                0x9c => cdb[12..14].copy_from_slice(&1u16.to_be_bytes()),
                _ => cdb[10..14].copy_from_slice(&1u32.to_be_bytes()),
            };
        }
        cdb
    }
    #[test]
    fn mode_page_and_standard_alias_policies_reject_before_native_submission() {
        let mut memory = vec![0u64; 32 * 1024];
        let (io, mut dma) = model(&mut memory, 0, false, Fault::None);
        let state = io.state.clone();
        let mut engine = Engine::new(io, &mut dma).unwrap();
        let always = quirks::Flags::from_id(0x4971, 0x8024, 0);
        let broken = quirks::Flags::from_id(0x152d, 0x0578, 0);
        for op in [0x1a, 0x5a] {
            for page in [8, 0x3f] {
                for pc in [0, 0x40, 0x80, 0xc0] {
                    for dbd in [0, 8] {
                        let mut cdb = vec![0; if op == 0x1a { 6 } else { 10 }];
                        cdb[0] = op;
                        cdb[1] = dbd;
                        cdb[2] = page | pc;
                        assert!(execute(&mut engine, always, [0; 8], &cdb, Data::In(4)).is_err());
                    }
                }
            }
        }
        for op in [0x2a, 0x2e, 0xaa, 0xae, 0x8a, 0x8e, 0x9c] {
            assert!(
                execute(
                    &mut engine,
                    broken,
                    [0; 8],
                    &write_form(op, None, true),
                    Data::Out(&[0; 512])
                )
                .is_err()
            );
        }
        for action in [0x0b, 0x0c] {
            assert!(
                execute(
                    &mut engine,
                    broken,
                    [0; 8],
                    &write_form(0x7f, Some(action), true),
                    Data::Out(&[0; 512])
                )
                .is_err()
            );
        }
        assert!(
            execute(
                &mut engine,
                quirks::Flags::from_id(0x059f, 0x105f, 0),
                [0; 8],
                &write_form(0x7f, Some(0x0d), false),
                Data::Out(&[0; 512])
            )
            .is_err()
        );
        assert!(
            execute(
                &mut engine,
                quirks::Flags::from_id(0x0bc2, 0, 0),
                [0; 8],
                &write_form(0x7f, Some(0x1ff0), false),
                Data::None
            )
            .is_err()
        );
        assert!(state.borrow().events.is_empty());
        assert_eq!(engine.tag, 0);
        assert!(always.permits(&[0x1a, 0, 0, 0, 4, 0]));
    }
}
