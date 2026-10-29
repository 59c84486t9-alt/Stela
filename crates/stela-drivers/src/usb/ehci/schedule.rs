//! EHCI 1.0 sections3.5/3.6/4.8/4.10 and AppendixB descriptor machinery.
//! All CPU reads/writes below require schedule-stop + DMA-write drain.
use super::*;

pub(super) const FRAME_LIST: usize = 4096 + MAX_TRANSFER;
pub(super) const ARENA_BYTES: usize = FRAME_LIST + 4096;
const QH: usize = 0;
const QTD_BASE: usize = 128;
const QTD_BYTES: usize = 64;
const SETUP_BYTES: usize = 1024;
const PAYLOAD: usize = 4096;
const ACTIVE: u32 = 1 << 7;
const HALTED: u32 = 1 << 6;
const ERRORS: u32 = 0x7c; // HALT,DBE,BABBLE,XACT,MMF; never PING.
const TOGGLE: u32 = 1 << 31;
const PING: u32 = 1;
const PID_IN: u32 = 1 << 8;
const PID_SETUP: u32 = 2 << 8;
const TERMINATE: u32 = 1;
const CHUNK: usize = 16_384; // Page/packet aligned; at most4 of5 buffer pages.
const MAX_QTDS: usize = 6; // SETUP +4 data +STATUS.
const QH_CURRENT: usize = 12;
const QH_NEXT: usize = 16;
const QH_ALT: usize = 20;
const QH_TOKEN: usize = 24;
const QTD_TOKEN: usize = 8;

/// Encodes one qTD; memory publication remains the Arena owner's job.
/// Kept separate so the ignored unchanged Linux oracle compares precisely the
/// production arithmetic, without manufacturing a DMA mapping/attachment.
#[derive(Clone, Copy)]
pub(super) struct Qtd {
    pub(super) bytes: usize,
    pub(super) pid: u32,
    pub(super) toggle: bool,
    pub(super) next: u32,
    pub(super) alternate: u32,
}
impl Qtd {
    pub(super) fn encode(self, pointer: u64) -> Result<[u32; 13], Error> {
        if self.bytes > CHUNK || !matches!(self.pid, 0 | PID_IN | PID_SETUP) {
            return Err(Error::Invalid);
        }
        let mut words = [0; 13];
        words[0] = self.next;
        words[1] = self.alternate;
        words[2] = ((self.bytes as u32) << 16)
            | (3 << 10)
            | self.pid
            | ACTIVE
            | if self.toggle { TOGGLE } else { 0 };
        if self.bytes != 0 {
            let last = pointer
                .checked_add(self.bytes as u64 - 1)
                .ok_or(Error::Invalid)?;
            let pages = ((last >> 12) - (pointer >> 12) + 1) as usize;
            if pages > 5 {
                return Err(Error::Invalid);
            }
            for page in 0..pages {
                let address = if page == 0 {
                    pointer
                } else {
                    (pointer & !4095) + page as u64 * 4096
                };
                words[3 + page] = address as u32;
                words[8 + page] = (address >> 32) as u32;
            }
        }
        Ok(words)
    }
}

pub(super) struct Arena {
    pub(super) cpu: CpuMapping,
    pub(super) dma: DmaMapping,
    pub(super) address: u64,
}
impl Arena {
    pub(super) fn new(cpu: CpuMapping, mut dma: DmaMapping) -> Result<Self, Error> {
        let address = dma.address()?;
        if cpu.bytes() < ARENA_BYTES
            || dma.bytes() < ARENA_BYTES
            || !address.is_multiple_of(4096)
            || address
                .checked_add(ARENA_BYTES as u64 - 1)
                .is_none_or(|last| last >> 32 != address >> 32)
        {
            // Not published; this fresh mapping can be removed safely.
            // SAFETY: no EHCI register or descriptor has received this IOVA.
            unsafe {
                dma.unmap()?;
            }
            return Err(Error::Unsupported("EHCI schedule crosses4GiB segment"));
        }
        Ok(Self { cpu, dma, address })
    }
    pub(super) fn bytes(&self) -> usize {
        ARENA_BYTES
    }
    fn word(&self, offset: usize) -> Result<*mut u32, Error> {
        if !offset.is_multiple_of(4) {
            return Err(Error::Invalid);
        }
        let pointer = self.cpu.address(offset, 4)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::Invalid);
        }
        Ok(pointer.as_ptr().cast())
    }
    pub(super) fn read(&self, offset: usize) -> Result<u32, Error> {
        // SAFETY: caller stopped/drained DMA, kept CPU mapping bounds.
        Ok(u32::from_le(unsafe { self.word(offset)?.read_volatile() }))
    }
    pub(super) fn write(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        // SAFETY: caller owns exact stopped arena and checked aligned word.
        unsafe {
            self.word(offset)?.write_volatile(value.to_le());
        }
        Ok(())
    }
    fn clear(&mut self) -> Result<(), Error> {
        let pointer = self.cpu.address(0, ARENA_BYTES)?;
        // SAFETY: complete private arena stopped/drained, no references escape.
        unsafe {
            ptr::write_bytes(pointer.as_ptr(), 0, ARENA_BYTES);
        }
        Ok(())
    }
    fn copy_in(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let pointer = self.cpu.address(offset, bytes.len())?;
        // SAFETY: validated disjoint ordinary input and exclusively owned arena.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), pointer.as_ptr(), bytes.len());
        }
        Ok(())
    }
    fn copy_out(&self, offset: usize, bytes: usize) -> Result<Vec<u8>, Error> {
        let pointer = self.cpu.address(offset, bytes)?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(bytes)
            .map_err(|_| Error::Exhausted)?;
        result.resize(bytes, 0);
        // SAFETY: stable completed bytes in the stopped/drained private arena.
        unsafe {
            ptr::copy_nonoverlapping(pointer.as_ptr(), result.as_mut_ptr(), bytes);
        }
        Ok(result)
    }
    fn qtd_address(&self, index: usize) -> u32 {
        (self.address + (QTD_BASE + index * QTD_BYTES) as u64) as u32
    }
    fn token(&self, index: usize) -> Result<u32, Error> {
        let current = self.read(QH_CURRENT)? & !31;
        // A current partially executed descriptor's memory token may be stale.
        // The stopped QH overlay is the authoritative current qTD snapshot.
        self.read(if current == self.qtd_address(index) {
            QH_TOKEN
        } else {
            QTD_BASE + index * QTD_BYTES + QTD_TOKEN
        })
    }
    pub(super) fn qtd(
        &mut self,
        index: usize,
        offset: usize,
        descriptor: Qtd,
    ) -> Result<(), Error> {
        if index >= MAX_QTDS
            || offset
                .checked_add(descriptor.bytes)
                .is_none_or(|end| end > ARENA_BYTES)
        {
            return Err(Error::Invalid);
        }
        let words = descriptor.encode(self.address + offset as u64)?;
        let base = QTD_BASE + index * QTD_BYTES;
        for (word, value) in words.into_iter().enumerate() {
            self.write(base + word * 4, value)?;
        }
        Ok(())
    }
    fn qh(
        &mut self,
        address: u8,
        endpoint: u8,
        control: bool,
        toggle: bool,
        ping: bool,
        periodic: Option<periodic::Recipe>,
    ) -> Result<(), Error> {
        self.write(
            QH,
            if periodic.is_some() {
                TERMINATE
            } else {
                self.address as u32 | 2
            },
        )?;
        let packet = periodic.map_or(if control { 64 } else { 512 }, |recipe| {
            u32::from(recipe.packet)
        });
        self.write(
            4,
            u32::from(address)
                | (u32::from(endpoint & 15) << 8)
                | (2 << 12)
                | if control { 1 << 14 } else { 0 }
                | if periodic.is_none() { 1 << 15 } else { 0 }
                | (packet << 16)
                | if periodic.is_none() { 4 << 28 } else { 0 },
        )?;
        self.write(8, periodic.map_or(1 << 30, |recipe| recipe.info()))?;
        if let Some(recipe) = periodic {
            for frame in 0..1024 {
                self.write(
                    FRAME_LIST + frame * 4,
                    if frame % recipe.frames() == 0 {
                        self.address as u32 | 2
                    } else {
                        TERMINATE
                    },
                )?;
            }
        }
        self.write(QH_NEXT, self.qtd_address(0))?;
        self.write(QH_ALT, TERMINATE)?;
        self.write(
            QH_TOKEN,
            if toggle { TOGGLE } else { 0 } | if ping { PING } else { 0 },
        )
    }
}

pub(super) struct Pending {
    device: DeviceId,
    serial: u64,
    endpoint: Option<u8>,
    input: bool,
    lengths: [usize; MAX_QTDS],
    count: usize,
    data_start: usize,
    data_count: usize,
    started: u64,
    timeout: u64,
    periodic: Option<periodic::Recipe>,
}
impl Pending {
    pub(super) fn is_periodic(&self) -> bool {
        self.periodic.is_some()
    }
    pub(super) fn root_port(&self) -> u8 {
        self.device.port
    }
    fn completion(&self, arena: &Arena) -> Result<Option<usize>, Error> {
        let overlay = arena.read(QH_TOKEN)?;
        if overlay & ERRORS != 0 {
            return Err(Error::Device(overlay));
        }
        let mut actual = 0;
        let mut short = false;
        for index in 0..self.count {
            let data = index >= self.data_start && index < self.data_start + self.data_count;
            if data && short {
                continue;
            } // Alternate skipped remaining IN data qTDs.
            let token = arena.token(index)?;
            if token & ERRORS != 0 {
                return Err(Error::Device(token));
            }
            if token & ACTIVE != 0 {
                return Ok(None);
            }
            let residual = ((token >> 16) & 0x7fff) as usize;
            if residual > self.lengths[index] {
                return Err(Error::Device(token));
            }
            if data {
                actual += self.lengths[index] - residual;
                if residual != 0 {
                    if !self.input {
                        return Err(Error::Device(token));
                    }
                    short = true;
                }
            } else if residual != 0 {
                return Err(Error::Device(token));
            }
        }
        Ok(Some(actual))
    }
}

impl Controller {
    pub(super) fn start(
        &mut self,
        id: &DeviceId,
        endpoint: Option<u8>,
        setup: Option<[u8; 8]>,
        data: &[u8],
        input_bytes: usize,
        timeout: u64,
    ) -> Result<TransferId, Error> {
        let index = self.live(id)?;
        if self.pending.is_some() {
            return Err(Error::Busy);
        }
        let bytes = if input_bytes != 0 {
            input_bytes
        } else {
            data.len()
        };
        if bytes > MAX_TRANSFER || timeout == 0 || timeout > 30_000_000 {
            return Err(Error::Invalid);
        }
        let serial = self.next_transfer.checked_add(1).ok_or(Error::Exhausted)?;
        let device = self.ports[index].as_ref().expect("live");
        let address = device.address;
        let (toggle, ping, periodic) = if let Some(endpoint) = endpoint {
            let ep = device.endpoints[endpoint_index(endpoint)].ok_or(Error::Stale)?;
            if ep.halted {
                return Err(Error::Device(HALTED));
            }
            if ep.periodic.is_some_and(|recipe| bytes > recipe.payload()) {
                return Err(Error::Unsupported(
                    "EHCI interrupt exceeds one service payload",
                ));
            }
            (ep.toggle, ep.ping, ep.periodic)
        } else {
            (false, false, None)
        };
        let result = self.schedule_off();
        self.guard(result)?;
        let input = setup.map_or_else(
            || endpoint.is_some_and(|endpoint| endpoint & 0x80 != 0),
            |setup| setup[0] & 0x80 != 0 && bytes != 0,
        );
        let control = setup.is_some();
        let chunks = if bytes == 0 {
            usize::from(!control)
        } else {
            bytes.div_ceil(CHUNK)
        };
        let data_start = usize::from(control);
        let count = chunks + if control { 2 } else { 0 };
        let mut pending = Pending {
            device: id.clone(),
            serial,
            endpoint,
            input,
            lengths: [0; MAX_QTDS],
            count,
            data_start,
            data_count: chunks,
            started: self.hw().now_us(),
            timeout,
            periodic,
        };
        let build = (|| {
            let arena = self.arena.as_mut().ok_or(Error::Invalid)?;
            arena.clear()?;
            arena.qh(
                address,
                endpoint.unwrap_or(0),
                control,
                toggle,
                ping,
                periodic,
            )?;
            if let Some(setup) = setup {
                arena.copy_in(SETUP_BYTES, &setup)?;
                pending.lengths[0] = 8;
                arena.qtd(
                    0,
                    SETUP_BYTES,
                    Qtd {
                        bytes: 8,
                        pid: PID_SETUP,
                        toggle: false,
                        next: arena.qtd_address(1),
                        alternate: TERMINATE,
                    },
                )?;
            }
            if !input {
                arena.copy_in(PAYLOAD, data)?;
            }
            let status_index = count - 1;
            for chunk in 0..chunks {
                let td = data_start + chunk;
                let len = bytes.saturating_sub(chunk * CHUNK).min(CHUNK);
                pending.lengths[td] = len;
                let next = if td + 1 < count {
                    arena.qtd_address(td + 1)
                } else {
                    TERMINATE
                };
                let alternate = if control && input {
                    arena.qtd_address(status_index)
                } else {
                    TERMINATE
                };
                // Control DATA1 first; every intermediate16K qTD is an even
                // number of64-byte packets, so subsequent starts remain DATA1.
                arena.qtd(
                    td,
                    PAYLOAD + chunk * CHUNK,
                    Qtd {
                        bytes: len,
                        pid: if input { PID_IN } else { 0 },
                        toggle: control,
                        next,
                        alternate,
                    },
                )?;
            }
            if control {
                // No-data control STATUS is always IN, regardless request bit.
                let status_pid = if bytes == 0 || !input { PID_IN } else { 0 };
                arena.qtd(
                    status_index,
                    0,
                    Qtd {
                        bytes: 0,
                        pid: status_pid,
                        toggle: true,
                        next: TERMINATE,
                        alternate: TERMINATE,
                    },
                )?;
            }
            Ok(())
        })();
        self.guard(build)?;
        self.next_transfer = serial;
        self.pending = Some(pending); // Keep owners before publication.
        let result = self.schedule_on();
        self.guard(result)?;
        Ok(TransferId {
            device: id.clone(),
            serial,
        })
    }
    fn ticket(&self, ticket: &TransferId) -> Result<(), Error> {
        self.identity(&ticket.device)?;
        let pending = self.pending.as_ref().ok_or(Error::Stale)?;
        if pending.serial != ticket.serial
            || pending.device.generation != ticket.device.generation
            || pending.device.port != ticket.device.port
        {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn save_toggle(&mut self) -> Result<(), Error> {
        let pending = self.pending.as_ref().ok_or(Error::Stale)?;
        if let Some(endpoint) = pending.endpoint {
            let index = self.identity(&pending.device)?;
            let token = self.arena.as_ref().ok_or(Error::Invalid)?.read(QH_TOKEN)?;
            let ep = self.ports[index].as_mut().expect("live").endpoints[endpoint_index(endpoint)]
                .as_mut()
                .ok_or(Error::Stale)?;
            ep.toggle = token & TOGGLE != 0;
            ep.ping = token & PING != 0;
            ep.halted |= token & ERRORS != 0;
        }
        Ok(())
    }
    /// Poll the exact transfer. Each poll returns DMA ownership only
    /// after ASS0/PSS0 and requester drain, and resumes unchanged partial overlays.
    pub fn poll(&mut self, ticket: &TransferId) -> Result<Option<Completion>, Error> {
        self.ticket(ticket)?;
        self.live(&ticket.device)?;
        let result = self.schedule_off();
        self.guard(result)?;
        let status = self
            .pending
            .as_ref()
            .expect("retained")
            .completion(self.arena.as_ref().expect("retained"));
        match status {
            Ok(Some(actual)) => {
                let result = self.save_toggle();
                self.guard(result)?;
                let input = self.pending.as_ref().expect("retained").input;
                let result = if input {
                    self.arena
                        .as_ref()
                        .expect("retained")
                        .copy_out(PAYLOAD, actual)
                } else {
                    Ok(Vec::new())
                };
                let data = self.guard(result)?;
                self.pending = None;
                Ok(Some(Completion { actual, data }))
            }
            Ok(None) => {
                let pending = self.pending.as_ref().expect("retained");
                let (started, timeout) = (pending.started, pending.timeout);
                if self.hw().now_us().wrapping_sub(started) >= timeout {
                    return self.fail(Error::Timeout);
                }
                let result = self.schedule_on();
                self.guard(result)?;
                Ok(None)
            }
            Err(Error::Device(token))
                if token & ERRORS == HALTED
                    && self.pending.as_ref().expect("retained").endpoint.is_some() =>
            {
                // Pure bulk STALL: schedule proved stopped. Preserve exact
                // endpoint halt; only successful clear_halt reopens it.
                let result = self.save_toggle();
                self.guard(result)?;
                self.pending = None;
                Err(Error::Device(token))
            }
            Err(error) => self.fail(error),
        }
    }
    /// Cancel only this TD. No payload is copied from an incomplete TD.
    pub fn cancel(&mut self, ticket: &TransferId) -> Result<(), Error> {
        self.ticket(ticket)?;
        self.live(&ticket.device)?;
        let result = self.schedule_off();
        self.guard(result)?;
        let token = self.arena.as_ref().ok_or(Error::Invalid)?.read(QH_TOKEN)?;
        if token & ERRORS != 0 && token & ERRORS != HALTED {
            return self.fail(Error::Device(token));
        }
        let result = self.save_toggle();
        self.guard(result)?;
        self.pending = None;
        Ok(())
    }
    pub(super) fn control_internal(
        &mut self,
        id: &DeviceId,
        setup: [u8; 8],
        data: &[u8],
        input_bytes: usize,
    ) -> Result<Vec<u8>, Error> {
        let expected = usize::from(u16::from_le_bytes([setup[6], setup[7]]));
        if expected != input_bytes + data.len()
            || (expected != 0 && ((setup[0] & 0x80 != 0) != (input_bytes != 0)))
        {
            return Err(Error::Invalid);
        }
        let ticket = self.start(id, None, Some(setup), data, input_bytes, 5_000_000)?;
        loop {
            if let Some(completion) = self.poll(&ticket)? {
                return Ok(completion.data);
            }
            self.hw().pause();
        }
    }
    fn pipe(&self, pipe: &BulkPipe) -> Result<usize, Error> {
        let index = self.identity(&pipe.device)?;
        let device = self.ports[index].as_ref().expect("validated");
        if device.configuration != pipe.configuration
            || device.endpoints[endpoint_index(pipe.endpoint)]
                .is_none_or(|ep| ep.periodic.is_some())
        {
            return Err(Error::Stale);
        }
        Ok(index)
    }
    pub fn submit_bulk_in(
        &mut self,
        pipe: &BulkPipe,
        bytes: usize,
        timeout_us: u64,
    ) -> Result<TransferId, Error> {
        self.pipe(pipe)?;
        if pipe.endpoint & 0x80 == 0 {
            return Err(Error::Invalid);
        }
        self.start(
            &pipe.device,
            Some(pipe.endpoint),
            None,
            &[],
            bytes,
            timeout_us,
        )
    }
    pub fn submit_bulk_out(
        &mut self,
        pipe: &BulkPipe,
        data: &[u8],
        timeout_us: u64,
    ) -> Result<TransferId, Error> {
        self.pipe(pipe)?;
        if pipe.endpoint & 0x80 != 0 {
            return Err(Error::Invalid);
        }
        self.start(&pipe.device, Some(pipe.endpoint), None, data, 0, timeout_us)
    }
    /// Clear this exact bulk halt with USB CLEAR_FEATURE STATUS ACK. No local
    /// toggle mutation occurs on failed control transfer or stale pipe.
    pub fn clear_halt(&mut self, pipe: &BulkPipe) -> Result<(), Error> {
        let index = self.pipe(pipe)?;
        self.control_internal(&pipe.device, [2, 1, 0, 0, pipe.endpoint, 0, 0, 0], &[], 0)?;
        self.ports[index].as_mut().expect("live").endpoints[endpoint_index(pipe.endpoint)] =
            Some(Endpoint {
                toggle: false,
                ping: false,
                halted: false,
                periodic: None,
            });
        Ok(())
    }
}
pub(super) fn endpoint_index(endpoint: u8) -> usize {
    usize::from(endpoint & 15) + if endpoint & 0x80 != 0 { 16 } else { 0 }
}
