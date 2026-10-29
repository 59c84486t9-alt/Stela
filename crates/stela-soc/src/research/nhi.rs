//! Programmed NHI DMA rings, independently of a host router implementation.
//!
//! Original Apple ring writers use sixteen-byte descriptors, POSTED bit22,
//! COMPLETED bit21 and interrupt-request bit23. The ACIO register layout and
//! native-frame boundary are documented in `docs/research/usb4-acio.md`.
//! A required [`Consumer`] owns router/wire protocol, framing, CRC,
//! E2E/isochronous behavior and notifications. No successful consumer, router
//! capability template, CIO readiness or machine admission is supplied here.
//! DMA completion is a separate phase so a fault cannot replay an
//! already accepted frame. Payload and timestamp precede completion ownership.
use crate::Result;
use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};
pub use ring::Direction;
use ring::{Descriptor, Ring, Transfer};
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction as AccessDirection,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};
use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::Wire};
pub mod control;
mod ring;
pub mod router;

const NAME: &str = "nhi";
const ENABLE: u32 = 1 << 31;
const RAW: u32 = 1 << 30;
const NO_SNOOP: u32 = 1 << 29;
const E2E: u32 = 1 << 28;
const ISOCH: u32 = 1 << 27;
const E2E_HOP: u32 = 0x7ff << 12;
const QUANTUM: usize = 64;
/// Logical base of the separately mapped PDF-register DeviceTree view.
pub const PDF_VIEW: u64 = 0x10_0000;
/// The ACIO NHI register aperture, independently of its physical placement.
pub const REGISTER_BYTES: u64 = 0x10_0000;

#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub tx: u64,
    pub rx: u64,
    pub stride: u64,
    pub status: u64,
    pub interrupt_enable: u64,
    pub throttle: u64,
}
impl Layout {
    /// Hardware layout recovered from HALGenericACIO, not a chip-name check.
    pub const ACIO: Self = Self {
        tx: 0x10000,
        rx: 0x80000,
        stride: 0x4000,
        status: 0xd0000,
        interrupt_enable: 0xd0010,
        throttle: 0xd004c,
    };
}

/// Capabilities supplied by the owning hardware profile. This module does
/// not infer generation, revision or capability bits from a board name.
pub struct Profile {
    pub layout: Layout,
    pub capability_words: [u32; 2],
    pub shared_tx_buffers: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub raw: bool,
    pub no_snoop: bool,
    pub e2e: bool,
    pub isochronous: bool,
    pub e2e_tx_hop: u16,
    pub parameter: u32,
    pub pdf: u32,
    pub receive_capacity: usize,
}

/// A completed native NHI frame, including receive error/time effects.
/// The consumer must implement CRC/PDF assembly according to its configured
/// options; setting `crc_error` is a result, not an instruction to skip CRC.
#[derive(Debug, Clone)]
pub struct Frame {
    hop: usize,
    bytes: Vec<u8>,
    sof: u8,
    eof: u8,
    timestamp: u32,
    crc_error: bool,
}
impl Frame {
    pub fn new(
        hop: usize,
        bytes: Vec<u8>,
        sof: u8,
        eof: u8,
        timestamp: u32,
        crc_error: bool,
    ) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 4096 || sof > 15 || eof > 15 {
            return Err(refuse!(
                "NHI native frame length or PDF is outside its wire encoding"
            ));
        }
        Ok(Self {
            hop,
            bytes,
            sof,
            eof,
            timestamp,
            crc_error,
        })
    }
}

/// A transmit presented once to the real native router/wire owner. Raw mode,
/// isochronous scheduling and PDF values keep their programmed meanings.
pub struct Transmit<'a> {
    pub hop: usize,
    pub bytes: &'a [u8],
    pub sof: u8,
    pub eof: u8,
    pub isochronous: bool,
    pub scheduled_time: u32,
    pub now: u64,
    pub options: Options,
    /// Posted receive slots available to the peer, indexed by receive HopID.
    pub receive_credits: &'a [usize],
}

pub struct Accepted {
    pub timestamp: u32,
    pub incoming: Vec<Frame>,
}

/// Required native protocol owner. Refusals must validate before committing
/// effects. Configuration must implement every requested mode or refuse it;
/// raw/E2E/isochronous/no-snoop fields are never successful held placeholders.
/// Incoming frames must obey the active PDF/CRC framing contract and consume
/// at most the supplied receive credits. The peer keeps wire traffic under
/// backpressure; this boundary does not invent an unbounded hardware FIFO.
pub trait Consumer {
    fn configure(
        &mut self,
        hop: usize,
        direction: Direction,
        options: Option<Options>,
    ) -> Result<()>;
    /// `None` applies real peer backpressure without consuming the frame or
    /// changing protocol state. A later poll/deadline may make it ready.
    fn transmit(&mut self, frame: Transmit<'_>) -> Result<Option<Accepted>>;
    fn poll(&mut self, now: u64, receive_credits: &[usize]) -> Result<(Vec<Frame>, Option<u64>)>;
    fn reset(&mut self) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Dma(DmaError),
    Unsupported(Refusal),
}
impl From<DmaError> for Error {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}
impl From<Refusal> for Error {
    fn from(reason: Refusal) -> Self {
        Self::Unsupported(reason)
    }
}

pub struct Nhi {
    profile: Profile,
    consumer: Box<dyn Consumer>,
    tx: Vec<Ring>,
    rx: Vec<Ring>,
    lines: Vec<AicInput>,
    pending: u32,
    enabled: u32,
    asserted: Vec<bool>,
    throttle: Vec<u16>,
    last_raised: Vec<Option<u64>>,
    powered: bool,
    cursor: usize,
    terminal: Option<Refusal>,
}
impl Nhi {
    pub fn new(
        profile: Profile,
        tx: Vec<AicInput>,
        rx: Vec<AicInput>,
        consumer: Box<dyn Consumer>,
    ) -> Result<Self> {
        let count = tx.len();
        if count == 0
            || count > 16
            || rx.len() != count
            || profile.capability_words[0] & 0x3ff != count as u32
        {
            return Err(refuse!("NHI capability/IRQ ring count is inconsistent"));
        }
        let l = profile.layout;
        let mut ranges = vec![
            (0, 8),
            (l.status, 4),
            (l.interrupt_enable, 4),
            (l.throttle, count as u64 * 8),
        ];
        if l.stride < 24 || l.stride & 3 != 0 || profile.shared_tx_buffers == 0 {
            return Err(refuse!(
                "NHI layout or shared transmit buffer budget is invalid"
            ));
        }
        for base in [l.tx, l.rx] {
            for hop in 0..count {
                ranges.push((
                    base.checked_add(
                        l.stride
                            .checked_mul(hop as u64)
                            .ok_or(refuse!("NHI layout overflow"))?,
                    )
                    .ok_or(refuse!("NHI layout overflow"))?,
                    24,
                ));
            }
        }
        ranges.sort_unstable();
        let mut end = 0;
        for (base, bytes) in ranges {
            if base & 3 != 0 || base < end {
                return Err(refuse!("NHI layout overlaps or is unaligned"));
            }
            end = base
                .checked_add(bytes)
                .ok_or(refuse!("NHI layout overflow"))?;
            if end > REGISTER_BYTES {
                return Err(refuse!("NHI layout exceeds its aperture"));
            }
        }
        let lines: Vec<_> = tx.into_iter().chain(rx).collect();
        if lines.iter().copied().collect::<BTreeSet<_>>().len() != lines.len() {
            return Err(refuse!("NHI dedicated interrupts alias"));
        }
        Ok(Self {
            profile,
            consumer,
            tx: (0..count).map(|_| Ring::new()).collect(),
            rx: (0..count).map(|_| Ring::new()).collect(),
            pending: 0,
            enabled: 0,
            asserted: vec![false; lines.len()],
            throttle: vec![0; lines.len()],
            last_raised: vec![None; lines.len()],
            lines,
            powered: false,
            cursor: 0,
            terminal: None,
        })
    }
    /// Physical power input from the owning ACIO complex. Power-on is not CIO
    /// readiness. A power cut resets the native owner before losing rings.
    pub fn set_powered(&mut self, powered: bool, access: &mut Access<'_>) -> Result<()> {
        if self.powered && !powered {
            self.reset(access)?;
        }
        self.powered = powered;
        self.update_lines(access);
        Ok(())
    }
    pub fn reset(&mut self, access: &mut Access<'_>) -> Result<()> {
        self.consumer.reset()?;
        for ring in self.tx.iter_mut().chain(&mut self.rx) {
            *ring = Ring::new();
        }
        self.pending = 0;
        self.enabled = 0;
        self.throttle.fill(0);
        self.last_raised.fill(None);
        self.cursor = 0;
        self.terminal = None;
        self.update_lines(access);
        Ok(())
    }
    fn rings(&self, direction: Direction) -> &[Ring] {
        match direction {
            Direction::Transmit => &self.tx,
            Direction::Receive => &self.rx,
        }
    }
    fn rings_mut(&mut self, direction: Direction) -> &mut [Ring] {
        match direction {
            Direction::Transmit => &mut self.tx,
            Direction::Receive => &mut self.rx,
        }
    }
    fn line(&self, direction: Direction, hop: usize) -> usize {
        hop + if direction == Direction::Receive {
            self.tx.len()
        } else {
            0
        }
    }
    fn throttle_ticks(&self, index: usize) -> u64 {
        (u64::from(self.throttle[index]) * 768).div_ceil(125)
    }
    fn update_lines(&mut self, access: &mut Access<'_>) -> Option<u64> {
        let mut next = None;
        for index in 0..self.lines.len() {
            let pending = self.powered && self.pending & self.enabled & (1 << index) != 0;
            let deadline =
                self.last_raised[index].map(|last| last.saturating_add(self.throttle_ticks(index)));
            let level =
                pending && (self.asserted[index] || deadline.is_none_or(|due| access.now >= due));
            if pending
                && !level
                && let Some(due) = deadline
            {
                next = Some(next.map_or(due, |old: u64| old.min(due)));
            }
            if level != self.asserted[index] {
                self.asserted[index] = level;
                if level {
                    self.last_raised[index] = Some(access.now);
                }
                access
                    .interrupts
                    .set_level(Wire::Aic(self.lines[index]), level);
            }
        }
        next
    }
    fn receive_credits(&self) -> Vec<usize> {
        self.rx
            .iter()
            .map(|ring| {
                if ring.active.is_none() {
                    return 0;
                }
                let posted = (usize::from(ring.posted) + usize::from(ring.count)
                    - usize::from(ring.consumed))
                    % usize::from(ring.count);
                posted.saturating_sub(ring.incoming.len())
            })
            .collect()
    }
    fn enqueue(&mut self, frames: Vec<Frame>) -> Result<()> {
        let mut credits = self.receive_credits();
        for frame in &frames {
            if let Some(credit) = credits.get_mut(frame.hop).filter(|credit| **credit != 0) {
                *credit -= 1;
            } else {
                let reason = "native NHI consumer returned a frame without posted receive credit";
                self.terminal = Some(reason.into());
                return Err(reason.into());
            }
        }
        for frame in frames {
            self.rx[frame.hop].incoming.push_back(frame);
        }
        Ok(())
    }
    pub fn dma_pending(&self) -> bool {
        self.powered
            && self.terminal.is_none()
            && (self
                .tx
                .iter()
                .any(|r| r.transfer.is_some() || r.has_posted())
                || self
                    .rx
                    .iter()
                    .any(|r| r.transfer.is_some() || r.has_posted() && !r.incoming.is_empty()))
    }
    /// At most one bounded quantum per call. A returned IOMMU fault preserves
    /// the accepted-frame latch; fixing the mapping and retrying cannot send
    /// the same native frame twice. The IOMMU owns its fault-reporting effects.
    pub fn service_dma(&mut self, port: &mut Port<'_, '_>) -> Result<(), Error> {
        if !self.powered {
            return Err(refuse!("NHI DMA while powered off").into());
        }
        if let Some(reason) = &self.terminal {
            return Err(reason.clone().into());
        }
        let total = self.tx.len() * 2;
        let mut done = 0;
        let mut idle = 0;
        while done < QUANTUM && idle < total {
            let slot = self.cursor;
            self.cursor = (self.cursor + 1) % total;
            let direction = if slot < self.tx.len() {
                Direction::Transmit
            } else {
                Direction::Receive
            };
            let hop = slot % self.tx.len();
            if self.step(direction, hop, port)? {
                done += 1;
                idle = 0;
            } else {
                idle += 1;
            }
        }
        Ok(())
    }
    fn step(
        &mut self,
        direction: Direction,
        hop: usize,
        port: &mut Port<'_, '_>,
    ) -> Result<bool, Error> {
        let r = &self.rings(direction)[hop];
        if r.transfer.is_none() {
            if !r.has_posted() || direction == Direction::Receive && r.incoming.is_empty() {
                return Ok(false);
            }
            let address = r.address();
            let descriptor = Descriptor::read(port, address)?;
            descriptor.validate(direction)?;
            match direction {
                Direction::Transmit => {
                    let options = r.active.unwrap();
                    if descriptor.isochronous() && !options.isochronous {
                        return Err(
                            refuse!("NHI isochronous descriptor on an asynchronous ring").into(),
                        );
                    }
                    let mut bytes = vec![0; descriptor.length()];
                    port.read(descriptor.address, &mut bytes)?;
                    let receive_credits = self.receive_credits();
                    let Some(accepted) = self.consumer.transmit(Transmit {
                        hop,
                        bytes: &bytes,
                        sof: descriptor.sof(),
                        eof: descriptor.eof(),
                        isochronous: descriptor.isochronous(),
                        scheduled_time: descriptor.time,
                        now: port.access.now,
                        options,
                        receive_credits: &receive_credits,
                    })?
                    else {
                        return Ok(false);
                    };
                    self.tx[hop].transfer = Some(Transfer {
                        descriptor: address,
                        metadata: descriptor.tx_completion(),
                        timestamp: accepted.timestamp,
                        payload: None,
                        payload_written: true,
                    });
                    self.enqueue(accepted.incoming)?;
                }
                Direction::Receive => {
                    let frame = &r.incoming[0];
                    let options = r.active.unwrap();
                    if !options.raw
                        && (options.parameter & (1 << frame.eof) == 0
                            || options.parameter & (1 << (16 + frame.sof)) == 0)
                    {
                        return Err(
                            refuse!("native NHI frame violates configured PDF framing").into()
                        );
                    }
                    let length = frame.bytes.len().min(r.capacity());
                    let transfer = Transfer {
                        descriptor: address,
                        metadata: descriptor.rx_completion(frame, length),
                        timestamp: frame.timestamp,
                        payload: Some((descriptor.address, frame.bytes[..length].to_vec())),
                        payload_written: false,
                    };
                    self.rx[hop].transfer = Some(transfer);
                }
            }
        }
        let r = &mut self.rings_mut(direction)[hop];
        let transfer = r.transfer.as_mut().unwrap();
        transfer.publish(port)?;
        let interrupt = transfer.metadata & ring::INTERRUPT != 0;
        r.transfer = None;
        r.advance();
        if direction == Direction::Receive {
            r.incoming.pop_front();
        }
        if interrupt {
            self.pending |= 1 << self.line(direction, hop);
        }
        self.update_lines(port.access);
        Ok(true)
    }
    fn locate(&self, offset: u64) -> Option<(Direction, usize, u64)> {
        for (direction, base) in [
            (Direction::Transmit, self.profile.layout.tx),
            (Direction::Receive, self.profile.layout.rx),
        ] {
            let Some(delta) = offset.checked_sub(base) else {
                continue;
            };
            let hop = delta / self.profile.layout.stride;
            let field = delta % self.profile.layout.stride;
            if hop < self.tx.len() as u64 && field < 24 {
                return Some((direction, hop as usize, field));
            }
        }
        None
    }
    fn options(&self, direction: Direction, hop: usize, flags: u32) -> Result<Options> {
        let allowed = ENABLE
            | RAW
            | NO_SNOOP
            | E2E
            | if direction == Direction::Transmit {
                ISOCH
            } else {
                E2E_HOP
            };
        if flags & !allowed != 0 {
            return Err(refuse!("NHI ring option field without a model"));
        }
        let e2e_tx_hop = ((flags & E2E_HOP) >> 12) as u16;
        if direction == Direction::Receive
            && flags & E2E != 0
            && usize::from(e2e_tx_hop) >= self.tx.len()
        {
            return Err(refuse!("NHI E2E transmit HopID is outside the controller"));
        }
        let r = &self.rings(direction)[hop];
        Ok(Options {
            raw: flags & RAW != 0,
            no_snoop: flags & NO_SNOOP != 0,
            e2e: flags & E2E != 0,
            isochronous: flags & ISOCH != 0,
            e2e_tx_hop,
            parameter: r.parameter,
            pdf: r.pdf,
            receive_capacity: r.capacity(),
        })
    }
    fn flags(&mut self, direction: Direction, hop: usize, flags: u32) -> Result<()> {
        let options = self.options(direction, hop, flags)?;
        let r = &self.rings(direction)[hop];
        if r.active.is_some() && flags & ENABLE != 0 {
            return if r.flags == flags {
                Ok(())
            } else {
                Err(refuse!("NHI live ring reconfiguration requires disable"))
            };
        }
        if r.transfer.is_some() || !r.incoming.is_empty() {
            return Err(refuse!("NHI ring has an accepted frame in flight"));
        }
        let active = if flags & ENABLE != 0 {
            r.validate_configuration()?;
            if direction == Direction::Receive && !(1..=256).contains(&r.capacity) {
                return Err(refuse!(
                    "NHI receive maximum-frame-size encoding is not qualified"
                ));
            }
            if direction == Direction::Transmit {
                let used: u64 = self
                    .tx
                    .iter()
                    .enumerate()
                    .filter(|(i, r)| *i != hop && r.active.is_some())
                    .map(|(_, r)| u64::from(r.parameter))
                    .sum();
                if r.parameter == 0
                    || used + u64::from(r.parameter) > u64::from(self.profile.shared_tx_buffers)
                {
                    return Err(refuse!(
                        "NHI shared transmit buffer allocation exceeds its profile"
                    ));
                }
            }
            Some(options)
        } else {
            None
        };
        self.consumer.configure(hop, direction, active)?;
        let r = &mut self.rings_mut(direction)[hop];
        r.flags = flags;
        r.active = active;
        Ok(())
    }
    fn ring_read(&self, direction: Direction, hop: usize, field: u64, width: Width) -> Option<u64> {
        let r = &self.rings(direction)[hop];
        let indices = if direction == Direction::Transmit {
            u32::from(r.consumed) | u32::from(r.posted) << 16
        } else {
            u32::from(r.posted) | u32::from(r.consumed) << 16
        };
        Some(match (field, width) {
            (0, Width::Double) => r.base,
            (0, Width::Word) => r.base as u32 as u64,
            (4, Width::Word) => r.base >> 32,
            (8, Width::Word) => u64::from(indices),
            (8, Width::Half) => u64::from(indices as u16),
            (10, Width::Half) => u64::from(indices >> 16),
            (12, Width::Word) => u64::from(r.count) | u64::from(r.capacity) << 16,
            (12, Width::Half) => u64::from(r.count),
            (14, Width::Half) => u64::from(r.capacity),
            (16, Width::Word) => u64::from(r.flags),
            (20, Width::Word) => u64::from(r.parameter),
            _ => return None,
        })
    }
    fn ring_write(
        &mut self,
        direction: Direction,
        hop: usize,
        field: u64,
        width: Width,
        value: u64,
    ) -> Result<()> {
        if field == 16 && width == Width::Word {
            return self.flags(direction, hop, value as u32);
        }
        let r = &mut self.rings_mut(direction)[hop];
        if matches!(
            (field, width),
            (8, Width::Word | Width::Half) | (10, Width::Half)
        ) {
            let stopped = r.active.is_none();
            let (posted, consumed) = match (direction, field, width) {
                (Direction::Transmit, 8, Width::Word) => {
                    (Some((value >> 16) as u16), stopped.then_some(value as u16))
                }
                (Direction::Receive, 8, Width::Word) => {
                    (Some(value as u16), stopped.then_some((value >> 16) as u16))
                }
                (Direction::Transmit, 10, Width::Half) | (Direction::Receive, 8, Width::Half) => {
                    (Some(value as u16), None)
                }
                _ => (None, stopped.then_some(value as u16)),
            };
            // Ownership applies while the ring runs. Once stopped, software
            // initializes both indexes before enabling a replacement table.
            // Validate both word halves before changing either one.
            for index in posted.into_iter().chain(consumed) {
                if index >= r.count && !(index == 0 && r.count == 0) {
                    return Err(refuse!("NHI index is outside the descriptor ring"));
                }
            }
            if let Some(index) = posted {
                r.posted = index;
            }
            if let Some(index) = consumed {
                r.consumed = index;
            }
            return Ok(());
        }
        if r.active.is_some() || r.transfer.is_some() {
            return Err(refuse!(
                "NHI descriptor configuration requires a disabled ring"
            ));
        }
        match (field, width) {
            (0, Width::Double) => r.base = value,
            (0, Width::Word) => r.base = r.base & !0xffff_ffff | value,
            (4, Width::Word) => r.base = r.base as u32 as u64 | value << 32,
            (12, Width::Word) if direction == Direction::Receive || value >> 16 == 0 => {
                r.count = value as u16;
                r.capacity = (value >> 16) as u16;
            }
            (12, Width::Half) => r.count = value as u16,
            (14, Width::Half) if direction == Direction::Receive || value == 0 => {
                r.capacity = value as u16
            }
            (20, Width::Word) => r.parameter = value as u32,
            _ => return Err(refuse!("NHI ring register or width without a model")),
        }
        Ok(())
    }
}

impl MmioDevice for Nhi {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, AccessDirection::Read, reason);
        if !self.powered {
            return Err(fail(refuse!("NHI MMIO while powered off")));
        }
        if width == Width::Word {
            if offset == 0 || offset == 4 {
                return Ok(u64::from(
                    self.profile.capability_words[(offset / 4) as usize],
                ));
            }
            if offset == self.profile.layout.status {
                return Ok(u64::from(self.pending));
            }
            if offset == self.profile.layout.interrupt_enable {
                return Ok(u64::from(self.enabled));
            }
            if let Some(delta) = offset
                .checked_sub(self.profile.layout.throttle)
                .filter(|d| d.is_multiple_of(4) && d / 4 < self.lines.len() as u64)
            {
                return Ok(u64::from(self.throttle[(delta / 4) as usize]));
            }
            if let Some(delta) = offset.checked_sub(PDF_VIEW).filter(|d| {
                d.is_multiple_of(self.profile.layout.stride)
                    && d / self.profile.layout.stride < self.rx.len() as u64
            }) {
                return Ok(u64::from(
                    self.rx[(delta / self.profile.layout.stride) as usize].pdf,
                ));
            }
        }
        if let Some((direction, hop, field)) = self.locate(offset)
            && let Some(value) = self.ring_read(direction, hop, field, width)
        {
            return Ok(value);
        }
        Err(fail(refuse!("NHI register or width without a model")))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, AccessDirection::Write, reason);
        if !self.powered {
            return Err(fail(refuse!("NHI MMIO while powered off")));
        }
        if value & !width.mask() != 0 {
            return Err(fail(refuse!("NHI write exceeds the access width")));
        }
        let valid = if self.lines.len() == 32 {
            u32::MAX
        } else {
            (1u32 << self.lines.len()) - 1
        };
        if width == Width::Word
            && offset == self.profile.layout.status
            && value & !u64::from(valid) == 0
        {
            self.pending &= !(value as u32);
        } else if width == Width::Word
            && offset == self.profile.layout.interrupt_enable
            && value & !u64::from(valid) == 0
        {
            self.enabled = value as u32;
        } else if width == Width::Word
            && let Some(delta) = offset
                .checked_sub(self.profile.layout.throttle)
                .filter(|d| d.is_multiple_of(4) && d / 4 < self.lines.len() as u64)
        {
            self.throttle[(delta / 4) as usize] = u16::try_from(value)
                .map_err(|_| fail(refuse!("NHI throttle field without a model")))?;
        } else if width == Width::Word
            && let Some(delta) = offset.checked_sub(PDF_VIEW).filter(|d| {
                d.is_multiple_of(self.profile.layout.stride)
                    && d / self.profile.layout.stride < self.rx.len() as u64
            })
        {
            let r = &mut self.rx[(delta / self.profile.layout.stride) as usize];
            if r.active.is_some() && u64::from(r.pdf) != value {
                return Err(fail(refuse!(
                    "NHI live PDF reconfiguration requires disable"
                )));
            }
            r.pdf = value as u32;
        } else if let Some((direction, hop, field)) = self.locate(offset) {
            self.ring_write(direction, hop, field, width, value)
                .map_err(fail)?;
        } else {
            return Err(fail(refuse!(
                "NHI register, field or width without a model"
            )));
        }
        self.update_lines(access);
        Ok(())
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        if !self.powered {
            return Ok(None);
        }
        if let Some(reason) = self.terminal.clone() {
            return Err(refuse(NAME, 0, Width::Word, AccessDirection::Read, reason));
        }
        let credits = self.receive_credits();
        let (incoming, native) = self
            .consumer
            .poll(access.now, &credits)
            .map_err(|reason| refuse(NAME, 0, Width::Word, AccessDirection::Read, reason))?;
        self.enqueue(incoming)
            .map_err(|reason| refuse(NAME, 0, Width::Word, AccessDirection::Read, reason))?;
        let interrupt = self.update_lines(access);
        Ok(match (native, interrupt) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        })
    }
}

#[cfg(test)]
mod tests;
