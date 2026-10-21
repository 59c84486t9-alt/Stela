//! Programmed NHI DMA rings, independently of a host router implementation.
//!
//! Original Apple ring writers use sixteen-byte descriptors, POSTED bit22,
//! COMPLETED bit21 and interrupt-request bit23. The ACIO register layout and
//! native-frame boundary are documented in `docs/research/usb4-acio.md`.
//! A required [`Consumer`] owns actual router/wire protocol, framing, CRC,
//! E2E/isochronous behavior and notifications. No successful consumer, router
//! capability template, CIO readiness or machine admission is supplied here.
//! DMA completion is a separate retained phase so a fault cannot replay an
//! already accepted frame. Payload and timestamp precede completion ownership.
use super::bus::{Access, Direction as AccessDirection, MmioDevice, MmioError, Width, refuse};
use super::interrupt::{AicInput, Wire};
use crate::platform::dma::{DmaError, Port};
use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};
pub use ring::Direction;
use ring::{Descriptor, Ring, Transfer};
mod ring;

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

/// A completed native NHI frame, including actual receive error/time effects.
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
    ) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > 4096 || sof > 15 || eof > 15 {
            return Err("NHI native frame length or PDF is outside its wire encoding");
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
/// isochronous scheduling and PDF values retain their programmed meanings.
pub struct Transmit<'a> {
    pub hop: usize,
    pub bytes: &'a [u8],
    pub sof: u8,
    pub eof: u8,
    pub isochronous: bool,
    pub scheduled_time: u32,
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
/// at most the supplied receive credits. The peer retains wire traffic under
/// backpressure; this boundary does not invent an unbounded hardware FIFO.
pub trait Consumer {
    fn configure(
        &mut self,
        hop: usize,
        direction: Direction,
        options: Option<Options>,
    ) -> Result<(), &'static str>;
    fn transmit(&mut self, frame: Transmit<'_>) -> Result<Accepted, &'static str>;
    fn poll(
        &mut self,
        now: u64,
        receive_credits: &[usize],
    ) -> Result<(Vec<Frame>, Option<u64>), &'static str>;
    fn reset(&mut self) -> Result<(), &'static str>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Dma(DmaError),
    Unsupported(&'static str),
}
impl From<DmaError> for Error {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}
impl From<&'static str> for Error {
    fn from(reason: &'static str) -> Self {
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
    terminal: Option<&'static str>,
}
impl Nhi {
    pub fn new(
        profile: Profile,
        tx: Vec<AicInput>,
        rx: Vec<AicInput>,
        consumer: Box<dyn Consumer>,
    ) -> Result<Self, &'static str> {
        let count = tx.len();
        if count == 0
            || count > 16
            || rx.len() != count
            || profile.capability_words[0] & 0x3ff != count as u32
        {
            return Err("NHI capability/IRQ ring count is inconsistent");
        }
        let l = profile.layout;
        let mut ranges = vec![
            (0, 8),
            (l.status, 4),
            (l.interrupt_enable, 4),
            (l.throttle, count as u64 * 8),
        ];
        if l.stride < 24 || l.stride & 3 != 0 || profile.shared_tx_buffers == 0 {
            return Err("NHI layout or shared transmit buffer budget is invalid");
        }
        for base in [l.tx, l.rx] {
            for hop in 0..count {
                ranges.push((
                    base.checked_add(
                        l.stride
                            .checked_mul(hop as u64)
                            .ok_or("NHI layout overflow")?,
                    )
                    .ok_or("NHI layout overflow")?,
                    24,
                ));
            }
        }
        ranges.sort_unstable();
        let mut end = 0;
        for (base, bytes) in ranges {
            if base & 3 != 0 || base < end {
                return Err("NHI layout overlaps or is unaligned");
            }
            end = base.checked_add(bytes).ok_or("NHI layout overflow")?;
            if end > REGISTER_BYTES {
                return Err("NHI layout exceeds its aperture");
            }
        }
        let lines: Vec<_> = tx.into_iter().chain(rx).collect();
        if lines.iter().copied().collect::<BTreeSet<_>>().len() != lines.len() {
            return Err("NHI dedicated interrupts alias");
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
    pub fn set_powered(
        &mut self,
        powered: bool,
        access: &mut Access<'_>,
    ) -> Result<(), &'static str> {
        if self.powered && !powered {
            self.reset(access)?;
        }
        self.powered = powered;
        self.update_lines(access);
        Ok(())
    }
    pub fn reset(&mut self, access: &mut Access<'_>) -> Result<(), &'static str> {
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
    fn enqueue(&mut self, frames: Vec<Frame>) -> Result<(), &'static str> {
        let mut credits = self.receive_credits();
        for frame in &frames {
            if let Some(credit) = credits.get_mut(frame.hop).filter(|credit| **credit != 0) {
                *credit -= 1;
            } else {
                let reason = "native NHI consumer returned a frame without posted receive credit";
                self.terminal = Some(reason);
                return Err(reason);
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
            return Err("NHI DMA while powered off".into());
        }
        if let Some(reason) = self.terminal {
            return Err(reason.into());
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
                        return Err("NHI isochronous descriptor on an asynchronous ring".into());
                    }
                    let mut bytes = vec![0; descriptor.length()];
                    port.read(descriptor.address, &mut bytes)?;
                    let receive_credits = self.receive_credits();
                    let accepted = self.consumer.transmit(Transmit {
                        hop,
                        bytes: &bytes,
                        sof: descriptor.sof(),
                        eof: descriptor.eof(),
                        isochronous: descriptor.isochronous(),
                        scheduled_time: descriptor.time,
                        options,
                        receive_credits: &receive_credits,
                    })?;
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
                        return Err("native NHI frame violates configured PDF framing".into());
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
    fn options(
        &self,
        direction: Direction,
        hop: usize,
        flags: u32,
    ) -> Result<Options, &'static str> {
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
            return Err("NHI ring option field without a model");
        }
        let e2e_tx_hop = ((flags & E2E_HOP) >> 12) as u16;
        if direction == Direction::Receive
            && flags & E2E != 0
            && usize::from(e2e_tx_hop) >= self.tx.len()
        {
            return Err("NHI E2E transmit HopID is outside the controller");
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
    fn flags(&mut self, direction: Direction, hop: usize, flags: u32) -> Result<(), &'static str> {
        let options = self.options(direction, hop, flags)?;
        let r = &self.rings(direction)[hop];
        if r.active.is_some() && flags & ENABLE != 0 {
            return if r.flags == flags {
                Ok(())
            } else {
                Err("NHI live ring reconfiguration requires disable")
            };
        }
        if r.transfer.is_some() || !r.incoming.is_empty() {
            return Err("NHI ring has an accepted frame in flight");
        }
        let active = if flags & ENABLE != 0 {
            r.validate_configuration()?;
            if direction == Direction::Receive && !(1..=256).contains(&r.capacity) {
                return Err("NHI receive maximum-frame-size encoding is not qualified");
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
                    return Err("NHI shared transmit buffer allocation exceeds its profile");
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
    ) -> Result<(), &'static str> {
        if field == 16 && width == Width::Word {
            return self.flags(direction, hop, value as u32);
        }
        let r = &mut self.rings_mut(direction)[hop];
        if matches!(
            (field, width),
            (8, Width::Word | Width::Half) | (10, Width::Half)
        ) {
            let owned = match (direction, field, width) {
                (Direction::Transmit, 8, Width::Word) => Some((value >> 16) as u16),
                (Direction::Transmit, 10, Width::Half) | (Direction::Receive, 8, Width::Half) => {
                    Some(value as u16)
                }
                (Direction::Receive, 8, Width::Word) => Some(value as u16),
                _ => None,
            };
            if let Some(index) = owned {
                if index >= r.count && !(index == 0 && r.count == 0) {
                    return Err("NHI posted index is outside the descriptor ring");
                }
                r.posted = index;
            }
            return Ok(());
        }
        if r.active.is_some() || r.transfer.is_some() {
            return Err("NHI descriptor configuration requires a disabled ring");
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
            _ => return Err("NHI ring register or width without a model"),
        }
        Ok(())
    }
}

impl MmioDevice for Nhi {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, AccessDirection::Read, reason);
        if !self.powered {
            return Err(fail("NHI MMIO while powered off"));
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
        Err(fail("NHI register or width without a model"))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, AccessDirection::Write, reason);
        if !self.powered {
            return Err(fail("NHI MMIO while powered off"));
        }
        if value & !width.mask() != 0 {
            return Err(fail("NHI write exceeds the access width"));
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
            self.throttle[(delta / 4) as usize] =
                u16::try_from(value).map_err(|_| fail("NHI throttle field without a model"))?;
        } else if width == Width::Word
            && let Some(delta) = offset.checked_sub(PDF_VIEW).filter(|d| {
                d.is_multiple_of(self.profile.layout.stride)
                    && d / self.profile.layout.stride < self.rx.len() as u64
            })
        {
            let r = &mut self.rx[(delta / self.profile.layout.stride) as usize];
            if r.active.is_some() && u64::from(r.pdf) != value {
                return Err(fail("NHI live PDF reconfiguration requires disable"));
            }
            r.pdf = value as u32;
        } else if let Some((direction, hop, field)) = self.locate(offset) {
            self.ring_write(direction, hop, field, width, value)
                .map_err(fail)?;
        } else {
            return Err(fail("NHI register, field or width without a model"));
        }
        self.update_lines(access);
        Ok(())
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        if !self.powered {
            return Ok(None);
        }
        if let Some(reason) = self.terminal {
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
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    use crate::platform::dma::{Iommu, Memory, tests::Ram};
    use alloc::rc::Rc;
    use core::cell::RefCell;

    #[derive(Default)]
    struct State {
        sent: Vec<(usize, Vec<u8>, u8, u8, bool, u32)>,
        configured: Vec<(usize, Direction, Option<Options>)>,
        notifications: Vec<Frame>,
        deadline: Option<u64>,
        refuse_send: bool,
        refuse_reset: bool,
        refuse_options: bool,
        resets: usize,
    }
    struct Peer(Rc<RefCell<State>>);
    impl Consumer for Peer {
        fn configure(
            &mut self,
            hop: usize,
            dir: Direction,
            options: Option<Options>,
        ) -> Result<(), &'static str> {
            let mut state = self.0.borrow_mut();
            if state.refuse_options {
                return Err("test wire cannot implement requested mode");
            }
            state.configured.push((hop, dir, options));
            Ok(())
        }
        fn transmit(&mut self, frame: Transmit<'_>) -> Result<Accepted, &'static str> {
            let mut state = self.0.borrow_mut();
            if state.refuse_send {
                return Err("test wire rejected frame before acceptance");
            }
            state.sent.push((
                frame.hop,
                frame.bytes.to_vec(),
                frame.sof,
                frame.eof,
                frame.isochronous,
                frame.scheduled_time,
            ));
            Ok(Accepted {
                timestamp: 0x12345678,
                incoming: Vec::new(),
            })
        }
        fn poll(&mut self, _: u64, _: &[usize]) -> Result<(Vec<Frame>, Option<u64>), &'static str> {
            let mut state = self.0.borrow_mut();
            Ok((core::mem::take(&mut state.notifications), state.deadline))
        }
        fn reset(&mut self) -> Result<(), &'static str> {
            let mut state = self.0.borrow_mut();
            if state.refuse_reset {
                return Err("test wire is not quiescent");
            }
            state.resets += 1;
            state.notifications.clear();
            Ok(())
        }
    }
    #[derive(Default)]
    struct Guard {
        fault: Option<(u64, bool)>,
        writes: Vec<u64>,
    }
    impl Iommu for Guard {
        fn page(&self) -> u64 {
            16
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            stream: usize,
            iova: u64,
            last: u64,
            write: bool,
            access: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            assert_eq!(stream, 1);
            assert_eq!(iova / 16, last / 16);
            if self.fault.is_some_and(|(address, direction)| {
                direction == write && (iova..=last).contains(&address)
            }) {
                access
                    .interrupts
                    .set_level(Wire::Aic(AicInput::new(0, 99)), true);
                return Err(DmaError::Fault(0x80));
            }
            if write {
                self.writes.push(iova);
            }
            Ok(iova)
        }
    }
    fn profile(count: u32) -> Profile {
        Profile {
            layout: Layout::ACIO,
            capability_words: [count, 0x76543210],
            shared_tx_buffers: 8,
        }
    }
    fn make(count: u32) -> (Nhi, Rc<RefCell<State>>) {
        let state = Rc::new(RefCell::new(State::default()));
        let tx = (0..count).map(|n| AicInput::new(0, n as u16)).collect();
        let rx = (0..count)
            .map(|n| AicInput::new(0, (n + count) as u16))
            .collect();
        let nhi = Nhi::new(profile(count), tx, rx, Box::new(Peer(state.clone()))).unwrap();
        (nhi, state)
    }
    fn write(nhi: &mut Nhi, access: &mut Access<'_>, offset: u64, width: Width, value: u64) {
        nhi.write(offset, width, value, access).unwrap();
    }
    fn read(nhi: &mut Nhi, access: &mut Access<'_>, offset: u64, width: Width) -> u64 {
        nhi.read(offset, width, access).unwrap()
    }
    fn program(
        nhi: &mut Nhi,
        access: &mut Access<'_>,
        direction: Direction,
        hop: usize,
        flags: u32,
        capacity: u16,
    ) {
        let base = if direction == Direction::Transmit {
            0x10000
        } else {
            0x80000
        } + hop as u64 * 0x4000;
        let descriptors = if direction == Direction::Transmit {
            0x1000
        } else {
            0x2000
        } + hop as u64 * 0x100;
        write(nhi, access, base, Width::Double, descriptors);
        write(
            nhi,
            access,
            base + 12,
            Width::Word,
            4 | u64::from(capacity) << 16,
        );
        write(
            nhi,
            access,
            base + 20,
            Width::Word,
            if direction == Direction::Transmit {
                2
            } else {
                0x00800400
            },
        );
        write(
            nhi,
            access,
            base + 16,
            Width::Word,
            u64::from(flags | ENABLE),
        );
    }
    fn descriptor(ram: &mut Ram, at: u64, payload: u64, metadata: u32, time: u32) {
        ram.put_u64(at, payload);
        ram.put_u64(at + 8, u64::from(metadata) | u64::from(time) << 32);
    }
    fn word(ram: &mut Ram, at: u64) -> u32 {
        let mut bytes = [0; 4];
        assert!(ram.read(at, &mut bytes));
        u32::from_le_bytes(bytes)
    }
    fn service(
        nhi: &mut Nhi,
        ram: &mut Ram,
        guard: &mut Guard,
        access: &mut Access<'_>,
    ) -> Result<(), Error> {
        nhi.service_dma(&mut Port {
            memory: ram,
            iommu: guard,
            stream: 1,
            access,
        })
    }

    #[test]
    fn programmed_dma_wraps_and_preserves_owned_index_halves() {
        let (mut nhi, state) = make(1);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 100, &mut latch);
        let mut ram = Ram::new(0, 0x10000);
        let mut guard = Guard::default();
        nhi.set_powered(true, &mut access).unwrap();
        program(
            &mut nhi,
            &mut access,
            Direction::Transmit,
            0,
            RAW | ISOCH,
            0,
        );
        assert!(ram.write(0x3000, b"NHI"));
        for slot in 0..4 {
            descriptor(&mut ram, 0x1000 + slot * 16, 0x3000, 0xd7a003, 0xabcdef);
        }
        write(
            &mut nhi,
            &mut access,
            0x10008,
            Width::Word,
            3 << 16 | 0xffff,
        );
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0x30003);
        assert_eq!(state.borrow().sent.len(), 3);
        assert_eq!(
            state.borrow().sent[0],
            (0, b"NHI".to_vec(), 7, 10, true, 0xabcdef)
        );
        assert_eq!(word(&mut ram, 0x1008), 0xb7a003);
        assert_eq!(word(&mut ram, 0x100c), 0x12345678);
        write(&mut nhi, &mut access, 0x10008, Width::Half, 0); // Hardware tail is read-only.
        write(&mut nhi, &mut access, 0x1000a, Width::Half, 0);
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Word), 0);
        assert_eq!(state.borrow().sent.len(), 4);
        assert!(!nhi.dma_pending());
    }

    #[test]
    fn completion_fault_retains_acceptance_and_dart_fault_is_separate() {
        let (mut nhi, state) = make(1);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 100, &mut latch);
        let mut ram = Ram::new(0, 0x10000);
        let mut guard = Guard {
            fault: Some((0x3000, false)),
            ..Guard::default()
        };
        nhi.set_powered(true, &mut access).unwrap();
        program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
        descriptor(&mut ram, 0x1000, 0x3000, 0xc00001, 0);
        write(&mut nhi, &mut access, 0x1000a, Width::Half, 1);
        write(&mut nhi, &mut access, 0xd0010, Width::Word, 1);
        assert_eq!(
            service(&mut nhi, &mut ram, &mut guard, &mut access),
            Err(Error::Dma(DmaError::Fault(0x80)))
        );
        assert!(state.borrow().sent.is_empty());
        guard.fault = Some((0x1008, true));
        assert_eq!(
            service(&mut nhi, &mut ram, &mut guard, &mut access),
            Err(Error::Dma(DmaError::Fault(0x80)))
        );
        assert_eq!(state.borrow().sent.len(), 1);
        assert_eq!(word(&mut ram, 0x1008), 0xc00001);
        assert_eq!(word(&mut ram, 0x100c), 0x12345678);
        assert_eq!(read(&mut nhi, &mut access, 0x10008, Width::Half), 0);
        assert!(nhi.write(0x10010, Width::Word, 0, &mut access).is_err());
        assert!(!nhi.asserted[0]);
        guard.fault = None;
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        assert_eq!(state.borrow().sent.len(), 1);
        assert_eq!(word(&mut ram, 0x1008), 0xa00001);
        assert!(nhi.asserted[0]);
        assert!(latch.is_asserted(Wire::Aic(AicInput::new(0, 99))));
    }

    #[test]
    fn receive_fault_never_publishes_ownership_before_payload_and_time() {
        let (mut nhi, state) = make(1);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ram = Ram::new(0, 0x10000);
        let mut guard = Guard {
            fault: Some((0x3010, true)),
            ..Guard::default()
        };
        nhi.set_powered(true, &mut access).unwrap();
        program(&mut nhi, &mut access, Direction::Receive, 0, 0, 20);
        descriptor(&mut ram, 0x2000, 0x3008, 0xc00000, 0);
        write(&mut nhi, &mut access, 0x80008, Width::Half, 1);
        state
            .borrow_mut()
            .notifications
            .push(Frame::new(0, (0..24).collect(), 7, 10, 0xfeed, true).unwrap());
        nhi.advance(&mut access).unwrap();
        assert_eq!(
            service(&mut nhi, &mut ram, &mut guard, &mut access),
            Err(Error::Dma(DmaError::Fault(0x80)))
        );
        assert_eq!(&ram.bytes[0x3008..0x3010], &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(word(&mut ram, 0x2008), 0xc00000);
        assert_eq!(word(&mut ram, 0x200c), 0);
        assert_eq!(read(&mut nhi, &mut access, 0x8000a, Width::Half), 0);
        guard.fault = None;
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        assert_eq!(&ram.bytes[0x3008..0x301c], &(0..20).collect::<Vec<u8>>());
        assert_eq!(word(&mut ram, 0x2008), 0xf7a014); // CRC + overrun alias POSTED.
        assert_eq!(word(&mut ram, 0x200c), 0xfeed);
        assert_eq!(read(&mut nhi, &mut access, 0x80008, Width::Word), 0x10001);
        assert_eq!(&guard.writes[guard.writes.len() - 2..], &[0x200c, 0x2008]);
        assert!(!nhi.dma_pending());
    }

    #[test]
    fn masked_sticky_interrupts_throttle_subsequent_edges_and_merge_deadlines() {
        let (mut nhi, state) = make(1);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 100, &mut latch);
        let mut ram = Ram::new(0, 0x10000);
        let mut guard = Guard::default();
        nhi.set_powered(true, &mut access).unwrap();
        program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
        for slot in 0..2 {
            descriptor(&mut ram, 0x1000 + slot * 16, 0x3000, 0xc00001, 0);
        }
        write(&mut nhi, &mut access, 0xd004c, Width::Word, 125); // 32us = 768 counter ticks.
        write(&mut nhi, &mut access, 0x1000a, Width::Half, 1);
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        assert_eq!(read(&mut nhi, &mut access, 0xd0000, Width::Word), 1);
        assert!(!nhi.asserted[0]);
        write(&mut nhi, &mut access, 0xd0010, Width::Word, 1);
        assert!(nhi.asserted[0]);
        write(&mut nhi, &mut access, 0xd0000, Width::Word, 1);
        assert!(!nhi.asserted[0]);
        write(&mut nhi, &mut access, 0x1000a, Width::Half, 2);
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        state.borrow_mut().deadline = Some(500);
        assert_eq!(nhi.advance(&mut access).unwrap(), Some(500));
        state.borrow_mut().deadline = None;
        assert_eq!(nhi.advance(&mut access).unwrap(), Some(868));
        access.now = 867;
        nhi.advance(&mut access).unwrap();
        assert!(!nhi.asserted[0]);
        access.now = 868;
        assert_eq!(nhi.advance(&mut access).unwrap(), None);
        assert!(nhi.asserted[0]);
        write(&mut nhi, &mut access, 0xd0010, Width::Word, 0);
        assert!(!nhi.asserted[0]);
        assert_eq!(read(&mut nhi, &mut access, 0xd0000, Width::Word), 1);
    }

    #[test]
    fn configuration_is_latched_validated_and_requires_native_support() {
        let (mut nhi, state) = make(2);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        nhi.set_powered(true, &mut access).unwrap();
        write(&mut nhi, &mut access, PDF_VIEW, Width::Word, 0x11223344);
        program(
            &mut nhi,
            &mut access,
            Direction::Receive,
            0,
            RAW | E2E | 1 << 12,
            256,
        );
        let configured = state.borrow().configured[0].2.unwrap();
        assert!(configured.raw && configured.e2e);
        assert_eq!(
            (
                configured.pdf,
                configured.e2e_tx_hop,
                configured.receive_capacity
            ),
            (0x11223344, 1, 256)
        );
        assert!(nhi.write(PDF_VIEW, Width::Word, 0, &mut access).is_err());
        assert!(
            nhi.write(0x80010, Width::Word, u64::from(ENABLE | RAW), &mut access)
                .is_err()
        );
        assert!(
            nhi.write(0x80000, Width::Double, 0x4000, &mut access)
                .is_err()
        );
        write(&mut nhi, &mut access, 0x80010, Width::Word, 0);
        state.borrow_mut().refuse_options = true;
        assert!(
            nhi.write(0x80010, Width::Word, u64::from(ENABLE | RAW), &mut access)
                .is_err()
        );
        assert_eq!(read(&mut nhi, &mut access, 0x80010, Width::Word), 0);
        state.borrow_mut().refuse_options = false;
        program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
        write(&mut nhi, &mut access, 0x14000, Width::Double, 0x1100);
        write(&mut nhi, &mut access, 0x1400c, Width::Word, 4);
        write(&mut nhi, &mut access, 0x14014, Width::Word, 7);
        assert!(
            nhi.write(0x14010, Width::Word, u64::from(ENABLE), &mut access)
                .is_err()
        );
        assert!(nhi.write(0x1000a, Width::Half, 4, &mut access).is_err());
        assert!(nhi.read(0x10000, Width::Byte, &mut access).is_err());
    }

    #[test]
    fn peer_rejection_is_retryable_and_power_loss_requires_quiescence() {
        let (mut nhi, state) = make(1);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ram = Ram::new(0, 0x10000);
        let mut guard = Guard::default();
        assert!(nhi.read(0, Width::Word, &mut access).is_err());
        assert!(service(&mut nhi, &mut ram, &mut guard, &mut access).is_err());
        nhi.set_powered(true, &mut access).unwrap();
        program(&mut nhi, &mut access, Direction::Transmit, 0, RAW, 0);
        descriptor(&mut ram, 0x1000, 0x3000, 0xc00001, 0);
        write(&mut nhi, &mut access, 0x1000a, Width::Half, 1);
        state.borrow_mut().refuse_send = true;
        assert!(matches!(
            service(&mut nhi, &mut ram, &mut guard, &mut access),
            Err(Error::Unsupported(_))
        ));
        assert_eq!(word(&mut ram, 0x1008), 0xc00001);
        assert_eq!(nhi.pending, 0);
        state.borrow_mut().refuse_reset = true;
        assert!(nhi.set_powered(false, &mut access).is_err());
        assert_eq!(read(&mut nhi, &mut access, 0x1000a, Width::Half), 1);
        state.borrow_mut().refuse_send = false;
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        assert_eq!(state.borrow().sent.len(), 1);
        state.borrow_mut().refuse_reset = false;
        nhi.set_powered(false, &mut access).unwrap();
        nhi.set_powered(true, &mut access).unwrap();
        assert_eq!(read(&mut nhi, &mut access, 0x10000, Width::Double), 0);
        assert_eq!(read(&mut nhi, &mut access, 0xd0000, Width::Word), 0);
        assert_eq!(state.borrow().resets, 1);
        assert_eq!(read(&mut nhi, &mut access, 4, Width::Word), 0x76543210);
    }

    #[test]
    fn profile_layout_is_explicit_and_rejects_overflow_overlap_or_irq_aliases() {
        let consumer =
            || Box::new(Peer(Rc::new(RefCell::new(State::default())))) as Box<dyn Consumer>;
        let line = AicInput::new(0, 1);
        assert!(Nhi::new(profile(1), vec![line], vec![line], consumer()).is_err());
        let mut bad = profile(3);
        bad.layout.stride = u64::MAX - 3;
        assert!(Nhi::new(bad, vec![line; 3], vec![line; 3], consumer()).is_err());
        let mut bad = profile(1);
        bad.layout.rx = bad.layout.tx;
        assert!(Nhi::new(bad, vec![line], vec![AicInput::new(0, 2)], consumer()).is_err());
        let mut reversed = profile(1);
        core::mem::swap(&mut reversed.layout.tx, &mut reversed.layout.rx);
        let mut nhi =
            Nhi::new(reversed, vec![line], vec![AicInput::new(0, 2)], consumer()).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        nhi.set_powered(true, &mut access).unwrap();
        write(&mut nhi, &mut access, 0x1000c, Width::Half, 4);
        assert_eq!(read(&mut nhi, &mut access, 0x1000c, Width::Half), 4);
    }
    #[test]
    fn native_notifications_require_posted_credit_and_terminal_fault_requires_reset() {
        let (mut nhi, state) = make(1);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        nhi.set_powered(true, &mut access).unwrap();
        state
            .borrow_mut()
            .notifications
            .push(Frame::new(0, vec![1], 0, 0, 0, false).unwrap());
        assert!(nhi.advance(&mut access).is_err());
        assert!(nhi.rx[0].incoming.is_empty());
        assert!(!nhi.dma_pending());
        state
            .borrow_mut()
            .notifications
            .push(Frame::new(0, vec![2], 0, 0, 0, false).unwrap());
        assert!(nhi.advance(&mut access).is_err());
        assert_eq!(state.borrow().notifications.len(), 1); // No second peer action after violation.
        nhi.reset(&mut access).unwrap();
        assert!(nhi.advance(&mut access).is_ok());
        write(&mut nhi, &mut access, 0x80000, Width::Double, 0x2000);
        write(&mut nhi, &mut access, 0x8000c, Width::Word, 4);
        assert!(
            nhi.write(0x80010, Width::Word, u64::from(ENABLE), &mut access)
                .is_err()
        );
        write(&mut nhi, &mut access, 0x8000e, Width::Half, 257);
        assert!(
            nhi.write(0x80010, Width::Word, u64::from(ENABLE), &mut access)
                .is_err()
        );
    }

    #[test]
    fn dma_quantum_is_bounded_and_pending_work_resumes_fairly() {
        let (mut nhi, state) = make(2);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut ram = Ram::new(0, 0x10000);
        let mut guard = Guard::default();
        nhi.set_powered(true, &mut access).unwrap();
        for hop in 0..2 {
            let registers = 0x10000 + hop * 0x4000;
            let descriptors = 0x1000 + hop * 0x1000;
            write(&mut nhi, &mut access, registers, Width::Double, descriptors);
            write(&mut nhi, &mut access, registers + 12, Width::Half, 100);
            write(&mut nhi, &mut access, registers + 20, Width::Word, 2);
            write(
                &mut nhi,
                &mut access,
                registers + 16,
                Width::Word,
                u64::from(ENABLE | RAW),
            );
            for slot in 0..99 {
                descriptor(&mut ram, descriptors + slot * 16, 0x4000, 0x400001, 0);
            }
            write(&mut nhi, &mut access, registers + 10, Width::Half, 99);
        }
        service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        assert_eq!(state.borrow().sent.len(), 64);
        assert_eq!(
            state
                .borrow()
                .sent
                .iter()
                .filter(|frame| frame.0 == 0)
                .count(),
            32
        );
        assert!(nhi.dma_pending());
        for _ in 0..3 {
            service(&mut nhi, &mut ram, &mut guard, &mut access).unwrap();
        }
        assert_eq!(state.borrow().sent.len(), 198);
        assert!(!nhi.dma_pending());
    }
}
