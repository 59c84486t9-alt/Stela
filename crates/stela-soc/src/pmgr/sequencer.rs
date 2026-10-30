//! Effect ownership for the original PMGR native write-packet emitter.
//!
//! J473 LLB file0x10810/0x109ec emits up to sixteen writes in a 1 KiB region,
//! with four packed offset bytes per word, optional high address, wide-value
//! alignment and little-endian values. This cursor decodes that format from
//! supplied SRAM bytes. It does not admit a hardware trigger, interpret other
//! instructions, acknowledge a controller or infer initial SRAM/PS contents.
//!
//! The owning controller must check its trigger before claiming effects,
//! release its mutable borrow, route each claimed write through the existing
//! checked RAM/MMIO boundary, then finish with its typed effect outcome. Only a
//! positively proven no-effect refusal permits retry. Uncertain or partial
//! effects quarantine the cursor; earlier committed writes remain recorded.
use alloc::{rc::Rc, vec::Vec};
use stela_contracts::bus::Width;

pub mod control;
pub mod copy;
pub mod delay;
pub mod poll;
mod stride;

const SRAM_ALIGNMENT: u64 = 32;
const MAX_PHYSICAL: u64 = 1 << 42;
const WRITE_TAG: u32 = 1;
const WIDE: u32 = 1 << 1;
const COUNT_SHIFT: u32 = 2;
const COUNT_MASK: u32 = 15;
const ADDRESS_MASK: u32 = 0xffff_ffc0;
const HIGH_ADDRESS_MASK: u32 = 63;
const HIGH_ADDRESS_SHIFT: u32 = 36;
const WIDE_PADDING: u32 = 0xdead_beef;

/// Original context+0x18: zero emits a separate six-bit high-address word;
/// one omits it. No other address format is checked by this component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    HighWord,
    Compact,
}

/// Non-mutating dispatch classification, not packet or trigger admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Write,
    Poll,
    Delay,
    Copy,
    CopyJoin,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnknownSram,
    SramGeometry,
    SramAlreadyOwned,
    Suspended,
    InFlight,
    NotDispatched,
    AlreadyDispatched,
    UncertainEffects,
    StaleClaim,
    TicketExhausted,
    TruncatedPacket,
    HighAddress,
    PhysicalAddress,
    UnusedOffsets,
    WidePadding,
    UnqualifiedInstruction(u32),
    UnqualifiedRetirement,
    FinalizedExtent,
    ExpectedWrite,
    ExpectedRead,
    PollEncoding,
    PollExpectedMask,
    UnqualifiedPollCondition(u8),
    UnqualifiedPollTimeout(u16),
    CounterExhausted,
    ExpectedDelay,
    DelayEncoding,
    RegressedCycles,
    UnqualifiedClockPhase,
    ExpectedCopyRead,
    ExpectedCopyWrite,
    ExpectedCopyJoin,
    CopyEncoding,
    CopyAlignment,
    CopyOverlap,
    UnqualifiedCopyJoin(u32),
    StrideEncoding,
    UnqualifiedStrideWidth,
    ControlEncoding,
    UnknownControlContext,
    ControlAlreadyOwned,
    ControlContextRejected,
    StaleControlQualification,
    ExpectedControl,
    ControlGenerationExhausted,
}

/// One physical store, without a claim that its target accepts that access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalWrite {
    pub address: u64,
    pub width: Width,
    pub value: u64,
}

/// Private cursor identity plus a monotonic claim generation. Keeping this
/// identity alive prevents stale tickets aliasing a later cursor's allocation.
#[derive(Debug)]
pub struct WriteClaim {
    owner: Rc<()>,
    ticket: u64,
    write: PhysicalWrite,
    context: Option<control::Snapshot>,
}
impl WriteClaim {
    pub fn write(&self) -> PhysicalWrite {
        self.write
    }
    pub fn control_context(&self) -> Option<control::Snapshot> {
        self.context
    }
    pub fn qualify_context(
        &self,
        accepted: control::Fields,
    ) -> Result<control::Qualification, Error> {
        control::qualify(
            &self.owner,
            self.ticket,
            FlightKind::Write,
            self.context,
            accepted,
        )
    }
}

/// Classification supplied by the checked physical route, never inferred from
/// a generic error. An error may follow committed MMIO or partial RAM effects.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteOutcome<E> {
    Committed,
    /// The route positively established that this individual write had no effect.
    NoEffect(E),
    /// Effects may have occurred. Retry and cancellation are no longer safe.
    Uncertain(E),
}

#[derive(Debug, PartialEq, Eq)]
pub enum FinishError<E> {
    /// Preserve even a misrouted result for the caller's ownership diagnosis.
    Ownership(Error, RouteOutcome<E>),
    NoEffect(E),
    Uncertain(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlightKind {
    Write,
    Poll,
    CopyRead,
    CopyWrite,
}
struct InFlight {
    ticket: u64,
    dispatched: bool,
    kind: FlightKind,
}

struct Sram {
    base: u64,
    words: Vec<u32>,
    format: AddressFormat,
}

struct Packet {
    writes: Vec<PhysicalWrite>,
    committed: usize,
    end: usize,
}

/// A kept packet-effect cursor, independent of hardware trigger/retirement
/// admission. `packet_pc` identifies the current packet, not a claimed physical
/// engine's internal micro-PC. Only committed packet effects advance it.
///
/// The image can be installed once, including after `unknown()`. Replacing an
/// owned image or clearing a partial prefix requires separately checked
/// controller/reset semantics; this API provides neither.
#[derive(Default)]
pub struct PacketCursor {
    owner: Rc<()>,
    sram: Option<Sram>,
    pc: usize,
    packet: Option<Packet>,
    poll: Option<poll::Packet>,
    delay: Option<delay::Packet>,
    copy: Option<copy::Packet>,
    last_copy: Option<copy::Completed>,
    in_flight: Option<InFlight>,
    uncertain: Option<PhysicalWrite>,
    uncertain_read: Option<poll::PhysicalRead>,
    uncertain_copy_read: Option<copy::PhysicalRead>,
    uncertain_copy_write: Option<copy::Transfer>,
    ticket: u64,
    committed_writes: u64,
    committed_reads: u64,
    suspended: bool,
    control: Option<control::Snapshot>,
}
impl PacketCursor {
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Own supplied bytes, never an invented reset/zero SRAM image. Geometry
    /// checks grant no hardware trigger, target-bank or instruction admission.
    pub fn install_sram(
        &mut self,
        base: u64,
        bytes: &[u8],
        format: AddressFormat,
    ) -> Result<(), Error> {
        if self.sram.is_some() {
            return Err(Error::SramAlreadyOwned);
        }
        if !base.is_multiple_of(SRAM_ALIGNMENT)
            || bytes.is_empty()
            || !bytes.len().is_multiple_of(4)
            || base
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > MAX_PHYSICAL)
        {
            return Err(Error::SramGeometry);
        }
        self.sram = Some(Sram {
            base,
            words: bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|word| u32::from_le_bytes(*word))
                .collect(),
            format,
        });
        Ok(())
    }

    pub fn packet_pc(&self) -> Option<u64> {
        self.sram
            .as_ref()
            .map(|sram| sram.base + self.pc as u64 * 4)
    }
    pub fn packet_kind(&self) -> Result<PacketKind, Error> {
        let sram = self.sram.as_ref().ok_or(Error::UnknownSram)?;
        let header = *sram.words.get(self.pc).ok_or(Error::TruncatedPacket)?;
        if header == 0 {
            return Err(Error::UnqualifiedRetirement);
        }
        if header & 1 != 0 || header & 0x1f == 6 {
            Ok(PacketKind::Write)
        } else if header & 0x1f == 2 {
            Ok(PacketKind::Poll)
        } else if header & 0x3f == 4 {
            Ok(PacketKind::Delay)
        } else if header & 0x3f == 8 {
            Ok(PacketKind::Copy)
        } else if header & 31 == 0x1c {
            Ok(PacketKind::Control)
        } else if header & 0x3f == 0x38 {
            Ok(PacketKind::CopyJoin)
        } else {
            Err(Error::UnqualifiedInstruction(header))
        }
    }

    pub(crate) fn check_progress(&self) -> Result<(), Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if self.in_flight.is_some() {
            return Err(Error::InFlight);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        Ok(())
    }
    pub(crate) fn in_flight(&self) -> Option<bool> {
        self.in_flight.as_ref().map(|flight| flight.dispatched)
    }
    /// The matching compiler appends one zero after its exact counted words.
    /// Only the controller's bound finalized-image owner may call this after
    /// every supported effect retired. An arbitrary/early zero is not an end.
    pub(crate) fn retire_finalized(&mut self, counted_words: u32) -> Result<(), Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if self.in_flight.is_some() {
            return Err(Error::InFlight);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        let sram = self.sram.as_ref().ok_or(Error::UnknownSram)?;
        if self.packet.is_some()
            || self.poll.is_some()
            || self.delay.is_some()
            || self.copy.is_some()
            || self.pc != counted_words as usize
            || sram.words.len() != self.pc + 1
            || sram.words[self.pc] != 0
        {
            return Err(Error::FinalizedExtent);
        }
        self.pc += 1;
        Ok(())
    }

    pub fn committed_writes(&self) -> u64 {
        self.committed_writes
    }

    #[cfg(test)]
    pub fn packet_progress(&self) -> Option<(usize, usize)> {
        self.packet
            .as_ref()
            .map(|packet| (packet.committed, packet.writes.len()))
    }

    /// Suspension blocks new claims and dispatch; an already routed
    /// store must still finish exactly once, preserving its effect.
    pub fn set_suspended(&mut self, suspended: bool) {
        self.suspended = suspended;
    }

    /// Exclusively claim one write. Fully decode/validate its packet before
    /// exposing its first effect. A nested service call cannot claim it again.
    /// No end/unknown instruction is treated as successful retirement.
    pub fn begin_write(&mut self) -> Result<WriteClaim, Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if self.in_flight.is_some() {
            return Err(Error::InFlight);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        if self.delay.is_some() {
            return Err(Error::ExpectedWrite);
        }
        if self.poll.is_some() {
            return Err(Error::ExpectedWrite);
        }
        if self.committed_writes == u64::MAX {
            return Err(Error::CounterExhausted);
        }
        let sram = self.sram.as_ref().ok_or(Error::UnknownSram)?;
        if self.packet.is_none() {
            self.packet = Some(decode(sram, self.pc)?);
        }
        let ticket = self.ticket.checked_add(1).ok_or(Error::TicketExhausted)?;
        // One generation for every claim, including retries of identical data.
        self.ticket = ticket;
        self.in_flight = Some(InFlight {
            ticket,
            dispatched: false,
            kind: FlightKind::Write,
        });
        let packet = self.packet.as_ref().expect("validated write packet");
        Ok(WriteClaim {
            owner: self.owner.clone(),
            ticket,
            write: packet.writes[packet.committed],
            context: self.control,
        })
    }

    fn check_claim(&self, claim: &WriteClaim) -> Result<(), Error> {
        if self.quarantined() {
            return Err(Error::UncertainEffects);
        }
        if Rc::ptr_eq(&claim.owner, &self.owner)
            && self.in_flight.as_ref().is_some_and(|state| {
                state.ticket == claim.ticket && state.kind == FlightKind::Write
            })
        {
            Ok(())
        } else {
            Err(Error::StaleClaim)
        }
    }

    fn quarantined(&self) -> bool {
        self.uncertain.is_some()
            || self.uncertain_read.is_some()
            || self.uncertain_copy_read.is_some()
            || self.uncertain_copy_write.is_some()
    }

    /// Mark exclusive ownership as dispatched immediately before calling the
    /// physical route. A second dispatch or cancellation is then forbidden.
    /// Inspection via `WriteClaim::write` alone does not dispatch an effect.
    pub fn dispatch_write(
        &mut self,
        claim: &WriteClaim,
        qualification: &control::Qualification,
    ) -> Result<PhysicalWrite, Error> {
        self.check_claim(claim)?;
        control::check(
            qualification,
            &claim.owner,
            claim.ticket,
            FlightKind::Write,
            claim.context,
        )?;
        let state = self.in_flight.as_mut().expect("checked claim");
        if state.dispatched {
            return Err(Error::AlreadyDispatched);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        state.dispatched = true;
        Ok(claim.write)
    }

    /// Cancel exclusive ownership only before dispatch. A proven no-effect
    /// outcome releases its claim through `finish_write`; an uncertain effect
    /// cannot be cancelled. Neither operation clears an earlier committed prefix.
    pub fn cancel_claim(&mut self, claim: &WriteClaim) -> Result<(), Error> {
        self.check_claim(claim)?;
        if self.in_flight.as_ref().expect("checked claim").dispatched {
            return Err(Error::AlreadyDispatched);
        }
        self.in_flight = None;
        Ok(())
    }

    /// The uncertain physical store is held for diagnosis. There is no
    /// retry, image replacement or reset API that can erase this uncertainty.
    pub fn uncertain_write(&self) -> Option<PhysicalWrite> {
        self.uncertain
    }

    /// Preserve the routed error type and committed prefix. Only a
    /// positively proven no-effect outcome releases the current write for retry.
    /// An uncertain/partial result permanently quarantines further claims.
    /// Success retires this write, never the controller or the native program.
    pub fn finish_write<E>(
        &mut self,
        claim: &WriteClaim,
        outcome: RouteOutcome<E>,
    ) -> Result<(), FinishError<E>> {
        if let Err(error) = self.check_claim(claim) {
            return Err(FinishError::Ownership(error, outcome));
        }
        if !self.in_flight.as_ref().expect("checked claim").dispatched {
            return Err(FinishError::Ownership(Error::NotDispatched, outcome));
        }
        self.in_flight = None;
        match outcome {
            RouteOutcome::NoEffect(error) => return Err(FinishError::NoEffect(error)),
            RouteOutcome::Uncertain(error) => {
                self.uncertain = Some(claim.write);
                return Err(FinishError::Uncertain(error));
            }
            RouteOutcome::Committed => {}
        }
        let packet = self.packet.as_mut().expect("claim owns a write packet");
        packet.committed += 1;
        self.committed_writes += 1;
        if packet.committed == packet.writes.len() {
            self.pc = packet.end;
            self.packet = None;
        }
        Ok(())
    }
}

fn decode(sram: &Sram, pc: usize) -> Result<Packet, Error> {
    if sram.words.get(pc).is_some_and(|header| header & 0x1f == 6) {
        return stride::decode(sram, pc);
    }
    let mut cursor = pc;
    let mut next = || {
        let value = *sram.words.get(cursor).ok_or(Error::TruncatedPacket)?;
        cursor += 1;
        Ok(value)
    };
    let header = next()?;
    if header == 0 {
        return Err(Error::UnqualifiedRetirement);
    }
    if header & WRITE_TAG == 0 {
        if header & 0x1f == 2 {
            return Err(Error::ExpectedWrite);
        }
        return Err(Error::UnqualifiedInstruction(header));
    }
    let wide = header & WIDE != 0;
    let count = ((header >> COUNT_SHIFT) & COUNT_MASK) as usize + 1;
    let mut base = u64::from(header & ADDRESS_MASK) << 4;
    if sram.format == AddressFormat::HighWord {
        let high = next()?;
        if high & !HIGH_ADDRESS_MASK != 0 {
            return Err(Error::HighAddress);
        }
        base |= u64::from(high) << HIGH_ADDRESS_SHIFT;
    }
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count.div_ceil(4) {
        let packed = next()?;
        for offset in packed.to_le_bytes() {
            if offsets.len() < count {
                offsets.push(u64::from(offset) << 2);
            } else if offset != 0 {
                return Err(Error::UnusedOffsets);
            }
        }
    }
    // Code starts on a 32-byte boundary. Original alignment tests the running
    // sequence word count, including all preceding packets/instructions.
    let values_start =
        pc + 1 + usize::from(sram.format == AddressFormat::HighWord) + count.div_ceil(4);
    if wide && !values_start.is_multiple_of(2) && next()? != WIDE_PADDING {
        return Err(Error::WidePadding);
    }
    let mut writes = Vec::with_capacity(count);
    for offset in offsets {
        let low = u64::from(next()?);
        let value = if wide {
            low | u64::from(next()?) << 32
        } else {
            low
        };
        let address = base + offset;
        let width = if wide { Width::Double } else { Width::Word };
        if address + width.bytes() > MAX_PHYSICAL {
            return Err(Error::PhysicalAddress);
        }
        writes.push(PhysicalWrite {
            address,
            width,
            value,
        });
    }
    Ok(Packet {
        writes,
        committed: 0,
        end: cursor,
    })
}

#[cfg(test)]
mod tests;
