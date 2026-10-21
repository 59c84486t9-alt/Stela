//! Effect ownership for the original PMGR native write-packet emitter.
//!
//! J473 LLB file0x10810/0x109ec emits up to sixteen writes in a 1 KiB region,
//! with four packed offset bytes per word, optional high address, wide-value
//! alignment and little-endian values. This cursor decodes that format from
//! supplied SRAM bytes. It does not admit a hardware trigger, interpret other
//! instructions, acknowledge a controller or infer initial SRAM/PS contents.
//!
//! The owning controller must qualify its trigger before claiming effects,
//! release its mutable borrow, route each claimed write through the existing
//! checked RAM/MMIO boundary, then finish with the actual result. A failure
//! must mean no effect for that individual write; earlier writes stay committed.
use crate::platform::apple::bus::Width;
use alloc::{rc::Rc, vec::Vec};

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
/// one omits it. No other address format is qualified by this component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    HighWord,
    Compact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnknownSram,
    SramGeometry,
    SramAlreadyOwned,
    Suspended,
    InFlight,
    StaleClaim,
    TicketExhausted,
    TruncatedPacket,
    HighAddress,
    PhysicalAddress,
    UnusedOffsets,
    WidePadding,
    UnqualifiedInstruction(u32),
    UnqualifiedRetirement,
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
}
impl WriteClaim {
    pub fn write(&self) -> PhysicalWrite {
        self.write
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FinishError<E> {
    Ownership(Error),
    Routed(E),
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

/// A retained packet-effect cursor, independent of hardware trigger/retirement
/// admission. `packet_pc` identifies the current packet, not a claimed physical
/// engine's internal micro-PC. Only committed packet effects advance it.
///
/// The image can be installed once, including after `unknown()`. Replacing an
/// owned image or clearing a partial prefix requires separately qualified
/// controller/reset semantics; this API deliberately provides neither.
#[derive(Default)]
pub struct PacketCursor {
    owner: Rc<()>,
    sram: Option<Sram>,
    pc: usize,
    packet: Option<Packet>,
    in_flight: Option<u64>,
    ticket: u64,
    committed_writes: u64,
    suspended: bool,
}
impl PacketCursor {
    pub fn unknown() -> Self {
        Self::default()
    }

    /// Own supplied bytes, never a fabricated reset/zero SRAM image. Geometry
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

    pub fn committed_writes(&self) -> u64 {
        self.committed_writes
    }

    pub fn packet_progress(&self) -> Option<(usize, usize)> {
        self.packet
            .as_ref()
            .map(|packet| (packet.committed, packet.writes.len()))
    }

    /// Retained suspension blocks new claims; an already routed store must
    /// still be finished exactly once, preserving its actual committed effect.
    pub fn set_suspended(&mut self, suspended: bool) {
        self.suspended = suspended;
    }

    /// Exclusively claim one write. Fully decode/validate its packet before
    /// exposing its first effect. A nested service call cannot claim it again.
    /// No end/unknown instruction is treated as successful retirement.
    pub fn begin_write(&mut self) -> Result<WriteClaim, Error> {
        if self.in_flight.is_some() {
            return Err(Error::InFlight);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        let sram = self.sram.as_ref().ok_or(Error::UnknownSram)?;
        if self.packet.is_none() {
            self.packet = Some(decode(sram, self.pc)?);
        }
        let ticket = self.ticket.checked_add(1).ok_or(Error::TicketExhausted)?;
        // One generation for every claim, including retries of identical data.
        self.ticket = ticket;
        self.in_flight = Some(ticket);
        let packet = self.packet.as_ref().expect("validated write packet");
        Ok(WriteClaim {
            owner: self.owner.clone(),
            ticket,
            write: packet.writes[packet.committed],
        })
    }

    fn check_claim(&self, claim: &WriteClaim) -> Result<(), Error> {
        if Rc::ptr_eq(&claim.owner, &self.owner) && self.in_flight == Some(claim.ticket) {
            Ok(())
        } else {
            Err(Error::StaleClaim)
        }
    }

    /// Cancel only exclusive service ownership before dispatch, or after a
    /// checked refusal with no effect. This retains the packet and committed
    /// prefix; it does not cancel hardware work or permit SRAM replacement.
    pub fn cancel_claim(&mut self, claim: &WriteClaim) -> Result<(), Error> {
        self.check_claim(claim)?;
        self.in_flight = None;
        Ok(())
    }

    /// Preserve the actual routed error type. A successful store retires only
    /// this write; it never acknowledges controller completion. A refused store
    /// releases its claim for retry without replaying the committed prefix.
    pub fn finish_write<E>(
        &mut self,
        claim: &WriteClaim,
        result: Result<(), E>,
    ) -> Result<(), FinishError<E>> {
        self.check_claim(claim).map_err(FinishError::Ownership)?;
        self.in_flight = None;
        result.map_err(FinishError::Routed)?;
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
mod tests {
    use super::*;
    use crate::platform::apple::bus::{Access, Bus, MmioError};
    use crate::platform::apple::interrupt::InterruptLatch;
    use crate::platform::apple::pmgr::{ACTIVE, Pmgr, PowerState};
    use crate::platform::dma::{Memory, tests::Ram};
    use alloc::boxed::Box;

    const SRAM: u64 = 0x23df05200;

    fn cursor(words: &[u32], format: AddressFormat) -> PacketCursor {
        let mut cursor = PacketCursor::unknown();
        let bytes: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        cursor.install_sram(SRAM, &bytes, format).unwrap();
        cursor
    }

    #[test]
    fn checked_mmio_refusal_retains_committed_prefix_and_original_error() {
        // Two native stores in one packet, offsets 0/8 in the same 1KiB bank.
        let mut cursor = cursor(
            &[0x105, 0x200, 0x1000000f, 0x1000000f, 0],
            AddressFormat::Compact,
        );
        let mut bus = Bus::new();
        let first = bus.add(Box::new(
            Pmgr::new([PowerState {
                address: 0x1000,
                initial: ACTIVE,
            }])
            .unwrap(),
        ));
        bus.map(first, 0x1000, 4, 0x1000).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let claim = cursor.begin_write().unwrap();
        let write = claim.write();
        cursor
            .finish_write(
                &claim,
                bus.write(write.address, write.width, write.value, &mut access),
            )
            .unwrap();
        assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0x100000ff));
        assert_eq!(cursor.packet_pc(), Some(SRAM));
        assert_eq!(cursor.packet_progress(), Some((1, 2)));
        let failed = cursor.begin_write().unwrap();
        let write = failed.write();
        let result = bus.write(write.address, write.width, write.value, &mut access);
        assert_eq!(
            cursor.finish_write(&failed, result),
            Err(FinishError::Routed(MmioError::Unmapped {
                address: 0x1008,
                width: Width::Word
            }))
        );
        assert_eq!(cursor.committed_writes(), 1);
        // An independent intervening write must not be overwritten by replay
        // of the native packet's already committed first store on retry.
        bus.write(0x1000, Width::Word, 0xf, &mut access).unwrap();
        let second = bus.add(Box::new(
            Pmgr::new([PowerState {
                address: 0x1008,
                initial: ACTIVE,
            }])
            .unwrap(),
        ));
        bus.map(second, 0x1008, 4, 0x1008).unwrap();
        let retry = cursor.begin_write().unwrap();
        assert_eq!(retry.write(), failed.write());
        assert_eq!(
            cursor.finish_write::<MmioError>(&failed, Ok(())),
            Err(FinishError::Ownership(Error::StaleClaim))
        );
        let write = retry.write();
        cursor
            .finish_write(
                &retry,
                bus.write(write.address, write.width, write.value, &mut access),
            )
            .unwrap();
        assert_eq!(cursor.committed_writes(), 2);
        assert_eq!(cursor.packet_pc(), Some(SRAM + 16));
        assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0xff));
        assert_eq!(bus.read(0x1008, Width::Word, &mut access), Ok(0x100000ff));
        assert!(matches!(
            cursor.begin_write(),
            Err(Error::UnqualifiedRetirement)
        ));
        assert_eq!(cursor.packet_pc(), Some(SRAM + 16));
    }

    #[test]
    fn actual_pmgr_coverage_refusal_cannot_be_acknowledged_as_a_write() {
        let mut cursor = cursor(&[0x101, 0, 4, 0], AddressFormat::Compact);
        let mut pmgr = Pmgr::new([PowerState {
            address: 0x1000,
            initial: ACTIVE,
        }])
        .unwrap();
        pmgr.refuse_lifecycle(0x1000).unwrap();
        let mut bus = Bus::new();
        let id = bus.add(Box::new(pmgr));
        bus.map(id, 0x1000, 4, 0x1000).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let claim = cursor.begin_write().unwrap();
        let write = claim.write();
        let error = bus
            .write(write.address, write.width, write.value, &mut access)
            .unwrap_err();
        assert!(matches!(error, MmioError::Unsupported { .. }));
        assert_eq!(
            cursor.finish_write(&claim, Err(error)),
            Err(FinishError::Routed(error))
        );
        assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0xff));
        assert_eq!(cursor.packet_pc(), Some(SRAM));
        assert_eq!(cursor.packet_progress(), Some((0, 1)));
        assert_eq!(cursor.committed_writes(), 0);
    }

    #[test]
    fn actual_ram_keeps_wide_values_and_running_sequence_alignment() {
        // The first packet occupies three words. The following wide packet
        // needs padding at word5; aligning each packet in isolation is wrong.
        let mut cursor = cursor(
            &[
                0x101,
                0,
                0x11223344,
                0x103,
                2,
                WIDE_PADDING,
                0x55667788,
                0x99aabbcc,
                0,
            ],
            AddressFormat::Compact,
        );
        let mut ram = Ram::new(0x1000, 32);
        for expected in [
            PhysicalWrite {
                address: 0x1000,
                width: Width::Word,
                value: 0x11223344,
            },
            PhysicalWrite {
                address: 0x1008,
                width: Width::Double,
                value: 0x99aabbcc55667788,
            },
        ] {
            let claim = cursor.begin_write().unwrap();
            let write = claim.write();
            assert_eq!(write, expected);
            let data = write.value.to_le_bytes();
            let result = ram.write(write.address, &data[..write.width.bytes() as usize]);
            cursor
                .finish_write(
                    &claim,
                    result.then_some(()).ok_or("RAM refused entire write"),
                )
                .unwrap();
        }
        assert_eq!(&ram.bytes[..4], &0x11223344u32.to_le_bytes());
        assert_eq!(&ram.bytes[8..16], &0x99aabbcc55667788u64.to_le_bytes());
        assert_eq!(cursor.packet_pc(), Some(SRAM + 32));
        assert!(matches!(
            cursor.begin_write(),
            Err(Error::UnqualifiedRetirement)
        ));
    }

    #[test]
    fn high_address_and_four_byte_aligned_wide_store_use_exact_geometry() {
        let mut cursor = cursor(
            &[0x103, 2, 1, WIDE_PADDING, 0x89abcdef, 0x1234567, 0],
            AddressFormat::HighWord,
        );
        let claim = cursor.begin_write().unwrap();
        let write = claim.write();
        assert_eq!(
            write,
            PhysicalWrite {
                address: 0x2000001004,
                width: Width::Double,
                value: 0x0123456789abcdef
            }
        );
        // Original emitter checks alignment4 even for wide. The actual target
        // boundary decides whether this physical access is qualified.
        let mut short = Ram::new(0x2000001000, 8);
        short.bytes.fill(0xa5);
        let result = short.write(write.address, &write.value.to_le_bytes());
        assert!(!result);
        assert_eq!(short.bytes, vec![0xa5; 8]);
        assert_eq!(
            cursor.finish_write(
                &claim,
                result
                    .then_some(())
                    .ok_or(crate::platform::dma::DmaError::Memory)
            ),
            Err(FinishError::Routed(crate::platform::dma::DmaError::Memory))
        );
        assert_eq!(cursor.committed_writes(), 0);
        let retry = cursor.begin_write().unwrap();
        assert_eq!(retry.write(), write);
        let mut ram = Ram::new(0x2000001000, 32);
        assert!(ram.write(write.address, &write.value.to_le_bytes()));
        cursor.finish_write::<()>(&retry, Ok(())).unwrap();
        assert_eq!(&ram.bytes[4..12], &write.value.to_le_bytes());
        assert_eq!(cursor.packet_pc(), Some(SRAM + 24));
    }

    #[test]
    fn exclusive_claim_cancellation_and_distinct_cursor_identity_reject_stale_results() {
        let mut a = cursor(&[0x101, 0, 0xf, 0], AddressFormat::Compact);
        let mut b = cursor(&[0x101, 0, 0xf, 0], AddressFormat::Compact);
        let old = a.begin_write().unwrap();
        assert!(matches!(a.begin_write(), Err(Error::InFlight)));
        let other = b.begin_write().unwrap();
        assert_eq!(
            b.finish_write::<()>(&old, Ok(())),
            Err(FinishError::Ownership(Error::StaleClaim))
        );
        a.cancel_claim(&old).unwrap();
        let new = a.begin_write().unwrap();
        assert_eq!(a.cancel_claim(&old), Err(Error::StaleClaim));
        assert_eq!(
            a.finish_write::<()>(&old, Ok(())),
            Err(FinishError::Ownership(Error::StaleClaim))
        );
        a.finish_write::<()>(&new, Ok(())).unwrap();
        b.finish_write::<()>(&other, Ok(())).unwrap();
        assert_eq!(a.committed_writes(), 1);
        assert_eq!(b.committed_writes(), 1);
    }

    #[test]
    fn retained_suspend_preserves_in_flight_effect_and_forbids_image_substitution() {
        let mut cursor = cursor(&[0x105, 0, 0xf, 4, 0], AddressFormat::Compact);
        let claim = cursor.begin_write().unwrap();
        cursor.set_suspended(true);
        assert_eq!(
            cursor.install_sram(SRAM, &[0; 4], AddressFormat::Compact),
            Err(Error::SramAlreadyOwned)
        );
        cursor.finish_write::<()>(&claim, Ok(())).unwrap();
        assert!(matches!(cursor.begin_write(), Err(Error::Suspended)));
        assert_eq!(cursor.packet_progress(), Some((1, 2)));
        cursor.set_suspended(false);
        let next = cursor.begin_write().unwrap();
        assert_eq!(next.write().value, 4);
        assert_eq!(cursor.packet_pc(), Some(SRAM));
        assert_eq!(
            cursor.install_sram(SRAM, &[0; 4], AddressFormat::Compact),
            Err(Error::SramAlreadyOwned)
        );
    }

    #[test]
    fn every_malformed_or_unknown_packet_refuses_before_any_effect() {
        for (words, format, error) in [
            (
                vec![0x105, 0x200, 7],
                AddressFormat::Compact,
                Error::TruncatedPacket,
            ),
            (
                vec![0x101, 0x100, 7],
                AddressFormat::Compact,
                Error::UnusedOffsets,
            ),
            (
                vec![0x103, 64, 0, WIDE_PADDING, 7, 0],
                AddressFormat::HighWord,
                Error::HighAddress,
            ),
            (
                vec![0x103, 0, 0, 0, 7, 0],
                AddressFormat::HighWord,
                Error::WidePadding,
            ),
            (
                vec![0xffff_ffc3, 63, 255, WIDE_PADDING, 7, 0],
                AddressFormat::HighWord,
                Error::PhysicalAddress,
            ),
            (
                vec![2],
                AddressFormat::Compact,
                Error::UnqualifiedInstruction(2),
            ),
            (
                vec![0x44],
                AddressFormat::Compact,
                Error::UnqualifiedInstruction(0x44),
            ),
            (
                vec![0],
                AddressFormat::Compact,
                Error::UnqualifiedRetirement,
            ),
        ] {
            let mut cursor = cursor(&words, format);
            assert!(matches!(cursor.begin_write(), Err(actual) if actual == error));
            assert_eq!(cursor.packet_pc(), Some(SRAM));
            assert_eq!(cursor.packet_progress(), None);
            assert_eq!(cursor.committed_writes(), 0);
        }
        let mut cursor = PacketCursor::unknown();
        assert!(matches!(cursor.begin_write(), Err(Error::UnknownSram)));
        assert_eq!(cursor.packet_pc(), None);
        for (base, bytes) in [
            (SRAM + 4, vec![0; 4]),
            (SRAM, vec![]),
            (SRAM, vec![0; 3]),
            (MAX_PHYSICAL, vec![0; 4]),
        ] {
            assert_eq!(
                cursor.install_sram(base, &bytes, AddressFormat::Compact),
                Err(Error::SramGeometry)
            );
        }
    }

    #[test]
    fn full_sixteen_write_batch_reaches_actual_ram_in_offset_order() {
        let mut words = vec![0x13d, 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c];
        words.extend(0x80..0x90);
        words.push(0);
        let mut cursor = cursor(&words, AddressFormat::Compact);
        let mut ram = Ram::new(0x1000, 64);
        for index in 0..16 {
            let claim = cursor.begin_write().unwrap();
            let write = claim.write();
            assert_eq!(write.address, 0x1000 + index * 4);
            assert_eq!(write.value, 0x80 + index);
            assert_eq!(write.width, Width::Word);
            assert!(ram.write(write.address, &write.value.to_le_bytes()[..4]));
            cursor.finish_write::<()>(&claim, Ok(())).unwrap();
            assert_eq!(cursor.committed_writes(), index + 1);
        }
        assert_eq!(cursor.packet_pc(), Some(SRAM + 21 * 4));
        assert_eq!(&ram.bytes[60..64], &0x8fu32.to_le_bytes());
        assert!(matches!(
            cursor.begin_write(),
            Err(Error::UnqualifiedRetirement)
        ));
    }

    #[test]
    fn ticket_exhaustion_refuses_without_reusing_an_old_generation() {
        let mut cursor = cursor(&[0x101, 0, 0xf, 0], AddressFormat::Compact);
        cursor.ticket = u64::MAX;
        assert!(matches!(cursor.begin_write(), Err(Error::TicketExhausted)));
        assert_eq!(cursor.packet_pc(), Some(SRAM));
        assert_eq!(cursor.committed_writes(), 0);
        assert!(cursor.in_flight.is_none());
    }
}
