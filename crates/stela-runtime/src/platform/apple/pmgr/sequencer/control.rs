//! Native transaction context from matching LLB106a0.
//!
//! The emitter checks five independent four-bit fields and their packing,
//! not names such as privilege, security, QoS or channel IDs. Every physical
//! claim carries this exact context. Its route must explicitly accept those
//! fields before dispatch; unknown initial context and raw0 are not neutral.
use super::{Error, FlightKind, PacketCursor};
use alloc::rc::Rc;

const TAG: u32 = 0x1c;
const FIELDS: u32 = (15 << 5) | (15 << 10) | (15 << 15) | (15 << 20) | (15 << 25);

/// Fields in the original source order (raw groups0,5,10,15,20). Their
/// physical meaning remains a requirement of the checked route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fields([u8; 5]);
impl Fields {
    pub fn new(fields: [u8; 5]) -> Result<Self, Error> {
        if fields.iter().any(|field| *field > 15) {
            return Err(Error::ControlEncoding);
        }
        Ok(Self(fields))
    }
    pub fn values(self) -> [u8; 5] {
        self.0
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initial {
    Captured(Fields),
    DeclaredStela(Fields),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Captured,
    DeclaredStela,
    Instruction { address: u64, raw: u32 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    fields: Fields,
    source: Source,
    generation: u64,
}
impl Snapshot {
    pub fn fields(self) -> Fields {
        self.fields
    }
    pub fn source(self) -> Source {
        self.source
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}

/// The checked physical route explicitly accepted this exact claim's
/// known fields. A token is private to one cursor, ticket and effect kind;
/// accepting a previous context cannot authorize another access or a retry.
#[derive(Debug)]
pub struct Qualification {
    owner: Rc<()>,
    ticket: u64,
    kind: FlightKind,
    context: Snapshot,
}
pub(super) fn qualify(
    owner: &Rc<()>,
    ticket: u64,
    kind: FlightKind,
    context: Option<Snapshot>,
    accepted: Fields,
) -> Result<Qualification, Error> {
    let context = context.ok_or(Error::UnknownControlContext)?;
    if context.fields != accepted {
        return Err(Error::ControlContextRejected);
    }
    Ok(Qualification {
        owner: owner.clone(),
        ticket,
        kind,
        context,
    })
}
pub(super) fn check(
    qualification: &Qualification,
    owner: &Rc<()>,
    ticket: u64,
    kind: FlightKind,
    context: Option<Snapshot>,
) -> Result<(), Error> {
    if !Rc::ptr_eq(&qualification.owner, owner)
        || qualification.ticket != ticket
        || qualification.kind != kind
        || Some(qualification.context) != context
    {
        return Err(Error::StaleControlQualification);
    }
    Ok(())
}

impl PacketCursor {
    pub fn control_context(&self) -> Option<Snapshot> {
        self.control
    }
    /// A whole explicitly supplied initial context, only before any packet
    /// progress/claim. Omission stays unknown; later source instructions own
    /// their context and cannot be replaced through this handoff API.
    pub fn bind_initial_control(&mut self, initial: Initial) -> Result<(), Error> {
        if self.control.is_some()
            || self.pc != 0
            || self.ticket != 0
            || self.packet.is_some()
            || self.poll.is_some()
            || self.delay.is_some()
            || self.copy.is_some()
        {
            return Err(Error::ControlAlreadyOwned);
        }
        let (fields, source) = match initial {
            Initial::Captured(fields) => (fields, Source::Captured),
            Initial::DeclaredStela(fields) => (fields, Source::DeclaredStela),
        };
        self.control = Some(Snapshot {
            fields,
            source,
            generation: 1,
        });
        Ok(())
    }
    /// The same engine transfers its context to a fresh job.
    /// This is not a public snapshot restoration or another captured handoff.
    pub(crate) fn inherit_control(&mut self, context: Snapshot) -> Result<(), Error> {
        if self.control.is_some()
            || self.pc != 0
            || self.ticket != 0
            || self.packet.is_some()
            || self.poll.is_some()
            || self.delay.is_some()
            || self.copy.is_some()
        {
            return Err(Error::ControlAlreadyOwned);
        }
        self.control = Some(context);
        Ok(())
    }
    /// Execute one source-checked context change. This changes real kept
    /// instruction state; it does not authorize any target bank, physical
    /// security interpretation or controller completion.
    pub fn advance_control(&mut self) -> Result<Snapshot, Error> {
        self.check_progress()?;
        if self.packet.is_some() || self.poll.is_some() || self.delay.is_some() {
            return Err(Error::ExpectedControl);
        }
        let sram = self.sram.as_ref().ok_or(Error::UnknownSram)?;
        let raw = *sram.words.get(self.pc).ok_or(Error::TruncatedPacket)?;
        if raw & 31 != TAG || raw & !(FIELDS | 31) != 0 {
            return Err(Error::ControlEncoding);
        }
        let fields = Fields([5, 15, 10, 20, 25].map(|shift| ((raw >> shift) & 15) as u8));
        let generation = self
            .control
            .map_or(0, |context| context.generation)
            .checked_add(1)
            .ok_or(Error::ControlGenerationExhausted)?;
        let context = Snapshot {
            fields,
            source: Source::Instruction {
                address: sram.base + self.pc as u64 * 4,
                raw,
            },
            generation,
        };
        self.control = Some(context);
        self.pc += 1;
        Ok(context)
    }
}

#[cfg(test)]
pub(crate) fn test_fields() -> Fields {
    Fields([0; 5])
}
#[cfg(test)]
pub(crate) fn test_initial() -> Initial {
    Initial::DeclaredStela(test_fields())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::pmgr::sequencer::{
        AddressFormat, FinishError, PacketKind, RouteOutcome, copy, poll,
    };
    use alloc::{vec, vec::Vec};
    const BASE: u64 = 0x292f01a00;
    fn cursor(words: &[u32]) -> PacketCursor {
        let mut cursor = PacketCursor::unknown();
        cursor
            .install_sram(
                BASE,
                &words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>(),
                AddressFormat::HighWord,
            )
            .unwrap();
        cursor
    }
    fn encoded(source: [u8; 5]) -> u32 {
        source
            .into_iter()
            .zip([5, 15, 10, 20, 25])
            .fold(TAG, |word, (field, shift)| word | u32::from(field) << shift)
    }
    #[test]
    fn all_five_source_fields_and_raw_zero_change_actual_context_without_target_admission() {
        for index in 0..5 {
            for value in 0..16 {
                let mut fields = [0; 5];
                fields[index] = value;
                let raw = encoded(fields);
                let mut cursor = cursor(&[raw, 0x101, 0, 0, 7, 0]);
                assert_eq!(cursor.control_context(), None);
                assert_eq!(cursor.packet_kind(), Ok(PacketKind::Control));
                let context = cursor.advance_control().unwrap();
                assert_eq!(context.fields().values(), fields);
                assert_eq!(context.source(), Source::Instruction { address: BASE, raw });
                assert_eq!(context.generation(), 1);
                assert_eq!(cursor.packet_pc(), Some(BASE + 4));
                let claim = cursor.begin_write().unwrap();
                assert_eq!(claim.control_context(), Some(context));
                let mut rejected = fields;
                rejected[index] ^= 1;
                assert_eq!(
                    claim
                        .qualify_context(Fields::new(rejected).unwrap())
                        .unwrap_err(),
                    Error::ControlContextRejected
                );
                assert_eq!(
                    cursor.finish_write::<()>(&claim, RouteOutcome::Committed),
                    Err(FinishError::Ownership(
                        Error::NotDispatched,
                        RouteOutcome::Committed
                    ))
                );
                assert_eq!(cursor.committed_writes(), 0);
                let accepted = claim.qualify_context(Fields::new(fields).unwrap()).unwrap();
                let actual = cursor.dispatch_write(&claim, &accepted).unwrap();
                assert_eq!((actual.address, actual.value), (0x1000, 7));
                cursor
                    .finish_write::<()>(&claim, RouteOutcome::Committed)
                    .unwrap();
                assert_eq!(cursor.committed_writes(), 1);
                assert_eq!(cursor.control_context(), Some(context));
            }
        }
    }
    #[test]
    fn unknown_initial_context_cannot_mint_any_route_qualification_or_blind_commit() {
        let mut cursor = cursor(&[0x101, 0, 0, 7, 0]);
        let claim = cursor.begin_write().unwrap();
        assert_eq!(claim.control_context(), None);
        assert_eq!(
            claim.qualify_context(test_fields()).unwrap_err(),
            Error::UnknownControlContext
        );
        assert_eq!(
            cursor.bind_initial_control(test_initial()),
            Err(Error::ControlAlreadyOwned)
        );
        assert_eq!(
            cursor.finish_write::<()>(&claim, RouteOutcome::Committed),
            Err(FinishError::Ownership(
                Error::NotDispatched,
                RouteOutcome::Committed
            ))
        );
        cursor.cancel_claim(&claim).unwrap();
        assert_eq!(cursor.committed_writes(), 0);
    }
    #[test]
    fn qualification_is_exclusive_to_one_effect_ticket_cursor_and_retained_context() {
        let mut cursor = cursor(&[0x101, 0, 0, 7, encoded([1, 2, 3, 4, 5]), 0x201, 0, 0, 9, 0]);
        cursor
            .bind_initial_control(Initial::Captured(test_fields()))
            .unwrap();
        let first = cursor.begin_write().unwrap();
        let old = first.qualify_context(test_fields()).unwrap();
        cursor.dispatch_write(&first, &old).unwrap();
        assert_eq!(cursor.advance_control(), Err(Error::InFlight));
        cursor
            .finish_write::<()>(&first, RouteOutcome::Committed)
            .unwrap();
        let next = cursor.advance_control().unwrap();
        assert_eq!(next.fields().values(), [1, 2, 3, 4, 5]);
        assert_eq!(next.generation(), 2);
        let claim = cursor.begin_write().unwrap();
        assert_eq!(
            cursor.dispatch_write(&claim, &old),
            Err(Error::StaleControlQualification)
        );
        let qualification = claim
            .qualify_context(Fields::new([1, 2, 3, 4, 5]).unwrap())
            .unwrap();
        cursor.set_suspended(true);
        assert_eq!(
            cursor.dispatch_write(&claim, &qualification),
            Err(Error::Suspended)
        );
        assert_eq!(cursor.control_context(), Some(next));
        cursor.set_suspended(false);
        cursor.dispatch_write(&claim, &qualification).unwrap();
        cursor.set_suspended(true);
        cursor
            .finish_write(&claim, RouteOutcome::Uncertain("actual target prefix"))
            .unwrap_err();
        assert_eq!(cursor.advance_control(), Err(Error::UncertainEffects));
        assert_eq!(cursor.control_context(), Some(next));
        assert_eq!(cursor.committed_writes(), 1);
        let mut other = self::cursor(&[TAG, 0x101, 0, 0, 7, 0]);
        other.advance_control().unwrap();
        let own = other.begin_write().unwrap();
        assert_eq!(
            other.dispatch_write(&own, &old),
            Err(Error::StaleControlQualification)
        );
    }
    #[test]
    fn polls_and_both_copy_phases_carry_the_same_actual_context_and_cannot_share_a_permit() {
        let raw = encoded([2, 3, 4, 5, 6]);
        let mut cursor = cursor(&[
            raw,
            0x102,
            0,
            0,
            1,
            1,
            (127 << 6) | 8,
            0,
            0x100,
            0x200,
            0xfffffff8,
            0,
        ]);
        let context = cursor.advance_control().unwrap();
        let read = cursor.begin_read().unwrap();
        assert_eq!(read.control_context(), Some(context));
        let read_permit = read
            .qualify_context(Fields::new([2, 3, 4, 5, 6]).unwrap())
            .unwrap();
        cursor.dispatch_read(&read, &read_permit).unwrap();
        assert!(
            cursor
                .finish_read::<()>(&read, poll::Outcome::Read(1))
                .unwrap()
        );
        let source = cursor.begin_copy_read().unwrap();
        assert_eq!(source.control_context(), Some(context));
        assert_eq!(
            cursor.dispatch_copy_read(&source, &read_permit),
            Err(Error::StaleControlQualification)
        );
        let permit = source
            .qualify_context(Fields::new([2, 3, 4, 5, 6]).unwrap())
            .unwrap();
        cursor.dispatch_copy_read(&source, &permit).unwrap();
        cursor
            .finish_copy_read::<()>(&source, copy::ReadOutcome::Read(vec![17; 128]))
            .unwrap();
        let destination = cursor.begin_copy_write().unwrap();
        assert_eq!(destination.control_context(), Some(context));
        assert_eq!(
            cursor.dispatch_copy_write(&destination, &permit),
            Err(Error::StaleControlQualification)
        );
        let permit = destination
            .qualify_context(Fields::new([2, 3, 4, 5, 6]).unwrap())
            .unwrap();
        cursor.dispatch_copy_write(&destination, &permit).unwrap();
        cursor
            .finish_copy_write::<()>(&destination, RouteOutcome::Committed)
            .unwrap();
        cursor.advance_copy_join().unwrap();
        assert_eq!(cursor.control_context(), Some(context));
    }
    #[test]
    fn malformed_context_generation_and_pause_preserve_unknownness_and_pc() {
        assert_eq!(Fields::new([16, 0, 0, 0, 0]), Err(Error::ControlEncoding));
        for raw in [TAG | 1 << 31, TAG | 1 << 29] {
            let mut cursor = cursor(&[raw, 0]);
            assert_eq!(cursor.advance_control(), Err(Error::ControlEncoding));
            assert_eq!(cursor.control_context(), None);
            assert_eq!(cursor.packet_pc(), Some(BASE));
        }
        let mut cursor = cursor(&[TAG, 0]);
        cursor.set_suspended(true);
        assert_eq!(cursor.advance_control(), Err(Error::Suspended));
        assert_eq!(cursor.control_context(), None);
        cursor.set_suspended(false);
        cursor.control = Some(Snapshot {
            fields: test_fields(),
            source: Source::Captured,
            generation: u64::MAX,
        });
        assert_eq!(
            cursor.advance_control(),
            Err(Error::ControlGenerationExhausted)
        );
        assert_eq!(cursor.packet_pc(), Some(BASE));
        assert_eq!(cursor.control_context().unwrap().generation(), u64::MAX);
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_IBOOTDATA, STELA_TEST_PMGR_M1_LLB"]
    fn original_control_emitter_all_callbacks_raw_operands_and_assertion_are_pinned() {
        use sha2::{Digest, Sha256};
        let llb = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").unwrap()).unwrap();
        let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&llb)),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095"
        );
        for (lo, hi, hash) in [
            (
                0x106a0,
                0x10804,
                "68af9728e5cd5b740fa7d66040b8b429d995d6626d51dc2d7945ba0bf4e20553",
            ),
            (
                0x47d14,
                0x47dbc,
                "7d823b6854db10df13fcab43549065dbaba66f5933e2c3aa87897d510ad831d9",
            ),
            (
                0x48fac,
                0x4902c,
                "ab5086bed411d491578a7f5d4535854753dabccb9655e4065c0fa3c299f6ea53",
            ),
            (
                0x23fae0,
                0x23fb40,
                "b0bb13477b763eadcc902d7eac40b146de13abbafb7b1abf19c16457f87615c5",
            ),
            (
                0x107ec,
                0x10804,
                "24bd786fff3ae38bdbda71a9eac47599f5efde557d4430006b508cb9b04a8f74",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), hash);
        }
        let word = |offset| u32::from_le_bytes(llb[offset..offset + 4].try_into().unwrap());
        for (at, opcode, handler) in [
            (0x23fae0, 0x28, 0x11800),
            (0x23fb00, 0x29, 0x48fac),
            (0x23fb20, 0x2d, 0x47d14),
        ] {
            assert_eq!((word(at), word(at + 8)), (opcode, handler));
        }
        for (at, sequence, source) in [
            (0x43f60, 12, 0),
            (0x57520, 36, 0x18000),
            (0x586c0, 48, 0x218002),
            (0x58c48, 48, 0),
        ] {
            let row = &data[at..at + 24];
            assert_eq!(u16::from_le_bytes(row[..2].try_into().unwrap()), sequence);
            assert_eq!(u16::from_le_bytes(row[2..4].try_into().unwrap()), 0x29);
            assert_eq!(u64::from_le_bytes(row[8..16].try_into().unwrap()), source);
        }
        // Exact full source windows establish field production and source0;
        // they do not identify physical attribute meanings or admit any route.
    }
}
