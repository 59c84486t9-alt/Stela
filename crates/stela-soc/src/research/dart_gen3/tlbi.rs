//! Typed gen3 invalidation requests, independently of MMIO execution.
//!
//! Original 26A434 T8152 SPTM VA 0xfffffff0270cc75c..0xfffffff0270cc870
//! constructs the two words; VA 0xfffffff0270cc7f0 submits them with STP.
//! DSB ISH, TLBI VALE1OS and DSB OSH follow at cc810..cc818. Decoding a
//! payload does not publish it or complete that architectural ordering.
use crate::Result;
use stela_contracts::refuse;

const PAGE_SHIFT: u32 = 14;
const PAGE_FIELD: u64 = (1 << 28) - 1;
const RANGE: u64 = PAGE_FIELD << PAGE_SHIFT;
const SID_SHIFT: u32 = 48;
const SID: u64 = 0xff << SID_SHIFT;
const INSTANCE_SHIFT: u32 = 56;
const INSTANCE: u64 = 0xf << INSTANCE_SHIFT;
const CLASS_SHIFT: u32 = 60;
const CLASS: u64 = 3 << CLASS_SHIFT;

/// The separate TRAD600 context-table publication command. Original SPTM
/// d366c..d36b8 duplicates the parent CTE slot into fields17:12/5:0 and
/// places SID in31:24. It broadcasts to every TRAD, checking ESB/DISR after
/// each write, then polls604 busy0 on every instance. Encoding does not
/// complete those obligations or the DMB ISHST/DSB SY publication barriers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextCommand {
    sid: u8,
    slot: u8,
}

impl ContextCommand {
    pub(super) fn new(sid: usize, slot: u16) -> Result<Self> {
        let sid = u8::try_from(sid)
            .map_err(|_| refuse!("gen3 DART publication SID exceeds its native command field"))?;
        if slot >= 64 {
            return Err(refuse!(
                "gen3 DART publication context slot exceeds its native command field"
            ));
        }
        Ok(Self {
            sid,
            slot: slot as u8,
        })
    }

    pub const fn sid(self) -> u8 {
        self.sid
    }

    pub const fn slot(self) -> u8 {
        self.slot
    }

    pub const fn word(self) -> u32 {
        (self.sid as u32) << 24 | (self.slot as u32) << 12 | self.slot as u32
    }
}

/// The recovered invalidation classes. Range endpoints are page numbers,
/// as supplied by the original request. Decoding does not infer whether the
/// final boundary is inclusive or exclusive in the hardware invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    All,
    Stream,
    Range { start_page: u32, end_page: u32 },
}

/// One original aperture submission, containing both 64-bit words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Command {
    instance: u8,
    sid: u8,
    operation: Operation,
}

impl Command {
    /// Validate a complete request before it has any device effect. Unknown
    /// classes and fields are unsupported, not weakened invalidations.
    pub fn decode(words: [u64; 2]) -> Result<Self> {
        let [first, second] = words;
        if first & !(RANGE | SID | INSTANCE | CLASS) != 0 || second & !RANGE != 0 {
            return Err(refuse!("gen3 DART TLBI payload contains unmodeled fields"));
        }
        let operation = match (first & CLASS) >> CLASS_SHIFT {
            class @ (0 | 1) => {
                if first & RANGE != 0 || second != 0 {
                    return Err(refuse!("gen3 DART non-range TLBI carries range fields"));
                }
                if class == 0 {
                    Operation::All
                } else {
                    Operation::Stream
                }
            }
            3 => {
                let start_page = ((first & RANGE) >> PAGE_SHIFT) as u32;
                let end_page = (second >> PAGE_SHIFT) as u32;
                if start_page > end_page {
                    return Err(refuse!("gen3 DART TLBI range endpoints are reversed"));
                }
                Operation::Range {
                    start_page,
                    end_page,
                }
            }
            _ => return Err(refuse!("gen3 DART TLBI command class is unsupported")),
        };
        Ok(Self {
            instance: ((first & INSTANCE) >> INSTANCE_SHIFT) as u8,
            sid: ((first & SID) >> SID_SHIFT) as u8,
            operation,
        })
    }

    /// Check routing before delivering a command to an instance. This is
    /// validation only; completion belongs to the owning ordering boundary.
    pub fn validate_target(self, instance: u8, streams: usize) -> Result<()> {
        if self.instance != instance {
            return Err(refuse!(
                "gen3 DART TLBI instance tag does not match its target"
            ));
        }
        if !(1..=256).contains(&streams) {
            return Err(refuse!(
                "gen3 DART TLBI target has an invalid native stream count"
            ));
        }
        if usize::from(self.sid) >= streams {
            return Err(refuse!(
                "gen3 DART TLBI stream is outside its target profile"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(class: u64, instance: u64, sid: u64) -> u64 {
        class << CLASS_SHIFT | instance << INSTANCE_SHIFT | sid << SID_SHIFT
    }

    #[test]
    fn original_whole_instance_stream_and_bounded_range_payloads_decode() {
        for (words, operation) in [
            ([header(0, 15, 255), 0], Operation::All),
            ([header(1, 15, 255), 0], Operation::Stream),
            (
                [
                    header(3, 15, 255) | 7 << PAGE_SHIFT,
                    PAGE_FIELD << PAGE_SHIFT,
                ],
                Operation::Range {
                    start_page: 7,
                    end_page: PAGE_FIELD as u32,
                },
            ),
        ] {
            let command = Command::decode(words).unwrap();
            assert_eq!(command.instance, 15);
            assert_eq!(command.sid, 255);
            assert_eq!(command.operation, operation);
            command.validate_target(15, 256).unwrap();
            assert!(command.validate_target(14, 256).is_err());
            assert!(command.validate_target(15, 16).is_err());
            assert!(command.validate_target(15, 0).is_err());
            assert!(command.validate_target(15, 257).is_err());
        }
    }

    #[test]
    fn neither_half_can_hide_unknown_fields_or_an_unrecovered_command_class() {
        for words in [
            [header(2, 0, 0), 0],
            [header(1, 0, 0) | 1, 0],
            [header(3, 0, 0), 1],
            [header(3, 0, 0) | 1 << 42, 0],
            [header(3, 0, 0), 1 << 42],
            [header(3, 0, 0) | 1 << 62, 0],
            [header(0, 0, 0), 1 << PAGE_SHIFT],
            [header(1, 0, 0) | 1 << PAGE_SHIFT, 0],
            [header(3, 0, 0) | 2 << PAGE_SHIFT, 1 << PAGE_SHIFT],
        ] {
            assert!(Command::decode(words).is_err(), "{words:x?}");
        }
    }

    #[test]
    fn publication_command_does_not_truncate_sid_or_context_slot() {
        assert_eq!(ContextCommand::new(255, 63).unwrap().word(), 0xff03_f03f);
        for (sid, slot) in [
            (256, 0),
            (usize::MAX, 63),
            (0, 64),
            (0, 2047),
            (0, u16::MAX),
        ] {
            assert!(ContextCommand::new(sid, slot).is_err());
        }
    }
}
