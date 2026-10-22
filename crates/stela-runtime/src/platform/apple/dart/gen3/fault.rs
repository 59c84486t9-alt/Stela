//! Per-SID fault capture and bitmap acknowledgement of gen3 and of t8110
//! revision 2.2, whose bank is the same: the Mac16 kernel's
//! `_DART_EXCEPTION` (VA 0xfffffe0009f32640) reads the 0x40-byte records and
//! the T8132 SPTM's CLEAR_EXCEPTION (VA 0xfffffff0270ce06c) writes the
//! pending words, at the offsets below.
//!
//! Original mac18g collection at VA fffffe0009289804 uses one 0x40-byte
//! record per SID, with a separate pending bitmap at TRAD4000. Its numbered
//! fault taxonomy and ordinary TRAD direction are recovered from the native
//! decoder. Other header fields, auxiliary AXI data and secondary-capture
//! behavior remain unqualified. Observations retain every raw summary bit;
//! failed DMA never fabricates a complete header from the known fields.
use crate::platform::apple::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::{vec, vec::Vec};

const PENDING: u64 = 0x4000;
const RECORDS: u64 = 0x8000;
const RECORD_BYTES: u64 = 0x40;
const ADDRESS_LOW: u64 = 8;
const ADDRESS_HIGH: u64 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Code {
    Invalid = 0,
    Write = 1,
    Read = 2,
    Drop = 3,
    AxiDecode = 4,
    Axi = 5,
    FillRegion = 6,
    Region = 7,
    CtrrWrite = 8,
    Apf = 9,
    Bpf = 10,
    SttMismatch = 11,
    SttFlush = 12,
    External = 13,
    IllegalSid = 14,
}

impl TryFrom<u8> for Code {
    type Error = &'static str;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Ok(match code {
            0 => Self::Invalid,
            1 => Self::Write,
            2 => Self::Read,
            3 => Self::Drop,
            4 => Self::AxiDecode,
            5 => Self::Axi,
            6 => Self::FillRegion,
            7 => Self::Region,
            8 => Self::CtrrWrite,
            9 => Self::Apf,
            10 => Self::Bpf,
            11 => Self::SttMismatch,
            12 => Self::SttFlush,
            13 => Self::External,
            14 => Self::IllegalSid,
            _ => return Err("per-SID DART observed fault code is outside the native decoder"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Level {
    Ttbr = 0,
    Cte = 1,
    Ste = 2,
    Pte = 3,
}

/// A supplied original TRAD summary, not a generated fault header. The
/// native classifier at mac18g92889b4..9288cc0 and jump table9288e68
/// identify these fields. Unknown bits are retained without interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedSummary {
    raw: u32,
    code: Code,
}

impl ObservedSummary {
    pub fn trad(raw: u32) -> Result<Self, &'static str> {
        if raw & 0x600 != 0 {
            return Err("per-SID DART non-TRAD summary access type is unqualified");
        }
        let code = Code::try_from((raw & 0xf) as u8)?;
        Ok(Self { raw, code })
    }

    pub const fn raw(self) -> u32 {
        self.raw
    }

    pub const fn code(self) -> Code {
        self.code
    }

    pub const fn write(self) -> bool {
        self.raw & 0x100 != 0
    }

    pub const fn invalid_level(self) -> Option<Level> {
        if !matches!(self.code, Code::Invalid) {
            return None;
        }
        Some(match self.raw >> 12 & 3 {
            0 => Level::Ttbr,
            1 => Level::Cte,
            2 => Level::Ste,
            _ => Level::Pte,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub code: Code,
    pub level: Level,
    pub write: bool,
    pub address: u64,
}

impl Record {
    /// Only the recovered class/level fields. This is an internal DMA error
    /// identifier, never a complete hardware fault header or its access type.
    pub const fn class(self) -> u32 {
        match self.code {
            Code::Invalid => (self.level as u32) << 12,
            code => code as u32,
        }
    }
}

pub struct Capture {
    records: Vec<Option<Record>>,
    pending: Vec<u32>,
}

impl Capture {
    pub fn new(streams: usize) -> Result<Self, &'static str> {
        if !(1..=256).contains(&streams) {
            return Err("per-SID DART fault stream count is outside its native bounds");
        }
        Ok(Self {
            records: vec![None; streams],
            pending: vec![0; streams.div_ceil(32)],
        })
    }

    /// Capture one real failed transfer. A second pending capture refuses
    /// until its retention/overflow contract is recovered, preserving the
    /// existing evidence without inventing overwrite or overflow behavior.
    pub fn capture(&mut self, sid: usize, record: Record) -> Result<(), &'static str> {
        let entry = self
            .records
            .get_mut(sid)
            .ok_or("per-SID DART fault SID is outside its native bounds")?;
        if entry.is_some() {
            return Err("per-SID DART secondary fault capture is unsupported");
        }
        *entry = Some(record);
        self.pending[sid / 32] |= 1 << (sid % 32);
        Ok(())
    }

    pub fn pending(&self, word: usize) -> Result<u32, &'static str> {
        self.pending
            .get(word)
            .copied()
            .ok_or("per-SID DART fault bitmap word is outside its native bounds")
    }

    pub fn record(&self, sid: usize) -> Result<Option<Record>, &'static str> {
        self.records
            .get(sid)
            .copied()
            .ok_or("per-SID DART fault SID is outside its native bounds")
    }

    /// The pending bitmap's recovered write-one acknowledgement. Removing a
    /// pending record here does not prescribe any historical MMIO readback.
    pub fn acknowledge(&mut self, word: usize, bits: u32) -> Result<(), &'static str> {
        let pending = self
            .pending
            .get_mut(word)
            .ok_or("per-SID DART fault bitmap word is outside its native bounds")?;
        let streams = (self.records.len() - word * 32).min(32);
        let valid = u32::MAX >> (32 - streams);
        if bits & !valid != 0 {
            return Err("per-SID DART fault acknowledgement names an out-of-profile SID");
        }
        *pending &= !bits;
        for sid in word * 32..self.records.len().min((word + 1) * 32) {
            if bits & (1 << (sid % 32)) != 0 {
                self.records[sid] = None;
            }
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.records.fill(None);
        self.pending.fill(0);
    }
}

impl MmioDevice for Capture {
    fn name(&self) -> &'static str {
        "dart-sid-fault"
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse("dart-sid-fault", offset, width, Direction::Read, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(fail(
                "per-SID DART fault registers are aligned 32-bit words",
            ));
        }
        if let Some(word) = offset.checked_sub(PENDING).filter(|offset| *offset < 32) {
            return self
                .pending((word / 4) as usize)
                .map(u64::from)
                .map_err(fail);
        }
        if let Some(relative) = offset.checked_sub(RECORDS) {
            let sid = usize::try_from(relative / RECORD_BYTES)
                .map_err(|_| fail("per-SID DART fault SID is outside its native bounds"))?;
            let record = self.record(sid).map_err(fail)?;
            let record = record
                .ok_or_else(|| fail("per-SID DART historical fault readback is unqualified"))?;
            return match relative % RECORD_BYTES {
                ADDRESS_LOW => Ok(u64::from(record.address as u32)),
                ADDRESS_HIGH => Ok(record.address >> 32),
                0 => Err(fail(
                    "per-SID DART complete fault access-type header is unsupported",
                )),
                _ => Err(fail("per-SID DART auxiliary fault data is unsupported")),
            };
        }
        Err(fail("unknown gen3 DART fault register"))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse("dart-sid-fault", offset, width, Direction::Write, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(fail(
                "per-SID DART fault registers are aligned 32-bit words",
            ));
        }
        if let Some(word) = offset.checked_sub(PENDING).filter(|offset| *offset < 32) {
            return self
                .acknowledge((word / 4) as usize, value as u32)
                .map_err(fail);
        }
        Err(fail(
            "unknown gen3 DART fault write or unrecovered acknowledgement",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    #[test]
    fn original_fault_taxonomy_keeps_observed_direction_and_unmodeled_bits() {
        // Original jump table9288e68, relative to9288b74, resolves the
        // source strings741e87d..741e95b. Reasons name decoder output;
        // they do not invent the hardware conditions generating each code.
        let reasons = [
            Code::Invalid,
            Code::Write,
            Code::Read,
            Code::Drop,
            Code::AxiDecode,
            Code::Axi,
            Code::FillRegion,
            Code::Region,
            Code::CtrrWrite,
            Code::Apf,
            Code::Bpf,
            Code::SttMismatch,
            Code::SttFlush,
            Code::External,
            Code::IllegalSid,
        ];
        for (code, reason) in reasons.into_iter().enumerate() {
            for write in [false, true] {
                for level in 0..4 {
                    let raw = 0xa5a5_00f0 | code as u32 | (u32::from(write) << 8) | level << 12;
                    let summary = ObservedSummary::trad(raw).unwrap();
                    assert_eq!(summary.raw(), raw);
                    assert_eq!(summary.code(), reason);
                    assert_eq!(summary.write(), write);
                    assert_eq!(summary.invalid_level().is_some(), code == 0);
                    if let Some(actual) = summary.invalid_level() {
                        assert_eq!(actual as u32, level);
                    }
                }
            }
        }
        for code in [15, 16, 255] {
            assert!(Code::try_from(code).is_err());
        }
        assert!(ObservedSummary::trad(15).is_err());
        for access_type in [0x200, 0x400, 0x600] {
            assert!(ObservedSummary::trad(access_type).is_err());
            assert!(ObservedSummary::trad(access_type | 0x100 | 7).is_err());
        }
    }

    #[test]
    fn sid_words_keep_independent_records_and_acknowledge_only_selected_bits() {
        let mut capture = Capture::new(256).unwrap();
        for sid in [0, 31, 32, 255] {
            capture
                .capture(
                    sid,
                    Record {
                        code: Code::Write,
                        level: Level::Pte,
                        write: true,
                        address: 0x1000 * sid as u64,
                    },
                )
                .unwrap();
        }
        assert_eq!(capture.pending(0), Ok(0x8000_0001));
        assert_eq!(capture.pending(1), Ok(1));
        assert_eq!(capture.pending(7), Ok(1 << 31));
        assert_eq!(capture.record(255).unwrap().unwrap().class(), 1);
        let saved = capture.record(31).unwrap().unwrap();
        assert_eq!(
            capture.capture(31, saved),
            Err("per-SID DART secondary fault capture is unsupported")
        );
        capture.acknowledge(0, 1).unwrap();
        assert_eq!(capture.record(0), Ok(None));
        assert_eq!(capture.record(31), Ok(Some(saved)));
        assert_eq!(capture.pending(0), Ok(1 << 31));
        assert!(capture.pending(8).is_err());
        assert!(capture.record(256).is_err());
        capture.clear();
        assert_eq!(capture.pending(7), Ok(0));
        assert_eq!(capture.record(255), Ok(None));
    }

    #[test]
    fn native_pending_and_address_registers_never_fabricate_a_complete_fault_dump() {
        let mut capture = Capture::new(64).unwrap();
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        capture
            .capture(
                33,
                Record {
                    code: Code::Read,
                    level: Level::Pte,
                    write: false,
                    address: 0x12_3456_789a,
                },
            )
            .unwrap();
        let record = RECORDS + 33 * RECORD_BYTES;
        assert_eq!(capture.read(PENDING + 4, Width::Word, &mut a), Ok(2));
        assert_eq!(
            capture.read(record + ADDRESS_LOW, Width::Word, &mut a),
            Ok(0x3456_789a)
        );
        assert_eq!(
            capture.read(record + ADDRESS_HIGH, Width::Word, &mut a),
            Ok(0x12)
        );
        for offset in [record, record + 4, record + 0x10, record + 0x14] {
            assert!(capture.read(offset, Width::Word, &mut a).is_err());
        }
        assert!(capture.write(record, Width::Word, 0, &mut a).is_err());
        assert_eq!(capture.pending(1), Ok(2));
        capture.write(PENDING + 4, Width::Word, 2, &mut a).unwrap();
        assert_eq!(capture.read(PENDING + 4, Width::Word, &mut a), Ok(0));
        assert!(
            capture
                .read(record + ADDRESS_LOW, Width::Word, &mut a)
                .is_err()
        );
    }

    #[test]
    fn reserved_acknowledgement_bits_cannot_clear_a_valid_capture() {
        let mut capture = Capture::new(19).unwrap();
        let record = Record {
            code: Code::Read,
            level: Level::Pte,
            write: false,
            address: 1,
        };
        capture.capture(18, record).unwrap();
        assert!(capture.acknowledge(0, (1 << 18) | (1 << 19)).is_err());
        assert_eq!(capture.pending(0), Ok(1 << 18));
        assert_eq!(capture.record(18), Ok(Some(record)));
        capture.acknowledge(0, 1 << 18).unwrap();
        assert_eq!(capture.record(18), Ok(None));
    }
}
