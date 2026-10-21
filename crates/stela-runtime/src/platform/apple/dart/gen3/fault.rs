//! Gen3 per-SID fault capture and bitmap acknowledgement.
//!
//! Original mac18g collection at VA fffffe0009289804 uses one 0x40-byte
//! record per SID, with a separate pending bitmap at TRAD4000. Its numbered
//! fault code and table level are recovered; its access-type header fields,
//! auxiliary AXI data and secondary-capture behavior are not. This component
//! retains direction as typed state and never fabricates a complete header.
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
    Region = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Level {
    Ttbr = 0,
    Cte = 1,
    Ste = 2,
    Pte = 3,
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
            return Err("gen3 DART fault stream count is outside its native bounds");
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
            .ok_or("gen3 DART fault SID is outside its native bounds")?;
        if entry.is_some() {
            return Err("gen3 DART secondary fault capture is unsupported");
        }
        *entry = Some(record);
        self.pending[sid / 32] |= 1 << (sid % 32);
        Ok(())
    }

    pub fn pending(&self, word: usize) -> Result<u32, &'static str> {
        self.pending
            .get(word)
            .copied()
            .ok_or("gen3 DART fault bitmap word is outside its native bounds")
    }

    pub fn record(&self, sid: usize) -> Result<Option<Record>, &'static str> {
        self.records
            .get(sid)
            .copied()
            .ok_or("gen3 DART fault SID is outside its native bounds")
    }

    /// The pending bitmap's recovered write-one acknowledgement. Removing a
    /// pending record here does not prescribe any historical MMIO readback.
    pub fn acknowledge(&mut self, word: usize, bits: u32) -> Result<(), &'static str> {
        let pending = self
            .pending
            .get_mut(word)
            .ok_or("gen3 DART fault bitmap word is outside its native bounds")?;
        let streams = (self.records.len() - word * 32).min(32);
        let valid = u32::MAX >> (32 - streams);
        if bits & !valid != 0 {
            return Err("gen3 DART fault acknowledgement names an out-of-profile SID");
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
        "dart-gen3-fault"
    }

    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse("dart-gen3-fault", offset, width, Direction::Read, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(fail("gen3 DART fault registers are aligned 32-bit words"));
        }
        if let Some(word) = offset.checked_sub(PENDING).filter(|offset| *offset < 32) {
            return self
                .pending((word / 4) as usize)
                .map(u64::from)
                .map_err(fail);
        }
        if let Some(relative) = offset.checked_sub(RECORDS) {
            let sid = usize::try_from(relative / RECORD_BYTES)
                .map_err(|_| fail("gen3 DART fault SID is outside its native bounds"))?;
            let record = self.record(sid).map_err(fail)?;
            let record =
                record.ok_or_else(|| fail("gen3 DART historical fault readback is unqualified"))?;
            return match relative % RECORD_BYTES {
                ADDRESS_LOW => Ok(u64::from(record.address as u32)),
                ADDRESS_HIGH => Ok(record.address >> 32),
                0 => Err(fail(
                    "gen3 DART complete fault access-type header is unsupported",
                )),
                _ => Err(fail("gen3 DART auxiliary fault data is unsupported")),
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
        let fail = |reason| refuse("dart-gen3-fault", offset, width, Direction::Write, reason);
        if width != Width::Word || !offset.is_multiple_of(4) {
            return Err(fail("gen3 DART fault registers are aligned 32-bit words"));
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
            Err("gen3 DART secondary fault capture is unsupported")
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
