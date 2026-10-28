//! Ordered SIO firmware setup effects, without a synthetic setup ACK.
//!
//! Selected 26A434 firmware VA0x6898 consumes 24-byte tunable rows:
//! {u32 offset,u32 width,u64 mask,u64 value}. Width0 skips a row;
//! width4/8 perform a read, compare masked bits, then write only if changed.
//! Reads and writes are physical MMIO, distinct from DMA of the table.
//! The machine must route them through its normal checked device path.
pub mod control;

use super::Error;
use alloc::vec::Vec;
use {stela_contracts::bus::Width, stela_contracts::dma::Port};

const ROW_BYTES: usize = 24;
/// Native resource bound, not a hardware table-length claim. Larger tables
/// remain an explicit requirement rather than causing unchecked allocation.
const MAX_TABLE_BYTES: u32 = 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct Row {
    address: u64,
    width: Width,
    mask: u64,
    value: u64,
}

/// One actual physical device access to perform outside the firmware borrow.
/// A mapped range does not qualify its hardware: the actual routed bank must
/// accept this access and its normal PMGR preflight/settle still applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Read {
        address: u64,
        width: Width,
    },
    Write {
        address: u64,
        width: Width,
        value: u64,
    },
}

/// One claimed operation. The private sequence prevents a stale completion
/// from retiring an identical later read/write in the same setup program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effect {
    sequence: u64,
    request: Request,
}
impl Effect {
    pub fn request(self) -> Request {
        self.request
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectResult {
    Read(u64),
    Written,
}

/// Routed access failures retain their original type and detail. Platform
/// code neither depends on the machine's error type nor replaces its reason.
#[derive(Debug, PartialEq, Eq)]
pub enum FinishError<E> {
    Ownership(&'static str),
    Access(E),
}

/// An acquired immutable tunable table and its partially committed effects.
/// Loading snapshots and validates all rows before the first MMIO access.
/// Completion only means these setup effects committed; it grants no SIO
/// protocol version, functional DMA, device ownership or PMGR sink credit.
pub struct TunableProgram {
    rows: Vec<Row>,
    row: usize,
    write: Option<u64>,
    sequence: u64,
    in_flight: Option<Effect>,
}

impl TunableProgram {
    pub fn load(
        port: &mut Port<'_, '_>,
        table_iova: u64,
        byte_len: u32,
        physical_base: u64,
        physical_span: u64,
    ) -> Result<Self, Error> {
        if byte_len > MAX_TABLE_BYTES || !byte_len.is_multiple_of(ROW_BYTES as u32) {
            return Err(Error::Unsupported(
                "SIO tunable table length is not qualified",
            ));
        }
        table_iova
            .checked_add(u64::from(byte_len))
            .ok_or(Error::Unsupported("SIO tunable table exceeds I/O space"))?;
        let end = physical_base
            .checked_add(physical_span)
            .ok_or(Error::Unsupported(
                "SIO tunable physical range exceeds address space",
            ))?;
        let mut data = alloc::vec![0; byte_len as usize];
        // Port is RAM-only; it cannot silently convert a guest register
        // aperture into successful table data. No MMIO effect has started.
        port.read(table_iova, &mut data)?;
        let mut rows = Vec::with_capacity(data.len() / ROW_BYTES);
        for row in data.as_chunks::<ROW_BYTES>().0 {
            let offset = u32::from_le_bytes(row[..4].try_into().unwrap());
            let width = u32::from_le_bytes(row[4..8].try_into().unwrap());
            // Original firmware skips width0 before reading its offset,
            // mask or value. Do not invent an access for a disabled row.
            if width == 0 {
                continue;
            }
            let width = match width {
                4 => Width::Word,
                8 => Width::Double,
                _ => return Err(Error::Unsupported("SIO tunable width is not qualified")),
            };
            let address = physical_base
                .checked_add(u64::from(offset))
                .filter(|address| address.is_multiple_of(width.bytes()))
                .filter(|address| {
                    address
                        .checked_add(width.bytes())
                        .is_some_and(|last| last <= end)
                })
                .ok_or(Error::Unsupported(
                    "SIO tunable exceeds its aligned physical range",
                ))?;
            rows.push(Row {
                address,
                width,
                mask: u64::from_le_bytes(row[8..16].try_into().unwrap()),
                value: u64::from_le_bytes(row[16..].try_into().unwrap()),
            });
        }
        Ok(Self {
            rows,
            row: 0,
            write: None,
            sequence: 0,
            in_flight: None,
        })
    }

    /// Claim one effect, then release all mutable firmware/bus borrows before
    /// routing it. Reentrant service cannot claim or execute it a second time.
    pub fn begin_effect(&mut self) -> Result<Option<Effect>, Error> {
        if self.in_flight.is_some() {
            return Err(Error::Unsupported("SIO setup effect is already in flight"));
        }
        let Some(row) = self.rows.get(self.row) else {
            return Ok(None);
        };
        let request = match self.write {
            Some(value) => Request::Write {
                address: row.address,
                width: row.width,
                value,
            },
            None => Request::Read {
                address: row.address,
                width: row.width,
            },
        };
        let effect = Effect {
            sequence: self.sequence,
            request,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Unsupported("SIO setup effect sequence is exhausted"))?;
        self.in_flight = Some(effect);
        Ok(Some(effect))
    }

    /// Retire only the claimed actual result. A failed routed access releases
    /// the claim for retry, retaining phase and any earlier read result.
    /// The caller propagates Access(E) intact; it must not substitute success.
    pub fn finish_effect<E>(
        &mut self,
        expected: Effect,
        result: Result<EffectResult, E>,
    ) -> Result<(), FinishError<E>> {
        if self.in_flight != Some(expected) {
            return Err(FinishError::Ownership(
                "SIO setup result has no matching in-flight owner",
            ));
        }
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                self.in_flight = None;
                return Err(FinishError::Access(error));
            }
        };
        let row = self.rows[self.row];
        match (expected.request, result) {
            (Request::Read { .. }, EffectResult::Read(value)) if value & !row.width.mask() == 0 => {
                let wanted = row.value & row.mask;
                if value & row.mask == wanted {
                    self.row += 1;
                } else {
                    // The original word path compares 64-bit masked bits,
                    // then stores only the low32 bits. Preserve that ordering
                    // even when a mask/value has bits outside a word access.
                    self.write = Some(((value & !row.mask) | wanted) & row.width.mask());
                }
            }
            (Request::Write { .. }, EffectResult::Written) => {
                self.write = None;
                self.row += 1;
            }
            _ => {
                return Err(FinishError::Ownership(
                    "SIO setup result does not match its access width or direction",
                ));
            }
        }
        self.in_flight = None;
        Ok(())
    }

    pub fn complete(&self) -> bool {
        self.row == self.rows.len() && self.in_flight.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use {
        crate::platform::apple::gpio::Gpio, stela_contracts::bus::Access,
        stela_contracts::bus::Bus, stela_contracts::bus::Direction,
        stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError,
        stela_contracts::bus::refuse, stela_contracts::dma::Physical,
        stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::AicInput,
        stela_contracts::interrupt::InterruptLatch,
    };

    const TABLE: u64 = 0x8000;
    const BANK: u64 = 0x238300000;

    fn table(rows: &[(u32, u32, u64, u64)]) -> Vec<u8> {
        rows.iter()
            .flat_map(|&(offset, width, mask, value)| {
                let mut data = [0; 24];
                data[..4].copy_from_slice(&offset.to_le_bytes());
                data[4..8].copy_from_slice(&width.to_le_bytes());
                data[8..16].copy_from_slice(&mask.to_le_bytes());
                data[16..].copy_from_slice(&value.to_le_bytes());
                data
            })
            .collect()
    }

    fn load(data: &[u8], base: u64, span: u64) -> Result<TunableProgram, Error> {
        let mut memory = Ram::new(TABLE, data.len());
        memory.bytes.copy_from_slice(data);
        let mut physical = Physical;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            memory: &mut memory,
            iommu: &mut physical,
            stream: 2,
            access: &mut access,
        };
        TunableProgram::load(&mut port, TABLE, data.len() as u32, base, span)
    }

    fn gpio() -> Gpio {
        Gpio::new(2, vec![AicInput::new(0, 30)], &[0, 1], vec![]).unwrap()
    }

    fn step(
        program: &mut TunableProgram,
        bus: &mut Bus,
        access: &mut Access<'_>,
    ) -> Result<(), FinishError<MmioError>> {
        let effect = program.begin_effect().unwrap().expect("pending effect");
        let result = match effect.request() {
            Request::Read { address, width } => {
                bus.read(address, width, access).map(EffectResult::Read)
            }
            Request::Write {
                address,
                width,
                value,
            } => bus
                .write(address, width, value, access)
                .map(|()| EffectResult::Written),
        };
        program.finish_effect(effect, result)
    }

    /// Only the one injected refusal is synthetic. All accepted accesses go
    /// through a real GPIO model and change its actual output state.
    struct RefuseWriteOnce {
        bank: Gpio,
        reads: usize,
        writes: usize,
    }
    impl MmioDevice for RefuseWriteOnce {
        fn name(&self) -> &'static str {
            "SIO setup test boundary"
        }
        fn read(
            &mut self,
            offset: u64,
            width: Width,
            access: &mut Access<'_>,
        ) -> Result<u64, MmioError> {
            self.reads += 1;
            self.bank.read(offset, width, access)
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            value: u64,
            access: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            self.writes += 1;
            if self.writes == 1 {
                return Err(refuse(
                    self.name(),
                    offset,
                    width,
                    Direction::Write,
                    "test write refused before effects",
                ));
            }
            self.bank.write(offset, width, value, access)
        }
    }

    #[test]
    fn mounted_native_bank_retains_read_value_and_phase_across_write_refusal() {
        let mut program = load(&table(&[(0, 4, 1, 0)]), BANK, 8).unwrap();
        let mut bus = Bus::new();
        let id = bus.add(Box::new(RefuseWriteOnce {
            bank: gpio(),
            reads: 0,
            writes: 0,
        }));
        bus.map(id, BANK, 8, 0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        step(&mut program, &mut bus, &mut access).unwrap();
        let refusal = step(&mut program, &mut bus, &mut access).unwrap_err();
        assert_eq!(
            refusal,
            FinishError::Access(refuse(
                "SIO setup test boundary",
                0,
                Width::Word,
                Direction::Write,
                "test write refused before effects"
            ))
        );
        assert!(!program.complete());
        assert_eq!(
            bus.device::<RefuseWriteOnce>(id).unwrap().bank.output(0),
            Some(true)
        );
        // Another owner changes the bank after our read. A retry must execute
        // the retained write2, not repeat the read and recalculate from0xe.
        bus.device_mut::<RefuseWriteOnce>(id)
            .unwrap()
            .bank
            .write(0, Width::Word, 0xe, &mut access)
            .unwrap();
        step(&mut program, &mut bus, &mut access).unwrap();
        let bank = bus.device::<RefuseWriteOnce>(id).unwrap();
        assert_eq!((bank.reads, bank.writes), (1, 2));
        assert_eq!(bank.bank.output(0), Some(false));
        assert!(program.complete());
        assert_eq!(program.begin_effect().unwrap(), None);
    }

    #[test]
    fn later_unmapped_bank_preserves_prior_native_effect_and_refuses_completion() {
        let mut program = load(&table(&[(0, 4, 1, 0), (0x1000, 4, 1, 0)]), BANK, 0x1008).unwrap();
        let mut bus = Bus::new();
        let first = bus.add(Box::new(gpio()));
        bus.map(first, BANK, 8, 0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        step(&mut program, &mut bus, &mut access).unwrap();
        step(&mut program, &mut bus, &mut access).unwrap();
        assert_eq!(bus.device::<Gpio>(first).unwrap().output(0), Some(false));
        assert_eq!(
            step(&mut program, &mut bus, &mut access),
            Err(FinishError::Access(MmioError::Unmapped {
                address: BANK + 0x1000,
                width: Width::Word
            }))
        );
        assert!(!program.complete());
        let second = bus.add(Box::new(gpio()));
        bus.map(second, BANK + 0x1000, 8, 0).unwrap();
        step(&mut program, &mut bus, &mut access).unwrap();
        step(&mut program, &mut bus, &mut access).unwrap();
        assert!(program.complete());
        assert_eq!(bus.device::<Gpio>(first).unwrap().output(0), Some(false));
        assert_eq!(bus.device::<Gpio>(second).unwrap().output(0), Some(false));
    }

    #[test]
    fn reentry_stale_results_and_wrong_access_results_cannot_retire_owned_effects() {
        let mut program = load(&table(&[(0, 4, 1, 1), (0, 4, 1, 1)]), BANK, 8).unwrap();
        let first = program.begin_effect().unwrap().unwrap();
        assert!(program.begin_effect().is_err());
        assert!(
            program
                .finish_effect::<()>(first, Ok(EffectResult::Written))
                .is_err()
        );
        assert!(program.begin_effect().is_err());
        assert!(
            program
                .finish_effect::<()>(first, Ok(EffectResult::Read(1 << 32)))
                .is_err()
        );
        program
            .finish_effect::<()>(first, Ok(EffectResult::Read(3)))
            .unwrap();
        let second = program.begin_effect().unwrap().unwrap();
        assert_eq!(first.request(), second.request());
        assert_ne!(first, second);
        assert!(
            program
                .finish_effect::<()>(first, Ok(EffectResult::Read(3)))
                .is_err()
        );
        assert!(!program.complete());
        program
            .finish_effect::<()>(second, Ok(EffectResult::Read(3)))
            .unwrap();
        assert!(program.complete());
    }

    #[test]
    fn exact_word_and_double_masking_skips_only_unchanged_bits_and_disabled_rows() {
        let mut program = load(
            &table(&[
                (u32::MAX, 0, u64::MAX, u64::MAX),
                (0, 8, 0xff00, 0x1234),
                (8, 4, 1 << 40, 1 << 40),
            ]),
            BANK,
            16,
        )
        .unwrap();
        let read = program.begin_effect().unwrap().unwrap();
        assert_eq!(
            read.request(),
            Request::Read {
                address: BANK,
                width: Width::Double
            }
        );
        program
            .finish_effect::<()>(read, Ok(EffectResult::Read(0xabcd)))
            .unwrap();
        let write = program.begin_effect().unwrap().unwrap();
        assert_eq!(
            write.request(),
            Request::Write {
                address: BANK,
                width: Width::Double,
                value: 0x12cd
            }
        );
        program
            .finish_effect::<()>(write, Ok(EffectResult::Written))
            .unwrap();
        let read = program.begin_effect().unwrap().unwrap();
        program
            .finish_effect::<()>(read, Ok(EffectResult::Read(3)))
            .unwrap();
        let write = program.begin_effect().unwrap().unwrap();
        // Original width4 compares 64-bit masked values then truncates store.
        assert_eq!(
            write.request(),
            Request::Write {
                address: BANK + 8,
                width: Width::Word,
                value: 3
            }
        );
        program
            .finish_effect::<()>(write, Ok(EffectResult::Written))
            .unwrap();
        assert!(program.complete());
        assert!(load(&[], BANK, 0).unwrap().complete());
    }

    #[test]
    #[ignore = "requires pinned original J473 26A434 SIO firmware; no Apple image is committed"]
    fn original_firmware_proves_typed_tunable_rows_and_conditional_physical_writes() {
        use sha2::{Digest, Sha256};
        let path =
            std::env::var("STELA_TEST_SIO_FIRMWARE").expect("pinned original SIO firmware path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "356dbeba0e7f5d0a36e3db2eddce66dca6869e8629aa322f4da1addf0a9780cc"
        );
        // Selected original PRELOAD __TEXT: VA0/file offset0x1000.
        // Bounded source-integrity evidence, never production dispatch keys.
        for (address, opcode) in [
            (0x68e8, 0xb85fc12c),
            (0x68ec, 0x3400034c),
            (0x68f0, 0xb85f812a),
            (0x68f4, 0xa940352b),
            (0x68f8, 0x7100119f),
            (0x6900, 0x7100219f),
            (0x6908, 0xf940040c),
            (0x690c, 0x8a0b01ad),
            (0x6910, 0xf86a698e),
            (0x6914, 0x8a0b01cf),
            (0x6920, 0x8a2b01cb),
            (0x6924, 0xaa0d016b),
            (0x6928, 0xf82a698b),
            (0x6938, 0xb86a698e),
            (0x6940, 0xeb0d01ff),
            (0x6948, 0x0a2b01cb),
            (0x694c, 0x2a0d016b),
            (0x6950, 0xb82a698b),
            (0x6954, 0x91006129),
            (0x6958, 0xf1000508),
            (0x695c, 0x54fffc61),
            (0x6a1c, 0x39400c28),
            (0x6a2c, 0x7100a51f),
        ] {
            let offset = address + 0x1000;
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original SIO setup at VA{address:#x}"
            );
        }
        for (parameter, target) in [
            (0x1a, 0x6ba0),
            (0x1b, 0x6bb8),
            (0x1c, 0x6c48),
            (0x1d, 0x6c34),
            (0x1e, 0x6a8c),
            (0x1f, 0x6b30),
            (0x20, 0x6aa8),
            (0x21, 0x6a74),
            (0x22, 0x6bd8),
            (0x23, 0x6bf0),
            (0x24, 0x6c84),
            (0x25, 0x6c6c),
            (0x28, 0x6a5c),
            (0x29, 0x6ad0),
            (0x2a, 0x6ca0),
        ] {
            assert_eq!(
                0x6a4c + usize::from(bytes[0x1c590 + parameter - 1]) * 4,
                target
            );
        }
    }

    #[test]
    fn malformed_or_unreadable_table_refuses_before_any_physical_effect_is_owned() {
        for rows in [
            vec![(0, 2, 1, 0)],
            vec![(0, 4, 1, 0), (2, 4, 1, 0)],
            vec![(0, 4, 1, 0), (8, 4, 1, 0)],
        ] {
            assert!(load(&table(&rows), BANK, 8).is_err());
        }
        assert!(load(&[0; 23], BANK, 8).is_err());
        assert!(load(&table(&[(0, 8, 1, 1)]), u64::MAX - 3, 8).is_err());
        let mut memory = Ram::new(TABLE, 24);
        let mut physical = Physical;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            memory: &mut memory,
            iommu: &mut physical,
            stream: 2,
            access: &mut access,
        };
        assert!(matches!(
            TunableProgram::load(&mut port, TABLE, 48, BANK, 8),
            Err(Error::Dma(_))
        ));
        assert!(matches!(
            TunableProgram::load(&mut port, TABLE, MAX_TABLE_BYTES + 1, BANK, 8),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            TunableProgram::load(&mut port, u64::MAX - 1, 24, BANK, 8),
            Err(Error::Unsupported(_))
        ));
    }
}
