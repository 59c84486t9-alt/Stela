use super::*;
use alloc::{boxed::Box, vec};
use {
    crate::platform::apple::gpio::Gpio, stela_contracts::bus::Access, stela_contracts::bus::Bus,
    stela_contracts::bus::Direction, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::refuse, stela_contracts::dma::Physical,
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
/// through a real GPIO model and change its output state.
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
fn mounted_native_bank_keeps_read_value_and_phase_across_write_refusal() {
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
    // the write2, not repeat the read and recalculate from0xe.
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
#[ignore = "oracle: STELA_TEST_SIO_FIRMWARE"]
fn original_firmware_proves_typed_tunable_rows_and_conditional_physical_writes() {
    use sha2::{Digest, Sha256};
    let path = std::env::var("STELA_TEST_SIO_FIRMWARE").expect("pinned original SIO firmware path");
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
