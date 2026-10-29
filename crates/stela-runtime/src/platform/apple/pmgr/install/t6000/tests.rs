use super::*;
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec,
};
use {
    crate::platform::apple::pmgr::install::Action, crate::platform::apple::pmgr::install::Blockage,
    crate::platform::apple::pmgr::install::FinishError,
    crate::platform::apple::pmgr::install::Outcome, stela_contracts::bus::Access,
    stela_contracts::bus::Bus, stela_contracts::bus::Direction, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::dma::Memory,
    stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::InterruptLatch,
};

const CAPTURED: u64 = 0xa5a55aa5;
#[derive(Default)]
struct Bank {
    words: BTreeMap<u64, u64>,
    writes: BTreeMap<u64, usize>,
    fault: Option<u64>,
}
impl MmioDevice for Bank {
    fn name(&self) -> &'static str {
        "supplied T6000 installation test bank"
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        self.words
            .get(&offset)
            .copied()
            .ok_or(MmioError::Unsupported {
                device: self.name(),
                offset,
                width,
                direction: Direction::Read,
                reason: "no supplied register observation",
            })
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.words.insert(offset, value);
        *self.writes.entry(offset).or_default() += 1;
        if self.fault == Some(offset) {
            return Err(MmioError::Unsupported {
                device: self.name(),
                offset,
                width,
                direction: Direction::Write,
                reason: "committed physical effect followed by failure",
            });
        }
        Ok(())
    }
}
fn images() -> Vec<NativeImage> {
    sequences()
        .into_iter()
        .filter(|row| !row.shared)
        .map(|row| NativeImage {
            sequence: row.id,
            counted_words: 1,
            // Explicit test-supplied opaque native image. It is installed as
            // data here, never executed or acknowledged as a native program.
            bytes: [0xa0000000 | u32::from(row.id), 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        })
        .collect()
}
fn bus(installation: &Installation) -> (Bus, stela_contracts::bus::DeviceId) {
    let mut addresses = BTreeSet::new();
    for step in &installation.steps {
        match step {
            Step::Write(write) if !(SRAM_BASE..SRAM_LIMIT).contains(&write.address) => {
                addresses.insert(write.address);
            }
            Step::Modify { address, .. } => {
                addresses.insert(*address);
            }
            _ => {}
        }
    }
    let mut bank = Bank::default();
    for address in &addresses {
        bank.words.insert(*address, CAPTURED);
    }
    let mut bus = Bus::new();
    let id = bus.add(Box::new(bank));
    for address in addresses {
        bus.map(id, address, 4, address).unwrap();
    }
    (bus, id)
}
fn route(
    action: Action,
    ram: &mut Ram,
    bus: &mut Bus,
    access: &mut Access<'_>,
) -> Outcome<MmioError> {
    match action {
        Action::Read { address, width } => match bus.read(address, width, access) {
            Ok(value) => Outcome::Read(value),
            Err(error) => Outcome::Uncertain(error),
        },
        Action::Write(write) if (SRAM_BASE..SRAM_LIMIT).contains(&write.address) => {
            assert!(ram.write(
                write.address,
                &write.value.to_le_bytes()[..write.width.bytes() as usize]
            ));
            Outcome::Written
        }
        Action::Write(write) => match bus.write(write.address, write.width, write.value, access) {
            Ok(()) => Outcome::Written,
            Err(error) => Outcome::Uncertain(error),
        },
        Action::DmbSy => panic!("no invented ordering instruction in this source phase"),
    }
}
#[test]
fn complete_family_installs_real_pointer_ram_aliases_and_actual_binding_fields() {
    let mut install = programs(0x20, Some(0), images()).unwrap();
    let (mut bus, id) = bus(&install);
    let mut ram = Ram::new(SRAM_BASE, (SRAM_LIMIT - SRAM_BASE) as usize);
    ram.bytes.fill(0xcc); // Explicit owned test initialization, not native reset.
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    let mut pointers = 0;
    let mut first_image = false;
    while let Some(claim) = install.begin().unwrap() {
        let action = install.dispatch(&claim).unwrap();
        if let Action::Write(write) = action {
            if write.width == Width::Double {
                assert!(!first_image);
                pointers += 1;
            } else if (CODE_BASE..SRAM_LIMIT).contains(&write.address) {
                first_image = true;
                assert_eq!(pointers, 144);
            }
        }
        install
            .finish(&claim, route(action, &mut ram, &mut bus, &mut access))
            .unwrap();
    }
    assert!(install.published());
    assert_eq!(install.placements().len(), 72);
    assert_eq!(install.committed_reads(), 32);
    assert_eq!(install.committed_writes(), 301);
    let mut preceding = None;
    for (placement, row) in install.placements().iter().zip(sequences()) {
        assert!(placement.code.is_multiple_of(32));
        let mut pointer = [0; 8];
        assert!(ram.read(
            placement.table + u64::from(placement.slot) * 8,
            &mut pointer
        ));
        assert_eq!(u64::from_le_bytes(pointer), placement.code >> 4);
        let mut code = [0; 8];
        assert!(ram.read(placement.code, &mut code));
        if row.shared {
            assert_eq!(placement.bytes, 0);
            assert_eq!(Some((placement.code, code)), preceding);
        } else {
            assert_eq!(placement.bytes, 8);
            assert_eq!(
                u32::from_le_bytes(code[..4].try_into().unwrap()),
                0xa0000000 | u32::from(row.id)
            );
            assert_eq!(&code[4..], &[0; 4]);
            preceding = Some((placement.code, code));
        }
    }
    let bank = bus.device::<Bank>(id).unwrap();
    assert_eq!(bank.words[&0x2925c0200], 0x1000);
    assert_eq!(bank.words[&0x2922c0300], 0x1100);
    assert_eq!(bank.words[&0x28e099004], 0x292f012);
    assert_eq!(bank.words[&0x2925c0208], 0x103);
    assert_eq!(bank.words[&0x2922c030c], 1);
    assert_eq!(bank.words[&(GPCE_BINDINGS + 4)], CAPTURED | 2 | (3 << 16));
    assert_eq!(bank.words[&(GPCE_BINDINGS + 8)], CAPTURED | 4 | (5 << 16));
    assert_eq!(bank.words[&(GPCE_BINDINGS + 0x28)], 2);
    assert_eq!(bank.writes[&(GPCE_BINDINGS + 0x28)], 1);
    assert_eq!(install.history(), History::default());
}
#[test]
fn physical_partial_failure_quarantines_current_write_without_replaying_a_prefix() {
    let mut install = programs(0x10, Some(1), images()).unwrap();
    let (mut bus, id) = bus(&install);
    bus.device_mut::<Bank>(id).unwrap().fault = Some(GPCE_BINDINGS + 4);
    let mut ram = Ram::new(SRAM_BASE, (SRAM_LIMIT - SRAM_BASE) as usize);
    ram.bytes.fill(0xcc);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    loop {
        let claim = install.begin().unwrap().unwrap();
        let action = install.dispatch(&claim).unwrap();
        match install.finish(&claim, route(action, &mut ram, &mut bus, &mut access)) {
            Ok(()) => {}
            Err(FinishError::Uncertain(_)) => break,
            other => panic!("unexpected routed outcome {other:?}"),
        }
    }
    assert!(matches!(install.blockage(), Some(Blockage::Uncertain(_))));
    assert!(matches!(install.begin(), Err(Error::Blocked)));
    assert!(!install.published());
    let bank = bus.device::<Bank>(id).unwrap();
    assert_eq!(bank.writes[&(GPCE_BINDINGS + 4)], 1);
    assert_eq!(bank.words[&(GPCE_BINDINGS + 4)], CAPTURED | 2);
    assert_eq!(bank.words[&0x2925c0204], 0x100);
    assert!(!bank.writes.contains_key(&(GPCE_BINDINGS + 0x28)));
    let mut untouched = [0; 4];
    assert!(ram.read(CODE_BASE, &mut untouched));
    assert_eq!(untouched, [0xcc; 4]);
}
#[test]
fn no_default_revision_history_image_alias_or_out_of_bounds_reservation() {
    assert!(matches!(
        programs(0, Some(0), images()),
        Err(Error::UnqualifiedRevision)
    ));
    assert!(matches!(
        programs(0x20, None, images()),
        Err(Error::UnknownHistory)
    ));
    let mut supplied = images();
    supplied.pop();
    assert!(matches!(
        programs(0x20, Some(0), supplied),
        Err(Error::MissingImage(224))
    ));
    let mut supplied = images();
    supplied.push(NativeImage {
        sequence: 65,
        counted_words: 0,
        bytes: vec![0; 4],
    });
    assert!(matches!(
        programs(0x20, Some(0), supplied),
        Err(Error::UnexpectedImage(65))
    ));
    let mut supplied = images();
    supplied[0].bytes = vec![0; (SRAM_LIMIT - CODE_BASE) as usize];
    supplied[0].counted_words = supplied[0].bytes.len() as u32 / 4 - 1;
    assert!(matches!(
        programs(0x20, Some(0), supplied),
        Err(Error::CodeExhausted(0))
    ));
}
#[cfg(feature = "std")]
#[test]
#[ignore = "oracle: STELA_TEST_PMGR_M1_LLB"]
fn original_complete_descriptors_and_binding_allocator_are_pinned() {
    use sha2::{Digest, Sha256};
    let llb = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").expect("original J314s LLB"))
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&llb)),
        "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
    );
    for (lo, hi, digest) in [
        (
            0x1337c,
            0x13c40,
            "1c4f0a6982a85fc2e0ef3ec23887175a163d53fa697f26f6bd02bfc08f2e7140",
        ),
        (
            0x47090,
            0x47d14,
            "a7037de932b795d7d4bc8911de86533b0f3ccd6a3d1ebc0ba7980c7cc3584b81",
        ),
        (
            0x49cf8,
            0x4a070,
            "58d7fef9b3a76a06258600c9bd261f04e962815552c02efba98227d9b387d7fa",
        ),
        (
            0x113e8,
            0x11658,
            "fcbd5fa7e33e51200c49daa4766d880c546961d79b19473347a4d3e89ce332ae",
        ),
        (
            0x240100,
            0x242100,
            "be49bc42a73b4af32744f24cb486a81aa3c4d96782a4adc75f17bcdf6ea82ad1",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
    }
    let word =
        |bytes: &[u8], offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    for mask in [8, 0x40, 0x40000] {
        let mut expected = Vec::new();
        for row in llb[0x240380..0x242100].as_chunks::<64>().0 {
            if word(row, 0x3c) & mask == 0 {
                continue;
            }
            expected.push(Sequence {
                id: word(row, 0) as u8,
                group: word(row, 4) as u8,
                slot: word(row, 0x28) as u8,
                shared: word(row, 0x38) == 1,
            });
        }
        expected.sort_by_key(|row| row.id);
        assert_eq!(sequences(), expected);
    }
    for group in 0..10 {
        let offset = 0x240100 + group * 64;
        assert_eq!(word(&llb, offset), group as u32);
        let address = u64::from_le_bytes(llb[offset + 0x18..offset + 0x20].try_into().unwrap());
        assert_eq!(address, TABLE_BASE + group as u64 * 0x100);
    }
}
