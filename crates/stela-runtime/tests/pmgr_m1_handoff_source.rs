//! Original J314s/T6000 source guards, independent of the earlier J473 ledger.
//! These qualify resource and access contracts, never physical reset values.
#![cfg(feature = "std")]

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use stela_runtime::machine::adt::Node;

fn original(variable: &str, digest: &str) -> Vec<u8> {
    let bytes =
        std::fs::read(std::env::var(variable).expect("pinned original J314s input")).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), digest);
    bytes
}
fn adt() -> Vec<u8> {
    original(
        "STELA_TEST_PMGR_M1_ADT",
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad",
    )
}
fn iboot() -> Vec<u8> {
    original(
        "STELA_TEST_PMGR_M1_IBOOT",
        "20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03",
    )
}
fn kernelcache() -> Vec<u8> {
    original(
        "STELA_TEST_PMGR_M1_KERNELCACHE",
        "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90",
    )
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn quad(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn half(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn branch_target(bytes: &[u8], offset: usize) -> usize {
    let opcode = word(bytes, offset);
    assert!(matches!(opcode >> 26, 0b000101 | 0b100101));
    offset.wrapping_add_signed(((opcode << 6) as i32 >> 4) as isize)
}
fn inventory(bytes: &[u8]) -> (BTreeMap<u16, [u8; 48]>, BTreeMap<u64, u16>) {
    let root = Node::root(bytes).unwrap();
    let io = root.child("arm-io").unwrap();
    let pmgr = io.child("pmgr").unwrap();
    assert_eq!(pmgr.property("compatible"), Some(&b"pmgr1,t6000\0"[..]));
    assert!(pmgr.property("ps-groups").is_none());
    let records = pmgr.property("devices").unwrap();
    assert_eq!(records.len(), 355 * 48);
    let placements = pmgr.cells32("ps-regs").unwrap();
    assert_eq!(placements.len(), 14 * 3);
    let registers = pmgr.pairs("reg").unwrap();
    assert_eq!(registers.len(), 241);
    let ranges = io.ranges().unwrap();
    let mut physical = BTreeMap::new();
    let mut by_id = BTreeMap::new();
    for record in records.as_chunks::<48>().0 {
        let id = half(record, 26);
        assert_ne!(id, 0, "this original uses the 16-bit ID format");
        assert!(by_id.insert(id, *record).is_none());
        if record[0] & 0x10 != 0 {
            continue;
        }
        let placement = &placements[usize::from(record[11]) * 3..][..3];
        let (base, size) = registers[placement[0] as usize];
        let offset = u64::from(placement[1]) + u64::from(record[10]) * 8;
        assert!(offset + 8 <= size);
        let address = base + offset;
        let (child, parent, _) = ranges
            .iter()
            .find(|&&(child, _, size)| address >= child && address - child < size)
            .unwrap();
        assert!(physical.insert(parent + address - child, id).is_none());
    }
    assert_eq!(physical.len(), 196);
    (by_id, physical)
}

#[test]
#[ignore = "requires original J314s ADT and iBoot; no Apple images are committed"]
fn original_m1_table_covers_all_196_physical_records_without_initial_state_credit() {
    let (_, physical) = inventory(&adt());
    let bytes = iboot();
    // The returned range is 349 sixteen-byte rows. The auxiliary fields are
    // not the all-zero J473 table and have no qualified initial-PS meaning.
    assert_eq!(word(&bytes, 0x42fa4), 0x5282ba0a); // byte extent 0x15d0
    let table = &bytes[0x1dd708..0x1decd8];
    assert_eq!(table.len(), 349 * 16);
    assert_eq!(
        hex::encode(Sha256::digest(table)),
        "f14f6b1010c752d13147cb1fb0f1576c8c9ab318d05b89a021ffea85b0881920"
    );
    let mut matched = BTreeSet::new();
    for row in table.as_chunks::<16>().0 {
        let address = quad(row, 0) & ((1 << 51) - 1);
        if physical.contains_key(&address) {
            assert!(matched.insert(address));
        }
        assert!(matches!(quad(row, 8), 0 | 3 | 4 | 5 | 6));
    }
    assert_eq!(matched, physical.keys().copied().collect());
    assert_eq!(quad(&bytes, 0x1de6b8), 0x28e5803a8);
    assert_eq!(
        quad(&bytes, 0x1de6c0),
        5,
        "auxiliary field, never an initial power level"
    );
    // Actual firmware setters read the physical register, preserve fields,
    // write a low-nibble target and poll target/current equality. Table
    // presence cannot substitute the original hardware reads or their effects.
    for (offset, opcode) in [
        (0x108d0, 0xb9400109), // read physical control
        (0x108e8, 0xb9000109), // clear bit28 through a physical store
        (0x108f8, 0xb9000109), // store target
        (0x1090c, 0x4a491108), // compare current nibble with target
        (0x11148, 0x9240c915), // physical PA field, not a state
    ] {
        assert_eq!(
            word(&bytes, offset),
            opcode,
            "original M1 setter {offset:#x}"
        );
    }
}

#[test]
#[ignore = "requires original J314s ADT; no Apple images are committed"]
fn original_isp_has_actual_camera_dart_sensor_and_performance_requirements() {
    let bytes = adt();
    let (records, physical) = inventory(&bytes);
    assert_eq!(physical[&0x28e5803a8], 0x125);
    assert_eq!(&records[&0x125][32..40], b"ISP_SYS\0");
    assert_eq!(half(&records[&0x125], 4), 0x7c);
    assert_eq!(half(&records[&0x7c], 4), 0x7a);
    // The two aliases have no independent PS register; both name the real
    // ISP_SYS parent. Performance nodes are not silently physical aliases.
    for id in [0x1d5, 0x1fb] {
        assert_ne!(records[&id][0] & 0x10, 0);
        assert_eq!(half(&records[&id], 4), 0x125);
    }
    for id in [0x1d6, 0x1d7] {
        assert_ne!(records[&id][0] & 0x10, 0);
        assert_eq!(half(&records[&id], 4), 0);
    }
    for (id, address) in [
        (0x75, 0x28e580128),
        (0x76, 0x28e580130),
        (0x77, 0x28e580138),
        (0x78, 0x28e580140),
    ] {
        assert_eq!(physical[&address], id);
    }
    let root = Node::root(&bytes).unwrap();
    let io = root.child("arm-io").unwrap();
    let isp = io.child("isp0").unwrap();
    let dart = io.child("dart-isp0").unwrap();
    assert_eq!(
        isp.property("compatible"),
        Some(&b"isp,h13-generic\0isp,s5l8960x\0"[..])
    );
    assert_eq!(dart.property("compatible"), Some(&b"dart,t6000\0"[..]));
    for property in ["clock-gates", "power-gates"] {
        assert_eq!(
            isp.cells32(property).unwrap(),
            [0x1d5, 0x75, 0x76, 0x77, 0x78, 0x1d6]
        );
        assert_eq!(dart.cells32(property).unwrap(), [0x1fb]);
    }
    let isp_registers = isp.pairs("reg").unwrap();
    assert_eq!(
        isp_registers,
        [(0x184000000, 0x4000000), (0x8e584000, 0x44)]
    );
    assert_eq!(dart.pairs("reg").unwrap().len(), 6);
    assert_eq!(
        isp.property("function-device_reset"),
        Some(&[0x99, 0, 0, 0, b'T', b'S', b'R', b'A', 0x25, 1, 0, 0][..])
    );
}

#[test]
#[ignore = "requires original M1 Pro kernelcache; no Apple image is committed"]
fn original_m1_restore_sweep_and_cio_geometry_are_separate_from_t8112() {
    let bytes = kernelcache();
    // IOService's software initial-power ordinal zero is not a physical PS
    // handoff value. Pin its exact return without interpreting it as one.
    assert_eq!(word(&bytes, 0x26740bc), 0xd2800000);
    for (start, end, digest) in [
        (
            0x2ef4f44,
            0x2ef5564,
            "1173133e2e884898a8b0f37dd4747314eef98bcebf3982ac865200efe8a2e584",
        ),
        (
            0x2ef6c4c,
            0x2ef7104,
            "9d9362488388beac302ca3c5e04259246d63b427be72bd3721c893a72a1198fb",
        ),
        (
            0x2b2b648,
            0x2b2ba84,
            "6da967b46c77f9d912dacbf622bd9dc3027b79faaa8429f7fa80db5270ed2c4c",
        ),
        (
            0x2b2ba84,
            0x2b2bd34,
            "0bd06a87f447d4ba5ea3a81409d56cd02e3affbc3d74b27225ed8b36a3c6ccc6",
        ),
        (
            0x2b446bc,
            0x2b44adc,
            "fd0fe3022977fd7ea6f44ff37c7b04ecb99f065522ad72ecc79f564ced5d2452",
        ),
        (
            0x2f0a720,
            0x2f0a7cc,
            "ecb38e666ddf93722fcd583727c128759fe77b12a074865893d7c9849b3fa5cc",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    assert_eq!(branch_target(&bytes, 0x2b2b724), 0x2b2ba84);
    assert_eq!(branch_target(&bytes, 0x2b2bcc0), 0x2b446bc);
    assert_eq!(branch_target(&bytes, 0x2b44a2c), 0x2b20344);
    assert_eq!(word(&bytes, 0x2b44a10), 0x54000340); // skip cached target f
    assert_eq!(word(&bytes, 0x2b44a24), 0x52800005); // auto=false, not initial PS
    // Source uses RegMap0 +1a034 with instance0/1, four ports per instance.
    // Direct low request writes and high response polling differ from T8112's
    // read|1 at RegMap0x63 +4000/+8000. Completion is still a hardware input.
    assert_eq!(word(&bytes, 0x2f0a754), 0x52a00029); // 0x10000 response mask
    assert_eq!(word(&bytes, 0x2f0a764), 0x52940696); // offset low16 a034
    assert_eq!(word(&bytes, 0x2f0a768), 0x72a00036); // offset high16 1
    assert_eq!(branch_target(&bytes, 0x2f0a778), 0x2f25784);
    assert_eq!(word(&bytes, 0x2f0a724), 0x34000522); // false path returns
}
