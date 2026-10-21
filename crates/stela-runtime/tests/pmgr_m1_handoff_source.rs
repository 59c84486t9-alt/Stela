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
    for index in 0..3 {
        let name = format!("function-conf_isp_ref{index}_clk_freq");
        let property = isp.property(&name).unwrap();
        assert_eq!(property.len(), 20);
        assert_eq!(word(property, 0), 0x99);
        assert_eq!(word(property, 4), 0x49535043); // ISPC
        assert_eq!(word(property, 8), index);
    }
    assert!(isp.property("function-conf_isp_ref3_clk_freq").is_none());
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

#[test]
#[ignore = "requires original M1 Pro kernelcache and J314s LLB; no Apple images are committed"]
fn complete_t6000_request_routes_preserve_wait_and_provider_boundaries() {
    let bytes = kernelcache();
    for (start, end, digest) in [
        (
            0x2ef6954,
            0x2ef6ae0,
            "5f78fe102ed3256745654d36f194cf75101c3a81a7e6d900cbec23559d5f219e",
        ),
        (
            0x2f08414,
            0x2f084bc,
            "a02cc8402b357f4c14642862ea91cc3304b0952210044a3a4260c555ca374ace",
        ),
        (
            0x2f0a498,
            0x2f0a550,
            "ed4326f6f931af2ac085e1a7750354633865e01d65394cd5cd63d3a3e8f3cad2",
        ),
        (
            0x2f0a8e0,
            0x2f0a9d4,
            "e8b00c80b50ac68b8b12a72c84138339f3deab8e915c166fbaf5619869ef391a",
        ),
        (
            0x2b2e458,
            0x2b2e538,
            "8b30327f842f642218e0a6e986f4c7d455f9476c68fec3a137435eb391767678",
        ),
        (
            0x2b4affc,
            0x2b4b1ec,
            "8cded4ff1c9695ad0cf835cb88ceb3326bb33e11e7ab3d52f3c5bb8271cbfdf5",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    // Resolve actual original call stubs through their pinned chained-fixup
    // metadata. This is source identity, not a fabricated authenticated pointer
    // installed in the executing guest.
    assert_eq!(quad(&bytes, 0x133dee0), 0x8011000002b2e458); // readPMGRReg
    assert_eq!(quad(&bytes, 0x133df08), 0x8011000002b2e4c8); // writePMGRReg
    assert_eq!(quad(&bytes, 0x133dfe8), 0x8011000002b4affc); // CIO wait callback
    assert_eq!(quad(&bytes, 0x133df98), 0x8011000002b2e978); // readPMGRClkGenSOCReg
    assert_eq!(word(&bytes, 0x2b2e9bc), 0x52800b61); // clock-gen RegMap5b
    for (offset, opcode) in [
        (0x2ef6abc, 0x52800003), // GPCE waits mask10 == zero, only target-on path
        (0x2f08458, 0x52981815), // CPM first control1c0c0
        (0x2f0848c, 0x110022b5), // three writes advance by8
        (0x2f0a4dc, 0x121a6008), // ISP divider/enable replacement
        (0x2f0a4e0, 0x12067508), // ISP source selection replacement
        (0x2f0a4e8, 0x33080689), // source bits25:24, divider bits5:0
        (0x2f0a50c, 0x52a80002), // poll ISP bit30 clear
    ] {
        assert_eq!(word(&bytes, offset), opcode);
    }
    assert_eq!(branch_target(&bytes, 0x2f0a500), 0x2f25904);
    assert_eq!(branch_target(&bytes, 0x2f0a53c), 0x2f258b4);
    // VDD_CIO is a feature-qualified provider transaction, not another direct
    // MMIO completion. Its persistent enableMask and callback must remain owned.
    assert_eq!(word(&bytes, 0x2f0a908), 0x52800941); // feature4a
    assert_eq!(word(&bytes, 0x2f0a974), 0xb905c92a); // retain enableMask
    assert_eq!(word(&bytes, 0x2f0a9ac), 0xd73f0910); // actual provider call
    let llb = original(
        "STELA_TEST_PMGR_M1_LLB",
        "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1",
    );
    for (start, end, digest) in [
        (
            0x236b38,
            0x236bb0,
            "20493a0b686596ab76aa37de99ec6550c90fada2ed44c386ef20d03f15dfce3d",
        ),
        (
            0x23f250,
            0x23f298,
            "d2fa93419cccf9b8a2fcd60f89cd2b0cbb1c4ba6bed2b67c042b7b776ddc95ec",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&llb[start..end])), digest);
    }
    // Native source performs f -> poll20 -> 2f; a later program polls40
    // before its first auxiliary51 write. None selects a PC from an AP request.
    assert_eq!(quad(&llb, 0x236b40), 0x28e098000);
    assert_eq!(quad(&llb, 0x236b48), 15);
    assert_eq!(quad(&llb, 0x236b70), 0x20);
    assert_eq!(quad(&llb, 0x236b78), 0x20);
    assert_eq!(quad(&llb, 0x236b90), 0x2f);
    assert_eq!(quad(&llb, 0x23f270), 0x40);
    assert_eq!(quad(&llb, 0x23f288), 0x28e09a000);
    assert_eq!(quad(&llb, 0x23f290), 0x51);
}

#[test]
#[ignore = "requires original J314s LLB; original storage and copied-cleanup lifetime guards"]
fn original_j314s_cram_aperture_consumers_and_copied_cleanup_are_exact() {
    let bytes = original(
        "STELA_TEST_PMGR_M1_LLB",
        "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1",
    );
    for (start, end, digest) in [
        (
            0x0,
            0x1bc,
            "84da23dc0681899fc5b564a70c12e1b830ab8580ed309d9546b845efdb6e8d24",
        ),
        (
            0xcf260,
            0xcf294,
            "9e29b912e96203e4a4829734f31f247edea493dccf995b444b48725c812a0bba",
        ),
        (
            0x15450,
            0x15468,
            "c7a33cac2d3a857faa9efeb894eb7fe77d64a514673fe10d8d3015e2858dfed5",
        ),
        (
            0x224e8,
            0x22688,
            "dd3adf4ea53fc3b09127e1f4b2afce8a7ba92b476b94a9645d0c02b62cf8165d",
        ),
        (
            0x226c8,
            0x226f0,
            "b84362351694dca88cad34b878121f4a06d5ece480c7493134df9c475c47f484",
        ),
        (
            0xa53b0,
            0xa5410,
            "17f825324943567697102c9c01e4470cbd204d95ed2159b494cfcf7609ac5c0f",
        ),
        (
            0xf616c,
            0xf61a4,
            "d48624b15de5528912e1878e1e3ab490c669e712a4fe6ab5772feb8096fc4404",
        ),
        (
            0xf57ec,
            0xf58e0,
            "4d2e820a27f95a241f20471ef00fe94958c914a1f112e9ac25e66548844ea2d0",
        ),
        (
            0x2c740,
            0x2cafc,
            "d0890f97d8e2b1da2eca0256b04ed880b766e0ee7af03721944362d047c71d75",
        ),
        (
            0xf7c60,
            0xf7cd8,
            "27b40ab1d0c851f9c4d96da40177c1357775d54a9cbebc2acee8e2fe0be3bc51",
        ),
        (
            0x102a08,
            0x102a70,
            "8eeaf0be51c235bec42ce7b5a6f8f2461d9ebdca94b194578b3fbe3413bd89e5",
        ),
        (
            0x102dd8,
            0x102de8,
            "5e20a4b30e198d46b8735dc19b7702758e4f3ebc423b470eee19294d4244bdb2",
        ),
        (
            0x59134,
            0x591fc,
            "d93a633da1d7c1f8c87a813e87f08d231c70fd0c521a8750d610008a6402df88",
        ),
        (
            0x25dc8,
            0x25dfc,
            "c5d0a6017b0b45cf6231651ce73ab9bf821891ef1cb393ffb7afa1ccaf77e3bb",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    let base = quad(&bytes, 0x226c8);
    let end = quad(&bytes, 0x226d0);
    assert_eq!((base, end), (0x1fc000000, 0x1fc3c0000));
    assert_eq!(end - base, 0x3c0000);
    assert_eq!(quad(&bytes, 0x380), 0x1fc058000); // linked image start
    assert_eq!(quad(&bytes, 0x388), 0x1fc2a11c0); // source image extent
    assert_eq!(quad(&bytes, 0x3c0), 0x1fc2d1dd0); // additional runtime extent
    assert!(quad(&bytes, 0x388) < quad(&bytes, 0x3c0));
    assert!(quad(&bytes, 0x3c0) < end);
    assert_eq!(quad(&bytes, 0x3d8), 0x1fc038000);
    assert_eq!(quad(&bytes, 0x3e0), 0x1fc03c000); // first explicit zero-store interval
    assert_eq!(branch_target(&bytes, 0x28), 0x282c0); // before relocation/initialization
    assert_eq!(word(&bytes, 0xcf274), 0xf0000ce3); // actual runtime-tail flag address
    assert_eq!(word(&bytes, 0xcf278), 0x91178063);
    assert_eq!(word(&bytes, 0xcf27c), 0x39400063); // unknown byte read before memory helper stores
    assert_eq!(word(&bytes, 0x1a8), 0xa8817d5f); // actual early STP xzr pair
    assert_eq!(branch_target(&bytes, 0x1b8), 0x224e8);
    assert_eq!(quad(&bytes, 0x22660), 0x1fc038000); // startup SP
    assert_eq!(branch_target(&bytes, 0x2250c), 0xf5210); // first identity load/store helper
    // Copied source extent and its runtime scratch bounds are distinct from
    // physical storage. The original code translates that runtime address.
    assert_eq!(quad(&bytes, 0x22628), 0x10064000000);
    assert_eq!(quad(&bytes, 0x22630) - quad(&bytes, 0x22628), 0x4000);
    assert_eq!(branch_target(&bytes, 0xf5888), 0xcf804); // source span copy
    assert_eq!(branch_target(&bytes, 0xf58a4), 0xcf770); // remaining scratch initialization
    assert_eq!(branch_target(&bytes, 0x102a14), 0xf57ec); // prepare copied cleanup
    assert_eq!(branch_target(&bytes, 0x102a18), 0xf7c60); // actual table translation
    assert_eq!(branch_target(&bytes, 0xf7c74), 0x22a40); // select translation regime
    assert_eq!(branch_target(&bytes, 0xf7cd4), 0xf7afc); // page-table descriptor walk
    assert_eq!(branch_target(&bytes, 0x102de4), 0x59134); // final transfer adapter
    assert_eq!(branch_target(&bytes, 0x591b0), 0x108368);
    assert_eq!(branch_target(&bytes, 0x108368), 0x25dc8); // returns runtime scratch bounds
    assert_eq!(word(&bytes, 0x591f4), 0xd63f0b1f); // actual authenticated indirect call
    // Release is inside the copied extent, not a standalone callable helper.
    assert_eq!(word(&bytes, 0x2c910), 0xd51bf702); // allocation count cleared before poll
    assert_eq!(branch_target(&bytes, 0x2ca48), 0x2cac0);
    // Tail uses PC-relative copied positions and scrubs its preceding prefix;
    // its code must remain live outside the revoked CRAM view until RET.
    assert_eq!(word(&bytes, 0x2cac8), 0xa8817c1f);
    assert_eq!(word(&bytes, 0x2caf8), 0xd65f03c0);
}

#[test]
#[ignore = "requires matching original J314s LLB/iBoot; complete physical alias occurrence and source consumers"]
fn original_physical_counter_alias_is_read_only_and_separate_from_siq_tuning() {
    let llb = original(
        "STELA_TEST_PMGR_M1_LLB",
        "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1",
    );
    for (bytes, direct, target, digest) in [
        (
            &llb,
            [0xf568c, 0xf56d4],
            0xf5678,
            "6a62c5a6ac10b9d3e1c97d1a64122f2d88ac3d1d2aba30aab12d9cd205a8fe2e",
        ),
        (
            &iboot(),
            [0x12268c, 0x1226d4],
            0x122678,
            "0e9fcfb65e270c8f78c9019ce0f748571dbc64d50ad33cddd05e0ab1fe73e0ce",
        ),
    ] {
        let occurrences = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
            .filter_map(|(index, bytes)| {
                let opcode = u32::from_le_bytes(*bytes);
                matches!(
                    opcode & 0xffffffe0,
                    0xd53cfa80 | 0xd51cfa80 | 0xd53cfaa0 | 0xd51cfaa0 | 0xd53cfac0 | 0xd51cfac0
                )
                .then_some((index * 4, opcode))
            })
            .collect::<Vec<_>>();
        assert_eq!(occurrences, [(0x190, 0xd51cfa9f), (0x438, 0xd53cfaa0)]);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes[target..target + 0x7c])),
            digest
        );
        assert_eq!(branch_target(bytes, 0x58c), 0x438);
        assert_eq!(branch_target(bytes, 0x5f4), 0x438);
        assert_eq!(branch_target(bytes, 0x5fc), 0x438);
        for caller in direct {
            assert_eq!(branch_target(bytes, caller), 0x438);
        }
        // The same physical counter drives actual CNTP TVAL/CTL timing.
        assert_eq!(branch_target(bytes, target + 0x30), 0x440);
        assert_eq!(branch_target(bytes, target + 0x38), 0x42c);
        assert_eq!(branch_target(bytes, target + 0x58), 0x440);
        assert_eq!(word(bytes, 0x440), 0xd51be200); // CNTP_TVAL_EL0
        assert_eq!(word(bytes, 0x42c), 0xd51be220); // CNTP_CTL_EL0
        assert_eq!(branch_target(bytes, 0x524), 0x44c);
        assert_eq!(word(bytes, 0x44c), 0xd53be000); // actual CNTFRQ_EL0
    }
    assert_eq!(branch_target(&llb, 0x119c20), 0x58c); // first actual live-entry caller
    // After the alias, the next actual entry requirement is the original
    // physical SEP transport. Metadata identifies ownership, not a ready bit.
    let bytes = adt();
    let root = Node::root(&bytes).unwrap();
    let io = root.child("arm-io").unwrap();
    let sep = io.child("sep").unwrap();
    assert_eq!(
        sep.property("compatible"),
        Some(&b"iop-sep,ascwrap-v4\0"[..])
    );
    assert!(sep.pairs("reg").unwrap().contains(&(0x196400000, 0x6c000)));
    assert_eq!(sep.cells32("clock-gates").unwrap(), [0x12a]);
    assert_eq!(sep.cells32("power-gates").unwrap(), [0x12a]);
    let (child, parent, _) = io
        .ranges()
        .unwrap()
        .into_iter()
        .find(|&(child, _, length)| 0x196400000 >= child && 0x196400000 - child < length)
        .unwrap();
    assert_eq!(parent + 0x196400000 - child, 0x396400000);
    assert_eq!(quad(&llb, 0x1a1628), 0x811400008110); // original transport offsets
    assert_eq!(word(&llb, 0x15654), 0xb940014a); // actual 32-bit physical read
}
