//! Original-source bridge tuning/model oracle kept with the native model.

use stela_soc_data::pmgr::t6000::tunables::{Profile, Tuning, check_optional_mask};
const fn t(offset: u32, mask: u32, value: u32) -> Tuning {
    Tuning {
        offset,
        mask,
        value,
    }
}
use sha2::{Digest, Sha256};
use {
    crate::platform::apple::bridge::Bridge, stela_contracts::adt::Node,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::Width,
};

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn pointer(bytes: &[u8], offset: usize) -> usize {
    // Source chained-fixup payload only, never an authenticated guest pointer.
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as u32 as usize
}
fn original(variable: &str, digest: &str) -> Vec<u8> {
    let bytes =
        std::fs::read(std::env::var(variable).expect("pinned original J314s input")).unwrap();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), digest);
    bytes
}
// Exact metadata lists selected by all native first-die guard paths under
// the checked profile. Source guard/constructor hashes are checked below.
const LISTS: [&[usize]; 193] = [
    &[0x133bcb8],
    &[0x1316b90],
    &[0x132f988],
    &[0x1316ab0],
    &[0x131a398],
    &[0x133db20],
    &[0x133bf00],
    &[],
    &[0x1339808],
    &[0x133ae68],
    &[0x133ae68],
    &[0x132dda8],
    &[0x133bdd8],
    &[0x131a268],
    &[0x13248b8],
    &[0x13248b8],
    &[0x13248b8],
    &[0x13248b8],
    &[0x133d860],
    &[0x132def8],
    &[0x133dc30],
    &[0x131a700],
    &[0x13163c8],
    &[0x131bb48],
    &[0x13249b8],
    &[0x1318720],
    &[0x1338dd8],
    &[0x1313aa8],
    &[0x1324378],
    &[0x1316e58],
    &[0x132e828],
    &[0x131e4c0],
    &[0x1338c08],
    &[0x132e808],
    &[0x1316388],
    &[0x131e450],
    &[0x132e958],
    &[0x1318740],
    &[0x1338d98],
    &[0x1316830],
    &[0x132ee68],
    &[0x13186d0],
    &[0x1316cc8],
    &[0x13397e8],
    &[0x13395a8],
    &[0x1316990],
    &[0x131bb28],
    &[0x133c9c8],
    &[0x1324a60],
    &[0x132e7e8],
    &[0x132e2e0],
    &[0x1316ef8],
    &[0x1338df8],
    &[0x13397c8],
    &[0x1316a70],
    &[0x1320308],
    &[0x1339688],
    &[0x132fad8],
    &[0x1324c90],
    &[0x133bb08],
    &[0x133bc98],
    &[0x133d960],
    &[0x133d9f0],
    &[0x133dd20],
    &[0x13249e8],
    &[0x132ccd0],
    &[0x1338c28],
    &[0x1316920],
    &[0x1318680],
    &[0x131a750],
    &[0x1339568],
    &[0x133d7f0],
    &[0x1320c08, 0x1320c18],
    &[0x1320c08, 0x1320c18],
    &[0x133cc40, 0x133cc50],
    &[0x133cc40, 0x133cc50],
    &[0x133cc40, 0x133cc50],
    &[0x133cc40, 0x133cc50],
    &[0x132d1e8, 0x132d1f8],
    &[0x132d1e8, 0x132d1f8],
    &[0x132d1e8, 0x132d1f8],
    &[0x132d1e8, 0x132d1f8],
    &[0x13372b8, 0x13372d8, 0x1337368, 0x13373a8],
    &[0x13372b8, 0x13372d8, 0x1337368, 0x13373a8],
    &[0x1317808, 0x1317818, 0x1317848, 0x1317888],
    &[0x1317808, 0x1317818, 0x1317848, 0x1317888],
    &[0x131ad28, 0x131ae40],
    &[0x131afe0, 0x131ae40],
    &[0x131b0f8, 0x131ae40],
    &[0x131b210, 0x131ae40],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x13393f8, 0x1339428, 0x1339440],
    &[0x131c3c8, 0x131c3f8],
    &[0x131c3c8, 0x131ccb0],
    &[0x131c3c8, 0x131ccb0],
    &[0x132e598, 0x132e5c8],
    &[0x132e598, 0x132e5c8],
    &[0x131fdf0, 0x131fe20, 0x131fe30],
    &[0x131fdf0, 0x131fe20, 0x131fe30],
    &[0x131fdf0, 0x131fe20, 0x131fe30],
    &[0x131fdf0, 0x131fe20, 0x131fe30],
    &[0x1327da0, 0x1327dd0],
    &[0x1329090, 0x13290c8],
    &[0x1329090, 0x132a2b8],
    &[0x1327da0, 0x132b5c8],
    &[0x1322580, 0x13225b8],
    &[0x1322580, 0x13225b8],
    &[0x1322580, 0x13225b8],
    &[0x1330808, 0x1330840],
    &[0x1330808, 0x1330840],
    &[0x1330808, 0x1330840],
    &[0x1330808, 0x1330840],
    &[0x1319198, 0x1319218],
    &[0x1319198, 0x1319218],
    &[0x133b248, 0x133b2c8],
    &[0x132f018, 0x132f0b0],
    &[0x133a3d0, 0x133a420],
    &[0x133a3d0, 0x133a420],
    &[0x1319d10, 0x1319d60],
    &[0x131dde0, 0x131de48],
    &[0x133c1d8, 0x133c258],
    &[0x132e978, 0x132e9c8],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
    &[],
];
#[test]
#[ignore = "oracle: STELA_TEST_PMGR_M1_ADT, STELA_TEST_PMGR_M1_KERNELCACHE"]
fn original_all_193_bridge_programs_keep_masks_order_and_dt_bounds() {
    let bytes = original(
        "STELA_TEST_PMGR_M1_KERNELCACHE",
        "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90",
    );
    for (start, end, digest) in [
        (
            0x2ef5dd8,
            0x2ef5e10,
            "9568f8e8048eefe27c0278fb0ac0b3e780b12b430389046af25013b0d8c8cee4",
        ),
        (
            0x2f0c374,
            0x2f0c3dc,
            "694095f26bad19048e19f53b0656d6616377a9d1d4c9ec0573d590fbae35394f",
        ),
        (
            0x2b1fba0,
            0x2b1fd18,
            "b2a2771901b183c92f047e3a3575025f855ca6e474c97dfff7787a0ee4ab86d5",
        ),
        (
            0x2f0c40c,
            0x2f0c6bc,
            "8a68fe84da18bc7ff4e4fbd7490bd41c680de6a3eb54d12dd642c2d2565fb929",
        ),
        (
            0x2f0c704,
            0x2f0c7a8,
            "ca79f38c3bfc1257b4cf346f0e993fb377f9b9cf3cdfe0b6eaa8683e821e4a86",
        ),
        (
            0x2f0c7b0,
            0x2f0cbbc,
            "67ab8425fc308057993018e2c372f7b9cb87a8b42e91ba50015b5d52cd1b1da3",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    for (start, end, digest) in [
        (
            0x2b15bbc,
            0x2b15c5c,
            "5480e09b90c6cf1d9df173a092c7d0b0fd0cfbebfae6e6ac6cba8d6094605d1c",
        ),
        (
            0x2b39cd0,
            0x2b39ec8,
            "00903d063a2e5e0142c1d9b67d0b4c0e327c81225c66fdadd43cca198586e551",
        ),
        (
            0x2b3a2c4,
            0x2b3af70,
            "84029520831cc028b5f337aa14e685660cb1e35392f7df16d4f2b4cb8a8b1288",
        ),
        (
            0x2b3af70,
            0x2b3b3f8,
            "8a4bc03fee120473cfb60671c63480d794d070f6d23ad4005008aa6961173520",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    assert_eq!(word(&bytes, 0x2b3a674), 0x39400389); // full u8 side, no boolean projection
    assert_eq!(word(&bytes, 0x2b3a694), 0x52800c0c); // stride0x60
    let profile = Profile::new(0x6000, 8, 0).unwrap();
    let mut count = 0;
    for (id, lists) in LISTS.iter().enumerate() {
        let mut source = Vec::new();
        for &list in *lists {
            for index in 0..2000 {
                let descriptor = pointer(&bytes, list + index * 8);
                if descriptor == 0 {
                    break;
                }
                assert_ne!(index, 1999, "complete terminated metadata list");
                let head = word(&bytes, descriptor);
                assert_eq!(head >> 28, 4);
                let payload = pointer(&bytes, descriptor + 4);
                let mask = word(&bytes, payload);
                assert_eq!(
                    &bytes[payload + 8..payload + 16],
                    &[0; 8],
                    "native callback must be qualified, never ignored"
                );
                source.push(t(
                    head & 0x0fff_ffff,
                    mask,
                    word(&bytes, payload + 4) & mask,
                ));
            }
        }
        count += source.len();
        assert_eq!(profile.program(id).unwrap(), source);
    }
    assert_eq!(count, 3299);
    let data = original(
        "STELA_TEST_PMGR_M1_ADT",
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad",
    );
    let root = Node::root(&data).unwrap();
    let io = root.child("arm-io").unwrap();
    assert_eq!(io.cells32("chip-revision").unwrap(), [0]);
    let pmgr = io.child("pmgr").unwrap();
    let registers = pmgr.pairs("reg").unwrap();
    let headers = pmgr.property("bridge-counters").unwrap();
    let configs = pmgr
        .property("bridge-counter-configs")
        .unwrap()
        .as_chunks::<36>()
        .0;
    let axi = pmgr.property("axi2af-axi-config").unwrap();
    assert_eq!(pmgr.property("optional-bridge-mask").unwrap().len(), 7 * 4);
    check_optional_mask(pmgr.property("optional-bridge-mask").unwrap()).unwrap();
    assert!(check_optional_mask(&[0; 24]).is_err());
    assert!(!profile.program(40).unwrap().is_empty());
    for id in 0..193 {
        let header: [u8; 4] = headers[id * 4..id * 4 + 4].try_into().unwrap();
        let selected =
            &configs[usize::from(header[2])..usize::from(header[2]) + usize::from(header[3])];
        let model = Bridge::t6000(
            profile,
            id,
            header,
            selected,
            Some(axi[id * 4..id * 4 + 4].try_into().unwrap()),
            &[],
        )
        .unwrap();
        for (offset, bytes) in model.spans() {
            assert!(
                offset + bytes <= registers[48 + id].1,
                "bridge{id} native word outside actual view"
            );
        }
        // No metadata-driven default word can satisfy a native RMW.
        let mut model = model;
        let mut irq = stela_contracts::interrupt::InterruptLatch::new();
        let mut access = stela_contracts::bus::Access::new(0, 0, &mut irq);
        for row in profile.program(id).unwrap() {
            assert!(
                model
                    .read(u64::from(row.offset), Width::Word, &mut access)
                    .is_err()
            );
        }
    }
}
