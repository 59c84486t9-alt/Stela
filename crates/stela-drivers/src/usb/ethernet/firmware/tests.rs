use super::*;

fn put(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn block(kind: u32, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    bytes
}
fn mac(pla: bool, old_usb: bool) -> Vec<u8> {
    let mut bytes = block(if pla { PLA } else { USB }, 72);
    put(&mut bytes, 8, 64);
    put(&mut bytes, 10, if pla || old_usb { 0xf800 } else { 0xe600 });
    put(&mut bytes, 12, 0xfc26);
    put(&mut bytes, 16, if pla || old_usb { 0xfc38 } else { 0xfc48 });
    put(&mut bytes, 20, 0xfc28);
    put(&mut bytes, 22, 1);
    put(&mut bytes, 24, 0x3210);
    bytes[64..].fill(0x5a);
    bytes
}
fn start() -> Vec<u8> {
    let mut bytes = block(START, 16);
    put(&mut bytes, 8, 0x8146);
    put(&mut bytes, 10, 0x7000);
    bytes
}
fn nc() -> Vec<u8> {
    let mut bytes = block(NC, 48);
    for (at, value) in [
        (8, 40),
        (10, 0xa014),
        (12, 0xa012),
        (16, 0xa01a),
        (20, 0xb820),
        (28, 0xa000),
        (30, 4),
    ] {
        put(&mut bytes, at, value);
    }
    bytes
}
fn union(kind: u32) -> Vec<u8> {
    let mut bytes = block(kind, 66);
    put(&mut bytes, 8, 58);
    put(&mut bytes, 10, 0xa000);
    bytes[56] = 2;
    bytes[57] = 8;
    bytes
}
fn image(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; HEADER];
    bytes[32..39].copy_from_slice(b"fixture");
    for block in blocks {
        bytes.extend(block);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
    }
    bytes.extend(block(END, 8));
    checksum(&mut bytes);
    bytes
}
fn checksum(bytes: &mut [u8]) {
    let digest = Sha256::digest(&bytes[32..]);
    bytes[..32].copy_from_slice(&digest);
}

pub(crate) fn synthetic_upload(revision: u16) -> Vec<u8> {
    let old = matches!(revision, 0x5c10 | 0x5c20 | 0x5c30);
    let mut usb = mac(false, old);
    put(&mut usb, 60, 0xcfd7);
    usb[62] = 4;
    let mut pla = mac(true, old);
    put(&mut pla, 60, 0xcfd6);
    pla[62] = 6;
    if revision == 0x6400 {
        put(&mut pla, 16, 0xfc48);
    }
    let mut blocks = vec![usb, pla];
    if old {
        blocks.extend([start(), nc(), block(STOP, 8)]);
    } else if revision == 0x7030 {
        let mut version = block(VERSION, 16);
        put(&mut version, 8, 0x801e);
        put(&mut version, 10, 0x21);
        let mut fixup = block(FIXUP, 16);
        put(&mut fixup, 8, 0xb820);
        put(&mut fixup, 10, 0x80);
        put(&mut fixup, 12, 1);
        blocks.extend([version, start(), fixup]);
        for kind in UNION_NC..=UNION_MISC {
            let mut patch = union(kind);
            put(&mut patch, 10, 0x9000 + kind as u16 * 0x100);
            patch[58..].fill(kind as u8);
            blocks.push(patch);
        }
        blocks.push(block(STOP, 8));
        blocks.push(union(UNION_MISC));
    } else if matches!(revision, 0x7410 | 0x7420) {
        let mut speed = block(SPEED_UP, 16 + 4224);
        put(&mut speed, 8, 16);
        put(&mut speed, 10, 0x21);
        put(&mut speed, 12, 0x9a00);
        for (index, byte) in speed[16..].iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(7).wrapping_add(13);
        }
        blocks.push(speed);
    }
    image(&blocks)
}

#[test]
fn all_mainstream_firmware_block_forms_are_typed_and_revision_checked() {
    for revision in [0x5c10, 0x5c20, 0x5c30] {
        let bytes = image(&[
            mac(false, true),
            mac(true, true),
            start(),
            nc(),
            block(STOP, 8),
        ]);
        let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
        assert_eq!(firmware.revision(), Revision(revision));
        assert_eq!(firmware.version(), b"fixture");
        assert_eq!(firmware.blocks().len(), 5);
        let Block::Mac(mac) = &firmware.blocks()[0] else {
            panic!()
        };
        assert_eq!(mac.bank(), Bank::Usb);
        assert_eq!(mac.register(), 0xf800);
        assert_eq!(mac.payload(), &[0x5a; 8]);
        assert_eq!(mac.breakpoints().collect::<Vec<_>>(), [0x3210]);
        assert!(Firmware::parse(&bytes, Revision(0x7030)).is_err());
    }
    let mut version = block(VERSION, 16);
    put(&mut version, 8, 0x801e);
    let mut fixup = block(FIXUP, 16);
    put(&mut fixup, 8, 0xb820);
    put(&mut fixup, 10, 0x80);
    let bytes = image(&[
        mac(false, false),
        mac(true, false),
        version,
        start(),
        fixup,
        union(UNION_NC),
        union(UNION_NC1),
        union(UNION_NC2),
        union(UNION_UC2),
        union(UNION_UC),
        union(UNION_MISC),
        block(STOP, 8),
        union(UNION_MISC),
    ]);
    assert_eq!(
        Firmware::parse(&bytes, Revision(0x7030))
            .unwrap()
            .blocks()
            .len(),
        13
    );
    assert!(Firmware::parse(&bytes, Revision(0x5c10)).is_err());
    let mut speed = block(SPEED_UP, 24);
    put(&mut speed, 8, 16);
    put(&mut speed, 12, 0x9a00);
    let bytes = image(&[mac(false, false), mac(true, false), speed]);
    assert!(Firmware::parse(&bytes, Revision(0x7410)).is_ok());
    assert!(Firmware::parse(&bytes, Revision(0x7420)).is_ok());
    assert!(Firmware::parse(&bytes, Revision(0x7030)).is_err());
}

#[test]
fn full_checksum_framing_and_all_truncations_are_required() {
    let bytes = image(&[mac(true, true)]);
    for end in 0..bytes.len() {
        assert!(Firmware::parse(&bytes[..end], Revision(0x5c10)).is_err());
    }
    for at in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(Firmware::parse(&bad, Revision(0x5c10)).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    checksum(&mut extra);
    assert!(Firmware::parse(&extra, Revision(0x5c10)).is_err());
    for length in [0, 7, u32::MAX] {
        let mut malformed = bytes.clone();
        malformed[68..72].copy_from_slice(&length.to_le_bytes());
        checksum(&mut malformed);
        assert!(Firmware::parse(&malformed, Revision(0x5c10)).is_err());
    }
    assert!(Firmware::parse(&image(&[block(0xffff, 8)]), Revision(0x5c10)).is_err());
    assert!(Firmware::parse(&bytes, Revision(0x4c10)).is_err());
}

#[test]
fn register_counts_offsets_and_phy_order_fail_before_upload() {
    for (at, value) in [
        (8, 62),
        (8, 72),
        (10, 0xe600),
        (12, 0xfc24),
        (16, 0xfc48),
        (20, 0xfc26),
        (22, 9),
        (26, 1),
    ] {
        let mut bad = mac(true, true);
        put(&mut bad, at, value);
        assert!(Firmware::parse(&image(&[bad]), Revision(0x5c10)).is_err());
    }
    for blocks in [
        vec![mac(true, true), mac(true, true)],
        vec![start(), nc()],
        vec![nc(), start(), block(STOP, 8)],
        vec![start(), start(), block(STOP, 8)],
        vec![start(), nc(), nc(), block(STOP, 8)],
        vec![block(STOP, 8)],
        vec![start(), block(STOP, 8), nc()],
    ] {
        assert!(Firmware::parse(&image(&blocks), Revision(0x5c10)).is_err());
    }
    for (at, value) in [
        (8, 38),
        (10, 0xa012),
        (12, 0xa014),
        (16, 0xa01c),
        (20, 0xb822),
        (28, 0xa002),
        (30, 5),
    ] {
        let mut bad = nc();
        put(&mut bad, at, value);
        assert!(
            Firmware::parse(&image(&[start(), bad, block(STOP, 8)]), Revision(0x5c10)).is_err()
        );
    }
    for at in [56, 57] {
        let mut bad = union(UNION_NC);
        bad[at] = 9;
        assert!(
            Firmware::parse(&image(&[start(), bad, block(STOP, 8)]), Revision(0x7030)).is_err()
        );
    }
}

#[test]
fn provider_boundary_preserves_exact_target_errors_and_borrowed_image_storage() {
    use crate::firmware::{
        Catalog, ErrorKind, HandoffProvider, Provenance, Provider, Resource, Target,
    };
    use core::cell::RefCell;
    struct Recording {
        catalog: Catalog,
        requests: RefCell<Vec<(String, String, String)>>,
    }
    impl Provider for Recording {
        fn load(
            &self,
            requirement: resources::Requirement<'_>,
        ) -> Result<resources::Image<'_>, resources::Error> {
            assert_eq!(requirement.target.driver, "usb-rtl815x");
            assert_eq!(requirement.target.board, None);
            self.requests.borrow_mut().push((
                requirement.name.into(),
                requirement.target.hardware.into(),
                requirement.target.revision.into(),
            ));
            self.catalog.load(requirement)
        }
    }
    fn catalog(bytes: Vec<u8>, hardware: &str) -> Catalog {
        let hash = Sha256::digest(&bytes).into();
        Catalog::from_handoff(vec![Resource {
            name: "rtl_nic/rtl8153a-2.fw",
            target: Target {
                driver: "usb-rtl815x",
                hardware,
                revision: "tcr-5c10",
                board: None,
            },
            provenance: Provenance {
                source: "linux-firmware-test",
                revision: "immutable-fixture",
                member: "rtl_nic/rtl8153a-2.fw",
                license: "LICENCE.rtlwifi_firmware.txt",
            },
            expected_length: bytes.len(),
            expected_sha256: hash,
            bytes,
        }])
        .unwrap()
    }
    let mut descriptor = [0; 18];
    descriptor[8..14].copy_from_slice(&[0xda, 0x0b, 0x53, 0x81, 0x00, 0x30]);
    let bytes = image(&[mac(true, true)]);
    let original = bytes.as_ptr();
    let provider = Recording {
        catalog: catalog(bytes, "usb:0bda:8153:3000"),
        requests: RefCell::new(Vec::new()),
    };
    assert!(
        load(&provider, &descriptor, Revision(0x4c10))
            .unwrap()
            .is_none()
    );
    assert!(provider.requests.borrow().is_empty());
    let (resource, parsed) = load(&provider, &descriptor, Revision(0x5c10))
        .unwrap()
        .unwrap();
    assert_eq!(resource.bytes().as_ptr(), original);
    assert_eq!(parsed.blocks().len(), 1);
    assert_eq!(
        provider.requests.borrow()[0],
        (
            "rtl_nic/rtl8153a-2.fw".into(),
            "usb:0bda:8153:3000".into(),
            "tcr-5c10".into()
        )
    );
    descriptor[12] = 1;
    let Err(Error::Firmware { request, error }) = load(&provider, &descriptor, Revision(0x5c10))
    else {
        panic!()
    };
    assert_eq!(error.kind, ErrorKind::WrongTarget);
    assert_eq!(request.hardware, "usb:0bda:8153:3001");
    let empty = HandoffProvider::new(None);
    let Err(Error::Firmware { request, error }) = load(&empty, &descriptor, Revision(0x5c10))
    else {
        panic!()
    };
    assert_eq!(request.name, "rtl_nic/rtl8153a-2.fw");
    assert_eq!(request.revision, "tcr-5c10");
    assert_eq!(error.kind, ErrorKind::Missing);
    descriptor[12] = 0;
    let mut bytes = image(&[mac(true, true)]);
    bytes[32] ^= 1; // Catalog-valid image, invalid vendor checksum.
    let invalid = catalog(bytes, "usb:0bda:8153:3000");
    assert!(matches!(
        load(&invalid, &descriptor, Revision(0x5c10)),
        Err(Error::Image { .. })
    ));
}

pub(crate) const FIXTURES: [(&str, u16, usize, &str); 7] = [
    (
        "rtl8153a-2.fw",
        0x5c10,
        5,
        "7d4f422ec0e8141576c1b486fe6b7c6ce8ec9ea1f650815fd4058878c038366d",
    ),
    (
        "rtl8153a-3.fw",
        0x5c20,
        5,
        "c7099a1b0fc80e02ff7276aacbb08b5771e2f5c763fb76a7a8df3a89d58d8208",
    ),
    (
        "rtl8153a-4.fw",
        0x5c30,
        5,
        "99a05414fc0ae3b99a453d73b5cae90bfa6d371320f78011fc58cb03a33e2a09",
    ),
    (
        "rtl8153b-2.fw",
        0x6010,
        2,
        "137c9c752e8648ecfcf3b74ffc7d675c098145c222e2969721e6257af31716bc",
    ),
    (
        "rtl8153c-1.fw",
        0x6400,
        2,
        "bbe5f74bd2625b71c9a70e0588472ef670b5eeb65f83b1202cd25b3381720a3f",
    ),
    (
        "rtl8156a-2.fw",
        0x7030,
        14,
        "7b50f4a307bde7b3f384935537c4d9705457fa42613eb0003ffbc4e19461a1e0",
    ),
    (
        "rtl8156b-2.fw",
        0x7410,
        3,
        "5a3b21e27305876af8eac4b9bd11a821487b338e4ac1b58b8be8d23467d3f91f",
    ),
];

#[test]
#[ignore = "oracle: STELA_RTL815X_FIRMWARE"]
fn pinned_real_firmware_files_parse_all_observed_block_effects() {
    extern crate std;
    let directory =
        std::env::var("STELA_RTL815X_FIRMWARE").expect("path to pinned fixture directory");
    for (name, revision, count, hash) in FIXTURES {
        let bytes = std::fs::read(std::path::Path::new(&directory).join(name)).unwrap();
        assert_eq!(alloc::format!("{:x}", Sha256::digest(&bytes)), hash);
        let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
        assert_eq!(firmware.blocks().len(), count, "{name}");
    }
}

#[test]
#[ignore = "oracle: STELA_RTL815X_FIRMWARE_ORACLE"]
fn unchanged_linux_firmware_validators_match_real_and_mutated_fields() {
    extern crate std;
    let path =
        std::env::var("STELA_RTL815X_FIRMWARE_ORACLE").expect("path to source oracle cases.txt");
    let cases = std::fs::read_to_string(path).unwrap();
    let mut count = 0;
    let mut accepted = 0;
    for line in cases.lines() {
        let mut fields = line.splitn(3, ' ');
        let revision = Revision(u16::from_str_radix(fields.next().unwrap(), 16).unwrap());
        let expected = fields.next().unwrap() == "1";
        let filename = fields.next().unwrap();
        let bytes = std::fs::read(filename).unwrap();
        let result = Firmware::parse(&bytes, revision);
        assert_eq!(result.is_ok(), expected, "{filename}: {result:?}");
        count += 1;
        accepted += usize::from(expected);
    }
    assert!(count > 200);
    assert!(accepted >= 7);
    assert!(accepted < count);
}
