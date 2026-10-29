use super::super::{
    auxiliary::Auxiliary,
    tests::{catalog, patch_bytes, requests},
};
use super::*;
extern crate std;
fn auxiliary_owner(chip: Chip, clc: &[u8]) -> Auxiliary {
    let mut bytes = clc.to_vec();
    let mut descriptor = [0; 40];
    descriptor[20..24].copy_from_slice(&(clc.len() as u32).to_le_bytes());
    descriptor[24] = 64;
    descriptor[25] = 2;
    bytes.extend_from_slice(&descriptor);
    let mut trailer = [0; 36];
    trailer[2] = 1;
    trailer[3] = 2;
    bytes.extend_from_slice(&trailer);
    let req = requests(chip);
    let provider = catalog(&req, patch_bytes(), bytes);
    req.load(&provider).unwrap().retain_auxiliary()
}
fn inputs(country: [u8; 2]) -> Inputs {
    Inputs {
        alpha2: country,
        environment: Environment::Outdoor,
        chip_capabilities: 1,
        power_limits_node: false,
        power_type: 2,
        acpi_flags: 0xa5,
        mtcl_configuration: 0x123456aa,
        world_mtcl_configuration: 0x876543bb,
    }
}
fn c2(slot: u8, country: &[u8; 2], payload: usize) -> Vec<u8> {
    let mut record = vec![0; 16];
    record[4] = slot;
    record[5] = 1;
    record.extend_from_slice(country);
    record.extend_from_slice(&[7, 9]);
    record.extend_from_slice(&(payload as u16).to_le_bytes());
    record.extend(core::iter::repeat_n(0x5a, payload));
    let length = record.len() as u32;
    record[..4].copy_from_slice(&length.to_le_bytes());
    record
}
fn c3() -> Vec<u8> {
    let mut record = vec![0; 16];
    record[4] = 0;
    record[5] = 2;
    record[8] = 1;
    let mut segment = [0; 16];
    segment[0] = 1;
    segment[4..8].copy_from_slice(&24u32.to_le_bytes());
    segment[8..12].copy_from_slice(&20u32.to_le_bytes());
    record.extend_from_slice(&segment);
    record.extend_from_slice(b"US");
    record.extend_from_slice(&[7, 9, 1, 0xa3, 0, 0]);
    record.extend_from_slice(&[0x5a; 20]);
    let length = record.len() as u32;
    record[..4].copy_from_slice(&length.to_le_bytes());
    record
}
#[test]
fn world_retry_is_explicit_with_separate_mtcl_and_no_invented_ack() {
    let bytes = c2(0, b"00", 20);
    let owner = auxiliary_owner(Chip::Mt7921, &bytes);
    let selection = owner.select_clc(0).unwrap();
    let mut input = inputs(*b"ZZ");
    input.chip_capabilities = 0;
    let plan = Plan::build(&selection, input).unwrap();
    assert_eq!(plan.requested_alpha2(), *b"ZZ");
    assert_eq!(plan.requested_environment(), Environment::Outdoor);
    let request = &plan.requests()[0];
    assert_eq!(request.alpha2(), *b"00");
    assert_eq!(request.environment(), Environment::Indoor);
    assert!(request.is_world_fallback());
    assert_eq!(request.body()[13], 0xbb);
    assert_eq!(request.completion(), Completion::OneWay);
    assert_eq!(request.pending_channel_flags(), None);
    let owner = owner_without_country();
    let selection = owner.select_clc(0).unwrap();
    assert_eq!(
        Plan::build(&selection, inputs(*b"ZZ")).unwrap_err(),
        Error::MissingCountry {
            slot: 0,
            requested: *b"ZZ"
        }
    );
}
fn owner_without_country() -> Auxiliary {
    auxiliary_owner(Chip::Mt7921, &c2(0, b"US", 20))
}
#[test]
fn source_c2_short_tail_is_not_a_rule_and_later_malformed_rule_is_atomic() {
    // The donor's >16-byte loop never consumes this valid
    // six-byte rule header with ten bytes of data.
    let owner = auxiliary_owner(Chip::Mt7922, &c2(0, b"US", 10));
    let selection = owner.select_clc(0).unwrap();
    assert!(matches!(
        Plan::build(&selection, inputs(*b"US")),
        Err(Error::MissingCountry { .. })
    ));
    let mut bytes = c2(0, b"US", 20);
    let mut malformed = c2(0, b"US", 20)[16..].to_vec();
    malformed[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    bytes.extend_from_slice(&malformed);
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&length.to_le_bytes());
    let owner = auxiliary_owner(Chip::Mt7921, &bytes);
    let selection = owner.select_clc(0).unwrap();
    assert!(matches!(
        Plan::build(&selection, inputs(*b"US")),
        Err(Error::MalformedRule { offset: 26, .. })
    ));
}
#[test]
fn c3_tables_indices_ranges_and_current_transport_limits_refuse_atomically() {
    let bytes = c3();
    let owner = auxiliary_owner(Chip::Mt7925, &bytes);
    let selection = owner.select_clc(0).unwrap();
    let plan = Plan::build(&selection, inputs(*b"US")).unwrap();
    let request = &plan.requests()[0];
    assert_eq!(request.body().len(), 104);
    assert_eq!(request.pending_channel_flags(), Some(0xa3));
    assert_eq!(request.body()[14], 0);
    for index in [0, 2, 255] {
        let mut malformed = bytes.clone();
        malformed[36] = index;
        let owner = auxiliary_owner(Chip::Mt7925, &malformed);
        let selection = owner.select_clc(0).unwrap();
        assert!(matches!(
            Plan::build(&selection, inputs(*b"US")),
            Err(Error::SegmentIndex { .. })
        ));
    }
    for end in [0u32, 15, 17, 23, 25, u32::MAX] {
        let mut malformed = bytes.clone();
        malformed[20..24].copy_from_slice(&end.to_le_bytes());
        let owner = auxiliary_owner(Chip::Mt7925, &malformed);
        let selection = owner.select_clc(0).unwrap();
        assert!(matches!(
            Plan::build(&selection, inputs(*b"US")),
            Err(Error::SegmentTable { .. })
        ));
    }
    let mut malformed = bytes.clone();
    malformed[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    let owner = auxiliary_owner(Chip::Mt7925, &malformed);
    let selection = owner.select_clc(0).unwrap();
    assert!(matches!(
        Plan::build(&selection, inputs(*b"US")),
        Err(Error::SegmentRange { .. })
    ));
    let owner = auxiliary_owner(Chip::Mt7921, &c2(0, b"US", 4000));
    let selection = owner.select_clc(0).unwrap();
    assert!(matches!(
        Plan::build(&selection, inputs(*b"US")),
        Err(Error::UnsupportedTransfer { .. })
    ));
    let mut repeated = Vec::new();
    for _ in 0..1025 {
        repeated.extend_from_slice(&c2(0, b"US", 20)[16..]);
    }
    let mut bytes = c2(0, b"US", 20)[..16].to_vec();
    bytes.extend_from_slice(&repeated);
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&length.to_le_bytes());
    let owner = auxiliary_owner(Chip::Mt7921, &bytes);
    let selection = owner.select_clc(0).unwrap();
    assert_eq!(
        Plan::build(&selection, inputs(*b"US")).unwrap_err(),
        Error::TooManyCommands
    );
}
#[test]
#[ignore = "oracle: STELA_MT792X_CLC_COUNTRY_ORACLE"]
fn complete_linux_country_helpers_match_every_request_and_fallback_fact() {
    let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_CLC_COUNTRY_ORACLE").unwrap());
    for (chip, number) in [
        (Chip::Mt7921, 7921),
        (Chip::Mt7922, 7922),
        (Chip::Mt7925, 7925),
    ] {
        let trace = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
        let mut at = 0;
        for _ in 0..108 {
            let meta = &trace[at..at + 23];
            at += 23;
            let n = le32(&trace, at) as usize;
            at += 4;
            let owner = auxiliary_owner(chip, &trace[at..at + n]);
            at += n;
            let selection = owner.select_clc(meta[0]).unwrap();
            let input = Inputs {
                alpha2: meta[1..3].try_into().unwrap(),
                environment: match meta[3] {
                    0 => Environment::Any,
                    1 => Environment::Indoor,
                    2 => Environment::Outdoor,
                    _ => panic!("source environment"),
                },
                acpi_flags: meta[4],
                power_type: meta[5],
                power_limits_node: meta[6] != 0,
                chip_capabilities: u64::from_le_bytes(meta[7..15].try_into().unwrap()),
                mtcl_configuration: le32(meta, 15),
                world_mtcl_configuration: le32(meta, 19),
            };
            let plan = Plan::build(&selection, input).unwrap();
            let count = usize::from(u16::from_le_bytes(trace[at..at + 2].try_into().unwrap()));
            at += 2;
            assert_eq!(plan.requests().len(), count);
            for request in plan.requests() {
                let command = le32(&trace, at);
                let wait = trace[at + 4] != 0;
                let flags = trace[at + 5];
                let n = usize::from(u16::from_le_bytes(
                    trace[at + 6..at + 8].try_into().unwrap(),
                ));
                at += 8;
                assert_eq!(
                    command,
                    if chip == Chip::Mt7925 {
                        (1 << 17) | 0x2c
                    } else {
                        (1 << 18) | 0x5c
                    }
                );
                assert_eq!(request.body(), &trace[at..at + n]);
                at += n;
                assert_eq!(wait, request.completion() != Completion::OneWay);
                if chip == Chip::Mt7925 {
                    assert_eq!(request.pending_channel_flags(), Some(flags));
                }
                assert_eq!(
                    request.is_world_fallback(),
                    request.alpha2() != input.alpha2
                );
                assert_eq!(
                    request.environment(),
                    if request.is_world_fallback() {
                        Environment::Indoor
                    } else {
                        input.environment
                    }
                );
            }
        }
        assert_eq!(at, trace.len());
    }
}

#[test]
#[ignore = "oracle: STELA_MT792X_CLC_WIRE_ORACLE"]
fn exact_country_requests_cross_complete_source_mcu_writers() {
    let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_CLC_WIRE_ORACLE").unwrap());
    for (chip, number) in [
        (Chip::Mt7921, 7921),
        (Chip::Mt7922, 7922),
        (Chip::Mt7925, 7925),
    ] {
        let country = std::fs::read(root.join(alloc::format!("country/{number}.trace"))).unwrap();
        let wire = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
        let mut encoder = crate::net::wifi::mediatek::mcu::Encoder::default();
        let mut at = 0;
        let mut wire_at = 0;
        for _ in 0..108 {
            let meta = &country[at..at + 23];
            at += 23;
            let n = le32(&country, at) as usize;
            at += 4;
            let owner = auxiliary_owner(chip, &country[at..at + n]);
            at += n;
            let selection = owner.select_clc(meta[0]).unwrap();
            let input = Inputs {
                alpha2: meta[1..3].try_into().unwrap(),
                environment: match meta[3] {
                    0 => Environment::Any,
                    1 => Environment::Indoor,
                    2 => Environment::Outdoor,
                    _ => panic!("source environment"),
                },
                acpi_flags: meta[4],
                power_type: meta[5],
                power_limits_node: meta[6] != 0,
                chip_capabilities: u64::from_le_bytes(meta[7..15].try_into().unwrap()),
                mtcl_configuration: le32(meta, 15),
                world_mtcl_configuration: le32(meta, 19),
            };
            let plan = Plan::build(&selection, input).unwrap();
            let count = usize::from(u16::from_le_bytes(country[at..at + 2].try_into().unwrap()));
            at += 2;
            assert_eq!(plan.requests().len(), count);
            for request in plan.requests() {
                let n = usize::from(u16::from_le_bytes(
                    country[at + 6..at + 8].try_into().unwrap(),
                ));
                at += 8 + n;
                let packet = encoder.encode_clc(request);
                assert_eq!(packet.chip(), chip);
                assert_eq!(packet.completion(), request.completion());
                let n = usize::from(u16::from_le_bytes(
                    wire[wire_at..wire_at + 2].try_into().unwrap(),
                ));
                wire_at += 2;
                assert_eq!(packet.bytes(), &wire[wire_at..wire_at + n]);
                wire_at += n;
            }
        }
        assert_eq!(at, country.len());
        assert_eq!(wire_at, wire.len());
    }
}
