use super::*;
#[test]
fn wide_headers_normalize_legacy_ids_and_split_at_twenty_bytes() {
    for len in (0..=129).chain([316, 317, MAX_PAYLOAD_BYTES]) {
        let payload: Vec<_> = (0..len).map(|n| n as u8).collect();
        let command = Command::encode(
            Id {
                group: 0,
                opcode: 0x80,
                version: 7,
            },
            31,
            0x12ab,
            &payload,
        )
        .unwrap();
        assert_eq!(
            command.id(),
            Id {
                group: 1,
                opcode: 0x80,
                version: 7
            }
        );
        assert_eq!(command.sequence(), 0x1fab);
        assert_eq!(
            &command.bytes()[..8],
            &[0x80, 1, 0xab, 0x1f, len as u8, (len >> 8) as u8, 0, 7]
        );
        assert_eq!(&command.bytes()[8..], payload);
        assert_eq!(command.first_tb().len(), (len + 8).min(20));
        assert_eq!(
            [command.first_tb(), command.remainder()].concat(),
            command.bytes()
        );
        let first = Region {
            address: 0x110000,
            bytes: command.first_tb().len(),
        };
        let rest = (!command.remainder().is_empty()).then_some(Region {
            address: 0x120000,
            bytes: command.remainder().len(),
        });
        let tfd = command.tfd(first, rest).unwrap();
        assert_eq!(
            u16::from_le_bytes(tfd.bytes()[..2].try_into().unwrap()),
            if rest.is_some() { 2 } else { 1 }
        );
        assert!(
            command
                .tfd(
                    Region {
                        bytes: first.bytes + 1,
                        ..first
                    },
                    rest
                )
                .is_err()
        );
        if let Some(rest) = rest {
            assert!(command.tfd(first, None).is_err());
            assert!(
                command
                    .tfd(
                        first,
                        Some(Region {
                            bytes: rest.bytes + 1,
                            ..rest
                        })
                    )
                    .is_err()
            );
        } else {
            assert!(
                command
                    .tfd(
                        first,
                        Some(Region {
                            address: 0x120000,
                            bytes: 1
                        })
                    )
                    .is_err()
            );
        }
    }
    assert_eq!(
        Id {
            group: 0,
            opcode: 2,
            version: 0
        }
        .wire()
        .group,
        0
    );
    assert_eq!(
        Id {
            group: 0,
            opcode: 2,
            version: 1
        }
        .wire()
        .group,
        1
    );
    assert_eq!(
        Command::encode(
            Id {
                group: 5,
                opcode: 3,
                version: 1
            },
            32,
            0,
            &[]
        )
        .unwrap_err(),
        Error::Queue
    );
    assert_eq!(
        Command::encode(
            Id {
                group: 5,
                opcode: 3,
                version: 1
            },
            0,
            0,
            &vec![0; MAX_PAYLOAD_BYTES + 1]
        )
        .unwrap_err(),
        Error::PayloadSize
    );
}
#[test]
fn tfh_descriptors_preserve_full_iovas_and_reject_invalid_regions() {
    for count in 1..=25 {
        let regions: Vec<_> = (0..count)
            .map(|i| Region {
                address: 0x123400000003 + i as u64 * 0x10000,
                bytes: 1 + i * 197,
            })
            .collect();
        let tfd = Tfd::encode(&regions).unwrap();
        for (i, region) in regions.iter().enumerate() {
            let at = 2 + i * 10;
            assert_eq!(
                u16::from_le_bytes(tfd.bytes()[at..at + 2].try_into().unwrap()) as usize,
                region.bytes
            );
            assert_eq!(
                u64::from_le_bytes(tfd.bytes()[at + 2..at + 10].try_into().unwrap()),
                region.address
            );
        }
        assert!(tfd.bytes()[2 + count * 10..].iter().all(|b| *b == 0));
    }
    for regions in [
        vec![],
        vec![
            Region {
                address: 0,
                bytes: 1
            };
            26
        ],
    ] {
        assert_eq!(Tfd::encode(&regions).unwrap_err(), Error::BufferCount);
    }
    for bytes in [0, 65536] {
        assert_eq!(
            Tfd::encode(&[Region {
                address: 0x100000,
                bytes
            }])
            .unwrap_err(),
            Error::BufferLength
        );
    }
    assert_eq!(
        Tfd::encode(&[Region {
            address: u64::MAX - 3,
            bytes: 8
        }])
        .unwrap_err(),
        Error::Address
    );
    for bytes in [16, 17] {
        assert_eq!(
            Tfd::encode(&[Region {
                address: 0xfffffff0,
                bytes
            }])
            .unwrap_err(),
            Error::Boundary
        );
    }
    Tfd::encode(&[Region {
        address: 0xfffffff0,
        bytes: 15,
    }])
    .unwrap();
    // An actual attached domain may legitimately assign IOVA0. A TB uses
    // its explicit nonzero length/count, not a null-pointer convention.
    Tfd::encode(&[Region {
        address: 0,
        bytes: 8,
    }])
    .unwrap();
}
fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes.iter().map(|b| alloc::format!("{b:02x}")).collect()
}
#[test]
#[ignore = "oracle: STELA_IWLWIFI_COMMAND_ORACLE"]
fn command_headers_and_tfh_descriptors_match_linux() {
    extern crate std;
    use sha2::{Digest, Sha256};
    let trace = std::fs::read(std::env::var("STELA_IWLWIFI_COMMAND_ORACLE").unwrap()).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&trace)),
        "08104fa131012c135693eea7674fab90cc1dd9092f78d3bb9f8daacd806bd72b"
    );
    let mut lines = core::str::from_utf8(&trace).unwrap().lines();
    assert_eq!(lines.next().unwrap(), "layout 8 4 7 10 256");
    let mut headers = 0;
    let mut descriptors = 0;
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields[0] {
            "header" => {
                let id = Id {
                    group: fields[1].parse().unwrap(),
                    version: fields[2].parse().unwrap(),
                    opcode: fields[3].parse().unwrap(),
                };
                let cmd = Command::encode(id, 31, 0xabcd, &vec![0x5a; 0x1234]).unwrap();
                assert_eq!(hex(&cmd.bytes()[..8]), fields[4]);
                headers += 1;
            }
            "tfd" => {
                let count = fields[1].parse::<usize>().unwrap();
                let regions: Vec<_> = (0..count)
                    .map(|i| Region {
                        address: 0x123400000003 + i as u64 * 0x10000,
                        bytes: 1 + i * 197,
                    })
                    .collect();
                assert_eq!(hex(Tfd::encode(&regions).unwrap().bytes()), fields[2]);
                descriptors += 1;
            }
            other => panic!("unexpected oracle record {other}"),
        }
    }
    assert_eq!(headers, 3072);
    assert_eq!(descriptors, 25);
}
