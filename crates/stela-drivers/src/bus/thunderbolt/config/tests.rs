use super::*;

fn response(request: &Request, data: &[u32], upstream: u8) -> Encoded {
    let h = request.route.header();
    let mut words = vec![h[0] | REPLY, h[1]];
    if let Some(address) = request.address {
        words.push((address.word(request.sequence) & !(63 << 19)) | (u32::from(upstream) << 19));
    }
    words.extend_from_slice(data);
    encode(request.kind, &words).unwrap()
}

#[test]
fn crc32c_matches_independent_standard_vector_and_wire_dword_order() {
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    let r = Request::read(
        Route::new(0x12_3456_789a).unwrap(),
        Address {
            port: 5,
            space: Space::Port,
            offset: 0x123,
            words: 2,
        },
        3,
    )
    .unwrap();
    assert_eq!(
        &r.frame.bytes[..8],
        &[0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a]
    );
    assert_eq!(
        &r.frame.bytes[8..12],
        &(0x1800_0000u32 | 1 << 25 | 5 << 19 | 2 << 13 | 0x123).to_be_bytes()
    );
}
#[test]
fn request_bounds_never_truncate_route_port_length_sequence_or_offset() {
    assert_eq!(Route::new(1 << 54), Err(Error::Route));
    let route = Route::new(0).unwrap();
    for (port, offset, words) in [
        (64, 0, 1),
        (0, 8192, 1),
        (0, 8191, 2),
        (0, 0, 0),
        (0, 0, 61),
    ] {
        assert!(
            Request::read(
                route,
                Address {
                    port,
                    space: Space::Router,
                    offset,
                    words
                },
                0
            )
            .is_err()
        );
    }
    assert!(
        Request::read(
            route,
            Address {
                port: 0,
                space: Space::Router,
                offset: 0,
                words: 1
            },
            4
        )
        .is_err()
    );
    let a = Address {
        port: 0,
        space: Space::Router,
        offset: 0,
        words: 60,
    };
    assert_eq!(
        Request::write(route, a, 0, &[0; 60])
            .unwrap()
            .frame
            .bytes
            .len(),
        256
    );
    assert!(Request::write(route, a, 0, &[0; 59]).is_err());
}
#[test]
fn reply_match_checks_all_ownership_fields_but_allows_real_upstream_port() {
    let r = Request::read(
        Route::new(0x30201).unwrap(),
        Address {
            port: 1,
            space: Space::Port,
            offset: 9,
            words: 2,
        },
        2,
    )
    .unwrap();
    let valid = response(&r, &[0xdead_beef, 0xaabb_ccdd], 7);
    let received = Received {
        kind: valid.kind,
        sof: 0,
        bytes: &valid.bytes,
    };
    assert_eq!(
        r.reply(&received),
        Ok(Reply::Configuration {
            upstream_port: 7,
            data: vec![0xdead_beef, 0xaabb_ccdd]
        })
    );
    for bit in [0, 13, 25, 27, 29] {
        let mut words = received.words().unwrap();
        words[2] ^= 1 << bit;
        let bad = encode(valid.kind, &words).unwrap();
        assert!(
            r.reply(&Received {
                kind: bad.kind,
                sof: 0,
                bytes: &bad.bytes
            })
            .is_err()
        );
    }
    for bit in [0, 22, 30, 31] {
        let mut words = received.words().unwrap();
        words[0] ^= 1 << bit;
        let bad = encode(valid.kind, &words).unwrap();
        assert!(
            r.reply(&Received {
                kind: bad.kind,
                sof: 0,
                bytes: &bad.bytes
            })
            .is_err()
        );
    }
    for index in 0..valid.bytes.len() {
        let mut bytes = valid.bytes.clone();
        bytes[index] ^= 0x80;
        assert!(
            r.reply(&Received {
                kind: valid.kind,
                sof: 0,
                bytes: &bytes
            })
            .is_err()
        );
    }
    assert_eq!(
        r.reply(&Received {
            kind: valid.kind,
            sof: 1,
            bytes: &valid.bytes
        }),
        Err(Error::FrameMarkers)
    );
}
#[test]
fn real_error_is_preserved_and_cannot_become_a_successful_read() {
    let route = Route::new(7).unwrap();
    let request = Request::read(
        route,
        Address {
            port: 0,
            space: Space::Router,
            offset: 1,
            words: 1,
        },
        0,
    )
    .unwrap();
    let e = encode(PacketType::Error, &[REPLY, 7, 0x8000_090f]).unwrap();
    assert_eq!(
        request.reply(&Received {
            kind: e.kind,
            sof: 0,
            bytes: &e.bytes
        }),
        Ok(Reply::ControllerError {
            route,
            port: 9,
            code: 15,
            packet_group: 2,
            raw: 0x8000_090f
        })
    );
    let e = encode(PacketType::Error, &[REPLY, 8, 0xf]).unwrap();
    assert!(matches!(
        request.reply(&Received {
            kind: e.kind,
            sof: 0,
            bytes: &e.bytes
        }),
        Ok(Reply::ControllerError {
            route: Route(8),
            ..
        })
    ));
    for code in [1, 12, 13, 32, 33, 34, 35, 36, 37, 38, 39] {
        for flags in [0, REPLY, 0xabc0_0000] {
            let e = encode(PacketType::Error, &[flags, 8, code]).unwrap();
            let received = Received {
                kind: e.kind,
                sof: 0,
                bytes: &e.bytes,
            };
            assert!(request.reply(&received).is_err());
            let notice = received.notification_error().unwrap().unwrap();
            assert_eq!(notice.code, code as u8);
            assert_eq!(notice.header_flags, (flags >> 22) as u16);
            let ack = notice.acknowledgement().unwrap();
            assert_eq!(ack.kind, PacketType::NotifyAck);
            assert_eq!(&ack.bytes[..8], &[0, 0, 0, 0, 0, 0, 0, 8]);
            assert_eq!(ack.bytes.len(), 12);
        }
    }
}
#[test]
fn plug_event_ack_preserves_actual_route_port_and_hotplug_group() {
    for unplug in [false, true] {
        let event = encode(
            PacketType::Event,
            &[REPLY, 0x201, 6 | if unplug { 1 << 31 } else { 0 }],
        )
        .unwrap();
        let actual = Received {
            kind: event.kind,
            sof: 0,
            bytes: &event.bytes,
        }
        .event()
        .unwrap();
        assert_eq!(
            actual,
            PlugEvent {
                route: Route::new(0x201).unwrap(),
                port: 6,
                unplug,
                header_flags: 512,
            }
        );
        let ack = actual.acknowledgement().unwrap();
        assert_eq!(&ack.bytes[..8], &[0, 0, 0, 0, 0, 0, 2, 1]);
        let word = u32::from_be_bytes(ack.bytes[8..12].try_into().unwrap());
        assert_eq!(word, 7 | 6 << 8 | if unplug { 3 << 30 } else { 2 << 30 });
    }
}

#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_CONFIG_ORACLE"]
fn unchanged_linux_config_frames_match_rust_wire_bytes() {
    extern crate std;
    use std::{env, fs};
    let path = env::var("STELA_THUNDERBOLT_CONFIG_ORACLE").expect("set oracle trace path");
    let trace = fs::read_to_string(path).unwrap();
    let mut count = 0;
    for line in trace.lines() {
        let f: Vec<_> = line.split_ascii_whitespace().collect();
        let number = |i: usize| f[i].parse::<u64>().unwrap();
        let (frame, at) = match f[0] {
            "C" => {
                let route = Route::new(number(1)).unwrap();
                let space = match number(2) {
                    0 => Space::Hops,
                    1 => Space::Port,
                    2 => Space::Router,
                    3 => Space::Counters,
                    _ => panic!("space"),
                };
                let address = Address {
                    space,
                    port: number(3) as u8,
                    offset: number(4) as u16,
                    words: number(5) as u8,
                };
                let sequence = number(6) as u8;
                let request = if number(7) == 0 {
                    Request::read(route, address, sequence).unwrap()
                } else {
                    let route_index = [
                        0,
                        1,
                        0x010203040506,
                        0xffffffff,
                        0x100000000,
                        0x3fffffffffffff,
                        0x3fffff00000000,
                    ]
                    .iter()
                    .position(|v| *v == route.raw())
                    .unwrap();
                    let data: Vec<u32> = (0..u32::from(address.words))
                        .map(|j| {
                            0x10203040
                                ^ j.wrapping_mul(0x01010101)
                                ^ ((route_index as u32) << 28)
                                ^ (u32::from(address.port) << 16)
                                ^ (u32::from(sequence) << 8)
                                ^ (space as u32)
                        })
                        .collect();
                    Request::write(route, address, sequence, &data).unwrap()
                };
                (request.frame().clone(), 8)
            }
            "P" => (
                PlugEvent {
                    route: Route::new(number(1)).unwrap(),
                    port: number(2) as u8,
                    unplug: number(3) != 0,
                    header_flags: 0,
                }
                .acknowledgement()
                .unwrap(),
                4,
            ),
            _ => panic!("record"),
        };
        assert_eq!(frame.kind as u64, number(at));
        assert_eq!(number(at), number(at + 1));
        assert_eq!(frame.bytes.len() as u64, number(at + 2));
        let bytes: Vec<u8> = f[at + 3]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(frame.bytes, bytes, "{line}");
        count += 1;
    }
    assert_eq!(count, 5432);
}
