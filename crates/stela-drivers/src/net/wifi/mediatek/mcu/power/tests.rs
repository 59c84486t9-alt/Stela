use super::*;
extern crate std;

pub(crate) struct Wire {
    pub command: u32,
    pub wait: bool,
    pub body: Vec<u8>,
    pub packet: Vec<u8>,
}
pub(crate) struct Source {
    pub alpha2: [u8; 2],
    pub bands: [Vec<Channel>; 3],
    pub wire: Vec<Wire>,
    pub hardware_bands: [bool; 3],
    pub clc_nonzero: bool,
}
impl Source {
    pub fn inputs(&self) -> Inputs<'_> {
        Inputs {
            alpha2: self.alpha2,
            ghz2: (!self.bands[0].is_empty()).then_some(self.bands[0].as_slice()),
            ghz5: (!self.bands[1].is_empty()).then_some(self.bands[1].as_slice()),
            ghz6: (!self.bands[2].is_empty()).then_some(self.bands[2].as_slice()),
        }
    }
}
fn word16(bytes: &[u8], at: &mut usize) -> usize {
    let n = usize::from(u16::from_le_bytes(bytes[*at..*at + 2].try_into().unwrap()));
    *at += 2;
    n
}
pub(crate) fn sources(root: &std::path::Path, chip: Chip) -> Vec<Source> {
    let number = match chip {
        Chip::Mt7921 => 7921,
        Chip::Mt7922 => 7922,
        Chip::Mt7925 => 7925,
    };
    let limits = std::fs::read(root.join(alloc::format!("{number}.limits"))).unwrap();
    let wire = std::fs::read(root.join(alloc::format!("{number}.trace"))).unwrap();
    let (mut at, mut wt) = (0, 0);
    let mut out = Vec::new();
    for case in 0..24 {
        let counts: [usize; 3] = core::array::from_fn(|_| word16(&limits, &mut at));
        let alpha2 = limits[at..at + 2].try_into().unwrap();
        at += 2;
        let mut bands: [Vec<Channel>; 3] = core::array::from_fn(|_| Vec::new());
        for (band, &count) in counts.iter().enumerate() {
            for _ in 0..count {
                let channel = limits[at];
                assert_eq!(limits[at + 1], [0, 1, 3][band]);
                at += 2;
                let mut take = |n: usize| {
                    let values = limits[at..at + n]
                        .iter()
                        .map(|&n| n as i8)
                        .collect::<Vec<_>>();
                    at += n;
                    values
                };
                let cck = take(4).try_into().unwrap();
                let ofdm = take(8).try_into().unwrap();
                let mcs = core::array::from_fn(|_| take(10).try_into().unwrap());
                let ru = core::array::from_fn(|_| take(12).try_into().unwrap());
                let eht = core::array::from_fn(|_| take(16).try_into().unwrap());
                bands[band].push(Channel {
                    hardware_value: channel,
                    limits: Limits {
                        cck,
                        ofdm,
                        mcs,
                        ru,
                        eht,
                    },
                });
            }
        }
        let count = word16(&wire, &mut wt);
        let mut packets = Vec::new();
        for _ in 0..count {
            let command = u32::from_le_bytes(wire[wt..wt + 4].try_into().unwrap());
            let wait = wire[wt + 4] != 0;
            wt += 5;
            let n = word16(&wire, &mut wt);
            let mut body = wire[wt..wt + n].to_vec();
            wt += n;
            let n = word16(&wire, &mut wt);
            let mut packet = wire[wt..wt + n].to_vec();
            wt += n;
            if chip == Chip::Mt7925 {
                // These source heap-header fields are genuinely unwritten;
                // canary allocation exposes them. Native deliberately zeroes
                // them, preserving all source-defined bytes exactly.
                for range in [0..4, 8..12, 15..16, 18..52] {
                    assert!(body[range.clone()].iter().all(|&b| b == 0x5a));
                    body[range.clone()].fill(0);
                    packet[48 + range.start..48 + range.end].fill(0);
                }
            }
            packets.push(Wire {
                command,
                wait,
                body,
                packet,
            });
        }
        out.push(Source {
            alpha2,
            bands,
            wire: packets,
            hardware_bands: {
                let mask = 1 + case % 7;
                [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0]
            },
            clc_nonzero: case % 4 != 0,
        });
    }
    assert_eq!(at, limits.len());
    assert_eq!(wt, wire.len());
    out
}
#[test]
fn sar_signed_units_first_configured_half_open_range_and_invalid_fallback_refusal() {
    let ranges = [
        None,
        Some(SarRange {
            start_mhz: 2400,
            end_mhz: 2500,
            quarter_dbm: -3,
        }),
        Some(SarRange {
            start_mhz: 2400,
            end_mhz: 2600,
            quarter_dbm: -30,
        }),
    ];
    assert_eq!(sar_limit(20, 2399, &ranges), Ok(20));
    assert_eq!(sar_limit(20, 2400, &ranges), Ok(-2));
    assert_eq!(sar_limit(20, 2499, &ranges), Ok(-2));
    assert_eq!(sar_limit(20, 2500, &ranges), Ok(-15));
    assert_eq!(sar_limit(20, 2600, &ranges), Ok(20));
    assert_eq!(sar_limit(-50, 2400, &ranges), Ok(-50));
    assert_eq!(sar_limit(-128, 2400, &ranges), Err(Error::PowerRange));
    assert_eq!(sar_limit(128, 2400, &ranges), Err(Error::PowerRange));
    assert_eq!(
        sar_limit(
            20,
            2400,
            &[Some(SarRange {
                start_mhz: 2400,
                end_mhz: 2500,
                quarter_dbm: -255
            })]
        ),
        Err(Error::PowerRange)
    );
    assert_eq!(
        sar_limit(
            20,
            2400,
            &[Some(SarRange {
                start_mhz: 2500,
                end_mhz: 2400,
                quarter_dbm: 0
            })]
        ),
        Err(Error::SarRange)
    );
    let mut invalid_later = ranges.to_vec();
    invalid_later.push(Some(SarRange {
        start_mhz: 2500,
        end_mhz: 2400,
        quarter_dbm: 0,
    }));
    assert_eq!(sar_limit(20, 2400, &invalid_later), Err(Error::SarRange));
}
#[test]
fn exact_fixed_channel_counts_order_and_flush_payload_bounds_refuse_before_publication() {
    for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
        let mut entries: Vec<_> = channels(chip, Band::Ghz2)
            .iter()
            .map(|&hardware_value| Channel {
                hardware_value,
                limits: Limits::uniform(-2),
            })
            .collect();
        entries[1].hardware_value = 0;
        assert!(matches!(
            Plan::build(
                chip,
                Inputs {
                    alpha2: *b"US",
                    ghz2: Some(&entries),
                    ghz5: None,
                    ghz6: None
                }
            ),
            Err(Error::ChannelOrder { index: 1, .. })
        ));
        assert!(matches!(
            Plan::build(
                chip,
                Inputs {
                    alpha2: *b"US",
                    ghz2: Some(&entries[..13]),
                    ghz5: None,
                    ghz6: None
                }
            ),
            Err(Error::Channels {
                expected: 14,
                actual: 13,
                ..
            })
        ));
    }
    for n in 0..8 {
        assert_eq!(flush_value(&vec![0; n]), Err(Error::TruncatedFlush));
    }
    assert_eq!(
        flush_value(&[0, 128, 12, 130, 255, 255, 255, 255, 0xaa]),
        Ok((0x820c8000, 0xffff_ffff))
    );
}
#[test]
#[ignore = "requires full unchanged SAR/SKU/rate-band/MCU source oracle"]
fn complete_source_sar_arithmetic_and_all_rate_batches_match_defined_bytes() {
    let root = std::path::PathBuf::from(std::env::var("STELA_MT792X_POWER_ORACLE").unwrap());
    for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
        let mut encoder = Encoder::default();
        for fixture in sources(&root, chip) {
            let plan = Plan::build(chip, fixture.inputs()).unwrap();
            assert_eq!(plan.requests().len(), fixture.wire.len());
            for (request, wire) in plan.requests().iter().zip(&fixture.wire) {
                assert_eq!(
                    wire.command,
                    if chip == Chip::Mt7925 {
                        (1 << 17) | 0x2c
                    } else {
                        (1 << 18)
                            | if request.kind() == Kind::PseFlush {
                                (1 << 16) | 0xc0
                            } else {
                                0x5d
                            }
                    }
                );
                assert_eq!(wire.wait, request.expects_response());
                assert_eq!(request.body(), wire.body);
                let packet = encoder.encode_power(request);
                assert_eq!(packet.bytes(), wire.packet);
            }
        }
    }
    let trace = std::fs::read(root.join("sar.trace")).unwrap();
    assert_eq!(trace.len(), 1024 * 46);
    let mut at = 0;
    for _ in 0..1024 {
        let power = i16::from_le_bytes(trace[at..at + 2].try_into().unwrap());
        let frequency = u32::from_le_bytes(trace[at + 2..at + 6].try_into().unwrap());
        at += 6;
        let ranges: [Option<SarRange>; 3] = core::array::from_fn(|_| {
            let present = trace[at] != 0;
            let start_mhz = u32::from_le_bytes(trace[at + 1..at + 5].try_into().unwrap());
            let end_mhz = u32::from_le_bytes(trace[at + 5..at + 9].try_into().unwrap());
            let quarter_dbm = i32::from_le_bytes(trace[at + 9..at + 13].try_into().unwrap());
            at += 13;
            present.then_some(SarRange {
                start_mhz,
                end_mhz,
                quarter_dbm,
            })
        });
        assert_eq!(sar_limit(power, frequency, &ranges), Ok(trace[at] as i8));
        at += 1;
    }
}
