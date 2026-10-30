// SPDX-License-Identifier: GPL-2.0-only
//! Original-C debounce controls; independent peer still owns W1C effects.
use super::*;

#[test]
#[ignore = "oracle: STELA_AMD_GPIO_ORACLE"]
fn unchanged_linux_debounce_bins_pin_zero_and_preserved_controls() {
    let path = std::env::var("STELA_AMD_GPIO_ORACLE").unwrap();
    let bytes = std::fs::read(path).unwrap();
    let text = core::str::from_utf8(&bytes).unwrap();
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("AMD_GPIO_DEBOUNCE a804c5742bff224d4cb4d25dd383554d598be32b 672")
    );
    let mut cases = 0;
    for pin in [0, 1, 62, 64, 127, 128, 183] {
        for internal in 0..if pin == 0 { 2 } else { 1 } {
            for seed in [0, 0x0000_03ff, 0x00e6_0000, 0x3101_0000] {
                for duration in [
                    0,
                    1,
                    60,
                    61,
                    62,
                    915,
                    975,
                    976,
                    977,
                    3899,
                    3900,
                    3901,
                    15624,
                    15625,
                    249999,
                    250000,
                    250001,
                    937500,
                    999999,
                    1000000,
                    u32::MAX,
                ] {
                    let fields: Vec<_> = lines
                        .next()
                        .expect("truncated C trace")
                        .split_whitespace()
                        .collect();
                    assert_eq!(fields.len(), 8);
                    assert_eq!(fields[0], "DB");
                    assert_eq!(fields[1].parse::<u8>().unwrap(), pin);
                    assert_eq!(fields[2].parse::<u32>().unwrap(), internal);
                    assert_eq!(u32::from_str_radix(fields[3], 16).unwrap(), seed);
                    assert_eq!(fields[4].parse::<u32>().unwrap(), duration);
                    let donor_result = fields[5].parse::<i32>().unwrap();
                    let donor_value = u32::from_str_radix(fields[6], 16).unwrap();
                    assert_eq!(fields[7], "1", "original callback always writes once");
                    assert_eq!(
                        donor_result,
                        if duration >= 1_000_000 && internal == 0 {
                            -22
                        } else {
                            0
                        }
                    );
                    for profile in profiles() {
                        let (mut controller, state, _) = setup(profile, &[pin]);
                        {
                            let mut state = state.borrow_mut();
                            state.pads[usize::from(pin)] = seed;
                            state.master = internal << 15;
                            state.trace.clear();
                        }
                        let result = controller.debounce(p(pin), duration);
                        let state_ref = state.borrow();
                        let writes: Vec<_> = state_ref
                            .trace
                            .iter()
                            .filter_map(|access| {
                                if let Access::Write32(offset, value) = access {
                                    Some((*offset, *value))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        if duration >= 1_000_000 {
                            // Deliberate stricter API: do not reproduce Linux's
                            // post-write error or pin0 override of invalid input.
                            assert_eq!(result, Err(Error::InvalidDebounce));
                            assert!(writes.is_empty());
                            assert_eq!(state_ref.pads[usize::from(pin)], seed);
                        } else {
                            result.unwrap();
                            assert_eq!(writes.len(), 2, "masked settle then final configuration");
                            assert!(writes.iter().all(|(offset, value)| {
                                *offset == usize::from(pin) * 4 && value & 0x3000_0000 == 0
                            }));
                            let value = state_ref.pads[usize::from(pin)];
                            // The donor's exact control encoding is compared in
                            // full; volatile input and W1C causes are separate.
                            assert_eq!(value & !0x3001_0000, donor_value & !0x3001_0000);
                            assert_eq!(value & 0x3001_0000, seed & 0x3001_0000);
                        }
                        drop(state_ref);
                        controller.retire().unwrap();
                    }
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 672);
    assert!(lines.next().is_none(), "unexpected trailing C cases");
}
