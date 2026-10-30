use super::*;
use crate::wifi::regulatory::database::tests::country_of;

const WIDE: u32 = NO_160MHZ | NO_320MHZ;

#[test]
fn a_single_rule_sets_its_restrictions_bandwidth_and_power() {
    for (flags, expected) in [
        (0, 0),
        (1, NO_OFDM),
        (2, INDOOR_ONLY),
        (4, RADAR),
        (8, NO_IR),
        (15, NO_OFDM | INDOOR_ONLY | RADAR | NO_IR),
    ] {
        let country = country_of(&[(5_150_000, 5_350_000, 80_000, 2350, flags)]);
        assert_eq!(
            country.channel(5180),
            Regulated {
                flags: expected | WIDE,
                max_reg_dbm: 23
            }
        );
    }
    let country = country_of(&[(5_150_000, 5_350_000, 20_000, 2000, 0)]);
    assert_eq!(
        country.channel(5340).flags,
        NO_HT40 | NO_80MHZ | WIDE,
        "a channel touching the rule's edge"
    );
    assert_eq!(country.channel(5345), Regulated::DISABLED);
    assert_eq!(country.channel(2412), Regulated::DISABLED);
}

#[test]
fn auto_bandwidth_spans_touching_rules() {
    let country = country_of(&[
        (5_170_000, 5_250_000, 20_000, 2000, 16),
        (5_250_000, 5_330_000, 20_000, 2000, 16),
    ]);
    assert_eq!(country.channel(5180).flags, NO_320MHZ);
    assert_eq!(country.channel(5320).flags, NO_320MHZ);
}

#[test]
fn a_channel_straddling_adjacent_rules_takes_both() {
    let country = country_of(&[
        (5_730_000, 5_850_000, 80_000, 3000, 0),
        (5_850_000, 5_895_000, 40_000, 2700, 2),
    ]);
    assert_eq!(
        country.channel(5845),
        Regulated {
            flags: NO_80MHZ | WIDE | INDOOR_ONLY,
            max_reg_dbm: 27
        }
    );
    let apart = country_of(&[
        (5_730_000, 5_845_000, 80_000, 3000, 0),
        (5_850_000, 5_895_000, 40_000, 2700, 0),
    ]);
    assert_eq!(apart.channel(5845), Regulated::DISABLED);
}

#[test]
fn a_band_marks_each_side_without_a_bonding_neighbor() {
    let centers: Vec<u16> = (0..13).map(|i| 2412 + 5 * i).chain([2484]).collect();
    let band = country_of(&[(2_402_000, 2_482_000, 40_000, 2000, 0)])
        .band(&centers)
        .unwrap();
    let base = NO_80MHZ | WIDE;
    // Channels 1-4 have no channel 20 MHz below; 10-13 none above; 14 is
    // outside the rule.
    for (i, channel) in band.iter().enumerate() {
        let expected = match i {
            0..4 => base | NO_HT40MINUS,
            9..13 => base | NO_HT40PLUS,
            13 => DISABLED | NO_HT40,
            _ => base,
        };
        assert_eq!(channel.flags, expected, "channel {}", i + 1);
    }
    let narrow = country_of(&[(2_402_000, 2_482_000, 20_000, 2000, 0)])
        .band(&centers[..2])
        .unwrap();
    assert!(narrow.iter().all(|c| c.flags & NO_HT40 == NO_HT40));
}
