use super::*;
use crate::wifi::station::phy::Role;
use alloc::{vec, vec::Vec};

fn ie(out: &mut Vec<u8>, id: u8, data: &[u8]) {
    out.extend_from_slice(&[id, data.len() as u8]);
    out.extend_from_slice(data);
}

fn ht(width40: bool) -> [u8; 26] {
    let mut data = [0; 26];
    data[..2].copy_from_slice(&(0x19e1_u16 | u16::from(width40) << 1).to_le_bytes());
    data[3..5].fill(0xff);
    data
}

fn vht(width160: bool) -> [u8; 12] {
    let mut data = [0; 12];
    let capability = 1_u32 | 0x60 | 0x180 | (3 << 23) | if width160 { 4 } else { 0 };
    data[..4].copy_from_slice(&capability.to_le_bytes());
    data[4..6].copy_from_slice(&0xfffa_u16.to_le_bytes());
    data[8..10].copy_from_slice(&0xfffa_u16.to_le_bytes());
    data
}

/// A 5 GHz HT+VHT station or AP; the AP operates on channel 36 with the
/// HT secondary above and the VHT operation `vht_operation`, with WMM when
/// `wmm`. `rates` are its supported rates.
fn elements(
    role: Role,
    rates: &[u8],
    wmm: bool,
    vht_operation: [u8; 5],
    width160: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    ie(&mut out, 1, rates);
    ie(&mut out, 45, &ht(true));
    ie(&mut out, 191, &vht(width160));
    if role == Role::AccessPoint {
        let mut operation = [0; 22];
        operation[0] = 36;
        operation[1] = 1 | 4;
        ie(&mut out, 61, &operation);
        ie(&mut out, 192, &vht_operation);
    }
    if wmm {
        ie(
            &mut out,
            221,
            &if role == Role::Station {
                vec![0, 0x50, 0xf2, 2, 0, 1, 0]
            } else {
                vec![
                    0, 0x50, 0xf2, 2, 1, 1, 0x89, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43,
                    94, 0, 0x62, 0x32, 47, 0,
                ]
            },
        );
    }
    out
}

const RATES: [u8; 8] = [0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108];
const EIGHTY: [u8; 5] = [1, 42, 0, 0, 0];

fn channel(number: u16) -> Channel {
    Channel {
        band: Band::Ghz5,
        number,
        frequency_mhz: 5000 + 5 * number,
    }
}

/// Channels 36 to 64, each with `flags(number)`.
fn domain(flags: impl Fn(u16) -> u32) -> Vec<(Channel, u32)> {
    (36..=64)
        .step_by(4)
        .map(|n| (channel(n), flags(n)))
        .collect()
}

fn run(
    local160: bool,
    ap: &[u8],
    flags: impl Fn(u16) -> u32,
) -> Result<(Mode, Width, u32), Refusal> {
    let local = Capabilities::parse(
        Band::Ghz5,
        Role::Station,
        &elements(Role::Station, &RATES, true, EIGHTY, local160),
    )
    .unwrap();
    let peer = Capabilities::parse(Band::Ghz5, Role::AccessPoint, ap).unwrap();
    let operations = Operations::parse(ap).unwrap();
    let channels = domain(flags);
    determine(&local, &peer, &operations, channel(36), Channels(&channels)).map(|c| {
        assert_eq!(c.definition.control, channel(36));
        (c.mode, c.definition.width, c.definition.center1_mhz)
    })
}

fn vht_ap(wmm: bool, operation: [u8; 5]) -> Vec<u8> {
    elements(Role::AccessPoint, &RATES, wmm, operation, true)
}

#[test]
fn an_unrestricted_vht_ap_associates_at_its_80_mhz() {
    assert_eq!(
        run(true, &vht_ap(true, EIGHTY), |_| 0),
        Ok((Mode::Vht, Width::Mhz80, 5210))
    );
}

#[test]
fn regulatory_flags_downgrade_the_channel_and_vht_to_ht() {
    // No 80 MHz: VHT at 40 MHz is HT.
    assert_eq!(
        run(true, &vht_ap(true, EIGHTY), |_| NO_80MHZ),
        Ok((Mode::Ht, Width::Mhz40, 5190))
    );
    // No HT40+ on the control channel either: HT at 20 MHz.
    assert_eq!(
        run(true, &vht_ap(true, EIGHTY), |n| NO_80MHZ
            | if n == 36 { NO_HT40PLUS } else { 0 }),
        Ok((Mode::Ht, Width::Mhz20, 5180))
    );
}

#[test]
fn the_station_s_bandwidth_narrows_the_ap_s_channel() {
    // The AP's deprecated 160 MHz VHT operation, centered on channel 50.
    let ap = vht_ap(true, [2, 50, 0, 0, 0]);
    assert_eq!(run(true, &ap, |_| 0), Ok((Mode::Vht, Width::Mhz160, 5250)));
    assert_eq!(run(false, &ap, |_| 0), Ok((Mode::Vht, Width::Mhz80, 5210)));
}

#[test]
fn an_ap_without_wmm_associates_legacy() {
    assert_eq!(
        run(true, &vht_ap(false, EIGHTY), |_| 0),
        Ok((Mode::Legacy, Width::Mhz20, 5180))
    );
}

#[test]
fn required_memberships_and_unusable_channels_are_refused() {
    // The AP requires the HE PHY the station lacks.
    let mut rates = RATES;
    rates[7] = 0x80 | 122;
    let ap = elements(Role::AccessPoint, &rates, true, EIGHTY, true);
    assert_eq!(run(true, &ap, |_| 0), Err(Refusal::Selectors));
    assert_eq!(
        run(true, &vht_ap(true, EIGHTY), |n| if n == 36 {
            DISABLED
        } else {
            0
        }),
        Err(Refusal::UnusableChannel)
    );
}
