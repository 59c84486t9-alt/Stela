use super::*;
use alloc::vec;

/// Rates, extended rates, HT, VHT, HE, HE 6 GHz, EHT and WMM, as a local
/// advertisement holds them.
fn advertised() -> Vec<u8> {
    vec![
        1, 1, 12, 50, 1, 48, 45, 1, 0xa, 191, 1, 0xb, 255, 2, 35, 0xc, 255, 2, 59, 0xd, 255, 2,
        108, 0xe, 221, 1, 0xf,
    ]
}

#[test]
fn the_request_orders_elements_as_mac80211_and_keeps_the_mode_s() {
    let rsn = [48, 2, 1, 0];
    let mut request = Request {
        ssid: b"nw",
        rsn: &rsn,
        rsnxe: None,
        mode: Mode::Vht,
        wmm: true,
        spectrum: Some((23, &[36, 40])),
    };
    assert_eq!(
        request_elements(&request, &advertised()),
        [
            0, 2, b'n', b'w', 1, 1, 12, 50, 1, 48, 33, 2, 0, 23, 36, 4, 36, 1, 40, 1, 48, 2, 1, 0,
            45, 1, 0xa, 191, 1, 0xb, 221, 1, 0xf,
        ]
    );
    request.mode = Mode::Eht;
    request.spectrum = None;
    let elements = request_elements(&request, &advertised());
    assert_eq!(elements.len(), 4 + 6 + 4 + advertised().len() - 6);
    request.mode = Mode::Legacy;
    request.wmm = false;
    assert_eq!(
        request_elements(&request, &advertised()),
        [0, 2, b'n', b'w', 1, 1, 12, 50, 1, 48, 48, 2, 1, 0]
    );
    // The RSN Extension element follows the capabilities, before WMM.
    request.mode = Mode::Ht;
    request.wmm = true;
    request.rsnxe = Some(&crate::wifi::sae::H2E_RSNXE);
    assert_eq!(
        request_elements(&request, &advertised())[14..],
        [45, 1, 0xa, 244, 1, 0x20, 221, 1, 0xf]
    );
}

#[test]
fn the_capability_field_follows_band_mode_and_spectrum_management() {
    assert_eq!(capability(Band::Ghz2, Mode::He, false), 0x431);
    assert_eq!(capability(Band::Ghz5, Mode::Eht, true), 0x110);
    assert!(spectrum_management(0x111));
    assert_eq!(find(&advertised(), 191), Some(&[0xb][..]));
    assert_eq!(find(&[0, 5, 1], 0), None);
}
