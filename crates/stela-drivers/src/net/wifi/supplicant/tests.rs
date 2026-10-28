use super::*;
use alloc::vec;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn passphrase_psk_matches_the_ieee_test_vectors() {
    assert_eq!(
        passphrase_psk(b"password", b"IEEE")[..],
        hex("f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")
    );
    assert_eq!(
        passphrase_psk(b"ThisIsAPassword", b"ThisIsASSID")[..],
        hex("0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af")
    );
}

#[test]
fn prf_matches_the_ieee_test_vector() {
    assert_eq!(
        prf_sha1(&[0x0b; 20], b"prefix", b"Hi There", 64)[..],
        hex(concat!(
            "bcd4c650b30b9684951829e0d75f9d54b862175ed9f00606e17d8da35402ffee",
            "75df78c3d31e0f889f012120c0862beb67753e7439ae242edb8373698356cf5a"
        ))
    );
}

#[test]
fn key_unwrap_matches_rfc_3394_and_refuses_a_wrong_kek() {
    let kek: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let wrapped = hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
    let plain = hex("00112233445566778899aabbccddeeff");
    assert_eq!(unwrap(&kek, &wrapped).unwrap()[..], plain);
    assert_eq!(wrap(&kek, &plain), wrapped);
    assert_eq!(unwrap(&[0; 16], &wrapped).unwrap_err(), Error::Unwrap);
}

#[test]
fn cmac_matches_rfc_4493() {
    let key: [u8; 16] = hex("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
    assert_eq!(cmac(&key, &[])[..], hex("bb1d6929e95937287fa37d129b756746"));
    assert_eq!(
        cmac(&key, &hex("6bc1bee22e409f96e93d7e117393172a"))[..],
        hex("070a16b46b4d4144f79bdd9dd04a287c")
    );
    let forty = hex(concat!(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411"
    ));
    assert_eq!(
        cmac(&key, &forty)[..],
        hex("dfa66747de9ae63030ca32611497c827")
    );
}

const STATION: Mac = Mac([0x02, 0, 0, 0, 0, 0x01]);
const AP: Mac = Mac([0x02, 0, 0, 0, 0, 0x02]);
const RSN: [u8; 22] = [
    0x30, 20, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0, 0,
];

fn suites(akm: Akm) -> Suites {
    Suites {
        akm,
        pairwise: Cipher::Ccmp128,
        group: Cipher::Ccmp128,
        management: None,
    }
}

/// The authenticator's side of the handshakes.
struct Authenticator {
    suites: Suites,
    akm: Akm,
    pmk: Zeroizing<[u8; 32]>,
    anonce: [u8; 32],
    replay: u64,
    ptk: Option<Ptk>,
}

impl Authenticator {
    fn new(suites: Suites) -> Self {
        Self {
            suites,
            akm: suites.akm,
            pmk: Zeroizing::new([0x44; 32]),
            anonce: [0xa1; 32],
            replay: 0,
            ptk: None,
        }
    }

    fn message_1(&mut self) -> Vec<u8> {
        self.replay += 1;
        build(
            self.akm,
            PAIRWISE | ACK,
            self.replay,
            &self.anonce,
            &[],
            None,
        )
    }

    /// Check message 2 and derive the PTK from its SNonce.
    fn message_2(&mut self, frame: &[u8]) {
        let key = Frame::parse(frame).unwrap();
        assert_eq!(key.info & (PAIRWISE | MIC | ACK), PAIRWISE | MIC);
        assert_eq!(key.data, RSN);
        let ptk = Ptk::derive(
            &self.suites,
            &self.pmk,
            AP,
            STATION,
            &self.anonce,
            &key.nonce,
        );
        key.verify(self.akm, ptk.kck()).unwrap();
        self.ptk = Some(ptk);
    }

    /// An encrypted, signed frame whose key data holds `elements`.
    fn signed(&mut self, info: u16, elements: &[u8]) -> Vec<u8> {
        let ptk = self.ptk.as_ref().unwrap();
        let mut plain = elements.to_vec();
        if !plain.len().is_multiple_of(8) || plain.len() < 16 {
            plain.push(VENDOR);
            while !plain.len().is_multiple_of(8) || plain.len() < 16 {
                plain.push(0);
            }
        }
        self.replay += 1;
        let wrapped = wrap(ptk.kek(), &plain);
        let mut frame = build(self.akm, info, self.replay, &self.anonce, &wrapped, None);
        frame[HEADER + 61..HEADER + 69].copy_from_slice(&[7, 0, 0, 0, 0, 0, 0, 0]);
        let signature = mic(self.akm, ptk.kck(), &frame);
        frame[MIC_OFFSET..MIC_OFFSET + MIC_BYTES].copy_from_slice(&signature);
        frame
    }

    fn message_3(&mut self, rsn: &[u8]) -> Vec<u8> {
        self.message_3_with(rsn, &[])
    }

    fn message_3_with(&mut self, rsn: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut elements = rsn.to_vec();
        let length = self.suites.group.key_length();
        elements.extend_from_slice(&gtk_kde(
            1,
            &(0x50..0x50 + length as u8).collect::<Vec<_>>(),
        ));
        elements.extend_from_slice(extra);
        self.signed(
            PAIRWISE | ACK | MIC | INSTALL | SECURE | ENCRYPTED,
            &elements,
        )
    }

    fn group_message_1(&mut self) -> Vec<u8> {
        self.signed(ACK | MIC | SECURE | ENCRYPTED, &gtk_kde(2, &[0x66; 16]))
    }

    fn signed_reply(&self, frame: &[u8], info: u16) {
        let key = Frame::parse(frame).unwrap();
        assert_eq!(key.info & !VERSION, info);
        assert_eq!(key.replay, self.replay);
        key.verify(self.akm, self.ptk.as_ref().unwrap().kck())
            .unwrap();
    }
}

fn gtk_kde(index: u8, key: &[u8]) -> Vec<u8> {
    let mut kde = vec![
        VENDOR,
        6 + key.len() as u8,
        0x00,
        0x0f,
        0xac,
        GTK_KDE,
        index,
        0,
    ];
    kde.extend_from_slice(key);
    kde
}

fn supplicant(suites: Suites) -> Supplicant {
    Supplicant::new(
        suites,
        Zeroizing::new([0x44; 32]),
        STATION,
        AP,
        RSN.to_vec(),
        RSN.to_vec(),
    )
    .unwrap()
}

/// The handshake through message 2.
fn begun(suites: Suites) -> (Authenticator, Supplicant) {
    let mut ap = Authenticator::new(suites);
    let mut station = supplicant(suites);
    let step = station.receive(&ap.message_1(), &mut random).unwrap();
    ap.message_2(&step.reply.unwrap());
    (ap, station)
}

fn random() -> [u8; 32] {
    [0x5c; 32]
}

#[test]
fn four_way_and_group_handshakes_install_the_authenticators_keys() {
    for akm in [Akm::Psk, Akm::PskSha256] {
        let (mut ap, mut station) = begun(suites(akm));
        assert!(!station.established());
        let step = station.receive(&ap.message_3(&RSN), &mut random).unwrap();
        ap.signed_reply(&step.reply.unwrap(), PAIRWISE | MIC | SECURE);
        let pairwise = step.pairwise.unwrap();
        assert_eq!(pairwise.material[..], ap.ptk.as_ref().unwrap().tk()[..]);
        assert_eq!(
            (pairwise.index, pairwise.cipher, pairwise.scope),
            (0, Cipher::Ccmp128, KeyScope::Pairwise(AP))
        );
        assert_eq!(pairwise.receive, ReplaySeed::ZERO);
        let group = step.group.unwrap();
        let expected: Vec<u8> = (0x50..0x60).collect();
        assert_eq!((group.index, &group.material[..]), (1, &expected[..]));
        assert_eq!(group.scope, KeyScope::Group(AP));
        assert_eq!(
            group.receive,
            ReplaySeed::uniform(PacketNumber::new(7).unwrap())
        );
        assert!(step.integrity.is_none());
        assert!(station.established());
        let step = station.receive(&ap.group_message_1(), &mut random).unwrap();
        ap.signed_reply(&step.reply.unwrap(), MIC | SECURE);
        let group = step.group.unwrap();
        assert_eq!((group.index, &group.material[..]), (2, &[0x66; 16][..]));
        assert!(step.pairwise.is_none());
    }
}

#[test]
fn a_pmf_message_3_yields_its_igtk_and_a_tkip_gtk_swaps_its_michael_keys() {
    let suites = Suites {
        group: Cipher::Tkip,
        management: Some(ManagementCipher::Cmac128),
        ..suites(Akm::PskSha256)
    };
    let (mut ap, mut station) = begun(suites);
    let mut igtk = vec![VENDOR, 4 + 8 + 16, 0x00, 0x0f, 0xac, IGTK_KDE, 4, 0];
    igtk.extend_from_slice(&[9, 0, 0, 0, 0, 0]);
    igtk.extend_from_slice(&[0x77; 16]);
    let step = station
        .receive(&ap.message_3_with(&RSN, &igtk), &mut random)
        .unwrap();
    let integrity = step.integrity.unwrap();
    assert_eq!(
        (integrity.index, integrity.cipher, integrity.receive),
        (4, ManagementCipher::Cmac128, PacketNumber::new(9).unwrap())
    );
    assert_eq!(integrity.material[..], [0x77; 16]);
    let group = step.group.unwrap();
    let mut expected: Vec<u8> = (0x50..0x70).collect();
    expected[16..].rotate_left(8);
    assert_eq!(
        (group.cipher, &group.material[..]),
        (Cipher::Tkip, &expected[..])
    );

    // An IGTK index other than 4 or 5 is refused.
    let (mut ap, mut station) = begun(suites);
    igtk[6] = 6;
    assert_eq!(
        station
            .receive(&ap.message_3_with(&RSN, &igtk), &mut random)
            .unwrap_err(),
        Error::GroupKey
    );
}

#[test]
fn suites_come_from_the_pmf_selection_and_refuse_unkeyed_ciphers() {
    let new = |suites| {
        Supplicant::new(suites, Zeroizing::new([0; 32]), STATION, AP, vec![], vec![]).err()
    };
    let tkip = Suites {
        pairwise: Cipher::Tkip,
        ..suites(Akm::Psk)
    };
    let wep = Suites {
        group: Cipher::Wep104,
        ..suites(Akm::Psk)
    };
    assert_eq!(
        (new(tkip), new(wep)),
        (Some(Error::Unsupported), Some(Error::Unsupported))
    );
    assert_eq!(new(suites(Akm::Psk)), None);
    assert_eq!(Akm::from_suite(6), Some(Akm::PskSha256));
    assert_eq!(Akm::from_suite(1), None);
}

#[test]
fn replayed_forged_and_mismatched_message_3_install_nothing() {
    let (mut ap, mut station) = begun(suites(Akm::Psk));
    let mut forged = ap.message_3(&RSN);
    forged[MIC_OFFSET] ^= 1;
    assert_eq!(
        station.receive(&forged, &mut random).unwrap_err(),
        Error::Mic
    );
    let mut other = RSN;
    other[19] = 6;
    assert_eq!(
        station
            .receive(&ap.message_3(&other), &mut random)
            .unwrap_err(),
        Error::RsnElement
    );
    let message_3 = ap.message_3(&RSN);
    station.receive(&message_3, &mut random).unwrap();
    assert_eq!(
        station.receive(&message_3, &mut random).unwrap_err(),
        Error::Replay
    );
}

#[test]
fn group_keys_and_message_3_wait_for_their_handshake() {
    let mut ap = Authenticator::new(suites(Akm::Psk));
    ap.ptk = Some(Ptk::derive(
        &ap.suites,
        &ap.pmk,
        AP,
        STATION,
        &ap.anonce,
        &random(),
    ));
    let mut station = supplicant(suites(Akm::Psk));
    assert_eq!(
        station
            .receive(&ap.group_message_1(), &mut random)
            .unwrap_err(),
        Error::Sequence
    );
    assert_eq!(
        station
            .receive(&ap.message_3(&RSN), &mut random)
            .unwrap_err(),
        Error::Sequence
    );
    let mut wrong = supplicant(suites(Akm::PskSha256));
    assert_eq!(
        wrong.receive(&ap.message_1(), &mut random).unwrap_err(),
        Error::Version
    );
}
