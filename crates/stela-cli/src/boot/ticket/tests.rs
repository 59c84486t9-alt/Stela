use super::*;
use sha2::{Digest, Sha384};
use std::{cell::RefCell, rc::Rc};

/// A made-up machine.
const ECID: u64 = 0xc118_e934_9665_abb9;

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let n = (body.len() as u32).to_be_bytes();
        let skip = n.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&n[skip..]);
    }
    out.extend_from_slice(body);
    out
}

/// An IM4M property or entry `name` holding `value` (a private tag whose
/// number is the four characters).
fn entry(name: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut n = u32::from_be_bytes(*name);
    let mut digits = Vec::new();
    loop {
        digits.push((n & 127) as u8);
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    let mut out = vec![255];
    for (i, d) in digits.iter().rev().enumerate() {
        out.push(if i + 1 < digits.len() { d | 128 } else { *d });
    }
    let body = tlv(0x30, &[tlv(0x16, name), value.to_vec()].concat());
    out.extend_from_slice(&tlv(0, &body)[1..]);
    out
}

/// A synthetic ticket for `ecid` covering `payload` as `tag`, bound to
/// `nonces` when given: the shape the signing service's answers take.
fn ticket(tag: &[u8; 4], payload: &[u8], ecid: u64, nonces: Option<&tss::Nonces>) -> Vec<u8> {
    let mut digits = ecid.to_be_bytes().to_vec();
    while digits.len() > 1 && digits[0] == 0 && digits[1] & 0x80 == 0 {
        digits.remove(0);
    }
    if digits[0] & 0x80 != 0 {
        digits.insert(0, 0);
    }
    let mut manp = [
        entry(b"CHIP", &tlv(2, &[0, 0x81, 0x12])),
        entry(b"BORD", &tlv(2, &[0x24])),
        entry(b"SDOM", &tlv(2, &[1])),
        entry(b"ECID", &tlv(2, &digits)),
    ]
    .concat();
    if let Some(nonces) = nonces {
        manp.extend(entry(b"BNCH", &tlv(4, &nonces.ap)));
        manp.extend(entry(b"snon", &tlv(4, &nonces.sep)));
    }
    let entries = [
        entry(b"MANP", &tlv(0x31, &manp)),
        entry(
            tag,
            &tlv(0x31, &entry(b"DGST", &tlv(4, &Sha384::digest(payload)))),
        ),
    ]
    .concat();
    tlv(
        0x30,
        &[
            tlv(0x16, b"IM4M"),
            tlv(2, &[0]),
            tlv(0x31, &entry(b"MANB", &tlv(0x31, &entries))),
            tlv(4, b"synthetic-signature"),
            tlv(0x30, b""),
        ]
        .concat(),
    )
}

fn identity(variant: &str, build: u8) -> Value {
    let digest = |byte| Value::dict([("Digest", Value::Data(vec![byte; 48]))]);
    Value::dict([
        ("ApChipID", Value::from("0x8112")),
        ("ApBoardID", Value::from("0x24")),
        ("ApSecurityDomain", Value::from("0x01")),
        ("UniqueBuildID", Value::Data(vec![build; 20])),
        ("Cryptex1,ChipID", Value::from("0xFF10")),
        ("Cryptex1,NonceDomain", Value::Integer(0)),
        ("Info", Value::dict([("Variant", Value::from(variant))])),
        (
            "Manifest",
            Value::dict([
                ("Cryptex1,SystemOS", digest(1)),
                ("Cryptex1,SystemVolume", digest(2)),
                (
                    "KernelCache",
                    Value::dict([
                        ("Digest", Value::Data(vec![3; 48])),
                        ("Trusted", Value::Boolean(true)),
                        ("Info", Value::dict([])),
                    ]),
                ),
            ]),
        ),
    ])
}

/// A BuildManifest with an erase identity (0), a `macOS Customer` one of
/// the same board (1) and one of another board (2).
fn manifest() -> Vec<u8> {
    let mut other = identity("macOS Customer", 0x33);
    if let Value::Dict(fields) = &mut other {
        fields.insert("ApBoardID".into(), Value::from("0x26"));
    }
    let manifest = Value::dict([(
        "BuildIdentities",
        Value::Array(vec![
            identity("Customer Erase Install (IPSW)", 0x11),
            identity("macOS Customer", 0x22),
            other,
        ]),
    )]);
    plist::encode_xml(&manifest, Limits::default()).unwrap()
}

/// The signing service as setup's tests fake it: each request's answer,
/// recording what was asked.
struct Apple {
    nonces: Rc<RefCell<Option<tss::Nonces>>>,
    asked: Rc<RefCell<Vec<Value>>>,
}

impl tss::Transport for Apple {
    fn exchange(
        &mut self,
        host: &str,
        path: &str,
        _: &[(&str, &str)],
        _: &str,
        body: &[u8],
    ) -> restore::Result<Option<Vec<u8>>> {
        assert_eq!((host, path), (tss::HOST, tss::PATH));
        let request = plist::decode(body, Limits::default())?;
        let ecid = request.required("ApECID")?.bits()?;
        let answer = if request.get("@Cryptex1,Ticket").is_some() {
            Value::dict([("Cryptex1,Ticket", Value::Data(vec![9, 8, 7]))])
        } else if request.get("Ap,LocalPolicy").is_some() {
            let policy = ticket(b"lpol", &tss::LOCAL_POLICY, ecid, None);
            Value::dict([("ApImg4Ticket", Value::Data(policy))])
        } else {
            let nonces = tss::Nonces {
                ap: request.required("ApNonce")?.data()?.try_into().unwrap(),
                sep: request.required("SepNonce")?.data()?.try_into().unwrap(),
            };
            let bound = ticket(b"krnl", b"k", ecid, Some(&nonces));
            self.nonces.borrow_mut().get_or_insert(nonces);
            Value::dict([("ApImg4Ticket", Value::Data(bound))])
        };
        self.asked.borrow_mut().push(request);
        let mut response = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".to_vec();
        response.extend(plist::encode_xml(&answer, Limits::default())?);
        Ok(Some(response))
    }
}

#[test]
fn setup_stages_the_installs_three_answers_after_the_ap_ticket() {
    let manifest = manifest();
    let asked = Rc::new(RefCell::new(Vec::new()));
    let mut apple = Apple {
        nonces: Rc::default(),
        asked: asked.clone(),
    };
    let ap_ticket = personalized_with(&manifest, 0, ECID, &mut apple).unwrap();
    let staged = staged_with(&manifest, 0, ECID, &ap_ticket, &mut apple).unwrap();
    let asked = asked.borrow();
    // The AP ticket, then the recoveryOS root, Cryptex1 and LocalPolicy.
    assert_eq!(asked.len(), 4);
    let nonces = apple.nonces.borrow().clone().unwrap();
    assert_eq!(
        asked[1].required("ApNonce").unwrap().data().unwrap(),
        nonces.ap
    );
    assert!(asked[1].get("KernelCache").is_some());
    // The Cryptex1 request names the installed identity's build and binds
    // the AP ticket's nonce.
    let cryptex = &asked[2];
    assert_eq!(
        cryptex.required("UniqueBuildID").unwrap().data().unwrap(),
        [0x22; 20]
    );
    assert_eq!(
        cryptex.required("Cryptex1,Nonce").unwrap().data().unwrap(),
        nonces.ap
    );
    let policy = &asked[3];
    assert_eq!(
        policy
            .required("Ap,NextStageIM4MHash")
            .unwrap()
            .data()
            .unwrap(),
        Sha384::digest(&ap_ticket).as_slice()
    );
    let set = tss::staged::Set::decode(&staged).unwrap();
    assert!(set.complete());
    let nonce = set.policy_nonce.unwrap();
    assert_eq!(
        policy
            .required("Ap,RecoveryOSPolicyNonceHash")
            .unwrap()
            .data()
            .unwrap(),
        Sha384::digest(nonce).as_slice()
    );
}

struct Refusing;

impl tss::Transport for Refusing {
    fn exchange(
        &mut self,
        _: &str,
        _: &str,
        _: &[(&str, &str)],
        _: &str,
        _: &[u8],
    ) -> restore::Result<Option<Vec<u8>>> {
        Ok(Some(
            b"STATUS=94&MESSAGE=This device isn't eligible for the requested build.".to_vec(),
        ))
    }
}

#[test]
fn a_refused_staging_request_fails_setup_with_apples_message() {
    let manifest = manifest();
    let mut apple = Apple {
        nonces: Rc::default(),
        asked: Rc::default(),
    };
    let ap_ticket = personalized_with(&manifest, 0, ECID, &mut apple).unwrap();
    let error = staged_with(&manifest, 0, ECID, &ap_ticket, &mut Refusing).unwrap_err();
    assert!(error.to_string().contains("STATUS=94"), "{error}");
    // A ticket for another machine is not the install's.
    assert!(staged_with(&manifest, 0, ECID + 1, &ap_ticket, &mut apple).is_err());
}

#[test]
fn signing_requests_are_asked_again_and_a_sign_in_page_is_named() {
    use stela_runtime::restore::tss::Transport as _;
    let tss = "STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<?xml version=\"1.0\"?>";
    let reply = |status: &str, body: &str| {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let (url, _) = crate::net::tests::serve(vec![
        reply("502 Bad Gateway", ""),
        reply("200 OK", tss),
        reply("200 OK", "<html><body>Sign in to Guest Wi-Fi</body></html>"),
    ]);
    let host = url
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .unwrap()
        .to_owned();
    let mut apple = Apple(Client::new());
    let answer = apple
        .exchange(&host, "/TSS/controller", &[], "text/xml", b"<plist/>")
        .unwrap();
    assert_eq!(answer.as_deref(), Some(tss.as_bytes()));
    let error = apple
        .exchange(&host, "/TSS/controller", &[], "text/xml", b"<plist/>")
        .unwrap_err()
        .to_string();
    assert!(error.contains("sign in to the network"), "{error}");
    assert!(error.contains("a web page"), "{error}");
}
