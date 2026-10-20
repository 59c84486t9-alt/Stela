//! A synthetic signing service for `--tss`: it records the request the
//! host would send to Apple and answers with an unsigned ticket naming the
//! dry run's ECID and covering the bare `lpol` policy. Nothing leaves the
//! machine; the ticket only exercises the host's request and stitching.
use super::{context::Ctx, image4};
use anyhow::{Result, anyhow, ensure};
use std::{cell::RefCell, io::Cursor, rc::Rc};
use stela_runtime::restore::{Result as HostResult, tss::Transport};

/// idevicerestore's `lpol_file`: an IM4P typed `lpol`, version `1.0`, with
/// a one-byte zero payload, written out independently of `restore::tss`.
fn local_policy() -> Vec<u8> {
    let body = [
        tlv(0x16, b"IM4P"),
        tlv(0x16, b"lpol"),
        tlv(0x16, b"1.0"),
        tlv(0x04, &[0]),
    ]
    .concat();
    tlv(0x30, &body)
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
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

fn private(tag: &[u8; 4], value: &[u8]) -> Vec<u8> {
    let mut n = u32::from_be_bytes(*tag);
    let mut digits = Vec::new();
    loop {
        digits.push((n & 0x7f) as u8);
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    let mut out = vec![0xff];
    for (i, d) in digits.iter().rev().enumerate() {
        out.push(if i + 1 < digits.len() { d | 0x80 } else { *d });
    }
    let body = tlv(0x30, &[tlv(0x16, tag), value.to_vec()].concat());
    out.extend_from_slice(&tlv(0, &body)[1..]);
    out
}

fn integer(n: u64) -> Vec<u8> {
    let mut b = n.to_be_bytes().to_vec();
    while b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
        b.remove(0);
    }
    if b[0] & 0x80 != 0 {
        b.insert(0, 0);
    }
    tlv(0x02, &b)
}

/// An unsigned IM4M for the board, personalized for `ecid`, covering `lpol`.
pub fn ticket(chip: u64, board: u64, domain: u64, ecid: u64) -> Vec<u8> {
    let manp = private(
        b"MANP",
        &tlv(
            0x31,
            &[
                private(b"BORD", &integer(board)),
                private(b"CHIP", &integer(chip)),
                private(b"ECID", &integer(ecid)),
                private(b"SDOM", &integer(domain)),
            ]
            .concat(),
        ),
    );
    let lpol = private(
        b"lpol",
        &tlv(
            0x31,
            &private(b"DGST", &tlv(0x04, &image4::sha384(&local_policy()))),
        ),
    );
    let manb = private(b"MANB", &tlv(0x31, &[manp, lpol].concat()));
    tlv(
        0x30,
        &[
            tlv(0x16, b"IM4M"),
            integer(0),
            tlv(0x31, &manb),
            tlv(0x04, b"unsigned dry-run ticket"),
            tlv(0x30, b""),
        ]
        .concat(),
    )
}

/// The recorded requests and the response the synthetic service gives.
pub struct Synthetic {
    pub ticket: Vec<u8>,
    pub requests: Rc<RefCell<Vec<Vec<u8>>>>,
}
impl Transport for Synthetic {
    fn post(&mut self, host: &str, path: &str, kind: &str, body: &[u8]) -> HostResult<Vec<u8>> {
        assert_eq!((host, path), ("gs.apple.com", "/TSS/controller?action=2"));
        assert!(kind.starts_with("text/xml"));
        self.requests.borrow_mut().push(body.to_vec());
        let mut answer = plist::Dictionary::new();
        answer.insert(
            "ApImg4Ticket".into(),
            plist::Value::Data(self.ticket.clone()),
        );
        let mut xml = Vec::new();
        plist::Value::Dictionary(answer)
            .to_writer_xml(&mut xml)
            .unwrap();
        let mut response = b"STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=".to_vec();
        response.extend(xml);
        Ok(response)
    }
}

thread_local! {
    pub static REQUESTS: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
}

/// The host's `Ap,LocalPolicy` and the request it sent the service.
pub fn check_policy(ctx: &mut Ctx, reply: &plist::Dictionary) -> Result<String> {
    let request = REQUESTS
        .with(|r| r.borrow().last().cloned())
        .ok_or_else(|| anyhow!("the host sent no TSS request"))?;
    let request = plist::Value::from_reader(Cursor::new(request))?;
    let r = request
        .as_dictionary()
        .ok_or_else(|| anyhow!("TSS request is not a dictionary"))?;
    let uint = |k: &str| r.get(k).and_then(plist::Value::as_unsigned_integer);
    ensure!(uint("ApECID") == Some(ctx.ecid), "TSS ApECID");
    for (k, id) in [
        ("ApChipID", "ApChipID"),
        ("ApBoardID", "ApBoardID"),
        ("ApSecurityDomain", "ApSecurityDomain"),
    ] {
        ensure!(uint(k) == ctx.number(id), "TSS {k}");
    }
    let lpol = local_policy();
    let digest = r
        .get("Ap,LocalPolicy")
        .and_then(plist::Value::as_dictionary)
        .and_then(|p| p.get("Digest"))
        .and_then(plist::Value::as_data);
    ensure!(
        digest == Some(image4::sha384(&lpol).as_slice()),
        "TSS Ap,LocalPolicy Digest"
    );
    ensure!(
        r.get("Ap,NextStageIM4MHash")
            .and_then(plist::Value::as_data)
            == Some(&[1u8; 48][..]),
        "TSS Ap,NextStageIM4MHash"
    );
    ensure!(
        r.get("Ap,VolumeUUID")
            .and_then(plist::Value::as_data)
            .is_some_and(|u| u.len() == 16 && u[0] == 0x3d),
        "TSS Ap,VolumeUUID is not the binary UUID"
    );
    let policy = reply
        .get("Ap,LocalPolicy")
        .and_then(plist::Value::as_data)
        .ok_or_else(|| anyhow!("no Ap,LocalPolicy data"))?;
    let (payload, ticket) = image4::img4(policy)?;
    ensure!(
        payload == lpol.as_slice(),
        "the policy IM4P is not the bare lpol"
    );
    let m = image4::im4m(ticket)?;
    ctx.check_ticket(&m, Some(ctx.ecid))?;
    ensure!(
        m.covers("lpol", &image4::sha384(payload)),
        "the ticket does not cover lpol"
    );
    Ok("TSS request carries libtatsu's local-policy tags; Ap,LocalPolicy stitches the ticket unchanged".into())
}
