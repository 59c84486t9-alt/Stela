//! DNS A queries and answers (RFC 1035 sections 4.1 and 4.1.4): one
//! recursive question; answers may carry a CNAME chain, which is followed
//! within the same response.
use super::{Ipv4, NetError};
use alloc::{format, string::String, vec::Vec};

pub const PORT: u16 = 53;
const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;
const RECURSION_DESIRED: u16 = 0x0100;
const RESPONSE: u16 = 0x8000;
const TRUNCATED: u16 = 0x0200;
const MAX_NAME: usize = 253;
/// Compression pointers followed in one name before it is refused.
const MAX_POINTERS: usize = 16;

/// A query for `name`'s A records.
pub fn query(id: u16, name: &str) -> Result<Vec<u8>, NetError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(NetError::Invalid("DNS name length"));
    }
    let mut bytes = Vec::with_capacity(18 + name.len());
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&RECURSION_DESIRED.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(NetError::Invalid("DNS label"));
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&TYPE_A.to_be_bytes());
    bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(bytes)
}

/// The name at `at`, lower-cased, and the offset after it in place.
fn name(message: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut text = String::new();
    let mut end = None;
    for _ in 0..MAX_POINTERS {
        loop {
            let length = usize::from(*message.get(at)?);
            match length >> 6 {
                0 if length == 0 => {
                    return Some((text, end.unwrap_or(at + 1)));
                }
                0 => {
                    let label = message.get(at + 1..at + 1 + length)?;
                    if !text.is_empty() {
                        text.push('.');
                    }
                    text.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
                    if text.len() > MAX_NAME {
                        return None;
                    }
                    at += 1 + length;
                }
                3 => {
                    let pointer = usize::from(u16::from_be_bytes([
                        message[at] & 0x3f,
                        *message.get(at + 1)?,
                    ]));
                    end.get_or_insert(at + 2);
                    at = pointer;
                    break;
                }
                _ => return None,
            }
        }
    }
    None
}

/// The addresses `wanted` resolves to in the response to query `id`.
pub fn answer(message: &[u8], id: u16, wanted: &str) -> Result<Vec<Ipv4>, NetError> {
    let bad = || NetError::Dns(String::from("malformed response"));
    if message.len() < 12 {
        return Err(bad());
    }
    let word = |at: usize| u16::from_be_bytes([message[at], message[at + 1]]);
    if word(0) != id || word(2) & RESPONSE == 0 {
        return Err(NetError::Dns(String::from(
            "not the response to this query",
        )));
    }
    if word(2) & TRUNCATED != 0 {
        return Err(NetError::Dns(String::from(
            "truncated response (TCP fallback is not implemented)",
        )));
    }
    match word(2) & 0xf {
        0 => {}
        3 => return Err(NetError::Dns(format!("{wanted}: no such name"))),
        code => return Err(NetError::Dns(format!("{wanted}: response code {code}"))),
    }
    let (questions, answers) = (word(4), word(6));
    let mut at = 12;
    for _ in 0..questions {
        at = name(message, at).ok_or_else(bad)?.1 + 4;
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        let (owner, after) = name(message, at).ok_or_else(bad)?;
        let header = message.get(after..after + 10).ok_or_else(bad)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let class = u16::from_be_bytes([header[2], header[3]]);
        let length = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let data = after + 10;
        message.get(data..data + length).ok_or_else(bad)?;
        records.push((owner, kind, class, data, length));
        at = data + length;
    }
    let mut target = String::from(wanted.strip_suffix('.').unwrap_or(wanted));
    target.make_ascii_lowercase();
    // Follow the CNAME chain, bounded by the record count.
    for _ in 0..=records.len() {
        let addresses: Vec<Ipv4> = records
            .iter()
            .filter(|r| r.0 == target && r.1 == TYPE_A && r.2 == CLASS_IN && r.4 == 4)
            .map(|r| Ipv4(message[r.3..r.3 + 4].try_into().unwrap()))
            .collect();
        if !addresses.is_empty() {
            return Ok(addresses);
        }
        let Some(alias) = records
            .iter()
            .find(|r| r.0 == target && r.1 == TYPE_CNAME && r.2 == CLASS_IN)
        else {
            break;
        };
        target = name(message, alias.3).ok_or_else(bad)?.0;
    }
    Err(NetError::Dns(format!("{wanted}: no A record")))
}

/// A response the tests' resolver sends: each answer is an owner, and
/// either an address or an alias.
#[cfg(test)]
pub(crate) fn response(id: u16, question: &str, records: &[(&str, Result<Ipv4, &str>)]) -> Vec<u8> {
    let encode = |name: &str, bytes: &mut Vec<u8>| {
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&(RESPONSE | RECURSION_DESIRED | 0x80).to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    // The question's name, so answers can point at it.
    encode(question, &mut bytes);
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    for (owner, data) in records {
        if *owner == question {
            bytes.extend_from_slice(&[0xc0, 12]);
        } else {
            encode(owner, &mut bytes);
        }
        let (kind, rdata) = match data {
            Ok(ip) => (TYPE_A, ip.0.to_vec()),
            Err(alias) => {
                let mut rdata = Vec::new();
                encode(alias, &mut rdata);
                (TYPE_CNAME, rdata)
            }
        };
        bytes.extend_from_slice(&kind.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&300u32.to_be_bytes());
        bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&rdata);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_encode_labels_and_refuse_bad_names() {
        let bytes = query(0xbeef, "gs.apple.com.").unwrap();
        assert_eq!(&bytes[..4], &[0xbe, 0xef, 0x01, 0x00]);
        assert_eq!(&bytes[12..], b"\x02gs\x05apple\x03com\x00\x00\x01\x00\x01");
        assert!(query(1, "").is_err());
        assert!(query(1, "a..b").is_err());
        assert!(query(1, &"x".repeat(64)).is_err());
    }

    #[test]
    fn answers_follow_cnames_and_compression() {
        let ip = Ipv4([17, 1, 2, 3]);
        let message = response(
            7,
            "gs.apple.com",
            &[
                ("gs.apple.com", Err("gs-cdn.apple.com")),
                ("gs-cdn.apple.com", Ok(ip)),
            ],
        );
        assert_eq!(answer(&message, 7, "GS.Apple.com").unwrap(), [ip]);
        assert!(answer(&message, 8, "gs.apple.com").is_err());
        let direct = response(
            7,
            "a.test",
            &[("a.test", Ok(ip)), ("b.test", Ok(Ipv4([1; 4])))],
        );
        assert_eq!(answer(&direct, 7, "a.test").unwrap(), [ip]);
        let none = response(7, "a.test", &[("b.test", Ok(ip))]);
        assert!(answer(&none, 7, "a.test").is_err());
    }

    #[test]
    fn error_codes_truncation_and_pointer_loops_refuse() {
        let mut message = response(7, "a.test", &[("a.test", Ok(Ipv4([1; 4])))]);
        let mut failed = message.clone();
        failed[3] |= 3;
        assert!(
            matches!(answer(&failed, 7, "a.test"), Err(NetError::Dns(e)) if e.contains("no such"))
        );
        let mut truncated = message.clone();
        truncated[2] |= 0x02;
        assert!(answer(&truncated, 7, "a.test").is_err());
        // The answer's owner points at itself.
        let owner = message.len() - 16;
        message[owner] = 0xc0;
        message[owner + 1] = owner as u8;
        assert!(answer(&message, 7, "a.test").is_err());
    }
}
