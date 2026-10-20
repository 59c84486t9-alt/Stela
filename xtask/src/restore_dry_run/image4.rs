//! Image4 as restored and the guest's Image4 validator read it, written
//! independently of `stela_runtime::img4` and `restore::ticket` so the dry
//! run does not check the host with the host's own parser.
//!
//! An `IMG4` is `SEQUENCE { IA5String "IMG4", IM4P, [0] IM4M, [1] IM4R? }`.
//! Image4 looks a payload up in the ticket by the IM4P's four-character type
//! and compares the ticket's `DGST` with SHA-384 of the whole IM4P encoding;
//! the BuildManifest `Digest` of a component is that same hash. No signature
//! is evaluated here.
use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const IA5: u8 = 0x16;
const INTEGER: u8 = 0x02;
const OCTETS: u8 = 0x04;
const BOOLEAN: u8 = 0x01;

/// One DER element: its first identifier octet, its tag number (for the
/// multi-octet private tags IM4M names its entries with), its contents and
/// its whole encoding.
pub struct Element<'a> {
    pub first: u8,
    pub number: u32,
    pub body: &'a [u8],
    pub whole: &'a [u8],
}

pub fn element(bytes: &[u8]) -> Result<(Element<'_>, &[u8])> {
    ensure!(!bytes.is_empty(), "DER: truncated identifier");
    let first = bytes[0];
    let mut at = 1;
    let mut number = u32::from(first & 0x1f);
    if number == 0x1f {
        number = 0;
        loop {
            ensure!(at < bytes.len() && at < 6, "DER: tag number");
            let b = bytes[at];
            at += 1;
            number = (number << 7) | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    ensure!(at < bytes.len(), "DER: truncated length");
    let lead = bytes[at];
    at += 1;
    let length = if lead < 0x80 {
        usize::from(lead)
    } else {
        let width = usize::from(lead & 0x7f);
        ensure!(
            (1..=4).contains(&width) && at + width <= bytes.len(),
            "DER: length width"
        );
        let digits = &bytes[at..at + width];
        ensure!(digits[0] != 0, "DER: non-minimal length");
        at += width;
        let n = digits
            .iter()
            .fold(0usize, |n, &d| (n << 8) | usize::from(d));
        ensure!(n >= 0x80, "DER: non-minimal length");
        n
    };
    ensure!(at + length <= bytes.len(), "DER: truncated contents");
    Ok((
        Element {
            first,
            number,
            body: &bytes[at..at + length],
            whole: &bytes[..at + length],
        },
        &bytes[at + length..],
    ))
}

fn expect<'a>(bytes: &'a [u8], first: u8, what: &str) -> Result<(Element<'a>, &'a [u8])> {
    let (e, rest) = element(bytes)?;
    ensure!(
        e.first == first,
        "{what}: identifier {:#04x}, expected {first:#04x}",
        e.first
    );
    Ok((e, rest))
}

fn fourcc(bytes: &[u8]) -> Result<String> {
    ensure!(
        bytes.len() == 4,
        "four-character code of {} bytes",
        bytes.len()
    );
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// A bare IM4P: its type and where that type is encoded.
pub struct Im4p {
    pub kind: String,
    pub type_offset: usize,
}

/// `bytes` must be exactly one IM4P.
pub fn im4p(bytes: &[u8]) -> Result<Im4p> {
    let (seq, rest) = expect(bytes, SEQUENCE, "IM4P")?;
    ensure!(rest.is_empty(), "IM4P: trailing bytes");
    let (label, rest) = expect(seq.body, IA5, "IM4P label")?;
    ensure!(label.body == b"IM4P", "not an IM4P");
    let (kind, _) = expect(rest, IA5, "IM4P type")?;
    let offset = kind.body.as_ptr() as usize - bytes.as_ptr() as usize;
    Ok(Im4p {
        kind: fourcc(kind.body)?,
        type_offset: offset,
    })
}

/// `bytes` must be an `IMG4` carrying one IM4P and neither a manifest nor
/// restore information: its IM4P.
pub fn img4_payload_alone(bytes: &[u8]) -> Result<&[u8]> {
    let (seq, rest) = expect(bytes, SEQUENCE, "IMG4")?;
    ensure!(rest.is_empty(), "IMG4: trailing bytes");
    let (label, payload) = expect(seq.body, IA5, "IMG4 label")?;
    ensure!(label.body == b"IMG4", "not an IMG4");
    im4p(payload)?;
    Ok(payload)
}

/// `bytes` with its IM4P type replaced, as a restore host sends one image
/// for another component.
pub fn retype(bytes: &[u8], kind: &str) -> Result<Vec<u8>> {
    let header = im4p(bytes)?;
    ensure!(kind.len() == 4, "type {kind:?} is not four characters");
    let mut out = bytes.to_vec();
    out[header.type_offset..header.type_offset + 4].copy_from_slice(kind.as_bytes());
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property {
    Integer(u64),
    Data(Vec<u8>),
    Boolean(bool),
}
impl Property {
    pub fn integer(&self) -> Option<u64> {
        match self {
            Self::Integer(n) => Some(*n),
            Self::Data(d) if d.len() <= 8 => {
                Some(d.iter().fold(0, |n, &b| (n << 8) | u64::from(b)))
            }
            _ => None,
        }
    }
}

/// An IM4M: its `MANP` properties and each object's properties by tag.
pub struct Im4m {
    pub entries: BTreeMap<String, BTreeMap<String, Property>>,
}
impl Im4m {
    pub fn manp(&self, key: &str) -> Option<&Property> {
        self.entries.get("MANP")?.get(key)
    }
    /// The tags whose `DGST` is `digest`.
    pub fn tags_with(&self, digest: &[u8]) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, p)| p.get("DGST") == Some(&Property::Data(digest.to_vec())))
            .map(|(t, _)| t.clone())
            .collect()
    }
    pub fn covers(&self, tag: &str, digest: &[u8]) -> bool {
        self.entries
            .get(tag)
            .and_then(|p| p.get("DGST"))
            .is_some_and(|d| *d == Property::Data(digest.to_vec()))
    }
}

/// A named IM4M entry: `[PRIVATE tag] { SEQUENCE { IA5String tag, value } }`.
fn named(bytes: &[u8]) -> Result<(String, &[u8], &[u8])> {
    let (outer, rest) = element(bytes)?;
    ensure!(
        outer.first == 0xff,
        "IM4M entry is not a private constructed tag"
    );
    let (seq, after) = expect(outer.body, SEQUENCE, "IM4M entry")?;
    ensure!(after.is_empty(), "IM4M entry: trailing fields");
    let (name, value) = expect(seq.body, IA5, "IM4M entry name")?;
    let tag = fourcc(name.body)?;
    ensure!(
        outer.number.to_be_bytes() == name.body,
        "IM4M entry tag {:#x} names {tag}",
        outer.number
    );
    Ok((tag, value, rest))
}

pub fn im4m(bytes: &[u8]) -> Result<Im4m> {
    let (seq, rest) = expect(bytes, SEQUENCE, "IM4M")?;
    ensure!(rest.is_empty(), "IM4M: trailing bytes");
    let (label, rest) = expect(seq.body, IA5, "IM4M label")?;
    ensure!(label.body == b"IM4M", "not an IM4M");
    let (version, rest) = expect(rest, INTEGER, "IM4M version")?;
    ensure!(version.body == [0], "IM4M version");
    let (set, rest) = expect(rest, SET, "IM4M body")?;
    let (_signature, rest) = expect(rest, OCTETS, "IM4M signature")?;
    let (_chain, rest) = expect(rest, SEQUENCE, "IM4M certificate chain")?;
    ensure!(rest.is_empty(), "IM4M: trailing fields");
    let (manb, value, after) = named(set.body)?;
    ensure!(
        manb == "MANB" && after.is_empty(),
        "IM4M body is not one MANB"
    );
    let (objects, after) = expect(value, SET, "MANB set")?;
    ensure!(after.is_empty(), "MANB: trailing fields");
    let mut entries = BTreeMap::new();
    let mut at = objects.body;
    while !at.is_empty() {
        let (tag, value, rest) = named(at)?;
        at = rest;
        let (props, after) = expect(value, SET, "IM4M object properties")?;
        ensure!(after.is_empty(), "IM4M object {tag}: trailing fields");
        let mut properties = BTreeMap::new();
        let mut p = props.body;
        while !p.is_empty() {
            let (key, value, rest) = named(p)?;
            p = rest;
            let (v, after) = element(value)?;
            ensure!(
                after.is_empty(),
                "IM4M property {tag}.{key}: trailing fields"
            );
            let property = match v.first {
                INTEGER => {
                    ensure!(!v.body.is_empty() && v.body.len() <= 9, "IM4M integer");
                    Property::Integer(v.body.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b)))
                }
                OCTETS => Property::Data(v.body.to_vec()),
                BOOLEAN => Property::Boolean(v.body.first().is_some_and(|&b| b != 0)),
                other => bail!("IM4M property {tag}.{key}: identifier {other:#04x}"),
            };
            ensure!(
                properties.insert(key.clone(), property).is_none(),
                "IM4M property {tag}.{key} repeats"
            );
        }
        ensure!(
            entries.insert(tag.clone(), properties).is_none(),
            "IM4M object {tag} repeats"
        );
    }
    ensure!(entries.contains_key("MANP"), "IM4M has no MANP");
    Ok(Im4m { entries })
}

/// An IMG4's IM4P encoding and IM4M encoding.
pub fn img4(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let (seq, rest) = expect(bytes, SEQUENCE, "IMG4")?;
    ensure!(rest.is_empty(), "IMG4: trailing bytes");
    let (label, rest) = expect(seq.body, IA5, "IMG4 label")?;
    ensure!(label.body == b"IMG4", "not an IMG4");
    let (payload, rest) = expect(rest, SEQUENCE, "IMG4 payload")?;
    im4p(payload.whole)?;
    let (manifest, rest) = expect(rest, 0xa0, "IMG4 [0] manifest")?;
    let (ticket, after) = expect(manifest.body, SEQUENCE, "IMG4 manifest")?;
    ensure!(after.is_empty(), "IMG4 [0]: trailing fields");
    if !rest.is_empty() {
        let (info, after) = expect(rest, 0xa1, "IMG4 [1] restore info")?;
        ensure!(after.is_empty(), "IMG4: fields after [1]");
        let _ = info;
    }
    Ok((payload.whole, ticket.whole))
}

pub fn sha384(bytes: &[u8]) -> Vec<u8> {
    Sha384::digest(bytes).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let body = tlv(SEQUENCE, &[tlv(IA5, tag), value.to_vec()].concat());
        out.extend_from_slice(&tlv(0, &body)[1..]);
        out
    }

    #[test]
    fn an_img4_alone_carries_exactly_one_im4p() {
        let file = tlv(
            SEQUENCE,
            &[
                tlv(IA5, b"IM4P"),
                tlv(IA5, b"rsep"),
                tlv(IA5, b"1"),
                tlv(OCTETS, b"x"),
            ]
            .concat(),
        );
        let alone = tlv(SEQUENCE, &[tlv(IA5, b"IMG4"), file.clone()].concat());
        assert_eq!(img4_payload_alone(&alone).unwrap(), file.as_slice());
        // A bare IM4P, a manifest after it, or another label is not one.
        assert!(img4_payload_alone(&file).is_err());
        let signed = tlv(
            SEQUENCE,
            &[tlv(IA5, b"IMG4"), file.clone(), tlv(0xa0, b"m")].concat(),
        );
        assert!(img4_payload_alone(&signed).is_err());
        let other = tlv(SEQUENCE, &[tlv(IA5, b"IMG5"), file].concat());
        assert!(img4_payload_alone(&other).is_err());
    }

    #[test]
    fn a_ticket_covers_the_retyped_im4p_its_digest_names() {
        let payload = [
            tlv(IA5, b"IM4P"),
            tlv(IA5, b"sepi"),
            tlv(IA5, b"1"),
            tlv(OCTETS, b"x"),
        ]
        .concat();
        let file = tlv(SEQUENCE, &payload);
        assert_eq!(im4p(&file).unwrap().kind, "sepi");
        let rsep = retype(&file, "rsep").unwrap();
        assert_eq!(im4p(&rsep).unwrap().kind, "rsep");
        assert_ne!(sha384(&rsep), sha384(&file));
        let manp = private(
            b"MANP",
            &tlv(SET, &private(b"CHIP", &tlv(INTEGER, &[0x00, 0x81, 0x12]))),
        );
        let object = private(
            b"rsep",
            &tlv(SET, &private(b"DGST", &tlv(OCTETS, &sha384(&rsep)))),
        );
        let manb = private(b"MANB", &tlv(SET, &[manp, object].concat()));
        let ticket = tlv(
            SEQUENCE,
            &[
                tlv(IA5, b"IM4M"),
                tlv(INTEGER, &[0]),
                tlv(SET, &manb),
                tlv(OCTETS, b"sig"),
                tlv(SEQUENCE, b""),
            ]
            .concat(),
        );
        let m = im4m(&ticket).unwrap();
        assert_eq!(m.manp("CHIP").and_then(Property::integer), Some(0x8112));
        assert_eq!(m.tags_with(&sha384(&rsep)), ["rsep"]);
        assert!(m.covers("rsep", &sha384(&rsep)));
        assert!(!m.covers("sepi", &sha384(&file)));
        let whole = tlv(
            SEQUENCE,
            &[tlv(IA5, b"IMG4"), rsep.clone(), tlv(0xa0, &ticket)].concat(),
        );
        let (p, t) = img4(&whole).unwrap();
        assert_eq!((p, t), (rsep.as_slice(), ticket.as_slice()));
    }
}
