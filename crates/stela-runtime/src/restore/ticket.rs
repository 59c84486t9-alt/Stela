//! IM4M coverage, not signature validation. A global ticket comes from a
//! digest-verified IPSW inventory, a personalized one from Apple's signing
//! service (`tss`). Guest Image4 still owns authentication. Require exact
//! chip/board/domain (and, personalized, the device's ECID) plus the SHA-384 of
//! the original IM4P before constructing an IMG4. No new signature, nonce
//! substitution, type rewrite or certificate is manufactured.
use super::{Error, Result, plist::Value, store::Identity};
use alloc::{collections::BTreeMap, vec::Vec};
use sha2::{Digest, Sha384};
const MAX_TICKET_BYTES: usize = 1024 * 1024;
#[derive(Clone, Copy)]
struct Der<'a> {
    rest: &'a [u8],
}
impl<'a> Der<'a> {
    fn next(&mut self) -> Result<(u8, u32, &'a [u8])> {
        let first = *self
            .rest
            .first()
            .ok_or(Error::Invalid("IM4M truncated tag"))?;
        self.rest = &self.rest[1..];
        let mut tag = (first & 31) as u32;
        if tag == 31 {
            tag = 0;
            let mut count = 0;
            loop {
                let byte = *self.rest.first().ok_or(Error::Invalid("IM4M tag"))?;
                self.rest = &self.rest[1..];
                count += 1;
                if count > 5 || tag >> 25 != 0 {
                    return Err(Error::Invalid("IM4M tag overflow"));
                }
                tag = (tag << 7) | (byte & 127) as u32;
                if byte & 128 == 0 {
                    break;
                }
            }
        }
        let byte = *self.rest.first().ok_or(Error::Invalid("IM4M length"))?;
        self.rest = &self.rest[1..];
        let len = if byte < 128 {
            byte as usize
        } else {
            let n = (byte & 127) as usize;
            if n == 0 || n > 4 || n > self.rest.len() || self.rest[0] == 0 {
                return Err(Error::Invalid("IM4M non-DER length"));
            }
            let value = self.rest[..n]
                .iter()
                .fold(0usize, |n, &b| (n << 8) | b as usize);
            self.rest = &self.rest[n..];
            if value < 128 {
                return Err(Error::Invalid("IM4M overlong length"));
            }
            value
        };
        let body = self
            .rest
            .get(..len)
            .ok_or(Error::Invalid("IM4M truncated body"))?;
        self.rest = &self.rest[len..];
        Ok((first, tag, body))
    }
    fn tag(&mut self, wanted: u8) -> Result<&'a [u8]> {
        let (first, _, b) = self.next()?;
        if first != wanted {
            return Err(Error::Invalid("IM4M unexpected tag"));
        }
        Ok(b)
    }
    fn end(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::Invalid("IM4M trailing fields"))
        }
    }
}
fn named<'a>(first: u8, tag: u32, body: &'a [u8]) -> Result<([u8; 4], Der<'a>)> {
    if first != 0xff {
        return Err(Error::Invalid("IM4M named entry"));
    }
    let name = tag.to_be_bytes();
    let mut outer = Der { rest: body };
    let mut entry = Der {
        rest: outer.tag(0x30)?,
    };
    outer.end()?;
    if entry.tag(0x16)? != name {
        return Err(Error::Invalid("IM4M tag/name mismatch"));
    }
    Ok((name, entry))
}
fn integer(b: &[u8]) -> Result<u64> {
    if b.is_empty() || b.len() > 9 || (b.len() == 9 && b[0] != 0) || b[0] & 128 != 0 {
        return Err(Error::Invalid("IM4M integer"));
    }
    Ok(b.iter().fold(0, |n, &v| (n << 8) | v as u64))
}
pub struct Ticket {
    bytes: Vec<u8>,
    entries: BTreeMap<[u8; 4], BTreeMap<[u8; 4], Value>>,
}
impl Ticket {
    /// A global ticket: one with any personalized or nonce-bound property
    /// refuses.
    pub fn global(bytes: Vec<u8>, identity: &Identity) -> Result<Self> {
        Self::parse(bytes, identity, None)
    }
    /// A ticket personalized for the device whose ECID is `ecid`: its `MANP`
    /// must name exactly that ECID. A nonce-bound property (`BNCH`, `snon`)
    /// still refuses, since no request here sends a nonce.
    pub fn personalized(bytes: Vec<u8>, identity: &Identity, ecid: u64) -> Result<Self> {
        let ticket = Self::parse(bytes, identity, Some(ecid))?;
        let named = ticket
            .entries
            .get(b"MANP")
            .and_then(|p| p.get(b"ECID"))
            .ok_or(Error::Invalid("personalized ticket names no ECID"))?
            .uint()?;
        if named != ecid {
            return Err(Error::Invalid("personalized ticket names another ECID"));
        }
        Ok(ticket)
    }
    fn parse(bytes: Vec<u8>, identity: &Identity, ecid: Option<u64>) -> Result<Self> {
        if bytes.len() > MAX_TICKET_BYTES {
            return Err(Error::Limit("IM4M bytes"));
        }
        let mut der = Der { rest: &bytes };
        let mut seq = Der {
            rest: der.tag(0x30)?,
        };
        der.end()?;
        if seq.tag(0x16)? != b"IM4M" || integer(seq.tag(2)?)? != 0 {
            return Err(Error::Invalid("IM4M label/version"));
        }
        let mut body = Der {
            rest: seq.tag(0x31)?,
        };
        let (first, tag, b) = body.next()?;
        body.end()?;
        let (name, mut manb) = named(first, tag, b)?;
        if name != *b"MANB" {
            return Err(Error::Invalid("IM4M MANB"));
        }
        let mut entries_der = Der {
            rest: manb.tag(0x31)?,
        };
        manb.end()?;
        let mut entries = BTreeMap::new();
        while !entries_der.rest.is_empty() {
            let (first, tag, b) = entries_der.next()?;
            let (name, mut entry) = named(first, tag, b)?;
            let mut properties = Der {
                rest: entry.tag(0x31)?,
            };
            entry.end()?;
            let mut props = BTreeMap::new();
            while !properties.rest.is_empty() {
                let (first, tag, b) = properties.next()?;
                let (key, mut property) = named(first, tag, b)?;
                let (first, _, b) = property.next()?;
                property.end()?;
                if matches!(&key, b"BNCH" | b"snon")
                    || (key == *b"ECID" && (ecid.is_none() || name != *b"MANP"))
                {
                    return Err(Error::Invalid("manifest is personalized/nonce-bound"));
                }
                let value = match first {
                    2 => Value::Integer(integer(b)?),
                    4 => Value::Data(b.to_vec()),
                    1 if b.len() == 1 && matches!(b[0], 0 | 255) => Value::Boolean(b[0] != 0),
                    _ => return Err(Error::Invalid("unsupported IM4M property")),
                };
                if props.insert(key, value).is_some() {
                    return Err(Error::Invalid("duplicate IM4M property"));
                }
            }
            if entries.insert(name, props).is_some() {
                return Err(Error::Invalid("duplicate IM4M entry"));
            }
        }
        seq.tag(4)?;
        seq.tag(0x30)?;
        seq.end()?;
        let manp = entries
            .get(b"MANP")
            .ok_or(Error::Invalid("IM4M missing MANP"))?;
        for (tag, key) in [
            (b"CHIP", "ApChipID"),
            (b"BORD", "ApBoardID"),
            (b"SDOM", "ApSecurityDomain"),
        ] {
            if manp
                .get(tag)
                .ok_or(Error::Invalid("IM4M missing platform property"))?
                .uint()?
                != identity.number(key)?
            {
                return Err(Error::Invalid("IM4M platform mismatch"));
            }
        }
        Ok(Self { bytes, entries })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn covers(&self, tag: [u8; 4], digest: &[u8]) -> bool {
        self.entries
            .get(&tag)
            .and_then(|p| p.get(b"DGST"))
            .and_then(|v| v.data().ok())
            == Some(digest)
    }
    /// Prefix and suffix for streaming an unchanged, digest-covered bare IM4P.
    pub fn envelope(
        &self,
        tag: [u8; 4],
        digest: &[u8],
        payload_bytes: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if !self.covers(tag, digest) {
            return Err(Error::Invalid("global manifest lacks component digest"));
        }
        let suffix = tlv(0xa0, &self.bytes);
        let label = tlv(0x16, b"IMG4");
        let total = payload_bytes
            .checked_add(label.len() as u64)
            .and_then(|n| n.checked_add(suffix.len() as u64))
            .ok_or(Error::Limit("IMG4 extent"))?;
        let total = u32::try_from(total).map_err(|_| Error::Limit("IMG4 DER length"))?;
        let mut prefix = vec![0x30];
        if total < 128 {
            prefix.push(total as u8);
        } else {
            let b = total.to_be_bytes();
            let skip = b.iter().take_while(|&&v| v == 0).count();
            prefix.push(0x80 | (4 - skip) as u8);
            prefix.extend_from_slice(&b[skip..]);
        }
        prefix.extend_from_slice(&label);
        Ok((prefix, suffix))
    }
    /// The tags whose `DGST` is `digest`.
    pub fn tags_with(&self, digest: &[u8]) -> Vec<[u8; 4]> {
        self.entries
            .iter()
            .filter(|(_, p)| p.get(b"DGST").and_then(|v| v.data().ok()) == Some(digest))
            .map(|(tag, _)| *tag)
            .collect()
    }
    /// Type a bare IM4P as the tag under which this ticket covers `digest`.
    /// Image4 finds an object in the ticket by its IM4P type, and one file
    /// can serve two components: the 26A434 J473 `RestoreDeviceTree` is the
    /// `dtre` DeviceTree file, and its manifest digest and ticket entry
    /// cover that IM4P typed `rdtr`. An image whose SHA-384 is already
    /// `digest` is left as it is; one no covered type makes hash to
    /// `digest` refuses.
    pub fn retype_covered(&self, im4p: &mut [u8], digest: &[u8]) -> Result<()> {
        if Sha384::digest(&*im4p).as_slice() == digest {
            return Ok(());
        }
        let original =
            crate::img4::payload_type(im4p).map_err(|_| Error::Invalid("IM4P payload type"))?;
        for tag in self.tags_with(digest) {
            crate::img4::set_payload_type(im4p, tag)
                .map_err(|_| Error::Invalid("IM4P payload type"))?;
            if Sha384::digest(&*im4p).as_slice() == digest {
                return Ok(());
            }
        }
        crate::img4::set_payload_type(im4p, original)
            .map_err(|_| Error::Invalid("IM4P payload type"))?;
        Err(Error::Invalid(
            "global manifest does not cover exact component digest",
        ))
    }
    pub fn wrap(&self, source: &[u8], manifest_digest: &[u8]) -> Result<Vec<u8>> {
        let parts = crate::img4::parse(source)
            .map_err(|_| Error::Invalid("personalized object needs original IM4P"))?;
        if parts.manifest.is_some() || parts.restore_info.is_some() {
            return Err(Error::Invalid(
                "refuse replacing existing IMG4 manifest/restore info",
            ));
        }
        let tag = crate::img4::payload_type(parts.payload)
            .map_err(|_| Error::Invalid("IM4P payload type"))?;
        let digest = Sha384::digest(parts.payload);
        if digest.as_slice() != manifest_digest || !self.covers(tag, manifest_digest) {
            return Err(Error::Invalid(
                "global manifest does not cover exact component digest",
            ));
        }
        Ok(tlv(
            0x30,
            &[
                tlv(0x16, b"IMG4"),
                parts.payload.to_vec(),
                tlv(0xa0, &self.bytes),
            ]
            .concat(),
        ))
    }
}
fn tlv(tag: u8, b: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if b.len() < 128 {
        out.push(b.len() as u8);
    } else {
        let n = (b.len() as u32).to_be_bytes();
        let skip = n.iter().take_while(|&&v| v == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&n[skip..]);
    }
    out.extend_from_slice(b);
    out
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
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
    pub(crate) fn manifest(payload: &[u8]) -> Vec<u8> {
        ticket_for(b"krnl", payload, None)
    }
    /// A synthetic ticket covering `payload` as `tag`, personalized for
    /// `ecid` when given.
    pub(crate) fn ticket_for(tag: &[u8; 4], payload: &[u8], ecid: Option<u64>) -> Vec<u8> {
        let mut p = [
            entry(b"CHIP", &tlv(2, &[0, 0x81, 0x12])),
            entry(b"BORD", &tlv(2, &[0x24])),
            entry(b"SDOM", &tlv(2, &[1])),
        ]
        .concat();
        if let Some(ecid) = ecid {
            let mut digits = ecid.to_be_bytes().to_vec();
            while digits.len() > 1 && digits[0] == 0 && digits[1] & 0x80 == 0 {
                digits.remove(0);
            }
            if digits[0] & 0x80 != 0 {
                digits.insert(0, 0);
            }
            p.extend(entry(b"ECID", &tlv(2, &digits)));
        }
        let entries = [
            entry(b"MANP", &tlv(0x31, &p)),
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
    #[test]
    fn a_personalized_ticket_must_name_this_devices_ecid() {
        let store = super::super::store::tests::fixture(b"x", false);
        let identity = store.identity();
        let bytes = ticket_for(b"lpol", b"policy", Some(0xabcd_1234));
        assert!(Ticket::global(bytes.clone(), identity).is_err());
        assert!(Ticket::personalized(bytes.clone(), identity, 0xabcd_1235).is_err());
        let ticket = Ticket::personalized(bytes, identity, 0xabcd_1234).unwrap();
        assert!(ticket.covers(*b"lpol", &Sha384::digest(b"policy")));
        let global = ticket_for(b"lpol", b"policy", None);
        assert!(Ticket::personalized(global, identity, 0xabcd_1234).is_err());
    }
    #[test]
    fn only_exact_payload_digest_can_be_wrapped() {
        let store = super::super::store::tests::fixture(b"x", false);
        let p = tlv(
            0x30,
            &[
                tlv(0x16, b"IM4P"),
                tlv(0x16, b"krnl"),
                tlv(0x16, b""),
                tlv(4, b"body"),
            ]
            .concat(),
        );
        let g = Ticket::global(manifest(&p), store.identity()).unwrap();
        let hash = Sha384::digest(&p);
        let wrapped = g.wrap(&p, &hash).unwrap();
        let parts = crate::img4::parse(&wrapped).unwrap();
        assert_eq!(parts.payload, p);
        assert_eq!(parts.manifest, Some(g.bytes()));
        assert!(g.wrap(&p, &[0; 48]).is_err());
        let mut changed = p.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(g.wrap(&changed, &hash).is_err());
        assert!(Ticket::global(vec![0; 6], store.identity()).is_err());
    }
    /// As 26A434 J473's `RestoreDeviceTree`: the `dtre` file, covered by the
    /// ticket's `rdtr` entry for the retyped IM4P.
    #[test]
    fn an_image_is_retyped_to_the_tag_that_covers_its_digest() {
        let store = super::super::store::tests::fixture(b"x", false);
        let file = tlv(
            0x30,
            &[
                tlv(0x16, b"IM4P"),
                tlv(0x16, b"dtre"),
                tlv(0x16, b""),
                tlv(4, b"tree"),
            ]
            .concat(),
        );
        let mut rdtr = file.clone();
        crate::img4::set_payload_type(&mut rdtr, *b"rdtr").unwrap();
        let digest = Sha384::digest(&rdtr);
        let g = Ticket::global(ticket_for(b"rdtr", &rdtr, None), store.identity()).unwrap();
        assert_eq!(g.tags_with(&digest), [*b"rdtr"]);
        let mut image = file.clone();
        g.retype_covered(&mut image, &digest).unwrap();
        assert_eq!(image, rdtr);
        let parts = crate::img4::parse(&g.wrap(&image, &digest).unwrap())
            .unwrap()
            .payload
            .to_vec();
        assert_eq!(parts, rdtr);
        // A digest the ticket covers under no tag leaves the image alone.
        let mut other = file.clone();
        assert!(g.retype_covered(&mut other, &[0; 48]).is_err());
        assert_eq!(other, file);
        // An image that already hashes to the digest is not retyped.
        let mut same = rdtr.clone();
        g.retype_covered(&mut same, &digest).unwrap();
        assert_eq!(same, rdtr);
    }
}
