//! The outer structure of Image4 files, in `no_std`: an `IMG4` container
//! holding an `IM4P` payload, an optional `IM4M` manifest and optional
//! `IM4R` restore information, or a bare `IM4P`.
//!
//! `IMG4 ::= SEQUENCE { IA5 "IMG4", IM4P, [0] EXPLICIT IM4M, [1] EXPLICIT
//! IM4R OPTIONAL }` and `IM4P ::= SEQUENCE { IA5 "IM4P", IA5 type, IA5
//! description, OCTET STRING payload, ... }`
//! ([blacktop/ipsw img4](https://github.com/blacktop/ipsw/tree/master/pkg/img4)).
//! This only splits the parts and names the payload type; decoding and
//! signature checks belong elsewhere.

/// The parts of an Image4 file, each its complete DER encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parts<'a> {
    pub payload: &'a [u8],
    pub manifest: Option<&'a [u8]>,
    pub restore_info: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Img4Error {
    Malformed(&'static str),
    /// Neither an `IMG4` nor an `IM4P`.
    NotImage4,
}

impl core::fmt::Display for Img4Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed Image4: {what}"),
            Self::NotImage4 => write!(f, "not an Image4 file"),
        }
    }
}

const SEQUENCE: u8 = 0x30;
const IA5_STRING: u8 = 0x16;
const CONTEXT_0: u8 = 0xa0;
const CONTEXT_1: u8 = 0xa1;

/// One DER element at the start of `bytes`: tag, contents and the whole
/// encoding.
fn element(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), Img4Error> {
    let malformed = Img4Error::Malformed("truncated DER");
    let tag = *bytes.first().ok_or(malformed)?;
    if tag & 0x1f == 0x1f {
        return Err(Img4Error::Malformed(
            "high-number tags are not Image4 structure",
        ));
    }
    let first = *bytes.get(1).ok_or(malformed)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let width = usize::from(first & 0x7f);
        if width == 0 || width > 4 {
            return Err(Img4Error::Malformed("unsupported DER length"));
        }
        let digits = bytes.get(2..2 + width).ok_or(malformed)?;
        if digits[0] == 0 {
            return Err(Img4Error::Malformed("nonminimal DER length"));
        }
        let length = digits
            .iter()
            .fold(0usize, |n, &b| (n << 8) | usize::from(b));
        if length < 128 {
            return Err(Img4Error::Malformed("nonminimal DER length"));
        }
        (length, 2 + width)
    };
    let end = header.checked_add(length).ok_or(malformed)?;
    let whole = bytes.get(..end).ok_or(malformed)?;
    Ok((tag, &whole[header..], whole))
}

/// The first field of a SEQUENCE when it is the IA5 string `label`.
fn labeled<'a>(sequence: &'a [u8], label: &[u8]) -> Result<&'a [u8], Img4Error> {
    let (tag, contents, _) = element(sequence)?;
    if tag != SEQUENCE {
        return Err(Img4Error::NotImage4);
    }
    let (tag, text, whole) = element(contents)?;
    if tag != IA5_STRING || text != label {
        return Err(Img4Error::NotImage4);
    }
    Ok(&contents[whole.len()..])
}

/// Split an `IMG4`, or accept a bare `IM4P` as a payload without manifest.
pub fn parse(bytes: &[u8]) -> Result<Parts<'_>, Img4Error> {
    let (_, _, whole) = element(bytes)?;
    if whole.len() != bytes.len() {
        return Err(Img4Error::Malformed("trailing bytes"));
    }
    if labeled(bytes, b"IM4P").is_ok() {
        return Ok(Parts {
            payload: bytes,
            manifest: None,
            restore_info: None,
        });
    }
    let mut rest = labeled(bytes, b"IMG4")?;
    let (tag, _, payload) = element(rest)?;
    if tag != SEQUENCE {
        return Err(Img4Error::Malformed("IMG4 without an IM4P"));
    }
    labeled(payload, b"IM4P")?;
    rest = &rest[payload.len()..];
    let mut parts = Parts {
        payload,
        manifest: None,
        restore_info: None,
    };
    while !rest.is_empty() {
        let (tag, contents, whole) = element(rest)?;
        match tag {
            CONTEXT_0 => {
                if parts.manifest.is_some() {
                    return Err(Img4Error::Malformed("duplicate IMG4 manifest"));
                }
                let (_, _, manifest) = element(contents)?;
                if manifest.len() != contents.len() {
                    return Err(Img4Error::Malformed("trailing fields in IMG4 manifest"));
                }
                labeled(contents, b"IM4M")
                    .map_err(|_| Img4Error::Malformed("[0] is not an IM4M"))?;
                parts.manifest = Some(contents);
            }
            CONTEXT_1 => {
                if parts.restore_info.is_some() {
                    return Err(Img4Error::Malformed("duplicate IMG4 restore information"));
                }
                let (_, _, restore) = element(contents)?;
                if restore.len() != contents.len() {
                    return Err(Img4Error::Malformed(
                        "trailing fields in IMG4 restore information",
                    ));
                }
                labeled(contents, b"IM4R")
                    .map_err(|_| Img4Error::Malformed("[1] is not an IM4R"))?;
                parts.restore_info = Some(contents);
            }
            _ => return Err(Img4Error::Malformed("unknown IMG4 field")),
        }
        rest = &rest[whole.len()..];
    }
    Ok(parts)
}

/// The four-character type of an `IM4P`, such as `krnl` or `dtre`.
pub fn payload_type(im4p: &[u8]) -> Result<[u8; 4], Img4Error> {
    let rest = labeled(im4p, b"IM4P")?;
    let (tag, text, _) = element(rest)?;
    if tag != IA5_STRING || text.len() != 4 {
        return Err(Img4Error::Malformed("IM4P type is not four characters"));
    }
    Ok(text.try_into().unwrap())
}

/// Set a bare `IM4P`'s four-character type, as a restore host retypes one
/// image for another component (the `SEP` image `sepi` sent as `RestoreSEP`
/// `rsep`, whose manifest digest covers the retyped encoding).
pub fn set_payload_type(im4p: &mut [u8], kind: [u8; 4]) -> Result<(), Img4Error> {
    parse(im4p)?;
    let rest = labeled(im4p, b"IM4P")?;
    let (tag, text, _) = element(rest)?;
    if tag != IA5_STRING || text.len() != 4 {
        return Err(Img4Error::Malformed("IM4P type is not four characters"));
    }
    // A four-byte IA5 string has a two-byte header.
    let at = im4p.len() - rest.len() + 2;
    im4p[at..at + 4].copy_from_slice(&kind);
    Ok(())
}

/// The header of a DER element: tag, the offset of its contents and its
/// declared content length; the contents need not be present.
fn header(bytes: &[u8]) -> Result<(u8, usize, usize), Img4Error> {
    let malformed = Img4Error::Malformed("truncated DER header");
    let tag = *bytes.first().ok_or(malformed)?;
    let first = *bytes.get(1).ok_or(malformed)?;
    if first < 0x80 {
        return Ok((tag, 2, usize::from(first)));
    }
    let width = usize::from(first & 0x7f);
    if width == 0 || width > 4 {
        return Err(Img4Error::Malformed("unsupported DER length"));
    }
    let digits = bytes.get(2..2 + width).ok_or(malformed)?;
    Ok((
        tag,
        2 + width,
        digits.iter().fold(0, |n, &b| (n << 8) | usize::from(b)),
    ))
}

/// The payload type of an `IMG4` or `IM4P` from the first bytes of the
/// file, without reading the whole payload; 64 bytes always suffice.
pub fn peek_payload_type(prefix: &[u8]) -> Result<[u8; 4], Img4Error> {
    let string = |at: usize| -> Result<(&[u8], usize), Img4Error> {
        let (tag, offset, length) = header(prefix.get(at..).ok_or(Img4Error::NotImage4)?)?;
        if tag != IA5_STRING {
            return Err(Img4Error::NotImage4);
        }
        let text = prefix
            .get(at + offset..at + offset + length)
            .ok_or(Img4Error::Malformed("truncated prefix"))?;
        Ok((text, at + offset + length))
    };
    let (tag, offset, _) = header(prefix)?;
    if tag != SEQUENCE {
        return Err(Img4Error::NotImage4);
    }
    let (label, mut at) = string(offset)?;
    if label == b"IMG4" {
        let (tag, offset, _) = header(prefix.get(at..).ok_or(Img4Error::NotImage4)?)?;
        if tag != SEQUENCE {
            return Err(Img4Error::Malformed("IMG4 without an IM4P"));
        }
        let (label, next) = string(at + offset)?;
        if label != b"IM4P" {
            return Err(Img4Error::Malformed("IMG4 without an IM4P"));
        }
        at = next;
    } else if label != b"IM4P" {
        return Err(Img4Error::NotImage4);
    }
    let (kind, _) = string(at)?;
    kind.try_into()
        .map_err(|_| Img4Error::Malformed("IM4P type is not four characters"))
}

/// The bytes of a DER element whose contents are `contents` bytes long:
/// tag, length and contents, as `encode` writes them.
fn encoded_bytes(contents: usize) -> usize {
    let length_bytes = match contents {
        0..0x80 => 1,
        length => 1 + (8 - (length as u64).leading_zeros() as usize / 8),
    };
    1 + length_bytes + contents
}

/// A DER length and contents after `tag`.
fn encode(tag: u8, contents: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![tag];
    match contents.len() {
        length @ 0..0x80 => out.push(length as u8),
        length => {
            let digits = (length as u64).to_be_bytes();
            let skip = digits.iter().take_while(|&&b| b == 0).count();
            out.push(0x80 | (8 - skip) as u8);
            out.extend_from_slice(&digits[skip..]);
        }
    }
    out.extend_from_slice(contents);
    out
}

/// An `IMG4` of a payload and the manifest that signs it, as iBoot forwards
/// one.
pub fn compose(im4p: &[u8], im4m: &[u8]) -> alloc::vec::Vec<u8> {
    let mut contents = encode(IA5_STRING, b"IMG4");
    contents.extend_from_slice(im4p);
    contents.extend(encode(CONTEXT_0, im4m));
    encode(SEQUENCE, &contents)
}

/// An `IMG4` of a payload alone: its manifest and restore information are
/// optional, and a firmware a manifest does not sign carries neither.
pub fn container(im4p: &[u8]) -> alloc::vec::Vec<u8> {
    let mut contents = encode(IA5_STRING, b"IMG4");
    contents.extend_from_slice(im4p);
    encode(SEQUENCE, &contents)
}

/// The length of `container` for an `IM4P` of `im4p` bytes, without
/// building it.
pub fn container_bytes(im4p: usize) -> usize {
    encoded_bytes(encoded_bytes(b"IMG4".len()) + im4p)
}

/// Where an `IMG4`'s manifest and restore information begin, from the first
/// bytes of the file; `None` for a bare `IM4P`, which has neither. 64 bytes
/// always suffice.
pub fn tail_offset(prefix: &[u8]) -> Result<Option<usize>, Img4Error> {
    let (tag, offset, _) = header(prefix)?;
    if tag != SEQUENCE {
        return Err(Img4Error::NotImage4);
    }
    let (tag, label_offset, label_length) =
        header(prefix.get(offset..).ok_or(Img4Error::NotImage4)?)?;
    let label = prefix
        .get(offset + label_offset..offset + label_offset + label_length)
        .ok_or(Img4Error::Malformed("truncated prefix"))?;
    if tag != IA5_STRING {
        return Err(Img4Error::NotImage4);
    }
    match label {
        b"IM4P" => Ok(None),
        b"IMG4" => {
            let at = offset + label_offset + label_length;
            let (tag, payload_offset, payload_length) =
                header(prefix.get(at..).ok_or(Img4Error::NotImage4)?)?;
            if tag != SEQUENCE {
                return Err(Img4Error::Malformed("IMG4 without an IM4P"));
            }
            Ok(Some(at + payload_offset + payload_length))
        }
        _ => Err(Img4Error::NotImage4),
    }
}

/// The `IM4M` among an `IMG4`'s trailing fields (the bytes from
/// [`tail_offset`] to the end of the file).
pub fn tail_manifest(mut tail: &[u8]) -> Result<Option<&[u8]>, Img4Error> {
    let mut manifest = None;
    while !tail.is_empty() {
        let (tag, contents, whole) = element(tail)?;
        match tag {
            CONTEXT_0 => {
                labeled(contents, b"IM4M")
                    .map_err(|_| Img4Error::Malformed("[0] is not an IM4M"))?;
                manifest = Some(contents);
            }
            CONTEXT_1 => {}
            _ => return Err(Img4Error::Malformed("unknown IMG4 field")),
        }
        tail = &tail[whole.len()..];
    }
    Ok(manifest)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;

    pub(crate) fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![tag];
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            let length = (value.len() as u32).to_be_bytes();
            let skip = length.iter().take_while(|&&b| b == 0).count();
            out.push(0x80 | (4 - skip) as u8);
            out.extend(&length[skip..]);
        }
        out.extend(value);
        out
    }

    pub(crate) fn im4p(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        der(
            SEQUENCE,
            &[
                der(IA5_STRING, b"IM4P"),
                der(IA5_STRING, kind),
                der(IA5_STRING, b"synthetic"),
                der(0x04, payload),
            ]
            .concat(),
        )
    }

    pub(crate) fn img4(payload: &[u8], manifest: &[u8]) -> Vec<u8> {
        der(
            SEQUENCE,
            &[
                der(IA5_STRING, b"IMG4"),
                payload.to_vec(),
                der(CONTEXT_0, manifest),
            ]
            .concat(),
        )
    }

    #[test]
    fn splits_img4_and_accepts_bare_im4p() {
        let payload = im4p(b"krnl", &[7; 200]);
        let manifest = der(
            SEQUENCE,
            &[der(IA5_STRING, b"IM4M"), der(0x02, &[0])].concat(),
        );
        let file = img4(&payload, &manifest);
        assert_eq!(compose(&payload, &manifest), file);
        let alone = container(&payload);
        assert_eq!(container_bytes(payload.len()), alone.len());
        // Every DER length width: short form and one to three length bytes.
        for bytes in [0, 0x70, 0x7a, 0x100, 0xfff0, 0x1_0000] {
            assert_eq!(
                container_bytes(bytes),
                container(&alloc::vec![0; bytes]).len()
            );
        }
        let parts = parse(&alone).unwrap();
        assert_eq!(parts.payload, payload.as_slice());
        assert!(parts.manifest.is_none() && parts.restore_info.is_none());
        assert_eq!(
            tail_offset(&alone[..alone.len().min(64)]).unwrap(),
            Some(alone.len())
        );
        let parts = parse(&file).unwrap();
        assert_eq!(parts.payload, payload.as_slice());
        assert_eq!(parts.manifest, Some(manifest.as_slice()));
        assert_eq!(payload_type(parts.payload).unwrap(), *b"krnl");
        assert_eq!(peek_payload_type(&file[..64]).unwrap(), *b"krnl");
        assert_eq!(peek_payload_type(&payload[..64]).unwrap(), *b"krnl");
        let tail = tail_offset(&file[..64]).unwrap().unwrap();
        assert_eq!(
            tail_manifest(&file[tail..]).unwrap(),
            Some(manifest.as_slice())
        );
        assert_eq!(tail_offset(&payload[..64]).unwrap(), None);
        assert_eq!(peek_payload_type(&manifest), Err(Img4Error::NotImage4));
        let bare = parse(&payload).unwrap();
        assert_eq!(bare.manifest, None);
        assert_eq!(parse(&manifest), Err(Img4Error::NotImage4));
        let mut trailing = file.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
    }
    #[test]
    fn ambiguous_manifests_restore_fields_and_nonminimal_lengths_refuse() {
        let payload = im4p(b"sepi", b"synthetic");
        let manifest = der(SEQUENCE, &der(IA5_STRING, b"IM4M"));
        let restore = der(SEQUENCE, &der(IA5_STRING, b"IM4R"));
        let prefix = [der(IA5_STRING, b"IMG4"), payload].concat();
        for fields in [
            [der(CONTEXT_0, &manifest), der(CONTEXT_0, &manifest)].concat(),
            [der(CONTEXT_1, &restore), der(CONTEXT_1, &restore)].concat(),
            der(CONTEXT_0, &[manifest.clone(), manifest.clone()].concat()),
            der(CONTEXT_1, &manifest),
        ] {
            assert!(parse(&der(SEQUENCE, &[prefix.clone(), fields].concat())).is_err());
        }
        assert!(parse(b"\x30\x81\x06\x16\x04IM4P").is_err());
        assert!(parse(b"\x30\x82\0\x80").is_err());
    }

    #[test]
    fn a_bare_im4p_is_retyped_in_place() {
        let mut im4p = [
            0x30, 0x11, 0x16, 0x04, b'I', b'M', b'4', b'P', 0x16, 0x04, b's', b'e', b'p', b'i',
            0x16, 0x00, 0x04, 0x01, 0x07,
        ];
        set_payload_type(&mut im4p, *b"rsep").unwrap();
        assert_eq!(payload_type(&im4p), Ok(*b"rsep"));
        assert_eq!(&im4p[14..], &[0x16, 0x00, 0x04, 0x01, 0x07]);
        let mut truncated = im4p[..10].to_vec();
        assert!(set_payload_type(&mut truncated, *b"sepi").is_err());
    }
}
