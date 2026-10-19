//! An image's embedded code signature (`LC_CODE_SIGNATURE`), as the kernel
//! reads it at exec (`bsd/kern/ubc_subr.c`, `osfmk/kern/cs_blobs.h`): the
//! best code directory's flags, platform and identifiers, its cdhash, and
//! the entitlements blobs, and whether Apple issued its signing identity.
//! Reading a signature is not validating it; page hashes and the CMS
//! signature's trust are not checked here.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

const LC_CODE_SIGNATURE: u32 = 0x1d;
const MH_MAGIC_64: u32 = 0xfeed_facf;
const MACH_HEADER_64_BYTES: usize = 32;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade_7172;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
const CSSLOT_SIGNATURESLOT: u32 = 0x1_0000;
/// The SHA-256 fingerprint of the Apple Code Signing Certification
/// Authority certificate, which issues only Apple's own signing identities
/// (Software Signing) under the Apple Root CA.
const APPLE_CODE_SIGNING_CA: [u8; 32] = [
    0x5b, 0xda, 0xb1, 0x28, 0x8f, 0xc1, 0x68, 0x92, 0xfe, 0xf5, 0x0c, 0x65, 0x8d, 0xb5, 0x4f, 0x1e,
    0x2e, 0x19, 0xcf, 0x8f, 0x71, 0xcc, 0x55, 0xf7, 0x7d, 0xe2, 0xb9, 0x5e, 0x05, 0x1e, 0x25, 0x62,
];
const CSSLOT_CODEDIRECTORY: u32 = 0;
/// `CSSLOT_ALTERNATE_CODEDIRECTORIES` through its last slot.
const CSSLOT_ALTERNATE_FIRST: u32 = 0x1000;
const CSSLOT_ALTERNATE_LAST: u32 = 0x1004;
pub const CS_HASHTYPE_SHA1: u8 = 1;
pub const CS_HASHTYPE_SHA256: u8 = 2;
pub const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
pub const CS_HASHTYPE_SHA384: u8 = 4;
/// `CS_CDHASH_LEN`.
pub const CDHASH_BYTES: usize = 20;
/// CodeDirectory field offsets (`CS_CodeDirectory`, big-endian).
const CD_VERSION: usize = 8;
const CD_FLAGS: usize = 12;
const CD_IDENT_OFFSET: usize = 20;
const CD_CODE_LIMIT: usize = 32;
const CD_HASH_TYPE: usize = 37;
const CD_PLATFORM: usize = 38;
const CD_PAGE_SIZE: usize = 39;
const CD_SCATTER_OFFSET: usize = 44;
const CD_TEAM_OFFSET: usize = 48;
const CS_SUPPORTSSCATTER: u32 = 0x20100;
const CS_SUPPORTSTEAMID: u32 = 0x20200;
/// `SC_Scatter.base`, in hash pages.
const SCATTER_BASE: usize = 4;

fn be32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at + 4)
            .context("truncated code signature")?
            .try_into()?,
    ))
}

fn le32(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .context("truncated load command")?
            .try_into()?,
    ))
}

fn c_string(bytes: &[u8], at: usize) -> Option<String> {
    let tail = bytes.get(at..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    String::from_utf8(tail[..end].to_vec()).ok()
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeSignature {
    /// The chosen code directory's `flags`.
    pub flags: u32,
    pub platform: u8,
    pub hash_type: u8,
    pub identifier: Option<String>,
    pub team_identifier: Option<String>,
    #[serde(with = "hex_bytes")]
    pub cdhash: [u8; CDHASH_BYTES],
    pub entitlements: Option<Vec<u8>>,
    pub der_entitlements: Option<Vec<u8>>,
    /// The range of the file, from the slice's start, that the code
    /// directory's page hashes cover, as `cs_blob_init_validated` records
    /// it: from the scatter base (zero without one) to `codeLimit` rounded
    /// up to the hash page.
    pub start_offset: u64,
    pub end_offset: u64,
    /// Whether the CMS signature's certificates include the Apple Code
    /// Signing Certification Authority: code Apple itself signed, which
    /// library validation admits into any process ("signed by Apple or with
    /// the same Team ID"). The CMS signature is not verified.
    pub apple_signed: bool,
}

mod hex_bytes {
    pub fn serialize<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }
}

/// XNU's preference among a signature's code directories
/// (`hash_rank`): SHA-256 over truncated SHA-256 over SHA-1; SHA-384 last
/// among the supported ones.
fn rank(hash_type: u8) -> u8 {
    match hash_type {
        CS_HASHTYPE_SHA1 => 1,
        CS_HASHTYPE_SHA256_TRUNCATED => 2,
        CS_HASHTYPE_SHA256 => 3,
        CS_HASHTYPE_SHA384 => 4,
        _ => 0,
    }
}

fn cdhash(hash_type: u8, directory: &[u8]) -> Option<[u8; CDHASH_BYTES]> {
    let digest: Vec<u8> = match hash_type {
        CS_HASHTYPE_SHA1 => Sha1::digest(directory).to_vec(),
        CS_HASHTYPE_SHA256 | CS_HASHTYPE_SHA256_TRUNCATED => Sha256::digest(directory).to_vec(),
        CS_HASHTYPE_SHA384 => sha2::Sha384::digest(directory).to_vec(),
        _ => return None,
    };
    digest[..CDHASH_BYTES].try_into().ok()
}

/// BER nesting deeper than this is refused.
const BER_DEPTH: u8 = 32;

/// One BER element at the start of `bytes` (X.690; codesign writes CMS with
/// indefinite lengths around DER certificates): its tag, its contents and
/// the whole element. Over-long lengths and malformed elements are `None`.
fn ber_element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    ber(bytes, BER_DEPTH)
}

fn ber(bytes: &[u8], depth: u8) -> Option<(u8, &[u8], &[u8])> {
    let tag = *bytes.first()?;
    let first = *bytes.get(1)?;
    if first == 0x80 {
        // Indefinite: the contents run to the end-of-contents octets.
        let depth = depth.checked_sub(1)?;
        let mut at = 2;
        loop {
            let rest = bytes.get(at..)?;
            if rest.starts_with(&[0, 0]) {
                return Some((tag, &bytes[2..at], &bytes[..at + 2]));
            }
            at += ber(rest, depth)?.2.len();
        }
    }
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count > 4 {
            return None;
        }
        let length = bytes
            .get(2..2 + count)?
            .iter()
            .fold(0usize, |length, &byte| length << 8 | usize::from(byte));
        (length, 2 + count)
    };
    let whole = bytes.get(..header.checked_add(length)?)?;
    Some((tag, &whole[header..], whole))
}

/// The elements of a constructed element's contents.
fn ber_children(mut contents: &[u8]) -> impl Iterator<Item = (u8, &[u8], &[u8])> {
    core::iter::from_fn(move || {
        let element = ber_element(contents)?;
        contents = &contents[element.2.len()..];
        Some(element)
    })
}

/// Whether a CMS `ContentInfo` holding `SignedData` (RFC 5652) carries a
/// certificate whose SHA-256 fingerprint is `fingerprint`.
fn carries_certificate(cms: &[u8], fingerprint: &[u8; 32]) -> bool {
    const SEQUENCE: u8 = 0x30;
    const CONTEXT_0: u8 = 0xa0;
    let signed_data = ber_element(cms)
        .filter(|(tag, ..)| *tag == SEQUENCE)
        .and_then(|(_, info, _)| ber_children(info).find(|(tag, ..)| *tag == CONTEXT_0))
        .and_then(|(_, explicit, _)| ber_element(explicit))
        .filter(|(tag, ..)| *tag == SEQUENCE);
    let Some((_, signed_data, _)) = signed_data else {
        return false;
    };
    // `certificates [0] IMPLICIT CertificateSet`, after the version, the
    // digest algorithms and the encapsulated content.
    ber_children(signed_data)
        .skip(3)
        .find(|(tag, ..)| *tag == CONTEXT_0)
        .is_some_and(|(_, certificates, _)| {
            ber_children(certificates)
                .any(|(_, _, certificate)| Sha256::digest(certificate)[..] == fingerprint[..])
        })
}

/// The signature of a thin 64-bit Mach-O slice, or `None` without one.
pub fn read(slice: &[u8]) -> Result<Option<CodeSignature>> {
    ensure!(le32(slice, 0)? == MH_MAGIC_64, "not a 64-bit Mach-O slice");
    let count = le32(slice, 16)? as usize;
    let mut offset = MACH_HEADER_64_BYTES;
    let mut blob = None;
    for _ in 0..count {
        let command = le32(slice, offset)?;
        let size = le32(slice, offset + 4)? as usize;
        ensure!(size >= 8, "load command too small");
        if command == LC_CODE_SIGNATURE {
            blob = Some((
                le32(slice, offset + 8)? as usize,
                le32(slice, offset + 12)? as usize,
            ));
        }
        offset += size;
    }
    let Some((start, size)) = blob else {
        return Ok(None);
    };
    let blob = slice
        .get(start..start + size)
        .context("code signature outside the slice")?;
    parse(blob).map(Some)
}

/// An embedded signature superblob, as `F_ADDFILESIGS` reads it from a file.
pub fn parse(blob: &[u8]) -> Result<CodeSignature> {
    ensure!(
        be32(blob, 0)? == CSMAGIC_EMBEDDED_SIGNATURE,
        "code signature is not an embedded signature superblob"
    );
    let slots = be32(blob, 8)? as usize;
    let mut best: Option<(u8, &[u8])> = None;
    let mut entitlements = None;
    let mut der_entitlements = None;
    let mut apple_signed = false;
    for index in 0..slots {
        let slot = be32(blob, 12 + index * 8)?;
        let at = be32(blob, 16 + index * 8)? as usize;
        let magic = be32(blob, at)?;
        let length = be32(blob, at + 4)? as usize;
        let body = blob
            .get(at..at + length)
            .context("truncated signature blob")?;
        match magic {
            CSMAGIC_CODEDIRECTORY
                if slot == CSSLOT_CODEDIRECTORY
                    || (CSSLOT_ALTERNATE_FIRST..=CSSLOT_ALTERNATE_LAST).contains(&slot) =>
            {
                let hash_type = *body.get(CD_HASH_TYPE).context("truncated code directory")?;
                if best.is_none_or(|(kind, _)| rank(hash_type) > rank(kind)) {
                    best = Some((hash_type, body));
                }
            }
            CSMAGIC_EMBEDDED_ENTITLEMENTS => entitlements = Some(body[8..].to_vec()),
            CSMAGIC_EMBEDDED_DER_ENTITLEMENTS => der_entitlements = Some(body[8..].to_vec()),
            CSMAGIC_BLOBWRAPPER if slot == CSSLOT_SIGNATURESLOT => {
                apple_signed = carries_certificate(&body[8..], &APPLE_CODE_SIGNING_CA);
            }
            _ => {}
        }
    }
    let (hash_type, directory) = best.context("code signature has no code directory")?;
    let version = be32(directory, CD_VERSION)?;
    let identifier = c_string(directory, be32(directory, CD_IDENT_OFFSET)? as usize);
    let team_identifier = if version >= CS_SUPPORTSTEAMID {
        match be32(directory, CD_TEAM_OFFSET)? {
            0 => None,
            at => c_string(directory, at as usize),
        }
    } else {
        None
    };
    let page_shift = *directory
        .get(CD_PAGE_SIZE)
        .context("truncated code directory")?;
    ensure!(page_shift < 32, "code directory page size out of range");
    let page_mask = (1u64 << page_shift) - 1;
    let end_offset = (u64::from(be32(directory, CD_CODE_LIMIT)?) + page_mask) & !page_mask;
    let scatter = if version >= CS_SUPPORTSSCATTER {
        be32(directory, CD_SCATTER_OFFSET)? as usize
    } else {
        0
    };
    let start_offset = if scatter == 0 {
        0
    } else {
        u64::from(be32(directory, scatter + SCATTER_BASE)?) << page_shift
    };
    Ok(CodeSignature {
        flags: be32(directory, CD_FLAGS)?,
        platform: *directory
            .get(CD_PLATFORM)
            .context("truncated code directory")?,
        hash_type,
        identifier,
        team_identifier,
        cdhash: cdhash(hash_type, directory).context("unsupported code directory hash")?,
        entitlements,
        der_entitlements,
        start_offset,
        end_offset,
        apple_signed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(hash_type: u8, platform: u8, flags: u32) -> Vec<u8> {
        let mut cd = vec![0u8; 64];
        cd[..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        cd[CD_VERSION..CD_VERSION + 4].copy_from_slice(&0x20400u32.to_be_bytes());
        cd[CD_FLAGS..CD_FLAGS + 4].copy_from_slice(&flags.to_be_bytes());
        cd[CD_IDENT_OFFSET..CD_IDENT_OFFSET + 4].copy_from_slice(&56u32.to_be_bytes());
        cd[CD_HASH_TYPE] = hash_type;
        cd[CD_PLATFORM] = platform;
        cd[CD_PAGE_SIZE] = 12;
        cd[CD_CODE_LIMIT..CD_CODE_LIMIT + 4].copy_from_slice(&0x1801u32.to_be_bytes());
        cd[56..63].copy_from_slice(b"com.ex\0");
        let length = cd.len() as u32;
        cd[4..8].copy_from_slice(&length.to_be_bytes());
        cd
    }

    #[test]
    fn best_directory_supplies_flags_and_cdhash() {
        let sha1 = directory(CS_HASHTYPE_SHA1, 0, 1);
        let sha256 = directory(CS_HASHTYPE_SHA256, 13, 0x2_0000);
        let mut superblob = Vec::new();
        let header = 12 + 2 * 8;
        superblob.extend(CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        superblob.extend(0u32.to_be_bytes());
        superblob.extend(2u32.to_be_bytes());
        superblob.extend(CSSLOT_CODEDIRECTORY.to_be_bytes());
        superblob.extend((header as u32).to_be_bytes());
        superblob.extend(CSSLOT_ALTERNATE_FIRST.to_be_bytes());
        superblob.extend(((header + sha1.len()) as u32).to_be_bytes());
        superblob.extend(&sha1);
        superblob.extend(&sha256);
        let total = superblob.len() as u32;
        superblob[4..8].copy_from_slice(&total.to_be_bytes());
        let mut slice = vec![0u8; 32 + 16];
        slice[..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        slice[16..20].copy_from_slice(&1u32.to_le_bytes());
        slice[32..36].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
        slice[36..40].copy_from_slice(&16u32.to_le_bytes());
        slice[40..44].copy_from_slice(&48u32.to_le_bytes());
        slice[44..48].copy_from_slice(&total.to_le_bytes());
        slice.extend(&superblob);
        let signature = read(&slice).unwrap().unwrap();
        assert_eq!(signature.hash_type, CS_HASHTYPE_SHA256);
        assert_eq!(signature.platform, 13);
        assert_eq!(signature.flags, 0x2_0000);
        assert_eq!(signature.identifier.as_deref(), Some("com.ex"));
        assert_eq!(signature.cdhash[..], Sha256::digest(&sha256)[..20]);
        assert_eq!((signature.start_offset, signature.end_offset), (0, 0x2000));
        assert_eq!(parse(&superblob).unwrap().cdhash, signature.cdhash);
        assert!(!signature.apple_signed);
    }

    /// A DER element with a definite length.
    fn element(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match contents.len() {
            length @ 0..0x80 => out.push(length as u8),
            length => {
                out.push(0x82);
                out.extend((length as u16).to_be_bytes());
            }
        }
        out.extend(contents);
        out
    }

    #[test]
    fn certificates_are_found_in_cms_signed_data() {
        let leaf = element(0x30, &[0x02, 0x01, 0x07]);
        let authority = element(0x30, &[0u8; 200]);
        let cms = |certificates: &[u8]| {
            let signed_data = element(
                0x30,
                &[
                    element(0x02, &[1]),
                    element(0x31, &[]),
                    element(0x30, &element(0x06, &[0x2a])),
                    element(0xa0, certificates),
                    element(0x31, &[]),
                ]
                .concat(),
            );
            element(
                0x30,
                &[
                    element(0x06, &[0x2a, 0x86, 0x48]),
                    element(0xa0, &signed_data),
                ]
                .concat(),
            )
        };
        let fingerprint = |certificate: &[u8]| -> [u8; 32] { Sha256::digest(certificate).into() };
        let both = cms(&[leaf.clone(), authority.clone()].concat());
        assert!(carries_certificate(&both, &fingerprint(&authority)));
        assert!(carries_certificate(&both, &fingerprint(&leaf)));
        assert!(!carries_certificate(&cms(&leaf), &fingerprint(&authority)));
        assert!(!carries_certificate(&both, &APPLE_CODE_SIGNING_CA));
        // codesign's indefinite lengths around the certificates.
        let indefinite = |tag: u8, contents: &[u8]| [&[tag, 0x80], contents, &[0, 0]].concat();
        let signed_data = indefinite(
            0x30,
            &[
                element(0x02, &[1]),
                element(0x31, &[]),
                indefinite(0x30, &element(0x06, &[0x2a])),
                indefinite(0xa0, &[leaf.clone(), authority.clone()].concat()),
                element(0x31, &[]),
            ]
            .concat(),
        );
        let ber = indefinite(
            0x30,
            &[
                element(0x06, &[0x2a, 0x86, 0x48]),
                indefinite(0xa0, &signed_data),
            ]
            .concat(),
        );
        assert!(carries_certificate(&ber, &fingerprint(&authority)));
        assert!(!carries_certificate(
            &ber[..ber.len() - 2],
            &fingerprint(&authority)
        ));
        assert!(!carries_certificate(
            &[0x30, 0x80, 0, 0],
            &fingerprint(&leaf)
        ));
    }
}
