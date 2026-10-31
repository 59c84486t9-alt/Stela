//! The collection's `__RECEIPT_INFO,__aux_kc_receipt`: the unsigned list of
//! the kexts it holds, which XNU's `kext_receipt` hands to CoreKDL for the
//! SEP's kext deny list. What boot trusts is the LocalPolicy's `auxr` digest
//! of it, so nothing here is a signature.
//!
//! The DER is the one `kernelmanagerd` 26A434 decodes at 0x10012149c:
//!
//! ```text
//! SEQUENCE {
//!     INTEGER 1,
//!     SEQUENCE {
//!         SEQUENCE {
//!             OCTET STRING,  -- CD hash, 20 bytes
//!             OCTET STRING,  -- team ID, 0 or 10 bytes
//!             OCTET STRING,  -- bundle ID hash, 32 bytes
//!             INTEGER,       -- OSKextVersion
//!         }...
//!     }
//! }
//! ```
//!
//! A kext linked from objects has no code signature, so no CD hash or team
//! ID: its objects' truncated SHA-256 names its code, as a code directory
//! hash would, and the team ID stays empty, as an ad hoc signature's does.
use super::{Kext, unit::Unit};
use crate::Result;
use sha2::{Digest, Sha256};
use stela_contracts::{refuse, require};

const INTEGER: u8 = 0x02;
const OCTET_STRING: u8 = 0x04;
const SEQUENCE: u8 = 0x30;

/// The only receipt version `kernelmanagerd` reads.
const VERSION: u64 = 1;
const CD_HASH_BYTES: usize = 20;

/// The receipt of `kexts`, each with the unit linked from it.
pub fn encode<'a>(
    kexts: impl IntoIterator<Item = (&'a Kext<'a>, &'a Unit<'a>)>,
) -> Result<Vec<u8>> {
    let mut entries = Vec::new();
    for (kext, unit) in kexts {
        let version = unit
            .info
            .get("CFBundleVersion")
            .and_then(plist::Value::as_string)
            .ok_or(refuse!("Info.plist has no CFBundleVersion"))?;
        let mut code = Sha256::new();
        kext.objects.iter().for_each(|object| code.update(object));
        entries.extend(tagged(
            SEQUENCE,
            &[
                tagged(OCTET_STRING, &code.finalize()[..CD_HASH_BYTES]),
                tagged(OCTET_STRING, &[]),
                tagged(OCTET_STRING, &Sha256::digest(&unit.identifier)),
                integer(kext_version(version)?),
            ]
            .concat(),
        ));
    }
    Ok(tagged(
        SEQUENCE,
        &[integer(VERSION), tagged(SEQUENCE, &entries)].concat(),
    ))
}

/// `OSKextParseVersionString` of a release version: four decimal digits each
/// of major, minor and revision, then the release stage. Kexts Stela links
/// are released, so a development, alpha, beta or candidate stage is refused.
fn kext_version(text: &str) -> Result<u64> {
    const PLACES: [u64; 3] = [1_000_000_000_000, 100_000_000, 10_000];
    const RELEASE: u64 = 9_000;
    let mut version = RELEASE;
    let mut parts = text.split('.');
    for (place, part) in PLACES.into_iter().zip(parts.by_ref()) {
        let number: u64 = part
            .parse()
            .map_err(|_| refuse!("{text} is not a release kext version", text))?;
        require!(number <= 9_999, "{text} has a part over 9999", text);
        version += number * place;
    }
    require!(parts.next().is_none(), "{text} has over three parts", text);
    Ok(version)
}

fn tagged(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut der = vec![tag];
    if let Ok(length @ 0..0x80) = u8::try_from(contents.len()) {
        der.push(length);
    } else {
        let bytes = contents.len().to_be_bytes();
        let length = minimal(&bytes);
        der.push(0x80 | length.len() as u8);
        der.extend(length);
    }
    der.extend(contents);
    der
}

fn integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let bytes = minimal(&bytes);
    // The high bit is the sign.
    let sign = if bytes[0] & 0x80 != 0 { &[0][..] } else { &[] };
    tagged(INTEGER, &[sign, bytes].concat())
}

/// `bytes` without leading zeros, keeping at least the last.
fn minimal(bytes: &[u8]) -> &[u8] {
    let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    &bytes[zeros.min(bytes.len() - 1)..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_match_oskext() -> Result<()> {
        assert_eq!(kext_version("1.2.3")?, 1_000_200_039_000);
        assert_eq!(kext_version("27")?, 27_000_000_009_000);
        assert!(kext_version("1.2.3.4").is_err());
        assert!(kext_version("1.0d3").is_err());
        assert!(kext_version("10000").is_err());
        Ok(())
    }

    #[test]
    fn der_is_minimal() {
        assert_eq!(integer(1), [2, 1, 1]);
        assert_eq!(integer(0), [2, 1, 0]);
        assert_eq!(integer(0x80), [2, 2, 0, 0x80]);
        let long = tagged(SEQUENCE, &[0; 0x100]);
        assert_eq!(long[..4], [0x30, 0x82, 1, 0]);
        assert_eq!(tagged(SEQUENCE, &[0; 0x7f])[1], 0x7f);
        assert_eq!(tagged(SEQUENCE, &[0; 0x80])[..3], [0x30, 0x81, 0x80]);
    }
}
