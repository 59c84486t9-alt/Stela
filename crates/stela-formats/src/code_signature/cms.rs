//! The CMS signature of a code signature (RFC 5652 `SignedData`, detached,
//! over the slot-0 code directory), verified as AMFI does before it treats
//! code as Apple's: the signer's RSA PKCS#1 v1.5 signature over its signed
//! attributes, the `messageDigest` attribute over the signed code
//! directory, Apple's `CDHashes2` attribute (1.2.840.113635.100.9.2) over
//! any other code directory the kernel chose, and each certificate's
//! signature up a chain whose issuing permission and root are pinned by
//! SHA-256 fingerprint. The certificates travel in the signature itself;
//! validity periods are not checked, as code signing does not expire
//! signed code.
use super::{CS_HASHTYPE_SHA1, CS_HASHTYPE_SHA256, CS_HASHTYPE_SHA384, ber_children, ber_element};
use crate::rsa::{self, Hash, Key};
use alloc::vec::Vec;
use sha2::{Digest as _, Sha384};
use stela_crypto::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Rsa(rsa::Error),
    Element,
    Field,
    DigestAlgorithm,
    SignatureAlgorithm,
    UnusedBits,
    CertificateAlgorithms,
    CertificateKey,
    CertificateIssuer,
    ContentType,
    SignerCount,
    MessageDigest,
    CodeDirectoryHash,
    CodeDirectoryBinding,
    SignerVersion,
    SignerCertificate,
    ChainAnchor,
}

impl From<rsa::Error> for Error {
    fn from(error: rsa::Error) -> Self {
        Self::Rsa(error)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rsa(error) => write!(f, "CMS: {error}"),

            Self::Element => f.write_str("CMS element missing or mistagged"),
            Self::Field => f.write_str("CMS field missing or mistagged"),
            Self::DigestAlgorithm => f.write_str("unsupported CMS digest algorithm"),
            Self::SignatureAlgorithm => f.write_str("unsupported CMS signature algorithm"),
            Self::UnusedBits => f.write_str("BIT STRING with unused bits"),
            Self::CertificateAlgorithms => f.write_str("certificate signature algorithms differ"),
            Self::CertificateKey => f.write_str("certificate key is not RSA"),
            Self::CertificateIssuer => {
                f.write_str("certificate issuer does not name its issuer's subject")
            }
            Self::ContentType => f.write_str("CMS content is not SignedData"),
            Self::SignerCount => f.write_str("CMS has more than one signer"),
            Self::MessageDigest => {
                f.write_str("CMS messageDigest does not match the code directory")
            }
            Self::CodeDirectoryHash => f.write_str("unsupported code directory hash type"),
            Self::CodeDirectoryBinding => {
                f.write_str("CMS CDHashes2 does not bind the chosen code directory")
            }
            Self::SignerVersion => f.write_str("CMS signer version is not 1"),
            Self::SignerCertificate => f.write_str("CMS signer certificate is missing"),
            Self::ChainAnchor => f.write_str("CMS chain lacks a pinned certificate"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Rsa(error) => Some(error),
            _ => None,
        }
    }
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OBJECT_IDENTIFIER: u8 = 0x06;
const CONTEXT_0: u8 = 0xa0;

const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
const CDHASHES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02];
const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const RSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
const RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];

/// The pinned SHA-256 fingerprints of the permission that issues the signing
/// certificate and of the root that issues the permission.
pub(super) struct Anchors {
    pub(super) authority: [u8; 32],
    pub(super) root: [u8; 32],
}

/// The contents of the one element at the start of `bytes`, if it has `tag`.
fn expect(bytes: &[u8], tag: u8) -> Result<&[u8], Error> {
    match ber_element(bytes) {
        Some((found, contents, _)) if found == tag => Ok(contents),
        _ => Err(Error::Element),
    }
}

/// The next child of a constructed element, which must have `tag`.
fn next<'a>(
    children: &mut impl Iterator<Item = (u8, &'a [u8], &'a [u8])>,
    tag: u8,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    match children.next() {
        Some((found, contents, whole)) if found == tag => Ok((contents, whole)),
        _ => Err(Error::Field),
    }
}

/// An `AlgorithmIdentifier`'s OID.
fn algorithm(contents: &[u8]) -> Result<&[u8], Error> {
    expect(contents, OBJECT_IDENTIFIER)
}

fn digest(oid: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(match oid {
        SHA1 => stela_crypto::Sha1::digest(message).to_vec(),
        SHA256 => Sha256::digest(message).to_vec(),
        SHA384 => Sha384::digest(message).to_vec(),
        _ => return Err(Error::DigestAlgorithm),
    })
}

/// The hash an RSA signature algorithm signs with; plain `rsaEncryption`
/// takes the signer's digest algorithm.
fn rsa_hash(signature: &[u8], digest: Option<&[u8]>) -> Result<Hash, Error> {
    match (signature, digest) {
        (RSA_SHA1, _) | (RSA_ENCRYPTION, Some(SHA1)) => Ok(Hash::Sha1),
        (RSA_SHA256, _) | (RSA_ENCRYPTION, Some(SHA256)) => Ok(Hash::Sha256),
        (RSA_SHA384, _) | (RSA_ENCRYPTION, Some(SHA384)) => Ok(Hash::Sha384),
        _ => Err(Error::SignatureAlgorithm),
    }
}

/// One X.509 certificate's parts (RFC 5280 §4.1).
struct Certificate<'a> {
    whole: &'a [u8],
    tbs: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    /// The `RSAPublicKey` inside the subject public key's BIT STRING.
    key: &'a [u8],
    algorithm: &'a [u8],
    signature: &'a [u8],
}

/// A BIT STRING's bytes, which must have no unused bits.
fn bits(contents: &[u8]) -> Result<&[u8], Error> {
    match contents.split_first() {
        Some((0, bytes)) => Ok(bytes),
        _ => Err(Error::UnusedBits),
    }
}

fn certificate(whole: &[u8]) -> Result<Certificate<'_>, Error> {
    let mut parts = ber_children(expect(whole, SEQUENCE)?);
    let (tbs_contents, tbs) = next(&mut parts, SEQUENCE)?;
    let (signature_algorithm, outer_algorithm) = next(&mut parts, SEQUENCE)?;
    let (signature, _) = next(&mut parts, BIT_STRING)?;
    let mut fields = ber_children(tbs_contents).peekable();
    if fields.peek().is_some_and(|(tag, ..)| *tag == CONTEXT_0) {
        fields.next();
    }
    let (serial, _) = next(&mut fields, INTEGER)?;
    if next(&mut fields, SEQUENCE)?.1 != outer_algorithm {
        return Err(Error::CertificateAlgorithms);
    }
    let (_, issuer) = next(&mut fields, SEQUENCE)?;
    next(&mut fields, SEQUENCE)?;
    let (_, subject) = next(&mut fields, SEQUENCE)?;
    let (public_key_info, _) = next(&mut fields, SEQUENCE)?;
    let mut public_key = ber_children(public_key_info);
    let (key_algorithm, _) = next(&mut public_key, SEQUENCE)?;
    if algorithm(key_algorithm)? != RSA_ENCRYPTION {
        return Err(Error::CertificateKey);
    }
    let (key, _) = next(&mut public_key, BIT_STRING)?;
    Ok(Certificate {
        whole,
        tbs,
        serial,
        issuer,
        subject,
        key: bits(key)?,
        algorithm: algorithm(signature_algorithm)?,
        signature: bits(signature)?,
    })
}

impl Certificate<'_> {
    fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.whole).into()
    }

    /// Whether `issuer` signed this certificate.
    fn issued_by(&self, issuer: &Certificate<'_>) -> Result<(), Error> {
        if self.issuer != issuer.subject {
            return Err(Error::CertificateIssuer);
        }
        Key::parse(issuer.key)?
            .verify(self.tbs, self.signature, rsa_hash(self.algorithm, None)?)
            .map_err(Error::Rsa)
    }
}

/// The parts of `SignedData` verification reads.
struct SignedData<'a> {
    certificates: Vec<&'a [u8]>,
    signer: &'a [u8],
}

fn signed_data(cms: &[u8]) -> Result<SignedData<'_>, Error> {
    let mut info = ber_children(expect(cms, SEQUENCE)?);
    if next(&mut info, OBJECT_IDENTIFIER)?.0 != SIGNED_DATA {
        return Err(Error::ContentType);
    }
    let (explicit, _) = next(&mut info, CONTEXT_0)?;
    let mut fields = ber_children(expect(explicit, SEQUENCE)?);
    next(&mut fields, INTEGER)?;
    next(&mut fields, SET)?;
    next(&mut fields, SEQUENCE)?;
    let (certificates, _) = next(&mut fields, CONTEXT_0)?;
    let mut rest = fields.skip_while(|(tag, ..)| *tag != SET);
    let (signers, _) = next(&mut rest, SET)?;
    let mut signers = ber_children(signers);
    let (signer, _) = next(&mut signers, SEQUENCE)?;
    if signers.next().is_some() {
        return Err(Error::SignerCount);
    }
    Ok(SignedData {
        certificates: ber_children(certificates)
            .map(|(_, _, whole)| whole)
            .collect(),
        signer,
    })
}

/// The certificates a CMS signature carries, in order.
#[cfg(test)]
pub(super) fn certificates(cms: &[u8]) -> Vec<&[u8]> {
    signed_data(cms).map_or_else(|_| Vec::new(), |data| data.certificates)
}

/// The values of the signed attribute `oid`.
fn attribute_values<'a>(
    attributes: &'a [u8],
    oid: &'a [u8],
) -> impl Iterator<Item = (u8, &'a [u8], &'a [u8])> + 'a {
    ber_children(attributes)
        .filter_map(move |(tag, attribute, _)| {
            let mut parts = ber_children(attribute);
            (tag == SEQUENCE && next(&mut parts, OBJECT_IDENTIFIER).ok()?.0 == oid)
                .then(|| next(&mut parts, SET).ok())
                .flatten()
        })
        .flat_map(|(values, _)| ber_children(values))
}

/// The CDHashes2 digest algorithm for a code directory hash type.
fn cdhash_algorithm(hash_type: u8) -> Option<&'static [u8]> {
    match hash_type {
        CS_HASHTYPE_SHA1 => Some(SHA1),
        CS_HASHTYPE_SHA256 => Some(SHA256),
        CS_HASHTYPE_SHA384 => Some(SHA384),
        _ => None,
    }
}

/// Whether the signed attributes bind `signed`, the content, by
/// `messageDigest` under `digest_algorithm`, and `chosen` (the code
/// directory the kernel uses, of `hash_type`) as the content itself or by a
/// `CDHashes2` entry.
fn binds(
    attributes: &[u8],
    digest_algorithm: &[u8],
    signed: &[u8],
    chosen: &[u8],
    hash_type: u8,
) -> Result<(), Error> {
    let mut digests = attribute_values(attributes, MESSAGE_DIGEST);
    let expected = digest(digest_algorithm, signed)?;
    match (digests.next(), digests.next()) {
        (Some((OCTET_STRING, found, _)), None) if found == expected.as_slice() => {}
        _ => return Err(Error::MessageDigest),
    }
    if chosen == signed {
        return Ok(());
    }
    let algorithm = cdhash_algorithm(hash_type).ok_or(Error::CodeDirectoryHash)?;
    let wanted = digest(algorithm, chosen)?;
    let bound = attribute_values(attributes, CDHASHES2).any(|(tag, entry, _)| {
        let mut parts = ber_children(entry);
        tag == SEQUENCE
            && next(&mut parts, OBJECT_IDENTIFIER).is_ok_and(|(oid, _)| oid == algorithm)
            && next(&mut parts, OCTET_STRING).is_ok_and(|(hash, _)| hash == wanted.as_slice())
    });
    if bound {
        Ok(())
    } else {
        Err(Error::CodeDirectoryBinding)
    }
}

/// Verify `cms` over `signed` (the slot-0 code directory), binding
/// `chosen`, signed by a certificate `anchors.authority` issued, itself
/// issued by `anchors.root`.
pub(super) fn verify(
    cms: &[u8],
    signed: &[u8],
    chosen: &[u8],
    hash_type: u8,
    anchors: &Anchors,
) -> Result<(), Error> {
    let data = signed_data(cms)?;
    let certificates = data
        .certificates
        .iter()
        .map(|whole| certificate(whole))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fields = ber_children(data.signer);
    if next(&mut fields, INTEGER)?.0 != [1] {
        return Err(Error::SignerVersion);
    }
    // `sid`: `issuerAndSerialNumber`, as version 1 requires.
    let (sid, _) = next(&mut fields, SEQUENCE)?;
    let mut sid = ber_children(sid);
    let (_, sid_issuer) = next(&mut sid, SEQUENCE)?;
    let (sid_serial, _) = next(&mut sid, INTEGER)?;
    let (digest_algorithm, _) = next(&mut fields, SEQUENCE)?;
    let digest_algorithm = algorithm(digest_algorithm)?;
    let (attributes, signed_attributes) = next(&mut fields, CONTEXT_0)?;
    let (signature_algorithm, _) = next(&mut fields, SEQUENCE)?;
    let (signature, _) = next(&mut fields, OCTET_STRING)?;
    binds(attributes, digest_algorithm, signed, chosen, hash_type)?;
    let leaf = certificates
        .iter()
        .find(|certificate| certificate.issuer == sid_issuer && certificate.serial == sid_serial)
        .ok_or(Error::SignerCertificate)?;
    // The signature covers the attributes' DER with the SET OF tag.
    let mut message = signed_attributes.to_vec();
    message[0] = SET;
    Key::parse(leaf.key)?.verify(
        &message,
        signature,
        rsa_hash(algorithm(signature_algorithm)?, Some(digest_algorithm))?,
    )?;
    let issuer_of = |child: &Certificate<'_>, fingerprint: &[u8; 32]| {
        certificates
            .iter()
            .find(|certificate| certificate.fingerprint() == *fingerprint)
            .ok_or(Error::ChainAnchor)
            .and_then(|issuer| child.issued_by(issuer).map(|()| issuer))
    };
    let authority = issuer_of(leaf, &anchors.authority)?;
    issuer_of(authority, &anchors.root)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated solely for Stela with LibreSSL: a synthetic root, an
    // permission it signed with SHA-1 and a leaf the permission signed with
    // SHA-1, and a detached SHA-256 CMS signature over a synthetic code
    // directory. Public certificates and the signature only; no Apple data
    // and no private key.
    const CMS: &str = concat!(
        "30820b2d06092a864886f70d010702a0820b1e30820b1a020101310d300b0609608648016503040201300b06",
        "092a864886f70d010701a082091b308202e4308201cc020900f5ee5662de7714a3300d06092a864886f70d01",
        "010b0500303431183016060355040a0c0f5374656c612053796e7468657469633118301606035504030c0f53",
        "74656c61205465737420526f6f74301e170d3236313032303030303535325a170d3336313031373030303535",
        "325a303431183016060355040a0c0f5374656c612053796e7468657469633118301606035504030c0f537465",
        "6c61205465737420526f6f7430820122300d06092a864886f70d01010105000382010f003082010a02820101",
        "00ec2572af4ddcd68215468fea00452afd7986f7754321ddef65254f65f03fa9241ef6f09b34490d2da07300",
        "47041f5d95cf55389942a62cddb0e876827a793417a55e7823a5092523efe82de160bc7c04b335700a959290",
        "ae12fa110c07c31ff8a5c0529b870a14d2b8f6fae483b4d5bf7daf6b5dbdaf54b11c208f77948652d83ca012",
        "65b25e559e0c8d5b4436427891eedd44f78d74d1acbc204dbe5238d0898c1841e88b9084a4aa8be4fcebf940",
        "4b0d03311d645ab2633d7d8938a15379022ea259746afecad94632ca07da13f315cb7c724f154cc50acedc8c",
        "6523dc7b14adca1c359d89e9a287e3b5e3fc319cdcf44d93a402f52fb98d15e3a57ddc3e0f0203010001300d",
        "06092a864886f70d01010b05000382010100246ea75d81c14979286e086ef24ae63d2bfc7a7f35438b89a8b4",
        "d33a0a919d8b522b18ef7d6d9b0b2ac162d87e002852d6e7495a893e316af36d57af2976f072c76245bbd08b",
        "39026edced9d925031d401ad3adf97271a1728839c64034b820d4b7bbd32f1b5131b1ca60fd4f7bfe619c6fb",
        "57df24c7cb38353cdde220d477b40cc6436a366690ab8bc8e1d974f198c06c03af6b5c6e894424d634d6f8d3",
        "73e7c3e5ca6545c6b3f876282469ee9db8bfa48889835ccdb850a46c62284ad3de702520ca198488bb10cdc1",
        "f9591169521290f07db2e3aa7383bc40f480ebf2a20416daf4edafffa050c6aacd86df278265651dfd69fb84",
        "45fd9d1e99b60cfeb64030820311308201f9a003020102020121300d06092a864886f70d0101050500303431",
        "183016060355040a0c0f5374656c612053796e7468657469633118301606035504030c0f5374656c61205465",
        "737420526f6f74301e170d3236313032303030303535325a170d3336313031373030303535325a303f311830",
        "16060355040a0c0f5374656c612053796e7468657469633123302106035504030c1a5374656c612054657374",
        "20436f6465205369676e696e6720434130820122300d06092a864886f70d01010105000382010f003082010a",
        "0282010100b3d05ff475dcada824f33578d02dd5e98bd345b802de9d9af69d0a1236b09d8cfc7c5c740713a4",
        "f99abe4f496d8737e8d46184c2086ffefd859d71e04b2662ef99ea0ecc258fed0a3ce945558a180460845317",
        "bec6f54ba9237450fcb235ec8867bdaee3240d3ef242fd4751c5142a294ce7c1fcde898f3091397c1bf42ea5",
        "74e56d78f40f923f6be1815962fc69fe8c18d84f40188053fc507440cab4c7e258420564113b41b4167c3c6d",
        "cea4bc2f029c6f36fc4d0a2e245ddcb3dda3310ea41cca759de7d796d74710e81514d4fe7eacc40d766853b0",
        "7390e91c331c77248955dd7aec7fd325f9492551bcd511048b22dde77fdb1a5564a88639158ae56b99020301",
        "0001a3233021300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300d06092a",
        "864886f70d01010505000382010100e03f2dd179fc47358ec8866c2a09206479ee1b84ee31bf3ebcfc90824b",
        "7c0a9faf2f3a0f9186a379a6b8f7407c69a84b373ac05c7e36da395806eb22f3f5573cb9f6522c2363475e70",
        "f736f1d799507e80e8089a646bb4af69797370a19d6402a35dd258f34d809055907ee42ad749d3dd525c9a10",
        "22cdccf6212f55eb9a152aff28755fe5cc2ca7008c1e1668a45bb242a120cbbc709a66fb2e5918c30663bed3",
        "6c61f325844997ab75cf6de0e47d1aec8588d38c7d66614e5af52b411ee6621b1eaeb45ada07a480e9ad73d2",
        "a77618abeee045846b4eaa0d8b59f4d008ba79fec584dccd4129a19d30b10f86e1ed82ca77f3968dd60f842d",
        "0d99bb0e7472d13082031a30820202a003020102020107300d06092a864886f70d0101050500303f31183016",
        "060355040a0c0f5374656c612053796e7468657469633123302106035504030c1a5374656c61205465737420",
        "436f6465205369676e696e67204341301e170d3236313032303030303535325a170d33363130313730303035",
        "35325a304031183016060355040a0c0f5374656c612053796e7468657469633124302206035504030c1b5374",
        "656c61205465737420536f667477617265205369676e696e6730820122300d06092a864886f70d0101010500",
        "0382010f003082010a0282010100c2e2a6916bf7a9814646e1bcddf8d20113f19f34bbae67687f5b2ca43a6a",
        "f9ab5c7e58b3db3d19795e6e01b95a967131f79cc6e67ebe7835eec1c1760ac2ff18ac5f385f436aa970d660",
        "ecef6a9be7e9a7c6128f746bd9d146b9907fd85cd26b8e86f2071f73555d231c4a98d1feae31ba7ffa3b4ad2",
        "604dd5c68b026aeb1d7c7f7ccd472108bfa158c2f032eaef4532fdf980c29b87353d8a4fe0458f58230a89a5",
        "d5b48ceef6e08b6e64d74794a31d59e7e1f35a8fa131eb4abdca39bd83df43a0b19cde320005ac0cc9fb98f5",
        "6e200bc0de0ed958898fb34961c5acb62d95a5b017b1be41e458fdc9e05197af24dd83b7ef9819920c243b61",
        "a8405b3a08790203010001a320301e300c0603551d130101ff04023000300e0603551d0f0101ff0404030207",
        "80300d06092a864886f70d010105050003820101002bf1a68fb3b70088207bb975c3b17f06f682e920e41d45",
        "6e91d44a7c86f7b8f56e1da29461b71f2d732551d98f26f98825e87612073b18fee35d20242dd3a858b73fb6",
        "ec9331f4ff71aa6666630e9c95b48bc9bb270d5248f9874c460323a0a24a45e31eeb992dad793beceab30329",
        "c03af444c96d19a9d29a2dc123aea0483b9eb50b01ba5b6f7386819d742174a1b4283aed22d694e3f066b9c1",
        "18a07da967361698e4466d46d048221cf1c0a40c0d0aed4aabb63b67a565faf8ade89104bcf21d8d4049e120",
        "e81f89f79f2ede7f16d29beef7457b2372c6d2c80a96423091bf30917fac61a7fb78e413f8f486264427bf89",
        "99d0e079707dd4a5920466115f318201d8308201d40201013044303f31183016060355040a0c0f5374656c61",
        "2053796e7468657469633123302106035504030c1a5374656c61205465737420436f6465205369676e696e67",
        "204341020107300b0609608648016503040201a069301806092a864886f70d010903310b06092a864886f70d",
        "010701301c06092a864886f70d010905310f170d3236313032303030303535325a302f06092a864886f70d01",
        "090431220420db52c66f9a03bd5ddfd13d4ef4e24ce8face2ed6ea3fb16679538805c507f1e6300d06092a86",
        "4886f70d0101010500048201002d13067284fd72618db0d4f2478cd9da25b240b3c5211cbdd997e56c9751bd",
        "2f412f382efa1ddff3cf7ccbabdeabc812af5716ba77c76927084778529c418543a036ed4f1bb1fe1dbc259a",
        "8256af9711836e64dd52c7e681dfc7c73bf6cd80447e5d50538cdd338ba2c6494bc5d31e73b45e837c4b4366",
        "724451412c41e0e1185d30ef72833659793f1abdd67b1923d5f623c563af8fad5f44a9d2ba159414931a8847",
        "67c5ba27e01ec5918d6df11c7bc7b3a1f7624439942989d1a37b3fa364ca153072bf07eb2855d7456606c5c0",
        "6108e13874ee194c8920c67ff622d93dffae2dd8dbb71d9d538e8c3e32a327f9475ce294847ef067bc7c08fe",
        "4cfbbfa509",
    );
    const SIGNED: &str =
        "fade0c020000003073796e74686574696320636f6465206469726563746f727920666f72205374656c61";
    const ANCHORS: Anchors = Anchors {
        authority: [
            0x73, 0x3d, 0x10, 0x7b, 0x50, 0xb7, 0xf4, 0x93, 0x28, 0x42, 0x3e, 0xfb, 0x5c, 0x1c,
            0xdd, 0xb8, 0x43, 0xe1, 0x5e, 0x00, 0xe1, 0xe9, 0x75, 0x8d, 0xfd, 0x55, 0xc0, 0x23,
            0xb6, 0xb7, 0x2d, 0x0f,
        ],
        root: [
            0x0e, 0xac, 0x4f, 0xaf, 0xac, 0xec, 0x71, 0xc3, 0xe3, 0x17, 0xbc, 0xbd, 0x75, 0xe7,
            0x68, 0xb6, 0x44, 0x58, 0xa5, 0xd6, 0x3a, 0x58, 0xb0, 0x0a, 0x8e, 0x60, 0xaf, 0xdb,
            0xa1, 0x55, 0x3d, 0x05,
        ],
    };

    fn fixture() -> (Vec<u8>, Vec<u8>) {
        (hex::decode(CMS).unwrap(), hex::decode(SIGNED).unwrap())
    }

    #[test]
    fn a_signature_verifies_up_its_pinned_chain() {
        let (cms, signed) = fixture();
        assert_eq!(
            verify(&cms, &signed, &signed, CS_HASHTYPE_SHA256, &ANCHORS),
            Ok(())
        );
        // Other anchors, such as Apple's, do not admit it.
        let swapped = Anchors {
            authority: ANCHORS.root,
            root: ANCHORS.authority,
        };
        assert!(verify(&cms, &signed, &signed, CS_HASHTYPE_SHA256, &swapped).is_err());
        let mut other = signed.clone();
        other[8] ^= 1;
        assert!(verify(&cms, &other, &other, CS_HASHTYPE_SHA256, &ANCHORS).is_err());
        // A code directory other than the signed one needs CDHashes2.
        assert!(verify(&cms, &signed, &other, CS_HASHTYPE_SHA256, &ANCHORS).is_err());
    }

    #[test]
    fn any_altered_byte_fails_verification() {
        let (cms, signed) = fixture();
        // From the certificates on: the content description before them is
        // not signed.
        for at in (54..cms.len()).step_by(7) {
            let mut altered = cms.clone();
            altered[at] ^= 0x10;
            assert!(
                verify(&altered, &signed, &signed, CS_HASHTYPE_SHA256, &ANCHORS).is_err(),
                "byte {at}"
            );
        }
        let truncated = &cms[..cms.len() - 1];
        assert!(verify(truncated, &signed, &signed, CS_HASHTYPE_SHA256, &ANCHORS).is_err());
    }

    /// A DER element with a definite length below 256 bytes.
    fn element(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if contents.len() >= 0x80 {
            out.push(0x81);
        }
        out.push(contents.len() as u8);
        out.extend(contents);
        out
    }

    #[test]
    fn cdhashes2_binds_another_code_directory() {
        let signed = b"slot-0 code directory".as_slice();
        let chosen = b"alternate code directory".as_slice();
        let attribute = |oid: &[u8], value: Vec<u8>| {
            element(
                SEQUENCE,
                &[element(OBJECT_IDENTIFIER, oid), element(SET, &value)].concat(),
            )
        };
        let entry = |algorithm: &[u8], hash: &[u8]| {
            element(
                SEQUENCE,
                &[
                    element(OBJECT_IDENTIFIER, algorithm),
                    element(OCTET_STRING, hash),
                ]
                .concat(),
            )
        };
        let digest_of = element(OCTET_STRING, &Sha256::digest(signed));
        let attributes = |entries: Vec<u8>| {
            [
                attribute(MESSAGE_DIGEST, digest_of.clone()),
                attribute(CDHASHES2, entries),
            ]
            .concat()
        };
        let sha1 = entry(SHA1, &sha1::Sha1::digest(signed));
        let sha256 = entry(SHA256, &Sha256::digest(chosen));
        let both = attributes([sha1.clone(), sha256].concat());
        assert_eq!(
            binds(&both, SHA256, signed, chosen, CS_HASHTYPE_SHA256),
            Ok(())
        );
        assert_eq!(
            binds(&both, SHA256, signed, signed, CS_HASHTYPE_SHA256),
            Ok(())
        );
        let only_sha1 = attributes(sha1);
        assert!(binds(&only_sha1, SHA256, signed, chosen, CS_HASHTYPE_SHA256).is_err());
        assert!(binds(&both, SHA256, chosen, chosen, CS_HASHTYPE_SHA256).is_err());
        assert!(binds(&both, SHA1, signed, chosen, CS_HASHTYPE_SHA256).is_err());
    }
}
