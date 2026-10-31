//! A LocalPolicy: the Image4 file that names what a volume group may boot,
//! written beside each OS on an Apple-silicon Mac.
//!
//! **File.** libbootpolicy writes the SEP's bytes to disk unchecked
//! (`bootpolicy_create_local_policy_ex2` -> `write_local_policy_with_nonce_hash`
//! 26A434 B 0x1e24..0x1f50). It is an `IMG4` of [`PAYLOAD`], the same bare
//! policy IM4P an Apple-signed recoveryOS policy covers, and an `IM4M`
//! whose `MANP` holds Apple's property names:
//! - `vuid` the volume group UUID, `nsih` the SHA-384 of the OS manifest that
//!   boots next, `lpnh` the SHA-384 of the local policy nonce;
//! - `spih` the SHA-384 of the splat (Cryptex1) manifest, when there is one,
//!   and `prot` the SHA-384 of the paired recoveryOS policy file, on a macOS
//!   policy;
//! - `smb0` and `smb1` for Reduced and Permissive Security;
//! - `smb2`, `sip0`, `auxp`, `auxi` and `auxr` for third-party kexts, which
//!   Stela grants together as [`Kexts`].
//!
//! **Trust.** The manifest's signature is Stela's: ECDSA P-384 with SHA-384
//! over the DER `SET` containing `MANB`, which is what an Image4 signature
//! covers, under a per-machine key only the SEP holds. There is no
//! certificate chain, because Apple's roots can't name that key. The
//! verifier is Stela's boot, which plays iBoot, with the machine's public
//! key, so it needs no SEP secret. Nothing here is a claim to reproduce
//! Apple's key or `prot` measurement.
use crate::der::{self, BOOLEAN, Cursor, Element, INTEGER, OCTET_STRING, SEQUENCE, SET};
use crate::img4;
use alloc::vec::Vec;
use p384::ecdsa::{DerSignature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha384};

pub const DIGEST_BYTES: usize = 48;
pub const UUID_BYTES: usize = 16;

/// The bare policy IM4P a policy's `lpol` digest covers (idevicerestore
/// `lpol_file`): type `lpol`, version `1.0`, a one-byte zero payload.
pub const PAYLOAD: [u8; 22] = [
    0x30, 0x14, 0x16, 0x04, 0x49, 0x4d, 0x34, 0x50, 0x16, 0x04, 0x6c, 0x70, 0x6f, 0x6c, 0x16, 0x03,
    0x31, 0x2e, 0x30, 0x04, 0x01, 0x00,
];

/// The `sip0` of a kext grant, and the only one a policy can carry:
/// `CSR_ALLOW_UNTRUSTED_KEXTS` and `CSR_ALLOW_UNAPPROVED_KEXTS`, which let a
/// kext without an Apple certificate load. Nothing else in SIP is relaxed.
pub const KEXT_SIP_BITS: u16 = 1 | 1 << 9;

/// Third-party kexts a policy admits: `smb2`, `sip0` of [`KEXT_SIP_BITS`] and
/// the digests of what admits them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kexts {
    /// `auxp`: SHA-384 of the approved kexts' list.
    pub approved: [u8; DIGEST_BYTES],
    /// `auxi`: SHA-384 of the auxiliary kernel collection.
    pub collection: [u8; DIGEST_BYTES],
    /// `auxr`: SHA-384 of the collection's receipt.
    pub receipt: [u8; DIGEST_BYTES],
}

/// The boot security a policy grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Full,
    Reduced,
    Permissive,
}

/// What a policy says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub volume_group: [u8; UUID_BYTES],
    pub next_stage: [u8; DIGEST_BYTES],
    pub nonce: [u8; DIGEST_BYTES],
    pub splat: Option<[u8; DIGEST_BYTES]>,
    pub paired: Option<[u8; DIGEST_BYTES]>,
    pub security: Security,
    pub kexts: Option<Kexts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Der(der::Error),
    Image4(img4::Img4Error),
    /// The file is not a LocalPolicy of this shape.
    Malformed(&'static str),
    /// The signature is not this machine's.
    Signature,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Der(error) => write!(f, "LocalPolicy: {error}"),
            Self::Image4(error) => write!(f, "LocalPolicy: {error}"),
            Self::Malformed(what) => write!(f, "malformed LocalPolicy: {what}"),
            Self::Signature => f.write_str("LocalPolicy signature is not this machine's"),
        }
    }
}

impl core::error::Error for Error {}

impl From<der::Error> for Error {
    fn from(error: der::Error) -> Self {
        Self::Der(error)
    }
}

impl From<img4::Img4Error> for Error {
    fn from(error: img4::Img4Error) -> Self {
        Self::Image4(error)
    }
}

fn property(name: [u8; 4], tag: u8, value: &[u8]) -> Vec<u8> {
    der::named(name, &der::encode(tag, value))
}

impl Policy {
    /// The DER `SET` containing `MANB`, which the signature covers.
    /// Properties and objects go in tag order, as a DER `SET` does.
    pub fn signed(&self) -> Vec<u8> {
        let mut properties = Vec::new();
        if let Some(kexts) = &self.kexts {
            properties.extend(property(*b"auxi", OCTET_STRING, &kexts.collection));
            properties.extend(property(*b"auxp", OCTET_STRING, &kexts.approved));
            properties.extend(property(*b"auxr", OCTET_STRING, &kexts.receipt));
        }
        properties.extend(property(*b"lpnh", OCTET_STRING, &self.nonce));
        properties.extend(property(*b"nsih", OCTET_STRING, &self.next_stage));
        if let Some(paired) = &self.paired {
            properties.extend(property(*b"prot", OCTET_STRING, paired));
        }
        if self.kexts.is_some() {
            properties.extend(property(*b"sip0", INTEGER, &KEXT_SIP_BITS.to_be_bytes()));
        }
        if self.security != Security::Full {
            properties.extend(property(*b"smb0", BOOLEAN, &[0xff]));
        }
        if self.security == Security::Permissive {
            properties.extend(property(*b"smb1", BOOLEAN, &[0xff]));
        }
        if self.kexts.is_some() {
            properties.extend(property(*b"smb2", BOOLEAN, &[0xff]));
        }
        if let Some(splat) = &self.splat {
            properties.extend(property(*b"spih", OCTET_STRING, splat));
        }
        properties.extend(property(*b"vuid", OCTET_STRING, &self.volume_group));
        let digest = property(*b"DGST", OCTET_STRING, &Sha384::digest(PAYLOAD));
        let mut objects = der::named(*b"MANP", &der::encode(SET, &properties));
        objects.extend(der::named(*b"lpol", &der::encode(SET, &digest)));
        der::encode(SET, &der::named(*b"MANB", &der::encode(SET, &objects)))
    }

    /// The boolean property `tag`: absent, as here, is how a policy says no.
    pub fn boolean_tag(&self, tag: [u8; 4]) -> Option<bool> {
        match &tag {
            b"smb0" => self.security != Security::Full,
            b"smb1" => self.security == Security::Permissive,
            b"smb2" => self.kexts.is_some(),
            _ => false,
        }
        .then_some(true)
    }

    /// The integer property `tag`.
    pub fn integer_tag(&self, tag: [u8; 4]) -> Option<u64> {
        (tag == *b"sip0" && self.kexts.is_some()).then_some(u64::from(KEXT_SIP_BITS))
    }

    /// The digest property `tag`.
    pub fn digest_tag(&self, tag: [u8; 4]) -> Option<&[u8; DIGEST_BYTES]> {
        match &tag {
            b"auxi" => self.kexts.as_ref().map(|kexts| &kexts.collection),
            b"auxp" => self.kexts.as_ref().map(|kexts| &kexts.approved),
            b"auxr" => self.kexts.as_ref().map(|kexts| &kexts.receipt),
            b"lpnh" => Some(&self.nonce),
            b"nsih" => Some(&self.next_stage),
            b"prot" => self.paired.as_ref(),
            b"spih" => self.splat.as_ref(),
            _ => None,
        }
    }

    /// The policy file, given the DER signature over [`Self::signed`].
    pub fn file(&self, signature: &[u8]) -> Vec<u8> {
        let mut manifest = der::encode(der::IA5_STRING, b"IM4M");
        manifest.extend(der::encode(INTEGER, &[0]));
        manifest.extend(self.signed());
        manifest.extend(der::encode(OCTET_STRING, signature));
        manifest.extend(der::encode(SEQUENCE, &[]));
        img4::compose(&PAYLOAD, &der::encode(SEQUENCE, &manifest))
    }
}

/// One named entry: its name and value elements, whose tag must repeat its
/// name.
fn entry<'a>(element: Element<'a>) -> Result<([u8; 4], Cursor<'a>), Error> {
    if element.class != 3 || !element.constructed {
        return Err(Error::Malformed("an entry is not a private tag"));
    }
    let mut body = der::sequence(element.value)?;
    let name: [u8; 4] = body
        .take(22)?
        .value
        .try_into()
        .map_err(|_| Error::Malformed("an entry name is not four characters"))?;
    if u32::from_be_bytes(name) != element.tag {
        return Err(Error::Malformed("an entry's tag is not its name"));
    }
    Ok((name, body))
}

/// The one object of `set`, which must be named `name`.
fn only<'a>(set: Element<'a>, name: [u8; 4]) -> Result<Cursor<'a>, Error> {
    let mut objects = Cursor(set.value);
    let (found, body) = entry(objects.next_element()?)?;
    objects.end()?;
    if found != name {
        return Err(Error::Malformed("an unexpected object"));
    }
    Ok(body)
}

fn digest(body: &mut Cursor<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
    body.take(4)?
        .value
        .try_into()
        .map_err(|_| Error::Malformed("a digest is not SHA-384"))
}

fn flag(body: &mut Cursor<'_>) -> Result<(), Error> {
    if body.take(1)?.value != [0xff] {
        return Err(Error::Malformed("a security property is not true"));
    }
    Ok(())
}

/// The properties of `signed`, the DER `SET` containing `MANB`.
fn parse(signed: Element<'_>) -> Result<Policy, Error> {
    let mut manb = only(signed, *b"MANB")?;
    let objects = manb.take(17)?;
    manb.end()?;
    let mut objects = Cursor(objects.value);
    let (name, mut body) = entry(objects.next_element()?)?;
    if name != *b"MANP" {
        return Err(Error::Malformed("no MANP"));
    }
    let properties = body.take(17)?;
    body.end()?;
    let (name, mut body) = entry(objects.next_element()?)?;
    objects.end()?;
    if name != *b"lpol" {
        return Err(Error::Malformed("no lpol object"));
    }
    let digests = body.take(17)?;
    body.end()?;
    let mut dgst = only(digests, *b"DGST")?;
    if digest(&mut dgst)?[..] != Sha384::digest(PAYLOAD)[..] {
        return Err(Error::Malformed("the lpol digest is not the bare policy's"));
    }
    dgst.end()?;
    let mut policy = Policy {
        volume_group: [0; UUID_BYTES],
        next_stage: [0; DIGEST_BYTES],
        nonce: [0; DIGEST_BYTES],
        splat: None,
        paired: None,
        security: Security::Full,
        kexts: None,
    };
    let (mut volume, mut next_stage, mut nonce) = (false, false, false);
    let (mut approved, mut collection, mut receipt) = (None, None, None);
    let (mut relaxed, mut admitted) = (false, false);
    let mut properties = Cursor(properties.value);
    while !properties.0.is_empty() {
        let (name, mut body) = entry(properties.next_element()?)?;
        match &name {
            b"auxi" => collection = Some(digest(&mut body)?),
            b"auxp" => approved = Some(digest(&mut body)?),
            b"auxr" => receipt = Some(digest(&mut body)?),
            b"lpnh" => (policy.nonce, nonce) = (digest(&mut body)?, true),
            b"nsih" => (policy.next_stage, next_stage) = (digest(&mut body)?, true),
            b"prot" => policy.paired = Some(digest(&mut body)?),
            b"sip0" => {
                if body.take(2)?.value != KEXT_SIP_BITS.to_be_bytes() {
                    return Err(Error::Malformed("sip0 is not the kext flags"));
                }
                relaxed = true;
            }
            b"spih" => policy.splat = Some(digest(&mut body)?),
            b"smb0" => {
                flag(&mut body)?;
                policy.security = Security::Reduced;
            }
            b"smb1" => {
                flag(&mut body)?;
                policy.security = Security::Permissive;
            }
            b"smb2" => {
                flag(&mut body)?;
                admitted = true;
            }
            b"vuid" => {
                policy.volume_group = body
                    .take(4)?
                    .value
                    .try_into()
                    .map_err(|_| Error::Malformed("vuid is not a UUID"))?;
                volume = true;
            }
            _ => return Err(Error::Malformed("an unknown property")),
        }
        body.end()?;
    }
    if !(volume && next_stage && nonce) {
        return Err(Error::Malformed("a required property is absent"));
    }
    policy.kexts = match (approved, collection, receipt, relaxed, admitted) {
        (None, None, None, false, false) => None,
        (Some(approved), Some(collection), Some(receipt), true, true) => Some(Kexts {
            approved,
            collection,
            receipt,
        }),
        _ => return Err(Error::Malformed("a partial kext grant")),
    };
    Ok(policy)
}

/// What the policy `file` says, once its signature proves `key` signed it.
pub fn verify(file: &[u8], key: &VerifyingKey) -> Result<Policy, Error> {
    let parts = img4::parse(file)?;
    if parts.payload != PAYLOAD || parts.restore_info.is_some() {
        return Err(Error::Malformed("not the bare policy payload"));
    }
    let manifest = parts.manifest.ok_or(Error::Malformed("no manifest"))?;
    let mut manifest = der::sequence(manifest)?;
    if manifest.take(22)?.value != b"IM4M" || manifest.take(2)?.value != [0] {
        return Err(Error::Malformed("not an IM4M version 0"));
    }
    let signed = manifest.take(17)?;
    let signature = manifest.take(4)?.value;
    if !manifest.take(16)?.value.is_empty() {
        return Err(Error::Malformed("a certificate chain"));
    }
    manifest.end()?;
    let signature = DerSignature::try_from(signature).map_err(|_| Error::Signature)?;
    key.verify(signed.encoded, &signature)
        .map_err(|_| Error::Signature)?;
    parse(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use p384::ecdsa::{SigningKey, signature::Signer};

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 48]).unwrap()
    }

    fn sign(policy: &Policy, key: &SigningKey) -> Vec<u8> {
        let signature: DerSignature = key.sign(&policy.signed());
        policy.file(signature.as_bytes())
    }

    fn policy() -> Policy {
        Policy {
            volume_group: [1; UUID_BYTES],
            next_stage: [2; DIGEST_BYTES],
            nonce: [3; DIGEST_BYTES],
            splat: Some([4; DIGEST_BYTES]),
            paired: Some([5; DIGEST_BYTES]),
            security: Security::Permissive,
            kexts: None,
        }
    }

    fn kexts() -> Kexts {
        Kexts {
            approved: [6; DIGEST_BYTES],
            collection: [7; DIGEST_BYTES],
            receipt: [8; DIGEST_BYTES],
        }
    }

    #[test]
    fn a_kext_grant_reads_back_with_the_kext_flags_alone() {
        let granted = Policy {
            kexts: Some(kexts()),
            ..policy()
        };
        let file = sign(&granted, &key(1));
        assert_eq!(verify(&file, key(1).verifying_key()), Ok(granted.clone()));
        assert_eq!(granted.boolean_tag(*b"smb2"), Some(true));
        assert_eq!(granted.integer_tag(*b"sip0"), Some(0x201));
        assert_eq!(granted.digest_tag(*b"auxi"), Some(&[7; DIGEST_BYTES]));
        assert_eq!(granted.digest_tag(*b"auxp"), Some(&[6; DIGEST_BYTES]));
        assert_eq!(granted.digest_tag(*b"auxr"), Some(&[8; DIGEST_BYTES]));
        assert_eq!(granted.digest_tag(*b"nsih"), Some(&[2; DIGEST_BYTES]));
        let plain = policy();
        assert_eq!(plain.boolean_tag(*b"smb2"), None);
        assert_eq!(plain.boolean_tag(*b"smb1"), Some(true));
        assert_eq!(plain.integer_tag(*b"sip0"), None);
        assert_eq!(plain.digest_tag(*b"auxp"), None);
    }

    /// `policy` with its `MANP` rebuilt from `properties`, signed.
    fn with_properties(properties: &[([u8; 4], u8, &[u8])]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for (name, tag, value) in properties {
            encoded.extend(property(*name, *tag, value));
        }
        let digest = property(*b"DGST", OCTET_STRING, &Sha384::digest(PAYLOAD));
        let mut objects = der::named(*b"MANP", &der::encode(SET, &encoded));
        objects.extend(der::named(*b"lpol", &der::encode(SET, &digest)));
        let signed = der::encode(SET, &der::named(*b"MANB", &der::encode(SET, &objects)));
        let signature: DerSignature = key(1).sign(&signed);
        let mut manifest = der::encode(der::IA5_STRING, b"IM4M");
        manifest.extend(der::encode(INTEGER, &[0]));
        manifest.extend(signed);
        manifest.extend(der::encode(OCTET_STRING, signature.as_bytes()));
        manifest.extend(der::encode(SEQUENCE, &[]));
        img4::compose(&PAYLOAD, &der::encode(SEQUENCE, &manifest))
    }

    #[test]
    fn a_policy_cannot_relax_more_than_the_kext_flags() {
        let (uuid, digest) = ([1; UUID_BYTES], [2; DIGEST_BYTES]);
        let base: [([u8; 4], u8, &[u8]); 3] = [
            (*b"lpnh", OCTET_STRING, &digest),
            (*b"nsih", OCTET_STRING, &digest),
            (*b"vuid", OCTET_STRING, &uuid),
        ];
        let grant = |bits: &'static [u8], smb2: bool| {
            let mut properties: Vec<([u8; 4], u8, &[u8])> = vec![
                (*b"auxi", OCTET_STRING, &digest),
                (*b"auxp", OCTET_STRING, &digest),
                (*b"auxr", OCTET_STRING, &digest),
            ];
            properties.extend(base);
            properties.push((*b"sip0", INTEGER, bits));
            if smb2 {
                properties.push((*b"smb2", BOOLEAN, &[0xff]));
            }
            with_properties(&properties)
        };
        let public = key(1);
        let public = public.verifying_key();
        assert!(matches!(
            verify(&grant(&[2, 1], true), public),
            Ok(Policy { kexts: Some(_), .. })
        ));
        assert_eq!(
            verify(&grant(&[0x7f], true), public),
            Err(Error::Malformed("sip0 is not the kext flags"))
        );
        assert_eq!(
            verify(&grant(&[2, 1], false), public),
            Err(Error::Malformed("a partial kext grant"))
        );
    }

    #[test]
    fn a_signed_policy_reads_back_under_its_key_alone() {
        let file = sign(&policy(), &key(1));
        assert_eq!(verify(&file, key(1).verifying_key()), Ok(policy()));
        assert_eq!(verify(&file, key(2).verifying_key()), Err(Error::Signature));
        let bare = Policy {
            splat: None,
            paired: None,
            security: Security::Full,
            ..policy()
        };
        let file = sign(&bare, &key(1));
        assert_eq!(verify(&file, key(1).verifying_key()), Ok(bare));
    }

    #[test]
    fn a_changed_policy_refuses() {
        let file = sign(&policy(), &key(1));
        let parts = img4::parse(&file).unwrap();
        let at = parts.manifest.unwrap().as_ptr() as usize - file.as_ptr() as usize;
        // Inside the volume group UUID, which is signed.
        let vuid = file.windows(16).rposition(|w| w == [1; 16]).unwrap();
        assert!(vuid > at);
        let mut changed = file.clone();
        changed[vuid] ^= 1;
        assert_eq!(
            verify(&changed, key(1).verifying_key()),
            Err(Error::Signature)
        );
        assert!(verify(&file[..file.len() - 1], key(1).verifying_key()).is_err());
    }

    #[test]
    fn the_file_is_an_image4_of_the_bare_policy() {
        let file = sign(&policy(), &key(1));
        let parts = img4::parse(&file).unwrap();
        assert_eq!(parts.payload, PAYLOAD);
        assert_eq!(img4::payload_type(parts.payload), Ok(*b"lpol"));
    }
}
