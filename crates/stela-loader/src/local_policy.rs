//! An installed system's LocalPolicy: the SEP-signed Image4 manifest on
//! Preboot (`<volume group>/LocalPolicy/<name>.img4`) whose `nsih` names
//! the boot directory LLB boots.
//!
//! Known: Apple Platform Security, "Contents of a LocalPolicy file for a Mac
//! with Apple silicon", lists its fields: `nsih` (SHA-384 of the next stage's
//! Image4 manifest), `vuid` (the volume group), `kuid` (the KEK group),
//! `lpnh`, `rpnh` and `ronh` (nonce hashes), `smb0`–`smb4` and `sip0`–`sip3`
//! (security modes and System Integrity Protection), among others. LLB opens
//! `<group>/boot/<nsih>` (26A434 J473 LLB 0xd3a80).
//!
//! Inferred: the fields are the properties of the manifest's `lpol` object,
//! else of its `MANP`; the file is a bare `IM4M` or an `IMG4` carrying one.
//!
//! Its signature is the SEP's, made with a key only the SEP holds. Stela
//! never treats an unverified LocalPolicy as permission: without a
//! [`PolicyAuthority`] its `nsih` only narrows which directory the
//! evidence of `stela_loader::installed` must check.
use crate::im4m::{self, Property, Value};
use crate::{Result, Within};
use alloc::{string::String, vec::Vec};
use serde::Serialize;
use stela_contracts::{Refusal, refuse, require};

const POLICY_OBJECT: &str = "lpol";
const SHA384_BYTES: usize = 48;
const UUID_BYTES: usize = 16;

/// Verifies a LocalPolicy's signature: implemented by the SEP model, which
/// signs and checks LocalPolicies with the machine's own SEP keys.
///
/// The SEP owner (root, on the main thread) provides the real implementation
/// against Stela's own SEP keys; `stela_loader::installed` and
/// `stela_loader::upgrade` take `Option<&dyn PolicyAuthority>` and, with
/// one, use the `nsih` and manifest signature as permission instead of
/// narrowing by evidence alone. [`Unverified`] is the placeholder until it
/// is wired: it refuses by name so a verified boot never silently succeeds.
pub trait PolicyAuthority {
    /// `Ok` only when `manifest`, an `IM4M`, is a LocalPolicy this
    /// machine's SEP signed.
    fn verify(&self, manifest: &[u8]) -> Result<(), Refusal>;
}

/// The SEP keys are not yet wired, so no LocalPolicy signature can be
/// checked. Passing this where a [`PolicyAuthority`] is wanted refuses every
/// policy by name rather than accepting an unverified one; a boot without an
/// permission falls back to evidence (`stela_loader::installed`).
pub struct Unverified;

impl PolicyAuthority for Unverified {
    fn verify(&self, _manifest: &[u8]) -> Result<(), Refusal> {
        Err(refuse!(
            "LocalPolicy signature verification needs the SEP owner's keys, which are not wired \
             into stela_loader::local_policy::PolicyAuthority yet"
        ))
    }
}

/// The fields Stela reads from a LocalPolicy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalPolicy {
    pub path: String,
    /// SHA-384 of the `IM4M`.
    pub sha384: String,
    /// The boot directory's name, uppercase hexadecimal.
    pub nsih: Option<String>,
    /// The volume group, as `uuid_t` bytes.
    pub volume_group: Option<[u8; UUID_BYTES]>,
    pub properties: Vec<Property>,
    /// Whether a [`PolicyAuthority`] verified its signature.
    pub verified: bool,
    #[serde(skip)]
    pub manifest: Vec<u8>,
}

fn data<'a>(properties: &'a [Property], name: &str, bytes: usize) -> Result<Option<&'a [u8]>> {
    match properties.iter().find(|p| p.name == name).map(|p| &p.value) {
        Some(Value::Data(value)) => {
            require!(
                value.len() == bytes,
                "LocalPolicy {name} is {value_len} bytes, not {bytes}",
                name,
                value_len = value.len(),
                bytes
            );
            Ok(Some(value))
        }
        Some(other) => Err(refuse!("LocalPolicy {name} is {other}, not data", name, ?other).into()),
        None => Ok(None),
    }
}

impl LocalPolicy {
    /// Parse the LocalPolicy file at `path`.
    pub fn parse(path: &str, file: &[u8]) -> Result<Self> {
        let manifest = match stela_formats::img4::parse(file) {
            Ok(parts) => parts
                .manifest
                .ok_or_else(|| refuse!("{path} is an IMG4 without a manifest", path))?
                .to_vec(),
            Err(_) => file.to_vec(),
        };
        let parsed = im4m::parse(&manifest).within(|| refuse!("LocalPolicy {path}", path))?;
        // LocalPolicy puts its grants in MANP and the payload digest in
        // lpol. Older inputs can put policy fields in lpol itself. Preserve
        // both namespaces, but never let one shadow a permission in the other.
        let mut properties = parsed.properties.clone();
        if let Some(object) = parsed.object(POLICY_OBJECT) {
            for property in &object.properties {
                require!(
                    !properties.iter().any(|other| other.name == property.name),
                    "LocalPolicy repeats property {name} across MANP and lpol",
                    name = property.name
                );
                properties.push(property.clone());
            }
        }
        let nsih = data(&properties, "nsih", SHA384_BYTES)?.map(hex::encode_upper);
        let volume_group = data(&properties, "vuid", UUID_BYTES)?
            .map(|bytes| bytes.try_into().expect("checked length"));
        Ok(Self {
            path: path.into(),
            sha384: parsed.sha384.clone(),
            nsih,
            volume_group,
            properties,
            verified: false,
            manifest,
        })
    }

    /// Ask `authority` to verify the signature.
    pub fn verify(&mut self, authority: &dyn PolicyAuthority) -> Result<()> {
        authority.verify(&self.manifest).map_err(|reason| {
            refuse!("LocalPolicy {path} does not verify", path = self.path).because(reason)
        })?;
        self.verified = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::im4m::tests::{der, entry, manifest};

    /// A LocalPolicy-shaped manifest with an `lpol` object.
    pub(crate) fn policy(nsih: &[u8], vuid: &[u8]) -> Vec<u8> {
        let properties = [
            entry("nsih", &der(&[0x04], nsih)),
            entry("vuid", &der(&[0x04], vuid)),
        ]
        .concat();
        manifest(&[], &[entry(POLICY_OBJECT, &der(&[0x31], &properties))])
    }

    struct Accept(bool);

    impl PolicyAuthority for Accept {
        fn verify(&self, _: &[u8]) -> Result<(), Refusal> {
            if self.0 {
                Ok(())
            } else {
                Err(refuse!("not signed by this SEP"))
            }
        }
    }

    #[test]
    fn the_policy_names_its_boot_directory_and_volume_group() {
        let bytes = policy(&[0xab; 48], &[0x11; 16]);
        let mut parsed = LocalPolicy::parse("G/LocalPolicy/x.img4", &bytes).unwrap();
        assert_eq!(parsed.nsih.as_deref(), Some("AB".repeat(48).as_str()));
        assert_eq!(parsed.volume_group, Some([0x11; 16]));
        assert!(!parsed.verified);
        assert!(parsed.verify(&Accept(false)).is_err());
        assert!(!parsed.verified);
        parsed.verify(&Accept(true)).unwrap();
        assert!(parsed.verified);
        assert!(LocalPolicy::parse("x", &policy(&[0xab; 47], &[0x11; 16])).is_err());
        assert!(LocalPolicy::parse("x", b"not a manifest").is_err());
    }

    #[test]
    fn the_unverified_permission_refuses_every_policy_by_name() {
        let bytes = policy(&[0xab; 48], &[0x11; 16]);
        let mut parsed = LocalPolicy::parse("G/LocalPolicy/x.img4", &bytes).unwrap();
        let error = format!("{:#}", parsed.verify(&Unverified).unwrap_err());
        assert!(error.contains("SEP"), "{error}");
        assert!(!parsed.verified);
    }

    #[test]
    fn manifest_wide_policy_fields_survive_an_lpol_payload_digest() {
        let next = entry("nsih", &der(&[0x04], &[0xab; 48]));
        let volume = entry("vuid", &der(&[0x04], &[0x11; 16]));
        let digest = entry("DGST", &der(&[0x04], &[0xcd; 48]));
        let object = entry(POLICY_OBJECT, &der(&[0x31], &digest));
        let file = manifest(&[next.clone(), volume], &[object]);
        let parsed = LocalPolicy::parse("policy", &file).unwrap();
        assert_eq!(parsed.nsih, Some("AB".repeat(48)));
        assert_eq!(parsed.volume_group, Some([0x11; 16]));
        let duplicate = entry(POLICY_OBJECT, &der(&[0x31], &next));
        assert!(LocalPolicy::parse("policy", &manifest(&[next], &[duplicate])).is_err());
    }
}
