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
//! never treats an unverified LocalPolicy as authority: without a
//! [`PolicyAuthority`] its `nsih` only narrows which directory the
//! evidence of `stela_loader::installed` must qualify.
use crate::im4m::{self, Property, Value};
use alloc::{format, string::String, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;

const POLICY_OBJECT: &str = "lpol";
const SHA384_BYTES: usize = 48;
const UUID_BYTES: usize = 16;

/// Verifies a LocalPolicy's signature: implemented by the SEP model, which
/// signs and checks LocalPolicies with the machine's own SEP keys.
///
/// The SEP owner (root, on the main thread) provides the real implementation
/// against Stela's own SEP keys; `stela_loader::installed` and
/// `stela_loader::upgrade` take `Option<&dyn PolicyAuthority>` and, with
/// one, use the `nsih` and manifest signature as authority instead of
/// narrowing by evidence alone. [`Unverified`] is the placeholder until it
/// is wired: it refuses by name so a verified boot never silently succeeds.
pub trait PolicyAuthority {
    /// `Ok` only when `manifest`, an `IM4M`, is a LocalPolicy this
    /// machine's SEP signed.
    fn verify(&self, manifest: &[u8]) -> core::result::Result<(), String>;
}

/// The SEP keys are not yet wired, so no LocalPolicy signature can be
/// checked. Passing this where a [`PolicyAuthority`] is wanted refuses every
/// policy by name rather than accepting an unverified one; a boot without an
/// authority falls back to evidence (`stela_loader::installed`).
pub struct Unverified;

impl PolicyAuthority for Unverified {
    fn verify(&self, _manifest: &[u8]) -> core::result::Result<(), String> {
        Err(
            "LocalPolicy signature verification needs the SEP owner's keys, which are not \
             wired into stela_loader::local_policy::PolicyAuthority yet"
                .into(),
        )
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
            ensure!(
                value.len() == bytes,
                "LocalPolicy {name} is {} bytes, not {bytes}",
                value.len()
            );
            Ok(Some(value))
        }
        Some(other) => anyhow::bail!("LocalPolicy {name} is {other:?}, not data"),
        None => Ok(None),
    }
}

impl LocalPolicy {
    /// Parse the LocalPolicy file at `path`.
    pub fn parse(path: &str, file: &[u8]) -> Result<Self> {
        let manifest = match stela_formats::img4::parse(file) {
            Ok(parts) => parts
                .manifest
                .with_context(|| format!("{path} is an IMG4 without a manifest"))?
                .to_vec(),
            Err(_) => file.to_vec(),
        };
        let parsed = im4m::parse(&manifest).with_context(|| String::from(path))?;
        let properties = parsed
            .object(POLICY_OBJECT)
            .map(|o| o.properties.clone())
            .unwrap_or_else(|| parsed.properties.clone());
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
        authority
            .verify(&self.manifest)
            .map_err(|e| anyhow::anyhow!("{}: {e}", self.path))?;
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
        fn verify(&self, _: &[u8]) -> core::result::Result<(), String> {
            if self.0 {
                Ok(())
            } else {
                Err("not signed by this SEP".into())
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
    fn the_unverified_authority_refuses_every_policy_by_name() {
        let bytes = policy(&[0xab; 48], &[0x11; 16]);
        let mut parsed = LocalPolicy::parse("G/LocalPolicy/x.img4", &bytes).unwrap();
        let error = format!("{:#}", parsed.verify(&Unverified).unwrap_err());
        assert!(error.contains("SEP"), "{error}");
        assert!(!parsed.verified);
    }
}
