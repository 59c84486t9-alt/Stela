//! Stela-owned UID/GID key substrate; not Apple's secret hardware KDF.
//!
//! Apple's Platform Security "Secure Enclave" describes device-unique UID
//! and shared GID roots that software cannot read. The restore image contains
//! neither. Stela requires explicit persistent provisioning and separates the
//! domains with HMAC-SHA256. docs/research/sep.md defines this Stela policy.
//! This primitive grants no Image4 trust, AKS wrapping format or keybag state.
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const UID_DOMAIN: &[u8] = b"Stela SEP UID v1\0";
const GID_DOMAIN: &[u8] = b"Stela SEP GID v1\0";
/// A Stela API bound, not a SEP hardware limit.
const MAX_CONTEXT_BYTES: usize = 1024;
pub const ROOT_BYTES: usize = 32;

/// Roots must be persisted outside guest RAM and reused on restore/installed
/// boots of the same machine. No Debug, serialization or root export API.
pub struct Roots {
    machine: Zeroizing<[u8; ROOT_BYTES]>,
    group: Zeroizing<[u8; ROOT_BYTES]>,
}

impl Roots {
    pub fn provisioned(
        machine: [u8; ROOT_BYTES],
        group: [u8; ROOT_BYTES],
    ) -> Result<Self, &'static str> {
        let machine = Zeroizing::new(machine);
        let group = Zeroizing::new(group);
        if machine.iter().all(|&b| b == 0) || group.iter().all(|&b| b == 0) {
            return Err("SEP roots require nonzero externally provisioned secrets");
        }
        Ok(Self { machine, group })
    }

    /// A machine-bound key; `context` is a public, length-delimited purpose.
    pub fn uid(&self, context: &[u8]) -> Result<Zeroizing<[u8; ROOT_BYTES]>, &'static str> {
        derive(&self.machine, UID_DOMAIN, context)
    }

    /// A group-bound key. Sharing the group root never shares UID keys.
    pub fn gid(&self, context: &[u8]) -> Result<Zeroizing<[u8; ROOT_BYTES]>, &'static str> {
        derive(&self.group, GID_DOMAIN, context)
    }
}

fn derive(
    root: &[u8; ROOT_BYTES],
    domain: &[u8],
    context: &[u8],
) -> Result<Zeroizing<[u8; ROOT_BYTES]>, &'static str> {
    if context.len() > MAX_CONTEXT_BYTES {
        return Err("SEP key-derivation context is too large");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(root).expect("HMAC accepts 256-bit keys");
    mac.update(domain);
    mac.update(&(context.len() as u32).to_be_bytes());
    mac.update(context);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_is_stable_machine_bound_and_separate_from_the_group_domain() {
        let a = Roots::provisioned([1; 32], [3; 32]).unwrap();
        let restored = Roots::provisioned([1; 32], [3; 32]).unwrap();
        let other = Roots::provisioned([2; 32], [3; 32]).unwrap();
        let context = b"keybag/class-c";
        assert_eq!(*a.uid(context).unwrap(), *restored.uid(context).unwrap());
        assert_ne!(*a.uid(context).unwrap(), *other.uid(context).unwrap());
        assert_eq!(*a.gid(context).unwrap(), *other.gid(context).unwrap());
        assert_ne!(*a.uid(context).unwrap(), *a.gid(context).unwrap());
        assert_ne!(*a.uid(context).unwrap(), *a.uid(b"keybag/class-a").unwrap());
        // Independent Python hmac/sha256 vector for the exact Stela framing.
        assert_eq!(
            hex::encode(*a.uid(context).unwrap()),
            "843dc8f871b8f9f93c7f23695132226cf1b426962527d91e0fdaf65d078095f1"
        );
    }

    #[test]
    fn provisioning_is_explicit_and_context_size_is_bounded() {
        assert!(Roots::provisioned([0; 32], [1; 32]).is_err());
        assert!(Roots::provisioned([1; 32], [0; 32]).is_err());
        let roots = Roots::provisioned([1; 32], [1; 32]).unwrap();
        assert_ne!(*roots.uid(b"").unwrap(), *roots.gid(b"").unwrap());
        assert!(roots.uid(&[0; MAX_CONTEXT_BYTES]).is_ok());
        assert!(roots.uid(&[0; MAX_CONTEXT_BYTES + 1]).is_err());
    }
}
