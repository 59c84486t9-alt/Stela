//! Stela-owned UID/GID key substrate; not Apple's secret hardware KDF.
//!
//! Apple's Platform Security "Secure Enclave" describes device-unique UID
//! and shared GID roots that software cannot read. The restore image contains
//! neither. Stela requires explicit persistent provisioning and separates the
//! domains with HMAC-SHA256. docs/research/sep.md defines this Stela policy.
//! This primitive grants no Image4 trust, AKS wrapping format or keybag state.
use crate::Result;
use hmac::{Hmac, Mac};
use stela_contracts::refuse;
use stela_crypto::Sha256;
use zeroize::Zeroizing;

const UID_DOMAIN: &[u8] = b"Stela SEP UID v1\0";
const GID_DOMAIN: &[u8] = b"Stela SEP GID v1\0";
/// A Stela API bound, not a SEP hardware limit.
const MAX_CONTEXT_BYTES: usize = 1024;
pub const ROOT_BYTES: usize = 32;

/// Roots must be persisted outside guest RAM and reused on restore/installed
/// boots of the same machine. No Debug, serialization or root export API.
///
/// The device's 64-bit ECID (`/chosen` `unique-chip-id`, Stela's per-machine
/// ApECID-style identifier set at setup and written by bundle preparation) is
/// bound into every derivation, so two machines with the same provisioned
/// roots but different ECIDs have different UID/GID keys. It is a public
/// identifier, not a secret; it is never treated as a root, and it is read
/// only from `/chosen`, never invented here.
pub struct Roots {
    machine: Zeroizing<[u8; ROOT_BYTES]>,
    group: Zeroizing<[u8; ROOT_BYTES]>,
    ecid: u64,
}

impl Roots {
    pub fn provisioned(
        machine: [u8; ROOT_BYTES],
        group: [u8; ROOT_BYTES],
        ecid: u64,
    ) -> Result<Self> {
        let machine = Zeroizing::new(machine);
        let group = Zeroizing::new(group);
        if machine.iter().all(|&b| b == 0) || group.iter().all(|&b| b == 0) {
            return Err(refuse!(
                "SEP roots require nonzero externally provisioned secrets"
            ));
        }
        if ecid == 0 {
            return Err(refuse!(
                "SEP roots require a nonzero ECID from /chosen unique-chip-id"
            ));
        }
        Ok(Self {
            machine,
            group,
            ecid,
        })
    }

    /// The machine's ECID, a public per-machine identifier.
    pub fn ecid(&self) -> u64 {
        self.ecid
    }

    /// A machine-bound key; `context` is a public, length-delimited purpose.
    pub fn uid(&self, context: &[u8]) -> Result<Zeroizing<[u8; ROOT_BYTES]>> {
        derive(&self.machine, UID_DOMAIN, self.ecid, context)
    }

    /// A group-bound key. Sharing the group root never shares UID keys.
    pub fn gid(&self, context: &[u8]) -> Result<Zeroizing<[u8; ROOT_BYTES]>> {
        derive(&self.group, GID_DOMAIN, self.ecid, context)
    }
}

fn derive(
    root: &[u8; ROOT_BYTES],
    domain: &[u8],
    ecid: u64,
    context: &[u8],
) -> Result<Zeroizing<[u8; ROOT_BYTES]>> {
    if context.len() > MAX_CONTEXT_BYTES {
        return Err(refuse!("SEP key-derivation context is too large"));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(root).expect("HMAC accepts 256-bit keys");
    mac.update(domain);
    mac.update(&ecid.to_be_bytes());
    mac.update(&(context.len() as u32).to_be_bytes());
    mac.update(context);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECID: u64 = 0x0123_4567_89ab_cdef;

    #[test]
    fn uid_is_stable_machine_bound_and_separate_from_the_group_domain() {
        let a = Roots::provisioned([1; 32], [3; 32], ECID).unwrap();
        let restored = Roots::provisioned([1; 32], [3; 32], ECID).unwrap();
        let other = Roots::provisioned([2; 32], [3; 32], ECID).unwrap();
        let context = b"keybag/class-c";
        assert_eq!(*a.uid(context).unwrap(), *restored.uid(context).unwrap());
        assert_ne!(*a.uid(context).unwrap(), *other.uid(context).unwrap());
        assert_eq!(*a.gid(context).unwrap(), *other.gid(context).unwrap());
        assert_ne!(*a.uid(context).unwrap(), *a.gid(context).unwrap());
        assert_ne!(*a.uid(context).unwrap(), *a.uid(b"keybag/class-a").unwrap());
        assert_eq!(a.ecid(), ECID);
        // A different ECID with the same roots yields different keys.
        let moved = Roots::provisioned([1; 32], [3; 32], 0x1122_3344_5566_7788).unwrap();
        assert_ne!(*a.uid(context).unwrap(), *moved.uid(context).unwrap());
        // Independent Python hmac/sha256 vectors for the exact Stela framing.
        assert_eq!(
            hex::encode(*a.uid(context).unwrap()),
            "802ffdb542bc4b50d73cee71a6d5b3a5b68f7a4b5184570758d689bd850e8518"
        );
        assert_eq!(
            hex::encode(*a.uid(b"keybag/class-a").unwrap()),
            "03dfc65b3efe14c33652aad5c247643fa482ef32420870a7ca31510ee734ab91"
        );
        assert_eq!(
            hex::encode(*moved.uid(context).unwrap()),
            "8b6d43a4c22f8bbb44141f9bfcdf66edac4df31577d1be4f79e92096a49b1121"
        );
    }

    #[test]
    fn provisioning_is_explicit_and_context_size_is_bounded() {
        assert!(Roots::provisioned([0; 32], [1; 32], ECID).is_err());
        assert!(Roots::provisioned([1; 32], [0; 32], ECID).is_err());
        assert!(Roots::provisioned([1; 32], [1; 32], 0).is_err());
        let roots = Roots::provisioned([1; 32], [1; 32], ECID).unwrap();
        assert_ne!(*roots.uid(b"").unwrap(), *roots.gid(b"").unwrap());
        assert!(roots.uid(&[0; MAX_CONTEXT_BYTES]).is_ok());
        assert!(roots.uid(&[0; MAX_CONTEXT_BYTES + 1]).is_err());
    }
}
