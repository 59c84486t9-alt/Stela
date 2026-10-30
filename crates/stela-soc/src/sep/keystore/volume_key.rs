//! FileVault volume keys: the AKS `fv` commands APFS creates and unlocks its
//! encrypted volumes with, served with Stela-owned keys and blob formats.
//!
//! **Wire.** 26A434 kernel file offsets. Each `_code_ipc_fv_*` codec sends
//! variant 0, then its request fields, and reads its reply fields after the
//! reply's variant; the two sets are disjoint. `fv_data` is a blob and
//! `fv_key` a blob and a u32 of `cpx` flags. An absent `fv_data` is empty.
//! - GET_SIZE 0x44 (`_code_ipc_fv_get_size` 0x2d46970): handle, parameters,
//!   type -> size. APFS sizes a wrapped KEK with type 2 ("wkek len") and a
//!   wrapped VEK with type 1 ("wvek len")
//!   (`_apfs_keybag_set_create_update_record` 0x481ff08).
//! - NEW_KEK 0x42 (0x2d46518): handle, parameters, type, secret, KEK UUID ->
//!   wrapped KEK. APFS sends type 2.
//! - NEW_VEK 0x40 (0x2d46044): handle, parameters, secret, wrapped KEK,
//!   volume UUID -> wrapped VEK, inline key. Without a KEK and secret the
//!   VEK is "system-enabled", bound to the device alone.
//! - UNWRAP_VEK 0x41 (0x2d46288): handle, parameters, type, secret, wrapped
//!   KEK, wrapped VEK, ACM data -> inline key; variant 1 also returns a
//!   blob. APFS unlocks with (secret, wrapped KEK, wrapped VEK)
//!   (`_apfs_keybag_unlock_record_tag` 0x481ed30).
//! - SET_PROTECTION 0x47 (`__ipc_fv_set_protection` 0x2d5c62c, codec
//!   0x2d46fa8): handle, parameters, operation, u64, three blobs -> blob.
//!   APFS commits a new VEK with operation 5 and the wrapped VEK third.
//! - GET_BLOB_STATE 0x48 (0x2d471f0): handle, parameters, wrapped VEK -> a
//!   DER dictionary `_decode_fv_blob_state` (0x2d5f8ec) reads: `kt` type,
//!   `kid` and `id` (16-byte octet strings), `f` flags, `kv` version, `sr`
//!   (up to eight reserved octets) and optional counters. Flags bit 2 means
//!   the VEK is system-protected and bit 3 user-protected
//!   (`_apfs_vek_get_aks_state` 0x482e554 reports an unencrypted volume as
//!   system-protected only).
//!
//! The inline key's flags bit 0 is `CP_RAW_KEY_WRAPPEDKEY`
//! (`_cst_from_fvkey` 0x481bee4 passes it to `cpx_set_is_sep_wrapped_key`):
//! the key is [`Engine::wrap`]'s form, which only the boot's
//! inline engine opens.
//!
//! **Keys.** Stela's formats, sealed with [`seal`] under keys
//! derived from the machine's system-key root, so no other machine opens
//! them. A wrapped KEK is sealed under the root, its UUID and the user's
//! secret; a wrapped VEK carries a system seal under the root, a user seal
//! under a KEK, or both, with the VEK UUID and its KEK's UUID bound in.
//! The keybag handle and parameters do not change these keys; they are not
//! interpreted. Commit keeps no record against replaying an older wrapped
//! VEK; it checks the VEK and reports that once. Other protection
//! operations, the remaining `fv` commands and other types refuse.
use super::super::Entropy;
use super::Fields;
use super::dictionary::{dictionary, number, tagged};
use crate::Result;
use crate::inline_key::{Engine, KEY_AREA_BYTES, KEY_BYTES, SEALED_BYTES, open, seal};
use alloc::{string::String, vec::Vec};
use hmac::{Hmac, Mac};
use stela_contracts::refuse;
use stela_crypto::Sha256;
use zeroize::Zeroizing;

pub(super) const NEW_VEK: u8 = 0x40;
pub(super) const UNWRAP_VEK: u8 = 0x41;
pub(super) const NEW_KEK: u8 = 0x42;
pub(super) const GET_SIZE: u8 = 0x44;
pub(super) const SET_PROTECTION: u8 = 0x47;
pub(super) const GET_BLOB_STATE: u8 = 0x48;

/// GET_SIZE's types.
const WRAPPED_VEK: u32 = 1;
const WRAPPED_KEK: u32 = 2;
/// The only KEK and unwrap type APFS sends.
const KEK_TYPE: u32 = 2;
const COMMIT: u32 = 5;
/// The inline key's `cpx` flags: `CP_RAW_KEY_WRAPPEDKEY`.
const SEP_WRAPPED: u32 = 1;
/// Blob-state flags.
pub(super) const SYSTEM_PROTECTED: u32 = 1 << 2;
pub(super) const USER_PROTECTED: u32 = 1 << 3;

const UUID_BYTES: usize = 16;
const KEK_MAGIC: [u8; 4] = *b"SKK1";
const VEK_MAGIC: [u8; 4] = *b"SVK1";
/// Magic, type, KEK UUID; then the sealed KEK.
const KEK_HEADER: usize = 4 + 4 + UUID_BYTES;
pub(super) const KEK_BYTES: usize = KEK_HEADER + SEALED_BYTES;
/// Magic, flags, VEK UUID, KEK UUID; then the system and user seals.
const VEK_HEADER: usize = 4 + 4 + 2 * UUID_BYTES;
pub(super) const VEK_BYTES: usize = VEK_HEADER + 2 * SEALED_BYTES;

const ROOT_DOMAIN: &[u8] = b"Stela SEP volume keys v1\0";
const PROTECTOR_DOMAIN: &[u8] = b"Stela SEP KEK protector v1\0";
const SYSTEM_DOMAIN: &[u8] = b"Stela SEP system VEK v1\0";
const KEK_DOMAIN: &[u8] = b"Stela SEP KEK v1\0";
const SYSTEM_VEK_DOMAIN: &[u8] = b"Stela SEP system-sealed VEK v1\0";
const USER_VEK_DOMAIN: &[u8] = b"Stela SEP user-sealed VEK v1\0";
const USER_KEY_DOMAIN: &[u8] = b"Stela SEP KEK-derived VEK key v1\0";

const UNINTERPRETED: &str = "SEP volume keys: keybag handle and parameters are not interpreted";
const UNRECORDED_COMMIT: &str =
    "SEP volume keys: commit keeps no anti-replay record of superseded wrapped VEKs";

pub(super) fn recognizes(command: u8) -> bool {
    matches!(
        command,
        NEW_VEK | UNWRAP_VEK | NEW_KEK | GET_SIZE | SET_PROTECTION | GET_BLOB_STATE
    )
}

/// The volume keys of one sepOS start.
pub(super) struct VolumeKeys {
    root: Zeroizing<[u8; 32]>,
    engine: Engine,
    /// Degraded answers already reported.
    reported: Vec<&'static str>,
}

impl VolumeKeys {
    /// Keys under `machine_root`, wrapping inline keys with `engine`, which
    /// gets a fresh wrapping key from `entropy`.
    pub(super) fn new(
        machine_root: &[u8; 32],
        engine: Engine,
        entropy: &mut dyn Entropy,
    ) -> Result<Self> {
        let mut wrapping = Zeroizing::new([0; 32]);
        entropy.fill(&mut *wrapping)?;
        engine.provision(wrapping);
        Ok(Self {
            root: derive(machine_root, ROOT_DOMAIN, &[]),
            engine,
            reported: Vec::new(),
        })
    }

    /// Answer `command`'s `fields` with its reply fields. Degraded answers
    /// are reported to `notes` once each.
    pub(super) fn request(
        &mut self,
        command: u8,
        variant: u32,
        fields: &mut Fields<'_>,
        entropy: &mut dyn Entropy,
        notes: &mut dyn FnMut(String),
    ) -> Result<Vec<u8>> {
        let expected = if command == UNWRAP_VEK {
            matches!(variant, 0 | 1)
        } else {
            variant == 0
        };
        if !expected {
            return Err(refuse!("SEP volume-key command variant is not modeled"));
        }
        let _handle = fields.lword()?;
        let _parameters = fields.blob()?;
        self.report(UNINTERPRETED, notes);
        let mut reply = Reply::default();
        match command {
            GET_SIZE => {
                let size = match fields.word()? {
                    WRAPPED_VEK => VEK_BYTES,
                    WRAPPED_KEK => KEK_BYTES,
                    _ => return Err(refuse!("SEP volume-key size type is not modeled")),
                };
                fields.end()?;
                reply.lword(size as u64);
            }
            NEW_KEK => {
                if fields.word()? != KEK_TYPE {
                    return Err(refuse!("SEP volume-key KEK type is not modeled"));
                }
                let secret = fields.blob()?;
                let uuid = uuid(fields.blob()?)?;
                fields.end()?;
                let kek = random(entropy)?;
                reply.blob(&self.seal_kek(uuid, secret, &kek));
            }
            NEW_VEK => {
                let secret = fields.blob()?;
                let wrapped_kek = fields.blob()?;
                let uuid = uuid(fields.blob()?)?;
                fields.end()?;
                let vek = random(entropy)?;
                let wrapped = if wrapped_kek.is_empty() {
                    if !secret.is_empty() {
                        return Err(refuse!("SEP volume-key secret has no KEK to open"));
                    }
                    self.seal_vek(uuid, Some(&*vek), None)
                } else {
                    let kek = self.open_kek(wrapped_kek, secret)?;
                    self.seal_vek(uuid, None, Some((kek.uuid, &*kek.key, &*vek)))
                };
                reply.blob(&wrapped);
                self.inline_key(&mut reply, &vek)?;
            }
            UNWRAP_VEK => {
                if fields.word()? != KEK_TYPE {
                    return Err(refuse!("SEP volume-key unwrap type is not modeled"));
                }
                let secret = fields.blob()?;
                let wrapped_kek = fields.blob()?;
                let wrapped_vek = fields.blob()?;
                if !fields.blob()?.is_empty() {
                    return Err(refuse!(
                        "SEP volume-key ACM-authorized unwrap is not modeled"
                    ));
                }
                fields.end()?;
                let vek = self.open_vek(wrapped_vek, secret, wrapped_kek)?;
                self.inline_key(&mut reply, &vek)?;
                if variant == 1 {
                    reply.blob(&[]);
                }
            }
            SET_PROTECTION => {
                let operation = fields.word()?;
                let value = fields.lword()?;
                let first = fields.blob()?;
                let second = fields.blob()?;
                let wrapped_vek = fields.blob()?;
                fields.end()?;
                if operation != COMMIT || value != 0 || !first.is_empty() || !second.is_empty() {
                    notes(alloc::format!(
                        "SEP volume keys: protection operation {operation} is not implemented"
                    ));
                    return Err(refuse!(
                        "SEP volume-key protection operation is not implemented"
                    ));
                }
                Vek::parse(wrapped_vek)?;
                self.report(UNRECORDED_COMMIT, notes);
                reply.blob(&[]);
            }
            GET_BLOB_STATE => {
                let wrapped_vek = fields.blob()?;
                fields.end()?;
                let vek = Vek::parse(wrapped_vek)?;
                reply.blob(&vek.state());
            }
            _ => return Err(refuse!("SEP volume-key command is not implemented")),
        }
        Ok(reply.0)
    }

    fn report(&mut self, note: &'static str, notes: &mut dyn FnMut(String)) {
        if !self.reported.contains(&note) {
            self.reported.push(note);
            notes(note.into());
        }
    }

    /// The inline key reply: the engine's wrapped form and its flags.
    fn inline_key(&self, reply: &mut Reply, vek: &[u8; KEY_BYTES]) -> Result<()> {
        let area: [u8; KEY_AREA_BYTES] = self.engine.wrap(vek)?;
        reply.blob(&area);
        reply.word(SEP_WRAPPED);
        Ok(())
    }

    fn protector(&self, uuid: [u8; UUID_BYTES], secret: &[u8]) -> Zeroizing<[u8; 32]> {
        derive(&self.root, PROTECTOR_DOMAIN, &[&uuid, secret].concat())
    }

    fn seal_kek(&self, uuid: [u8; UUID_BYTES], secret: &[u8], kek: &[u8; KEY_BYTES]) -> Vec<u8> {
        let mut blob = KEK_MAGIC.to_vec();
        blob.extend_from_slice(&KEK_TYPE.to_le_bytes());
        blob.extend_from_slice(&uuid);
        let sealed = seal(&self.protector(uuid, secret), KEK_DOMAIN, &blob, kek);
        blob.extend_from_slice(&sealed);
        blob
    }

    fn open_kek(&self, blob: &[u8], secret: &[u8]) -> Result<Kek> {
        if blob.len() != KEK_BYTES || blob[..4] != KEK_MAGIC || blob[4..8] != KEK_TYPE.to_le_bytes()
        {
            return Err(refuse!("SEP volume-key wrapped KEK is not a Stela KEK"));
        }
        let uuid = blob[8..KEK_HEADER].try_into().unwrap();
        let sealed = blob[KEK_HEADER..].try_into().unwrap();
        let key = open(
            &self.protector(uuid, secret),
            KEK_DOMAIN,
            &blob[..KEK_HEADER],
            sealed,
        )
        .map_err(|_| refuse!("SEP volume-key secret does not open the wrapped KEK"))?;
        Ok(Kek { uuid, key })
    }

    /// A wrapped VEK for volume `uuid`: sealed for the system when `system`
    /// holds the VEK, and under the KEK `user` holds.
    fn seal_vek(
        &self,
        uuid: [u8; UUID_BYTES],
        system: Option<&[u8; KEY_BYTES]>,
        user: Option<([u8; UUID_BYTES], &[u8; KEY_BYTES], &[u8; KEY_BYTES])>,
    ) -> Vec<u8> {
        let flags = system.map_or(0, |_| SYSTEM_PROTECTED) | user.map_or(0, |_| USER_PROTECTED);
        let mut blob = VEK_MAGIC.to_vec();
        blob.extend_from_slice(&flags.to_le_bytes());
        blob.extend_from_slice(&uuid);
        blob.extend_from_slice(&user.map_or([0; UUID_BYTES], |(kek, ..)| kek));
        let header = blob.clone();
        let system_key = derive(&self.root, SYSTEM_DOMAIN, &[]);
        blob.extend_from_slice(&system.map_or([0; SEALED_BYTES], |vek| {
            seal(&system_key, SYSTEM_VEK_DOMAIN, &header, vek)
        }));
        blob.extend_from_slice(&user.map_or([0; SEALED_BYTES], |(_, kek, vek)| {
            seal(
                &derive(kek, USER_KEY_DOMAIN, &[]),
                USER_VEK_DOMAIN,
                &header,
                vek,
            )
        }));
        blob
    }

    /// The VEK in `blob`: system-protected without a KEK and secret,
    /// otherwise through the KEK the secret opens.
    fn open_vek(
        &self,
        blob: &[u8],
        secret: &[u8],
        wrapped_kek: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
        let vek = Vek::parse(blob)?;
        let header = &blob[..VEK_HEADER];
        if wrapped_kek.is_empty() {
            if !secret.is_empty() || vek.flags & SYSTEM_PROTECTED == 0 {
                return Err(refuse!(
                    "SEP volume-key VEK is not system-protected for an unlock without a KEK"
                ));
            }
            let system_key = derive(&self.root, SYSTEM_DOMAIN, &[]);
            return open(&system_key, SYSTEM_VEK_DOMAIN, header, vek.system);
        }
        let kek = self.open_kek(wrapped_kek, secret)?;
        if vek.flags & USER_PROTECTED == 0 || kek.uuid != vek.kek {
            return Err(refuse!(
                "SEP volume-key VEK is not protected by the supplied KEK"
            ));
        }
        open(
            &derive(&kek.key, USER_KEY_DOMAIN, &[]),
            USER_VEK_DOMAIN,
            header,
            vek.user,
        )
    }
}

struct Kek {
    uuid: [u8; UUID_BYTES],
    key: Zeroizing<[u8; KEY_BYTES]>,
}

/// A wrapped VEK's fields; its seals open only with their keys.
struct Vek<'a> {
    flags: u32,
    uuid: &'a [u8],
    kek: [u8; UUID_BYTES],
    system: &'a [u8; SEALED_BYTES],
    user: &'a [u8; SEALED_BYTES],
}

impl<'a> Vek<'a> {
    fn parse(blob: &'a [u8]) -> Result<Self> {
        if blob.len() != VEK_BYTES || blob[..4] != VEK_MAGIC {
            return Err(refuse!("SEP volume-key wrapped VEK is not a Stela VEK"));
        }
        let flags = u32::from_le_bytes(blob[4..8].try_into().unwrap());
        let system: &[u8; SEALED_BYTES] = blob[VEK_HEADER..][..SEALED_BYTES].try_into().unwrap();
        let user: &[u8; SEALED_BYTES] = blob[VEK_HEADER + SEALED_BYTES..].try_into().unwrap();
        let kek = blob[24..VEK_HEADER].try_into().unwrap();
        let sealed = |present: bool, seal: &[u8], uuid: Option<[u8; UUID_BYTES]>| {
            present == seal.iter().any(|&b| b != 0)
                && uuid.is_none_or(|uuid| present == (uuid != [0; UUID_BYTES]))
        };
        if flags & !(SYSTEM_PROTECTED | USER_PROTECTED) != 0
            || flags == 0
            || !sealed(flags & SYSTEM_PROTECTED != 0, system, None)
            || !sealed(flags & USER_PROTECTED != 0, user, Some(kek))
        {
            return Err(refuse!(
                "SEP volume-key wrapped VEK flags disagree with its seals"
            ));
        }
        Ok(Self {
            flags,
            uuid: &blob[8..24],
            kek,
            system,
            user,
        })
    }

    /// Its blob state, the dictionary `_decode_fv_blob_state` reads.
    fn state(&self) -> Vec<u8> {
        dictionary(&[
            (b"f", number(self.flags as u8)),
            (b"id", tagged(4, &self.kek)),
            (b"kid", tagged(4, self.uuid)),
            (b"kt", number(WRAPPED_VEK as u8)),
            (b"kv", number(1)),
            (b"sr", tagged(4, &[0; 8])),
        ])
    }
}

/// Reply fields in the codecs' encoding.
#[derive(Default)]
struct Reply(Vec<u8>);

impl Reply {
    fn word(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn lword(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn blob(&mut self, bytes: &[u8]) {
        self.word(bytes.len() as u32);
        self.0.extend_from_slice(bytes);
        self.0.resize(self.0.len().next_multiple_of(4), 0);
    }
}

fn uuid(bytes: &[u8]) -> Result<[u8; UUID_BYTES]> {
    bytes
        .try_into()
        .map_err(|_| refuse!("SEP volume-key UUID is not 16 bytes"))
}

fn random(entropy: &mut dyn Entropy) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let mut key = Zeroizing::new([0; KEY_BYTES]);
    entropy.fill(&mut *key)?;
    Ok(key)
}

fn derive(key: &[u8; 32], domain: &[u8], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts 256-bit keys");
    mac.update(domain);
    mac.update(context);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

#[cfg(test)]
pub(super) mod tests;
