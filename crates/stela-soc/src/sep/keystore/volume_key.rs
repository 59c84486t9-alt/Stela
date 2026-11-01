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
//!   wrapped KEK. APFS sends type 2. `aks_fv_new_verifier`, with which
//!   opendirectoryd records a user's password, is the same call with type 0
//!   and the user's UUID; its result is a KEK sized like any other.
//! - NEW_VEK 0x40 (0x2d46044): handle, parameters, secret, wrapped KEK,
//!   volume UUID -> wrapped VEK, inline key. Without a KEK and secret the
//!   VEK is "system-enabled", bound to the device alone.
//! - UNWRAP_VEK 0x41 (0x2d46288): handle, parameters, type, secret, wrapped
//!   KEK, wrapped VEK, ACM data -> inline key; variant 1 also returns a
//!   blob. APFS unlocks with (secret, wrapped KEK, wrapped VEK)
//!   (`_apfs_keybag_unlock_record_tag` 0x481ed30). `aks_fv_verify_user` is
//!   the same call with type 0 and no VEK: it asks only whether the secret
//!   opens the verifier, and gets an empty key back.
//! - SET_PROTECTION 0x47 (`__ipc_fv_set_protection` 0x2d5c62c, codec
//!   0x2d46fa8): handle, parameters, operation, u64, three blobs -> blob.
//!   APFS's `fv_set_protection` arguments x3..x5 are the three blobs. It
//!   commits a new VEK with operation 5 and the wrapped VEK third
//!   (`apfs_vek_commit_internal` 0x481f2dc), drops a VEK's state with 6 and
//!   the VEK third (`apfs_vek_remove_aks_state`, 0x490f484), commits an
//!   updated wrapped KEK record with 22 and the KEK second (0x4820924),
//!   retains an unlock record's state with 15 and releases it with 11, the
//!   KEK second (`apfs_keybag_aks_retain_unlock_record_for_volumes_group`
//!   0x481fa6c, 0x481fb80). `apfs_vek_set_protection` (file 0x4873050) sets
//!   a VEK's user protection with 3: the secret, the wrapped KEK that binds
//!   it and the wrapped VEK, answered by the rewrapped VEK, which it keeps in
//!   the container keybag. It sends that only for a VEK with no user
//!   protection. opendirectoryd binds a volume's first user this way, with
//!   the user's verifier as the KEK. It loads a volume's class keys with 18
//!   (`apfs_keybag_load_class_keys` 0x481e864, call 0x481ea44): the secret
//!   and its wrapped KEK (the volume keybag's tag 3 unlock record) first and
//!   second, both empty for a system-enabled VEK, and the wrapped VEK (the
//!   container keybag's tag 2) third. The u64 is 0, or bit 2 when the
//!   volume is a group's Data volume whose System volume is sealed (bit 5,
//!   `APFS_INCOMPAT_SEALED_VOLUME`, of its incompatible features, shifted
//!   right by 3). The call passes no output.
//! - GET_BLOB_STATE 0x48 (0x2d471f0): handle, parameters, wrapped VEK -> a
//!   DER dictionary `_decode_fv_blob_state` (0x2d5f8ec) reads: `kt` type,
//!   `kid` and `id` (16-byte octet strings), `f` flags, `kv` version, `sr`
//!   (up to eight reserved octets) and optional counters. Flags bit 2 means
//!   the VEK is user-protected and bit 3 system-protected
//!   (`_apfs_vek_get_aks_state` 0x482e554, whose results
//!   `setDictionaryForVolume` publishes as `VEKUserProtected` and
//!   `VEKSystemProtected`). `handle_is_vol_locked` reads the second as a
//!   volume that can be unlocked during mount, and calls any other locked.
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
//! Setting user protection adds the user seal and keeps the system seal,
//! which still mounts the volume at boot.
//! The keybag handle and parameters do not change these keys; they are not
//! interpreted. Commits keep no record against replaying an older wrapped
//! key and retained unlock records do not outlive the sepOS start; each
//! checks its key and reports that once. Loading class keys opens the VEK
//! as an unwrap does, which checks the secret and KEK, and keeps the
//! volume's class keys for [`file_key`] until the sepOS restarts, the VEK's
//! state is dropped or they are unloaded with 19 and the VEK third, as APFS
//! does on unmount (`apfs_keybag_unload_class_keys` 0x481e660, call
//! 0x481e808); the sealed-System bit is not interpreted, which
//! it reports once. Dropping an unlock record's state releases nothing, as
//! none is held. Other protection operations, the remaining `fv` commands
//! and other types refuse. [`media`] serves the container media keys under
//! the same root and inline engine.
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
/// The type of a user's password verifier.
const VERIFIER_TYPE: u32 = 0;
/// Protection operations.
const SET_USER_PROTECTION: u32 = 3;
const RELEASE_UNLOCK_RECORD: u32 = 11;
const COMMIT: u32 = 5;
const REMOVE_VEK_STATE: u32 = 6;
const RETAIN_UNLOCK_RECORD: u32 = 15;
const LOAD_CLASS_KEYS: u32 = 18;
const UNLOAD_CLASS_KEYS: u32 = 19;
const COMMIT_KEK: u32 = 22;
/// LOAD_CLASS_KEYS's u64: the volume group's System volume is sealed.
const SEALED_SYSTEM: u64 = 1 << 2;
/// The inline key's `cpx` flags: `CP_RAW_KEY_WRAPPEDKEY`.
const SEP_WRAPPED: u32 = 1;
/// Blob-state flags: `VEKUserProtected`, `VEKSystemProtected`.
pub(super) const USER_PROTECTED: u32 = 1 << 2;
pub(super) const SYSTEM_PROTECTED: u32 = 1 << 3;
/// A wrapped VEK's flags: the seals it carries.
const SYSTEM_SEAL: u32 = 1 << 2;
const USER_SEAL: u32 = 1 << 3;

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
    "SEP volume keys: commit keeps no anti-replay record of superseded wrapped keys";
const UNRETAINED: &str = "SEP volume keys: retained unlock records do not outlive the sepOS start";
const UNREAD_SEALED_SYSTEM: &str =
    "SEP volume keys: loading class keys does not interpret the sealed-System bit";

mod file_key;
mod keychain;
mod media;

pub(super) fn recognizes(command: u8) -> bool {
    matches!(
        command,
        NEW_VEK | UNWRAP_VEK | NEW_KEK | GET_SIZE | SET_PROTECTION | GET_BLOB_STATE
    ) || media::recognizes(command)
        || command == file_key::REWRAP
        || file_key::recognizes(command)
        || keychain::recognizes(command)
}

/// The volume keys of one sepOS start.
pub(super) struct VolumeKeys {
    root: Zeroizing<[u8; 32]>,
    engine: Engine,
    /// The volumes whose class keys are loaded.
    class_keys: Vec<file_key::ClassKeys>,
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
            class_keys: Vec::new(),
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
        if media::recognizes(command) {
            return self.media(command, variant, fields, entropy, notes);
        }
        if command == file_key::REWRAP {
            return self.rewrap(variant, fields, notes);
        }
        if file_key::recognizes(command) {
            return self.file_key(command, variant, fields, entropy, notes);
        }
        if keychain::recognizes(command) {
            return self.keychain(command, variant, fields, notes);
        }
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
                if !matches!(fields.word()?, KEK_TYPE | VERIFIER_TYPE) {
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
                let kind = fields.word()?;
                if !matches!(kind, KEK_TYPE | VERIFIER_TYPE) {
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
                if kind == VERIFIER_TYPE && wrapped_vek.is_empty() {
                    self.open_kek(wrapped_kek, secret)?;
                    reply.blob(&[]);
                    reply.word(0);
                } else {
                    let vek = self.open_vek(wrapped_vek, secret, wrapped_kek)?;
                    self.inline_key(&mut reply, &vek)?;
                }
                if variant == 1 {
                    reply.blob(&[]);
                }
            }
            SET_PROTECTION => {
                let operation = fields.word()?;
                let value = fields.lword()?;
                let first = fields.blob()?;
                let second = fields.blob()?;
                let third = fields.blob()?;
                fields.end()?;
                let vek_only = value == 0 && first.is_empty() && second.is_empty();
                let kek_only = value == 0 && first.is_empty() && third.is_empty();
                let mut output = Vec::new();
                match operation {
                    SET_USER_PROTECTION if value == 0 => {
                        output = self.set_user_protection(third, first, second)?;
                    }
                    COMMIT if vek_only => {
                        Vek::parse(third)?;
                        self.report(UNRECORDED_COMMIT, notes);
                    }
                    REMOVE_VEK_STATE | UNLOAD_CLASS_KEYS if vek_only => {
                        let volume = Vek::parse(third)?.volume();
                        self.class_keys.retain(|keys| keys.volume() != volume);
                    }
                    COMMIT_KEK if kek_only => {
                        kek_uuid(second)?;
                        self.report(UNRECORDED_COMMIT, notes);
                    }
                    RETAIN_UNLOCK_RECORD if kek_only => {
                        kek_uuid(second)?;
                        self.report(UNRETAINED, notes);
                    }
                    RELEASE_UNLOCK_RECORD if kek_only => {
                        kek_uuid(second)?;
                    }
                    LOAD_CLASS_KEYS if value & !SEALED_SYSTEM == 0 => {
                        let vek = self.open_vek(third, first, second)?;
                        let volume = Vek::parse(third)?.volume();
                        self.class_keys.retain(|keys| keys.volume() != volume);
                        self.class_keys.push(file_key::ClassKeys::new(volume, &vek));
                        if value & SEALED_SYSTEM != 0 {
                            self.report(UNREAD_SEALED_SYSTEM, notes);
                        }
                    }
                    _ => {
                        notes(alloc::format!(
                            "SEP volume keys: protection operation {operation} is not implemented"
                        ));
                        return Err(refuse!(
                            "SEP volume-key protection operation is not implemented"
                        ));
                    }
                }
                reply.blob(&output);
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
        let uuid = kek_uuid(blob)?;
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
        let flags = system.map_or(0, |_| SYSTEM_SEAL) | user.map_or(0, |_| USER_SEAL);
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

    /// A system-protected VEK, sealed also under the KEK `secret` opens.
    fn set_user_protection(
        &self,
        blob: &[u8],
        secret: &[u8],
        wrapped_kek: &[u8],
    ) -> Result<Vec<u8>> {
        let volume = Vek::parse(blob)?.volume();
        let vek = self.open_vek(blob, &[], &[])?;
        let kek = self.open_kek(wrapped_kek, secret)?;
        Ok(self.seal_vek(volume, Some(&*vek), Some((kek.uuid, &*kek.key, &*vek))))
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
            if !secret.is_empty() || vek.flags & SYSTEM_SEAL == 0 {
                return Err(refuse!(
                    "SEP volume-key VEK is not system-protected for an unlock without a KEK"
                ));
            }
            let system_key = derive(&self.root, SYSTEM_DOMAIN, &[]);
            return open(&system_key, SYSTEM_VEK_DOMAIN, header, vek.system);
        }
        let kek = self.open_kek(wrapped_kek, secret)?;
        if vek.flags & USER_SEAL == 0 || kek.uuid != vek.kek {
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
        if flags & !(SYSTEM_SEAL | USER_SEAL) != 0
            || flags == 0
            || !sealed(flags & SYSTEM_SEAL != 0, system, None)
            || !sealed(flags & USER_SEAL != 0, user, Some(kek))
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

    fn volume(&self) -> [u8; UUID_BYTES] {
        self.uuid.try_into().unwrap()
    }

    /// Its blob state, the dictionary `_decode_fv_blob_state` reads.
    fn state(&self) -> Vec<u8> {
        let protection = [(SYSTEM_SEAL, SYSTEM_PROTECTED), (USER_SEAL, USER_PROTECTED)]
            .into_iter()
            .filter(|(seal, _)| self.flags & seal != 0)
            .fold(0, |flags, (_, protected)| flags | protected);
        dictionary(&[
            (b"f", number(protection as u8)),
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

/// The UUID of a wrapped KEK in Stela's format; its seal is not opened.
fn kek_uuid(blob: &[u8]) -> Result<[u8; UUID_BYTES]> {
    if blob.len() != KEK_BYTES || blob[..4] != KEK_MAGIC || blob[4..8] != KEK_TYPE.to_le_bytes() {
        return Err(refuse!("SEP volume-key wrapped KEK is not a Stela KEK"));
    }
    Ok(blob[8..KEK_HEADER].try_into().unwrap())
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
