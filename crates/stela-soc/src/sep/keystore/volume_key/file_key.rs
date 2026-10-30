//! Per-file keys: the keys APFS gives each file on a volume whose class keys
//! are loaded, wrapped under the file's protection class.
//!
//! **Wire.** 26A434 kernel file offsets. `fs_new_key` (0x2d4f958) and
//! `fs_unwrap_key` (0x2d22d14) send the u64 1 every client request starts
//! with, the keybag handle `_fs_handle` (0x2d54e88) finds for the file's
//! volume, and the volume's encoded parameters
//! (`_encode_pfk_params_public` 0x2d5fb5c): a DER dictionary with the
//! 16-byte octet strings `persona_uuid` when the parameters' flags bit 0 is
//! set and `volume_uuid` when bit 1 is, which `_volume_handle` (0x2d5249c)
//! sets for a volume mapped to handle -5; no flags encode no dictionary.
//! - NEW_KEY 0x10 (`__ipc_new_pfk_data_v2` 0x2d59448, codec 0x2d3f6d0),
//!   variant 2 from `new_key` (0x2d51d48) for request type 1: u64, handle,
//!   parameters, class, flags, a 28-byte file-system context and an empty
//!   blob -> key, IV key, a blob the caller takes no buffer for, wrapped
//!   key, another such blob, flags and the wrapped key's class, which lands
//!   at `aks_wrapped_key_s` + 12. `check_class` (0x2d25df4), APFS's class
//!   availability check, sends the same command with flags 0, no context
//!   and no buffer for any reply field: no key is made, and the class is
//!   available when its volume's class keys are loaded.
//! - UNWRAP_KEY 0x09 (`__ipc_unwrap_pfk_data_v1` 0x2d58d74, codec
//!   0x2d3e22c), variant 1 from `unwrap_data` (0x2d25f78) for request type
//!   1: u64, handle, parameters, the wrapped key's class, wrapped key, flags
//!   -> key, IV key, flags.
//!
//! The request flags are 2 for a new key and 0x102 for an unwrap, with bit
//! 0 set when the caller takes no key; bit 8's meaning is not recovered.
//! The reply flags' bit 1 becomes the raw key's `CP_RAW_KEY_WRAPPEDKEY`
//! (0x2d51f28, 0x2d26354). Other request types send other variants
//! (`rewrap_data_with_opts`, unwrap variants 0 and 2), which refuse.
//!
//! **Keys.** The key is the inline engine's wrapped form, as for a VEK;
//! there is no IV key. Loading a volume's class keys (protection operation
//! 18) keeps a class root derived from its VEK until the sepOS restarts or
//! the VEK's state is dropped; each class key derives from it. A wrapped key
//! is Stela's format: magic, class and volume UUID, then the key sealed
//! under that class key, so it opens only on its machine, volume and class
//! once the volume's class keys are loaded. The volume comes from the
//! parameters' `volume_uuid`; a request without one refuses. Keybag
//! handles, personas, file-system contexts and request flag bit 8 are not
//! interpreted, and classes differ only in their keys: none is ever locked,
//! so class A and B keys stay available. That is reported once.
use super::super::super::Entropy;
use super::super::Fields;
use super::super::dictionary::octet_strings;
use super::{KEY_BYTES, Reply, UUID_BYTES, VolumeKeys, derive, random};
use crate::Result;
use crate::inline_key::{SEALED_BYTES, open, seal};
use alloc::{string::String, vec::Vec};
use stela_contracts::refuse;
use zeroize::Zeroizing;

pub(super) const UNWRAP_KEY: u8 = 0x09;
pub(super) const NEW_KEY: u8 = 0x10;

const NEW_KEY_VARIANT: u32 = 2;
const UNWRAP_KEY_VARIANT: u32 = 1;
/// The u64 `new_key` and `unwrap_data` send first.
const CLIENT: u64 = 1;
/// Request flags: the caller takes no key; it wants a SEP-wrapped key; bit
/// 8, not recovered.
const NO_KEY: u32 = 1;
const WRAPPED_KEY: u32 = 1 << 1;
const UNRECOVERED: u32 = 1 << 8;
/// `check_class`'s request flags.
const CHECK_CLASS: u32 = 0;
/// Reply flags: the key is SEP-wrapped.
const SEP_WRAPPED: u32 = 1 << 1;
const CONTEXT_BYTES: usize = 28;

const MAGIC: [u8; 4] = *b"SFK1";
/// Magic, class, volume UUID; then the sealed key.
const HEADER: usize = 4 + 4 + UUID_BYTES;
pub(super) const WRAPPED_BYTES: usize = HEADER + SEALED_BYTES;

const CLASS_ROOT_DOMAIN: &[u8] = b"Stela SEP class keys v1\0";
const CLASS_KEY_DOMAIN: &[u8] = b"Stela SEP class key v1\0";
const FILE_KEY_DOMAIN: &[u8] = b"Stela SEP per-file key v1\0";

pub(super) const UNINTERPRETED: &str = "SEP per-file keys: keybag handles, personas, \
     file-system contexts and request flag bit 8 are not interpreted, and no class is ever locked";

pub(super) fn recognizes(command: u8) -> bool {
    matches!(command, NEW_KEY | UNWRAP_KEY)
}

/// A volume's loaded class keys.
pub(super) struct ClassKeys {
    volume: [u8; UUID_BYTES],
    root: Zeroizing<[u8; 32]>,
}

impl ClassKeys {
    pub(super) fn new(volume: [u8; UUID_BYTES], vek: &[u8; KEY_BYTES]) -> Self {
        Self {
            volume,
            root: derive(vek, CLASS_ROOT_DOMAIN, &volume),
        }
    }

    pub(super) fn volume(&self) -> [u8; UUID_BYTES] {
        self.volume
    }

    fn key(&self, class: u32) -> Zeroizing<[u8; 32]> {
        derive(&self.root, CLASS_KEY_DOMAIN, &class.to_le_bytes())
    }
}

impl VolumeKeys {
    pub(super) fn file_key(
        &mut self,
        command: u8,
        variant: u32,
        fields: &mut Fields<'_>,
        entropy: &mut dyn Entropy,
        notes: &mut dyn FnMut(String),
    ) -> Result<Vec<u8>> {
        let expected = if command == NEW_KEY {
            NEW_KEY_VARIANT
        } else {
            UNWRAP_KEY_VARIANT
        };
        if variant != expected {
            return Err(refuse!("SEP per-file key command variant is not modeled"));
        }
        if fields.lword()? != CLIENT {
            return Err(refuse!(
                "SEP per-file key request does not start with the kernel's u64"
            ));
        }
        let _handle = fields.word()?;
        let volume = volume(fields.blob()?)?;
        let class = fields.word()?;
        if class == 0 {
            return Err(refuse!("SEP per-file key names no protection class"));
        }
        let mut reply = Reply::default();
        if command == NEW_KEY {
            let request = fields.word()?;
            let context = fields.blob()?.len();
            let trailing = fields.blob()?.len();
            if request == CHECK_CLASS && context == 0 && trailing == 0 {
                fields.end()?;
                self.class_keys(volume)?;
                for _ in 0..5 {
                    reply.blob(&[]);
                }
                reply.word(0);
                reply.word(class);
                self.report(UNINTERPRETED, notes);
                return Ok(reply.0);
            }
            flags(request)?;
            if context != CONTEXT_BYTES || trailing != 0 {
                return Err(refuse!(
                    "SEP new per-file key context or trailing blob is not modeled"
                ));
            }
            fields.end()?;
            let classes = self.class_keys(volume)?;
            let key = random(entropy)?;
            let wrapped = wrap(classes, class, &key);
            self.key_reply(&mut reply, &key)?;
            reply.blob(&[]);
            reply.blob(&wrapped);
            reply.blob(&[]);
            reply.word(SEP_WRAPPED);
            reply.word(class);
        } else {
            let wrapped = fields.blob()?;
            flags(fields.word()?)?;
            fields.end()?;
            let key = unwrap(self.class_keys(volume)?, class, wrapped)?;
            self.key_reply(&mut reply, &key)?;
            reply.word(SEP_WRAPPED);
        }
        self.report(UNINTERPRETED, notes);
        Ok(reply.0)
    }

    fn class_keys(&self, volume: [u8; UUID_BYTES]) -> Result<&ClassKeys> {
        self.class_keys
            .iter()
            .find(|keys| keys.volume == volume)
            .ok_or(refuse!("SEP per-file key volume has no loaded class keys"))
    }

    /// The key, its absent IV key.
    fn key_reply(&self, reply: &mut Reply, key: &[u8; KEY_BYTES]) -> Result<()> {
        reply.blob(&self.engine.wrap(key)?);
        reply.blob(&[]);
        Ok(())
    }
}

/// The volume UUID the encoded parameters name.
fn volume(parameters: &[u8]) -> Result<[u8; UUID_BYTES]> {
    let entries = octet_strings(parameters)?;
    let uuid = entries
        .iter()
        .find(|(key, _)| *key == b"volume_uuid")
        .ok_or(refuse!("SEP per-file key parameters name no volume"))?
        .1;
    if entries.iter().any(|(key, value)| {
        !matches!(*key, b"volume_uuid" | b"persona_uuid") || value.len() != UUID_BYTES
    }) {
        return Err(refuse!("SEP per-file key parameters are not modeled"));
    }
    Ok(uuid.try_into().unwrap())
}

/// Request flags: a SEP-wrapped key, optionally not taken.
fn flags(flags: u32) -> Result<()> {
    if flags & WRAPPED_KEY == 0 || flags & !(NO_KEY | WRAPPED_KEY | UNRECOVERED) != 0 {
        return Err(refuse!("SEP per-file key request flags are not modeled"));
    }
    Ok(())
}

fn header(class: u32, volume: [u8; UUID_BYTES]) -> [u8; HEADER] {
    let mut header = [0; HEADER];
    header[..4].copy_from_slice(&MAGIC);
    header[4..8].copy_from_slice(&class.to_le_bytes());
    header[8..].copy_from_slice(&volume);
    header
}

fn wrap(classes: &ClassKeys, class: u32, key: &[u8; KEY_BYTES]) -> Vec<u8> {
    let header = header(class, classes.volume);
    let mut wrapped = header.to_vec();
    wrapped.extend_from_slice(&seal(&classes.key(class), FILE_KEY_DOMAIN, &header, key));
    wrapped
}

fn unwrap(classes: &ClassKeys, class: u32, wrapped: &[u8]) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    if wrapped.len() != WRAPPED_BYTES || wrapped[..HEADER] != header(class, classes.volume) {
        return Err(refuse!(
            "SEP wrapped per-file key is not a Stela key of this class and volume"
        ));
    }
    open(
        &classes.key(class),
        FILE_KEY_DOMAIN,
        &wrapped[..HEADER],
        wrapped[HEADER..].try_into().unwrap(),
    )
    .map_err(|_| refuse!("SEP wrapped per-file key does not open under its class key"))
}
