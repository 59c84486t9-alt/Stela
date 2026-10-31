//! Keychain item keys: what `kc_wrap_data` protects for a client.
//!
//! **Wire.** 26A434 kernel file offsets. Both commands send variant 0, and a
//! u64, a keybag handle, a class, a blob and a u32 the reply gives back:
//! - KC_WRAP 0x08 (`__ipc_kc_wrap` 0x2d58c44, codec 0x2d3dffc): the key ->
//!   wrapped key, the u32.
//! - KC_UNWRAP 0x45 (`__ipc_kc_unwrap` 0x2d5c3bc, codec 0x2d46b5c): the
//!   wrapped key -> key, a blob this model leaves empty, the u32.
//!
//! **Keys.** A key is 32 bytes and its wrapped form [`seal_compact`]'s 40,
//! the sizes `aks_wrap_key` gives item keys, under a key of the machine's
//! volume-key root bound to the class. The keybag named is not interpreted, so
//! one keybag opens what another wrapped, and no class is ever locked.
use super::super::Fields;
use super::{Reply, VolumeKeys, derive};
use crate::Result;
use crate::inline_key::{COMPACT_SEALED_BYTES, KEY_BYTES, open_compact, seal_compact};
use alloc::{string::String, vec::Vec};
use stela_contracts::refuse;

pub(super) const KC_WRAP: u8 = 0x08;
pub(super) const KC_UNWRAP: u8 = 0x45;

const VARIANT: u32 = 0;
const KEYCHAIN_DOMAIN: &[u8] = b"Stela SEP keychain key v1\0";
const UNBOUND: &str = "SEP keychain keys: keybag handles are not interpreted, \
     and no class is ever locked";

pub(super) fn recognizes(command: u8) -> bool {
    matches!(command, KC_WRAP | KC_UNWRAP)
}

impl VolumeKeys {
    pub(super) fn keychain(
        &mut self,
        command: u8,
        variant: u32,
        fields: &mut Fields<'_>,
        notes: &mut dyn FnMut(String),
    ) -> Result<Vec<u8>> {
        if variant != VARIANT {
            return Err(refuse!("SEP keychain command variant is not modeled"));
        }
        let _client = fields.lword()?;
        let _keybag = fields.word()?;
        let class = fields.word()?.to_le_bytes();
        let blob = fields.blob()?;
        let carried = fields.word()?;
        fields.end()?;
        let wrapping = derive(&self.root, KEYCHAIN_DOMAIN, &class);
        let mut reply = Reply::default();
        if command == KC_WRAP {
            let key: &[u8; KEY_BYTES] = blob
                .try_into()
                .map_err(|_| refuse!("SEP keychain key is not 32 bytes"))?;
            reply.blob(&seal_compact(&wrapping, KEYCHAIN_DOMAIN, &class, key));
        } else {
            let wrapped: &[u8; COMPACT_SEALED_BYTES] = blob
                .try_into()
                .map_err(|_| refuse!("SEP wrapped keychain key is not 40 bytes"))?;
            let key = open_compact(&wrapping, KEYCHAIN_DOMAIN, &class, wrapped)
                .map_err(|_| refuse!("SEP wrapped keychain key does not open"))?;
            reply.blob(key.as_slice());
            reply.blob(&[]);
        }
        reply.word(carried);
        self.report(UNBOUND, notes);
        Ok(reply.0)
    }
}
