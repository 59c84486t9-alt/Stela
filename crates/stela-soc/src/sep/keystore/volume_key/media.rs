//! Container media keys: the keys APFS encrypts its container keybag with.
//!
//! **Wire.** 26A434 kernel file offsets. `fs_new_media_key` (0x2d4fc70)
//! calls `new_media_key` (0x2d54f8c) with no keybag (handle -1) and class 0;
//! `fs_unwrap_media_key_from_uid` reaches `unwrap_media_key` (0x2d55020).
//! Both send variant 1 and the u64 1 every client request starts with:
//! - NEW_MEDIA_KEY 0x31 (`__ipc_new_media_key_v1` 0x2d5ade4, codec
//!   0x2d43da4): handle, class -> key, IV key, flags, wrapped key.
//! - UNWRAP_MEDIA_KEY 0x32 (`__ipc_unwrap_media_key_v1` 0x2d5b180, codec
//!   0x2d44080): wrapped key, handle, class -> key, IV key, flags.
//!
//! The reply's flags bit 1 makes the kernel set `CP_RAW_KEY_WRAPPEDKEY`
//! (0x2d54ff4) and `_cst_from_rawkey` (0x481bf54) gives the key and IV key to
//! `cpx`. APFS stores the wrapped key in a 40-byte container keybag entry
//! (`_wrapping_key_set` 0x481c090) and unwraps tags 1, 2 and 13 from the UID
//! (`_wrapping_key_get` 0x481caa0); other tags take keybag class keys.
//!
//! **Keys.** The key is the inline engine's wrapped form, so ANS encrypts
//! the keybag blocks with it; there is no IV key. The wrapped key is
//! [`seal_compact`]'s 40 bytes under the machine's volume-key root, bound to
//! the class. Keys under a keybag class refuse.
use super::super::super::Entropy;
use super::super::Fields;
use super::{Reply, VolumeKeys, derive, random};
use crate::Result;
use crate::inline_key::{COMPACT_SEALED_BYTES, open_compact, seal_compact};
use alloc::vec::Vec;
use stela_contracts::refuse;

pub(super) const NEW_MEDIA_KEY: u8 = 0x31;
pub(super) const UNWRAP_MEDIA_KEY: u8 = 0x32;

const VARIANT: u32 = 1;
/// The u64 `new_media_key` and `unwrap_media_key` send first.
const CLIENT: u64 = 1;
/// The handle of a key bound to the device alone.
const NO_KEYBAG: u32 = u32::MAX;
/// Reply flags: the key is SEP-wrapped.
const SEP_WRAPPED: u32 = 1 << 1;
const MEDIA_DOMAIN: &[u8] = b"Stela SEP media key v1\0";

pub(super) fn recognizes(command: u8) -> bool {
    matches!(command, NEW_MEDIA_KEY | UNWRAP_MEDIA_KEY)
}

impl VolumeKeys {
    pub(super) fn media(
        &mut self,
        command: u8,
        variant: u32,
        fields: &mut Fields<'_>,
        entropy: &mut dyn Entropy,
    ) -> Result<Vec<u8>> {
        if variant != VARIANT {
            return Err(refuse!("SEP media-key command variant is not modeled"));
        }
        if fields.lword()? != CLIENT {
            return Err(refuse!(
                "SEP media-key request does not start with the kernel's u64"
            ));
        }
        let mut reply = Reply::default();
        if command == NEW_MEDIA_KEY {
            let class = device_class(fields)?;
            fields.end()?;
            let key = random(entropy)?;
            self.media_key(&mut reply, &key)?;
            reply.blob(&seal_compact(
                &derive(&self.root, MEDIA_DOMAIN, &[]),
                MEDIA_DOMAIN,
                &class.to_le_bytes(),
                &key,
            ));
        } else {
            let wrapped: &[u8; COMPACT_SEALED_BYTES] = fields
                .blob()?
                .try_into()
                .map_err(|_| refuse!("SEP wrapped media key is not 40 bytes"))?;
            let class = device_class(fields)?;
            fields.end()?;
            let key = open_compact(
                &derive(&self.root, MEDIA_DOMAIN, &[]),
                MEDIA_DOMAIN,
                &class.to_le_bytes(),
                wrapped,
            )
            .map_err(|_| {
                refuse!("SEP wrapped media key does not open for this machine and class")
            })?;
            self.media_key(&mut reply, &key)?;
        }
        Ok(reply.0)
    }

    /// The key, its absent IV key and the flags.
    fn media_key(&self, reply: &mut Reply, key: &[u8; 32]) -> Result<()> {
        reply.blob(&self.engine.wrap(key)?);
        reply.blob(&[]);
        reply.word(SEP_WRAPPED);
        Ok(())
    }
}

/// The class of a key bound to the device alone.
fn device_class(fields: &mut Fields<'_>) -> Result<u32> {
    let handle = fields.word()?;
    let class = fields.word()?;
    if handle != NO_KEYBAG {
        return Err(refuse!(
            "SEP media keys under a keybag class need the keystore keybag lifecycle"
        ));
    }
    Ok(class)
}
