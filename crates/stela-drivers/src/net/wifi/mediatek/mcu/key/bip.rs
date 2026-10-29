// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Exact MT7925 BIP-CMAC128 batch over an already installed CCMP128 GTK.
//! Wire bytes carry the source GTK index, not an invented IGTK index field.
use super::{Context, Error, Request as DataRequest};
use crate::net::wifi::{
    mediatek::identity::Chip,
    security::{Cipher, KeyIdentity, KeyScope},
};
use zeroize::Zeroize;

/// Sensitive source request. The native owning installer binds both material
/// borrows to its GTK and new management-key operation.
pub struct Request {
    data: DataRequest,
}
impl Request {
    pub fn install(
        chip: Chip,
        context: Context,
        gtk: KeyIdentity,
        gtk_material: &[u8],
        index: u8,
        igtk: &[u8],
    ) -> Result<Self, Error> {
        if chip != Chip::Mt7925 {
            return Err(Error::UnsupportedBip);
        }
        if gtk.cipher() != Cipher::Ccmp128 || !matches!(gtk.scope(), KeyScope::Group(_)) {
            return Err(Error::InvalidBipDataKey);
        }
        if !matches!(index, 4 | 5) {
            return Err(Error::InvalidBipIndex);
        }
        if gtk_material.len() != 16 || igtk.len() != 16 {
            return Err(Error::InvalidKeyLength);
        }
        let mut data = DataRequest::build(chip, context, gtk, Some(gtk_material))?;
        const BIP_CMAC128: u8 = 6;
        data.bytes[23] = BIP_CMAC128;
        data.bytes[25] = 32;
        data.bytes[44..60].copy_from_slice(igtk);
        Ok(Self { data })
    }
    pub fn bytes(&self) -> &[u8] {
        self.data.bytes()
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        self.data.bytes.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        Mac,
        wifi::security::{InstallOutcome, KeySlot, ReplaySeed, TransmitSeed},
    };
    use sha2::{Digest, Sha256};
    #[test]
    fn complete_source_cached_gtk_igtk_batch_and_removal_match_all_request_bytes() {
        let mut hash = Sha256::new();
        for i in 0u16..128 {
            let mut peer = core::array::from_fn(|j| (2 + i * 7 + j as u16) as u8);
            peer[0] &= 0xfe;
            let context = Context {
                bss_index: (i * 13) as u8,
                omac_index: ((i * 7) % 64) as u8,
                station_disabled: (i / 8) % 2 != 0,
            };
            let material: [u8; 16] = core::array::from_fn(|j| (i * 17 + j as u16) as u8);
            let igtk: [u8; 16] = core::array::from_fn(|j| (i * 31 + j as u16) as u8);
            // SAFETY: independent source request model, no physical slot/users.
            let mut slot = unsafe { KeySlot::new((i * 3) % 20) }.unwrap();
            let ticket = slot
                .begin_install(
                    ((i / 2) % 4) as u8,
                    Cipher::Ccmp128,
                    &material,
                    ReplaySeed::ZERO,
                    KeyScope::Group(Mac(peer)),
                    TransmitSeed::RECEIVE_ONLY,
                )
                .unwrap();
            let gtk = DataRequest::install(Chip::Mt7925, context, ticket, &material).unwrap();
            slot.complete_install(ticket, InstallOutcome::Accepted)
                .unwrap();
            let key = slot.installed().unwrap();
            let batch = Request::install(
                Chip::Mt7925,
                context,
                key,
                &material,
                4 + (i % 2) as u8,
                &igtk,
            )
            .unwrap();
            let remove = DataRequest::remove(Chip::Mt7925, context, key).unwrap();
            for (operation, bytes) in [gtk.bytes(), batch.bytes(), remove.bytes()]
                .into_iter()
                .enumerate()
            {
                hash.update([i as u8, operation as u8, bytes.len() as u8]);
                hash.update(bytes);
            }
        }
        assert_eq!(
            alloc::format!("{:x}", hash.finalize()),
            "b0c5eedd5c3889404576c54fca865ff88ddb13b15d6e469122f939d76454ea96"
        );
    }
}
