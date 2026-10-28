//! Inline AES-XTS keys the SEP installs for the ANS2 NVMMU data path.
//!
//! Apple-silicon Data Protection encrypts the internal SSD with AES-XTS whose
//! keys the SEP owns; `IONVMeFamily` programs them into the NVMe engine
//! through the NVMMU TCB and SPTM's `pmap_iommu_ioctl`
//! (docs/research/sep.md "APFS on non-internal disks"). Presenting the boot
//! disk as the ANS2 internal SSD therefore commits Stela to inline AES-XTS
//! keyed from its own SEP model.
//!
//! This is the **narrow key interface** between Stela's SEP and ANS models:
//! the SEP installs a key into a slot ([`InlineKeys::install`]); the ANS data
//! path transforms a sector with it ([`InlineKeys::transform`]). The crypto is
//! faithful AES-XTS with the data-unit (sector) tweak as the kernel and SPTM
//! set it up: the tweak is the 16-byte little-endian sector number encrypted
//! under the second key, advanced by the XTS GF(2^128) doubling per 16-byte
//! block. Sector lengths are a multiple of the block, so no ciphertext
//! stealing is needed; a non-multiple length refuses.
//!
//! Open gate: how the NVMMU TCB key area (bytes 0x40..) names the slot or
//! carries the wrapped key is part of the SEP crypto contract that is not yet
//! recovered (docs/research/ans2.md "Refusals and encryption"), and the SEP
//! install path itself rides the unrecovered `sks` service. Until both are
//! recovered no key is installed, so the ANS key path still refuses; this
//! module is the interface and the verified cipher they will use.
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use alloc::collections::BTreeMap;
use stela_crypto::{Aes128, Aes256};
use zeroize::{Zeroize, Zeroizing};

const BLOCK: usize = 16;

/// One inline volume key: an AES-XTS key pair (data key, tweak key).
pub enum InlineKey {
    /// AES-128-XTS: a 32-byte key (two 16-byte keys).
    Aes128(Zeroizing<[u8; 32]>),
    /// AES-256-XTS: a 64-byte key (two 32-byte keys).
    Aes256(Zeroizing<[u8; 64]>),
}

impl InlineKey {
    /// Encrypt (`encrypt`) or decrypt a sector in place with this key and the
    /// data-unit number `sector`. The length must be a nonzero multiple of the
    /// 16-byte block.
    fn transform(&self, sector: u64, data: &mut [u8], encrypt: bool) -> Result<(), &'static str> {
        if data.is_empty() || !data.len().is_multiple_of(BLOCK) {
            return Err("AES-XTS sector length is not a multiple of the 16-byte block");
        }
        match self {
            InlineKey::Aes128(key) => {
                let (k1, k2) = key.split_at(16);
                xts::<Aes128>(k1, k2, sector, data, encrypt)
            }
            InlineKey::Aes256(key) => {
                let (k1, k2) = key.split_at(32);
                xts::<Aes256>(k1, k2, sector, data, encrypt)
            }
        }
    }
}

/// Advance the XTS tweak by one block: multiply by the primitive element in
/// GF(2^128), little-endian, reducing with x^128 + x^7 + x^2 + x + 1 (0x87).
fn double_tweak(tweak: &mut [u8; BLOCK]) {
    let mut carry = 0u8;
    for byte in tweak.iter_mut() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        tweak[0] ^= 0x87;
    }
}

fn xts<C: BlockEncrypt<BlockSize = aes::cipher::consts::U16> + BlockDecrypt + KeyInit>(
    data_key: &[u8],
    tweak_key: &[u8],
    sector: u64,
    data: &mut [u8],
    encrypt: bool,
) -> Result<(), &'static str> {
    let data_cipher =
        C::new_from_slice(data_key).map_err(|_| "AES-XTS data key length is invalid")?;
    let tweak_cipher =
        C::new_from_slice(tweak_key).map_err(|_| "AES-XTS tweak key length is invalid")?;
    // The tweak starts as the 16-byte little-endian sector number encrypted
    // under the tweak key.
    let mut tweak = [0u8; BLOCK];
    tweak[..8].copy_from_slice(&sector.to_le_bytes());
    let mut block = GenericArray::clone_from_slice(&tweak);
    tweak_cipher.encrypt_block(&mut block);
    tweak.copy_from_slice(&block);
    let mut blocks: [aes::cipher::Block<C>; 8] = core::array::from_fn(|_| Default::default());
    let mut masks = [[0u8; BLOCK]; 8];
    let (chunks, _) = data.as_chunks_mut::<BLOCK>();
    for group in chunks.chunks_mut(8) {
        for (index, chunk) in group.iter().enumerate() {
            masks[index] = tweak;
            for ((byte, plain), mask) in blocks[index].iter_mut().zip(chunk.iter()).zip(tweak) {
                *byte = *plain ^ mask;
            }
            double_tweak(&mut tweak);
        }
        if encrypt {
            data_cipher.encrypt_blocks(&mut blocks[..group.len()]);
        } else {
            data_cipher.decrypt_blocks(&mut blocks[..group.len()]);
        }
        for (index, chunk) in group.iter_mut().enumerate() {
            for ((byte, cipher), mask) in chunk.iter_mut().zip(blocks[index]).zip(masks[index]) {
                *byte = cipher ^ mask;
            }
        }
    }
    // Decryption batches can retain plaintext and key-derived tweak masks.
    // Erase them before releasing this invocation's stack frame.
    for block in &mut blocks {
        block.as_mut_slice().zeroize();
    }
    masks.zeroize();
    tweak.zeroize();
    Ok(())
}

/// The inline-key slots the SEP installs and the ANS path reads. A slot holds
/// at most one key; installing replaces it, and an Erase Install or a volume
/// teardown clears it.
#[derive(Default)]
pub struct InlineKeys {
    slots: BTreeMap<u32, InlineKey>,
}

impl InlineKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install (or replace) the key in `slot`.
    pub fn install(&mut self, slot: u32, key: InlineKey) {
        self.slots.insert(slot, key);
    }

    /// Remove a slot's key, if present.
    pub fn remove(&mut self, slot: u32) {
        self.slots.remove(&slot);
    }

    /// Clear every slot (Erase Install / full teardown).
    pub fn clear(&mut self) {
        self.slots.clear();
    }

    /// Whether `slot` holds a key.
    pub fn contains(&self, slot: u32) -> bool {
        self.slots.contains_key(&slot)
    }

    /// Transform `data` (one sector, a block multiple) for `slot` with the
    /// data-unit number `sector`. Refuses when the slot holds no key, so a
    /// referenced-but-uninstalled key never silently passes data in the clear.
    pub fn transform(
        &self,
        slot: u32,
        sector: u64,
        data: &mut [u8],
        encrypt: bool,
    ) -> Result<(), &'static str> {
        self.slots
            .get(&slot)
            .ok_or("ANS inline key slot holds no SEP-installed key")?
            .transform(sector, data, encrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key128() -> InlineKey {
        let mut key = [0u8; 32];
        for (n, byte) in key.iter_mut().enumerate() {
            *byte = n as u8;
        }
        InlineKey::Aes128(Zeroizing::new(key))
    }

    #[test]
    fn xts_batches_match_scalar_sector_transforms() {
        let data_key = [0x51; 16];
        let tweak_key = [0xc3; 16];
        for count in [1usize, 7, 8, 9, 31, 32, 33, 256] {
            for sector in [0u64, 1, u64::MAX] {
                let plain: alloc::vec::Vec<u8> = (0..count * BLOCK)
                    .map(|i| i.wrapping_mul(71) as u8)
                    .collect();
                let mut scalar = plain.clone();
                let cipher = aes::Aes128::new_from_slice(&data_key).unwrap();
                let tweak_cipher = aes::Aes128::new_from_slice(&tweak_key).unwrap();
                let mut tweak = [0; BLOCK];
                tweak[..8].copy_from_slice(&sector.to_le_bytes());
                tweak_cipher.encrypt_block(GenericArray::from_mut_slice(&mut tweak));
                for chunk in scalar.as_chunks_mut::<BLOCK>().0 {
                    for (byte, mask) in chunk.iter_mut().zip(tweak) {
                        *byte ^= mask;
                    }
                    cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
                    for (byte, mask) in chunk.iter_mut().zip(tweak) {
                        *byte ^= mask;
                    }
                    double_tweak(&mut tweak);
                }
                let mut batched = plain.clone();
                xts::<Aes128>(&data_key, &tweak_key, sector, &mut batched, true).unwrap();
                assert_eq!(batched, scalar, "blocks={count} sector={sector}");
                xts::<Aes128>(&data_key, &tweak_key, sector, &mut batched, false).unwrap();
                assert_eq!(batched, plain);
            }
        }
    }

    #[test]
    fn aes_128_xts_matches_the_openssl_known_answer() {
        // Independent OpenSSL `enc -aes-128-xts` vector: key1 = 00..0f,
        // key2 = 10..1f, data-unit (sector) 1.
        let plaintext =
            hex::decode("00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f")
                .unwrap();
        let expected =
            hex::decode("ac0f5a931d555f32c189b35891efcc1cc2d233fcd8fd7993beaf5fa1f05885bb")
                .unwrap();
        let mut data = plaintext.clone();
        key128().transform(1, &mut data, true).unwrap();
        assert_eq!(data, expected);
        // Decryption is the inverse.
        key128().transform(1, &mut data, false).unwrap();
        assert_eq!(data, plaintext);
    }

    #[test]
    fn the_tweak_depends_on_the_sector_and_spans_many_blocks() {
        let plaintext = [0x5au8; 64];
        let mut a = plaintext;
        let mut b = plaintext;
        key128().transform(1, &mut a, true).unwrap();
        key128().transform(2, &mut b, true).unwrap();
        // A different sector gives different ciphertext for the same data.
        assert_ne!(a, b);
        // Each 16-byte block differs (the tweak advances), and decrypts back.
        assert_ne!(a[..16], a[16..32]);
        key128().transform(1, &mut a, false).unwrap();
        assert_eq!(a, plaintext);
    }

    #[test]
    fn aes_256_xts_round_trips_and_a_wrong_key_does_not() {
        let key = InlineKey::Aes256(Zeroizing::new([9u8; 64]));
        let other = InlineKey::Aes256(Zeroizing::new([8u8; 64]));
        let plaintext = [0xa5u8; 512];
        let mut data = plaintext;
        key.transform(7, &mut data, true).unwrap();
        assert_ne!(data, plaintext);
        // The wrong key does not recover the plaintext.
        let mut wrong = data;
        other.transform(7, &mut wrong, false).unwrap();
        assert_ne!(wrong, plaintext);
        key.transform(7, &mut data, false).unwrap();
        assert_eq!(data, plaintext);
    }

    #[test]
    fn slots_install_lookup_and_refuse_when_empty() {
        let mut keys = InlineKeys::new();
        let mut data = [0u8; 32];
        assert!(keys.transform(3, 0, &mut data, true).is_err());
        keys.install(3, key128());
        assert!(keys.contains(3));
        assert!(keys.transform(3, 0, &mut data, true).is_ok());
        // A non-block length refuses.
        let mut short = [0u8; 20];
        assert!(keys.transform(3, 0, &mut short, true).is_err());
        keys.remove(3);
        assert!(!keys.contains(3));
        assert!(keys.transform(3, 0, &mut data, false).is_err());
    }
}
