//! The inline AES-XTS engine between Stela's SEP and ANS models.
//!
//! Apple-silicon Data Protection encrypts the internal SSD in line, with
//! AES-XTS volume keys only the SEP can unwrap
//! (docs/research/sep.md "APFS on non-internal disks"). APFS keeps each
//! volume key SEP-wrapped, has the keystore's FileVault commands hand it an
//! inline-wrapped form, and marks that key `cpx_is_sep_wrapped_key`;
//! creating a volume on hardware crypto panics without the mark ("HW CRYPTO:
//! [create]: CP_RAW_KEY_WRAPPEDKEY is NOT set"). For each I/O,
//! `IONVMeBlockStorageDevice::doAsyncReadWrite` (0x3dedbbc) gives
//! `AppleNVMeRequest::BuildCommandReadWriteStruct` (0x3deba30) the key and
//! the data-unit number `(offset + cpx IV offset) >> 12`, one per 4 KiB.
//! That sets CDW0 bits 11:10 to 1 for a wrapped key (2 for a raw one), puts
//! the data-unit number in CDW14..15 and fills the request's 64-byte key
//! area: a wrapped key must be 64 bytes, whose first word lands at area 0
//! and bytes 16..64 at area 16..64 (area 4..16 stays zero); a raw key must
//! be 32 bytes and lands at area 32..64. CG v2's TCB entry (0x3de4b18)
//! copies the area to TCB 0x40, and SPTM's MAP_PAGES (`270c8130`) copies
//! the whole image into the NVMMU TCB with CDW0 bits 12:8 in byte 1.
//!
//! The engine is Stela's. The SEP provisions a fresh wrapping key at every
//! sepOS start ([`Engine::provision`]) and wraps volume keys for the AP
//! ([`Engine::wrap`]); ANS unwraps a TCB key area ([`Engine::unwrap`]) and
//! transforms each data unit ([`InlineKey::transform`]). The wrapped form is
//! a deterministic authenticated encryption (SIV over HMAC-SHA256,
//! [`seal`]), not Apple's hardware format. As with the hardware's wrapped
//! keys, nothing persists it: the AP asks the SEP again after each boot.
use crate::Result;
use alloc::rc::Rc;
use core::cell::RefCell;
use hmac::{Hmac, Mac};
use stela_contracts::refuse;
use stela_crypto::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};
use stela_crypto::{Aes128, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// The NVMMU TCB key area and the wrapped key the AP carries in it.
pub const KEY_AREA_BYTES: usize = 64;
/// One XTS data unit: the data-unit number counts 4 KiB.
pub const DATA_UNIT_BYTES: usize = 4096;
/// CDW0 bits 11:10 (TCB byte 1 bits 3:2): the key area holds a wrapped key.
pub const WRAPPED: u8 = 1;
/// CDW0 bits 11:10: the key area holds a raw 32-byte key at 32..64.
pub const RAW: u8 = 2;
/// An AES-128-XTS key: the data key, then the tweak key.
pub const KEY_BYTES: usize = 32;
/// A sealed key: its synthetic IV (tag), then the encrypted key.
pub const SEALED_BYTES: usize = TAG_BYTES + KEY_BYTES;

const BLOCK: usize = 16;
const TAG_BYTES: usize = 16;
/// "Stela inline key", format 1: AES-128-XTS sealed under the boot's key.
const HEADER: [u8; 4] = [b'S', b'I', b'K', 1];
const CARRIED: usize = 16;
const INLINE_DOMAIN: &[u8] = b"Stela inline key v1\0";
const TAG_DOMAIN: &[u8] = b"Stela SIV tag v1\0";
const PAD_DOMAIN: &[u8] = b"Stela SIV pad v1\0";

/// Seal `key` under `wrapping`, bound to `domain` and `aad`: a synthetic IV
/// over all three, then `key` encrypted with a pad derived from the IV.
/// Deterministic: the same inputs give the same sealed bytes.
pub fn seal(
    wrapping: &[u8; 32],
    domain: &[u8],
    aad: &[u8],
    key: &[u8; KEY_BYTES],
) -> [u8; SEALED_BYTES] {
    let tag = synthetic_iv(wrapping, domain, aad, key);
    let mut sealed = [0; SEALED_BYTES];
    sealed[..TAG_BYTES].copy_from_slice(&tag);
    let pad = pad(wrapping, &tag);
    for ((out, byte), mask) in sealed[TAG_BYTES..].iter_mut().zip(key).zip(pad.iter()) {
        *out = byte ^ mask;
    }
    sealed
}

/// Open what [`seal`] sealed with the same `wrapping`, `domain` and `aad`.
pub fn open(
    wrapping: &[u8; 32],
    domain: &[u8],
    aad: &[u8],
    sealed: &[u8; SEALED_BYTES],
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    let (tag, encrypted) = sealed.split_at(TAG_BYTES);
    let pad = pad(wrapping, tag);
    let mut key = Zeroizing::new([0; KEY_BYTES]);
    for ((out, byte), mask) in key.iter_mut().zip(encrypted).zip(pad.iter()) {
        *out = byte ^ mask;
    }
    let mut mac = tag_mac(wrapping, domain, aad);
    mac.update(&*key);
    mac.verify_truncated_left(tag)
        .map_err(|_| refuse!("sealed key does not authenticate under this key"))?;
    Ok(key)
}

fn tag_mac(wrapping: &[u8; 32], domain: &[u8], aad: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(wrapping).expect("HMAC accepts 256-bit keys");
    mac.update(TAG_DOMAIN);
    mac.update(&(domain.len() as u32).to_le_bytes());
    mac.update(domain);
    mac.update(&(aad.len() as u32).to_le_bytes());
    mac.update(aad);
    mac
}

fn synthetic_iv(
    wrapping: &[u8; 32],
    domain: &[u8],
    aad: &[u8],
    key: &[u8; KEY_BYTES],
) -> [u8; TAG_BYTES] {
    let mut mac = tag_mac(wrapping, domain, aad);
    mac.update(key);
    mac.finalize().into_bytes()[..TAG_BYTES].try_into().unwrap()
}

fn pad(wrapping: &[u8; 32], tag: &[u8]) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(wrapping).expect("HMAC accepts 256-bit keys");
    mac.update(PAD_DOMAIN);
    mac.update(tag);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// One inline volume key: AES-128-XTS, the only width a 64-byte wrapped key
/// or a 32-byte raw key carries.
pub struct InlineKey(Zeroizing<[u8; KEY_BYTES]>);

impl InlineKey {
    /// A raw key area (mode [`RAW`]): the key at 32..64, zeros before it.
    pub fn raw(area: &[u8; KEY_AREA_BYTES]) -> Result<Self> {
        if area[..KEY_AREA_BYTES - KEY_BYTES]
            .iter()
            .any(|&byte| byte != 0)
        {
            return Err(refuse!("ANS raw inline key area has bytes before its key"));
        }
        Ok(Self(Zeroizing::new(
            area[KEY_AREA_BYTES - KEY_BYTES..].try_into().unwrap(),
        )))
    }

    /// Encrypt (`encrypt`) or decrypt `data` in place, a whole number of
    /// data units, the first of which is data-unit `unit`.
    pub fn transform(&self, unit: u64, data: &mut [u8], encrypt: bool) -> Result<()> {
        if data.is_empty() || !data.len().is_multiple_of(DATA_UNIT_BYTES) {
            return Err(refuse!(
                "inline AES-XTS data is not a whole number of 4 KiB data units"
            ));
        }
        let (data_key, tweak_key) = self.0.split_at(BLOCK);
        let data_cipher = Aes128::new_from_slice(data_key).expect("16-byte AES-128 key");
        let tweak_cipher = Aes128::new_from_slice(tweak_key).expect("16-byte AES-128 key");
        let (units, _) = data.as_chunks_mut::<DATA_UNIT_BYTES>();
        for (index, chunk) in units.iter_mut().enumerate() {
            xts(
                &data_cipher,
                &tweak_cipher,
                unit.wrapping_add(index as u64),
                chunk,
                encrypt,
            );
        }
        Ok(())
    }
}

/// The boot's wrapping key, shared by the SEP that provisions it and ANS,
/// which unwraps the keys the SEP wrapped with it.
#[derive(Clone, Default)]
pub struct Engine(Rc<RefCell<Option<Zeroizing<[u8; 32]>>>>);

impl Engine {
    /// Install the wrapping key sepOS chose at this start, replacing the
    /// previous boot's: keys wrapped under that one no longer unwrap.
    pub fn provision(&self, key: Zeroizing<[u8; 32]>) {
        *self.0.borrow_mut() = Some(key);
    }

    /// The 64-byte wrapped form of `key` the AP carries to the key area.
    pub fn wrap(&self, key: &[u8; KEY_BYTES]) -> Result<[u8; KEY_AREA_BYTES]> {
        let wrapping = self.0.borrow();
        let wrapping = wrapping
            .as_ref()
            .ok_or(refuse!("the SEP has not provisioned the inline key engine"))?;
        let mut area = [0; KEY_AREA_BYTES];
        area[..HEADER.len()].copy_from_slice(&HEADER);
        area[CARRIED..].copy_from_slice(&seal(wrapping, INLINE_DOMAIN, &HEADER, key));
        Ok(area)
    }

    /// Unwrap a key area (mode [`WRAPPED`]) the AP filled from [`wrap`].
    ///
    /// [`wrap`]: Self::wrap
    pub fn unwrap(&self, area: &[u8; KEY_AREA_BYTES]) -> Result<InlineKey> {
        if area[..HEADER.len()] != HEADER || area[HEADER.len()..CARRIED].iter().any(|&b| b != 0) {
            return Err(refuse!(
                "ANS wrapped inline key area is not a Stela inline-wrapped key"
            ));
        }
        let wrapping = self.0.borrow();
        let wrapping = wrapping
            .as_ref()
            .ok_or(refuse!("the SEP has not provisioned the inline key engine"))?;
        let sealed = area[CARRIED..].try_into().unwrap();
        Ok(InlineKey(open(wrapping, INLINE_DOMAIN, &HEADER, sealed)?))
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

/// One data unit: the tweak starts as the 16-byte little-endian unit number
/// encrypted under the tweak key and doubles per block. Units are block
/// multiples, so no ciphertext stealing is needed.
fn xts(data_cipher: &Aes128, tweak_cipher: &Aes128, unit: u64, data: &mut [u8], encrypt: bool) {
    let mut tweak = [0u8; BLOCK];
    tweak[..8].copy_from_slice(&unit.to_le_bytes());
    tweak_cipher.encrypt_block(GenericArray::from_mut_slice(&mut tweak));
    let mut blocks: [stela_crypto::cipher::Block<Aes128>; 8] = Default::default();
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
    // Decryption batches can keep plaintext and key-derived tweak masks.
    // Erase them before releasing this invocation's stack frame.
    for block in &mut blocks {
        block.as_mut_slice().zeroize();
    }
    masks.zeroize();
    tweak.zeroize();
}

#[cfg(test)]
mod tests;
