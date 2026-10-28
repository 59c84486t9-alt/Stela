//! AES ciphers with RustCrypto's block API and a zeroizing hardware schedule.
use ::aes::cipher::{
    BlockBackend, BlockCipher, BlockClosure, BlockDecrypt, BlockEncrypt, BlockSizeUser, Key,
    KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U8, U16, U24, U32},
    inout::InOut,
};
#[cfg(target_arch = "x86_64")]
use zeroize::Zeroizing;

#[cfg(target_arch = "x86_64")]
#[derive(Clone)]
struct Schedule {
    enc: Zeroizing<[u8; 240]>,
    dec: Zeroizing<[u8; 240]>,
    rounds: usize,
}
#[cfg(target_arch = "x86_64")]
impl Schedule {
    fn new(key: &[u8]) -> Option<Self> {
        if !super::x86_64::aes_usable() {
            return None;
        }
        let nk = key.len() / 4;
        let rounds = nk + 6;
        let count = 4 * (rounds + 1);
        let mut words = Zeroizing::new([0u32; 60]);
        for (word, bytes) in words.iter_mut().zip(key.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let mut rcon = 1u8;
        for i in nk..count {
            let mut word = words[i - 1];
            if i % nk == 0 {
                // SAFETY: AES and SSE controls were checked above. This is
                // FIPS 197 KEYEXPANSION's RotWord/SubWord/Rcon step.
                word = unsafe { super::x86_64::aes_sub_word(word, true) } ^ u32::from(rcon);
                rcon = (rcon << 1) ^ (0x1b & 0u8.wrapping_sub(rcon >> 7));
            } else if nk == 8 && i % nk == 4 {
                // SAFETY: the same checked AES backend, without RotWord.
                word = unsafe { super::x86_64::aes_sub_word(word, false) };
            }
            words[i] = words[i - nk] ^ word;
        }
        let mut enc = Zeroizing::new([0u8; 240]);
        let mut dec = Zeroizing::new([0u8; 240]);
        for (bytes, word) in enc
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(words.iter())
            .take(count)
        {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        for i in 0..=rounds {
            dec[i * 16..i * 16 + 16]
                .copy_from_slice(&enc[(rounds - i) * 16..(rounds - i + 1) * 16]);
        }
        // SAFETY: the middle round keys are writable complete blocks and
        // AES/SSE controls were checked; AESDEC takes inverse-mixed keys.
        unsafe { super::x86_64::aes_inverse_keys(dec.as_mut_ptr().add(16), rounds - 1) };
        Some(Self { enc, dec, rounds })
    }
}

#[cfg(target_arch = "x86_64")]
struct Backend<'a> {
    schedule: &'a Schedule,
    encrypt: bool,
}
#[cfg(target_arch = "x86_64")]
impl BlockSizeUser for Backend<'_> {
    type BlockSize = U16;
}
#[cfg(target_arch = "x86_64")]
impl ParBlocksSizeUser for Backend<'_> {
    type ParBlocksSize = U8;
}
#[cfg(target_arch = "x86_64")]
impl BlockBackend for Backend<'_> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, ::aes::cipher::Block<Self>>) {
        let input = block.get_in().as_ptr();
        let output = block.get_out().as_mut_ptr();
        // SAFETY: BlockBackend's input and output are valid 16-byte blocks,
        // disjoint or identical; the cipher selected this usable backend.
        unsafe { self.run(input, output, 1) };
    }
    fn proc_par_blocks(&mut self, mut blocks: InOut<'_, '_, ::aes::cipher::ParBlocks<Self>>) {
        let input = blocks.get_in().as_ptr().cast();
        let output = blocks.get_out().as_mut_ptr().cast();
        // SAFETY: eight complete input/output blocks from the cipher API.
        unsafe { self.run(input, output, 8) };
    }
}
#[cfg(target_arch = "x86_64")]
impl Backend<'_> {
    unsafe fn run(&self, input: *const u8, output: *mut u8, count: usize) {
        if self.encrypt {
            // SAFETY: the caller provides the extents and qualified AES backend.
            unsafe {
                super::x86_64::aes_encrypt(
                    self.schedule.enc.as_ptr(),
                    input,
                    output,
                    count,
                    self.schedule.rounds,
                )
            };
        } else {
            // SAFETY: same extents, with the inverse-mixed decryption schedule.
            unsafe {
                super::x86_64::aes_decrypt(
                    self.schedule.dec.as_ptr(),
                    input,
                    output,
                    count,
                    self.schedule.rounds,
                )
            };
        }
    }
}

macro_rules! cipher {
    ($name:ident, $size:ty, $soft:ty, $bytes:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            soft: Option<$soft>,
            #[cfg(target_arch = "x86_64")]
            hardware: Option<(Schedule, Zeroizing<[u8; $bytes]>)>,
        }
        impl KeySizeUser for $name {
            type KeySize = $size;
        }
        impl BlockSizeUser for $name {
            type BlockSize = U16;
        }
        impl BlockCipher for $name {}
        impl KeyInit for $name {
            fn new(key: &Key<Self>) -> Self {
                #[cfg(target_arch = "x86_64")]
                if let Some(schedule) = Schedule::new(key) {
                    // Keep only the protected original key for a later CPU/OS
                    // fallback, rather than eagerly expanding a second cipher
                    // schedule for every sector on the hardware path.
                    return Self {
                        soft: None,
                        hardware: Some((
                            schedule,
                            Zeroizing::new(
                                key.as_slice()
                                    .try_into()
                                    .expect("AES key has its declared fixed size"),
                            ),
                        )),
                    };
                }
                Self {
                    soft: Some(<$soft>::new(key)),
                    #[cfg(target_arch = "x86_64")]
                    hardware: None,
                }
            }
        }
        impl BlockEncrypt for $name {
            fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                #[cfg(target_arch = "x86_64")]
                if let Some((schedule, _)) = self
                    .hardware
                    .as_ref()
                    .filter(|_| super::x86_64::aes_usable())
                {
                    f.call(&mut Backend {
                        schedule,
                        encrypt: true,
                    });
                    return;
                }
                if let Some(soft) = &self.soft {
                    soft.encrypt_with_backend(f);
                    return;
                }
                #[cfg(target_arch = "x86_64")]
                if let Some((_, key)) = &self.hardware {
                    <$soft>::new(Key::<Self>::from_slice(key.as_ref())).encrypt_with_backend(f);
                }
            }
        }
        impl BlockDecrypt for $name {
            fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = U16>) {
                #[cfg(target_arch = "x86_64")]
                if let Some((schedule, _)) = self
                    .hardware
                    .as_ref()
                    .filter(|_| super::x86_64::aes_usable())
                {
                    f.call(&mut Backend {
                        schedule,
                        encrypt: false,
                    });
                    return;
                }
                if let Some(soft) = &self.soft {
                    soft.decrypt_with_backend(f);
                    return;
                }
                #[cfg(target_arch = "x86_64")]
                if let Some((_, key)) = &self.hardware {
                    <$soft>::new(Key::<Self>::from_slice(key.as_ref())).decrypt_with_backend(f);
                }
            }
        }
    };
}
cipher!(
    Aes128,
    U16,
    ::aes::Aes128,
    16,
    "AES-128 with the host's usable backend."
);
cipher!(
    Aes192,
    U24,
    ::aes::Aes192,
    24,
    "AES-192 with the host's usable backend."
);
cipher!(
    Aes256,
    U32,
    ::aes::Aes256,
    32,
    "AES-256 with the host's usable backend."
);
