//! Seeded infallible ChaCha20 streams for retained host owners.
//! Synchronization, true seed acquisition and execution-context ownership
//! belong to the platform that retains the generator, not to this primitive.
use chacha20::ChaCha20Rng;
use rand_core::{SeedableRng, TryRng};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A ChaCha20 stream with a caller-supplied 256-bit entropy seed.
/// The platform owns synchronization and keeps this state for the boot.
pub struct Generator {
    rng: ChaCha20Rng,
    block: [u8; 64],
    used: usize,
}

impl Generator {
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let rng = ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        Self {
            rng,
            block: [0; 64],
            used: 64,
        }
    }

    /// Produce the next bytes from an initialized stream. There is no
    /// fallible source operation after seeding, so a caller can publish the
    /// complete output after this method returns.
    pub fn fill(&mut self, mut output: &mut [u8]) {
        while !output.is_empty() {
            if self.used == self.block.len() {
                match self.rng.try_fill_bytes(&mut self.block) {
                    Ok(()) => {}
                    Err(never) => match never {},
                }
                self.used = 0;
            }
            let take = output.len().min(self.block.len() - self.used);
            let (next, rest) = output.split_at_mut(take);
            next.copy_from_slice(&self.block[self.used..self.used + take]);
            self.block[self.used..self.used + take].fill(0);
            self.used += take;
            output = rest;
        }
    }
}

impl Drop for Generator {
    fn drop(&mut self) {
        // The pinned ChaCha RNG's ZeroizeOnDrop covers its key/state and its
        // internal BlockRng buffer. Erase this wrapper's prefetched bytes too.
        self.block.zeroize();
        self.used.zeroize();
    }
}
impl ZeroizeOnDrop for Generator {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn zero_seed_matches_chacha20_known_answer() {
        // RFC 8439 A.1, test vector 1: zero key, nonce and block counter.
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        let mut generator = Generator::from_seed([0; 32]);
        let mut output = [0; 64];
        generator.fill(&mut output);
        assert_eq!(output, expected);
    }

    #[test]
    fn chunk_boundaries_preserve_the_stream() {
        let mut expected = [0; 256];
        Generator::from_seed([0x39; 32]).fill(&mut expected);
        for split in 0..=expected.len() {
            let mut generator = Generator::from_seed([0x39; 32]);
            let mut output = [0; 256];
            generator.fill(&mut output[..split]);
            generator.fill(&mut output[split..]);
            assert_eq!(output, expected, "split {split}");
        }
    }
    #[test]
    fn both_state_and_prefetch_owners_guarantee_drop_zeroization() {
        fn owns_zeroization<T: ZeroizeOnDrop>() {}
        owns_zeroization::<ChaCha20Rng>();
        owns_zeroization::<Generator>();
    }
}
