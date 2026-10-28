//! A boot-scoped cryptographic stream seeded by the platform's entropy source.
use chacha20::ChaCha20Rng;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use rand_core::{SeedableRng, TryRng};
use stela_drivers::entropy::{Entropy, EntropyError};

/// A ChaCha20 stream with a caller-supplied 256-bit entropy seed.
/// The platform owns synchronization and keeps this state for the boot.
pub struct Generator {
    rng: ChaCha20Rng,
    block: [u8; 64],
    used: usize,
}

impl Generator {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
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

/// A shared generator capability. Contention and reentrancy return
/// `Unavailable` before consuming stream bytes or changing the output.
pub struct Source {
    held: AtomicBool,
    generator: UnsafeCell<Generator>,
}

// SAFETY: `held` gives one caller exclusive access to the generator.
unsafe impl Sync for Source {}

impl Source {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            held: AtomicBool::new(false),
            generator: UnsafeCell::new(Generator::from_seed(seed)),
        }
    }
}

struct Held<'a>(&'a Source);
impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

impl Entropy for Source {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError> {
        self.held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| EntropyError::Unavailable)?;
        let _held = Held(self);
        // SAFETY: the exclusive guard holds until generation completes.
        unsafe { &mut *self.generator.get() }.fill(output);
        Ok(())
    }
}

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
    fn a_busy_source_preserves_output_and_stream_position() {
        let source = Source::from_seed([0x71; 32]);
        let mut expected = [0; 32];
        Generator::from_seed([0x71; 32]).fill(&mut expected);
        source.held.store(true, Ordering::Relaxed);
        let mut output = [0xa5; 32];
        assert_eq!(source.fill(&mut output), Err(EntropyError::Unavailable));
        assert_eq!(output, [0xa5; 32]);
        source.held.store(false, Ordering::Relaxed);
        source.fill(&mut output).unwrap();
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
}
