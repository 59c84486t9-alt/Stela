//! Seeded CSPRNG state kept by a Linux execution owner.
//! This supplies random bytes, not CPU, IRQ, task or Linux CRNG readiness.
use stela_crypto::random::Generator;
use stela_driver_base::entropy::{Entropy, EntropyError};
use zeroize::{ZeroizeOnDrop, Zeroizing};

unsafe extern "C" {
    fn stela_linux_random_mix_key(
        key: *const u8,
        ticks: u64,
        bytes: *const u8,
        size: usize,
        seed: *mut u8,
    );
}

/// An owned stream created only after the platform supplied its secure seed.
/// Construction belongs before kernel registration. The eventual owner keeps
/// this value private and supplies IRQ-safe, non-migrating serialization
/// before calling it through the common C random callback. This type alone
/// grants no native execution permission.
pub struct Seeded {
    generator: Generator,
}
impl Seeded {
    pub fn from_entropy(source: &dyn Entropy) -> Result<Self, EntropyError> {
        let mut seed = Zeroizing::new([0; 32]);
        source.fill(seed.as_mut())?;
        Ok(Self {
            generator: Generator::from_seed(*seed),
        })
    }

    /// Advance this owner's infallible stream without consulting a fallible
    /// provider, allocating or waiting. Exclusive access remains the owner's.
    pub fn fill(&mut self, output: &mut [u8]) {
        self.generator.fill(output);
    }

    /// Rekey the stream with auxiliary input. The keyed digest consumes
    /// private bytes from the prior stream and credits no additional entropy.
    pub fn mix(&mut self, ticks: u64, bytes: &[u8]) {
        let mut key = Zeroizing::new([0; 32]);
        let mut seed = Zeroizing::new([0; 32]);
        self.generator.fill(key.as_mut());
        // SAFETY: the pure BLAKE2s helper reads the fixed key and input slice,
        // writes exactly 32 seed bytes and retains no pointers.
        unsafe {
            stela_linux_random_mix_key(
                key.as_ptr(),
                ticks,
                bytes.as_ptr(),
                bytes.len(),
                seed.as_mut_ptr(),
            );
        }
        self.generator = Generator::from_seed(*seed);
    }
}
impl ZeroizeOnDrop for Seeded {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct Reject {
        error: EntropyError,
        calls: AtomicUsize,
    }
    impl Entropy for Reject {
        fn fill(&self, _: &mut [u8]) -> Result<(), EntropyError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(self.error)
        }
    }

    #[test]
    fn unavailable_and_failed_sources_mint_no_stream() {
        for error in [EntropyError::Unavailable, EntropyError::Failed] {
            let source = Reject {
                error,
                calls: AtomicUsize::new(0),
            };
            assert!(matches!(Seeded::from_entropy(&source), Err(actual) if actual == error));
            assert_eq!(source.calls.load(Ordering::Relaxed), 1);
        }
    }

    // Deterministic seed fixture: tests one-shot ownership, not entropy quality.
    struct Once(AtomicUsize);
    impl Entropy for Once {
        fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError> {
            assert_eq!(self.0.fetch_add(1, Ordering::Relaxed), 0);
            assert_eq!(output.len(), 32);
            output.fill(0x93);
            Ok(())
        }
    }

    #[test]
    fn device_input_rekeys_the_seeded_stream() {
        let mut stream = Seeded {
            generator: Generator::from_seed([0; 32]),
        };
        stream.mix(7, b"device input");
        let mut actual = [0; 64];
        stream.fill(&mut actual);
        let mut expected = [0; 64];
        Generator::from_seed([
            0x48, 0x81, 0x02, 0x98, 0x6d, 0xdf, 0xdb, 0x7a, 0x93, 0xee, 0xcb, 0xf6, 0xc7, 0x17,
            0xfb, 0x3d, 0x89, 0x01, 0xfe, 0x84, 0xba, 0x21, 0x59, 0xef, 0x8e, 0x8b, 0xdf, 0x18,
            0x98, 0x24, 0x73, 0x5a,
        ])
        .fill(&mut expected);
        assert_eq!(actual, expected);
    }

    #[test]
    fn post_seed_fills_keep_state_without_source_calls() {
        let mut stream = {
            let source = Once(AtomicUsize::new(0));
            let stream = Seeded::from_entropy(&source).unwrap();
            assert_eq!(source.0.load(Ordering::Relaxed), 1);
            stream
        };
        let mut expected = [0; 4097];
        Generator::from_seed([0x93; 32]).fill(&mut expected);
        let mut actual = [0; 4097];
        stream.fill(&mut actual[..1]);
        stream.fill(&mut actual[1..63]);
        stream.fill(&mut actual[63..]);
        assert_eq!(actual, expected);
        fn zeroizes<T: ZeroizeOnDrop>() {}
        zeroizes::<Seeded>();
    }
}
