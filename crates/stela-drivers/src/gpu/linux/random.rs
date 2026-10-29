//! Seeded CSPRNG state kept by a Linux execution owner.
//! This supplies random bytes, not CPU, IRQ, task or Linux CRNG readiness.
use crate::entropy::{Entropy, EntropyError};
use stela_crypto::random::Generator;
use zeroize::{ZeroizeOnDrop, Zeroizing};

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
    fn post_seed_fills_retain_state_without_source_calls() {
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
