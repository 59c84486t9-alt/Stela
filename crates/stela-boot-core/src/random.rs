//! A boot-scoped cryptographic stream seeded by the platform's entropy source.
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};
use stela_crypto::random::Generator;
use stela_drivers::entropy::{Entropy, EntropyError};

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
}
