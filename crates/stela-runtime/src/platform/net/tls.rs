//! Keep the platform entropy capability behind the protocol provider's trait.
use alloc::sync::Arc;
use stela_drivers::entropy::Entropy;
use stela_tls::{EntropySource, ProviderOwner};

struct OwnedEntropy(Arc<dyn Entropy>);
impl EntropySource for OwnedEntropy {
    fn fill(&self, output: &mut [u8]) -> Result<(), stela_tls::RandomUnavailable> {
        self.0
            .fill(output)
            .map_err(|_| stela_tls::RandomUnavailable)
    }
}

/// The returned owner keeps the original secure source, including its failure
/// and unchanged-output contract. The boot composition must keep this exact
/// owner for its whole provider lifetime; this does not supply time permission.
pub fn provider_owner(entropy: Arc<dyn Entropy>) -> ProviderOwner {
    ProviderOwner::new(Arc::new(OwnedEntropy(entropy)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_drivers::entropy::EntropyError;
    struct Refusing;
    impl Entropy for Refusing {
        fn fill(&self, _: &mut [u8]) -> Result<(), EntropyError> {
            Err(EntropyError::Unavailable)
        }
    }
    #[test]
    fn original_source_is_kept_and_failure_preserves_output() {
        let source: Arc<dyn Entropy> = Arc::new(Refusing);
        let weak = Arc::downgrade(&source);
        let adapter = OwnedEntropy(source.clone());
        let mut bytes = [0xa5; 16];
        assert!(adapter.fill(&mut bytes).is_err());
        assert_eq!(bytes, [0xa5; 16]);
        drop(adapter);
        let owner = provider_owner(source);
        assert!(weak.upgrade().is_some());
        drop(owner);
        assert!(weak.upgrade().is_none());
    }
}
