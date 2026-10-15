//! Canonical instruction-PAuth two-modifier primitive over one supplied Context.
//!
//! This leaf grants no CPU feature or instruction authority. Callers must bind
//! original operands/source, address space, keys and actual PAuth_LR controls.
//! Explicit forms always supply two modifiers; old conditional forms require
//! the CPU owner's PACM decision. BTI/GCS and all state commits remain outside.
//! The selected QARMA5 Context retains VA47/instruction-TBI-off pointer policy.

use super::{AuthResult, AuthenticationError, Context, Key, Version};

const FIRST_MODIFIER_LOW_BIT: u32 = 4;
const SECOND_MODIFIER_LOW_BIT: u32 = 5;
const MODIFIER_COMPONENT_BITS: u32 = u32::BITS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigurationError {
    DataKey { key: Key },
    UnsupportedVersion { version: Version },
    KeyUnavailable { key: Key },
}

impl Context {
    /// ComputePAC2QARMA packing plus the existing InsertPAC implementation.
    /// The actual CPU/source owner must separately qualify APA6/API0/APA3zero.
    pub(crate) fn sign_two_modifiers(
        &self,
        key: Key,
        pointer: u64,
        modifier1: u64,
        modifier2: u64,
    ) -> Result<u64, ConfigurationError> {
        self.check_two_modifier_configuration(key)?;
        self.sign(key, pointer, pack_modifiers(modifier1, modifier2))
            .map_err(|_| ConfigurationError::KeyUnavailable { key })
    }

    /// Return canonical standalone/combined policy results without a state commit.
    /// Configuration errors remain separate from architectural authentication.
    pub(crate) fn authenticate_two_modifiers(
        &self,
        key: Key,
        pointer: u64,
        modifier1: u64,
        modifier2: u64,
        combined: bool,
    ) -> Result<Result<AuthResult, AuthenticationError>, ConfigurationError> {
        self.check_two_modifier_configuration(key)?;
        Ok(self.authenticate_operation(
            key,
            pointer,
            pack_modifiers(modifier1, modifier2),
            combined,
        ))
    }

    fn check_two_modifier_configuration(&self, key: Key) -> Result<(), ConfigurationError> {
        if key.is_data() {
            return Err(ConfigurationError::DataKey { key });
        }
        if self.version() != Version::FaultingCombined {
            return Err(ConfigurationError::UnsupportedVersion {
                version: self.version(),
            });
        }
        if !self.has_key(key) {
            return Err(ConfigurationError::KeyUnavailable { key });
        }
        Ok(())
    }
}

/// Exact June ComputePAC2QARMA: modifier2[36:5] :: modifier1[35:4].
/// This is not the implementation-defined ComputePAC2 primitive.
const fn pack_modifiers(modifier1: u64, modifier2: u64) -> u64 {
    let low = (modifier1 >> FIRST_MODIFIER_LOW_BIT) as u32;
    let high = (modifier2 >> SECOND_MODIFIER_LOW_BIT) as u32;
    ((high as u64) << MODIFIER_COMPONENT_BITS) | low as u64
}

#[cfg(test)]
#[path = "two_modifier/tests.rs"]
mod tests;
