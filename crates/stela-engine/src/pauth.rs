//! Software pointer authentication (QARMA5) for arm64e.
//!
//! The default profile is PAuth1 with a 47-bit VA, instruction TBI off and data
//! TBI on. Signing a pointer with an invalid extension corrupts the PAC; a failed
//! authentication returns the classic poisoned pointer. Optional profiles add
//! PAuth2 XOR insertion and FPAC/FPACCOMBINE faults. The caller owns the keys and
//! binds the context to its address space. QARMA (`qarma`) never indexes memory
//! with secret data: its S-box is Boolean polynomials or, with SSSE3, PSHUFB
//! register lookups (Arm pseudocode `ComputePACQARMA`, `InsertPAC`,
//! `Authenticate`).
use core::fmt;
use serde::Serialize;

pub mod generic;
pub mod memory;
pub mod policy;
pub use policy::Version;

pub const PROFILE_ID: &str = "stela-classic-arm64e-qarma5-va47-itbi0-ib-v1";
pub const FULL_PROFILE_ID: &str = "stela-classic-arm64e-qarma5-va47-itbi0-dtbi1-all-keys-v1";
pub const GENERIC_PROFILE_ID: &str =
    "stela-classic-arm64e-qarma5-va47-itbi0-dtbi1-explicit-keys-ga-v1";
pub const ENHANCED_PROFILE_ID: &str = "stela-pauth2-qarma5-va47-itbi0-dtbi1-explicit-keys-v1";
pub const FAULTING_PROFILE_ID: &str = "stela-fpac-qarma5-va47-itbi0-dtbi1-explicit-keys-v1";
pub const COMBINED_PROFILE_ID: &str = "stela-fpaccombine-qarma5-va47-itbi0-dtbi1-explicit-keys-v1";
const GENERIC_CODE_MASK: u64 = (u32::MAX as u64) << u32::BITS;
#[cfg(test)]
const ADDRESS_MASK: u64 = (1 << 47) - 1;
#[cfg(test)]
const REGION_BIT: u64 = 1 << 55;
#[cfg(test)]
const PAC_MASK: u64 = !(ADDRESS_MASK | REGION_BIT);
#[cfg(test)]
const POISON_MASK: u64 = 3 << 61;
#[cfg(test)]
const IB_POISON: u64 = 2 << 61;
#[cfg(test)]
const DATA_EXTENSION_MASK: u64 = 0x00ff_ffff_ffff_ffff & !ADDRESS_MASK;
#[cfg(test)]
const DATA_PAC_MASK: u64 = DATA_EXTENSION_MASK & !REGION_BIT;

use stela_contracts::pauth::Key;

const fn key_domain(key: Key) -> policy::Domain {
    if key.is_data() {
        policy::Domain::Data
    } else {
        policy::Domain::Instruction
    }
}
#[cfg(test)]
const fn key_pac_mask(key: Key) -> u64 {
    if key.is_data() {
        DATA_PAC_MASK
    } else {
        PAC_MASK
    }
}

/// Process keys, never Debug or Serialize. Each pair follows the architectural
/// KeyLo/KeyHi registers. A missing key is not a zero key.
pub struct Keys {
    words: [Option<[u64; 2]>; 4],
    generic: Option<[u64; 2]>,
}
impl Keys {
    pub fn from_ib_words(low: u64, high: u64) -> Self {
        Self::from_optional_words([None, Some([low, high]), None, None])
    }
    pub fn from_words(ia: [u64; 2], ib: [u64; 2], da: [u64; 2], db: [u64; 2]) -> Self {
        Self::from_optional_words([Some(ia), Some(ib), Some(da), Some(db)])
    }
    /// Build a key set where absent keys stay absent rather than zero.
    pub(crate) fn from_optional_words(words: [Option<[u64; 2]>; 4]) -> Self {
        Self {
            words,
            generic: None,
        }
    }
    pub fn with_generic_words(mut self, words: [u64; 2]) -> Self {
        self.generic = Some(words);
        self
    }
    fn get(&self, key: Key) -> Result<&[u64; 2], AuthenticationError> {
        self.words[key.index()]
            .as_ref()
            .ok_or(AuthenticationError::KeyUnavailable { key })
    }
}

pub struct Context {
    address_space: u64,
    keys: Keys,
    version: Version,
    /// TCR_EL1 of the system-mode regime; `None` keeps the process profile.
    regime: Option<u64>,
}
impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("address_space", &self.address_space)
            .field("profile", &self.profile_id())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AuthResult {
    pub pointer: u64,
    pub authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthenticationError {
    KeyUnavailable { key: Key },
    GenericKeyUnavailable,
    Failure { code: u8 },
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyUnavailable { key } => write!(
                formatter,
                "pointer authentication key {key:?} is unavailable"
            ),
            Self::GenericKeyUnavailable => {
                formatter.write_str("generic pointer authentication key is unavailable")
            }
            Self::Failure { code } => write!(
                formatter,
                "architectural pointer authentication failure {code}"
            ),
        }
    }
}

impl core::error::Error for AuthenticationError {}

impl Context {
    pub fn new(address_space: u64, keys: Keys) -> Self {
        Self::new_with_version(address_space, keys, Version::Classic)
    }
    pub fn new_with_version(address_space: u64, keys: Keys, version: Version) -> Self {
        Self {
            address_space,
            keys,
            version,
            regime: None,
        }
    }

    /// Lay PAC fields out for the EL1&0 regime this TCR_EL1 describes, as
    /// the system-mode engine requires, instead of the fixed process profile.
    pub fn with_translation_regime(mut self, tcr: u64) -> Self {
        self.regime = Some(tcr);
        self
    }

    /// The PAC field of `pointer` for an `operation` in `domain`. Arm
    /// `AddPAC` selects the range whose TnSZ bounds the field by bit 55 when
    /// either range ignores the domain's top byte and by bit 63 otherwise;
    /// `Auth` and `Strip` always select by bit 55
    /// (`CalculateBottomPACBit(ptr<55>)`), since a signed pointer's bit 63 is
    /// PAC whenever the top byte is not ignored.
    fn layout(&self, domain: policy::Domain, pointer: u64, signing: bool) -> policy::Layout {
        let Some(tcr) = self.regime else {
            return domain.layout();
        };
        // EffectiveTBI selects TBI0/TBI1 by bit 55; TBIDn exempts instructions.
        let ignores_top_byte = |upper: bool| {
            let (tbi, tbid) = if upper { (38, 52) } else { (37, 51) };
            tcr & (1 << tbi) != 0
                && !(domain == policy::Domain::Instruction && tcr & (1 << tbid) != 0)
        };
        let tbi = ignores_top_byte(pointer & (1 << 55) != 0);
        let select = if signing && !ignores_top_byte(false) && !ignores_top_byte(true) {
            63
        } else {
            55
        };
        let tnsz = if pointer & (1 << select) != 0 {
            (tcr >> 16) & 63
        } else {
            tcr & 63
        };
        // CalculateBottomPACBit: an out-of-range TnSZ is CONSTRAINED
        // UNPREDICTABLE, FORCE or NONE; FORCE to 16..=39 (no FEAT_TTST or
        // 52-bit VAs), the range the system engine's walker admits.
        let tnsz = tnsz.clamp(MIN_TNSZ, MAX_TNSZ);
        policy::Layout {
            address_bits: 64 - tnsz as u32,
            top_shift: if tbi { 55 } else { 63 },
        }
    }
    pub fn version(&self) -> Version {
        self.version
    }
    pub fn address_space(&self) -> u64 {
        self.address_space
    }
    pub fn profile_id(&self) -> &'static str {
        match self.version {
            Version::Enhanced => ENHANCED_PROFILE_ID,
            Version::Faulting => FAULTING_PROFILE_ID,
            Version::FaultingCombined => COMBINED_PROFILE_ID,
            Version::Classic if self.keys.generic.is_some() => GENERIC_PROFILE_ID,
            Version::Classic if self.keys.words.iter().all(Option::is_some) => FULL_PROFILE_ID,
            Version::Classic => PROFILE_ID,
        }
    }
    pub fn has_key(&self, key: Key) -> bool {
        self.keys.words[key.index()].is_some()
    }

    /// InsertPAC with fixed VA47 instruction-TBI-off/data-TBI-on controls.
    /// Data keeps its tag in both QARMA input and output; it is not ignored by
    /// authentication. Null is signed. Classic invalid extension corrupts
    /// PAC bit62 (instruction) or54 (data), following June2026 Arm ASL, rather
    /// than the older Unicorn invalid-extension behavior. Enhanced profiles XOR the PAC field.
    pub fn sign(&self, key: Key, pointer: u64, modifier: u64) -> Result<u64, AuthenticationError> {
        let words = self.keys.get(key)?;
        let layout = self.layout(key_domain(key), pointer, true);
        let input = policy::signing_input(layout, pointer);
        Ok(policy::sign(
            self.version,
            layout,
            pointer,
            qarma5(input, modifier, words),
        ))
    }

    /// Standalone AUT policy; combined loads/transfers use authenticate_operation.
    pub fn authenticate(
        &self,
        key: Key,
        pointer: u64,
        modifier: u64,
    ) -> Result<AuthResult, AuthenticationError> {
        self.authenticate_operation(key, pointer, modifier, false)
    }

    pub fn authenticate_operation(
        &self,
        key: Key,
        pointer: u64,
        modifier: u64,
        combined: bool,
    ) -> Result<AuthResult, AuthenticationError> {
        let words = self.keys.get(key)?;
        let domain = key_domain(key);
        let layout = self.layout(domain, pointer, false);
        let input = policy::authentication_input(layout, pointer);
        let result = policy::authenticate(
            self.version,
            domain,
            layout,
            if key.is_b() {
                policy::Side::B
            } else {
                policy::Side::A
            },
            combined,
            pointer,
            qarma5(input, modifier, words),
        )
        .map_err(|failure| AuthenticationError::Failure { code: failure.code })?;
        Ok(AuthResult {
            pointer: result.pointer,
            authenticated: result.authenticated,
        })
    }

    pub fn has_generic_key(&self) -> bool {
        self.keys.generic.is_some()
    }

    /// PACGA has no address-domain canonicalization; all64 data/modifier bits enter QARMA.
    pub fn generic_code(&self, data: u64, modifier: u64) -> Result<u64, AuthenticationError> {
        let words = self
            .keys
            .generic
            .as_ref()
            .ok_or(AuthenticationError::GenericKeyUnavailable)?;
        Ok(qarma5(data, modifier, words) & GENERIC_CODE_MASK)
    }

    /// Architectural XPAC: keyless restoration, never an authentication check.
    /// Ia/Ib select instruction layout, Da/Db tagged-data layout; this succeeds
    /// even when that domain's cryptographic key was not provided.
    pub fn strip(&self, key: Key, pointer: u64) -> u64 {
        policy::authentication_input(self.layout(key_domain(key), pointer, false), pointer)
    }

    /// The bits kept by XPAC in the lower and upper address ranges.
    /// Strip selects both its TnSZ and effective TBI by pointer bit 55.
    /// These masks contain no key material and do not depend on key enables.
    pub(crate) fn stripping_masks(&self, data: bool) -> [u64; 2] {
        let domain = if data {
            policy::Domain::Data
        } else {
            policy::Domain::Instruction
        };
        [0, 1 << 55].map(|pointer| !self.layout(domain, pointer, false).extension_mask())
    }

    /// Sign with the IB key (the original single-key profile).
    pub fn sign_ib(&self, pointer: u64, modifier: u64) -> Result<u64, AuthenticationError> {
        self.sign(Key::Ib, pointer, modifier)
    }
    pub fn authenticate_ib(
        &self,
        pointer: u64,
        modifier: u64,
    ) -> Result<AuthResult, AuthenticationError> {
        self.authenticate(Key::Ib, pointer, modifier)
    }
}

/// TnSZ limits of the PAC field without FEAT_TTST or 52-bit VAs.
const MIN_TNSZ: u64 = 16;
const MAX_TNSZ: u64 = 39;

mod qarma;
use qarma::compute as qarma5;

pub(crate) mod features;
pub use features::UnsupportedInstructionProfile;

pub(crate) mod lr_instruction;

mod two_modifier;

pub(crate) mod conditional;

impl stela_contracts::pauth::TranslationSigner for Context {
    fn with_translation_regime(self, tcr_el1: u64) -> Self {
        Self::with_translation_regime(self, tcr_el1)
    }
}

impl stela_contracts::pauth::Signer for Context {
    type Error = AuthenticationError;
    fn address_space(&self) -> u64 {
        self.address_space()
    }
    fn profile_id(&self) -> &'static str {
        self.profile_id()
    }
    fn sign(&self, key: Key, pointer: u64, modifier: u64) -> Result<u64, AuthenticationError> {
        self.sign(key, pointer, modifier)
    }
}

#[cfg(test)]
mod tests;
