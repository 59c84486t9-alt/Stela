//! Software pointer authentication (QARMA5) for arm64e.
//!
//! The default profile is PAuth1 with a 47-bit VA, instruction TBI off and data
//! TBI on. Signing a pointer with an invalid extension corrupts the PAC; a failed
//! authentication returns the classic poisoned pointer. Optional profiles add
//! PAuth2 XOR insertion and FPAC/FPACCOMBINE faults. The caller owns the keys and
//! binds the context to its address space. QARMA substitution uses Boolean
//! polynomials rather than secret-indexed tables (Arm pseudocode
//! `ComputePACQARMA`, `InsertPAC`, `Authenticate`).
use anyhow::Result;
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

/// Cryptographic key and address domain; XPAC uses only the address domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Key {
    Ia,
    Ib,
    Da,
    Db,
}
impl Key {
    const fn index(self) -> usize {
        match self {
            Self::Ia => 0,
            Self::Ib => 1,
            Self::Da => 2,
            Self::Db => 3,
        }
    }
    pub const fn is_data(self) -> bool {
        matches!(self, Self::Da | Self::Db)
    }
    const fn is_b(self) -> bool {
        matches!(self, Self::Ib | Self::Db)
    }
    const fn domain(self) -> policy::Domain {
        if self.is_data() {
            policy::Domain::Data
        } else {
            policy::Domain::Instruction
        }
    }
    #[cfg(test)]
    const fn pac_mask(self) -> u64 {
        if self.is_data() {
            DATA_PAC_MASK
        } else {
            PAC_MASK
        }
    }
}

/// Explicit process-owned keys, never Debug/Serialize. Limbs follow each
/// architectural KeyLo/KeyHi register. A missing domain is not a zero key.
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
    /// Initialize this same fresh bank with explicit absent domains, never zero keys.
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
    fn get(&self, key: Key) -> Result<&[u64; 2]> {
        self.words[key.index()]
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pointer authentication key {key:?} is unavailable"))
    }
}

pub struct Context {
    address_space: u64,
    keys: Keys,
    version: Version,
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
    Failure { code: u8 },
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyUnavailable { key } => write!(
                formatter,
                "pointer authentication key {key:?} is unavailable"
            ),
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
    /// Data retains its tag in both QARMA input and output; it is not ignored by
    /// authentication. Null is signed. Classic invalid extension corrupts
    /// PAC bit62 (instruction) or54 (data), following June2026 Arm ASL, rather
    /// than the older Unicorn invalid-extension behavior. Enhanced profiles XOR the PAC field.
    pub fn sign(&self, key: Key, pointer: u64, modifier: u64) -> Result<u64> {
        let words = self.keys.get(key)?;
        let domain = key.domain();
        let input = policy::signing_input(domain, pointer);
        Ok(policy::sign(
            self.version,
            domain,
            pointer,
            qarma5(input, modifier, words),
        ))
    }

    /// Standalone AUT policy; combined loads/transfers use authenticate_operation.
    pub fn authenticate(&self, key: Key, pointer: u64, modifier: u64) -> Result<AuthResult> {
        Ok(self.authenticate_operation(key, pointer, modifier, false)?)
    }

    pub fn authenticate_operation(
        &self,
        key: Key,
        pointer: u64,
        modifier: u64,
        combined: bool,
    ) -> core::result::Result<AuthResult, AuthenticationError> {
        let words = self.keys.words[key.index()]
            .as_ref()
            .ok_or(AuthenticationError::KeyUnavailable { key })?;
        let domain = key.domain();
        let input = policy::authentication_input(domain, pointer);
        let result = policy::authenticate(
            self.version,
            domain,
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
    pub fn generic_code(&self, data: u64, modifier: u64) -> Result<u64> {
        let words =
            self.keys.generic.as_ref().ok_or_else(|| {
                anyhow::anyhow!("generic pointer authentication key is unavailable")
            })?;
        Ok(qarma5(data, modifier, words) & GENERIC_CODE_MASK)
    }

    /// Architectural XPAC: keyless restoration, never an authentication check.
    /// Ia/Ib select instruction layout, Da/Db tagged-data layout; this succeeds
    /// even when that domain's cryptographic key was not provided.
    pub fn strip(&self, key: Key, pointer: u64) -> Result<u64> {
        Ok(strip_domain(key, pointer))
    }

    /// Backward-compatible IB/SP service with exactly the original profile math.
    pub fn sign_ib(&self, pointer: u64, modifier: u64) -> Result<u64> {
        self.sign(Key::Ib, pointer, modifier)
    }
    pub fn authenticate_ib(&self, pointer: u64, modifier: u64) -> Result<AuthResult> {
        self.authenticate(Key::Ib, pointer, modifier)
    }
}

fn strip_domain(key: Key, pointer: u64) -> u64 {
    policy::authentication_input(key.domain(), pointer)
}

const CELL_MASK: u64 = 0x1111_1111_1111_1111;
const SHUFFLE: [u8; 16] = [13, 6, 11, 0, 7, 12, 1, 10, 8, 3, 14, 5, 2, 9, 4, 15];
const INV_SHUFFLE: [u8; 16] = [3, 6, 12, 9, 14, 11, 1, 4, 8, 13, 7, 2, 5, 0, 10, 15];
const TWEAK_SHUFFLE: [u8; 16] = [4, 5, 6, 7, 11, 2, 3, 8, 12, 13, 14, 15, 0, 1, 10, 9];
const TWEAK_ROTATED: u16 = 0xd894;
const ROUND_CONSTANTS: [u64; 5] = [
    0,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
    0x4528_21e6_38d0_1377,
];

/// Sixteen independent four-bit substitutions in parallel bitplanes. The
/// polynomials are the algebraic normal form of Arm's factual PRINCE tables.
fn substitute(value: u64, inverse: bool) -> u64 {
    let m = CELL_MASK;
    let a = value & m;
    let b = (value >> 1) & m;
    let c = (value >> 2) & m;
    let d = (value >> 3) & m;
    let ab = a & b;
    let ac = a & c;
    let ad = a & d;
    let bc = b & c;
    let bd = b & d;
    let cd = c & d;
    let abc = ab & c;
    let abd = ab & d;
    let acd = ac & d;
    let bcd = bc & d;
    let planes = if inverse {
        [
            m ^ a ^ c ^ bc ^ abc ^ d ^ ad ^ bd ^ abd ^ cd ^ bcd,
            a ^ ab ^ c ^ ac ^ bc ^ abc ^ d ^ ad ^ acd,
            m ^ ab ^ c ^ abc ^ d ^ ad ^ bd ^ abd ^ acd ^ bcd,
            a ^ b ^ ab ^ c ^ ac ^ ad ^ cd ^ bcd,
        ]
    } else {
        [
            m ^ a ^ b ^ c ^ ac ^ abc ^ ad ^ abd ^ cd ^ bcd,
            m ^ b ^ ab ^ c ^ bc ^ abd ^ acd,
            a ^ c ^ bc ^ bd ^ abd ^ bcd,
            m ^ a ^ ab ^ d ^ ad ^ abd ^ cd ^ acd ^ bcd,
        ]
    };
    planes[0] | (planes[1] << 1) | (planes[2] << 2) | (planes[3] << 3)
}

fn cell(value: u64, index: usize) -> u64 {
    (value >> (index * 4)) & 15
}
fn permute(value: u64, order: &[u8; 16]) -> u64 {
    order.iter().enumerate().fold(0, |out, (index, source)| {
        out | (cell(value, usize::from(*source)) << (index * 4))
    })
}
fn rotate_cell(value: u64, count: u32) -> u64 {
    ((value << count) | (value >> (4 - count))) & 15
}
fn mix(value: u64) -> u64 {
    let mut out = 0;
    for column in 0..4 {
        let [a, b, c, d] = core::array::from_fn(|row| cell(value, column + row * 4));
        let rows = [
            rotate_cell(d, 1) ^ rotate_cell(c, 2) ^ rotate_cell(b, 1),
            rotate_cell(d, 2) ^ rotate_cell(c, 1) ^ rotate_cell(a, 1),
            rotate_cell(d, 1) ^ rotate_cell(b, 1) ^ rotate_cell(a, 2),
            rotate_cell(c, 1) ^ rotate_cell(b, 2) ^ rotate_cell(a, 1),
        ];
        for (row, value) in rows.into_iter().enumerate() {
            out |= value << ((column + row * 4) * 4);
        }
    }
    out
}
fn tweak_rotation(value: u64, inverse: bool) -> u64 {
    if inverse {
        ((value << 1) & 15) | ((value ^ (value >> 3)) & 1)
    } else {
        (value >> 1) | (((value ^ (value >> 1)) & 1) << 3)
    }
}
fn tweak(value: u64, inverse: bool) -> u64 {
    let mut out = 0;
    for (destination, source) in TWEAK_SHUFFLE.into_iter().enumerate() {
        let (input, output) = if inverse {
            (destination, usize::from(source))
        } else {
            (usize::from(source), destination)
        };
        let mut nibble = cell(value, input);
        if TWEAK_ROTATED & (1 << destination) != 0 {
            nibble = tweak_rotation(nibble, inverse);
        }
        out |= nibble << (output * 4);
    }
    out
}

fn qarma5(data: u64, modifier: u64, key: &[u64; 2]) -> u64 {
    let [key_low, key_high] = *key;
    let reflected_key = key_high.rotate_right(1) ^ (key_high >> 63);
    let mut state = data ^ key_high;
    let mut running = modifier;
    for (round, constant) in ROUND_CONSTANTS.into_iter().enumerate() {
        state ^= key_low ^ running ^ constant;
        if round != 0 {
            state = mix(permute(state, &SHUFFLE));
        }
        state = substitute(state, false);
        running = tweak(running, false);
    }
    state ^= reflected_key ^ running;
    state = substitute(mix(permute(state, &SHUFFLE)), false);
    state = mix(permute(state, &SHUFFLE)) ^ key_low;
    state = substitute(permute(state, &INV_SHUFFLE), true);
    state = permute(mix(state), &INV_SHUFFLE) ^ key_high ^ running;
    for (round, constant) in ROUND_CONSTANTS.into_iter().rev().enumerate() {
        state = substitute(state, true);
        if round != 4 {
            state = permute(mix(state), &INV_SHUFFLE);
        }
        running = tweak(running, true);
        state ^= constant ^ key_low ^ running ^ 0xc0ac_29b7_c97c_50dd;
    }
    state ^ reflected_key
}

#[cfg(test)]
mod tests;

pub(crate) mod features;
pub use features::UnsupportedInstructionProfile;

#[cfg(feature = "std")]
pub(crate) mod lr_context;

#[cfg(feature = "std")]
pub(crate) mod lr_instruction;

#[cfg(feature = "std")]
pub(crate) mod lr_service;

#[cfg(feature = "std")]
mod two_modifier;

#[cfg(feature = "std")]
pub(crate) use two_modifier::ConfigurationError as TwoModifierError;

#[cfg(feature = "std")]
pub(crate) mod lr_effects;

#[cfg(feature = "std")]
pub(crate) mod conditional;
