//! Versioned software pointer authentication for explicit arm64e profiles.
//!
//! The default is a coherent QARMA5/PAuth1 guest profile, not an Apple hardware key or
//! signature equivalence claim. VA width is 47; instruction TBI is disabled
//! and data TBI enabled. Both extension regions and every u64 input are modeled.
//! Invalid-extension signing corrupts the PAC; failed authentication returns
//! classic A/B poison. Tagged data preserves its top byte, which participates in
//! authentication. No pointer is dereferenced or normalized for a host access.
//! Additional profiles enable PAuth2 XOR insertion and FPAC/FPACCOMBINE failures,
//! with typed failure boundaries. Generic PAC uses its own optional process key.
//! PAuth_LR, dynamic system controls and exception delivery remain outside these profiles. The caller owns process key lifetime and must
//! bind this context to the executing address space before changing guest state.
//!
//! Algorithm/bit layout: Arm ISA_A64_xml_A_profile-2026-06 shared_pseudocode.xml,
//! ComputePACQARMA/PACSub/PACInvSub/PACMult/PACCellShuffle/TweakShuffle,
//! InsertPAC and Authenticate. Round constants and permutations are factual
//! algorithm parameters; substitution uses parallel Boolean polynomials rather
//! than secret-indexed lookup tables. No constant-time/security audit is claimed.
use anyhow::Result;
use serde::Serialize;
use std::fmt;

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

impl std::error::Error for AuthenticationError {}

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
    ) -> std::result::Result<AuthResult, AuthenticationError> {
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
        let [a, b, c, d] = std::array::from_fn(|row| cell(value, column + row * 4));
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
mod tests {
    use super::*;

    // Original PACIBSP/AUTIBSP under explicitly enabled Unicorn 2.1.4 MAX,
    // QARMA5/PAuth1 and VA47/instruction-TBI-off. These are public fixed test
    // keys, never production context material. Source/controls are retained in
    // .stela/research/pac-implementation/oracle-ib-vectors.json.
    // Fixture SHA256: 577f508d22a8807b01cbf87a11d606169617f710b501edba0c9177231b417dcd
    const POINTERS: [u64; 4] = [0x0, 0x1400, 0x7fffffffffff, 0x123456789abc];
    const MODIFIERS: [u64; 4] = [0x0, 0x2000, 0xffffffffffffffff, 0x123456789abcdef];
    const IB_VECTORS: [([u64; 2], [u64; 16]); 4] = [
        (
            [0x1122334455667788, 0x99aabbccddeeff00],
            [
                0xf90e800000000000,
                0xcd1f800000000000,
                0xf911000000000000,
                0x3041800000000000,
                0x6709800000001400,
                0xce76000000001400,
                0xc405800000001400,
                0xfe1d000000001400,
                0xfd717fffffffffff,
                0xdc587fffffffffff,
                0x7564ffffffffffff,
                0xa1457fffffffffff,
                0xa630923456789abc,
                0xb00e923456789abc,
                0xa248123456789abc,
                0x9f09923456789abc,
            ],
        ),
        (
            [0x0, 0x0],
            [
                0x7624000000000000,
                0xb51800000000000,
                0x7c16000000000000,
                0x1c15000000000000,
                0x603d000000001400,
                0xff3a000000001400,
                0x983c800000001400,
                0xb67e800000001400,
                0x75affffffffffff,
                0x8b39ffffffffffff,
                0x6d56ffffffffffff,
                0xc102ffffffffffff,
                0x757b123456789abc,
                0xdd1e123456789abc,
                0xc15c923456789abc,
                0xbd0c123456789abc,
            ],
        ),
        (
            [0xffffffffffffffff, 0xffffffffffffffff],
            [
                0xdd57000000000000,
                0x1a0d800000000000,
                0x4855800000000000,
                0x852e000000000000,
                0x8160000000001400,
                0x6419000000001400,
                0x2d50000000001400,
                0xb354000000001400,
                0xa620ffffffffffff,
                0xdb7b7fffffffffff,
                0xf43dffffffffffff,
                0x32347fffffffffff,
                0xd615923456789abc,
                0x9c7a123456789abc,
                0x3f66923456789abc,
                0xa109923456789abc,
            ],
        ),
        (
            [0x1, 0x2],
            [
                0xc56e800000000000,
                0x3c40000000000000,
                0x825c800000000000,
                0x2f70000000000000,
                0xac7f000000001400,
                0x4071800000001400,
                0xe407800000001400,
                0x714b800000001400,
                0x751b7fffffffffff,
                0xe0397fffffffffff,
                0xe6767fffffffffff,
                0xff62ffffffffffff,
                0xb04123456789abc,
                0x253a123456789abc,
                0x5c4c123456789abc,
                0x2968923456789abc,
            ],
        ),
    ];
    #[test]
    fn original_enabled_arm_ib_vectors_match_and_round_trip() -> Result<()> {
        for (words, signed) in IB_VECTORS {
            let context = Context::new(73, Keys::from_ib_words(words[0], words[1]));
            for (pointer_index, pointer) in POINTERS.into_iter().enumerate() {
                for (modifier_index, modifier) in MODIFIERS.into_iter().enumerate() {
                    let encoded = signed[pointer_index * 4 + modifier_index];
                    assert_eq!(context.sign_ib(pointer, modifier)?, encoded);
                    assert_eq!(
                        context.authenticate_ib(encoded, modifier)?,
                        AuthResult {
                            pointer,
                            authenticated: true,
                        }
                    );
                }
            }
        }
        Ok(())
    }

    // Independent nibble-array ASL reference; full64 is mathematical evidence,
    // while its upper32 was additionally checked using original PACGA.
    // oracle-full64-asl.json SHA256: 9c5147fc8dde0cdf8580997d3213e0930f8da99a60578ad72b771db3af9523b2
    #[test]
    fn full64_qarma5_matches_independent_nibble_asl_vectors() {
        let vectors = [
            (
                0x0,
                0x0,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0xf98eebd04f80fec6,
            ),
            (
                0x3c810c2558894393,
                0x33a14317477358e7,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x7cec813deab63a55,
            ),
            (
                0xdb75f319b483fcd5,
                0xdd1af32ab32cfb22,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0xa5f20d0d7776814,
            ),
            (
                0x2524e003c1432543,
                0xcfe77676c7b84f90,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0xdb69675548508432,
            ),
            (
                0x2ed789064fa6bbcc,
                0x6e54c8b49abb51bc,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0xe61fc538e854699f,
            ),
            (
                0xc1c675b87fc42511,
                0x7e206026f6549718,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x4fbdd31c41849186,
            ),
            (
                0xa4601de012b07be3,
                0xb9577bd89b48ee52,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0xd06fb2fcb27e5d50,
            ),
            (
                0x291e514e4fd5e8d3,
                0x6f9d0c33b844f4c4,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0xe68256a379ad2504,
            ),
            (
                0xa9de99224d3581bf,
                0xaf2fb1590a2fc6bd,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x3beaabf4a9184e65,
            ),
            (
                0x23e3647c64a0f3a2,
                0xc6b21be5b51aaccf,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x48f9fe3106eb6ae3,
            ),
            (
                0x53471cc4cd40c33c,
                0x6c90e18ec551138a,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0xd3f029020f7b0356,
            ),
            (
                0x965121dfe4b238ca,
                0x60c2b6f7672b9a4e,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x3fe103f2b39dc30,
            ),
            (
                0x907fa48493109c21,
                0x66dd128e6f419835,
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x8251a27e4a52ba06,
            ),
            (
                0xdef475e27b35192d,
                0x8e8c0dd51c21f2b3,
                0x842fa07b630a8282,
                0x37fdc673abbf343f,
                0x5779db86552f2e3a,
            ),
            (
                0x83c0808da71ed9e2,
                0xa57f47a258ed2136,
                0x7acc0887b148a07d,
                0xe0d85e13ee6a7663,
                0x74ebc6ad8e41fc56,
            ),
            (
                0x29cf741c9173ab3d,
                0x33d9b70ddf7b9df9,
                0xf28c190a408ce61c,
                0x219d7e95e231c536,
                0x93f53a7591dfb34b,
            ),
        ];
        for (data, modifier, low, high, expected) in vectors {
            assert_eq!(qarma5(data, modifier, &[low, high]), expected);
        }
    }

    #[test]
    fn every_pac_bit_corruption_produces_ib_poison_without_stripping() -> Result<()> {
        let context = Context::new(
            7,
            Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
        );
        let signed = context.sign_ib(0x1400, 0x2000)?;
        assert_eq!(signed, 0xce76000000001400);
        for bit in 0..64 {
            if PAC_MASK & (1 << bit) != 0 {
                assert_eq!(
                    context.authenticate_ib(signed ^ (1 << bit), 0x2000)?,
                    AuthResult {
                        pointer: 0x4000000000001400,
                        authenticated: false,
                    }
                );
            }
        }
        assert_eq!(
            context.authenticate_ib(signed, 0x2010)?,
            AuthResult {
                pointer: 0x4000000000001400,
                authenticated: false,
            }
        );
        let other = Context::new(
            7,
            Keys::from_ib_words(0x1122334455667789, 0x99aabbccddeeff00),
        );
        assert!(!other.authenticate_ib(signed, 0x2000)?.authenticated);
        assert!(!context.authenticate_ib(signed ^ 4, 0x2000)?.authenticated);
        Ok(())
    }

    #[test]
    fn null_upper_region_and_invalid_extensions_follow_classic_math() -> Result<()> {
        let context = Context::new(
            7,
            Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
        );
        assert_ne!(context.sign_ib(0, 0x2000)?, 0);
        for pointer in [0, ADDRESS_MASK, !ADDRESS_MASK, u64::MAX] {
            let encoded = context.sign_ib(pointer, 0x2000)?;
            assert_eq!(encoded & REGION_BIT, pointer & REGION_BIT);
            assert_eq!(
                context.authenticate_ib(encoded, 0x2000)?,
                AuthResult {
                    pointer,
                    authenticated: true,
                }
            );
        }
        // The exact June ASL invalid-extension corruption is PAC bit62.
        // Installed Unicorn's older helper flips bit63 instead; canonical
        // vectors above agree, while these cases deliberately follow June ASL.
        for bit in 47..64 {
            for pointer in [(1u64 << bit) | 0x1400, !(1u64 << bit) & !0x1234] {
                let extension = pointer >> 47;
                if extension == 0 || extension == u64::MAX >> 47 {
                    continue;
                }
                let canonical =
                    (pointer & ADDRESS_MASK) | if pointer >> 63 != 0 { !ADDRESS_MASK } else { 0 };
                let encoded = context.sign_ib(pointer, 0x2000)?;
                assert_eq!(encoded, context.sign_ib(canonical, 0x2000)? ^ (1 << 62));
                let failed = context.authenticate_ib(encoded, 0x2000)?;
                assert!(!failed.authenticated);
                assert_eq!(failed.pointer, (canonical & !POISON_MASK) | IB_POISON);
            }
        }
        Ok(())
    }

    #[test]
    fn substitution_permutations_and_tweaks_match_factual_cells_and_are_invertible() {
        let forward = [11u64, 6, 8, 15, 12, 0, 9, 14, 3, 7, 4, 5, 13, 2, 1, 10];
        for (nibble, expected) in forward.into_iter().enumerate() {
            let repeated = (nibble as u64) * CELL_MASK;
            assert_eq!(substitute(repeated, false), expected * CELL_MASK);
            assert_eq!(substitute(expected * CELL_MASK, true), repeated);
        }
        for value in [0, 1, u64::MAX, 0x0123456789abcdef, 0xfedcba9876543210] {
            assert_eq!(permute(permute(value, &SHUFFLE), &INV_SHUFFLE), value);
            assert_eq!(substitute(substitute(value, false), true), value);
            assert_eq!(tweak(tweak(value, false), true), value);
            assert_eq!(tweak(tweak(value, true), false), value);
        }
    }

    #[test]
    fn context_metadata_and_debug_never_include_secret_key_words() {
        let context = Context::new(
            73,
            Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
        );
        assert_eq!(context.address_space(), 73);
        assert_eq!(context.profile_id(), PROFILE_ID);
        assert_eq!(
            format!("{context:?}"),
            format!("Context {{ address_space: 73, profile: {PROFILE_ID:?}, .. }}")
        );
    }
    fn all_keys() -> Keys {
        let words = [0x1122334455667788, 0x99aabbccddeeff00];
        Keys::from_words(words, words, words, words)
    }

    #[test]
    fn generic_domains_match_original_canonical_sign_auth_and_xpac_vectors() -> Result<()> {
        // Original enabled Unicorn2.1.4 MAX, QARMA5/VA47/iTBIoff/dTBIon.
        // oracle-receipt.json SHA256:
        // 2b0bb3e6c7c7cf9bb3958745ec00c2accda46e114cce9f19940895a18ac0b91e
        let context = Context::new(73, all_keys());
        let vectors = [
            (
                0x0000000000000000,
                0x0000000000000000,
                0xf90e800000000000,
                0x000e800000000000,
            ),
            (
                0x0000000000000000,
                0x0000000000002000,
                0xcd1f800000000000,
                0x001f800000000000,
            ),
            (
                0x0000000000000000,
                0xffffffffffffffff,
                0xf911000000000000,
                0x0011000000000000,
            ),
            (
                0x0000000000001400,
                0x0000000000000000,
                0x6709800000001400,
                0x0009800000001400,
            ),
            (
                0x0000000000001400,
                0x0000000000002000,
                0xce76000000001400,
                0x0076000000001400,
            ),
            (
                0x0000000000001400,
                0xffffffffffffffff,
                0xc405800000001400,
                0x0005800000001400,
            ),
            (
                0x00007fffffffffff,
                0x0000000000000000,
                0xfd717fffffffffff,
                0x00717fffffffffff,
            ),
            (
                0x00007fffffffffff,
                0x0000000000002000,
                0xdc587fffffffffff,
                0x00587fffffffffff,
            ),
            (
                0x00007fffffffffff,
                0xffffffffffffffff,
                0x7564ffffffffffff,
                0x0064ffffffffffff,
            ),
            (
                0xffff800000001400,
                0x0000000000000000,
                0x3cc4800000001400,
                0xffc4800000001400,
            ),
            (
                0xffff800000001400,
                0x0000000000002000,
                0xf8a9800000001400,
                0xffa9800000001400,
            ),
            (
                0xffff800000001400,
                0xffffffffffffffff,
                0xb598800000001400,
                0xff98800000001400,
            ),
        ];
        for (pointer, modifier, instruction, data) in vectors {
            for key in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
                let signed = if key.is_data() { data } else { instruction };
                assert_eq!(context.sign(key, pointer, modifier)?, signed);
                assert_eq!(
                    context.authenticate(key, signed, modifier)?,
                    AuthResult {
                        pointer,
                        authenticated: true,
                    }
                );
                assert_eq!(context.strip(key, signed)?, pointer);
            }
        }
        Ok(())
    }

    #[test]
    fn tagged_data_matches_original_and_retains_tag_on_auth_and_strip() -> Result<()> {
        let context = Context::new(73, all_keys());
        let vectors = [
            (0x8000000000001400, 0x0000000000000000, 0x805d800000001400),
            (0x8000000000001400, 0x0000000000002000, 0x8026800000001400),
            (0x8000000000001400, 0xffffffffffffffff, 0x807a800000001400),
            (0x7aff800000001400, 0x0000000000000000, 0x7abe000000001400),
            (0x7aff800000001400, 0x0000000000002000, 0x7acb000000001400),
            (0x7aff800000001400, 0xffffffffffffffff, 0x7ad1000000001400),
        ];
        for (pointer, modifier, signed) in vectors {
            for key in [Key::Da, Key::Db] {
                assert_eq!(context.sign(key, pointer, modifier)?, signed);
                assert_eq!(signed >> 56, pointer >> 56);
                assert_eq!(
                    context.authenticate(key, signed, modifier)?,
                    AuthResult {
                        pointer,
                        authenticated: true,
                    }
                );
                assert_eq!(context.strip(key, signed)?, pointer);
                for bit in 47..55 {
                    let failed = context.authenticate(key, signed ^ (1 << bit), modifier)?;
                    assert!(!failed.authenticated);
                    assert_eq!(failed.pointer >> 56, pointer >> 56);
                    assert_eq!(failed.pointer & REGION_BIT, pointer & REGION_BIT);
                    let poison = if key == Key::Db { 2u64 } else { 1 };
                    assert_eq!(failed.pointer, (pointer & !(3 << 53)) | (poison << 53));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_domains_poison_every_corrupted_pac_bit_and_key_selection_is_explicit() -> Result<()> {
        let context = Context::new(73, all_keys());
        for key in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
            let signed = context.sign(key, 0x1400, 0x2000)?;
            let shift = if key.is_data() { 53 } else { 61 };
            let poison = if key.is_b() { 2u64 } else { 1 };
            for bit in 0..64 {
                if key.pac_mask() & (1 << bit) != 0 {
                    assert_eq!(
                        context.authenticate(key, signed ^ (1 << bit), 0x2000)?,
                        AuthResult {
                            pointer: 0x1400 | (poison << shift),
                            authenticated: false,
                        }
                    );
                }
            }
        }
        // Distinct domain keys use the same independently verified QARMA
        // primitive; no artificial IA/IB/DA/DB domain tag is added to the MAC.
        let context = Context::new(
            73,
            Keys::from_words(
                [0, 0],
                [u64::MAX, u64::MAX],
                [1, 2],
                [0x1122334455667788, 0x99aabbccddeeff00],
            ),
        );
        for (key, expected) in [
            (Key::Ia, 0xff3a000000001400),
            (Key::Ib, 0x6419000000001400),
            (Key::Da, 0x0071800000001400),
            (Key::Db, 0x0076000000001400),
        ] {
            assert_eq!(context.sign(key, 0x1400, 0x2000)?, expected);
            assert!(context.authenticate(key, expected, 0x2000)?.authenticated);
        }
        Ok(())
    }

    #[test]
    fn data_invalid_extension_corruption_follows_june_asl_not_old_emulator() -> Result<()> {
        let context = Context::new(73, all_keys());
        for key in [Key::Da, Key::Db] {
            for tag in [0u64, 0x80, 0x7a, 0xff] {
                for bit in 47..56 {
                    for pointer in [
                        (tag << 56) | (1 << bit) | 0x1400,
                        (tag << 56) | (DATA_EXTENSION_MASK & !(1 << bit)) | 0x1400,
                    ] {
                        let canonical = strip_domain(key, pointer);
                        let signed = context.sign(key, pointer, 0x2000)?;
                        assert_eq!(signed, context.sign(key, canonical, 0x2000)? ^ (1 << 54));
                        let failed = context.authenticate(key, signed, 0x2000)?;
                        assert!(!failed.authenticated);
                        let poison = if key.is_b() { 2u64 } else { 1 };
                        assert_eq!(failed.pointer, (canonical & !(3 << 53)) | (poison << 53));
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn missing_keys_decline_sign_and_auth_but_xpac_is_keyless() -> Result<()> {
        let ib = Context::new(
            73,
            Keys::from_ib_words(0x1122334455667788, 0x99aabbccddeeff00),
        );
        assert_eq!(ib.profile_id(), PROFILE_ID);
        assert!(ib.has_key(Key::Ib));
        for key in [Key::Ia, Key::Da, Key::Db] {
            assert!(!ib.has_key(key));
            assert!(ib.sign(key, 0x1400, 0x2000).is_err());
            assert!(ib.authenticate(key, 0x1400, 0x2000).is_err());
            assert_eq!(ib.strip(key, 0x1400)?, 0x1400);
        }
        assert_eq!(ib.sign_ib(0x1400, 0x2000)?, 0xce76000000001400);
        let full = Context::new(73, all_keys());
        assert_eq!(full.profile_id(), FULL_PROFILE_ID);
        assert_eq!(
            format!("{full:?}"),
            format!("Context {{ address_space: 73, profile: {FULL_PROFILE_ID:?}, .. }}")
        );
        for (key, name) in [
            (Key::Ia, "ia"),
            (Key::Ib, "ib"),
            (Key::Da, "da"),
            (Key::Db, "db"),
        ] {
            assert!(full.has_key(key));
            assert_eq!(serde_json::to_value(key)?, serde_json::json!(name));
        }
        Ok(())
    }
    #[test]
    fn generic_key_is_independent_and_pacga_zeros_its_lower_half() -> Result<()> {
        let key = [0x1122334455667788, 0x99aabbccddeeff00];
        let context = Context::new(73, all_keys().with_generic_words(key));
        assert!(context.has_generic_key());
        assert_eq!(context.profile_id(), GENERIC_PROFILE_ID);
        assert_eq!(context.generic_code(0, 0)?, 0xf98e_ebd0_0000_0000);
        assert_eq!(
            context.generic_code(0x3c810c2558894393, 0x33a14317477358e7)?,
            0x7cec_813d_0000_0000
        );
        let old = Context::new(73, all_keys());
        assert!(!old.has_generic_key());
        assert!(old.generic_code(0, 0).is_err());
        for domain in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
            assert_eq!(
                context.sign(domain, 0x1400, 0x2000)?,
                old.sign(domain, 0x1400, 0x2000)?
            );
        }
        assert!(!format!("{context:?}").contains("1122334455667788"));
        Ok(())
    }

    #[test]
    fn modern_versions_keep_key_and_faulting_policies_explicit() -> Result<()> {
        for (version, profile) in [
            (Version::Enhanced, ENHANCED_PROFILE_ID),
            (Version::Faulting, FAULTING_PROFILE_ID),
            (Version::FaultingCombined, COMBINED_PROFILE_ID),
        ] {
            let context = Context::new_with_version(73, all_keys(), version);
            assert_eq!(context.version(), version);
            assert_eq!(context.profile_id(), profile);
            for key in [Key::Ia, Key::Ib, Key::Da, Key::Db] {
                for pointer in [0x1400, !0xfu64] {
                    let signed = context.sign(key, pointer, 0x2000)?;
                    for combined in [false, true] {
                        assert_eq!(
                            context.authenticate_operation(key, signed, 0x2000, combined)?,
                            AuthResult {
                                pointer,
                                authenticated: true
                            }
                        );
                        let result = context.authenticate_operation(
                            key,
                            signed ^ (1 << 47),
                            0x2000,
                            combined,
                        );
                        if version == Version::FaultingCombined
                            || (version == Version::Faulting && !combined)
                        {
                            assert_eq!(
                                result,
                                Err(AuthenticationError::Failure {
                                    code: (u8::from(key.is_data()) << 1) | u8::from(key.is_b())
                                })
                            );
                        } else {
                            assert_eq!(result?.pointer, pointer ^ (1 << 47));
                        }
                    }
                }
            }
            let missing = Context::new_with_version(73, Keys::from_ib_words(1, 2), version);
            assert_eq!(
                missing.authenticate_operation(Key::Da, 0, 0, true),
                Err(AuthenticationError::KeyUnavailable { key: Key::Da })
            );
        }
        Ok(())
    }
}

pub(crate) mod features;
pub use features::UnsupportedInstructionProfile;

pub(crate) mod lr_context;

pub(crate) mod lr_instruction;

pub(crate) mod lr_service;

mod two_modifier;

pub(crate) use two_modifier::ConfigurationError as TwoModifierError;

pub(crate) mod lr_effects;

pub(crate) mod conditional;
