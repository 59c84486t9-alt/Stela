//! Apple's separate EL2 pointer-authentication key bank.
//!
//! The original T6000 LLB writes all five pairs at 0x22858..0x228b8;
//! 0xfa398 initializes pair A before enabling SCTLR.EnIA and using PAC.
//! These are PAC inputs, not opaque implementation-defined storage.
//! Original T8112 SPTM writes the standard EL1 names at EL2 before PACGA
//! (file 0xab7b0..0xab8c4). Stela joins those accesses to this canonical
//! EL2 state; equivalence to C13/C14 is an inference, not a physical alias
//! measurement. EL1 remains separate; EL12 permissions are not inferred.
use core::fmt;
use stela_compiler::aarch64::system::registers::Encoding;

/// The five complete key pairs, in architectural IA, IB, DA, DB, GA order.
pub(crate) const KEY_COUNT: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Register {
    pair: usize,
    word: usize,
}

impl Register {
    /// Standard names used by original SPTM at EL2. Arm's accessors establish
    /// EL2 access permission; the original producer/use chain establishes the
    /// required EL2 state join, not a new reset value or HCR-based selector.
    pub(crate) fn architectural(register: super::system::Register) -> Option<Self> {
        use super::system::Register as R;
        let (pair, word) = match register {
            R::APIAKeyLo_EL1 => (0, 0),
            R::APIAKeyHi_EL1 => (0, 1),
            R::APIBKeyLo_EL1 => (1, 0),
            R::APIBKeyHi_EL1 => (1, 1),
            R::APDAKeyLo_EL1 => (2, 0),
            R::APDAKeyHi_EL1 => (2, 1),
            R::APDBKeyLo_EL1 => (3, 0),
            R::APDBKeyHi_EL1 => (3, 1),
            R::APGAKeyLo_EL1 => (4, 0),
            R::APGAKeyHi_EL1 => (4, 1),
            _ => return None,
        };
        Some(Self { pair, word })
    }

    /// All ten source-proven C13/C14 words. No adjacent unknown encoding
    /// acquires storage because it resembles a key register.
    pub(crate) fn decode(encoding: Encoding) -> Option<Self> {
        if (encoding.op0(), encoding.op1(), encoding.crn()) != (3, 6, 15) {
            return None;
        }
        let index = match (encoding.crm(), encoding.op2()) {
            (13, word) => usize::from(word),
            (14, word @ 0..=1) => 8 + usize::from(word),
            _ => return None,
        };
        Some(Self {
            pair: index / 2,
            word: index % 2,
        })
    }
}

/// One PE owns these words. An unwritten half stays unknown; completing
/// another pair does not authorize it. Debug output contains no key material.
#[derive(Clone, Default)]
pub struct Bank {
    words: [[u64; 2]; KEY_COUNT],
    known: [[bool; 2]; KEY_COUNT],
}

impl fmt::Debug for Bank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bank")
            .field("initialized_halves", &self.known)
            .finish()
    }
}

impl Bank {
    pub(crate) fn read(&self, register: Register) -> Result<u64, &'static str> {
        self.known[register.pair][register.word]
            .then_some(self.words[register.pair][register.word])
            .ok_or("EL2 pointer authentication key half is unavailable")
    }

    pub(crate) fn write(&mut self, register: Register, value: u64) {
        self.words[register.pair][register.word] = value;
        self.known[register.pair][register.word] = true;
    }

    /// The address of a known half's word, which native code may write.
    pub(crate) fn storage(&self, register: Register) -> Option<u64> {
        self.known[register.pair][register.word]
            .then_some(&self.words[register.pair][register.word] as *const u64 as u64)
    }

    /// Per-pair initialization presence for bounded reference diagnostics.
    /// Key material remains private to the architectural implementation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn initialized(&self) -> [bool; KEY_COUNT] {
        self.known.map(|pair| pair == [true; 2])
    }

    pub(crate) fn pairs(&self) -> [Option<[u64; 2]>; KEY_COUNT] {
        core::array::from_fn(|pair| (self.known[pair] == [true; 2]).then_some(self.words[pair]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_five_pairs_keep_unknown_halves_and_independent_ownership() {
        let mut bank = Bank::default();
        assert_eq!(bank.pairs(), [None; KEY_COUNT]);
        for pair in 0..KEY_COUNT {
            let index = pair * 2;
            let encoding =
                |word| Encoding::new(3, 6, 15, 13 + (index / 8) as u8, ((index + word) % 8) as u8);
            bank.write(Register::decode(encoding(0)).unwrap(), 11 + pair as u64);
            assert!(bank.pairs()[pair].is_none());
            bank.write(Register::decode(encoding(1)).unwrap(), 21 + pair as u64);
            assert_eq!(
                bank.pairs()[pair],
                Some([11 + pair as u64, 21 + pair as u64])
            );
            assert!(bank.pairs()[pair + 1..].iter().all(Option::is_none));
        }
        let mut other = Bank::default();
        let low = Register::decode(Encoding::new(3, 6, 15, 13, 0)).unwrap();
        other.write(low, 99);
        assert_eq!(bank.pairs()[0], Some([11, 21]));
        assert_eq!(other.pairs(), [None; KEY_COUNT]);
        assert!(Register::decode(Encoding::new(3, 6, 15, 14, 2)).is_none());
        assert!(Register::decode(Encoding::new(3, 6, 15, 7, 0)).is_none());
    }

    #[test]
    fn debug_never_formats_key_material() {
        let mut bank = Bank::default();
        bank.write(
            Register::decode(Encoding::new(3, 6, 15, 13, 0)).unwrap(),
            123456789,
        );
        let rendered = alloc::format!("{bank:?}");
        assert!(!rendered.contains("123456789"));
        assert!(rendered.contains("true"));
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_PAUTH_LLB"]
    fn original_t6000_llb_writes_all_five_typed_pairs_with_ordering() {
        let bytes = std::fs::read(std::env::var("STELA_TEST_PAUTH_LLB").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&bytes),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        for (pair, offset) in [0x22858, 0x2286c, 0x22880, 0x22894, 0x228a8]
            .into_iter()
            .enumerate()
        {
            let words: [u32; 5] = core::array::from_fn(|index| {
                u32::from_le_bytes(
                    bytes[offset + index * 4..offset + (index + 1) * 4]
                        .try_into()
                        .unwrap(),
                )
            });
            for (half, &word) in words[..2].iter().enumerate() {
                let index = pair * 2 + half;
                let encoding = Encoding::new(3, 6, 15, 13 + (index / 8) as u8, (index % 8) as u8);
                assert_eq!(
                    Register::decode(encoding),
                    Some(Register { pair, word: half })
                );
                let rt = u32::from(half == 0);
                assert_eq!(
                    word,
                    0xd500_0000 | u32::from(super::super::system::key(encoding)) << 5 | rt
                );
            }
            assert_eq!(words[2..], [0xd503_3f9f, 0xd503_3fdf, 0xd65f_03c0]);
        }
    }
}
