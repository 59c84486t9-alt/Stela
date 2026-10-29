//! Matching T6000 native-program clock inputs and kept phase ownership.
//!
//! LLB4a80c/4036c selects parameter29, not the fixed24MHz branch. Its
//! 1a7f40 descriptor reads292240000 and recursively selects PLL0/1 through
//! 408a0. The five raw words and the native clock phase are separate inputs;
//! no enable, lock, frequency, phase or physical reset value is invented.
use super::identity::Authority;
use alloc::{rc::Rc, vec::Vec};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

pub(super) mod phase;
pub use phase::{Phase, Snapshot};

const NAME: &str = "t6000-native-clock-inputs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Pll0Control,
    Pll0Configuration,
    Pll1Control,
    Pll1Configuration,
    Selection,
}
impl Register {
    pub const ALL: [Self; 5] = [
        Self::Pll0Control,
        Self::Pll0Configuration,
        Self::Pll1Control,
        Self::Pll1Configuration,
        Self::Selection,
    ];
    pub const fn address(self) -> u64 {
        match self {
            Self::Pll0Control => 0x292200000,
            Self::Pll0Configuration => 0x29220000c,
            Self::Pll1Control => 0x292202000,
            Self::Pll1Configuration => 0x29220200c,
            Self::Selection => 0x292240000,
        }
    }
    fn index(self) -> usize {
        Self::ALL.iter().position(|item| *item == self).unwrap()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub register: Register,
    pub value: u32,
    pub known: u32,
}
pub enum Input {
    Captured(Vec<Observation>),
    DeclaredStela(Vec<Observation>),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Duplicate,
    IncompleteDeclaration,
    Unknown(Register),
    UnknownPhase,
    InvalidPhase,
    Regressed,
    Exhausted,
    PhaseHistory,
    UnqualifiedRoute,
    UnqualifiedRate,
}
impl Error {
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Duplicate => "T6000 native clock input repeats a physical word",
            Self::IncompleteDeclaration => {
                "T6000 declared clock inputs require every complete physical word"
            }
            Self::Unknown(_) => "T6000 native clock physical input is not fully known",
            Self::UnknownPhase => "T6000 native clock phase is unqualified",
            Self::InvalidPhase => "T6000 native clock fractional phase exceeds its actual timebase",
            Self::Regressed => "T6000 native clock system time regressed",
            Self::Exhausted => "T6000 native clock cycle accumulator exhausted",
            Self::PhaseHistory => "T6000 native clock phase predates an unaccounted lifecycle edge",
            Self::UnqualifiedRoute => {
                "T6000 native clock selector has no positive source parent route"
            }
            Self::UnqualifiedRate => {
                "T6000 source clock query loses native rate authority through zero/overflow"
            }
        }
    }
}
struct Inputs {
    authority: Authority,
    words: [Observation; Register::ALL.len()],
}

/// One immutable supplied input image, shared by the bus and phase
/// owner. Writes/programming/lock changes remain unchecked. In particular a
/// source frequency calculation is not a native PLL lock observation.
#[derive(Clone)]
pub struct Image(Rc<Inputs>);
impl Image {
    pub fn new(input: Input) -> Result<Self, Error> {
        let (authority, supplied) = match input {
            Input::Captured(words) => (Authority::Captured, words),
            Input::DeclaredStela(words) => (Authority::DeclaredStela, words),
        };
        let mut words = Register::ALL.map(|register| Observation {
            register,
            value: 0,
            known: 0,
        });
        let mut seen = [false; Register::ALL.len()];
        for word in supplied {
            let index = word.register.index();
            if seen[index] {
                return Err(Error::Duplicate);
            }
            seen[index] = true;
            words[index] = Observation {
                value: word.value & word.known,
                ..word
            };
        }
        if authority == Authority::DeclaredStela && words.iter().any(|word| word.known != u32::MAX)
        {
            return Err(Error::IncompleteDeclaration);
        }
        Ok(Self(Rc::new(Inputs { authority, words })))
    }
    pub fn authority(&self) -> Authority {
        self.0.authority
    }
    pub fn observations(&self) -> &[Observation] {
        &self.0.words
    }
    pub fn addresses(&self) -> impl Iterator<Item = u64> {
        Register::ALL.into_iter().map(Register::address)
    }
    pub fn raw(&self, register: Register) -> Result<u32, Error> {
        let word = self.0.words[register.index()];
        if word.known != u32::MAX {
            return Err(Error::Unknown(register));
        }
        Ok(word.value)
    }
    fn pll0(&self) -> Result<u32, Error> {
        // Preserve native W-register arithmetic and the original read-before-
        // disable ordering. A captured disabled control cannot waive unknown
        // configuration reads which the helper performs first.
        let configuration = self.raw(Register::Pll0Configuration)?;
        let mut value = (configuration & 0x3fff) << 16;
        value = value.wrapping_mul(1 + ((configuration >> 20) & 1));
        let divisor = (configuration >> 16) & 15;
        if divisor != 0 {
            value = (value >> 1) / (divisor + 1);
        }
        let control = self.raw(Register::Pll0Control)?;
        Ok(if control & (1 << 31) == 0 {
            0
        } else if control & (1 << 27) != 0 {
            32768
        } else {
            value
        })
    }
    fn pll1(&self) -> Result<u32, Error> {
        let configuration = self.raw(Register::Pll1Configuration)?;
        let parent = self.pll0()?;
        let value = parent.wrapping_mul((configuration & 7) + 1).wrapping_mul(2);
        let control = self.raw(Register::Pll1Control)?;
        Ok(if control & (1 << 31) == 0 {
            0
        } else if control & (1 << 27) != 0 {
            parent
        } else {
            value
        })
    }
    /// Source query for the admitted parameter29 descriptor. This does not
    /// admit its caller's revision/feature guards, reconstruct firmware caches
    /// or assert a physical oscillator's phase. Zero is a computed
    /// disabled/zero-divisor result, not an invented healthy frequency.
    pub fn frequency(&self) -> Result<u32, Error> {
        let raw = self.raw(Register::Selection)?;
        if raw & (1 << 31) == 0 {
            return Ok(0);
        }
        let (parent, divisor) = match (raw >> 24) & 15 {
            0 => (self.pll0()?, 16),
            1 => (self.pll1()?, 16),
            2 => (self.pll1()?, 32),
            3 => (self.pll1()?, 48),
            4 => (self.pll0()?, 32),
            // Original remaining descriptor entries are zero. Its parent0
            // constant is then divided by0: architectural UDIV produces0.
            _ => return Ok(0),
        };
        Ok((parent / divisor) << 4)
    }
    pub(super) fn execution_frequency(&self) -> Result<u32, Error> {
        let selection = self.raw(Register::Selection)?;
        if selection & (1 << 31) == 0 {
            return Ok(0);
        }
        let selector = (selection >> 24) & 15;
        if selector > 4 {
            return Err(Error::UnqualifiedRoute);
        }
        let frequency = self.frequency()?;
        let pll0 = self.raw(Register::Pll0Control)?;
        let uses_pll1 = matches!(selector, 1..=3);
        let pll1 = if uses_pll1 {
            self.raw(Register::Pll1Control)?
        } else {
            0
        };
        let disabled = pll0 & (1 << 31) == 0 || (uses_pll1 && pll1 & (1 << 31) == 0);
        if frequency == 0 && !disabled {
            return Err(Error::UnqualifiedRate);
        }
        if uses_pll1 && pll1 & (1 << 31) != 0 && pll1 & (1 << 27) == 0 {
            let multiplier = 2 * ((self.raw(Register::Pll1Configuration)? & 7) + 1);
            if self.pll0()?.checked_mul(multiplier).is_none() {
                return Err(Error::UnqualifiedRate);
            }
        }
        Ok(frequency)
    }
}
impl MmioDevice for Image {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word {
            return Err(fail("T6000 native clock input width is unqualified"));
        }
        let register = Register::ALL
            .into_iter()
            .find(|register| register.address() == offset)
            .ok_or_else(|| fail("T6000 native clock input address is unqualified"))?;
        self.raw(register)
            .map(u64::from)
            .map_err(|error| fail(error.reason()))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        _: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        Err(refuse(
            NAME,
            offset,
            width,
            Direction::Write,
            "T6000 native clock input image does not qualify PLL/mux programming or lock changes",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use {stela_contracts::bus::Bus, stela_contracts::interrupt::InterruptLatch};

    pub(super) fn image(selection: u32, pll0: u32, pll1: u32, config0: u32, config1: u32) -> Image {
        let values = [pll0, config0, pll1, config1, selection];
        Image::new(Input::DeclaredStela(
            Register::ALL
                .into_iter()
                .zip(values)
                .map(|(register, value)| Observation {
                    register,
                    value,
                    known: u32::MAX,
                })
                .collect(),
        ))
        .unwrap()
    }
    #[test]
    fn original_integer_clock_family_keeps_bypass_disable_mux_and_wrapping_distinct() {
        let enabled = 1 << 31;
        let bypass = 1 << 27;
        let sample = image(enabled, enabled, enabled, 3000, 3);
        let parent0 = 3000 << 16;
        let parent1 = parent0 * 8;
        assert_eq!(sample.frequency(), Ok(parent0));
        for (selector, frequency) in [
            (1, parent1),
            (2, parent1 / 2),
            (3, (parent1 / 48) << 4),
            (4, parent0 / 2),
            (5, 0),
            (15, 0),
        ] {
            assert_eq!(
                image(enabled | selector << 24, enabled, enabled, 3000, 3).frequency(),
                Ok(frequency)
            );
        }
        assert_eq!(
            image(enabled, enabled | bypass, enabled, 3000, 3).frequency(),
            Ok(32768)
        );
        assert_eq!(
            image(enabled | 1 << 24, enabled, enabled | bypass, 3000, 3).frequency(),
            Ok(parent0)
        );
        assert_eq!(image(enabled, 0, enabled, 3000, 3).frequency(), Ok(0));
        assert_eq!(image(0, enabled, enabled, 3000, 3).frequency(), Ok(0));
        assert_eq!(
            image(enabled, enabled, enabled, (3 << 16) | (1 << 20) | 3000, 3).frequency(),
            Ok(((parent0 / 4) / 16) << 4)
        );
        let wrapped = (16383u32 << 16).wrapping_mul(2 * 8 * 2);
        assert_eq!(
            image(enabled | 1 << 24, enabled, enabled, (1 << 20) | 16383, 7).frequency(),
            Ok((wrapped / 16) << 4)
        );
    }
    #[test]
    fn unknown_inputs_refuse_programming() {
        let image = Image::new(Input::Captured(vec![
            Observation {
                register: Register::Selection,
                value: 1 << 31,
                known: u32::MAX,
            },
            Observation {
                register: Register::Pll0Control,
                value: 0,
                known: u32::MAX,
            },
        ]))
        .unwrap();
        assert_eq!(
            image.frequency(),
            Err(Error::Unknown(Register::Pll0Configuration))
        );
        let mut bus = Bus::new();
        let device = bus.add(Box::new(image.clone()));
        for address in image.addresses() {
            bus.map(device, address, 4, address).unwrap();
        }
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 1, &mut pins);
        assert_eq!(
            bus.read(Register::Pll0Control.address(), Width::Word, &mut access),
            Ok(0)
        );
        assert!(
            bus.read(
                Register::Pll0Configuration.address(),
                Width::Word,
                &mut access
            )
            .is_err()
        );
        assert!(
            bus.write(Register::Selection.address(), Width::Word, 0, &mut access)
                .is_err()
        );
        assert_eq!(image.raw(Register::Selection), Ok(1 << 31));
        assert!(matches!(
            Image::new(Input::DeclaredStela(image.observations().to_vec())),
            Err(Error::IncompleteDeclaration)
        ));
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_LLB"]
    fn original_native_delay_clock_routing_full_descriptor_and_pll_rules_are_pinned() {
        use sha2::{Digest, Sha256};
        let llb =
            std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").expect("original J314s LLB"))
                .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&llb)),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        for (lo, hi, digest) in [
            (
                0x10cd8,
                0x10eac,
                "9ad48af551ebd339203c324174bc24fcf7e31f2b8eeca30a69b2ca51fd19a65a",
            ),
            (
                0x10eac,
                0x11008,
                "db1df6fbaee2bdf86c972f498bea41121e0a213b47c64288264be8600adcb9f4",
            ),
            (
                0x48050,
                0x480d0,
                "5247ceec4a21a032d9c97d1c9d65abe03db5f8860c6def8f171cbccf071bf21a",
            ),
            (
                0x4658c,
                0x46620,
                "6b4413e53291a64497dd172b8a14cb060b7708a3d8dfaff27bbabe1f83db4936",
            ),
            (
                0x4a80c,
                0x4a814,
                "aa33a8e2714e2bf2548d1b1cba864ec757280ab060afabfdec8f0d8f11f78183",
            ),
            (
                0x4036c,
                0x4041c,
                "6d8ce83353fec0ac248368206eb95a0371fb3ff6f1780aa2f24c2c013ba034bf",
            ),
            (
                0x408a0,
                0x40964,
                "c6ec9a7a9aaa59788f1a99e28aedd31977f0149df2d3f38afeb6a1733a52b10c",
            ),
            (
                0xd728,
                0xdd80,
                "e5546035fe6856a6ca1053254e5c1ce77c2e9ac32f584df19eeaa3b71411e678",
            ),
            (
                0x3dcfc,
                0x3dd14,
                "3422d258b6f08b3582239dcecf3664580458d486bfa5944fbb8d3ee916ed8aa5",
            ),
            (
                0xf208,
                0xf254,
                "8c545ba4efeedb699bded73f541cf4fa36f74e284ccf91ce97e771726ea412e8",
            ),
            (
                0x2f17c,
                0x2f19c,
                "78f2bf233408889b28159524c9e1dbcfd61e499d7d00a1b7393abcdf1825ea61",
            ),
            (
                0x1a76d0,
                0x1a7770,
                "d85882b81b21c5ef6381f097fdee7cae709f4dff241fbdd51a494d9ca587e5ef",
            ),
            (
                0x1a7f40,
                0x1a7f90,
                "f7fb11d4a40ccfcff4e8281012a5446c45880712b8ae6b8566ed1b61e68dfab6",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
        }
        let word = |offset: usize| u32::from_le_bytes(llb[offset..offset + 4].try_into().unwrap());
        let quad = |offset: usize| u64::from_le_bytes(llb[offset..offset + 8].try_into().unwrap());
        for (register, offset) in [
            (Register::Pll0Configuration, 0x408b8),
            (Register::Pll1Configuration, 0x408c8),
        ] {
            let mut address = 0;
            for (index, opcode) in [0xd2800000, 0xf2a00000, 0xf2c00000].into_iter().enumerate() {
                let actual = word(offset + index * 4);
                assert_eq!(actual & 0xffe00000, opcode);
                address |= u64::from((actual >> 5) & 0xffff) << (index * 16);
            }
            assert_eq!(register.address(), address);
        }
        assert_eq!(
            Register::Pll0Control.address() + 12,
            Register::Pll0Configuration.address()
        );
        assert_eq!(
            Register::Pll1Control.address() + 12,
            Register::Pll1Configuration.address()
        );
        assert_eq!(quad(0x1a7f48), Register::Selection.address());
        assert_eq!(word(0x1a7f40), 0xc04c);
        let parameters: Vec<_> = (0..16).map(|index| word(0x1a7f50 + index * 4)).collect();
        assert_eq!(
            &parameters[..5],
            &[0x10002, 0x10003, 0x20003, 0x30003, 0x20002]
        );
        assert!(parameters[5..].iter().all(|entry| *entry == 0));
        // Parent2/3 call the PLL decoder with0/1, not a fixed24MHz alias.
        for (offset, instance) in [(0x1a76d0, 0), (0x1a7720, 1)] {
            assert_eq!(word(offset), 0x1c);
            assert_eq!(quad(offset + 8), instance);
        }
        // Delay count units, clock selector, parameter routing, PLL bypass base,
        // and native integer divisor/truncation operations from the original.
        for (offset, opcode) in [
            (0x10d30, 0x531a7e89),
            (0x10df8, 0x52800089),
            (0x10dfc, 0x2a141929),
            (0x10e60, 0xd297b809),
            (0x10e74, 0x52884809),
            (0x10e78, 0x72a001e9),
            (0x10e7c, 0x9ac90901),
            (0x10fcc, 0x52800889),
            (0x4a80c, 0x52800440),
            (0x40414, 0x528003a0),
            (0x40934, 0x52900000), // PLL0 bypass32768
        ] {
            assert_eq!(word(offset), opcode, "source{offset:x}");
        }
    }
}
