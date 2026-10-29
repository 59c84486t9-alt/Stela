//! First-die T6000 physical identity and revision inputs.
//!
//! Matching J314s LLB readers consume complete 32-bit physical words, even
//! where their result uses only a few bits. A capture may leave any bits
//! unknown. A declared Stela input must explicitly supply the whole input
//! family; neither permission fills omitted words from DT or reset guesses.
//! This image owns no fuse programming, bit31 lock, PMGR supply, firmware RAM
//! cache, native trigger or retirement. Those operations cannot mutate or
//! replace it through this read interface.
use alloc::{rc::Rc, vec::Vec};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "t6000-identity-inputs";

/// Exact first-die input words in the source identity/revision reader family.
/// Neutral fuse-offset names avoid assigning unproved hardware meanings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Chip,
    Revision,
    Discriminator,
    Fuse058,
    Fuse0cc,
    Fuse164,
    Feature,
    FeaturePrefix,
}
impl Register {
    pub const ALL: [Self; 8] = [
        Self::Chip,
        Self::Revision,
        Self::Discriminator,
        Self::Fuse058,
        Self::Fuse0cc,
        Self::Fuse164,
        Self::Feature,
        Self::FeaturePrefix,
    ];
    pub const fn address(self) -> u64 {
        match self {
            Self::Chip => 0x2922dc22c,
            Self::Revision => 0x2922bc05c,
            Self::Discriminator => 0x2922bc144,
            Self::Fuse058 => 0x2922bc058,
            Self::Fuse0cc => 0x2922bc0cc,
            Self::Fuse164 => 0x2922bc164,
            Self::Feature => 0x2922bc010,
            Self::FeaturePrefix => 0x2922d0020,
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

/// The caller keeps evidence for its supplied input permission. Naming a
/// capture here does not authenticate it or turn a live observation into a
/// cold firmware handoff. Stela declarations describe emulated resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    Captured,
    DeclaredStela,
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
    InvalidChip,
}
impl Error {
    fn reason(self) -> &'static str {
        match self {
            Self::Duplicate => "T6000 identity input repeats a physical word",
            Self::IncompleteDeclaration => {
                "T6000 declared identity must explicitly supply every complete physical word"
            }
            Self::Unknown(_) => "T6000 physical identity/revision input word is not fully known",
            Self::InvalidChip => "T6000 native chip decoder rejects low identity bits3",
        }
    }
}

struct State {
    authority: Authority,
    words: [Observation; Register::ALL.len()],
}

/// Clones expose the same immutable input image. There is no replacement or
/// write API which could substitute an input during an in-flight native read.
#[derive(Clone)]
pub struct Image(Rc<State>);
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
        Ok(Self(Rc::new(State { authority, words })))
    }
    pub fn authority(&self) -> Authority {
        self.0.authority
    }
    pub fn observations(&self) -> &[Observation] {
        &self.0.words
    }
    /// Full-PA offsets to map individually, each with extent4. The sparse
    /// surrounding physical banks are not claimed by this input owner.
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
    /// Original `2e744`: low2 selects6000/6001/6002;3 takes the fatal branch.
    /// Requires the complete word, as does its physical LDR.
    pub fn chip(&self) -> Result<u16, Error> {
        let low = (self.raw(Register::Chip)? & 3) as u16;
        if low == 3 {
            return Err(Error::InvalidChip);
        }
        Ok(0x6000 | low)
    }
    /// Original uncached `2e9a8`/`2e9ec` interpretation. The discriminator is
    /// bits23:14;8f suppresses revision bits6:4. The firmware's independently
    /// initialized RAM cache at source212958 is not owned or initialized here.
    pub fn revision(&self) -> Result<u8, Error> {
        let mut raw = self.raw(Register::Revision)?;
        let discriminator = (self.raw(Register::Discriminator)? >> 14) & 0x3ff;
        if discriminator == 0x8f {
            raw &= !0x70;
        }
        Ok(((raw & 0x70) | ((raw >> 1) & 7)) as u8)
    }
}

impl MmioDevice for Image {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |why| refuse(NAME, offset, width, Direction::Read, why);
        if width != Width::Word {
            return Err(fail("T6000 identity input reader width is not qualified"));
        }
        let register = Register::ALL
            .into_iter()
            .find(|register| register.address() == offset)
            .ok_or_else(|| fail("T6000 physical identity input address is not qualified"))?;
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
            "T6000 identity input image does not qualify physical programming/feature lock/readback",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use {stela_contracts::bus::Bus, stela_contracts::interrupt::InterruptLatch};

    fn word(register: Register, value: u32) -> Observation {
        Observation {
            register,
            value,
            known: u32::MAX,
        }
    }
    fn declared() -> Image {
        Image::new(Input::DeclaredStela(
            Register::ALL
                .into_iter()
                .enumerate()
                .map(|(i, register)| word(register, 0xa5000000 | (i as u32 * 0x10)))
                .collect(),
        ))
        .unwrap()
    }
    fn mount(image: &Image) -> Bus {
        let mut bus = Bus::new();
        let device = bus.add(Box::new(image.clone()));
        for address in image.addresses() {
            bus.map(device, address, 4, address).unwrap();
        }
        bus
    }

    #[test]
    fn actual_sparse_bus_reads_share_explicit_authority_without_claiming_surrounding_banks() {
        let image = declared();
        let mut bus = mount(&image);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 123, &mut pins);
        assert_eq!(image.authority(), Authority::DeclaredStela);
        for observation in image.observations() {
            assert_eq!(
                bus.read(observation.register.address(), Width::Word, &mut access),
                Ok(u64::from(observation.value))
            );
        }
        assert!(matches!(
            bus.read(Register::Chip.address() + 4, Width::Word, &mut access),
            Err(MmioError::Unmapped { .. })
        ));
        assert!(
            bus.read(Register::Chip.address(), Width::Byte, &mut access)
                .is_err()
        );
        assert!(image.clone().lifecycle().is_none());
    }

    #[test]
    fn partial_capture_never_promotes_only_consumed_low_bits_to_a_complete_ldr() {
        let image = Image::new(Input::Captured(vec![Observation {
            register: Register::Chip,
            value: 0xfffffff0,
            known: 3,
        }]))
        .unwrap();
        assert_eq!(image.authority(), Authority::Captured);
        assert_eq!(image.chip(), Err(Error::Unknown(Register::Chip)));
        assert_eq!(
            image.raw(Register::Revision),
            Err(Error::Unknown(Register::Revision))
        );
        assert_eq!(image.observations()[0].value, 0);
        let mut bus = mount(&image);
        let mut pins = InterruptLatch::new();
        assert!(
            bus.read(
                Register::Chip.address(),
                Width::Word,
                &mut Access::new(0, 0, &mut pins)
            )
            .is_err()
        );
        assert!(matches!(
            Image::new(Input::DeclaredStela(image.observations().to_vec())),
            Err(Error::IncompleteDeclaration)
        ));
        assert!(matches!(
            Image::new(Input::Captured(vec![
                word(Register::Chip, 0),
                word(Register::Chip, 0)
            ])),
            Err(Error::Duplicate)
        ));
    }

    #[test]
    fn native_revision_discriminator_and_all_chip_branches_retain_exact_source_rules() {
        for chip in 0..=3 {
            for raw in [0, 0x10, 0x20, 0x21, 0x42, 0xfffffff6] {
                for discriminator in [0, 0x8e, 0x8f, 0x90, 0x3ff] {
                    let image = Image::new(Input::Captured(vec![
                        word(Register::Chip, 0xabcdef00 | chip),
                        word(Register::Revision, raw),
                        word(Register::Discriminator, 0xa5000001 | discriminator << 14),
                    ]))
                    .unwrap();
                    assert_eq!(
                        image.chip(),
                        if chip == 3 {
                            Err(Error::InvalidChip)
                        } else {
                            Ok(0x6000 | chip as u16)
                        }
                    );
                    let upper = if discriminator == 0x8f { 0 } else { raw & 0x70 };
                    assert_eq!(image.revision(), Ok((upper | (raw >> 1) & 7) as u8));
                }
            }
        }
    }

    #[test]
    fn feature_lock_write_refuses_without_fabricating_barrier_readback_or_losing_other_reads() {
        let image = declared();
        let before = image.observations().to_vec();
        let mut bus = mount(&image);
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 55, &mut pins);
        let address = Register::Feature.address();
        let old = bus.read(address, Width::Word, &mut access).unwrap();
        assert!(matches!(
            bus.write(address, Width::Word, old | 1 << 31, &mut access),
            Err(MmioError::Unsupported {
                direction: Direction::Write,
                ..
            })
        ));
        assert_eq!(bus.read(address, Width::Word, &mut access), Ok(old));
        assert_eq!(image.observations(), before);
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_LLB"]
    fn original_identity_address_producers_and_revision_branches_are_pinned() {
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
                0x2e744,
                0x2e79c,
                "e7336bb3f4c1a272b06f8fe64d8dcb700cb6c896f2368b59cf2f77c5f12100d6",
            ),
            (
                0x2e978,
                0x2eaac,
                "052db995465dcadec56e651f0a7b99fccc705dce2a2f87ee4db304c0775216cc",
            ),
            (
                0x2eaac,
                0x2eb68,
                "22ef408e9906e37565ef74001a902323937f7d0986ea53e24a9af68c725c902b",
            ),
            (
                0x2ebf4,
                0x2ec0c,
                "82682e5a30a4a4763a755f845a3c55fbe017ff2cdf3632932d4306c8cb6fc9a0",
            ),
            (
                0x2f110,
                0x2f13c,
                "5b59b4289fce917dfa494b352d461b430c9d479b27f2008774b7ddacaae5d090",
            ),
            (
                0x2b470,
                0x2b4bc,
                "76f6786faf0fba634375986e2a2aa3e409fe13a539f83d085f8a62365779e132",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
        }
        let word = |offset: usize| u32::from_le_bytes(llb[offset..offset + 4].try_into().unwrap());
        assert_eq!(word(0x212958), u32::MAX); // copied file input, not BSS/reset
        for (register, offsets, load) in [
            (Register::Chip, [0x2e744, 0x2e748, 0x2e74c], 0x2e750),
            (Register::Revision, [0x2e9b8, 0x2e9bc, 0x2e9c0], 0x2e9c4),
            (
                Register::Discriminator,
                [0x2ea00, 0x2ea04, 0x2ea08],
                0x2ea0c,
            ),
            (Register::Fuse058, [0x2ea1c, 0x2ea20, 0x2ea24], 0x2ea28),
            (Register::Fuse0cc, [0x2ea3c, 0x2ea40, 0x2ea44], 0x2ea4c),
            (Register::Fuse164, [0x2ea34, 0x2f12c, 0x2f130], 0x2f134),
            (Register::Feature, [0x2e978, 0x2e97c, 0x2e980], 0x2e984),
            (
                Register::FeaturePrefix,
                [0x2b488, 0x2b48c, 0x2b490],
                0x2b494,
            ),
        ] {
            let mut address = 0;
            let destination = word(offsets[0]) & 0x1f;
            for (index, offset) in offsets.into_iter().enumerate() {
                let opcode = word(offset);
                assert_eq!(opcode & 0x1f, destination);
                assert_eq!(
                    opcode & 0xffe00000,
                    [0xd2800000, 0xf2a00000, 0xf2c00000][index]
                );
                address |= u64::from((opcode >> 5) & 0xffff) << (index * 16);
            }
            assert_eq!(register.address(), address);
            assert_eq!(word(load) & 0xffffffe0, 0xb9400000 | destination << 5);
        }
        // Native decoders, including the fatal low2==3 branch and the
        // discriminator's firmware-RAM cache. No synthetic initial cache value.
        for (offset, opcode) in [
            (0x2e754, 0x12000509), // AND low2
            (0x2e75c, 0x33000501), // BFXIL chip low2
            (0x2e760, 0x71000d3f), // CMP low2,3
            (0x2e764, 0x54000060), // EQ fatal
            (0x2e9cc, 0x12197268), // clear revision bits6:4
            (0x2e9d0, 0x71023c1f), // compare discriminator8f
            (0x2e9d4, 0x1a930108), // CSEL preserved/cleared raw
            (0x2e9d8, 0x121c0900), // AND70
            (0x2e9dc, 0x33010d00), // BFXIL bits3:1
            (0x2e9f4, 0x3100041f), // cached discriminator == u32::MAX
            (0x2ea10, 0x530e5d20), // UBFX23:14
            (0x2eb08, 0x32010108), // original feature OR bit31
            (0x2eb0c, 0xb90002a8), // physical write
            (0x2eb10, 0x97ffda6f), // barrier helper
            (0x2eb14, 0xb94002a8), // readback, not implicit completion
        ] {
            assert_eq!(word(offset), opcode, "source{offset:x}");
        }
    }
}
