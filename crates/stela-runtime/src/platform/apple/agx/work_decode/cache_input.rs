//! Original command -> scheduler buffer-cache descriptor fields.
//! Capturing these inputs is separate from cache allocation/native effects.

use super::{Encoding, Submission, range};
use crate::platform::apple::agx::{channel::Kind, ring::Shared};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferCacheInput {
    submission: Submission,
    address: u64,
    /// Raw AP words are retained even where the source BFI takes low11.
    units: u32,
    policy: u32,
}
impl BufferCacheInput {
    pub(super) fn read(
        memory: &mut dyn Shared,
        submission: &Submission,
    ) -> Result<Self, &'static str> {
        // Four source-qualified scheduler-descriptor consumers. The G15
        // packet/program ABI cannot inherit these fields by resemblance.
        let offset = match (submission.encoding, submission.command.kind) {
            (Encoding::Fixed, Kind::Ta) => 0x558,
            (Encoding::Fixed, Kind::ThreeD) => 0x8bc,
            (Encoding::Fixed, Kind::FastBlit) => 0x624,
            (Encoding::Fixed, Kind::Cl) => 0x284,
            (Encoding::G14X, Kind::Ta) => 0x85c,
            (Encoding::G14X, Kind::ThreeD) => 0xba4,
            (Encoding::G14X, Kind::FastBlit) => 0x914,
            (Encoding::G14X, Kind::Cl) => 0x7fc,
            (Encoding::G15G, _) => {
                return Err("GFX G15 buffer-cache input descriptor is not qualified");
            }
            _ => return Err("GFX buffer-cache inputs require a work command"),
        };
        let mut bytes = [0; 16];
        memory.read(
            range(submission.command.va, offset, bytes.len())?,
            &mut bytes,
        )?;
        Ok(Self {
            submission: submission.clone(),
            address: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            units: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            policy: u32::from_le_bytes(bytes[12..].try_into().unwrap()),
        })
    }
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn units(&self) -> u32 {
        self.units
    }
    pub fn policy(&self) -> u32 {
        self.policy
    }
    pub fn submission(&self) -> &Submission {
        &self.submission
    }
    /// The three original BFI/BFXIL operations preserve the scheduler's
    /// high nibble. This packs inputs only; it allocates/enables no cache.
    pub fn descriptor_word(&self, previous: u32) -> u32 {
        (previous & 0xf0000000)
            | (self.submission.context & 0x3f)
            | (self.units & 0x7ff) << 6
            | (self.policy & 0x7ff) << 17
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::{
        channel::{Command, Stamp},
        generation,
        ring::tests::Flat,
        work_decode::{Accepted, Submission},
    };
    const BASE: u64 = 0x10000;
    #[test]
    fn original_work_inputs_preserve_raw_words_and_source_descriptor_masks() {
        for (family, rows) in [
            (
                &generation::G13G,
                [
                    (Kind::Ta, 0x558),
                    (Kind::ThreeD, 0x8bc),
                    (Kind::FastBlit, 0x624),
                    (Kind::Cl, 0x284),
                ],
            ),
            (
                &generation::G13X,
                [
                    (Kind::Ta, 0x558),
                    (Kind::ThreeD, 0x8bc),
                    (Kind::FastBlit, 0x624),
                    (Kind::Cl, 0x284),
                ],
            ),
            (
                &generation::G14G,
                [
                    (Kind::Ta, 0x558),
                    (Kind::ThreeD, 0x8bc),
                    (Kind::FastBlit, 0x624),
                    (Kind::Cl, 0x284),
                ],
            ),
            (
                &generation::G14X,
                [
                    (Kind::Ta, 0x85c),
                    (Kind::ThreeD, 0xba4),
                    (Kind::FastBlit, 0x914),
                    (Kind::Cl, 0x7fc),
                ],
            ),
        ] {
            for (kind, at) in rows {
                let input = Submission {
                    command: Command { va: BASE, kind },
                    encoding: Encoding::for_family(family).unwrap(),
                    counter: 7,
                    context: 37,
                    stamp: Stamp {
                        driver: 0,
                        firmware: 0,
                        value: 0,
                        index: 0,
                    },
                    stream: BASE + 0x1000,
                    stream_bytes: 64,
                };
                let mut memory = Flat::new(BASE, 0x2000);
                memory.put_u64(BASE + at, 0x123456789abcdef0);
                memory.put_u32(BASE + at + 8, 0xf1234567);
                memory.put_u32(BASE + at + 12, 0xe9876543);
                let snapshot = BufferCacheInput::read(&mut memory, &input).unwrap();
                assert_eq!(snapshot.submission(), &input);
                assert_eq!(
                    (snapshot.address, snapshot.units, snapshot.policy),
                    (0x123456789abcdef0, 0xf1234567, 0xe9876543)
                );
                for high in 0..16 {
                    assert_eq!(
                        snapshot.descriptor_word(high << 28 | 0x0fffffff),
                        high << 28 | 37 | (0x567 << 6) | (0x543 << 17)
                    );
                }
                memory.put_u64(BASE + at, 0);
                assert_eq!(snapshot.address, 0x123456789abcdef0);
                let mut wrapping = input.clone();
                wrapping.command.va = u64::MAX - at - 14;
                assert!(BufferCacheInput::read(&mut memory, &wrapping).is_err());
                let mut newer = input.clone();
                newer.encoding = Encoding::G15G;
                assert!(BufferCacheInput::read(&mut memory, &newer).is_err());
            }
        }
    }
    #[test]
    fn accepted_cache_inputs_do_not_reread_after_a_later_record_fault() {
        let mut memory = Flat::new(BASE, 0x1000);
        memory.put_u32(BASE, 3);
        memory.put_u64(BASE + 4, 11);
        memory.put_u32(BASE + 12, 5);
        memory.put_u64(BASE + 0x1e8, BASE + 0x1000); // unmapped record
        memory.put_u32(BASE + 0x1f0, 64);
        memory.put_u64(BASE + 0x284, 0x90000000);
        memory.put_u32(BASE + 0x28c, 9);
        memory.put_u32(BASE + 0x290, 3);
        let mut accepted = Accepted::read(
            &mut memory,
            &generation::G13X,
            Command {
                va: BASE,
                kind: Kind::Cl,
            },
        )
        .unwrap();
        assert!(accepted.cache_input().is_err());
        let original = accepted.capture_cache_input(&mut memory).unwrap().clone();
        assert!(accepted.current(&mut memory).is_err());
        memory.put_u64(BASE + 0x284, 0xb0000000);
        memory.put_u32(BASE + 0x28c, 0);
        assert!(accepted.current(&mut memory).is_err());
        assert_eq!(accepted.cache_input(), Ok(&original));
        assert_eq!(accepted.capture_cache_input(&mut memory), Ok(&original));
        assert_eq!(original.descriptor_word(0xa0000000), 0xa0060245);
        assert_eq!(memory.read_u32(BASE + 0x2a8), Ok(0));
    }
    #[test]
    fn later_sku_acceptance_cannot_capture_new_scheduler_inputs() {
        let mut memory = Flat::new(BASE, 0x2000);
        memory.put_u32(BASE, 3);
        memory.put_u64(BASE + 4, 11);
        memory.put_u32(BASE + 12, 5);
        memory.put_u64(BASE + 0x1e8, BASE + 0x1000);
        memory.put_u32(BASE + 0x1f0, 0x200);
        memory.put_u32(BASE + 0x1000, 11);
        let mut accepted = Accepted::read(
            &mut memory,
            &generation::G14G,
            Command {
                va: BASE,
                kind: Kind::Cl,
            },
        )
        .unwrap();
        accepted.current(&mut memory).unwrap();
        let snapshot = accepted.clone();
        assert!(accepted.capture_cache_input(&mut memory).is_err());
        assert_eq!(accepted, snapshot);
        assert!(accepted.cache_input().is_err());
    }
}
