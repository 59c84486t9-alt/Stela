//! Original SPMI handler layouts, independent of board or PMIC identity.
//!
//! 26A434 mac13j SHA256 5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90:
//! Gen1 init VA fffffe0009d499c4; Gen2 init 9d49f8c. Both use the same
//! request/response/interrupt queue bank. Gen1 fault counters instead use
//! independently mapped reg[2] (init 9d49afc..9b40 and table 82a8f78).
//! Controller::start reads response vector from interrupts[0] at 9d4cf28
//! and queue-depth byte counts at 9d4d230..264. The latter become words
//! through division by four at 9d52698..69c, not one word per DT byte.

use super::COUNTERS;
const WORD_BYTES: u32 = 4;
/// A full extended read consumes one header plus four payload words.
const COMPLETE_CHUNK_BYTES: u32 = 5 * WORD_BYTES;
const VECTOR_COUNT: u32 = 9 * 32;
const GEN1_COUNTER_OFFSETS: [u64; 16] = [
    0, 4, 8, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x5c, 0x60, 0x64, 0x68, 0x6c, 0x70, 0x74,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Gen1,
    Gen2,
}
impl Profile {
    pub const fn bank_bytes(self) -> u64 {
        match self {
            Self::Gen1 => 0x100,
            Self::Gen2 => 0x4000,
        }
    }
    pub const fn counter_bytes(self) -> Option<u64> {
        match self {
            Self::Gen1 => Some(0x78),
            Self::Gen2 => None,
        }
    }
    pub(super) fn counter(self, offset: u64) -> bool {
        match self {
            Self::Gen1 => offset
                .checked_sub(COUNTERS)
                .is_some_and(|at| GEN1_COUNTER_OFFSETS.contains(&at)),
            Self::Gen2 => offset
                .checked_sub(super::BANK_B)
                .is_some_and(|at| (0x200..0x228).contains(&at) || (0x25c..0x278).contains(&at)),
        }
    }
}

/// Immutable declared FIFO and interrupt resources. This carries no physical
/// address or native execution authority; placement must resolve the source DT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Configuration {
    profile: Profile,
    response_vector: u32,
    queue_bytes: [u32; 2],
}
impl Configuration {
    pub const GEN2: Self = Self {
        profile: Profile::Gen2,
        response_vector: 0x100,
        queue_bytes: [256, 256],
    };
    pub fn new(
        profile: Profile,
        response_vector: u32,
        queue_bytes: [u32; 2],
    ) -> Result<Self, &'static str> {
        if response_vector >= VECTOR_COUNT {
            return Err("SPMI response vector exceeds the nine interrupt groups");
        }
        if queue_bytes
            .iter()
            .any(|&bytes| bytes < COMPLETE_CHUNK_BYTES || !bytes.is_multiple_of(WORD_BYTES))
        {
            return Err(
                "SPMI FIFO byte depths must hold a complete extended chunk and whole words",
            );
        }
        Ok(Self {
            profile,
            response_vector,
            queue_bytes,
        })
    }
    pub const fn profile(self) -> Profile {
        self.profile
    }
    pub const fn response_vector(self) -> u32 {
        self.response_vector
    }
    pub const fn queue_bytes(self) -> [u32; 2] {
        self.queue_bytes
    }
    pub(super) const fn response_words(self) -> usize {
        (self.queue_bytes[1] / WORD_BYTES) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independently_qualified_fifo_bytes_and_vector_do_not_follow_generation_labels() {
        let cfg = Configuration::new(Profile::Gen1, 192, [256, 256]).unwrap();
        assert_eq!(cfg.response_words(), 64);
        assert_eq!(cfg.queue_bytes(), [256, 256]);
        assert_eq!(cfg.profile().bank_bytes(), 256);
        assert_eq!(cfg.profile().counter_bytes(), Some(120));
        assert!(cfg.profile().counter(COUNTERS + 0x74));
        assert!(!cfg.profile().counter(COUNTERS + 0xc));
        assert!(!cfg.profile().counter(super::super::BANK_B + 0x200));
        for bad in [[0, 256], [256, 16], [256, 255], [21, 256]] {
            assert!(Configuration::new(Profile::Gen1, 192, bad).is_err());
        }
        assert!(Configuration::new(Profile::Gen2, 288, [256, 256]).is_err());
        assert!(Configuration::new(Profile::Gen1, 287, [20, 24]).is_ok());
    }
}
