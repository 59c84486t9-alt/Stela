//! Original SPMI handler layouts, independent of board or PMIC identity.
//!
//! 26A434 mac13j SHA256 5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90:
//! Gen1 init VA fffffe0009d499c4; Gen2 init 9d49f8c. Both use the same
//! request/response/interrupt queue bank. Gen1 fault counters instead use
//! independently mapped `reg[2]` (init 9d49afc..9b40 and table 82a8f78).
//! Controller::start reads response vector from `interrupts[0]` at 9d4cf28
//! and queue-depth byte counts at 9d4d230..264. The latter become words
//! through division by four at 9d52698..69c, not one word per DT byte.
//!
//! 26A434 J813AP (M5) kernelcache, AppleSPMI: the handler factory
//! fffffe0009e3fe18 builds `AppleGen3SPMIHandler` for `gen = 3` and
//! `AppleGen4SPMIHandler` for `gen = 4`; the J613AP (M3) kernelcache has the
//! same Gen3 handler (`initHandler` fffffe0009d57f48).
//!
//! - Gen3 (`initHandler` fffffe0009e385f8) keeps Gen2's bank A and fault
//!   FIFO, moves the six fault latches to B+0x200..0x214 (`clearInterrupt`
//!   fffffe0009e38c08, table fffffe0008315be8) and the 37 counters to
//!   B+0x400.. (table fffffe0008315998), and fails without `reg[2]`, whose
//!   +0x20 `resetArbiter` (fffffe0009e38800) pulses only after a queue
//!   reset that left the FIFOs non-empty (`resetQueueBase` fffffe0009e3f6c0).
//! - Gen4 (`initHandler` fffffe0009e38eac, offsets from the constant pool at
//!   fffffe0007759040) moves bank A: control A+0, queue reset A+4, status
//!   A+0x200 (request empty bit 14, full bit 15, response empty bit 30, full
//!   bit 31), request A+0x210, response A+0x220, enable/status A+0x400/0x600.
//!   The fault FIFO is B+0x200 (empty bit 30) with its pop at B+0x220, the
//!   latches B+0x1200..0x1214 (table fffffe0008316040) and the counters
//!   B+0x1400.. (table fffffe0008315df0). It also requires `reg[2]`, with the
//!   same `resetArbiter` (fffffe0009e390ec). `getQueueDepths`
//!   (fffffe0009e39084) reads both FIFO depths from A+0x48, request words in
//!   bits 25:16 and response words in bits 9:0, and returns true, so
//!   `AppleSPMIController::start` (fffffe0009e3b2a8) skips `queue-depth`;
//!   the Gen1-3 handlers inherit the base `getQueueDepths`, which returns
//!   false (fffffe0009e384e0), and take the DT's depths.
use crate::Result;
use stela_contracts::refuse;

/// Logical bank stride used by the controller's independently placed views.
/// Bank B's device offset; the placement maps `reg[1]` here.
pub const BANK_BYTES: u64 = 0x4000;
/// Bank B's device offset; the placement maps `reg[1]` here.
pub const BANK_B: u64 = BANK_BYTES;
/// The device offset of `reg[2]`: Gen1's independently mapped fault-counter
/// view, or the Gen3 and Gen4 arbiter bank.
pub const BANK_C: u64 = 2 * BANK_BYTES;
const WORD_BYTES: u32 = 4;
/// A full extended read consumes one header plus four payload words.
const COMPLETE_CHUNK_BYTES: u32 = 5 * WORD_BYTES;
const VECTOR_COUNT: u32 = 9 * 32;
const GEN1_COUNTER_OFFSETS: [u64; 16] = [
    0, 4, 8, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x5c, 0x60, 0x64, 0x68, 0x6c, 0x70, 0x74,
];
/// The Gen3 counter runs in bank B; Gen4's are the same runs 0x1000 higher.
const GEN3_COUNTER_RUNS: [(u64, u64); 4] = [
    (0x400, 0x428),
    (0x440, 0x464),
    (0x480, 0x4ac),
    (0x4c0, 0x4dc),
];
/// The Gen4 depth register holds each FIFO's words in ten bits.
const GEN4_DEPTH_WORDS: u32 = 0x3ff;

/// A generation's register offsets in the device: bank A from 0, bank B
/// from [`BANK_B`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub status: u64,
    pub request: u64,
    pub response: u64,
    pub enable: u64,
    pub pending: u64,
    pub control: u64,
    pub queue_reset: u64,
    pub request_empty: u32,
    pub response_empty: u32,
    pub response_full: u32,
    pub fault_status: u64,
    pub fault_response: u64,
    pub fault_empty: u32,
    /// The fault latches' span, read and written back to acknowledge.
    pub latches: Option<(u64, u64)>,
    /// The FIFO depth register.
    pub depth: Option<u64>,
}

const GEN2_LAYOUT: Layout = Layout {
    status: 0,
    request: 4,
    response: 8,
    enable: 0x20,
    pending: 0x60,
    control: 0xa0,
    queue_reset: 0xa4,
    request_empty: 1 << 8,
    response_empty: 1 << 24,
    response_full: 1 << 25,
    fault_status: BANK_B,
    fault_response: BANK_B + 8,
    fault_empty: 1 << 24,
    latches: Some((BANK_B + 0x110, BANK_B + 0x120)),
    depth: None,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Gen1,
    Gen2,
    Gen3,
    Gen4,
}
impl Profile {
    pub const fn bank_bytes(self) -> u64 {
        match self {
            Self::Gen1 => 0x100,
            Self::Gen2 | Self::Gen3 | Self::Gen4 => 0x4000,
        }
    }
    /// The size of Gen1's separate fault-counter view in `reg[2]`.
    pub const fn counter_bytes(self) -> Option<u64> {
        match self {
            Self::Gen1 => Some(0x78),
            Self::Gen2 | Self::Gen3 | Self::Gen4 => None,
        }
    }
    /// Does the handler always map `reg[2]` as a full bank, the arbiter's?
    pub const fn arbiter_bank(self) -> bool {
        matches!(self, Self::Gen3 | Self::Gen4)
    }
    pub const fn layout(self) -> Layout {
        match self {
            Self::Gen1 => Layout {
                latches: None,
                ..GEN2_LAYOUT
            },
            Self::Gen2 => GEN2_LAYOUT,
            Self::Gen3 => Layout {
                latches: Some((BANK_B + 0x200, BANK_B + 0x218)),
                ..GEN2_LAYOUT
            },
            Self::Gen4 => Layout {
                status: 0x200,
                request: 0x210,
                response: 0x220,
                enable: 0x400,
                pending: 0x600,
                control: 0,
                queue_reset: 4,
                request_empty: 1 << 14,
                response_empty: 1 << 30,
                response_full: 1 << 31,
                fault_status: BANK_B + 0x200,
                fault_response: BANK_B + 0x220,
                fault_empty: 1 << 30,
                latches: Some((BANK_B + 0x1200, BANK_B + 0x1218)),
                depth: Some(0x48),
            },
        }
    }
    pub fn counter(self, offset: u64) -> bool {
        let runs = |base: u64| {
            offset.checked_sub(base).is_some_and(|at| {
                GEN3_COUNTER_RUNS
                    .iter()
                    .any(|&(start, end)| (start..end).contains(&at))
            })
        };
        match self {
            Self::Gen1 => offset
                .checked_sub(BANK_C)
                .is_some_and(|at| GEN1_COUNTER_OFFSETS.contains(&at)),
            Self::Gen2 => offset
                .checked_sub(BANK_B)
                .is_some_and(|at| (0x200..0x228).contains(&at) || (0x25c..0x278).contains(&at)),
            Self::Gen3 => runs(BANK_B),
            Self::Gen4 => runs(BANK_B + 0x1000),
        }
    }
}

/// Immutable declared FIFO and interrupt resources. This carries no physical
/// address or native execution permission; placement must resolve the source DT.
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
    pub fn new(profile: Profile, response_vector: u32, queue_bytes: [u32; 2]) -> Result<Self> {
        if response_vector >= VECTOR_COUNT {
            return Err(refuse!(
                "SPMI response vector exceeds the nine interrupt groups"
            ));
        }
        if queue_bytes
            .iter()
            .any(|&bytes| bytes < COMPLETE_CHUNK_BYTES || !bytes.is_multiple_of(WORD_BYTES))
        {
            return Err(refuse!(
                "SPMI FIFO byte depths must hold a complete extended chunk and whole words"
            ));
        }
        if profile.layout().depth.is_some()
            && queue_bytes
                .iter()
                .any(|&bytes| bytes / WORD_BYTES > GEN4_DEPTH_WORDS)
        {
            return Err(refuse!(
                "SPMI FIFO depths exceed the depth register's ten-bit word fields"
            ));
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
    pub const fn response_words(self) -> usize {
        (self.queue_bytes[1] / WORD_BYTES) as usize
    }
    /// The depth register: request words in bits 25:16, response words in
    /// bits 9:0.
    pub const fn depth_register(self) -> u32 {
        ((self.queue_bytes[0] / WORD_BYTES) << 16) | (self.queue_bytes[1] / WORD_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independently_checked_fifo_bytes_and_vector_do_not_follow_generation_labels() {
        let cfg = Configuration::new(Profile::Gen1, 192, [256, 256]).unwrap();
        assert_eq!(cfg.response_words(), 64);
        assert_eq!(cfg.queue_bytes(), [256, 256]);
        assert_eq!(cfg.profile().bank_bytes(), 256);
        assert_eq!(cfg.profile().counter_bytes(), Some(120));
        assert!(cfg.profile().counter(BANK_C + 0x74));
        assert!(!cfg.profile().counter(BANK_C + 0xc));
        assert!(!cfg.profile().counter(BANK_B + 0x200));
        for bad in [[0, 256], [256, 16], [256, 255], [21, 256]] {
            assert!(Configuration::new(Profile::Gen1, 192, bad).is_err());
        }
        assert!(Configuration::new(Profile::Gen2, 288, [256, 256]).is_err());
        assert!(Configuration::new(Profile::Gen1, 287, [20, 24]).is_ok());
    }

    #[test]
    fn counters_follow_their_handler_tables() {
        // 37 counters each, the kernel tables' exact offsets.
        for (profile, base) in [(Profile::Gen3, BANK_B), (Profile::Gen4, BANK_B + 0x1000)] {
            let counters = (0..BANK_C)
                .step_by(4)
                .filter(|&at| profile.counter(at))
                .collect::<alloc::vec::Vec<_>>();
            assert_eq!(counters.len(), 37);
            assert_eq!(counters[0], base + 0x400);
            assert_eq!(counters[9], base + 0x424);
            assert_eq!(counters[10], base + 0x440);
            assert_eq!(counters[36], base + 0x4d8);
            assert!(profile.arbiter_bank());
        }
        assert!(!Profile::Gen2.arbiter_bank());
        let cfg = Configuration::new(Profile::Gen4, 0x100, [256, 128]).unwrap();
        assert_eq!(cfg.depth_register(), 64 << 16 | 32);
        assert!(Configuration::new(Profile::Gen4, 0x100, [4096, 256]).is_err());
        assert!(Configuration::new(Profile::Gen3, 0x100, [4096, 256]).is_ok());
    }
}
