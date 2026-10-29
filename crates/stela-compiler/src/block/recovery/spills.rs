//! Allocation-free capture of initialized invocation-owned native spill words.

pub const NATIVE_SPILL_WORDS: usize = 16;
const WORD_BYTES: u16 = core::mem::size_of::<u64>() as u16;

/// A byte offset from the interrupted host RSP, within the bounded bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SpillOffset(u16);
impl SpillOffset {
    pub const fn new(bytes: u16) -> Result<Self, InvalidSpillOffset> {
        if !bytes.is_multiple_of(WORD_BYTES) || bytes >= NATIVE_SPILL_WORDS as u16 * WORD_BYTES {
            Err(InvalidSpillOffset { bytes })
        } else {
            Ok(Self(bytes))
        }
    }
    pub const fn bytes(self) -> u16 {
        self.0
    }
    const fn index(self) -> usize {
        (self.0 / WORD_BYTES) as usize
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSpillOffset {
    pub bytes: u16,
}
impl core::fmt::Display for InvalidSpillOffset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "native spill offset {} must be 8-byte aligned and below 128",
            self.bytes
        )
    }
}
impl core::error::Error for InvalidSpillOffset {}

/// A bounded snapshot populated only by the invocation's capture owner.
/// Each recorded word requires a checked RSP+offset, kept mapped stack-root
/// and code/plan epoch, and an initialized interval in that invocation's lease.
/// Numeric bounds alone do not authorize reading native memory. Missing words
/// remain unavailable; XSAVE initialization rules never initialize spill memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSpillSnapshot {
    words: [u64; NATIVE_SPILL_WORDS],
    available: u16,
}
impl HostSpillSnapshot {
    pub const fn new() -> Self {
        Self {
            words: [0; NATIVE_SPILL_WORDS],
            available: 0,
        }
    }
    /// Record a word after the platform has proved its capture permission.
    /// This method copies data and never reads a native address.
    pub fn record(&mut self, offset: SpillOffset, value: u64) {
        self.words[offset.index()] = value;
        self.available |= 1 << offset.index();
    }
    pub const fn get(&self, offset: SpillOffset) -> Option<u64> {
        if self.available & (1 << offset.index()) == 0 {
            None
        } else {
            Some(self.words[offset.index()])
        }
    }
    /// Invalidate a previous capture without treating stale words as initialized.
    pub fn clear(&mut self) {
        self.available = 0;
    }
}
impl Default for HostSpillSnapshot {
    fn default() -> Self {
        Self::new()
    }
}
