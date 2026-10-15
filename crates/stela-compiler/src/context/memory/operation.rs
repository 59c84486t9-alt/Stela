//! Shared typed memory-service classes and explicit ordering intent.

/// A CPU owner must opt in before native entry for a typed service class.
/// This Rust-only category is not a wire discriminator or guest opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOperationClass {
    Atomic,
    Ordered,
    Exclusive,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOrder {
    Relaxed = 0,
    AcquireRcpc = 1,
    AcquireRcsc = 2,
    Release = 3,
    AcquireRelease = 4,
}

impl MemoryOrder {
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            value if value == Self::Relaxed as u32 => Some(Self::Relaxed),
            value if value == Self::AcquireRcpc as u32 => Some(Self::AcquireRcpc),
            value if value == Self::AcquireRcsc as u32 => Some(Self::AcquireRcsc),
            value if value == Self::Release as u32 => Some(Self::Release),
            value if value == Self::AcquireRelease as u32 => Some(Self::AcquireRelease),
            _ => None,
        }
    }
}
