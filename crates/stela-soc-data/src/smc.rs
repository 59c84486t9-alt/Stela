//! Immutable SMC key/wake geometry and original RTC helper interface.
//! These fields grant no oscillator, wake-delivery or SRAM permission.
pub const SRAM_BYTES: u64 = 0x4000;
pub const WATCHDOG_BYTES: u64 = 0x14;
pub const fn code(name: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*name)
}

pub const RTC_KEY: u32 = code(b"CLKM");

/// The `MBSW` bits of the wake sources the board models, from `smc-pmu`'s
/// `event_name-bitN` names `pwrbtn` and `rtc`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WakeBits {
    pub power_button: Option<u8>,
    pub rtc: Option<u8>,
}

/// Declared key interface recovered from the original raw keyR consumer and
/// independently observed on the T6000/26B118 reference. This does not claim
/// that reference firmware or its persistent epoch is a 26A434 handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcKeyProfile {
    /// Six little-endian 32768 Hz ticks, hex_, attributes0x94. The original
    /// caller zero-initializes its eight-byte destination before raw keyR.
    Hex48Little,
}

impl RtcKeyProfile {
    /// Match the complete original helper descriptor to its resolved SMC PMU
    /// provider. A phandle alone cannot assign a key or an oscillator owner.
    pub fn from_function(cells: &[u32], provider: u32) -> Result<Self, &'static str> {
        if provider != 0 && cells == [provider, code(b"keyR"), RTC_KEY] {
            Ok(Self::Hex48Little)
        } else {
            Err("SMC RTC helper/provider descriptor is unqualified")
        }
    }
}
