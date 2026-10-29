//! Validated initial kept-history bytes; live read/acknowledgement state stays device-owned.
use super::Window;
use crate::Result;
use alloc::vec::Vec;
use stela_contracts::refuse;
#[derive(Debug, Clone)]
pub struct FaultHistory {
    pub window: Window,
    initial: Vec<u8>,
}

impl FaultHistory {
    pub fn new(window: Window, initial: Vec<u8>) -> Result<Self> {
        if window.bytes == 0
            // The original driver's declared fault-log count is one byte.
            || window.bytes > u16::from(u8::MAX)
            || u32::from(window.base) + u32::from(window.bytes) > 0x10000
            || initial.len() != usize::from(window.bytes)
        {
            return Err(refuse!(
                "PMU fault history requires a byte-sized count, valid extent and all initial bytes"
            ));
        }
        Ok(Self { window, initial })
    }
}

impl FaultHistory {
    /// Transfer only the declared initial bytes; no live acknowledgement state exists here.
    pub fn into_parts(self) -> (Window, Vec<u8>) {
        (self.window, self.initial)
    }
}
