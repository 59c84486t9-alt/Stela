// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Serialized legacy-width queued invalidation with checked status writeback.
use super::*;

const DESCRIPTOR_BYTES: usize = 16;
const QUEUE_FAULTS: u32 = 1 << 4 | 1 << 5 | 1 << 6;

#[derive(Clone, Copy)]
pub(super) struct Descriptor([u64; 2]);
impl Descriptor {
    pub(super) fn context_global() -> Self {
        Self([1 | 1 << 4, 0])
    }
    pub(super) fn iec(index: Option<u16>) -> Self {
        Self([
            4 | index.map_or(0, |index| 1 << 4 | u64::from(index) << 32),
            0,
        ])
    }
    pub(super) fn iotlb(
        cap: u64,
        granularity: u8,
        did: u16,
        address: u64,
        mask: u8,
    ) -> Result<Self, VtdError> {
        if !(1..=3).contains(&granularity) || mask > 63 || address & 0xfff != 0 {
            return Err(VtdError::Unsupported);
        }
        let mut low = 2 | u64::from(granularity) << 4 | u64::from(did) << 16;
        if cap & CAP_WRITE_DRAIN != 0 {
            low |= 1 << 6
        }
        if cap & CAP_READ_DRAIN != 0 {
            low |= 1 << 7
        }
        Ok(Self([low, address | u64::from(mask)]))
    }
    fn wait(physical: u64, token: u32) -> Result<Self, VtdError> {
        if physical & 3 != 0 || physical & !ADDRESS != 0 || token == 0 {
            return Err(VtdError::Unsupported);
        }
        Ok(Self([
            5 | 1 << 5 | 1 << 6 | u64::from(token) << 32,
            physical,
        ]))
    }
}

impl State {
    fn completed_token(&self) -> u32 {
        // SAFETY: status page is kept mapped WB, DWORD aligned; Wait performs
        // the architecture's coherent DWORD status write to this same RAM.
        unsafe { self.status.pointer(0).cast::<u32>().read_volatile() }
    }
    pub(super) fn quiescent<R: Registers>(&self, unit: &Unit<R>) -> Result<(), VtdError> {
        if unit.registers.read64(IQH) != self.tail as u64
            || unit.registers.read64(IQT) != self.tail as u64
            || self.completed_token() != self.token
        {
            return Err(VtdError::Invalidation);
        }
        Ok(())
    }
    pub(super) fn execute<R: Registers>(
        &mut self,
        unit: &Unit<R>,
        descriptors: &[Descriptor],
    ) -> Result<(), VtdError> {
        self.check(unit)?;
        if descriptors.is_empty() || descriptors.len() > 2 {
            return Err(VtdError::Unsupported);
        }
        if let Err(error) = self.quiescent(unit) {
            self.poisoned = true;
            return Err(error);
        }
        let sequence = self.sequence.checked_add(1).ok_or(VtdError::Exhausted)?;
        let token = if self.token == u32::MAX {
            1
        } else {
            self.token + 1
        };
        let wait = Descriptor::wait(self.status.physical(), token)?;
        self.poisoned = true;
        // VT-d 5.0 section 6.5.2 defines quiescence as an empty queue whose
        // last completed descriptor was Wait. Its coherent DWORD write has
        // been observed above, so no earlier status write remains pending.
        // Only at that boundary may the same status word/wire token be reused.
        // Zero is never emitted by Wait; publish and observe this sentinel
        // before any new tail publication, even when the wire token repeats.
        // Timeout/fault paths stay poisoned and never clear/reuse this word.
        // SAFETY: same retained WB, aligned coherent DWORD as completed_token.
        unsafe { self.status.pointer(0).cast::<u32>().write_volatile(0) };
        publish();
        if self.completed_token() != 0 {
            return Err(VtdError::Invalidation);
        }
        let mut next = self.tail;
        for descriptor in descriptors.iter().copied().chain(core::iter::once(wait)) {
            self.ring.write(next / 8, descriptor.0[0]);
            self.ring.write(next / 8 + 1, descriptor.0[1]);
            next = (next + DESCRIPTOR_BYTES) % PAGE;
        }
        self.publish(unit, &self.ring);
        self.sequence = sequence;
        self.token = token;
        self.tail = next;
        unit.registers.write64(IQT, next as u64);
        let start = unit.registers.ticks();
        loop {
            self.check_hardware(unit)?;
            if unit.registers.read32(FSTS) & QUEUE_FAULTS != 0 {
                return Err(VtdError::Invalidation);
            }
            let head = unit.registers.read64(IQH);
            if head >= PAGE as u64
                || !head.is_multiple_of(DESCRIPTOR_BYTES as u64)
                || unit.registers.read64(IQT) != next as u64
            {
                return Err(VtdError::Invalidation);
            }
            let observed = self.completed_token();
            if observed != 0 && observed != token {
                return Err(VtdError::Invalidation);
            }
            if observed == token && head == next as u64 {
                self.check_hardware(unit)?;
                publish();
                self.poisoned = false;
                return Ok(());
            }
            if unit.registers.ticks().wrapping_sub(start) >= unit.registers.timeout_ticks() {
                return Err(VtdError::Timeout);
            }
            core::hint::spin_loop();
        }
    }
}
