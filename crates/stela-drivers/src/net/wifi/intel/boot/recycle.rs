// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2003-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
//! Explicit RX pool reuse using source free-ring producer granularity.
use super::*;
use alloc::collections::VecDeque;
#[derive(Clone, Copy, Default)]
struct Slot {
    device: bool,
    completed: bool,
}
pub(super) struct Ring {
    write: u16,
    actual: u16,
    slots: Vec<Slot>,
    staged: VecDeque<(u16, u16)>,
    buffer_staged: Vec<bool>,
    buffer_slot: Vec<u16>,
}
impl Ring {
    pub(super) fn new(entries: u16) -> Self {
        Self {
            write: 0,
            actual: 0,
            slots: alloc::vec![Slot::default();usize::from(entries)],
            staged: VecDeque::with_capacity(usize::from(entries)),
            buffer_staged: alloc::vec![false;usize::from(entries-1)],
            buffer_slot: (0..entries - 1).collect(),
        }
    }
    pub(super) fn initial(&mut self, entries: u16, published: u16) {
        self.write = entries - 1;
        self.actual = published;
        for slot in 0..entries - 1 {
            if slot < published {
                self.slots[usize::from(slot)].device = true;
            } else {
                self.staged.push_back((slot, slot + 1));
                self.buffer_staged[usize::from(slot)] = true;
            }
        }
    }
    pub(super) fn complete(&mut self, vid: u16) -> Result<(), Error> {
        let index = usize::from(vid - 1);
        let slot = usize::from(self.buffer_slot[index]);
        if self.buffer_staged[index] || !self.slots[slot].device || self.slots[slot].completed {
            return Err(Error::CompletionId(vid));
        }
        self.slots[slot].completed = true;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replenished {
    pub returned: u16,
    pub published: u16,
    pub device_credits: u16,
    pub waiting_for_completed_slot: bool,
}
impl<Q: BootIo> RomBoot<'_, Q> {
    /// Explicit process-context rearm of buffers whose real RX completion and
    /// CPU visibility already finished. Previously returned byte vectors are
    /// owned copies; no device/CPU references to recycled payload RAM escape.
    /// Staging alone grants no device credit: only actual producer publication
    /// in source groups of8 does. No allocation, IRQ queue or timeout is used.
    pub fn replenish_completed_receive(&mut self) -> Result<Replenished, Error> {
        if self.state != State::PnvmObserved {
            return Err(Error::State);
        }
        let result = self.replenish_receive_inner();
        if result.is_err() {
            self.state = State::Poisoned;
        }
        result
    }
    fn replenish_receive_inner(&mut self) -> Result<Replenished, Error> {
        let stride = if self.profile.family() == Family::Ax210 {
            16
        } else {
            8
        };
        let mut returned = 0;
        let mut waiting = false;
        for index in 0..self.buffers.len() {
            if self.buffers[index].device_owned || self.receive_ring.buffer_staged[index] {
                continue;
            }
            let slot = usize::from(self.receive_ring.write);
            let owner = &mut self.receive_ring.slots[slot];
            if owner.device {
                if !owner.completed {
                    waiting = true;
                    break;
                }
                // The exact descriptor's prior actual buffer completion
                // proves its device access ended. Other slots stay live.
                unsafe {
                    self.free
                        .complete_for_cpu(slot * stride..(slot + 1) * stride)?;
                }
                owner.device = false;
                owner.completed = false;
            }
            let buffer = &self.buffers[index];
            // Actual completed_buffer already transferred this payload to
            // the CPU and copied it. Return it to DMA before its next pointer.
            unsafe {
                buffer.allocation.ready_for_device()?;
            }
            let vid = index as u16 + 1;
            let descriptor = receive::free_descriptor(
                self.profile.family(),
                buffer.allocation.region().address,
                vid,
            )?;
            let bytes = match &descriptor {
                FreeDescriptor::Ax200(b) => b.as_slice(),
                FreeDescriptor::Ax210(b) => b.as_slice(),
            };
            unsafe {
                self.free.write_owned(slot * stride, bytes)?;
            }
            self.receive_ring.buffer_staged[index] = true;
            self.receive_ring.buffer_slot[index] = slot as u16;
            self.receive_ring.staged.push_back((slot as u16, vid));
            self.receive_ring.write = (self.receive_ring.write + 1) & (self.entries - 1);
            returned += 1;
        }
        let actual = self.receive_ring.write & !7;
        let published = actual.wrapping_sub(self.receive_ring.actual) & (self.entries - 1);
        if usize::from(published) > self.receive_ring.staged.len()
            || self
                .credits
                .checked_add(published)
                .is_none_or(|n| n >= self.entries)
        {
            return Err(Error::CompletionCredit);
        }
        if published != 0 {
            // All actual eligible IDs/leases precede the potentially uncertain
            // producer MMIO, including the initial7 staged descriptors.
            for _ in 0..published {
                let (slot, vid) = self
                    .receive_ring
                    .staged
                    .pop_front()
                    .ok_or(Error::CompletionCredit)?;
                let index = usize::from(vid - 1);
                if self.buffers[index].device_owned || !self.receive_ring.buffer_staged[index] {
                    return Err(Error::CompletionId(vid));
                }
                self.buffers[index].device_owned = true;
                self.receive_ring.buffer_staged[index] = false;
                self.receive_ring.slots[usize::from(slot)] = Slot {
                    device: true,
                    completed: false,
                };
            }
            self.credits += published;
            self.receive_ring.actual = actual;
            fence(Ordering::Release);
            self.write(0x1c80, u32::from(actual))?;
        }
        Ok(Replenished {
            returned,
            published,
            device_credits: self.credits,
            waiting_for_completed_slot: waiting,
        })
    }
}
