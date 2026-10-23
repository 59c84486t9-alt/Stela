// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2015, Intel Corporation.
//! Native parent MSI-X table programming and immutable child fanout. The child
//! message encodes the VMD table index, not a CPU APIC destination/vector.
use super::*;
use crate::bus::irq::{Disposition, Handler, MsiMessage};
use alloc::sync::Arc;

const ENABLE: u16 = 1 << 15;
const FUNCTION_MASK: u16 = 1 << 14;
const VECTOR_MASK: u32 = 1;
const ENTRY_BYTES: u64 = 16;
const MSI_ADDRESS: u64 = 0xfee0_0000;

/// Immutable source list, held by the actual parent IRQ registration. Unlike
/// Linux's RCU list, membership changes require complete source retirement;
/// dispatch allocates, locks and drops no references in hard IRQ context.
pub struct Fanout {
    children: alloc::boxed::Box<[Arc<dyn Handler>]>,
}
impl Fanout {
    pub fn new(children: Vec<Arc<dyn Handler>>) -> Result<Self, Error> {
        if children.is_empty()
            || children
                .iter()
                .enumerate()
                .any(|(i, child)| children[..i].iter().any(|old| Arc::ptr_eq(child, old)))
        {
            return Err(Error::Address);
        }
        Ok(Self {
            children: children.into_boxed_slice(),
        })
    }
}
impl Handler for Fanout {
    fn handle(&self) -> Disposition {
        let mut disposition = Disposition::NotMine;
        for child in &self.children {
            if child.handle() == Disposition::Handled {
                disposition = Disposition::Handled;
            }
        }
        disposition
    }
}

/// Index allocation follows Linux's NVMe fast-vector/other-device slow-vector
/// policy. Allocation alone supplies neither an IRQ route nor a child grant.
pub struct Assignments {
    first: u8,
    counts: Vec<u32>,
}
impl Assignments {
    pub fn new(profile: Profile, parent_vectors: u16) -> Result<Self, Error> {
        if parent_vectors <= u16::from(profile.first_vector) || parent_vectors > 256 {
            return Err(Error::Address);
        }
        Ok(Self {
            first: profile.first_vector,
            counts: alloc::vec![0; usize::from(parent_vectors)],
        })
    }
    pub fn allocate(&mut self, class: [u8; 3]) -> Result<u8, Error> {
        let first = usize::from(self.first);
        let index = if self.counts.len() == first + 1 || class != [1, 8, 2] {
            first
        } else {
            (first + 1..self.counts.len())
                .min_by_key(|i| self.counts[*i])
                .unwrap()
        };
        self.counts[index] = self.counts[index].checked_add(1).ok_or(Error::Exhausted)?;
        Ok(index as u8)
    }
    /// # Safety
    /// The exact child's source is masked, stopped and drained, the native CPU
    /// registration has retired and no fanout callback may retain this child.
    pub unsafe fn release(&mut self, index: u8) -> Result<(), Error> {
        if index < self.first {
            return Err(Error::Address);
        }
        let count = self
            .counts
            .get_mut(usize::from(index))
            .ok_or(Error::Address)?;
        *count = count.checked_sub(1).ok_or(Error::Address)?;
        Ok(())
    }
    pub fn message(&self, index: u8) -> Result<MsiMessage, Error> {
        if index < self.first
            || self
                .counts
                .get(usize::from(index))
                .is_none_or(|count| *count == 0)
        {
            return Err(Error::Address);
        }
        Ok(MsiMessage {
            address: MSI_ADDRESS | u64::from(index) << 12,
            data: 0,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Layout {
    control: u16,
    table: u64,
    count: u16,
    pending: u64,
}
fn discover<R: Registers>(host: &mut Host<R>) -> Result<Layout, Error> {
    if host.io().parent_read(6, 2)? & 0x10 == 0 {
        return Err(Error::Capability);
    }
    let mut offset = host.io().parent_read(0x34, 1)? as u16;
    let mut visited = [false; 256];
    let mut layout = None;
    while offset != 0 {
        if !(0x40..=0xfc).contains(&offset) || offset & 3 != 0 || visited[usize::from(offset)] {
            return Err(Error::Capability);
        }
        visited[usize::from(offset)] = true;
        let header = host.io().parent_read(offset, 2)?;
        if header as u8 == 5 && host.io().parent_read(offset + 2, 2)? & 1 != 0 {
            return Err(Error::ActiveChild);
        }
        if header as u8 == 0x11 {
            if offset > 0xf4 || layout.is_some() {
                return Err(Error::Capability);
            }
            let control = host.io().parent_read(offset + 2, 2)? as u16;
            let table = host.io().parent_read(offset + 4, 4)?;
            let pending = host.io().parent_read(offset + 8, 4)?;
            if control == u16::MAX || table & 7 != 4 || pending & 7 != 4 {
                return Err(Error::Capability);
            }
            let count = (control & 0x7ff) + 1;
            let table = u64::from(table & !7);
            let pending = u64::from(pending & !7);
            let table_end = table
                .checked_add(u64::from(count) * ENTRY_BYTES)
                .ok_or(Error::InvalidResource)?;
            let pending_end = pending
                .checked_add(u64::from(count).div_ceil(64) * 8)
                .ok_or(Error::InvalidResource)?;
            let shadow = match host.profile.shadow {
                Shadow::Native => Some(0x2000..0x2010),
                Shadow::Bios => Some(0x2818..0x2848),
                Shadow::Vendor => None,
            };
            if table_end > host.membar2_reserved
                || pending_end > host.membar2_reserved
                || (table < pending_end && pending < table_end)
                || shadow.is_some_and(|span| {
                    (table < span.end && span.start < table_end)
                        || (pending < span.end && span.start < pending_end)
                })
            {
                return Err(Error::InvalidResource);
            }
            layout = Some(Layout {
                control: offset + 2,
                table,
                count,
                pending,
            });
        }
        offset = (header >> 8) as u16;
    }
    let layout = layout.ok_or(Error::Capability)?;
    if host.remap_layout.is_some_and(|original| original != layout) {
        host.poisoned = true;
        return Err(Error::Capability);
    }
    Ok(layout)
}
fn write<R: Registers>(host: &mut Host<R>, offset: u64, value: u32) -> Result<(), Error> {
    host.io().table_write(offset, value)?;
    if host.io().table_read(offset)? != value {
        return Err(Error::Readback);
    }
    Ok(())
}
impl<R: Registers> Host<R> {
    /// Program actual parent MSI-X table while every vector is masked. The
    /// first software-only vector on client profiles stays unused and masked.
    ///
    /// # Safety
    /// Every message is from the actual native IRQ registry and its retained
    /// Fanout is published before a parent vector can be enabled. All children,
    /// old parent messages and callbacks are stopped/drained. These routes and
    /// callbacks must remain retained through this host's retirement. This API
    /// programs hardware but does not create IRQ-controller authority.
    pub unsafe fn program_parent_vectors(&mut self, messages: &[MsiMessage]) -> Result<u16, Error> {
        self.check_live()?;
        let layout = discover(self)?;
        let first = self.profile.first_vector;
        if messages.is_empty()
            || messages.len() + usize::from(first) > usize::from(layout.count)
            || messages.len() + usize::from(first) > 256
            || messages.iter().any(|m| m.address & 3 != 0)
        {
            return Err(Error::Address);
        }
        let result = (|| {
            let control = self.io().parent_read(layout.control, 2)? as u16;
            self.parent_write_checked(layout.control, control | ENABLE | FUNCTION_MASK)?;
            for index in 0..layout.count {
                write(
                    self,
                    layout.table + u64::from(index) * ENTRY_BYTES + 12,
                    VECTOR_MASK,
                )?;
            }
            for (i, message) in messages.iter().enumerate() {
                let base = layout.table + (i as u64 + u64::from(first)) * ENTRY_BYTES;
                write(self, base, message.address as u32)?;
                write(self, base + 4, (message.address >> 32) as u32)?;
                write(self, base + 8, message.data)?;
            }
            self.set_remapping(true)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result.map(|()| {
            let end = messages.len() as u16 + u16::from(first);
            self.programmed_vectors = Some(end);
            self.remap_layout = Some(layout);
            end
        })
    }
    /// # Safety
    /// Actual live native parent registrations retain published handlers for
    /// every enabled vector; children carry only matching remapped messages.
    /// No unprogrammed vector may be enabled. The range must be the exact range
    /// successfully programmed by program_parent_vectors in this same epoch.
    pub unsafe fn unmask_parent_vectors(&mut self, end: u16) -> Result<(), Error> {
        self.check_live()?;
        let layout = discover(self)?;
        if self.programmed_vectors != Some(end)
            || end <= u16::from(self.profile.first_vector)
            || end > layout.count
            || end > 256
        {
            return Err(Error::Address);
        }
        let result = (|| {
            for index in u16::from(self.profile.first_vector)..end {
                write(self, layout.table + u64::from(index) * ENTRY_BYTES + 12, 0)?;
            }
            let control = self.io().parent_read(layout.control, 2)? as u16;
            self.parent_write_checked(layout.control, (control | ENABLE) & !FUNCTION_MASK)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Mask all parent vectors; this is never evidence of child DMA/callback
    /// completion. Pending MSI writes remain the native IRQ owner's obligation.
    pub fn mask_parent_vectors(&mut self) -> Result<(), Error> {
        self.check_live()?;
        let layout = discover(self)?;
        let result = (|| {
            let control = self.io().parent_read(layout.control, 2)? as u16;
            self.parent_write_checked(layout.control, control | FUNCTION_MASK)?;
            for index in 0..layout.count {
                write(
                    self,
                    layout.table + u64::from(index) * ENTRY_BYTES + 12,
                    VECTOR_MASK,
                )?;
            }
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(super) fn disable_parent_vectors(&mut self) -> Result<(), Error> {
        if self.programmed_vectors.is_none() {
            return Ok(());
        }
        self.mask_parent_vectors()?;
        let layout = discover(self)?;
        let control = self.io().parent_read(layout.control, 2)? as u16;
        self.parent_write_checked(layout.control, (control | FUNCTION_MASK) & !ENABLE)?;
        self.programmed_vectors = None;
        Ok(())
    }
}
