//! The software CM's actual channel and closed producer boundary.
use crate::bus::thunderbolt::{
    channel::{self, Channel, Event},
    cold::MappedRegisters,
    config::{Address, Route},
    manager::Transport,
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    cell::UnsafeCell,
    mem::ManuallyDrop,
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) struct SharedChannel {
    channel: UnsafeCell<ManuallyDrop<Option<Box<Channel<MappedRegisters>>>>>,
    locked: AtomicBool,
    closed: AtomicBool,
}
// SAFETY: all channel access is serialized by the actual lock below. Closing
// gates every Transport method before returning the locked disable boundary;
// no channel/pointer is lent. Source mappings/DMA additionally check context.
unsafe impl Send for SharedChannel {}
// SAFETY: same exclusive lock; final Drop keeps the actual Channel object and
// its DMA/frame/root/register graph rather than releasing an uncertain epoch.
unsafe impl Sync for SharedChannel {}
struct Unlock<'a>(&'a AtomicBool);
impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl SharedChannel {
    pub(super) fn new(channel: Channel<MappedRegisters>) -> Arc<Self> {
        Arc::new(Self {
            channel: UnsafeCell::new(ManuallyDrop::new(Some(Box::new(channel)))),
            locked: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }
    fn access<T>(
        &self,
        closed: bool,
        operation: impl FnOnce(&mut Channel<MappedRegisters>) -> Result<T, channel::Error>,
    ) -> Result<T, channel::Error> {
        if !closed && self.closed.load(Ordering::Acquire) {
            return Err(channel::Error::Stopped);
        }
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| channel::Error::Busy)?;
        let _unlock = Unlock(&self.locked);
        if !closed && self.closed.load(Ordering::Acquire) {
            return Err(channel::Error::Stopped);
        }
        // SAFETY: actual exclusive channel lock, no reference can escape the
        // operation. Other calls either wait outside ownership or refuse.
        let slot = unsafe { &mut *self.channel.get() };
        operation(slot.as_deref_mut().ok_or(channel::Error::Stopped)?)
    }
    /// Close real transport entry permanently, then join/disable under its
    /// actual lock. Busy/error retains the graph; there is no reset/retry claim.
    pub(super) fn close(&self) -> Result<(), channel::Error> {
        self.closed.store(true, Ordering::Release);
        self.access(true, Channel::disable)
    }
    /// # Safety
    /// Actual NHI FLR completed, original current-domain payload path drained,
    /// IRQ/work users are independently excluded/joined, and this exact gate
    /// is permanently closed. No raw Channel is accessible to the CM future.
    pub(super) unsafe fn release(&self) -> Result<(), channel::Error> {
        if !self.closed.load(Ordering::Acquire) {
            return Err(channel::Error::Busy);
        }
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| channel::Error::Busy)?;
        let _unlock = Unlock(&self.locked);
        // SAFETY: actual closed channel lock; normal Senders cannot enter or
        // obtain a reference. Keep the original Box on every unmap failure.
        let slot = unsafe { &mut *self.channel.get() };
        let channel = slot.as_deref_mut().ok_or(channel::Error::Stopped)?;
        // SAFETY: same original closed transport/reset/payload/IRQ proof.
        unsafe { channel.release() }?;
        // DMA unmapping acknowledged. Closed senders never inspect the slot;
        // now free the actual ring CPU mappings/pages in this process scope.
        drop(slot.take());
        Ok(())
    }
}
pub(super) struct Sender(pub(super) Arc<SharedChannel>);
impl Transport for Sender {
    fn read(
        &mut self,
        route: Route,
        address: Address,
        now: u64,
        deadline: u64,
    ) -> Result<u64, channel::Error> {
        self.0
            .access(false, |channel| channel.read(route, address, now, deadline))
    }
    fn write(
        &mut self,
        route: Route,
        address: Address,
        data: &[u32],
        now: u64,
        deadline: u64,
    ) -> Result<u64, channel::Error> {
        self.0.access(false, |channel| {
            channel.write(route, address, data, now, deadline)
        })
    }
    fn poll(&mut self, now: u64) -> Result<Option<Event>, channel::Error> {
        self.0.access(false, |channel| channel.poll(now))
    }
}
