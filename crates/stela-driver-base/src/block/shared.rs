//! One device shared by several clients: the locked disk, merged requests and
//! per-client windows.

use super::*;

/// One disk several owners share, each through its own [`Window`]: the
/// disk's request queue. The owners may run on different processors at once
/// (a guest's storage on any PE, the host's NOR and log stores on another),
/// so each reaches the disk under its lock, which no one holds while the
/// device works on queued commands: the owners' commands wait in order, the
/// device runs as many as it has room for, and whichever owner next looks
/// for a result collects every completed one and starts those waiting
/// ([`Window::finish`]). Consecutive waiting reads, or writes, of adjoining
/// blocks go to the device as one command, as Linux's block layer merges
/// them.
#[derive(Clone)]
pub struct Shared(pub(super) Arc<Disk>);

pub(super) struct Disk {
    pub(super) held: AtomicBool,
    pub(super) profile_callbacks: AtomicBool,
    pub(super) activity: profile::Activity,
    pub(super) device: UnsafeCell<Box<dyn BlockDevice>>,
    pub(super) requests: UnsafeCell<Requests>,
}

/// The owners' commands, by ticket: those waiting in order with the
/// counter when each was submitted, those the device runs and the results
/// no owner has taken yet; and the disk's accounting, with the counter
/// when the device last went from idle to running a command.
#[derive(Default)]
pub(super) struct Requests {
    pub(super) waiting: VecDeque<(u32, Command, u64)>,
    pub(super) running: Vec<Merged>,
    pub(super) finished: BTreeMap<u32, Finished>,
    pub(super) next: u32,
    pub(super) stats: Stats,
    pub(super) busy_since: u64,
}

/// A device command and the tickets merged into it: each ticket's offset
/// and length in a read's data. What the accounting counts it as, and when
/// its first ticket was submitted.
pub(super) struct Merged {
    pub(super) tag: u32,
    pub(super) tickets: Vec<(u32, usize, usize)>,
    pub(super) accounted: (Direction, u64),
    pub(super) submitted: u64,
}

// SAFETY: a device reaches the disk only through its own state and the
// controller's registers, not through anything of the processor that made
// it, and `Shared::lock` lets one processor at a time reach it.
unsafe impl Send for Disk {}
// SAFETY: as for `Send`; every access holds the lock.
unsafe impl Sync for Disk {}

/// The disk, held until dropped.
pub(super) struct Held<'a>(pub(super) &'a Disk);

impl Deref for Held<'_> {
    type Target = Box<dyn BlockDevice>;
    fn deref(&self) -> &Self::Target {
        // SAFETY: the lock is held, so no other reference to the device lives.
        unsafe { &*self.0.device.get() }
    }
}

impl DerefMut for Held<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as for `deref`.
        unsafe { &mut *self.0.device.get() }
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.held.store(false, Ordering::Release);
    }
}

/// `next` joined to the end of `command` when it continues it, within the
/// device's transfer limit: both reads, or both writes asking the same
/// durability. The joined length of `next` in a read's data, or `None`.
pub(super) fn merge(
    command: &mut Command,
    next: &Command,
    block: usize,
    limit: usize,
) -> Option<usize> {
    let limit = if limit == 0 { usize::MAX } else { limit };
    match (command, next) {
        (
            Command::Read { lba, bytes },
            Command::Read {
                lba: at,
                bytes: more,
            },
        ) if *lba + (*bytes / block) as u64 == *at && *bytes + more <= limit => {
            *bytes += more;
            Some(*more)
        }
        (
            Command::Write { lba, data, fua },
            Command::Write {
                lba: at,
                data: more,
                fua: also,
            },
        ) if fua == also
            && *lba + (data.len() / block) as u64 == *at
            && data.len() + more.len() <= limit =>
        {
            data.extend_from_slice(more);
            Some(0)
        }
        _ => None,
    }
}

impl Held<'_> {
    pub(super) fn requests(&mut self) -> &mut Requests {
        // SAFETY: the lock is held; the requests are apart from the device.
        unsafe { &mut *self.0.requests.get() }
    }

    /// Whether no command waits or runs: a transfer may reach the device
    /// directly.
    pub(super) fn idle(&mut self) -> bool {
        let requests = self.requests();
        requests.running.is_empty() && requests.waiting.is_empty()
    }

    /// Queue `command`; its ticket.
    pub(super) fn submit(&mut self, command: Command) -> u32 {
        let requests = self.requests();
        let ticket = requests.next;
        requests.next = requests.next.wrapping_add(1);
        requests
            .waiting
            .push_back((ticket, command, crate::Clock::ticks()));
        self.advance();
        ticket
    }

    /// Count a command `accounted` as, with `merges` requests joined into
    /// it, submitted at `submitted` and completed at `now`.
    pub(super) fn account(
        &mut self,
        (direction, bytes): (Direction, u64),
        merges: u64,
        submitted: u64,
        now: u64,
    ) {
        let counts = &mut self.requests().stats.directions[direction as usize];
        counts.ios += 1;
        counts.merges += merges;
        counts.bytes += bytes;
        counts.ticks += now.wrapping_sub(submitted);
    }

    /// Run `run` on the device, which runs nothing else meanwhile, as one
    /// command `accounted` as and submitted at `submitted`.
    pub(super) fn direct<T>(
        &mut self,
        accounted: (Direction, u64),
        submitted: u64,
        run: impl FnOnce(&mut Box<dyn BlockDevice>) -> T,
    ) -> T {
        let observing = self.0.profile_callbacks.load(Ordering::Relaxed);
        let started = crate::Clock::ticks();
        let disk = self.0;
        let _active = observing.then(|| disk.activity.direct.enter(started));
        let result = run(self);
        let now = crate::Clock::ticks();
        let stats = &mut self.requests().stats;
        stats.busy += now.wrapping_sub(started);
        stats.deepest = stats.deepest.max(1);
        if observing {
            self.requests()
                .stats
                .callbacks
                .get_or_insert_default()
                .direct
                .record(now.wrapping_sub(started), profile::Work::default());
        }
        self.account(accounted, 0, submitted, now);
        result
    }

    /// The disk's accounting, its device's time running a command so far
    /// included.
    pub(super) fn stats(&mut self) -> Stats {
        let requests = self.requests();
        let mut stats = requests.stats;
        if !requests.running.is_empty() {
            stats.busy += crate::Clock::ticks().wrapping_sub(requests.busy_since);
        }
        stats
    }

    /// Collect the device's completed commands, then start those waiting
    /// while it has room. A device that takes no queued commands runs each
    /// here, its caller waiting.
    pub(super) fn advance(&mut self) {
        let observing = self.0.profile_callbacks.load(Ordering::Relaxed);
        let started = observing.then(crate::Clock::ticks);
        let disk = self.0;
        let _active = started.map(|ticks| disk.activity.advance.enter(ticks));
        let mut work = profile::Work::default();
        self.advance_inner(&mut work);
        if let Some(started) = started {
            let elapsed = crate::Clock::ticks().wrapping_sub(started);
            self.requests()
                .stats
                .callbacks
                .get_or_insert_default()
                .advance
                .record(elapsed, work);
        }
    }

    pub(super) fn advance_inner(&mut self, work: &mut profile::Work) {
        let mut index = 0;
        while index < self.requests().running.len() {
            let tag = self.requests().running[index].tag;
            let Some(result) = self.finish(tag) else {
                index += 1;
                continue;
            };
            work.finishes = work.finishes.saturating_add(1);
            let merged = self.requests().running.swap_remove(index);
            let now = crate::Clock::ticks();
            let merges = merged.tickets.len() as u64 - 1;
            self.account(merged.accounted, merges, merged.submitted, now);
            let requests = self.requests();
            if requests.running.is_empty() {
                requests.stats.busy += now.wrapping_sub(requests.busy_since);
            }
            let finished = &mut self.requests().finished;
            for (ticket, offset, bytes) in merged.tickets {
                let part = match &result {
                    Ok(Some(data)) => Ok(Some(data[offset..offset + bytes].to_vec())),
                    other => other.clone(),
                };
                finished.insert(ticket, part);
            }
        }
        let queued = self.depth() > 0;
        let (block, limit) = {
            let identity = self.identity();
            (identity.block_size as usize, identity.features.max_transfer)
        };
        loop {
            if queued && !self.room() {
                return;
            }
            let Some((ticket, mut command, submitted)) = self.requests().waiting.pop_front() else {
                return;
            };
            if !queued {
                let accounted = command.accounted(block);
                let result = self.direct(accounted, submitted, |device| device.execute(command));
                self.requests().finished.insert(ticket, result);
                continue;
            }
            let first = match &command {
                Command::Read { bytes, .. } => *bytes,
                _ => 0,
            };
            let mut tickets = vec![(ticket, 0, first)];
            let mut offset = first;
            while let Some((next, following, _)) = self.requests().waiting.front() {
                let Some(bytes) = merge(&mut command, following, block, limit) else {
                    break;
                };
                tickets.push((*next, offset, bytes));
                offset += bytes;
                self.requests().waiting.pop_front();
            }
            let accounted = command.accounted(block);
            work.starts = work.starts.saturating_add(1);
            match self.start(command) {
                Ok(tag) => {
                    let requests = self.requests();
                    if requests.running.is_empty() {
                        requests.busy_since = crate::Clock::ticks();
                    }
                    requests.running.push(Merged {
                        tag,
                        tickets,
                        accounted,
                        submitted,
                    });
                    requests.stats.deepest = requests.stats.deepest.max(requests.running.len());
                }
                Err(error) => {
                    for (ticket, ..) in tickets {
                        self.requests().finished.insert(ticket, Err(error.clone()));
                    }
                }
            }
        }
    }

    /// Ticket `ticket`'s result, once it has one.
    pub(super) fn take(&mut self, ticket: u32) -> Option<Finished> {
        self.advance();
        self.requests().finished.remove(&ticket)
    }
}

impl Shared {
    pub fn new(device: Box<dyn BlockDevice>) -> Self {
        Self(Arc::new(Disk {
            held: AtomicBool::new(false),
            profile_callbacks: AtomicBool::new(false),
            activity: profile::Activity::default(),
            device: UnsafeCell::new(device),
            requests: UnsafeCell::new(Requests::default()),
        }))
    }

    /// Observe callback wall time from subsequent operations. Default off;
    /// disabling keeps earlier observations and adds no timing reads.
    pub fn set_callback_profile(&self, enabled: bool) {
        self.0.profile_callbacks.store(enabled, Ordering::Relaxed);
    }

    /// Bounded observations without taking the disk's lock or touching a driver.
    /// Enabled samples bracket independent generation/start reads with counters;
    /// disabling adds no counter reads. None means profiling is disabled.
    /// Activity never grants completion, DMA or quiescence permission.
    pub fn callback_activity(&self) -> Option<CallbackActivity> {
        if !self.0.profile_callbacks.load(Ordering::Relaxed) {
            return None;
        }
        let observed_before_ticks = crate::Clock::ticks();
        let advance = self.0.activity.advance.snapshot();
        let direct = self.0.activity.direct.snapshot();
        let observed_after_ticks = crate::Clock::ticks();
        Some(CallbackActivity {
            observed_before_ticks,
            observed_after_ticks,
            advance,
            direct,
        })
    }

    /// Callback observations with one try-lock and no counter read.
    /// None means disabled, not yet observed, or currently held by an owner.
    /// This snapshot grants no DMA, mapping or quiescence permission.
    pub fn callback_stats(&self) -> Option<CallbackStats> {
        if !self.0.profile_callbacks.load(Ordering::Relaxed)
            || self
                .0
                .held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            return None;
        }
        Held(&self.0).requests().stats.callbacks
    }

    /// The disk, once no other owner is using it.
    pub(super) fn lock(&self) -> Held<'_> {
        while self
            .0
            .held
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Held(&self.0)
    }

    /// Run `command` to completion, the caller waiting: at once while no
    /// queued command is ahead of it, else in its turn.
    pub(super) fn run(&self, command: Command) -> Finished {
        let ticket = {
            let mut disk = self.lock();
            if disk.idle() {
                let accounted = command.accounted(disk.identity().block_size as usize);
                return disk.direct(accounted, crate::Clock::ticks(), |device| {
                    device.execute(command)
                });
            }
            disk.submit(command)
        };
        loop {
            if let Some(result) = self.lock().take(ticket) {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// The disk's I/O accounting since it was shared.
    pub fn stats(&self) -> Stats {
        self.lock().stats()
    }

    /// Whether `other` shares this same disk.
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Shut the disk down, as [`BlockDevice::shutdown`]; once for all its
    /// windows, after every queued command.
    pub fn shutdown(&self, power_off: bool) -> Result<(), BlockError> {
        let mut disk = self.lock();
        while !disk.idle() {
            disk.advance();
            core::hint::spin_loop();
        }
        disk.shutdown(power_off)
    }

    /// Every block, as a device of its own.
    pub fn whole(&self) -> Window {
        let identity = self.lock().identity().clone();
        Window {
            disk: self.clone(),
            first: 0,
            identity,
            started: Vec::new(),
        }
    }

    /// The `blocks` blocks from `first`, as a device of their own.
    pub fn window(&self, first: u64, blocks: u64) -> Result<Window, BlockError> {
        let mut identity = self.lock().identity().clone();
        match first.checked_add(blocks) {
            Some(end) if end <= identity.blocks => (),
            _ => return Err(range(&identity, first, blocks)),
        }
        identity.blocks = blocks;
        Ok(Window {
            disk: self.clone(),
            first,
            identity,
            started: Vec::new(),
        })
    }

    /// The blocks of `runs`, each a first block and a count, in order, as
    /// one device: a file's clusters where they lie on the disk.
    pub fn runs(&self, runs: Vec<(u64, u64)>) -> Result<Runs, BlockError> {
        let mut identity = self.lock().identity().clone();
        let mut blocks = 0u64;
        for &(first, count) in &runs {
            match first.checked_add(count) {
                Some(end) if end <= identity.blocks => blocks += count,
                _ => return Err(range(&identity, first, count)),
            }
        }
        identity.blocks = blocks;
        Ok(Runs {
            disk: self.clone(),
            runs,
            identity,
        })
    }
}

/// The commands a [`Window`] keeps in its disk's queue at most.
pub(super) const WINDOW_DEPTH: usize = 64;

/// A run of blocks of a [`Shared`] disk.
pub struct Window {
    pub(super) disk: Shared,
    pub(super) first: u64,
    pub(super) identity: Identity,
    /// The tickets of this window's started commands not yet finished.
    pub(super) started: Vec<u32>,
}

impl Window {
    /// The disk this window is part of.
    pub fn shared(&self) -> &Shared {
        &self.disk
    }

    pub(super) fn run(&self, command: Command) -> Result<(), BlockError> {
        let command = command.within(&self.identity, self.first)?;
        self.disk.run(command).map(drop)
    }
}

impl BlockDevice for Window {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        let mut disk = self.disk.lock();
        if disk.idle() {
            let accounted = (Direction::Read, buffer.len() as u64);
            let lba = self.first + lba;
            return disk.direct(accounted, crate::Clock::ticks(), |device| {
                device.read(lba, buffer)
            });
        }
        drop(disk);
        let command = Command::Read {
            lba: self.first + lba,
            bytes: buffer.len(),
        };
        let data = self.disk.run(command)?;
        buffer.copy_from_slice(&data.ok_or(BlockError::Protocol("a read returned no data"))?);
        Ok(())
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        let mut disk = self.disk.lock();
        if disk.idle() {
            let accounted = (Direction::Write, data.len() as u64);
            let lba = self.first + lba;
            return disk.direct(accounted, crate::Clock::ticks(), |device| {
                device.write(lba, data)
            });
        }
        drop(disk);
        self.run(Command::Write {
            lba,
            data: data.to_vec(),
            fua: false,
        })
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.run(Command::Flush)
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.run(Command::Write {
            lba,
            data: data.to_vec(),
            fua: true,
        })
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.run(Command::discard(lba, blocks))
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        self.run(Command::WriteZeroes { lba, blocks, unmap })
    }

    /// Every window takes queued commands: its disk runs them in turn.
    fn depth(&self) -> usize {
        WINDOW_DEPTH
    }

    fn room(&self) -> bool {
        self.started.len() < WINDOW_DEPTH
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let command = command.within(&self.identity, self.first)?;
        if !self.room() {
            return Err(BlockError::Protocol("the disk window queue is full"));
        }
        let ticket = self.disk.lock().submit(command);
        self.started.push(ticket);
        Ok(ticket)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        let finished = self.disk.lock().take(tag)?;
        self.started.retain(|&ticket| ticket != tag);
        Some(finished)
    }

    /// One of this window's commands has a result, or the disk has posted
    /// a completion: another window's results never count.
    fn posted(&self) -> bool {
        let mut disk = self.disk.lock();
        let finished = &disk.requests().finished;
        self.started
            .iter()
            .any(|ticket| finished.contains_key(ticket))
            || disk.posted()
    }

    fn signals(&self) -> bool {
        self.disk.lock().signals()
    }
}
