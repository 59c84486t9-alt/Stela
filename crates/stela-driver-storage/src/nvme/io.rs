//! The I/O queue: publishing tagged commands, collecting completions, deadlines
//! and aborts.

use super::*;

impl Controller {
    /// Before the CPU takes back memory a completion released: an owned
    /// controller's completion counts only while its registers answer
    /// without a fatal status, which a removed hierarchy or a failed engine
    /// would not.
    pub(super) fn trust_completion(&self) -> Result<(), BlockError> {
        match self.owned {
            Some(_) => self.check_fatal(),
            None => Ok(()),
        }
    }

    /// Tag `tag`'s bounce memory: its data and its PRP list.
    pub(super) fn slot(&mut self, tag: usize) -> (&mut Buffer, &mut Buffer) {
        match tag {
            0 => (&mut self.bounce, &mut self.prp_list),
            _ => {
                let slot = &mut self.slots[tag - 1];
                (&mut slot.bounce, &mut slot.prp_list)
            }
        }
    }

    /// Whether command identifier `id` names a command still outstanding.
    pub(super) fn outstanding(&self, id: u16) -> bool {
        self.events.request == Some(id)
            || self.aborts.contains(&id)
            || self
                .tags
                .iter()
                .any(|tag| matches!(tag, Tag::Running { id: running, .. } if *running == id))
            || matches!(
                self.recovery,
                Some(Recovery::Deleting { id: step, .. } | Recovery::Admin { id: step, .. })
                    if step == id
            )
    }

    /// Publish `command` on queue `io`, giving the controller tag `tag`'s
    /// memory when it moves data, and ring its doorbell; its identifier,
    /// one no outstanding command holds.
    pub(super) fn publish(
        &mut self,
        io: bool,
        command: [u32; 16],
        tag: Option<usize>,
    ) -> Result<u16, BlockError> {
        let stride = self.doorbell_stride;
        loop {
            self.command_id = self.command_id.wrapping_add(1);
            if !self.outstanding(self.command_id) {
                break;
            }
        }
        let id = self.command_id;
        if let Some(tag) = tag {
            let (bounce, prp_list) = self.slot(tag);
            bounce.give()?;
            prp_list.give()?;
        }
        let registers = &self.registers;
        let queue = if io { &mut self.io } else { &mut self.admin };
        // SAFETY: the controller only reads submission entries, and the tail
        // entry is none it has yet to fetch: fewer commands are outstanding
        // than the queue holds.
        unsafe { queue.submissions.resume_writes() };
        let base = usize::from(queue.tail) * 64;
        for (index, word) in command.iter().enumerate() {
            queue.submissions.write(
                base + 4 * index,
                if index == 0 {
                    word | u32::from(id) << 16
                } else {
                    *word
                },
            );
        }
        queue.submissions.give()?;
        queue.tail = (queue.tail + 1) % queue.entries;
        fence(Ordering::SeqCst);
        registers.write32(
            DOORBELLS + 2 * usize::from(queue.id) * stride,
            u32::from(queue.tail),
        )?;
        Ok(id)
    }

    /// The completion at queue `io`'s head, once the controller has posted
    /// it: its identifier, result, status and submission head, which must
    /// not have moved back nor past the tail.
    pub(super) fn posted(&mut self, io: bool) -> Result<Option<(u16, u32, u32, u16)>, BlockError> {
        let queue = if io { &mut self.io } else { &mut self.admin };
        let entry = usize::from(queue.head) * 16;
        if (queue.completions.coherent(entry + 12)? >> 16 & 1 == 1) != queue.phase {
            return Ok(None);
        }
        // The domain checks the coherent observation; this barrier orders
        // later CQ words after the device's final phase/status publication.
        fence(Ordering::SeqCst);
        let result = queue.completions.coherent(entry)?;
        let submission = queue.completions.coherent(entry + 8)?;
        let tail_word = queue.completions.coherent(entry + 12)?;
        let head = submission as u16;
        if ((tail_word >> 16 & 1) == 1) != queue.phase
            || submission >> 16 != u32::from(queue.id)
            || !queue.consumes(head)
        {
            return Err(BlockError::Device { status: 0xffff });
        }
        queue.consumed = head;
        queue.head = (queue.head + 1) % queue.entries;
        if queue.head == 0 {
            queue.phase = !queue.phase;
        }
        Ok(Some((
            tail_word as u16,
            result,
            tail_word >> 17 & 0x7fff,
            head,
        )))
    }

    /// Whether a running command's completion is posted at the I/O
    /// queue's head, or one is done and not yet taken: memory alone.
    pub(super) fn posted_completion(&self) -> bool {
        let mut running = false;
        for tag in &self.tags {
            match tag {
                Tag::Done(_) => return true,
                Tag::Running { .. } => running = true,
                _ => {}
            }
        }
        let entry = usize::from(self.io.head) * 16;
        running
            && self
                .io
                .completions
                .coherent(entry + 12)
                .is_ok_and(|word| (word >> 16 & 1 == 1) == self.io.phase)
    }

    /// Ring queue `io`'s completion doorbell at its head.
    pub(super) fn release(&mut self, io: bool) -> Result<(), BlockError> {
        let stride = self.doorbell_stride;
        let queue = if io { &self.io } else { &self.admin };
        self.registers.write32(
            DOORBELLS + (2 * usize::from(queue.id) + 1) * stride,
            u32::from(queue.head),
        )
    }

    /// Whether a command runs, waits to run again or the controller resets.
    pub(super) fn busy(&self) -> bool {
        self.recovery.is_some()
            || self.tags.iter().any(|tag| {
                matches!(
                    tag,
                    Tag::Running { .. } | Tag::Waiting { .. } | Tag::Delayed { .. }
                )
            })
    }

    /// Wait for every queued command, keeping each result for its tag, and
    /// for a reset to end: a command of a waiting caller's own follows.
    /// Every running command and reset step has a deadline, and retries are
    /// bounded, so this ends.
    pub(super) fn settle(&mut self) -> Result<(), BlockError> {
        loop {
            self.advance();
            if let Some(error) = &self.fault {
                return Err(error.clone());
            }
            if !self.busy() {
                return Ok(());
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// The I/O command for `command` with tag `tag`'s memory, its data
    /// copied in.
    pub(super) fn io_command(
        &mut self,
        tag: usize,
        namespace: u32,
        block: usize,
        command: &Command,
    ) -> Result<[u32; 16], BlockError> {
        let mut words = [0u32; 16];
        words[1] = namespace;
        match command {
            Command::Read { lba, bytes } => {
                let pointers = self.data_pointers(tag, *bytes)?;
                Ok(transfer_command(
                    IO_READ,
                    namespace,
                    *lba,
                    (bytes / block) as u32,
                    pointers,
                    0,
                ))
            }
            Command::Write { lba, data, fua } => {
                self.slot(tag).0.bytes_mut()[..data.len()].copy_from_slice(data);
                let pointers = self.data_pointers(tag, data.len())?;
                let access = if *fua { FORCE_UNIT_ACCESS } else { 0 };
                let blocks = (data.len() / block) as u32;
                Ok(transfer_command(
                    IO_WRITE, namespace, *lba, blocks, pointers, access,
                ))
            }
            Command::Flush => {
                words[0] = u32::from(IO_FLUSH);
                Ok(words)
            }
            Command::Discard { extents } => {
                let (bounce, _) = self.slot(tag);
                // Each range: context attributes, length, starting LBA.
                for (index, extent) in extents.iter().enumerate() {
                    let count = u32::try_from(extent.blocks)
                        .map_err(|_| BlockError::Unsupported("an NVMe range past 2^32 blocks"))?;
                    let range = index * RANGE_BYTES;
                    bounce.write(range, 0u32);
                    bounce.write(range + 4, count);
                    bounce.write(range + 8, extent.lba);
                }
                let address = bounce.address()?;
                words[0] = u32::from(IO_DATASET_MANAGEMENT);
                words[6] = address as u32;
                words[7] = (address >> 32) as u32;
                words[10] = extents.len() as u32 - 1;
                words[11] = ATTRIBUTE_DEALLOCATE;
                Ok(words)
            }
            Command::WriteZeroes { lba, blocks, unmap } => {
                let count = u16::try_from(blocks.wrapping_sub(1))
                    .map_err(|_| BlockError::Unsupported("Write Zeroes past 65536 blocks"))?;
                words[0] = u32::from(IO_WRITE_ZEROES);
                words[10] = *lba as u32;
                words[11] = (*lba >> 32) as u32;
                words[12] = u32::from(count) | if *unmap { DEALLOCATE } else { 0 };
                Ok(words)
            }
        }
    }

    /// Whether [`Self::start`] answers now: a tag is free and no reset runs,
    /// or the controller failed or shut down, which it refuses at once
    /// rather than leaving the command waiting for room it never gets.
    pub(super) fn room(&self) -> bool {
        self.fault.is_some()
            || self.shut_down
            || (self.recovery.is_none() && self.tags.iter().any(|tag| matches!(tag, Tag::Free)))
    }

    /// Run `command` of `namespace` under a free tag; the tag.
    pub(super) fn start(
        &mut self,
        namespace: u32,
        block: usize,
        command: Command,
    ) -> Result<u32, BlockError> {
        self.ready()?;
        let tag = self
            .tags
            .iter()
            .position(|tag| matches!(tag, Tag::Free))
            .filter(|_| self.recovery.is_none())
            .ok_or(BlockError::Protocol("every NVMe tag is in use"))?;
        self.submit(tag, namespace, block, command, 0);
        Ok(tag as u32)
    }

    /// Run `command` of `namespace` once every queued command ended, and
    /// wait for it. A fatal controller is reset before it is sent, as
    /// Linux's timeout handling would reset it.
    pub(super) fn run(&mut self, namespace: u32, block: usize, command: Command) -> Finished {
        self.ready()?;
        self.settle()?;
        match self.registers.read32(STATUS)? {
            REMOVED => return Err(self.poison(removed())),
            status if status & FATAL != 0 => {
                self.reset();
                self.settle()?;
            }
            _ => {}
        }
        let tag = self.start(namespace, block, command)? as usize;
        loop {
            if let Some(result) = self.finish(tag) {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Publish `command` under `tag`, which holds no other.
    pub(super) fn submit(
        &mut self,
        tag: usize,
        namespace: u32,
        block: usize,
        command: Command,
        retries: u8,
    ) {
        let slot = self.io.tail;
        // A command whose deadline cannot be kept is not sent; the deadline
        // runs from its doorbell.
        let published = self.deadline(self.command_timeout_us).and_then(|_| {
            let words = self.io_command(tag, namespace, block, &command)?;
            let id = self.publish(true, words, Some(tag))?;
            Ok((id, self.deadline(self.command_timeout_us)?))
        });
        self.tags[tag] = match published {
            Ok((id, deadline)) => Tag::Running {
                id,
                slot,
                fetched: false,
                namespace,
                block,
                command,
                deadline,
                retries,
                aborted: false,
            },
            Err(error) => Tag::Done(Err(self.poison(error))),
        };
    }

    /// Collect every completion the controller has posted, run delayed
    /// retries, check the running commands' deadlines and move a reset on;
    /// never waits.
    pub(super) fn advance(&mut self) {
        if self.fault.is_some() {
            self.fail_all();
            return;
        }
        if self.recovery.is_some() {
            if let Err(error) = self.recover() {
                self.poison(error);
                self.fail_all();
            }
            return;
        }
        // Abort and event completions, which the I/O commands do not wait for.
        if (self.events.request.is_some() || !self.aborts.is_empty())
            && let Err(error) = self.admin_completion(None)
        {
            self.poison(error);
            self.fail_all();
            return;
        }
        // A controller posts completions only for running commands.
        let running = self
            .tags
            .iter()
            .any(|tag| matches!(tag, Tag::Running { .. }));
        let mut reaped = false;
        loop {
            if !running {
                break;
            }
            let (head, phase, consumed) = (self.io.head, self.io.phase, self.io.consumed);
            match self.posted(true) {
                Ok(None) => break,
                Ok(Some((id, _, status, sq_head))) => {
                    if !reaped && let Err(error) = self.trust_completion() {
                        (self.io.head, self.io.phase, self.io.consumed) = (head, phase, consumed);
                        self.poison(error);
                        self.fail_all();
                        return;
                    }
                    if !self.complete(id, status, sq_head) {
                        // A completion for no running command, or for one the
                        // controller had not fetched: the queue is corrupt.
                        // It stays unretired.
                        (self.io.head, self.io.phase, self.io.consumed) = (head, phase, consumed);
                        self.poison(BlockError::Device { status: 0xffff });
                        self.fail_all();
                        return;
                    }
                    reaped = true;
                }
                Err(error) => {
                    self.poison(error);
                    self.fail_all();
                    return;
                }
            }
        }
        if reaped && let Err(error) = self.release(true) {
            self.poison(error);
            self.fail_all();
            return;
        }
        // One clock reading serves every retry delay and command deadline.
        let now = crate::Clock::ticks();
        for tag in 0..self.tags.len() {
            if matches!(&self.tags[tag], Tag::Delayed { until, .. } if until.passed_at(now)) {
                let Tag::Delayed {
                    namespace,
                    block,
                    command,
                    retries,
                    ..
                } = core::mem::take(&mut self.tags[tag])
                else {
                    unreachable!();
                };
                self.submit(tag, namespace, block, command, retries);
            }
        }
        for tag in 0..self.tags.len() {
            let Tag::Running {
                id,
                deadline,
                aborted,
                ..
            } = &self.tags[tag]
            else {
                continue;
            };
            if !deadline.passed_at(now) {
                continue;
            }
            if *aborted {
                self.reset();
                return;
            }
            let id = *id;
            match self.abort(tag, id) {
                Ok(true) => {}
                Ok(false) => {
                    self.reset();
                    return;
                }
                Err(error) => {
                    self.poison(error);
                    self.fail_all();
                    return;
                }
            }
        }
    }

    /// Command `id` completed with `status`, the controller reporting
    /// submission head `head`: its tag takes the result, or, for an error
    /// without Do Not Retry and retries left, runs it again after the delay
    /// its Command Retry Delay selects (`nvme_decide_disposition`). Whether
    /// a running command matched.
    pub(super) fn complete(&mut self, id: u16, status: u32, head: u16) -> bool {
        let io = &self.io;
        // NVMe SQHD is a snapshot when the CQE is created, not the completed
        // command's slot (Base 1.1, section 4.6). A fetched command may remain
        // in flight while later commands carry the ring through another turn.
        for tag in &mut self.tags {
            if let Tag::Running { slot, fetched, .. } = tag {
                *fetched |= io.fetched(*slot, head);
            }
        }
        let Some(tag) = self.tags.iter().position(|tag| {
            matches!(tag, Tag::Running { id: running, fetched: true, .. }
                if *running == id)
        }) else {
            return false;
        };
        let Tag::Running {
            namespace,
            block,
            command,
            retries,
            ..
        } = core::mem::take(&mut self.tags[tag])
        else {
            unreachable!();
        };
        // SAFETY: the controller completed this exact command; its memory
        // is the CPU's again.
        let taken = unsafe {
            let (bounce, prp_list) = self.slot(tag);
            bounce.take().and_then(|()| prp_list.take())
        };
        let retry = status != 0 && status & STATUS_DO_NOT_RETRY == 0 && retries < RETRIES;
        self.tags[tag] = match (taken, status, command) {
            (Err(error), ..) => Tag::Done(Err(self.poison(error))),
            (Ok(()), _, command) if retry => {
                let delay = match (status & STATUS_RETRY_DELAY) >> 11 {
                    0 => 0,
                    index => u64::from(self.retry_delays[index as usize - 1]) * RETRY_DELAY_UNIT_US,
                };
                match self.deadline(delay) {
                    Ok(until) => Tag::Delayed {
                        namespace,
                        block,
                        command,
                        retries: retries + 1,
                        until,
                    },
                    Err(error) => Tag::Done(Err(error)),
                }
            }
            (Ok(()), 0, Command::Read { bytes, .. }) => {
                Tag::Done(Ok(Some(self.slot(tag).0.bytes()[..bytes].to_vec())))
            }
            (Ok(()), 0, _) => Tag::Done(Ok(None)),
            (Ok(()), status, _) => Tag::Done(Err(BlockError::Device { status })),
        };
        true
    }

    /// Tag `tag`'s result once its command completed; never waits.
    pub(super) fn finish(&mut self, tag: usize) -> Option<Finished> {
        self.advance();
        if !matches!(self.tags.get(tag)?, Tag::Done(_)) {
            return None;
        }
        match core::mem::take(&mut self.tags[tag]) {
            Tag::Done(result) => Some(result),
            _ => unreachable!(),
        }
    }

    /// The PRP entries for the first `bytes` of tag `tag`'s bounce buffer.
    pub(super) fn data_pointers(
        &mut self,
        tag: usize,
        bytes: usize,
    ) -> Result<(u64, u64), BlockError> {
        let initialized = self.prp_pages[tag];
        let (bounce, prp_list) = self.slot(tag);
        let first = bounce.address()?;
        match bytes.div_ceil(PAGE) {
            0 | 1 => Ok((first, 0)),
            2 => Ok((first, first + PAGE as u64)),
            pages => {
                let second = prp_list.address()?;
                for page in initialized..pages {
                    prp_list.write(8 * (page - 1), first + (page * PAGE) as u64);
                }
                self.prp_pages[tag] = initialized.max(pages);
                Ok((first, second))
            }
        }
    }

    pub(super) fn deadline(&self, us: u64) -> Result<crate::Deadline, BlockError> {
        self.clock
            .try_deadline(us)
            .map_err(|_| BlockError::Unsupported("NVMe requires a representable deadline"))
    }

    /// Linux `nvme_timeout` for an I/O command's first deadline: abort it
    /// and give it another, unless the controller is fatally failed, which
    /// is reset at once (`false`).
    pub(super) fn abort(&mut self, tag: usize, id: u16) -> Result<bool, BlockError> {
        match self.registers.read32(STATUS)? {
            REMOVED => return Err(removed()),
            status if status & FATAL != 0 => return Ok(false),
            _ => {}
        }
        let mut command = [0u32; 16];
        command[0] = u32::from(ADMIN_ABORT);
        command[10] = u32::from(id) << 16 | u32::from(self.io.id);
        let abort = self.publish(false, command, None)?;
        self.aborts.push(abort);
        let renewed = self.deadline(self.command_timeout_us)?;
        if let Tag::Running {
            deadline, aborted, ..
        } = &mut self.tags[tag]
        {
            (*deadline, *aborted) = (renewed, true);
        }
        Ok(true)
    }

    /// End every command with the controller's fault.
    pub(super) fn fail_all(&mut self) {
        let error = self.fault.clone().unwrap_or(BlockError::Timeout);
        for tag in &mut self.tags {
            if matches!(
                tag,
                Tag::Running { .. } | Tag::Waiting { .. } | Tag::Delayed { .. }
            ) {
                *tag = Tag::Done(Err(error.clone()));
            }
        }
        self.recovery = None;
    }
}
