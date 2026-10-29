//! Command slots: issuing, launching and completing ATA commands and the queued
//! block commands.

use super::*;

impl AhciDisk {
    /// The commands the port runs at once: a slot each while NCQ is on.
    pub(super) fn queue_depth(&self) -> usize {
        if self.ncq.enabled() {
            1 + self.slots.len()
        } else {
            1
        }
    }

    /// The lowest slot within the queue depth no started command holds.
    pub(super) fn free_slot(&self) -> Option<usize> {
        (0..self.queue_depth()).find(|slot| self.running.iter().all(|run| run.slot != *slot))
    }

    pub(super) fn table(&self, slot: usize) -> &DmaBuffer {
        match slot {
            0 => &self.table,
            slot => &self.slots[slot - 1].table,
        }
    }

    pub(super) fn bounce(&self, slot: usize) -> &DmaBuffer {
        match slot {
            0 => &self.bounce,
            slot => &self.slots[slot - 1].bounce,
        }
    }

    pub(super) fn bounce_mut(&mut self, slot: usize) -> &mut DmaBuffer {
        match slot {
            0 => &mut self.bounce,
            slot => &mut self.slots[slot - 1].bounce,
        }
    }

    /// Run one ATA command in slot 0 with `bytes` of data through the bounce
    /// buffer.
    pub(super) fn issue(
        &mut self,
        command: u8,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<(), BlockError> {
        let port = self.port;
        self.issue_on(&port, command, lba, count, bytes, write)
    }

    /// One command through libata's error handling: recover the port after a
    /// failure, then retry as `ata_eh_finish` decides, and complete a failed
    /// command by its fetched or generated sense data as sd does.
    pub(super) fn issue_on(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<(), BlockError> {
        self.issue_with(port, (command, 0), lba, count, bytes, write)
    }

    /// [`Self::issue_on`] with the command's FEATURE field.
    pub(super) fn issue_with(
        &mut self,
        port: &impl CommandPort,
        command: (u8, u16),
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<(), BlockError> {
        let issue = self.prepare(command, lba, count, bytes, write)?;
        self.complete(port, issue)
    }

    /// Run `issue` to its result in slot 0, after the started block
    /// commands'.
    pub(super) fn complete(
        &mut self,
        port: &impl CommandPort,
        mut issue: Issue,
    ) -> Result<(), BlockError> {
        while self.running.iter().any(|running| running.result.is_none()) {
            self.run(port);
            crate::waiting();
            core::hint::spin_loop();
        }
        loop {
            if let Some(result) = self.step(port, &mut issue) {
                return result;
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    pub(super) fn prepare(
        &self,
        (command, feature): (u8, u16),
        lba: u64,
        count: u16,
        bytes: usize,
        write: bool,
    ) -> Result<Issue, BlockError> {
        self.ready()?;
        Ok(Issue {
            slot: 0,
            command,
            feature,
            lba,
            count,
            bytes,
            write,
            io: matches!(
                command,
                ATA_READ_DMA_EXT
                    | ATA_WRITE_DMA_EXT
                    | ATA_READ_FPDMA_QUEUED
                    | ATA_WRITE_FPDMA_QUEUED
            ),
            prepared: self.clock.try_start().map_err(|_| BlockError::Timeout)?,
            retries: 0,
            launched: None,
            resume: None,
        })
    }

    /// Move `issue` on without waiting, the port running nothing else:
    /// [`Self::advance`] for one command.
    pub(super) fn step(
        &mut self,
        port: &impl CommandPort,
        issue: &mut Issue,
    ) -> Option<Result<(), BlockError>> {
        self.advance(port, &mut [issue]).pop().flatten()
    }

    /// Move `issues`, each in its own slot, on without waiting: launch
    /// those that may run, take one look at the port, and recover it from a
    /// failure, after which each failed command is retried as
    /// `ata_eh_finish` decides and completes by its fetched or generated
    /// sense data, as sd does. Each issue's result once it has one.
    ///
    /// Linux `ata_std_qc_defer`: in turn, a queued command launches beside
    /// queued ones, any other alone. A failure reaches every launched
    /// command, as `ata_link_abort` does; one the NCQ Command Error log does
    /// not blame runs again uncharged (`ata_eh_qc_retry` without an error).
    pub(super) fn advance(
        &mut self,
        port: &impl CommandPort,
        issues: &mut [&mut Issue],
    ) -> Vec<Option<Result<(), BlockError>>> {
        let mut results: Vec<_> = issues.iter().map(|_| None).collect();
        let mut launched = issues
            .iter()
            .filter(|issue| issue.launched.is_some())
            .count();
        let mut plain = issues.iter().any(|issue| {
            issue
                .launched
                .as_ref()
                .is_some_and(|launched| !launched.queued)
        });
        for (index, issue) in issues.iter_mut().enumerate() {
            if issue.launched.is_some() || issue.resume.is_some_and(|resume| !resume.passed()) {
                continue;
            }
            issue.resume = None;
            if let Err(error) = self.ready() {
                results[index] = Some(Err(error));
                continue;
            }
            let command = self.rw_command(issue.command);
            let queued = matches!(command, ATA_READ_FPDMA_QUEUED | ATA_WRITE_FPDMA_QUEUED);
            if plain || (!queued && launched > 0) {
                break;
            }
            let buffer = self.bounce(issue.slot).bus_address();
            match self.launch(
                port,
                issue.slot,
                launched == 0,
                AtaRequest {
                    command,
                    feature: issue.feature,
                    lba: issue.lba,
                    count: issue.count,
                    bytes: issue.bytes,
                    write: issue.write,
                    buffer,
                },
            ) {
                Ok(started) => {
                    issue.launched = Some(started);
                    launched += 1;
                    plain |= !queued;
                }
                Err(failure) => results[index] = Some(Err(failure.error)),
            }
        }
        let seen = {
            let launched: Vec<&Launched> = issues
                .iter()
                .filter_map(|issue| issue.launched.as_ref())
                .collect();
            if launched.is_empty() {
                return results;
            }
            match self.look(port, &launched) {
                Some(seen) => seen,
                None => return results,
            }
        };
        for (index, issue) in issues.iter_mut().enumerate() {
            if issue
                .launched
                .as_ref()
                .is_some_and(|launched| seen.done >> launched.slot & 1 != 0)
            {
                issue.launched = None;
                // ata_verify_xfer: a completed DMA transfer verifies it.
                if issue.io {
                    self.dubious = false;
                }
                results[index] = Some(Ok(()));
            }
        }
        let Some(mut failure) = seen.failure else {
            return results;
        };
        let io = issues
            .iter()
            .any(|issue| issue.launched.is_some() && issue.io);
        if let Err(error) = self.recover(port, &mut failure, io) {
            self.fault = Some(error.clone());
            for (index, issue) in issues.iter_mut().enumerate() {
                if issue.launched.take().is_some() {
                    results[index] = Some(Err(error.clone()));
                }
            }
            return results;
        }
        for (index, issue) in issues.iter_mut().enumerate() {
            let Some(launched) = issue.launched.take() else {
                continue;
            };
            let blamed = match failure.named {
                Some(slot) => slot == launched.slot,
                None => seen.blamed >> launched.slot & 1 != 0,
            };
            if blamed {
                results[index] = self.dispose(issue, failure.clone());
            }
        }
        results
    }

    /// `ata_build_rw_tf`: reads and writes are queued while NCQ is enabled.
    pub(super) fn rw_command(&self, command: u8) -> u8 {
        match command {
            ATA_READ_DMA_EXT if self.ncq.enabled() => ATA_READ_FPDMA_QUEUED,
            ATA_WRITE_DMA_EXT if self.ncq.enabled() => ATA_WRITE_FPDMA_QUEUED,
            _ => command,
        }
    }

    /// An internal command (`ata_exec_internal`): a failure kicks the engine
    /// so it forgets the command, and is returned as is.
    pub(super) fn internal(
        &mut self,
        port: &impl CommandPort,
        command: u8,
        feature: u8,
        count: u16,
        bytes: usize,
        buffer: u64,
    ) -> Result<(), Failure> {
        self.ready().map_err(Failure::new)?;
        let Err(failure) = self.attempt(
            port,
            AtaRequest {
                command,
                feature: u16::from(feature),
                lba: 0,
                count,
                bytes,
                write: false,
                buffer,
            },
        ) else {
            return Ok(());
        };
        stop_engine(port, self.clock).map_err(Failure::new)?;
        start_engine(port);
        Err(failure)
    }

    /// Issue the command once in slot 0, the port running nothing else, and
    /// wait for its completion or error.
    pub(super) fn attempt(
        &mut self,
        port: &impl CommandPort,
        request: AtaRequest,
    ) -> Result<(), Failure> {
        let launched = self.launch(port, 0, true, request)?;
        loop {
            if let Some(seen) = self.look(port, &[&launched]) {
                return seen.failure.map_or(Ok(()), Err);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }

    /// Issue the command once in `slot`; `alone` when the port runs no
    /// other command, whose interrupts and ending FIS marks it may clear.
    pub(super) fn launch(
        &mut self,
        port: &impl CommandPort,
        slot: usize,
        alone: bool,
        request: AtaRequest,
    ) -> Result<Launched, Failure> {
        let AtaRequest {
            command,
            feature,
            lba,
            count,
            bytes,
            write,
            buffer,
        } = request;
        let table = self.table(slot).bus_address();
        // A queued command's sector count moves to the features registers;
        // the count register carries its tag, its slot, in bits 7:3.
        let queued = matches!(command, ATA_READ_FPDMA_QUEUED | ATA_WRITE_FPDMA_QUEUED);
        let (feature, count) = if queued {
            (count, (slot as u16) << 3)
        } else {
            (feature, count)
        };
        let fis = [
            FIS_REGISTER_HOST_TO_DEVICE,
            FIS_COMMAND,
            command,
            feature as u8,
            lba as u8,
            (lba >> 8) as u8,
            (lba >> 16) as u8,
            if command == ATA_IDENTIFY {
                0
            } else {
                DEVICE_LBA
            },
            (lba >> 24) as u8,
            (lba >> 32) as u8,
            (lba >> 40) as u8,
            (feature >> 8) as u8,
            count as u8,
            (count >> 8) as u8,
        ];
        let entries = u32::from(bytes > 0);
        let tables = match slot {
            0 => &mut self.table,
            slot => &mut self.slots[slot - 1].table,
        };
        tables.bytes_mut()[..TABLE_HEADER_BYTES].fill(0);
        tables.bytes_mut()[..fis.len()].copy_from_slice(&fis);
        if bytes > 0 {
            tables.write(PRDT_ADDRESS, buffer);
            tables.write(PRDT_BYTE_COUNT, bytes as u32 - 1);
        }
        let flags = COMMAND_FIS_DWORDS
            | u32::from(write) << COMMAND_WRITE_SHIFT
            | entries << COMMAND_PRDT_SHIFT;
        let header = slot * COMMAND_HEADER_BYTES;
        self.commands.write(header, flags);
        self.commands.write(header + 4, 0u32);
        self.commands.write(header + 8, table);
        fence(Ordering::SeqCst);
        // The FIS a command ends with lands in the received-FIS area in RAM.
        // Mark its types with the H2D Register type, as a hardreset does, to
        // see one arrive; a look marks a queued command's again.
        if alone {
            port.write32(PORT_INTERRUPTS, u32::MAX);
            for &(at, _) in ending(queued) {
                self.commands.write(at, FIS_REGISTER_HOST_TO_DEVICE);
            }
            // The first look reads the registers too: an emulated port may
            // finish at the PxCI write.
            self.looks = 0;
        }
        fence(Ordering::SeqCst);
        let deadline = self
            .clock
            .try_deadline(self.command_timeout_us)
            .map_err(|_| Failure::new(BlockError::Timeout))?;
        // ahci_qc_issue: a queued command is active in PxSACT until the
        // disk's Set Device Bits FIS clears it.
        if queued {
            port.write32(PORT_SATA_ACTIVE, 1 << slot);
        }
        port.write32(PORT_ISSUE, 1 << slot);
        Ok(Launched {
            slot,
            queued,
            deadline,
        })
    }

    /// One look at `launched`, all queued commands or one other; never
    /// waits. PxIS and PxSACT or PxCI, which a hypervisor traps, are read
    /// when an ending FIS arrived, every few looks since a failure may post
    /// none, and at a deadline. A queued command's Set Device Bits FIS is
    /// marked again before PxSACT is read, so a later one is seen. Nothing
    /// when no command completed or failed.
    pub(super) fn look(&mut self, port: &impl CommandPort, launched: &[&Launched]) -> Option<Seen> {
        let queued = launched.iter().any(|launched| launched.queued);
        let active = if queued { PORT_SATA_ACTIVE } else { PORT_ISSUE };
        let due = self.looks.is_multiple_of(REGISTER_POLL_INTERVAL);
        self.looks = self.looks.wrapping_add(1);
        let posted = ending(queued)
            .iter()
            .any(|&(at, kind)| self.commands.read::<u8>(at) == kind);
        // The deadlines are read only when nothing else calls for a look.
        if !posted && !due && !launched.iter().any(|launched| launched.deadline.passed()) {
            return None;
        }
        if queued && posted {
            self.commands
                .write(RECEIVED_SDB, FIS_REGISTER_HOST_TO_DEVICE);
            fence(Ordering::SeqCst);
        }
        let interrupts = port.read32(PORT_INTERRUPTS) & INTERRUPT_ERROR;
        let running = port.read32(active);
        fence(Ordering::SeqCst);
        let slots = launched
            .iter()
            .fold(0, |slots, launched| slots | 1 << launched.slot);
        let done = slots & !running;
        let expired = launched
            .iter()
            .filter(|launched| running >> launched.slot & 1 != 0 && launched.deadline.passed())
            .fold(0, |slots, launched| slots | 1 << launched.slot);
        if interrupts == 0 && expired == 0 {
            return (done != 0).then_some(Seen {
                done,
                failure: None,
                blamed: 0,
            });
        }
        // AHCI needs SError cleared; otherwise it might lock up.
        let serror = port.read32(PORT_SATA_ERROR);
        port.write32(PORT_SATA_ERROR, serror);
        port.write32(PORT_INTERRUPTS, port.read32(PORT_INTERRUPTS));
        let timed_out = interrupts == 0;
        let mut failure = classify(interrupts, serror, port.read32(PORT_TASK_FILE), timed_out);
        // ahci_qc_fill_rtf, before error handling issues anything else: the
        // Set Device Bits FIS for a queued command, else the last D2H FIS.
        let fis = if queued { RECEIVED_SDB } else { RECEIVED_D2H };
        let fis = &self.commands.bytes()[fis..fis + FIS_BYTES];
        failure.result = [fis[2], fis[3]];
        failure.queued = queued;
        failure.slots = if queued { slots } else { 0 };
        // An error interrupt reaches every launched command, as
        // ata_link_abort does: those that completed run again. A timeout
        // charges the expired commands, after those that completed.
        Some(if timed_out {
            Seen {
                done,
                failure: Some(failure),
                blamed: expired,
            }
        } else {
            Seen {
                done: 0,
                failure: Some(failure),
                blamed: slots,
            }
        })
    }

    /// Take `command` as a started block command, in the lowest free slot.
    pub(super) fn begin(&mut self, command: Command) -> Result<u32, BlockError> {
        self.ready()?;
        let command = command.within(&self.identity, 0)?;
        let Some(slot) = self.free_slot() else {
            return Err(BlockError::Protocol(
                "every AHCI command slot is running a command",
            ));
        };
        let tag = self.next_tag;
        self.next_tag = tag.wrapping_add(1);
        self.running.push(Running {
            tag,
            slot,
            command,
            done: 0,
            data: Vec::new(),
            issue: None,
            result: None,
        });
        Ok(tag)
    }

    /// Move the started block commands on as far as they go without
    /// waiting.
    pub(super) fn run(&mut self, port: &impl CommandPort) {
        let mut running = core::mem::take(&mut self.running);
        loop {
            for command in running
                .iter_mut()
                .filter(|command| command.result.is_none() && command.issue.is_none())
            {
                match self.next_issue(command) {
                    Ok(Some(issue)) => command.issue = Some(issue),
                    Ok(None) => {
                        let data = core::mem::take(&mut command.data);
                        let read = matches!(command.command, Command::Read { .. });
                        command.result = Some(Ok(read.then_some(data)));
                    }
                    Err(error) => command.result = Some(Err(error)),
                }
            }
            let mut issues: Vec<&mut Issue> = running
                .iter_mut()
                .filter_map(|command| command.issue.as_mut())
                .collect();
            if issues.is_empty() {
                break;
            }
            let results = self.advance(port, &mut issues);
            let mut progressed = false;
            for (command, result) in running
                .iter_mut()
                .filter(|command| command.issue.is_some())
                .zip(results)
            {
                let Some(result) = result else {
                    continue;
                };
                progressed = true;
                let Some(issue) = command.issue.take() else {
                    continue;
                };
                match result {
                    Err(error) => command.result = Some(Err(error)),
                    Ok(()) => {
                        if let Command::Read { .. } = command.command {
                            command.data.extend_from_slice(
                                &self.bounce(command.slot).bytes()[..issue.bytes],
                            );
                        }
                        command.done += issue.bytes.max(1);
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        self.running = running;
    }

    /// The next part of `running`'s command, its data staged in its slot's
    /// bounce buffer, or `None` once all of it is done.
    pub(super) fn next_issue(&mut self, running: &Running) -> Result<Option<Issue>, BlockError> {
        let block = self.identity.block_size as usize;
        let done = running.done;
        let slot = running.slot;
        let issue = match &running.command {
            Command::Read { lba, bytes } if done < *bytes => {
                let part = (bytes - done).min(self.chunk_bytes());
                let first = lba + (done / block) as u64;
                let count = self.sectors(part);
                self.prepare((ATA_READ_DMA_EXT, 0), first, count, part, false)?
            }
            Command::Write {
                lba,
                data,
                fua: false,
            } if done < data.len() => {
                let part = (data.len() - done).min(self.chunk_bytes());
                self.bounce_mut(slot).bytes_mut()[..part].copy_from_slice(&data[done..done + part]);
                let first = lba + (done / block) as u64;
                let count = self.sectors(part);
                self.prepare((ATA_WRITE_DMA_EXT, 0), first, count, part, true)?
            }
            Command::Flush if done == 0 => match self.flush {
                Some(command) => self.prepare((command, 0), 0, 0, 0, false)?,
                None => return Ok(None),
            },
            Command::Discard { lba, blocks } if done == 0 => self.trim(*lba, *blocks, slot)?,
            Command::Write { fua: true, .. } => {
                return Err(BlockError::Unsupported(
                    "the device takes no Force Unit Access",
                ));
            }
            Command::WriteZeroes { .. } => {
                return Err(BlockError::Unsupported("the device takes no Write Zeroes"));
            }
            _ => return Ok(None),
        };
        Ok(Some(Issue { slot, ..issue }))
    }

    /// TRIM in one block of ranges, as libata's `ata_format_dsm_trim_descr`
    /// writes them: each the starting logical sector in bits 47:0 and the
    /// count in bits 63:48, staged in `slot`'s bounce buffer.
    pub(super) fn trim(&mut self, lba: u64, blocks: u64, slot: usize) -> Result<Issue, BlockError> {
        let bytes = usize::try_from(blocks)
            .ok()
            .and_then(|blocks| blocks.checked_mul(self.identity.block_size as usize))
            .ok_or(BlockError::Unsupported("a TRIM past one block of ranges"))?;
        self.identity.check_write(lba, bytes)?;
        let (mut sector, mut sectors) = (lba, blocks);
        if sectors > TRIM_RANGES * TRIM_RANGE_SECTORS {
            return Err(BlockError::Unsupported("a TRIM past one block of ranges"));
        }
        self.ready()?;
        let ranges = &mut self.bounce_mut(slot).bytes_mut()[..ATA_SECTOR_BYTES as usize];
        ranges.fill(0);
        for range in ranges.chunks_mut(8) {
            if sectors == 0 {
                break;
            }
            let count = sectors.min(TRIM_RANGE_SECTORS);
            range.copy_from_slice(&(sector | count << 48).to_le_bytes());
            (sector, sectors) = (sector + count, sectors - count);
        }
        self.prepare(
            (ATA_DATA_SET_MANAGEMENT, TRIM),
            0,
            1,
            ATA_SECTOR_BYTES as usize,
            true,
        )
    }
}
