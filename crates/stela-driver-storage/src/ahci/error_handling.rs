//! libata error handling: failed-command disposal, port recovery, resets and
//! speed-down.

use super::*;

impl AhciDisk {
    /// `ata_eh_finish` and sd's completion for a command `failure` was
    /// charged to, after recovery: retry it, or complete it by its fetched
    /// or generated sense data.
    pub(super) fn dispose(
        &mut self,
        issue: &mut Issue,
        mut failure: Failure,
    ) -> Option<Result<(), BlockError>> {
        // With valid sense, only a NEEDS_RETRY disposition with an error
        // left besides the device's is retried.
        let retry = match failure.sense {
            Some(sense) => failure.mask != 0 && sense.needs_retry(),
            None => worth_retry(failure.mask, issue.io),
        };
        if retry && issue.retries < COMMAND_RETRIES {
            issue.retries += 1;
            return None;
        }
        let sense = match failure.sense {
            Some(sense) => sense,
            None => self.generated_sense(&mut failure),
        };
        // A fixed disk: no media change.
        match sense.completion(false) {
            SenseCompletion::Done => Some(Ok(())),
            SenseCompletion::Fail | SenseCompletion::MediaChanged => Some(Err(failure.error)),
            SenseCompletion::Retry(delay_us) => {
                // scsi_cmd_runtime_exceeced: sd requeues end (allowed + 1)
                // timeouts after the command was first prepared.
                let runtime_us = (u64::from(COMMAND_RETRIES) + 1) * self.command_timeout_us;
                let Ok(elapsed) = self.clock.try_elapsed_us(issue.prepared) else {
                    return Some(Err(BlockError::Timeout));
                };
                if elapsed > runtime_us {
                    return Some(Err(failure.error));
                }
                match self.clock.try_deadline(delay_us) {
                    Ok(resume) => issue.resume = Some(resume),
                    Err(_) => return Some(Err(BlockError::Timeout)),
                }
                None
            }
        }
    }

    /// Linux `ahci_error_handler` and `ata_eh_recover`: restart an unfrozen
    /// engine, analyze an NCQ error, fetch sense data and consider a
    /// speed-down; when a reset is due, hard reset the
    /// link (one try per `ata_eh_reset_timeouts` entry) and revalidate the
    /// disk, up to `ATA_EH_DEV_TRIES` times. An error disables the disk.
    pub(super) fn recover(
        &mut self,
        port: &impl CommandPort,
        failure: &mut Failure,
        io: bool,
    ) -> Result<(), BlockError> {
        self.minimum.check()?;
        if !failure.frozen {
            stop_engine(port, self.clock)?;
            start_engine(port);
        }
        // ahci_error_intr charges a queued command's device error to the
        // link, where valid sense does not clear it, unless the NCQ error log
        // names the command.
        let mut link_device = failure.queued && failure.interrupts & INTERRUPT_TASK_FILE_ERROR != 0;
        if link_device && !failure.frozen && self.analyze_ncq_error(port, failure)? {
            link_device = false;
        }
        // ata_eh_analyze_tf fetches reported sense data the log did not hold
        // unless the port is frozen or reporting is off; valid sense
        // supersedes the device error.
        if failure.sense.is_none()
            && failure.sense_reported
            && !failure.frozen
            && self.sense_reporting
        {
            failure.sense = self.request_sense(port)?;
        }
        if let Some(sense) = failure.sense {
            failure.error = BlockError::Sense(sense);
            failure.mask &= !ERR_DEVICE;
        }
        let all = failure.mask | if link_device { ERR_DEVICE } else { 0 };
        let slowed = self.speed_down(port, all, io)?;
        // ata_eh_link_autopsy's default actions: a frozen port, a timeout or
        // an HSM violation resets; any other error of an I/O command, and any
        // but a device error of another, revalidates.
        let reset = failure.reset || slowed || failure.frozen || all & (ERR_HSM | ERR_TIMEOUT) != 0;
        let revalidate = if io { all != 0 } else { all & !ERR_DEVICE != 0 };
        if !reset && !revalidate {
            return Ok(());
        }
        let last = failure.error.clone();
        self.reconfigure(port, reset, failure.hotplug, last, DEVICE_TRIES)
    }

    /// `ata_eh_recover`: a reset when one is due, then revalidation and
    /// configuration, `tries` times at most; each retry resets.
    pub(super) fn reconfigure(
        &mut self,
        port: &impl CommandPort,
        mut reset: bool,
        mut hotplug: bool,
        mut last: BlockError,
        mut tries: usize,
    ) -> Result<(), BlockError> {
        loop {
            self.minimum.ready()?;
            if reset {
                let mut online = None;
                for timeout in RESET_TIMEOUTS_US {
                    match self.hardreset(port, timeout, hotplug) {
                        Ok(present) => {
                            online = Some(present);
                            break;
                        }
                        Err(error) => {
                            self.minimum.ready()?;
                            last = error;
                        }
                    }
                }
                match online {
                    None => return Err(last),
                    Some(false) => return Err(DETACHED),
                    Some(true) => {}
                }
            }
            reset = true;
            // ata_eh_revalidate_and_attach wakes a power-saving link first;
            // then ATA_EHI_SETMODE and config_lpm.
            let woken = if self.lpm.policy > LPM_MAX_POWER {
                self.set_lpm(port, LPM_MAX_POWER, tries)
            } else {
                Ok(())
            };
            let Err(error) = woken
                .and_then(|()| self.revalidate(port))
                .and_then(|()| self.set_mode(port))
                .and_then(|()| self.configure_lpm(port, tries))
            else {
                return Ok(());
            };
            self.minimum.ready()?;
            // ata_eh_handle_dev_fail: another device gets one more chance,
            // and the last chance runs slower; -EAGAIN costs no try.
            if error != AGAIN {
                tries -= 1;
                if error == DETACHED {
                    tries = tries.min(1);
                }
                if tries == 1 {
                    self.lower_speed_limit(port);
                    self.lower_transfer_limit(StepDown::Pio);
                }
            }
            if tries == 0 {
                return Err(error);
            }
            last = error;
            hotplug = false;
        }
    }

    /// Linux `ata_eh_speed_down`: record the error and, when the verdict
    /// calls for it, lower the SATA link speed limit; whether a reset must
    /// apply it. NCQ_OFF turns NCQ off instead, and PIO fallback excludes
    /// SATA ATA disks.
    pub(super) fn speed_down(
        &mut self,
        port: &impl CommandPort,
        mask: u32,
        io: bool,
    ) -> Result<bool, BlockError> {
        self.minimum.check()?;
        let mut eflags = if io { EFLAG_IO } else { 0 };
        if self.dubious {
            eflags |= EFLAG_DUBIOUS;
        }
        if categorize(eflags, mask, &mut false) == 0 {
            return Ok(false);
        }
        let at = self.clock.try_start().map_err(|_| BlockError::Timeout)?;
        self.errors.record(eflags, mask, at);
        let verdict = self.verdict()?;
        if verdict & VERDICT_NCQ_OFF != 0 && self.ncq.enabled() {
            self.ncq.off = true;
            if verdict & VERDICT_KEEP_ERRORS == 0 {
                self.errors.clear();
            }
            return Ok(false);
        }
        if verdict & VERDICT_SPEED_DOWN == 0 {
            return Ok(false);
        }
        // The link speed first, then the transfer mode, twice.
        if !self.lower_speed_limit(port) {
            if self.step_downs >= 2 {
                return Ok(false);
            }
            let step = [StepDown::Dma, StepDown::FortyWire][usize::from(self.step_downs)];
            self.step_downs += 1;
            if !self.lower_transfer_limit(step) {
                return Ok(false);
            }
        }
        if verdict & VERDICT_KEEP_ERRORS == 0 {
            self.errors.clear();
        }
        Ok(true)
    }

    /// Linux `ata_eh_speed_down_verdict`.
    pub(super) fn verdict(&mut self) -> Result<u32, BlockError> {
        let short = self.error_counts(VERDICT_SHORT_US)?;
        let long = self.error_counts(VERDICT_LONG_US)?;
        let dubious = |category| short[CATEGORY_DUBIOUS + category];
        let mut verdict = 0;
        if dubious(CATEGORY_ATA_BUS) + dubious(CATEGORY_TIMEOUT_HSM) > 1 {
            verdict |= VERDICT_SPEED_DOWN | VERDICT_FALLBACK_TO_PIO | VERDICT_KEEP_ERRORS;
        }
        if dubious(CATEGORY_TIMEOUT_HSM) + dubious(CATEGORY_UNKNOWN_DEVICE) > 1 {
            verdict |= VERDICT_NCQ_OFF | VERDICT_KEEP_ERRORS;
        }
        if short[CATEGORY_ATA_BUS] + short[CATEGORY_TIMEOUT_HSM] + short[CATEGORY_UNKNOWN_DEVICE]
            > 6
        {
            verdict |= VERDICT_FALLBACK_TO_PIO;
        }
        if long[CATEGORY_TIMEOUT_HSM] + long[CATEGORY_UNKNOWN_DEVICE] > 3 {
            verdict |= VERDICT_NCQ_OFF;
        }
        if long[CATEGORY_ATA_BUS] + long[CATEGORY_TIMEOUT_HSM] > 3
            || long[CATEGORY_UNKNOWN_DEVICE] > 6
        {
            verdict |= VERDICT_SPEED_DOWN;
        }
        Ok(verdict)
    }

    /// `speed_down_verdict_cb` over `ata_ering_map`: categorized errors
    /// within the window, newest first, up to the first cleared or older one.
    pub(super) fn error_counts(&mut self, window_us: u64) -> Result<[u32; CATEGORIES], BlockError> {
        let clock = self.clock;
        let mut counts = [0; CATEGORIES];
        let mut verified = false;
        for entry in self.errors.newest() {
            let age = clock
                .try_elapsed_us(entry.at)
                .map_err(|_| BlockError::Timeout)?;
            if entry.eflags & EFLAG_OLD != 0 || age > window_us {
                break;
            }
            counts[categorize(entry.eflags, entry.mask, &mut verified)] += 1;
        }
        Ok(counts)
    }

    /// Linux `sata_down_spd_limit`: drop the highest allowed speed and every
    /// speed at or above the current one; false when already at the bottom.
    pub(super) fn lower_speed_limit(&mut self, port: &impl CommandPort) -> bool {
        let status = port.read32(PORT_SATA_STATUS);
        let speed = if status & SATA_STATUS_DETECTION == DEVICE_PRESENT {
            (status >> SPEED_SHIFT) & 0xf
        } else {
            self.speed
        };
        let mut mask = self.speed_limit;
        if mask <= 1 {
            return false;
        }
        mask &= !(1 << (fls(mask) - 1));
        if speed > 1 {
            mask &= (1 << (speed - 1)) - 1;
        } else if self.speed != 0 {
            return false;
        }
        if mask == 0 {
            return false;
        }
        self.speed_limit = mask;
        true
    }

    /// Linux `ahci_do_hardreset` with `sata_link_hardreset`: whether an ATA
    /// disk is online afterwards.
    pub(super) fn hardreset(
        &mut self,
        port: &impl CommandPort,
        timeout_us: u64,
        hotplug: bool,
    ) -> Result<bool, BlockError> {
        self.minimum.check()?;
        let clock = self.clock;
        let start = clock.try_start().map_err(|_| BlockError::Timeout)?;
        let elapsed = || clock.try_elapsed_us(start).map_err(|_| BlockError::Timeout);
        // Its failure is not fatal here, as in Linux.
        let _ = stop_engine(port, clock);
        // Clear the D2H reception area to BSY to wait for the new D2H FIS.
        let mut d2h = [0u8; FIS_BYTES];
        d2h[0] = FIS_REGISTER_HOST_TO_DEVICE;
        d2h[2] = STATUS_BUSY;
        d2h[7] = DEVICE_OBSOLETE;
        self.commands.bytes_mut()[RECEIVED_D2H..RECEIVED_D2H + FIS_BYTES].copy_from_slice(&d2h);
        port.write32(PORT_SATA_ERROR, port.read32(PORT_SATA_ERROR));
        port.write32(PORT_INTERRUPTS, port.read32(PORT_INTERRUPTS));
        // sata_set_spd_needed: with the Phy off, program the limit's speed.
        let target = speed_target(self.speed_limit);
        if (port.read32(PORT_SATA_CONTROL) & SATA_CONTROL_SPEED) >> SPEED_SHIFT != target {
            let control = port.read32(PORT_SATA_CONTROL) & SATA_CONTROL_SPEED;
            port.write32(PORT_SATA_CONTROL, control | SATA_CONTROL_OFFLINE);
            let control = port.read32(PORT_SATA_CONTROL) & !SATA_CONTROL_SPEED;
            port.write32(PORT_SATA_CONTROL, control | target << SPEED_SHIFT);
        }
        let speed = port.read32(PORT_SATA_CONTROL) & SATA_CONTROL_SPEED;
        self.minimum.wait_after(COMRESET_HOLD_US, || {
            port.write32(PORT_SATA_CONTROL, speed | SATA_CONTROL_COMRESET);
            port.read32(PORT_SATA_CONTROL);
        })?;
        // sata_link_resume
        let mut resumed = false;
        let mut control = port.read32(PORT_SATA_CONTROL);
        for _ in 0..RESUME_TRIES {
            self.minimum.wait_after(RESUME_SETTLE_US, || {
                port.write32(
                    PORT_SATA_CONTROL,
                    control & SATA_CONTROL_SPEED | SATA_CONTROL_RESUMED,
                );
                port.read32(PORT_SATA_CONTROL);
            })?;
            control = port.read32(PORT_SATA_CONTROL);
            if control & SATA_CONTROL_RESUME_MASK == SATA_CONTROL_RESUMED {
                resumed = true;
                break;
            }
        }
        let result = (|| {
            if resumed {
                let timing = if hotplug {
                    DEBOUNCE_HOTPLUG
                } else {
                    DEBOUNCE_NORMAL
                };
                debounce(
                    port,
                    clock,
                    &self.minimum,
                    timing,
                    timeout_us.saturating_sub(elapsed()?),
                )?;
                port.write32(PORT_SATA_ERROR, port.read32(PORT_SATA_ERROR));
            }
            if port.read32(PORT_SATA_STATUS) & SATA_STATUS_DETECTION != DEVICE_PRESENT {
                return Ok(false);
            }
            // ata_wait_ready with ahci_check_ready.
            let remaining = timeout_us.saturating_sub(elapsed()?);
            if !clock.wait(remaining, || {
                port.read32(PORT_TASK_FILE) as u8 & STATUS_BUSY == 0
            }) {
                return Err(BlockError::Timeout);
            }
            Ok(true)
        })();
        // A timing callback may have failed during debounce. Do not execute
        // Linux's ordinary error-path engine restart after that terminal loss.
        self.minimum.ready()?;
        start_engine(port);
        let online = result?;
        // ata_eh_reset records the current link speed.
        self.speed = (port.read32(PORT_SATA_STATUS) >> SPEED_SHIFT) & 0xf;
        // ahci_dev_classify: only an ATA disk is the same device.
        Ok(online && port.read32(PORT_SIGNATURE) == SIGNATURE_ATA)
    }

    /// Linux `ata_eh_analyze_ncq_error`: the NCQ Command Error log names
    /// the failed command and holds its result taskfile and, with NCQ
    /// autosense, its sense data. Whether it named a launched command, whose
    /// slot `failure` then names.
    pub(super) fn analyze_ncq_error(
        &mut self,
        port: &impl CommandPort,
        failure: &mut Failure,
    ) -> Result<bool, BlockError> {
        if !self.read_log(port, LOG_SATA_NCQ, 0)? {
            return Ok(false);
        }
        let log = &self.table.bytes()[LOG_DATA..LOG_DATA + ATA_SECTOR_BYTES as usize];
        // A tag no launched command holds names none, as Linux reports an
        // inactive tag.
        let tag = usize::from(log[0] & LOG_NCQ_TAG);
        if log[0] & LOG_NCQ_NQ != 0 || failure.slots >> tag & 1 == 0 {
            return Ok(false);
        }
        let [status, error] = [log[2], log[3]];
        let sense = if self.ncq.autosense && status & STATUS_SENSE != 0 {
            valid_sense(log[14], log[15], log[16])
        } else {
            None
        };
        let task_file = u32::from(status) | u32::from(error) << 8;
        *failure = Failure {
            queued: true,
            slots: failure.slots,
            named: Some(tag),
            result: [status, error],
            sense,
            ..classify(failure.interrupts, failure.serror, task_file, false)
        };
        Ok(true)
    }

    /// Linux `ata_gen_ata_sense` for a failed command without sense data,
    /// from its result taskfile. The error stays the transport's own when
    /// that reports no device error.
    pub(super) fn generated_sense(&self, failure: &mut Failure) -> Sense {
        let [status, error] = failure.result;
        let sense = if self.locked {
            // Logical unit access not authorized.
            Sense {
                key: Sense::DATA_PROTECT,
                asc: 0x74,
                ascq: 0x71,
            }
        } else {
            translate_error(status, error)
        };
        if self.locked || status & (STATUS_BUSY | STATUS_FAULT | STATUS_ERROR | STATUS_REQUEST) != 0
        {
            failure.error = BlockError::Sense(sense);
        }
        sense
    }

    /// Linux `ata_eh_request_sense`: REQUEST SENSE DATA EXT, whose D2H FIS
    /// carries the sense key, ASC and ASCQ in LBA bits 23:0. Its own error is
    /// ignored, as ERR might be set; a timeout leaves no result.
    pub(super) fn request_sense(
        &mut self,
        port: &impl CommandPort,
    ) -> Result<Option<Sense>, BlockError> {
        let buffer = self.bounce.bus_address();
        if let Err(failure) = self.attempt(
            port,
            AtaRequest {
                command: ATA_REQUEST_SENSE_DATA_EXT,
                feature: 0,
                lba: 0,
                count: 0,
                bytes: 0,
                write: false,
                buffer,
            },
        ) {
            stop_engine(port, self.clock)?;
            start_engine(port);
            if failure.frozen {
                return Ok(None);
            }
        }
        let d2h = &self.commands.bytes()[RECEIVED_D2H..RECEIVED_D2H + FIS_BYTES];
        if d2h[2] & STATUS_SENSE == 0 {
            return Ok(None);
        }
        Ok(valid_sense(d2h[6], d2h[5], d2h[4]))
    }

    /// Linux `ata_down_xfermask_limit`: false when nothing changed or no PIO
    /// mode would remain.
    pub(super) fn lower_transfer_limit(&mut self, step: StepDown) -> bool {
        let (mut pio, mut udma) = (self.pio_mask, self.udma_mask);
        match step {
            StepDown::Pio => pio &= !(1 << (fls(pio) - 1)),
            StepDown::Dma if udma != 0 => {
                udma &= !(1 << (fls(udma) - 1));
                if udma == 0 {
                    return false;
                }
            }
            StepDown::Dma => {}
            StepDown::FortyWire => udma &= UDMA_MASK_40_WIRE,
        }
        if pio == 0 || (pio, udma) == (self.pio_mask, self.udma_mask) {
            return false;
        }
        (self.pio_mask, self.udma_mask) = (pio, udma);
        true
    }
}
