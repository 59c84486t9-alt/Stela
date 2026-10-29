//! Debug exceptions, breakpoints, traces, watches and research surveys of a
//! running machine.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    pub(super) fn debug_mode(&mut self) -> DebugMode {
        *self.debug.get_or_insert_with(|| {
            let cpu = &self.cpu;
            DebugMode {
                breakpoints: debug::watching(cpu) && debug::any_breakpoint(cpu),
                step: debug::enabled(cpu) && cpu.field(SystemRegister::MDSCR_EL1, 0, 1) != 0,
            }
        })
    }

    /// A breakpoint, software step or watchpoint exception: to EL2 from EL2
    /// and, under HCR_EL2.TGE or MDCR_EL2.TDE, from EL0 and EL1; else to EL1
    /// (Arm `AArch64_BreakpointException` and the others).
    pub(super) fn debug_exception(
        &self,
        lower: Class,
        same: Class,
        iss: u32,
        pc: u64,
    ) -> Exception {
        let el = self.cpu.pstate.el;
        let target = if el == 2 || debug::target(&self.cpu) == 2 {
            2
        } else {
            1
        };
        let class = if target > el { lower } else { same };
        Exception::synchronous(class, iss, pc).to(target)
    }

    /// Arm `SSAdvance` before SVC, HVC and SMC take their exception, so
    /// SPSR.SS records the step as complete.
    pub(super) fn advance_step(&mut self) {
        if self.cpu.step_advance {
            self.cpu.step_advance = false;
            self.cpu.pstate.ss = false;
        }
    }

    /// Stop the run when any PE reaches one of these guest PCs, before its
    /// instruction executes: a diagnostic of the host, invisible to the
    /// guest. Compiled code is discarded so no block runs past one.
    pub fn set_breakpoints(&mut self, pcs: &[u64]) {
        self.breakpoints = pcs.to_vec();
        self.breakpoints.sort_unstable();
        self.breakpoints.dedup();
        self.discard_code();
    }

    /// Record, without stopping, when a PE reaches one of these guest PCs
    /// as a block start through the engine: always its first execution
    /// there, then whenever no chained block enters it directly. Like a
    /// breakpoint, a host diagnostic invisible to the guest.
    pub fn set_traces(&mut self, pcs: &[u64]) {
        self.traces = pcs.to_vec();
        self.traces.sort_unstable();
        self.traces.dedup();
        self.discard_code();
    }

    /// Record, without stopping, every device access whose first byte lies
    /// in one of these physical ranges (base, bytes). A host diagnostic
    /// invisible to the guest.
    pub fn set_watches(&mut self, ranges: &[(u64, u64)]) {
        self.watches = ranges
            .iter()
            .filter(|&&(_, bytes)| bytes != 0)
            .map(|&(base, bytes)| (base, base.saturating_add(bytes - 1)))
            .collect();
    }

    /// The watch hits since the last call, oldest first, at most
    /// [`WATCH_HITS`] of them; later hits are counted in the last one.
    pub fn take_watch_hits(&mut self) -> Vec<WatchHit> {
        core::mem::take(&mut self.watch_hits)
    }

    pub(super) fn watch(&mut self, physical: u64, bytes: u8, value: Option<u64>, write: bool) {
        if !self
            .watches
            .iter()
            .any(|&(first, last)| (first..=last).contains(&physical))
        {
            return;
        }
        if self.watch_hits.len() == WATCH_HITS {
            if let Some(last) = self.watch_hits.last_mut() {
                last.dropped += 1;
            }
            return;
        }
        self.watch_hits.push(WatchHit {
            pc: self.cpu.pc,
            pe: self.current,
            physical,
            bytes,
            value: value.unwrap_or(0),
            write,
            completed: value.is_some(),
            dropped: 0,
        });
    }

    /// The trace hits since the last call, oldest first, at most
    /// [`TRACE_HITS`] of them; later hits are counted in the last one.
    pub fn take_trace_hits(&mut self) -> Vec<TraceHit> {
        core::mem::take(&mut self.trace_hits)
    }

    /// For diagnostics: which parts of the running regime's TTBR1 range
    /// its tables map, read from RAM without changing anything. `None`
    /// unless the regime has two ranges, its MMU is on, TTBR1 walks are
    /// enabled and its walks start at level 1 of a 16 KiB granule (T1SZ
    /// 17 to 27, as 26A434 XNU's T1SZ_BOOT 17), or the root is not RAM.
    pub fn upper_occupancy(&mut self) -> Option<Occupancy> {
        const TG1_16K: u64 = 0b01;
        const LEVEL1_SHIFT: u32 = 36;
        const LEVEL2_SHIFT: u32 = 25;
        const VALID: u64 = 1;
        const TABLE: u64 = 0b11;
        const ADDRESS: u64 = 0x0000_ffff_ffff_c000;
        let controls = self.cpu.controls(self.cpu.regime());
        let tcr = controls.tcr;
        let t1sz = (tcr >> 16 & 0x3f) as u32;
        let epd1 = tcr >> 23 & 1 != 0;
        if controls.regime == mmu::Regime::El2
            || controls.sctlr & 1 == 0
            || epd1
            || tcr >> 30 & 0b11 != TG1_16K
            || !(17..=27).contains(&t1sz)
        {
            return None;
        }
        let entries = 1usize << (64 - t1sz - LEVEL1_SHIFT);
        let root = controls.ttbr1 & ADDRESS & !((entries as u64 * 8).max(64) - 1);
        let mut table = alloc::vec![0u8; entries * 8];
        if !self.host.read_ram(root, &mut table) {
            return None;
        }
        let descriptor = |bytes: &[u8], index: usize| {
            u64::from_le_bytes(bytes[index * 8..][..8].try_into().unwrap())
        };
        let base = u64::MAX << (64 - t1sz);
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut valid = Vec::new();
        for index in 0..entries {
            if descriptor(&table, index) & VALID == 0 {
                continue;
            }
            valid.push(index);
            let first = base + ((index as u64) << LEVEL1_SHIFT);
            let last = first + ((1u64 << LEVEL1_SHIFT) - 1);
            match ranges.last_mut() {
                Some(range) if range.1.wrapping_add(1) == first => range.1 = last,
                _ => ranges.push((first, last)),
            }
        }
        // The lowest and highest mapped 32 MiB, one level below the
        // outermost level-1 entries.
        let mut edge = |index: usize, highest: bool| -> u64 {
            let start = base + ((index as u64) << LEVEL1_SHIFT);
            let entry = descriptor(&table, index);
            let mut next = alloc::vec![0u8; 2048 * 8];
            let table_read =
                entry & TABLE == TABLE && self.host.read_ram(entry & ADDRESS, &mut next);
            let mut slots =
                (0..2048).filter(|&slot| table_read && descriptor(&next, slot) & VALID != 0);
            let slot = if highest {
                slots.next_back()
            } else {
                slots.next()
            };
            let (first, bytes) = match slot {
                Some(slot) => (start + ((slot as u64) << LEVEL2_SHIFT), 1 << LEVEL2_SHIFT),
                None => (start, 1u64 << LEVEL1_SHIFT),
            };
            if highest { first + (bytes - 1) } else { first }
        };
        let lowest = valid.first().map(|&index| edge(index, false));
        let highest = valid.last().map(|&index| edge(index, true));
        Some(Occupancy {
            root,
            ranges,
            lowest,
            highest,
        })
    }

    /// Research only: from now on a device access the devices refuse, or
    /// that reaches no device, completes as a zero read or a discarded
    /// write and is recorded instead of stopping the machine. The values
    /// are invented, so a surveyed run proves nothing about the guest; it
    /// lists every register a driver needs in one run.
    pub fn begin_survey(&mut self) {
        self.survey = Some(Survey::default());
    }

    /// The registers the survey answered first since the last call, with
    /// their counts so far.
    pub fn take_survey(&mut self) -> Vec<Surveyed> {
        let Some(survey) = self.survey.as_mut() else {
            return Vec::new();
        };
        let fresh = core::mem::take(&mut survey.fresh);
        fresh
            .into_iter()
            .filter_map(|key| survey.records.get(&key).cloned())
            .collect()
    }

    /// Whether a survey answered the refused access; `value` is a write's.
    pub(super) fn surveyed(
        &mut self,
        physical: u64,
        bytes: u8,
        write: Option<u64>,
        error: &DeviceError,
    ) -> bool {
        if matches!(error, DeviceError::TransferRefused(_)) {
            return false;
        }
        let pc = self.cpu.pc;
        let link = self.strip_instruction_pointer(self.cpu.state.x[30]);
        let Some(survey) = self.survey.as_mut() else {
            return false;
        };
        let key = (physical, write.is_some());
        let record = survey.records.entry(key).or_insert_with(|| {
            survey.fresh.push(key);
            Surveyed {
                physical,
                bytes,
                write: write.is_some(),
                pc,
                link,
                count: 0,
                value: 0,
                detail: match error {
                    DeviceError::NoDevice => "no device model".into(),
                    DeviceError::Refused(detail) | DeviceError::TransferRefused(detail) => {
                        detail.clone()
                    }
                },
            }
        });
        record.count += 1;
        record.value = write.unwrap_or(0);
        true
    }

    /// Guest threads by thread pointer, with where each stopped running,
    /// while they stay suspended.
    pub fn suspended(&self) -> &BTreeMap<u64, Suspension> {
        &self.suspended
    }

    /// Record that software at `now` replaces the running thread pointer
    /// (TPIDR_EL1) with `next`: the thread it named is suspended where the
    /// PE stands, and `next` runs.
    pub(super) fn trace(&mut self, pc: u64) {
        if self.trace_hits.len() == TRACE_HITS {
            if let Some(last) = self.trace_hits.last_mut() {
                last.dropped += 1;
            }
            return;
        }
        let x = &self.cpu.state.x;
        self.trace_hits.push(TraceHit {
            pc,
            pe: self.current,
            el: self.cpu.pstate.el,
            arguments: [x[0], x[1], x[2], x[3]],
            lr: x[30],
            dropped: 0,
        });
    }

    pub(super) fn switch_thread(&mut self, next: u64, now: u64) {
        let previous = self.cpu.read(SystemRegister::TPIDR_EL1);
        if previous == next {
            return;
        }
        self.suspended.remove(&next);
        if previous != 0 && self.suspended.len() < SUSPENSIONS {
            let state = &self.cpu.state;
            let suspension = Suspension {
                at: now,
                pc: self.cpu.pc,
                frame: state.x[29],
                link: state.x[30],
            };
            self.suspended.insert(previous, suspension);
        }
    }
}
