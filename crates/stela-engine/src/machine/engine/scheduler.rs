//! The serial run loop: device polling, stepping, native execution and block
//! linking.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    /// Run until a stop. `budget` limits executed blocks (0 = unlimited).
    pub fn run(&mut self, budget: u64) -> Stop {
        self.run_with_budget(RunBudget {
            blocks: budget,
            host_ticks: None,
        })
    }

    /// Run within block and optional host-time limits, yielding between
    /// engine steps. An entered native chain or host callback may overrun.
    pub fn run_with_budget(&mut self, budget: RunBudget) -> Stop {
        self.latch_canonical_native_failure();
        if let Some(failure) = &self.native_failure {
            return Stop::NativeFailure(failure.summary.clone());
        }
        if let Some(pending) = self.pending_native_device_access() {
            return pending;
        }
        if self.cpu.has_canonical_memory() || self.peers.iter().any(|peer|
            matches!(peer, processors::Peer::Parked(parked) if parked.cpu().has_canonical_memory())) {
            return self.unsupported(RequirementKind::Native(
                "converted shared-memory PEs run only through run_serialized or the native scheduler",
            ));
        }
        self.run_blocks_with_budget(budget)
    }

    /// The serial scheduler and chained native blocks, until a stop.
    pub(super) fn run_blocks(&mut self, budget: u64) -> Stop {
        self.run_blocks_with_budget(RunBudget {
            blocks: budget,
            host_ticks: None,
        })
    }

    pub(super) fn run_blocks_with_budget(&mut self, budget: RunBudget) -> Stop {
        self.latch_canonical_native_failure();
        if let Some(failure) = &self.native_failure {
            return Stop::NativeFailure(failure.summary.clone());
        }
        let deadline = budget
            .host_ticks
            .map(|ticks| budget::Deadline::new(self.host.counter(), ticks));
        self.observe_parallel_source(SourcePhase::SliceEnter);
        self.block_limit = if budget.blocks == 0 {
            u64::MAX
        } else {
            budget.blocks
        };
        self.waited = 0;
        // The host may have changed the devices between runs (`devices` is
        // theirs too): their lines are asked again.
        self.device_lines = None;
        loop {
            if self.statistics.blocks >= self.block_limit
                || deadline
                    .is_some_and(|deadline| deadline.remaining(self.host.counter()).is_none())
            {
                self.observe_parallel_source(SourcePhase::SliceExit);
                return Stop::Budget;
            }
            let started = self.timing_start();
            let scheduled = match deadline {
                Some(deadline) => self.schedule_with_deadline(Some(deadline)),
                None => self.schedule(),
            };
            self.timing_charge(step_timing::Phase::Schedule, started);
            if let Err(stop) = scheduled
                .and_then(|()| self.step())
                .or_else(|stop| self.undefined_instead(stop))
            {
                self.observe_parallel_source(SourcePhase::SliceExit);
                return stop;
            }
        }
    }

    /// The same RAM publication path as MMIO-triggered DMA, reached with no
    /// translated invocation live. Called while running and while all PEs wait.
    pub(super) fn poll_devices(&mut self, now: u64) -> Step {
        if let Some(deadline) = self.devices.dma_deadline() {
            self.poll_devices_at(now, deadline)?;
        }
        Ok(())
    }

    /// Dispatch need not observe time when no asynchronous DMA is pending.
    /// Scheduler callers already have a timestamp and use `poll_devices`.
    pub(super) fn poll_due_devices(&mut self) -> Step {
        if let Some(deadline) = self.devices.dma_deadline() {
            let now = self.now();
            self.poll_devices_at(now, deadline)?;
        }
        Ok(())
    }

    pub(super) fn poll_devices_at(&mut self, now: u64, deadline: u64) -> Step {
        if now >= deadline {
            // A device's asynchronous work it cannot carry out is dropped,
            // reported once.
            let started = self.timing_start();
            if let Err(error) = self.device_transfer(now) {
                let advance = RequirementKind::DeviceAdvance(format!("{error:?}"));
                self.degrade(self.requirement(advance));
            }
            self.statistics.due_transfers += 1;
            self.statistics.transfer_ticks += self.timing_since(started);
            self.device_lines = None;
        }
        Ok(())
    }

    pub(super) fn step(&mut self) -> Step {
        let started = self.timing_start();
        self.poll_due_devices()?;
        let delivered = self.deliver_interrupts();
        self.timing_charge(step_timing::Phase::Devices, started);
        if let Some(reason) = self.devices.take_reset() {
            return Err(Stop::Reset(reason));
        }
        if delivered {
            return Ok(());
        }
        let pc = self.cpu.pc;
        let mode = self.debug_mode();
        // Active-pending software step comes before every other exception
        // of the instruction (Arm `CheckSoftwareStep`).
        if mode.step && !self.cpu.pstate.ss {
            let exception = self.debug_exception(Class::StepLower, Class::StepSame, 0x22, pc);
            self.take(exception);
            return Ok(());
        }
        if !pc.is_multiple_of(INSTRUCTION) {
            let mut exception = Exception::synchronous(Class::PcAlignment, 0, pc);
            exception.fault_address = Some(pc);
            self.take(exception);
            return Ok(());
        }
        if (mode.breakpoints || self.cpu.pstate.il)
            && let Some(exception) = self.instruction_checks(pc, mode.breakpoints)?
        {
            self.take(exception);
            return Ok(());
        }
        if self.breakpoints.binary_search(&pc).is_ok() {
            return Err(Stop::Breakpoint(pc));
        }
        if self.traces.binary_search(&pc).is_ok() {
            self.trace(pc);
        }
        // Active-not-pending: this one instruction advances the step.
        self.cpu.step_advance = mode.step;
        // PSTATE.PACM applies to the one instruction after PACM.
        let pacm = self.cpu.pstate.pacm;
        let single = mode.breakpoints || mode.step || pacm;
        let fetching = self.timing_start();
        let fetched = self.fetch_block(pc, single);
        self.timing_charge(step_timing::Phase::Fetch, fetching);
        let index = match fetched? {
            Fetched::Block(index) => index,
            Fetched::Exception(exception) => {
                self.cpu.step_advance = false;
                self.take(exception);
                return Ok(());
            }
            Fetched::Checked(word) => {
                let step = self.checked_instruction(pc, word);
                if !core::mem::take(&mut self.pacm_written) && pacm {
                    self.cpu.pstate.pacm = false;
                }
                self.advance_step();
                return step;
            }
        };
        if self.cpu.pstate.btype != 0 && self.fetch_guarded(pc) {
            let word = self.word(index, pc)?;
            if let Some(exception) = self.branch_target_exception(pc, word) {
                self.take(exception);
                return Ok(());
            }
        }
        let step = self.execute(index, if single { 0 } else { self.chain_budget() });
        if self.native_failure.is_some() {
            return step;
        }
        if !core::mem::take(&mut self.pacm_written) && pacm {
            self.cpu.pstate.pacm = false;
        }
        self.advance_step();
        step
    }

    /// Blocks the next native run may chain into: none past the time slice
    /// or the run's limit.
    pub(super) fn chain_budget(&self) -> u64 {
        let next = self.statistics.blocks + 1;
        CHAIN_LIMIT
            .min(self.slice_end.saturating_sub(next))
            .min(self.block_limit.saturating_sub(next))
    }

    /// Run compiled block `index` and the blocks it chains into, up to
    /// `budget` of them, and complete the last one's exit or fault.
    pub(super) fn execute(&mut self, index: usize, budget: u64) -> Step {
        let entry = self.blocks[index].code;
        self.chain.begin(index, budget);
        let entered = self.timing_start();
        // SAFETY: installed by this machine since the last discard, for the system-mode block ABI;
        // chained blocks and thunks too.
        let exit = unsafe { self.host.execute(entry, &mut self.cpu.state) };
        let returned = self.timing_charge(step_timing::Phase::Native, entered);
        let remaining = self.chain.budget().load(Ordering::Relaxed);
        let (block, retired, hits, linked) = self.chain.completed();
        let chained = linked + hits;
        let last = (block & u64::from(u32::MAX)) as usize;
        if let NativeExit::Fault(fault) = exit
            && (last >= self.blocks.len() || self.blocks[last].code.0 == 0)
        {
            return Err(self.fail_native(index, fault, NativeFailureReason::UnknownCode));
        }
        self.statistics.blocks += 1 + chained;
        self.statistics.chained += chained;
        self.statistics.lookup_hits += hits;
        // A transfer entered the last block, with the BTYPE it names: 0
        // from every thunk but those of BR and BLR forms.
        let btype = (chained > 0).then_some((block >> chain::BLOCK_BTYPE_SHIFT) as u8);
        match exit {
            NativeExit::Exit { next_pc, kind } => {
                self.cpu.retired = self.cpu.retired.wrapping_add(retired);
                if let Some(btype) = btype {
                    self.cpu.pstate.btype = btype;
                }
                if let Some(count) = self.statistics.exit_kinds.get_mut(kind as usize) {
                    *count += 1;
                }
                if let Some(miss) = self.lookup_miss(last, next_pc, kind, remaining > budget) {
                    self.statistics.lookup_misses[miss] += 1;
                }
                let exited = self.exit(last, next_pc, kind);
                if exited.is_ok() {
                    let btype = self.cpu.pstate.btype;
                    match ExitKind::try_from(kind) {
                        Ok(kind @ (ExitKind::Fallthrough | ExitKind::Direct | ExitKind::Call))
                            if btype == 0 =>
                        {
                            self.link(last, next_pc, kind);
                        }
                        Ok(ExitKind::Return | ExitKind::Indirect | ExitKind::Call) => {
                            self.link_dynamic(last, btype);
                        }
                        _ => {}
                    }
                }
                self.timing_exit(kind as usize, returned);
                exited
            }
            NativeExit::Fault(mut fault) => {
                let at = (entry.0 as u64).wrapping_add(fault.offset as u64);
                fault.offset = at.wrapping_sub(self.blocks[last].code.0 as u64) as usize;
                let slot = step_timing::fault_slot(&fault.cause);
                let handled = self.native_fault(last, fault, retired, btype);
                self.timing_exit(slot, returned);
                handled
            }
        }
    }

    /// Why block `index`'s exit of `kind` to `next_pc` took no lookup
    /// transfer, as an index of `Statistics::lookup_misses`, when it is one
    /// a lookup thunk serves; `spent` when a thunk found no budget left.
    pub(super) fn lookup_miss(
        &self,
        index: usize,
        next_pc: u64,
        kind: u64,
        spent: bool,
    ) -> Option<usize> {
        let block = &self.blocks[index];
        let kind = ExitKind::try_from(kind).ok()?;
        let unlinked = if dynamic_branch(block.terminal.1).is_some() {
            block.dynamic_site.is_some()
        } else if (next_pc ^ block.pc) & !(FETCH_PAGE - 1) != 0
            && matches!(
                kind,
                ExitKind::Fallthrough | ExitKind::Direct | ExitKind::Call
            )
        {
            block
                .successors
                .iter()
                .any(|exit| exit.target.0 == next_pc && exit.kind == kind)
        } else {
            return None;
        };
        if self.variants[block.variant.0 as usize].single {
            return None;
        }
        let entry = &self.targets[chain::lookup_slot(next_pc)];
        Some(if unlinked {
            0
        } else if entry.pc != next_pc {
            1
        } else if entry.context != self.chain.contexts()[chain::half(next_pc)] {
            2
        } else if spent {
            3
        } else {
            4
        })
    }

    /// Redirect block `index`'s direct exit to `next_pc` into the block a
    /// fetch there would run, once that block exists: one in the same
    /// page, so the same translation and permissions, compiled for the same
    /// variant. Its BTYPE is 0, as no branch that sets it ends in a direct
    /// exit, and every System register write, exception and device access
    /// that changes what the next fetch checks returns to the engine. An
    /// exit out of the page goes through a lookup thunk instead.
    pub(super) fn link(&mut self, index: usize, next_pc: u64, kind: ExitKind) {
        let block = &self.blocks[index];
        if self.variants[block.variant.0 as usize].single
            || self.traces.binary_search(&next_pc).is_ok()
        {
            return;
        }
        let Some(position) = block
            .successors
            .iter()
            .position(|exit| exit.target.0 == next_pc && exit.kind == kind)
        else {
            return;
        };
        if (next_pc ^ block.pc) & !(FETCH_PAGE - 1) != 0 {
            let exit = block.successors[position];
            let retired = block.source_map.len() as u32;
            if self.redirect_through_lookup(exit.site, retired, Some(exit.target), kind, 0) {
                self.blocks[index].successors.swap_remove(position);
            }
            return;
        }
        let physical = block.physical.wrapping_add(next_pc.wrapping_sub(block.pc));
        let Some(&target) = self.index.get(&(next_pc, physical, block.variant)) else {
            return;
        };
        let exit = block.successors[position];
        let site = exit.site;
        let retired = block.source_map.len() as u32;
        let entry = self.blocks[target].code.0 as u64;
        let control = self.chain.address();
        let Ok(thunk) = self.host.install(&[0; chain::THUNK_BYTES]) else {
            return;
        };
        let at = thunk.0 as u64;
        let (Some(code), Some(jump)) = (
            chain::thunk(
                at,
                control,
                retired,
                target as u32,
                entry,
                exit.target,
                exit.kind,
            ),
            chain::jump(site, at),
        ) else {
            return;
        };
        self.patch_native(thunk, &code);
        self.patch_native(NativeCode(site as usize), &jump);
        self.blocks[index].successors.swap_remove(position);
        self.statistics.links += 1;
    }

    /// Redirect block `index`'s exit to the target in RAX, which just left
    /// BTYPE `btype`, through a lookup thunk, whose target any fetch may
    /// have run. The thunk sets the BTYPE the form sets from the block's
    /// page: 0 for RET, 0b10 for BLR forms, 0b01 for BR forms through X16
    /// or X17, and for BR forms through another register 0b11 in a guarded
    /// page and 0b01 elsewhere. Blocks are compiled per guarded page, so
    /// the page's BTYPE is the block's.
    pub(super) fn link_dynamic(&mut self, index: usize, btype: u8) {
        let block = &self.blocks[index];
        let Some(site) = block
            .dynamic_site
            .filter(|_| !self.variants[block.variant.0 as usize].single)
        else {
            return;
        };
        let Some((kind, fixed)) = dynamic_branch(block.terminal.1) else {
            return;
        };
        let page = if self.variants[block.variant.0 as usize].guarded_page {
            0b11
        } else {
            0b01
        };
        if fixed.unwrap_or(page) != btype {
            return;
        }
        let retired = block.source_map.len() as u32;
        if self.redirect_through_lookup(site, retired, None, kind, btype) {
            self.blocks[index].dynamic_site = None;
        }
    }

    /// Install a lookup thunk for the exit of `kind` at host address `site`
    /// (to `target`, or the target in RAX) by a branch that sets `btype`,
    /// and jump there from the exit.
    pub(super) fn redirect_through_lookup(
        &mut self,
        site: u64,
        retired: u32,
        target: Option<GuestAddress>,
        kind: ExitKind,
        btype: u8,
    ) -> bool {
        let control = self.chain.address();
        let Some(code) = chain::lookup_thunk(control, retired, target, kind, btype) else {
            return false;
        };
        let Ok(thunk) = self.host.install(&code) else {
            return false;
        };
        let Some(jump) = chain::jump(site, thunk.0 as u64) else {
            return false;
        };
        self.patch_native(NativeCode(site as usize), &jump);
        self.statistics.lookups += 1;
        true
    }
}
