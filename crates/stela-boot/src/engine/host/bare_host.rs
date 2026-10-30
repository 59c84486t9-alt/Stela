//! The engine's Host on bare metal: guest RAM, native code, shadow tables, time
//! and waiting.

use super::*;
use stela_contracts::refuse;

/// The engine's handle; mutable native state belongs to this host processor.
pub struct BareHost<'a> {
    pub(super) _owner: core::marker::PhantomData<&'a mut HostOwner>,
    pub(super) _pinned: core::marker::PhantomData<*mut ()>,
}

/// The parts of the code arena, reclaimed oldest first for new code or
/// for memory: a reclaim costs only the oldest thirty-second's blocks, and
/// low memory finds an older part to release while the arena is a part
/// full rather than discarding every block.
pub(super) const CODE_UNITS: u64 = 32;

pub(super) fn code_unit_bytes(state: &State) -> u64 {
    state.code_bytes / CODE_UNITS / 16 * 16
}

impl Host for BareHost<'_> {
    #[cfg(feature = "native-profile")]
    fn native_timing_work_start(
        &mut self,
        work: stela_engine::machine::engine::NativeTimingWork,
    ) -> Option<u64> {
        state().native_profile.work_start(work, profile_timestamp)
    }
    #[cfg(feature = "native-profile")]
    fn native_timing_work_end(
        &mut self,
        work: stela_engine::machine::engine::NativeTimingWork,
        started: u64,
    ) {
        state()
            .native_profile
            .work_end(work, started, profile_timestamp());
    }
    #[cfg(feature = "native-profile")]
    fn native_timing(&mut self, phase: stela_engine::machine::engine::NativeTimingPhase) {
        let profile = &mut state().native_profile;
        if phase == stela_engine::machine::engine::NativeTimingPhase::Begin
            && profile.needs_calibration()
        {
            profile.calibrate(profile_timestamp);
        }
        profile.event(phase, profile_timestamp);
    }
    #[cfg(feature = "native-profile")]
    fn native_instruction_sample(
        &mut self,
        sample: stela_engine::machine::engine::NativeInstructionSample<'_>,
    ) {
        state().native_profile.instructions(sample);
    }
    fn native_worker(&self) -> Option<stela_engine::machine::engine::publication::WorkerId> {
        local::native_worker()
    }

    fn native_cpu_lease(&self) -> Option<stela_engine::NativeCpuLease> {
        local::native_cpu_lease()
    }

    fn read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
        // The engine reads guest RAM only once its translation allowed it.
        super::super::speculation::fence();
        if let Some(ram) = &state().registered_ram {
            // SAFETY: the runtime passes private staging while the adopted
            // canonical reservation/mapping and source controls remain live.
            return unsafe { ram.read_physical(physical, buffer) }.is_ok();
        }
        state().copy(physical, buffer.len(), |host, done, chunk| {
            // SAFETY: guest RAM through the physmap and a distinct buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    host as *const u8,
                    buffer[done..].as_mut_ptr(),
                    chunk,
                )
            };
        })
    }

    fn write_ram(&mut self, physical: u64, data: &[u8]) -> bool {
        if let Some(ram) = &state().registered_ram {
            // SAFETY: private copyout staging; the canonical owner performs
            // every reached host write under the same physical writer gates.
            return unsafe { ram.publish_physical(physical, data) }.is_ok();
        }
        state().copy(physical, data.len(), |host, done, chunk| {
            // SAFETY: guest RAM through the physmap and a distinct buffer.
            unsafe {
                core::ptr::copy_nonoverlapping(data[done..].as_ptr(), host as *mut u8, chunk)
            };
        })
    }

    fn compare_exchange_ram(
        &mut self,
        physical: u64,
        expected: &mut [u8],
        new: &[u8],
    ) -> Option<bool> {
        let ram = state().registered_ram.as_ref()?;
        // SAFETY: the adopted canonical reservation and mapping remain live;
        // every other core's writes reach the same bytes.
        unsafe { ram.compare_exchange_physical(physical, expected, new) }.ok()
    }

    fn check_ram_range(
        &mut self,
        physical: u64,
        bytes: usize,
        write: bool,
    ) -> Result<(), stela_engine::machine::engine::DmaError> {
        let ram = state().registered_ram.as_ref().ok_or(
            stela_engine::machine::engine::DmaError::Unsupported(refuse!(
                "canonical DMA RAM owner is not installed"
            )),
        )?;
        ram.check_dma_range(physical, bytes, write)
            .map_err(|_| stela_engine::machine::engine::DmaError::Memory)
    }
    fn read_ram_progress(
        &mut self,
        physical: u64,
        buffer: &mut [u8],
    ) -> Result<(), stela_engine::machine::engine::TransferFault> {
        super::super::speculation::fence();
        let Some(ram) = &state().registered_ram else {
            return self.read_ram(physical, buffer).then_some(()).ok_or(
                stela_engine::machine::engine::TransferFault {
                    error: stela_engine::machine::engine::DmaError::Memory,
                    completed: 0,
                },
            );
        };
        // SAFETY: private DMA staging, same canonical reader/owner contract.
        unsafe { ram.read_physical_progress(physical, buffer) }.map_err(|fault| {
            stela_engine::machine::engine::TransferFault {
                error: stela_engine::machine::engine::DmaError::Memory,
                completed: fault.completed,
            }
        })
    }
    fn write_ram_progress(
        &mut self,
        physical: u64,
        data: &[u8],
    ) -> Result<(), stela_engine::machine::engine::TransferFault> {
        let Some(ram) = &state().registered_ram else {
            return self.write_ram(physical, data).then_some(()).ok_or(
                stela_engine::machine::engine::TransferFault {
                    error: stela_engine::machine::engine::DmaError::Memory,
                    completed: 0,
                },
            );
        };
        // SAFETY: private staging, every writer participates in this same domain.
        unsafe { ram.publish_physical(physical, data) }.map_err(|fault| {
            stela_engine::machine::engine::TransferFault {
                error: stela_engine::machine::engine::DmaError::Memory,
                completed: fault.completed,
            }
        })
    }
    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        let state = state();
        let offset = state.code_used.next_multiple_of(16);
        let end = offset + code.len() as u64;
        if end > (state.code_unit + 1) * code_unit_bytes(state) {
            return Err(InstallError::Full);
        }
        state.installed_ranges[state.code_unit as usize]
            .try_reserve(1)
            .map_err(|_| InstallError::Full)?;
        if code.is_empty() {
            return Err(InstallError::Full);
        }
        // SAFETY: arena bytes through the writable physmap alias.
        unsafe {
            core::ptr::copy_nonoverlapping(
                code.as_ptr(),
                layout::physical(state.code_physical + offset) as *mut u8,
                code.len(),
            );
        }
        serialize_code();
        state.installed_ranges[state.code_unit as usize].push((offset, end));
        state.code_used = end;
        state.code_peak = state.code_peak.max(end);
        #[cfg(feature = "native-profile")]
        state.native_profile.copied(code.len());
        Ok(NativeCode((state.code_virtual + offset) as usize))
    }

    fn install_immutable(&mut self, code: &Arc<Vec<u8>>) -> Result<NativeCode, InstallError> {
        if let Some(installed) = state().installed_immutable.lookup(code) {
            #[cfg(feature = "native-profile")]
            state().native_profile.installed(true);
            return Ok(installed);
        }
        #[cfg(feature = "native-profile")]
        state().native_profile.installed(false);
        let installed = self.install(code.as_slice())?;
        state().installed_immutable.record(code, installed);
        Ok(installed)
    }

    fn read_native(&mut self, code: NativeCode, bytes: &mut [u8]) -> bool {
        let state = state();
        if state.native || !state.owns_installed(code, bytes.len()) {
            return false;
        }
        let offset = code.0 as u64 - state.code_virtual;
        // SAFETY: successful install metadata proves this exact initialized,
        // unreclaimed extent. The IF0 CPU owner keeps the arena's
        // backing/root and physmap; no native frame/executable borrow is live.
        unsafe {
            core::ptr::copy_nonoverlapping(
                layout::physical(state.code_physical + offset) as *const u8,
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        true
    }

    fn patch(&mut self, code: NativeCode, bytes: &[u8]) {
        let state = state();
        state.installed_immutable.clear();
        assert!(
            state.owns_installed(code, bytes.len()),
            "a patch outside a retained initialized install"
        );
        let offset = code.0 as u64 - state.code_virtual;
        assert!(
            offset + bytes.len() as u64 <= state.code_bytes,
            "a patch outside the code arena"
        );
        // SAFETY: installed arena bytes through the writable physmap alias.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                layout::physical(state.code_physical + offset) as *mut u8,
                bytes.len(),
            );
        }
        serialize_code();
    }

    fn discard_code(&mut self) {
        let state = state();
        state.installed_immutable.clear();
        state.code_unit = 0;
        state.code_used = 0;
        for ranges in &mut state.installed_ranges {
            ranges.clear();
        }
    }

    fn reclaim_code(&mut self) -> Option<core::ops::Range<usize>> {
        let state = state();
        state.installed_immutable.clear();
        let unit = code_unit_bytes(state);
        state.code_unit = (state.code_unit + 1) % CODE_UNITS;
        state.installed_ranges[state.code_unit as usize].clear();
        state.code_used = state.code_unit * unit;
        let start = (state.code_virtual + state.code_used) as usize;
        Some(start..start + unit as usize)
    }

    fn release_oldest_code(&mut self) -> Option<core::ops::Range<usize>> {
        let state = state();
        // The ring fills parts in turn: the first holding code after the
        // one being filled is the oldest.
        let part = (1..CODE_UNITS)
            .map(|step| (state.code_unit + step) % CODE_UNITS)
            .find(|&part| !state.installed_ranges[part as usize].is_empty())?;
        state.installed_immutable.clear();
        state.installed_ranges[part as usize].clear();
        let unit = code_unit_bytes(state);
        let start = (state.code_virtual + part * unit) as usize;
        Some(start..start + unit as usize)
    }

    fn memory_low(&self) -> bool {
        crate::ALLOCATOR.low()
    }

    unsafe fn execute(&mut self, code: NativeCode, guest: &mut GuestState) -> NativeExit {
        assert!(!state().native, "nested native block entry");
        state().native = true;
        let entered = rdtsc();
        // SAFETY: the engine passes installed system-mode block code.
        let exit = unsafe { stela_enter_block(guest, code.0) };
        native_return(code, exit, entered)
    }

    unsafe fn execute_context(
        &mut self,
        code: NativeCode,
        guest: &mut GuestState,
        context: &mut stela_compiler::context::ExecutionContext,
    ) -> Option<NativeExit> {
        assert!(!state().native, "nested native context entry");
        #[cfg(feature = "native-profile")]
        let measured = state().native_profile.work_start(
            stela_engine::machine::engine::NativeTimingWork::NativeCall,
            profile_timestamp,
        );
        state().native = true;
        let entered = rdtsc();
        // SAFETY: caller holds the installed context block, live frame
        // and service owners. The current GS HostOwner keeps recovery state.
        let exit = unsafe { stela_enter_context_block(guest, context, code.0) };
        let returned = native_return(code, exit, entered);
        #[cfg(feature = "native-profile")]
        if let Some(started) = measured {
            state().native_profile.work_end(
                stela_engine::machine::engine::NativeTimingWork::NativeCall,
                started,
                profile_timestamp(),
            );
        }
        Some(returned)
    }

    fn context_entry(&mut self, code: NativeCode) -> Option<usize> {
        // Installed code is callable where it lies, through the executable arena alias.
        Some(code.0)
    }

    fn set_regime(&mut self, regime: &Regime) {
        let state = state();
        if let Some(current) = state.regime
            && current.controls != regime.controls
        {
            let (from, to) = (current.controls, regime.controls);
            // What the lower half's own inputs, E0PD1 and SPRR's
            // permission registers leave of the controls: the lower half has
            // its own reset and the others their bank, and they compose (a
            // context switch writes TTBR0 and the thread's SPRR_PERM_EL0
            // together).
            let (lower_tcr, user_tcr) = match to.regime {
                mmu::Regime::El10 | mmu::Regime::El20 => (LOWER_TCR, USER_TCR),
                _ => (0, 0),
            };
            let own = lower_tcr | user_tcr;
            let rest = mmu::Controls {
                ttbr0: to.ttbr0,
                tcr: from.tcr & !own | to.tcr & own,
                // The fields that keep an index writable after the locks
                // change no access.
                sprr: mmu::Sprr {
                    el0: to.sprr.el0,
                    el1: to.sprr.el1,
                    fields: to.sprr.fields,
                    ..from.sprr
                },
                ..from
            };
            let lower = from.ttbr0 != to.ttbr0 || (from.tcr ^ to.tcr) & lower_tcr != 0;
            // TTBR0 translates only the lower half, but it can name the
            // ASID the upper half's non-global entries were made in.
            let asid = mmu::current_asid(&from) == mmu::current_asid(&to);
            if rest == to && (!lower || asid || !state.extents[UPPER].private()) {
                if lower {
                    let key = |c: &mmu::Controls| (c.ttbr0, c.tcr & lower_tcr);
                    state.switch_lower(key(&from), key(&to));
                }
                let rights = |c: &mmu::Controls| (c.sprr.el0, c.sprr.el1, c.tcr & user_tcr);
                let (from, to) = (rights(&from), rights(&to));
                if from != to {
                    state.switch_bank(from, to);
                }
            } else {
                let ttbr0 = mmu::Controls {
                    ttbr0: to.ttbr0,
                    ..from
                };
                let sprr = mmu::Controls {
                    sprr: to.sprr,
                    ..from
                };
                let cause = if sprr == to {
                    Cause::Sprr
                } else if ttbr0 == to {
                    Cause::Table
                } else {
                    Cause::Controls
                };
                if matches!(cause, Cause::Controls) && state.legacy_translations_dirty {
                    let fields = differing(&from, &to);
                    for (count, differs) in state.control_fields.iter_mut().zip(fields) {
                        *count += u64::from(differs);
                    }
                    state.last_controls = Some((from, to));
                }
                state.reset_shadow(cause);
            }
        }
        // The tag-checked roots hold one pattern of checked halves.
        if regime.tag_checked() && regime.tag_checks != state.tag_checks {
            if state.tag_checks.contains(&true) {
                state.reset_shadow(Cause::Tags);
            }
            state.tag_checks = regime.tag_checks;
        }
        state.regime = Some(*regime);
        // EL0, EL1, EL1 with PAN, and the GXF guarded level (GL1).
        let view = match (
            regime.requester.el,
            regime.requester.pan,
            regime.requester.guarded,
        ) {
            (0, _, _) => EL0_VIEW,
            (_, _, true) => GUARDED_VIEW,
            (_, false, false) => EL1_VIEW,
            (_, true, false) => PAN_VIEW,
        } + if regime.tag_checked() { VIEWS } else { 0 };
        if state.current != view {
            state.current = view;
            state.view_switches += 1;
            load_root(state.roots[view]);
        }
    }

    fn isolate_predictions(&mut self) {
        super::super::speculation::isolate();
    }

    fn speculation_barrier(&self) {
        super::super::speculation::fence();
    }

    fn invalidate_translations(&mut self) {
        state().reset_shadow(Cause::Invalidated);
    }

    fn invalidate_reach(&mut self, reach: Reach, everywhere: Everywhere) {
        let state = state();
        if !state.kept.is_empty() {
            let bounds = state.half_range(LOWER);
            let entry_bits = 12 + 9 * layout::top_level();
            let pool = &state.pool;
            let dropped =
                state
                    .kept
                    .invalidate(everywhere, bounds, entry_bits, |entry, first, last| {
                        tables::unmap_under(pool, entry, first, last)
                    });
            state.kept_dropped += dropped as u64;
        }
        if reach == Reach::All {
            return state.reset_shadow(Cause::Maintained);
        }
        state.tlb.clear();
        let mut unmapped = Vec::new();
        let mut whole = false;
        for half in [LOWER, UPPER] {
            match state.extents[half].ranges(reach, state.half_range(half)) {
                None => {
                    state.clear(half);
                    whole = true;
                }
                Some(ranges) => unmapped.extend(ranges),
            }
        }
        let mut pages = 0u64;
        for &(first, last) in &unmapped {
            for root in state.all_roots() {
                tables::unmap(&state.pool, root, first, last);
            }
            pages = pages.saturating_add(((last - first) >> 12) + 1);
        }
        if whole || pages > INVLPG_PAGES {
            state.reload();
        } else {
            for &(first, last) in &unmapped {
                let mut page = first & !(PAGE - 1);
                loop {
                    invlpg(page);
                    if page >= last & !(PAGE - 1) {
                        break;
                    }
                    page += PAGE;
                }
            }
        }
        if whole {
            state.resets += 1;
        } else {
            state.scoped += 1;
        }
    }

    fn profile_ticks(&mut self) -> u64 {
        rdtsc()
    }

    fn counter(&mut self) -> u64 {
        fresh_counter()
    }

    fn tsc_counter(&self) -> Option<(u64, u64)> {
        let state = state();
        Some((state.tsc_base, state.counter_per_tsc))
    }

    fn arm_timer(&mut self, deadline: Option<u64>) {
        let now = self.counter();
        let state = state();
        let Some(deadline) = deadline else {
            if !crate::native_clock::arm_guest(None) {
                state.apic.write(apic::INITIAL, 0);
            }
            return;
        };
        let guest = deadline.saturating_sub(now).max(1);
        let ticks = u128::from(guest) * u128::from(state.apic_hz) / u128::from(COUNTER_HZ);
        let ticks = ticks.clamp(1, u128::from(u32::MAX)) as u32;
        if !crate::native_clock::arm_guest(Some(ticks)) {
            state.apic.write(apic::LVT_TIMER, u32::from(TIMER_VECTOR));
            state.apic.write(apic::INITIAL, ticks);
        }
    }

    fn wait_for_interrupt(&mut self) {
        crate::native_mmio::shootdown::service();
        local::clear_interrupt();
        // The wait sends queued serial output until an interrupt comes,
        // opening a window for one after each burst.
        while crate::output::send_queued() {
            // SAFETY: STI holds interrupts off for one more instruction, so
            // only the NOP's boundary takes a pending one.
            unsafe { asm!("sti", "nop", "cli", options(nomem, nostack)) };
            if local::interrupted() {
                return;
            }
        }
        // SAFETY: STI's interrupt shadow covers HLT, so no wake-up is lost.
        unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
    }

    fn report(&mut self, event: &stela_engine::machine::Event) {
        super::super::report(event);
    }

    fn placement(&self) -> Placement {
        state().placement
    }

    fn translation_helper(&self) -> Option<u64> {
        state().bounce.as_ref().map(|_| translated::slot())
    }

    fn translations(&mut self) -> Option<&mut dyn stela_engine::machine::Translations> {
        super::super::translations::store()
            .map(|store| store as &mut dyn stela_engine::machine::Translations)
    }
}
