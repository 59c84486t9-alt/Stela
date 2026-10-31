//! The run loop: slices, host service between them, and the heartbeat that
//! reports the running PEs.

use super::*;

/// Exit kinds by `ExitKind` value, then native faults by cause
/// (`step_timing::fault_slot`), as the PROFILE line names them.
pub(super) const EXIT_NAMES: [&str; step_timing::EXIT_SLOTS] = [
    "fallthrough",
    "direct",
    "indirect",
    "call",
    "return",
    "trap",
    "pointer-auth",
    "clock",
    "thread-register",
    "floating-point",
    "scalable",
    "system",
    "amx",
    "fault-guest",
    "fault-device",
    "fault-check",
    "fault-watched",
    "fault-translation",
];

/// `--profile`'s heartbeat lines: of `elapsed` ticks, the share inside the
/// engine (`sliced`) and in each of its phases, the rest of the engine's
/// time unattributed, and each exit kind's count, share and mean cost.
pub(super) fn profile_report(
    timing: &step_timing::StepTiming,
    sliced: u64,
    elapsed: u64,
    tsc_hz: u64,
) {
    let share = |ticks: u64| {
        let permille = u128::from(ticks) * 1000 / u128::from(elapsed.max(1));
        format!("{}.{}%", permille / 10, permille % 10)
    };
    let mut line = format!(
        "PROFILE seconds={} engine={} host_service={}",
        elapsed / tsc_hz.max(1),
        share(sliced),
        share(elapsed.saturating_sub(sliced)),
    );
    let mut attributed = 0u64;
    for phase in step_timing::Phase::ALL {
        let ticks = timing.phases[phase as usize];
        attributed = attributed.saturating_add(ticks);
        line.push_str(&format!(" {}={}", phase.name(), share(ticks)));
    }
    line.push_str(&format!(
        " unattributed={}\n",
        share(sliced.saturating_sub(attributed))
    ));
    output::arguments(format_args!("{line}"));
    let mut exits: Vec<(usize, (u64, u64))> = timing
        .exits
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, (count, _))| *count > 0)
        .collect();
    exits.sort_by_key(|exit| core::cmp::Reverse(exit.1.1));
    let mut line = String::from("PROFILE exits");
    for (slot, (count, ticks)) in exits {
        let mean_ns =
            u128::from(ticks) * 1_000_000_000 / u128::from(count) / u128::from(tsc_hz.max(1));
        line.push_str(&format!(
            " {}={}x/{}/{}ns",
            EXIT_NAMES[slot],
            count,
            share(ticks),
            mean_ns
        ));
    }
    output::arguments(format_args!("{line}\n"));
}

/// Completed intervals of this owned home machine only. Other PEs' state
/// is not inspected; an unfinished phase has no completed maximum yet.
pub(super) fn profile_lifetime_maxima(timing: &step_timing::StepTiming, tsc_hz: u64, report: &str) {
    for phase in step_timing::Phase::ALL {
        let maximum = timing.lifetime_maxima[phase as usize];
        if maximum.ticks == 0 {
            continue;
        }
        output::arguments(format_args!(
            "PROFILE MAX observer=home report={report} phase={} scope=lifetime counter_hz={tsc_hz} ticks={} finished_ticks={} pc_after={:#x} el_after={} daif_after={:#x} snapshot=materialized-after completed-only=true precise_pc=false cost_bound=false\n",
            phase.name(),
            maximum.ticks,
            maximum.finished_ticks,
            maximum.pc_after,
            maximum.el_after,
            maximum.daif_after,
        ));
    }
}

pub(super) fn level_name(guarded: bool) -> &'static str {
    if guarded { "GL" } else { "EL" }
}

/// Blocks between checks of whether the screen or a heartbeat is due.
pub(super) const SLICE: u64 = 1 << 18;

/// How often the waits of every PE return to the run loop to take host
/// inputs, at least (`Machine::set_wait_limit`).
pub(super) const WAIT_POLLS_PER_SECOND: u64 = 20;

/// Seconds between heartbeats, which locate a guest that runs without output.
pub(super) const BEAT_SECONDS: u64 = 10;

/// Run up to `budget` blocks (0: no limit), showing what macOS prints last
/// as the running step's detail, reporting the PE's position
/// every [`BEAT_SECONDS`]. The caller supplies
/// its admitted execution path; reporting and host polling never select a
/// different memory or native-entry path.
pub(super) fn run<H: Host>(
    machine: &mut Machine<H, parallel::Board>,
    budget: u64,
    tsc_hz: u64,
    boot_progress: &mut progress::BootProgress,
    mut execute: impl FnMut(&mut Machine<H, parallel::Board>, u64) -> Stop,
) -> Stop {
    let mut heartbeat = Heartbeat::new(machine, host::rdtsc());
    let mut service = ServiceTimes::new(heartbeat.beat.at);
    boot_progress.start(heartbeat.beat.at, machine.statistics.blocks);
    loop {
        let slice = machine.statistics.blocks + SLICE;
        let limit = if budget == 0 {
            slice
        } else {
            budget.min(slice)
        };
        let slice_started = host::rdtsc();
        service.slice_start(slice_started);
        machine.observe_parallel_source(parallel::SourcePhase::SliceEnter);
        let stop = execute(machine, limit);
        machine.observe_parallel_source(parallel::SourcePhase::SliceExit);
        let service_now = host::rdtsc();
        service.slice_end(service_now);
        heartbeat.sliced_ticks += service_now.wrapping_sub(slice_started);
        // One hold of the devices' lock, which every PE's device accesses
        // take, for everything they left for the reports.
        let drained = machine.devices.with(Drained::take);
        report_drained(machine, drained, boot_progress, service_now, tsc_hz);
        service.parts.lap(ServiceParts::REPORTS, host::rdtsc());
        // A wait the limit or the host's inputs ended goes on like a slice.
        let waiting = matches!(stop, Stop::Waiting);
        // The boot PE holds no lock another PE spins on while it waits for
        // an interrupt or runs at EL0 (`service`).
        let quiet = machine.yielded_for_interrupt(&stop) || machine.cpu.pstate.el == 0;
        let requested = machine.devices.hub().service_unclaimed();
        if !machine.runs_parallel() || quiet || service::starved(tsc_hz, requested) {
            machine.exclude_host_time(|_| service::serve(true));
        }
        machine.exclude_host_time(|_| super::gpu::pump());
        if service::shutdown_pending() {
            machine.exclude_host_time(|_| service::serve(true));
        }
        service.parts.lap(ServiceParts::SERVICE, host::rdtsc());

        // A wall-time service yield may precede even the final block limit.
        // Only the executed count can establish budget completion.
        let budget_reached = budget != 0 && machine.statistics.blocks >= budget;
        let sliced = waiting || matches!(stop, Stop::Budget) && !budget_reached;
        let now = host::rdtsc();
        if !sliced {
            service.report(tsc_hz);
            output::report_log_stores();
            return stop;
        }
        heartbeat.sample(machine, now, tsc_hz);
        // The heartbeat's reports wait for a quiet boot PE, as the service
        // does, for one more interval at most.
        let due = now - heartbeat.beat.at;
        if due >= BEAT_SECONDS * tsc_hz && (quiet || due >= 2 * BEAT_SECONDS * tsc_hz) {
            heartbeat.beat(machine, &mut service, now, tsc_hz);
        }
    }
}

/// Report what the PEs' device accesses left since the last slice: the
/// guest's console and the installer's step, the boot's progress, and the
/// unmodeled requests and device logs.
pub(super) fn report_drained<H: Host>(
    machine: &mut Machine<H, parallel::Board>,
    drained: Drained,
    boot_progress: &mut progress::BootProgress,
    now: u64,
    tsc_hz: u64,
) {
    let lines = drained.lines;
    if let Some(step) = lines.iter().rev().find_map(|line| installer_step(line)) {
        crate::status::progress(&step);
        boot_progress.installer(step);
    }
    if boot_progress.due(now, tsc_hz) {
        let physical = observed_instruction(machine);
        if let Some(update) = boot_progress.sample(physical, now, tsc_hz, machine.statistics.blocks)
        {
            if let Some(component) = update.first_component {
                output::arguments(format_args!(
                    "BOOT PROGRESS observed={} blocks={}\n",
                    component.name(),
                    machine.statistics.blocks,
                ));
            }
            crate::status::progress(&update.detail);
        }
    }
    crate::status::stream(lines.iter().map(String::as_str));
    crate::status::tick();
    unmodeled_report(machine, drained.unmodeled);
    for line in drained.sep {
        output::arguments(format_args!("SEP OBSERVE {line}\n"));
    }
    parallel::report_diagnostics(machine);
    for log in drained.usb {
        use stela_soc::machine::UsbLog;
        match log {
            UsbLog::Descriptor(descriptor) => output::arguments(format_args!(
                "USB descriptor type={} index={} lang={:#x} bytes={:02x?}\n",
                descriptor.kind, descriptor.index, descriptor.language, descriptor.bytes
            )),
            UsbLog::MuxControl(bytes) => {
                output::arguments(format_args!("USB mux control bytes={:02x?}\n", bytes))
            }
            UsbLog::MuxRejected(bytes) => {
                output::arguments(format_args!("USB mux rejected bytes={:02x?}\n", bytes))
            }
            UsbLog::QueryTypeReply(bytes) => output::arguments(format_args!(
                "USB QueryType reply bytes={:02x?} text={}\n",
                bytes,
                String::from_utf8_lossy(&bytes)
            )),
        }
    }
    for (port, line) in drained.usb_transfers {
        output::arguments(format_args!("USB transfer port={port} {line}\n"));
    }
    for (port, line) in drained.usb_host {
        output::arguments(format_args!("XHCI port={port} {line}\n"));
    }

    for log in drained.smc {
        output::arguments(format_args!(
            "SMC key-write op={:#x} id={} flags={:#x} key={:#010x} command={:x?} request={:#018x} reply={:x?} dropped={}\n",
            log.request as u8,
            (log.request >> 12) & 0xf,
            (log.request >> 8) & 0xf,
            (log.request >> 32) as u32,
            log.system_event,
            log.request,
            log.reply,
            log.dropped_before
        ));
    }

    for entry in drained.display {
        display::print_log(&entry);
    }

    for log in drained.power {
        use stela_soc::machine::PowerLog;
        match log {
            PowerLog::Sleep => output::arguments(format_args!(
                "POWER SoC sleep: every PE is down after slpa\n"
            )),
            PowerLog::Wake(source) => output::arguments(format_args!("POWER SoC wake: {source}\n")),
            PowerLog::Masked(source) => output::arguments(format_args!(
                "POWER SoC wake by the {source} masked by the AP; still asleep\n"
            )),
        }
    }
}

/// The host service between slices: how many boundaries, the longest gap
/// between two slices and the longest service, by part, since the last beat.
pub(super) struct ServiceTimes {
    /// When the last slice ended.
    pub(super) serviced: u64,
    pub(super) boundaries: u64,
    pub(super) gap: u64,
    /// With every PE on a core of its own, the boot PE's guest time passes
    /// meanwhile.
    pub(super) longest: u64,
    pub(super) parts: ServiceParts,
}

impl ServiceTimes {
    pub(super) fn new(now: u64) -> Self {
        Self {
            serviced: now,
            boundaries: 0,
            gap: 0,
            longest: 0,
            parts: ServiceParts::new(now),
        }
    }

    /// A slice starts at `now`, ending the service since the last one.
    pub(super) fn slice_start(&mut self, now: u64) {
        self.longest = self.longest.max(now.wrapping_sub(self.serviced));
        self.parts.lap(ServiceParts::BEAT, now);
    }

    /// The slice ended at `now`, starting the next service.
    pub(super) fn slice_end(&mut self, now: u64) {
        self.parts.start(now);
        self.gap = self.gap.max(now.wrapping_sub(self.serviced));
        self.serviced = now;
        self.boundaries = self.boundaries.saturating_add(1);
    }

    pub(super) fn report(&self, tsc_hz: u64) {
        output::arguments(format_args!(
            "HOST SERVICE boundaries={} maximum_gap_us={} maximum_service_us={} {} {}\n",
            self.boundaries,
            u128::from(self.gap) * 1_000_000 / u128::from(tsc_hz),
            u128::from(self.longest) * 1_000_000 / u128::from(tsc_hz),
            self.parts.report(tsc_hz),
            service::report(tsc_hz),
        ));
    }

    /// Start the next beat's maxima.
    pub(super) fn restart(&mut self) {
        self.gap = 0;
        self.longest = 0;
        self.parts.longest = [0; ServiceParts::PARTS];
    }
}

/// The counts a heartbeat reports the change in, as of the last beat.
#[derive(Clone, Copy)]
pub(super) struct Beat {
    /// The TSC at the beat.
    pub(super) at: u64,
    /// TSC ticks spent in compiled code.
    pub(super) native: u64,
    pub(super) blocks: u64,
    pub(super) compiled: u64,
    pub(super) chained: u64,
    /// Exceptions, interrupts and waits.
    pub(super) events: (u64, u64, u64),
}

impl Beat {
    pub(super) fn at<H: Host>(machine: &Machine<H, parallel::Board>, at: u64) -> Self {
        let statistics = &machine.statistics;
        Self {
            at,
            native: host::native_ticks(),
            blocks: statistics.blocks,
            compiled: statistics.compiled,
            chained: statistics.chained,
            events: (
                statistics.exceptions,
                statistics.interrupts,
                statistics.waits,
            ),
        }
    }
}

/// What the heartbeat compares against and samples between beats.
pub(super) struct Heartbeat {
    pub(super) beat: Beat,
    /// Guest instructions retired by the last beat.
    pub(super) retired: u128,
    /// Each PE's counts at the last beat.
    pub(super) pe_counts: Vec<parallel::Counts>,
    /// Lock waits at the last beat: the devices', by call, and the heap's.
    pub(super) lock_waits: ([u64; Call::ALL.len()], u64),
    /// Counter ticks spent compiling, the guest instructions compiled and
    /// the blocks taken from the translation store, at the last beat.
    pub(super) translation: (u64, u64, u64),
    /// At most one call-chain sample per second, bounded by the heartbeat
    /// interval. Host-service yields can be much more frequent than sampling.
    pub(super) samples: Vec<[u64; CHAIN]>,
    pub(super) sampled: u64,
    /// The running PE's PC at service boundaries, at most once a millisecond.
    pub(super) hot: BTreeMap<u64, HotPc>,
    pub(super) hot_sampled: u64,
    /// Samples taken at EL0.
    pub(super) user: u32,
    pub(super) beats: u64,
    pub(super) exits: ExitsSeen,
    pub(super) translated: TranslatedSeen,
    pub(super) shadows: ShadowSeen,
    pub(super) occupancy: Option<stela_engine::machine::engine::Occupancy>,
    /// Ticks inside `execute` since the last beat, and the step timing then.
    pub(super) sliced_ticks: u64,
    pub(super) timing: Option<step_timing::StepTiming>,
}

impl Heartbeat {
    pub(super) fn new<H: Host>(machine: &Machine<H, parallel::Board>, now: u64) -> Self {
        Self {
            beat: Beat::at(machine, now),
            retired: machine.retired_instructions(),
            pe_counts: parallel::counts(machine),
            lock_waits: ([0; Call::ALL.len()], 0),
            translation: (
                machine.statistics.compile_ticks,
                machine.statistics.compiled_instructions,
                machine.statistics.stored,
            ),
            samples: Vec::with_capacity(BEAT_SECONDS as usize),
            sampled: now,
            hot: BTreeMap::new(),
            hot_sampled: now,
            user: 0,
            beats: 0,
            exits: ExitsSeen::default(),
            translated: TranslatedSeen::default(),
            shadows: ShadowSeen::default(),
            occupancy: None,
            sliced_ticks: 0,
            timing: machine.step_timing().copied(),
        }
    }

    /// Sample the running PE's PC and, once a second, its call chain.
    pub(super) fn sample<H: Host>(
        &mut self,
        machine: &mut Machine<H, parallel::Board>,
        now: u64,
        tsc_hz: u64,
    ) {
        if now.wrapping_sub(self.hot_sampled) >= tsc_hz / 1000 {
            let pc = machine.cpu.pc;
            self.hot
                .entry(pc)
                .or_insert_with(|| {
                    let mut code = [0; HOT_CODE_BYTES];
                    if !machine.read_virtual(pc.wrapping_sub(HOT_CODE_BEFORE), &mut code) {
                        code.fill(0);
                    }
                    HotPc { count: 0, code }
                })
                .count += 1;
            self.hot_sampled = now;
        }
        if now.wrapping_sub(self.sampled) >= tsc_hz && self.samples.len() < BEAT_SECONDS as usize {
            let (pc, frame) = (machine.cpu.pc, machine.cpu.state.x[29]);
            self.samples.push(call_chain(machine, pc, frame));
            self.user += u32::from(machine.cpu.pstate.el == 0);
            self.sampled = now;
        }
    }

    /// Report the interval since the last beat, which ends `now`.
    pub(super) fn beat<H: Host>(
        &mut self,
        machine: &mut Machine<H, parallel::Board>,
        service: &mut ServiceTimes,
        now: u64,
        tsc_hz: u64,
    ) {
        let mut cost = BeatCost::new(now);
        let next = Beat::at(machine, now);
        let elapsed = now - self.beat.at;
        beat_report(machine, &self.beat, &next, elapsed);
        service.report(tsc_hz);
        self.report_processors(machine, &next, elapsed, tsc_hz);
        if let (Some(now), Some(then)) = (machine.step_timing().copied(), self.timing) {
            profile_report(&now.since(&then), self.sliced_ticks, elapsed, tsc_hz);
            self.timing = Some(now);
        }
        self.sliced_ticks = 0;
        #[cfg(feature = "native-profile")]
        native_profile_report(machine);
        service.restart();
        let compiled = next.compiled - self.beat.compiled;
        self.beat = next;
        cost.mark("performance");
        self.translation = translation_report(machine, self.translation, compiled);
        cost.mark("translation");
        self.exits.report(machine, tsc_hz);
        self.translated.report(machine);
        self.shadows.report();
        cost.mark("exits");
        peers_report(machine);
        cost.mark("peers");
        let stale = machine.stale_code();
        if stale.stale > 0 {
            output::arguments(format_args!("STALE {stale:?}\n"));
        }
        cost.mark("stale");
        sample_report(&mut self.samples, self.user);
        hot_report(&mut self.hot);
        timer_report(machine);
        cost.mark("samples");
        for state in machine
            .devices
            .with(|devices| devices.coprocessor_diagnostics())
        {
            output::arguments(format_args!("ASC {state}\n"));
        }
        let (now, _) = machine.timer_snapshot();
        for state in machine
            .devices
            .with(|devices| devices.storage_diagnostics(now))
        {
            output::arguments(format_args!("ANS {state}\n"));
        }
        for state in machine.devices.with(|devices| devices.usb_diagnostics()) {
            output::arguments(format_args!("USB {state}\n"));
        }
        cost.mark("devices");
        survey_report(machine);
        occupancy_report(machine, &mut self.occupancy);
        cost.mark("occupancy");
        self.user = 0;
        self.beats += 1;
        if self.beats.is_multiple_of(SUSPENSION_BEATS) {
            suspension_report(machine);
            cost.mark("suspension");
        }
        cost.report(tsc_hz);
    }

    /// The guest instructions retired in the interval and, with each PE on
    /// a host core of its own, each PE's rate and time and the lock waits.
    pub(super) fn report_processors<H: Host>(
        &mut self,
        machine: &mut Machine<H, parallel::Board>,
        next: &Beat,
        elapsed: u64,
        tsc_hz: u64,
    ) {
        // Each PE on its own host core counts for itself.
        parallel::report_source_observations(machine);
        if machine.runs_parallel() {
            let clock = machine.devices.hub().clock(host::fresh_counter);
            match clock.holder {
                Some((pe, horizon)) => output::arguments(format_args!(
                    "CLOCK count={:#x} held_by={pe} horizon={horizon:#x}\n",
                    clock.count
                )),
                None => output::arguments(format_args!(
                    "CLOCK count={:#x} held_by=none\n",
                    clock.count
                )),
            }
        }
        let per_pe = parallel::counts(machine);
        let retired = per_pe
            .iter()
            .map(|counts| u128::from(counts.retired))
            .sum::<u128>();
        let instructions = retired.saturating_sub(self.retired);
        if per_pe.len() > 1 {
            let interval_ticks =
                u128::from(elapsed.max(1)) * u128::from(host::COUNTER_HZ) / u128::from(tsc_hz);
            let percent = |ticks: u64| u128::from(ticks) * 100 / interval_ticks.max(1);
            let mut rates = String::from("PES RETIRED millions_per_second");
            // Per PE: idle, monitor-polling and synchronizing shares of
            // the interval, its waits, and the blocks it compiled and
            // installed from another PE.
            let mut shares = String::from("PES TIME idle%/spin%/sync%/waits/compiled/shared");
            // Per PE: the interval's share compiling, reading and hashing
            // fetch pages, finding shared blocks and installing blocks.
            let mut fetches = String::from("PES FETCH compile%/page%/shared%/install%");
            // Per PE: device transfers whose deadline came and device line
            // queries, each as a count and, with `--profile`, a share of the
            // interval.
            let mut device_work = String::from("PES DEVICES transfers/transfer%/queries/query%");
            // Per PE with `--profile`: the interval's share in each engine
            // phase, in step timing's order.
            let mut phases = String::from("PES PHASES");
            for phase in step_timing::Phase::ALL {
                phases.push_str(if phase == step_timing::Phase::Schedule {
                    " "
                } else {
                    "/"
                });
                phases.push_str(phase.name());
                phases.push('%');
            }
            let tsc_percent = |ticks: u64| u128::from(ticks) * 100 / u128::from(elapsed.max(1));
            let mut totals = parallel::Counts::default();
            for (pe, (now, before)) in per_pe.iter().zip(&mut self.pe_counts).enumerate() {
                let rate = u128::from(now.retired.saturating_sub(before.retired))
                    .saturating_mul(u128::from(tsc_hz))
                    / u128::from(elapsed.max(1))
                    / 1_000_000;
                rates.push_str(&format!(" {pe}:{rate}"));
                shares.push_str(&format!(
                    " {pe}:{}/{}/{}/{}/{}/{}",
                    percent(now.sleep_ticks.saturating_sub(before.sleep_ticks)),
                    percent(now.spin_ticks.saturating_sub(before.spin_ticks)),
                    percent(now.sync_ticks.saturating_sub(before.sync_ticks)),
                    now.waits.saturating_sub(before.waits),
                    now.compiled.saturating_sub(before.compiled),
                    now.shared.saturating_sub(before.shared),
                ));
                fetches.push_str(&format!(
                    " {pe}:{}/{}/{}/{}",
                    percent(now.compile_ticks.saturating_sub(before.compile_ticks)),
                    percent(now.page_ticks.saturating_sub(before.page_ticks)),
                    percent(now.shared_ticks.saturating_sub(before.shared_ticks)),
                    percent(now.install_ticks.saturating_sub(before.install_ticks)),
                ));
                device_work.push_str(&format!(
                    " {pe}:{}/{}/{}/{}",
                    now.due_transfers.saturating_sub(before.due_transfers),
                    tsc_percent(now.transfer_ticks.saturating_sub(before.transfer_ticks)),
                    now.line_queries.saturating_sub(before.line_queries),
                    tsc_percent(now.line_ticks.saturating_sub(before.line_ticks)),
                ));
                phases.push_str(&format!(" {pe}:"));
                for (slot, (now, before)) in now.phases.iter().zip(before.phases).enumerate() {
                    if slot > 0 {
                        phases.push('/');
                    }
                    phases.push_str(&format!("{}", tsc_percent(now.saturating_sub(before))));
                }
                totals.broadcasts += now.broadcasts.saturating_sub(before.broadcasts);
                totals.forwards += now.forwards.saturating_sub(before.forwards);
                *before = *now;
            }
            // Lock waits since the last beat: the devices', by call, and
            // the heap's.
            let waits = (machine.devices.waits(), crate::ALLOCATOR.waits());
            let mut devices = String::new();
            for (call, (now, before)) in
                Call::ALL.iter().zip(waits.0.iter().zip(&self.lock_waits.0))
            {
                devices.push_str(&format!(" {}={}", call.name(), now - before));
            }
            output::arguments(format_args!(
                "{rates} broadcasts={} forwards={} device_waits{devices} heap_waits={}\n",
                totals.broadcasts,
                totals.forwards,
                waits.1 - self.lock_waits.1
            ));
            self.lock_waits = waits;
            output::arguments(format_args!("{shares}\n"));
            output::arguments(format_args!("{fetches}\n"));
            output::arguments(format_args!("{device_work}\n"));
            if machine.step_timing().is_some() {
                output::arguments(format_args!("{phases}\n"));
            }
        }
        output::arguments(format_args!(
            "GUEST PERFORMANCE retired={retired} interval_retired={instructions} instructions_per_second={} instructions_per_block_milli={}\n",
            instructions.saturating_mul(u128::from(tsc_hz)) / u128::from(elapsed.max(1)),
            instructions.saturating_mul(1000) / u128::from((next.blocks - self.beat.blocks).max(1)),
        ));
        self.retired = retired;
    }
}

/// `HEAP small=310M large=62M 128K:352/73M cores=300M/20M classes=16:8M,…`:
/// the heap's live bytes in size-class blocks and free-list allocations,
/// the latter by power of two where a size holds a megabyte or more, each
/// tagged core's share, and the tagged cores' bytes by size class.
fn heap_report(heap: &stela_boot_core::heap::Usage) {
    let large: usize = heap.large.iter().map(|&(_, bytes)| bytes).sum();
    let mut line = format!(
        "HEAP small={}M large={}M",
        heap.live.saturating_sub(large) >> 20,
        large >> 20
    );
    for (bucket, &(count, bytes)) in heap.large.iter().enumerate() {
        if bytes >= 1 << 20 {
            let size = 4096usize << bucket;
            let size = if size >= 1 << 20 {
                format!("{}M", size >> 20)
            } else {
                format!("{}K", size >> 10)
            };
            line.push_str(&format!(" {size}:{count}/{}M", bytes >> 20));
        }
    }
    let cores: Vec<String> = crate::ALLOCATOR
        .owned()
        .map(|own| format!("{}M", own >> 20))
        .collect();
    line.push_str(&format!(" cores={}", cores.join("/")));
    let classes: Vec<String> = crate::ALLOCATOR
        .class_live()
        .iter()
        .enumerate()
        .map(|(class, &bytes)| format!("{}:{}M", 16 << class, bytes >> 20))
        .collect();
    line.push_str(&format!(" classes={}", classes.join(",")));
    output::arguments(format_args!("{line}\n"));
}

/// `(maintenance=9,memory=2)`: the causes of the discards so far, or
/// nothing before the first.
fn discard_causes(counts: &[u64]) -> String {
    let causes: Vec<String> = stela_engine::machine::engine::Discard::ALL
        .iter()
        .zip(counts)
        .filter(|&(_, &count)| count != 0)
        .map(|(cause, count)| format!("{}={count}", cause.name()))
        .collect();
    if causes.is_empty() {
        String::new()
    } else {
        format!("({})", causes.join(","))
    }
}

/// The heartbeat's position and engine lines: the boot PE's place, the
/// ticks per block and compiled share, compilation, discards, chaining and
/// events over the interval, the heap and the shadow and code pools.
pub(super) fn beat_report<H: Host>(
    machine: &Machine<H, parallel::Board>,
    last: &Beat,
    next: &Beat,
    elapsed: u64,
) {
    let cpu = &machine.cpu;
    let blocks = (next.blocks - last.blocks).max(1);
    let heap = crate::ALLOCATOR.usage();
    let shadow = host::statistics();
    output::arguments(format_args!(
        "BEAT blocks={} pc={:#x} {}{} lr={:#x} ticks/block={} native={}% \
         compiled={} discards={}{} evictions={} chained={}% exceptions={} interrupts={} \
         waits={} \
         heap={}M/{}M carved={}M peak={}M largest={}M extents={} carves={} \
         shadow_peak={}M/{}M/{}M exhausted={} code_peak={}M/{}M\n",
        next.blocks,
        cpu.pc,
        level_name(cpu.pstate.guarded),
        cpu.pstate.el,
        cpu.state.x[30],
        elapsed / blocks,
        (next.native - last.native) * 100 / elapsed.max(1),
        next.compiled - last.compiled,
        machine.statistics.code_discards.iter().sum::<u64>(),
        discard_causes(&machine.statistics.code_discards),
        machine.statistics.code_evictions,
        (next.chained - last.chained) * 100 / blocks,
        next.events.0 - last.events.0,
        next.events.1 - last.events.1,
        next.events.2 - last.events.2,
        heap.live >> 20,
        heap.total >> 20,
        heap.carved >> 20,
        heap.peak >> 20,
        heap.largest >> 20,
        heap.extents,
        heap.carves,
        shadow.shadow_peak[0] >> 20,
        shadow.shadow_peak[1] >> 20,
        shadow.shadow_bytes >> 20,
        shadow.exhausted,
        shadow.code_peak >> 20,
        shadow.code_bytes >> 20,
    ));
    heap_report(&heap);
    output::arguments(format_args!(
        "REGISTERS pe={} pc={:#x} x19={:#x} x20={:#x} x21={:#x} x22={:#x} x23={:#x} lr={:#x}\n",
        machine.processor(),
        cpu.pc,
        cpu.state.x[19],
        cpu.state.x[20],
        cpu.state.x[21],
        cpu.state.x[22],
        cpu.state.x[23],
        cpu.state.x[30],
    ));
}

/// `native-profile`'s heartbeat lines: the BSP's reference ticks, the word
/// and work profiles, the board's and the home PE's native statistics.
#[cfg(feature = "native-profile")]
pub(super) fn native_profile_report<H: Host>(machine: &mut Machine<H, parallel::Board>) {
    output::arguments(format_args!(
        "NATIVE PROFILE bsp_reference_ticks {:?}\n",
        host::profile_snapshot()
    ));
    host::profile_word_report();
    host::profile_work_report();
    output::arguments(format_args!(
        "NATIVE BOARD {:?}\n",
        machine.devices.with(|devices| devices.advance_statistics())
    ));
    let pe = machine.processor();
    output::arguments(format_args!(
        "NATIVE DATA TLB pe={pe} {:?}\n",
        machine.native_data_tlb_statistics()
    ));
    output::arguments(format_args!(
        "NATIVE EPOCH pe={pe} {:?}\n",
        machine.native_epoch_statistics()
    ));
    output::arguments(format_args!(
        "NATIVE SOURCE pe={pe} {:?}\n",
        machine.native_source_statistics()
    ));
}

/// Observe the current instruction's source range after all native owners
/// have recovered. This walker can read RAM descriptors only: diagnostic
/// failures neither update guest tables nor raise a guest exception.
pub(super) fn observed_instruction<H: Host>(
    machine: &mut Machine<H, parallel::Board>,
) -> Option<u64> {
    use stela_engine::machine::mmu;
    use stela_engine::machine::mmu::Access;
    use stela_engine::machine::mmu::Outcome;
    use stela_engine::machine::mmu::TableMemory;
    struct ReadOnlyTables<'a, H>(&'a mut H);
    impl<H: Host> TableMemory for ReadOnlyTables<'_, H> {
        fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
            let mut bytes = [0; size_of::<u64>()];
            self.0
                .read_ram(physical, &mut bytes)
                .then(|| u64::from_le_bytes(bytes))
        }

        fn update_descriptor(&mut self, _: u64, _: u64, _: u64) -> Option<bool> {
            None
        }
    }
    match mmu::translate(
        &machine.cpu.controls(machine.cpu.regime()),
        machine.cpu.pc,
        Access::Execute,
        machine.cpu.requester(),
        &mut ReadOnlyTables(&mut machine.host),
    ) {
        Outcome::Mapped(translation) => Some(translation.physical),
        _ => None,
    }
}

/// The PC and return addresses a call chain sample keeps.
pub(super) const CHAIN: usize = 6;

/// `pc` and the return addresses of the frame records from `frame`,
/// without their PACs; zero past the chain's end.
pub(super) fn call_chain<const N: usize, H: Host>(
    machine: &mut Machine<H, parallel::Board>,
    pc: u64,
    mut frame: u64,
) -> [u64; N] {
    let mut chain = [0; N];
    chain[0] = pc;
    for slot in &mut chain[1..] {
        let mut record = [0u8; 16];
        if frame == 0 || !frame.is_multiple_of(8) || !machine.read_virtual(frame, &mut record) {
            break;
        }
        let link = u64::from_le_bytes(record[8..].try_into().expect("8 bytes"));
        *slot = machine.strip_instruction_pointer(link);
        frame = u64::from_le_bytes(record[..8].try_into().expect("8 bytes"));
    }
    chain
}

/// Heartbeats between reports of the suspended guest threads.
pub(super) const SUSPENSION_BEATS: u64 = 6;

/// The return addresses a suspended thread's chain keeps.
pub(super) const SUSPENSION_CHAIN: usize = 12;

/// The suspended guest threads grouped by where they wait: each distinct
/// chain of the link register and the frame records, with its thread count
/// and the seconds since the most recent of them stopped. A guest that idles
/// without progress shows here the wait it never leaves.
pub(super) fn suspension_report<H: Host>(machine: &mut Machine<H, parallel::Board>) {
    const SHOWN: usize = 32;
    let now = machine.host.counter();
    let frequency = stela_engine::machine::timer::system_frequency(&machine.cpu).max(1);
    let suspended: Vec<_> = machine.suspended().values().copied().collect();
    let mut chains: Vec<([u64; SUSPENSION_CHAIN], u64)> = suspended
        .iter()
        .map(|suspension| {
            let link = machine.strip_instruction_pointer(suspension.link);
            (call_chain(machine, link, suspension.frame), suspension.at)
        })
        .collect();
    chains.sort_unstable();
    // Each chain's thread count and the latest suspension among them.
    let mut groups: Vec<(u64, usize, [u64; SUSPENSION_CHAIN])> = chains
        .chunk_by(|a, b| a.0 == b.0)
        .map(|run| {
            (
                run.iter().map(|&(_, at)| at).max().unwrap_or(0),
                run.len(),
                run[0].0,
            )
        })
        .collect();
    groups.sort_unstable_by(|a, b| b.cmp(a));
    output::arguments(format_args!(
        "SUSPENDED threads={} chains={}\n",
        suspended.len(),
        groups.len()
    ));
    for (at, count, chain) in groups.into_iter().take(SHOWN) {
        output::arguments(format_args!(
            "SUSPENSION x{count} age={}s",
            now.saturating_sub(at) / frequency
        ));
        for address in chain.into_iter().take_while(|&address| address != 0) {
            output::arguments(format_args!(" {address:#x}"));
        }
        output::arguments(format_args!("\n"));
    }
}

/// The share of the heartbeat's time-spaced samples at EL0 and the call
/// chains they found most often, which show where a guest without output
/// spends its time.
pub(super) fn sample_report(samples: &mut Vec<[u64; CHAIN]>, user: u32) {
    const SHOWN: usize = 3;
    samples.sort_unstable();
    let mut counts: Vec<(usize, [u64; CHAIN])> = samples
        .chunk_by(|a, b| a == b)
        .map(|run| (run.len(), run[0]))
        .collect();
    counts.sort_unstable_by(|a, b| b.cmp(a));
    output::arguments(format_args!("SAMPLES el0={user}/{}\n", samples.len()));
    for (count, chain) in counts.into_iter().take(SHOWN) {
        output::arguments(format_args!("SAMPLE x{count}"));
        for address in chain.into_iter().take_while(|&address| address != 0) {
            output::arguments(format_args!(" {address:#x}"));
        }
        output::arguments(format_args!("\n"));
    }
    samples.clear();
}

/// The longest each part of the service between two slices took since the
/// last beat: with every PE on a core of its own, the boot PE's guest time
/// passes meanwhile.
pub(super) struct ServiceParts {
    pub(super) at: u64,
    pub(super) longest: [u64; Self::PARTS],
}

impl ServiceParts {
    const PARTS: usize = 3;
    const REPORTS: usize = 0;
    const SERVICE: usize = 1;
    const BEAT: usize = 2;
    const NAMES: [&str; Self::PARTS] = ["reports", "service", "beat"];

    pub(super) fn new(now: u64) -> Self {
        Self {
            at: now,
            longest: [0; Self::PARTS],
        }
    }

    pub(super) fn start(&mut self, now: u64) {
        self.at = now;
    }

    /// The part `part` ended at `now`.
    pub(super) fn lap(&mut self, part: usize, now: u64) {
        self.longest[part] = self.longest[part].max(now.wrapping_sub(self.at));
        self.at = now;
    }

    pub(super) fn report(&self, tsc_hz: u64) -> String {
        let mut line = String::from("longest_us");
        for (name, ticks) in Self::NAMES.iter().zip(self.longest) {
            line.push_str(&format!(
                " {name}={}",
                u128::from(ticks) * 1_000_000 / u128::from(tsc_hz)
            ));
        }
        line
    }
}

/// What each of the heartbeat's reports took, which holds the boot PE's
/// guest up.
pub(super) struct BeatCost {
    pub(super) at: u64,
    pub(super) parts: Vec<(&'static str, u64)>,
}

impl BeatCost {
    pub(super) fn new(now: u64) -> Self {
        Self {
            at: now,
            parts: Vec::new(),
        }
    }

    /// The reports since the last mark were `name`'s.
    pub(super) fn mark(&mut self, name: &'static str) {
        let now = host::rdtsc();
        self.parts.push((name, now.wrapping_sub(self.at)));
        self.at = now;
    }

    pub(super) fn report(&self, tsc_hz: u64) {
        let mut line = String::from("BEAT COST us");
        for (name, ticks) in &self.parts {
            line.push_str(&format!(
                " {name}={}",
                u128::from(*ticks) * 1_000_000 / u128::from(tsc_hz)
            ));
        }
        output::arguments(format_args!("{line}\n"));
    }
}
