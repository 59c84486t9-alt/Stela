//! Bounded owner observations at profile publication, outside native execution.
use super::{Devices, Host, Machine, Prepared, Refused, Statistics};
use serde::Serialize;

#[derive(Clone, Copy, Serialize)]
pub struct Snapshot {
    pub statistics: Statistics,
    preparation: Option<PreparationMetrics>,
    block_slots: usize,
    free_block_slots: usize,
    indexed_blocks: usize,
    indexed_code_pages: usize,
    retained_source_pages: usize,
    compile_wall_ticks_scope: &'static str,
    preparation_scope: &'static str,
    lookup_counter_scope: &'static str,
    counter_scope: &'static str,
}

#[derive(Clone, Copy, Default, Serialize)]
pub(super) struct PreparationMetrics {
    calls: u64,
    wall_ticks: u64,
    blocks: u64,
    checked: u64,
    fp_traps: u64,
    refused: u64,
    short_window_retries: u64,
    returned_native_bytes: u64,
    counter_saturated: bool,
}

fn add(total: &mut u64, value: u64, saturated: &mut bool) {
    let (next, overflow) = total.overflowing_add(value);
    *total = if overflow { u64::MAX } else { next };
    *saturated |= overflow;
}

impl PreparationMetrics {
    pub(super) fn record(
        &mut self,
        result: Option<&Result<Prepared, Refused>>,
        ticks: u64,
        short: bool,
    ) {
        add(&mut self.calls, 1, &mut self.counter_saturated);
        add(&mut self.wall_ticks, ticks, &mut self.counter_saturated);
        let retry = short && !matches!(result, Some(Ok(_)));
        let outcome = match result {
            Some(Ok(Prepared::Block { compiled, .. })) => {
                let bytes = compiled.native.x86_64_code.len() as u64;
                add(
                    &mut self.returned_native_bytes,
                    bytes,
                    &mut self.counter_saturated,
                );
                &mut self.blocks
            }
            Some(Ok(Prepared::Checked(_))) => &mut self.checked,
            Some(Ok(Prepared::FloatingPointTrap)) => &mut self.fp_traps,
            Some(Err(_)) => &mut self.refused,
            None => &mut self.short_window_retries,
        };
        add(outcome, 1, &mut self.counter_saturated);
        if retry && result.is_some() {
            add(
                &mut self.short_window_retries,
                1,
                &mut self.counter_saturated,
            );
        }
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Start a new diagnostic epoch, including after a host PID change.
    pub fn enable_engine_metrics(&mut self) {
        self.preparation_metrics = Some(PreparationMetrics::default());
    }

    pub fn disable_engine_metrics(&mut self) {
        self.preparation_metrics = None;
    }

    pub fn metrics_snapshot(&self) -> Snapshot {
        Snapshot {
            statistics: self.statistics,
            preparation: self.preparation_metrics,
            block_slots: self.blocks.len(),
            free_block_slots: self.free_blocks.len(),
            indexed_blocks: self.index.len(),
            indexed_code_pages: self.index.pages(),
            retained_source_pages: self.pages.len(),
            compile_wall_ticks_scope: "accepted foreground prepare only; excludes discarded short-window attempts, refusals and background compilation; host counter ticks, not CPU cycles",
            preparation_scope: "since this writer enabled metrics; all foreground preparation probes and wall ticks, including internal retry work; short probes that reach the end of input emit no code; returned bytes exclude internal discarded emissions; not exact emitter invocation counts or CPU cycles; excludes shared/stored rebase and background workers",
            lookup_counter_scope: "lookups counts exits sent to lookup dispatchers; lookup_hits counts successful native transfers; their ratio is not a hit rate",
            counter_scope: "raw engine lifetime counters; subtract initial_statistics for writer epoch; legacy u64 counters have no saturation detection; residency fields are gauges, not RSS",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_outcomes_partition_calls_and_report_saturation() {
        let mut metrics = PreparationMetrics::default();
        metrics.record(Some(&Ok(Prepared::Checked(0))), 3, false);
        metrics.record(Some(&Ok(Prepared::FloatingPointTrap)), 5, false);
        metrics.record(
            Some(&Err(Refused {
                pc: 0,
                error: stela_compiler::CompileError::new(
                    stela_compiler::CompileErrorKind::IncompleteSourceInstruction,
                ),
            })),
            7,
            true,
        );
        assert_eq!(
            (
                metrics.calls,
                metrics.checked,
                metrics.fp_traps,
                metrics.refused
            ),
            (3, 1, 1, 1)
        );
        assert_eq!((metrics.wall_ticks, metrics.short_window_retries), (15, 1));
        assert!(!metrics.counter_saturated);
        metrics.calls = u64::MAX;
        metrics.wall_ticks = u64::MAX;
        metrics.record(Some(&Ok(Prepared::Checked(0))), 1, false);
        assert_eq!((metrics.calls, metrics.wall_ticks), (u64::MAX, u64::MAX));
        assert!(metrics.counter_saturated);
    }

    #[test]
    fn short_probe_retries_without_emitting_a_partial_block() {
        use super::super::{
            Fetched,
            tests::{BASE, machine},
        };
        let mut words = alloc::vec![0x9100_0400; 63]; // add x0, x0, #1
        words.push(0xd400_0001); // svc #0
        let mut plain = machine(&words);
        let mut profiled = machine(&words);
        profiled.enable_engine_metrics();
        assert!(matches!(
            plain.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
        assert!(matches!(
            profiled.fetch_block(BASE, false),
            Ok(Fetched::Block(_))
        ));
        let metrics = profiled.preparation_metrics.unwrap();
        assert_eq!(
            (metrics.calls, metrics.blocks, metrics.short_window_retries),
            (2, 1, 1)
        );
        assert!(metrics.returned_native_bytes > 0);
        assert_eq!(profiled.statistics.compiled, 1);
        assert_eq!(plain.host.installed, profiled.host.installed);
        assert_eq!(plain.cpu.state, profiled.cpu.state);
        assert_eq!(profiled.host.counter_reads, plain.host.counter_reads + 2);
        profiled.disable_engine_metrics();
        assert!(profiled.preparation_metrics.is_none());
    }

    #[test]
    fn bounded_snapshot_preserves_counter_values_without_serializing_block_maps() {
        let mut machine = super::super::tests::machine(&[]);
        machine.statistics.compiled = 7;
        machine.statistics.compile_ticks = 123;
        machine.statistics.lookups = 5;
        machine.statistics.lookup_hits = 19;
        let before = machine.statistics;
        let snapshot = machine.metrics_snapshot();
        let json = serde_json::to_value(snapshot).unwrap();
        assert_eq!(json["statistics"]["compiled"], 7);
        assert_eq!(json["statistics"]["compile_ticks"], 123);
        assert_eq!(json["statistics"]["lookups"], 5);
        assert_eq!(json["statistics"]["lookup_hits"], 19);
        assert_eq!(json["indexed_blocks"], 0);
        assert_eq!(machine.statistics, before);
        assert!(serde_json::to_vec(&snapshot).unwrap().len() < 4096);
    }
}
