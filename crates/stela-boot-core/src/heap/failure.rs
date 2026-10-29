//! First failed ordinary allocation: no allocation, waiting or caller formatter.
use super::{Heap, Usage};
use core::{alloc::Layout, fmt, sync::atomic::Ordering};

struct Report {
    layout: Layout,
    usage: Option<Usage>,
}

fn capture(heap: &Heap, layout: Layout) -> Option<Report> {
    if heap
        .failure_reported
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return None;
    }
    let usage = heap.try_lock().and_then(|guard| {
        // SAFETY: the successful one-shot guard owns heap metadata and masks
        // local IRQ reentry. No state borrow or guard reaches UART formatting.
        let state = unsafe { &*heap.state.get() };
        let usage = state.ready.then(|| heap.usage_locked(state));
        drop(guard);
        usage
    });
    Some(Report { layout, usage })
}
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HEAP ALLOCATION FAILURE bytes={} align={}",
            self.layout.size(),
            self.layout.align()
        )?;
        match self.usage {
            Some(usage) => writeln!(
                f,
                " snapshot=locked-metadata live_estimate={} cpu_counters=relaxed total={} carved={} peak={} largest={}",
                usage.live, usage.total, usage.carved, usage.peak, usage.largest
            ),
            None => writeln!(f, " snapshot=unavailable"),
        }
    }
}

pub(super) fn report(heap: &Heap, layout: Layout) {
    if let Some(report) = capture(heap, layout) {
        // This formatter emits only fixed strings and integer fields; the
        // sink is bounded, lock-free output that runs no queue or log.
        (heap.failure_sink)(format_args!("\n{report}\n"));
    }
}

#[cfg(test)]
#[path = "failure/tests.rs"]
mod tests;
