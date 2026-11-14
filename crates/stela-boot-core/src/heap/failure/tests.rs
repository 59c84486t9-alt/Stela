use super::*;
use core::{alloc::GlobalAlloc, fmt::Write};

#[repr(align(4096))]
struct Ram([u8; 4096]);
struct Text {
    bytes: [u8; 512],
    used: usize,
}
impl Text {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            used: 0,
        }
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.used]).unwrap()
    }
}
impl fmt::Write for Text {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.used.checked_add(value.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.used..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}

std::thread_local! {
    static REPORTED: core::cell::RefCell<Text> = core::cell::RefCell::new(Text::new());
}

/// Records into fixed storage, as the mount's serial sink writes without
/// allocating.
fn record(report: fmt::Arguments<'_>) {
    REPORTED.with(|text| text.borrow_mut().write_fmt(report).unwrap());
}

#[test]
fn first_exhaustion_reports_once_without_allocating() {
    let heap = Heap::new().reporting_failures(record);
    let mut ram = Ram([0; 4096]);
    // SAFETY: fresh exclusive aligned stack storage outlives this heap/model.
    unsafe { heap.initialize(ram.0.as_mut_ptr(), ram.0.len()) };
    let layout = Layout::from_size_align(16, 16).unwrap();
    assert_eq!(heap.first_failure(), None);
    // SAFETY: all allocations remain owned until this synchronous fixture ends;
    // neither their raw pointers nor this model heap escape to another thread.
    while !unsafe { heap.alloc(layout) }.is_null() {}
    let reported = REPORTED.with(|text| text.borrow().as_str().to_owned());
    assert!(reported.contains("bytes=16 align=16 snapshot=locked-metadata"));
    assert!(reported.contains("live_estimate="));
    assert!(reported.contains("cpu_counters=relaxed total=4096"));
    assert!(reported.contains("largest=0\nHEAP AT FAILURE large classes 16:0M"));
    let first = heap.first_failure().unwrap();
    assert_eq!((first.bytes, first.align), (16, 16));
    let found = first.heap.unwrap();
    assert_eq!((found.total, found.largest), (4096, 0));
    assert!(found.live <= found.carved && found.carved <= found.total);
    // SAFETY: as above; this second failure must not report again, and the
    // first stays the one named.
    assert!(unsafe { heap.alloc(Layout::from_size_align(64, 8).unwrap()) }.is_null());
    assert_eq!(heap.first_failure(), Some(first));
    REPORTED.with(|text| assert_eq!(text.borrow().as_str(), reported));
    assert!(capture(&heap, layout).is_none());
}

#[test]
fn held_metadata_reports_unavailable_once() {
    let heap = Heap::new();
    let guard = heap.lock();
    let report = capture(&heap, Layout::from_size_align(14, 2).unwrap()).unwrap();
    assert!(report.usage.is_none());
    let mut text = Text::new();
    write!(&mut text, "{report}").unwrap();
    assert_eq!(
        text.as_str(),
        "HEAP ALLOCATION FAILURE bytes=14 align=2 snapshot=unavailable\n\
         HEAP AT FAILURE classes 16:0M 32:0M 64:0M 128:0M 256:0M 512:0M 1024:0M 2048:0M 4096:0M cores\n"
    );
    assert!(capture(&heap, Layout::new::<u8>()).is_none());
    drop(guard);
}

#[test]
fn the_stop_line_names_the_heap_the_failure_found() {
    let failure = Failure {
        bytes: 17_609_526,
        align: 1,
        heap: Some(FailedHeap {
            live: 2619 << 20,
            carved: 2776 << 20,
            largest: 16 << 20,
            total: 3072 << 20,
        }),
    };
    let mut text = Text::new();
    write!(&mut text, "{failure}").unwrap();
    assert_eq!(
        text.as_str(),
        " (the heap had no room for 17609526 bytes aligned to 1: heap=2619M/3072M \
         carved=2776M largest=16M)"
    );
    let mut text = Text::new();
    write!(
        &mut text,
        "{}",
        Failure {
            heap: None,
            ..failure
        }
    )
    .unwrap();
    assert_eq!(
        text.as_str(),
        " (the heap had no room for 17609526 bytes aligned to 1)"
    );
}

#[test]
fn a_failure_under_held_metadata_keeps_no_heap() {
    let heap = Heap::new();
    let guard = heap.lock();
    // The guard makes the failure's snapshot unavailable.
    let _ = capture(&heap, Layout::from_size_align(32, 8).unwrap());
    drop(guard);
    assert_eq!(
        heap.first_failure(),
        Some(Failure {
            bytes: 32,
            align: 8,
            heap: None
        })
    );
}
