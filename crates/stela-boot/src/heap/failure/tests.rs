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

#[test]
fn first_exhaustion_reports_without_allocating() {
    let heap = Heap::new();
    let mut ram = Ram([0; 4096]);
    // SAFETY: fresh exclusive aligned stack storage outlives this heap/model.
    unsafe { heap.initialize(ram.0.as_mut_ptr(), ram.0.len()) };
    let layout = Layout::from_size_align(16, 16).unwrap();
    // SAFETY: all allocations remain owned until this synchronous fixture ends;
    // neither their raw pointers nor this model heap escape to another thread.
    while !unsafe { heap.alloc(layout) }.is_null() {}
    let report = capture(&heap, layout).unwrap();
    let usage = report.usage.unwrap();
    assert_eq!(usage.total, 4096);
    assert_eq!(usage.largest, 0);
    let mut text = Text::new();
    write!(&mut text, "{report}").unwrap();
    assert!(
        text.as_str()
            .contains("bytes=16 align=16 snapshot=locked-metadata")
    );
    assert!(text.as_str().contains("live_estimate="));
    assert!(text.as_str().contains("cpu_counters=relaxed"));
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
        "HEAP ALLOCATION FAILURE bytes=14 align=2 snapshot=unavailable\n"
    );
    assert!(capture(&heap, Layout::new::<u8>()).is_none());
    drop(guard);
}
