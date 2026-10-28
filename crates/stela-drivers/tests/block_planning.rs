//! Memory used to prepare a large range request through the public block API.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use stela_drivers::block::{Features, Identity, Request, Submission, Transport, WriteZeroes};

struct Observed;
static RECORD: AtomicBool = AtomicBool::new(false);
static LARGEST: AtomicUsize = AtomicUsize::new(0);

fn record(bytes: usize) {
    if RECORD.load(Ordering::Relaxed) {
        LARGEST.fetch_max(bytes, Ordering::Relaxed);
    }
}

// SAFETY: every allocation operation forwards its pointer and layout to System.
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        // SAFETY: the caller supplies the live pointer, its layout and new size.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: this pointer and layout came from the same System allocator.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Observed = Observed;

#[test]
fn large_zeroing_request_does_not_materialize_every_command() {
    let identity = Identity {
        transport: Transport::Ram,
        location: String::new(),
        model: String::new(),
        serial: String::new(),
        blocks: 400_000_000,
        block_size: 512,
        read_only: false,
        features: Features {
            write_zeroes: Some(WriteZeroes {
                blocks: 256,
                unmap: true,
            }),
            ..Features::default()
        },
    };
    LARGEST.store(0, Ordering::Relaxed);
    RECORD.store(true, Ordering::Relaxed);
    let submission = Submission::batch(
        vec![Request::WriteZeroes {
            lba: 0,
            blocks: identity.blocks,
            unmap: true,
        }],
        &identity,
    );
    RECORD.store(false, Ordering::Relaxed);
    assert!(submission.is_ok());
    assert!(
        LARGEST.load(Ordering::Relaxed) <= 1024 * 1024,
        "planning a range allocated a command array larger than 1 MiB"
    );
}
