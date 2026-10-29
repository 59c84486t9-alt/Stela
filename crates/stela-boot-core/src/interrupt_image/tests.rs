use super::*;
const BYTES: usize = 4096;
fn location(backing: &Backing<BYTES>) -> Location {
    let frame = backing.frame_address().unwrap();
    Location {
        frame,
        image: (frame - 512 - ENTRY_METADATA_BYTES) & !63,
        image_bytes: 512,
        handler_bytes: 512,
    }
}
unsafe fn initialize(backing: &Backing<BYTES>, location: Location) {
    let base = backing.as_mut_ptr();
    // SAFETY: test exclusively owns this initialized Backing and its
    // checked local offsets; this simulates memory writes, not CPU admission.
    unsafe {
        base.add(location.frame - base.addr())
            .cast::<Frame>()
            .write(Frame {
                rip: 0x1234,
                ..Frame::default()
            });
        base.add(location.image - base.addr())
            .write_bytes(0x5a, location.image_bytes);
    }
}
#[test]
fn hardware_frame_copy_and_return_are_disjoint_from_the_kept_image() {
    let backing = Backing::<BYTES>::new();
    let location = location(&backing);
    // SAFETY: isolated initialized test allocation and complete test save.
    unsafe { initialize(&backing, location) };
    // SAFETY: the backing was initialized above and holds a complete test save.
    let mut captured = unsafe { backing.capture(location) }.unwrap();
    // SAFETY: `location` addresses the frame slot inside this test's live backing.
    let frame = unsafe {
        backing
            .as_mut_ptr()
            .add(location.frame - backing.as_mut_ptr().addr())
            .cast::<Frame>()
    };
    // A same-slot terminal hardware overwrite touches only the original Frame.
    // This test proves memory separation, not resumable nested IRQ handling.
    // SAFETY: `frame` points at the backing's saved frame, which outlives this write.
    unsafe {
        frame.write(Frame {
            rip: 0xdead,
            ..Frame::default()
        })
    };
    assert_eq!(captured.frame.rip, 0x1234);
    assert!(captured.image.iter().all(|byte| *byte == 0x5a));
    captured.frame.rip = 0x5678;
    captured.writeback();
    // SAFETY: `frame` points at the backing's saved frame, which outlives this read.
    assert_eq!(unsafe { frame.read() }.rip, 0x5678);
}
#[test]
fn foreign_frame_image_bad_alignment_and_insufficient_handler_capacity_refuse() {
    assert!(Backing::<128>::new().frame_address().is_none());
    assert!(Backing::<4097>::new().frame_address().is_none());
    let backing = Backing::<BYTES>::new();
    let other = Backing::<BYTES>::new();
    let valid = location(&backing);
    let cases = [
        Location {
            frame: location(&other).frame,
            ..valid
        },
        Location {
            image: location(&other).image,
            ..valid
        },
        Location {
            image: valid.image + 1,
            ..valid
        },
        Location {
            image_bytes: 511,
            ..valid
        },
        Location {
            image_bytes: 513,
            ..valid
        },
        Location {
            handler_bytes: BYTES,
            ..valid
        },
        Location {
            handler_bytes: usize::MAX,
            ..valid
        },
        Location {
            image_bytes: MAX_IMAGE_BYTES + 64,
            ..valid
        },
    ];
    for case in cases {
        // SAFETY: the validator rejects geometry before reading any image.
        assert!(unsafe { backing.capture(case) }.is_none());
    }
}
#[test]
fn terminal_backing_never_reuses_an_ordinary_saved_image() {
    let ordinary = Backing::<BYTES>::new();
    let terminal = Backing::<BYTES>::new();
    let first = location(&ordinary);
    let second = location(&terminal);
    // SAFETY: each backing is this test's isolated allocation, initialized once.
    unsafe {
        initialize(&ordinary, first);
        initialize(&terminal, second)
    };
    // SAFETY: the backing was initialized above and holds a complete test save.
    let retained = unsafe { ordinary.capture(first) }.unwrap();
    // SAFETY: the backing was initialized above and holds a complete test save.
    let stopped = unsafe { terminal.capture(second) }.unwrap();
    assert_ne!(retained.image.as_ptr(), stopped.image.as_ptr());
    assert!(retained.image.iter().all(|byte| *byte == 0x5a));
    assert_eq!(core::mem::size_of::<Frame>(), 22 * 8);
    assert_eq!(core::mem::align_of::<Backing<BYTES>>(), 64);
    assert_eq!(core::mem::size_of::<Backing<BYTES>>(), BYTES);
}
