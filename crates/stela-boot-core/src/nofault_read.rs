//! Recoverable kernel reads at one x86-64 instruction in the host fault path.
use crate::interrupt_image::Frame;
use core::arch::global_asm;

global_asm!(
    ".text",
    ".global {read}",
    ".global {instruction}",
    ".global {resume}",
    "{read}:",
    "mov rcx, rdx",
    "{instruction}:",
    "rep movsb",
    "{resume}:",
    "mov rax, rcx",
    "ret",
    read = sym stela_nofault_read,
    instruction = sym stela_nofault_read_instruction,
    resume = sym stela_nofault_read_return,
);

unsafe extern "sysv64" {
    fn stela_nofault_read(dst: *mut u8, src: *const u8, len: usize) -> usize;
    static stela_nofault_read_instruction: u8;
    static stela_nofault_read_return: u8;
}

/// Read a prefix and return the number of unread bytes. The host uses four
/// levels of paging and rejects ranges that cross a noncanonical address.
///
/// # Safety
/// The engine's host fault handler must be active. The caller owns a valid
/// destination and authorizes the whole source range as kernel memory. Source
/// and destination must be disjoint. The source may be unmapped or unreadable.
pub unsafe fn read(dst: *mut u8, src: *const u8, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let start = src.addr();
    let Some(end) = start.checked_add(len - 1) else {
        return len;
    };
    const LOWER_END: usize = (1 << 47) - 1;
    const UPPER_START: usize = usize::MAX - LOWER_END;
    if end > LOWER_END && start < UPPER_START {
        return len;
    }
    // SAFETY: the caller supplies destination validity and source authority.
    // The canonical-range check excludes source general-protection faults.
    unsafe { stela_nofault_read(dst, src, len) }
}

/// Resume a supervisor data-read fault raised by the copy instruction. REP
/// preserves RSI and RCX at the faulting byte, so the fixup returns the
/// exact unread length without retrying or touching the remaining destination.
pub fn fixup(frame: &mut Frame, address: u64) -> bool {
    if frame.vector != 14
        || frame.cs & 3 != 0
        || frame.error & !1 != 0
        || frame.rip != (&raw const stela_nofault_read_instruction).addr() as u64
        || frame.rsi != address
        || frame.rcx == 0
    {
        return false;
    }
    frame.rip = (&raw const stela_nofault_read_return).addr() as u64;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_valid_source_and_refuses_noncanonical_ranges() {
        let source = [1, 2, 3, 4, 5];
        let mut destination = [0; 5];
        // SAFETY: both arrays are valid and disjoint. The valid-source case
        // cannot fault and the other range is rejected before the load.
        unsafe {
            assert_eq!(read(destination.as_mut_ptr(), source.as_ptr(), 5), 0);
            assert_eq!(
                read(
                    destination.as_mut_ptr(),
                    ((1usize << 47) - 1) as *const u8,
                    2
                ),
                2,
            );
        }
        assert_eq!(destination, source);
    }

    #[test]
    fn resumes_only_the_expected_supervisor_read() {
        let original = Frame {
            vector: 14,
            cs: 8,
            rip: (&raw const stela_nofault_read_instruction).addr() as u64,
            rsi: 0x1000,
            rcx: 3,
            ..Frame::default()
        };
        for error in [0, 1] {
            let mut frame = Frame { error, ..original };
            assert!(fixup(&mut frame, original.rsi));
            assert_eq!(
                frame.rip,
                (&raw const stela_nofault_read_return).addr() as u64,
            );
            assert_eq!(frame.rcx, original.rcx);
        }

        for mut frame in [
            Frame {
                error: 2,
                ..original
            },
            Frame {
                error: 4,
                ..original
            },
            Frame {
                error: 8,
                ..original
            },
            Frame {
                rip: original.rip + 1,
                ..original
            },
            Frame { rcx: 0, ..original },
        ] {
            let rip = frame.rip;
            assert!(!fixup(&mut frame, original.rsi));
            assert_eq!(frame.rip, rip);
        }
        let mut frame = original;
        assert!(!fixup(&mut frame, original.rsi + 1));
    }
}
