//! DRM character-device numbering over the shared Linux file service.
use stela_linux::{client, owner::Errno};

/// Open DRM's character device `minor`, for a descriptor or negative errno.
///
/// # Safety
/// Entered in a Linux owner on a task; the open operation may sleep.
pub unsafe fn open(minor: u32) -> Errno {
    const DRM_MAJOR: u32 = 226;
    const MINOR_BITS: u32 = 20;
    const READ_WRITE: u32 = 2;
    // SAFETY: the caller supplies the entered owner and task.
    unsafe { client::open(DRM_MAJOR << MINOR_BITS | minor, READ_WRITE) }
}
