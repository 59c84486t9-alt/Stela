//! Interior-mutable IST backing and disjoint entry copies. These layout checks
//! do not grant a CPU, active interrupt, mapping, or native invocation lease.
use crate::xstate::{
    ENTRY_METADATA_BYTES, EntryMetadata, IMAGE_ALIGNMENT, LEGACY_BYTES, MAX_IMAGE_BYTES,
};
use core::{cell::UnsafeCell, marker::PhantomData, ptr::NonNull};

/// The legacy registers saved by the stub, followed by the hardware frame.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Frame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

/// Hardware entries and the Rust handler stack write this allocation. A
/// shared descriptor reference must not freeze any part of the whole stack.
#[repr(C, align(64))]
pub struct Backing<const BYTES: usize> {
    bytes: UnsafeCell<[u8; BYTES]>,
}
impl<const BYTES: usize> Default for Backing<BYTES> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const BYTES: usize> Backing<BYTES> {
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; BYTES]),
        }
    }
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.bytes.get().cast()
    }
    pub fn frame_address(&self) -> Option<usize> {
        if BYTES < core::mem::size_of::<Frame>() || !BYTES.is_multiple_of(IMAGE_ALIGNMENT) {
            return None;
        }
        self.as_mut_ptr()
            .addr()
            .checked_add(BYTES)?
            .checked_sub(core::mem::size_of::<Frame>())
    }
    /// # Safety
    /// The actual installed descriptor owns and maps this original backing.
    /// Its assembly has finished the complete frame/image/metadata save, with
    /// a stable image size and no Rust stack writes into the saved intervals.
    /// All image bytes remain initialized from this zeroed allocation or saved
    /// bytes. Nested same-slot entries must refuse before image reuse and may
    /// not return into this scope. Separate terminal stacks cannot resume it.
    /// Retain the CPU, allocation and mappings for the complete lifetime of
    /// EVERY returned image/metadata borrow, including references copied out of
    /// Captured. No hardware, assembly or Rust writer may change those saved
    /// intervals while any such borrow is live; consuming writeback does not
    /// end independently copied borrows. Frame writeback is disjoint from them.
    pub unsafe fn capture(&self, location: Location) -> Option<Captured<'_>> {
        let base = self.as_mut_ptr();
        let bottom = base.addr();
        let frame_address = self.frame_address()?;
        if location.frame != frame_address
            || location.image_bytes < LEGACY_BYTES
            || location.image_bytes > MAX_IMAGE_BYTES
            || !location.image_bytes.is_multiple_of(IMAGE_ALIGNMENT)
        {
            return None;
        }
        let expected = frame_address
            .checked_sub(location.image_bytes)?
            .checked_sub(ENTRY_METADATA_BYTES)?
            & !(IMAGE_ALIGNMENT - 1);
        if location.image != expected || expected < bottom.checked_add(location.handler_bytes)? {
            return None;
        }
        let frame_offset = frame_address.checked_sub(bottom)?;
        let image_offset = expected.checked_sub(bottom)?;
        // SAFETY: all extents were checked against the ORIGINAL UnsafeCell
        // allocation. Derive provenance from it, not the supplied addresses.
        // No reference to the original hardware Frame or whole array is made.
        let (pointer, frame, image, metadata) = unsafe {
            let pointer = base.add(frame_offset).cast::<Frame>();
            (
                NonNull::new(pointer)?,
                pointer.read(),
                core::slice::from_raw_parts(base.add(image_offset), location.image_bytes),
                &*base
                    .add(image_offset + location.image_bytes)
                    .cast::<EntryMetadata>(),
            )
        };
        Some(Captured {
            frame,
            image,
            metadata,
            pointer,
            _local: PhantomData,
        })
    }
}

/// Assembly addresses for agreement with the actual retained Backing only.
/// This record carries no ownership or permission on its own.
#[derive(Debug, Clone, Copy)]
pub struct Location {
    pub frame: usize,
    pub image: usize,
    pub image_bytes: usize,
    pub handler_bytes: usize,
}

/// Owned local Frame copy and read-only disjoint image/metadata. The original
/// frame may be overwritten by a terminal nested entry without aliasing this
/// Rust value. Only successful ordinary dispatch writes its edited copy back.
pub struct Captured<'entry> {
    pub frame: Frame,
    pub image: &'entry [u8],
    pub metadata: &'entry EntryMetadata,
    pointer: NonNull<Frame>,
    _local: PhantomData<*mut ()>,
}
impl Captured<'_> {
    pub fn writeback(self) {
        // SAFETY: capture retains the actual backing through this borrow. Its
        // exclusive entry contract permits this one ordinary return write;
        // image and metadata intervals are disjoint from the original Frame.
        unsafe { self.pointer.as_ptr().write(self.frame) };
    }
}

#[cfg(test)]
mod tests;
