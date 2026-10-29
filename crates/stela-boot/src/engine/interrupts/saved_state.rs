//! A view of the image the assembly entry saved on its IST.
//! Construction is private to that entry: a source pointer or stack interval
//! supplied by a native producer cannot mint this resource borrow.
use super::{Frame, HANDLER_STACK_BYTES, Tables, host};
use crate::engine::xstate;
use core::marker::PhantomData;

/// Short-lived, read-only image of one active descriptor-owned interrupt entry.
/// The original Tables keeps both this IST allocation and its CPU layout.
/// This is not an invocation, code-arena or initialized native-spill permit.
pub(crate) struct SavedState<'entry> {
    owner: &'entry xstate::XstateOwner,
    image: &'entry [u8],
    low: [u64; 16],
    format: xstate::SaveFormat,
    _local: PhantomData<*mut ()>,
}

impl SavedState<'_> {
    pub(crate) fn registers(
        &self,
    ) -> Result<stela_compiler::block::HostGprSnapshot, xstate::ImageError> {
        Ok(match self.extended_gprs()? {
            None => stela_compiler::block::HostGprSnapshot::legacy(self.low),
            Some(high) => {
                let mut all = [0; 32];
                all[..16].copy_from_slice(&self.low);
                all[16..].copy_from_slice(&high);
                stela_compiler::block::HostGprSnapshot::complete(all)
            }
        })
    }

    /// Only the exact enabled bank saved by this entry may be interpreted.
    /// CPU admission remains separate; disabled component19 stays unavailable.
    fn extended_gprs(&self) -> Result<Option<[u64; 16]>, xstate::ImageError> {
        match self.format {
            xstate::SaveFormat::Fxsave => Ok(None),
            xstate::SaveFormat::Xsave { mask } | xstate::SaveFormat::XsaveLegacySse { mask } => {
                self.owner.extended_gprs(self.image, mask)
            }
        }
    }
}

/// Assembly supplies raw addresses after a complete save. Never borrow the
/// original hardware Frame: a nested same-IST entry may overwrite it before
/// observing the active slot and stopping. Rust handlers receive a local copy.
pub(super) extern "sysv64" fn dispatch(frame: *mut Frame, image: *const u8) {
    let (tables, handler, active) = host::local::interrupt_owner();
    let mut captured = tables
        .capture_entry(frame, image, active)
        .unwrap_or_else(|| {
            crate::output::fatal("interrupt image does not belong to its active IST owner")
        });
    let saved = tables.saved_state(&captured).unwrap_or_else(|| {
        crate::output::fatal("interrupt image has no valid saved state metadata")
    });
    handler(&mut captured.frame, &saved);
    captured.writeback();
}

pub(super) fn terminal(frame: *mut Frame, image: *const u8) -> ! {
    let (tables, _, active) = host::local::interrupt_owner();
    let captured = tables
        .capture_entry(frame, image, active)
        .unwrap_or_else(|| {
            crate::output::fatal("terminal image does not belong to its active IST owner")
        });
    // Same-IST terminal recursion stops in assembly before image reuse. Its
    // raw original Frame can be overwritten, but this local copy lives below
    // the image and is never written back or returned through IRETQ.
    super::fatal(&captured.frame)
}

impl Tables {
    fn capture_entry(
        &self,
        frame: *mut Frame,
        image: *const u8,
        active: [u64; 2],
    ) -> Option<stela_boot_core::interrupt_image::Captured<'_>> {
        let slot = if self.fault_stack.frame_address()? == frame.addr() {
            0
        } else if self.fatal_stack.frame_address()? == frame.addr() {
            1
        } else {
            return None;
        };
        if active[slot] != 1 {
            return None;
        }
        let owner = self.xstate.as_ref()?;
        let stack = if slot == 0 {
            &self.fault_stack
        } else {
            &self.fatal_stack
        };
        // SAFETY: original permanently pinned descriptor/UnsafeCell backing,
        // exact active slot and assembly-provided addresses. The same-slot
        // active check halts BEFORE allocating/saving another image. IF0 alone
        // is not the exclusion: NMI/DF/MCE use the separate terminal IST and
        // never return; nested terminal entries also halt before image reuse.
        // The image region is initialized by Stack::new and never overlaps
        // Rust's downward-growing handler stack or the mutable hardware Frame.
        let captured = unsafe {
            stack.capture(stela_boot_core::interrupt_image::Location {
                frame: frame.addr(),
                image: image.addr(),
                image_bytes: usize::try_from(owner.abi().image_bytes).ok()?,
                handler_bytes: HANDLER_STACK_BYTES,
            })
        }?;
        if usize::from(matches!(captured.frame.vector, 2 | 8 | 18)) != slot {
            return None;
        }
        Some(captured)
    }

    fn saved_state<'entry>(
        &'entry self,
        captured: &stela_boot_core::interrupt_image::Captured<'entry>,
    ) -> Option<SavedState<'entry>> {
        let owner = self.xstate.as_ref()?;
        let abi = owner.abi();
        let format = captured.metadata.save_format()?;
        if (abi.extended != 0) != !matches!(format, xstate::SaveFormat::Fxsave) {
            return None;
        }
        let mask = match format {
            xstate::SaveFormat::Fxsave => 0,
            xstate::SaveFormat::Xsave { mask } | xstate::SaveFormat::XsaveLegacySse { mask } => {
                mask
            }
        };
        if mask & !abi.supported_mask != 0 || mask & !xstate::ADMITTED_MASK != 0 {
            return None;
        }
        let frame = captured.frame;
        Some(SavedState {
            owner,
            image: captured.image,
            low: [
                frame.rax, frame.rcx, frame.rdx, frame.rbx, frame.rsp, frame.rbp, frame.rsi,
                frame.rdi, frame.r8, frame.r9, frame.r10, frame.r11, frame.r12, frame.r13,
                frame.r14, frame.r15,
            ],
            format,
            _local: PhantomData,
        })
    }
}
