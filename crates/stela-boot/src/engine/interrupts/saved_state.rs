//! A view of the image the actual assembly entry saved on its retained IST.
//! Construction is private to that entry: a source pointer or stack interval
//! supplied by a native producer cannot mint this resource borrow.
use super::{Frame, HANDLER_STACK_BYTES, IST_BYTES, Tables, host};
use crate::engine::xstate;
use core::marker::PhantomData;

/// Short-lived, read-only image of one active descriptor-owned interrupt entry.
/// The original Tables retains both this IST allocation and its CPU layout.
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

/// Assembly supplies both addresses after a complete save, before any native
/// return or image restoration. No public caller can construct SavedState.
pub(super) extern "sysv64" fn dispatch(frame: &mut Frame, image: *const u8) {
    let (tables, handler, active) = host::local::interrupt_owner();
    let entry = ();
    let saved = tables
        .saved_state(frame, image, active, &entry)
        .unwrap_or_else(|| {
            crate::output::fatal("interrupt image does not belong to its active IST owner")
        });
    handler(frame, &saved);
}

impl Tables {
    fn saved_state<'entry>(
        &'entry self,
        frame: &Frame,
        image: *const u8,
        active: [u64; 2],
        _entry: &'entry (),
    ) -> Option<SavedState<'entry>> {
        let terminal = matches!(frame.vector, 2 | 8 | 18);
        let stack = if terminal {
            &self.fatal_stack
        } else {
            &self.fault_stack
        };
        if active[usize::from(terminal)] != 1 {
            return None;
        }
        let owner = self.xstate.as_ref()?;
        let abi = owner.abi();
        let bottom = core::ptr::from_ref(stack).addr();
        let top = bottom.checked_add(IST_BYTES)?;
        let frame_address = core::ptr::from_ref(frame).addr();
        if frame_address != top.checked_sub(core::mem::size_of::<Frame>())? {
            return None;
        }
        owner
            .check_entry_extent(frame_address, bottom.checked_add(HANDLER_STACK_BYTES)?, top)
            .ok()?;
        let bytes = usize::try_from(abi.image_bytes).ok()?;
        let expected = frame_address
            .checked_sub(bytes)?
            .checked_sub(xstate::ENTRY_METADATA_BYTES)?
            & !(xstate::IMAGE_ALIGNMENT - 1);
        if image.addr() != expected || expected < bottom.checked_add(HANDLER_STACK_BYTES)? {
            return None;
        }
        // Derive provenance from the actual retained allocation, never from
        // the numeric image address the assembly supplied for agreement.
        let owned_image = core::ptr::from_ref(stack)
            .cast::<u8>()
            .wrapping_add(expected - bottom);
        // SAFETY: the original pinned Stack allocation above owns exactly this
        // image and metadata. The assembly owns its active, nonnested slot and
        // completed the save before dispatch; no arbitrary interrupted RSP is
        // dereferenced. This borrow ends before restoration reuses those bytes.
        let (image_bytes, metadata) = unsafe {
            (
                core::slice::from_raw_parts(owned_image, bytes),
                &*owned_image.add(bytes).cast::<xstate::EntryMetadata>(),
            )
        };
        let format = metadata.save_format()?;
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
        Some(SavedState {
            owner,
            image: image_bytes,
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
