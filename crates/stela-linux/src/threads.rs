//! Native process-segment ownership used by original kernel-thread metadata.
use crate::owner::Platform;
use alloc::sync::Arc;
mod data;
pub(crate) mod geometry;
pub use data::{TaskDataBacking, TaskDataStorage};
pub use geometry::{GeometryBinding, OriginalKernelGeometry};
use stela_driver_base::platform::work::{EnteredProcess, WorkError};

/// Supplies a fresh borrowed native execution guard to one metadata operation.
/// This interface alone initializes no original task/resource graph or broker.
///
/// # Safety
/// The provider borrows the actual current RootExecution/DriverExecution for
/// the same kernel Runtime, physical CPU and retained root/code owners. It
/// verifies that exact segment before invoking body once, synchronously, and
/// clears its transient borrow before that segment guard is dropped. Identity
/// metadata, task IDs, RAM-absence epochs or an Arc do not create a segment.
/// Refusal invokes no body. No default or fallback permission is supplied.
pub unsafe trait KernelThreadPlatform: Platform {
    /// Retain the actual code/native-root and source storage allocation owners
    /// for an original task's measured-execution data sink. No Queue, Runtime,
    /// KernelOwner, Platform or binding ownership edge may be retained by it.
    /// This is lifetime only, never CPU/current/IRQ/write permission. The
    /// genuine source get_task_struct lease and exact native writer/reader
    /// joins remain independent. No successful default is provided.
    fn task_data_backing(&self) -> Result<Arc<dyn TaskDataBacking>, WorkError>;

    /// Borrow the existing segment without recursively entering a native epoch.
    /// Outer WorkError denotes segment admission only; R may itself be the
    /// metadata operation's typed Result and keeps that failure distinction.
    ///
    /// # Safety
    /// Body performs one bounded nonblocking native metadata operation. It
    /// cannot park, switch continuations, reconfigure native roots, recursively
    /// acquire this segment or call original resource/driver code that may do
    /// so. Any native leaf provider/metadata callback meets the same contract.
    /// No entered guard/reference may escape in a request, escrow, retained
    /// callback, raw-pointer consumer or suspended frame. Finish this borrow
    /// before original resource allocation/unwind waits, then obtain fresh
    /// actual permission separately for the next metadata transaction.
    unsafe fn with_process<R>(
        &self,
        body: impl FnOnce(&dyn EnteredProcess) -> R,
    ) -> Result<R, WorkError>;
}

/// The retained original native kernel root allocation and mapping owner.
/// This is read-only initial-mm identity, never authority to edit page tables.
///
/// # Safety
/// Retain the actual same original LoaderTables root page allocation and its
/// CPU mapping, source/native roots and compiled code for the complete kernel
/// lifetime, including partial bootstrap, callback tails and retained failures.
/// An address, CR3 value, RootIdentity or unrelated Arc cannot substitute for
/// that owner. No successful default or compatibility permission is provided.
pub unsafe trait OriginalKernelRoot: Send + Sync {
    /// Lend the exact original root page's CPU address for one initial-mm bind.
    /// Verify this actual EnteredProcess segment, the same original manager-
    /// entered LoaderTables root, and its real root-page VA-to-PA mapping with
    /// WB/supervisor/read-write attributes. The returned address is borrowed
    /// from this kept owner and is no mutation/mapping/address-space grant.
    ///
    /// The call is bounded and nonblocking. No continuation switch, native
    /// root change, nested entry, allocation, C callback or owner release may
    /// occur. Caller must keep this actual owner before requesting the view
    /// and through any C publication/unwind and all initial-mm/child users.
    fn pgd(
        &self,
        process: &dyn EnteredProcess,
    ) -> Result<core::ptr::NonNull<core::ffi::c_void>, WorkError>;
}

unsafe extern "C" {
    fn stela_linux_task_initial_root_levels() -> u32;
}
/// Actual published native Linux page-table geometry, not root admission.
/// Reads the one-time original geometry publication, not native table bytes. The actual
/// producer separately retains its code and validates the root mode/mapping.
/// Unpublished/unsupported/inconsistent geometry is explicit refusal.
pub fn initial_root_levels() -> Result<u32, WorkError> {
    // SAFETY: the C getter observes only the one-time published geometry state.
    match unsafe { stela_linux_task_initial_root_levels() } {
        4 => Ok(4),
        5 => Ok(5),
        _ => Err(WorkError::Unavailable),
    }
}
