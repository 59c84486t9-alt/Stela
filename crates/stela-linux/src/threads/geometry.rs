//! One canonical, actual native-root geometry publication before Linux starts.
use crate::owner::RawOwner;
use core::marker::PhantomData;
use stela_driver_base::platform::work::{EnteredProcess, WorkError};

unsafe extern "C" {
    fn stela_linux_kernel_geometry_bind(owner: *const RawOwner, levels: u32) -> i32;
    fn stela_linux_kernel_geometry_ready(owner: *const RawOwner) -> i32;
    fn stela_linux_kernel_geometry_storage(owner: *const RawOwner, addresses: *mut usize) -> i32;
}
/// The exact claimed canonical owner's synchronous bootstrap target.
/// No public constructor, Clone, Send or numeric mode product is provided.
pub struct GeometryBinding<'owner> {
    owner: *const RawOwner,
    _owner: PhantomData<&'owner RawOwner>,
    _local: PhantomData<*mut ()>,
}
impl GeometryBinding<'_> {
    pub(crate) fn new(owner: &RawOwner) -> GeometryBinding<'_> {
        GeometryBinding {
            owner,
            _owner: PhantomData,
            _local: PhantomData,
        }
    }
    /// Actual publication DATA addresses for precommit mapping validation only.
    /// This grants no read/write/root permission. The same privately captured
    /// fresh owner is checked by C; no caller range selects these globals.
    pub fn storage(&self) -> Result<[usize; 4], WorkError> {
        let mut addresses = [0; 4];
        // SAFETY: fixed-size writable Rust output and exact private owner.
        match unsafe { stela_linux_kernel_geometry_storage(self.owner, addresses.as_mut_ptr()) } {
            0 => Ok(addresses),
            _ => Err(WorkError::Unavailable),
        }
    }
    /// Commit the original unsigned-int runtime geometry exactly once.
    ///
    /// # Safety
    /// Only an actual OriginalKernelGeometry provider may call this after
    /// validating its same retained original entered LoaderTables/root, CPU,
    /// process segment, actual CR4.LA57, code and geometry-global writable
    /// backing. `actual_levels` is that validated owner's level count (4|5),
    /// never a requested mode, CPUID support flag or equivalent numeric CR3.
    /// No root change/callback/borrow escape or fallible provider operation may
    /// occur between validation and this synchronous commit or after success.
    pub unsafe fn publish(self, actual_levels: u32) -> Result<(), WorkError> {
        // SAFETY: private exact-owner target and the provider contract above.
        match unsafe { stela_linux_kernel_geometry_bind(self.owner, actual_levels) } {
            0 => Ok(()),
            _ => Err(WorkError::Unavailable),
        }
    }
}
pub(crate) fn accepted(owner: &RawOwner) -> Result<(), WorkError> {
    // SAFETY: actual pinned canonical owner; this is a bounded metadata check.
    match unsafe { stela_linux_kernel_geometry_ready(owner) } {
        0 => Ok(()),
        _ => Err(WorkError::Unavailable),
    }
}
/// Retains the real native Host/root/table/code owners through Linux lifetime.
/// This does not grant task/data/IRQ/EOI/page-table mutation authority.
///
/// # Safety
/// Implement only from the actual original BootHost/Handoff LoaderTables/code
/// allocation owners. Bind checks the supplied fresh actual process segment,
/// same CPU/entered original root and CR4.LA57 against those exact retained
/// tables; a bool, root number or unrelated Arc is insufficient. Before
/// publication verify code/data backing and all fallible prerequisites. Invoke
/// the privately minted target synchronously exactly once and perform no
/// fallible operation or foreign callback after a successful commit. No scope,
/// target or entered reference may escape. No successful default exists.
pub unsafe trait OriginalKernelGeometry: Send + Sync {
    fn bind(
        &self,
        process: &dyn EnteredProcess,
        target: GeometryBinding<'_>,
    ) -> Result<(), WorkError>;
}
