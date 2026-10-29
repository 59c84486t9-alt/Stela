//! Whole-kernel retention for original Linux initial resource caches.
use super::pages::{Catalog, Entered, Error as CatalogError, Provider};
use crate::platform::work::{EnteredProcess, WorkError};
use core::{
    ffi::c_int,
    mem::{ManuallyDrop, size_of},
    sync::atomic::{AtomicU64, Ordering},
};

static RETAINED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Work(WorkError),
    Catalog(CatalogError),
    AlreadyAttempted,
    Native(c_int),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "kernel resource initialization: {self:?}")
    }
}
impl core::error::Error for Error {}

#[repr(C)]
struct Request {
    version: u32,
    bytes: u32,
    page_generation: u64,
}
unsafe extern "C" {
    fn stela_linux_resources_initialize(request: *const Request) -> c_int;
}

/// Lost whole-kernel owners retained with their original catalog/provider.
/// This is an ownership diagnostic, never a task/current/readiness capability.
pub fn retained_owners() -> u64 {
    RETAINED.load(Ordering::Relaxed)
}

/// Consumes the one canonical catalog for kernel-lifetime root caches. C also
/// irreversibly retains its descriptor owner once initialization starts, even
/// before any slab payload exists. A second kernel cannot reset those globals.
///
/// There is no full-kernel teardown yet. Drop/forget retains this catalog and
/// provider; it cannot release mappings under live global caches. Per-task
/// resources must still use their original reference/RCU releases. This type
/// grants no task/current, child stack loan, device or native service entry.
#[must_use = "cancel before initialization or retain for the whole kernel lifetime"]
pub struct KernelResources<P: Provider> {
    catalog: ManuallyDrop<Catalog<P>>,
    attempted: bool,
    owns: bool,
}
impl<P: Provider> KernelResources<P> {
    pub fn new(catalog: Catalog<P>) -> Self {
        Self {
            catalog: ManuallyDrop::new(catalog),
            attempted: false,
            owns: true,
        }
    }
    /// Initialize original UID/exec-state caches, in their explicit boot order.
    /// A refusal retains the same owner. No borrowed native authority escapes.
    /// A started or partial attempt is never retried or rolled back as empty.
    ///
    /// # Safety
    /// The catalog's original same-CPU/root/process/IRQ exclusion contract holds
    /// throughout this call and owner exit; `entered` borrows that actual native
    /// entered guard. No producer can race initialization or retarget mappings.
    /// This is taskless global-resource preparation, not permission to execute
    /// any current-dependent original helper or register a native C task.
    pub unsafe fn initialize(&mut self, entered: &dyn EnteredProcess) -> Result<(), Error> {
        entered.check().map_err(Error::Work)?;
        if self.attempted {
            return Err(Error::AlreadyAttempted);
        }
        let result = {
            let _owner = Entered::try_new().map_err(Error::Catalog)?;
            entered.check().map_err(Error::Work)?;
            self.attempted = true;
            let request = Request {
                version: 1,
                bytes: size_of::<Request>() as u32,
                page_generation: self.catalog.generation(),
            };
            // SAFETY: fixed repr(C) request names the SAME retained catalog;
            // exclusive actual context is the caller's contract. C permanently
            // retains the catalog before creating any original global cache.
            unsafe { stela_linux_resources_initialize(&request) }
        };
        entered.check().map_err(Error::Work)?;
        if result == 0 {
            Ok(())
        } else {
            Err(Error::Native(result))
        }
    }
    /// Return the same catalog only before any C initialization attempt. The
    /// caller resumes its original catalog context/retirement obligations.
    pub fn cancel(mut self, entered: &dyn EnteredProcess) -> Result<Catalog<P>, (Self, Error)> {
        if let Err(error) = entered.check() {
            return Err((self, Error::Work(error)));
        }
        if self.attempted {
            return Err((self, Error::AlreadyAttempted));
        }
        self.owns = false;
        // SAFETY: this unattempted owner uniquely holds the original catalog;
        // initialization never ran and no other take/drop path can run twice.
        Ok(unsafe { ManuallyDrop::take(&mut self.catalog) })
    }
}
impl<P: Provider> Drop for KernelResources<P> {
    fn drop(&mut self) {
        if self.owns {
            // No native entered guard is retained on a possibly stale stack.
            // Keep the real provider/context; C's kernel-root hold additionally
            // refuses unregister independently of Rust handle/borrow lifetime.
            let _ = RETAINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
