//! `stela.efi` aborts on panic, so a compiler bug stops the machine here where
//! `catch_unwind` would have returned an error to NVK.
use alloc_crate::boxed::Box;
use core::any::Any;
pub use core::panic::{AssertUnwindSafe, Location, PanicInfo, RefUnwindSafe, UnwindSafe};

pub fn catch_unwind<F: FnOnce() -> R, R>(body: F) -> Result<R, Box<dyn Any + Send>> {
    Ok(body())
}
