//! NIR a pipeline job reads after its call's turn has returned it to the
//! compiler ([`pin_nir`]). The driver only reads a stage's NIR: Mesa's
//! runtime serializes it for the cache key and clones it to compile. So a
//! job may share the compiler's shader, which a turn may lend at the same
//! time, as long as it is not freed meanwhile: a release of a pinned shader
//! leaves the free to its last unpin. While a pin stands, the shader's
//! address names that shader alone, so a key of NIR handles stays true.
use super::ShaderCode;
use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    ffi::c_void,
    sync::atomic::{AtomicBool, Ordering},
};

/// What frees a shader once no pin holds it.
type Release = unsafe extern "C" fn(*mut c_void);

struct Pin {
    code: u64,
    pins: u32,
    /// Released by its compiler while pinned: freed by the last unpin.
    released: Option<Release>,
}

/// The pinned shaders, behind a spin lock no interrupt handler takes; few
/// are pinned at once (a job's stages and the pipelines kept for calls).
struct Pins {
    held: AtomicBool,
    pins: UnsafeCell<Vec<Pin>>,
}

// SAFETY: `with` holds `held` for every access to the list.
unsafe impl Sync for Pins {}

static PINS: Pins = Pins {
    held: AtomicBool::new(false),
    pins: UnsafeCell::new(Vec::new()),
};

/// Runs `f` on the list, under its lock, which counts as held
/// ([`crate::metal::deferred::hold_lock`]): a job drops its pins, and a pin
/// allocates.
fn with<R>(f: impl FnOnce(&mut Vec<Pin>) -> R) -> R {
    let _held = crate::metal::deferred::hold_lock();
    while PINS
        .held
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while PINS.held.load(Ordering::Relaxed) {
            core::hint::spin_loop();
        }
    }
    // SAFETY: `held` excludes every other access until it is released.
    let result = f(unsafe { &mut *PINS.pins.get() });
    PINS.held.store(false, Ordering::Release);
    result
}

/// A shader kept from being freed until this drops.
#[derive(Debug)]
pub struct PinnedNir(ShaderCode);

impl PinnedNir {
    pub fn code(&self) -> ShaderCode {
        self.0
    }
}

/// Pins `code`, NIR the caller's turn holds now: it stays until the pin
/// drops, though its compiler releases it before.
pub fn pin_nir(code: ShaderCode) -> PinnedNir {
    with(
        |pins| match pins.iter_mut().find(|pin| pin.code == code.0) {
            Some(pin) => pin.pins += 1,
            None => pins.push(Pin {
                code: code.0,
                pins: 1,
                released: None,
            }),
        },
    );
    PinnedNir(code)
}

impl Drop for PinnedNir {
    fn drop(&mut self) {
        let free = with(|pins| {
            let at = pins.iter().position(|pin| pin.code == self.0.0)?;
            pins[at].pins -= 1;
            if pins[at].pins != 0 {
                return None;
            }
            pins.swap_remove(at).released
        });
        if let Some(release) = free {
            // SAFETY: its compiler released the shader while pinned, and
            // this was the last pin: nothing else holds it.
            unsafe { release(self.0.0 as usize as *mut c_void) };
        }
    }
}

/// Whether `code`'s free waits for its pins: its compiler releases it now,
/// and the last unpin frees it with `release`.
pub(super) fn release_when_unpinned(code: ShaderCode, release: Release) -> bool {
    with(|pins| {
        pins.iter_mut()
            .find(|pin| pin.code == code.0)
            .map(|pin| pin.released = Some(release))
            .is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    std::thread_local! {
        static FREED: core::cell::RefCell<Vec<u64>> = const { core::cell::RefCell::new(Vec::new()) };
    }

    unsafe extern "C" fn free(shader: *mut c_void) {
        FREED.with_borrow_mut(|freed| freed.push(shader as usize as u64));
    }

    fn freed() -> Vec<u64> {
        FREED.with_borrow(Clone::clone)
    }

    #[test]
    fn a_shader_released_while_pinned_is_freed_by_its_last_unpin() {
        // Addresses of this test alone: the list is the image's.
        let code = ShaderCode(0x7e57_0001_0000);
        let first = pin_nir(code);
        let second = pin_nir(code);
        assert!(release_when_unpinned(code, free));
        drop(first);
        assert!(freed().is_empty());
        assert_eq!(second.code(), code);
        drop(second);
        assert_eq!(freed(), [code.0]);
        // Unpinned now: a release frees at once, as its compiler does.
        assert!(!release_when_unpinned(code, free));
    }

    #[test]
    fn a_pin_that_outlives_no_release_frees_nothing() {
        let code = ShaderCode(0x7e57_0002_0000);
        drop(pin_nir(code));
        assert!(freed().is_empty());
        assert!(!release_when_unpinned(code, free));
    }
}
