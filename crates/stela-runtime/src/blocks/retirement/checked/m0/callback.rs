//! One reached scalar request from the exact bound M0 native body.
//!
//! This owns no PE permission. Only the closed native session may lend this
//! view while the original authority guard owns the prepared RAM transaction.
use crate::memory::domain::m0_read::{M0RamReadPlatformError, M0RamReadPrepared};
use stela_compiler::context::memory::{
    MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest, MemoryStatus,
};

pub(crate) enum CallbackFailure {
    InvalidRequest {
        address: u64,
        pc: u64,
        bytes: u32,
        flags: u32,
        attempts: u32,
        completed_bytes: u64,
    },
    Platform(M0RamReadPlatformError),
    Panicked {
        completed_bytes: u64,
    },
}

pub(super) struct ReadCallback<'call, 'loan, 'owner> {
    prepared: &'call mut M0RamReadPrepared<'loan, 'owner>,
    attempts: u32,
    failure: Option<CallbackFailure>,
}

impl<'call, 'loan, 'owner> ReadCallback<'call, 'loan, 'owner> {
    pub(super) fn new(prepared: &'call mut M0RamReadPrepared<'loan, 'owner>) -> Self {
        Self {
            prepared,
            attempts: 0,
            failure: None,
        }
    }

    /// Stack-view scoping only; this neither enters native code nor grants a
    /// permit. The closed session supplies the actual call under its PE guard.
    pub(super) fn with_view<R>(&mut self, call: impl FnOnce(&mut MemoryContextView) -> R) -> R {
        let mut view = MemoryContextView {
            version: MEMORY_CONTEXT_VERSION,
            bytes: MEMORY_CONTEXT_BYTES,
            callback: reached_read,
            opaque: (self as *mut Self).cast(),
            fault_kind: MemoryStatus::Success as u32,
            reserved: 0,
            fault_address: 0,
            fault_pc: 0,
            completed_bytes: 0,
            reserved_tail: 0,
        };
        call(&mut view)
    }

    pub(super) fn take_failure(&mut self) -> Option<CallbackFailure> {
        self.failure.take()
    }

    pub(super) const fn attempts(&self) -> u32 {
        self.attempts
    }

    fn dispatch(&mut self, request: &MemoryRequest) -> Result<u64, CallbackFailure> {
        self.attempts = self.attempts.saturating_add(1);
        let intent = self.prepared.intent();
        if self.attempts != 1
            || request.address != intent.raw_address
            || request.pc != intent.source_pc.0
            || request.bytes != u32::from(intent.bytes)
            || request.flags != intent.flags
            || request.data.is_null()
        {
            return Err(CallbackFailure::InvalidRequest {
                address: request.address,
                pc: request.pc,
                bytes: request.bytes,
                flags: request.flags,
                attempts: self.attempts,
                completed_bytes: self.prepared.completed_bytes(),
            });
        }
        self.prepared.read().map_err(CallbackFailure::Platform)
    }
}

/// # Safety
/// Native code is the exact validated one-word scalar-load body. `view` and `request`
/// are its live ABI objects; opaque points to this invocation's retained
/// ReadCallback, and request.data is writable private source-width staging
/// quantity disjoint from RAM, architectural state, source and host metadata.
/// The original PE settlement guard already owns prepared RAM/order/source
/// resources before entry and retains them through this callback and commit.
unsafe extern "C" fn reached_read(
    view: *mut MemoryContextView,
    request: *const MemoryRequest,
) -> u32 {
    if view.is_null() {
        return MemoryStatus::InvalidRequest as u32;
    }
    // SAFETY: the closed native-session ABI contract above retains this view.
    let view = unsafe { &mut *view };
    if !view.has_supported_header() || view.opaque.is_null() || request.is_null() {
        view.record(MemoryStatus::InvalidRequest, 0, 0, view.completed_bytes);
        return MemoryStatus::InvalidRequest as u32;
    }
    // SAFETY: only with_view publishes this opaque pointer and the native call
    // returns before its original exclusive callback borrow ends.
    let callback = unsafe { &mut *view.opaque.cast::<ReadCallback<'_, '_, '_>>() };
    // SAFETY: the generated ABI retains its request throughout the callback.
    let request = unsafe { &*request };
    if callback.failure.is_some() {
        view.record(
            MemoryStatus::Unsupported,
            request.address,
            request.pc,
            callback.prepared.completed_bytes(),
        );
        return MemoryStatus::Unsupported as u32;
    }
    // Never unwind through the C ABI. The transaction is a field outside this
    // closure, so catching a producer panic cannot release its Device pin.
    let result = crate::platform::unwind::invoke(core::panic::AssertUnwindSafe(|| {
        callback.dispatch(request)
    }));
    let result = match result {
        Ok(result) => result,
        Err(_) => Err(CallbackFailure::Panicked {
            completed_bytes: callback.prepared.completed_bytes(),
        }),
    };
    match result {
        Ok(value) => {
            // SAFETY: exact bound generated code supplies a private valid
            // staging quantity; all descriptor/source checks passed above.
            let bytes = usize::from(callback.prepared.intent().bytes);
            unsafe {
                core::ptr::copy_nonoverlapping(value.to_le_bytes().as_ptr(), request.data, bytes)
            };
            view.record(
                MemoryStatus::Success,
                request.address,
                request.pc,
                u64::from(callback.prepared.intent().bytes),
            );
            MemoryStatus::Success as u32
        }
        Err(error) => {
            callback.failure = Some(error);
            // Unsupported is only an ABI stop signal. The original typed
            // error and completion survive separately; this is no guest abort.
            view.record(
                MemoryStatus::Unsupported,
                request.address,
                request.pc,
                callback.prepared.completed_bytes(),
            );
            MemoryStatus::Unsupported as u32
        }
    }
}

impl core::fmt::Debug for CallbackFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRequest {
                address,
                pc,
                bytes,
                flags,
                attempts,
                completed_bytes,
            } => f
                .debug_struct("InvalidRequest")
                .field("address", address)
                .field("pc", pc)
                .field("bytes", bytes)
                .field("flags", flags)
                .field("attempts", attempts)
                .field("completed_bytes", completed_bytes)
                .finish(),
            Self::Platform(value) => f.debug_tuple("Platform").field(value).finish(),
            Self::Panicked { completed_bytes } => f
                .debug_struct("Panicked")
                .field("completed_bytes", completed_bytes)
                .finish(),
        }
    }
}
