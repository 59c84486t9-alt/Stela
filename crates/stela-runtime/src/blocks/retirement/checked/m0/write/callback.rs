//! Memory-service callback for the M0 scalar store or STP.
use crate::memory::domain::physical::{
    M0RamWritePlatformError, M0RamWritePrepared, M0RamWriteProgress,
};
use stela_compiler::context::memory::{
    MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest, MemoryStatus,
};

const MEMBER_BYTES: usize = size_of::<u64>();

pub(crate) enum CallbackFailure {
    InvalidRequest {
        address: u64,
        pc: u64,
        bytes: u32,
        flags: u32,
        attempts: u32,
        completed_bytes: u64,
    },
    Platform(M0RamWritePlatformError),
    Panicked {
        progress: M0RamWriteProgress,
    },
}

pub(super) struct WriteCallback<'call, 'loan, 'owner> {
    prepared: &'call mut M0RamWritePrepared<'loan, 'owner>,
    attempts: u32,
    failure: Option<CallbackFailure>,
}

impl<'call, 'loan, 'owner> WriteCallback<'call, 'loan, 'owner> {
    pub(super) fn new(prepared: &'call mut M0RamWritePrepared<'loan, 'owner>) -> Self {
        Self {
            prepared,
            attempts: 0,
            failure: None,
        }
    }

    /// Scopes the stack view; the session makes the native call.
    pub(super) fn with_view<R>(&mut self, call: impl FnOnce(&mut MemoryContextView) -> R) -> R {
        let mut view = MemoryContextView {
            version: MEMORY_CONTEXT_VERSION,
            bytes: MEMORY_CONTEXT_BYTES,
            callback: reached_write,
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

    fn dispatch(&mut self, request: &MemoryRequest) -> Result<(), CallbackFailure> {
        self.attempts = self.attempts.saturating_add(1);
        let intent = self.prepared.intent();
        if self.attempts != 1
            || request.address != intent.raw_address
            || request.pc != intent.source_pc.0
            || u64::from(request.bytes) != intent.bytes()
            || request.flags != intent.flags
            || request.data.is_null()
        {
            return Err(CallbackFailure::InvalidRequest {
                address: request.address,
                pc: request.pc,
                bytes: request.bytes,
                flags: request.flags,
                attempts: self.attempts,
                completed_bytes: self.prepared.progress().completed_bytes,
            });
        }
        // SAFETY: the generated body supplies private staging for this
        // request. Every staged value is checked before any physical effect.
        if !unsafe { staged_values_match(intent, request.data) } {
            return Err(CallbackFailure::InvalidRequest {
                address: request.address,
                pc: request.pc,
                bytes: request.bytes,
                flags: request.flags,
                attempts: self.attempts,
                completed_bytes: self.prepared.progress().completed_bytes,
            });
        }
        self.prepared.attempt().map_err(CallbackFailure::Platform)
    }
}

/// Whether the private staging holds the intent's values.
///
/// # Safety
/// `data` is the request's private staging: one u64 per member, even when a
/// narrow store publishes only its low bytes.
unsafe fn staged_values_match(
    intent: crate::memory::domain::m0_write::M0WriteIntent,
    data: *const u8,
) -> bool {
    (0..intent.member_count()).all(|index| {
        // SAFETY: guaranteed by the caller.
        let value = unsafe {
            data.add(index * MEMBER_BYTES)
                .cast::<u64>()
                .read_unaligned()
        };
        u64::from_le(value) == intent.data[index]
    })
}

/// # Safety
/// The native code is the validated scalar store or X-register STP body.
/// `view` and `request` are its live ABI objects; `opaque` points to this
/// call's WriteCallback, and `request.data` is readable private 8- or 16-byte
/// staging, disjoint from RAM,
/// architectural state, source and host metadata. The PE's guard holds the
/// prepared RAM, ordering and source resources from before entry until commit.
unsafe extern "sysv64" fn reached_write(
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
    // SAFETY: only `with_view` publishes this pointer, and the native call
    // returns before its exclusive borrow ends.
    let callback = unsafe { &mut *view.opaque.cast::<WriteCallback<'_, '_, '_>>() };
    // SAFETY: the generated ABI retains its request throughout the callback.
    let request = unsafe { &*request };
    if callback.failure.is_some() {
        view.record(
            MemoryStatus::Unsupported,
            request.address,
            request.pc,
            callback.prepared.progress().completed_bytes,
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
            progress: callback.prepared.progress(),
        }),
    };
    match result {
        Ok(()) => {
            view.record(
                MemoryStatus::Success,
                request.address,
                request.pc,
                callback.prepared.progress().completed_bytes,
            );
            MemoryStatus::Success as u32
        }
        Err(error) => {
            callback.failure = Some(error);
            // Unsupported only tells the native code to stop; the typed error
            // and completion are kept separately. It is not a guest abort.
            view.record(
                MemoryStatus::Unsupported,
                request.address,
                request.pc,
                callback.prepared.progress().completed_bytes,
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
            Self::Panicked { progress } => f
                .debug_struct("Panicked")
                .field("progress", progress)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests;
