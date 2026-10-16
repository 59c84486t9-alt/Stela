//! Memory-service callback for the M0 LDP.
use crate::memory::domain::m0_read::{M0RamPairReadPlatformError, M0RamPairReadPrepared};
use stela_compiler::context::memory::{
    MEMORY_CONTEXT_BYTES, MEMORY_CONTEXT_VERSION, MemoryContextView, MemoryRequest, MemoryStatus,
};

const READ_BYTES: u32 = (size_of::<u64>() * 2) as u32;

pub(crate) enum CallbackFailure {
    InvalidRequest {
        address: u64,
        pc: u64,
        bytes: u32,
        flags: u32,
        attempts: u32,
        completed_bytes: u64,
    },
    Platform(M0RamPairReadPlatformError),
    Panicked {
        completed_bytes: u64,
    },
}

pub(super) struct PairReadCallback<'call, 'loan, 'owner> {
    prepared: &'call mut M0RamPairReadPrepared<'loan, 'owner>,
    attempts: u32,
    failure: Option<CallbackFailure>,
    values: Option<[u64; 2]>,
}

impl<'call, 'loan, 'owner> PairReadCallback<'call, 'loan, 'owner> {
    pub(super) fn new(prepared: &'call mut M0RamPairReadPrepared<'loan, 'owner>) -> Self {
        Self {
            prepared,
            attempts: 0,
            failure: None,
            values: None,
        }
    }

    /// Scopes the stack view; the session makes the native call.
    pub(super) fn with_view<R>(&mut self, call: impl FnOnce(&mut MemoryContextView) -> R) -> R {
        let mut view = MemoryContextView {
            version: MEMORY_CONTEXT_VERSION,
            bytes: MEMORY_CONTEXT_BYTES,
            callback: reached_pair_read,
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

    pub(super) fn values(&self) -> Option<[u64; 2]> {
        self.values
    }

    fn dispatch(&mut self, request: &MemoryRequest) -> Result<[u64; 2], CallbackFailure> {
        self.attempts = self.attempts.saturating_add(1);
        let intent = self.prepared.intent();
        if self.attempts != 1
            || request.address != intent.raw_address
            || request.pc != intent.source_pc.0
            || request.bytes != READ_BYTES
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
        self.prepared.read().map_err(CallbackFailure::Platform)
    }
}

/// # Safety
/// The native code is the validated LDP body. `view` and `request` are its live
/// ABI objects; `opaque` points to this call's PairReadCallback, and
/// `request.data` is writable private 16-byte staging, disjoint from RAM,
/// architectural state, source and host metadata. The PE's guard holds the
/// prepared RAM, ordering and source resources from before entry until commit.
unsafe extern "C" fn reached_pair_read(
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
    let callback = unsafe { &mut *view.opaque.cast::<PairReadCallback<'_, '_, '_>>() };
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
            completed_bytes: callback.prepared.progress().completed_bytes,
        }),
    };
    match result {
        Ok(values) => {
            // SAFETY: exact bound generated code supplies a private valid
            // staging quantity; all descriptor/source checks passed above.
            for (index, value) in values.into_iter().enumerate() {
                // SAFETY: the exact checked pair ABI reserves both private words.
                unsafe {
                    request
                        .data
                        .add(index * size_of::<u64>())
                        .cast::<u64>()
                        .write_unaligned(value.to_le())
                };
            }
            callback.values = Some(values);
            view.record(
                MemoryStatus::Success,
                request.address,
                request.pc,
                READ_BYTES.into(),
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
            Self::Panicked { completed_bytes } => f
                .debug_struct("Panicked")
                .field("completed_bytes", completed_bytes)
                .finish(),
        }
    }
}
