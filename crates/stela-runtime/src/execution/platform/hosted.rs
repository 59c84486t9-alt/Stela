//! Native code mappings on x86-64 macOS and Linux.
use crate::execution::native_image::{ExecutableStorage, NativeImage};
use anyhow::{Context, Result, ensure};
use core::{convert::Infallible, ptr::NonNull};
use stela_compiler::GuestState;

pub(crate) type StorageError = Infallible;

pub fn ensure_supported() -> Result<()> {
    // Every x86-64 CPU implements Stela's integer and SSE2 baseline.
    // Mac x86-64 and Linux x86-64 both use the required System V C ABI.
    Ok(())
}

#[derive(Debug)]
pub struct Mapping {
    pointer: NonNull<u8>,
    length: usize,
}

impl Mapping {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        ensure!(!bytes.is_empty(), "cannot map empty native code");
        // SAFETY: Request fresh anonymous private RW storage. MAP_FAILED is
        // checked before the pointer is used. Never request executable RW.
        let pointer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                bytes.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("allocate RW native code");
        }
        let Some(pointer) = NonNull::new(pointer.cast::<u8>()) else {
            // Address zero cannot back a Rust NonNull mapping, even if an OS
            // were to honor it. Release the successful OS allocation first.
            unsafe { libc::munmap(pointer, bytes.len()) };
            anyhow::bail!("OS returned an unusable null native mapping");
        };
        let mapping = Self {
            pointer,
            length: bytes.len(),
        };
        // SAFETY: mmap returned at least length fresh RW bytes, disjoint from
        // the input Vec, and this mapping has not escaped.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), mapping.pointer.as_ptr(), bytes.len());
        }
        // SAFETY: the whole mapping is initialized. The OS switches it from
        // RW to RX atomically, and x86 instruction and data caches are
        // coherent.
        let result = unsafe {
            libc::mprotect(
                mapping.pointer.as_ptr().cast(),
                mapping.length,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };
        if result != 0 {
            // mapping's Drop releases memory on this error path too.
            return Err(std::io::Error::last_os_error()).context("protect native code RX");
        }
        Ok(mapping)
    }

    pub unsafe fn call(&self, state: &mut GuestState) -> Result<()> {
        // SAFETY: the mapping is still owned and the caller upholds the
        // leaf ABI.
        let reached = match unsafe { NativeImage::borrow(self).call(state) } {
            Ok(reached) => reached,
            Err(never) => match never {},
        };
        reached.into_infallible();
        Ok(())
    }

    pub unsafe fn call_context_block(
        &self,
        state: &mut GuestState,
        context: &mut stela_compiler::context::ExecutionContext,
    ) -> Result<stela_compiler::block::BlockExit> {
        // SAFETY: the mapping and the block's context stay borrowed for
        // this synchronous call.
        let reached = match unsafe { self.call_context_block_observed(state, context) } {
            Ok(reached) => reached,
            Err(never) => match never {},
        };
        Ok(reached.into_infallible())
    }

    /// Call the two-argument context-leaf ABI. Architectural failures are
    /// recorded in the memory view, never inferred from RAX.
    pub unsafe fn call_context(
        &self,
        state: &mut GuestState,
        context: &mut stela_compiler::context::ExecutionContext,
    ) -> Result<()> {
        // SAFETY: The context entry owns the checked source/profile and
        // validates its live borrowed views before this synchronous call.
        let function: unsafe extern "sysv64" fn(
            *mut GuestState,
            *mut stela_compiler::context::ExecutionContext,
        ) = unsafe { core::mem::transmute(self.pointer.as_ptr()) };
        unsafe { function(state, context) };
        Ok(())
    }

    /// Keep the native result alongside the storage check. Err is a refusal
    /// before the call; hosted storage cannot fail.
    ///
    /// # Safety
    /// The source, native code, ABI, map, requirements and context must be
    /// bound. A PE may call only from its session, which holds the thread,
    /// system state, backend, source and domain through this call, the
    /// context finalization and PC settlement.
    pub(crate) unsafe fn call_context_block_observed(
        &self,
        state: &mut GuestState,
        context: &mut stela_compiler::context::ExecutionContext,
    ) -> core::result::Result<
        crate::execution::ObservedNativeCall<stela_compiler::block::BlockExit, Infallible>,
        Infallible,
    > {
        // SAFETY: the mapping stays borrowed, and the caller upholds the
        // execution contract.
        unsafe { NativeImage::borrow(self).call_context_block(state, context) }
    }

    /// Call the resident-budget block ABI. The budget bounds execution.
    ///
    /// # Safety
    /// The caller binds the source, ABI, target and register bank. Resident
    /// loops are non-faulting integer code; a fallback has the ordinary
    /// call's memory, fault and target requirements. Not for asynchronous
    /// producer domains or checked, system or threaded entry.
    pub unsafe fn call_budgeted_block(
        &self,
        state: &mut GuestState,
        budget: &mut stela_compiler::block::loop_budget::LoopBudget,
    ) -> Result<stela_compiler::block::BlockExit> {
        // SAFETY: the mapping, register bank and budget stay borrowed
        // through the call.
        let reached = match unsafe { NativeImage::borrow(self).call_budgeted_block(state, budget) }
        {
            Ok(reached) => reached,
            Err(never) => match never {},
        };
        Ok(reached.into_infallible())
    }

    /// The native result and storage check for the one-pointer block ABI.
    /// The PE's session must hold its state, source and domain through
    /// settlement.
    pub(crate) unsafe fn call_block_observed(
        &self,
        state: &mut GuestState,
    ) -> core::result::Result<
        crate::execution::ObservedNativeCall<stela_compiler::block::BlockExit, Infallible>,
        Infallible,
    > {
        // SAFETY: the caller upholds the source, profile, ABI and map, and
        // the session contract.
        unsafe { NativeImage::borrow(self).call_block(state) }
    }

    pub unsafe fn call_block(
        &self,
        state: &mut GuestState,
    ) -> Result<stela_compiler::block::BlockExit> {
        // SAFETY: the caller upholds the struct-return ABI and the
        // direct-RAM contract.
        let reached = match unsafe { self.call_block_observed(state) } {
            Ok(reached) => reached,
            Err(never) => match never {},
        };
        Ok(reached.into_infallible())
    }

    /// Call the AMX kernel at `offset` in this library image.
    ///
    /// # Safety
    /// As for `NativeImage::call_amx_kernel`.
    pub(crate) unsafe fn call_amx_kernel(
        &self,
        offset: usize,
        z: *mut u8,
        x: *const u8,
        y: *const u8,
        row: u64,
    ) -> Result<()> {
        ensure!(
            offset < self.length,
            "AMX kernel offset outside its library"
        );
        // SAFETY: the mapping stays borrowed and the caller upholds the
        // kernel ABI.
        let reached =
            match unsafe { NativeImage::borrow(self).call_amx_kernel(offset, z, x, y, row) } {
                Ok(reached) => reached,
                Err(never) => match never {},
            };
        reached.into_infallible();
        Ok(())
    }

    #[cfg(test)]
    pub fn address(&self) -> usize {
        self.pointer.as_ptr() as usize
    }
}

// SAFETY: Mapping::new exclusively owns fresh initialized mmap storage,
// atomically transitioned to RX. Its pointer never escapes. All calls borrow
// self; no unmap or writable alias can coexist through safe runtime APIs.
// Host ownership is infallible to retain, so no fallible frame postcheck is
// invented for this implementation. Guest ABI/PE admission stays at callsite.
unsafe impl ExecutableStorage for Mapping {
    type Error = Infallible;
    fn entry(&self) -> NonNull<u8> {
        self.pointer
    }
    fn revalidate(&self) -> core::result::Result<(), Self::Error> {
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the mapping is uniquely owned and no pointer into it
        // escapes; calls borrow `self`, so none outlives Drop.
        unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.length) };
    }
}
