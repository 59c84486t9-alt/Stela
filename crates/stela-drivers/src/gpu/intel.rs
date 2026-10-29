//! Native Intel packet construction using kept Xe and i915 emitters. This module
//! does not initialize a device, map GPU memory, submit jobs or expose Metal.
use core::marker::PhantomData;

pub mod activation;
pub mod ct_storage;
pub mod firmware;
pub mod ggtt;
pub mod guc_reset;
pub mod pat;
pub mod wopcm;

/// The VM's supported width, supplied by the device/VM owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AddressBits {
    Bits48 = 48,
    Bits57 = 57,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpace {
    Global,
    PerProcess,
}

/// The kept i915 packet form selected by the engine policy. This
/// enum is not a device-support or Metal-feature declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum I915BatchEncoding {
    Gen4 = 4,
    Gen6 = 6,
    Haswell = 75,
    Gen8 = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    InvalidArgument,
    NoSpace,
    Native(i32),
}

/// Exact shader/resource policy for a direct Gen12.5+ COMPUTE_WALKER. This is
/// a packet input, not device validation. The physical owner supplies
/// installed state bases, CFE/scratch, mappings/lifetimes, limits, cache policy,
/// async throttling and workarounds. Encoded fields come from the original
/// hosted Intel helpers and the selected compiled binary. Push-bearing shaders,
/// indirect/predicated/partitioned dispatch and completion writes are unsupported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ComputeDispatch {
    pub gfx_verx10: u32,
    pub local_size: [u32; 3],
    pub simd_size: u32,
    pub threads: u32,
    pub right_mask: u32,
    pub groups: [u32; 3],
    /// Selected kernel's offset from instruction state base, aligned 64.
    pub kernel_offset: u32,
    /// Offset from the installed surface state base, aligned 32.
    pub binding_table_offset: u32,
    /// Hardware prefetch hint, not the complete runtime resource table extent.
    pub binding_table_entry_count: u32,
    pub sampler_offset: u32,
    pub sampler_count: u32,
    pub slm_encoding: u32,
    pub preferred_slm_encoding: u32,
    pub barrier_encoding: u32,
    pub thread_group_dispatch_size: u32,
    pub register_blocks: u32,
    pub generate_local_id: u32,
    pub walk_order: u32,
    pub uses_sampler: u32,
    pub post_sync_mocs: u32,
    /// The total compiled push requirement; this path requires zero.
    pub push_bytes: u32,
}

#[repr(C)]
struct NativeCommands {
    words: *mut u32,
    capacity: usize,
    used: usize,
    address_bits: u32,
}

unsafe extern "C" {
    fn stela_intel_batch_start(commands: *mut NativeCommands, address: u64, ppgtt: bool) -> i32;
    fn stela_intel_store_qword(commands: *mut NativeCommands, address: u64, value: u64) -> i32;
    fn stela_intel_batch_end(commands: *mut NativeCommands) -> i32;
    fn stela_intel_user_interrupt(commands: *mut NativeCommands) -> i32;
    fn stela_intel_i915_batch_start(
        commands: *mut NativeCommands,
        encoding: u32,
        address: u64,
        secure: bool,
        no_preempt: bool,
    ) -> i32;
    fn stela_intel_compute_dispatch(
        commands: *mut NativeCommands,
        dispatch: *const ComputeDispatch,
    ) -> i32;
}

/// Exclusively borrowed CPU storage for Intel command packets. C receives
/// native pointers only during a method call and keeps none. Storage may be
/// ordinary RAM; its physical placement and DMA visibility are the queue owner's
/// responsibility. Completion of these methods establishes no GPU execution.
pub struct CommandBuffer<'a> {
    native: NativeCommands,
    _storage: PhantomData<&'a mut [u32]>,
}

impl<'a> CommandBuffer<'a> {
    pub fn new(storage: &'a mut [u32], address_bits: AddressBits) -> Self {
        Self {
            native: NativeCommands {
                words: storage.as_mut_ptr(),
                capacity: storage.len(),
                used: 0,
                address_bits: address_bits as u32,
            },
            _storage: PhantomData,
        }
    }

    /// Append a batch-start packet. Addresses use the low VM address bits;
    /// canonical conversion and mapping validation belong to the VM owner.
    pub fn batch_start(&mut self, address: u64, space: AddressSpace) -> Result<(), CommandError> {
        // SAFETY: storage is exclusively borrowed, its bounds fit usize, and
        // the C function validates the complete packet before writing it.
        result(unsafe {
            stela_intel_batch_start(
                &mut self.native,
                address,
                matches!(space, AddressSpace::PerProcess),
            )
        })
    }

    /// Append an immediate qword store. The packet requires an 8-byte aligned
    /// address below 2^48 even when the VM itself supports 57-bit addresses.
    pub fn store_qword(&mut self, address: u64, value: u64) -> Result<(), CommandError> {
        // SAFETY: same exclusive bounded storage contract as batch_start.
        result(unsafe { stela_intel_store_qword(&mut self.native, address, value) })
    }

    /// Append an older i915 batch packet using the engine owner's selected
    /// form. Gen4/6/Haswell use 32-bit addresses and Gen8 uses 48-bit addresses,
    /// all aligned to 8 bytes. `secure` is a trusted owner's privileged selector;
    /// the runtime must not let untrusted input choose it. `no_preempt` applies
    /// only to Gen8, whose request teardown must eventually restore arbitration.
    /// No context setup, flush, workarounds or submission are synthesized here.
    pub fn i915_batch_start(
        &mut self,
        encoding: I915BatchEncoding,
        address: u64,
        secure: bool,
        no_preempt: bool,
    ) -> Result<(), CommandError> {
        // SAFETY: the borrowed slice remains exclusive and live for this
        // call. Native validation checks all bounds before any packet write.
        result(unsafe {
            stela_intel_i915_batch_start(
                &mut self.native,
                encoding as u32,
                address,
                secure,
                no_preempt,
            )
        })
    }

    pub fn batch_end(&mut self) -> Result<(), CommandError> {
        // SAFETY: same exclusive bounded storage contract as batch_start.
        result(unsafe { stela_intel_batch_end(&mut self.native) })
    }

    /// Append the original native COMPUTE_WALKER encoding. Validates packet
    /// bounds before modifying storage; does not initialize or submit a queue.
    pub fn compute_dispatch(&mut self, dispatch: &ComputeDispatch) -> Result<(), CommandError> {
        // SAFETY: the slice is exclusively borrowed for this call, the input
        // has the asserted C layout, and C keeps neither pointer.
        result(unsafe { stela_intel_compute_dispatch(&mut self.native, dispatch) })
    }

    /// Append Xe's user interrupt and arbitration sequence. Interrupt routing
    /// and delivery still require the real engine and interrupt owner.
    pub fn user_interrupt(&mut self) -> Result<(), CommandError> {
        // SAFETY: same exclusive bounded storage contract as batch_start.
        result(unsafe { stela_intel_user_interrupt(&mut self.native) })
    }

    pub fn words(&self) -> &[u32] {
        // SAFETY: native calls preserve used <= capacity and the storage
        // borrow outlives self. Shared access excludes a concurrent mutation.
        unsafe { core::slice::from_raw_parts(self.native.words, self.native.used) }
    }

    pub fn remaining(&self) -> usize {
        self.native.capacity - self.native.used
    }
}

fn result(status: i32) -> Result<(), CommandError> {
    match status {
        0 => Ok(()),
        -22 => Err(CommandError::InvalidArgument),
        -28 => Err(CommandError::NoSpace),
        other => Err(CommandError::Native(other)),
    }
}

const _: () = {
    assert!(size_of::<ComputeDispatch>() == 25 * size_of::<u32>());
    assert!(core::mem::offset_of!(ComputeDispatch, groups) == 7 * size_of::<u32>());
    assert!(core::mem::offset_of!(ComputeDispatch, push_bytes) == 24 * size_of::<u32>());
    assert!(core::mem::offset_of!(NativeCommands, capacity) == size_of::<usize>());
    assert!(core::mem::offset_of!(NativeCommands, used) == 2 * size_of::<usize>());
    assert!(core::mem::offset_of!(NativeCommands, address_bits) == 3 * size_of::<usize>());
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_calls_preserve_the_rust_storage_borrow_and_atomic_errors() {
        let mut storage = [0xa5a5_a5a5; 8];
        {
            let mut commands = CommandBuffer::new(&mut storage, AddressBits::Bits57);
            assert_eq!(
                commands.batch_start(1 << 56, AddressSpace::PerProcess),
                Ok(())
            );
            let before = commands.words().to_vec();
            assert_eq!(
                commands.store_qword(1 << 48, 42),
                Err(CommandError::InvalidArgument)
            );
            assert_eq!(commands.words(), before);
            assert_eq!(commands.store_qword(0x2000, 42), Ok(()));
            assert_eq!(commands.batch_end(), Err(CommandError::NoSpace));
            assert_eq!(commands.remaining(), 0);
            assert_eq!(commands.words().len(), 8);
        }
        assert_eq!(
            storage,
            [0x18800101, 0, 0x01000000, 0x10200003, 0x2000, 0, 42, 0]
        );
    }

    #[test]
    fn empty_storage_stays_empty_and_errors_remain_distinct() {
        let mut storage = [];
        let mut commands = CommandBuffer::new(&mut storage, AddressBits::Bits48);
        assert_eq!(commands.user_interrupt(), Err(CommandError::NoSpace));
        assert_eq!(commands.remaining(), 0);
        assert!(commands.words().is_empty());
        assert_eq!(result(-123), Err(CommandError::Native(-123)));
    }

    #[test]
    fn i915_encoding_uses_actual_native_packet_and_range_checks() {
        let mut storage = [0xa5a5_a5a5; 8];
        let mut commands = CommandBuffer::new(&mut storage, AddressBits::Bits48);
        assert_eq!(
            commands.i915_batch_start(I915BatchEncoding::Haswell, 1 << 32, false, false),
            Err(CommandError::InvalidArgument)
        );
        assert!(commands.words().is_empty());
        assert_eq!(
            commands.i915_batch_start(I915BatchEncoding::Haswell, 0x2000, false, false),
            Ok(())
        );
        assert_eq!(
            commands.i915_batch_start(I915BatchEncoding::Gen8, 0x1234_5678_9000, false, false),
            Ok(())
        );
        assert_eq!(
            commands.words(),
            [
                0x18802100, 0x2000, 0x04000001, 0x18800101, 0x56789000, 0x1234, 0x04000000, 0
            ]
        );
        assert_eq!(commands.remaining(), 0);
    }

    #[test]
    fn compute_dispatch_uses_bounded_native_encoder_without_submission() {
        let mut storage = [0xa5a5_a5a5; 44];
        let mut commands = CommandBuffer::new(&mut storage, AddressBits::Bits57);
        let mut dispatch = ComputeDispatch {
            gfx_verx10: 300,
            local_size: [32, 1, 1],
            simd_size: 16,
            threads: 2,
            right_mask: 0xffff,
            groups: [2, 3, 4],
            kernel_offset: 0x1000,
            binding_table_offset: 0x2000,
            binding_table_entry_count: 1,
            sampler_offset: 0,
            sampler_count: 0,
            slm_encoding: 0,
            preferred_slm_encoding: 0,
            barrier_encoding: 0,
            thread_group_dispatch_size: 0,
            register_blocks: 0,
            generate_local_id: 0,
            walk_order: 0,
            uses_sampler: 0,
            post_sync_mocs: 2,
            push_bytes: 32,
        };
        assert_eq!(
            commands.compute_dispatch(&dispatch),
            Err(CommandError::Native(-95))
        );
        assert!(commands.words().is_empty());
        dispatch.push_bytes = 0;
        dispatch.post_sync_mocs = 0;
        assert_eq!(
            commands.compute_dispatch(&dispatch),
            Err(CommandError::InvalidArgument)
        );
        assert!(commands.words().is_empty());
        dispatch.post_sync_mocs = 2;
        assert_eq!(commands.compute_dispatch(&dispatch), Ok(()));
        assert_eq!(commands.words().len(), 40);
        assert_eq!(commands.words()[0] & 0xff, 38);
        assert_eq!(commands.words()[19], 0x1000);
        assert_eq!(
            commands.compute_dispatch(&dispatch),
            Err(CommandError::NoSpace)
        );
        assert_eq!(commands.words().len(), 40);
    }
}
