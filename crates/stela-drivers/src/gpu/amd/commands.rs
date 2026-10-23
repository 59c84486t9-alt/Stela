//! Bounded native AMD compute command encoding. This does not initialize a GPU,
//! submit work or expose a Metal device. The native device owner supplies real
//! device information and owns residency, scratch, barriers and completion.
use core::{ffi::c_void, marker::PhantomData, ptr::NonNull};

/// Number of compute user SGPRs represented by the native command interface.
pub const COMPUTE_USER_SGPRS: usize = 16;

/// Native shader configuration from the AMD compiler, with its resident GPU VA.
/// The native owner must validate hardware limits and maintain shader/resource
/// lifetimes through completion before submitting these encoded commands.
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputePipeline {
    pub program_va: u64,
    pub rsrc1: u32,
    pub rsrc2: u32,
    pub rsrc3: u32,
    pub resource_limits: u32,
    pub block_size: [u32; 3],
    pub wave_size: u32,
    pub user_sgpr_count: u32,
    pub user_sgprs: [u32; COMPUTE_USER_SGPRS],
}

/// Direct compute dispatch, starting at zero. All-zero or partially zero grids
/// encode no work. Setting `threads` permits a partial final threadgroup.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ComputeDispatch {
    pub size: [u32; 3],
    pub threads: bool,
    pub ordered: bool,
    /// Enable only if the native queue owner has permitted tunneling.
    pub tunnel: bool,
}

/// Native compute queue preamble. Border colors must remain GPU-resident while
/// used. Unsupported generation-specific settings return an explicit error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ComputePreamble {
    pub border_color_va: u64,
    pub dispatch_interleave: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandError {
    Invalid,
    Unsupported,
    BufferTooSmall {
        required: usize,
    },
    /// The C ABI uses a 32-bit dword count.
    CapacityTooLarge,
    /// A linked encoder violated the native result contract.
    InvalidResult,
}

/// Borrows the immutable native `radeon_info` produced by device initialization.
/// Command buffers are CPU data until separately validated and submitted by the
/// native queue owner. This type does not authorize hardware access.
pub struct ComputeEncoder<'a> {
    info: NonNull<c_void>,
    _borrow: PhantomData<&'a c_void>,
}

impl<'a> ComputeEncoder<'a> {
    /// Borrow the initialized device owner's native Mesa `radeon_info`.
    ///
    /// # Safety
    ///
    /// `info` must point to a live, aligned, fully initialized `radeon_info` from
    /// the exact linked Mesa build. It must remain readable and immutable for
    /// `'a`, including against concurrent C access. Its capabilities must describe
    /// the actual initialized device. The pointer is never retained by C beyond
    /// an encoding call. A PCI identity alone cannot satisfy this contract.
    /// Encoding tests may borrow immutable native model fixtures, which do not
    /// authorize submission or qualify hardware support.
    pub unsafe fn borrow_initialized(info: *const c_void) -> Result<Self, CommandError> {
        Ok(Self {
            info: NonNull::new(info.cast_mut()).ok_or(CommandError::Invalid)?,
            _borrow: PhantomData,
        })
    }

    /// Encode the actual generation-specific compute queue setup. An empty
    /// output slice requests the required size through `BufferTooSmall`.
    pub fn preamble(
        &self,
        preamble: ComputePreamble,
        output: &mut [u32],
    ) -> Result<usize, CommandError> {
        self.encode(output, |output, capacity, written| {
            // SAFETY: the constructor borrows valid immutable native device
            // information; encode supplies a unique writable slice and count.
            unsafe {
                stela_amd_compute_preamble_native(
                    self.info.as_ptr(),
                    preamble.border_color_va,
                    preamble.dispatch_interleave,
                    output,
                    capacity,
                    written,
                )
            }
        })
    }

    /// Encode compiler resource configuration and user SGPRs. A dispatch must
    /// follow the appropriate queue preamble and this pipeline configuration.
    pub fn pipeline(
        &self,
        pipeline: &ComputePipeline,
        output: &mut [u32],
    ) -> Result<usize, CommandError> {
        self.encode(output, |output, capacity, written| {
            // SAFETY: the borrowed native info and repr(C) pipeline are valid;
            // encode supplies a unique writable slice and count.
            unsafe {
                stela_amd_compute_pipeline(self.info.as_ptr(), pipeline, output, capacity, written)
            }
        })
    }

    /// Encode a direct dispatch. Invalid inputs and insufficient capacity leave
    /// the output unchanged. Zero work succeeds with zero dwords written.
    pub fn dispatch(
        &self,
        pipeline: &ComputePipeline,
        dispatch: ComputeDispatch,
        output: &mut [u32],
    ) -> Result<usize, CommandError> {
        self.encode(output, |output, capacity, written| {
            // SAFETY: repr(C) inputs are initialized for the entire C call;
            // encode supplies a unique writable slice and count.
            unsafe {
                stela_amd_compute_dispatch(
                    self.info.as_ptr(),
                    pipeline,
                    &dispatch,
                    output,
                    capacity,
                    written,
                )
            }
        })
    }

    fn encode(
        &self,
        output: &mut [u32],
        call: impl FnOnce(*mut u32, u32, *mut u32) -> u32,
    ) -> Result<usize, CommandError> {
        let capacity = u32::try_from(output.len()).map_err(|_| CommandError::CapacityTooLarge)?;
        let mut written = 0;
        let status = call(output.as_mut_ptr(), capacity, &mut written);
        let written = written as usize;
        match status {
            0 if written <= output.len() => Ok(written),
            1 if written == 0 => Err(CommandError::Invalid),
            2 if written == 0 => Err(CommandError::Unsupported),
            3 if written > output.len() => Err(CommandError::BufferTooSmall { required: written }),
            _ => Err(CommandError::InvalidResult),
        }
    }
}

unsafe extern "C" {
    fn stela_amd_compute_preamble_native(
        info: *const c_void,
        border_color_va: u64,
        dispatch_interleave: u32,
        output: *mut u32,
        capacity: u32,
        written: *mut u32,
    ) -> u32;
    fn stela_amd_compute_pipeline(
        info: *const c_void,
        pipeline: *const ComputePipeline,
        output: *mut u32,
        capacity: u32,
        written: *mut u32,
    ) -> u32;
    fn stela_amd_compute_dispatch(
        info: *const c_void,
        pipeline: *const ComputePipeline,
        dispatch: *const ComputeDispatch,
        output: *mut u32,
        capacity: u32,
        written: *mut u32,
    ) -> u32;
}

// hosted/commands.h independently asserts the corresponding C layouts.
const _: () = {
    assert!(core::mem::size_of::<ComputePipeline>() == 112);
    assert!(core::mem::align_of::<ComputePipeline>() == 8);
    assert!(core::mem::offset_of!(ComputePipeline, block_size) == 24);
    assert!(core::mem::offset_of!(ComputePipeline, wave_size) == 36);
    assert!(core::mem::offset_of!(ComputePipeline, user_sgprs) == 44);
    assert!(core::mem::size_of::<ComputeDispatch>() == 16);
    assert!(core::mem::offset_of!(ComputeDispatch, threads) == 12);
    assert!(core::mem::offset_of!(ComputeDispatch, ordered) == 13);
    assert!(core::mem::offset_of!(ComputeDispatch, tunnel) == 14);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::ffi::c_void;

    #[link(name = "stela-amd-commands-test", kind = "static")]
    unsafe extern "C" {
        fn stela_amd_test_info() -> *const c_void;
    }

    fn encoder() -> ComputeEncoder<'static> {
        // SAFETY: the C fixture returns a static, fully initialized immutable
        // radeon_info from the linked Mesa build, for command encoding tests only.
        unsafe { ComputeEncoder::borrow_initialized(stela_amd_test_info()) }.unwrap()
    }

    fn pipeline() -> ComputePipeline {
        ComputePipeline {
            program_va: 0x1234_0200_0000,
            rsrc1: 0x13579,
            rsrc2: 0x24680,
            rsrc3: 0,
            resource_limits: 0x456,
            block_size: [8, 4, 2],
            wave_size: 32,
            user_sgpr_count: 0,
            user_sgprs: [0; COMPUTE_USER_SGPRS],
        }
    }

    #[test]
    fn rust_facade_calls_real_native_encoders_and_reports_capacity() {
        let encoder = encoder();
        let mut output = [0xa5a5_a5a5; 128];
        let preamble = ComputePreamble {
            border_color_va: 0x10_0000,
            dispatch_interleave: 256,
        };
        let Err(CommandError::BufferTooSmall { required }) = encoder.preamble(preamble, &mut [])
        else {
            panic!("expected a preamble size query");
        };
        assert_eq!(encoder.preamble(preamble, &mut output).unwrap(), required);
        assert!(encoder.pipeline(&pipeline(), &mut output).unwrap() > 0);
        let dispatch = ComputeDispatch {
            size: [19, 7, 3],
            threads: true,
            ordered: false,
            tunnel: false,
        };
        let written = encoder
            .dispatch(&pipeline(), dispatch, &mut output)
            .unwrap();
        // Independent DISPATCH_DIRECT packet check; generation-specific register
        // writes precede it. Nonuniform thread grids round up to complete groups.
        assert_eq!(&output[written - 5..written - 1], &[0xc003_1502, 3, 2, 2]);
        assert_ne!(output[written - 1] & (1 << 1), 0);
        assert_ne!(output[written - 1] & (1 << 15), 0);
    }

    #[test]
    fn errors_and_zero_work_preserve_the_output() {
        let encoder = encoder();
        let mut output = [0x3c3c_3c3c; 128];
        let original = output;
        assert!(matches!(
            encoder.pipeline(&pipeline(), &mut output[..1]),
            Err(CommandError::BufferTooSmall { required: 2.. })
        ));
        assert_eq!(output, original);
        let mut shader = pipeline();
        shader.program_va += 1;
        assert_eq!(
            encoder.pipeline(&shader, &mut output),
            Err(CommandError::Invalid)
        );
        assert_eq!(output, original);
        assert_eq!(
            encoder.preamble(
                ComputePreamble {
                    dispatch_interleave: 7,
                    ..Default::default()
                },
                &mut output
            ),
            Err(CommandError::Invalid)
        );
        let dispatch = ComputeDispatch {
            size: [0, 1, 1],
            threads: false,
            ordered: true,
            tunnel: false,
        };
        assert_eq!(encoder.dispatch(&pipeline(), dispatch, &mut output), Ok(0));
        assert_eq!(output, original);
    }

    #[test]
    fn null_native_info_is_rejected_before_ffi() {
        // SAFETY: the null pointer is rejected without dereferencing it.
        assert!(matches!(
            unsafe { ComputeEncoder::borrow_initialized(core::ptr::null()) },
            Err(CommandError::Invalid)
        ));
    }
}
