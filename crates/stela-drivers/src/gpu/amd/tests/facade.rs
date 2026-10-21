#![no_std]
#[path = "../../amd.rs"]
pub mod amd;
use amd::*;
use core::ffi::c_void;

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
    let Err(CommandError::BufferTooSmall { required }) = encoder.preamble(preamble, &mut []) else {
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
