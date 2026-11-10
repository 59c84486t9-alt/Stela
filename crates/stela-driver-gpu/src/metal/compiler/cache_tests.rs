//! The compiler's caches and deferred compilations, over a service that
//! counts its calls.
extern crate std;

use super::*;
use crate::metal::{
    library::tests::fixture,
    nvidia::{CHIPS, fixture::nvk},
};
use alloc::vec;
use core::cell::Cell;

std::thread_local! {
    /// Reflections, compilations and releases the service made.
    static CALLS: Cell<(u32, u32, u32)> = const { Cell::new((0, 0, 0)) };
}

fn calls() -> (u32, u32, u32) {
    CALLS.get()
}

unsafe extern "C" fn reflect(
    _: *const c_void,
    _: usize,
    _: *const c_char,
    _: *const ffi::ConstantValue,
    _: u32,
    reflection: *mut ffi::Reflection,
    _: *mut ffi::AirError,
) -> bool {
    let (reflected, compiled, released) = CALLS.get();
    CALLS.set((reflected + 1, compiled, released));
    let mut answer = ffi::Reflection::ZERO;
    // A kernel.
    answer.stage = 3;
    // SAFETY: the compiler passes its reflection record.
    unsafe { *reflection = answer };
    true
}

unsafe extern "C" fn reflect_bindings(
    _: *const c_void,
    _: usize,
    _: *const c_char,
    _: *const ffi::ConstantValue,
    _: u32,
    _: *mut ffi::Bindings,
    _: *mut ffi::AirError,
) -> bool {
    false
}

unsafe extern "C" fn sampler_states(
    _: *const c_void,
    _: usize,
    _: *mut u64,
    count: *mut u32,
    _: *mut ffi::AirError,
) -> bool {
    // SAFETY: the compiler passes its count.
    unsafe { *count = 0 };
    true
}

unsafe extern "C" fn functions(
    _: *const c_void,
    _: usize,
    _: ffi::VisitFunction,
    _: *mut c_void,
    _: *mut ffi::AirError,
) -> bool {
    true
}

unsafe extern "C" fn stitch(
    _: *const ffi::StitchSource,
    _: u32,
    _: *const ffi::StitchGraph,
    _: u32,
    _: ffi::VisitBytes,
    _: *mut c_void,
    _: *mut ffi::AirError,
) -> bool {
    false
}

/// Each compilation's NIR is at its own address.
unsafe extern "C" fn compile(
    _: *const c_void,
    _: usize,
    _: *const c_char,
    _: *const ffi::Target,
    _: *const ffi::Specialization,
    _: *const ffi::Reflection,
    _: *mut ffi::AirError,
) -> *mut c_void {
    let (reflected, compiled, released) = CALLS.get();
    CALLS.set((reflected, compiled + 1, released));
    ptr::without_provenance_mut(0x1000 * (compiled as usize + 1))
}

unsafe extern "C" fn tessellation_stages(
    _: *const ffi::Target,
    _: *const ffi::Tessellation,
    _: *mut *mut c_void,
) {
}

unsafe extern "C" fn kernel(_: *const c_void) -> *mut c_void {
    ptr::null_mut()
}

unsafe extern "C" fn release(_: *mut c_void) {
    let (reflected, compiled, released) = CALLS.get();
    CALLS.set((reflected, compiled, released + 1));
}

unsafe extern "C" fn buffer_reads(_: *const c_void) -> u32 {
    0
}

fn caching() -> (AirCompiler, u64) {
    let service = Service {
        reflect,
        reflect_bindings,
        sampler_states,
        functions,
        exports: functions,
        stitch,
        compile,
        tessellation_stages,
        accumulate_kernel: kernel,
        select_kernel: kernel,
        resolve_draws_kernel: kernel,
        resolve_dispatches_kernel: kernel,
        store_texels_kernel: kernel,
        load_texels_kernel: kernel,
        average_samples_kernel: kernel,
        decode_etc_kernel: kernel,
        decode_pvrtc_kernel: kernel,
        reorder_blocks_kernel: kernel,
        decode_astc_kernel: kernel,
        release,
        buffer_reads,
        nir_options: NonNull::dangling(),
    };
    // SAFETY: the fake service never reads the options.
    let mut compiler = unsafe { AirCompiler::new(service, &nvk(&CHIPS[0], 8 << 30)) };
    compiler.keep_compilations(NIR_BUDGET);
    let library = compiler.add_library(fixture(false)).unwrap();
    (compiler, library)
}

#[test]
fn a_function_made_again_reflects_nothing() {
    let (mut compiler, library) = caching();
    // A function without values, and one with: its declaration and the
    // specialization reflect once each.
    compiler.constants(library, "kernel").unwrap();
    compiler.prepare_function(library, "kernel", None).unwrap();
    let values = vec![(0, vec![1])];
    compiler
        .prepare_function(library, "kernel", Some(values.clone()))
        .unwrap();
    assert_eq!(calls().0, 2);
    // Another library of the same bytes, as another process loads it.
    let again = compiler.add_library(fixture(false)).unwrap();
    compiler.constants(again, "kernel").unwrap();
    compiler
        .prepare_function(again, "kernel", Some(values))
        .unwrap();
    assert_eq!(calls().0, 2);
}

#[test]
fn a_compilation_made_again_is_lent_from_the_cache() {
    let (mut compiler, library) = caching();
    let specialization = Specialization {
        workgroup_size: Some([64, 1, 1]),
        ..Specialization::default()
    };
    let first = compiler
        .compile(library, "kernel", &specialization)
        .unwrap();
    compiler.release(first.code);
    let again = compiler.add_library(fixture(false)).unwrap();
    let second = compiler.compile(again, "kernel", &specialization).unwrap();
    assert_eq!(first, second);
    compiler.release(second.code);
    // Another shape compiles.
    let other = Specialization {
        workgroup_size: Some([32, 1, 1]),
        ..specialization
    };
    let third = compiler.compile(library, "kernel", &other).unwrap();
    assert_ne!(third.code, first.code);
    compiler.release(third.code);
    // The service compiled twice and released nothing the cache holds.
    assert_eq!((calls().1, calls().2), (2, 0));
}

#[test]
fn a_deferred_compilation_runs_outside_and_the_call_finds_it() {
    let (mut compiler, library) = caching();
    let lock = compiler.compile_lock(core::hint::spin_loop);
    compiler.set_deferring(true);
    let specialization = Specialization::default();
    assert_eq!(
        compiler.compile(library, "kernel", &specialization),
        Err(DEFERRED)
    );
    assert!(lock.deferred());
    let job = compiler.take_deferred().unwrap();
    assert!(!lock.deferred());
    assert_eq!(job.name(), "kernel");
    assert_eq!(calls().1, 0);
    let finished = job.run_outside(&lock.hold(core::hint::spin_loop));
    assert_eq!(calls().1, 1);
    compiler.adopt(finished);
    // The call's next run finds the shader without compiling.
    let shader = compiler
        .compile(library, "kernel", &specialization)
        .unwrap();
    compiler.release(shader.code);
    compiler.end_call();
    assert_eq!((calls().1, calls().2), (1, 0));
    assert!(compiler.report().contains("nir_hits=1"));
}

#[test]
fn a_call_that_stopped_deferring_compiles_in_its_turn() {
    let (mut compiler, library) = caching();
    let lock = compiler.compile_lock(core::hint::spin_loop);
    compiler.set_deferring(true);
    // A commit that changed an indirect command buffer cannot run again.
    compiler.stop_deferring();
    let shader = compiler
        .compile(library, "kernel", &Specialization::default())
        .unwrap();
    compiler.release(shader.code);
    assert!(!lock.deferred() && compiler.take_deferred().is_none());
    assert_eq!(calls().1, 1);
}

#[test]
fn without_kept_compilations_nothing_defers_or_stays() {
    let (mut compiler, library) = caching();
    compiler.nir = None;
    compiler.set_deferring(true);
    let shader = compiler
        .compile(library, "kernel", &Specialization::default())
        .unwrap();
    compiler.release(shader.code);
    assert_eq!((calls().1, calls().2), (1, 1));
}
