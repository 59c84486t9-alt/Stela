//! The [`Service`] of the compiler's C linked into this image.
use super::{Service, ffi};
use core::{
    ffi::{c_char, c_void},
    ptr::NonNull,
};

unsafe extern "C" {
    fn stela_metal_reflect(
        air: *const c_void,
        size: usize,
        entry: *const c_char,
        constants: *const ffi::ConstantValue,
        constant_count: u32,
        reflection: *mut ffi::Reflection,
        error: *mut ffi::AirError,
    ) -> bool;
    fn stela_metal_reflect_bindings(
        air: *const c_void,
        size: usize,
        entry: *const c_char,
        constants: *const ffi::ConstantValue,
        constant_count: u32,
        bindings: *mut ffi::Bindings,
        error: *mut ffi::AirError,
    ) -> bool;
    fn stela_metal_sampler_states(
        air: *const c_void,
        size: usize,
        states: *mut u64,
        count: *mut u32,
        error: *mut ffi::AirError,
    ) -> bool;
    fn stela_metal_functions(
        air: *const c_void,
        size: usize,
        visit: ffi::VisitFunction,
        data: *mut c_void,
        error: *mut ffi::AirError,
    ) -> bool;
    fn stela_metal_stitch(
        sources: *const ffi::StitchSource,
        source_count: u32,
        graphs: *const ffi::StitchGraph,
        graph_count: u32,
        visit: ffi::VisitBytes,
        data: *mut c_void,
        error: *mut ffi::AirError,
    ) -> bool;
    fn stela_metal_compile_reflected(
        air: *const c_void,
        size: usize,
        entry: *const c_char,
        target: *const ffi::Target,
        specialization: *const ffi::Specialization,
        reflection: *const ffi::Reflection,
        error: *mut ffi::AirError,
    ) -> *mut c_void;
    fn stela_metal_tessellation_stages(
        target: *const ffi::Target,
        tessellation: *const ffi::Tessellation,
        stages: *mut *mut c_void,
    );
    fn stela_metal_accumulate_kernel(options: *const c_void) -> *mut c_void;
    fn stela_metal_select_kernel(options: *const c_void) -> *mut c_void;
    fn stela_metal_resolve_draws_kernel(options: *const c_void) -> *mut c_void;
    fn stela_metal_resolve_dispatches_kernel(options: *const c_void) -> *mut c_void;
    fn stela_metal_release(shader: *mut c_void);
}

impl Service {
    /// The linked service, compiling with the driver's `nir_options`.
    pub fn linked(nir_options: NonNull<c_void>) -> Self {
        Self {
            reflect: stela_metal_reflect,
            reflect_bindings: stela_metal_reflect_bindings,
            sampler_states: stela_metal_sampler_states,
            functions: stela_metal_functions,
            stitch: stela_metal_stitch,
            compile: stela_metal_compile_reflected,
            tessellation_stages: stela_metal_tessellation_stages,
            accumulate_kernel: stela_metal_accumulate_kernel,
            select_kernel: stela_metal_select_kernel,
            resolve_draws_kernel: stela_metal_resolve_draws_kernel,
            resolve_dispatches_kernel: stela_metal_resolve_dispatches_kernel,
            release: stela_metal_release,
            nir_options,
        }
    }
}
