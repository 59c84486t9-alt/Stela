extern crate std;

use super::*;
use crate::gpu::metal::{
    abi::{
        IndexType, TessellationControlPointIndexType, TessellationFactorStepFunction,
        TessellationPartitionMode, Winding,
    },
    library::tests::fixture,
    nvidia::{CHIPS, fixture::nvk},
    shader::{Patch, PatchDomain},
    vertex::{STRIDE_DYNAMIC, StageInputDescriptor, VertexDescriptor},
};
use alloc::vec;
use core::{cell::RefCell, ffi::CStr, ptr, slice};

/// A compilation the fake service saw.
#[derive(Debug, Default, PartialEq)]
struct Compiled {
    workgroup_size: [u32; 3],
    lengths: Vec<(u32, u32)>,
    varyings: Vec<(String, bool)>,
    constants: Vec<(u32, Vec<u8>)>,
    amplified: bool,
    launched_by_grid: bool,
    tessellation: Option<ffi::Tessellation>,
    /// Each attribute's index, format, offset and buffer, with that
    /// buffer's stride, step function and rate.
    stage_in: Vec<[u32; 7]>,
    /// The stage-in's index bytes and buffer.
    stage_in_indices: Option<(u32, u32)>,
}

/// A refusal's kind, instruction and detail.
type Refused = (u32, u32, &'static str);

/// The fake service's answers and what it saw, per test thread.
struct Fake {
    reflection: ffi::Reflection,
    refuse_reflection: Option<Refused>,
    refuse_compilation: Option<Refused>,
    compiled: Vec<Compiled>,
    released: Vec<usize>,
}

std::thread_local! {
    static FAKE: RefCell<Fake> = const {
        RefCell::new(Fake {
            reflection: ffi::Reflection::ZERO,
            refuse_reflection: None,
            refuse_compilation: None,
            compiled: Vec::new(),
            released: Vec::new(),
        })
    };
}

/// Fills `error` with `refused`, if any; true when it did.
fn refused(refusal: Option<Refused>, error: *mut ffi::AirError) -> bool {
    let Some((kind, instruction, detail)) = refusal else {
        return false;
    };
    // SAFETY: the compiler passes its error record.
    let error = unsafe { &mut *error };
    error.kind = kind;
    error.instruction = instruction;
    error.detail[..detail.len()].copy_from_slice(detail.as_bytes());
    true
}

/// Checks that the service receives the fixture's unwrapped bitcode.
fn check_input(air: *const c_void, size: usize, entry: *const c_char) {
    // SAFETY: the compiler passes the AIR and entry it selected.
    let (air, entry) = unsafe {
        (
            slice::from_raw_parts(air.cast::<u8>(), size),
            CStr::from_ptr(entry),
        )
    };
    assert!(air.starts_with(b"BC\xc0\xde"), "the service reads bitcode");
    assert_eq!(entry, c"kernel");
}

unsafe extern "C" fn reflect(
    air: *const c_void,
    size: usize,
    entry: *const c_char,
    reflection: *mut ffi::Reflection,
    error: *mut ffi::AirError,
) -> bool {
    check_input(air, size, entry);
    FAKE.with_borrow(|fake| {
        if refused(fake.refuse_reflection, error) {
            return false;
        }
        // SAFETY: the compiler passes its reflection record.
        unsafe { *reflection = fake.reflection };
        true
    })
}

unsafe extern "C" fn compile(
    air: *const c_void,
    size: usize,
    entry: *const c_char,
    target: *const ffi::Target,
    specialization: *const ffi::Specialization,
    error: *mut ffi::AirError,
) -> *mut c_void {
    check_input(air, size, entry);
    // SAFETY: the compiler passes its target and specialization, whose
    // arrays and identifiers it keeps alive for the call.
    let (target, specialization) = unsafe { (&*target, &*specialization) };
    assert!(!target.nir.is_null());
    // SAFETY: as above.
    let (lengths, varyings, constants) = unsafe {
        (
            slice::from_raw_parts(
                specialization.threadgroup_lengths,
                specialization.threadgroup_length_count as usize,
            ),
            slice::from_raw_parts(
                specialization.varyings,
                specialization.varying_count as usize,
            ),
            slice::from_raw_parts(
                specialization.constants,
                specialization.constant_count as usize,
            ),
        )
    };
    // SAFETY: as above.
    let (tessellation, stage_in) = unsafe {
        (
            specialization.tessellation.as_ref().copied(),
            specialization.stage_in.as_ref(),
        )
    };
    let stage_in_indices = stage_in.map(|stage_in| (stage_in.index_bytes, stage_in.index_buffer));
    let stage_in = stage_in.map_or(Vec::new(), |stage_in| {
        (0..)
            .zip(&stage_in.attributes)
            .filter(|(_, attribute)| attribute.format != 0)
            .map(|(index, attribute)| {
                let layout = stage_in.layouts[attribute.buffer as usize];
                [
                    index,
                    attribute.format,
                    attribute.offset,
                    attribute.buffer,
                    layout.stride,
                    layout.step,
                    layout.rate,
                ]
            })
            .collect()
    });
    let constants = constants
        .iter()
        .map(|constant| {
            // SAFETY: as above.
            let value =
                unsafe { slice::from_raw_parts(constant.bytes.cast::<u8>(), constant.size) };
            (constant.index, value.to_vec())
        })
        .collect();
    let varyings = varyings
        .iter()
        .map(|varying| {
            // SAFETY: as above.
            let identifier = unsafe {
                slice::from_raw_parts(varying.identifier.cast::<u8>(), varying.identifier_bytes)
            };
            (
                String::from(str::from_utf8(identifier).unwrap()),
                varying.per_primitive != 0,
            )
        })
        .collect();
    FAKE.with_borrow_mut(|fake| {
        if refused(fake.refuse_compilation, error) {
            return ptr::null_mut();
        }
        fake.compiled.push(Compiled {
            workgroup_size: specialization.workgroup_size,
            lengths: lengths
                .iter()
                .map(|length| (length.index, length.bytes))
                .collect(),
            varyings,
            constants,
            amplified: specialization.amplified != 0,
            launched_by_grid: specialization.launched_by_grid != 0,
            tessellation,
            stage_in,
            stage_in_indices,
        });
        ptr::without_provenance_mut(0x1000 * fake.compiled.len())
    })
}

/// The synthesized stages, at addresses no compilation takes.
unsafe extern "C" fn tessellation_stages(
    target: *const ffi::Target,
    tessellation: *const ffi::Tessellation,
    stages: *mut *mut c_void,
) {
    assert!(!target.is_null() && !tessellation.is_null());
    // SAFETY: the compiler passes room for the two stages.
    let stages = unsafe { slice::from_raw_parts_mut(stages, 2) };
    stages[0] = ptr::without_provenance_mut(0x10);
    stages[1] = ptr::without_provenance_mut(0x20);
}

unsafe extern "C" fn release(shader: *mut c_void) {
    FAKE.with_borrow_mut(|fake| fake.released.push(shader.addr()));
}

fn compiler(device: &PhysicalDevice) -> AirCompiler {
    let service = Service {
        reflect,
        compile,
        tessellation_stages,
        release,
        nir_options: NonNull::dangling(),
    };
    // SAFETY: the fake service never reads the options.
    unsafe { AirCompiler::new(service, device) }
}

fn with_library() -> (AirCompiler, u64) {
    let mut compiler = compiler(&nvk(&CHIPS[0], 8 << 30));
    let library = compiler.add_library(fixture(false)).unwrap();
    (compiler, library)
}

/// Appends `bytes` to the reflection's names, returning their offset.
fn add_name(reflection: &mut ffi::Reflection, bytes: &[u8]) -> u32 {
    let offset = reflection.names_bytes;
    let at = offset as usize;
    reflection.names[at..at + bytes.len()].copy_from_slice(bytes);
    reflection.names_bytes += bytes.len() as u32;
    offset
}

fn add_varying(
    reflection: &mut ffi::Reflection,
    identifier: &str,
    primitive: u32,
    components: u32,
) {
    let offset = add_name(reflection, identifier.as_bytes());
    reflection.varyings[reflection.varying_count as usize] = ffi::Varying {
        identifier: offset,
        identifier_bytes: identifier.len() as u32,
        primitive,
        components,
        per_primitive: 0,
    };
    reflection.varying_count += 1;
}

fn reflecting(edit: impl FnOnce(&mut ffi::Reflection)) {
    FAKE.with_borrow_mut(|fake| {
        fake.reflection = ffi::Reflection::ZERO;
        edit(&mut fake.reflection);
    });
}

const IDENT: &[u8] = b"Apple metal version 32023.922";

#[test]
fn reflections_become_interfaces_with_their_provenance() {
    use ffi::primitive::{FLOAT, UINT};
    reflecting(|r| {
        r.stage = 1;
        r.ident_bytes = IDENT.len() as u32;
        r.ident = add_name(r, IDENT);
        r.buffers[..2].copy_from_slice(&[
            ffi::BufferUse {
                index: 0,
                access: 1,
                argument_buffer: 0,
            },
            ffi::BufferUse {
                index: 3,
                access: 1,
                argument_buffer: 1,
            },
        ]);
        r.buffer_count = 2;
        r.textures[0] = ffi::TextureUse {
            index: 2,
            access: 4,
            texture_type: 3,
            primitive: UINT,
        };
        r.texture_count = 1;
        r.samplers[0] = 5;
        r.sampler_count = 1;
        r.attributes[0] = ffi::AttributeUse {
            index: 1,
            primitive: FLOAT,
            components: 3,
        };
        r.attribute_count = 1;
        add_varying(r, "user(uv)", FLOAT, 2);
        r.amplification = 1;
        let name = add_name(r, b"tint");
        let type_name = add_name(r, b"half3");
        r.function_constants[0] = ffi::FunctionConstant {
            index: 4,
            name,
            name_bytes: 4,
            type_name,
            type_bytes: 5,
            required: 1,
        };
        r.function_constant_count = 1;
    });
    let (mut compiler, library) = with_library();
    let interface = compiler
        .reflect(library, "kernel", &Specialization::default())
        .unwrap();
    assert_eq!(interface.stage, Stage::Vertex);
    assert_eq!(
        interface.buffers,
        [
            BufferUse {
                index: 0,
                access: Access::READ,
                argument_buffer: false
            },
            BufferUse {
                index: 3,
                access: Access::READ,
                argument_buffer: true
            },
        ]
    );
    assert_eq!(
        interface.textures,
        [TextureUse {
            index: 2,
            access: Access::SAMPLE,
            texture_type: TextureType::D2,
            numeric: NumericClass::Uint,
        }]
    );
    assert_eq!(interface.samplers, [5]);
    assert_eq!(
        interface.attributes,
        [AttributeUse {
            index: 1,
            numeric: NumericClass::Float,
            components: 3
        }]
    );
    assert_eq!(
        interface.varyings,
        [Varying {
            identifier: String::from("user(uv)"),
            scalar: Scalar::Float,
            components: 2,
            per_primitive: false,
        }]
    );
    assert!(interface.amplification);
    assert_eq!(
        interface.constants,
        [FunctionConstant {
            name: String::from("tint"),
            data_type: DataType::Half3,
            index: 4,
            required: true,
        }]
    );
    assert_eq!(interface.max_total_threads, None);
    assert_eq!(
        interface.features,
        ShaderFeatures::VERTEX_FRAGMENT
            | ShaderFeatures::TEXTURE_SAMPLE
            | ShaderFeatures::ARGUMENT_BUFFERS
            | ShaderFeatures::VERTEX_AMPLIFICATION
    );

    let data = fixture(false);
    let digest = *Library::parse(&data).unwrap().functions()[0].digest;
    let compiled = compiler
        .compile(library, "kernel", &Specialization::default())
        .unwrap();
    assert_eq!(compiled.interface, interface);
    assert_eq!(
        compiled.provenance,
        Provenance {
            build_id: IDENT.to_vec(),
            slice_hash: digest,
            source_map: None,
            entry: String::from("kernel"),
        }
    );
}

#[test]
fn compilations_carry_their_specialization_and_release_through_the_service() {
    use ffi::primitive::{FLOAT, HALF};
    reflecting(|r| {
        r.stage = 2;
        add_varying(r, "user(normal)", HALF, 4);
        r.color_outputs[0] = ffi::ColorOutput {
            index: 0,
            primitive: FLOAT,
            dual_source: 0,
        };
        r.color_output_count = 1;
        r.discards = 1;
    });
    let (mut compiler, library) = with_library();
    let varying = |identifier: &str, scalar, per_primitive| Varying {
        identifier: String::from(identifier),
        scalar,
        components: 4,
        per_primitive,
    };
    let specialization = Specialization {
        varyings: vec![
            varying("user(color)", Scalar::Float, false),
            varying("user(normal)", Scalar::Half, true),
        ],
        ..Specialization::default()
    };
    let fragment = compiler
        .compile(library, "kernel", &specialization)
        .unwrap();
    assert!(fragment.interface.discards);
    assert_eq!(
        fragment
            .interface
            .color_output(0)
            .map(|output| output.numeric),
        Some(NumericClass::Float)
    );

    reflecting(|r| {
        r.stage = 3;
        r.max_total_threads = 256;
        r.threadgroup_bytes = 64;
        r.threadgroup[0] = ffi::ThreadgroupUse {
            index: 1,
            bytes: 16,
        };
        r.threadgroup_count = 1;
    });
    let specialization = Specialization {
        constants: vec![(2, vec![1, 0])],
        workgroup_size: Some([64, 2, 1]),
        threadgroup_lengths: vec![(1, 512)],
        ..Specialization::default()
    };
    let kernel = compiler
        .compile(library, "kernel", &specialization)
        .unwrap();
    assert_eq!(kernel.interface.max_total_threads, Some(256));
    assert_eq!(
        kernel.interface.threadgroup,
        [ThreadgroupUse {
            index: 1,
            declared_bytes: 16
        }]
    );
    assert_eq!(kernel.interface.static_threadgroup_bytes, 64);
    assert!(
        kernel
            .interface
            .features
            .contains(ShaderFeatures::COMPUTE | ShaderFeatures::THREADGROUP_MEMORY)
    );

    let oversized = Specialization {
        threadgroup_lengths: vec![(1, 1 << 32)],
        ..specialization
    };
    assert_eq!(
        compiler.compile(library, "kernel", &oversized),
        Err(Error::Invalid("threadgroup memory length"))
    );
    compiler.release(fragment.code);
    compiler.release(kernel.code);
    FAKE.with_borrow(|fake| {
        let linked = vec![
            (String::from("user(color)"), false),
            (String::from("user(normal)"), true),
        ];
        assert_eq!(
            fake.compiled,
            [
                Compiled {
                    varyings: linked,
                    ..Compiled::default()
                },
                Compiled {
                    workgroup_size: [64, 2, 1],
                    lengths: vec![(1, 512)],
                    constants: vec![(2, vec![1, 0])],
                    ..Compiled::default()
                },
            ]
        );
        assert_eq!(
            fake.released,
            [fragment.code.0 as usize, kernel.code.0 as usize]
        );
    });
}

#[test]
fn refusals_name_their_kind_and_keep_their_detail() {
    use ffi::kind;
    reflecting(|r| r.stage = 3);
    let (mut compiler, library) = with_library();
    let specialization = Specialization::default();
    for (refusal, error) in [
        (kind::INSTRUCTION, Error::Unsupported("AIR instructions")),
        (
            kind::LIMIT,
            Error::Unsupported("AIR beyond the compiler's limits"),
        ),
        (kind::ALLOCATION, Error::OutOfMemory),
        (kind::INPUT, Error::Invalid("compiler request")),
    ] {
        FAKE.with_borrow_mut(|fake| {
            fake.refuse_reflection = Some((refusal, 7, "call to air.unknown"));
        });
        assert_eq!(
            compiler.reflect(library, "kernel", &specialization),
            Err(error)
        );
    }
    assert_eq!(
        compiler.refusal(),
        Some(&Refusal {
            entry: String::from("kernel"),
            instruction: 7,
            detail: String::from("call to air.unknown"),
        })
    );
    FAKE.with_borrow_mut(|fake| {
        fake.refuse_reflection = None;
        fake.refuse_compilation = Some((kind::CONTROL_FLOW, 2, "indirect branch"));
    });
    assert_eq!(
        compiler.compile(library, "kernel", &specialization),
        Err(Error::Unsupported("AIR control flow"))
    );
    assert_eq!(compiler.refusal().unwrap().detail, "indirect branch");
}

#[test]
fn what_the_service_cannot_take_is_refused_before_it_runs() {
    let (mut compiler, library) = with_library();
    let specialization = Specialization::default();
    assert_eq!(
        compiler.reflect(library, "missing", &specialization),
        Err(Error::Invalid("no function of that name"))
    );
    assert_eq!(
        compiler.reflect(library + 1, "kernel", &specialization),
        Err(Error::Invalid("unknown library"))
    );
    assert_eq!(
        compiler.add_library(vec![0; 16]),
        Err(Error::Invalid("Metal library"))
    );
    let mut corrupted = fixture(false);
    let module_at = Library::parse(&corrupted).unwrap().functions()[0].module_offset;
    corrupted[module_at + 24] ^= 1;
    let corrupted = compiler.add_library(corrupted).unwrap();
    assert_ne!(corrupted, library, "ids are not reused");
    assert_eq!(
        compiler.reflect(corrupted, "kernel", &specialization),
        Err(Error::Invalid("Metal library")),
        "the AIR must match its digest"
    );
    compiler.remove_library(library).unwrap();
    assert_eq!(
        compiler.reflect(library, "kernel", &specialization),
        Err(Error::Invalid("unknown library"))
    );
    FAKE.with_borrow(|fake| assert!(fake.compiled.is_empty()));
    assert_eq!(compiler.refusal(), None);
}

#[test]
fn kernels_compile_with_their_stage_in() {
    use crate::gpu::metal::vertex::{Attribute, StageInLayout, StageInStep, VertexFormat};
    reflecting(|r| {
        r.stage = 3;
        r.attributes[0] = ffi::AttributeUse {
            index: 2,
            primitive: ffi::primitive::UINT,
            components: 2,
        };
        r.attribute_count = 1;
    });
    let (mut compiler, library) = with_library();
    let specialization = Specialization {
        stage_in: Some(StageInputDescriptor {
            attributes: vec![Attribute {
                index: 2,
                format: VertexFormat::UInt2,
                offset: 4,
                buffer_index: 6,
            }],
            layouts: vec![StageInLayout {
                buffer_index: 6,
                stride: 12,
                step_function: StageInStep::ThreadPositionInGridYIndexed,
                step_rate: 2,
            }],
            index_type: IndexType::UInt32,
            index_buffer_index: 9,
        }),
        ..Specialization::default()
    };
    compiler
        .compile(library, "kernel", &specialization)
        .unwrap();
    FAKE.with_borrow(|fake| {
        let compiled = fake.compiled.last().unwrap();
        assert_eq!(
            compiled.stage_in,
            [[
                2,
                VertexFormat::UInt2.raw() as u32,
                4,
                6,
                12,
                StageInStep::ThreadPositionInGridYIndexed.raw() as u32,
                2
            ]]
        );
        assert_eq!(compiled.stage_in_indices, Some((4, 9)));
        assert_eq!(compiled.tessellation, None);
    });

    // Without a descriptor, the kernel fetches nothing.
    compiler
        .compile(library, "kernel", &Specialization::default())
        .unwrap();
    FAKE.with_borrow(|fake| assert_eq!(fake.compiled.last().unwrap().stage_in_indices, None));
}

#[test]
fn post_tessellation_vertex_functions_compile_with_their_stage_in() {
    use crate::gpu::metal::vertex::{Attribute, Layout, StepFunction, VertexFormat};
    reflecting(|r| {
        r.stage = 1;
        r.patch = 2;
        r.patch_control_points = 4;
        r.attributes[0] = ffi::AttributeUse {
            index: 3,
            primitive: ffi::primitive::FLOAT,
            components: 4,
        };
        r.attribute_count = 1;
    });
    let (mut compiler, library) = with_library();
    let patch = Patch {
        domain: PatchDomain::Quad,
        control_points: Some(4),
    };
    let interface = compiler
        .reflect(library, "kernel", &Specialization::default())
        .unwrap();
    assert_eq!(interface.patch, Some(patch));
    assert!(interface.features.contains(ShaderFeatures::TESSELLATION));
    let tessellation = Tessellation {
        patch,
        partition: TessellationPartitionMode::FractionalOdd,
        max_factor: 16,
        factor_scale: false,
        step_function: TessellationFactorStepFunction::PerPatch,
        control_point_index: TessellationControlPointIndexType::UInt16,
        winding: Winding::CounterClockwise,
        vertex_descriptor: Some(VertexDescriptor {
            attributes: vec![Attribute {
                index: 3,
                format: VertexFormat::Float4,
                offset: 8,
                buffer_index: 5,
            }],
            layouts: vec![Layout {
                buffer_index: 5,
                stride: STRIDE_DYNAMIC,
                step_function: StepFunction::PerPatchControlPoint,
                step_rate: 1,
            }],
        }),
    };
    let stages = compiler
        .compile_tessellation(library, "kernel", &Specialization::default(), &tessellation)
        .unwrap();
    assert_eq!(
        (stages.vertex, stages.control),
        (ShaderCode(0x10), ShaderCode(0x20))
    );
    assert_eq!(stages.evaluation.interface.patch, Some(patch));
    FAKE.with_borrow(|fake| {
        let compiled = fake.compiled.last().unwrap();
        assert_eq!(
            compiled.tessellation,
            Some(ffi::Tessellation {
                quad: true,
                partition: TessellationPartitionMode::FractionalOdd.raw() as u32,
                max_factor: 16,
                step: TessellationFactorStepFunction::PerPatch.raw() as u32,
                winding: Winding::CounterClockwise.raw() as u32,
                control_point_index_bytes: 2,
            })
        );
        assert_eq!(
            compiled.stage_in,
            [[
                3,
                VertexFormat::Float4.raw() as u32,
                8,
                5,
                ffi::STRIDE_DYNAMIC,
                4,
                1
            ]]
        );
    });

    // Without a vertex descriptor, the function fetches nothing.
    let bare = Tessellation {
        vertex_descriptor: None,
        ..tessellation
    };
    compiler
        .compile_tessellation(library, "kernel", &Specialization::default(), &bare)
        .unwrap();
    FAKE.with_borrow(|fake| assert!(fake.compiled.last().unwrap().stage_in.is_empty()));
    // Their stage-in is their vertex descriptor's.
    let kernel_stage_in = Specialization {
        stage_in: Some(StageInputDescriptor {
            attributes: Vec::new(),
            layouts: Vec::new(),
            index_type: IndexType::UInt16,
            index_buffer_index: 0,
        }),
        ..Specialization::default()
    };
    assert_eq!(
        compiler
            .compile_tessellation(library, "kernel", &kernel_stage_in, &bare)
            .map(drop),
        Err(Error::Invalid("kernel stage-in of a vertex function"))
    );
}

#[test]
fn malformed_reflections_are_refused() {
    let (mut compiler, library) = with_library();
    let edits: [fn(&mut ffi::Reflection); 8] = [
        |r| r.stage = 4,
        |r| {
            r.stage = 1;
            r.patch = 3;
        },
        |r| {
            r.stage = 1;
            r.patch = 1;
            r.patch_control_points = 33;
        },
        |r| r.buffer_count = 32,
        |r| {
            r.stage = 1;
            r.varyings[0].identifier_bytes = 1;
            r.varying_count = 1;
        },
        |r| {
            r.stage = 3;
            r.textures[0].primitive = ffi::primitive::FLOAT;
            r.texture_count = 1;
        },
        |r| {
            r.stage = 3;
            r.buffers[0].access = 16;
            r.buffer_count = 1;
        },
        |r| {
            r.stage = 3;
            r.function_constants[0].type_bytes = 4;
            r.function_constant_count = 1;
        },
    ];
    for edit in edits {
        reflecting(edit);
        assert_eq!(
            compiler.reflect(library, "kernel", &Specialization::default()),
            Err(MALFORMED)
        );
    }
}

#[test]
fn targets_follow_the_device() {
    let mut device = nvk(&CHIPS[0], 8 << 30);
    let mesh = device.limits.mesh.unwrap();
    let target = compiler(&device).target;
    assert_eq!(
        (
            target.max_threadgroup_bytes,
            target.max_constant_bytes,
            target.max_varying_slots
        ),
        (
            device.limits.max_compute_shared_memory_size,
            device.limits.max_uniform_buffer_range,
            32
        )
    );
    assert_eq!(
        (
            target.max_payload_bytes,
            target.max_mesh_vertices,
            target.max_mesh_primitives
        ),
        (
            mesh.max_task_payload_size,
            mesh.max_mesh_output_vertices,
            mesh.max_mesh_output_primitives
        )
    );
    device.limits.mesh = None;
    device.limits.max_compute_shared_memory_size = 100 << 10;
    let target = compiler(&device).target;
    assert_eq!(target.max_threadgroup_bytes, u16::MAX.into());
    assert_eq!(target.max_payload_bytes, 0);
}

#[test]
fn function_constant_types_follow_their_spelling() {
    for (spelling, expected) in [
        (&b"float"[..], DataType::Float),
        (b"uint3", DataType::UInt3),
        (b"bool4", DataType::Bool4),
        (b"half2", DataType::Half2),
        (b"ulong", DataType::ULong),
    ] {
        assert_eq!(data_type(spelling), Ok(expected));
    }
    for spelling in [&b"uint5"[..], b"double", b""] {
        assert_eq!(
            data_type(spelling),
            Err(Error::Unsupported("function constant type"))
        );
    }
}
