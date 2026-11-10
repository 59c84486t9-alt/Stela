//! Pipeline descriptors' promises, hints and limits, and what pipeline
//! states report: the same work with call stack depths, buffer
//! mutability, function groups, handles found by name, binary functions
//! added to a finished pipeline, required threadgroup sizes, forward
//! progress and persistence hints, concurrent passes and the older
//! library insertion; and calls into visible functions another library
//! defines, linked into compute, render and mesh pipelines.
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::values::{Dtype, Random, f32r, f32s, u32s};
use serde_json::json;

const FUNCTIONS: [&str; 3] = ["twice", "square", "negate_plus"];

/// The words `pipeline_properties` writes: those the descriptor fixes,
/// exactly, and the limits the device chooses, each only nonzero.
fn properties(case: Case, fixed: &[u32], limits: usize) -> Case {
    let mut words = fixed.to_vec();
    words.resize(8, 0);
    let mut nonzero = vec![1u32; limits];
    nonzero.resize(limits.div_ceil(4) * 4, 0);
    case.set(
        "pipeline_properties",
        json!({"fixed": "fixed", "limits": "limits"}),
    )
    .buffer(Buffer::zeroed("fixed", 0, 32).unbound())
    .buffer(Buffer::zeroed("limits", 0, nonzero.len() * 4).unbound())
    .output(Output::new("fixed", Dtype::U32, Tolerance::exact()).expect_same(u32s(&words)))
    .output(
        Output::new("limits", Dtype::U32, Tolerance::exact())
            .expect_same(u32s(&nonzero))
            .set("derive", "nonzero"),
    )
}

/// A compute pipeline's fixed words: static threadgroup memory, indirect
/// command buffer support, the required threadgroup size and, when the
/// descriptor names one, the forward progress usage (automatic leaves it
/// to the device).
fn compute_fixed(required: [u32; 3], forward_progress: Option<u32>) -> Vec<u32> {
    let mut words = vec![0, 0, required[0], required[1], required[2]];
    words.extend(forward_progress);
    words
}

fn compute(plan: &mut Plan) {
    let table = "arguments.visible_function_table";
    let immutable = |case: Case| {
        case.edit("buffers", "in", "mutability", "immutable")
            .edit("buffers", "which", "mutability", "immutable")
            .edit("buffers", "out", "mutability", "mutable")
    };
    // Promises that leave the result alone: a call stack one call deep,
    // threadgroups a multiple of the execution width, inputs immutable
    // and the table's functions in one call-site group, found by name.
    plan.vary(table, "hints", |case| {
        properties(
            immutable(case)
                .set("call_stack_depth", 1)
                .set("group_multiple_of_width", true)
                .set("handles_by_name", true)
                .set("function_groups", json!({"calls": FUNCTIONS})),
            &compute_fixed([0; 3], None),
            2,
        )
    });
    // Two of the three functions added as binaries to the finished
    // pipeline, whose new state fills the table.
    // Mutability left to the default a buffer's kind gives it.
    plan.vary(table, "default_mutability", |case| {
        case.edit("buffers", "in", "mutability", "default")
    });
    plan.vary(table, "added_binary_functions", |case| {
        case.set("visible_functions", json!(["twice"]))
            .set("added_binary_functions", json!(["square", "negate_plus"]))
    });
    plan.vary(table, "required_threads", |case| {
        properties(
            case.set("required_threads", json!([64, 1, 1])),
            &compute_fixed([64, 1, 1], None),
            2,
        )
    });
    // Weak forward progress and no contention relief; and a persistent
    // kernel, with the threadgroup count it should launch, which the
    // feature set tables' forward progress guarantees give to Apple11.
    plan.vary(table, "weak_progress", |case| {
        properties(
            case.set("forward_progress", "weak")
                .set("contention_relief", "none"),
            &compute_fixed([0; 3], Some(1)),
            2,
        )
    });
    // Both hints named as their defaults, which leave the usage to the
    // device; and SIMD-group parallel progress, which the feature set
    // tables' forward progress guarantees give to Apple11.
    plan.vary(table, "automatic_progress", |case| {
        properties(
            case.set("forward_progress", "automatic")
                .set("contention_relief", "automatic"),
            &compute_fixed([0; 3], None),
            2,
        )
    });
    plan.vary(table, "simdgroup_parallel_progress", |case| {
        properties(
            case.set("forward_progress", "simdgroup_parallel")
                .requires(&["apple11"], &["function_pointers"]),
            &compute_fixed([0; 3], Some(2)),
            2,
        )
    });
    plan.vary(table, "persistent", |case| {
        properties(
            case.set("forward_progress", "weak")
                .set("contention_relief", "none")
                .set("persistent", true)
                .requires(&["apple11"], &["function_pointers"]),
            &compute_fixed([0; 3], Some(1)),
            3,
        )
    });
    plan.vary(table, "concurrent_pass", |case| {
        case.set("concurrent", "pass")
    });
    // A dynamic library given by the older insertLibraries.
    plan.vary("arguments.dynamic_library.preloaded", "inserted", |case| {
        let libraries = case.get("preload").clone();
        case.set("insert", libraries.clone())
            .set("uses", libraries)
            .set("preload", json!([]))
    });
}

fn render(plan: &mut Plan) {
    let immutable = |case: Case| {
        case.edit("buffers", "in", "mutability", "immutable").edit(
            "buffers",
            "which",
            "mutability",
            "immutable",
        )
    };
    for stage in ["vertex", "fragment"] {
        let name = format!("arguments.visible_function_tables.{stage}.single");
        plan.vary(&name, "hints", |case| {
            immutable(case)
                .set_at(&["render", "call_stack_depth"], 2)
                .set_at(&["render", "handles_by_name"], true)
                .set_at(
                    &["render", &format!("{stage}_function_groups")],
                    json!({"calls": FUNCTIONS}),
                )
        });
        plan.vary(&name, "added_binary_functions", |case| {
            case.set_at(
                &["render", &format!("{stage}_visible_functions")],
                json!(["twice"]),
            )
            .set_at(
                &["render", &format!("added_{stage}_binary_functions")],
                json!(["square", "negate_plus"]),
            )
        });
    }
}

/// Calls into `linked_def.metal`'s functions: shade(x) = 4x + 0.5 and
/// bias() = 0.25, each linked privately (callable only directly), as a
/// linked function, or in a call-site group.
fn linked(plan: &mut Plan, rng: &mut Random) {
    let library = plan.library("linked", "linked.metal", &[], super::plan::LATEST);
    let def = plan.library("linked_def", "linked_def.metal", &[], super::plan::LATEST);
    let entry = |f: &str| json!({"library": def, "name": f});
    let n = 64usize;
    let input: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-8.0, 8.0))).collect();
    let shade: Vec<f64> = input.iter().map(|&x| f32r(x * 4.0 + 0.5)).collect();
    let both = json!([entry("linked_shade"), entry("linked_bias")]);
    for (how, set) in [
        ("private", json!({"private_functions": both})),
        ("functions", json!({"visible_functions": both})),
        (
            "groups",
            json!({"visible_functions": both, "function_groups": {"calls": ["linked_shade", "linked_bias"]}}),
        ),
    ] {
        let mut case = Case::compute1(
            &format!("pipelines.linked.compute.{how}"),
            &library,
            "call_linked",
            n as u32,
        )
        .set("uses", json!([def]))
        .buffer(Buffer::data("in", 0, f32s(&input)))
        .buffer(Buffer::zeroed("out", 1, n * 4))
        .output(
            Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(
                &shade.iter().map(|&v| f32r(v + 0.25)).collect::<Vec<_>>(),
            )),
        );
        for (k, v) in set.as_object().unwrap() {
            case = case.set(k, v.clone());
        }
        plan.add(case);
    }
    // A function descriptor's specializedName is the name the kernel's
    // call links by: x * 3 + 7 from a specialization of linked_scale_impl.
    let named = plan.library(
        "linked_named",
        "linked_named.metal",
        &[],
        super::plan::LATEST,
    );
    let ints: Vec<u32> = (0..n as u32).map(|i| i.wrapping_mul(0x9e37_79b9)).collect();
    let scaled: Vec<u32> = ints
        .iter()
        .map(|x| x.wrapping_mul(3).wrapping_add(7))
        .collect();
    plan.add(
        Case::compute1(
            "pipelines.linked.compute.specialized_name",
            &library,
            "call_linked_scaled",
            n as u32,
        )
        .set("uses", json!([named]))
        .set(
            "private_functions",
            json!([{"library": named, "name": "linked_scale_impl",
                    "specialized_name": "linked_scaled",
                    "constants": [{"type": "uint", "index": 0, "value": 3}]}]),
        )
        .buffer(Buffer::data("in", 0, u32s(&ints)))
        .buffer(Buffer::zeroed("out", 1, n * 4))
        .output(Output::new("out", Dtype::U32, Tolerance::exact()).expect_same(u32s(&scaled))),
    );
    let pixels =
        |values: &[f64]| -> Vec<f64> { values.iter().flat_map(|&v| [v, 0.25, 0.0, 1.0]).collect() };
    let target = || Texture::d2("target", "rgba32float", 8, 8).usage(&["render"]);
    let colors = json!([{"texture": "target", "clear": [0, 0, 0, 0]}]);
    plan.add(
        Case::render(
            "pipelines.linked.render",
            &library,
            "vert_linked",
            Some("frag_linked"),
            json!({"colors": colors, "primitive": "point", "vertex_count": n,
                   "vertex_private_functions": [entry("linked_shade")],
                   "fragment_private_functions": [entry("linked_bias")]}),
        )
        .set("uses", json!([def]))
        .buffer(Buffer::data("in", 0, f32s(&input)).stage("vertex"))
        .texture(target())
        .output(
            Output::new("target", Dtype::F32, Tolerance::exact())
                .expect_same(f32s(&pixels(&shade))),
        ),
    );
    // The object stage's payload carries the bias the mesh subtracts;
    // the pipeline states its payload size and its grid's one group,
    // promises its threadgroups fill whole execution widths and reports
    // its mesh stages' bindings.
    let meshed: Vec<f64> = shade.iter().map(|&v| f32r(v - 0.25)).collect();
    plan.add(properties(
        Case::render(
            "pipelines.linked.mesh",
            &library,
            "mesh_linked",
            Some("frag_linked"),
            json!({"colors": colors, "fragment_private_functions": [entry("linked_bias")],
                   "mesh": {"object": "object_linked", "mesh": "mesh_linked", "threadgroups": [1],
                            "object_threads": [32], "mesh_threads": [64], "payload_length": 16,
                            "max_threadgroups": 1, "group_multiple_of_width": true,
                            "object_private_functions": [entry("linked_bias")],
                            "mesh_private_functions": [entry("linked_shade")]}}),
        )
        .set("uses", json!([def]))
        .set("reflection", "reflection")
        .buffer(
            Buffer::data("in", 0, f32s(&input))
                .stage("mesh")
                .set("mutability", "immutable"),
        )
        .buffer(Buffer::zeroed("reflection", 0, 1024).unbound())
        .texture(target())
        .output(
            Output::new("target", Dtype::F32, Tolerance::exact())
                .expect_same(f32s(&pixels(&meshed))),
        )
        .output(
            Output::new("reflection", Dtype::U8, Tolerance::exact())
                .expect_same(text(&MESH_REFLECTION, 1024)),
        ),
        &[0, 1, 0, 0],
        4,
    ));
}

fn text(lines: &[&str], length: usize) -> Vec<u8> {
    let mut t = lines.join("\n").into_bytes();
    t.resize(length, 0);
    t
}

/// The mesh pipeline's bindings: the payload each of its object and mesh
/// stages addresses at no index, and the mesh stage's input.
const MESH_REFLECTION: [&str; 7] = [
    "object",
    "payload type=34 index=4294967295 access=1 used=1 argument=1 size=4 align=4",
    "mesh",
    "in type=0 index=0 access=0 used=1 argument=1 size=4 align=4 data=3",
    "payload type=34 index=4294967295 access=0 used=1 argument=1 size=4 align=4",
    "fragment",
    "\n",
];

/// Argument buffers written through argument encoders rather than as
/// Tier 2 layouts: consecutive entries in one call, a nested struct
/// through the encoder for its member, each element of an array of
/// structs, pipelines, depth-stencil states and indirect command
/// buffers, with encoders from a function, from the older reflecting
/// call and from a pipeline's binding.
fn encoders(plan: &mut Plan) {
    let id =
        |kind: &str, id: u32, resource: &str| json!({"kind": kind, "id": id, "resource": resource});
    let encoder =
        |function: &str, from: &str| json!({"function": function, "index": 0, "from": from});
    // struct Arguments { values, image, linear, counter, layers[3], inner,
    // count }, whose encoded length and alignment the device chooses:
    // some length that fits the buffer, at a power-of-two alignment.
    plan.vary("arguments.argument_buffer.encoder", "ranges", |case| {
        case.set(
            "arguments",
            json!([{"buffer": "args", "encoder": encoder("argument_buffer", "function"), "layout": "layout", "entries": [
                id("buffer", 0, "values"), id("texture", 1, "image"), id("sampler", 2, "linear"),
                id("buffer", 3, "counter"),
                {"kind": "texture", "id": 4, "resources": ["layer0", "layer1", "layer2"]},
                {"kind": "nested", "id": 7, "buffer": "inner", "entries": [
                    {"kind": "buffer", "id": 0, "resources": ["inner_values"]}]},
                {"kind": "constant", "id": 8, "value": 0xABCD}]}]),
        )
        .buffer(Buffer::zeroed("layout", 0, 16).unbound())
        .output(Output::new("layout", Dtype::U32, Tolerance::exact()).expect_same(u32s(&[1, 1, 1, 0])))
    });
    // The encoder from the pipeline's buffer binding, entry by entry.
    plan.vary("arguments.argument_buffer.encoder", "binding", |case| {
        let mut arguments = case.get("arguments").clone();
        arguments[0]["encoder"] = encoder("argument_buffer", "binding");
        case.set("arguments", arguments).set(
            "reference_divergence",
            "the M1 Pro's encoder from a buffer binding sets a texture array's first element at its last",
        )
    });
    plan.vary("arguments.argument_buffer.encoder", "reflected", |case| {
        let mut arguments = case.get("arguments").clone();
        arguments[0]["encoder"] = encoder("argument_buffer", "reflected");
        case.set("arguments", arguments)
    });
    // Each { source, bias } element's pointer set from its own start;
    // the biases stay as the buffer holds them.
    plan.vary("arguments.argument_array", "encoder", |case| {
        let elements: Vec<_> = (0..4)
            .map(|k| {
                json!({"buffer": "items", "encoder": encoder("argument_array", "function"), "element": k,
                       "entries": [id("buffer", 0, &format!("source{k}"))]})
            })
            .collect();
        case.set("arguments", elements)
    });
    let commands = |function: &str, from: &str, entries: serde_json::Value| json!([{"buffer": "commands", "encoder": encoder(function, from), "entries": entries}]);
    plan.vary("sequence.icb.gpu_dispatch", "encoder", |case| {
        case.set(
            "arguments",
            commands(
                "encode_dispatches",
                "function",
                json!([id("icb", 0, "icb")]),
            ),
        )
    });
    plan.vary("sequence.icb.gpu_full_dispatches", "encoder", |case| {
        case.set(
            "arguments",
            commands("encode_full_dispatches", "binding", json!([
                {"kind": "icb", "id": 0, "resources": ["icb"]},
                {"kind": "compute_pipeline", "id": 1, "functions": ["icb_scale", "icb_block_sum"]}])),
        )
    });
    let state = |compare: &str, write: bool| json!({"compare": compare, "write": write});
    plan.vary("sequence.icb.gpu_draw_state", "encoder", |case| {
        case.set(
            "arguments",
            commands("encode_draw_state", "reflected", json!([
                id("icb", 0, "icb"),
                {"kind": "depth_stencil", "id": 1, "states": [state("always", false), state("always", true),
                                                              state("less_equal", true), state("less", false)]}])),
        )
    });
    plan.vary("sequence.icb.gpu_draw_state", "encoder_single", |case| {
        case.set(
            "arguments",
            commands(
                "encode_draw_state",
                "function",
                json!([
                id("icb", 0, "icb"),
                {"kind": "depth_stencil", "id": 1, "compare": "always", "write": false},
                {"kind": "depth_stencil", "id": 2, "compare": "always", "write": true},
                {"kind": "depth_stencil", "id": 3, "compare": "less_equal", "write": true},
                {"kind": "depth_stencil", "id": 4, "compare": "less", "write": false}]),
            ),
        )
    });
    let pipeline =
        json!({"vertex": "vert_rect", "fragment": "frag_constant", "format": "rgba32float"});
    plan.vary("sequence.icb.gpu_indexed_draw", "encoder", |case| {
        let mut single = pipeline.clone();
        single["kind"] = "render_pipeline".into();
        single["id"] = 1.into();
        case.set(
            "arguments",
            commands(
                "encode_indexed_draws",
                "function",
                json!([id("icb", 0, "icb"), single]),
            ),
        )
    });
    plan.vary("sequence.icb.gpu_indexed_draw", "encoder_ranges", |case| {
        case.set(
            "arguments",
            commands("encode_indexed_draws", "binding", json!([
                id("icb", 0, "icb"), {"kind": "render_pipeline", "id": 1, "pipelines": [pipeline]}])),
        )
    });
}

/// The ways a pipeline and its functions are created: functions from a
/// descriptor, with a specialized name, and through completion handlers;
/// compute pipelines from the function alone, with options and through
/// handlers; render and mesh pipelines through handlers; libraries from
/// source and stitched libraries through handlers.
fn creation(plan: &mut Plan) {
    for mode in [
        "descriptor_async",
        "function",
        "function_options",
        "function_async",
        "function_options_async",
    ] {
        plan.vary(
            "api.runtime_library.metal3_precise",
            &format!("pipeline_{mode}"),
            |case| case.set("pipeline_creation", mode),
        );
    }
    for mode in [
        "function_options",
        "function_options_async",
        "descriptor_async",
    ] {
        plan.vary(
            "api.reflection.compute",
            &format!("pipeline_{mode}"),
            |case| case.set("pipeline_creation", mode),
        );
    }
    plan.vary("api.reflection.render", "pipeline_async", |case| {
        case.set("pipeline_creation", "async")
    });
    plan.vary(
        "arguments.visible_function_tables.fragment.single",
        "pipeline_async",
        |case| case.set("pipeline_creation", "async"),
    );
    plan.vary("pipelines.linked.mesh", "pipeline_async", |case| {
        case.set("pipeline_creation", "async")
    });
    for mode in ["descriptor", "async"] {
        plan.vary(
            "arguments.constants.all",
            &format!("functions_{mode}"),
            |case| case.set("creation", mode),
        );
        plan.vary(
            "arguments.visible_function_table.binary",
            &format!("functions_{mode}"),
            |case| case.set("creation", mode),
        );
    }
    plan.vary("arguments.stitched_function", "functions_async", |case| {
        case.set("creation", "async")
    });
}

pub fn build(plan: &mut Plan) {
    if plan.has("arguments.metal", "visible_table") {
        compute(plan);
    }
    if plan.has("arguments.metal", "visible_pair") {
        render(plan);
    }
    linked(plan, &mut Random::new(2101));
    encoders(plan);
    creation(plan);
}
