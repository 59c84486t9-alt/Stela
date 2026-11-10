//! corpus/api.metal: the API around shaders. Buffers and textures in each
//! storage mode, filled and read back by the CPU (host copies, padded rows,
//! no-copy buffers, linear textures over buffers) or by blits; constants
//! set inline; visibility results, timestamps and statistics; shader
//! logging; pipeline reflection; libraries compiled from source at run
//! time; alpha to one; rendering into one level, slice, plane or face;
//! depth and stencil resolves; indexed indirect draws; primitive restart;
//! wireframe fill; and two and eight samples. Every result is one the
//! specification fixes, or a relation it fixes where a value is the
//! device's (timestamps, which samples a line lights).
use super::plan::{Buffer, Case, Output, Plan, Step, Texture, Tolerance, VERSIONS};
use super::textures::{decode, format_named, texel_bytes};
use super::values::{Dtype, Random, f16_bits, f32s, ints, u32s};
use serde_json::{Value, json};

const SOURCE: &str = "api.metal";

fn u64s(values: &[u64]) -> Vec<u8> {
    ints(
        Dtype::U64,
        &values.iter().map(|&v| i128::from(v)).collect::<Vec<_>>(),
    )
}

fn touched(v: &[u32]) -> Vec<u32> {
    v.iter()
        .enumerate()
        .map(|(i, &x)| x.wrapping_mul(2).wrapping_add(i as u32))
        .collect()
}

/// A full-target strip drawn with a rectangle and colour set inline.
fn inline_rect(rect: [f64; 4], color: [f64; 4]) -> [Buffer; 2] {
    [
        Buffer::data("rect", 0, f32s(&rect))
            .stage("vertex")
            .set("inline", true),
        Buffer::data("color", 0, f32s(&color))
            .stage("fragment")
            .set("inline", true),
    ]
}

fn strip(state: Value) -> Value {
    let mut state = state;
    state["primitive"] = "triangle_strip".into();
    state["vertex_count"] = state.get("vertex_count").cloned().unwrap_or(4.into());
    state
}

/// One colour over texels where `inside` holds, zero elsewhere.
fn image(w: u32, h: u32, color: [f64; 4], inside: impl Fn(u32, u32) -> bool) -> Vec<u8> {
    let texels: Vec<f64> = (0..h)
        .flat_map(|y| (0..w).map(move |x| (x, y)))
        .flat_map(|(x, y)| if inside(x, y) { color } else { [0.0; 4] })
        .collect();
    f32s(&texels)
}

fn storage(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 256u32;
    let v: Vec<u32> = (0..n).map(|_| rng.u32()).collect();
    // Write-combined memory the CPU writes but does not read back fast;
    // the results arrive through a copy as for private storage.
    for (name, mode, no_copy, write_combined) in [
        ("shared", "shared", false, false),
        ("managed", "managed", false, false),
        ("private", "private", false, false),
        ("no_copy", "shared", true, false),
        ("managed_no_copy", "managed", true, false),
        ("shared.write_combined", "shared", false, true),
        ("managed.write_combined", "managed", false, true),
    ] {
        let mut data = Buffer::data("data", 0, u32s(&v)).set("storage", mode);
        if no_copy {
            data = data.set("no_copy", true);
        }
        if write_combined {
            data = data.set("write_combined", true);
        }
        plan.add(
            Case::compute1(&format!("api.storage.buffer.{name}"), library, "touch", n)
                .buffer(data)
                .output(Output::exact("data", Dtype::U32, u32s(&touched(&v))).set("length", n * 4)),
        );
    }
    // A texture written by a kernel from another, each in a storage mode:
    // filled by host copies with rows padded or not, or by a blit.
    let (w, h) = (16u32, 8u32);
    let f = format_named("rgba8unorm");
    let texels: Vec<u8> = (0..w * h).flat_map(|_| texel_bytes(&f, rng)).collect();
    let inverted: Vec<u8> = texels.iter().map(|&b| 255 - b).collect();
    for (name, mode, pad) in [
        ("shared", "shared", 0),
        ("shared.padded", "shared", 12),
        ("managed", "managed", 0),
        ("managed.padded", "managed", 4),
        ("private", "private", 0),
        ("shared.write_combined", "shared", 0),
    ] {
        plan.add(
            Case::compute(
                &format!("api.storage.texture.{name}"),
                library,
                "invert_texture",
                [w, h, 1],
                [8, 8, 1],
            )
            .texture(
                Texture::d2("in", "rgba8unorm", w, h)
                    .index(0)
                    .set("storage", mode)
                    .set("row_padding", pad)
                    .set("write_combined", name.ends_with("write_combined"))
                    .data(texels.clone()),
            )
            .texture(
                Texture::d2("out", "rgba8unorm", w, h)
                    .index(1)
                    .usage(&["write"])
                    .set("storage", mode),
            )
            .output(Output::exact("out", Dtype::U8, inverted.clone())),
        );
    }
    // Every slice and level of an array and of a 3D texture, through the
    // host's copies alone.
    let array: Vec<u8> = (0..3)
        .flat_map(|_| [64u32, 16, 4].map(|t| t as usize).to_vec())
        .flat_map(|texels| {
            (0..texels * 8)
                .map(|_| (rng.u32() % 256) as u8)
                .collect::<Vec<_>>()
        })
        .collect();
    let volume: Vec<u8> = (0..8 * 4 * 4 * 4)
        .map(|_| (rng.u32() % 256) as u8)
        .collect();
    for (mode, pad) in [("shared", 0), ("shared", 20), ("managed", 8)] {
        let suffix = if pad > 0 { ".padded" } else { "" };
        plan.add(
            Case::compute1(
                &format!("api.host_copy.array_levels.{mode}{suffix}"),
                library,
                "nothing",
                1,
            )
            .texture(
                Texture::new("t", "rgba16uint", "2d_array", [8, 8, 1])
                    .array(3)
                    .mipmaps(3)
                    .set("storage", mode)
                    .set("row_padding", pad)
                    .data(array.clone()),
            )
            .output(Output::exact("t", Dtype::U16, array.clone())),
        );
        plan.add(
            Case::compute1(
                &format!("api.host_copy.volume.{mode}{suffix}"),
                library,
                "nothing",
                1,
            )
            .texture(
                Texture::new("t", "r32float", "3d", [8, 4, 4])
                    .set("storage", mode)
                    .set("row_padding", pad)
                    .data(volume.clone()),
            )
            .output(Output::exact("t", Dtype::U8, volume.clone())),
        );
    }
    // A linear texture over a buffer's rows, 256 bytes apart.
    let row = 256usize;
    let mut bytes = vec![0u8; row * h as usize];
    let mut expect = vec![];
    for y in 0..h as usize {
        for x in 0..w as usize {
            let t = texel_bytes(&f, rng);
            bytes[y * row + 4 * x..y * row + 4 * x + 4].copy_from_slice(&t);
            expect.extend(decode(&f, &t));
        }
    }
    plan.add(
        Case::compute(
            "api.linear_texture",
            library,
            "read_rows",
            [w, h, 1],
            [8, 8, 1],
        )
        .buffer(Buffer::data("rows", 0, bytes).unbound())
        .buffer(Buffer::zeroed("out", 0, (w * h * 16) as usize))
        .texture(
            Texture::d2("t", "rgba8unorm", w, h)
                .index(0)
                .set("over_buffer", "rows")
                .set("bytes_per_row", row),
        )
        .output(Output::new("out", Dtype::F32, Tolerance::ulp(1.0)).expect_same(f32s(&expect))),
    );
}

fn inline_constants(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 64u32;
    let v: Vec<u32> = (0..n).map(|_| rng.u32() % 1000).collect();
    let (scale, offset, weights) = (3u32, 11u32, [1.0f64, 2.0, 5.0, 9.0]);
    let mut params = u32s(&[scale, offset, 0, 0]);
    params.extend(f32s(&weights));
    let expect: Vec<u32> = v
        .iter()
        .enumerate()
        .map(|(i, &x)| x * scale + offset + weights[i % 4] as u32)
        .collect();
    plan.add(
        Case::compute1("api.inline.compute", library, "params", n)
            .buffer(Buffer::data("data", 0, u32s(&v)))
            .buffer(Buffer::data("params", 1, params).set("inline", true))
            .output(Output::exact("data", Dtype::U32, u32s(&expect))),
    );
    let color = [0.25, 0.5, 0.75, 1.0];
    plan.add(
        Case::render(
            "api.inline.render",
            library,
            "vert_inline_rect",
            Some("frag_flat"),
            strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}]})),
        )
        .buffers(inline_rect([-1.0, -1.0, 0.0, 1.0], color))
        .texture(Texture::d2("a", "rgba32float", 8, 8).usage(&["render"]))
        .output(Output::exact(
            "a",
            Dtype::F32,
            image(8, 8, color, |x, _| x < 4),
        )),
    );
}

/// Three rectangles over a depth-tested target: a full one at 0.5, a full
/// one behind it at 0.75 and a quarter in front at 0.25.
fn visibility(plan: &mut Plan, library: &str) {
    let rects = f32s(&[
        -1.0, -1.0, 1.0, 1.0, 0.5, 0.0, 0.0, 0.0, //
        -1.0, -1.0, 1.0, 1.0, 0.75, 0.0, 0.0, 0.0, //
        -1.0, -1.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0,
    ]);
    let draws: Vec<Value> = (0..3)
        .map(|k| json!({"vertex_start": 4 * k, "vertex_count": 4, "visibility_offset": 8 * k}))
        .collect();
    // Results reset when the pass begins, or added to what the buffer
    // already holds.
    for (kind, expect) in [("reset", [64u64, 0, 16]), ("accumulate", [69, 5, 21])] {
        plan.add(
            Case::render(
                &format!("api.visibility.counting.{kind}"),
                library,
                "vert_depth_rect",
                Some("frag_flat"),
                strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}],
                             "depth": {"texture": "depth", "clear": 1.0, "compare": "less"},
                             "visibility": {"buffer": "visibility", "mode": "counting", "type": kind},
                             "draws": draws})),
            )
            .buffer(Buffer::data("rects", 0, rects.clone()).stage("vertex"))
            .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).stage("fragment"))
            .buffer(Buffer::data("visibility", 0, u64s(&[5; 3])).unbound())
            .texture(Texture::d2("a", "rgba8unorm", 8, 8).usage(&["render"]))
            .texture(Texture::d2("depth", "depth32float", 8, 8).usage(&["render"]))
            .output(Output::exact("visibility", Dtype::U64, u64s(&expect))),
        );
    }
    // Counting turned off for the third draw, whose result stays zero.
    let mut disabled = draws.clone();
    disabled[2]["visibility_mode"] = "disabled".into();
    plan.add(
        Case::render(
            "api.visibility.counting.disabled_draw",
            library,
            "vert_depth_rect",
            Some("frag_flat"),
            strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}],
                         "depth": {"texture": "depth", "clear": 1.0, "compare": "less"},
                         "visibility": {"buffer": "visibility", "mode": "counting"}, "draws": disabled})),
        )
        .buffer(Buffer::data("rects", 0, rects.clone()).stage("vertex"))
        .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).stage("fragment"))
        .buffer(Buffer::zeroed("visibility", 0, 24).unbound())
        .texture(Texture::d2("a", "rgba8unorm", 8, 8).usage(&["render"]))
        .texture(Texture::d2("depth", "depth32float", 8, 8).usage(&["render"]))
        .output(Output::exact("visibility", Dtype::U64, u64s(&[64, 0, 0]))),
    );
    for (mode, expect) in [("counting", vec![64u64, 0, 16]), ("boolean", vec![1, 0, 1])] {
        let mut out = Output::new("visibility", Dtype::U64, Tolerance::exact());
        out = if mode == "boolean" {
            // Boolean mode writes a nonzero value, of the device's choice.
            out.set("derive", "nonzero")
                .expect_same(u32s(&expect.iter().map(|&v| v as u32).collect::<Vec<_>>()))
        } else {
            out.expect_same(u64s(&expect))
        };
        plan.add(
            Case::render(
                &format!("api.visibility.{mode}"),
                library,
                "vert_depth_rect",
                Some("frag_flat"),
                strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}],
                             "depth": {"texture": "depth", "clear": 1.0, "compare": "less"},
                             "visibility": {"buffer": "visibility", "mode": mode}, "draws": draws})),
            )
            .buffer(Buffer::data("rects", 0, rects.clone()).stage("vertex"))
            .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).stage("fragment"))
            .buffer(Buffer::zeroed("visibility", 0, 24).unbound())
            .texture(Texture::d2("a", "rgba8unorm", 8, 8).usage(&["render"]))
            .texture(Texture::d2("depth", "depth32float", 8, 8).usage(&["render"]))
            .output(out),
        );
    }
}

fn counters(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 256u32;
    let v: Vec<u32> = (0..n).map(|_| rng.u32()).collect();
    let timestamps = ["counters_stage_boundary", "counter_set_timestamp"];
    plan.add(
        Case::compute1("api.counters.compute_timestamps", library, "touch", n)
            .requires(&[], &timestamps)
            .set("timestamps", json!({"buffer": "stamps"}))
            .buffer(Buffer::data("data", 0, u32s(&v)))
            .buffer(Buffer::zeroed("stamps", 0, 16).unbound())
            .output(Output::exact("data", Dtype::U32, u32s(&touched(&v))))
            .output(Output::exact("stamps", Dtype::U64, u32s(&[1, 1])).set("derive", "ordered")),
    );
    plan.add(
        Case::render(
            "api.counters.render_timestamps",
            library,
            "vert_inline_rect",
            Some("frag_flat"),
            strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}],
                         "timestamps": {"buffer": "stamps"}})),
        )
        .requires(&[], &timestamps)
        .buffers(inline_rect([-1.0, -1.0, 1.0, 1.0], [1.0; 4]))
        .buffer(Buffer::zeroed("stamps", 0, 32).unbound())
        .texture(Texture::d2("a", "rgba8unorm", 8, 8).usage(&["render"]))
        .output(Output::exact("stamps", Dtype::U64, u32s(&[1, 1, 1, 1])).set("derive", "nonzero")),
    );
    // Statistics between the encoder's start and end: one kernel
    // invocation per thread and no other stage's work.
    let mut stats = [0u64; 8];
    stats[7] = u64::from(n);
    plan.add(
        Case::compute1("api.counters.compute_statistics", library, "touch", n)
            .requires(&[], &["counters_stage_boundary", "counter_set_statistic"])
            .set(
                "timestamps",
                json!({"buffer": "stats", "counters": "statistic"}),
            )
            .buffer(Buffer::data("data", 0, u32s(&v)))
            .buffer(Buffer::zeroed("stats", 0, 64).unbound())
            .output(Output::exact("stats", Dtype::U64, u64s(&stats))),
    );
}

/// What `log_values` logs: the format strings filled in, with each
/// message's subsystem, category and `MTLLogLevel`.
fn logging(plan: &mut Plan, rng: &mut Random) {
    let library = plan.library("api_logging", SOURCE, &["-fmetal-enable-logging"], "3.2");
    let data = [rng.u32(), (-12345i32) as u32, 0xBEEF, 77, 13, 5];
    let text = format!(
        "- - 3 value {} signed -12345 hex beef\n\
         com.stela.suite api 1 debug 77\n\
         com.stela.suite api 2 info 1.625\n\
         com.stela.suite api 4 error text 15\n\
         com.stela.suite api 5 fault 5\n",
        data[0]
    );
    let mut expect = text.into_bytes();
    expect.resize(1024, 0);
    // The same messages from the library the device compiles with
    // logging enabled by its compile options.
    let runtime = plan.runtime_library(
        "api_logging_runtime",
        SOURCE,
        json!({"language": "3.2", "logging": true}),
    );
    for (name, library) in [("api.log", &library), ("api.log.runtime", &runtime)] {
        plan.add(
            Case::compute1(name, library, "log_values", 64)
                .requires(&[], &["logging"])
                .set("log", json!({"buffer": "log", "lines": 5}))
                .buffer(Buffer::data("data", 0, u32s(&data)))
                .buffer(Buffer::zeroed("log", 0, 1024).unbound())
                .output(Output::exact("log", Dtype::U8, expect.clone())),
        );
    }
}

fn reflection(plan: &mut Plan, library: &str) {
    let text = |lines: &[&str]| {
        let mut t = lines.join("\n").into_bytes();
        t.resize(2048, 0);
        t
    };
    plan.add(
        Case::compute1("api.reflection.compute", library, "reflected", 64)
            .set("reflection", "reflection")
            .set("reflection_only", true)
            .buffer(Buffer::zeroed("reflection", 0, 2048).unbound())
            .output(Output::exact(
                "reflection",
                Dtype::U8,
                text(&COMPUTE_REFLECTION),
            )),
    );
    plan.add(
        Case::render(
            "api.reflection.render",
            library,
            "vert_depth_rect",
            Some("frag_flat"),
            strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}]})),
        )
        .set("reflection", "reflection")
        .buffer(
            Buffer::data(
                "rects",
                0,
                f32s(&[-1.0, -1.0, 1.0, 1.0, 0.5, 0.0, 0.0, 0.0]),
            )
            .stage("vertex"),
        )
        .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).stage("fragment"))
        .buffer(Buffer::zeroed("reflection", 0, 2048).unbound())
        .texture(Texture::d2("a", "rgba8unorm", 4, 4).usage(&["render"]))
        .output(Output::exact(
            "reflection",
            Dtype::U8,
            text(&RENDER_REFLECTION),
        )),
    );
}

/// Reflection in full and through the older arguments: `reflected`'s
/// bindings as `MTLArgument`s, a vertex and fragment pipeline's, and
/// `reflected_types`, whose nested structs, arrays, pointers, argument
/// buffer of textures and sampler, and atomic reflection describes
/// member by member (name@offset#argument index:data type=type).
fn reflection_types(plan: &mut Plan, library: &str) {
    let text = |lines: &[&str]| {
        let mut t = lines.join("\n").into_bytes();
        t.resize(4096, 0);
        t
    };
    plan.add(
        Case::compute1("api.reflection.compute.arguments", library, "reflected", 64)
            .set("reflection", "reflection")
            .set("reflection_only", true)
            .set("reflection_arguments", true)
            .buffer(Buffer::zeroed("reflection", 0, 4096).unbound())
            .output(Output::exact(
                "reflection",
                Dtype::U8,
                text(&COMPUTE_ARGUMENTS),
            )),
    );
    plan.add(
        Case::render(
            "api.reflection.render.arguments",
            library,
            "vert_depth_rect",
            Some("frag_flat"),
            strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}]})),
        )
        .set("reflection", "reflection")
        .set("reflection_arguments", true)
        .buffer(
            Buffer::data(
                "rects",
                0,
                f32s(&[-1.0, -1.0, 1.0, 1.0, 0.5, 0.0, 0.0, 0.0]),
            )
            .stage("vertex"),
        )
        .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).stage("fragment"))
        .buffer(Buffer::zeroed("reflection", 0, 4096).unbound())
        .texture(Texture::d2("a", "rgba8unorm", 4, 4).usage(&["render"]))
        .output(Output::exact(
            "reflection",
            Dtype::U8,
            text(&RENDER_ARGUMENTS),
        )),
    );
    let n = 4u32;
    for (suffix, legacy, expect) in [
        ("", false, &TYPES_REFLECTION[..]),
        (".arguments", true, &TYPES_ARGUMENTS[..]),
    ] {
        plan.add(
            Case::compute1(
                &format!("api.reflection.types{suffix}"),
                library,
                "reflected_types",
                n,
            )
            .set("dispatch", "threads")
            .set("reflection", "reflection")
            .set("reflection_types", !legacy)
            .set("reflection_arguments", legacy)
            .buffer(Buffer::zeroed("outer", 0, 80 * n as usize))
            .buffer(Buffer::zeroed("res", 1, 48))
            .buffer(Buffer::zeroed("count", 2, 16))
            .buffer(Buffer::data("data", 0, f32s(&[1.0; 4])).unbound())
            .buffer(Buffer::zeroed("reflection", 0, 4096).unbound())
            .texture(Texture::d2("image", "rgba8unorm", 2, 2))
            .texture(Texture::d2("shadow", "depth32float", 2, 2))
            .texture(Texture::d2("layer0", "rgba8unorm", 2, 2))
            .texture(Texture::d2("layer1", "rgba8unorm", 2, 2))
            .sampler(json!({"name": "s", "argument_buffers": true}))
            .set(
                "arguments",
                json!([{"buffer": "res", "entries": [
                    {"kind": "texture", "offset": 0, "resource": "image"},
                    {"kind": "texture", "offset": 8, "resource": "shadow"},
                    {"kind": "sampler", "offset": 16, "resource": "s"},
                    {"kind": "buffer", "offset": 24, "resource": "data"},
                    {"kind": "texture", "offset": 32, "resource": "layer0"},
                    {"kind": "texture", "offset": 40, "resource": "layer1"}]}]),
            )
            .output(Output::exact("count", Dtype::U32, u32s(&[n, 0, 0, 0])))
            .output(Output::exact("reflection", Dtype::U8, text(expect))),
        );
    }
}

/// `reflected`'s bindings as the older `MTLArgument`s list them: each
/// active, with its pointee in full.
const COMPUTE_ARGUMENTS: [&str; 9] = [
    "items type=0 index=0 access=1 active=1 size=80 align=16 data=1 pointer=*(1 access=1 align=16 size=80 argument_buffer=0 {position@0#0:6 id@16#0:33 uv@20#0:17 basis@32#0:11})",
    "weights type=0 index=2 access=0 active=1 size=16 align=16 data=6 pointer=*(6 access=0 align=16 size=16 argument_buffer=0)",
    "ids type=0 index=5 access=0 active=1 size=4 align=4 data=33 pointer=*(33 access=0 align=4 size=4 argument_buffer=0)",
    "scratch type=1 index=0 access=1 active=1 size=4 align=4",
    "src type=2 index=0 access=0 active=1 texture=2 data=16 depth=0 array=1",
    "dst type=2 index=3 access=2 active=1 texture=3 data=33 depth=0 array=1",
    "shadow type=2 index=4 access=0 active=1 texture=2 data=3 depth=1 array=1",
    "s type=3 index=1 access=0 active=1",
    "static_threadgroup_memory=256\n",
];

const RENDER_ARGUMENTS: [&str; 5] = [
    "vertex",
    "rects type=0 index=0 access=0 active=1 size=32 align=16 data=1 pointer=*(1 access=0 align=16 size=32 argument_buffer=0 {rect@0#0:6 depth@16#0:6})",
    "fragment",
    "color type=0 index=0 access=0 active=1 size=16 align=16 data=6 pointer=*(6 access=0 align=16 size=16 argument_buffer=0)",
    "",
];

/// `Outer` is 80 bytes: its color, two 24-byte `Inner`s (a float2 and
/// three uints, aligned to 8) from 16, and a packed float3 at 64. The
/// argument buffer holds 8-byte texture, sampler and pointer entries,
/// each at its own argument index, the texture array's two from 4.
const TYPES_REFLECTION: [&str; 5] = [
    "outer type=0 index=0 access=1 used=1 argument=1 size=80 align=16 data=1 color@0:6 inner@16:2 p@64:5 pointer=*(1 access=1 align=16 size=80 argument_buffer=0 {color@0#0:6 inner@16#0:2=[2 stride=24 ids=0 1 {uv@0#0:4 ids@8#0:2=[3 stride=4 ids=0 33]}] p@64#0:5})",
    "res type=0 index=1 access=0 used=1 argument=1 size=48 align=8 data=1 image@0:58 shadow@8:58 s@16:59 data@24:60 layers@32:2 pointer=*(1 access=0 align=8 size=48 argument_buffer=1 {image@0#0:58=texture(2 data=3 access=0 depth=0) shadow@8#1:58=texture(2 data=3 access=0 depth=1) s@16#2:59 data@24#3:60=*(3 access=1 align=4 size=4 argument_buffer=0) layers@32#4:2=[2 stride=0 ids=1 58 texture(2 data=3 access=0 depth=0)]})",
    "count type=0 index=2 access=1 used=1 argument=1 size=4 align=4 data=1 __s@0:33 pointer=*(1 access=1 align=4 size=4 argument_buffer=0 {__s@0#0:33})",
    "static_threadgroup_memory=0",
    "state=none\n",
];

const TYPES_ARGUMENTS: [&str; 4] = [
    "outer type=0 index=0 access=1 active=1 size=80 align=16 data=1 pointer=*(1 access=1 align=16 size=80 argument_buffer=0 {color@0#0:6 inner@16#0:2=[2 stride=24 ids=0 1 {uv@0#0:4 ids@8#0:2=[3 stride=4 ids=0 33]}] p@64#0:5})",
    "res type=0 index=1 access=0 active=1 size=48 align=8 data=1 pointer=*(1 access=0 align=8 size=48 argument_buffer=1 {image@0#0:58=texture(2 data=3 access=0 depth=0) shadow@8#1:58=texture(2 data=3 access=0 depth=1) s@16#2:59 data@24#3:60=*(3 access=1 align=4 size=4 argument_buffer=0) layers@32#4:2=[2 stride=0 ids=1 58 texture(2 data=3 access=0 depth=0)]})",
    "count type=0 index=2 access=1 active=1 size=4 align=4 data=1 pointer=*(1 access=1 align=4 size=4 argument_buffer=0 {__s@0#0:33})",
    "static_threadgroup_memory=0\n",
];

/// Each binding of `reflected` as `MTLComputePipelineReflection` lists
/// it: `MTLBindingType`, index, `MTLBindingAccess`, whether used and an
/// argument, then a buffer's data size, alignment, `MTLDataType` and
/// struct members, a texture's `MTLTextureType`, data type, depth and
/// array length, or threadgroup memory's size and alignment.
const COMPUTE_REFLECTION: [&str; 9] = [
    "items type=0 index=0 access=1 used=1 argument=1 size=80 align=16 data=1 position@0:6 id@16:33 uv@20:17 basis@32:11",
    "weights type=0 index=2 access=0 used=1 argument=1 size=16 align=16 data=6",
    "ids type=0 index=5 access=0 used=1 argument=1 size=4 align=4 data=33",
    "scratch type=1 index=0 access=1 used=1 argument=1 size=4 align=4",
    "src type=2 index=0 access=0 used=1 argument=1 texture=2 data=16 depth=0 array=1",
    "dst type=2 index=3 access=2 used=1 argument=1 texture=3 data=33 depth=0 array=1",
    "shadow type=2 index=4 access=0 used=1 argument=1 texture=2 data=3 depth=1 array=1",
    "s type=3 index=1 access=0 used=1 argument=1",
    "static_threadgroup_memory=256\n",
];

const RENDER_REFLECTION: [&str; 5] = [
    "vertex",
    "rects type=0 index=0 access=0 used=1 argument=1 size=32 align=16 data=1 rect@0:6 depth@16:6",
    "fragment",
    "color type=0 index=0 access=0 used=1 argument=1 size=16 align=16 data=6",
    "",
];

fn runtime(plan: &mut Plan, rng: &mut Random) {
    let n = 64u32;
    let v: Vec<u32> = (0..n).map(|_| rng.u32() % 100_000).collect();
    for (name, options, scale, offset, version) in [
        (
            "metal3_precise",
            json!({"language": "3.0", "fast_math": false, "macros": {"SCALE": "3u"}}),
            3,
            7,
            300,
        ),
        (
            "metal2_size",
            json!({"language": "2.4", "fast_math": true, "optimization": "size",
                   "macros": {"SCALE": "5u", "OFFSET": "1u"}}),
            5,
            1,
            240,
        ),
    ] {
        let library =
            plan.runtime_library(&format!("api_runtime_{name}"), "api_runtime.metal", options);
        let expect: Vec<u32> = v.iter().map(|&x| x * scale + offset + version).collect();
        plan.add(
            Case::compute1(
                &format!("api.runtime_library.{name}"),
                &library,
                "runtime_scale",
                n,
            )
            .buffer(Buffer::data("data", 0, u32s(&v)))
            .output(Output::exact("data", Dtype::U32, u32s(&expect))),
        );
    }
    // Every language version an application may ask for, each seen by
    // the source as its __METAL_VERSION__.
    for (language, .., number) in VERSIONS {
        let label = language.replace('.', "_");
        let library = plan.runtime_library(
            &format!("api_runtime_language_{label}"),
            "api_runtime.metal",
            json!({"language": language, "macros": {"SCALE": "2u"}}),
        );
        let expect: Vec<u32> = v.iter().map(|&x| x * 2 + 7 + number).collect();
        plan.add(
            Case::compute1(
                &format!("api.runtime_library.language_{label}"),
                &library,
                "runtime_scale",
                n,
            )
            .buffer(Buffer::data("data", 0, u32s(&v)))
            .output(Output::exact("data", Dtype::U32, u32s(&expect))),
        );
    }
}

/// A float's nearest half toward zero: the bits round down in magnitude,
/// and a magnitude past the largest half saturates to it.
fn f16_toward_zero(x: f64) -> u16 {
    let sign = if x.is_sign_negative() { 0x8000 } else { 0 };
    let a = x.abs();
    if a.is_nan() {
        return sign | 0x7E00;
    }
    if a.is_infinite() {
        return sign | 0x7C00;
    }
    if a < 2f64.powi(-14) {
        return sign | (a * 2f64.powi(24)).trunc() as u16;
    }
    let exponent = ((a.to_bits() >> 52) & 0x7FF) as i32 - 1023;
    if exponent > 15 {
        return sign | 0x7BFF;
    }
    let mantissa = ((a / 2f64.powi(exponent) - 1.0) * 1024.0).trunc() as u16;
    sign | ((exponent + 15) as u16) << 10 | mantissa
}

/// Compile options that change what a kernel computes or how it runs:
/// the rounding of float-to-half conversions, a required threadgroup
/// size, and logging enabled at run time rather than by a build flag.
fn runtime_options(plan: &mut Plan, rng: &mut Random) {
    let mut input: Vec<f64> = vec![
        1.0 + 2f64.powi(-11) + 2f64.powi(-20),
        -(1.0 + 2f64.powi(-11) + 2f64.powi(-20)),
        1.0 + 3.0 * 2f64.powi(-11),
        70000.0,
        -70000.0,
        3.0 * 2f64.powi(-25),
        65519.0,
        0.1,
    ];
    input.extend((0..56).map(|_| f64::from(rng.uniform(-300.0, 300.0) as f32)));
    let input: Vec<f64> = input.iter().map(|&x| f64::from(x as f32)).collect();
    for (mode, narrow) in [
        ("nearest_even", f16_bits as fn(f64) -> u16),
        ("toward_zero", f16_toward_zero),
    ] {
        let library = plan.runtime_library(
            &format!("api_runtime_rounding_{mode}"),
            "api_runtime.metal",
            json!({"conversion_rounding": mode, "macros": {"SCALE": "1u"}}),
        );
        let expect: Vec<u8> = input
            .iter()
            .flat_map(|&x| narrow(x).to_le_bytes())
            .collect();
        plan.add(
            Case::compute1(
                &format!("api.runtime_library.conversion_rounding.{mode}"),
                &library,
                "runtime_narrow",
                input.len() as u32,
            )
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::zeroed("out", 1, input.len() * 2))
            .output(Output::exact("out", Dtype::U16, expect)),
        );
    }
    let library = plan.runtime_library(
        "api_runtime_required_threads",
        "api_runtime.metal",
        json!({"required_threads": [64, 1, 1], "macros": {"SCALE": "1u"}}),
    );
    let words: Vec<u32> = (0..128u32).flat_map(|i| [64, 1, 1, i % 64]).collect();
    plan.add(
        Case::compute1(
            "api.runtime_library.required_threads",
            &library,
            "runtime_group",
            128,
        )
        .buffer(Buffer::zeroed("out", 0, 128 * 16))
        .output(Output::exact("out", Dtype::U32, u32s(&words))),
    );
}

fn targets(plan: &mut Plan, library: &str) {
    let color = [0.25, 0.5, 0.75, 1.0];
    for (on, expect) in [(false, [0.25, 0.5, 0.75, 0.3]), (true, color)] {
        plan.add(
            Case::render(
                &format!("api.alpha_to_one.{}", if on { "on" } else { "off" }),
                library,
                "vert_inline_rect",
                Some("frag_translucent"),
                strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "alpha_to_one": on})),
            )
            .buffer(inline_rect([-1.0, -1.0, 1.0, 1.0], color)[0].clone())
            .texture(Texture::d2("a", "rgba32float", 4, 4).usage(&["render"]))
            .output(
                Output::new("a", Dtype::F32, Tolerance::ulp(1.0))
                    .expect_same(image(4, 4, expect, |_, _| true)),
            ),
        );
    }
    // One subresource of each kind of texture rendered into, the others
    // keeping their zeros.
    let size = 4u32;
    let face = size * size * 16;
    let zeros = |bytes: u32| vec![0u8; bytes as usize];
    let lit = image(size, size, color, |_, _| true);
    let empty = |texels: u32| zeros(texels * 16);
    let cases: Vec<(&str, Texture, Value, Vec<u8>)> = vec![
        (
            "slice",
            Texture::new("a", "rgba32float", "2d_array", [size, size, 1]).array(3),
            json!({"slice": 1}),
            [empty(16), lit.clone(), empty(16)].concat(),
        ),
        (
            "level",
            Texture::d2("a", "rgba32float", 2 * size, 2 * size).mipmaps(3),
            json!({"level": 1}),
            [empty(64), lit.clone(), empty(4)].concat(),
        ),
        (
            "depth_plane",
            Texture::new("a", "rgba32float", "3d", [size, size, 3]),
            json!({"depth_plane": 2}),
            [empty(32), lit.clone()].concat(),
        ),
        (
            "cube_face",
            Texture::new("a", "rgba32float", "cube", [size, size, 1]),
            json!({"slice": 4}),
            [zeros(4 * face), lit.clone(), zeros(face)].concat(),
        ),
    ];
    for (name, texture, at, expect) in cases {
        let mut attachment =
            json!({"texture": "a", "clear": [color[0], color[1], color[2], color[3]]});
        for (k, v) in at.as_object().unwrap() {
            attachment[k] = v.clone();
        }
        let initial = zeros(expect.len() as u32);
        plan.add(
            Case::render(
                &format!("api.render_into.{name}"),
                library,
                "vert_inline_rect",
                Some("frag_flat"),
                strip(json!({"colors": [attachment]})),
            )
            .buffers(inline_rect([-1.0, -1.0, 1.0, 1.0], color))
            .texture(texture.usage(&["render"]).data(initial))
            .output(Output::exact("a", Dtype::F32, expect)),
        );
    }
    // Framebuffer reads of attachments no storage view reads, which render
    // in copies of their texels: a 3D texture's depth plane and an A8Unorm
    // texture, each the colour less its clear colour.
    let white = [1.0; 4];
    plan.add(
        Case::render(
            "api.render_into.depth_plane.read",
            library,
            "vert_inline_rect",
            Some("frag_flat_less_target"),
            strip(json!({"colors": [{"texture": "a", "depth_plane": 2,
                                     "clear": [color[0], color[1], color[2], color[3]]}]})),
        )
        .buffers(inline_rect([-1.0, -1.0, 1.0, 1.0], white))
        .texture(
            Texture::new("a", "rgba32float", "3d", [size, size, 3])
                .usage(&["render"])
                .data(zeros(3 * face)),
        )
        .output(Output::exact(
            "a",
            Dtype::F32,
            [
                empty(32),
                image(size, size, [0.75, 0.5, 0.25, 0.0], |_, _| true),
            ]
            .concat(),
        ))
        .requires(&["apple3"], &[]),
    );
    // 0.6 and 0.4 are 153 and 102 of 255.
    plan.add(
        Case::render(
            "api.render_into.a8unorm.read",
            library,
            "vert_inline_rect",
            Some("frag_flat_less_target"),
            strip(json!({"colors": [{"texture": "a", "clear": [0.0, 0.0, 0.0, 0.6]}]})),
        )
        .buffers(inline_rect([-1.0, -1.0, 1.0, 1.0], white))
        .texture(
            Texture::d2("a", "a8unorm", size, size)
                .usage(&["render"])
                .data(zeros(size * size)),
        )
        .output(Output::exact(
            "a",
            Dtype::U8,
            vec![102; (size * size) as usize],
        ))
        .requires(&["apple3"], &[]),
    );
    // A multisampled pass resolved into one slice of an array.
    plan.add(
        Case::render(
            "api.render_into.resolve_slice",
            library,
            "vert_inline_rect",
            Some("frag_flat"),
            strip(
                json!({"samples": 4, "colors": [{"texture": "ms", "clear": [0, 0, 0, 0],
                                                   "resolve": "a", "resolve_slice": 2}]}),
            ),
        )
        .buffers(inline_rect([-1.0, -1.0, 1.0, 1.0], color))
        .texture(
            Texture::new("ms", "rgba32float", "2d_ms", [size, size, 1])
                .samples(4)
                .usage(&["render"]),
        )
        .texture(
            Texture::new("a", "rgba32float", "2d_array", [size, size, 1])
                .array(3)
                .usage(&["render"])
                .data(zeros(3 * face)),
        )
        .output(Output::exact("a", Dtype::F32, [empty(32), lit].concat())),
    );
}

/// Four samples at depths 0.1 to 0.4 and stencil 1 to 4, resolved.
fn resolves(plan: &mut Plan, library: &str) {
    let size = 4u32;
    let base = |name: &str, fragment: &str, state: Value| {
        Case::render(
            name,
            library,
            "vert_inline_rect",
            Some(fragment),
            strip(state),
        )
        .buffer(inline_rect([-1.0, -1.0, 1.0, 1.0], [0.0; 4])[0].clone())
        .texture(
            Texture::new("c", "rgba8unorm", "2d_ms", [size, size, 1])
                .samples(4)
                .usage(&["render"]),
        )
    };
    // Samples resolved into the second plane of a 3D texture; the first
    // keeps what it held.
    let pixels = (size * size) as usize;
    let mut planes = vec![0u8; pixels * 4];
    planes.extend([0u8, 255, 51, 255].repeat(pixels));
    plan.add(
        Case::render(
            "api.resolve.depth_plane",
            library,
            "vert_inline_rect",
            Some("frag_flat"),
            strip(json!({"samples": 4, "colors": [{"texture": "c", "clear": [0, 0, 0, 0], "resolve": "volume",
                                                   "resolve_depth_plane": 1}]})),
        )
        .buffers(inline_rect([-1.0, -1.0, 1.0, 1.0], [0.0, 1.0, 0.2, 1.0]))
        .texture(Texture::new("c", "rgba8unorm", "2d_ms", [size, size, 1]).samples(4).usage(&["render"]))
        .texture(
            Texture::new("volume", "rgba8unorm", "3d", [size, size, 2])
                .usage(&["render"])
                .data(vec![0; pixels * 8]),
        )
        .output(Output::exact("volume", Dtype::U8, planes)),
    );
    for (filter, depth) in [("sample0", 0.1f64), ("min", 0.1), ("max", 0.4)] {
        plan.add(
            base(
                &format!("api.resolve.depth.{filter}"),
                "frag_sample_depth_only",
                json!({"samples": 4, "colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                       "depth": {"texture": "ms", "clear": 1.0, "compare": "always",
                                 "resolve": "d", "resolve_filter": filter}}),
            )
            .texture(
                Texture::new("ms", "depth32float", "2d_ms", [size, size, 1])
                    .samples(4)
                    .usage(&["render"]),
            )
            .texture(Texture::d2("d", "depth32float", size, size).usage(&["render"]))
            .output(
                Output::new("d", Dtype::F32, Tolerance::exact())
                    .expect_same(f32s(&vec![f64::from(depth as f32); (size * size) as usize])),
            ),
        );
    }
    for (name, depth_filter, filter, stencil) in [
        ("sample0", "sample0", "sample0", 1u8),
        ("depth_resolved_min", "min", "depth_resolved", 1),
        ("depth_resolved_max", "max", "depth_resolved", 4),
    ] {
        plan.add(
            base(
                &format!("api.resolve.stencil.{name}"),
                "frag_sample_depth",
                json!({"samples": 4, "colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                       "depth": {"texture": "ms", "clear": 1.0, "compare": "always",
                                 "resolve": "d", "resolve_filter": depth_filter},
                       "stencil": {"texture": "ms", "clear": 0, "compare": "always", "pass": "replace",
                                   "resolve": "d", "resolve_filter": filter}}),
            )
            .texture(Texture::new("ms", "depth32float_stencil8", "2d_ms", [size, size, 1]).samples(4).usage(&["render"]))
            .texture(Texture::d2("d", "depth32float_stencil8", size, size).usage(&["render"]))
            .output(
                Output::new("d", Dtype::U8, Tolerance::exact())
                    .set("aspect", "stencil")
                    .set("as", "stencil")
                    .expect_same(vec![stencil; (size * size) as usize]),
            ),
        );
    }
}

fn draws(plan: &mut Plan, library: &str) {
    let (w, h) = (8u32, 8u32);
    let color = [1.0, 0.5, 0.25, 1.0];
    let quad = |x0: f64, x1: f64| [x0, -1.0, x1, -1.0, x0, 1.0, x1, 1.0];
    plan.add(
        Case::render(
            "api.indirect.indexed_draw",
            library,
            "vert_corner",
            Some("frag_flat"),
            strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}],
                         "index_buffer": "indices", "indirect": {"buffer": "arguments", "offset": 0}})),
        )
        .buffer(Buffer::data("corners", 0, f32s(&quad(0.0, 1.0))).stage("vertex"))
        .buffer(Buffer::data("color", 0, f32s(&color)).stage("fragment"))
        .buffer(Buffer::data("indices", 0, ints(Dtype::U16, &[0, 1, 2, 3])).unbound())
        .buffer(Buffer::data("arguments", 0, u32s(&[4, 1, 0, 0, 0])).unbound())
        .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render"]))
        .output(Output::exact("a", Dtype::F32, image(w, h, color, |x, _| x >= 4))),
    );
    // Two strips in one draw, split by the restart index.
    let corners = [quad(-1.0, -0.5), quad(0.5, 1.0)].concat();
    for (kind, restart) in [("uint16", 0xFFFFu32), ("uint32", 0xFFFF_FFFF)] {
        let list = [0, 1, 2, 3, restart, 4, 5, 6, 7];
        let indices = if kind == "uint16" {
            ints(Dtype::U16, &list.map(i128::from))
        } else {
            u32s(&list)
        };
        plan.add(
            Case::render(
                &format!("api.primitive_restart.{kind}"),
                library,
                "vert_corner",
                Some("frag_flat"),
                strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}],
                             "index_buffer": "indices", "index_type": kind, "vertex_count": 9})),
            )
            .buffer(Buffer::data("corners", 0, f32s(&corners)).stage("vertex"))
            .buffer(Buffer::data("color", 0, f32s(&color)).stage("fragment"))
            .buffer(Buffer::data("indices", 0, indices).unbound())
            .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render"]))
            .output(Output::exact(
                "a",
                Dtype::F32,
                image(w, h, color, |x, _| !(2..6).contains(&x)),
            )),
        );
    }
}

/// A triangle drawn as lines: its interior and exterior stay clear and
/// each edge is lit along its length.
fn wireframe(plan: &mut Plan, library: &str) {
    let size = 32u32;
    let ndc = [[-0.75, -0.75], [0.75, -0.75], [0.0, 0.75]];
    let px = ndc.map(|[x, y]| {
        [
            (x + 1.0) / 2.0 * f64::from(size),
            (1.0 - y) / 2.0 * f64::from(size),
        ]
    });
    let edges: Vec<f64> = (0..3)
        .flat_map(|k| {
            let (a, b) = (px[k], px[(k + 1) % 3]);
            [a[0], a[1], b[0], b[1]]
        })
        .collect();
    let distance = |p: [f64; 2], a: [f64; 2], b: [f64; 2]| {
        let (dx, dy) = (b[0] - a[0], b[1] - a[1]);
        let t = (((p[0] - a[0]) * dx + (p[1] - a[1]) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
        ((p[0] - a[0] - t * dx).powi(2) + (p[1] - a[1] - t * dy).powi(2)).sqrt()
    };
    let mask: Vec<u8> = (0..size)
        .flat_map(|y| (0..size).map(move |x| [f64::from(x) + 0.5, f64::from(y) + 0.5]))
        .map(|p| u8::from((0..3).all(|k| distance(p, px[k], px[(k + 1) % 3]) > 2.0)))
        .collect();
    let corners: Vec<f64> = ndc.iter().flatten().copied().collect();
    plan.add(
        Case::sequence(
            "api.wireframe",
            library,
            vec![
                Step::render(
                    "vert_corner",
                    "frag_flat",
                    json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "fill": "lines",
                           "primitive": "triangle", "vertex_count": 3}),
                )
                .bind_stage("vertex", &[("corners", 0)])
                .bind_stage("fragment", &[("color", 0)]),
                Step::compute("edge_hits", [3, 1, 1], [3, 1, 1])
                    .bind(&[("edges", 0), ("hits", 1)])
                    .bind_textures(&[("a", 0)]),
            ],
        )
        .buffer(Buffer::data("corners", 0, f32s(&corners)).unbound())
        .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).unbound())
        .buffer(Buffer::data("edges", 0, f32s(&edges)).unbound())
        .buffer(Buffer::zeroed("hits", 0, 12).unbound())
        .texture(Texture::d2("a", "r32float", size, size).usage(&["render", "read"]))
        .output(Output::exact("hits", Dtype::U32, u32s(&[1, 1, 1])).set("length", 12))
        .output(
            Output::exact("a", Dtype::F32, f32s(&vec![0.0; (size * size) as usize]))
                .expect_mask(mask),
        ),
    );
}

/// Two and eight samples: each sample's value and their resolved mean.
fn sample_counts(plan: &mut Plan, library: &str) {
    let size = 4u32;
    for n in [2u32, 8] {
        let texels = (size * size) as usize;
        let mean = (0..n).map(|s| f64::from(s) / 8.0).sum::<f64>() / f64::from(n);
        plan.add(
            Case::render(
                &format!("api.samples.{n}"),
                library,
                "vert_inline_rect",
                Some("frag_sample_value"),
                strip(json!({"samples": n, "colors": [{"texture": "ms", "clear": [0, 0, 0, 0], "resolve": "a"}]})),
            )
            .requires(&[], &[&format!("samples{n}")])
            .buffer(inline_rect([-1.0, -1.0, 1.0, 1.0], [0.0; 4])[0].clone())
            .texture(Texture::new("ms", "rgba32float", "2d_ms", [size, size, 1]).samples(n).usage(&["render"]))
            .texture(Texture::d2("a", "rgba32float", size, size).usage(&["render"]))
            .output(
                Output::new("a", Dtype::F32, Tolerance::ulp(2.0))
                    .expect_same(f32s(&vec![mean; 4 * texels])),
            ),
        );
    }
}

/// Each depth and stencil format as an attachment: a full rectangle at
/// 0.5, a quarter in front at 0.25 and a full one behind at 0.75, each
/// writing its depth as its colour and replacing the stencil with 7 over
/// a clear of 2. Depth tested, the quarter keeps 0.25, the rest 0.5 and
/// the last draw fails everywhere; stencil alone, the last draw wins.
fn depth_stencil_formats(plan: &mut Plan, library: &str) {
    let size = 8u32;
    let rects = f32s(&[
        -1.0, -1.0, 1.0, 1.0, 0.5, 0.0, 0.0, 0.0, //
        -1.0, -1.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, //
        -1.0, -1.0, 1.0, 1.0, 0.75, 0.0, 0.0, 0.0,
    ]);
    // The quarter at (-1, -1) to (0, 0) covers the bottom-left texels.
    let quarter = move |x: u32, y: u32| x < size / 2 && y >= size / 2;
    let draws: Vec<Value> = (0..3)
        .map(|k| json!({"vertex_start": 4 * k, "vertex_count": 4}))
        .collect();
    for (format, depth, stencil, requires) in [
        ("depth32float", true, false, None),
        ("depth16unorm", true, false, None),
        (
            "depth24unorm_stencil8",
            true,
            true,
            Some("depth24_stencil8"),
        ),
        ("depth32float_stencil8", true, true, None),
        ("stencil8", false, true, None),
    ] {
        let mut state =
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "draws": draws});
        if depth {
            state["depth"] = json!({"texture": "ds", "clear": 1.0, "compare": "less"});
        }
        if stencil {
            state["stencil"] = json!({"texture": "ds", "clear": 2, "compare": "always", "pass": "replace",
                                      "reference": 7});
        }
        let z = |x: u32, y: u32| match (depth, quarter(x, y)) {
            (false, _) => 0.75,
            (true, true) => 0.25,
            (true, false) => 0.5,
        };
        let colors: Vec<f64> = (0..size)
            .flat_map(|y| (0..size).flat_map(move |x| [z(x, y); 4]))
            .collect();
        let colors = f32s(&colors);
        let mut case = Case::render(
            &format!("api.depth_stencil_format.{format}"),
            library,
            "vert_depth_rect",
            Some("frag_depth_color"),
            strip(state),
        )
        .buffer(Buffer::data("rects", 0, rects.clone()).stage("vertex"))
        .texture(Texture::d2("c", "rgba32float", size, size).usage(&["render"]))
        .texture(Texture::d2("ds", format, size, size).usage(&["render"]))
        .output(Output::exact("c", Dtype::F32, colors));
        if let Some(feature) = requires {
            case = case.requires(&[], &[feature]);
        }
        if format.starts_with("depth32float") {
            let depths: Vec<f64> = (0..size)
                .flat_map(|y| (0..size).map(move |x| if quarter(x, y) { 0.25 } else { 0.5 }))
                .collect();
            case = case.output(
                Output::new("ds", Dtype::F32, Tolerance::exact())
                    .set("aspect", "depth")
                    .expect_same(f32s(&depths)),
            );
        }
        if stencil {
            case = case.output(
                Output::new("ds", Dtype::U8, Tolerance::exact())
                    .set("aspect", "stencil")
                    .set("as", "stencil")
                    .expect_same(vec![7; (size * size) as usize]),
            );
        }
        plan.add(case);
    }
    // Stencil written by a pass, then read by a kernel through a view.
    for (format, view) in [
        ("depth32float_stencil8", "x32_stencil8"),
        ("depth24unorm_stencil8", "x24_stencil8"),
    ] {
        let mut case = Case::sequence(
            &format!("api.stencil_view.{view}"),
            library,
            vec![
                Step::render(
                    "vert_depth_rect",
                    "frag_flat",
                    strip(json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                                 "stencil": {"texture": "ds", "clear": 2, "compare": "always", "pass": "replace",
                                             "reference": 9}})),
                )
                .bind_stage("vertex", &[("quarter", 0)])
                .bind_stage("fragment", &[("color", 0)]),
                Step::compute("read_stencil", [size, size, 1], [8, 8, 1])
                    .bind(&[("out", 0)])
                    .bind_textures(&[("stencil", 0)]),
            ],
        )
        .buffer(Buffer::data("quarter", 0, f32s(&[-1.0, -1.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0])).unbound())
        .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).unbound())
        .buffer(Buffer::zeroed("out", 0, (size * size * 4) as usize).unbound())
        .texture(Texture::d2("c", "rgba8unorm", size, size).usage(&["render"]))
        .texture(Texture::d2("ds", format, size, size).usage(&["render", "read", "view"]))
        .texture(Texture::d2("stencil", view, size, size).set("view_of", "ds"))
        .output(Output::exact(
            "out",
            Dtype::U32,
            u32s(&(0..size).flat_map(|y| (0..size).map(move |x| if quarter(x, y) { 9 } else { 2 })).collect::<Vec<_>>()),
        ));
        if format == "depth24unorm_stencil8" {
            case = case.requires(&[], &["depth24_stencil8"]);
        }
        plan.add(case);
    }
}

/// Each table and size at its limit for Mac2 and Apple7 GPUs: 1024
/// threads and 32 KiB of threadgroup memory, buffer 30, texture 127,
/// sampler 15, eight colour attachments, and vertex attribute and buffer
/// 30.
fn limits(plan: &mut Plan, library: &str) {
    let sums: Vec<u32> = (0..1024u32)
        .map(|l| (0..8).map(|j| 3 * (8191 - (l + 1024 * j))).sum())
        .collect();
    plan.add(
        Case::compute(
            "api.limits.threadgroup",
            library,
            "big_group",
            [1024, 1, 1],
            [1024, 1, 1],
        )
        .set("threadgroup_memory", json!([{"index": 0, "length": 32768}]))
        .buffer(Buffer::zeroed("out", 0, 4096))
        .output(Output::exact("out", Dtype::U32, u32s(&sums))),
    );
    plan.add(
        Case::compute(
            "api.limits.last_slots",
            library,
            "last_slots",
            [1, 1, 1],
            [1, 1, 1],
        )
        .buffer(Buffer::zeroed("out", 30, 16))
        .buffer(Buffer::data("k", 29, u32s(&[1000])))
        .texture(
            Texture::d2("t", "rgba8unorm", 1, 1)
                .index(127)
                .data(vec![51, 0, 0, 255]),
        )
        .sampler(json!({"name": "s", "index": 15}))
        .output(Output::exact("out", Dtype::U32, u32s(&[1051, 0, 0, 0]))),
    );
    let size = 4u32;
    let mut case = Case::render(
        "api.limits.color_attachments",
        library,
        "vert_inline_rect",
        Some("frag_eight"),
        strip(json!({"colors": (0..8).map(|k| json!({"texture": format!("c{k}"), "clear": [0, 0, 0, 0]})).collect::<Vec<_>>()})),
    )
    .buffer(inline_rect([-1.0, -1.0, 1.0, 1.0], [0.0; 4])[0].clone());
    for k in 0..8 {
        case = case
            .texture(Texture::d2(&format!("c{k}"), "r32float", size, size).usage(&["render"]))
            .output(Output::exact(
                &format!("c{k}"),
                Dtype::F32,
                f32s(&vec![f64::from(k + 1); (size * size) as usize]),
            ));
    }
    plan.add(case);
    plan.add(
        Case::render(
            "api.limits.vertex_attribute",
            library,
            "vert_last_attribute",
            Some("frag_flat"),
            strip(json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}],
                         "vertex_descriptor": {"attributes": [{"index": 30, "format": "float2", "offset": 0, "buffer": 30}],
                                               "layouts": [{"buffer": 30, "stride": 8}]}})),
        )
        .buffer(Buffer::data("corners", 30, f32s(&[-1.0, -1.0, 0.0, -1.0, -1.0, 1.0, 0.0, 1.0])).stage("vertex"))
        .buffer(Buffer::data("color", 0, f32s(&[1.0; 4])).stage("fragment"))
        .texture(Texture::d2("a", "rgba32float", 8, 8).usage(&["render"]))
        .output(Output::exact("a", Dtype::F32, image(8, 8, [1.0; 4], |x, _| x < 4))),
    );
}

/// Apple's frameworks running their own shaders on the device: an MPS
/// matrix product and box filter and a Core Image filter.
fn frameworks(plan: &mut Plan, rng: &mut Random) {
    let n = 32usize;
    let a: Vec<f64> = (0..n * n).map(|_| f64::from(rng.u32() % 7) - 3.0).collect();
    let b: Vec<f64> = (0..n * n).map(|_| f64::from(rng.u32() % 7) - 3.0).collect();
    let c: Vec<f64> = (0..n * n)
        .map(|i| (0..n).map(|k| a[i / n * n + k] * b[k * n + i % n]).sum())
        .collect();
    plan.add(
        Case::framework(
            "api.framework.mps_matrix_multiply",
            json!({"kind": "mps_matrix_multiply", "rows": n, "columns": n, "interior": n}),
        )
        .buffer(Buffer::data("a", 0, f32s(&a)).unbound())
        .buffer(Buffer::data("b", 0, f32s(&b)).unbound())
        .buffer(Buffer::zeroed("c", 0, n * n * 4).unbound())
        .output(Output::exact("c", Dtype::F32, f32s(&c))),
    );
    // Shapes MPS tiles differently: whole tiles, edges in each dimension,
    // and a product smaller than any tile.
    for (m, n, k) in [
        (128usize, 128usize, 128usize),
        (64, 32, 16),
        (17, 5, 3),
        (96, 160, 40),
    ] {
        let a: Vec<f64> = (0..m * k).map(|_| f64::from(rng.u32() % 7) - 3.0).collect();
        let b: Vec<f64> = (0..k * n).map(|_| f64::from(rng.u32() % 7) - 3.0).collect();
        let c: Vec<f64> = (0..m * n)
            .map(|i| (0..k).map(|j| a[i / n * k + j] * b[j * n + i % n]).sum())
            .collect();
        plan.add(
            Case::framework(
                &format!("api.framework.mps_matrix_multiply.{m}x{n}x{k}"),
                json!({"kind": "mps_matrix_multiply", "rows": m, "columns": n, "interior": k}),
            )
            .buffer(Buffer::data("a", 0, f32s(&a)).unbound())
            .buffer(Buffer::data("b", 0, f32s(&b)).unbound())
            .buffer(Buffer::zeroed("c", 0, m * n * 4).unbound())
            .output(Output::exact("c", Dtype::F32, f32s(&c))),
        );
    }
    let (w, h) = (16usize, 8usize);
    let texels: Vec<u8> = (0..w * h * 4)
        .map(|i| {
            if i % 4 == 3 {
                255
            } else {
                (rng.u32() % 256) as u8
            }
        })
        .collect();
    // A 3x3 mean with edges clamped, within a step of its rounding.
    let at = |x: i64, y: i64, k: usize| {
        f64::from(
            texels[((y.clamp(0, h as i64 - 1) as usize) * w + x.clamp(0, w as i64 - 1) as usize)
                * 4
                + k],
        )
    };
    let boxed: Vec<u8> = (0..h as i64)
        .flat_map(|y| (0..w as i64).map(move |x| (x, y)))
        .flat_map(|(x, y)| {
            (0..4).map(move |k| {
                let s: f64 = (-1..=1)
                    .flat_map(|dy| (-1..=1).map(move |dx| at(x + dx, y + dy, k)))
                    .sum();
                (s / 9.0).round() as u8
            })
        })
        .collect();
    plan.add(
        Case::framework(
            "api.framework.mps_image_box",
            json!({"kind": "mps_image_box"}),
        )
        .texture(Texture::d2("in", "rgba8unorm", w as u32, h as u32).data(texels.clone()))
        .texture(Texture::d2("out", "rgba8unorm", w as u32, h as u32).usage(&["read", "write"]))
        .output(Output::new("out", Dtype::U8, Tolerance::units(1.0)).expect_same(boxed)),
    );
    let inverted: Vec<u8> = texels
        .iter()
        .enumerate()
        .map(|(i, &v)| if i % 4 == 3 { v } else { 255 - v })
        .collect();
    plan.add(
        Case::framework(
            "api.framework.core_image_invert",
            json!({"kind": "core_image_invert"}),
        )
        .texture(Texture::d2("in", "rgba8unorm", w as u32, h as u32).data(texels))
        .texture(
            Texture::d2("out", "rgba8unorm", w as u32, h as u32)
                .usage(&["read", "write", "render"]),
        )
        .output(Output::new("out", Dtype::U8, Tolerance::units(1.0)).expect_same(inverted)),
    );
    // Core Image's Lanczos downscale to 0.6, as the Mac's within a unit: of
    // the image mirrored, Core Image stitches ci_lanczosDownH_affine, whose
    // filter takes the sampler struct another library builds.
    let gradient: Vec<u8> = (0..64u32 * 64)
        .flat_map(|i| {
            [
                (i * 7 % 256) as u8,
                (i / 64 * 4) as u8,
                (i % 64 * 4) as u8,
                255,
            ]
        })
        .collect();
    for (label, mirrored) in [("lanczos", false), ("lanczos_mirrored", true)] {
        plan.add(
            Case::framework(
                &format!("api.framework.core_image_{label}"),
                json!({"kind": "core_image_lanczos", "scale": 0.6, "mirrored": mirrored}),
            )
            .texture(Texture::d2("in", "rgba8unorm", 64, 64).data(gradient.clone()))
            .texture(Texture::d2("out", "rgba8unorm", 39, 39).usage(&["read", "write", "render"]))
            .output(Output::new("out", Dtype::U8, Tolerance::units(1.0))),
        );
    }
    mps_graph(plan);
}

/// MPSGraph's elementwise operations relu(sin(a * b + 0.75)), which it fuses
/// into one kernel stitched from its own visible functions, over a count with
/// a scalar tail after its four-wide body. The product and sum round as f32;
/// MPSGraph's sine is within a few ulps of the exact one.
fn mps_graph(plan: &mut Plan) {
    let count = 258u32;
    let offset = 0.75f32;
    let a: Vec<f32> = (0..count).map(|i| (i % 37) as f32 / 9.0 - 2.0).collect();
    let b: Vec<f32> = (0..count).map(|i| 1.5 - (i % 23) as f32 / 8.0).collect();
    let fused: Vec<f64> = a
        .iter()
        .zip(&b)
        .map(|(&a, &b)| f64::from(a * b + offset).sin().max(0.0))
        .collect();
    let widen = |values: &[f32]| values.iter().map(|&v| f64::from(v)).collect::<Vec<_>>();
    plan.add(
        Case::framework(
            "api.framework.mps_graph_fused",
            json!({"kind": "mps_graph_fused", "count": count, "offset": offset}),
        )
        .buffer(Buffer::data("a", 0, f32s(&widen(&a))).unbound())
        .buffer(Buffer::data("b", 0, f32s(&widen(&b))).unbound())
        .buffer(Buffer::zeroed("out", 0, count as usize * 4).unbound())
        .output(Output::new("out", Dtype::F32, Tolerance::abs(4e-6)).expect_same(f32s(&fused))),
    );
}

/// MetalFX's spatial and temporal upscalers doubling a checkerboard with
/// gradients, as the reference device's within a few units. The scalers'
/// kernels are MetalFX's own, the same on every device MetalFX supports;
/// their arithmetic rounds differently across GPUs, which the spatial
/// scaler's sharpening amplifies to 4 units of the gradients. MetalFX makes
/// a temporal scaler only for a device in Apple7.
fn metalfx(plan: &mut Plan) {
    let (w, h) = (32u32, 32u32);
    let texels: Vec<u8> = (0..h)
        .flat_map(|y| {
            (0..w).flat_map(move |x| {
                let check = if (x / 8 + y / 8) % 2 == 0 { 200 } else { 40 };
                [check, (x * 8) as u8, (y * 8) as u8, 255]
            })
        })
        .collect();
    plan.add(
        Case::framework(
            "api.framework.metalfx_spatial",
            json!({"kind": "metalfx_spatial"}),
        )
        .texture(Texture::d2("in", "rgba8unorm", w, h).data(texels.clone()))
        .texture(Texture::d2("out", "rgba8unorm", 2 * w, 2 * h).usage(&["read", "write", "render"]))
        .output(Output::new("out", Dtype::U8, Tolerance::units(4.0))),
    );
    let color: Vec<u8> = texels
        .iter()
        .flat_map(|&v| f16_bits(f64::from(v) / 255.0).to_le_bytes())
        .collect();
    let pixels = (w * h) as usize;
    plan.add(
        Case::framework(
            "api.framework.metalfx_temporal",
            json!({"kind": "metalfx_temporal"}),
        )
        .texture(Texture::d2("color", "rgba16float", w, h).data(color))
        .texture(Texture::d2("depth", "depth32float", w, h).data(f32s(&vec![0.5; pixels])))
        .texture(Texture::d2("motion", "rg16float", w, h).data(vec![0; pixels * 4]))
        .texture(
            Texture::d2("out", "rgba16float", 2 * w, 2 * h).usage(&["read", "write", "render"]),
        )
        .output(Output::new("out", Dtype::F16, Tolerance::abs(0.02))),
    );
}

/// Core Animation's renderer drawing its materials over a gradient: a
/// translucent panel, backdrop filters, compositing filters and SDF glass. What
/// Core Animation draws is its own, so each frame is held to the reference
/// device's within a few units.
fn core_animation(plan: &mut Plan) {
    // Red and blue swapped, alpha kept.
    let swap = json!([0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    let blur = json!({"type": "gaussianBlur", "values": {"inputRadius": 6}});
    // The glass inputs SwiftUI gives an `NSGlassEffectView`.
    let glass = json!({
        "inputInnerRefractionAmount": -32, "inputInnerRefractionHeight": 16,
        "inputRefractionDistance0": -1, "inputBlurRadius": 5,
        "inputBlurOpacity0": 0.4, "inputBlurOpacity1": 0.4, "inputBlurOpacity2": 1, "inputBlurOpacity3": 1,
        "inputFaceOpacity": 1, "inputFaceColorMatrixWhite": 1.125, "inputFaceColorMatrixBlack": 0.08,
        "inputFaceColorMatrixSaturation": 1.3, "inputFaceColorMatrixMaxLuma": 0.6,
        "inputFaceColorMatrixMaxLumaSDR": 0.6, "inputBleedAmount": 22.4, "inputBleedHeight": 22.4,
        "inputBleedDistance0": 1, "inputBleedColorMatrixWhite": 0.5, "inputBleedColorMatrixBlack": 0.125,
        "inputBleedColorMatrixSaturation": 1, "inputShadowColorMatrixWhite": 1,
        "inputShadowColorMatrixSaturation": 1, "inputRingShadowOffset": 8, "inputRingShadowStrokeWidth": 4,
        "inputRingShadowBlurRadius": 5, "inputRingShadowMask": 1, "inputKeyFillHighlightHeight": 0.5,
        "inputKeyFillHighlightAngle": core::f64::consts::FRAC_PI_2, "inputKeyFillHighlightSpread": 2.0943951,
        "inputKeyFillHighlightSpreadSDR": 2.0943951, "inputKeyFillHighlightAmount": 0.5,
        "inputKeyFillHighlightEffectOffset": -0.5, "inputKeyFillHighlightColorBias": -0.1875,
        "inputBlurFillBlurRadius": 8, "inputBlurFillDarkenOpacity": 0.9,
        "inputBlurFillNormalOpacity": 0.6867394, "inputSDRHoldingToneWhite": 1,
        "inputSDRGradientDistance0": 1, "inputSDRGradientDistance1": 1, "inputMaxHeadroom": 1.2,
        "inputClamp": 1.308311,
    });
    let mut scenes: Vec<(String, Value)> = [
        ("panel", json!({})),
        ("backdrop.blur", json!({"backdrop": [blur]})),
        (
            "backdrop.color_matrix",
            json!({"backdrop": [{"type": "colorMatrix", "matrix": swap}]}),
        ),
        (
            "backdrop.blur_saturate",
            json!({"backdrop": [blur, {"type": "colorSaturate", "values": {"inputAmount": 2}}]}),
        ),
        // Liquid Glass as SwiftUI builds it: the filter takes its shape
        // from the backdrop's SDF sublayer, and draws nothing without one.
        (
            "backdrop.glass",
            json!({"backdrop": [{"type": "glassBackground", "values": glass}], "sdf": {"corner_radius": 8}}),
        ),
        // Glass shaped by a plain image sublayer's alpha, with no SDF.
        (
            "backdrop.glass_mask",
            json!({"backdrop": [{"type": "glassBackground", "values": glass}], "mask": true}),
        ),
        // An SDF element shaped by an image's coverage, as Setup Assistant's
        // lettering is: Core Animation derives distances by a jump flood.
        (
            "backdrop.glass_sdf_contents",
            json!({"backdrop": [{"type": "glassBackground", "values": glass}], "sdf": {"contents": true}}),
        ),
        // Drop shadows: of the panel's shape, which Core Animation blurs
        // from its coverage, and of a path, which it draws from a shadow
        // image it caches.
        (
            "shadow",
            json!({"shadow": {"opacity": 0.6, "radius": 6, "offset": [0, -3]}}),
        ),
        (
            "shadow.path",
            json!({"shadow": {"opacity": 0.6, "radius": 6, "offset": [0, -3], "path": true}}),
        ),
        (
            "shadow.wide",
            json!({"shadow": {"opacity": 0.8, "radius": 14, "offset": [2, -6], "path": true}}),
        ),
        (
            "compositing.vibrant_color_matrix",
            json!({"compositing": {"type": "vibrantColorMatrix", "matrix": swap}}),
        ),
    ]
    .into_iter()
    .map(|(label, scene)| (label.to_string(), scene))
    .collect();
    for (label, mode) in [
        ("vibrant_light", "vibrantLight"),
        ("vibrant_dark", "vibrantDark"),
        ("plus_darker", "plusD"),
        ("plus_lighter", "plusL"),
        ("multiply", "multiplyBlendMode"),
        ("overlay", "overlayBlendMode"),
    ] {
        scenes.push((
            format!("compositing.{label}"),
            json!({"compositing": {"type": mode}}),
        ));
    }
    for (label, mut scene) in scenes {
        scene["kind"] = "core_animation".into();
        plan.add(
            Case::framework(&format!("api.framework.core_animation.{label}"), scene)
                .texture(Texture::d2("out", "bgra8unorm", 64, 64).usage(&["read", "render"]))
                .output(Output::new("out", Dtype::U8, Tolerance::units(3.0))),
        );
    }
    text(plan, &glass);
}

/// A push button's label, from the CPU's text to Core Animation's glass. Core
/// Text sets it into a bitmap context: in BGRA over clear, over opaque white
/// with font smoothing, and alpha only, as an A8 backing store holds it. Core
/// Animation then draws it as a text layer, as an alpha-only image it tints,
/// as an A8 backing store a delegate draws (SwiftUI's text), with SwiftUI's
/// vibrant color matrix, through a portal that hides its source, and so
/// above glass, as SwiftUI composes a glass button; and AppKit's own glass
/// button, where a window server session allows one. What Core Text and Core
/// Animation draw is their own, so each is held to the reference device's.
fn text(plan: &mut Plan, glass: &Value) {
    for (label, format, pixel_format) in [
        ("rgba", "rgba", "bgra8unorm"),
        ("smoothed", "smoothed", "bgra8unorm"),
        ("alpha", "alpha", "r8unorm"),
    ] {
        plan.add(
            Case::framework(
                &format!("api.framework.core_text.{label}"),
                json!({"kind": "core_text", "format": format}),
            )
            .texture(Texture::d2("out", pixel_format, 160, 40).usage(&["read"]))
            .output(Output::new("out", Dtype::U8, Tolerance::units(1.0))),
        );
    }
    let backdrop = json!([{"type": "glassBackground", "values": glass}]);
    for (label, scene) in [
        (
            "core_animation.text.layer",
            json!({"text": {"kind": "layer"}}),
        ),
        (
            "core_animation.text.tinted",
            json!({"text": {"kind": "tinted"}}),
        ),
        (
            "core_animation.text.backing",
            json!({"text": {"kind": "backing"}}),
        ),
        (
            "core_animation.text.backing_vibrant",
            json!({"text": {"kind": "backing", "vibrant": true}}),
        ),
        (
            "core_animation.text.portal",
            json!({"text": {"kind": "backing", "vibrant": true, "portal": true}}),
        ),
        (
            "core_animation.text.glass_portal",
            json!({"text": {"kind": "backing", "vibrant": true, "portal": true},
                   "backdrop": backdrop, "sdf": {"corner_radius": 12}}),
        ),
        // AppKit's own, under its own name, which a run can leave out.
        ("appkit.glass_button", json!({"appkit_button": true})),
    ] {
        let mut scene = scene;
        scene["kind"] = "core_animation".into();
        plan.add(
            Case::framework(&format!("api.framework.{label}"), scene)
                .texture(Texture::d2("out", "bgra8unorm", 160, 48).usage(&["read", "render"]))
                .output(Output::new("out", Dtype::U8, Tolerance::units(3.0))),
        );
    }
}

/// A desktop picture as an app hands it to MetalKit for a background:
/// MTKTextureLoader decodes TIFF data of an opaque sRGB image of odd size
/// into an sRGB texture and generates its mipmaps, which glass samples
/// blurred. The decoder, the upload and the mipmaps are MetalKit's and the
/// device's, so they are held to the reference device's.
/// The desktop picture's texel at (x, y), 8-bit components as the runner
/// draws it: a gradient under a 4-texel checker, opaque.
fn desktop_texel(x: u32, y: u32, width: u32, height: u32) -> [u8; 4] {
    let checker = if (x / 4 + y / 4) & 1 == 1 { 224 } else { 32 };
    [
        (x * 255 / (width - 1)) as u8,
        (y * 255 / (height - 1)) as u8,
        checker,
        255,
    ]
}

/// The sRGB transfer function's inverse.
fn srgb_to_linear(v: f64) -> f64 {
    if v <= 0.04045 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

/// A desktop picture as an app makes it a texture: MetalKit's loader on the
/// 8-bit TIFF AppKit writes, and on the 16-bit linear PNG Core Image's
/// bitmap becomes (RGBA16Unorm); Core Image rendering the TIFF into that
/// bitmap; and MPS's Gaussian blur of a mipmapped RGBA16Unorm texture into
/// RGBA16Float. Setup Assistant's hello view takes its background this way.
fn texture_loader(plan: &mut Plan) {
    let (width, height) = (203u32, 118u32);
    let levels = 32 - width.max(height).leading_zeros();
    let texels: u32 = (0..levels)
        .map(|l| (width >> l).max(1) * (height >> l).max(1))
        .sum();
    for (name, bits) in [("texture_loader", 8usize), ("texture_loader_rgba16", 16)] {
        let mut spec = json!({"kind": "texture_loader", "width": width, "height": height});
        if bits == 16 {
            spec["bits"] = json!(bits);
        }
        plan.add(
            Case::framework(&format!("api.framework.metalkit.{name}"), spec)
                .buffer(Buffer::zeroed("out", 0, 16 + texels as usize * bits / 2).unbound())
                .output(Output::new("out", Dtype::U8, Tolerance::units(1.0))),
        );
    }
    // Core Image converts sRGB to linear in half precision: within 64 of
    // 65535 of the exact curve.
    let linear: Vec<i128> = (0..height)
        .flat_map(|y| (0..width).map(move |x| (x, y)))
        .flat_map(|(x, y)| {
            let texel = desktop_texel(x, y, width, height);
            (0..4).map(move |k| {
                let v = f64::from(texel[k]) / 255.0;
                let v = if k == 3 { v } else { srgb_to_linear(v) };
                (v * 65535.0).round() as i128
            })
        })
        .collect();
    plan.add(
        Case::framework(
            "api.framework.core_image.bitmap_rgba16",
            json!({"kind": "core_image_bitmap", "width": width, "height": height}),
        )
        .buffer(Buffer::zeroed("out", 0, (width * height * 8) as usize).unbound())
        .output(
            Output::new("out", Dtype::U16, Tolerance::units(64.0))
                .expect_same(ints(Dtype::U16, &linear)),
        ),
    );
    // The blur reads the source's base level; its other levels hold the
    // base's 2 x 2 means, as generated mipmaps do.
    let (w, h) = (256u32, 128u32);
    let mut level: Vec<[f64; 4]> = (0..h)
        .flat_map(|y| (0..w).map(move |x| (x, y)))
        .map(|(x, y)| {
            let texel = desktop_texel(x, y, w, h);
            core::array::from_fn(|k| f64::from(texel[k]) / 255.0)
        })
        .collect();
    let mut data = Vec::new();
    let (mut lw, mut lh) = (w, h);
    let mips = 32 - w.max(h).leading_zeros();
    for index in 0..mips {
        if index > 0 {
            let (nw, nh) = ((lw / 2).max(1), (lh / 2).max(1));
            level = (0..nh)
                .flat_map(|y| (0..nw).map(move |x| (x, y)))
                .map(|(x, y)| {
                    let at = |dx: u32, dy: u32| {
                        level[((y * 2 + dy).min(lh - 1) * lw + (x * 2 + dx).min(lw - 1)) as usize]
                    };
                    core::array::from_fn(|k| {
                        (at(0, 0)[k] + at(1, 0)[k] + at(0, 1)[k] + at(1, 1)[k]) / 4.0
                    })
                })
                .collect();
            (lw, lh) = (nw, nh);
        }
        let words: Vec<i128> = level
            .iter()
            .flat_map(|texel| texel.map(|v| (v * 65535.0).round() as i128))
            .collect();
        data.extend(ints(Dtype::U16, &words));
    }
    plan.add(
        Case::framework(
            "api.framework.mps_gaussian_blur",
            json!({"kind": "mps_gaussian_blur", "sigma": 8.0}),
        )
        .texture(
            Texture::d2("in", "rgba16unorm", w, h)
                .mipmaps(mips)
                .set("storage", "managed")
                .data(data),
        )
        .texture(Texture::d2("out", "rgba16float", w, h).usage(&["read", "write"]))
        .output(Output::new("out", Dtype::F16, Tolerance::abs(1.0 / 256.0))),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("api", SOURCE, &[], super::plan::LATEST);
    let mut rng = Random::new(1201);
    storage(plan, &library, &mut rng);
    inline_constants(plan, &library, &mut rng);
    visibility(plan, &library);
    counters(plan, &library, &mut rng);
    logging(plan, &mut rng);
    reflection(plan, &library);
    reflection_types(plan, &library);
    runtime(plan, &mut rng);
    runtime_options(plan, &mut rng);
    targets(plan, &library);
    resolves(plan, &library);
    draws(plan, &library);
    wireframe(plan, &library);
    sample_counts(plan, &library);
    depth_stencil_formats(plan, &library);
    limits(plan, &library);
    frameworks(plan, &mut rng);
    metalfx(plan);
    core_animation(plan);
    texture_loader(plan);
}
