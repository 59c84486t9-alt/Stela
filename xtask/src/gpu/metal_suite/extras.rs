//! corpus/extras.metal: shader features macOS's own shaders use that the
//! other families do not reach, found by `coverage`. Each result is one the
//! specification fixes; where it leaves a parameter to the device (the
//! SIMD-group width), every allowed value is accepted.
use super::convert::bfloat;
use super::plan::{Buffer, Case, Output, Plan, Step, Texture, Tolerance};
use super::values::{Dtype, Random, bits32, f32r, f32s, u32s};
use serde_json::json;

const SOURCE: &str = "extras.metal";

/// SIMD-group indices and counts of a 160-thread grid in threadgroups of
/// 128, whose second threadgroup has 32 threads, for each SIMD width. The
/// plain counts describe the threadgroup as it runs and the `dispatch_` ones
/// the size the dispatch gave; Apple reports the dispatched size for the
/// partial threadgroup's `threads_per_threadgroup`, so either is accepted.
fn simd_ids(plan: &mut Plan, library: &str) {
    let (grid, group) = (160u32, 128u32);
    let ids = |w: u32| -> Vec<u32> {
        let mut out = vec![];
        for i in 0..grid {
            let local = i % group;
            let actual = if i < group { group } else { grid - group };
            out.extend([local / w, actual.div_ceil(w), group.div_ceil(w), local % w]);
        }
        out
    };
    let width = |w: u32, partial: u32| vec![w, group, partial, group];
    let mut ids_out = Output::exact("out", Dtype::U32, u32s(&ids(32)));
    let mut width_out = Output::exact("width", Dtype::U32, u32s(&width(32, grid - group)));
    for w in [4, 8, 16, 32, 64] {
        if w != 32 {
            ids_out = ids_out.expect_alternative(u32s(&ids(w)));
            width_out = width_out.expect_alternative(u32s(&width(w, grid - group)));
        }
        width_out = width_out.expect_alternative(u32s(&width(w, group)));
    }
    plan.add(
        Case::compute(
            "extras.simd_ids",
            library,
            "simd_ids",
            [grid, 1, 1],
            [group, 1, 1],
        )
        .dispatch_threads()
        .buffer(Buffer::zeroed("out", 0, grid as usize * 16))
        .buffer(Buffer::zeroed("width", 1, 16))
        .output(ids_out)
        .output(width_out),
    );
    // Quadgroups are four threads at any SIMD width; the partial
    // threadgroup may count its quadgroups as run or as dispatched.
    let quads = |dispatched_partial: bool| -> Vec<u32> {
        (0..grid)
            .flat_map(|i| {
                let local = i % group;
                let actual = if i < group || dispatched_partial {
                    group
                } else {
                    grid - group
                };
                [local / 4, actual.div_ceil(4), group / 4, local % 4]
            })
            .collect()
    };
    plan.add(
        Case::compute(
            "extras.quad_ids",
            library,
            "quad_ids",
            [grid, 1, 1],
            [group, 1, 1],
        )
        .dispatch_threads()
        .buffer(Buffer::zeroed("out", 0, grid as usize * 16))
        .output(
            Output::exact("out", Dtype::U32, u32s(&quads(false)))
                .expect_alternative(u32s(&quads(true))),
        ),
    );
}

/// Atomic booleans, four bytes each, every thread on its own flags.
fn atomic_flags(plan: &mut Plan, library: &str) {
    let n = 8u32;
    let first: Vec<u32> = (0..n).map(|i| i & 1).collect();
    let second: Vec<u32> = (0..n).map(|i| (i >> 1) & 1).collect();
    let out: Vec<u32> = (0..n)
        .map(|i| {
            (i & 1) | (u32::from(second[i as usize] == 0) << 1) | (second[i as usize] << 2) | 8
        })
        .collect();
    plan.add(
        Case::compute(
            "extras.atomic_bool",
            library,
            "atomic_flags",
            [n, 1, 1],
            [n, 1, 1],
        )
        .dispatch_threads()
        .buffer(Buffer::data("first", 0, u32s(&first)))
        .buffer(Buffer::data("second", 1, u32s(&second)))
        .buffer(Buffer::zeroed("out", 2, n as usize * 4))
        .output(Output::exact(
            "first",
            Dtype::U32,
            u32s(&vec![0; n as usize]),
        ))
        .output(Output::exact(
            "second",
            Dtype::U32,
            u32s(&vec![1; n as usize]),
        ))
        .output(Output::exact("out", Dtype::U32, u32s(&out))),
    );
}

fn handles(plan: &mut Plan, library: &str) {
    plan.add(
        Case::compute(
            "extras.null_handles",
            library,
            "null_handles",
            [1, 1, 1],
            [1, 1, 1],
        )
        .texture(Texture::new("line", "rgba8unorm", "1d", [4, 1, 1]).index(0))
        .texture(
            Texture::new("cubes", "rgba8unorm", "cube_array", [4, 4, 1])
                .array(1)
                .index(2),
        )
        .buffer(Buffer::zeroed("out", 0, 32))
        .output(Output::exact("out", Dtype::U32, u32s(&[0, 1, 0, 1, 1])).set("length", 20)),
    );
    let n = 256u32;
    let expected: Vec<u32> = (0..n).map(|i| (i ^ 1) * 7 + 3).collect();
    plan.add(
        Case::compute1("extras.coherent_exchange", library, "coherent_exchange", n)
            .buffer(Buffer::zeroed("data", 0, n as usize * 4))
            .buffer(Buffer::zeroed("out", 1, n as usize * 4))
            .output(Output::exact("out", Dtype::U32, u32s(&expected))),
    );
    let expected: Vec<u32> = (0..n).map(|i| i * 3 + 64).collect();
    plan.add(
        Case::compute(
            "extras.max_total_threads",
            library,
            "limited",
            [n, 1, 1],
            [64, 1, 1],
        )
        .buffer(Buffer::zeroed("out", 0, n as usize * 4))
        .output(Output::exact("out", Dtype::U32, u32s(&expected))),
    );
}

/// Packing and unpacking 565 and 10:10:10:2 normalized formats, from
/// inputs on each format's lattice, so rounding has no ties to break.
fn packing(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 64usize;
    let (mut input, mut packed, mut unpacked) = (vec![], vec![], vec![]);
    let field = |k: i64, bits: u32| (k as u32) & ((1 << bits) - 1);
    for _ in 0..n {
        let [r, g, b] = [31, 63, 31].map(|m| rng.below(m + 1));
        input.extend([r as f64 / 31.0, g as f64 / 63.0, b as f64 / 31.0, 0.0]);
        let p565 = field(r, 5) | field(g, 6) << 5 | field(b, 5) << 11;
        unpacked.extend([r as f64 / 31.0, g as f64 / 63.0, b as f64 / 31.0, 0.0]);
        let u = [1023, 1023, 1023, 3].map(|m| rng.below(m + 1));
        input.extend([
            u[0] as f64 / 1023.0,
            u[1] as f64 / 1023.0,
            u[2] as f64 / 1023.0,
            u[3] as f64 / 3.0,
        ]);
        let pu =
            field(u[0], 10) | field(u[1], 10) << 10 | field(u[2], 10) << 20 | field(u[3], 2) << 30;
        unpacked.extend([
            u[0] as f64 / 1023.0,
            u[1] as f64 / 1023.0,
            u[2] as f64 / 1023.0,
            u[3] as f64 / 3.0,
        ]);
        let s = [511u32, 511, 511, 1].map(|m| rng.below(2 * m + 1) - i64::from(m));
        let snorm = |k: i64, m: i64| k as f64 / m as f64;
        let values = [
            snorm(s[0], 511),
            snorm(s[1], 511),
            snorm(s[2], 511),
            snorm(s[3], 1),
        ];
        input.extend(values);
        let ps =
            field(s[0], 10) | field(s[1], 10) << 10 | field(s[2], 10) << 20 | field(s[3], 2) << 30;
        unpacked.extend(values);
        packed.extend([p565, pu, ps, 0]);
    }
    let input: Vec<f64> = input.into_iter().map(f32r).collect();
    plan.add(
        Case::compute1("extras.pack_formats", library, "pack_formats", n as u32)
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::zeroed("packed", 1, n * 16))
            .buffer(Buffer::zeroed("unpacked", 2, n * 48))
            .output(Output::exact("packed", Dtype::U32, u32s(&packed)))
            .output(
                Output::new("unpacked", Dtype::F32, Tolerance::ulp(1.0))
                    .expect_same(f32s(&unpacked.into_iter().map(f32r).collect::<Vec<_>>())),
            ),
    );
}

/// A multisampled depth target and a two-slice multisampled colour array,
/// slice 1 cleared by one pass and slice 0 drawn over with the depth target
/// by another, then read sample by sample. A layered pass would need a depth
/// array: every attachment has the pass's render target array length.
fn multisampled(plan: &mut Plan, library: &str) {
    let (w, h, samples) = (4u32, 4u32, 4u32);
    let texels = (w * h * samples) as usize;
    let drawn = [0.25, 0.5, 0.75, 1.0];
    let clear = [0.5, 0.25, 0.0, 1.0];
    let colors: Vec<f64> = [drawn, clear]
        .iter()
        .flat_map(|c| (0..texels).flat_map(move |_| *c))
        .collect();
    plan.add(
        Case::sequence(
            "extras.multisampled_reads",
            library,
            vec![
                Step::render(
                    "vert_full",
                    "frag_first",
                    json!({"colors": [{"texture": "layers", "slice": 1, "clear": clear}],
                           "samples": samples, "draws": []}),
                ),
                Step::render(
                    "vert_full",
                    "frag_first",
                    json!({"colors": [{"texture": "layers", "slice": 0, "clear": clear}], "samples": samples,
                           "depth": {"texture": "depth", "clear": 0.75, "compare": "always"},
                           "primitive": "triangle_strip", "vertex_count": 4}),
                ),
                Step::compute("read_ms", [w, h, 1], [w, h, 1])
                    .bind_textures(&[("depth", 0), ("layers", 1)])
                    .bind(&[("depths", 0), ("colors", 1)]),
            ],
        )
        .texture(
            Texture::new("depth", "depth32float", "2d_ms", [w, h, 1])
                .samples(samples)
                .usage(&["render", "read"]),
        )
        .texture(
            Texture::new("layers", "rgba16float", "2d_ms_array", [w, h, 1])
                .array(2)
                .samples(samples)
                .usage(&["render", "read"]),
        )
        .buffer(Buffer::zeroed("depths", 0, texels * 4).unbound())
        .buffer(Buffer::zeroed("colors", 0, texels * 2 * 16).unbound())
        .output(Output::exact(
            "depths",
            Dtype::F32,
            f32s(&vec![0.5; texels]),
        ))
        .output(Output::exact("colors", Dtype::F32, f32s(&colors))),
    );
    // The same pass over a two-slice depth array: the draw reaches slice
    // 0 at depth 0.5, and slice 1 keeps its clear.
    let mut depths = vec![0.5; texels];
    depths.extend(vec![0.75; texels]);
    plan.add(
        Case::sequence(
            "extras.multisampled_reads.depth_array",
            library,
            vec![
                Step::render(
                    "vert_full",
                    "frag_first",
                    json!({"colors": [{"texture": "layers", "clear": clear}], "samples": samples,
                           "depth": {"texture": "depth", "clear": 0.75, "compare": "always"},
                           "primitive": "triangle_strip", "vertex_count": 4}),
                ),
                Step::compute("read_ms_depth_array", [w, h, 1], [w, h, 1])
                    .bind_textures(&[("depth", 0)])
                    .bind(&[("depths", 0)]),
            ],
        )
        .texture(
            Texture::new("depth", "depth32float", "2d_ms_array", [w, h, 1])
                .array(2)
                .samples(samples)
                .usage(&["render", "read"]),
        )
        .texture(
            Texture::new("layers", "rgba16float", "2d_ms_array", [w, h, 1])
                .array(2)
                .samples(samples)
                .usage(&["render", "read"]),
        )
        .buffer(Buffer::zeroed("depths", 0, texels * 2 * 4).unbound())
        .output(Output::exact("depths", Dtype::F32, f32s(&depths))),
    );
}

/// Explicit gradients choosing mipmap levels of a 3D texture, a cube and a
/// 2D array of 16 texels a side, whose every texel is (level, slice or
/// face, 0, 1). A gradient g spans 16 g texels in the 3D texture and the
/// array, and 8 g on a cube face, whose coordinates span 2; each level of
/// detail lies a quarter from a rounding boundary.
fn gradients(plan: &mut Plan, library: &str) {
    let size = 16u32;
    let levels = 5u32;
    let texel = |level: u32, slice: u32| [f64::from(level), f64::from(slice), 0.0, 1.0];
    let chain = |slices: u32, depth: bool| -> Vec<f64> {
        let mut out = vec![];
        for s in 0..slices {
            for l in 0..levels {
                let side = size >> l;
                let count = side * side * if depth { side } else { 1 };
                for _ in 0..count {
                    out.extend(texel(l, s));
                }
            }
        }
        out
    };
    let lods: [f64; 6] = [-1.0, 1.25, 2.25, 3.25, 4.25, 7.0];
    let level = |lod: f64| lod.round().clamp(0.0, f64::from(levels - 1)) as u32;
    let mut grads = vec![];
    let mut expected = vec![];
    for lod in lods {
        let g = 2f64.powf(lod) / f64::from(size);
        grads.extend([g, 0.0, 0.0, 0.0]);
        expected.extend(texel(level(lod), 0));
        expected.extend(texel(level(lod - 1.0), 0));
        expected.extend(texel(level(lod), 1));
    }
    plan.add(
        Case::compute1(
            "extras.sample_gradients",
            library,
            "sample_gradients",
            lods.len() as u32,
        )
        .texture(
            Texture::new("volume", "rgba32float", "3d", [size, size, size])
                .mipmaps(levels)
                .data(f32s(&chain(1, true)))
                .index(0),
        )
        .texture(
            Texture::new("cube", "rgba32float", "cube", [size, size, 1])
                .mipmaps(levels)
                .data(f32s(&chain(6, false)))
                .index(1),
        )
        .texture(
            Texture::new("layers", "rgba32float", "2d_array", [size, size, 1])
                .array(2)
                .mipmaps(levels)
                .data(f32s(&chain(2, false)))
                .index(2),
        )
        .sampler(
            json!({"name": "s", "index": 0, "min": "nearest", "mag": "nearest", "mip": "nearest"}),
        )
        .buffer(Buffer::data("grads", 0, f32s(&grads)))
        .buffer(Buffer::zeroed("out", 1, lods.len() * 48))
        .output(Output::exact("out", Dtype::F32, f32s(&expected))),
    );
}

/// Compute stage-in: a float2 and a uchar4 per thread, each from its own
/// buffer stepping with the grid's x position.
fn stage_in(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 64usize;
    let a: Vec<f64> = (0..2 * n).map(|_| f32r(rng.uniform(-8.0, 8.0))).collect();
    let b: Vec<u8> = (0..4 * n).map(|_| rng.u32() as u8).collect();
    let expected: Vec<f64> = (0..n)
        .flat_map(|i| {
            let c = |k: usize| f64::from(b[4 * i + k]);
            [a[2 * i], a[2 * i + 1], c(0) + c(1) * 256.0, c(2) - c(3)]
        })
        .collect();
    let stage_input = json!({"attributes": [{"index": 0, "format": "float2", "offset": 0, "buffer": 0},
                                            {"index": 1, "format": "uchar4", "offset": 0, "buffer": 1}],
                             "layouts": [{"buffer": 0, "stride": 8, "step": "grid_x"},
                                         {"buffer": 1, "stride": 4, "step": "grid_x"}]});
    // The float2s padded to 16 bytes, read at the stride each binding gives.
    let padded: Vec<f64> = a.chunks(2).flat_map(|p| [p[0], p[1], 0.0, 0.0]).collect();
    let mut dynamic = stage_input.clone();
    dynamic["layouts"][0]["stride"] = "dynamic".into();
    let base = |name: &str, input: &serde_json::Value, first: Buffer| {
        Case::compute(
            name,
            library,
            "stage_in_compute",
            [n as u32, 1, 1],
            [64, 1, 1],
        )
        .dispatch_threads()
        .set("stage_input", input.clone())
        .buffer(first)
        .buffer(Buffer::data("b", 1, b.clone()))
        .buffer(Buffer::zeroed("out", 2, n * 16))
        .output(Output::exact("out", Dtype::F32, f32s(&expected)))
    };
    let case = |name: &str| base(name, &stage_input, Buffer::data("a", 0, f32s(&a)));
    let strided = |name: &str| {
        base(
            name,
            &dynamic,
            Buffer::data("a", 0, f32s(&padded)).set("attribute_stride", 16),
        )
    };
    plan.add(case("extras.stage_in"));
    plan.add(strided("extras.stage_in.dynamic_stride"));
    // The bytes fetched once for every thread, the first element's.
    let mut constant = stage_input.clone();
    constant["layouts"][1]["step"] = "constant".into();
    let once: Vec<f64> = (0..n)
        .flat_map(|i| {
            let c = |k: usize| f64::from(b[k]);
            [a[2 * i], a[2 * i + 1], c(0) + c(1) * 256.0, c(2) - c(3)]
        })
        .collect();
    plan.add(
        Case::compute(
            "extras.stage_in.step.constant",
            library,
            "stage_in_compute",
            [n as u32, 1, 1],
            [64, 1, 1],
        )
        .dispatch_threads()
        .set("stage_input", constant)
        .buffer(Buffer::data("a", 0, f32s(&a)))
        .buffer(Buffer::data("b", 1, b.clone()))
        .buffer(Buffer::zeroed("out", 2, n * 16))
        .output(Output::exact("out", Dtype::F32, f32s(&once))),
    );
    // Elements stepped by the grid's y, over a grid one thread wide.
    let mut rows = stage_input.clone();
    for layout in rows["layouts"].as_array_mut().unwrap() {
        layout["step"] = "grid_y".into();
    }
    plan.add(
        Case::compute(
            "extras.stage_in.step.grid_y",
            library,
            "stage_in_rows",
            [1, n as u32, 1],
            [1, 64, 1],
        )
        .dispatch_threads()
        .set("stage_input", rows)
        .buffer(Buffer::data("a", 0, f32s(&a)))
        .buffer(Buffer::data("b", 1, b.clone()))
        .buffer(Buffer::zeroed("out", 2, n * 16))
        .output(Output::exact("out", Dtype::F32, f32s(&expected))),
    );
    // A region that starts past the first attributes: each thread fetches
    // the one at the origin plus its position, and reads the region back.
    let (origin, size) = (5u32, 16u32);
    let words: Vec<u32> = (0..32).map(|k| 1000 + k * 7).collect();
    let fetched: Vec<u32> = (0..size)
        .flat_map(|p| [words[(origin + p) as usize], origin, size, p])
        .collect();
    let index_input = json!({"attributes": [{"index": 0, "format": "uint", "offset": 0, "buffer": 0}],
                             "layouts": [{"buffer": 0, "stride": 4, "step": "grid_x"}]});
    plan.add(
        Case::compute(
            "extras.stage_in.origin",
            library,
            "stage_in_origin",
            [size, 1, 1],
            [size, 1, 1],
        )
        .dispatch_threads()
        .set("stage_input", index_input)
        .set("stage_in_region_buffer", "region")
        .buffer(Buffer::data("region", 0, u32s(&[origin, 0, 0, size, 1, 1])).unbound())
        .buffer(Buffer::data("words", 0, u32s(&words)))
        .buffer(Buffer::zeroed("out", 1, size as usize * 16))
        .output(Output::exact("out", Dtype::U32, u32s(&fetched))),
    );
    // Attributes fetched through an index buffer of each width: the first
    // by each thread's x position, the second by its y.
    let (w, h) = (4u32, 3u32);
    let indices = [7u32, 3, 0, 5, 1, 1, 6, 2];
    let a_words: Vec<u32> = (0..16).map(|k| 100 + k).collect();
    let b_words: Vec<u32> = (0..16).map(|k| 200 + k).collect();
    let pairs: Vec<u32> = (0..h)
        .flat_map(|y| (0..w).map(move |x| (x, y)))
        .flat_map(|(x, y)| {
            [
                a_words[indices[x as usize] as usize],
                b_words[indices[y as usize] as usize],
            ]
        })
        .collect();
    for index_type in ["uint16", "uint32"] {
        let index_bytes: Vec<u8> = if index_type == "uint16" {
            indices
                .iter()
                .flat_map(|&i| (i as u16).to_le_bytes())
                .collect()
        } else {
            u32s(&indices)
        };
        plan.add(
            Case::compute(
                &format!("extras.stage_in.indexed.{index_type}"),
                library,
                "stage_in_indexed",
                [w, h, 1],
                [w, h, 1],
            )
            .dispatch_threads()
            .set(
                "stage_input",
                json!({
                "attributes": [{"index": 0, "format": "uint", "offset": 0, "buffer": 0},
                               {"index": 1, "format": "uint", "offset": 0, "buffer": 1}],
                "layouts": [{"buffer": 0, "stride": 4, "step": "grid_x_indexed"},
                            {"buffer": 1, "stride": 4, "step": "grid_y_indexed"}],
                "index_buffer": 3, "index_type": index_type}),
            )
            .buffer(Buffer::data("a", 0, u32s(&a_words)))
            .buffer(Buffer::data("b", 1, u32s(&b_words)))
            .buffer(Buffer::zeroed("out", 2, (w * h * 8) as usize))
            .buffer(Buffer::data("indices", 3, index_bytes))
            .output(Output::exact("out", Dtype::U32, u32s(&pairs))),
        );
    }
    // The region read from a buffer: origin 0, size n by 1 by 1.
    plan.add(
        case("extras.stage_in.indirect_region")
            .set("stage_in_region_buffer", "region")
            .buffer(Buffer::data("region", 0, u32s(&[0, 0, 0, n as u32, 1, 1])).unbound()),
    );
    // The same fetch as the one command of an indirect command buffer,
    // whose range a buffer holds; then with the float2s at a stride the
    // command gives.
    let uses = |name: &str, index: u32| json!({"name": name, "index": index, "offset": 0});
    let command = |input: &serde_json::Value, a: serde_json::Value, dynamic_stride: bool| {
        json!([{"name": "icb", "type": "dispatch", "count": 1, "max_buffers": 3, "dynamic_stride": dynamic_stride,
                "commands": [{"function": "stage_in_compute", "stage_input": input, "stage_in_region": [n],
                              "buffers": [a, uses("b", 1), uses("out", 2)],
                              "threadgroups": [n / 64], "threadgroup": [64]}]}])
    };
    plan.add(
        case("extras.stage_in.indirect_command")
            .set("supports_icb", true)
            .set(
                "execute_icb",
                json!({"icb": "icb", "range_buffer": "range"}),
            )
            .set("icbs", command(&stage_input, uses("a", 0), false))
            .buffer(Buffer::data("range", 0, u32s(&[0, 1])).unbound()),
    );
    let mut a_strided = uses("a", 0);
    a_strided["attribute_stride"] = 16.into();
    plan.add(
        strided("extras.stage_in.indirect_command.dynamic_stride")
            .set("supports_icb", true)
            .set("execute_icb", json!({"icb": "icb", "count": 1}))
            .set("icbs", command(&dynamic, a_strided, true)),
    );
    // A kernel encodes that command: its buffers, the stride and the region.
    plan.add(
        Case::sequence(
            "extras.stage_in.gpu_command",
            library,
            vec![
                Step::compute("encode_stage_in", [1, 1, 1], [1, 1, 1])
                    .bind(&[("commands", 0), ("a", 1), ("b", 2), ("out", 3), ("n", 4)]),
                Step::compute("stage_in_compute", [n as u32, 1, 1], [64, 1, 1])
                    .set("stage_input", dynamic.clone())
                    .set("supports_icb", true)
                    .set("use", json!(["a", "b", "out"]))
                    .set("execute_icb", json!({"icb": "icb", "count": 1})),
            ],
        )
        .buffer(Buffer::data("a", 0, f32s(&padded)).unbound())
        .buffer(Buffer::data("b", 0, b.clone()).unbound())
        .buffer(Buffer::zeroed("out", 0, n * 16).unbound())
        .buffer(Buffer::data("n", 0, u32s(&[n as u32])).unbound())
        .buffer(Buffer::zeroed("commands", 0, 16).unbound())
        .set("icbs", json!([{"name": "icb", "type": "dispatch", "count": 1, "max_buffers": 3,
                              "inherit_pipeline": true, "dynamic_stride": true}]))
        .set("arguments", json!([{"buffer": "commands", "entries": [{"kind": "icb", "offset": 0, "resource": "icb"}]}]))
        .output(Output::exact("out", Dtype::F32, f32s(&expected))),
    );
}

/// Stencil export: each fragment's own value replaces the reference.
fn stencil_export(plan: &mut Plan, library: &str) {
    let size = 8u32;
    let expected: Vec<u8> = (0..size)
        .flat_map(|y| (0..size).map(move |x| (x * 16 + y) as u8))
        .collect();
    plan.add(
        Case::render(
            "extras.stencil_export",
            library,
            "vert_full",
            Some("frag_stencil"),
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                   "depth": {"texture": "ds", "clear": 1.0, "compare": "always", "write": false},
                   "stencil": {"texture": "ds", "clear": 0, "compare": "always", "pass": "replace", "reference": 0},
                   "primitive": "triangle_strip", "vertex_count": 4}),
        )
        .texture(Texture::d2("c", "rgba8unorm", size, size).usage(&["render"]))
        .texture(Texture::d2("ds", "depth32float_stencil8", size, size).usage(&["render"]))
        .output(
            Output::new("ds", Dtype::U8, Tolerance::exact())
                .set("aspect", "stencil")
                .set("as", "stencil")
                .expect_same(expected),
        ),
    );
}

/// An invariant position: a second pass with another fragment function
/// and depth test "equal" covers every pixel the first pass wrote.
fn invariance(plan: &mut Plan, library: &str) {
    let size = 8u32;
    let corners = [
        [-1.0, -1.0, 0.3, 0.0],
        [1.0, -1.0, 0.9, 0.0],
        [-1.0, 1.0, 1.7, 0.0],
        [1.0, 1.0, 2.3, 0.0],
    ];
    let state = |first: bool| {
        let mut s = json!({"colors": [{"texture": "c"}], "primitive": "triangle_strip", "vertex_count": 4,
                           "depth": {"texture": "d", "compare": if first { "less" } else { "equal" }, "write": first}});
        if first {
            s["colors"][0]["clear"] = json!([0, 0, 0, 0]);
            s["depth"]["clear"] = 1.0.into();
        }
        s
    };
    let second = [1.0, 0.0, 0.5, 1.0];
    plan.add(
        Case::sequence(
            "extras.invariant_position",
            library,
            vec![
                Step::render("vert_invariant", "frag_first", state(true))
                    .bind_stage("vertex", &[("corners", 0), ("scale", 1)]),
                Step::render("vert_invariant", "frag_second", state(false))
                    .bind_stage("vertex", &[("corners", 0), ("scale", 1)]),
            ],
        )
        .buffer(Buffer::data("corners", 0, f32s(&corners.concat())).unbound())
        .buffer(Buffer::data("scale", 0, f32s(&[1.0])).unbound())
        .texture(Texture::d2("c", "rgba32float", size, size).usage(&["render"]))
        .texture(Texture::d2("d", "depth32float", size, size).usage(&["render"]))
        .output(Output::exact(
            "c",
            Dtype::F32,
            f32s(&second.repeat((size * size) as usize)),
        )),
    );
}

/// Scalar bfloat conversion, ties to even, and back.
fn bfloat_scalar(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 256usize;
    let mut input: Vec<f64> = (0..n - 6)
        .map(|_| f32r(rng.log_uniform(1e-30, 1e30) * if rng.u32() & 1 == 1 { -1.0 } else { 1.0 }))
        .collect();
    // Exact ties between two bfloats, rounding to the even one either way.
    input.extend([
        1.0 + 2f64.powi(-8),
        1.0 + 3.0 * 2f64.powi(-8),
        -(2.0 + 2f64.powi(-7)),
        0.0,
        f64::INFINITY,
        65504.0,
    ]);
    let narrow: Vec<u8> = input
        .iter()
        .flat_map(|&x| ((bits32(bfloat(x)) >> 16) as u16).to_le_bytes())
        .collect();
    let wide: Vec<f64> = input.iter().map(|&x| f32r(bfloat(x) * 2.0)).collect();
    plan.add(
        Case::compute1("extras.bfloat_scalar", library, "bfloat_scalar", n as u32)
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::zeroed("narrow", 1, n * 2))
            .buffer(Buffer::zeroed("wide", 2, n * 4))
            .output(Output::exact("narrow", Dtype::U16, narrow))
            .output(Output::exact("wide", Dtype::F32, f32s(&wide))),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library(
        "extras",
        SOURCE,
        &["-fpreserve-invariance"],
        super::plan::LATEST,
    );
    let mut rng = Random::new(2718);
    simd_ids(plan, &library);
    handles(plan, &library);
    atomic_flags(plan, &library);
    packing(plan, &library, &mut rng);
    multisampled(plan, &library);
    gradients(plan, &library);
    stage_in(plan, &library, &mut rng);
    stencil_export(plan, &library);
    invariance(plan, &library);
    bfloat_scalar(plan, &library, &mut rng);
}
