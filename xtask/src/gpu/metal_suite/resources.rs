//! corpus/resources.metal: heaps, texture views and programmable sample
//! positions, each result asserted exactly unless a format conversion
//! allows rounding.
//!
//! - Heaps: buffers from an automatic heap; buffers a placement heap puts
//!   at chosen offsets, one aliasing another's memory; resources an
//!   argument buffer alone names, resident through `useHeap`; and work
//!   ordered across encoders by a tracked heap.
//! - Views: the same memory as another pixel format of its size, as an
//!   sRGB format, over a mipmap range, over a slice range, as a cube, and
//!   with each component swizzled for reads and samples.
//! - Sample positions: the samples an edge covers at positions the render
//!   pass sets, read back sample by sample.
use super::plan::{Buffer, Case, Output, Plan, Step, Texture, Tolerance};
use super::textures::{srgb, srgb_decode};
use super::values::{Dtype, Random, f16_bits, f32s, u32s};
use serde_json::json;

const SOURCE: &str = "resources.metal";
const N: u32 = 256;

fn scaled(v: &[u32]) -> Vec<u32> {
    v.iter()
        .map(|x| x.wrapping_mul(3).wrapping_add(1))
        .collect()
}

fn heaps(plan: &mut Plan, library: &str, rng: &mut Random) {
    let v: Vec<u32> = (0..N).map(|_| rng.u32()).collect();
    let w: Vec<u32> = (0..N).map(|_| rng.u32()).collect();
    let bytes = N as usize * 4;
    let shared = |name: &str, kind: &str| json!({"name": name, "type": kind, "size": 1 << 20});
    plan.add(
        Case::compute1("heap.automatic", library, "scale_words", N)
            .buffer(Buffer::data("in", 0, u32s(&v)).set("heap", "h"))
            .buffer(Buffer::zeroed("out", 1, bytes).set("heap", "h"))
            .set("heaps", json!([shared("h", "automatic")]))
            .output(Output::exact("out", Dtype::U32, u32s(&scaled(&v)))),
    );
    // "a" and "b" share their first bytes; "c" lies past both. The kernel
    // reads "a"'s contents through "b".
    let at = 1 << 16;
    plan.add(
        Case::compute1("heap.placement_alias", library, "copy_words", N)
            .buffer(
                Buffer::data("a", 0, u32s(&v))
                    .unbound()
                    .set("heap", "p")
                    .set("heap_offset", 0),
            )
            .buffer(
                Buffer::zeroed("b", 0, bytes)
                    .set("heap", "p")
                    .set("heap_offset", 0)
                    .set("alias_of", "a"),
            )
            .buffer(
                Buffer::zeroed("c", 1, bytes)
                    .set("heap", "p")
                    .set("heap_offset", at),
            )
            .set(
                "heaps",
                json!([{"name": "p", "type": "placement", "size": 1 << 20, "untracked": true}]),
            )
            .output(Output::exact("c", Dtype::U32, u32s(&v))),
    );
    // An argument buffer of a heap buffer and a heap texture, which no
    // encoder binds or names by useResource.
    let image: Vec<f64> = (0..N * 4)
        .map(|_| f64::from(rng.below(256) as u32) / 4.0)
        .collect();
    let expected: Vec<f64> = image
        .chunks(4)
        .zip(&w)
        .flat_map(|(t, &x)| {
            let x = f64::from(x as f32);
            t.iter()
                .map(move |c| f64::from((c + x) as f32))
                .collect::<Vec<_>>()
        })
        .collect();
    plan.add(
        Case::compute1("heap.use_heap", library, "read_heap_arguments", 64)
            .buffer(Buffer::zeroed("args", 0, 16))
            .buffer(Buffer::zeroed("out", 1, 64 * 16))
            .buffer(Buffer::data("values", 0, u32s(&w[..64])).unbound().set("heap", "h"))
            .texture(
                Texture::d2("image", "rgba32float", 8, 8)
                    .data(f32s(&image[..256]))
                    .set("heap", "t"),
            )
            .set(
                "heaps",
                json!([shared("h", "automatic"), {"name": "t", "type": "automatic", "storage": "private", "size": 1 << 20}]),
            )
            .set("use_heaps", json!(["h", "t"]))
            .set("arguments", json!([{"buffer": "args", "entries": [
                {"kind": "buffer", "offset": 0, "resource": "values"},
                {"kind": "texture", "offset": 8, "resource": "image"}]}]))
            .output(
                Output::new("out", Dtype::F32, Tolerance::ulp(1.0)).expect_same(f32s(&expected[..256])),
            ),
    );
    // A tracked heap orders a dispatch after the one that wrote its input.
    plan.add(
        Case::sequence(
            "heap.tracked_encoders",
            library,
            vec![
                Step::compute("scale_words", [N, 1, 1], [64, 1, 1]).bind(&[("in", 0), ("mid", 1)]),
                Step::compute("scale_words", [N, 1, 1], [64, 1, 1]).bind(&[("mid", 0), ("out", 1)]),
            ],
        )
        .buffer(Buffer::data("in", 0, u32s(&v)).unbound().set("heap", "h"))
        .buffer(Buffer::zeroed("mid", 0, bytes).unbound().set("heap", "h"))
        .buffer(Buffer::zeroed("out", 0, bytes).unbound().set("heap", "h"))
        .set("heaps", json!([shared("h", "automatic")]))
        .output(Output::exact("out", Dtype::U32, u32s(&scaled(&scaled(&v))))),
    );
}

/// A float read kernel over a view (after the texture it views) of `size`
/// (width, height, slices read), whose queries answer `levels` and
/// `slices`.
fn read_view(
    name: &str,
    library: &str,
    [source, view]: [Texture; 2],
    size: [u32; 3],
    levels: u32,
    slices: u32,
) -> Case {
    let [w, h, d] = size;
    let function = if d > 1 { "read_array" } else { "read_float" };
    Case::compute(name, library, function, [w, h, d], [w.min(8), h.min(8), 1])
        .dispatch_threads()
        .texture(source)
        .texture(view.index(0))
        .buffer(Buffer::zeroed("out", 0, (w * h * d * 16) as usize))
        .buffer(Buffer::zeroed("size", 1, 16))
        .output(Output::exact(
            "size",
            Dtype::U32,
            u32s(&[w, h, levels, slices]),
        ))
}

fn views(plan: &mut Plan, library: &str, rng: &mut Random) {
    let (w, h) = (8u32, 8u32);
    let texels = (w * h) as usize;
    // Format views of rgba8unorm: as rgba8uint (its bytes), as sRGB
    // (decoded), and of rgba16float as rg32uint (its bits).
    let bytes: Vec<u8> = (0..texels * 4).map(|_| rng.u32() as u8).collect();
    let source = || {
        Texture::d2("source", "rgba8unorm", w, h)
            .data(bytes.clone())
            .usage(&["read", "view"])
    };
    let view = |format: &str| Texture::d2("view", format, w, h).set("view_of", "source");
    plan.add(
        Case::compute(
            "view.format.rgba8uint",
            library,
            "read_uint",
            [w, h, 1],
            [8, 8, 1],
        )
        .dispatch_threads()
        .texture(source())
        .texture(view("rgba8uint").index(0))
        .buffer(Buffer::zeroed("out", 0, texels * 16))
        .output(Output::exact(
            "out",
            Dtype::U32,
            u32s(&bytes.iter().map(|&b| u32::from(b)).collect::<Vec<_>>()),
        )),
    );
    let decoded: Vec<f64> = bytes
        .chunks(4)
        .flat_map(|t| {
            let c = |b: u8| f64::from(b) / 255.0;
            [srgb(c(t[0])), srgb(c(t[1])), srgb(c(t[2])), c(t[3])]
        })
        .collect();
    plan.add(
        read_view(
            "view.format.srgb",
            library,
            [source(), view("rgba8unorm_srgb")],
            [w, h, 1],
            1,
            1,
        )
        .output(Output::new("out", Dtype::F32, srgb_decode()).expect_same(f32s(&decoded))),
    );
    let halves: Vec<u16> = (0..texels * 4)
        .map(|_| f16_bits(rng.uniform(-8.0, 8.0)))
        .collect();
    let words: Vec<u32> = halves
        .chunks(2)
        .map(|p| u32::from(p[0]) | u32::from(p[1]) << 16)
        .collect();
    let mut expected = vec![];
    for pair in words.chunks(2) {
        expected.extend([pair[0], pair[1], 0, 1]);
    }
    plan.add(
        Case::compute(
            "view.format.rg32uint",
            library,
            "read_uint",
            [w, h, 1],
            [8, 8, 1],
        )
        .dispatch_threads()
        .texture(
            Texture::d2("source", "rgba16float", w, h)
                .data(halves.iter().flat_map(|x| x.to_le_bytes()).collect())
                .usage(&["read", "view"]),
        )
        .texture(view("rg32uint").index(0))
        .buffer(Buffer::zeroed("out", 0, texels * 16))
        .output(Output::exact("out", Dtype::U32, u32s(&expected))),
    );
    // Mipmap and slice ranges of rgba32float textures whose every texel
    // names its slice, level and position.
    let texel = |slice: u32, level: u32, x: u32, y: u32| {
        [
            f64::from(slice),
            f64::from(level),
            f64::from(x),
            f64::from(y),
        ]
    };
    let image = |slices: u32, levels: u32, w: u32, h: u32| -> Vec<f64> {
        let mut out = vec![];
        for s in 0..slices {
            for l in 0..levels {
                for y in 0..(h >> l).max(1) {
                    for x in 0..(w >> l).max(1) {
                        out.extend(texel(s, l, x, y));
                    }
                }
            }
        }
        out
    };
    let level = |s: u32, l: u32| -> Vec<f64> {
        (0..h >> l)
            .flat_map(|y| (0..w >> l).flat_map(move |x| texel(s, l, x, y)))
            .collect()
    };
    let mipped = Texture::d2("source", "rgba32float", w, h)
        .mipmaps(4)
        .data(f32s(&image(1, 4, w, h)));
    plan.add(
        read_view(
            "view.levels",
            library,
            [
                mipped,
                Texture::d2("view", "rgba32float", w / 2, h / 2)
                    .set("view_of", "source")
                    .set("levels", json!([1, 2])),
            ],
            [w / 2, h / 2, 1],
            2,
            1,
        )
        .output(Output::exact("out", Dtype::F32, f32s(&level(0, 1)))),
    );
    let layered = |slices: u32| {
        Texture::new("source", "rgba32float", "2d_array", [w, h, 1])
            .array(slices)
            .data(f32s(&image(slices, 1, w, h)))
    };
    plan.add(
        read_view(
            "view.slice_as_2d",
            library,
            [
                layered(4),
                Texture::d2("view", "rgba32float", w, h)
                    .set("view_of", "source")
                    .set("type", "2d")
                    .set("slices", json!([2, 1])),
            ],
            [w, h, 1],
            1,
            1,
        )
        .output(Output::exact("out", Dtype::F32, f32s(&level(2, 0)))),
    );
    plan.add(
        read_view(
            "view.slice_range",
            library,
            [
                layered(4),
                Texture::new("view", "rgba32float", "2d_array", [w, h, 1])
                    .set("view_of", "source")
                    .set("slices", json!([1, 2])),
            ],
            [w, h, 2],
            1,
            2,
        )
        .output(Output::exact(
            "out",
            Dtype::F32,
            f32s(&[level(1, 0), level(2, 0)].concat()),
        )),
    );
    plan.add(
        Case::compute(
            "view.array_as_cube",
            library,
            "read_cube",
            [w, h, 6],
            [8, 8, 1],
        )
        .dispatch_threads()
        .texture(layered(6))
        .texture(
            Texture::new("view", "rgba32float", "cube", [w, h, 1])
                .set("view_of", "source")
                .index(0),
        )
        .buffer(Buffer::zeroed("out", 0, (w * h * 6 * 16) as usize))
        .output(Output::exact(
            "out",
            Dtype::F32,
            f32s(&(0..6).flat_map(|s| level(s, 0)).collect::<Vec<_>>()),
        )),
    );
    // Swizzles, for reads and nearest samples alike.
    let values: Vec<f64> = (0..texels * 4)
        .map(|_| f64::from(rng.below(256) as u32) / 8.0)
        .collect();
    for swizzle in ["bgra", "0a1r", "rrrg"] {
        let pick = |t: &[f64], k: char| match k {
            'r' => t[0],
            'g' => t[1],
            'b' => t[2],
            'a' => t[3],
            '0' => 0.0,
            _ => 1.0,
        };
        let swizzled: Vec<f64> = values
            .chunks(4)
            .flat_map(|t| swizzle.chars().map(|k| pick(t, k)).collect::<Vec<_>>())
            .collect();
        let source = || Texture::d2("source", "rgba32float", w, h).data(f32s(&values));
        let swizzled_view = || {
            Texture::d2("view", "rgba32float", w, h)
                .set("view_of", "source")
                .set("swizzle", swizzle)
                .index(0)
        };
        plan.add(
            Case::compute(
                &format!("view.swizzle.{swizzle}.read"),
                library,
                "read_float",
                [w, h, 1],
                [8, 8, 1],
            )
            .dispatch_threads()
            .texture(source())
            .texture(swizzled_view())
            .buffer(Buffer::zeroed("out", 0, texels * 16))
            .buffer(Buffer::zeroed("size", 1, 16))
            .output(Output::exact("out", Dtype::F32, f32s(&swizzled))),
        );
        plan.add(
            Case::compute(
                &format!("view.swizzle.{swizzle}.sample"),
                library,
                "sample_float",
                [w, h, 1],
                [8, 8, 1],
            )
            .dispatch_threads()
            .texture(source())
            .texture(swizzled_view())
            .sampler(json!({"name": "s", "index": 0}))
            .buffer(Buffer::zeroed("out", 0, texels * 16))
            .output(Output::exact("out", Dtype::F32, f32s(&swizzled))),
        );
    }
}

/// Coverage at the positions a pass sets: a rectangle whose right and
/// bottom edges cross pixels between samples covers exactly the samples
/// on its side, which a constant fragment then fills.
fn sample_positions(plan: &mut Plan, library: &str) {
    let (w, h) = (4u32, 4u32);
    // In window coordinates the rectangle spans x < 2.5 and y < 1.5.
    let (right, bottom) = (2.5, 1.5);
    let rect = [
        -1.0,
        1.0 - bottom / f64::from(h) * 2.0,
        right / f64::from(w) * 2.0 - 1.0,
        1.0,
    ];
    for (name, positions) in [
        (
            "grid",
            [[0.25, 0.25], [0.75, 0.25], [0.25, 0.75], [0.75, 0.75]],
        ),
        (
            "skewed",
            [
                [0.0625, 0.5625],
                [0.5625, 0.9375],
                [0.9375, 0.4375],
                [0.4375, 0.0625],
            ],
        ),
    ] {
        let expected: Vec<f64> = (0..h)
            .flat_map(|y| (0..w).map(move |x| (x, y)))
            .flat_map(|(x, y)| {
                positions.iter().flat_map(move |p| {
                    let covered = f64::from(x) + p[0] < right && f64::from(y) + p[1] < bottom;
                    [if covered { 1.0 } else { 0.0 }; 4]
                })
            })
            .collect();
        plan.add(
            Case::sequence(
                &format!("render.sample_positions.{name}"),
                library,
                vec![
                    Step::render(
                        "vert_rect",
                        "frag_one",
                        json!({"colors": [{"texture": "ms", "clear": [0, 0, 0, 0]}], "samples": 4,
                               "primitive": "triangle_strip", "vertex_count": 4, "sample_positions": positions}),
                    )
                    .bind_stage("vertex", &[("rect", 0)]),
                    Step::compute("read_samples4", [w, h, 1], [4, 4, 1])
                        .bind_textures(&[("ms", 0)])
                        .bind(&[("out", 0)]),
                ],
            )
            .requires(&[], &["programmable_sample_positions"])
            .buffer(Buffer::data("rect", 0, f32s(&rect)).unbound())
            .buffer(Buffer::zeroed("out", 0, (w * h * 64) as usize).unbound())
            .texture(
                Texture::new("ms", "rgba16float", "2d_ms", [w, h, 1])
                    .samples(4)
                    .usage(&["render", "read"]),
            )
            .output(Output::exact("out", Dtype::F32, f32s(&expected))),
        );
        // The rectangle's depth over a cleared multisampled depth target,
        // stored with the custom positions that decide which samples it
        // covers.
        let depths: Vec<f64> = expected
            .chunks(4)
            .map(|s| if s[0] == 1.0 { 0.0 } else { 0.75 })
            .collect();
        plan.add(
            Case::sequence(
                &format!("render.sample_positions.{name}.depth"),
                library,
                vec![
                    Step::render(
                        "vert_rect",
                        "frag_one",
                        json!({"colors": [{"texture": "ms", "clear": [0, 0, 0, 0]}], "samples": 4,
                               "depth": {"texture": "d", "clear": 0.75, "compare": "always",
                                         "custom_sample_positions": true},
                               "primitive": "triangle_strip", "vertex_count": 4, "sample_positions": positions}),
                    )
                    .bind_stage("vertex", &[("rect", 0)]),
                    Step::compute("read_depth_samples4", [w, h, 1], [4, 4, 1])
                        .bind_textures(&[("d", 0)])
                        .bind(&[("out", 0)]),
                ],
            )
            .requires(&[], &["programmable_sample_positions"])
            .buffer(Buffer::data("rect", 0, f32s(&rect)).unbound())
            .buffer(Buffer::zeroed("out", 0, (w * h * 16) as usize).unbound())
            .texture(Texture::new("ms", "rgba16float", "2d_ms", [w, h, 1]).samples(4).usage(&["render"]))
            .texture(Texture::new("d", "depth32float", "2d_ms", [w, h, 1]).samples(4).usage(&["render", "read"]))
            .output(Output::exact("out", Dtype::F32, f32s(&depths))),
        );
    }
}

/// More heaps: two textures a private placement heap holds at their own
/// offsets, and an untracked heap whose buffers a fence orders.
fn heaps_more(plan: &mut Plan, library: &str, rng: &mut Random) {
    let (w, h) = (8u32, 8u32);
    let a: Vec<f64> = (0..w * h * 4)
        .map(|_| f64::from(rng.below(256) as u32) / 4.0)
        .collect();
    let b: Vec<f64> = (0..w * h * 4)
        .map(|_| f64::from(rng.below(256) as u32) / 8.0)
        .collect();
    let both: Vec<f64> = a
        .chunks(4)
        .zip(b.chunks(4))
        .flat_map(|(x, y)| [x, y].concat())
        .collect();
    plan.add(
        Case::compute("heap.placement_textures", library, "read_two", [w, h, 1], [8, 8, 1])
            .dispatch_threads()
            .set("heaps", json!([{"name": "p", "type": "placement", "storage": "private", "untracked": true, "size": 1 << 22}]))
            .texture(Texture::d2("a", "rgba32float", w, h).data(f32s(&a)).set("heap", "p").set("heap_offset", 0).index(0))
            .texture(
                Texture::d2("b", "rgba32float", w, h)
                    .data(f32s(&b))
                    .set("heap", "p")
                    .set("heap_offset", 1 << 21)
                    .index(1),
            )
            .set("use_heaps", json!(["p"]))
            .buffer(Buffer::zeroed("out", 0, (w * h * 32) as usize))
            .output(Output::exact("out", Dtype::F32, f32s(&both))),
    );
    let v: Vec<u32> = (0..N).map(|_| rng.u32()).collect();
    let bytes = N as usize * 4;
    plan.add(
        Case::sequence(
            "heap.untracked_fence",
            library,
            vec![
                Step::compute("scale_words", [N, 1, 1], [64, 1, 1])
                    .bind(&[("in", 0), ("mid", 1)])
                    .update_fences(&["f"]),
                Step::compute("scale_words", [N, 1, 1], [64, 1, 1])
                    .bind(&[("mid", 0), ("out", 1)])
                    .wait_fences(&["f"]),
            ],
        )
        .set(
            "heaps",
            json!([{"name": "u", "type": "automatic", "untracked": true, "size": 1 << 20}]),
        )
        .buffer(Buffer::data("in", 0, u32s(&v)).unbound().set("heap", "u"))
        .buffer(Buffer::zeroed("mid", 0, bytes).unbound().set("heap", "u"))
        .buffer(Buffer::zeroed("out", 0, bytes).unbound().set("heap", "u"))
        .output(Output::exact("out", Dtype::U32, u32s(&scaled(&scaled(&v))))),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("resources", SOURCE, &[], super::plan::LATEST);
    let mut rng = Random::new(4242);
    heaps(plan, &library, &mut rng);
    heaps_more(plan, &library, &mut rng);
    views(plan, &library, &mut rng);
    sample_positions(plan, &library);
}
