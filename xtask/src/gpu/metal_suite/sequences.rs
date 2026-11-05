//! corpus/sequences.metal: work that reads what earlier work in the same
//! command buffer or queue wrote, each result asserted exactly. Every
//! dependency here is one Metal orders: dispatches of one encoder (serial
//! dispatch), encoders of one command buffer and command buffers of one
//! queue for tracked resources, fences between encoders and events between
//! command buffers for untracked ones.
use super::plan::{Buffer, Case, Output, Plan, Step, Texture, Tolerance};
use super::values::{Dtype, Random, f32s, u32s};
use serde_json::json;

const SOURCE: &str = "sequences.metal";
const N: u32 = 256;

fn exact(name: &str, dtype: Dtype, data: Vec<u8>) -> Output {
    Output::new(name, dtype, Tolerance::exact()).expect_same(data)
}

fn scaled(v: &[u32]) -> Vec<u32> {
    v.iter()
        .map(|x| x.wrapping_mul(3).wrapping_add(1))
        .collect()
}

fn neighbours(v: &[u32]) -> Vec<u32> {
    (0..v.len())
        .map(|i| v[i].wrapping_add(v[(i + 1) % v.len()].wrapping_mul(2)))
        .collect()
}

fn grid(n: u32) -> [u32; 3] {
    [n, 1, 1]
}

/// Dependent compute: within one encoder, across encoders, across command
/// buffers, and ordered by a fence or an event on an untracked buffer.
fn compute(plan: &mut Plan, library: &str, rng: &mut Random) {
    let v: Vec<u32> = (0..N).map(|_| rng.u32()).collect();
    let mid = scaled(&v);
    let out = neighbours(&mid);
    let again = neighbours(&out);
    let buffers = |untracked: bool| {
        let mid = Buffer::zeroed("mid", 0, N as usize * 4).unbound();
        [
            Buffer::data("in", 0, u32s(&v)).unbound(),
            if untracked {
                mid.set("untracked", true)
            } else {
                mid
            },
            Buffer::zeroed("out", 0, N as usize * 4).unbound(),
            Buffer::zeroed("again", 0, N as usize * 4).unbound(),
            Buffer::data("n", 0, u32s(&[N])).unbound(),
        ]
    };
    let produce = || Step::compute("scale", grid(N), [64, 1, 1]).bind(&[("in", 0), ("mid", 1)]);
    let consume = || {
        Step::compute("neighbours", grid(N), [64, 1, 1]).bind(&[("mid", 0), ("out", 1), ("n", 2)])
    };
    let again_step = || {
        Step::compute("neighbours", grid(N), [64, 1, 1]).bind(&[("out", 0), ("again", 1), ("n", 2)])
    };
    for (name, steps, untracked) in [
        (
            "sequence.compute.one_encoder",
            vec![produce(), consume().continues(), again_step().continues()],
            false,
        ),
        (
            "sequence.compute.encoders",
            vec![produce(), consume(), again_step()],
            false,
        ),
        (
            "sequence.compute.command_buffers",
            vec![
                produce(),
                consume().new_command_buffer(),
                again_step().new_command_buffer(),
            ],
            false,
        ),
        (
            "sequence.compute.fence",
            vec![
                produce().update_fences(&["mid"]),
                consume().wait_fences(&["mid"]).update_fences(&["out"]),
                again_step().wait_fences(&["out"]),
            ],
            true,
        ),
        (
            "sequence.compute.event",
            vec![
                produce().signal_events(&[("e", 1)]),
                consume()
                    .new_command_buffer()
                    .wait_events(&[("e", 1)])
                    .signal_events(&[("e", 2)]),
                again_step().wait_events(&[("e", 2)]),
            ],
            true,
        ),
    ] {
        plan.add(
            Case::sequence(name, library, steps)
                .buffers(buffers(untracked))
                .output(exact("out", Dtype::U32, u32s(&out)))
                .output(exact("again", Dtype::U32, u32s(&again))),
        );
    }
    // Blits before and after compute: a fill the dispatch reads, and a copy
    // of what it wrote.
    let filled = vec![0x0707_0707u32; N as usize];
    plan.add(
        Case::sequence(
            "sequence.blit_compute_blit",
            library,
            vec![
                Step::blit(json!([{"op": "fill_buffer", "dst": "in", "offset": 0, "size": N * 4, "value": 7}])),
                Step::compute("scale", grid(N), [64, 1, 1]).bind(&[("in", 0), ("mid", 1)]),
                Step::blit(json!([{"op": "copy_buffer", "src": "mid", "src_offset": 0, "dst": "copy",
                                   "dst_offset": 0, "size": N * 4}])),
            ],
        )
        .buffer(Buffer::data("in", 0, u32s(&v)).unbound())
        .buffer(Buffer::zeroed("mid", 0, N as usize * 4).unbound())
        .buffer(Buffer::zeroed("copy", 0, N as usize * 4).unbound())
        .output(exact("copy", Dtype::U32, u32s(&scaled(&filled)))),
    );
}

/// A dispatch and a draw whose arguments an earlier dispatch wrote.
fn indirect(plan: &mut Plan, library: &str) {
    let threads = 5 * 64;
    let mut seen = vec![0u32; 512];
    for (i, s) in seen.iter_mut().enumerate().take(threads) {
        *s = (i / 64) as u32 * 1000 + i as u32;
    }
    let arguments = Step::compute("write_arguments", [1, 1, 1], [1, 1, 1]).bind(&[
        ("dispatch", 0),
        ("draw", 1),
        ("corners", 2),
    ]);
    plan.add(
        Case::sequence(
            "sequence.indirect.dispatch",
            library,
            vec![
                arguments,
                Step::compute("count_threads", [0, 0, 0], [64, 1, 1])
                    .indirect("dispatch", 0)
                    .bind(&[("count", 0), ("seen", 1)]),
            ],
        )
        .buffer(Buffer::zeroed("dispatch", 0, 16).unbound())
        .buffer(Buffer::zeroed("draw", 0, 16).unbound())
        .buffer(Buffer::zeroed("corners", 0, 64).unbound())
        .buffer(Buffer::zeroed("count", 0, 16).unbound())
        .buffer(Buffer::zeroed("seen", 0, 512 * 4).unbound())
        .output(exact("count", Dtype::U32, u32s(&[threads as u32])).set("length", 4))
        .output(exact("seen", Dtype::U32, u32s(&seen))),
    );
    let color = [0.25, 0.5, 0.75, 1.0];
    plan.add(
        Case::sequence(
            "sequence.indirect.draw",
            library,
            vec![
                Step::compute("write_arguments", [1, 1, 1], [1, 1, 1])
                    .bind(&[("dispatch", 0), ("draw", 1), ("corners", 2)]),
                Step::render(
                    "vert_corners",
                    "frag_constant",
                    json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "primitive": "triangle_strip",
                           "indirect": {"buffer": "draw", "offset": 0}}),
                )
                .bind_stage("vertex", &[("corners", 0)])
                .bind_stage("fragment", &[("color", 0)]),
            ],
        )
        .buffer(Buffer::zeroed("dispatch", 0, 16).unbound())
        .buffer(Buffer::zeroed("draw", 0, 16).unbound())
        .buffer(Buffer::zeroed("corners", 0, 64).unbound())
        .buffer(Buffer::data("color", 0, f32s(&color)).unbound())
        .texture(Texture::d2("c", "rgba32float", 8, 8).usage(&["render"]))
        .output(exact("c", Dtype::F32, f32s(&color.repeat(64)))),
    );
}

/// Render targets read by compute and by later passes, a pass that loads
/// an earlier pass's target, and textures compute wrote read by a draw.
fn passes(plan: &mut Plan, library: &str) {
    let (w, h) = (8u32, 8u32);
    let pixels = || (0..h).flat_map(move |y| (0..w).map(move |x| (x, y)));
    let strip = |clear: bool| {
        let mut state =
            json!({"colors": [{"texture": "a"}], "primitive": "triangle_strip", "vertex_count": 4});
        if clear {
            state["colors"][0]["clear"] = json!([0, 0, 0, 0]);
        }
        state
    };
    let coordinates: Vec<f64> = pixels()
        .flat_map(|(x, y)| {
            [
                (f64::from(x) + 0.5) / 16.0,
                (f64::from(y) + 0.5) / 16.0,
                0.25,
                1.0,
            ]
            .map(|c| c * 2.0)
        })
        .collect();
    plan.add(
        Case::sequence(
            "sequence.render_then_compute",
            library,
            vec![
                Step::render("vert_rect", "frag_coordinates", strip(true))
                    .bind_stage("vertex", &[("full", 0)]),
                Step::compute("read_target", [w, h, 1], [8, 8, 1])
                    .bind_textures(&[("a", 0)])
                    .bind(&[("out", 0)]),
            ],
        )
        .buffer(Buffer::data("full", 0, f32s(&[-1.0, -1.0, 1.0, 1.0])).unbound())
        .buffer(Buffer::zeroed("out", 0, (w * h * 16) as usize).unbound())
        .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render", "read"]))
        .output(exact("out", Dtype::F32, f32s(&coordinates))),
    );
    // Pass 1 clears and fills the left half, pass 2 loads and fills the
    // right, pass 3 writes one minus their result into another target.
    let (left, right) = ([0.25, 0.5, 0.0, 1.0], [0.75, 0.0, 0.5, 0.5]);
    let first: Vec<f64> = pixels()
        .flat_map(|(x, _)| if x < w / 2 { left } else { right })
        .collect();
    let inverted: Vec<f64> = first.iter().map(|c| 1.0 - c).collect();
    let mut invert = strip(true);
    invert["colors"][0]["texture"] = "b".into();
    plan.add(
        Case::sequence(
            "sequence.render_passes",
            library,
            vec![
                Step::render("vert_rect", "frag_constant", strip(true))
                    .bind_stage("vertex", &[("left_rect", 0)])
                    .bind_stage("fragment", &[("left", 0)]),
                Step::render("vert_rect", "frag_constant", strip(false))
                    .bind_stage("vertex", &[("right_rect", 0)])
                    .bind_stage("fragment", &[("right", 0)]),
                Step::render("vert_rect", "frag_invert", invert)
                    .bind_stage("vertex", &[("full", 0)])
                    .bind_textures(&[("a", 0)]),
            ],
        )
        .buffer(Buffer::data("left_rect", 0, f32s(&[-1.0, -1.0, 0.0, 1.0])).unbound())
        .buffer(Buffer::data("right_rect", 0, f32s(&[0.0, -1.0, 1.0, 1.0])).unbound())
        .buffer(Buffer::data("full", 0, f32s(&[-1.0, -1.0, 1.0, 1.0])).unbound())
        .buffer(Buffer::data("left", 0, f32s(&left)).unbound())
        .buffer(Buffer::data("right", 0, f32s(&right)).unbound())
        .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render", "read"]))
        .texture(Texture::d2("b", "rgba32float", w, h).usage(&["render"]))
        .output(exact("a", Dtype::F32, f32s(&first)))
        .output(exact("b", Dtype::F32, f32s(&inverted))),
    );
    let halves: Vec<f64> = pixels()
        .flat_map(|(x, y)| [f64::from(x) * 0.125, f64::from(y) * 0.25, 0.5, 1.0].map(|c| c * 0.5))
        .collect();
    let mut halve = strip(true);
    halve["colors"][0]["texture"] = "b".into();
    plan.add(
        Case::sequence(
            "sequence.compute_then_render",
            library,
            vec![
                Step::compute("write_texture", [w, h, 1], [8, 8, 1]).bind_textures(&[("a", 0)]),
                Step::render("vert_rect", "frag_halve", halve)
                    .bind_stage("vertex", &[("full", 0)])
                    .bind_textures(&[("a", 0)]),
            ],
        )
        .buffer(Buffer::data("full", 0, f32s(&[-1.0, -1.0, 1.0, 1.0])).unbound())
        .texture(Texture::d2("a", "rgba32float", w, h).usage(&["read", "write"]))
        .texture(Texture::d2("b", "rgba32float", w, h).usage(&["render"]))
        .output(exact("b", Dtype::F32, f32s(&halves))),
    );
    // A 4x multisampled target shaded per sample over its left half, then
    // every sample read back by compute.
    let mut samples = vec![];
    for (x, _) in pixels() {
        for s in 0..4 {
            samples.push(if x < w / 2 {
                f64::from(s + 1) * 0.25
            } else {
                0.0
            });
        }
    }
    let mut per_sample = strip(true);
    per_sample["colors"][0]["texture"] = "ms".into();
    per_sample["samples"] = 4.into();
    plan.add(
        Case::sequence(
            "sequence.msaa_samples",
            library,
            vec![
                Step::render("vert_rect", "frag_sample", per_sample)
                    .bind_stage("vertex", &[("left_rect", 0)]),
                Step::compute("read_samples", [w, h, 1], [8, 8, 1])
                    .bind_textures(&[("ms", 0)])
                    .bind(&[("out", 0), ("count", 1)]),
            ],
        )
        .buffer(Buffer::data("left_rect", 0, f32s(&[-1.0, -1.0, 0.0, 1.0])).unbound())
        .buffer(Buffer::zeroed("out", 0, (w * h * 16) as usize).unbound())
        .buffer(Buffer::zeroed("count", 0, 16).unbound())
        .texture(
            Texture::new("ms", "rgba32float", "2d_ms", [w, h, 1])
                .samples(4)
                .usage(&["render", "read"]),
        )
        .output(exact("out", Dtype::F32, f32s(&samples)))
        .output(exact("count", Dtype::U32, u32s(&[4])).set("length", 4)),
    );
}

/// A command's buffer binding: `name` at `index`, from `offset` bytes.
fn uses(name: &str, index: u32, offset: u32) -> serde_json::Value {
    json!({"name": name, "index": index, "offset": offset})
}

/// Indirect command buffers: dispatches and draws encoded on the CPU, with
/// their own pipelines and buffers or inheriting the encoder's, ordered by
/// barriers, executed whole or over a range; and the same encoded by a
/// kernel through an argument buffer, then executed by a later encoder.
fn indirect_commands(plan: &mut Plan, library: &str, rng: &mut Random) {
    let slice = 64u32;
    let v: Vec<u32> = (0..slice * 4).map(|_| rng.u32() >> 4).collect();
    let step = |x: u32, k: u32| x.wrapping_mul(2).wrapping_add(k);
    let part = |s: u32| v[(s * slice) as usize..((s + 1) * slice) as usize].to_vec();
    // Slice 0 takes k = 1 then, after a barrier, k = 2; slice 1 is scaled;
    // slice 2 takes k = 5; slice 3 is untouched.
    let commands = json!([
        {"function": "icb_step", "buffers": [uses("data", 0, 0), uses("k1", 1, 0)], "threadgroups": [1], "threadgroup": [slice]},
        {"function": "icb_step", "buffers": [uses("data", 0, 0), uses("k2", 1, 0)], "threadgroups": [1], "threadgroup": [slice], "barrier": true},
        {"function": "icb_scale", "buffers": [uses("data", 0, slice * 4)], "threadgroups": [1], "threadgroup": [slice]},
        {"function": "icb_step", "buffers": [uses("data", 0, slice * 8), uses("k5", 1, 0)], "threadgroups": [1], "threadgroup": [slice]},
    ]);
    let whole: Vec<u32> = [
        part(0)
            .iter()
            .map(|&x| step(step(x, 1), 2))
            .collect::<Vec<_>>(),
        scaled(&part(1)),
        part(2).iter().map(|&x| step(x, 5)).collect(),
        part(3),
    ]
    .concat();
    let ranged: Vec<u32> = [
        part(0),
        scaled(&part(1)),
        whole[(slice * 2) as usize..(slice * 3) as usize].to_vec(),
        part(3),
    ]
    .concat();
    for (name, start, count, expected) in [
        ("sequence.icb.cpu_dispatch", 0, 4, &whole),
        ("sequence.icb.cpu_dispatch_range", 2, 2, &ranged),
    ] {
        plan.add(
            Case::sequence(
                name,
                library,
                vec![
                    Step::compute("icb_scale", grid(slice), [slice, 1, 1])
                        .set("supports_icb", true)
                        .set("execute_icb", json!({"icb": "icb", "start": start, "count": count})),
                ],
            )
            .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
            .buffer(Buffer::data("k1", 0, u32s(&[1])).unbound())
            .buffer(Buffer::data("k2", 0, u32s(&[2])).unbound())
            .buffer(Buffer::data("k5", 0, u32s(&[5])).unbound())
            .set("icbs", json!([{"name": "icb", "type": "dispatch", "count": 4, "max_buffers": 2, "commands": commands}]))
            .output(exact("data", Dtype::U32, u32s(expected))),
        );
    }
    // One dispatch inheriting the encoder's pipeline and buffers.
    plan.add(
        Case::sequence(
            "sequence.icb.cpu_dispatch_inherited",
            library,
            vec![
                Step::compute("icb_scale", grid(slice * 4), [slice, 1, 1])
                    .bind(&[("data", 0)])
                    .set("supports_icb", true)
                    .set("execute_icb", json!({"icb": "icb", "count": 1})),
            ],
        )
        .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
        .set("icbs", json!([{"name": "icb", "type": "dispatch", "count": 1, "inherit_pipeline": true,
                              "inherit_buffers": true, "commands": [{"threadgroups": [4], "threadgroup": [slice]}]}]))
        .output(exact("data", Dtype::U32, u32s(&scaled(&v)))),
    );
    // A kernel encodes one dispatch per slice; the next encoder runs them
    // with its own pipeline.
    plan.add(
        Case::sequence(
            "sequence.icb.gpu_dispatch",
            library,
            vec![
                Step::compute("encode_dispatches", grid(4), [4, 1, 1]).bind(&[("commands", 0), ("data", 1)]),
                Step::compute("icb_scale", grid(slice), [slice, 1, 1])
                    .set("supports_icb", true)
                    .set("use", json!(["data"]))
                    .set("execute_icb", json!({"icb": "icb", "count": 4})),
            ],
        )
        .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
        .buffer(Buffer::zeroed("commands", 0, 8).unbound())
        .set("icbs", json!([{"name": "icb", "type": "dispatch", "count": 4, "inherit_pipeline": true, "max_buffers": 1}]))
        .set("arguments", json!([{"buffer": "commands", "entries": [{"kind": "icb", "offset": 0, "resource": "icb"}]}]))
        .output(exact("data", Dtype::U32, u32s(&scaled(&v)))),
    );
    // Two rectangles drawn from commands: the left half, then the top
    // right quarter, each in its own colour over a cleared target.
    let (w, h) = (8u32, 8u32);
    let rects = [[-1.0, -1.0, 0.0, 1.0], [0.0, 0.0, 1.0, 1.0]];
    let colors = [[0.25, 0.5, 0.75, 1.0], [1.0, 0.0, 0.5, 0.25]];
    let image: Vec<f64> = (0..h)
        .flat_map(|y| (0..w).map(move |x| (x, y)))
        .flat_map(|(x, y)| {
            if x < w / 2 {
                colors[0]
            } else if y < h / 2 {
                colors[1]
            } else {
                [0.0; 4]
            }
        })
        .collect();
    let target = |execute: serde_json::Value| json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "supports_icb": true, "execute_icb": execute});
    let draws: Vec<serde_json::Value> = (0..2)
        .map(|k| {
            json!({"primitive": "triangle_strip", "vertex_count": 4, "buffers": [
                {"name": format!("rect{k}"), "stage": "vertex", "index": 0},
                {"name": format!("color{k}"), "stage": "fragment", "index": 0}]})
        })
        .collect();
    let mut cpu = Case::sequence(
        "sequence.icb.cpu_draw",
        library,
        vec![Step::render(
            "vert_rect",
            "frag_constant",
            target(json!({"icb": "icb", "count": 2})),
        )],
    )
    .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render"]))
    .set(
        "icbs",
        json!([{"name": "icb", "type": "draw", "count": 2, "max_buffers": 1, "commands": draws}]),
    )
    .output(exact("a", Dtype::F32, f32s(&image)));
    for k in 0..2 {
        cpu = cpu
            .buffer(Buffer::data(&format!("rect{k}"), 0, f32s(&rects[k])).unbound())
            .buffer(Buffer::data(&format!("color{k}"), 0, f32s(&colors[k])).unbound());
    }
    plan.add(cpu);
    plan.add(
        Case::sequence(
            "sequence.icb.gpu_draw",
            library,
            vec![
                Step::compute("encode_draws", grid(2), [2, 1, 1]).bind(&[("commands", 0), ("rects", 1), ("colors", 2)]),
                Step::render("vert_rect", "frag_constant", target(json!({"icb": "icb", "count": 2})))
                    .set("use", json!(["rects", "colors"])),
            ],
        )
        .buffer(Buffer::data("rects", 0, f32s(&rects.concat())).unbound())
        .buffer(Buffer::data("colors", 0, f32s(&colors.concat())).unbound())
        .buffer(Buffer::zeroed("commands", 0, 8).unbound())
        .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render"]))
        .set("icbs", json!([{"name": "icb", "type": "draw", "count": 2, "max_buffers": 1}]))
        .set("arguments", json!([{"buffer": "commands", "entries": [{"kind": "icb", "offset": 0, "resource": "icb"}]}]))
        .output(exact("a", Dtype::F32, f32s(&image))),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("sequences", SOURCE, &[], super::plan::LATEST);
    let mut rng = Random::new(5150);
    compute(plan, &library, &mut rng);
    indirect(plan, &library);
    passes(plan, &library);
    indirect_commands(plan, &library, &mut rng);
}
