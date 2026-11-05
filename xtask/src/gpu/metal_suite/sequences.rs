//! corpus/sequences.metal: work that reads what earlier work in the same
//! command buffer or queue wrote, each result asserted exactly. Every
//! dependency here is one Metal orders: dispatches of one encoder (serial
//! dispatch), encoders of one command buffer and command buffers of one
//! queue for tracked resources, fences between encoders and events between
//! command buffers for untracked ones.
use super::plan::{Buffer, Case, Output, Plan, Step, Texture};
use super::values::{Dtype, Random, f32s, u32s};
use serde_json::json;

const SOURCE: &str = "sequences.metal";
const N: u32 = 256;

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
                .output(Output::exact("out", Dtype::U32, u32s(&out)))
                .output(Output::exact("again", Dtype::U32, u32s(&again))),
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
        .output(Output::exact("copy", Dtype::U32, u32s(&scaled(&filled)))),
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
        .output(Output::exact("count", Dtype::U32, u32s(&[threads as u32])).set("length", 4))
        .output(Output::exact("seen", Dtype::U32, u32s(&seen))),
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
        .output(Output::exact("c", Dtype::F32, f32s(&color.repeat(64)))),
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
        .output(Output::exact("out", Dtype::F32, f32s(&coordinates))),
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
        .output(Output::exact("a", Dtype::F32, f32s(&first)))
        .output(Output::exact("b", Dtype::F32, f32s(&inverted))),
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
        .output(Output::exact("b", Dtype::F32, f32s(&halves))),
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
        .output(Output::exact("out", Dtype::F32, f32s(&samples)))
        .output(Output::exact("count", Dtype::U32, u32s(&[4])).set("length", 4)),
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
    // The whole buffer again with its range read from a buffer, then a
    // fifth command summing the untouched slice through threadgroup memory
    // it sizes, its barrier set and cleared.
    let mut fifth = commands.clone();
    fifth.as_array_mut().unwrap().push(json!(
        {"function": "icb_group_sum", "buffers": [uses("data", 0, slice * 12), uses("sum", 1, 0)],
         "threadgroups": [1], "threadgroup": [slice], "threadgroup_memory": [{"index": 0, "length": slice * 4}],
         "barrier": true, "clear_barrier": true}));
    let untouched = part(3).iter().fold(0u32, |a, &x| a.wrapping_add(x));
    // Commands reset after encoding: command 1 by the command itself and
    // commands 2 and 3 by a range reset, so only k = 1 reaches slice 0.
    let mut reset = commands.clone();
    reset[1]["reset"] = true.into();
    let only_first: Vec<u32> = [
        part(0).iter().map(|&x| step(x, 1)).collect::<Vec<_>>(),
        part(1),
        part(2),
        part(3),
    ]
    .concat();
    plan.add(
        Case::sequence(
            "sequence.icb.cpu_dispatch_reset",
            library,
            vec![
                Step::compute("icb_scale", grid(slice), [slice, 1, 1])
                    .set("supports_icb", true)
                    .set("execute_icb", json!({"icb": "icb", "count": 4})),
            ],
        )
        .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
        .buffer(Buffer::data("k1", 0, u32s(&[1])).unbound())
        .buffer(Buffer::data("k2", 0, u32s(&[2])).unbound())
        .buffer(Buffer::data("k5", 0, u32s(&[5])).unbound())
        .set(
            "icbs",
            json!([{"name": "icb", "type": "dispatch", "count": 4, "max_buffers": 2,
                              "commands": reset, "reset_range": [2, 2]}]),
        )
        .output(Output::exact("data", Dtype::U32, u32s(&only_first))),
    );
    plan.add(
        Case::sequence(
            "sequence.icb.cpu_dispatch_range_buffer",
            library,
            vec![
                Step::compute("icb_scale", grid(slice), [slice, 1, 1])
                    .set("supports_icb", true)
                    .set(
                        "execute_icb",
                        json!({"icb": "icb", "range_buffer": "range"}),
                    ),
            ],
        )
        .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
        .buffer(Buffer::data("k1", 0, u32s(&[1])).unbound())
        .buffer(Buffer::data("k2", 0, u32s(&[2])).unbound())
        .buffer(Buffer::data("k5", 0, u32s(&[5])).unbound())
        .buffer(Buffer::zeroed("sum", 0, 4).unbound())
        .buffer(Buffer::data("range", 0, u32s(&[0, 5])).unbound())
        .set(
            "icbs",
            json!([{"name": "icb", "type": "dispatch", "count": 5, "max_buffers": 2,
                              "max_threadgroup_memory": 1, "commands": fifth}]),
        )
        .output(Output::exact("data", Dtype::U32, u32s(&whole)))
        .output(Output::exact("sum", Dtype::U32, u32s(&[untouched])).set("length", 4)),
    );
    // Slice 2's command as a grid of threads short of its group, so its
    // last eight words keep their values.
    let mut threads = commands.clone();
    threads[3]["threads_per_grid"] = json!([slice - 8]);
    let short: Vec<u32> = whole
        .iter()
        .zip(&v)
        .enumerate()
        .map(|(i, (&w, &x))| {
            if i as u32 >= slice * 3 - 8 && (i as u32) < slice * 3 {
                x
            } else {
                w
            }
        })
        .collect();
    plan.add(
        Case::sequence(
            "sequence.icb.cpu_dispatch_threads",
            library,
            vec![
                Step::compute("icb_scale", grid(slice), [slice, 1, 1])
                    .set("supports_icb", true)
                    .set("execute_icb", json!({"icb": "icb", "count": 4})),
            ],
        )
        .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
        .buffer(Buffer::data("k1", 0, u32s(&[1])).unbound())
        .buffer(Buffer::data("k2", 0, u32s(&[2])).unbound())
        .buffer(Buffer::data("k5", 0, u32s(&[5])).unbound())
        .set("icbs", json!([{"name": "icb", "type": "dispatch", "count": 4, "max_buffers": 2, "commands": threads}]))
        .output(Output::exact("data", Dtype::U32, u32s(&short))),
    );
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
            .output(Output::exact("data", Dtype::U32, u32s(expected))),
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
        .output(Output::exact("data", Dtype::U32, u32s(&scaled(&v)))),
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
        .output(Output::exact("data", Dtype::U32, u32s(&scaled(&v)))),
    );
    // Commands the kernel copies, resets and orders: slice 0 scaled twice,
    // the second time after a barrier; slice 1 once by a copy; slice 2's
    // command reset to nothing; slice 3 untouched.
    let once = |x: u32| x.wrapping_mul(3).wrapping_add(1);
    let edited: Vec<u32> = v
        .iter()
        .enumerate()
        .map(|(i, &x)| match i as u32 / slice {
            0 => once(once(x)),
            1 => once(x),
            _ => x,
        })
        .collect();
    plan.add(
        Case::sequence(
            "sequence.icb.gpu_dispatch_edits",
            library,
            vec![
                Step::compute("encode_dispatch_edits", grid(1), [1, 1, 1]).bind(&[("commands", 0), ("data", 1)]),
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
        .output(Output::exact("data", Dtype::U32, u32s(&edited))),
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
    .output(Output::exact("a", Dtype::F32, f32s(&image)));
    for k in 0..2 {
        cpu = cpu
            .buffer(Buffer::data(&format!("rect{k}"), 0, f32s(&rects[k])).unbound())
            .buffer(Buffer::data(&format!("color{k}"), 0, f32s(&colors[k])).unbound());
    }
    plan.add(cpu);
    icb_draw_state(plan, library);
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
        .output(Output::exact("a", Dtype::F32, f32s(&image))),
    );
}

/// Draw commands setting their own fixed-function state over an 8x8
/// target cleared to depth 1, each in one quadrant (strips wind counter
/// clockwise): a back face culled; a back face drawn once the command
/// makes counter-clockwise the front; a rectangle at z 1.5 kept by depth
/// clamping; and a rectangle at z 0.5 drawn twice, the second passing a
/// "less" test only through its depth bias. The last two orders through
/// a barrier.
fn icb_draw_state(plan: &mut Plan, library: &str) {
    let size = 8u32;
    let colors = [
        [1.0, 0.0, 0.0, 1.0],
        [0.0, 1.0, 0.0, 1.0],
        [0.0, 0.0, 1.0, 1.0],
        [1.0, 1.0, 0.0, 1.0],
        [0.0, 1.0, 1.0, 1.0],
    ];
    let rects = [
        [-1.0, 0.0, 0.0, 1.0],
        [0.0, 0.0, 1.0, 1.0],
        [-1.0, -1.0, 0.0, 0.0],
        [0.0, -1.0, 1.0, 0.0],
        [0.0, -1.0, 1.0, 0.0],
    ];
    let depths = [0.5, 0.5, 1.5, 0.5, 0.5];
    let states = [
        json!({"cull": "back"}),
        json!({"cull": "back", "winding": "counter_clockwise"}),
        json!({"depth_clip": "clamp", "depth_write": true}),
        json!({"depth_compare": "less_equal", "depth_write": true}),
        json!({"depth_compare": "less", "depth_bias": [-1000.0, 0.0, 0.0]}),
    ];
    let mut commands: Vec<serde_json::Value> = (0..5)
        .map(|k| {
            json!({"primitive": "triangle_strip", "vertex_count": 4, "state": states[k], "barrier": k == 4, "clear_barrier": k == 2,
                   "buffers": [{"name": format!("rect{k}"), "stage": "vertex", "index": 0},
                               {"name": format!("z{k}"), "stage": "vertex", "index": 1},
                               {"name": format!("color{k}"), "stage": "fragment", "index": 0}]})
        })
        .collect();
    // A sixth command over the whole target, reset after encoding.
    let mut sixth = commands[0].clone();
    sixth["state"] = json!({"cull": "none"});
    sixth["buffers"][0]["name"] = "whole".into();
    sixth["reset"] = true.into();
    commands.push(sixth);
    let image: Vec<f64> = (0..size)
        .flat_map(|y| (0..size).map(move |x| (x, y)))
        .flat_map(|(x, y)| match (x < size / 2, y < size / 2) {
            (true, true) => [0.0; 4],
            (false, true) => colors[1],
            (true, false) => colors[2],
            (false, false) => colors[4],
        })
        .collect();
    let mut case = Case::sequence(
        "sequence.icb.cpu_draw_state",
        library,
        vec![Step::render(
            "vert_rect_z",
            "frag_constant",
            json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "depth": {"texture": "d", "clear": 1.0},
                   "supports_icb": true, "execute_icb": {"icb": "icb", "count": 6}}),
        )],
    )
    .requires(&["apple10"], &[])
    .texture(Texture::d2("a", "rgba32float", size, size).usage(&["render"]))
    .texture(Texture::d2("d", "depth32float", size, size).usage(&["render"]))
    .set("icbs", json!([{"name": "icb", "type": "draw", "count": 6, "max_buffers": 2, "inherit_state": false,
                          "commands": commands}]))
    .buffer(Buffer::data("whole", 0, f32s(&[-1.0, -1.0, 1.0, 1.0])).unbound())
    .output(Output::exact("a", Dtype::F32, f32s(&image)));
    for k in 0..5 {
        case = case
            .buffer(Buffer::data(&format!("rect{k}"), 0, f32s(&rects[k])).unbound())
            .buffer(Buffer::data(&format!("z{k}"), 0, f32s(&[depths[k]])).unbound())
            .buffer(Buffer::data(&format!("color{k}"), 0, f32s(&colors[k])).unbound());
    }
    plan.add(case);
    // The same six commands encoded by a kernel, which takes the
    // depth-stencil states from its argument buffer.
    let depth = |offset: u32, compare: &str, write: bool| json!({"kind": "depth_stencil", "offset": offset, "compare": compare, "write": write});
    let mut all_rects = rects.concat();
    all_rects.extend([-1.0, -1.0, 1.0, 1.0]);
    let mut all_colors = colors.concat();
    all_colors.extend(colors[0]);
    plan.add(
        Case::sequence(
            "sequence.icb.gpu_draw_state",
            library,
            vec![
                Step::compute("encode_draw_state", grid(6), [6, 1, 1])
                    .bind(&[("commands", 0), ("rects", 1), ("depths", 2), ("colors", 3)]),
                Step::render(
                    "vert_rect_z",
                    "frag_constant",
                    json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "depth": {"texture": "d", "clear": 1.0},
                           "supports_icb": true, "execute_icb": {"icb": "icb", "count": 6}}),
                )
                .set("use", json!(["rects", "depths", "colors"])),
            ],
        )
        .requires(&["apple10"], &[])
        .texture(Texture::d2("a", "rgba32float", size, size).usage(&["render"]))
        .texture(Texture::d2("d", "depth32float", size, size).usage(&["render"]))
        .buffer(Buffer::data("rects", 0, f32s(&all_rects)).unbound())
        .buffer(Buffer::data("depths", 0, f32s(&[depths.as_slice(), &[0.5]].concat())).unbound())
        .buffer(Buffer::data("colors", 0, f32s(&all_colors)).unbound())
        .buffer(Buffer::zeroed("commands", 0, 48).unbound())
        .set("icbs", json!([{"name": "icb", "type": "draw", "count": 6, "max_buffers": 2, "inherit_state": false}]))
        .set("arguments", json!([{"buffer": "commands", "entries": [
            {"kind": "icb", "offset": 0, "resource": "icb"},
            depth(8, "always", false), depth(16, "always", true),
            depth(24, "less_equal", true), depth(32, "less", false)]}]))
        .output(Output::exact("a", Dtype::F32, f32s(&image))),
    );
    // Draws fetching corners through a layout of dynamic stride, each
    // command its own stride: 8 for the left half, 16 for the right.
    let mut corners = f32s(&[-1.0, -1.0, 0.0, -1.0, -1.0, 1.0, 0.0, 1.0]);
    for [x, y] in [[0.0, -1.0], [1.0, -1.0], [0.0, 1.0], [1.0, 1.0]] {
        corners.extend(f32s(&[x, y, 0.0, 0.0]));
    }
    let strided: Vec<serde_json::Value> = [(0u32, 8u32), (32, 16)]
        .iter()
        .enumerate()
        .map(|(k, &(offset, stride))| {
            json!({"primitive": "triangle_strip", "vertex_count": 4, "buffers": [
                {"name": "corners", "stage": "vertex", "index": 1, "offset": offset, "attribute_stride": stride},
                {"name": format!("color{k}"), "stage": "fragment", "index": 0}]})
        })
        .collect();
    let halves: Vec<f64> = (0..size * size)
        .flat_map(|i| {
            if i % size < size / 2 {
                colors[0]
            } else {
                colors[1]
            }
        })
        .collect();
    plan.add(
        Case::sequence(
            "sequence.icb.cpu_draw_dynamic_stride",
            library,
            vec![Step::render(
                "vert_corner_attribute",
                "frag_constant",
                json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "supports_icb": true,
                       "vertex_descriptor": {"attributes": [{"index": 0, "format": "float2", "offset": 0, "buffer": 1}],
                                             "layouts": [{"buffer": 1, "stride": "dynamic"}]},
                       "execute_icb": {"icb": "icb", "count": 2}}),
            )],
        )
        .texture(Texture::d2("a", "rgba32float", size, size).usage(&["render"]))
        .buffer(Buffer::data("corners", 0, corners.clone()).unbound())
        .buffer(Buffer::data("color0", 0, f32s(&colors[0])).unbound())
        .buffer(Buffer::data("color1", 0, f32s(&colors[1])).unbound())
        .set("icbs", json!([{"name": "icb", "type": "draw", "count": 2, "max_buffers": 2, "dynamic_stride": true,
                              "commands": strided}]))
        .output(Output::exact("a", Dtype::F32, f32s(&halves))),
    );
    // The same strides given by commands a kernel encodes.
    let layout = json!({"attributes": [{"index": 0, "format": "float2", "offset": 0, "buffer": 1}],
                        "layouts": [{"buffer": 1, "stride": "dynamic"}]});
    plan.add(
        Case::sequence(
            "sequence.icb.gpu_draw_dynamic_stride",
            library,
            vec![
                Step::compute("encode_strided_draws", grid(2), [2, 1, 1])
                    .bind(&[("commands", 0), ("corners", 1), ("colors", 2)]),
                Step::render(
                    "vert_corner_attribute",
                    "frag_constant",
                    json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "supports_icb": true,
                           "vertex_descriptor": layout, "execute_icb": {"icb": "icb", "count": 2}}),
                )
                .set("use", json!(["corners", "colors"])),
            ],
        )
        .texture(Texture::d2("a", "rgba32float", size, size).usage(&["render"]))
        .buffer(Buffer::data("corners", 0, corners).unbound())
        .buffer(Buffer::data("colors", 0, f32s(&[colors[0], colors[1]].concat())).unbound())
        .buffer(Buffer::zeroed("commands", 0, 8).unbound())
        .set("icbs", json!([{"name": "icb", "type": "draw", "count": 2, "max_buffers": 2, "dynamic_stride": true}]))
        .set("arguments", json!([{"buffer": "commands", "entries": [{"kind": "icb", "offset": 0, "resource": "icb"}]}]))
        .output(Output::exact("a", Dtype::F32, f32s(&halves))),
    );
}

/// More indirect command buffers: a kernel encoding commands with their
/// own pipelines, a dispatch of threads, threadgroup memory and a barrier;
/// indexed draws from the CPU and from a kernel that sets the pipeline;
/// and commands copied, reset and optimized by blits before running.
fn indirect_commands_more(plan: &mut Plan, library: &str, rng: &mut Random) {
    let slice = 64u32;
    let v: Vec<u32> = (0..slice * 4).map(|_| rng.u32() >> 4).collect();
    let mut data = v.clone();
    for x in &mut data[..100] {
        *x = x.wrapping_mul(3).wrapping_add(1);
    }
    let sums: Vec<u32> = data
        .chunks(64)
        .map(|c| c.iter().fold(0u32, |a, &x| a.wrapping_add(x)))
        .collect();
    plan.add(
        Case::sequence(
            "sequence.icb.gpu_full_dispatches",
            library,
            vec![
                Step::compute("encode_full_dispatches", grid(1), [1, 1, 1])
                    .bind(&[("commands", 0), ("data", 1), ("sums", 2)]),
                Step::compute("icb_scale", grid(slice), [slice, 1, 1])
                    .set("supports_icb", true)
                    .set("use", json!(["data", "sums"]))
                    .set("execute_icb", json!({"icb": "icb", "count": 2})),
            ],
        )
        .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
        .buffer(Buffer::zeroed("sums", 0, 16).unbound())
        .buffer(Buffer::zeroed("commands", 0, 24).unbound())
        .set("icbs", json!([{"name": "icb", "type": "dispatch", "count": 2, "inherit_pipeline": false, "max_buffers": 2}]))
        .set("arguments", json!([{"buffer": "commands", "entries": [
            {"kind": "icb", "offset": 0, "resource": "icb"},
            {"kind": "compute_pipeline", "offset": 8, "function": "icb_scale"},
            {"kind": "compute_pipeline", "offset": 16, "function": "icb_block_sum"}]}]))
        .output(Output::exact("data", Dtype::U32, u32s(&data)))
        .output(Output::exact("sums", Dtype::U32, u32s(&sums))),
    );
    // Indexed rectangles: corners 0..3 as two triangles.
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
    let indices: Vec<u8> = [0u16, 1, 2, 2, 1, 3]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();
    let target = |execute: serde_json::Value| json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0]}], "supports_icb": true, "execute_icb": execute});
    let draws: Vec<serde_json::Value> = (0..2)
        .map(|k| {
            json!({"primitive": "triangle", "indices": "indices", "index_count": 6, "buffers": [
                {"name": format!("rect{k}"), "stage": "vertex", "index": 0},
                {"name": format!("color{k}"), "stage": "fragment", "index": 0}]})
        })
        .collect();
    let mut cpu = Case::sequence(
        "sequence.icb.cpu_indexed_draw",
        library,
        vec![Step::render(
            "vert_rect",
            "frag_constant",
            target(json!({"icb": "icb", "count": 2})),
        )],
    )
    .buffer(Buffer::data("indices", 0, indices.clone()).unbound())
    .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render"]))
    .set(
        "icbs",
        json!([{"name": "icb", "type": "draw", "count": 2, "max_buffers": 1, "commands": draws}]),
    )
    .output(Output::exact("a", Dtype::F32, f32s(&image)));
    for k in 0..2 {
        cpu = cpu
            .buffer(Buffer::data(&format!("rect{k}"), 0, f32s(&rects[k])).unbound())
            .buffer(Buffer::data(&format!("color{k}"), 0, f32s(&colors[k])).unbound());
    }
    plan.add(cpu);
    plan.add(
        Case::sequence(
            "sequence.icb.gpu_indexed_draw",
            library,
            vec![
                Step::compute("encode_indexed_draws", grid(2), [2, 1, 1])
                    .bind(&[("commands", 0), ("rects", 1), ("colors", 2), ("indices", 3)]),
                Step::render("vert_rect", "frag_constant", target(json!({"icb": "icb", "count": 2})))
                    .set("use", json!(["rects", "colors", "indices"])),
            ],
        )
        .buffer(Buffer::data("rects", 0, f32s(&rects.concat())).unbound())
        .buffer(Buffer::data("colors", 0, f32s(&colors.concat())).unbound())
        .buffer(Buffer::data("indices", 0, indices).unbound())
        .buffer(Buffer::zeroed("commands", 0, 16).unbound())
        .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render"]))
        .set("icbs", json!([{"name": "icb", "type": "draw", "count": 2, "inherit_pipeline": false, "max_buffers": 1}]))
        .set("arguments", json!([{"buffer": "commands", "entries": [
            {"kind": "icb", "offset": 0, "resource": "icb"},
            {"kind": "render_pipeline", "offset": 8, "vertex": "vert_rect", "fragment": "frag_constant", "format": "rgba32float"}]}]))
        .output(Output::exact("a", Dtype::F32, f32s(&image))),
    );
    // CPU commands copied into another buffer, the second reset to a no-op,
    // then optimized and run.
    let step = |x: u32, k: u32| x.wrapping_mul(2).wrapping_add(k);
    let part = |s: u32| v[(s * slice) as usize..((s + 1) * slice) as usize].to_vec();
    let uses = |name: &str, index: u32, offset: u32| json!({"name": name, "index": index, "offset": offset});
    let commands = json!([
        {"function": "icb_step", "buffers": [uses("data", 0, 0), uses("k1", 1, 0)], "threadgroups": [1], "threadgroup": [slice]},
        {"function": "icb_step", "buffers": [uses("data", 0, 0), uses("k2", 1, 0)], "threadgroups": [1], "threadgroup": [slice], "barrier": true},
        {"function": "icb_scale", "buffers": [uses("data", 0, slice * 4)], "threadgroups": [1], "threadgroup": [slice]},
    ]);
    let expected = |first: &dyn Fn(u32) -> u32| -> Vec<u32> {
        [
            part(0).into_iter().map(first).collect::<Vec<_>>(),
            scaled(&part(1)),
            part(2),
            part(3),
        ]
        .concat()
    };
    let (all, without_second) = (
        expected(&|x| step(step(x, 1), 2)),
        expected(&|x| step(x, 1)),
    );
    let copy = json!({"op": "copy_icb", "src": "source", "dst": "icb", "start": 0, "count": 3});
    let reset = |icb: &str| json!({"op": "reset_icb", "icb": icb, "start": 1, "count": 1});
    let optimize = |icb: &str| json!({"op": "optimize_icb", "icb": icb, "start": 0, "count": 3});
    for (name, ops, icb, expected) in [
        ("copy", json!([copy]), "icb", &all),
        (
            "copy_reset",
            json!([copy, reset("icb")]),
            "icb",
            &without_second,
        ),
        (
            "copy_reset_optimize",
            json!([copy, reset("icb"), optimize("icb")]),
            "icb",
            &without_second,
        ),
        (
            "reset_optimize",
            json!([reset("source"), optimize("source")]),
            "source",
            &without_second,
        ),
    ] {
        plan.add(
            Case::sequence(
                &format!("sequence.icb.{name}"),
                library,
                vec![
                    Step::blit(ops),
                    Step::compute("icb_scale", grid(slice), [slice, 1, 1])
                        .set("supports_icb", true)
                        .set("execute_icb", json!({"icb": icb, "count": 3})),
                ],
            )
            .buffer(Buffer::data("data", 0, u32s(&v)).unbound())
            .buffer(Buffer::data("k1", 0, u32s(&[1])).unbound())
            .buffer(Buffer::data("k2", 0, u32s(&[2])).unbound())
            .set("icbs", json!([{"name": "source", "type": "dispatch", "count": 3, "max_buffers": 2, "commands": commands},
                                {"name": "icb", "type": "dispatch", "count": 3, "max_buffers": 2}]))
            .output(Output::exact("data", Dtype::U32, u32s(expected))),
        );
    }
}

/// Ordering that the API, not a resource, defines: a parallel render
/// encoder's sub-encoders, recorded in reverse, blend in the order they
/// were created; a command buffer waits for a value the host signals on a
/// shared event; and a multisampled pass stores only its resolve.
fn api_ordering(plan: &mut Plan, library: &str, rng: &mut Random) {
    let (w, h) = (8u32, 8u32);
    let over =
        json!({"rgb": "add", "src_rgb": "source_alpha", "dst_rgb": "one_minus_source_alpha"});
    let part = |color: &str| {
        json!({"buffers": [{"name": "full", "stage": "vertex", "index": 0},
                                               {"name": color, "stage": "fragment", "index": 0}]})
    };
    // A then B over a cleared target: B * 0.5 + A * 0.5 * 0.5.
    let blended: Vec<f64> = (0..w * h).flat_map(|_| [0.25, 0.0, 0.5, 0.5]).collect();
    plan.add(
        Case::sequence(
            "sequence.parallel_render_order",
            library,
            vec![Step::render(
                "vert_rect",
                "frag_constant",
                json!({"colors": [{"texture": "a", "clear": [0, 0, 0, 0], "blend": over}],
                       "primitive": "triangle_strip", "vertex_count": 4,
                       "parallel": [part("first"), part("second")]}),
            )],
        )
        .buffer(Buffer::data("full", 0, f32s(&[-1.0, -1.0, 1.0, 1.0])).unbound())
        .buffer(Buffer::data("first", 0, f32s(&[1.0, 0.0, 0.0, 0.5])).unbound())
        .buffer(Buffer::data("second", 0, f32s(&[0.0, 0.0, 1.0, 0.5])).unbound())
        .texture(Texture::d2("a", "rgba32float", w, h).usage(&["render"]))
        .output(Output::exact("a", Dtype::F32, f32s(&blended))),
    );
    let v: Vec<u32> = (0..N).map(|_| rng.u32()).collect();
    plan.add(
        Case::sequence(
            "sequence.event.host_signal",
            library,
            vec![
                Step::compute("scale", grid(N), [64, 1, 1]).bind(&[("in", 0), ("mid", 1)]),
                Step::compute("neighbours", grid(N), [64, 1, 1])
                    .bind(&[("mid", 0), ("out", 1), ("n", 2)])
                    .new_command_buffer()
                    .wait_events(&[("host", 1)]),
            ],
        )
        .buffer(Buffer::data("in", 0, u32s(&v)).unbound())
        .buffer(Buffer::zeroed("mid", 0, N as usize * 4).unbound())
        .buffer(Buffer::zeroed("out", 0, N as usize * 4).unbound())
        .buffer(Buffer::data("n", 0, u32s(&[N])).unbound())
        .set("host_signals", json!([["host", 1]]))
        .output(Output::exact(
            "out",
            Dtype::U32,
            u32s(&neighbours(&scaled(&v))),
        )),
    );
    let color = [0.25, 0.75, 0.5, 1.0];
    plan.add(
        Case::sequence(
            "sequence.msaa_resolve_only",
            library,
            vec![Step::render(
                "vert_rect",
                "frag_constant",
                json!({"colors": [{"texture": "ms", "clear": [0, 0, 0, 0], "resolve": "c", "store": "resolve"}],
                       "samples": 4, "primitive": "triangle_strip", "vertex_count": 4}),
            )
            .bind_stage("vertex", &[("full", 0)])
            .bind_stage("fragment", &[("color", 0)])],
        )
        .buffer(Buffer::data("full", 0, f32s(&[-1.0, -1.0, 1.0, 1.0])).unbound())
        .buffer(Buffer::data("color", 0, f32s(&color)).unbound())
        .texture(Texture::new("ms", "rgba16float", "2d_ms", [w, h, 1]).samples(4).usage(&["render"]))
        .texture(Texture::d2("c", "rgba16float", w, h).usage(&["render"]))
        .output(Output::exact("c", Dtype::F16, super::values::floats(Dtype::F16, &color.repeat((w * h) as usize)))),
    );
}

/// Ordering across queues and command buffers: a second queue's work an
/// event orders before the first's, a listener the host registers for a
/// value the GPU signals, command buffers that retain nothing, a
/// concurrent encoder whose barrier orders two dispatches, and completion
/// handlers that run in commit order after scheduling.
fn queues_and_handlers(plan: &mut Plan, library: &str, rng: &mut Random) {
    let v: Vec<u32> = (0..N).map(|_| rng.u32()).collect();
    let expect = u32s(&neighbours(&scaled(&v)));
    let base = |name: &str, steps: Vec<Step>| {
        Case::sequence(name, library, steps)
            .buffer(Buffer::data("in", 0, u32s(&v)).unbound())
            .buffer(Buffer::zeroed("mid", 0, N as usize * 4).unbound())
            .buffer(Buffer::zeroed("out", 0, N as usize * 4).unbound())
            .buffer(Buffer::data("n", 0, u32s(&[N])).unbound())
            .output(Output::exact("out", Dtype::U32, expect.clone()))
    };
    let scale = || Step::compute("scale", grid(N), [64, 1, 1]).bind(&[("in", 0), ("mid", 1)]);
    let neighbour = || {
        Step::compute("neighbours", grid(N), [64, 1, 1]).bind(&[("mid", 0), ("out", 1), ("n", 2)])
    };
    plan.add(base(
        "sequence.queues.event",
        vec![
            scale().set("queue", 1).signal_events(&[("e", 1)]),
            neighbour().wait_events(&[("e", 1)]),
        ],
    ));
    plan.add(
        base(
            "sequence.event.listener",
            vec![
                scale().signal_events(&[("e", 5)]),
                neighbour().new_command_buffer(),
            ],
        )
        .set("listen", json!([["e", 5, "heard"]]))
        .buffer(Buffer::zeroed("heard", 0, 16).unbound())
        .output(Output::exact("heard", Dtype::U32, u32s(&[1, 5, 0, 0]))),
    );
    // Listeners on a queue of their own and the framework's shared one.
    for listener in ["own", "shared"] {
        plan.vary("sequence.event.listener", listener, |case| {
            case.set("listener", listener)
        });
    }
    plan.add(base("sequence.unretained", vec![scale(), neighbour()]).set("unretained", true));
    plan.add(base(
        "sequence.compute.concurrent_barrier",
        vec![
            scale().set("concurrent", true),
            neighbour().continues().set("barrier", "buffers"),
        ],
    ));
    plan.add(
        base(
            "sequence.handlers",
            vec![scale(), neighbour().new_command_buffer()],
        )
        .set("handlers", "order")
        .buffer(Buffer::zeroed("order", 0, 40).unbound())
        // Buffers 0 and 1 complete in order, each after its scheduling,
        // the last with MTLCommandBufferStatusCompleted (4).
        .output(Output::exact(
            "order",
            Dtype::U32,
            u32s(&[0, 1, 0, 0, 0, 0, 0, 0, 1, 4]),
        )),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("sequences", SOURCE, &[], super::plan::LATEST);
    let mut rng = Random::new(5150);
    compute(plan, &library, &mut rng);
    indirect(plan, &library);
    passes(plan, &library);
    indirect_commands(plan, &library, &mut rng);
    indirect_commands_more(plan, &library, &mut rng);
    api_ordering(plan, &library, &mut rng);
    queues_and_handlers(plan, &library, &mut rng);
    // The same waits on events only the GPU signals.
    for name in ["sequence.compute.event", "sequence.queues.event"] {
        plan.vary(name, "device", |case| {
            case.set("device_events", json!(["e"]))
        });
    }
}
