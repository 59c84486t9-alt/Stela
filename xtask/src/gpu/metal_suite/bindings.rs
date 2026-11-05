//! Every stage's binding slots, bound each way the encoders offer: one
//! call per slot, one call over each run of consecutive slots, buffers
//! bound at offset 0 and then moved to their offsets, and the deprecated
//! residency calls that name no stages. Each way reads back the same
//! words, so the cases share their expectations.
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::values::{Dtype, u32s};
use serde_json::{Value, json};

const SOURCE: &str = "bindings.metal";

/// The ways the runner binds a case's resources (its `bind`).
const MODES: [&str; 4] = ["single", "ranges", "offsets", "legacy"];

/// Each stage's number, which sets the values its slots hold.
const STAGES: [(&str, u32); 5] = [
    ("compute", 0),
    ("vertex", 1),
    ("fragment", 2),
    ("object", 3),
    ("mesh", 4),
];

/// Bytes before each input buffer's word: the binding's offset.
const OFFSET: usize = 16;

/// Texture `k`'s red value at `level`, unique across stages.
fn texel(stage: u32, k: u32, level: u32) -> u32 {
    16 * stage + 4 * k + level + 1
}

/// The words a stage writes: its three buffers' words, the inline word,
/// each texture at level 0, texture 0 at the binding's clamped level 1,
/// texture 1 at the state's clamped level 2, and the argument buffer's
/// heap word and resident word.
fn expected(stage: u32) -> Vec<u32> {
    let b = 100 * stage;
    vec![
        b + 1,
        b + 2,
        b + 3,
        b + 4,
        texel(stage, 0, 0),
        texel(stage, 1, 0),
        texel(stage, 3, 0),
        texel(stage, 0, 1),
        texel(stage, 1, 2),
        4242,
        b + 7,
        0,
    ]
}

/// One stage's slots: `out` at 0; words at 1, 2 and 4 behind an offset;
/// an inline word at 3; an argument buffer at 6; textures at 0, 1 and 3;
/// samplers at 0, 1 (clamped to level 1 by the binding) and 3 (clamped
/// to level 2 by its state). Bound by ranges, the pipeline also declares
/// the inputs immutable and `out` mutable.
fn slots(case: Case, name: &str, stage: u32, compute: bool, mode: &str) -> Case {
    let bound = |b: Buffer, mutability: &str| {
        let b = if compute { b } else { b.stage(name) };
        if mode == "ranges" {
            b.set("mutability", mutability)
        } else {
            b
        }
    };
    let at = |b: Buffer| bound(b, "immutable");
    let word = |v: u32| {
        let mut data = vec![0xEEu8; OFFSET];
        data.extend(u32s(&[v, 0, 0, 0]));
        data
    };
    let base = 100 * stage;
    let mut case = case
        .buffer(bound(
            Buffer::zeroed(&format!("out_{name}"), 0, 48),
            "mutable",
        ))
        .buffer(at(
            Buffer::data(&format!("b1_{name}"), 1, word(base + 1)).set("offset", OFFSET)
        ))
        .buffer(at(
            Buffer::data(&format!("b2_{name}"), 2, word(base + 2)).set("offset", OFFSET)
        ))
        .buffer(at(Buffer::data(
            &format!("word_{name}"),
            3,
            u32s(&[base + 3, 0, 0, 0]),
        )
        .set("inline", true)))
        .buffer(at(
            Buffer::data(&format!("b4_{name}"), 4, word(base + 4)).set("offset", OFFSET)
        ))
        .buffer(at(Buffer::zeroed(&format!("args_{name}"), 6, 16)))
        .buffer(Buffer::data(&format!("resident_{name}"), 0, u32s(&[base + 7, 0, 0, 0])).unbound());
    for k in [0, 1, 3] {
        // 4x4, 2x2 and 1x1 levels, each one value in red.
        let data: Vec<u8> = [16, 4, 1]
            .iter()
            .zip(0..)
            .flat_map(|(&n, level)| [texel(stage, k, level) as u8, 0, 0, 255].repeat(n))
            .collect();
        let mut texture = Texture::d2(&format!("t{k}_{name}"), "rgba8unorm", 4, 4)
            .mipmaps(3)
            .data(data)
            .index(k);
        if !compute {
            texture = texture.set("stage", name);
        }
        case = case.texture(texture);
    }
    for (k, extra) in [
        (0, json!({})),
        (1, json!({"bind_lod": [1.0, 1.0]})),
        (3, json!({"lod_min": 2.0, "lod_max": 2.0})),
    ] {
        let mut sampler = json!({"name": format!("s{k}_{name}"), "index": k, "min": "nearest",
                                 "mag": "nearest", "mip": "nearest", "lod_average": k == 0});
        if !compute {
            sampler["stage"] = name.into();
        }
        sampler
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        case = case.sampler(sampler);
    }
    case.output(
        Output::new(&format!("out_{name}"), Dtype::U32, Tolerance::exact())
            .expect_same(u32s(&expected(stage))),
    )
}

/// The heap word every stage's argument buffer reaches, and each stage's
/// argument buffer's entries.
fn arguments(case: Case, stages: &[&str]) -> Case {
    let fills: Vec<Value> = stages
        .iter()
        .map(|s| {
            json!({"buffer": format!("args_{s}"), "entries": [
                {"kind": "buffer", "offset": 0, "resource": "heaped"},
                {"kind": "buffer", "offset": 8, "resource": format!("resident_{s}")}]})
        })
        .collect();
    case.buffer(
        Buffer::data("heaped", 0, u32s(&[4242, 0, 0, 0]))
            .unbound()
            .set("heap", "h"),
    )
    .set(
        "heaps",
        json!([{"name": "h", "type": "automatic", "storage": "shared", "size": 1 << 16}]),
    )
    .set("use_heaps", json!(["h"]))
    .set("arguments", fills)
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("bindings", SOURCE, &[], super::plan::LATEST);
    let stage = |name: &str| STAGES.iter().find(|(s, _)| *s == name).unwrap().1;
    let target = || Texture::d2("target", "rgba8unorm", 1, 1).usage(&["render"]);
    let point = |extra: Value| {
        let mut state = json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}],
                               "primitive": "point", "vertex_count": 1});
        state
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        state
    };
    for mode in MODES {
        let compute = slots(
            Case::compute(
                &format!("bindings.compute.{mode}"),
                &library,
                "bound_compute",
                [1, 1, 1],
                [1, 1, 1],
            ),
            "compute",
            stage("compute"),
            true,
            mode,
        );
        plan.add(arguments(compute, &["compute"]).set("bind", mode));
        let mut render = Case::render(
            &format!("bindings.render.{mode}"),
            &library,
            "bound_vertex",
            Some("bound_fragment"),
            point(json!({})),
        )
        .texture(target());
        for s in ["vertex", "fragment"] {
            render = slots(render, s, stage(s), false, mode);
        }
        plan.add(arguments(render, &["vertex", "fragment"]).set("bind", mode));
        let mut mesh = Case::render(
            &format!("bindings.mesh.{mode}"),
            &library,
            "bound_mesh",
            Some("bound_fragment"),
            point(
                json!({"mesh": {"object": "bound_object", "mesh": "bound_mesh", "threadgroups": [1],
                                  "object_threads": [1], "mesh_threads": [1]}}),
            ),
        )
        .texture(target());
        for s in ["object", "mesh", "fragment"] {
            mesh = slots(mesh, s, stage(s), false, mode);
        }
        plan.add(arguments(mesh, &["object", "mesh", "fragment"]).set("bind", mode));
    }
}
