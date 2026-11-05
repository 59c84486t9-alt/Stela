//! corpus/stages.metal: programmable stages beyond vertex and fragment.
//!
//! Tessellation of quad patches with uniform factors, whose domain points
//! the specification fixes: a regular grid of `n` segments per side, `n`
//! being the factor clamped to the pipeline's maximum and rounded up to an
//! integer (integer partitioning) or a power of two (pow2). A patch with a
//! zero edge factor is culled. Each evaluated point is recorded by its grid
//! slot, and the tessellated quads are rasterized: control point values
//! linear in the patch's coordinates make the image exact whatever
//! triangles the tessellator chooses, fractional partitioning included.
//!
//! Mesh pipelines (mesh functions alone and behind an object function that
//! sizes the mesh grid and fills its payload) and vertex amplification
//! (views mapped to target layers and to viewports) draw rectangles whose
//! images are exact.
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::values::{Dtype, f16_bits, f32s, u32s};
use serde_json::json;

const SOURCE: &str = "stages.metal";
/// An image's tolerance: the tessellator's domain coordinates are fixed
/// point of a precision the specification leaves open (Apple's are within
/// 2e-4), far below a visible difference.
const IMAGE: f64 = 1.0 / 1024.0;
const SIZE: u32 = 8;

/// Two patches: the left and right halves of clip space, as corners
/// (x0, y0), (x1, y0), (x1, y1), (x0, y1), with a value at each corner.
const PATCHES: [([f64; 4], [f64; 4]); 2] = [
    ([-1.0, -1.0, 0.0, 1.0], [0.1, 0.5, 0.9, 0.5]),
    ([0.0, -1.0, 1.0, 1.0], [0.2, 0.3, 0.6, 0.5]),
];

fn control_points() -> Vec<f64> {
    PATCHES
        .iter()
        .flat_map(|([x0, y0, x1, y1], v)| {
            [[*x0, *y0], [*x1, *y0], [*x1, *y1], [*x0, *y1]]
                .into_iter()
                .zip(v)
                .flat_map(|(p, v)| [p[0], p[1], *v])
        })
        .collect()
}

/// The value the patch's corners give at (u, v).
fn value(v: &[f64; 4], u: f64, w: f64) -> f64 {
    let a = v[0] + (v[1] - v[0]) * u;
    let b = v[3] + (v[2] - v[3]) * u;
    a + (b - a) * w
}

/// Quad factors as MTLQuadTessellationFactorsHalf: four edges, two inside.
fn factors(per_patch: &[[f64; 6]]) -> Vec<u8> {
    per_patch
        .iter()
        .flatten()
        .flat_map(|&f| f16_bits(f).to_le_bytes())
        .collect()
}

/// A tessellation case: name, partition mode, maximum factor, factors per
/// patch and the segments per side they give.
type Tessellation = (&'static str, &'static str, u32, [[f64; 6]; 2], u32);

fn tessellation(plan: &mut Plan, library: &str) {
    let uniform = |f: f64| [f; 6];
    // (name, partition, maximum, factors per patch, segments per side)
    let cases: [Tessellation; 5] = [
        ("integer", "integer", 16, [uniform(4.0); 2], 4),
        ("integer_odd", "integer", 16, [uniform(3.0); 2], 3),
        ("integer_rounded", "integer", 16, [uniform(2.25); 2], 3),
        ("pow2", "pow2", 16, [uniform(3.0); 2], 4),
        ("clamped", "integer", 8, [uniform(20.0); 2], 8),
    ];
    let culled = [uniform(4.0), [4.0, 0.0, 4.0, 4.0, 4.0, 4.0]];
    for (name, partition, max, per_patch, n, live) in cases
        .into_iter()
        .map(|(a, b, c, d, e)| (a, b, c, d, e, 2))
        .chain([("culled", "integer", 16, culled, 4, 1)])
    {
        let side = (n + 1) as usize;
        let mut points = vec![-1.0; 2 * side * side * 4];
        for (p, (_, v)) in PATCHES.iter().enumerate().take(live) {
            for j in 0..side {
                for i in 0..side {
                    let (u, w) = (i as f64 / f64::from(n), j as f64 / f64::from(n));
                    let slot = (p * side * side + j * side + i) * 4;
                    points[slot..slot + 4].copy_from_slice(&[u, w, value(v, u, w), p as f64]);
                }
            }
        }
        let image: Vec<f64> = (0..SIZE)
            .flat_map(|y| (0..SIZE).map(move |x| (x, y)))
            .flat_map(|(x, y)| {
                let cx = (f64::from(x) + 0.5) / f64::from(SIZE) * 2.0 - 1.0;
                let cy = 1.0 - (f64::from(y) + 0.5) / f64::from(SIZE) * 2.0;
                let p = usize::from(cx > 0.0);
                if p >= live {
                    return [0.0; 4];
                }
                let ([x0, y0, x1, y1], v) = PATCHES[p];
                [
                    value(&v, (cx - x0) / (x1 - x0), (cy - y0) / (y1 - y0)),
                    0.0,
                    0.0,
                    1.0,
                ]
            })
            .collect();
        let state = |extra: serde_json::Value| {
            let mut state = json!({
                "tessellation": {"partition": partition, "max_factor": max, "factors": "factors",
                                 "control_points": 4, "patch_count": 2},
                "vertex_descriptor": {
                    "attributes": [{"index": 0, "format": "float2", "offset": 0, "buffer": 0},
                                   {"index": 1, "format": "float", "offset": 8, "buffer": 0}],
                    "layouts": [{"buffer": 0, "stride": 12, "step": "patch_control_point"}]}});
            state
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            state
        };
        let inputs = |case: Case| {
            case.buffer(Buffer::data("controls", 0, f32s(&control_points())).stage("vertex"))
                .buffer(Buffer::data("factors", 0, factors(&per_patch)).unbound())
        };
        plan.add(
            inputs(Case::render(
                &format!("stages.tessellation.{name}.points"),
                library,
                "tess_record",
                None,
                state(json!({"rasterize": false, "target_size": [1, 1]})),
            ))
            .buffer(Buffer::data("points", 2, f32s(&vec![-1.0; points.len()])).stage("vertex"))
            .buffer(Buffer::data("n", 3, u32s(&[n])).stage("vertex"))
            .output(
                Output::new("points", Dtype::F32, Tolerance::abs(1e-5)).expect_same(f32s(&points)),
            ),
        );
        plan.add(
            inputs(Case::render(
                &format!("stages.tessellation.{name}.image"),
                library,
                "tess_quad",
                Some("frag_tessellated"),
                state(json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}]})),
            ))
            .texture(Texture::d2("target", "rgba32float", SIZE, SIZE).usage(&["render"]))
            .output(
                Output::new("target", Dtype::F32, Tolerance::abs(IMAGE)).expect_same(f32s(&image)),
            ),
        );
    }
}

/// Fractional partitioning places domain points the specification leaves
/// to the tessellator, so only the image, exact for linear values, is
/// asserted.
fn fractional(plan: &mut Plan, library: &str) {
    let image: Vec<f64> = pixels()
        .flat_map(|(cx, cy)| {
            let ([x0, y0, x1, y1], v) = PATCHES[usize::from(cx > 0.0)];
            [
                value(&v, (cx - x0) / (x1 - x0), (cy - y0) / (y1 - y0)),
                0.0,
                0.0,
                1.0,
            ]
        })
        .collect();
    for (partition, factor) in [
        ("fractional_odd", 3.5),
        ("fractional_even", 3.5),
        ("fractional_odd", 6.25),
    ] {
        plan.add(
            Case::render(
                &format!("stages.tessellation.{partition}_{factor}.image"),
                library,
                "tess_quad",
                Some("frag_tessellated"),
                json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}],
                       "tessellation": {"partition": partition, "max_factor": 16, "factors": "factors",
                                        "control_points": 4, "patch_count": 2},
                       "vertex_descriptor": {
                           "attributes": [{"index": 0, "format": "float2", "offset": 0, "buffer": 0},
                                          {"index": 1, "format": "float", "offset": 8, "buffer": 0}],
                           "layouts": [{"buffer": 0, "stride": 12, "step": "patch_control_point"}]}}),
            )
            .buffer(Buffer::data("controls", 0, f32s(&control_points())).stage("vertex"))
            .buffer(Buffer::data("factors", 0, factors(&[[factor; 6]; 2])).unbound())
            .texture(Texture::d2("target", "rgba32float", SIZE, SIZE).usage(&["render"]))
            .output(Output::new("target", Dtype::F32, Tolerance::abs(IMAGE)).expect_same(f32s(&image))),
        );
    }
}

/// A value linear in clip space, which every patch below shares, so the
/// image is exact whichever patch or triangle owns a pixel.
fn linear(x: f64, y: f64) -> f64 {
    0.3 + 0.2 * x + 0.1 * y
}

/// The linear value at every pixel centre, or 0 where `covered` says not.
fn linear_image(covered: impl Fn(f64, f64) -> bool) -> Vec<f64> {
    pixels()
        .flat_map(|(x, y)| {
            if covered(x, y) {
                [linear(x, y), 0.0, 0.0, 1.0]
            } else {
                [0.0; 4]
            }
        })
        .collect()
}

/// Control points (x, y, value) at the corners given.
fn corners(points: &[[f64; 2]]) -> Vec<f64> {
    points
        .iter()
        .flat_map(|&[x, y]| [x, y, linear(x, y)])
        .collect()
}

/// The two halves of clip space as quad patches, corners in the order
/// tess_quad expects.
fn halves() -> Vec<f64> {
    corners(&[
        [-1.0, -1.0],
        [0.0, -1.0],
        [0.0, 1.0],
        [-1.0, 1.0],
        [0.0, -1.0],
        [1.0, -1.0],
        [1.0, 1.0],
        [0.0, 1.0],
    ])
}

fn half_factors(per_patch: &[f64]) -> Vec<u8> {
    per_patch
        .iter()
        .flat_map(|&f| f16_bits(f).to_le_bytes())
        .collect()
}

/// Tessellation the specification leaves the points of: triangle patches,
/// uneven factors, patches chosen by an index buffer or drawn from an
/// indirect buffer, instances with their own factors, and patches with no
/// control points. Each image is asserted.
fn tessellation_images(plan: &mut Plan, library: &str) {
    let layout = |stride: u32, attributes: bool| {
        if attributes {
            json!({"attributes": [{"index": 0, "format": "float2", "offset": 0, "buffer": 0},
                                  {"index": 1, "format": "float", "offset": 8, "buffer": 0}],
                   "layouts": [{"buffer": 0, "stride": stride, "step": "patch_control_point"}]})
        } else {
            json!({"attributes": [], "layouts": []})
        }
    };
    let case = |name: &str,
                vertex: &str,
                tess: serde_json::Value,
                controls: Option<Vec<f64>>,
                image: Vec<f64>| {
        let mut state =
            json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}], "tessellation": tess});
        if controls.is_some() {
            state["vertex_descriptor"] = layout(12, true);
        }
        let mut case = Case::render(
            &format!("stages.tessellation.{name}"),
            library,
            vertex,
            Some("frag_tessellated"),
            state,
        )
        .texture(Texture::d2("target", "rgba32float", SIZE, SIZE).usage(&["render"]))
        .output(Output::new("target", Dtype::F32, Tolerance::abs(IMAGE)).expect_same(f32s(&image)));
        if let Some(c) = controls {
            case = case.buffer(Buffer::data("controls", 0, f32s(&c)).stage("vertex"));
        }
        case
    };
    let full = linear_image(|_, _| true);
    let right = linear_image(|x, _| x > 0.0);
    let left = linear_image(|x, _| x < 0.0);
    // Two triangles covering clip space, sharing its diagonal.
    let triangles = corners(&[
        [-1.0, -1.0],
        [1.0, -1.0],
        [-1.0, 1.0],
        [1.0, -1.0],
        [1.0, 1.0],
        [-1.0, 1.0],
    ]);
    for (name, partition, factors) in [
        ("triangle.integer_3", "integer", [3.0, 3.0, 3.0, 3.0]),
        ("triangle.uneven", "integer", [1.0, 3.0, 5.0, 2.0]),
        (
            "triangle.fractional_odd_2.5",
            "fractional_odd",
            [2.5, 2.5, 2.5, 2.5],
        ),
        (
            "triangle.fractional_even_4.75",
            "fractional_even",
            [4.75, 3.0, 1.5, 4.75],
        ),
    ] {
        plan.add(
            case(name, "tess_triangle",
                 json!({"partition": partition, "max_factor": 16, "factors": "factors", "control_points": 3, "patch_count": 2}),
                 Some(triangles.clone()), full.clone())
            .buffer(Buffer::data("factors", 0, half_factors(&[factors, factors].concat())).unbound()),
        );
    }
    let quad = |e: [f64; 6]| half_factors(&[e, e].concat());
    plan.add(
        case("quad.uneven", "tess_quad",
             json!({"partition": "integer", "max_factor": 16, "factors": "factors", "control_points": 4, "patch_count": 2}),
             Some(halves()), full.clone())
        .buffer(Buffer::data("factors", 0, quad([1.0, 2.0, 3.0, 4.0, 5.0, 2.0])).unbound()),
    );
    // Patch 1 twice by index buffer; patch 1 alone from an indirect draw.
    plan.add(
        case("quad.indexed", "tess_quad",
             json!({"partition": "integer", "max_factor": 16, "factors": "factors", "control_points": 4,
                    "patch_count": 2, "patch_index": "index"}),
             Some(halves()), right.clone())
        .buffer(Buffer::data("factors", 0, quad([4.0; 6])).unbound())
        .buffer(Buffer::data("index", 0, u32s(&[1, 1])).unbound()),
    );
    plan.add(
        case("quad.indirect", "tess_quad",
             json!({"partition": "integer", "max_factor": 16, "factors": "factors", "control_points": 4,
                    "indirect": "arguments"}),
             Some(halves()), right.clone())
        .buffer(Buffer::data("factors", 0, quad([4.0; 6])).unbound())
        .buffer(Buffer::data("arguments", 0, u32s(&[1, 1, 1, 0])).unbound()),
    );
    // The left patch drawn twice, the second instance one unit right, each
    // with its own factors: both live, or one culled by a zero edge.
    let cut = [3.0, 0.0, 3.0, 3.0, 3.0, 3.0];
    for (name, first, second, image) in [
        ("quad.instances", [2.0; 6], [3.0; 6], full.clone()),
        ("quad.instance_culled", [2.0; 6], cut, left.clone()),
        ("quad.first_instance_culled", cut, [3.0; 6], right.clone()),
    ] {
        plan.add(
            case(name, "tess_quad_instanced",
                 json!({"partition": "integer", "max_factor": 16, "factors": "factors", "control_points": 4,
                        "patch_count": 1, "instance_count": 2, "instance_stride": 12}),
                 Some(halves()[..12].to_vec()), image)
            .buffer(Buffer::data("factors", 0, half_factors(&[first, second].concat())).unbound()),
        );
    }
    // No control points: each patch reads its rectangle by patch id.
    plan.add(
        case("quad.no_control_points", "tess_quad_free",
             json!({"partition": "integer", "max_factor": 16, "factors": "factors", "control_points": 0, "patch_count": 2}),
             None, full)
        .buffer(Buffer::data("rects", 0, f32s(&[-1.0, -1.0, 0.0, 1.0, 0.0, -1.0, 1.0, 1.0])).stage("vertex"))
        .buffer(Buffer::data("factors", 0, quad([3.0; 6])).unbound()),
    );
}

/// Pixel centres in clip space, row by row from the top.
fn pixels() -> impl Iterator<Item = (f64, f64)> {
    (0..SIZE).flat_map(|y| {
        (0..SIZE).map(move |x| {
            (
                (f64::from(x) + 0.5) / f64::from(SIZE) * 2.0 - 1.0,
                1.0 - (f64::from(y) + 0.5) / f64::from(SIZE) * 2.0,
            )
        })
    })
}

const RECTS: [[f64; 4]; 3] = [
    [-1.0, -1.0, 0.0, 1.0],
    [0.0, 0.0, 1.0, 1.0],
    [0.0, -1.0, 1.0, 0.0],
];
const COLORS: [[f64; 4]; 3] = [
    [0.25, 0.5, 0.75, 1.0],
    [1.0, 0.0, 0.5, 0.25],
    [0.125, 0.875, 0.0, 0.5],
];

/// The image of the first `count` rectangles over a cleared target.
fn rects_image(count: usize) -> Vec<f64> {
    pixels()
        .flat_map(|(x, y)| {
            RECTS[..count]
                .iter()
                .zip(COLORS)
                .find(|(r, _)| x > r[0] && x < r[2] && y > r[1] && y < r[3])
                .map_or([0.0; 4], |(_, c)| c)
        })
        .collect()
}

/// Mesh pipelines: a mesh grid drawing one rectangle per threadgroup, and
/// an object stage choosing the mesh grid's size and filling its payload,
/// including a grid of none.
fn mesh(plan: &mut Plan, library: &str) {
    let target = |mesh: serde_json::Value| json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}], "mesh": mesh});
    let inputs = |case: Case, stage: &str| {
        case.buffer(Buffer::data("rects", 0, f32s(&RECTS.concat())).stage(stage))
            .buffer(Buffer::data("colors", 1, f32s(&COLORS.concat())).stage(stage))
            .texture(Texture::d2("target", "rgba32float", SIZE, SIZE).usage(&["render"]))
    };
    plan.add(
        inputs(
            Case::render(
                "stages.mesh.rects",
                library,
                "mesh_rects",
                Some("frag_mesh"),
                target(json!({"mesh": "mesh_rects", "threadgroups": [2], "mesh_threads": [6]})),
            ),
            "mesh",
        )
        .output(
            Output::new("target", Dtype::F32, Tolerance::exact())
                .expect_same(f32s(&rects_image(2))),
        ),
    );
    for count in [3u32, 1, 0] {
        plan.add(
            inputs(
                Case::render(
                    &format!("stages.mesh.object_{count}"),
                    library,
                    "mesh_payload",
                    Some("frag_mesh"),
                    target(json!({"object": "object_rects", "mesh": "mesh_payload", "threadgroups": [1],
                                  "object_threads": [8], "mesh_threads": [6]})),
                ),
                "object",
            )
            .buffer(Buffer::data("count", 2, u32s(&[count])).stage("object"))
            .output(
                Output::new("target", Dtype::F32, Tolerance::exact())
                    .expect_same(f32s(&rects_image(count as usize))),
            ),
        );
    }
}

/// Vertex amplification: one full-target draw amplified into two views,
/// mapped to two layers of an array target or to two viewports.
fn amplification(plan: &mut Plan, library: &str) {
    let view = |k: usize| [COLORS[k][0], COLORS[k][1], COLORS[k][2], 0.5];
    let layers: Vec<f64> = (0..2)
        .flat_map(|k| pixels().flat_map(move |_| view(k)))
        .collect();
    let halves: Vec<f64> = pixels()
        .flat_map(|(x, _)| view(usize::from(x > 0.0)))
        .collect();
    let half = f64::from(SIZE / 2);
    for (name, texture, extra, expected) in [
        (
            "layers",
            Texture::new("target", "rgba32float", "2d_array", [SIZE, SIZE, 1]).array(2),
            json!({"amplification": {"count": 2, "mappings": [[0, 0], [0, 1]]}}),
            layers,
        ),
        (
            "viewports",
            Texture::d2("target", "rgba32float", SIZE, SIZE),
            json!({"amplification": {"count": 2, "mappings": [[0, 0], [1, 0]]},
                   "viewports": [[0, 0, half, f64::from(SIZE)], [half, 0, half, f64::from(SIZE)]]}),
            halves,
        ),
    ] {
        let mut state = json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}],
                               "primitive": "triangle_strip", "vertex_count": 4});
        state
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        plan.add(
            Case::render(
                &format!("stages.amplification.{name}"),
                library,
                "vert_amplified",
                Some("frag_amplified"),
                state,
            )
            .requires(&[], &["vertex_amplification2"])
            .buffer(Buffer::data("colors", 0, f32s(&COLORS.concat())).stage("vertex"))
            .texture(texture.usage(&["render"]))
            .output(
                Output::new("target", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)),
            ),
        );
    }
}

/// Mesh outputs that route primitives: to target layers, to viewports, and
/// cut by a per-vertex clip distance.
fn mesh_routing(plan: &mut Plan, library: &str) {
    let half = f64::from(SIZE / 2);
    let full = f64::from(SIZE);
    let color = |k: usize| COLORS[k];
    let layers: Vec<f64> = (0..2)
        .flat_map(|k| pixels().flat_map(move |_| color(k)))
        .collect();
    let halves: Vec<f64> = pixels()
        .flat_map(|(x, _)| color(usize::from(x > 0.0)))
        .collect();
    let clipped: Vec<f64> = pixels()
        .flat_map(|(x, _)| if x > 0.0 { color(0) } else { [0.0; 4] })
        .collect();
    for (name, groups, texture, route, clip, viewports, expected) in [
        (
            "layers",
            2,
            Texture::new("target", "rgba32float", "2d_array", [SIZE, SIZE, 1]).array(2),
            [0u32, 0, 1, 0],
            [-2.0, -2.0],
            json!([[0, 0, full, full]]),
            layers,
        ),
        (
            "viewports",
            2,
            Texture::d2("target", "rgba32float", SIZE, SIZE),
            [0, 0, 0, 1],
            [-2.0, -2.0],
            json!([[0, 0, half, full], [half, 0, half, full]]),
            halves,
        ),
        (
            "clip_distance",
            1,
            Texture::d2("target", "rgba32float", SIZE, SIZE),
            [0, 0, 0, 0],
            [0.0, 0.0],
            json!([[0, 0, full, full]]),
            clipped,
        ),
    ] {
        plan.add(
            Case::render(
                &format!("stages.mesh.{name}"),
                library,
                "mesh_routed",
                Some("frag_routed"),
                json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}], "viewports": viewports,
                       "mesh": {"mesh": "mesh_routed", "threadgroups": [groups], "mesh_threads": [6]}}),
            )
            .buffer(Buffer::data("colors", 0, f32s(&COLORS.concat())).stage("mesh"))
            .buffer(Buffer::data("clip", 1, f32s(&clip)).stage("mesh"))
            .buffer(Buffer::data("route", 2, u32s(&route)).stage("mesh"))
            .texture(texture.usage(&["render"]))
            .output(Output::new("target", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
        );
    }
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("stages", SOURCE, &[], super::plan::LATEST);
    tessellation(plan, &library);
    fractional(plan, &library);
    tessellation_images(plan, &library);
    mesh(plan, &library);
    mesh_routing(plan, &library);
    amplification(plan, &library);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corner_values_are_linear() {
        for (_, v) in PATCHES {
            assert!((v[0] + v[2] - v[1] - v[3]).abs() < 1e-12);
        }
    }
}
