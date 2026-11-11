//! corpus/render.metal: the render pipeline, asserted against a reference
//! rasterizer. Coverage follows the pixel centers and, under
//! multisampling, the standard sample positions; pixels and samples
//! within a hundredth of a pixel of an edge are left out, since which
//! side they fall on is the rasterizer's fixed-point call, and shared
//! edges are asserted by what software relies on (each pixel drawn once)
//! rather than by a fill convention. Vertices lie on a 1/16-pixel grid so
//! snapping leaves them where the reference puts them. Interpolation is
//! asserted to the precision of fp32 plane equations, blending and format
//! conversion to their formats' resolution, and the depth, stencil and
//! blend equations exactly.
use super::plan::{Buffer, Case, LATEST, Output, Plan, Step, Texture, Tolerance};
use super::textures::{srgb, xr};
use super::values::{Dtype, Random, f16_bits, f16r, f32r, f32s, floats, ints, libm, u32s};
use serde_json::{Value, json};

const SOURCE: &str = "render.metal";
const W: u32 = 16;
const H: u32 = 16;
/// Pixels, or samples, this close to an edge are the rasterizer's call.
const MARGIN: f64 = 0.01;
/// The standard 4x sample positions within a pixel.
const SAMPLES4: [(f64, f64); 4] = [
    (0.375, 0.125),
    (0.875, 0.375),
    (0.125, 0.625),
    (0.625, 0.875),
];
const CLEAR: [f64; 4] = [-7.0, -7.0, -7.0, -7.0];

/// A vertex in window coordinates: x, y (pixels, y down), z and 1/w.
#[derive(Clone, Copy)]
struct Win {
    x: f64,
    y: f64,
    z: f64,
    inv_w: f64,
}

/// A clip-space vertex at a window position, depth and w, on a viewport.
fn clip(x: f64, y: f64, z: f64, w: f64, viewport: [f64; 4]) -> [f64; 4] {
    let ndc_x = (x - viewport[0]) / viewport[2] * 2.0 - 1.0;
    let ndc_y = 1.0 - (y - viewport[1]) / viewport[3] * 2.0;
    [ndc_x * w, ndc_y * w, z * w, w]
}

fn window(c: [f64; 4], viewport: [f64; 4]) -> Win {
    let (x, y, z) = (c[0] / c[3], c[1] / c[3], c[2] / c[3]);
    Win {
        x: viewport[0] + (x + 1.0) / 2.0 * viewport[2],
        y: viewport[1] + (1.0 - y) / 2.0 * viewport[3],
        z,
        inv_w: 1.0 / c[3],
    }
}

fn edge(a: Win, b: Win, x: f64, y: f64) -> f64 {
    (b.x - a.x) * (y - a.y) - (b.y - a.y) * (x - a.x)
}

/// Where a point lies relative to a triangle.
#[derive(Clone, Copy, Debug)]
enum Px {
    /// Inside, with screen-space barycentrics.
    In([f64; 3]),
    Out,
    /// Within MARGIN of an edge.
    Edge,
}

fn locate(t: &[Win; 3], x: f64, y: f64) -> Px {
    let area = edge(t[0], t[1], t[2].x, t[2].y);
    if area == 0.0 {
        return Px::Out;
    }
    let b = [
        edge(t[1], t[2], x, y) / area,
        edge(t[2], t[0], x, y) / area,
        edge(t[0], t[1], x, y) / area,
    ];
    let length = |a: Win, c: Win| ((a.x - c.x).powi(2) + (a.y - c.y).powi(2)).sqrt();
    let lengths = [length(t[1], t[2]), length(t[2], t[0]), length(t[0], t[1])];
    let distance: Vec<f64> = (0..3).map(|i| b[i] * area.abs() / lengths[i]).collect();
    if distance.iter().all(|&d| d > MARGIN) {
        Px::In(b)
    } else if distance.iter().any(|&d| d < -MARGIN) {
        Px::Out
    } else {
        Px::Edge
    }
}

/// Whether a triangle is counter-clockwise in normalized device
/// coordinates (y up), Metal's default front face.
fn ccw(t: &[Win; 3]) -> bool {
    edge(t[0], t[1], t[2].x, t[2].y) < 0.0
}

/// Perspective-correct barycentrics from screen-space ones.
fn perspective(t: &[Win; 3], b: [f64; 3]) -> [f64; 3] {
    let p = [b[0] * t[0].inv_w, b[1] * t[1].inv_w, b[2] * t[2].inv_w];
    let s = p[0] + p[1] + p[2];
    p.map(|v| v / s)
}

fn mix4(b: [f64; 3], a: &[[f64; 4]; 3]) -> [f64; 4] {
    [0, 1, 2, 3].map(|k| b[0] * a[0][k] + b[1] * a[1][k] + b[2] * a[2][k])
}

fn constant(which: i32) -> Value {
    json!([{"type": "int", "index": 0, "value": which}])
}

fn target(name: &str, format: &str) -> Texture {
    Texture::d2(name, format, W, H).usage(&["render"])
}

fn pixels() -> impl Iterator<Item = (u32, u32)> {
    (0..H).flat_map(|y| (0..W).map(move |x| (x, y)))
}

/// An image of per-pixel texels and which pixels are asserted.
struct Image {
    texels: Vec<[f64; 4]>,
    defined: Vec<u8>,
}

impl Image {
    fn new() -> Self {
        Self {
            texels: vec![],
            defined: vec![],
        }
    }

    fn push(&mut self, texel: Option<[f64; 4]>) {
        self.defined.push(u8::from(texel.is_some()));
        self.texels.push(texel.unwrap_or([0.0; 4]));
    }

    fn values(&self) -> Vec<f64> {
        self.texels.iter().flatten().copied().collect()
    }

    /// The rgba32float target output asserting this image.
    fn output(&self, name: &str, tol: Tolerance) -> Output {
        Output::new(name, Dtype::F32, tol.clone())
            .expect(
                f32s(&self.values().into_iter().map(f32r).collect::<Vec<_>>()),
                tol,
            )
            .expect_mask(self.defined.clone())
            .set("stride", 4)
    }
}

/// A draw of one triangle list from buffers 0 (positions) and 1
/// (attributes), into an rgba32float target cleared to CLEAR.
#[allow(clippy::too_many_arguments)]
fn draw(
    name: &str,
    library: &str,
    vertex: &str,
    fragment: &str,
    positions: &[[f64; 4]],
    attrs: &[[f64; 4]],
    format: &str,
    state: Value,
) -> Case {
    let mut render =
        json!({"colors": [{"texture": "c", "clear": CLEAR}], "vertex_count": positions.len()});
    for (k, v) in state.as_object().unwrap() {
        render[k] = v.clone();
    }
    Case::render(name, library, vertex, Some(fragment), render)
        .buffer(Buffer::data("positions", 0, f32s(&positions.concat())).stage("vertex"))
        .buffer(Buffer::data("attributes", 1, f32s(&attrs.concat())).stage("vertex"))
        .texture(target("c", format))
}

/// The triangle the interpolation cases draw: w of 1, 4 and 1/2.
fn perspective_triangle() -> ([[f64; 4]; 3], [Win; 3]) {
    let full = [0.0, 0.0, W as f64, H as f64];
    let c = [
        clip(1.0, 1.5, 0.25, 1.0, full),
        clip(15.0, 4.0, 0.5, 4.0, full),
        clip(4.5, 15.25, 0.75, 0.5, full),
    ];
    (c, c.map(|v| window(v, full)))
}

fn interpolation(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(901);
    let (positions, t) = perspective_triangle();
    let attrs: [[f64; 4]; 3] =
        std::array::from_fn(|_| [0; 4].map(|_| f32r(rng.uniform(-1.0, 1.0))));
    // Vertices 5 to 7, so flat values come from vertex 5.
    let mut pos = vec![[0.0, 0.0, 0.0, 1.0]; 5];
    pos.extend(positions);
    let mut att = vec![[0.0; 4]; 5];
    att.extend(attrs);
    let start = json!({"vertex_start": 5, "vertex_count": 3});
    let halves = attrs.map(|a| a.map(f16r));
    let float = Tolerance::abs(1e-4);
    let half = Tolerance::abs(2e-3);
    for (which, label) in [
        (0, "flat"),
        (1, "center_perspective"),
        (2, "center_no_perspective"),
        (3, "centroid_perspective"),
        (4, "centroid_no_perspective"),
        (5, "sample_perspective"),
        (6, "sample_no_perspective"),
        (7, "half"),
        (8, "vectors"),
        (9, "flat_int"),
    ] {
        let mut image = Image::new();
        for (x, y) in pixels() {
            image.push(match locate(&t, x as f64 + 0.5, y as f64 + 0.5) {
                Px::Edge => None,
                Px::Out => Some(CLEAR),
                Px::In(b) => {
                    let p = perspective(&t, b);
                    Some(match which {
                        0 => attrs[0],
                        2 | 4 | 6 => mix4(b, &attrs),
                        7 => mix4(p, &halves).map(f16r),
                        8 => {
                            let v = mix4(p, &attrs);
                            [v[1], v[2], v[3], 1.0]
                        }
                        9 => attrs[0].map(|a| f32r(a * 1000.0).trunc()),
                        _ => mix4(p, &attrs),
                    })
                }
            });
        }
        let tol = match which {
            0 | 9 => Tolerance::exact(),
            7 => half.clone(),
            _ => float.clone(),
        };
        plan.add(
            draw(
                &format!("render.interpolate.{label}"),
                library,
                "vert_interp",
                "frag_interp",
                &pos,
                &att,
                "rgba32float",
                start.clone(),
            )
            .set("constants", constant(which))
            .output(image.output("c", tol)),
        );
    }
    // Each vertex's value, uninterpolated, in drawing order: vertex 5's
    // first. The feature set tables give these values to Apple10.
    let mut image = Image::new();
    for (x, y) in pixels() {
        image.push(match locate(&t, x as f64 + 0.5, y as f64 + 0.5) {
            Px::Edge => None,
            Px::Out => Some(CLEAR),
            Px::In(_) => Some([attrs[0][3], attrs[1][3], attrs[2][3], 1.0]),
        });
    }
    plan.add(
        draw(
            "render.interpolate.vertex_values",
            library,
            "vert_interp",
            "frag_vertex_values",
            &pos,
            &att,
            "rgba32float",
            start.clone(),
        )
        .requires(&["apple10"], &[])
        .output(image.output("c", Tolerance::exact())),
    );
    // Flat unsigned integers, bit for bit.
    let mut expected = vec![];
    let mut defined = vec![];
    for (x, y) in pixels() {
        let p = locate(&t, x as f64 + 0.5, y as f64 + 0.5);
        defined.push(u8::from(!matches!(p, Px::Edge)));
        expected.extend(if matches!(p, Px::In(_)) {
            [5, 35, 0xFFFF_FFFA, 0x8000_0005]
        } else {
            [0; 4]
        });
    }
    plan.add(
        draw("render.interpolate.flat_uint", library, "vert_interp", "frag_interp_uint", &pos, &att, "rgba32uint",
             json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "vertex_start": 5, "vertex_count": 3}))
        .output(Output::new("c", Dtype::U32, Tolerance::exact()).expect_same(u32s(&expected)).expect_mask(defined).set("stride", 4)),
    );
    // Every qualifier at once into four targets.
    let mut images: Vec<Image> = (0..4).map(|_| Image::new()).collect();
    for (x, y) in pixels() {
        let at = locate(&t, x as f64 + 0.5, y as f64 + 0.5);
        for (k, image) in images.iter_mut().enumerate() {
            image.push(match at {
                Px::Edge => None,
                Px::Out => Some(CLEAR),
                Px::In(b) => Some(match k {
                    0 => attrs[0],
                    1 => mix4(perspective(&t, b), &attrs),
                    2 => mix4(b, &attrs),
                    _ => mix4(perspective(&t, b), &halves).map(f16r),
                }),
            });
        }
    }
    let mut case = Case::render(
        "render.interpolate.all_targets",
        library,
        "vert_interp",
        Some("frag_interp_all"),
        json!({"colors": (0..4).map(|k| json!({"texture": format!("c{k}"), "clear": CLEAR})).collect::<Vec<_>>(),
               "vertex_start": 5, "vertex_count": 3}),
    )
    .buffer(Buffer::data("positions", 0, f32s(&pos.concat())).stage("vertex"))
    .buffer(Buffer::data("attributes", 1, f32s(&att.concat())).stage("vertex"));
    for (k, image) in images.iter().enumerate() {
        case = case
            .texture(target(&format!("c{k}"), "rgba32float"))
            .output(image.output(
                &format!("c{k}"),
                if k == 3 { half.clone() } else { float.clone() },
            ));
    }
    plan.add(case);
    // Under 4x multisampling, resolved: centroid and center interpolation
    // at the pixel center of covered pixels, sample interpolation averaged
    // over the four sample positions.
    for (which, label) in [
        (1, "center_perspective"),
        (3, "centroid_perspective"),
        (5, "sample_perspective"),
        (6, "sample_no_perspective"),
    ] {
        let mut image = Image::new();
        for (x, y) in pixels() {
            let (fx, fy) = (x as f64, y as f64);
            let samples: Vec<Px> = SAMPLES4
                .iter()
                .map(|&(sx, sy)| locate(&t, fx + sx, fy + sy))
                .collect();
            let center = locate(&t, fx + 0.5, fy + 0.5);
            image.push(
                if samples.iter().all(|p| matches!(p, Px::Out)) && matches!(center, Px::Out) {
                    Some([0.0; 4])
                } else if let (true, Px::In(b)) =
                    (samples.iter().all(|p| matches!(p, Px::In(_))), center)
                {
                    Some(match which {
                        5 | 6 => {
                            let mut sum = [0.0; 4];
                            for p in &samples {
                                let Px::In(s) = p else { unreachable!() };
                                let v = if which == 5 {
                                    mix4(perspective(&t, *s), &attrs)
                                } else {
                                    mix4(*s, &attrs)
                                };
                                (0..4).for_each(|k| sum[k] += v[k] / 4.0);
                            }
                            sum
                        }
                        _ => mix4(perspective(&t, b), &attrs),
                    })
                } else {
                    None
                },
            );
        }
        let tol = Tolerance::abs(2e-3);
        let values: Vec<f64> = image.values().into_iter().map(f16r).collect();
        plan.add(
            Case::render(
                &format!("render.interpolate.msaa4.{label}"),
                library,
                "vert_interp",
                Some("frag_interp"),
                json!({"colors": [{"texture": "ms", "clear": [0, 0, 0, 0], "resolve": "c"}], "samples": 4,
                       "vertex_start": 5, "vertex_count": 3}),
            )
            .set("constants", constant(which))
            .buffer(Buffer::data("positions", 0, f32s(&pos.concat())).stage("vertex"))
            .buffer(Buffer::data("attributes", 1, f32s(&att.concat())).stage("vertex"))
            .texture(Texture::new("ms", "rgba16float", "2d_ms", [W, H, 1]).samples(4).usage(&["render"]))
            .texture(target("c", "rgba16float"))
            .output(
                Output::new("c", Dtype::F16, tol.clone())
                    .expect(floats(Dtype::F16, &values), tol)
                    .expect_mask(image.defined)
                    .set("stride", 4),
            ),
        );
    }
    // Provoking vertices: the first of each triangle of a list and a strip.
    for (primitive, count) in [("triangle", 6usize), ("triangle_strip", 5)] {
        let full = [0.0, 0.0, W as f64, H as f64];
        let corners = [
            (1.0, 1.0),
            (15.0, 1.0),
            (1.0, 15.0),
            (15.0, 15.0),
            (8.0, 8.0),
            (15.0, 8.0),
        ];
        let order: Vec<usize> = if primitive == "triangle" {
            vec![0, 1, 2, 2, 1, 3]
        } else {
            vec![0, 1, 2, 3, 5]
        };
        let pos: Vec<[f64; 4]> = order
            .iter()
            .map(|&i| clip(corners[i].0, corners[i].1, 0.5, 1.0, full))
            .collect();
        let att: Vec<[f64; 4]> = (0..count).map(|i| [i as f64, 0.0, 0.0, 1.0]).collect();
        let tris: Vec<([Win; 3], usize)> = if primitive == "triangle" {
            (0..2)
                .map(|k| ([0, 1, 2].map(|j| window(pos[3 * k + j], full)), 3 * k))
                .collect()
        } else {
            (0..count - 2)
                .map(|k| ([0, 1, 2].map(|j| window(pos[k + j], full)), k))
                .collect()
        };
        let mut image = Image::new();
        for (x, y) in pixels() {
            let mut texel = Some(CLEAR);
            for (t, first) in &tris {
                match locate(t, x as f64 + 0.5, y as f64 + 0.5) {
                    Px::In(_) => texel = Some(att[*first]),
                    Px::Edge => texel = None,
                    Px::Out => {}
                }
            }
            image.push(texel);
        }
        plan.add(
            draw(
                &format!("render.provoking.{primitive}"),
                library,
                "vert_interp",
                "frag_interp",
                &pos,
                &att,
                "rgba32float",
                json!({"primitive": primitive}),
            )
            .set("constants", constant(0))
            .output(image.output("c", Tolerance::exact())),
        );
    }
}

/// u, v and p of the window-filling derivative triangle at a point.
fn deriv_attr(x: f64, y: f64) -> [f64; 4] {
    [
        x / 16.0 + y / 64.0,
        y * 0.75 / 16.0 + x / 128.0 + 0.125,
        0.5 + x / 32.0 - y / 32.0,
        1.0,
    ]
}

fn derivatives(plan: &mut Plan, library: &str) {
    let full = [0.0, 0.0, W as f64, H as f64];
    let corners = [(0.0, 0.0), (32.0, 0.0), (0.0, 32.0)];
    let pos: Vec<[f64; 4]> = corners
        .iter()
        .map(|&(x, y)| clip(x, y, 0.5, 1.0, full))
        .collect();
    let att: Vec<[f64; 4]> = corners.iter().map(|&(x, y)| deriv_attr(x, y)).collect();
    let at = |x: u32, y: u32| deriv_attr(x as f64 + 0.5, y as f64 + 0.5);
    type F = fn([f64; 4]) -> [f64; 2];
    // Each case: the values its derivatives are of, as f32 or half.
    let cases: [(i32, &str, F, bool); 13] = [
        (0, "u", |a| [a[0], 0.0], false),
        (1, "v", |a| [a[1], 0.0], false),
        (2, "position", |_| [0.0, 0.0], false),
        (3, "product", |a| [f32r(a[0] * a[1]), 0.0], false),
        (4, "square", |a| [f32r(a[0] * a[0]), 0.0], false),
        (5, "half", |a| [f16r(a[0]), 0.0], true),
        (6, "half_scaled", |a| [f16r(f16r(a[1]) * 0.5), 0.0], true),
        (7, "float2", |a| [a[0], a[1]], false),
        (8, "half2", |a| [f16r(a[0]), f16r(a[1])], true),
        (9, "perspective", |a| [a[0], a[2]], false),
        (10, "discard", |a| [f32r(a[0] + a[1]), 0.0], false),
        (12, "divergent", |a| [f32r(a[0] * a[0]), 0.0], false),
        (
            11,
            "sin",
            |a| [f32r(libm::sin(f32r(a[0] * 3.0)) * a[1]), 0.0],
            false,
        ),
    ];
    for (which, label, f, is_half) in cases {
        // Fine derivatives pair the pixel with its quad neighbour in its
        // own row or column; coarse ones use the quad's top-left pixel's.
        let mut fine = vec![];
        let mut coarse = vec![];
        let round = |v: f64| if is_half { f16r(v) } else { f32r(v) };
        for (x, y) in pixels() {
            let (x0, y0) = (x & !1, y & !1);
            let value = f(at(x, y));
            for (out, kind) in [(&mut fine, true), (&mut coarse, false)] {
                let (ry, cx) = if kind { (y, x) } else { (y0, x0) };
                let dx = [0, 1].map(|k| round(f(at(x0 + 1, ry))[k] - f(at(x0, ry))[k]));
                let dy = [0, 1].map(|k| round(f(at(cx, y0 + 1))[k] - f(at(cx, y0))[k]));
                let width = [0, 1].map(|k| round(dx[k].abs() + dy[k].abs()));
                out.extend(match which {
                    2 => [1.0, 0.0, 0.0, 1.0],
                    7 | 8 => [dx[0], dx[1], width[0], width[1]],
                    9 => {
                        let p = at(x, y);
                        let (dpx, dpz) = (
                            round(at(x0 + 1, ry)[0] - at(x0, ry)[0]),
                            1.0 / 32.0 + 1.0 / 32.0,
                        );
                        [dpx, round(at(cx, y0 + 1)[1] - at(cx, y0)[1]), dpz, p[3]]
                    }
                    10 if x & 1 == 1 => CLEAR,
                    12 if (x + y) % 3 == 0 => [0.0; 4],
                    10 => [width[0]; 4],
                    _ => [dx[0], dy[0], width[0], value[0]],
                });
            }
        }
        let tol = match which {
            5 | 6 | 8 => Tolerance::abs(2.5e-3),
            11 => Tolerance::abs(5e-4),
            _ => Tolerance::abs(1e-5),
        };
        plan.add(
            draw(
                &format!("render.derivative.{label}"),
                library,
                "vert_plain",
                "frag_deriv",
                &pos,
                &att,
                "rgba32float",
                json!({}),
            )
            .set("constants", constant(which))
            .output(
                Output::new("c", Dtype::F32, tol.clone())
                    .expect(f32s(&fine), tol)
                    .expect_alternative(f32s(&coarse)),
            ),
        );
    }
}

/// The colour of each level but the first of the 64x64 texture the bicubic
/// bias case samples, one flat rgba8unorm colour a level.
fn level_colour(level: u32) -> [u8; 4] {
    [
        (level * 36 + 20) as u8,
        (250 - level * 30) as u8,
        ((level * 53 + 7) % 256) as u8,
        255,
    ]
}

/// A derivative in a branch a third of the pixels skip, one in every quad,
/// of a value the branch computes from an interpolant and a constant
/// buffer: Apple GPUs take it from the values every pixel of the quad
/// holds, as if no pixel had skipped. Derivatives of longer computations in
/// such a branch are undefined in the skipping pixels, so no case holds
/// them.
fn branch_derivatives(plan: &mut Plan, library: &str) {
    let full = [0.0, 0.0, W as f64, H as f64];
    let corners = [(0.0, 0.0), (32.0, 0.0), (0.0, 32.0)];
    let pos: Vec<[f64; 4]> = corners
        .iter()
        .map(|&(x, y)| clip(x, y, 0.5, 1.0, full))
        .collect();
    let att: Vec<[f64; 4]> = corners.iter().map(|&(x, y)| deriv_attr(x, y)).collect();
    let at = |x: u32, y: u32| deriv_attr(x as f64 + 0.5, y as f64 + 0.5);
    // scale, level scale, bias.
    let (scale, lod_scale, bias) = (0.5, 2.0 / 64.0, 1.0);
    let uniforms = f32s(&[scale, lod_scale, bias]);
    let value = |x: u32, y: u32| f32r(f32r(at(x, y)[0] * at(x, y)[0]) * scale);
    let (mut fine, mut coarse) = (vec![], vec![]);
    for (x, y) in pixels() {
        let (x0, y0) = (x & !1, y & !1);
        for (out, kind) in [(&mut fine, true), (&mut coarse, false)] {
            let (ry, cx) = if kind { (y, x) } else { (y0, x0) };
            let dx = f32r(value(x0 + 1, ry) - value(x0, ry));
            let dy = f32r(value(cx, y0 + 1) - value(cx, y0));
            out.extend(if (x + y) % 3 == 0 {
                [0.0; 4]
            } else {
                [dx, dy, f32r(dx.abs() + dy.abs()), value(x, y)]
            });
        }
    }
    let tol = Tolerance::abs(1e-5);
    let case = |name: &str, which: i32| {
        draw(
            name,
            library,
            "vert_plain",
            "frag_deriv_branch",
            &pos,
            &att,
            "rgba32float",
            json!({}),
        )
        .set("constants", constant(which))
        .buffer(Buffer::data("k", 0, uniforms.clone()).stage("fragment"))
    };
    plan.add(
        case("render.derivative.divergent_buffer", 0)
            .texture(
                Texture::d2("levels", "rgba8unorm", 1, 1)
                    .index(0)
                    .data(vec![0; 4]),
            )
            .sampler(json!({"name": "s", "index": 0}))
            .output(
                Output::new("c", Dtype::F32, tol.clone())
                    .expect(f32s(&fine), tol)
                    .expect_alternative(f32s(&coarse)),
            ),
    );
    // A bicubic sample's bias moves the level past lod_max_clamp, which
    // holds it at level 1, whose texel centers the coordinates fall on:
    // each pixel takes its texel there, the taps beside it weighed zero.
    let pattern = |x: u32, y: u32| {
        [
            (x * 7 + y * 3) % 256,
            (x * 5 + y * 11) % 256,
            (x ^ y) * 8 % 256,
            255,
        ]
    };
    let mut levels = vec![];
    for level in 0..7u32 {
        let side = 64u32 >> level;
        for (x, y) in (0..side).flat_map(|y| (0..side).map(move |x| (x, y))) {
            levels.extend(if level == 1 {
                pattern(x, y).map(|c| c as u8)
            } else {
                level_colour(level)
            });
        }
    }
    let expected: Vec<f64> = pixels()
        .flat_map(|(x, y)| pattern(x, y).map(|c| f64::from(c) / 255.0))
        .collect();
    let tol = Tolerance::abs(0.5 / 255.0);
    plan.add(
        case("render.sample.bicubic.bias_clamped", 1)
            .texture(
                Texture::d2("levels", "rgba8unorm", 64, 64)
                    .index(0)
                    .mipmaps(7)
                    .data(levels),
            )
            .sampler(
                json!({"name": "s", "index": 0, "min": "bicubic", "mag": "bicubic",
                            "mip": "nearest", "lod_max": 1.0}),
            )
            .output(Output::new("c", Dtype::F32, tol.clone()).expect(f32s(&expected), tol)),
    );
    divergent_levels_and_texels(plan, library, &pos, &att);
}

/// A sample with an implicit level, and the derivatives of a texel read at
/// the pixel, in a branch a third of the quads skip, which divergence
/// analysis cannot prove uniform. Where only some pixels of a quad skip, an
/// M1 Pro returns other values in the others, so no case holds that.
fn divergent_levels_and_texels(plan: &mut Plan, library: &str, pos: &[[f64; 4]], att: &[[f64; 4]]) {
    let skips = |x: u32, y: u32| ((x >> 1) + (y >> 1)).is_multiple_of(3);
    let mut levels = vec![];
    for level in 0..7u32 {
        let side = 64u32 >> level;
        levels.extend((0..side * side).flat_map(|_| level_colour(level)));
    }
    let tol = Tolerance::abs(0.5 / 255.0);
    // uv advances `texels_per_pixel` texels a pixel on both axes, which
    // selects level log2 of it, nearest of the 64x64 texture's levels.
    for texels_per_pixel in [2u32, 4] {
        let level = texels_per_pixel.ilog2();
        let colour = level_colour(level).map(|c| f64::from(c) / 255.0);
        let expected: Vec<f64> = pixels()
            .flat_map(|(x, y)| if skips(x, y) { [0.0; 4] } else { colour })
            .collect();
        let uniforms = f32s(&[0.0, f64::from(texels_per_pixel) / 64.0, 0.0]);
        plan.add(
            draw(
                &format!("render.derivative.divergent_sample.{texels_per_pixel}"),
                library,
                "vert_plain",
                "frag_deriv_branch",
                pos,
                att,
                "rgba32float",
                json!({}),
            )
            .set("constants", constant(2))
            .buffer(Buffer::data("k", 0, uniforms).stage("fragment"))
            .texture(
                Texture::d2("levels", "rgba8unorm", 64, 64)
                    .index(0)
                    .mipmaps(7)
                    .data(levels.clone()),
            )
            .sampler(
                json!({"name": "s", "index": 0, "min": "linear", "mag": "linear",
                            "mip": "nearest"}),
            )
            .output(Output::new("c", Dtype::F32, tol.clone()).expect(f32s(&expected), tol.clone())),
        );
    }
    // Two channels that vary along both axes, one of them not linearly, so
    // fine and coarse derivatives differ.
    let texel = |x: u32, y: u32| {
        let (x, y) = (f64::from(x), f64::from(y));
        [x * x + 3.0 * y, 2.0 * y * y + x, 0.0, 1.0]
    };
    let texels: Vec<f64> = pixels().flat_map(|(x, y)| texel(x, y)).collect();
    let (mut fine, mut coarse) = (vec![], vec![]);
    for (x, y) in pixels() {
        let (x0, y0) = (x & !1, y & !1);
        for (out, is_fine) in [(&mut fine, true), (&mut coarse, false)] {
            let (ry, cx) = if is_fine { (y, x) } else { (y0, x0) };
            let dx = |c: usize| texel(x0 + 1, ry)[c] - texel(x0, ry)[c];
            let dy = |c: usize| texel(cx, y0 + 1)[c] - texel(cx, y0)[c];
            out.extend(if skips(x, y) {
                [0.0; 4]
            } else {
                [dx(0), dy(0), dx(1), dy(1)]
            });
        }
    }
    let tol = Tolerance::exact();
    plan.add(
        draw(
            "render.derivative.divergent_texel",
            library,
            "vert_plain",
            "frag_deriv_branch",
            pos,
            att,
            "rgba32float",
            json!({}),
        )
        .set("constants", constant(3))
        .buffer(Buffer::data("k", 0, f32s(&[0.0; 3])).stage("fragment"))
        .texture(
            Texture::d2("levels", "rgba32float", W, H)
                .index(0)
                .data(f32s(&texels)),
        )
        .sampler(json!({"name": "s", "index": 0}))
        .output(
            Output::new("c", Dtype::F32, tol.clone())
                .expect(f32s(&fine), tol)
                .expect_alternative(f32s(&coarse)),
        ),
    );
}

/// How fragments pack into SIMD-groups, which Metal leaves to the GPU. An
/// M1 Pro packs a full 8 x 4 block of pixels into one: its 2 x 2 quads in
/// lanes of four, row by row, four quads to a row. NVIDIA packs a 4 x 8
/// block, which no lane order turns into Apple's, so the layout is
/// reported, not asserted, as a known hardware difference. What every device keeps is asserted: each quad is four
/// lanes in a row, x in bit 0 and y in bit 1, which lane-indexed shuffles
/// reach.
fn fragment_simd_layout(plan: &mut Plan, library: &str) {
    let corners = [(0.0, 0.0), (32.0, 0.0), (0.0, 32.0)];
    let full = [0.0, 0.0, W as f64, H as f64];
    let pos: Vec<[f64; 4]> = corners
        .iter()
        .map(|&(x, y)| clip(x, y, 0.5, 1.0, full))
        .collect();
    let att = [[0.0; 4]; 3];
    let expected: Vec<f64> = pixels()
        .flat_map(|(x, y)| {
            let lane = x & 1 | (y & 1) << 1 | (x >> 1 & 3) << 2 | (y >> 1 & 1) << 4;
            [
                f64::from(lane),
                f64::from((x & !7) + (y & !3) * 1024),
                32.0,
                32.0,
            ]
        })
        .collect();
    plan.add(
        draw(
            "render.simd.fragment_layout",
            library,
            "vert_plain",
            "frag_simd_layout",
            &pos,
            &att,
            "rgba32float",
            json!({}),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)))
        .informational()
        .note("fragment SIMD-group layout is the GPU's own"),
    );
    let index = |x: u32, y: u32| f64::from(x + y * 1024);
    let quads: Vec<f64> = pixels()
        .flat_map(|(x, y)| {
            [
                f64::from(x & 1 | (y & 1) << 1),
                index(x ^ 1, y),
                index(x, y ^ 1),
                index(x | 1, y | 1),
            ]
        })
        .collect();
    plan.add(
        draw(
            "render.simd.fragment_quads",
            library,
            "vert_plain",
            "frag_simd_quads",
            &pos,
            &att,
            "rgba32float",
            json!({}),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&quads))),
    );
}

fn builtins(plan: &mut Plan, library: &str) {
    let (positions, t) = perspective_triangle();
    let attrs = [[0.0; 4]; 3];
    // [[position]]: the pixel center, window depth and 1/w.
    let mut image = Image::new();
    for (x, y) in pixels() {
        image.push(match locate(&t, x as f64 + 0.5, y as f64 + 0.5) {
            Px::Edge => None,
            Px::Out => Some(CLEAR),
            Px::In(b) => Some([
                x as f64 + 0.5,
                y as f64 + 0.5,
                b[0] * t[0].z + b[1] * t[1].z + b[2] * t[2].z,
                b[0] * t[0].inv_w + b[1] * t[1].inv_w + b[2] * t[2].inv_w,
            ]),
        });
    }
    plan.add(
        draw(
            "render.position",
            library,
            "vert_plain",
            "frag_position",
            &positions,
            &attrs,
            "rgba32float",
            json!({}),
        )
        .output(image.output("c", Tolerance::abs(1e-5).with_rel(1e-5))),
    );
    // A viewport smaller than the target and offset into it.
    let viewport = [2.0, 4.0, 8.0, 6.0];
    let c = [
        clip(2.5, 4.25, 0.5, 1.0, viewport),
        clip(9.75, 5.0, 0.5, 2.0, viewport),
        clip(4.0, 9.5, 0.5, 1.0, viewport),
    ];
    let t = c.map(|v| window(v, viewport));
    let mut image = Image::new();
    for (x, y) in pixels() {
        image.push(match locate(&t, x as f64 + 0.5, y as f64 + 0.5) {
            Px::Edge => None,
            Px::Out => Some(CLEAR),
            Px::In(b) => Some([
                x as f64 + 0.5,
                y as f64 + 0.5,
                0.5,
                b[0] * t[0].inv_w + b[1] * t[1].inv_w + b[2] * t[2].inv_w,
            ]),
        });
    }
    plan.add(
        draw(
            "render.viewport",
            library,
            "vert_plain",
            "frag_position",
            &c,
            &attrs,
            "rgba32float",
            json!({"viewport": viewport}),
        )
        .output(image.output("c", Tolerance::abs(1e-5).with_rel(1e-5))),
    );
    // Facing, culling and primitive IDs: four triangles, alternately wound.
    let full = [0.0, 0.0, W as f64, H as f64];
    let mut quads = vec![];
    for (k, &(ox, oy)) in [(0.0, 0.0), (8.0, 0.0), (0.0, 8.0), (8.0, 8.0)]
        .iter()
        .enumerate()
    {
        let mut tri = [
            (ox + 1.0, oy + 1.0),
            (ox + 7.0, oy + 1.5),
            (ox + 2.0, oy + 7.0),
        ];
        if k % 2 == 1 {
            tri.swap(1, 2);
        }
        quads.push(tri.map(|(x, y)| clip(x, y, 0.5, 1.0, full)));
    }
    let pos: Vec<[f64; 4]> = quads.concat();
    let att = vec![[0.0; 4]; pos.len()];
    for (winding, cull) in [
        ("ccw", "none"),
        ("cw", "none"),
        ("ccw", "back"),
        ("ccw", "front"),
        ("cw", "back"),
    ] {
        let mut image = Image::new();
        for (x, y) in pixels() {
            let mut texel = Some(CLEAR);
            for (k, q) in quads.iter().enumerate() {
                let t = q.map(|v| window(v, full));
                let front = ccw(&t) == (winding == "ccw");
                let culled = (cull == "back" && !front) || (cull == "front" && front);
                match locate(&t, x as f64 + 0.5, y as f64 + 0.5) {
                    Px::In(_) if !culled => {
                        texel = Some([f64::from(u8::from(front)), k as f64, 0.0, 1.0])
                    }
                    Px::Edge if !culled => texel = None,
                    _ => {}
                }
            }
            image.push(texel);
        }
        plan.add(
            draw(
                &format!("render.facing.{winding}.cull_{cull}"),
                library,
                "vert_plain",
                "frag_facing",
                &pos,
                &att,
                "rgba32float",
                json!({"winding": winding, "cull": cull}),
            )
            .output(image.output("c", Tolerance::exact())),
        );
    }
    if plan.has(SOURCE, "frag_barycentric") {
        let (positions, t) = perspective_triangle();
        let mut image = Image::new();
        for (x, y) in pixels() {
            image.push(match locate(&t, x as f64 + 0.5, y as f64 + 0.5) {
                Px::Edge => None,
                Px::Out => Some(CLEAR),
                Px::In(b) => {
                    let p = perspective(&t, b);
                    Some([p[0], p[1], p[2], 1.0])
                }
            });
        }
        plan.add(
            draw(
                "render.barycentric",
                library,
                "vert_plain",
                "frag_barycentric",
                &positions,
                &attrs,
                "rgba32float",
                json!({}),
            )
            .requires(&[], &["barycentrics"])
            .output(image.output("c", Tolerance::abs(1e-4))),
        );
    }
}

/// A window-filling draw whose fragments return buffer 0's texel for
/// their pixel.
fn full(name: &str, library: &str, fragment: &str, colors: &[f64], state: Value) -> Case {
    full_at(name, library, fragment, colors, 0.5, state)
}

/// `full` at a depth.
fn full_at(
    name: &str,
    library: &str,
    fragment: &str,
    colors: &[f64],
    depth: f64,
    state: Value,
) -> Case {
    let mut render = json!({"vertex_count": 3});
    for (k, v) in state.as_object().unwrap() {
        render[k] = v.clone();
    }
    Case::render(name, library, "vert_full", Some(fragment), render)
        .buffer(Buffer::data("colors", 0, f32s(colors)).stage("fragment"))
        .buffer(Buffer::data("width", 1, u32s(&[W])).stage("fragment"))
        .buffer(Buffer::data("depth", 2, f32s(&[depth])).stage("vertex"))
}

fn unorm_bytes(v: f64, bits: u32) -> u64 {
    (v.clamp(0.0, 1.0) * ((1u64 << bits) - 1) as f64).round() as u64
}

fn snorm_bits(v: f64, bits: u32) -> u64 {
    let max = ((1i64 << (bits - 1)) - 1) as f64;
    ((v.clamp(-1.0, 1.0) * max).round() as i64 as u64) & ((1u64 << bits) - 1)
}

fn srgb_encode(v: f64) -> f64 {
    let v = v.clamp(0.0, 1.0);
    if v <= 0.0031308 {
        v * 12.92
    } else {
        1.055 * libm::pow(v, 1.0 / 2.4) - 0.055
    }
}

/// Values a target of this resolution stores exactly: a lattice of its
/// steps, off the rounding midpoints by up to 0.3 of a step, with values
/// outside the range the format clamps to.
///
/// Vulkan lets a store round to either of the two nearest codes. A lane of
/// eight or more bits rounds to the nearest on every device, but NVIDIA's
/// ROP narrows 4-, 5- and 6-bit lanes from an 8-bit rounding, so those take
/// only values on the lattice, which each rule stores alike.
fn lattice(rng: &mut Random, steps: f64, signed: bool) -> f64 {
    let n = steps as u32;
    let k = if signed {
        rng.below(2 * n + 1) as f64 - steps
    } else {
        f64::from(rng.u32() % (n + 1))
    };
    let offset = rng.uniform(-0.3, 0.3);
    let v = if steps >= 255.0 {
        (k + offset) / steps
    } else {
        k / steps
    };
    match rng.u32() % 16 {
        0 if signed => -1.5,
        0 => -0.5,
        1 => 1.5,
        _ => f32r(v),
    }
}

/// The bytes rendering `values` (one RGBA texel each) stores in a format,
/// and the integer element type to compare them as.
fn store(format: &str, texel: [f64; 4]) -> (Vec<u8>, Dtype) {
    let [r, g, b, a] = texel;
    fn u16s(v: &[u64]) -> Vec<u8> {
        v.iter().flat_map(|&x| (x as u16).to_le_bytes()).collect()
    }
    match format {
        "rgba8unorm" => (
            [r, g, b, a].map(|v| unorm_bytes(v, 8) as u8).to_vec(),
            Dtype::U8,
        ),
        "bgra8unorm" => (
            [b, g, r, a].map(|v| unorm_bytes(v, 8) as u8).to_vec(),
            Dtype::U8,
        ),
        "rgba8unorm_srgb" => (
            [srgb_encode(r), srgb_encode(g), srgb_encode(b), a]
                .map(|v| unorm_bytes(v, 8) as u8)
                .to_vec(),
            Dtype::U8,
        ),
        "bgra8unorm_srgb" => (
            [srgb_encode(b), srgb_encode(g), srgb_encode(r), a]
                .map(|v| unorm_bytes(v, 8) as u8)
                .to_vec(),
            Dtype::U8,
        ),
        "rgba8snorm" => (
            [r, g, b, a].map(|v| snorm_bits(v, 8) as u8).to_vec(),
            Dtype::U8,
        ),
        "r8unorm" => (vec![unorm_bytes(r, 8) as u8], Dtype::U8),
        "r8snorm" => (vec![snorm_bits(r, 8) as u8], Dtype::U8),
        "rg8snorm" => (
            vec![snorm_bits(r, 8) as u8, snorm_bits(g, 8) as u8],
            Dtype::U8,
        ),
        "r16unorm" => (u16s(&[unorm_bytes(r, 16)]), Dtype::U16),
        "r16snorm" => (u16s(&[snorm_bits(r, 16)]), Dtype::U16),
        "rg16unorm" => (u16s(&[unorm_bytes(r, 16), unorm_bytes(g, 16)]), Dtype::U16),
        "rg16snorm" => (u16s(&[snorm_bits(r, 16), snorm_bits(g, 16)]), Dtype::U16),
        "r8unorm_srgb" => (vec![unorm_bytes(srgb_encode(r), 8) as u8], Dtype::U8),
        "rg8unorm_srgb" => (
            vec![
                unorm_bytes(srgb_encode(r), 8) as u8,
                unorm_bytes(srgb_encode(g), 8) as u8,
            ],
            Dtype::U8,
        ),
        // Packed 16-bit formats, lanes from the least significant bits.
        "abgr4unorm" => (
            u16s(&[unorm_bytes(a, 4)
                | unorm_bytes(b, 4) << 4
                | unorm_bytes(g, 4) << 8
                | unorm_bytes(r, 4) << 12]),
            Dtype::U16,
        ),
        "a1bgr5unorm" => (
            u16s(&[unorm_bytes(a, 1)
                | unorm_bytes(b, 5) << 1
                | unorm_bytes(g, 5) << 6
                | unorm_bytes(r, 5) << 11]),
            Dtype::U16,
        ),
        "bgr5a1unorm" => (
            u16s(&[unorm_bytes(b, 5)
                | unorm_bytes(g, 5) << 5
                | unorm_bytes(r, 5) << 10
                | unorm_bytes(a, 1) << 15]),
            Dtype::U16,
        ),
        "rg8unorm" => (
            vec![unorm_bytes(r, 8) as u8, unorm_bytes(g, 8) as u8],
            Dtype::U8,
        ),
        "rgba16unorm" => (u16s(&[r, g, b, a].map(|v| unorm_bytes(v, 16))), Dtype::U16),
        "rgba16snorm" => (u16s(&[r, g, b, a].map(|v| snorm_bits(v, 16))), Dtype::U16),
        "rgb10a2unorm" => {
            let q = [
                unorm_bytes(r, 10),
                unorm_bytes(g, 10),
                unorm_bytes(b, 10),
                unorm_bytes(a, 2),
            ];
            (
                u32s(&[(q[0] | q[1] << 10 | q[2] << 20 | q[3] << 30) as u32]),
                Dtype::U32,
            )
        }
        "bgr10a2unorm" => {
            let q = [
                unorm_bytes(b, 10),
                unorm_bytes(g, 10),
                unorm_bytes(r, 10),
                unorm_bytes(a, 2),
            ];
            (
                u32s(&[(q[0] | q[1] << 10 | q[2] << 20 | q[3] << 30) as u32]),
                Dtype::U32,
            )
        }
        "b5g6r5unorm" => (
            u16s(&[unorm_bytes(b, 5) | unorm_bytes(g, 6) << 5 | unorm_bytes(r, 5) << 11]),
            Dtype::U16,
        ),
        "rgba16float" => (floats(Dtype::F16, &[r, g, b, a]), Dtype::F16),
        "r16float" => (floats(Dtype::F16, &[r]), Dtype::F16),
        "rg16float" => (floats(Dtype::F16, &[r, g]), Dtype::F16),
        "rgba32float" => (f32s(&[r, g, b, a]), Dtype::F32),
        "r32float" => (f32s(&[r]), Dtype::F32),
        "rg32float" => (f32s(&[r, g]), Dtype::F32),
        "rg11b10float" => {
            let small = |v: f64, mantissa: u32| -> u32 {
                // Values chosen exact: a 5-bit exponent and this mantissa.
                if v <= 0.0 {
                    return 0;
                }
                let e = v.log2().floor() as i32;
                let m = ((v / 2f64.powi(e) - 1.0) * f64::from(1u32 << mantissa)).round() as u32;
                ((e + 15) as u32) << mantissa | m
            };
            (
                u32s(&[small(r, 6) | small(g, 6) << 11 | small(b, 5) << 22]),
                Dtype::U32,
            )
        }
        "bgr10_xr" | "bgr10_xr_srgb" => {
            let curve = format.ends_with("srgb");
            let code = |v: f64| xr_code(v, curve);
            (
                u32s(&[(code(b) | code(g) << 10 | code(r) << 20 | 3 << 30) as u32]),
                Dtype::U32,
            )
        }
        "bgra10_xr" | "bgra10_xr_srgb" => {
            let curve = format.ends_with("srgb");
            let codes = [
                xr_code(b, curve),
                xr_code(g, curve),
                xr_code(r, curve),
                xr_alpha_code(a),
            ];
            (u16s(&codes.map(|code| code << 6)), Dtype::U16)
        }
        // getBytes returns only the color plane: blue, green and red codes
        // from bit 0, the two top bits zero (alpha is the other plane's).
        "rgb10a8_2p_xr10" | "rgb10a8_2p_xr10_srgb" => {
            let curve = format.ends_with("srgb");
            let code = |v: f64| xr_code(v, curve);
            (
                u32s(&[(code(b) | code(g) << 10 | code(r) << 20) as u32]),
                Dtype::U32,
            )
        }
        _ => panic!("no store for {format}"),
    }
}

/// The code an extended-range target stores for a written value: its
/// nearest, through the sRGB curve mirrored below zero for the `sRGB`
/// variants, clamped to the ten bits.
fn xr_code(v: f64, srgb_curve: bool) -> u64 {
    let encoded = if !srgb_curve {
        v
    } else if v.abs() <= 0.0031308 {
        v * 12.92
    } else {
        v.signum() * (1.055 * libm::pow(v.abs(), 1.0 / 2.4) - 0.055)
    };
    (encoded * 510.0 + 384.0).round().clamp(0.0, 1023.0) as u64
}

/// An extended-range alpha's code, in [384, 894].
fn xr_alpha_code(a: f64) -> u64 {
    (a * 510.0 + 384.0).round().clamp(384.0, 894.0) as u64
}

/// A value to write to an extended-range target: mostly a code's value
/// (near it, for the linear variants), sometimes one beyond the range the
/// target clamps to. Alpha holds [0, 1].
fn xr_value(rng: &mut Random, srgb_curve: bool, lane: usize) -> f64 {
    if rng.u32().is_multiple_of(8) {
        return if rng.u32().is_multiple_of(2) {
            -2.0
        } else {
            2.0
        };
    }
    if lane == 3 {
        return xr(u64::from(384 + rng.u32() % 511), false);
    }
    let code = u64::from(rng.u32() % 1024);
    if srgb_curve {
        // An Apple GPU's curve misses the exact one by most of half a code.
        xr(code, true)
    } else {
        xr(code, false) + rng.uniform(-0.2, 0.2) / 510.0
    }
}

/// Values a float format stores exactly: halves, or for rg11b10 values
/// with that format's mantissas.
fn exact_float(format: &str, rng: &mut Random, lane: usize) -> f64 {
    match format {
        "rg11b10float" => {
            let mantissa = if lane == 2 { 5 } else { 6 };
            let e = rng.below(8) - 4;
            (1.0 + f64::from(rng.u32() % (1 << mantissa)) / f64::from(1u32 << mantissa))
                * 2f64.powi(e as i32)
        }
        "rgba32float" | "r32float" | "rg32float" => f32r(rng.uniform(-100.0, 100.0)),
        _ => f16r(rng.uniform(-8.0, 8.0)),
    }
}

fn targets(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(902);
    for format in [
        "rgba8unorm",
        "bgra8unorm",
        "rgba8unorm_srgb",
        "bgra8unorm_srgb",
        "rgba8snorm",
        "r8unorm",
        "rg8unorm",
        "rgba16unorm",
        "rgba16snorm",
        "rgb10a2unorm",
        "bgr10a2unorm",
        "b5g6r5unorm",
        "rgba16float",
        "r16float",
        "rg16float",
        "rgba32float",
        "r32float",
        "rg32float",
        "rg11b10float",
        "r8snorm",
        "rg8snorm",
        "r16unorm",
        "r16snorm",
        "rg16unorm",
        "rg16snorm",
        "r8unorm_srgb",
        "rg8unorm_srgb",
        "abgr4unorm",
        "a1bgr5unorm",
        "bgr5a1unorm",
        "bgr10_xr",
        "bgr10_xr_srgb",
        "bgra10_xr",
        "bgra10_xr_srgb",
        "rgb10a8_2p_xr10",
        "rgb10a8_2p_xr10_srgb",
    ] {
        let float = format.contains("float");
        let extended = format.contains("_xr");
        let snorm = format.contains("snorm");
        let steps = |lane: usize| match format {
            "b5g6r5unorm" if lane == 1 => 63.0,
            "b5g6r5unorm" => 31.0,
            "abgr4unorm" => 15.0,
            "a1bgr5unorm" | "bgr5a1unorm" if lane == 3 => 1.0,
            "a1bgr5unorm" | "bgr5a1unorm" => 31.0,
            f if f.contains("10a2") && lane == 3 => 3.0,
            f if f.contains("10a2") => 1023.0,
            f if f.contains("16") && snorm => 32767.0,
            f if f.contains("16") => 65535.0,
            _ if snorm => 127.0,
            _ => 255.0,
        };
        let texels: Vec<[f64; 4]> = (0..W * H)
            .map(|_| {
                std::array::from_fn(|lane| {
                    if extended {
                        xr_value(&mut rng, format.ends_with("srgb"), lane)
                    } else if float {
                        exact_float(format, &mut rng, lane)
                    } else {
                        lattice(&mut rng, steps(lane), snorm)
                    }
                })
            })
            .collect();
        let mut expected = vec![];
        let mut dtype = Dtype::U8;
        for t in &texels {
            let (bytes, d) = store(format, *t);
            expected.extend(bytes);
            dtype = d;
        }
        // sRGB encoding is approximate; extended-range values lie at
        // their codes, or clamp.
        let tol = if format.contains("srgb") && !extended {
            Tolerance::units(1.0)
        } else {
            Tolerance::exact()
        };
        plan.add(
            full(
                &format!("render.target.{format}"),
                library,
                "frag_color",
                &texels.concat(),
                json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}]}),
            )
            .texture(target("c", format))
            .output(Output::new("c", dtype, tol.clone()).expect(expected, tol)),
        );
    }
    // Integer targets: in-range values stored as they are.
    for (format, lanes, bits, signed) in [
        ("r8uint", 1, 8, false),
        ("r8sint", 1, 8, true),
        ("rg8uint", 2, 8, false),
        ("rg8sint", 2, 8, true),
        ("rgba8uint", 4, 8, false),
        ("rgba8sint", 4, 8, true),
        ("r16uint", 1, 16, false),
        ("r16sint", 1, 16, true),
        ("rg16uint", 2, 16, false),
        ("rg16sint", 2, 16, true),
        ("rgba16uint", 4, 16, false),
        ("rgba16sint", 4, 16, true),
        ("r32uint", 1, 32, false),
        ("r32sint", 1, 32, true),
        ("rg32uint", 2, 32, false),
        ("rg32sint", 2, 32, true),
        ("rgba32uint", 4, 32, false),
        ("rgba32sint", 4, 32, true),
        ("rgb10a2uint", 4, 10, false),
    ] {
        let width = |lane: usize| {
            if format == "rgb10a2uint" && lane == 3 {
                2
            } else {
                bits
            }
        };
        let texels: Vec<[i64; 4]> = (0..W * H)
            .map(|_| {
                std::array::from_fn(|lane| {
                    let w = width(lane);
                    let v = i64::from(rng.u32()) & ((1i64 << w) - 1);
                    if signed && v >= 1 << (w - 1) {
                        v - (1 << w)
                    } else {
                        v
                    }
                })
            })
            .collect();
        let shader: Vec<u8> = texels
            .iter()
            .flatten()
            .flat_map(|&v| (v as i32).to_le_bytes())
            .collect();
        let stored: Vec<i128> = texels
            .iter()
            .flat_map(|t| t[..lanes].iter().map(|&v| i128::from(v)))
            .collect();
        let (dtype, bytes) = if format == "rgb10a2uint" {
            let words: Vec<u32> = texels
                .iter()
                .map(|t| (t[0] | t[1] << 10 | t[2] << 20 | t[3] << 30) as u32)
                .collect();
            (Dtype::U32, u32s(&words))
        } else {
            let dtype = match (bits, signed) {
                (8, false) => Dtype::U8,
                (8, true) => Dtype::I8,
                (16, false) => Dtype::U16,
                (16, true) => Dtype::I16,
                (_, false) => Dtype::U32,
                _ => Dtype::I32,
            };
            (dtype, ints(dtype, &stored))
        };
        let fragment = if signed {
            "frag_color_int"
        } else {
            "frag_color_uint"
        };
        plan.add(
            Case::render(
                &format!("render.target.{format}"),
                library,
                "vert_full",
                Some(fragment),
                json!({"vertex_count": 3, "colors": [{"texture": "c", "clear": [0, 0, 0, 0]}]}),
            )
            .buffer(Buffer::data("colors", 0, shader).stage("fragment"))
            .buffer(Buffer::data("width", 1, u32s(&[W])).stage("fragment"))
            .buffer(Buffer::data("depth", 2, f32s(&[0.5])).stage("vertex"))
            .texture(target("c", format))
            .output(Output::new("c", dtype, Tolerance::exact()).expect_same(bytes)),
        );
    }
    // A half4 fragment output.
    let texels: Vec<f64> = (0..W * H * 4)
        .map(|_| f16r(rng.uniform(-8.0, 8.0)))
        .collect();
    plan.add(
        full(
            "render.target.half_output",
            library,
            "frag_color_half",
            &texels,
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}]}),
        )
        .texture(target("c", "rgba16float"))
        .output(
            Output::new("c", Dtype::F16, Tolerance::exact())
                .expect_same(floats(Dtype::F16, &texels)),
        ),
    );
    // Multiple render targets of four kinds.
    let values: Vec<[f64; 4]> = (0..W * H)
        .map(|_| std::array::from_fn(|_| f32r(f64::from(rng.u32() % 256) / 255.0)))
        .collect();
    let mut outs: [Vec<u8>; 4] = Default::default();
    for (i, v) in values.iter().enumerate() {
        outs[0].extend(v.map(|x| unorm_bytes(x, 8) as u8));
        outs[1].extend(
            v.iter()
                .flat_map(|&x| (f32r(x * 65535.0).trunc() as u16).to_le_bytes()),
        );
        outs[2].extend(floats(Dtype::F16, &v.map(|x| f32r(x * 2.0 - 1.0))));
        outs[3].extend((i as i32 - 128).to_le_bytes());
    }
    let [o0, o1, o2, o3] = outs;
    plan.add(
        full(
            "render.mrt",
            library,
            "frag_mrt",
            &values.concat(),
            json!({"colors": [
            {"texture": "c0", "clear": [0, 0, 0, 0]}, {"texture": "c1", "clear": [0, 0, 0, 0]},
            {"texture": "c2", "clear": [0, 0, 0, 0]}, {"texture": "c3", "clear": [0, 0, 0, 0]}]}),
        )
        .texture(target("c0", "rgba8unorm"))
        .texture(target("c1", "rgba16uint"))
        .texture(target("c2", "rgba16float"))
        .texture(target("c3", "r32sint"))
        .output(Output::new("c0", Dtype::U8, Tolerance::exact()).expect_same(o0))
        .output(Output::new("c1", Dtype::U16, Tolerance::exact()).expect_same(o1))
        .output(Output::new("c2", Dtype::F16, Tolerance::exact()).expect_same(o2))
        .output(Output::new("c3", Dtype::I32, Tolerance::exact()).expect_same(o3)),
    );
    // Discarded fragments leave the target as it was.
    let values: Vec<[f64; 4]> = (0..W * H)
        .map(|_| std::array::from_fn(|_| f32r(rng.uniform(0.0, 1.0))))
        .collect();
    let clear = [0.125, 0.25, 0.375, 0.5];
    let expected: Vec<f64> = values
        .iter()
        .flat_map(|v| if v[3] < 0.5 { clear } else { *v })
        .collect();
    plan.add(
        full(
            "render.discard",
            library,
            "frag_discard",
            &values.concat(),
            json!({"colors": [{"texture": "c", "clear": clear}]}),
        )
        .texture(target("c", "rgba32float"))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
    );
    // A scissor rectangle bounds every write.
    let values: Vec<f64> = (0..W * H * 4)
        .map(|_| f32r(rng.uniform(0.0, 1.0)))
        .collect();
    let scissor = [3u32, 2, 7, 9];
    let expected: Vec<f64> = pixels()
        .flat_map(|(x, y)| {
            let inside = (scissor[0]..scissor[0] + scissor[2]).contains(&x)
                && (scissor[1]..scissor[1] + scissor[3]).contains(&y);
            let i = ((y * W + x) * 4) as usize;
            if inside {
                [values[i], values[i + 1], values[i + 2], values[i + 3]]
            } else {
                [0.0; 4]
            }
        })
        .collect();
    plan.add(
        full(
            "render.scissor",
            library,
            "frag_color",
            &values,
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "scissor": scissor}),
        )
        .texture(target("c", "rgba32float"))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
    );
}

/// A blend factor's value for the RGB (alpha = false) or alpha lanes.
fn factor(
    name: &str,
    alpha: bool,
    s: [f64; 4],
    s1: [f64; 4],
    d: [f64; 4],
    c: [f64; 4],
) -> [f64; 3] {
    let rgb = |v: [f64; 4]| if alpha { [v[3]; 3] } else { [v[0], v[1], v[2]] };
    let a = |v: f64| [v; 3];
    let inv = |v: [f64; 3]| v.map(|x| 1.0 - x);
    match name {
        "zero" => a(0.0),
        "one" => a(1.0),
        "source_color" => rgb(s),
        "one_minus_source_color" => inv(rgb(s)),
        "source_alpha" => a(s[3]),
        "one_minus_source_alpha" => a(1.0 - s[3]),
        "destination_color" => rgb(d),
        "one_minus_destination_color" => inv(rgb(d)),
        "destination_alpha" => a(d[3]),
        "one_minus_destination_alpha" => a(1.0 - d[3]),
        "source_alpha_saturated" => a(if alpha { 1.0 } else { s[3].min(1.0 - d[3]) }),
        "blend_color" => rgb(c),
        "one_minus_blend_color" => inv(rgb(c)),
        "blend_alpha" => a(c[3]),
        "one_minus_blend_alpha" => a(1.0 - c[3]),
        "source1_color" => rgb(s1),
        "one_minus_source1_color" => inv(rgb(s1)),
        "source1_alpha" => a(s1[3]),
        "one_minus_source1_alpha" => a(1.0 - s1[3]),
        _ => panic!("blend factor {name}"),
    }
}

#[derive(Clone)]
struct Blend {
    rgb: &'static str,
    alpha: &'static str,
    src_rgb: &'static str,
    dst_rgb: &'static str,
    src_alpha: &'static str,
    dst_alpha: &'static str,
}

impl Blend {
    fn simple(op: &'static str, src: &'static str, dst: &'static str) -> Self {
        Self {
            rgb: op,
            alpha: op,
            src_rgb: src,
            dst_rgb: dst,
            src_alpha: src,
            dst_alpha: dst,
        }
    }

    fn json(&self) -> Value {
        json!({"rgb": self.rgb, "alpha": self.alpha, "src_rgb": self.src_rgb, "dst_rgb": self.dst_rgb,
               "src_alpha": self.src_alpha, "dst_alpha": self.dst_alpha})
    }

    fn apply(&self, s: [f64; 4], s1: [f64; 4], d: [f64; 4], c: [f64; 4], clamp: bool) -> [f64; 4] {
        let unit = |v: [f64; 4]| {
            if clamp {
                v.map(|x| x.clamp(0.0, 1.0))
            } else {
                v
            }
        };
        let (s, s1, d, c) = (unit(s), unit(s1), d, unit(c));
        let fs = factor(self.src_rgb, false, s, s1, d, c);
        let fd = factor(self.dst_rgb, false, s, s1, d, c);
        let fsa = factor(self.src_alpha, true, s, s1, d, c)[0];
        let fda = factor(self.dst_alpha, true, s, s1, d, c)[0];
        let op = |op: &str, a: f64, fa: f64, b: f64, fb: f64| match op {
            "add" => a * fa + b * fb,
            "subtract" => a * fa - b * fb,
            "reverse_subtract" => b * fb - a * fa,
            "min" => a.min(b),
            _ => a.max(b),
        };
        let out = [
            op(self.rgb, s[0], fs[0], d[0], fd[0]),
            op(self.rgb, s[1], fs[1], d[1], fd[1]),
            op(self.rgb, s[2], fs[2], d[2], fd[2]),
            op(self.alpha, s[3], fsa, d[3], fda),
        ];
        unit(out)
    }

    /// The least and greatest results over d of a source that may carry
    /// half a unit of an 8-bit target in each component, in the encoded
    /// space for an sRGB target's color: blending need be no more precise
    /// than the destination. The blend is monotonic in each component, so
    /// the corners of that box bound it.
    fn bounds(&self, s: [f64; 4], d: [f64; 4], c: [f64; 4], srgb_target: bool) -> [[f64; 4]; 2] {
        const HALF: f64 = 0.5 / 255.0;
        let mut bounds = [[f64::INFINITY; 4], [f64::NEG_INFINITY; 4]];
        for corner in 0..81u32 {
            let s: [f64; 4] = std::array::from_fn(|k| {
                let e = f64::from(corner / 3u32.pow(k as u32) % 3) - 1.0;
                let v = s[k].clamp(0.0, 1.0);
                if srgb_target && k < 3 {
                    srgb((srgb_encode(v) + e * HALF).clamp(0.0, 1.0))
                } else {
                    (v + e * HALF).clamp(0.0, 1.0)
                }
            });
            let out = self.apply(s, s, d, c, true);
            for k in 0..4 {
                bounds[0][k] = bounds[0][k].min(out[k]);
                bounds[1][k] = bounds[1][k].max(out[k]);
            }
        }
        bounds
    }
}

const FACTORS: [&str; 15] = [
    "zero",
    "one",
    "source_color",
    "one_minus_source_color",
    "source_alpha",
    "one_minus_source_alpha",
    "destination_color",
    "one_minus_destination_color",
    "destination_alpha",
    "one_minus_destination_alpha",
    "source_alpha_saturated",
    "blend_color",
    "one_minus_blend_color",
    "blend_alpha",
    "one_minus_blend_alpha",
];

fn blending(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(903);
    let blend_color = [0.25, 0.5, 0.75, 0.625];
    let n = (W * H) as usize;
    let halves = |rng: &mut Random, lo: f64, hi: f64| -> Vec<[f64; 4]> {
        (0..n)
            .map(|_| std::array::from_fn(|_| f16r(rng.uniform(lo, hi))))
            .collect()
    };
    // Every case but dual-source blending is repeated with the target's
    // value also read in the shader, which leaves the fixed-function
    // blend and write mask to the read's ordered write.
    let mut read: Vec<String> = vec![];
    let mut blends: Vec<(String, Blend)> = vec![];
    for f in FACTORS {
        blends.push((format!("src.{f}"), Blend::simple("add", f, "one")));
        blends.push((format!("dst.{f}"), Blend::simple("add", "one", f)));
    }
    for op in ["add", "subtract", "reverse_subtract", "min", "max"] {
        blends.push((
            format!("op.{op}"),
            Blend::simple(op, "source_alpha", "one_minus_source_alpha"),
        ));
    }
    blends.push((
        "separate".into(),
        Blend {
            rgb: "subtract",
            alpha: "max",
            src_rgb: "destination_alpha",
            dst_rgb: "source_color",
            src_alpha: "zero",
            dst_alpha: "one",
        },
    ));
    // Half-float target: the blend in at least half precision.
    for (label, blend) in &blends {
        let (s, d) = (halves(&mut rng, 0.0, 2.0), halves(&mut rng, 0.0, 1.0));
        let expected: Vec<f64> = s
            .iter()
            .zip(&d)
            .flat_map(|(&s, &d)| blend.apply(s, s, d, blend_color, false))
            .collect();
        let tol = Tolerance::ulp(3.0).with_abs(2f64.powi(-12));
        let name = format!("render.blend.rgba16float.{label}");
        // Two devices, each within the bound of the exact blend.
        let cross = tol.doubled();
        read.push(name.clone());
        plan.add(
            full(&name, library, "frag_color", &s.concat(),
                 json!({"colors": [{"texture": "c", "blend": blend.json()}], "blend_color": blend_color}))
            .texture(target("c", "rgba16float").data(floats(Dtype::F16, &d.concat())))
            .output(Output::new("c", Dtype::F16, cross).expect(floats(Dtype::F16, &expected), tol)),
        );
    }
    // Normalized targets clamp sources, factors and results; sRGB targets
    // blend in linear space.
    for format in [
        "rgba8unorm",
        "rgba8unorm_srgb",
        "bgra8unorm",
        "bgra8unorm_srgb",
    ] {
        for (label, blend) in blends.iter().filter(|(l, _)| {
            matches!(
                l.as_str(),
                "src.source_alpha"
                    | "dst.one_minus_source_alpha"
                    | "src.destination_color"
                    | "op.add"
                    | "op.subtract"
                    | "op.reverse_subtract"
                    | "op.min"
                    | "op.max"
                    | "src.blend_color"
                    | "src.source_alpha_saturated"
            )
        }) {
            let s: Vec<[f64; 4]> = (0..n)
                .map(|_| std::array::from_fn(|_| f32r(rng.uniform(-0.25, 1.25))))
                .collect();
            let stored: Vec<[u8; 4]> = (0..n)
                .map(|_| std::array::from_fn(|_| (rng.u32() % 256) as u8))
                .collect();
            let srgb_target = format.ends_with("srgb");
            let bgra = format.starts_with("bgra");
            // A texel's channels in RGBA order, from its bytes.
            let decode = |b: [u8; 4]| {
                let b = if bgra { [b[2], b[1], b[0], b[3]] } else { b };
                let v = b.map(|x| f64::from(x) / 255.0);
                if srgb_target {
                    [srgb(v[0]), srgb(v[1]), srgb(v[2]), v[3]]
                } else {
                    v
                }
            };
            let (mut expected, mut lows, mut highs) = (vec![], vec![], vec![]);
            for (s, b) in s.iter().zip(&stored) {
                let out = blend.apply(*s, *s, decode(*b), blend_color, true);
                expected.extend(store(format, out).0);
                let [low, high] = blend.bounds(*s, decode(*b), blend_color, srgb_target);
                lows.extend(store(format, low).0);
                highs.extend(store(format, high).0);
            }
            // Any result within the bounds, by alternatives a tolerance
            // apart.
            let tol = Tolerance::units(1.0);
            let widest = lows
                .iter()
                .zip(&highs)
                .map(|(l, h)| h - l)
                .max()
                .unwrap_or(0);
            let mut output = Output::new("c", Dtype::U8, tol.clone()).expect(expected, tol);
            for step in 0..=widest.div_ceil(3) {
                let at = |(&l, &h): (&u8, &u8)| l.saturating_add(step.saturating_mul(3)).min(h);
                output = output.expect_alternative(lows.iter().zip(&highs).map(at).collect());
            }
            let name = format!("render.blend.{format}.{label}");
            read.push(name.clone());
            let case = |name: &str, output: Output| {
                full(name, library, "frag_color", &s.concat(),
                     json!({"colors": [{"texture": "c", "blend": blend.json()}], "blend_color": blend_color}))
                .texture(target("c", format).data(stored.concat()))
                .output(output)
            };
            plan.add(case(&name, output.clone().judged_by_expectation()));
            // The same blend against the Mac's rounding within a unit,
            // reported only: Apple GPUs blend the float source, NVIDIA's
            // blend unit the source at the target's 8 bits, which the band
            // above allows (a known hardware precision difference).
            plan.add(
                case(&format!("{name}.reference"), output)
                    .informational()
                    .note("8-bit blends take the source at the target's precision"),
            );
        }
    }
    // Dual-source blending: the second output as a factor.
    let source1 = [
        "source1_color",
        "one_minus_source1_color",
        "source1_alpha",
        "one_minus_source1_alpha",
    ];
    for f in source1 {
        let (s, s1, d) = (
            halves(&mut rng, 0.0, 1.0),
            halves(&mut rng, 0.0, 1.0),
            halves(&mut rng, 0.0, 1.0),
        );
        let blend = Blend::simple("add", "source_alpha", f);
        let expected: Vec<f64> = (0..n)
            .flat_map(|i| blend.apply(s[i], s1[i], d[i], blend_color, false))
            .collect();
        let tol = Tolerance::ulp(3.0).with_abs(2f64.powi(-12));
        plan.add(
            full(
                &format!("render.blend.dual_source.{f}"),
                library,
                "frag_dual",
                &s.concat(),
                json!({"colors": [{"texture": "c", "blend": blend.json()}]}),
            )
            .buffer(Buffer::data("second", 3, f32s(&s1.concat())).stage("fragment"))
            .texture(target("c", "rgba16float").data(floats(Dtype::F16, &d.concat())))
            .output(
                Output::new("c", Dtype::F16, tol.clone())
                    .expect(floats(Dtype::F16, &expected), tol),
            ),
        );
    }
    // Write masks, with and without blending.
    for (mask, blended) in [
        ("", false),
        ("r", false),
        ("ga", false),
        ("rgb", false),
        ("rb", true),
        ("a", true),
    ] {
        let (s, d) = (halves(&mut rng, 0.0, 1.0), halves(&mut rng, 0.0, 1.0));
        let blend = Blend::simple("add", "one", "one");
        let expected: Vec<f64> = (0..n)
            .flat_map(|i| {
                let v = if blended {
                    blend.apply(s[i], s[i], d[i], blend_color, false)
                } else {
                    s[i]
                };
                [0, 1, 2, 3].map(|k| {
                    if mask.contains(["r", "g", "b", "a"][k]) {
                        v[k]
                    } else {
                        d[i][k]
                    }
                })
            })
            .collect();
        let mut color = json!({"texture": "c", "write_mask": mask});
        if blended {
            color["blend"] = blend.json();
        }
        let tol = Tolerance::ulp(1.0);
        let name = format!(
            "render.write_mask.{}{}",
            if mask.is_empty() { "none" } else { mask },
            if blended { ".blended" } else { "" }
        );
        read.push(name.clone());
        plan.add(
            full(
                &name,
                library,
                "frag_color",
                &s.concat(),
                json!({"colors": [color]}),
            )
            .texture(target("c", "rgba16float").data(floats(Dtype::F16, &d.concat())))
            .output(
                Output::new("c", Dtype::F16, tol.clone())
                    .expect(floats(Dtype::F16, &expected), tol),
            ),
        );
    }
    for name in &read {
        plan.vary(name, "framebuffer_read", |case| {
            case.set("fragment", "frag_color_read")
                .requires(&["apple3"], &[])
        });
    }
}

fn compare(function: &str, a: f64, b: f64) -> bool {
    match function {
        "never" => false,
        "less" => a < b,
        "equal" => a == b,
        "less_equal" => a <= b,
        "greater" => a > b,
        "not_equal" => a != b,
        "greater_equal" => a >= b,
        _ => true,
    }
}

const COMPARES: [&str; 8] = [
    "never",
    "less",
    "equal",
    "less_equal",
    "greater",
    "not_equal",
    "greater_equal",
    "always",
];

fn depth(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(904);
    let n = (W * H) as usize;
    let z = 0.5;
    // Stored depths on a 1/64 lattice, a quarter of them equal to z.
    let stored = |rng: &mut Random| -> Vec<f64> {
        (0..n)
            .map(|_| {
                if rng.u32().is_multiple_of(4) {
                    z
                } else {
                    f64::from(rng.u32() % 65) / 64.0
                }
            })
            .collect()
    };
    let colors = |rng: &mut Random| -> Vec<f64> {
        (0..n * 4).map(|_| f32r(rng.uniform(0.0, 1.0))).collect()
    };
    for function in COMPARES {
        for write in [true, false] {
            let (d, c) = (stored(&mut rng), colors(&mut rng));
            let mut color = vec![];
            let mut depth = vec![];
            for i in 0..n {
                let pass = compare(function, z, d[i]);
                color.extend(if pass {
                    [c[4 * i], c[4 * i + 1], c[4 * i + 2], c[4 * i + 3]]
                } else {
                    [0.0; 4]
                });
                depth.push(if pass && write { z } else { d[i] });
            }
            plan.add(
                full(
                    &format!(
                        "render.depth.{function}{}",
                        if write { "" } else { ".no_write" }
                    ),
                    library,
                    "frag_color",
                    &c,
                    json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                            "depth": {"texture": "d", "compare": function, "write": write}}),
                )
                .texture(target("c", "rgba32float"))
                .texture(target("d", "depth32float").data(f32s(&d)))
                .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&color)))
                .output(Output::new("d", Dtype::F32, Tolerance::exact()).expect_same(f32s(&depth))),
            );
        }
    }
    // Fragment depth: any value, or one the qualifier bounds by the
    // interpolated depth; written depth stays within the viewport's range.
    for (fragment, label) in [
        ("frag_depth", "any"),
        ("frag_depth_greater", "greater"),
        ("frag_depth_less", "less"),
    ] {
        let d = stored(&mut rng);
        let c: Vec<f64> = (0..n)
            .flat_map(|_| {
                let x = if rng.u32().is_multiple_of(8) {
                    [-0.5, 1.5][rng.below(2) as usize]
                } else {
                    f64::from(rng.u32() % 65) / 64.0 + 1.0 / 128.0
                };
                [x, 0.0, 0.0, 0.0]
            })
            .collect();
        let mut depth = vec![];
        let mut color = vec![];
        for i in 0..n {
            let written = match label {
                "greater" => c[4 * i].max(z),
                "less" => c[4 * i].min(z),
                _ => c[4 * i],
            }
            .clamp(0.0, 1.0);
            let pass = written < d[i];
            depth.push(if pass { written } else { d[i] });
            color.extend(if pass { [1.0; 4] } else { [0.0; 4] });
        }
        plan.add(
            full(&format!("render.depth.output.{label}"), library, fragment, &c,
                 json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "depth": {"texture": "d", "compare": "less"}}))
            .texture(target("c", "rgba32float"))
            .texture(target("d", "depth32float").data(f32s(&d)))
            .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&color)))
            .output(Output::new("d", Dtype::F32, Tolerance::exact()).expect_same(f32s(&depth))),
        );
    }
    // A 16-bit normalized depth target, values clear of the rounding.
    let zq = 16384u16;
    let z16 = f32r(f64::from(zq) / 65535.0);
    let d: Vec<u16> = (0..n)
        .map(|_| {
            if rng.u32().is_multiple_of(4) {
                zq
            } else {
                (rng.u32() % 65536) as u16
            }
        })
        .map(|v| {
            if v != zq && v.abs_diff(zq) < 3 {
                zq + 3
            } else {
                v
            }
        })
        .collect();
    let c = colors(&mut rng);
    let mut color = vec![];
    let mut depth: Vec<i128> = vec![];
    for i in 0..n {
        let pass = zq <= d[i];
        color.extend(if pass {
            [c[4 * i], c[4 * i + 1], c[4 * i + 2], c[4 * i + 3]]
        } else {
            [0.0; 4]
        });
        depth.push(i128::from(if pass { zq } else { d[i] }));
    }
    plan.add(
        full_at("render.depth.depth16unorm", library, "frag_color", &c, z16,
             json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "depth": {"texture": "d", "compare": "less_equal"}}))
        .texture(target("c", "rgba32float"))
        .texture(target("d", "depth16unorm").data(ints(Dtype::U16, &d.iter().map(|&v| i128::from(v)).collect::<Vec<_>>())))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&color)))
        .output(Output::new("d", Dtype::U16, Tolerance::exact()).expect_same(ints(Dtype::U16, &depth))),
    );
    // Beyond the far plane: clipped, or with depth clamping kept at 1.
    for clamp in [false, true] {
        let d = vec![0.75; n];
        let c = colors(&mut rng);
        let color: Vec<f64> = if clamp { c.clone() } else { vec![0.0; n * 4] };
        let depth = if clamp { vec![1.0; n] } else { d.clone() };
        let mut state = json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "depth": {"texture": "d", "compare": "always"}});
        if clamp {
            state["depth_clip"] = "clamp".into();
        }
        plan.add(
            full_at(
                &format!(
                    "render.depth.far.{}",
                    if clamp { "clamped" } else { "clipped" }
                ),
                library,
                "frag_color",
                &c,
                1.5,
                state,
            )
            .texture(target("c", "rgba32float"))
            .texture(target("d", "depth32float").data(f32s(&d)))
            .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&color)))
            .output(Output::new("d", Dtype::F32, Tolerance::exact()).expect_same(f32s(&depth))),
        );
    }
    // Constant depth bias on a float target moves depth by the bias in
    // units of the depth's resolution, 2^(e - 23) for the exponent e of the
    // primitive's depth, within half that; a clamp bounds it exactly.
    for (bias, z, slope, clamp) in [
        (64.0, 0.5, 0.0, 0.0),
        (-300.0, 0.75, 0.0, 0.0),
        (1e6, 0.5, 0.0, 0.01),
        (5.0, 0.125, 2.0, 0.0),
    ] {
        // frexp's exponent is one above z's: 0.5 = 0.5 * 2^0.
        let mut e = 0;
        libm::frexp(z, &mut e);
        // The window-filling triangle has no depth slope, so the slope
        // factor adds nothing.
        let mut offset = bias * 2f64.powi(e - 1 - 23);
        if clamp > 0.0 {
            offset = offset.min(clamp);
        }
        let c = colors(&mut rng);
        plan.add(
            full_at(&format!("render.depth.bias.{bias}.{z}.{slope}.{clamp}"), library, "frag_color", &c, z,
                 json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "depth": {"texture": "d", "compare": "always"},
                        "depth_bias": [bias, slope, clamp]}))
            .texture(target("c", "rgba32float"))
            .texture(target("d", "depth32float").data(f32s(&vec![1.0; n])))
            .output({
                let tol = if clamp > 0.0 { Tolerance::ulp(1.0) } else { Tolerance::abs(offset.abs() / 2.0) };
                Output::new("d", Dtype::F32, tol.clone()).expect(f32s(&vec![f32r((z + offset).clamp(0.0, 1.0)); n]), tol)
            }),
        );
    }
}

fn stencil_op(op: &str, s: u8, reference: u8) -> u8 {
    match op {
        "zero" => 0,
        "replace" => reference,
        "increment_clamp" => s.saturating_add(1),
        "decrement_clamp" => s.saturating_sub(1),
        "invert" => !s,
        "increment_wrap" => s.wrapping_add(1),
        "decrement_wrap" => s.wrapping_sub(1),
        _ => s,
    }
}

const STENCIL_OPS: [&str; 8] = [
    "keep",
    "zero",
    "replace",
    "increment_clamp",
    "decrement_clamp",
    "invert",
    "increment_wrap",
    "decrement_wrap",
];

#[derive(Clone, Copy)]
struct Face {
    compare: &'static str,
    fail: &'static str,
    depth_fail: &'static str,
    pass: &'static str,
    read_mask: u8,
    write_mask: u8,
}

impl Face {
    fn json(&self) -> Value {
        json!({"compare": self.compare, "fail": self.fail, "depth_fail": self.depth_fail, "pass": self.pass,
               "read_mask": self.read_mask, "write_mask": self.write_mask})
    }

    /// The stored value after a fragment, and whether its color is written.
    fn apply(&self, s: u8, reference: u8, depth_pass: bool) -> (u8, bool) {
        let pass = compare(
            self.compare,
            f64::from(reference & self.read_mask),
            f64::from(s & self.read_mask),
        );
        let op = if !pass {
            self.fail
        } else if !depth_pass {
            self.depth_fail
        } else {
            self.pass
        };
        let value = stencil_op(op, s, reference);
        (
            (s & !self.write_mask) | (value & self.write_mask),
            pass && depth_pass,
        )
    }
}

fn stencil(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(905);
    let n = (W * H) as usize;
    let reference = 0x5Au8;
    let face = |compare, fail, depth_fail, pass| Face {
        compare,
        fail,
        depth_fail,
        pass,
        read_mask: 0xFF,
        write_mask: 0xFF,
    };
    let mut faces: Vec<(String, Face, Option<Face>, bool)> = vec![];
    for op in STENCIL_OPS {
        faces.push((
            format!("pass.{op}"),
            face("always", "keep", "keep", op),
            None,
            false,
        ));
        faces.push((
            format!("fail.{op}"),
            face("never", op, "keep", "keep"),
            None,
            false,
        ));
        faces.push((
            format!("depth_fail.{op}"),
            face("always", "keep", op, "keep"),
            None,
            false,
        ));
    }
    for c in COMPARES {
        faces.push((
            format!("compare.{c}"),
            face(c, "zero", "keep", "replace"),
            None,
            false,
        ));
    }
    faces.push((
        "masks".into(),
        Face {
            read_mask: 0x0F,
            write_mask: 0x3C,
            ..face("less_equal", "invert", "keep", "increment_wrap")
        },
        None,
        false,
    ));
    // The window-filling triangle is front-facing; clockwise winding makes
    // it a back face, selecting the back state and reference.
    faces.push((
        "front_back.front".into(),
        face("always", "keep", "keep", "replace"),
        Some(face("always", "keep", "keep", "zero")),
        false,
    ));
    faces.push((
        "front_back.back".into(),
        face("always", "keep", "keep", "replace"),
        Some(face("always", "keep", "keep", "invert")),
        true,
    ));
    for (label, front, back, back_facing) in faces {
        let s: Vec<u8> = (0..n)
            .map(|i| {
                if i % 5 == 0 {
                    reference
                } else {
                    (rng.u32() % 256) as u8
                }
            })
            .collect();
        // Depth passes (stored 1, z 0.5 under less) except in a quarter.
        let d: Vec<f64> = (0..n)
            .map(|i| if i % 4 == 1 { 0.25 } else { 1.0 })
            .collect();
        let c: Vec<f64> = (0..n * 4).map(|_| f32r(rng.uniform(0.0, 1.0))).collect();
        let (active, back_reference) = if back_facing {
            (back.unwrap(), 0xA5u8)
        } else {
            (front, 0xA5)
        };
        let used_reference = if back_facing {
            back_reference
        } else {
            reference
        };
        let mut stencil_out = vec![];
        let mut color = vec![];
        for i in 0..n {
            let (value, written) = active.apply(s[i], used_reference, 0.5 < d[i]);
            stencil_out.push(value);
            color.extend(if written {
                [c[4 * i], c[4 * i + 1], c[4 * i + 2], c[4 * i + 3]]
            } else {
                [0.0; 4]
            });
        }
        let mut st = front.json();
        st["texture"] = "ds".into();
        st["reference"] = reference.into();
        st["reference_back"] = back_reference.into();
        if let Some(b) = back {
            st["front"] = front.json();
            st["back"] = b.json();
        }
        let mut state = json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                               "depth": {"texture": "ds", "compare": "less", "write": false}, "stencil": st});
        if back_facing {
            state["winding"] = "cw".into();
        }
        plan.add(
            full(
                &format!("render.stencil.{label}"),
                library,
                "frag_color",
                &c,
                state,
            )
            .texture(
                target("ds", "depth32float_stencil8")
                    .data(f32s(&d))
                    .stencil(s),
            )
            .texture(target("c", "rgba32float"))
            .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&color)))
            .output(
                Output::new("ds", Dtype::U8, Tolerance::exact())
                    .set("aspect", "stencil")
                    .set("as", "stencil")
                    .expect_same(stencil_out),
            ),
        );
    }
}

/// The samples of the standard 4x pattern a triangle covers in a pixel, or
/// None when one lies on an edge.
fn coverage(t: &[Win; 3], x: u32, y: u32) -> Option<u32> {
    let mut count = 0;
    for &(sx, sy) in &SAMPLES4 {
        match locate(t, x as f64 + sx, y as f64 + sy) {
            Px::In(_) => count += 1,
            Px::Edge => return None,
            Px::Out => {}
        }
    }
    Some(count)
}

fn multisampling(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(906);
    let full_vp = [0.0, 0.0, W as f64, H as f64];
    let ms = || {
        Texture::new("ms", "rgba8unorm", "2d_ms", [W, H, 1])
            .samples(4)
            .usage(&["render"])
    };
    let state =
        json!({"colors": [{"texture": "ms", "clear": [0, 0, 0, 0], "resolve": "c"}], "samples": 4});
    let units = Tolerance::units(1.0);
    // Coverage of a slanted triangle at the standard sample positions.
    let c = [
        clip(0.5, 1.25, 0.5, 1.0, full_vp),
        clip(15.5, 6.75, 0.5, 1.0, full_vp),
        clip(3.25, 15.0, 0.5, 1.0, full_vp),
    ];
    let t = c.map(|v| window(v, full_vp));
    let attrs = [[0.0; 4]; 3];
    let mut expected = vec![];
    let mut defined = vec![];
    let mut squared = vec![];
    for (x, y) in pixels() {
        let k = coverage(&t, x, y);
        defined.push(u8::from(k.is_some()));
        let k = f64::from(k.unwrap_or(0));
        expected.extend([k / 4.0; 4].map(|v| (v * 255.0).round() as u8));
        // frag_mask_in: each covered sample stores popcount(mask) / 4.
        let r = (k * k / 16.0 * 255.0).round() as u8;
        squared.extend([
            r,
            0,
            0,
            if k > 0.0 {
                (k / 4.0 * 255.0).round() as u8
            } else {
                0
            },
        ]);
    }
    let case = |name: &str, fragment: &str| {
        Case::render(name, library, "vert_plain", Some(fragment), {
            let mut s = state.clone();
            s["vertex_count"] = 3.into();
            s
        })
        .buffer(Buffer::data("positions", 0, f32s(&c.concat())).stage("vertex"))
        .buffer(Buffer::data("attributes", 1, f32s(&attrs.concat())).stage("vertex"))
        .texture(ms())
        .texture(target("c", "rgba8unorm"))
    };
    plan.add(
        case("render.msaa4.coverage", "frag_one").output(
            Output::new("c", Dtype::U8, units.clone())
                .expect(expected, units.clone())
                .expect_mask(defined.clone())
                .set("stride", 4),
        ),
    );
    plan.add(
        case("render.msaa4.sample_mask_input", "frag_mask_in").output(
            Output::new("c", Dtype::U8, units.clone())
                .expect(squared, units.clone())
                .expect_mask(defined)
                .set("stride", 4),
        ),
    );
    // A fragment's sample mask output, ANDed with full coverage.
    let masks: Vec<u32> = (0..W * H).map(|_| rng.u32()).collect();
    let expected: Vec<u8> = masks
        .iter()
        .flat_map(|&m| [(f64::from((m & 0xF).count_ones()) / 4.0 * 255.0).round() as u8; 4])
        .collect();
    // The fragment reinterprets x's bits as the mask: 0x3F80_00mm, a
    // normal float whose low byte is random.
    let bits: Vec<f64> = masks
        .iter()
        .flat_map(|&m| {
            [
                f64::from(f32::from_bits(0x3F80_0000 | (m & 0xFF))),
                0.0,
                0.0,
                0.0,
            ]
        })
        .collect();
    plan.add(
        full(
            "render.msaa4.sample_mask_output",
            library,
            "frag_sample_mask",
            &bits,
            state.clone(),
        )
        .texture(ms())
        .texture(target("c", "rgba8unorm"))
        .output(Output::new("c", Dtype::U8, units.clone()).expect(expected, units.clone())),
    );
    // The four standard sample positions average to the pixel's centre.
    plan.add(
        full(
            "render.msaa4.sample_position",
            library,
            "frag_sample_position",
            &[0.0; 4],
            state.clone(),
        )
        .texture(ms())
        .texture(target("c", "rgba8unorm"))
        .output(
            Output::new("c", Dtype::U8, units.clone())
                .expect([128, 128, 0, 255].repeat((W * H) as usize), units.clone()),
        ),
    );
    // Per-sample shading: the resolve averages each sample's value.
    let r = ((0.25 + 0.5 + 0.75 + 1.0) / 4.0 * 255.0f64).round() as u8;
    let g = ((0.0 + 0.125 + 0.25 + 0.375) / 4.0 * 255.0f64).round() as u8;
    plan.add(
        full(
            "render.msaa4.sample_id",
            library,
            "frag_sample_id",
            &[0.0; 4],
            state.clone(),
        )
        .texture(ms())
        .texture(target("c", "rgba8unorm"))
        .output(
            Output::new("c", Dtype::U8, units.clone())
                .expect([r, g, 0, 255].repeat((W * H) as usize), units.clone()),
        ),
    );
    // Alpha to coverage covers samples in proportion to alpha, each then
    // holding that alpha: alpha k/4 resolves to k/4 in color and (k/4)^2 in
    // alpha, within one sample (a quarter), as any dither allows.
    let alphas: Vec<f64> = (0..W * H)
        .flat_map(|i| [1.0, 1.0, 1.0, f64::from(i % 5) / 4.0])
        .collect();
    let expected: Vec<u8> = (0..W * H)
        .flat_map(|i| {
            let k = f64::from(i % 5);
            let c = (k / 4.0 * 255.0).round() as u8;
            [c, c, c, (k * k / 16.0 * 255.0).round() as u8]
        })
        .collect();
    let mut a2c = state.clone();
    a2c["alpha_to_coverage"] = true.into();
    // The Mac's own pattern is held to within a unit: a device that covers
    // other samples, or dithers otherwise, differs from it by a sample.
    plan.add(
        full(
            "render.msaa4.alpha_to_coverage",
            library,
            "frag_alpha",
            &alphas,
            a2c.clone(),
        )
        .texture(ms())
        .texture(target("c", "rgba8unorm"))
        .output(
            Output::new("c", Dtype::U8, Tolerance::units(1.0))
                .expect(expected, Tolerance::units(64.0)),
        ),
    );
    // Every alpha k/255, one a pixel: how many samples, and which, each
    // covers at each pixel of the target, as the Mac's.
    let alphas: Vec<f64> = (0..W * H)
        .flat_map(|i| [1.0, 1.0, 1.0, f64::from(i % 256) / 255.0])
        .collect();
    let expected: Vec<u8> = (0..W * H)
        .flat_map(|i| {
            let a = f64::from(i % 256) / 255.0;
            let c = (a * 255.0).round() as u8;
            [c, c, c, (a * a * 255.0).round() as u8]
        })
        .collect();
    plan.add(
        full(
            "render.msaa4.alpha_to_coverage.levels",
            library,
            "frag_alpha",
            &alphas,
            a2c,
        )
        .texture(ms())
        .texture(target("c", "rgba8unorm"))
        .output(
            Output::new("c", Dtype::U8, Tolerance::units(1.0))
                .expect(expected, Tolerance::units(64.0)),
        ),
    );
}

/// Which pixels lines and wireframe triangles cover, which Metal leaves to
/// the GPU: held to the Mac's pixels exactly. Each fragment adds a quarter
/// to an r8unorm target, so a pixel two primitives cover holds a half.
/// Lines run at slopes 0, 1/3, 1, 3 and vertical, both ways, from pixel
/// centres, edges and corners, each in its own 16 x 16 cell; a strip shows
/// its joints, and two wireframe triangles their shared edge. Lines through
/// the corners of pixels' diamonds, where the exit rule ties, and lines
/// under 4x multisampling, where Apple GPUs cover a parallelogram and
/// Vulkan a rectangle, are reported, not asserted (known hardware
/// differences).
fn lines(plan: &mut Plan, library: &str) {
    let quarter = [0.25; 4];
    let state = |primitive: &str, count: usize, fill: bool| {
        let mut state = json!({
            "colors": [{"texture": "c", "clear": [0, 0, 0, 0],
                        "blend": Blend::simple("add", "one", "one").json()}],
            "primitive": primitive, "vertex_count": count,
        });
        if fill {
            state["fill"] = "lines".into();
        }
        state
    };
    let case = |name: &str, (w, h): (u32, u32), points: &[[f64; 2]], state: Value| -> Case {
        let viewport = [0.0, 0.0, f64::from(w), f64::from(h)];
        let pos: Vec<f64> = points
            .iter()
            .flat_map(|&[x, y]| clip(x, y, 0.5, 1.0, viewport))
            .collect();
        let attrs: Vec<f64> = points.iter().flat_map(|_| quarter).collect();
        let mut case = Case::render(
            name,
            library,
            "vert_plain",
            Some("frag_attribute"),
            state.clone(),
        )
        .buffer(Buffer::data("positions", 0, f32s(&pos)).stage("vertex"))
        .buffer(Buffer::data("attributes", 1, f32s(&attrs)).stage("vertex"))
        .texture(Texture::d2("c", "r8unorm", w, h).usage(&["render"]));
        // Under 4x multisampling, the resolve's mean of the samples each
        // primitive covers.
        if state["samples"] == 4 {
            case = case.texture(
                Texture::new("ms", "r8unorm", "2d_ms", [w, h, 1])
                    .samples(4)
                    .usage(&["render"]),
            );
        }
        case.output(Output::new("c", Dtype::U8, Tolerance::exact()))
    };
    let starts = [(2.5, 2.5), (2.0, 2.5), (2.0, 2.0)];
    let directions = [(9.0, 0.0), (9.0, 3.0), (9.0, 9.0), (3.0, 9.0), (0.0, 9.0)];
    let (mut segments, mut ties) = (vec![], vec![]);
    for reversed in [false, true] {
        for &(sx, sy) in &starts {
            for &(dx, dy) in &directions {
                let (a, b) = ([sx, sy], [sx + dx, sy + dy]);
                let segment = if reversed { [b, a] } else { [a, b] };
                // From a pixel edge's midpoint at slopes 1/3 and 1, a line
                // runs through diamond corners.
                if (sx, sy) == (2.0, 2.5) && matches!(dy, 3.0 | 9.0) && dx == 9.0 {
                    ties.push(segment);
                } else {
                    segments.push(segment);
                }
            }
        }
    }
    // A shallow line between sixteenths, both ways.
    let (a, b) = ([1.25, 3.75], [14.75, 7.25]);
    segments.extend([[a, b], [b, a]]);
    let cells = |segments: &[[[f64; 2]; 2]]| -> Vec<[f64; 2]> {
        segments
            .iter()
            .enumerate()
            .flat_map(|(cell, segment)| {
                let origin = [(cell % 8 * 16) as f64, (cell / 8 * 16) as f64];
                segment.map(|[x, y]| [origin[0] + x, origin[1] + y])
            })
            .collect()
    };
    let list = cells(&segments);
    plan.add(case(
        "render.lines.list",
        (128, 64),
        &list,
        state("line", list.len(), false),
    ));
    let tied = cells(&ties);
    plan.add(
        case(
            "render.lines.ties",
            (64, 16),
            &tied,
            state("line", tied.len(), false),
        )
        .informational()
        .note("lines through diamond corners tie, so either pixel may light"),
    );
    segments.extend(ties);
    let all = cells(&segments);
    let mut msaa = state("line", all.len(), false);
    msaa["colors"][0]["texture"] = "ms".into();
    msaa["colors"][0]["resolve"] = "c".into();
    msaa["samples"] = 4.into();
    plan.add(
        case("render.lines.list_msaa4", (128, 64), &all, msaa)
            .informational()
            .note("multisampled lines are parallelograms on Apple GPUs, rectangles in Vulkan"),
    );
    let strip = [
        [2.5, 2.5],
        [20.5, 8.5],
        [8.0, 26.0],
        [28.0, 28.0],
        [28.0, 4.0],
        [16.5, 16.5],
        [3.0, 14.0],
    ];
    plan.add(case(
        "render.lines.strip",
        (32, 32),
        &strip,
        state("line_strip", strip.len(), false),
    ));
    let triangles = [
        [2.5, 2.5],
        [28.0, 4.0],
        [6.0, 28.5],
        [28.0, 4.0],
        [29.5, 29.5],
        [6.0, 28.5],
    ];
    plan.add(case(
        "render.wireframe",
        (32, 32),
        &triangles,
        state("triangle", triangles.len(), true),
    ));
}

fn points(plan: &mut Plan, library: &str) {
    let full_vp = [0.0, 0.0, W as f64, H as f64];
    // Centers and sizes whose squares' edges fall between pixel centers.
    let spots = [
        (2.5, 2.5, 1.0),
        (8.0, 3.0, 2.0),
        (4.0, 10.0, 4.0),
        (11.5, 11.5, 3.0),
        (13.0, 4.0, 6.0),
    ];
    let pos: Vec<[f64; 4]> = spots
        .iter()
        .map(|&(x, y, _)| clip(x, y, 0.5, 1.0, full_vp))
        .collect();
    let att: Vec<[f64; 4]> = spots.iter().map(|&(_, _, s)| [s, 0.0, 0.0, 0.0]).collect();
    let mut image = Image::new();
    for (x, y) in pixels() {
        let (cx, cy) = (x as f64 + 0.5, y as f64 + 0.5);
        let mut texel = CLEAR;
        for &(px, py, s) in &spots {
            let (u, v) = ((cx - (px - s / 2.0)) / s, (cy - (py - s / 2.0)) / s);
            if (0.0..1.0).contains(&u) && (0.0..1.0).contains(&v) {
                texel = [u, v, 0.0, 1.0];
            }
        }
        image.push(Some(texel));
    }
    plan.add(
        draw(
            "render.points",
            library,
            "vert_point",
            "frag_point",
            &pos,
            &att,
            "rgba32float",
            json!({"primitive": "point"}),
        )
        .output(image.output("c", Tolerance::abs(1e-5))),
    );
    // Apple GPUs draw a point at most 511 pixels wide: larger sizes draw
    // that square, here the pixels 257 to 767 on each axis about a centre
    // off the pixel grid.
    let side = 1024u32;
    let viewport = [0.0, 0.0, f64::from(side), f64::from(side)];
    let centre = 512.25;
    for size in [600.0, 1000.0] {
        let covered = |p: u32| (257..=767).contains(&p);
        let expected: Vec<u8> = (0..side)
            .flat_map(|y| (0..side).map(move |x| if covered(x) && covered(y) { 255 } else { 0 }))
            .collect();
        plan.add(
            Case::render(
                &format!("render.points.large.{size}"),
                library,
                "vert_point",
                Some("frag_point_cover"),
                json!({"colors": [{"texture": "c", "clear": [0.0, 0.0, 0.0, 0.0]}],
                       "vertex_count": 1, "primitive": "point"}),
            )
            .buffer(
                Buffer::data(
                    "positions",
                    0,
                    f32s(&clip(centre, centre, 0.5, 1.0, viewport)),
                )
                .stage("vertex"),
            )
            .buffer(Buffer::data("attributes", 1, f32s(&[size, 0.0, 0.0, 0.0])).stage("vertex"))
            .texture(Texture::d2("c", "r8unorm", side, side).usage(&["render"]))
            .output(Output::exact("c", Dtype::U8, expected)),
        );
    }
}

/// Each pixel of the union of triangles that share edges through pixel
/// centers is drawn exactly once: no gaps, no double blends.
fn edges(plan: &mut Plan, library: &str) {
    let full_vp = [0.0, 0.0, W as f64, H as f64];
    let center = (8.5, 8.5);
    // A fan around a pixel center whose spokes pass through pixel centers.
    let rim = [
        (0.0, 0.0),
        (8.5, 0.0),
        (16.0, 0.0),
        (16.0, 8.5),
        (16.0, 16.0),
        (8.5, 16.0),
        (0.0, 16.0),
        (0.0, 8.5),
    ];
    let mut pos = vec![];
    for k in 0..rim.len() {
        let (a, b) = (rim[k], rim[(k + 1) % rim.len()]);
        pos.extend([center, a, b].map(|(x, y)| clip(x, y, 0.5, 1.0, full_vp)));
    }
    let att = vec![[0.0; 4]; pos.len()];
    let blend = Blend::simple("add", "blend_alpha", "one");
    let once = vec![0.25; (W * H * 4) as usize];
    plan.add(
        draw("render.edges.shared_once", library, "vert_plain", "frag_one", &pos, &att, "rgba16float",
             json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0], "blend": blend.json()}], "blend_color": [0, 0, 0, 0.25]}))
        .output(Output::new("c", Dtype::F16, Tolerance::exact()).expect_same(floats(Dtype::F16, &once))),
    );
}

/// A vertex format: its size and how its bytes decode to four lanes.
struct VertexFormat {
    name: &'static str,
    size: usize,
    shader: &'static str,
    decode: fn(&[u8]) -> [f64; 4],
}

fn lanes(v: &[f64]) -> [f64; 4] {
    let mut out = [0.0, 0.0, 0.0, 1.0];
    out[..v.len()].copy_from_slice(v);
    out
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[2 * i], b[2 * i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap())
}

macro_rules! vf {
    ($name:literal, $size:expr, $shader:literal, $decode:expr) => {
        VertexFormat {
            name: $name,
            size: $size,
            shader: $shader,
            decode: $decode,
        }
    };
}

fn snorm_of(v: f64, max: f64) -> f64 {
    (v / max).max(-1.0)
}

fn vertex_formats() -> Vec<VertexFormat> {
    vec![
        vf!("uchar", 1, "uint", |b| lanes(&[f64::from(b[0])])),
        vf!("uchar2", 2, "uint", |b| lanes(&[
            f64::from(b[0]),
            f64::from(b[1])
        ])),
        vf!("uchar4", 4, "uint", |b| [0, 1, 2, 3]
            .map(|i| f64::from(b[i]))),
        vf!("char", 1, "int", |b| lanes(&[f64::from(b[0] as i8)])),
        vf!("char3", 3, "int", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(b[i] as i8))
        )),
        vf!("char4", 4, "int", |b| [0, 1, 2, 3]
            .map(|i| f64::from(b[i] as i8))),
        vf!("ucharnormalized", 1, "float", |b| lanes(&[
            f64::from(b[0]) / 255.0
        ])),
        vf!("uchar2normalized", 2, "float", |b| lanes(&[
            f64::from(b[0]) / 255.0,
            f64::from(b[1]) / 255.0
        ])),
        vf!("uchar4normalized", 4, "float", |b| [0, 1, 2, 3]
            .map(|i| f64::from(b[i]) / 255.0)),
        vf!("uchar4normalized_bgra", 4, "float", |b| [2, 1, 0, 3]
            .map(|i| f64::from(b[i]) / 255.0)),
        vf!("char2normalized", 2, "float", |b| lanes(
            &[0, 1].map(|i| snorm_of(f64::from(b[i] as i8), 127.0))
        )),
        vf!("char4normalized", 4, "float", |b| [0, 1, 2, 3]
            .map(|i| snorm_of(f64::from(b[i] as i8), 127.0))),
        vf!("ushort", 2, "uint", |b| lanes(&[f64::from(u16_at(b, 0))])),
        vf!("ushort4", 8, "uint", |b| [0, 1, 2, 3]
            .map(|i| f64::from(u16_at(b, i)))),
        vf!("short2", 4, "int", |b| lanes(
            &[0, 1].map(|i| f64::from(u16_at(b, i) as i16))
        )),
        vf!("short4", 8, "int", |b| [0, 1, 2, 3]
            .map(|i| f64::from(u16_at(b, i) as i16))),
        vf!("ushort2normalized", 4, "float", |b| lanes(
            &[0, 1].map(|i| f64::from(u16_at(b, i)) / 65535.0)
        )),
        vf!("ushort4normalized", 8, "float", |b| [0, 1, 2, 3]
            .map(|i| f64::from(u16_at(b, i)) / 65535.0)),
        vf!("short4normalized", 8, "float", |b| [0, 1, 2, 3]
            .map(|i| snorm_of(f64::from(u16_at(b, i) as i16), 32767.0))),
        vf!("half", 2, "half", |b| lanes(&[
            super::values::f16_from_bits(u16_at(b, 0))
        ])),
        vf!("half2", 4, "half", |b| lanes(
            &[0, 1].map(|i| super::values::f16_from_bits(u16_at(b, i)))
        )),
        vf!("half4", 8, "half", |b| [0, 1, 2, 3]
            .map(|i| super::values::f16_from_bits(u16_at(b, i)))),
        vf!("float", 4, "float", |b| lanes(&[f64::from(
            f32::from_bits(u32_at(b, 0))
        )])),
        vf!("float2", 8, "float", |b| lanes(
            &[0, 1].map(|i| f64::from(f32::from_bits(u32_at(b, i))))
        )),
        vf!("float3", 12, "float", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(f32::from_bits(u32_at(b, i))))
        )),
        vf!("float4", 16, "float", |b| [0, 1, 2, 3]
            .map(|i| f64::from(f32::from_bits(u32_at(b, i))))),
        vf!("int", 4, "int", |b| lanes(&[
            f64::from(u32_at(b, 0) as i32)
        ])),
        vf!("int3", 12, "int", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(u32_at(b, i) as i32))
        )),
        vf!("uint2", 8, "uint", |b| lanes(
            &[0, 1].map(|i| f64::from(u32_at(b, i)))
        )),
        vf!("uint4", 16, "uint", |b| [0, 1, 2, 3]
            .map(|i| f64::from(u32_at(b, i)))),
        vf!("uchar3", 3, "uint", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(b[i]))
        )),
        vf!("char2", 2, "int", |b| lanes(
            &[0, 1].map(|i| f64::from(b[i] as i8))
        )),
        vf!("uchar3normalized", 3, "float", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(b[i]) / 255.0)
        )),
        vf!("charnormalized", 1, "float", |b| lanes(&[snorm_of(
            f64::from(b[0] as i8),
            127.0
        )])),
        vf!("char3normalized", 3, "float", |b| lanes(
            &[0, 1, 2].map(|i| snorm_of(f64::from(b[i] as i8), 127.0))
        )),
        vf!("ushort2", 4, "uint", |b| lanes(
            &[0, 1].map(|i| f64::from(u16_at(b, i)))
        )),
        vf!("ushort3", 6, "uint", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(u16_at(b, i)))
        )),
        vf!("short", 2, "int", |b| lanes(&[f64::from(
            u16_at(b, 0) as i16
        )])),
        vf!("short3", 6, "int", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(u16_at(b, i) as i16))
        )),
        vf!("ushortnormalized", 2, "float", |b| lanes(&[f64::from(
            u16_at(b, 0)
        ) / 65535.0])),
        vf!("ushort3normalized", 6, "float", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(u16_at(b, i)) / 65535.0)
        )),
        vf!("shortnormalized", 2, "float", |b| lanes(&[snorm_of(
            f64::from(u16_at(b, 0) as i16),
            32767.0
        )])),
        vf!("short2normalized", 4, "float", |b| lanes(
            &[0, 1].map(|i| snorm_of(f64::from(u16_at(b, i) as i16), 32767.0))
        )),
        vf!("short3normalized", 6, "float", |b| lanes(
            &[0, 1, 2].map(|i| snorm_of(f64::from(u16_at(b, i) as i16), 32767.0))
        )),
        vf!("half3", 6, "half", |b| lanes(
            &[0, 1, 2].map(|i| super::values::f16_from_bits(u16_at(b, i)))
        )),
        vf!("int2", 8, "int", |b| lanes(
            &[0, 1].map(|i| f64::from(u32_at(b, i) as i32))
        )),
        vf!("int4", 16, "int", |b| [0, 1, 2, 3]
            .map(|i| f64::from(u32_at(b, i) as i32))),
        vf!("uint", 4, "uint", |b| lanes(&[f64::from(u32_at(b, 0))])),
        vf!("uint3", 12, "uint", |b| lanes(
            &[0, 1, 2].map(|i| f64::from(u32_at(b, i)))
        )),
        vf!("floatrg11b10", 4, "float", |b| {
            let w = u32_at(b, 0);
            let small = |at: u32, bits: u32, mantissa: u32| {
                let q = (w >> at) & ((1 << bits) - 1);
                let (e, m) = (q >> mantissa, q & ((1 << mantissa) - 1));
                let fraction = f64::from(m) / f64::from(1u32 << mantissa);
                if e == 0 {
                    fraction * 2f64.powi(-14)
                } else {
                    (1.0 + fraction) * 2f64.powi(e as i32 - 15)
                }
            };
            [small(0, 11, 6), small(11, 11, 6), small(22, 10, 5), 1.0]
        }),
        vf!("floatrgb9e5", 4, "float", |b| {
            let w = u32_at(b, 0);
            let scale = 2f64.powi((w >> 27) as i32 - 15 - 9);
            let lane = |at: u32| f64::from((w >> at) & 511) * scale;
            [lane(0), lane(9), lane(18), 1.0]
        }),
        vf!("int1010102normalized", 4, "float", |b| {
            let w = u32_at(b, 0);
            let field = |at: u32, bits: u32| {
                let v = (w >> at) & ((1 << bits) - 1);
                let v = if v >> (bits - 1) == 1 {
                    i64::from(v) - (1 << bits)
                } else {
                    i64::from(v)
                };
                snorm_of(v as f64, ((1 << (bits - 1)) - 1) as f64)
            };
            [field(0, 10), field(10, 10), field(20, 10), field(30, 2)]
        }),
        vf!("uint1010102normalized", 4, "float", |b| {
            let w = u32_at(b, 0);
            let field = |at: u32| f64::from((w >> at) & 1023) / 1023.0;
            [field(0), field(10), field(20), f64::from(w >> 30) / 3.0]
        }),
    ]
}

/// Random bytes for a vertex format, finite for its float lanes.
fn vertex_bytes(f: &VertexFormat, rng: &mut Random) -> Vec<u8> {
    if f.name == "floatrg11b10" {
        // Exponents below 31: no infinities or NaNs.
        let field = |rng: &mut Random, mantissa: u32| {
            (rng.below(31) << mantissa) | rng.below(1 << mantissa)
        };
        let w = field(rng, 6) | (field(rng, 6) << 11) | (field(rng, 5) << 22);
        return (w as u32).to_le_bytes().to_vec();
    }
    match f.shader {
        "half" => (0..f.size / 2)
            .flat_map(|_| f16_bits(f16r(rng.uniform(-100.0, 100.0))).to_le_bytes())
            .collect(),
        "float" if f.name.starts_with("float") => (0..f.size / 4)
            .flat_map(|_| (rng.uniform(-100.0, 100.0) as f32).to_le_bytes())
            .collect(),
        _ => (0..f.size).map(|_| (rng.u32() % 256) as u8).collect(),
    }
}

fn fetch(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(907);
    let count = 64usize;
    for f in vertex_formats() {
        for offset in [0usize, 4] {
            let stride = (offset + f.size).div_ceil(4) * 4 + 4;
            let mut data = vec![0u8; stride * count];
            let mut expected = vec![];
            for v in 0..count {
                let bytes = vertex_bytes(&f, &mut rng);
                data[v * stride + offset..v * stride + offset + f.size].copy_from_slice(&bytes);
                expected.extend((f.decode)(&bytes));
            }
            let (shader, dtype) = match f.shader {
                "uint" => ("uint", Dtype::U32),
                "int" => ("int", Dtype::I32),
                "half" => ("half", Dtype::F32),
                _ => ("float", Dtype::F32),
            };
            let tol = if f.name.contains("normalized") {
                Tolerance::ulp(1.0)
            } else {
                Tolerance::exact()
            };
            let out = match dtype {
                Dtype::F32 => f32s(&expected.iter().map(|&v| f32r(v)).collect::<Vec<_>>()),
                _ => ints(
                    dtype,
                    &expected.iter().map(|&v| v as i128).collect::<Vec<_>>(),
                ),
            };
            let name = format!(
                "render.fetch.{}{}",
                f.name,
                if offset > 0 { ".offset" } else { "" }
            );
            let attributes = json!({"attributes": [{"index": 0, "format": f.name, "offset": offset, "buffer": 0}],
                                    "layouts": [{"buffer": 0, "stride": stride}]});
            plan.add(
                Case::render(
                    &name,
                    library,
                    &format!("vert_fetch_{shader}"),
                    None,
                    json!({"rasterize": false, "primitive": "point", "vertex_count": count, "target_size": [1, 1],
                           "vertex_descriptor": attributes}),
                )
                .buffer(Buffer::data("vertices", 0, data.clone()).stage("vertex"))
                .buffer(Buffer::zeroed("out", 2, count * 16).stage("vertex"))
                .output(Output::new("out", dtype, tol.clone()).expect(out.clone(), tol.clone())),
            );
            // The same attribute fetched by a kernel's stage input.
            plan.add(
                Case::compute(
                    &format!("{name}.stage_in"),
                    library,
                    &format!("stage_fetch_{shader}"),
                    [count as u32, 1, 1],
                    [64, 1, 1],
                )
                .dispatch_threads()
                .set("stage_input", attributes)
                .buffer(Buffer::data("vertices", 0, data))
                .buffer(Buffer::zeroed("out", 2, count * 16))
                .output(Output::new("out", dtype, tol.clone()).expect(out, tol)),
            );
        }
    }
    // One interleaved layout of mixed widths in buffer 1 (float4 @0, float2
    // @16 and @24, half4 @32, stride 48), bound at offset 0 and at an offset.
    for bind_offset in [0usize, 96] {
        let mut data = vec![0u8; bind_offset];
        let mut expected = vec![];
        for _ in 0..count {
            let f: Vec<f64> = (0..8).map(|_| f32r(rng.uniform(-100.0, 100.0))).collect();
            let h: Vec<f64> = (0..4).map(|_| f16r(rng.uniform(-100.0, 100.0))).collect();
            data.extend(f32s(&f));
            data.extend(floats(Dtype::F16, &h));
            data.extend([0xCDu8; 8]);
            expected.extend(&f);
            expected.extend(&h);
        }
        plan.add(
            Case::render(
                &format!("render.fetch.mixed_layout.bind_offset{bind_offset}"),
                library,
                "vert_fetch_mixed",
                None,
                json!({"rasterize": false, "primitive": "point", "vertex_count": count, "target_size": [1, 1],
                       "vertex_descriptor": {
                           "attributes": [{"index": 0, "format": "float4", "offset": 0, "buffer": 1},
                                          {"index": 1, "format": "float2", "offset": 16, "buffer": 1},
                                          {"index": 2, "format": "float2", "offset": 24, "buffer": 1},
                                          {"index": 3, "format": "half4", "offset": 32, "buffer": 1}],
                           "layouts": [{"buffer": 1, "stride": 48}]}}),
            )
            .buffer(Buffer::data("vertices", 1, data).stage("vertex").set("offset", bind_offset))
            .buffer(Buffer::zeroed("out", 2, count * 48).stage("vertex"))
            .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
        );
    }
    // Step functions: per vertex, per instance at a rate, and constant,
    // with a first vertex and a base instance.
    for (rate, start, base) in [(1u32, 0u32, 0u32), (2, 2, 3), (3, 1, 0)] {
        let (vertices, instances) = (6u32, 5u32);
        let per = |n: u32, rng: &mut Random| -> Vec<[f64; 4]> {
            (0..n)
                .map(|_| std::array::from_fn(|_| f32r(rng.uniform(-1.0, 1.0))))
                .collect()
        };
        let a = per(start + vertices, &mut rng);
        let b = per(base + instances, &mut rng);
        let c = per(1, &mut rng);
        let mut expected = vec![0.0; (vertices * instances * 16) as usize];
        for i in base..base + instances {
            for v in start..start + vertices {
                let slot = (((i - base) * vertices + (v - start)) * 16) as usize;
                let bi = (base + (i - base) / rate) as usize;
                let values = [
                    a[v as usize],
                    b[bi],
                    c[0],
                    [
                        f64::from(v),
                        f64::from(i),
                        f64::from(start),
                        f64::from(base),
                    ],
                ];
                expected[slot..slot + 16].copy_from_slice(&values.concat());
            }
        }
        plan.add(
            Case::render(
                &format!("render.instancing.rate{rate}.start{start}.base{base}"),
                library,
                "vert_instanced",
                None,
                json!({"rasterize": false, "primitive": "point", "vertex_start": start, "vertex_count": vertices,
                       "instance_count": instances, "base_instance": base, "target_size": [1, 1],
                       "vertex_descriptor": {
                           "attributes": [{"index": 0, "format": "float4", "buffer": 0}, {"index": 1, "format": "float4", "buffer": 1},
                                          {"index": 2, "format": "float4", "buffer": 2}],
                           "layouts": [{"buffer": 0, "stride": 16}, {"buffer": 1, "stride": 16, "step": "instance", "rate": rate},
                                       {"buffer": 2, "stride": 16, "step": "constant"}]}}),
            )
            .buffer(Buffer::data("a", 0, f32s(&a.concat())).stage("vertex"))
            .buffer(Buffer::data("b", 1, f32s(&b.concat())).stage("vertex"))
            .buffer(Buffer::data("c", 2, f32s(&c.concat())).stage("vertex"))
            .buffer(Buffer::zeroed("out", 3, expected.len() * 4).stage("vertex"))
            .buffer(Buffer::data("count", 4, u32s(&[vertices])).stage("vertex"))
            .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
        );
    }
    // Indexed draws: 16- and 32-bit indices, an index buffer offset and a
    // base vertex.
    for (kind, base_vertex, offset) in [
        ("uint16", 0i64, 0usize),
        ("uint32", 0, 0),
        ("uint16", 7, 4),
        ("uint32", 3, 8),
    ] {
        let (indices, instances, slots) = (12usize, 3u32, 24u32);
        let values: Vec<u32> = (0..indices)
            .map(|_| rng.u32() % (slots - base_vertex as u32))
            .collect();
        let size = if kind == "uint16" { 2 } else { 4 };
        let mut data = vec![0xEEu8; offset];
        for &v in &values {
            data.extend(&v.to_le_bytes()[..size]);
        }
        let mut expected = vec![0u32; (slots * instances * 2) as usize];
        for i in 0..instances {
            for &v in &values {
                let id = v + base_vertex as u32;
                let slot = ((i * slots + id) * 2) as usize;
                expected[slot] = id;
                expected[slot + 1] = i;
            }
        }
        plan.add(
            Case::render(
                &format!("render.indexed.{kind}.base{base_vertex}.offset{offset}"),
                library,
                "vert_ids",
                None,
                json!({"rasterize": false, "primitive": "point", "vertex_count": indices, "instance_count": instances,
                       "index_buffer": "indices", "index_type": kind, "index_offset": offset, "base_vertex": base_vertex,
                       "target_size": [1, 1]}),
            )
            .buffer(Buffer::data("indices", 0, data).unbound())
            .buffer(Buffer::zeroed("out", 2, expected.len() * 4).stage("vertex"))
            .buffer(Buffer::data("count", 3, u32s(&[slots])).stage("vertex"))
            .output(Output::new("out", Dtype::U32, Tolerance::exact()).expect_same(u32s(&expected))),
        );
    }
    // Every vertex of every primitive type runs, with its ID.
    for primitive in ["point", "line", "line_strip", "triangle", "triangle_strip"] {
        let (count, instances) = (12u32, 2u32);
        let expected: Vec<u32> = (0..instances)
            .flat_map(|i| (0..count).flat_map(move |v| [v, i]))
            .collect();
        plan.add(
            Case::render(
                &format!("render.vertex_ids.{primitive}"),
                library,
                "vert_ids",
                None,
                json!({"rasterize": false, "primitive": primitive, "vertex_count": count, "instance_count": instances,
                       "target_size": [1, 1]}),
            )
            .buffer(Buffer::zeroed("out", 2, expected.len() * 4).stage("vertex"))
            .buffer(Buffer::data("count", 3, u32s(&[count])).stage("vertex"))
            .output(Output::new("out", Dtype::U32, Tolerance::exact()).expect_same(u32s(&expected))),
        );
        // The same draw from a pipeline that names its primitives' class.
        let class = primitive.trim_end_matches("_strip");
        plan.vary(
            &format!("render.vertex_ids.{primitive}"),
            "topology",
            |case| case.set_at(&["render", "input_primitive"], class),
        );
        // The same draw as a command of an indirect command buffer, using
        // the encoder's buffers.
        plan.add(
            Case::render(
                &format!("render.vertex_ids.indirect_command.{primitive}"),
                library,
                "vert_ids",
                None,
                json!({"rasterize": false, "target_size": [1, 1], "supports_icb": true,
                       "execute_icb": {"icb": "icb", "count": 1}}),
            )
            .set("icbs", json!([{"name": "icb", "type": "draw", "count": 1, "max_buffers": 4, "inherit_buffers": true,
                                  "commands": [{"primitive": primitive, "vertex_count": count, "instance_count": instances}]}]))
            .buffer(Buffer::zeroed("out", 2, expected.len() * 4).stage("vertex"))
            .buffer(Buffer::data("count", 3, u32s(&[count])).stage("vertex"))
            .output(Output::new("out", Dtype::U32, Tolerance::exact()).expect_same(u32s(&expected))),
        );
    }
}

/// Fragment-only queries: the level of detail derivatives select, the
/// pass's sample count, helper threads, and an interpolant evaluated where
/// the shader asks.
fn fragment_queries(plan: &mut Plan, library: &str) {
    let fill = |clear: bool| {
        let mut colors = json!({"texture": "c"});
        if clear {
            colors["clear"] = json!(CLEAR);
        }
        json!({"colors": [colors], "vertex_count": 3})
    };
    // uv advances `scale` per pixel on both axes over a 64x64 texture, so the
    // level is log2(64 scale), within a 32nd as the device computes it; the
    // sampler clamps it to [0, 2]. Querying the level needs a device that
    // reports it (all of Apple8, some of Apple7).
    for texels_per_pixel in [0.5, 2.0, 4.0, 8.0] {
        let lod: f64 = libm::log2(texels_per_pixel);
        let expected: Vec<f64> = pixels()
            .flat_map(|_| [lod.clamp(0.0, 2.0), lod, 0.0, 1.0])
            .collect();
        plan.add(
            Case::render(
                &format!("render.calculate_lod.{texels_per_pixel}"),
                library,
                "vert_full",
                Some("frag_lod"),
                fill(true),
            )
            .requires(&[], &["query_texture_lod"])
            .buffer(Buffer::data("depth", 2, f32s(&[0.0])).stage("vertex"))
            .buffer(Buffer::data("scale", 3, f32s(&[texels_per_pixel / 64.0])).stage("fragment"))
            .texture(Texture::d2("t", "rgba8unorm", 64, 64).index(0).mipmaps(7))
            .texture(target("c", "rgba32float"))
            .sampler(
                json!({"name": "s", "index": 0, "min": "linear", "mag": "linear", "mip": "linear",
                            "lod_min": 0.0, "lod_max": 2.0}),
            )
            .output(
                Output::new("c", Dtype::F32, Tolerance::abs(1.0 / 32.0))
                    .expect(f32s(&expected), Tolerance::abs(1.0 / 32.0)),
            ),
        );
    }
    // The whole target is covered, so no fragment is a helper.
    for samples in [1u32, 4] {
        let expected: Vec<f64> = pixels()
            .flat_map(|_| [f64::from(samples), 0.0, 0.0, 1.0])
            .collect();
        let mut state = fill(true);
        let mut case = Case::render(
            &format!("render.samples_and_helpers.msaa{samples}"),
            library,
            "vert_full",
            Some("frag_samples_helpers"),
            state.clone(),
        );
        if samples > 1 {
            state["colors"][0] = json!({"texture": "ms", "clear": CLEAR, "resolve": "c"});
            state["samples"] = samples.into();
            case = Case::render(
                &format!("render.samples_and_helpers.msaa{samples}"),
                library,
                "vert_full",
                Some("frag_samples_helpers"),
                state,
            )
            .texture(
                Texture::new("ms", "rgba16float", "2d_ms", [W, H, 1])
                    .samples(samples)
                    .usage(&["render"]),
            );
        }
        plan.add(
            case.buffer(Buffer::data("depth", 2, f32s(&[0.0])).stage("vertex"))
                .texture(target("c", "rgba16float"))
                .output(
                    Output::new("c", Dtype::F16, Tolerance::exact())
                        .expect_same(floats(Dtype::F16, &expected)),
                ),
        );
    }
    if plan.has(SOURCE, "frag_interpolant") {
        // Offsets are from the pixel's upper-left corner; a covered
        // pixel's centroid is its centre.
        let offset = [0.25, 0.75];
        let expected: Vec<f64> = pixels()
            .flat_map(|(x, y)| {
                let (x, y) = (f64::from(x), f64::from(y));
                [
                    0.0,
                    (y + 0.5) / f64::from(H),
                    (x + offset[0]) / f64::from(W),
                    (y + offset[1]) / f64::from(H),
                ]
            })
            .collect();
        let tol = Tolerance::abs(1e-5);
        plan.add(
            Case::render(
                "render.interpolant.at",
                library,
                "vert_uv",
                Some("frag_interpolant"),
                fill(true),
            )
            .buffer(Buffer::data("offset", 0, f32s(&offset)).stage("fragment"))
            .texture(target("c", "rgba32float"))
            .output(Output::new("c", Dtype::F32, tol.clone()).expect(f32s(&expected), tol))
            .requires(&[], &["pull_model_interpolation"]),
        );
    }
}

/// Layered rendering through several viewports, clip distances, and a
/// fragment function that reads its target.
fn layers_and_clipping(plan: &mut Plan, library: &str) {
    let viewports = [
        [0u32, 0, W, H],
        [0, 0, W / 2, H / 2],
        [W / 2, H / 2, W / 2, H / 2],
    ];
    let mut expected = vec![];
    for (layer, v) in viewports.iter().enumerate() {
        for (x, y) in pixels() {
            let inside = x >= v[0] && x < v[0] + v[2] && y >= v[1] && y < v[1] + v[3];
            let l = layer as f64;
            expected.extend(if inside {
                [l, l, f64::from(x) + 0.5, f64::from(y) + 0.5]
            } else {
                CLEAR
            });
        }
    }
    plan.add(
        Case::render(
            "render.layered.viewports",
            library,
            "vert_layered",
            Some("frag_layer"),
            json!({"colors": [{"texture": "c", "clear": CLEAR}], "vertex_count": 3, "instance_count": 3,
                   "viewports": viewports, "input_primitive": "triangle"}),
        )
        .texture(Texture::new("c", "rgba32float", "2d_array", [W, H, 1]).array(3).usage(&["render"]))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
    );
    // The same into a multisampled array, each layer resolved.
    plan.add(
        Case::render(
            "render.layered.multisampled",
            library,
            "vert_layered",
            Some("frag_layer"),
            json!({"colors": [{"texture": "ms", "clear": CLEAR, "resolve": "c"}], "samples": 4,
                   "vertex_count": 3, "instance_count": 3, "viewports": viewports,
                   "input_primitive": "triangle"}),
        )
        .texture(
            Texture::new("ms", "rgba32float", "2d_ms_array", [W, H, 1])
                .array(3)
                .samples(4)
                .usage(&["render"]),
        )
        .texture(
            Texture::new("c", "rgba32float", "2d_array", [W, H, 1])
                .array(3)
                .usage(&["render"]),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
    );
    // Clip distances x + 1/4 and 1/2 - y keep the pixels right of x = 6 and
    // below y = 4.
    let expected: Vec<f64> = pixels()
        .flat_map(|(x, y)| if x >= 6 && y >= 4 { [1.0; 4] } else { CLEAR })
        .collect();
    plan.add(
        Case::render(
            "render.clip_distance",
            library,
            "vert_clip",
            Some("frag_white"),
            json!({"colors": [{"texture": "c", "clear": CLEAR}], "vertex_count": 3}),
        )
        .buffer(Buffer::data("planes", 0, f32s(&[1.0, 0.25, -1.0, 0.5])).stage("vertex"))
        .texture(target("c", "rgba32float"))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected))),
    );
    // The planes bound to both stages at once; the fragment function
    // binds no buffers.
    plan.vary("render.clip_distance", "both_stages", |case| {
        case.edit("buffers", "planes", "stage", "both")
    });
    let mut rng = Random::new(6061);
    let n = (W * H * 4) as usize;
    let initial: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-2.0, 2.0))).collect();
    let added: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-2.0, 2.0))).collect();
    let expected: Vec<f64> = initial
        .iter()
        .zip(&added)
        .map(|(d, c)| f32r(d * 0.5 + c))
        .collect();
    plan.add(
        full(
            "render.framebuffer_fetch",
            library,
            "frag_fetch",
            &added,
            json!({"colors": [{"texture": "c"}]}),
        )
        .texture(target("c", "rgba32float").data(f32s(&initial)))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)))
        .requires(&["apple3"], &[]),
    );
    // Overlapping primitives of one draw read the target in their order:
    // every pixel counts all 64 instances, each seeing exactly those
    // before it.
    const INSTANCES: u32 = 64;
    let expected: Vec<f64> = pixels()
        .flat_map(|_| [f64::from(INSTANCES), f64::from(INSTANCES), 0.0, 1.0])
        .collect();
    plan.add(
        Case::render(
            "render.framebuffer_fetch.within_draw",
            library,
            "vert_ordered",
            Some("frag_ordered"),
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                   "vertex_count": 3, "instance_count": INSTANCES}),
        )
        .texture(target("c", "rgba32float"))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)))
        .requires(&["apple3"], &[]),
    );
    // Overlapping primitives of one draw access a raster order group's
    // device memory in the same order.
    let counts: Vec<u32> = pixels().flat_map(|_| [INSTANCES; 2]).collect();
    plan.add(
        Case::render(
            "render.raster_order_groups",
            library,
            "vert_ordered",
            Some("frag_raster_ordered"),
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                   "vertex_count": 3, "instance_count": INSTANCES}),
        )
        .texture(target("c", "rgba32float"))
        .buffer(Buffer::zeroed("counts", 0, (W * H * 8) as usize).stage("fragment"))
        .buffer(Buffer::data("width", 1, u32s(&[W])).stage("fragment"))
        .output(Output::new("counts", Dtype::U32, Tolerance::exact()).expect_same(u32s(&counts)))
        .requires(&[], &["raster_order_groups"]),
    );
}

/// Tile functions after a draw of per-pixel colors over a target that ends
/// partway through its last tiles: each threadgroup reads and writes its
/// tile's pixels, and its threadgroup memory persists across the pass's
/// tile dispatches.
/// What `render.tile.reflection` reports of `tile_call`.
const TILE_REFLECTION: [&str; 8] = [
    "tile",
    "shift type=0 index=2 access=0 used=1 argument=1 size=4 align=4 data=33",
    "block type=17 index=0 access=0 used=1 argument=1",
    "first type=24 index=0 access=0 used=1 argument=1",
    "second type=24 index=1 access=0 used=1 argument=1",
    "arguments=4",
    "required=16,16,1",
    "",
];

fn tiles(plan: &mut Plan, library: &str) {
    const TW: u32 = 48;
    const TH: u32 = 40;
    let mut rng = Random::new(4417);
    let colors: Vec<f64> = (0..TW * TH * 4)
        .map(|_| (rng.uniform(-16.0, 16.0) * 4.0).round() / 4.0)
        .collect();
    let at = |x: u32, y: u32| &colors[((y * TW + x) * 4) as usize..][..4];
    let image = |texel: &dyn Fn(u32, u32) -> [f64; 4]| -> Vec<f64> {
        (0..TH)
            .flat_map(|y| (0..TW).map(move |x| (x, y)))
            .flat_map(|(x, y)| texel(x, y))
            .collect()
    };
    let case = |name: &str, tiles: Value, state: Value| {
        let mut render = json!({"vertex_count": 3, "colors": [{"texture": "c"}], "tiles": tiles});
        for (k, v) in state.as_object().unwrap() {
            render[k] = v.clone();
        }
        Case::render(name, library, "vert_full", Some("frag_color"), render)
            .buffer(Buffer::data("colors", 0, f32s(&colors)).stage("fragment"))
            .buffer(Buffer::data("width", 1, u32s(&[TW])).stage("fragment"))
            .buffer(Buffer::data("depth", 2, f32s(&[0.5])).stage("vertex"))
            .texture(Texture::d2("c", "rgba32float", TW, TH).usage(&["render"]))
    };
    let rewritten = image(&|x, y| {
        let c = at(x, y);
        [
            c[0] + f64::from(x % 16),
            c[1] + f64::from(y % 16),
            f64::from(x / 16),
            f64::from(y / 16) + 4.0,
        ]
    });
    plan.add(
        case(
            "render.tile.rewrite",
            json!([{"function": "tile_rewrite", "threads": [16, 8]}]),
            json!({"tile_size": [16, 16]}),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&rewritten))),
    );
    // Threadgroups the size of the tile.
    plan.add(
        case(
            "render.tile.rewrite.matching_threads",
            json!([{"function": "tile_rewrite", "threads": [16, 16], "matches_tile_size": true}]),
            json!({"tile_size": [16, 16]}),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&rewritten))),
    );
    let recalled = image(&|x, y| {
        let c = at(x, y);
        [f64::from(x / 32 + 10 * (y / 32) + 100), c[1], c[2], c[3]]
    });
    let memory = json!([{"index": 0, "length": 16, "offset": 16}]);
    plan.add(
        case(
            "render.tile.threadgroup_memory_persists",
            json!([
                {"function": "tile_remember", "threads": [32, 4], "threadgroup_memory": memory},
                {"function": "tile_recall", "threads": [16, 16], "threadgroup_memory": memory}
            ]),
            json!({"tile_memory": 32}),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&recalled))),
    );
    // Tiles of 32 by 16: two by three of them.
    let dimensions = image(&|_, _| [32.0, 16.0, 2.0, 3.0]);
    plan.add(
        case(
            "render.tile.dimensions",
            json!([{"function": "tile_dimensions", "threads": [8, 8]}]),
            json!({"tile_size": [32, 16]}),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&dimensions))),
    );
    // A pass's imageblock data: a tile function sets each pixel's from its
    // position before two draws, which each add to it in raster order and
    // color the pixel with it, and another writes it out after them. Each
    // sample's tile memory holds its color attachments' texels and the
    // data, all of a tile's within Apple's 32 KiB.
    let add = [0.5, 0.25, 2.0, 0.0];
    let data = image(&|x, y| {
        let (x, y) = (f64::from(x), f64::from(y));
        [
            x + 2.0 * add[0],
            y + 2.0 * add[1],
            2.0 * add[2],
            x + 100.0 * y + 2000.0,
        ]
    });
    let colored = image(&|x, y| {
        let (x, y) = (f64::from(x), f64::from(y));
        [x + 2.0 * add[0], y + 2.0 * add[1], 2.0 * add[2], 1.0]
    });
    for samples in [1, 2] {
        let multisampled = samples > 1;
        let colors = if multisampled {
            json!([{"texture": "ms", "clear": [0, 0, 0, 0]}])
        } else {
            json!([{"texture": "c", "clear": [0, 0, 0, 0]}])
        };
        let tiles = json!([
            {"function": "tile_ib_init", "threads": [16, 16], "before": true},
            {"function": "tile_ib_resolve", "threads": [16, 16]}
        ]);
        let mut render = json!({"vertex_count": 3, "instance_count": 2, "colors": colors,
                                "tiles": tiles, "tile_size": [16, 16],
                                "imageblock_sample_length": 48});
        if multisampled {
            render["samples"] = json!(samples);
        }
        let name = if multisampled {
            "render.imageblock.fragment_data.multisampled"
        } else {
            "render.imageblock.fragment_data"
        };
        let mut case = Case::render(name, library, "vert_full", Some("frag_ib_add"), render)
            .buffer(Buffer::data("add", 0, f32s(&add)).stage("fragment"))
            .buffer(Buffer::data("depth", 2, f32s(&[0.5])).stage("vertex"))
            .buffer(Buffer::zeroed("out", 0, (TW * TH * 16) as usize).stage("tile"))
            .buffer(Buffer::data("size", 1, u32s(&[TW, TH])).stage("tile"))
            .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&data)));
        case = if multisampled {
            case.texture(
                Texture::new("ms", "rgba32float", "2d_ms", [TW, TH, 1])
                    .samples(2)
                    .usage(&["render"]),
            )
        } else {
            case.texture(Texture::d2("c", "rgba32float", TW, TH).usage(&["render"]))
                .output(
                    Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&colored)),
                )
        };
        plan.add(case);
    }
    // A tile function of both imageblocks between the draws and the data's
    // resolve: it reads each pixel's color and data and writes both.
    let mixed = |x: u32, y: u32| {
        let (x, y) = (f64::from(x), f64::from(y));
        (x + 2.0 * add[0], y + 2.0 * add[1], x + 100.0 * y + 2000.0)
    };
    let n = |x: u32, y: u32| {
        let (ax, ay, n) = mixed(x, y);
        n + ax + ay
    };
    let data = image(&|x, y| {
        let (ax, ay, _) = mixed(x, y);
        [ax, ay, 2.0 * add[2], n(x, y)]
    });
    let colored = image(&|x, y| {
        let (ax, ay, _) = mixed(x, y);
        [2.0 * ax, 2.0 * ay, 2.0 * add[2] + n(x, y), 3.0]
    });
    let tiles = json!([
        {"function": "tile_ib_init", "threads": [16, 16], "before": true},
        {"function": "tile_ib_mix", "threads": [16, 16]},
        {"function": "tile_ib_resolve", "threads": [16, 16]}
    ]);
    let render = json!({"vertex_count": 3, "instance_count": 2,
                        "colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                        "tiles": tiles, "tile_size": [16, 16], "imageblock_sample_length": 48});
    plan.add(
        Case::render(
            "render.tile.both_imageblocks",
            library,
            "vert_full",
            Some("frag_ib_add"),
            render,
        )
        .buffer(Buffer::data("add", 0, f32s(&add)).stage("fragment"))
        .buffer(Buffer::data("depth", 2, f32s(&[0.5])).stage("vertex"))
        .buffer(Buffer::zeroed("out", 0, (TW * TH * 16) as usize).stage("tile"))
        .buffer(Buffer::data("size", 1, u32s(&[TW, TH])).stage("tile"))
        .texture(Texture::d2("c", "rgba32float", TW, TH).usage(&["render"]))
        .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&data)))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&colored))),
    );
    // Where an Apple GPU places a tile function's threads: in SIMD-groups of
    // 8 by 4 blocks of the threadgroup, cut short at its edges, of 2 by 2
    // quads in rows two threads high; its index runs the same quads across
    // the whole width. Odd sizes leave quads part empty.
    for [w, h] in [[16u32, 16u32], [12, 10], [3, 5], [32, 4], [1, 8]] {
        let (pw, ph) = (w.next_multiple_of(2), h.next_multiple_of(2));
        let mut out = vec![[0u32; 4]; 32 * 32];
        for y in 0..h {
            for x in 0..w {
                let (by, bx) = (y / 4, x / 8);
                let (bh, bw) = ((ph - 4 * by).min(4), (pw - 8 * bx).min(8));
                let quads = |x: u32, y: u32, across: u32| {
                    ((y / 2 * across + x / 2) << 2) | (y % 2) << 1 | (x % 2)
                };
                let lane = by * 4 * pw + bx * 8 * bh + quads(x % 8, y % 4, bw / 2);
                let index = quads(x, y, pw / 2);
                let neighbor = |x: u32, y: u32, inside: bool| {
                    if inside { x | y << 8 | 1 << 16 } else { 0 }
                };
                out[(y * 32 + x) as usize] = [
                    lane,
                    index | ((x % 2) | (y % 2) << 1) << 16,
                    neighbor(x ^ 1, y, (x ^ 1) < w),
                    neighbor(x, y ^ 1, (y ^ 1) < h),
                ];
            }
        }
        let words: Vec<u32> = out.into_iter().flatten().collect();
        plan.add(
            case(
                &format!("render.tile.lanes.{w}x{h}"),
                json!([{"function": "tile_lanes", "threads": [w, h]}]),
                json!({"tile_size": [32, 32]}),
            )
            .buffer(Buffer::zeroed("out", 0, 32 * 32 * 16).stage("tile"))
            .output(Output::exact("out", Dtype::U32, u32s(&words))),
        );
    }
    // Core Animation's blur downsample: tile_downsample_8 on a pipeline
    // limited to (32 / 4)^2 = 64 threads, 8 x 8 threads per 32 x 32 tile,
    // over a BGRA attachment (WindowServer's 'RGB10A8_2P_XR10' surface on
    // this device). Each output pixel averages an 8 x 8 block in half.
    {
        const W: u32 = 64;
        let texel = |x: u32, y: u32| -> [f64; 4] {
            let k = |v: u32| f64::from(v % 256) / 255.0;
            [
                k(x * 4 + y),
                k(y * 3 + 7 * x),
                k(x * y + 11),
                k(200 + x + y),
            ]
        };
        let colors: Vec<f64> = (0..W)
            .flat_map(|y| (0..W).flat_map(move |x| texel(x, y)))
            .collect();
        let average: Vec<f64> = (0..W / 8)
            .flat_map(|oy| (0..W / 8).map(move |ox| (ox, oy)))
            .flat_map(|(ox, oy)| {
                let mut sum = [0.0; 4];
                for y in oy * 8..oy * 8 + 8 {
                    for x in ox * 8..ox * 8 + 8 {
                        for (s, v) in sum.iter_mut().zip(texel(x, y)) {
                            *s += v / 64.0;
                        }
                    }
                }
                sum
            })
            .collect();
        let tiles = json!([{"function": "tile_downsample_ca8", "threads": [8, 8],
                            "max_total_threads": 64}]);
        let render = json!({"vertex_count": 3, "colors": [{"texture": "c"}], "tiles": tiles,
                            "tile_size": [32, 32]});
        plan.add(
            Case::render(
                "render.tile.downsample_8",
                library,
                "vert_full",
                Some("frag_color"),
                render,
            )
            .buffer(Buffer::data("colors", 0, f32s(&colors)).stage("fragment"))
            .buffer(Buffer::data("width", 1, u32s(&[W])).stage("fragment"))
            .buffer(Buffer::data("depth", 2, f32s(&[0.5])).stage("vertex"))
            .buffer(Buffer::data("offset", 9, u32s(&[0])).stage("tile"))
            // half 1.0
            .buffer(Buffer::data("edr_scale", 6, u32s(&[0x3c00])).stage("tile"))
            .texture(Texture::d2("c", "bgra8unorm", W, W).usage(&["render"]))
            .texture(
                Texture::d2("o", "rgba32float", W / 8, W / 8)
                    .usage(&["write"])
                    .index(0)
                    .set("stage", "tile"),
            )
            .output(Output::new("o", Dtype::F32, Tolerance::abs(2e-3)).expect_same(f32s(&average))),
        );
    }
    // Pipelines made from an archive given their functions, by completion
    // handler.
    plan.add(
        case(
            "render.tile.archived",
            json!([{"function": "tile_rewrite", "threads": [16, 8], "archive": true, "made": "async"}]),
            json!({"tile_size": [16, 16]}),
        )
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&rewritten))),
    );
    // Visible function tables of tile functions: entry (x + y + 1) % 2 of
    // the first, then the offset.
    let offset = |c: [f64; 4], x: f64, y: f64| [c[0] + x, c[1] + y, c[2] + 1.0, c[3]];
    let called = image(&|x, y| {
        let c: [f64; 4] = at(x, y).try_into().unwrap();
        let (lx, ly) = (f64::from(x % 16), f64::from(y % 16));
        let first = if (x % 16 + y % 16 + 1) % 2 == 0 {
            offset(c, lx, ly)
        } else {
            [c[1], c[0], c[3], lx * 2.0 + ly]
        };
        offset(first, lx, ly)
    });
    let tables = json!([
        {"index": 0, "functions": ["tile_offset", "tile_swap"]},
        {"index": 1, "functions": ["tile_offset"]}
    ]);
    let call = |name: &str, tile: Value| {
        let mut entry = json!({"function": "tile_call", "threads": [16, 16], "tables": tables,
                               "immutable_buffers": [2]});
        for (k, v) in tile.as_object().unwrap() {
            entry[k] = v.clone();
        }
        case(name, json!([entry]), json!({"tile_size": [16, 16]}))
            .buffer(Buffer::data("shift", 2, u32s(&[1])).stage("tile"))
            .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&called)))
    };
    let visible = json!({"visible_functions": ["tile_offset", "tile_swap"]});
    plan.add(call("render.tile.function_tables", visible.clone()));
    plan.add(call("render.tile.function_tables.ranges", visible.clone()).set("bind", "ranges"));
    plan.add(call(
        "render.tile.function_tables.binary_functions",
        json!({"added_binary_functions": ["tile_offset", "tile_swap"]}),
    ));
    let mut reflected = visible;
    reflected["reflection"] = json!("reflection");
    reflected["required_threads"] = json!([16, 16, 1]);
    let mut reflection = TILE_REFLECTION.join("\n").into_bytes();
    reflection.resize(2048, 0);
    plan.add(
        call("render.tile.reflection", reflected)
            .buffer(Buffer::zeroed("reflection", 0, 2048).unbound())
            .output(Output::exact("reflection", Dtype::U8, reflection)),
    );
}

/// Early fragment tests: an occluding instance, then one over the whole
/// target behind it, whose fragment function counts its runs. The hidden
/// fragments are rejected before they run, so the counts are exact.
fn early_fragment_tests(plan: &mut Plan, library: &str) {
    let colors = [[0.25, 0.5, 0.75, 1.0], [1.0, 0.0, 0.5, 0.25]];
    let image: Vec<f64> = pixels()
        .flat_map(|(x, _)| colors[usize::from(x >= W / 2)])
        .collect();
    let half = W / 2 * H;
    plan.add(
        Case::render(
            "render.depth.early_fragment_tests",
            library,
            "vert_occluder",
            Some("frag_early"),
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}],
                   "depth": {"texture": "d", "clear": 1.0, "compare": "less"},
                   "primitive": "triangle_strip", "vertex_count": 4, "instance_count": 2}),
        )
        .texture(target("c", "rgba32float"))
        .texture(target("d", "depth32float"))
        .buffer(Buffer::zeroed("runs", 0, 16).stage("fragment"))
        .buffer(Buffer::data("colors", 1, f32s(&colors.concat())).stage("fragment"))
        .output(Output::new("c", Dtype::F32, Tolerance::exact()).expect_same(f32s(&image)))
        .output(
            Output::new("runs", Dtype::U32, Tolerance::exact())
                .expect_same(u32s(&[half, half, 0, 0])),
        ),
    );
}

/// Formats a device may render through their raw texels: blended and
/// resolved as Metal's are, and cleared to the texel a clear color rounds
/// to.
fn raw_rendered(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(907);
    let n = (W * H) as usize;
    for format in ["r8unorm_srgb", "rg8unorm_srgb", "abgr4unorm"] {
        let srgb_target = format.ends_with("srgb");
        // Over: the source's alpha mixes it with the target, in linear
        // space for sRGB. ABGR4 adds lattice values whose sums stay on it.
        let (blend, texels, stored): (Value, Vec<[f64; 4]>, Vec<[f64; 4]>) = if srgb_target {
            let s = (0..n)
                .map(|_| std::array::from_fn(|_| f32r(rng.uniform(0.0, 1.0))))
                .collect();
            let d = (0..n)
                .map(|_| {
                    std::array::from_fn(|lane| match lane {
                        0 | 1 => srgb(f64::from(rng.u32() % 256) / 255.0),
                        2 => 0.0,
                        _ => 1.0,
                    })
                })
                .collect();
            (
                Blend::simple("add", "source_alpha", "one_minus_source_alpha").json(),
                s,
                d,
            )
        } else {
            let pairs: Vec<([f64; 4], [f64; 4])> = (0..n)
                .map(|_| {
                    let mut s = [0.0; 4];
                    let mut d = [0.0; 4];
                    for lane in 0..4 {
                        let a = rng.u32() % 16;
                        let b = rng.u32() % (16 - a);
                        s[lane] = f64::from(a) / 15.0;
                        d[lane] = f64::from(b) / 15.0;
                    }
                    (s, d)
                })
                .collect();
            (
                Blend::simple("add", "one", "one").json(),
                pairs.iter().map(|p| p.0).collect(),
                pairs.iter().map(|p| p.1).collect(),
            )
        };
        let over = Blend::simple("add", "source_alpha", "one_minus_source_alpha");
        let (mut initial, mut expected, mut lows, mut highs) = (vec![], vec![], vec![], vec![]);
        let mut dtype = Dtype::U8;
        for (s, d) in texels.iter().zip(&stored) {
            initial.extend(store(format, *d).0);
            let out = if srgb_target {
                let a = s[3];
                let [low, high] = over.bounds(*s, *d, [0.0; 4], true);
                lows.extend(store(format, low).0);
                highs.extend(store(format, high).0);
                std::array::from_fn(|lane| s[lane] * a + d[lane] * (1.0 - a))
            } else {
                std::array::from_fn(|lane| s[lane] + d[lane])
            };
            let (bytes, d) = store(format, out);
            expected.extend(bytes);
            dtype = d;
        }
        let output = if srgb_target {
            // A blend unit may take the source at the target's precision,
            // as the sRGB blends do: any result within the bounds, by
            // alternatives a tolerance apart.
            let tol = Tolerance::units(1.0);
            let widest = lows
                .iter()
                .zip(&highs)
                .map(|(l, h)| h - l)
                .max()
                .unwrap_or(0);
            let mut output = Output::new("c", dtype, tol.clone())
                .expect(expected, tol)
                .judged_by_expectation();
            for step in 0..=widest.div_ceil(3) {
                let at = |(&l, &h): (&u8, &u8)| l.saturating_add(step.saturating_mul(3)).min(h);
                output = output.expect_alternative(lows.iter().zip(&highs).map(at).collect());
            }
            output
        } else {
            Output::new("c", dtype, Tolerance::exact()).expect(expected, Tolerance::exact())
        };
        plan.add(
            full(
                &format!("render.blend.{format}.raw"),
                library,
                "frag_color",
                &texels.concat(),
                json!({"colors": [{"texture": "c", "blend": blend}]}),
            )
            .texture(target("c", format).data(initial))
            .output(output),
        );
        let tol = if srgb_target {
            Tolerance::units(1.0)
        } else {
            Tolerance::exact()
        };

        // A 4x resolve of a slanted triangle's coverage: each pixel's mean
        // of its samples, decoded and encoded by the format.
        let full_vp = [0.0, 0.0, W as f64, H as f64];
        let c = [
            clip(0.5, 1.25, 0.5, 1.0, full_vp),
            clip(15.5, 6.75, 0.5, 1.0, full_vp),
            clip(3.25, 15.0, 0.5, 1.0, full_vp),
        ];
        let t = c.map(|v| window(v, full_vp));
        // 0.8 in quarters stays on ABGR4's lattice: 0.2 k is 3 k / 15.
        let attrs = [[0.8; 4]; 3];
        // A pixel with a sample on an edge is covered as the device's edge
        // rule decides, which the expectation leaves out.
        let (mut resolved, mut defined) = (vec![], vec![]);
        for (x, y) in pixels() {
            let k = coverage(&t, x, y);
            defined.push(u8::from(k.is_some()));
            resolved.extend(store(format, [0.8 * f64::from(k.unwrap_or(0)) / 4.0; 4]).0);
        }
        let stride = store(format, [0.0; 4]).0.len() / dtype.size();
        plan.add(
            Case::render(
                &format!("render.msaa4.resolve.{format}"),
                library,
                "vert_plain",
                Some("frag_attribute"),
                json!({"colors": [{"texture": "ms", "clear": [0, 0, 0, 0], "resolve": "c"}],
                       "samples": 4, "vertex_count": 3}),
            )
            .buffer(Buffer::data("positions", 0, f32s(&c.concat())).stage("vertex"))
            .buffer(Buffer::data("attributes", 1, f32s(&attrs.concat())).stage("vertex"))
            .texture(
                Texture::new("ms", format, "2d_ms", [W, H, 1])
                    .samples(4)
                    .usage(&["render"]),
            )
            .texture(target("c", format))
            .output(
                Output::new("c", dtype, tol.clone())
                    .expect(resolved, tol.clone())
                    .expect_mask(defined)
                    .set("stride", stride),
            ),
        );

        // A clear and nothing drawn.
        // Away from ABGR4's rounding ties.
        let clear = [0.32, 0.55, 0.8, 0.45];
        let cleared: Vec<u8> = (0..n).flat_map(|_| store(format, clear).0).collect();
        plan.add(
            Case::render(
                &format!("render.clear.{format}"),
                library,
                "vert_plain",
                Some("frag_one"),
                json!({"colors": [{"texture": "c", "clear": clear}], "vertex_count": 0}),
            )
            .buffer(Buffer::data("positions", 0, f32s(&[0.0; 4])).stage("vertex"))
            .buffer(Buffer::data("attributes", 1, f32s(&[0.0; 4])).stage("vertex"))
            .texture(target("c", format))
            .output(Output::new("c", dtype, tol.clone()).expect(cleared, tol)),
        );
    }
}

/// Extended-range targets the blend unit blends: a result past the codes'
/// range stores code 1023, and each result its nearest code, as the Mac's.
fn extended_range_blends(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(911);
    let n = (W * H) as usize;
    for (format, label, blend) in [
        (
            "bgr10_xr",
            "add_one_one",
            Blend::simple("add", "one", "one"),
        ),
        (
            "bgra10_xr",
            "over",
            Blend::simple("add", "source_alpha", "one_minus_source_alpha"),
        ),
        (
            "bgra10_xr_srgb",
            "over",
            Blend::simple("add", "source_alpha", "one_minus_source_alpha"),
        ),
    ] {
        let curve = format.ends_with("srgb");
        // The packed target's codes share a word, so its sources are codes'
        // values (and values beyond the range), whose sums with 1.0 are codes
        // again; the others' are any values and their results within a code.
        let packed = format == "bgr10_xr";
        let s: Vec<[f64; 4]> = (0..n)
            .map(|_| {
                std::array::from_fn(|lane| {
                    if packed {
                        f32r(xr_value(&mut rng, false, lane))
                    } else {
                        f32r(rng.uniform(0.0, if lane == 3 { 1.0 } else { 1.6 }))
                    }
                })
            })
            .collect();
        // 1.0 is a code's value, linear or through the curve.
        let d = [1.0; 4];
        let initial: Vec<u8> = (0..n).flat_map(|_| store(format, d).0).collect();
        let mut expected = vec![];
        let mut dtype = Dtype::U8;
        for s in &s {
            // Apple GPUs blend the output as the target holds it: each color
            // its nearest code's value, clamped to the codes, alpha in [0, 1].
            let held: [f64; 4] = std::array::from_fn(|lane| {
                if lane == 3 {
                    s[3].clamp(0.0, 1.0)
                } else {
                    xr(xr_code(s[lane], curve), curve)
                }
            });
            let (bytes, kind) = store(format, blend.apply(held, held, d, [0.0; 4], false));
            expected.extend(bytes);
            dtype = kind;
        }
        // A code of the half-word formats is 64 units.
        let tol = Tolerance::units(if packed { 0.0 } else { 64.0 });
        let colors = json!({"colors": [{"texture": "c", "blend": blend.json()}]});
        plan.add(
            full(
                &format!("render.blend.{format}.{label}"),
                library,
                "frag_color",
                &s.concat(),
                colors.clone(),
            )
            .texture(target("c", format).data(initial.clone()))
            .output(Output::new("c", dtype, tol.clone()).expect(expected, tol)),
        );
        if curve {
            continue;
        }
        // The same blend read back by a kernel, which sees the texels the
        // GPU holds rather than the bytes a CPU read converts: each the
        // value of its code, within the codes' range.
        let read: Vec<f64> = s
            .iter()
            .flat_map(|s| {
                let held: [f64; 4] = std::array::from_fn(|lane| {
                    if lane == 3 {
                        s[3].clamp(0.0, 1.0)
                    } else {
                        xr(xr_code(s[lane], false), false)
                    }
                });
                let out = blend.apply(held, held, d, [0.0; 4], false);
                let alpha = if packed {
                    1.0
                } else {
                    xr(xr_alpha_code(out[3]), false)
                };
                [0, 1, 2]
                    .map(|lane| xr(xr_code(out[lane], false), false))
                    .into_iter()
                    .chain([alpha])
            })
            .collect();
        // Half a code, within which a half float holds each code's value,
        // and a code more where sources are not codes: Apple GPUs blend
        // them within one.
        let codes = Tolerance::abs(if packed { 0.5 } else { 1.5 } / 510.0);
        let mut state = colors;
        state["vertex_count"] = 3.into();
        plan.add(
            Case::sequence(
                &format!("render.blend.{format}.{label}.read"),
                library,
                vec![
                    Step::render("vert_full", "frag_color", state)
                        .bind_stage("fragment", &[("colors", 0), ("width", 1)])
                        .bind_stage("vertex", &[("depth", 2)]),
                    Step::compute("read_texels", [W, H, 1], [8, 8, 1])
                        .bind_textures(&[("c", 0)])
                        .bind(&[("texels", 0)]),
                ],
            )
            .buffer(Buffer::data("colors", 0, f32s(&s.concat())).unbound())
            .buffer(Buffer::data("width", 0, u32s(&[W])).unbound())
            .buffer(Buffer::data("depth", 0, f32s(&[0.5])).unbound())
            .buffer(Buffer::zeroed("texels", 0, (W * H * 16) as usize).unbound())
            .texture(
                Texture::d2("c", format, W, H)
                    .usage(&["render", "read"])
                    .data(initial),
            )
            .output(Output::new("texels", Dtype::F32, codes.clone()).expect(f32s(&read), codes)),
        );
    }
}

/// `RGB10A8_2P_XR10` (550), the format of WindowServer's framebuffers and
/// Core Animation's surfaces. Measured on an M1 Pro (macOS 27.2): color
/// holds the extended-range codes of `BGR10_XR`, alpha 8-bit unorm; reads
/// and samples return the codes' values; blending adds in those values and
/// clamps at the codes' ends; a tile function reads the fragment outputs
/// unclamped from the imageblock, as half floats.
fn extended_range_two_plane(plan: &mut Plan, library: &str) {
    const FORMAT: &str = "rgb10a8_2p_xr10";
    let mut rng = Random::new(913);
    let n = (W * H) as usize;
    let alpha8 = |a: f64| (a.clamp(0.0, 1.0) * 255.0).round() / 255.0;
    let held = |t: [f64; 4]| -> [f64; 4] {
        std::array::from_fn(|lane| {
            if lane == 3 {
                alpha8(t[3])
            } else {
                xr(xr_code(t[lane], false), false)
            }
        })
    };
    // Codes' values, a few past the range; alpha on its 8-bit lattice,
    // a few past [0, 1].
    let values: Vec<[f64; 4]> = (0..n)
        .map(|_| {
            std::array::from_fn(|lane| {
                if lane == 3 {
                    return match rng.u32() % 8 {
                        0 => -0.5,
                        1 => 1.5,
                        _ => f64::from(rng.u32() % 256) / 255.0,
                    };
                }
                f32r(xr_value(&mut rng, false, lane))
            })
        })
        .collect();
    let read = |name: &str, state: Value, expected: Vec<f64>, tolerance: Tolerance| {
        Case::sequence(
            name,
            library,
            vec![
                Step::render("vert_full", "frag_color", state)
                    .bind_stage("fragment", &[("colors", 0), ("width", 1)])
                    .bind_stage("vertex", &[("depth", 2)]),
                Step::compute("read_texels", [W, H, 1], [8, 8, 1])
                    .bind_textures(&[("c", 0)])
                    .bind(&[("texels", 0)]),
            ],
        )
        .buffer(Buffer::data("width", 0, u32s(&[W])).unbound())
        .buffer(Buffer::data("depth", 0, f32s(&[0.5])).unbound())
        .buffer(Buffer::zeroed("texels", 0, (W * H * 16) as usize).unbound())
        .texture(Texture::d2("c", FORMAT, W, H).usage(&["render", "read"]))
        .output(
            Output::new("texels", Dtype::F32, tolerance.clone()).expect(f32s(&expected), tolerance),
        )
    };
    // Written values read back: each color its code's value, clamped to the
    // codes, alpha to 1/255.
    let expected: Vec<f64> = values.iter().flat_map(|t| held(*t)).collect();
    plan.add(
        read(
            &format!("render.{FORMAT}.read"),
            json!({"vertex_count": 3, "colors": [{"texture": "c", "clear": [0, 0, 0, 0]}]}),
            expected,
            Tolerance::abs(1e-4),
        )
        .buffer(Buffer::data("colors", 0, f32s(&values.concat())).unbound()),
    );
    // Source over a cleared target: the blend of the held source and
    // destination, then held again. The Mac lands within 3 codes of that
    // where the source is past the codes (measured: code 845 for 848).
    let blend = Blend::simple("add", "source_alpha", "one_minus_source_alpha");
    let clear = [1.0, 0.5, -0.5, 0.6];
    let sources: Vec<[f64; 4]> = (0..n)
        .map(|_| {
            std::array::from_fn(|lane| f32r(rng.uniform(-0.5, if lane == 3 { 1.0 } else { 1.6 })))
        })
        .collect();
    let blended: Vec<f64> = sources
        .iter()
        .flat_map(|s| {
            let s = held(*s);
            held(blend.apply(s, s, held(clear), [0.0; 4], false))
        })
        .collect();
    plan.add(
        read(
            &format!("render.{FORMAT}.blend.over.read"),
            json!({"vertex_count": 3,
                   "colors": [{"texture": "c", "clear": clear, "blend": blend.json()}]}),
            blended,
            Tolerance::abs(4.0 / 510.0),
        )
        .buffer(Buffer::data("colors", 0, f32s(&sources.concat())).unbound()),
    );
    // The fragment outputs as a tile function reads them in the pass: half
    // floats, past the codes' range too.
    let unclamped: Vec<f64> = values.iter().flatten().map(|&v| f16r(v)).collect();
    let tiles = json!([{"function": "tile_store_colors", "threads": [16, 16]}]);
    plan.add(
        full(
            &format!("render.{FORMAT}.tile_read"),
            library,
            "frag_color",
            &values.concat(),
            json!({"colors": [{"texture": "c", "clear": [0, 0, 0, 0]}], "tiles": tiles,
                   "tile_size": [16, 16]}),
        )
        .buffer(Buffer::zeroed("out", 0, (W * H * 16) as usize).stage("tile"))
        .buffer(Buffer::data("out_width", 1, u32s(&[W])).stage("tile"))
        .texture(target("c", FORMAT))
        .output(Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&unclamped))),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("render", SOURCE, &[], LATEST);
    extended_range_blends(plan, &library);
    extended_range_two_plane(plan, &library);
    early_fragment_tests(plan, &library);
    interpolation(plan, &library);
    derivatives(plan, &library);
    branch_derivatives(plan, &library);
    fragment_simd_layout(plan, &library);
    builtins(plan, &library);
    targets(plan, &library);
    blending(plan, &library);
    depth(plan, &library);
    stencil(plan, &library);
    multisampling(plan, &library);
    raw_rendered(plan, &library);
    points(plan, &library);
    lines(plan, &library);
    edges(plan, &library);
    fetch(plan, &library);
    tiles(plan, &library);
    fragment_queries(plan, &library);
    layers_and_clipping(plan, &library);
    plan.add(Case::device("device.properties"));
    // What the driver claims and leaves unclaimed, feature by feature:
    // checked on the device compared with the Mac.
    plan.add(Case::device("device.policy").set(
        "policy",
        json!({
            "families.apple1": true, "families.apple2": true, "families.apple3": true,
            "families.common1": true, "families.common2": true, "families.common3": true,
            "families.mac2": true, "families.apple4": true,
            "families.apple5": true, "families.apple6": true, "families.apple7": true,
            "families.apple8": false, "families.apple9": false, "families.apple10": false,
            "families.apple11": false, "families.metal3": true, "families.metal4": false,
            "features.raytracing": false, "features.raster_order_groups": true,
            "features.framebuffer_reads": true,
            "features.primitive_motion_blur": false, "features.memoryless_render_targets": true,
        }),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rasterizer_classifies_centers() {
        let full = [0.0, 0.0, 16.0, 16.0];
        let t = [
            clip(0.0, 0.0, 0.5, 1.0, full),
            clip(8.0, 0.0, 0.5, 1.0, full),
            clip(0.0, 8.0, 0.5, 1.0, full),
        ]
        .map(|c| window(c, full));
        assert!(matches!(locate(&t, 1.5, 1.5), Px::In(_)));
        assert!(matches!(locate(&t, 4.0, 4.0), Px::Edge));
        assert!(matches!(locate(&t, 7.5, 7.5), Px::Out));
        // Top-left, top-right, bottom-left turns clockwise however y points.
        assert!(!ccw(&t));
    }

    #[test]
    fn perspective_weights_follow_one_over_w() {
        let full = [0.0, 0.0, 16.0, 16.0];
        let t = [
            clip(0.0, 0.0, 0.0, 1.0, full),
            clip(16.0, 0.0, 0.0, 4.0, full),
            clip(0.0, 16.0, 0.0, 1.0, full),
        ]
        .map(|c| window(c, full));
        let p = perspective(&t, [0.5, 0.5, 0.0]);
        assert!((p[0] - 0.8).abs() < 1e-12 && (p[1] - 0.2).abs() < 1e-12);
    }

    #[test]
    fn blend_and_stencil_equations() {
        let b = Blend::simple("add", "source_alpha", "one_minus_source_alpha");
        let out = b.apply(
            [1.0, 0.0, 0.0, 0.25],
            [0.0; 4],
            [0.0, 1.0, 0.0, 1.0],
            [0.0; 4],
            true,
        );
        assert_eq!(out, [0.25, 0.75, 0.0, 0.25 * 0.25 + 0.75]);
        assert_eq!(stencil_op("decrement_wrap", 0, 9), 255);
        assert_eq!(stencil_op("increment_clamp", 255, 9), 255);
        let f = Face {
            compare: "equal",
            fail: "zero",
            depth_fail: "keep",
            pass: "replace",
            read_mask: 0x0F,
            write_mask: 0xF0,
        };
        assert_eq!(f.apply(0x35, 0xA5, true), (0xA5, true));
        assert_eq!(f.apply(0x34, 0xA5, true), (0x04, false));
    }

    #[test]
    fn vertex_formats_decode() {
        let f = vertex_formats()
            .into_iter()
            .find(|f| f.name == "int1010102normalized")
            .unwrap();
        assert_eq!(
            (f.decode)(&0xC000_01FFu32.to_le_bytes()),
            [1.0, 0.0, 0.0, -1.0]
        );
    }
}
