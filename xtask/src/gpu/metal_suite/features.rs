//! corpus/features.metal: the compute features `coverage` found macOS's
//! shaders use and the other families leave out, each asserted exactly
//! (sRGB packing to within one unit). SIMD-group results assume 32-lane
//! groups of consecutive threads, as compute.rs does.
use super::convert::{bfloat, srgb_encode};
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::textures::{decode, format_named, read_tolerance, texel_bytes};
use super::values::{Dtype, Random, bits32, f16r, f32r, f32s, floats, ints, u32s};

const SOURCE: &str = "features.metal";
const SIMD: usize = 32;

fn exact(name: &str, dtype: Dtype, data: Vec<u8>) -> Output {
    Output::new(name, dtype, Tolerance::exact()).expect_same(data)
}

fn relational(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 256;
    let v: Vec<[i64; 4]> = (0..n)
        .map(|_| [0; 4].map(|_: i64| rng.below(13) - 6))
        .collect();
    let mut out = vec![];
    for x in &v {
        let b = |c: bool| u32::from(c);
        out.extend([
            b(x.iter().all(|&e| e > 0)),
            b(x.iter().any(|&e| e > 0)),
            b(x[0] == x[2] && x[1] == x[3]),
            b(x[..3].iter().any(|&e| e < -5)),
            b(x[..3].iter().all(|&e| e != 0)),
            b(x.iter().any(|&e| e & 1 != 0)),
            b(x[0] != 0 && x[1] != 0),
            if x[1..].iter().any(|&e| e != 0) { 7 } else { 9 },
        ]);
    }
    let input: Vec<i128> = v.iter().flatten().map(|&e| i128::from(e)).collect();
    plan.add(
        Case::compute1("features.relational", library, "relational", n as u32)
            .buffer(Buffer::data("in", 0, ints(Dtype::I32, &input)))
            .buffer(Buffer::zeroed("out", 1, n * 32))
            .output(exact("out", Dtype::U32, u32s(&out))),
    );
}

fn atomics(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 256;
    let v: Vec<u32> = (0..n).map(|_| rng.u32()).collect();
    let data: Vec<u32> = v
        .iter()
        .map(|x| x.wrapping_mul(5).wrapping_add(3))
        .collect();
    let flags: Vec<u32> = v.iter().map(|x| x ^ 0x5A5A_5A5A).collect();
    let signed: Vec<u32> = v.iter().map(|x| (-((x % 1000) as i32)) as u32).collect();
    let out: Vec<u32> = (0..n)
        .flat_map(|i| [flags[i].wrapping_add(data[i]), signed[i]])
        .collect();
    plan.add(
        Case::compute1(
            "features.atomic_store_fence",
            library,
            "atomic_store_fence",
            n as u32,
        )
        .buffer(Buffer::data("in", 0, u32s(&v)))
        .buffer(Buffer::zeroed("data", 1, n * 4))
        .buffer(Buffer::zeroed("flags", 2, n * 4))
        .buffer(Buffer::zeroed("signed_flags", 3, n * 4))
        .buffer(Buffer::zeroed("out", 4, n * 8))
        .output(exact("data", Dtype::U32, u32s(&data)))
        .output(exact("flags", Dtype::U32, u32s(&flags)))
        .output(exact("signed_flags", Dtype::U32, u32s(&signed)))
        .output(exact("out", Dtype::U32, u32s(&out))),
    );
    let (n, group) = (1024, 64);
    let v: Vec<u32> = (0..n).map(|_| rng.u32()).collect();
    let mut out = vec![];
    for g in v.chunks(group) {
        let (mut or, mut and, mut xor) = (0u32, u32::MAX, 0u32);
        for (local, &x) in g.iter().enumerate() {
            or |= x & (0x0101_0101 << (local % 8));
            and &= x | 0x0F0F_0F0F;
            xor ^= x;
        }
        out.extend([or, and, xor]);
    }
    plan.add(
        Case::compute1(
            "features.atomics.threadgroup_bits",
            library,
            "atomics_threadgroup_bits",
            n as u32,
        )
        .buffer(Buffer::data("in", 0, u32s(&v)))
        .buffer(Buffer::zeroed("out", 1, n / group * 12))
        .output(exact("out", Dtype::U32, u32s(&out))),
    );
}

fn simd(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 256;
    let v: Vec<u32> = (0..n).map(|_| rng.u32()).collect();
    let out: Vec<u32> = (0..n)
        .map(|i| {
            let lane = i % SIMD;
            v[i - lane + (lane + 13) % SIMD]
                .wrapping_mul(3)
                .wrapping_add(1)
        })
        .collect();
    plan.add(
        Case::compute1(
            "features.simdgroup_barrier",
            library,
            "simdgroup_exchange",
            n as u32,
        )
        .buffer(Buffer::data("in", 0, u32s(&v)))
        .buffer(Buffer::zeroed("out", 1, n * 4))
        .output(exact("out", Dtype::U32, u32s(&out))),
    );
    if plan.has(SOURCE, "quad_more") {
        let v: Vec<u32> = (0..n).map(|_| rng.u32() % 600).collect();
        let mut out = vec![];
        for i in 0..n {
            let lane = i % 4;
            let q = &v[i - lane..i - lane + 4];
            let s: Vec<i32> = q.iter().map(|&x| x as i32 - 300).collect();
            let fill = |k: usize| q[k] + 1000;
            let product = |xs: &[u32], m: u32| xs.iter().map(|x| x % m + 1).product::<u32>();
            let flags = u32::from(q.iter().all(|&x| x < 500))
                | u32::from(q.iter().any(|&x| x > 550)) << 1
                | u32::from(lane == 0) << 2;
            out.extend([
                if lane >= 1 { q[lane - 1] } else { q[lane] },
                if lane + 2 < 4 { q[lane + 2] } else { q[lane] },
                q[(lane + 3) % 4],
                q[(lane + 3) % 4],
                if lane >= 1 {
                    q[lane - 1]
                } else {
                    fill(3 + lane)
                },
                if lane + 2 < 4 {
                    q[lane + 2]
                } else {
                    fill(lane + 2 - 4)
                },
                q.iter().fold(u32::MAX, |a, x| a & (x | 0xF0)),
                q.iter().fold(0, |a, x| a | (x & 0x30)),
                q.iter().fold(0, |a, x| a ^ x),
                product(q, 5),
                q[..lane].iter().sum(),
                product(&q[..=lane], 3),
                product(&q[..lane], 3),
                q[0],
                flags,
                0xF,
                s.iter().sum::<i32>() as u32,
                *s.iter().min().unwrap() as u32,
                bits32(q.iter().map(|&x| f64::from(x % 64) * 0.25).sum()),
                bits32(
                    s.iter()
                        .map(|&x| f64::from(x) * 0.5)
                        .fold(f64::MIN, f64::max),
                ),
            ]);
        }
        plan.add(
            Case::compute1("features.quad.more", library, "quad_more", n as u32)
                .buffer(Buffer::data("in", 0, u32s(&v)))
                .buffer(Buffer::zeroed("out", 1, n * 80))
                .output(exact("out", Dtype::U32, u32s(&out))),
        );
    }
    if plan.has(SOURCE, "simdgroup_diagonal") {
        let b: Vec<f64> = (0..64).map(|_| (rng.below(9) - 4) as f64).collect();
        let mut expected: Vec<f64> = b.iter().map(|x| x * 2.5).collect();
        expected.extend([-1.5; 64]);
        plan.add(
            Case::compute(
                "features.simdgroup_matrix.diagonal",
                library,
                "simdgroup_diagonal",
                [32, 1, 1],
                [32, 1, 1],
            )
            .buffer(Buffer::data("b", 0, f32s(&b)))
            .buffer(Buffer::zeroed("out", 1, 512))
            .output(exact("out", Dtype::F32, f32s(&expected)))
            .requires(&[], &["simd_reduction"]),
        );
    }
}

/// Each thread's quad-group index, the group count and its lane, in
/// threadgroups of 64.
fn quadgroups(plan: &mut Plan, library: &str) {
    let out: Vec<u32> = (0..256u32)
        .map(|i| ((i % 64 / 4) << 16) | (16 << 8) | (i % 4))
        .collect();
    plan.add(
        Case::compute1("features.quadgroup_ids", library, "quadgroup_ids", 256)
            .buffer(Buffer::zeroed("out", 0, 1024))
            .output(exact("out", Dtype::U32, u32s(&out))),
    );
}

fn textures(plan: &mut Plan, library: &str, rng: &mut Random) {
    if !plan.has(SOURCE, "null_textures") {
        return;
    }
    let pick = [1u32, 0, 1, 0, 0, 1, 1, 0];
    let texels: Vec<u8> = (0..16).map(|_| (rng.u32() % 256) as u8).collect();
    let out: Vec<u32> = pick
        .iter()
        .enumerate()
        .flat_map(|(i, &p)| {
            if p != 0 {
                [0x10, u32::from(texels[i % 4 * 4])]
            } else {
                [0x1F, 0xFFFF]
            }
        })
        .collect();
    plan.add(
        Case::compute1("features.null_textures", library, "null_textures", 8)
            .texture(
                Texture::d2("bound", "rgba8unorm", 4, 1)
                    .index(0)
                    .data(texels),
            )
            .texture(
                Texture::new("layers", "rgba8unorm", "2d_array", [4, 1, 1])
                    .array(2)
                    .index(1),
            )
            .texture(Texture::new("cube", "rgba8unorm", "cube", [1, 1, 1]).index(2))
            .texture(Texture::new("volume", "rgba8unorm", "3d", [1, 1, 1]).index(3))
            .buffer(Buffer::data("pick", 0, u32s(&pick)))
            .buffer(Buffer::zeroed("out", 1, 64))
            .output(exact("out", Dtype::U32, u32s(&out))),
    );
}

/// rg16snorm: each lane k / 32767, with -32768 as -1.
fn rg16snorm(b: &[u8]) -> [f64; 4] {
    let lane =
        |k: usize| (f64::from(i16::from_le_bytes([b[2 * k], b[2 * k + 1]])) / 32767.0).max(-1.0);
    [lane(0), lane(1), 0.0, 0.0]
}

fn pixels(plan: &mut Plan, library: &str, rng: &mut Random) {
    let n = 64;
    if plan.has(SOURCE, "pixel_unpack") {
        let mut case = Case::compute1(
            "features.pixel_types.unpack",
            library,
            "pixel_unpack",
            n as u32,
        );
        for (k, format) in [
            "rgba8unorm",
            "rgba8unorm_srgb",
            "rgb10a2unorm",
            "rg11b10float",
            "rgb9e5float",
        ]
        .into_iter()
        .enumerate()
        {
            let f = format_named(format);
            let raw: Vec<Vec<u8>> = (0..n).map(|_| texel_bytes(&f, rng)).collect();
            let values: Vec<f64> = raw
                .iter()
                .flat_map(|t| {
                    let mut d = decode(&f, t);
                    if k >= 3 {
                        d[3] = 0.0;
                    }
                    d
                })
                .collect();
            case = case
                .buffer(Buffer::data(&format!("in{k}"), k as u32, raw.concat()))
                .buffer(Buffer::zeroed(&format!("out{k}"), k as u32 + 6, n * 16))
                .output(
                    Output::new(&format!("out{k}"), Dtype::F32, read_tolerance(&f))
                        .expect_same(f32s(&values)),
                );
        }
        let raw: Vec<u8> = (0..n * 4).map(|_| (rng.u32() % 256) as u8).collect();
        let values: Vec<f64> = raw.chunks(4).flat_map(|t| rg16snorm(t).map(f32r)).collect();
        plan.add(
            case.buffer(Buffer::data("in5", 5, raw))
                .buffer(Buffer::zeroed("out5", 11, n * 16))
                .output(
                    Output::new("out5", Dtype::F32, Tolerance::ulp(1.0)).expect_same(f32s(&values)),
                ),
        );
    }
    if plan.has(SOURCE, "pixel_pack") {
        // Every input but the sRGB one is exactly representable, so its
        // encoding is the only correct one.
        let mut input = vec![];
        let (mut a, mut b, mut c, mut d, mut e, mut f) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        for _ in 0..n {
            let bytes: [u8; 4] = [0; 4].map(|_: u8| (rng.u32() % 256) as u8);
            input.extend(bytes.map(|q| f64::from(q) / 255.0));
            a.extend(bytes);
            let linear: [f64; 4] = [0; 4].map(|_: u8| f32r(rng.uniform(0.0, 1.0)));
            input.extend(linear);
            b.extend(
                linear[..3]
                    .iter()
                    .map(|&x| (srgb_encode(x) * 255.0).round() as u8),
            );
            b.push((linear[3] * 255.0).round() as u8);
            let q = [
                rng.u32() % 1024,
                rng.u32() % 1024,
                rng.u32() % 1024,
                rng.u32() % 4,
            ];
            input.extend([
                f64::from(q[0]) / 1023.0,
                f64::from(q[1]) / 1023.0,
                f64::from(q[2]) / 1023.0,
                f64::from(q[3]) / 3.0,
            ]);
            c.push(q[0] | q[1] << 10 | q[2] << 20 | q[3] << 30);
            let small = texel_bytes(&format_named("rg11b10float"), rng);
            let decoded = decode(&format_named("rg11b10float"), &small);
            input.extend([decoded[0], decoded[1], decoded[2], 0.0]);
            d.extend(small);
            // A shared exponent of 2..30 with the largest mantissa in
            // 256..511: the encoding the largest component determines.
            let exponent = rng.u32() % 29 + 2;
            let top = rng.u32() % 256 + 256;
            let largest = (rng.u32() % 3) as usize;
            let mantissas: [u32; 3] = std::array::from_fn(|k| {
                if k == largest {
                    top
                } else {
                    rng.u32() % (top + 1)
                }
            });
            let scale = 2f64.powi(exponent as i32 - 24);
            input.extend([mantissas[0], mantissas[1], mantissas[2]].map(|m| f64::from(m) * scale));
            input.push(0.0);
            e.push(mantissas[0] | mantissas[1] << 9 | mantissas[2] << 18 | exponent << 27);
            let s = [rng.below(65535) - 32767, rng.below(65535) - 32767];
            input.extend([s[0] as f64 / 32767.0, s[1] as f64 / 32767.0, 0.0, 0.0]);
            f.extend(s.iter().flat_map(|&x| (x as i16).to_le_bytes()));
        }
        let input: Vec<f64> = input.into_iter().map(f32r).collect();
        plan.add(
            Case::compute1("features.pixel_types.pack", library, "pixel_pack", n as u32)
                .buffer(Buffer::data("in", 0, f32s(&input)))
                .buffer(Buffer::zeroed("a", 1, n * 4))
                .buffer(Buffer::zeroed("b", 2, n * 4))
                .buffer(Buffer::zeroed("c", 3, n * 4))
                .buffer(Buffer::zeroed("d", 4, n * 4))
                .buffer(Buffer::zeroed("e", 5, n * 4))
                .buffer(Buffer::zeroed("f", 6, n * 4))
                .output(exact("a", Dtype::U8, a))
                .output(Output::new("b", Dtype::U8, Tolerance::units(1.0)).expect_same(b))
                .output(exact("c", Dtype::U32, u32s(&c)))
                .output(exact("d", Dtype::U8, d))
                .output(exact("e", Dtype::U32, u32s(&e)))
                .output(exact("f", Dtype::U8, f)),
        );
    }
}

fn values(plan: &mut Plan, library: &str, rng: &mut Random) {
    if plan.has(SOURCE, "uniform_values") {
        let v: Vec<u32> = (0..64).map(|_| rng.u32() % 1000).collect();
        let out: Vec<u32> = (0..64)
            .map(|i| (0..10).map(|j| v[(i + j) % 64]).sum())
            .collect();
        plan.add(
            Case::compute1("features.uniform", library, "uniform_values", 64)
                .buffer(Buffer::data("in", 0, u32s(&v)))
                .buffer(Buffer::data("k", 1, u32s(&[5])))
                .buffer(Buffer::zeroed("out", 2, 256))
                .output(exact("out", Dtype::U32, u32s(&out))),
        );
    }
    if plan.has(SOURCE, "bfloat_vectors") {
        let n = 64;
        let x: Vec<f64> = (0..n * 4)
            .map(|k| {
                f32r(if k % 3 == 0 {
                    rng.log_uniform(1e-3, 1e3)
                } else {
                    rng.uniform(-1000.0, 1000.0)
                })
            })
            .collect();
        let narrowed: Vec<f64> = x.iter().map(|&v| bfloat(v)).collect();
        let bits: Vec<i128> = narrowed
            .iter()
            .map(|&v| i128::from(bits32(v) >> 16))
            .collect();
        let pairs: Vec<i128> = bits.chunks(4).flat_map(|c| [c[2], c[3]]).collect();
        plan.add(
            Case::compute1(
                "features.bfloat_vectors",
                library,
                "bfloat_vectors",
                n as u32,
            )
            .buffer(Buffer::data("in", 0, f32s(&x)))
            .buffer(Buffer::zeroed("narrow", 1, n * 8))
            .buffer(Buffer::zeroed("wide", 2, n * 16))
            .buffer(Buffer::zeroed("halves", 3, n * 8))
            .buffer(Buffer::zeroed("pairs", 4, n * 4))
            .output(exact("narrow", Dtype::U16, ints(Dtype::U16, &bits)))
            .output(exact("wide", Dtype::F32, f32s(&narrowed)))
            .output(exact(
                "halves",
                Dtype::F16,
                floats(
                    Dtype::F16,
                    &narrowed.iter().map(|&v| f16r(v)).collect::<Vec<_>>(),
                ),
            ))
            .output(exact("pairs", Dtype::U16, ints(Dtype::U16, &pairs))),
        );
    }
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("features", SOURCE, &[], super::plan::LATEST);
    let mut rng = Random::new(4401);
    relational(plan, &library, &mut rng);
    atomics(plan, &library, &mut rng);
    simd(plan, &library, &mut rng);
    quadgroups(plan, &library);
    textures(plan, &library, &mut rng);
    pixels(plan, &library, &mut rng);
    values(plan, &library, &mut rng);
}
