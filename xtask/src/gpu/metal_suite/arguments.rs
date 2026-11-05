//! corpus/arguments.metal: function constants, Tier 2 argument buffers,
//! visible function tables and stitched functions.
use super::plan::{Buffer, Case, LATEST, Output, Plan, Texture, Tolerance};
use super::values::{Dtype, Random, f16_bits, f32r, f32s, u32s};
use serde_json::{Value, json};

const SOURCE: &str = "arguments.metal";

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for k in 0..4 {
            out.push(if k <= chunk.len() {
                TABLE[(n >> (18 - 6 * k) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn constant(kind: &str, index: u32, value: impl Into<Value>) -> Value {
    json!({"type": kind, "index": index, "value": value.into()})
}

fn constants(plan: &mut Plan, library: &str) {
    let vector = [1.5f32, -0.0, 3.0e-39, f32::INFINITY];
    let vector_bytes: Vec<u8> = vector.iter().flat_map(|v| v.to_le_bytes()).collect();
    for (label, extra, named) in [
        ("all", true, Some(-12345i32)),
        ("optional_absent", false, None),
    ] {
        let (c_int, c_float, c_uint, c_half, c_short) =
            (-7i32, 0.1f32, 0xC0FF_EE00u32, -2.5f64, -300i16);
        let mut list = vec![
            constant("int", 0, c_int),
            constant("float", 1, f64::from(c_float)),
            constant("bool", 2, 1),
            constant("uint", 3, c_uint),
            constant("half", 4, c_half),
            constant("bool", 5, u8::from(extra)),
            constant("short", 6, c_short),
            json!({"type": "float4", "index": 7, "bytes": base64(&vector_bytes)}),
        ];
        if let Some(v) = named {
            list.push(json!({"type": "int", "name": "c_named", "value": v}));
        }
        let mut expected = vec![
            c_int as u32,
            c_float.to_bits(),
            1,
            c_uint,
            u32::from(f16_bits(c_half)),
            if extra { 0x1234_5678 } else { 0xDEAD },
            i32::from(c_short) as u32,
            (c_int * 3 + 1) as u32,
            named.map_or(0xFFFF_FFFF, |v| v as u32),
        ];
        expected.extend(vector.map(f32::to_bits));
        let mut case = Case::compute(
            &format!("arguments.constants.{label}"),
            library,
            "constants",
            [1, 1, 1],
            [1, 1, 1],
        )
        .set("constants", Value::Array(list))
        .buffer(Buffer::zeroed("out", 0, 64))
        .output(
            Output::new("out", Dtype::U32, Tolerance::exact())
                .expect_same(u32s(&expected))
                .set("length", 52),
        );
        if extra {
            case = case.buffer(Buffer::data("extra", 1, u32s(&[0x1234_5678])));
        }
        plan.add(case);
    }
    let mut rng = Random::new(1001);
    let input: Vec<f64> = (0..256).map(|_| f32r(rng.uniform(-10.0, 10.0))).collect();
    for (count, negate) in [(0, false), (3, true), (17, false)] {
        let expected: Vec<f64> = input
            .iter()
            .map(|&x| {
                let mut v = x;
                for _ in 0..count {
                    v = f32r(f32r(v * 0.5) + 1.0);
                }
                if negate { -v } else { v }
            })
            .collect();
        // v * 0.5 is exact, so fusing the multiply-add rounds the same.
        let tol = Tolerance::ulp(2.0);
        plan.add(
            Case::compute1(&format!("arguments.constant_branches.{count}.{negate}"), library, "constant_branches", 256)
                .set("constants", json!([constant("int", 0, count), constant("bool", 2, u8::from(negate)), constant("float", 1, 0.0),
                    constant("uint", 3, 0), constant("half", 4, 0.0), constant("bool", 5, 0), constant("short", 6, 0),
                    {"type": "float4", "index": 7, "bytes": base64(&[0; 16])}]))
                .buffer(Buffer::data("in", 0, f32s(&input)))
                .buffer(Buffer::zeroed("out", 1, 1024))
                .output(Output::new("out", Dtype::F32, tol.clone()).expect(f32s(&expected), tol)),
        );
    }
}

fn entry(kind: &str, offset: usize, resource: &str) -> Value {
    json!({"kind": kind, "offset": offset, "resource": resource})
}

fn argument_buffers(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(1002);
    let n = 64usize;
    let values: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-1.0, 1.0))).collect();
    let texels =
        |rng: &mut Random| -> Vec<f64> { (0..16).map(|_| f32r(rng.uniform(0.0, 1.0))).collect() };
    let image = texels(&mut rng);
    let layers: Vec<Vec<f64>> = (0..3).map(|_| texels(&mut rng)).collect();
    let inner_values: Vec<u32> = (0..8).map(|_| rng.u32() % 1000).collect();
    let (scale, count) = (7u32, 0xABCDu32);
    // struct Arguments: values @0, image @8, linear @16, counter @24,
    // layers[3] @32, inner @56, count @64.
    let mut args = vec![0u8; 72];
    args[64..68].copy_from_slice(&count.to_le_bytes());
    let mut inner = vec![0u8; 16];
    inner[8..12].copy_from_slice(&scale.to_le_bytes());
    let mut expected = vec![];
    for i in 0..n {
        let t = &image[4 * (i % 4)..4 * (i % 4) + 4];
        expected.extend(t.iter().map(|&x| f32r(x + values[i])));
        let l = &layers[i % 3][4 * (i % 4)..4 * (i % 4) + 4];
        expected.extend([
            l[0],
            f64::from(inner_values[i % 8] * scale),
            f64::from(count),
            l[3],
        ]);
    }
    let texture =
        |name: &str, data: &[f64]| Texture::d2(name, "rgba32float", 4, 1).data(f32s(data));
    // The same arguments written as Tier 2 layouts and through the
    // argument encoder the function's buffer describes, by [[id]] in
    // member order, the inline count set as constant data.
    let tier2 = json!([
        {"buffer": "args", "entries": [
            entry("buffer", 0, "values"), entry("texture", 8, "image"), entry("sampler", 16, "linear"),
            entry("buffer", 24, "counter"), entry("texture", 32, "layer0"), entry("texture", 40, "layer1"),
            entry("texture", 48, "layer2"), entry("buffer", 56, "inner")]},
        {"buffer": "inner", "entries": [entry("buffer", 0, "inner_values")]}
    ]);
    let id =
        |kind: &str, id: u32, resource: &str| json!({"kind": kind, "id": id, "resource": resource});
    let encoded = json!([
        {"buffer": "args", "encoder": {"function": "argument_buffer", "index": 0}, "entries": [
            id("buffer", 0, "values"), id("texture", 1, "image"), id("sampler", 2, "linear"),
            id("buffer", 3, "counter"), id("texture", 4, "layer0"), id("texture", 5, "layer1"),
            id("texture", 6, "layer2"), id("buffer", 7, "inner"), {"kind": "constant", "id": 8, "value": count}]},
        {"buffer": "inner", "entries": [entry("buffer", 0, "inner_values")]}
    ]);
    for (name, arguments, features) in [
        (
            "arguments.argument_buffer",
            tier2,
            &["argument_buffers_tier2"][..],
        ),
        ("arguments.argument_buffer.encoder", encoded, &[][..]),
    ] {
        plan.add(
        Case::compute1(name, library, "argument_buffer", n as u32)
            .requires(&[], features)
            .buffer(Buffer::data("args", 0, args.clone()))
            .buffer(Buffer::zeroed("out", 1, n * 32))
            .buffer(Buffer::data("values", 0, f32s(&values)).unbound())
            .buffer(Buffer::zeroed("counter", 0, 16).unbound())
            .buffer(Buffer::data("inner", 0, inner.clone()).unbound())
            .buffer(Buffer::data("inner_values", 0, u32s(&inner_values)).unbound())
            .texture(texture("image", &image))
            .texture(texture("layer0", &layers[0]))
            .texture(texture("layer1", &layers[1]))
            .texture(texture("layer2", &layers[2]))
            .sampler(json!({"name": "linear", "min": "linear", "mag": "linear", "argument_buffers": true}))
            .set("arguments", arguments)
            .output(Output::new("out", Dtype::F32, Tolerance::ulp(1.0)).expect_same(f32s(&expected)))
            .output(Output::new("counter", Dtype::U32, Tolerance::exact()).expect_same(u32s(&[n as u32, 0, 0, 0]))),
    );
    }
    // An array of four { pointer, float } structs, 16 bytes apart.
    let sources: Vec<Vec<f64>> = (0..4)
        .map(|_| (0..n).map(|_| f32r(rng.uniform(-5.0, 5.0))).collect())
        .collect();
    let biases: Vec<f32> = (0..4).map(|_| rng.uniform(-1.0, 1.0) as f32).collect();
    let mut items = vec![0u8; 64];
    for (k, b) in biases.iter().enumerate() {
        items[16 * k + 8..16 * k + 12].copy_from_slice(&b.to_le_bytes());
    }
    let expected: Vec<f64> = (0..n)
        .map(|i| f32r(sources[i % 4][i] + f64::from(biases[i % 4])))
        .collect();
    // The sources resident by useResource, and by a residency set alone.
    for residency_set in [false, true] {
        let entries: Vec<Value> = (0..4)
            .map(|k| {
                let mut e = entry("buffer", 16 * k, &format!("source{k}"));
                e["residency_set"] = residency_set.into();
                e
            })
            .collect();
        let name = if residency_set {
            "arguments.argument_array.residency_set"
        } else {
            "arguments.argument_array"
        };
        let mut case = Case::compute1(name, library, "argument_array", n as u32)
            .requires(&[], &["argument_buffers_tier2"])
            .buffer(Buffer::data("items", 0, items.clone()))
            .buffer(Buffer::zeroed("out", 1, n * 4))
            .set(
                "arguments",
                json!([{"buffer": "items", "entries": entries}]),
            )
            .output(
                Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)),
            );
        if residency_set {
            case = case.set(
                "residency_set",
                json!(["source0", "source1", "source2", "source3"]),
            );
        }
        for (k, s) in sources.iter().enumerate() {
            case = case.buffer(Buffer::data(&format!("source{k}"), 0, f32s(s)).unbound());
        }
        plan.add(case);
    }
}

fn function_pointers(plan: &mut Plan, library: &str) {
    let mut rng = Random::new(1003);
    let n = 256usize;
    if plan.has(SOURCE, "visible_table") {
        let input: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-4.0, 4.0))).collect();
        let which: Vec<u32> = (0..n).map(|_| rng.u32() % 3).collect();
        let expected: Vec<f64> = input
            .iter()
            .zip(&which)
            .map(|(&x, &w)| {
                f32r(match w {
                    0 => x * 2.0,
                    1 => x * x,
                    _ => 1.0 - x,
                })
            })
            .collect();
        plan.add(
            Case::compute1(
                "arguments.visible_function_table",
                library,
                "visible_table",
                n as u32,
            )
            .requires(&[], &["function_pointers"])
            .set(
                "visible_functions",
                json!(["twice", "square", "negate_plus"]),
            )
            .set(
                "function_tables",
                json!([{"index": 1, "functions": ["twice", "square", "negate_plus"]}]),
            )
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::zeroed("out", 2, n * 4))
            .buffer(Buffer::data("which", 3, u32s(&which)))
            .output(
                Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)),
            ),
        );
        // The same functions compiled to binaries and linked as such.
        plan.add(
            Case::compute1(
                "arguments.visible_function_table.binary",
                library,
                "visible_table",
                n as u32,
            )
            .requires(&[], &["function_pointers"])
            .set(
                "binary_functions",
                json!(["twice", "square", "negate_plus"]),
            )
            .set(
                "function_tables",
                json!([{"index": 1, "functions": ["twice", "square", "negate_plus"]}]),
            )
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::zeroed("out", 2, n * 4))
            .buffer(Buffer::data("which", 3, u32s(&which)))
            .output(
                Output::new("out", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)),
            ),
        );
    }
    if plan.has(SOURCE, "visible_table") {
        // The table from a fragment function: one call per pixel of 8x8.
        let n = 64usize;
        let input: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-4.0, 4.0))).collect();
        let which: Vec<u32> = (0..n).map(|_| rng.u32() % 3).collect();
        let expected: Vec<f64> = input
            .iter()
            .zip(&which)
            .flat_map(|(&x, &w)| {
                let y = f32r(match w {
                    0 => x * 2.0,
                    1 => x * x,
                    _ => 1.0 - x,
                });
                [y, 0.0, 0.0, 1.0]
            })
            .collect();
        let functions = json!(["twice", "square", "negate_plus"]);
        plan.add(
            Case::render(
                "arguments.visible_function_table.fragment",
                library,
                "vert_visible",
                Some("frag_visible"),
                json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}],
                       "primitive": "triangle_strip", "vertex_count": 4,
                       "fragment_visible_functions": functions,
                       "fragment_tables": [{"index": 1, "functions": functions}]}),
            )
            .requires(&[], &["function_pointers_render"])
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::data("which", 3, u32s(&which)))
            .texture(Texture::d2("target", "rgba32float", 8, 8).usage(&["render"]))
            .output(
                Output::new("target", Dtype::F32, Tolerance::exact()).expect_same(f32s(&expected)),
            ),
        );
    }
    if plan.has(SOURCE, "stitched_call") {
        let input: Vec<f64> = (0..2 * n).map(|_| f32r(rng.uniform(-4.0, 4.0))).collect();
        // stitched(a, b) = stitch_add(stitch_mul(a, b), a), which may be
        // contracted into a fused multiply-add (Apple's GPUs fuse it): both
        // roundings are allowed, and near cancellation they differ widely.
        let expected: Vec<f64> = input
            .chunks(2)
            .map(|p| f32r(f32r(p[0] * p[1]) + p[0]))
            .collect();
        let fused: Vec<f64> = input.chunks(2).map(|p| f32r(p[0] * p[1] + p[0])).collect();
        let tol = Tolerance::ulp(1.0);
        plan.add(
            Case::compute1(
                "arguments.stitched_function",
                library,
                "stitched_call",
                n as u32,
            )
            .requires(&[], &["function_pointers"])
            .set(
                "stitched",
                json!([{"name": "stitched_mul_add", "inputs": 2, "nodes": [
                    {"id": "n0", "function": "stitch_mul", "args": ["in0", "in1"]},
                    {"id": "n1", "function": "stitch_add", "args": ["n0", "in0"]}]}]),
            )
            .set(
                "function_tables",
                json!([{"index": 1, "functions": ["stitched_mul_add"]}]),
            )
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::zeroed("out", 2, n * 4))
            .output(
                Output::new("out", Dtype::F32, tol.clone())
                    .expect(f32s(&expected), tol)
                    .expect_alternative(f32s(&fused)),
            ),
        );
    }
}

/// Dynamic libraries: a kernel calling into one Metal loads by its
/// install name, the same with the library preloaded, and a fragment
/// function calling into it.
fn dynamic_libraries(plan: &mut Plan, rng: &mut Random) {
    let dynamic = plan.dynamic_library("dynamic", "dynamic.metal", LATEST);
    let user = plan.library("dynamic_user", "dynamic_user.metal", &[], LATEST);
    plan.link(&user, &[&dynamic]);
    let n = 256usize;
    let input: Vec<f64> = (0..n).map(|_| f32r(rng.uniform(-4.0, 4.0))).collect();
    let expected: Vec<f64> = input.iter().map(|&x| f32r(f32r(x * 3.0) + 1.0)).collect();
    let fused: Vec<f64> = input.iter().map(|&x| f32r(x * 3.0 + 1.0)).collect();
    for (name, preload) in [("loaded", json!([])), ("preloaded", json!([dynamic]))] {
        plan.add(
            Case::compute1(
                &format!("arguments.dynamic_library.{name}"),
                &user,
                "use_dynamic",
                n as u32,
            )
            .requires(&[], &["dynamic_libraries"])
            .set("preload", preload)
            .buffer(Buffer::data("in", 0, f32s(&input)))
            .buffer(Buffer::zeroed("out", 1, n * 4))
            .output(
                Output::new("out", Dtype::F32, Tolerance::exact())
                    .expect_same(f32s(&expected))
                    .expect_alternative(f32s(&fused)),
            ),
        );
    }
    let color = [0.25, 0.5, 0.75, 0.125];
    let tinted = [color[2], color[1], color[0], 1.0 - color[3]];
    plan.add(
        Case::render(
            "arguments.dynamic_library.fragment",
            &user,
            "vert_full",
            Some("frag_dynamic"),
            json!({"colors": [{"texture": "target", "clear": [0, 0, 0, 0]}], "preload": [dynamic],
                   "primitive": "triangle_strip", "vertex_count": 4}),
        )
        .requires(&[], &["render_dynamic_libraries"])
        .set("preload", json!([dynamic]))
        .buffer(Buffer::data("color", 0, f32s(&color)).stage("fragment"))
        .texture(Texture::d2("target", "rgba32float", 8, 8).usage(&["render"]))
        .output(
            Output::new("target", Dtype::F32, Tolerance::exact())
                .expect_same(f32s(&tinted.repeat(64))),
        ),
    );
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("arguments", SOURCE, &[], LATEST);
    constants(plan, &library);
    argument_buffers(plan, &library);
    function_pointers(plan, &library);
    dynamic_libraries(plan, &mut Random::new(1004));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_pads() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
    }
}
