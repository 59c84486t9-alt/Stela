//! corpus/host.metal: the host's side of the device. Drawables of a layer
//! in each pixel format, IOSurface-backed textures over one and two
//! planes, a texture and an event another process opens, binary archives
//! written and loaded, the errors creation calls report, command buffer
//! status and enqueue order, purgeable state, and work at scale: grids at
//! their dimension limits, long command streams, threads and queues
//! encoding at once, resources dropped while in flight and a buffer past
//! 4 GiB.
use super::plan::{Buffer, Case, Output, Plan, Tolerance};
use super::values::{Dtype, Random, u32s};
use serde_json::json;

const SOURCE: &str = "host.metal";

fn exact(name: &str, dtype: Dtype, data: Vec<u8>) -> Output {
    Output::new(name, dtype, Tolerance::exact()).expect_same(data)
}

fn props(count: usize) -> Buffer {
    Buffer::zeroed("props", 0, count * 4).unbound()
}

/// One texel of colour `c`, whose components are 0 or 1, in `format`.
fn texel(format: &str, c: [u32; 4]) -> Vec<u8> {
    let [r, g, b, a] = c;
    match format {
        "bgra8unorm" | "bgra8unorm_srgb" => [b, g, r, a].map(|v| (v * 255) as u8).to_vec(),
        "rgba16float" => c
            .iter()
            .flat_map(|&v| (if v == 1 { 0x3c00u16 } else { 0 }).to_le_bytes())
            .collect(),
        "bgr10a2unorm" => ((b * 1023) | (g * 1023) << 10 | (r * 1023) << 20 | (a * 3) << 30)
            .to_le_bytes()
            .to_vec(),
        _ => unreachable!("{format}"),
    }
}

/// Three drawables of an 8x4 layer, each cleared and drawn on its left
/// half, then read back (unless framebuffer only) and presented.
fn drawables(plan: &mut Plan, library: &str) {
    let (w, h) = (8usize, 4usize);
    let clears = [[1, 0, 0, 1], [0, 1, 0, 1], [0, 0, 1, 1]];
    let color = [1, 1, 0, 1];
    let values = [
        ("bgra8unorm", 80),
        ("bgra8unorm_srgb", 81),
        ("rgba16float", 115),
        ("bgr10a2unorm", 94),
    ];
    for (format, value) in values {
        let bytes = texel(format, color).len();
        let image: Vec<u8> = clears
            .iter()
            .flat_map(|&clear| {
                (0..w * h)
                    .flat_map(move |i| texel(format, if i % w < w / 2 { color } else { clear }))
            })
            .collect();
        let expected: Vec<u32> = (0..3)
            .flat_map(|_| [w as u32, h as u32, value, 1, 1])
            .collect();
        plan.add(
            Case::host(
                &format!("host.drawables.{format}"),
                library,
                json!({"kind": "drawables", "format": format, "width": w, "height": h,
                       "count": 3, "clears": clears, "color": color}),
            )
            .buffer(Buffer::zeroed("out", 0, 3 * w * h * bytes).unbound())
            .buffer(props(15))
            .output(exact("out", Dtype::U8, image))
            .output(exact("props", Dtype::U32, u32s(&expected))),
        );
    }
    let expected: Vec<u32> = (0..3)
        .flat_map(|_| [w as u32, h as u32, 80, 1, 0])
        .collect();
    plan.add(
        Case::host(
            "host.drawables.framebuffer_only",
            library,
            json!({"kind": "drawables", "format": "bgra8unorm", "width": w, "height": h,
                   "count": 3, "clears": clears, "color": color, "framebuffer_only": true}),
        )
        .buffer(props(15))
        .output(exact("props", Dtype::U32, u32s(&expected))),
    );
}

/// A BGRA surface the CPU fills and a kernel inverts into another the CPU
/// reads, and a two-plane 4:2:0 surface a kernel reads both planes of.
fn iosurface(plan: &mut Plan, library: &str, rng: &mut Random) {
    let (w, h) = (16usize, 8usize);
    let bgra: Vec<u8> = (0..w * h * 4).map(|_| rng.u32() as u8).collect();
    let inverted: Vec<u8> = bgra
        .iter()
        .enumerate()
        .map(|(i, &v)| if i % 4 == 3 { v } else { 255 - v })
        .collect();
    let luma: Vec<u8> = (0..w * h).map(|_| rng.u32() as u8).collect();
    let chroma: Vec<u8> = (0..w * h / 2).map(|_| rng.u32() as u8).collect();
    let planes: Vec<u32> = (0..w * h)
        .map(|i| {
            let (x, y) = (i % w, i / w);
            let c = (y / 2 * (w / 2) + x / 2) * 2;
            u32::from(luma[i]) | u32::from(chroma[c]) << 8 | u32::from(chroma[c + 1]) << 16
        })
        .collect();
    plan.add(
        Case::host(
            "host.iosurface",
            library,
            json!({"kind": "iosurface", "width": w, "height": h}),
        )
        .buffer(Buffer::data("in", 0, bgra).unbound())
        .buffer(Buffer::data("luma", 0, luma).unbound())
        .buffer(Buffer::data("chroma", 0, chroma).unbound())
        .buffer(Buffer::zeroed("out", 0, w * h * 4).unbound())
        .buffer(Buffer::zeroed("planes", 0, w * h * 4).unbound())
        .buffer(props(4))
        .output(Output::new("out", Dtype::U8, Tolerance::units(1.0)).expect_same(inverted))
        .output(exact("planes", Dtype::U32, u32s(&planes)))
        .output(exact(
            "props",
            Dtype::U32,
            u32s(&[1, 0, w as u32, h as u32]),
        )),
    );
}

/// A shared texture this process clears and the share service writes the
/// top rows of, ordered by a shared event both processes wait on.
fn share(plan: &mut Plan, library: &str, rng: &mut Random) {
    let (w, h, rows) = (8usize, 8usize, 4usize);
    let top: Vec<u8> = (0..w * rows * 4).map(|_| rng.u32() as u8).collect();
    let mut image = top.clone();
    image.extend((0..w * (h - rows)).flat_map(|_| [0, 255, 0, 255]));
    plan.add(
        Case::host(
            "host.share.texture_event",
            library,
            json!({"kind": "share", "width": w, "height": h, "clear": [0, 1, 0, 1]}),
        )
        .buffer(Buffer::data("rows", 0, top).unbound())
        .buffer(Buffer::zeroed("out", 0, w * h * 4).unbound())
        .buffer(props(1))
        .output(exact("out", Dtype::U8, image))
        .output(exact("props", Dtype::U32, u32s(&[2])).set("length", 4)),
    );
}

fn archive(plan: &mut Plan, library: &str, rng: &mut Random) {
    let data: Vec<u32> = (0..64).map(|_| rng.u32() >> 4).collect();
    let expected: Vec<u32> = data
        .iter()
        .map(|v| v.wrapping_mul(3).wrapping_add(1))
        .collect();
    plan.add(
        Case::host("host.binary_archive", library, json!({"kind": "archive"}))
            .buffer(Buffer::data("data", 0, u32s(&data)).unbound())
            .buffer(props(8))
            .output(exact("data", Dtype::U32, u32s(&expected)))
            .output(exact("props", Dtype::U32, u32s(&[1; 8]))),
    );
}

/// A library that does not compile reports MTLLibraryErrorCompileFailure
/// (3), an absent function is nil and an unlinked varying fails the
/// pipeline; a command buffer goes from not enqueued (0) through enqueued
/// (1) to completed (4) without error; and the buffer enqueued first runs
/// first though committed second (`v * 10 + digit`: 2, then 21).
fn errors(plan: &mut Plan, library: &str) {
    plan.add(
        Case::host("host.errors_and_status", library, json!({"kind": "errors"}))
            .buffer(Buffer::zeroed("order", 0, 4).unbound())
            .buffer(props(9))
            .output(exact("order", Dtype::U32, u32s(&[21])).set("length", 4))
            .output(exact(
                "props",
                Dtype::U32,
                u32s(&[1, 1, 3, 1, 1, 0, 1, 4, 1]),
            )),
    );
}

/// setPurgeableState: returns the state before it (non-volatile 2,
/// volatile 3, empty 4): keep, empty, keep, non-volatile, keep, volatile,
/// for a buffer, a private texture and a heap.
fn purgeable(plan: &mut Plan, library: &str) {
    let states: Vec<u32> = (0..3).flat_map(|_| [2, 2, 4, 4, 2, 2]).collect();
    plan.add(
        Case::host("host.purgeable", library, json!({"kind": "purgeable"}))
            .buffer(props(18))
            .output(exact("props", Dtype::U32, u32s(&states))),
    );
}

/// 10000 dispatches in one encoder, 512 command buffers in one queue, 8
/// threads committing 64 each into one queue, and 8 queues adding 64
/// each at once.
fn streams(plan: &mut Plan, library: &str) {
    let threads = 8u32;
    let mut counts = vec![10000, 512];
    counts.extend((0..threads).map(|_| 64));
    counts.push(64 * threads);
    plan.add(
        Case::host(
            "host.streams",
            library,
            json!({"kind": "streams", "dispatches": 10000, "command_buffers": 512,
                   "threads": threads, "per_thread": 64}),
        )
        .set("timeout", 60.0)
        .buffer(Buffer::zeroed("counts", 0, counts.len() * 4).unbound())
        .output(exact("counts", Dtype::U32, u32s(&counts))),
    );
}

/// 256 rounds of a 1 MiB buffer and a private texture made, used by one
/// command buffer and dropped before it runs.
fn churn(plan: &mut Plan, library: &str) {
    let rounds = 256u32;
    let words: Vec<u32> = (0..rounds).map(|i| i.wrapping_mul(2_654_435_761)).collect();
    let texels: Vec<u32> = (0..rounds).collect();
    plan.add(
        Case::host(
            "host.churn",
            library,
            json!({"kind": "churn", "rounds": rounds, "size": 1 << 20}),
        )
        .set("timeout", 60.0)
        .buffer(Buffer::zeroed("words", 0, rounds as usize * 4).unbound())
        .buffer(Buffer::zeroed("texels", 0, rounds as usize * 4).unbound())
        .output(exact("words", Dtype::U32, u32s(&words)))
        .output(exact("texels", Dtype::U32, u32s(&texels))),
    );
}

/// A private buffer of 4 GiB and 32 MiB, stamped below 2 GiB, across 2
/// and 4 GiB and at its end, and filled past 4 GiB.
fn large_buffer(plan: &mut Plan, library: &str) {
    let length: u64 = (1 << 32) + (1 << 25);
    let count = 256u32;
    let windows = [
        0u32,
        (1 << 29) - count / 2,
        (1 << 30) - count / 2,
        (length / 4) as u32 - count,
    ];
    let fill = ((1u64 << 32) + (1 << 24), 128usize, 0xa5u8);
    let mut expected: Vec<u8> = windows
        .iter()
        .flat_map(|&first| u32s(&(first..first + count).collect::<Vec<_>>()))
        .collect();
    expected.extend(std::iter::repeat_n(fill.2, fill.1));
    plan.add(
        Case::host(
            "host.large_buffer",
            library,
            json!({"kind": "large_buffer", "length": length,
                   "windows": windows.map(|w| [w, count]), "fill": [fill.0, fill.1, fill.2]}),
        )
        .set("timeout", 60.0)
        .buffer(Buffer::zeroed("out", 0, expected.len()).unbound())
        .output(exact("out", Dtype::U8, expected)),
    );
}

/// The sum, xor, count and largest `y + z` of every thread's position
/// hash, as grid_hash reduces them.
fn grid_hash(grid: [u32; 3]) -> [u32; 4] {
    let mut out = [0u32; 4];
    for z in 0..grid[2] {
        for y in 0..grid[1] {
            let yz = y.wrapping_mul(0x85eb_ca77) ^ z.wrapping_mul(0xc2b2_ae3d);
            for x in 0..grid[0] {
                let h = x.wrapping_mul(0x9e37_79b1) ^ yz;
                out[0] = out[0].wrapping_add(h);
                out[1] ^= h;
            }
            out[3] = out[3].max(y + z);
        }
    }
    out[2] = grid[0].wrapping_mul(grid[1]).wrapping_mul(grid[2]);
    out
}

/// A non-uniform grid of 67.7 million threads, and 65535 threadgroups
/// along y and along z.
fn grids(plan: &mut Plan, library: &str) {
    let cases: [(&str, [u32; 3], [u32; 3], bool); 3] = [
        ("non_uniform", [100_003, 677, 1], [256, 1, 1], true),
        ("y_limit", [1, 65535, 1], [32, 1, 1], false),
        ("z_limit", [1, 1, 65535], [32, 1, 1], false),
    ];
    for (label, grid, group, threads) in cases {
        let total = if threads {
            grid
        } else {
            [grid[0] * group[0], grid[1] * group[1], grid[2] * group[2]]
        };
        let mut case = Case::compute(
            &format!("host.grid.{label}"),
            library,
            "grid_hash",
            grid,
            group,
        )
        .set("threadgroup_memory", json!([{"index": 0, "length": 16}]))
        .set("timeout", 60.0)
        .buffer(Buffer::zeroed("sums", 0, 16))
        .output(exact("sums", Dtype::U32, u32s(&grid_hash(total))));
        if threads {
            case = case.dispatch_threads();
        }
        plan.add(case);
    }
}

pub fn build(plan: &mut Plan) {
    let library = plan.library("host", SOURCE, &[], super::plan::LATEST);
    let mut rng = Random::new(1301);
    drawables(plan, &library);
    iosurface(plan, &library, &mut rng);
    share(plan, &library, &mut rng);
    archive(plan, &library, &mut rng);
    errors(plan, &library);
    purgeable(plan, &library);
    streams(plan, &library);
    churn(plan, &library);
    large_buffer(plan, &library);
    grids(plan, &library);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grid_hash_reduces_every_thread() {
        let [sum, xor, count, top] = grid_hash([2, 2, 1]);
        let h = |x: u32, y: u32| x.wrapping_mul(0x9e37_79b1) ^ y.wrapping_mul(0x85eb_ca77);
        let all = [h(0, 0), h(1, 0), h(0, 1), h(1, 1)];
        assert_eq!(sum, all.iter().fold(0u32, |a, &v| a.wrapping_add(v)));
        assert_eq!(xor, all.iter().fold(0, |a, &v| a ^ v));
        assert_eq!((count, top), (4, 1));
    }

    #[test]
    fn packed_texels_put_blue_lowest() {
        assert_eq!(texel("bgr10a2unorm", [0, 0, 1, 0]), 1023u32.to_le_bytes());
        assert_eq!(texel("bgra8unorm", [1, 0, 0, 1]), [0, 0, 255, 255]);
    }
}
