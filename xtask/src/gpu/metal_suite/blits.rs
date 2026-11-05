//! Blit commands: buffer copies and fills, copies between buffers and
//! textures with row and image pitches, texture copies between levels and
//! slices, and mipmap generation.
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::values::{Dtype, Random};
use serde_json::json;

fn bytes(rng: &mut Random, n: usize) -> Vec<u8> {
    (0..n).map(|_| (rng.u32() % 256) as u8).collect()
}

fn exact(name: &str, data: Vec<u8>) -> Output {
    Output::new(name, Dtype::U8, Tolerance::exact()).expect_same(data)
}

pub fn build(plan: &mut Plan) {
    let mut rng = Random::new(1101);
    // Copies and fills at 4-byte aligned offsets and sizes, overlapping
    // nothing, then a copy within one buffer to a disjoint range.
    let (src, dst) = (bytes(&mut rng, 256), bytes(&mut rng, 256));
    let mut expected = dst.clone();
    expected[40..140].copy_from_slice(&src[16..116]);
    expected[200..236].fill(0xA7);
    let mut own = src.clone();
    own.copy_within(0..64, 128);
    plan.add(
        Case::blit(
            "blit.buffers",
            json!([
                {"op": "copy_buffer", "src": "src", "src_offset": 16, "dst": "dst", "dst_offset": 40, "size": 100},
                {"op": "fill_buffer", "dst": "dst", "offset": 200, "size": 36, "value": 0xA7},
                {"op": "copy_buffer", "src": "src", "src_offset": 0, "dst": "own", "dst_offset": 128, "size": 64},
            ]),
        )
        .buffer(Buffer::data("src", 0, src.clone()).unbound())
        .buffer(Buffer::data("dst", 0, dst).unbound())
        .buffer(Buffer::data("own", 0, src).unbound())
        .output(exact("dst", expected))
        .output(exact("own", own)),
    );
    // A buffer region into a texture region, rows 48 bytes apart.
    let (w, h) = (8usize, 8usize);
    let texture = bytes(&mut rng, w * h * 4);
    let source = bytes(&mut rng, 48 * 3);
    let (ox, oy, rw, rh) = (2usize, 1usize, 4usize, 3usize);
    let mut expected = texture.clone();
    for y in 0..rh {
        let row = (oy + y) * w * 4 + ox * 4;
        expected[row..row + rw * 4].copy_from_slice(&source[y * 48..y * 48 + rw * 4]);
    }
    plan.add(
        Case::blit(
            "blit.buffer_to_texture",
            json!([{"op": "buffer_to_texture", "src": "staging", "bytes_per_row": 48, "bytes_per_image": 48 * 3,
                    "size": [rw, rh, 1], "dst": "t", "origin": [ox, oy, 0]}]),
        )
        .buffer(Buffer::data("staging", 0, source).unbound())
        .texture(Texture::d2("t", "rgba8unorm", w as u32, h as u32).data(texture.clone()))
        .output(exact("t", expected)),
    );
    // A texture region into a buffer with padded rows, at an offset.
    let mut expected = vec![0x55u8; 16 + 64 * rh];
    for y in 0..rh {
        let row = (oy + y) * w * 4 + ox * 4;
        expected[16 + y * 64..16 + y * 64 + rw * 4].copy_from_slice(&texture[row..row + rw * 4]);
    }
    plan.add(
        Case::blit(
            "blit.texture_to_buffer",
            json!([{"op": "texture_to_buffer", "src": "t", "origin": [ox, oy, 0], "size": [rw, rh, 1], "dst": "out",
                    "dst_offset": 16, "bytes_per_row": 64, "bytes_per_image": 64 * rh}]),
        )
        .buffer(Buffer::data("out", 0, vec![0x55; 16 + 64 * rh]).unbound())
        .texture(Texture::d2("t", "rgba8unorm", w as u32, h as u32).data(texture))
        .output(exact("out", expected)),
    );
    // Level 1 of slice 2 of a mipmapped array into level 0 of a texture,
    // at an offset; the rest of the destination is unchanged.
    let levels = [(16usize, 8usize), (8, 4), (4, 2)];
    let per_slice: usize = levels.iter().map(|(a, b)| a * b * 8).sum();
    // The runner's texture data holds each slice's levels in turn.
    let array = bytes(&mut rng, per_slice * 3);
    let level_offset = |level: usize, slice: usize| -> usize {
        slice * per_slice
            + levels[..level]
                .iter()
                .map(|(a, b)| a * b * 8)
                .sum::<usize>()
    };
    let dst = bytes(&mut rng, 8 * 8 * 8);
    let mut expected = dst.clone();
    let (sx, sy, cw, ch, dx, dy) = (2usize, 1usize, 5usize, 3usize, 3usize, 4usize);
    for y in 0..ch {
        let from = level_offset(1, 2) + ((sy + y) * 8 + sx) * 8;
        let to = ((dy + y) * 8 + dx) * 8;
        expected[to..to + cw * 8].copy_from_slice(&array[from..from + cw * 8]);
    }
    plan.add(
        Case::blit(
            "blit.copy_texture",
            json!([{"op": "copy_texture", "src": "a", "src_slice": 2, "src_level": 1, "src_origin": [sx, sy, 0],
                    "size": [cw, ch, 1], "dst": "b", "dst_origin": [dx, dy, 0]}]),
        )
        .texture(Texture::new("a", "rgba16float", "2d_array", [16, 8, 1]).array(3).mipmaps(3).data(array))
        .texture(Texture::d2("b", "rgba16float", 8, 8).data(dst))
        .output(exact("b", expected)),
    );
    // Mipmap generation: a 2x2 box filter.
    let base = bytes(&mut rng, 16 * 16 * 4);
    let mut expected = base.clone();
    let mut level = base;
    let mut size = 16;
    while size > 1 {
        let half = size / 2;
        let mut next = vec![0u8; half * half * 4];
        for y in 0..half {
            for x in 0..half {
                for c in 0..4 {
                    let at = |xx: usize, yy: usize| u32::from(level[(yy * size + xx) * 4 + c]);
                    let sum = at(2 * x, 2 * y)
                        + at(2 * x + 1, 2 * y)
                        + at(2 * x, 2 * y + 1)
                        + at(2 * x + 1, 2 * y + 1);
                    next[(y * half + x) * 4 + c] = ((f64::from(sum) / 4.0).round()) as u8;
                }
            }
        }
        expected.extend(&next);
        level = next;
        size = half;
    }
    let mut data = expected[..16 * 16 * 4].to_vec();
    data.resize(expected.len(), 0);
    plan.add(
        Case::blit(
            "blit.generate_mipmaps",
            json!([{"op": "generate_mipmaps", "texture": "t"}]),
        )
        .texture(
            Texture::d2("t", "rgba8unorm", 16, 16)
                .mipmaps(5)
                .usage(&["read", "render"])
                .data(data),
        )
        .output(Output::new("t", Dtype::U8, Tolerance::units(2.0)).expect_same(expected)),
    );
}
