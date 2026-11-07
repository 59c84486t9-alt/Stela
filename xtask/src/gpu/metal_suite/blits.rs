//! Blit commands: buffer copies and fills, small and large, copies between
//! buffers and textures with row and image pitches into any slice, level,
//! 3D region or depth-stencil plane, texture copies of a region, of whole
//! textures and of slice and level ranges, of compressed blocks, mipmap
//! generation for 2D, array, cube and 3D textures, and access hints that
//! leave contents as they were, and copies of texels held in another
//! encoding.
use super::plan::{Buffer, Case, Output, Plan, Texture, Tolerance};
use super::values::{Dtype, Random, u32s};
use serde_json::json;

fn bytes(rng: &mut Random, n: usize) -> Vec<u8> {
    (0..n).map(|_| (rng.u32() % 256) as u8).collect()
}

fn exact(name: &str, data: Vec<u8>) -> Output {
    Output::new(name, Dtype::U8, Tolerance::exact()).expect_same(data)
}

/// Where each (slice, level) of a texture starts in the runner's packed
/// layout (slices outermost, levels inner), and the total length.
struct Layout {
    size: [usize; 3],
    slices: usize,
    levels: usize,
    texel: usize,
}

impl Layout {
    fn extent(&self, level: usize) -> [usize; 3] {
        self.size.map(|s| (s >> level).max(1))
    }

    fn level_bytes(&self, level: usize) -> usize {
        self.extent(level).iter().product::<usize>() * self.texel
    }

    fn offset(&self, slice: usize, level: usize) -> usize {
        let per_slice: usize = (0..self.levels).map(|l| self.level_bytes(l)).sum();
        slice * per_slice + (0..level).map(|l| self.level_bytes(l)).sum::<usize>()
    }

    fn total(&self) -> usize {
        self.offset(self.slices, 0)
    }

    /// The byte of texel (x, y, z) of a subresource.
    fn at(&self, slice: usize, level: usize, [x, y, z]: [usize; 3]) -> usize {
        let [w, h, _] = self.extent(level);
        self.offset(slice, level) + ((z * h + y) * w + x) * self.texel
    }
}

/// A 2x2 (2x2x2 for 3D) box filter of one level into the next, rounded
/// to the nearest unorm8 step.
fn box_level(level: &[u8], [w, h, d]: [usize; 3], channels: usize) -> Vec<u8> {
    let next = [(w / 2).max(1), (h / 2).max(1), (d / 2).max(1)];
    let mut out = vec![0u8; next.iter().product::<usize>() * channels];
    for z in 0..next[2] {
        for y in 0..next[1] {
            for x in 0..next[0] {
                for c in 0..channels {
                    let mut sum = 0.0;
                    let mut count = 0.0;
                    for dz in 0..if d > 1 { 2 } else { 1 } {
                        for dy in 0..if h > 1 { 2 } else { 1 } {
                            for dx in 0..if w > 1 { 2 } else { 1 } {
                                let (xx, yy, zz) = (2 * x + dx, 2 * y + dy, 2 * z + dz);
                                sum += f64::from(level[((zz * h + yy) * w + xx) * channels + c]);
                                count += 1.0;
                            }
                        }
                    }
                    out[((z * next[1] + y) * next[0] + x) * channels + c] =
                        (sum / count).round() as u8;
                }
            }
        }
    }
    out
}

fn more(plan: &mut Plan, rng: &mut Random) {
    // A buffer region into level 1 of slice 1 of an array, rows padded.
    let array = Layout {
        size: [8, 8, 1],
        slices: 2,
        levels: 2,
        texel: 4,
    };
    let texture = bytes(rng, array.total());
    let source = bytes(rng, 32 * 2);
    let mut expected = texture.clone();
    for y in 0..2 {
        let to = array.at(1, 1, [1, 1 + y, 0]);
        expected[to..to + 12].copy_from_slice(&source[y * 32..y * 32 + 12]);
    }
    plan.add(
        Case::blit(
            "blit.buffer_to_texture.array_level",
            json!([{"op": "buffer_to_texture", "src": "staging", "bytes_per_row": 32, "bytes_per_image": 64,
                    "size": [3, 2, 1], "dst": "t", "slice": 1, "level": 1, "origin": [1, 1, 0]}]),
        )
        .buffer(Buffer::data("staging", 0, source).unbound())
        .texture(Texture::new("t", "rgba8unorm", "2d_array", [8, 8, 1]).array(2).mipmaps(2).data(texture))
        .output(exact("t", expected)),
    );
    // A 2x2x2 region of a 3D texture from and to buffers with padded rows
    // and images.
    let volume = Layout {
        size: [4, 4, 4],
        slices: 1,
        levels: 1,
        texel: 4,
    };
    let texture = bytes(rng, volume.total());
    let source = bytes(rng, 48 * 2);
    let mut expected = texture.clone();
    let mut read = vec![0x33u8; 48 * 2];
    for z in 0..2 {
        for y in 0..2 {
            let at = volume.at(0, 0, [1, 1 + y, 1 + z]);
            expected[at..at + 8].copy_from_slice(&source[z * 48 + y * 16..z * 48 + y * 16 + 8]);
            read[z * 48 + y * 16..z * 48 + y * 16 + 8].copy_from_slice(&texture[at..at + 8]);
        }
    }
    plan.add(
        Case::blit(
            "blit.buffer_to_texture.volume",
            json!([{"op": "buffer_to_texture", "src": "staging", "bytes_per_row": 16, "bytes_per_image": 48,
                    "size": [2, 2, 2], "dst": "t", "origin": [1, 1, 1]}]),
        )
        .buffer(Buffer::data("staging", 0, source).unbound())
        .texture(Texture::new("t", "r32uint", "3d", [4, 4, 4]).data(texture.clone()))
        .output(exact("t", expected)),
    );
    plan.add(
        Case::blit(
            "blit.texture_to_buffer.volume",
            json!([{"op": "texture_to_buffer", "src": "t", "origin": [1, 1, 1], "size": [2, 2, 2], "dst": "out",
                    "bytes_per_row": 16, "bytes_per_image": 48}]),
        )
        .buffer(Buffer::data("out", 0, vec![0x33; 96]).unbound())
        .texture(Texture::new("t", "r32uint", "3d", [4, 4, 4]).data(texture))
        .output(exact("out", read)),
    );
    // Each plane of a depth-stencil texture written and read on its own.
    let (w, h) = (8usize, 4usize);
    let depth: Vec<u8> = (0..w * h)
        .flat_map(|i| (i as f32 / 32.0).to_le_bytes())
        .collect();
    let stencil = bytes(rng, w * h);
    plan.add(
        Case::blit(
            "blit.depth_stencil_planes",
            json!([{"op": "buffer_to_texture_plane", "aspect": "depth", "src": "depth", "bytes_per_row": w * 4,
                    "bytes_per_image": w * h * 4, "size": [w, h, 1], "dst": "ds", "origin": [0, 0, 0]},
                   {"op": "buffer_to_texture_plane", "aspect": "stencil", "src": "stencil", "bytes_per_row": w,
                    "bytes_per_image": w * h, "size": [w, h, 1], "dst": "ds", "origin": [0, 0, 0]},
                   {"op": "texture_to_buffer_plane", "aspect": "stencil", "src": "ds", "origin": [0, 0, 0],
                    "size": [w, h, 1], "dst": "stencil_out", "bytes_per_row": w, "bytes_per_image": w * h}]),
        )
        .buffer(Buffer::data("depth", 0, depth.clone()).unbound())
        .buffer(Buffer::data("stencil", 0, stencil.clone()).unbound())
        .buffer(Buffer::zeroed("stencil_out", 0, w * h).unbound())
        .texture(Texture::d2("ds", "depth32float_stencil8", w as u32, h as u32).usage(&["render"]))
        .output(exact("stencil_out", stencil))
        .output(exact("ds", depth).set("aspect", "depth")),
    );
    // A whole mipmapped array, then two of four slices with both levels.
    let full = Layout {
        size: [8, 4, 1],
        slices: 4,
        levels: 2,
        texel: 8,
    };
    let a = bytes(rng, full.total());
    let b = bytes(rng, full.total());
    let mut sliced = b.clone();
    for slice in 0..2 {
        for level in 0..2 {
            let (from, to) = (full.offset(slice + 1, level), full.offset(slice, level));
            let n = full.level_bytes(level);
            sliced[to..to + n].copy_from_slice(&a[from..from + n]);
        }
    }
    let arrays = |data: &[u8]| {
        Texture::new("", "rgba16uint", "2d_array", [8, 4, 1])
            .array(4)
            .mipmaps(2)
            .data(data.to_vec())
    };
    let named = |t: Texture, name: &str| t.set("name", name);
    plan.add(
        Case::blit(
            "blit.copy_whole_texture",
            json!([{"op": "copy_whole_texture", "src": "a", "dst": "b"}]),
        )
        .texture(named(arrays(&a), "a"))
        .texture(named(arrays(&b), "b"))
        .output(exact("b", a.clone())),
    );
    plan.add(
        Case::blit(
            "blit.copy_slices",
            json!([{"op": "copy_slices", "src": "a", "src_slice": 1, "dst": "b", "dst_slice": 0, "slices": 2, "levels": 2}]),
        )
        .texture(named(arrays(&a), "a"))
        .texture(named(arrays(&b), "b"))
        .output(exact("b", sliced)),
    );
    // A block of a compressed texture copied to another position.
    let blocks = bytes(rng, 4 * 8);
    let mut moved = blocks.clone();
    moved[3 * 8..4 * 8].copy_from_slice(&blocks[..8]);
    plan.add(
        Case::blit(
            "blit.copy_texture.compressed",
            json!([{"op": "copy_texture", "src": "a", "src_origin": [0, 0, 0], "size": [4, 4, 1], "dst": "b",
                    "dst_origin": [4, 4, 0]}]),
        )
        .requires(&[], &["bc_compression"])
        .texture(Texture::d2("a", "bc1_rgba", 8, 8).data(blocks.clone()))
        .texture(Texture::d2("b", "bc1_rgba", 8, 8).data(blocks))
        .output(exact("b", moved)),
    );
    // Large copies and fills, past any single transfer's size.
    let large = 4 << 20;
    let src = bytes(rng, large + 16);
    let mut expected = vec![0u8; large + 16];
    expected[8..8 + large].copy_from_slice(&src[4..4 + large]);
    plan.add(
        Case::blit(
            "blit.buffers.large",
            json!([{"op": "copy_buffer", "src": "src", "src_offset": 4, "dst": "dst", "dst_offset": 8, "size": large},
                   {"op": "fill_buffer", "dst": "filled", "offset": 0, "size": large, "value": 0x5C}]),
        )
        .buffer(Buffer::data("src", 0, src).unbound())
        .buffer(Buffer::zeroed("dst", 0, large + 16).unbound())
        .buffer(Buffer::zeroed("filled", 0, large).unbound())
        .output(exact("dst", expected))
        .output(exact("filled", vec![0x5C; large])),
    );
    // Mipmaps of each slice of an array, each face of a cube and a volume.
    for (name, kind, size, slices) in [
        ("array", "2d_array", [8usize, 8, 1], 2usize),
        ("cube", "cube", [8, 8, 1], 6),
        ("volume", "3d", [8, 8, 8], 1),
    ] {
        let layout = Layout {
            size,
            slices,
            levels: 4,
            texel: 4,
        };
        let mut data = vec![0u8; layout.total()];
        let mut expected = vec![0u8; layout.total()];
        for slice in 0..slices {
            let mut level = bytes(rng, layout.level_bytes(0));
            let at = layout.offset(slice, 0);
            data[at..at + level.len()].copy_from_slice(&level);
            expected[at..at + level.len()].copy_from_slice(&level);
            for l in 1..4 {
                level = box_level(&level, layout.extent(l - 1), 4);
                let at = layout.offset(slice, l);
                expected[at..at + level.len()].copy_from_slice(&level);
            }
        }
        let mut t = Texture::new(
            "t",
            "rgba8unorm",
            kind,
            [size[0] as u32, size[1] as u32, size[2] as u32],
        )
        .mipmaps(4)
        .usage(&["read", "render"])
        .data(data);
        if kind == "2d_array" {
            t = t.array(slices as u32);
        }
        plan.add(
            Case::blit(
                &format!("blit.generate_mipmaps.{name}"),
                json!([{"op": "generate_mipmaps", "texture": "t"}]),
            )
            .texture(t)
            .output(Output::new("t", Dtype::U8, Tolerance::units(2.0)).expect_same(expected)),
        );
    }
    // Access hints change no texel.
    let data = bytes(rng, 16 * 16 * 4);
    plan.add(
        Case::blit(
            "blit.optimize_access",
            json!([{"op": "optimize_gpu_access", "texture": "t"}, {"op": "optimize_cpu_access", "texture": "t"}]),
        )
        .texture(Texture::d2("t", "rgba8unorm", 16, 16).data(data.clone()))
        .output(exact("t", data.clone())),
    );
    // The same hints for one level of one slice, in a pass that samples
    // timestamps at its start and end. Hints may do no work, so the pass
    // also fills a buffer, which gives the samples something to bound.
    plan.add(
        Case::blit(
            "blit.optimize_access.slice_level",
            json!([{"op": "optimize_gpu_access", "texture": "t", "slice": 1, "level": 0},
                   {"op": "optimize_cpu_access", "texture": "t", "slice": 1, "level": 0},
                   {"op": "fill_buffer", "dst": "filled", "offset": 0, "size": 256, "value": 0x3C}]),
        )
        .buffer(Buffer::zeroed("filled", 0, 256).unbound())
        .output(exact("filled", vec![0x3C; 256]))
        .requires(&[], &["counters_stage_boundary", "counter_set_timestamp"])
        .set("timestamps", json!({"buffer": "stamps"}))
        .buffer(Buffer::zeroed("stamps", 0, 16).unbound())
        .texture(
            Texture::new("t", "rgba8unorm", "2d_array", [16, 16, 1])
                .array(2)
                .data([data.clone(), data.clone()].concat()),
        )
        .output(exact("t", [data.clone(), data].concat()))
        .output(
            Output::new("stamps", Dtype::U64, Tolerance::exact())
                .expect_same(u32s(&[1, 1]))
                .set("derive", "ordered"),
        ),
    );
}

/// Texels of a format as Metal holds them. An extended-range format's are
/// codes in their bits with the padding a device writes and alpha within
/// [0, 1]: a device may store the values rather than the bits, so other
/// padding need not survive. A 16-bit format's are any bits.
fn stored_texels(rng: &mut Random, count: usize, format: &str) -> Vec<u8> {
    if matches!(format, "a1bgr5unorm" | "rg8unorm_srgb") {
        return bytes(rng, 2 * count);
    }
    let alpha = format.starts_with("bgra");
    let mut out = Vec::new();
    for _ in 0..count {
        let mut code = || u64::from(rng.u32() % 1024);
        if alpha {
            let (b, g, r) = (code(), code(), code());
            let a = 384 + u64::from(rng.u32() % 511);
            for word in [b, g, r, a] {
                out.extend_from_slice(&((word << 6) as u16).to_le_bytes());
            }
        } else {
            let bits = code() | code() << 10 | code() << 20 | 3 << 30;
            out.extend_from_slice(&(bits as u32).to_le_bytes());
        }
    }
    out
}

/// Buffer copies into and out of textures whose images hold their texels
/// in another encoding carry Metal's bytes: extended-range codes, A1BGR5
/// texels, which a device may hold rotated, and RG8Unorm_sRGB ones, which
/// it may hold padded.
fn stored_encodings(plan: &mut Plan, rng: &mut Random) {
    let (w, h, ox, oy, rw, rh) = (8usize, 8usize, 2usize, 3usize, 5usize, 3usize);
    for (format, texel, into) in [
        ("bgra10_xr_srgb", 8, true),
        ("bgr10_xr", 4, true),
        ("bgra10_xr", 8, false),
        ("bgr10_xr_srgb", 4, false),
        ("a1bgr5unorm", 2, true),
        ("a1bgr5unorm", 2, false),
        ("rg8unorm_srgb", 2, true),
        ("rg8unorm_srgb", 2, false),
    ] {
        let row = rw * texel + 24;
        let texture = stored_texels(rng, w * h, format);
        let staging = stored_texels(rng, row / texel * rh, format);
        let mut copied = texture.clone();
        let mut read = vec![0x5Au8; row * rh];
        for y in 0..rh {
            let at = ((oy + y) * w + ox) * texel;
            if into {
                copied[at..at + rw * texel]
                    .copy_from_slice(&staging[y * row..y * row + rw * texel]);
            } else {
                read[y * row..y * row + rw * texel].copy_from_slice(&texture[at..at + rw * texel]);
            }
        }
        let texture = Texture::d2("t", format, w as u32, h as u32).data(texture);
        let case = if into {
            Case::blit(
                &format!("blit.buffer_to_texture.{format}"),
                json!([{"op": "buffer_to_texture", "src": "staging", "bytes_per_row": row, "bytes_per_image": row * rh,
                        "size": [rw, rh, 1], "dst": "t", "origin": [ox, oy, 0]}]),
            )
            .buffer(Buffer::data("staging", 0, staging).unbound())
            .texture(texture)
            .output(exact("t", copied))
        } else {
            Case::blit(
                &format!("blit.texture_to_buffer.{format}"),
                json!([{"op": "texture_to_buffer", "src": "t", "origin": [ox, oy, 0], "size": [rw, rh, 1], "dst": "out",
                        "bytes_per_row": row, "bytes_per_image": row * rh}]),
            )
            .buffer(Buffer::data("out", 0, vec![0x5A; row * rh]).unbound())
            .texture(texture)
            .output(exact("out", read))
        };
        plan.add(case);
    }
}

/// Copies of formats a device may sample decoded carry their blocks: into
/// a texture from a buffer, out of one and between two, which reads return.
fn held_blocks(plan: &mut Plan, rng: &mut Random) {
    // 8x8 texels: two block rows of two blocks.
    for (format, block) in [("eac_rgba8", 16usize), ("etc2_rgb8a1", 8)] {
        let texture = bytes(rng, 4 * block);
        // The right column's two blocks, from rows a block and a half apart.
        let row = 2 * block + block;
        let row = row.next_multiple_of(block);
        let staging = bytes(rng, 2 * row);
        let mut copied = texture.clone();
        for y in 0..2 {
            let at = (y * 2 + 1) * block;
            copied[at..at + block].copy_from_slice(&staging[y * row..y * row + block]);
        }
        plan.add(
            Case::blit(
                &format!("blit.buffer_to_texture.{format}"),
                json!([{"op": "buffer_to_texture", "src": "staging", "bytes_per_row": row, "bytes_per_image": 2 * row,
                        "size": [4, 8, 1], "dst": "t", "origin": [4, 0, 0]}]),
            )
            .requires(&["apple1"], &[])
            .buffer(Buffer::data("staging", 0, staging).unbound())
            .texture(Texture::d2("t", format, 8, 8).data(texture.clone()))
            .output(exact("t", copied)),
        );
        // The lower block row, into rows padded by a block.
        let row = 3 * block;
        let mut read = vec![0x5A; row];
        read[..2 * block].copy_from_slice(&texture[2 * block..]);
        plan.add(
            Case::blit(
                &format!("blit.texture_to_buffer.{format}"),
                json!([{"op": "texture_to_buffer", "src": "t", "origin": [0, 4, 0], "size": [8, 4, 1], "dst": "out",
                        "bytes_per_row": row, "bytes_per_image": row}]),
            )
            .requires(&["apple1"], &[])
            .buffer(Buffer::data("out", 0, vec![0x5A; row]).unbound())
            .texture(Texture::d2("t", format, 8, 8).data(texture.clone()))
            .output(exact("out", read)),
        );
        let other = bytes(rng, 4 * block);
        let mut moved = other.clone();
        moved[3 * block..].copy_from_slice(&texture[..block]);
        plan.add(
            Case::blit(
                &format!("blit.copy_texture.{format}"),
                json!([{"op": "copy_texture", "src": "a", "src_origin": [0, 0, 0], "size": [4, 4, 1], "dst": "b",
                        "dst_origin": [4, 4, 0]}]),
            )
            .requires(&["apple1"], &[])
            .texture(Texture::d2("a", format, 8, 8).data(texture))
            .texture(Texture::d2("b", format, 8, 8).data(other))
            .output(exact("b", moved)),
        );
    }
}

/// PVRTC blits copy rows of a region's blocks, as other compressed formats'
/// do, which the device keeps in each level's Morton order: the order in
/// which shared textures receive and return their blocks from the CPU.
fn pvrtc_rows(plan: &mut Plan, rng: &mut Random) {
    // 16x16 texels: four rows of four 8-byte blocks.
    for shared in [false, true] {
        let at = |x: u32, y: u32| {
            8 * if shared {
                super::compressed::twiddle(4, 4, x, y)
            } else {
                (y * 4 + x) as usize
            }
        };
        let storage = |texture: Texture| {
            if shared {
                texture.set("storage", "shared")
            } else {
                texture
            }
        };
        let suffix = if shared { "_shared" } else { "" };
        let texture = bytes(rng, 128);
        let staging = bytes(rng, 64);
        // The lower right 2x2 blocks, from rows of two.
        let mut copied = texture.clone();
        for y in 0..2 {
            for x in 0..2 {
                let (to, from) = (at(2 + x, 2 + y), (y * 16 + x * 8) as usize);
                copied[to..to + 8].copy_from_slice(&staging[from..from + 8]);
            }
        }
        plan.add(
            Case::blit(
                &format!("blit.buffer_to_texture.pvrtc_rgba_4bpp{suffix}"),
                json!([{"op": "buffer_to_texture", "src": "staging", "bytes_per_row": 16, "bytes_per_image": 32,
                        "size": [8, 8, 1], "dst": "t", "origin": [8, 8, 0]}]),
            )
            .requires(&["apple1"], &[])
            .buffer(Buffer::data("staging", 0, staging).unbound())
            .texture(storage(Texture::d2("t", "pvrtc_rgba_4bpp", 16, 16).data(texture.clone())))
            .output(exact("t", copied)),
        );
        // The upper right 2x2 blocks, into rows padded by a block.
        let mut read = vec![0x5A; 72];
        for y in 0..2 {
            for x in 0..2 {
                let (to, from) = ((y * 24 + x * 8) as usize, at(2 + x, y));
                read[to..to + 8].copy_from_slice(&texture[from..from + 8]);
            }
        }
        plan.add(
            Case::blit(
                &format!("blit.texture_to_buffer.pvrtc_rgba_4bpp{suffix}"),
                json!([{"op": "texture_to_buffer", "src": "t", "origin": [8, 0, 0], "size": [8, 8, 1], "dst": "out",
                        "bytes_per_row": 24, "bytes_per_image": 48}]),
            )
            .requires(&["apple1"], &[])
            .buffer(Buffer::data("out", 0, vec![0x5A; 72]).unbound())
            .texture(storage(Texture::d2("t", "pvrtc_rgba_4bpp", 16, 16).data(texture)))
            .output(exact("out", read)),
        );
    }
}

pub fn build(plan: &mut Plan) {
    let mut rng = Random::new(1101);
    pvrtc_rows(plan, &mut Random::new(1105));
    held_blocks(plan, &mut Random::new(1104));
    more(plan, &mut Random::new(1102));
    stored_encodings(plan, &mut Random::new(1103));
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
