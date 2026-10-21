//! Render passes: a VDM stream's draws rasterized into a framebuffer one
//! tile at a time (docs/research/agx.md §5.4, RAS-1..RAS-19).
//!
//! A pass runs in two phases, as the vertex and fragment halves of the
//! hardware do:
//! - [`geometry`] walks the VDM stream, shades vertices, assembles, clips
//!   and culls primitives and bins them with the PPP state they were drawn
//!   with. Binned geometry stays inside the model: the tiled vertex buffer
//!   is hardware-private and no AP code reads it (FW-16), so the model
//!   never overflows it and never runs a partial render (RAS-19).
//! - [`fragment`] then visits every tile of every layer: the ZLS loads or
//!   clears depth and stencil, the background program initializes the
//!   tilebuffer, the primitives are shaded in submission order, the
//!   end-of-tile program stores the tilebuffer through its PBEs and the ZLS
//!   stores depth and stencil.
//!
//! The pass parameters are the register values a 3D command carries
//! (Public: Asahi's `drm_asahi_cmd_render` and Mesa `hk_queue.c`, which
//! fill them from `cmdbuf.xml` packs). How the firmware's own 3D command
//! names them is FW-8 (Blocked), so [`RenderPass`] is the engine's input
//! and nothing builds one from a firmware record yet.

pub mod fragment;
pub mod geometry;

use super::WorkError;
use crate::platform::apple::agx::isa::machine::Memory;
use crate::platform::apple::agx::stream::field;

/// A background or end-of-tile program: its USC word list and resource
/// counts (`drm_asahi_bg_eot`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Program {
    /// The word list's offset from the USC base. Mesa sets bit 2 (meaning
    /// unrecorded); other low bits refuse.
    pub usc: u64,
    /// `Counts` (`rsrc_spec`).
    pub counts: u32,
}

/// A ZLS surface (`drm_asahi_zls_buffer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Zls {
    /// The level's first layer.
    pub base: u64,
    /// `((pages - 1) << 14) | 1`: the layer stride in 16 KiB pages.
    pub stride: u32,
    /// Compression metadata of the level's first layer.
    pub meta: u64,
    /// `(lines - 1) << 14`: the metadata layer stride in 128-byte lines.
    pub meta_stride: u32,
}

/// The parameters of one render pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RenderPass {
    pub vdm_stream: u64,
    /// The base USC offsets (pipelines, code) are relative to.
    pub usc_base: u64,
    /// The UAT context the pass runs in (`vm_slot`).
    pub vm_slot: u32,
    /// `CR PPP Control`.
    pub ppp_control: u32,
    pub width: u32,
    pub height: u32,
    pub layers: u32,
    pub samples: u32,
    /// Tile width and height in pixels (`utile_width_px`/`_height_px`).
    pub tile: (u32, u32),
    /// Tilebuffer bytes per sample (`sample_size_B`).
    pub sample_bytes: u32,
    /// `PPP_MULTISAMPLECTL`: the sample positions.
    pub multisample_control: u32,
    pub background: Program,
    pub end_of_tile: Program,
    /// `ZLS Control`.
    pub zls_control: u64,
    /// `CR ISP ZLS Pixels`: the depth and stencil surfaces' size.
    pub zls_pixels: u32,
    pub depth: Zls,
    pub stencil: Zls,
    /// `isp_bgobjdepth`: the depth clear (unorm16 for Z16, else f32 bits).
    pub depth_clear: u32,
    /// `isp_bgobjvals`: `0x300` and the stencil clear.
    pub background_values: u32,
    /// The scissor array (16-byte `Scissor` entries).
    pub scissors: u64,
    /// The depth-bias array (12-byte `Depth bias` entries).
    pub depth_biases: u64,
    /// The visibility (occlusion) result array, a u64 per index.
    pub visibility: u64,
    /// The sampler heap (8-byte samplers) and its entry count.
    pub sampler_heap: u64,
    pub sampler_count: u32,
}

/// What a pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub draws: u64,
    /// Primitives that reached the rasterizer.
    pub primitives: u64,
    pub tiles: u64,
    /// Fragment SIMD groups shaded.
    pub fragment_groups: u64,
}

/// `CR PPP Control` fields.
pub mod ppp_control {
    pub const OPENGL: u32 = 1 << 0;
    pub const W_CLAMP: u32 = 1 << 1;
    pub const DEFAULT_POINT_SIZE: u32 = 1 << 8;
    pub const FIXED_POINT_FORMAT: u32 = 1 << 9;
    pub const KNOWN: u32 = OPENGL | W_CLAMP | DEFAULT_POINT_SIZE | FIXED_POINT_FORMAT;
}

/// `ZLS Control` fields.
pub mod zls {
    pub const Z_LOAD_TILING: u32 = 1;
    pub const Z_LOAD_COMPRESS: u32 = 2;
    pub const S_LOAD_TILING: u32 = 3;
    pub const S_LOAD_COMPRESS: u32 = 4;
    pub const Z_STORE_TILING: u32 = 5;
    pub const Z_STORE_COMPRESS: u32 = 6;
    pub const S_STORE_TILING: u32 = 7;
    pub const S_STORE_COMPRESS: u32 = 8;
    pub const S_LOAD: u32 = 14;
    pub const Z_LOAD: u32 = 15;
    pub const S_STORE: u32 = 18;
    pub const Z_STORE: u32 = 19;
    pub const Z_FORMAT: u32 = 25;
    pub const Z_RESOLVE: u32 = 56;
    pub const S_RESOLVE: u32 = 58;
    /// `ZLS Format` values.
    pub const FORMAT_32F: u64 = 0;
    pub const FORMAT_16: u64 = 2;
}

/// Tile sizes the hardware has (USC `Shared layout`).
const TILE_SIZES: [(u32, u32); 3] = [(32, 32), (32, 16), (16, 16)];
/// `isp_bgobjvals` bits Mesa always sets (meaning unrecorded).
const BACKGROUND_FIXED: u32 = 0x300;
/// The stencil clear in `isp_bgobjvals`.
const STENCIL_CLEAR: u32 = 0xff;
/// Low bits of a background or end-of-tile USC offset: Mesa sets bit 2.
const PROGRAM_FLAG: u64 = 1 << 2;
const PROGRAM_ALIGN: u64 = 64;
/// A ZLS layer-stride unit and a metadata layer-stride unit.
const PAGE: u64 = 16384;
const CACHE_LINE: u64 = 128;
const STRIDE_SHIFT: u32 = 14;

impl Program {
    /// The word list's offset, checked.
    pub fn offset(&self) -> Result<u64, WorkError> {
        if self.usc & (PROGRAM_ALIGN - 1) & !PROGRAM_FLAG != 0 {
            return Err(WorkError::Refused(
                "a background or end-of-tile program with unnamed low address bits",
            ));
        }
        Ok(self.usc & !(PROGRAM_ALIGN - 1))
    }
}

impl Zls {
    /// The layer stride in bytes.
    pub fn layer_stride(&self) -> Result<u64, WorkError> {
        if self.stride & !(u32::MAX << STRIDE_SHIFT) != 1 {
            return Err(WorkError::Refused(
                "a ZLS stride whose low bits are not Mesa's 1 (meaning unrecorded)",
            ));
        }
        Ok((u64::from(self.stride >> STRIDE_SHIFT) + 1) * PAGE)
    }

    /// The metadata layer stride in bytes.
    pub fn meta_layer_stride(&self) -> Result<u64, WorkError> {
        if self.meta_stride & !(u32::MAX << STRIDE_SHIFT) != 0 {
            return Err(WorkError::Refused(
                "a ZLS metadata stride with low bits set (meaning unrecorded)",
            ));
        }
        Ok((u64::from(self.meta_stride >> STRIDE_SHIFT) + 1) * CACHE_LINE)
    }
}

impl RenderPass {
    pub fn zls(&self, bit: u32) -> bool {
        field(self.zls_control, bit, 1) != 0
    }

    /// Z16 depth (else 32-bit float).
    pub fn depth_16(&self) -> bool {
        field(self.zls_control, zls::Z_FORMAT, 2) == zls::FORMAT_16
    }

    /// The ZLS surfaces' width and height.
    pub fn zls_size(&self) -> (u32, u32) {
        let x = self.zls_pixels & 0x7fff;
        let y = (self.zls_pixels >> 15) & 0x7fff;
        (x + 1, y + 1)
    }

    pub fn stencil_clear(&self) -> u8 {
        (self.background_values & STENCIL_CLEAR) as u8
    }

    /// Refuse parameters outside what the sources define.
    pub(crate) fn check(&self) -> Result<(), WorkError> {
        if !TILE_SIZES.contains(&self.tile) {
            return Err(WorkError::Refused("a tile size the hardware lacks"));
        }
        if ![1, 2, 4].contains(&self.samples) {
            return Err(WorkError::Refused("a sample count other than 1, 2 or 4"));
        }
        if self.width == 0 || self.height == 0 || self.layers == 0 {
            return Err(WorkError::Refused("an empty framebuffer"));
        }
        if self.ppp_control & !ppp_control::KNOWN != 0 {
            return Err(WorkError::Refused("a PPP control with unnamed bits"));
        }
        if self.ppp_control & ppp_control::FIXED_POINT_FORMAT == 0 {
            return Err(WorkError::Refused(
                "fixed-point format 0 (its precision is unrecorded; Mesa sets 1)",
            ));
        }
        let known = [
            (zls::Z_LOAD_TILING, 8),
            (zls::S_LOAD, 2),
            (zls::S_STORE, 2),
            (zls::Z_FORMAT, 2),
            (zls::Z_RESOLVE, 1),
            (zls::S_RESOLVE, 1),
        ]
        .iter()
        .fold(0u64, |m, &(start, size)| m | ((1u64 << size) - 1) << start);
        if self.zls_control & !known != 0 {
            return Err(WorkError::Refused("a ZLS control with unnamed bits"));
        }
        if self.zls(zls::Z_RESOLVE) || self.zls(zls::S_RESOLVE) {
            return Err(WorkError::Refused(
                "ZLS resolves (the resolve's filter is unrecorded)",
            ));
        }
        let format = field(self.zls_control, zls::Z_FORMAT, 2);
        if format != zls::FORMAT_16 && format != zls::FORMAT_32F {
            return Err(WorkError::Refused("a ZLS format the description lacks"));
        }
        if self.background_values & !(BACKGROUND_FIXED | STENCIL_CLEAR) != 0 {
            return Err(WorkError::Refused("background values with unnamed bits"));
        }
        Ok(())
    }
}

/// Run a render pass to completion.
pub fn run(memory: &mut dyn Memory, pass: &RenderPass) -> Result<Stats, WorkError> {
    pass.check()?;
    let mut stats = Stats::default();
    let binned = geometry::run(memory, pass, &mut stats)?;
    fragment::run(memory, pass, &binned, &mut stats)?;
    Ok(stats)
}

/// Entry `index` of the pass's sampler heap.
pub(crate) fn heap_sampler(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    index: u32,
) -> Result<[u8; 8], &'static str> {
    if pass.sampler_heap == 0 || index >= pass.sampler_count {
        return Err("a sampler-heap index past the pass's sampler heap");
    }
    let mut sampler = [0u8; 8];
    memory
        .read(pass.sampler_heap + 8 * u64::from(index), &mut sampler)
        .map_err(|_| "a fault reading the sampler heap")?;
    Ok(sampler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::format::descriptor::Tiling;
    use crate::platform::apple::agx::format::image::{At, Image};
    use crate::platform::apple::agx::format::texel::{Format, channels, ty};
    use crate::platform::apple::agx::isa::assemble::program;
    use crate::platform::apple::agx::isa::machine::tests::Flat;
    use crate::platform::apple::agx::stream::tests::words;
    use alloc::vec::Vec;

    const BASE: u64 = 0x1_0000_0000;
    const VS_USC: u64 = 0x100;
    const FS_USC: u64 = 0x200;
    const BG_USC: u64 = 0x300;
    const EOT_USC: u64 = 0x380;
    const CF: u64 = 0x400;
    const VS_UNIFORMS: u64 = 0x500;
    const BG_UNIFORMS: u64 = 0x540;
    const PBE: u64 = 0x600;
    const PPP: u64 = 0x700;
    const VERTICES: u64 = 0x800;
    const STREAM: u64 = 0xc00;
    const VS_CODE: u64 = 0x1000;
    const FS_CODE: u64 = 0x1400;
    const BG_CODE: u64 = 0x1800;
    const EOT_CODE: u64 = 0x1c00;
    const IMAGE: u64 = 0x10000;
    const DEPTH: u64 = 0x20000;
    const VISIBILITY: u64 = 0x30000;
    const SIZE: u32 = 32;
    const CLEAR: [f32; 4] = [0.25, 0.5, 0.75, 1.0];

    /// A USC list: uniforms (start, halves, address), a texture state,
    /// fragment properties and the code.
    fn usc(
        memory: &mut Flat,
        at: u64,
        uniforms: Option<(u64, u64, u64)>,
        texture: Option<u64>,
        early_z: Option<bool>,
        code: u64,
    ) {
        let mut bytes = Vec::new();
        if let Some((start, halves, address)) = uniforms {
            let word = 0x1d | start << 8 | halves << 20 | ((BASE + address) >> 2) << 26;
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        if let Some(address) = texture {
            let word = 0xdd_u64 | 1 << 20 | ((BASE + address) >> 3) << 27;
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&0x8d_u32.to_le_bytes());
        if let Some(early) = early_z {
            bytes.extend_from_slice(&(0x58 | u32::from(early) << 8).to_le_bytes());
        }
        bytes.extend_from_slice(&[0x0d, 0]);
        bytes.extend_from_slice(&(code as u32).to_le_bytes());
        bytes.extend_from_slice(&[0x88, 0]);
        memory.put(BASE + at, &bytes);
    }

    /// A linear RGBA8 PBE over the framebuffer at [`IMAGE`].
    fn pbe() -> [u8; 24] {
        let mut pbe = [0u8; 24];
        let mut put = |start: u32, size: u32, value: u64| {
            for i in 0..size {
                let bit = start + i;
                pbe[(bit / 8) as usize] |= ((value >> i & 1) as u8) << (bit % 8);
            }
        };
        put(0, 4, 2);
        put(6, 7, u64::from(channels::R8G8B8A8));
        put(16, 2, 0);
        put(18, 2, 1);
        put(20, 2, 2);
        put(22, 2, 3);
        put(24, 14, u64::from(SIZE - 1));
        put(38, 14, u64::from(SIZE - 1));
        put(64, 36, (BASE + IMAGE) >> 4);
        put(104, 21, u64::from(4 * SIZE - 4));
        pbe
    }

    /// A pass drawing `vertices` (clip position then colour) as one
    /// triangle list, with `face` and fragment `control` PPP words.
    fn scene(
        vertices: &[[f32; 8]],
        face: u32,
        control: u32,
        zls_control: u64,
    ) -> (Flat, RenderPass) {
        let mut memory = Flat::new(BASE, 0x40000);
        memory.put(
            BASE + VS_CODE,
            &program(
                "load r8_r9_r10_r11, du0, r5, lsl 3, i32, xyzw, a\n\
                 load r12_r13_r14_r15, du2, r5, lsl 3, i32, xyzw, a\n\
                 st_var r8, 0\nst_var r9, 1\nst_var r10, 2\nst_var r11, 3\n\
                 st_var r12, 4\nst_var r13, 5\nst_var r14, 6\nst_var r15, 7\n\
                 stop",
            ),
        );
        memory.put(
            BASE + FS_CODE,
            &program(
                "iter r4_r5_r6_r7, cf1, cf0\n\
                 st_tile r4_r5_r6_r7, 0, 255, 0, u8norm, xyzw\n\
                 stop",
            ),
        );
        memory.put(
            BASE + BG_CODE,
            &program(
                "mov r4, u4\nmov r5, u5\nmov r6, u6\nmov r7, u7\n\
                 st_tile r4_r5_r6_r7, 0, 255, 0, u8norm, xyzw\n\
                 stop",
            ),
        );
        memory.put(
            BASE + EOT_CODE,
            &program("imgwblk r0l, ts0, r0, 0, 2d, u8norm\nstop"),
        );
        usc(
            &mut memory,
            VS_USC,
            Some((0, 8, VS_UNIFORMS)),
            None,
            None,
            VS_CODE,
        );
        usc(&mut memory, FS_USC, None, None, Some(true), FS_CODE);
        usc(
            &mut memory,
            BG_USC,
            Some((8, 8, BG_UNIFORMS)),
            None,
            None,
            BG_CODE,
        );
        usc(&mut memory, EOT_USC, None, Some(PBE), None, EOT_CODE);
        // CF bindings: 1/W (slot 0, linear) and the colour (slots 1..4,
        // perspective).
        words(
            &mut memory,
            BASE + CF,
            &[5 | 5 << 8, 3 << 2, 3 | 7 << 2 | 1 << 8 | 1 << 16],
        );
        memory.put(BASE + VS_UNIFORMS, &(BASE + VERTICES).to_le_bytes());
        memory.put(
            BASE + VS_UNIFORMS + 8,
            &(BASE + VERTICES + 16).to_le_bytes(),
        );
        let clear: Vec<u8> = CLEAR.iter().flat_map(|c| c.to_le_bytes()).collect();
        memory.put(BASE + BG_UNIFORMS, &clear);
        memory.put(BASE + PBE, &pbe());
        let data: Vec<u8> = vertices
            .iter()
            .flatten()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        memory.put(BASE + VERTICES, &data);
        let half = (SIZE / 2) as f32;
        let header: u32 = (0..8).filter(|&b| b != 1).fold(0, |h, b| h | 1 << b)
            | 1 << 11
            | 1 << 17
            | 1 << 18
            | 1 << 21
            | 1 << 22
            | 1 << 23
            | 1 << 24;
        let face_2 = face & (1 << 21 | 7 << 24);
        let mut record = alloc::vec![header, control, face, face_2, 0, face, face_2, 0, 0];
        record.extend([half, half, half, half, 0.0, 1.0].map(f32::to_bits));
        record.extend([1 << 16, 4, 0, 0]);
        record.extend([2 << 16, FS_USC as u32, CF as u32, 0, 3 << 17]);
        words(&mut memory, BASE + PPP, &record);
        let ppp = BASE + PPP;
        words(
            &mut memory,
            BASE + STREAM,
            &[
                2 << 29 | 1 << 1 | 1 << 2 | 1 << 3,
                0,
                VS_USC as u32,
                8 | 8 << 8,
                (ppp >> 32) as u32 | (record.len() as u32) << 8,
                ppp as u32,
                3 << 29 | 6 << 8 | 1 << 22 | 1 << 23 | 1 << 24,
                vertices.len() as u32,
                1,
                0,
                6 << 29,
            ],
        );
        let pass = RenderPass {
            vdm_stream: BASE + STREAM,
            usc_base: BASE,
            ppp_control: ppp_control::FIXED_POINT_FORMAT,
            width: SIZE,
            height: SIZE,
            layers: 1,
            samples: 1,
            tile: (32, 32),
            sample_bytes: 4,
            multisample_control: 0x88,
            background: Program {
                usc: BG_USC | 4,
                counts: 0,
            },
            end_of_tile: Program {
                usc: EOT_USC | 4,
                counts: 0,
            },
            zls_control,
            zls_pixels: (SIZE - 1) | (SIZE - 1) << 15,
            depth: Zls {
                base: BASE + DEPTH,
                stride: 1,
                meta: 0,
                meta_stride: 0,
            },
            depth_clear: 1.0f32.to_bits(),
            background_values: 0x300,
            visibility: BASE + VISIBILITY,
            ..RenderPass::default()
        };
        (memory, pass)
    }

    fn vertex(x: f32, y: f32, z: f32, colour: [f32; 4]) -> [f32; 8] {
        [x, y, z, 1.0, colour[0], colour[1], colour[2], colour[3]]
    }

    fn unorm8(value: f64) -> i32 {
        crate::platform::apple::agx::isa::math::round(value.clamp(0.0, 1.0) * 255.0) as i32
    }

    const ALWAYS_NO_WRITE: u32 = 7 << 24 | 1 << 21;

    #[test]
    fn a_triangle_interpolates_its_colours_over_the_background() {
        let (red, green, blue) = (
            [1.0, 0.0, 0.0, 1.0],
            [0.0, 1.0, 0.0, 1.0],
            [0.0, 0.0, 1.0, 1.0],
        );
        let (mut memory, pass) = scene(
            &[
                vertex(-1.0, -1.0, 0.5, red),
                vertex(1.0, -1.0, 0.5, green),
                vertex(-1.0, 1.0, 0.5, blue),
            ],
            ALWAYS_NO_WRITE,
            0,
            0,
        );
        let stats = run(&mut memory, &pass).unwrap();
        assert_eq!((stats.draws, stats.primitives, stats.tiles), (1, 1, 1));
        let background = CLEAR.map(|c| unorm8(f64::from(c)));
        for y in 0..SIZE {
            for x in 0..SIZE {
                let at = BASE + IMAGE + u64::from(4 * (y * SIZE + x));
                let got: Vec<i32> = memory.get(at, 4).iter().map(|&b| i32::from(b)).collect();
                let (px, py) = (f64::from(x) + 0.5, f64::from(y) + 0.5);
                if px + py == f64::from(SIZE) {
                    continue; // On the shared edge: the fill rule decides.
                }
                // The reference: barycentric weights in the window.
                let (l1, l2) = (px / f64::from(SIZE), py / f64::from(SIZE));
                let expected = if px + py < f64::from(SIZE) {
                    [1.0 - l1 - l2, l1, l2, 1.0].map(unorm8)
                } else {
                    background
                };
                for c in 0..4 {
                    assert!(
                        (got[c] - expected[c]).abs() <= 1,
                        "pixel ({x}, {y}) got {got:?} expected {expected:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn depth_tests_keep_the_nearer_triangle_and_the_zls_stores_depth() {
        let (red, green) = ([1.0, 0.0, 0.0, 1.0], [0.0, 1.0, 0.0, 1.0]);
        // Two screen-covering triangles (clipped to the volume): near red,
        // then far green; LESS keeps red. Visibility counts samples.
        let near = [
            vertex(-1.0, -1.0, 0.25, red),
            vertex(3.0, -1.0, 0.25, red),
            vertex(-1.0, 3.0, 0.25, red),
        ];
        let far = [
            vertex(-1.0, -1.0, 0.75, green),
            vertex(3.0, -1.0, 0.75, green),
            vertex(-1.0, 3.0, 0.75, green),
        ];
        let all: Vec<[f32; 8]> = near.iter().chain(&far).copied().collect();
        let zls_control = 1 << zls::Z_STORE;
        let (mut memory, pass) = scene(&all, 1 << 24, 2 << 14, zls_control);
        let stats = run(&mut memory, &pass).unwrap();
        // Each triangle clips to the framebuffer square: two fan triangles.
        assert_eq!(stats.primitives, 4);
        for i in 0..SIZE * SIZE {
            assert_eq!(
                memory.get(BASE + IMAGE + 4 * u64::from(i), 4),
                [255, 0, 0, 255],
                "pixel {i}"
            );
        }
        assert_eq!(memory.u32(BASE + VISIBILITY + 8 * 3), SIZE * SIZE);
        let surface = Image::surface(
            Format {
                channels: channels::R32,
                ty: ty::FLOAT,
                srgb: false,
                srgb_2_channel: false,
            },
            Tiling::Gpu,
            (SIZE, SIZE),
            1,
            1,
            BASE + DEPTH,
            16384,
            None,
        )
        .unwrap();
        for (x, y) in [(0, 0), (31, 0), (17, 29)] {
            let depth = surface.read(&mut memory, At::new(0, x, y, 0, 0)).unwrap();
            assert_eq!(depth.value[0], 0.25);
        }
    }

    #[test]
    fn unsupported_pass_parameters_refuse_by_name() {
        let (mut memory, mut pass) = scene(&[], ALWAYS_NO_WRITE, 0, 0);
        pass.tile = (16, 32);
        assert!(matches!(
            run(&mut memory, &pass),
            Err(WorkError::Refused(_))
        ));
        pass.tile = (32, 32);
        pass.zls_control = 1 << zls::Z_RESOLVE;
        assert!(matches!(
            run(&mut memory, &pass),
            Err(WorkError::Refused(_))
        ));
    }
}
