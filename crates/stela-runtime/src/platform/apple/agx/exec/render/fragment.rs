//! The fragment half of a render pass: tiles, the tilebuffer, fragment
//! shading, depth/stencil and the background and end-of-tile programs.
//!
//! Semantics (Public: Mesa `agx_tilebuffer.c`, `agx_nir_lower_tilebuffer.c`,
//! `agx_nir_lower_sample_mask.c`, `agx_nir_lower_interpolation.c`,
//! `agx_bg_eot.c`, `agx_uvs.h` and `hk_cmd_draw.c`; Inferred where marked):
//! - A tile holds every sample of its pixels, `sample_size_B` bytes each;
//!   a render target sits at its byte offset in the ISA format `ld_tile`,
//!   `st_tile` and `imgwblk` name, component `i` at `i` element sizes in
//!   (packed formats in one word).
//! - Per tile and layer: depth and stencil load through the ZLS or clear to
//!   `isp_bgobjdepth`/`isp_bgobjvals`; the background program runs once per
//!   pixel with every sample covered; primitives shade in submission order
//!   (so `pixwait`/`pixrel` never wait); the end-of-tile program runs on one
//!   thread (Inferred) and its `imgwblk` stores the tile's render target
//!   through the PBE; the ZLS stores depth and stencil.
//! - Fragment SIMD groups cover 8x4 pixels as eight 2x2 quads, lane `4q +
//!   (x & 1) + 2 (y & 1)` with quads row-major (Inferred); a quad with any
//!   covered pixel is present and its uncovered pixels are helpers.
//! - The fragment's 32-bit slots are 1/W (slot 0), window Z when `Frag
//!   coord Z` is selected (slot 1), then the user varyings: slot `1 + fragz
//!   + i` is UVS word `4 + i` (Mesa `agx_link_varyings_vs_fs`).
//!   Coefficient registers hold planes relative to the pixel's 32x32 region;
//!   a perspective plane carries `v / w` and `iterproj` divides by the 1/W
//!   plane; flat values keep their bits in `C`.
//! - With `early Z`, every covered sample is tested before shading;
//!   otherwise tests happen at `sample_mask`/`zs_emit` (samples a shader
//!   never tests are tested when it ends, Inferred). `st_tile` writes the
//!   live samples, and refuses on samples still untested (rule 1 of Mesa's
//!   `sample_mask` contract). `tag write disable` tests without shading.
//! - Visibility counts passing samples (`Counting`) or records any pass
//!   (`Boolean`, as 1) into the u64 at `visibility + 8 index`; counts add
//!   to what is there (Mesa zeroes queries before a pass).
//! - Point coordinates run 0..1 across the point, `t` growing down the
//!   window for `Point sprite UV=01` and up for `UV=10` (Inferred).
//!
//! Refused by name: shaders reading barycentrics (the fragment pipeline), several-sample
//! tilebuffer loads, tests run twice or discards of tested samples,
//! block stores that would resolve samples, and rotated PBEs.

use super::super::{GROUP_BUDGET, ShaderState, WorkError};
use super::geometry::{Binned, POSITION_WORDS, Primitive, Shape, Vertex, object, output};
use super::{Program as PassProgram, RenderPass, Stats, heap_sampler, zls};
mod pipeline;
mod primitive;
use crate::platform::apple::agx::format::descriptor::{Pbe, Tiling};
use crate::platform::apple::agx::format::image::{At, Image, ImageError};
use crate::platform::apple::agx::format::isa::{IsaFormat, register_float};
use crate::platform::apple::agx::format::texel::{Format, channels, ty};
use crate::platform::apple::agx::isa::machine::{
    BlockStore, Env, Exit, Fault, Interpolation, Memory, Program, SIMD_WIDTH, Specials, TileAccess,
};
use crate::platform::apple::agx::isa::math;
use crate::platform::apple::agx::raster::coverage::{self, MAX_SAMPLES, Rect};
use crate::platform::apple::agx::raster::plane::{Plane, REGION};
use crate::platform::apple::agx::raster::zs::{self, FaceState, Sample};
use crate::platform::apple::agx::stream::cdm::extended_samplers;
use crate::platform::apple::agx::stream::ppp::FragmentControl;
use crate::platform::apple::agx::stream::{field, usc};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use pipeline::{FragmentPipeline, shade, source};

/// Pixels of a fragment SIMD group.
const GROUP_WIDTH: u32 = 8;
const GROUP_HEIGHT: u32 = 4;
/// `sample_mask`/`st_tile` "all samples".
const ALL_SAMPLES: u32 = 0xff;
/// `Visibility Mode` values.
mod visibility {
    pub const NONE: u32 = 0;
    pub const COUNTING: u32 = 2;
    pub const BOOLEAN: u32 = 3;
}
const UNORM16_MAX: f64 = 65535.0;

/// One tile's storage.
pub struct Tile {
    pub origin: [u32; 2],
    pub size: [u32; 2],
    pub index: [u32; 2],
    pub layer: u32,
    pub samples: u32,
    pub sample_bytes: usize,
    pub colour: Vec<u8>,
    pub zs: Vec<Sample>,
}

impl Tile {
    fn slot(&self, local: [u32; 2], sample: u32) -> usize {
        ((local[1] * self.size[0] + local[0]) * self.samples + sample) as usize
    }

    fn local(&self, pixel: [u32; 2]) -> [u32; 2] {
        [pixel[0] - self.origin[0], pixel[1] - self.origin[1]]
    }

    /// The bytes of render-target components at `offset` of one sample.
    fn bytes(
        &mut self,
        local: [u32; 2],
        sample: u32,
        offset: u32,
        length: usize,
    ) -> Result<&mut [u8], &'static str> {
        if local[0] >= self.size[0] || local[1] >= self.size[1] {
            return Err("a tilebuffer access outside the tile");
        }
        if offset as usize + length > self.sample_bytes {
            return Err("a tilebuffer access past the sample size");
        }
        let start = self.slot(local, sample) * self.sample_bytes + offset as usize;
        Ok(&mut self.colour[start..start + length])
    }

    /// Every component of a render target as register bits.
    fn load(
        &mut self,
        local: [u32; 2],
        sample: u32,
        offset: u32,
        format: IsaFormat,
        register_bits: u32,
    ) -> Result<[u64; 4], &'static str> {
        if format.packed() {
            let bytes = self.bytes(local, sample, offset, 4)?;
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            return Ok(format.load_packed(word, register_bits));
        }
        let element = format.element_bytes();
        let available = (self.sample_bytes.saturating_sub(offset as usize) / element).min(4);
        let bytes = self.bytes(local, sample, offset, available * element)?;
        let mut values = [0u64; 4];
        for (c, value) in values.iter_mut().enumerate().take(available) {
            *value = format.load(c, &bytes[c * element..], register_bits);
        }
        Ok(values)
    }

    /// Store the components in `mask` (register bits by component).
    fn store(
        &mut self,
        local: [u32; 2],
        sample: u32,
        access: &TileAccess,
        values: [u64; 4],
    ) -> Result<(), &'static str> {
        let format = access.format;
        if format.packed() {
            let mut all = self.load(local, sample, access.offset, format, access.register_bits)?;
            for (c, value) in all.iter_mut().enumerate() {
                if access.mask >> c & 1 != 0 {
                    *value = values[c];
                }
            }
            let word = format.store_packed(all, access.register_bits);
            self.bytes(local, sample, access.offset, 4)?
                .copy_from_slice(&word.to_le_bytes());
            return Ok(());
        }
        let element = format.element_bytes();
        for (c, &value) in values.iter().enumerate() {
            if access.mask >> c & 1 == 0 {
                continue;
            }
            let bytes = format.store(c, value, access.register_bits);
            self.bytes(local, sample, access.offset + (c * element) as u32, element)?
                .copy_from_slice(&bytes[..element]);
        }
        Ok(())
    }
}

/// A fragment thread's pixel and samples.
#[derive(Debug, Clone, Copy, Default)]
struct Lane {
    pixel: [u32; 2],
    covered: u32,
    alive: u32,
    tested: u32,
}

/// What depth/stencil tests a fragment runs.
struct Tests {
    face: FaceState,
    depth: Plane,
    clamp: Option<(f32, f32)>,
    depth_16: bool,
    visibility: Option<(u32, u32)>,
}

/// Visibility results by index: mode and value.
type Visibility = BTreeMap<u32, (u32, u64)>;

struct FragmentEnv<'a> {
    memory: &'a mut dyn Memory,
    pass: &'a RenderPass,
    tile: &'a mut Tile,
    lanes: [Lane; SIMD_WIDTH],
    positions: &'a [[f64; 2]; MAX_SAMPLES],
    all: u32,
    coefficients: Vec<[f32; 3]>,
    tests: Option<Tests>,
    block_stores: bool,
    visibility: &'a mut Visibility,
}

impl Memory for FragmentEnv<'_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
        self.memory.read(address, buffer)
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault> {
        self.memory.write(address, data)
    }
}

impl FragmentEnv<'_> {
    fn samples(&self, mask: u32) -> u32 {
        if mask == ALL_SAMPLES {
            self.all
        } else {
            mask & self.all
        }
    }

    /// Test one sample; returns whether it passed.
    fn test(&mut self, lane: usize, sample: u32, depth: Option<f32>, stencil: Option<u8>) -> bool {
        let tests = self
            .tests
            .as_ref()
            .expect("tests run only where configured");
        let pixel = self.lanes[lane].pixel;
        let position = self.positions[sample as usize];
        let mut depth = depth.unwrap_or_else(|| {
            tests.depth.at(
                f64::from(pixel[0]) + position[0],
                f64::from(pixel[1]) + position[1],
            ) as f32
        });
        if let Some((low, high)) = tests.clamp {
            depth = depth.clamp(low.min(high), high.max(low));
        }
        let mut face = tests.face;
        if let Some(reference) = stencil {
            face.face.stencil_reference = reference;
        }
        let depth_16 = tests.depth_16;
        let visibility = tests.visibility;
        let local = self.tile.local(pixel);
        let slot = self.tile.slot(local, sample);
        let passed = zs::test(&face, depth, &mut self.tile.zs[slot], |d| {
            quantize(d, depth_16)
        });
        if passed && let Some((mode, index)) = visibility {
            let entry = self.visibility.entry(index).or_insert((mode, 0));
            entry.1 += 1;
        }
        passed
    }

    /// Test the untested live samples in `mask` of a lane.
    fn test_samples(&mut self, lane: usize, mask: u32, depth: Option<f32>, stencil: Option<u8>) {
        let pending = mask & self.lanes[lane].alive & !self.lanes[lane].tested;
        for sample in bits(pending) {
            if !self.test(lane, sample, depth, stencil) {
                self.lanes[lane].alive &= !(1 << sample);
            }
        }
        self.lanes[lane].tested |= pending;
    }

    fn local(&self, access: &TileAccess) -> [u32; 2] {
        match access.coords {
            Some(coords) => coords,
            None => self.tile.local(self.lanes[access.lane].pixel),
        }
    }
}

fn quantize(depth: f32, depth_16: bool) -> f32 {
    if depth_16 {
        (math::round(f64::from(depth).clamp(0.0, 1.0) * UNORM16_MAX) / UNORM16_MAX) as f32
    } else {
        depth
    }
}

fn bits(mask: u32) -> impl Iterator<Item = u32> {
    (0..32).filter(move |b| mask >> b & 1 != 0)
}

impl Env for FragmentEnv<'_> {
    fn coefficient(&mut self, cf: u32) -> Result<[f32; 3], &'static str> {
        self.coefficients
            .get(cf as usize)
            .copied()
            .ok_or("a coefficient register past the shader's CF bindings")
    }

    fn interpolation_point(
        &mut self,
        lane: usize,
        mode: Interpolation,
    ) -> Result<[f32; 2], &'static str> {
        let state = self.lanes[lane];
        let region = [state.pixel[0] % REGION, state.pixel[1] % REGION].map(f64::from);
        let offset = match mode {
            Interpolation::Center => [0.5, 0.5],
            Interpolation::Sample(sample) => {
                if sample >= self.tile.samples {
                    return Err("iter at a sample past the pass's sample count");
                }
                self.positions[sample as usize]
            }
            Interpolation::Centroid => {
                if state.covered == self.all || state.covered == 0 {
                    [0.5, 0.5]
                } else {
                    self.positions[state.covered.trailing_zeros() as usize]
                }
            }
        };
        Ok([
            (region[0] + offset[0]) as f32,
            (region[1] + offset[1]) as f32,
        ])
    }

    fn tile_load(&mut self, access: &TileAccess) -> Result<[u64; 4], &'static str> {
        let samples = self.samples(access.samples);
        if samples.count_ones() != 1 {
            return Err("a tilebuffer load of several samples");
        }
        let local = self.local(access);
        let all = self.tile.load(
            local,
            samples.trailing_zeros(),
            access.offset,
            access.format,
            access.register_bits,
        )?;
        // Compact the masked components in mask order.
        let mut out = [0u64; 4];
        for (slot, c) in bits(access.mask & 0xf).enumerate() {
            out[slot] = all[c as usize];
        }
        Ok(out)
    }

    fn tile_store(&mut self, access: &TileAccess, values: [u64; 4]) -> Result<(), &'static str> {
        let lane = self.lanes[access.lane];
        let samples = self.samples(access.samples) & lane.alive;
        if self.tests.is_some() && samples & !lane.tested != 0 {
            return Err("a tilebuffer store before its samples' depth/stencil tests");
        }
        let mut by_component = [0u64; 4];
        for (slot, c) in bits(access.mask & 0xf).enumerate() {
            by_component[c as usize] = values[slot];
        }
        let local = self.local(access);
        for sample in bits(samples) {
            self.tile.store(local, sample, access, by_component)?;
        }
        Ok(())
    }

    fn sample_mask(&mut self, lane: usize, target: u32, live: u32) -> Result<bool, &'static str> {
        if self.tests.is_none() {
            return Err("sample_mask in a background program");
        }
        let target = self.samples(target);
        let state = self.lanes[lane];
        let affected = target & state.alive;
        if affected & state.tested & live != 0 {
            return Err("sample_mask testing a sample twice");
        }
        if affected & state.tested & !live != 0 {
            return Err("sample_mask discarding a tested sample");
        }
        self.lanes[lane].alive &= !(affected & !live);
        self.test_samples(lane, affected & live, None, None);
        Ok(self.lanes[lane].alive == 0)
    }

    fn zs_emit(
        &mut self,
        lane: usize,
        mask: u32,
        depth: Option<f32>,
        stencil: Option<u8>,
    ) -> Result<bool, &'static str> {
        if self.tests.is_none() {
            return Err("zs_emit in a background program");
        }
        let mask = self.samples(mask);
        let state = self.lanes[lane];
        if mask & state.alive & state.tested != 0 {
            return Err("zs_emit testing a sample twice");
        }
        self.test_samples(lane, mask, depth, stencil);
        Ok(self.lanes[lane].alive == 0)
    }

    fn sampler_heap(&mut self, index: u32) -> Result<[u8; 8], &'static str> {
        heap_sampler(self.memory, self.pass, index)
    }

    fn block_store(&mut self, store: &BlockStore) -> Result<(), ImageError> {
        if !self.block_stores {
            return Err(ImageError::Refused(
                "imgwblk outside an end-of-tile program",
            ));
        }
        let pbe = Pbe::decode(&store.pbe)?;
        if pbe.rotate_90 {
            return Err(ImageError::Refused(
                "rotated PBE writes (the rotation's direction is unrecorded)",
            ));
        }
        let image = Image::from_pbe(&pbe)?;
        if image.samples != self.tile.samples {
            return Err(ImageError::Refused(
                "a block store whose sample count differs from the tile's (a resolve)",
            ));
        }
        let (width, height, layers) = image.level_size(pbe.level);
        if store.layer >= layers {
            return Ok(());
        }
        let element_bits = 8 * store.format.element_bytes() as u32;
        for ly in 0..self.tile.size[1] {
            for lx in 0..self.tile.size[0] {
                let (x, y) = (self.tile.origin[0] + lx, self.tile.origin[1] + ly);
                if x >= width || y >= height || x >= self.pass.width || y >= self.pass.height {
                    continue;
                }
                for sample in 0..self.tile.samples {
                    let raw = self
                        .tile
                        .load([lx, ly], sample, store.offset, store.format, 32)
                        .map_err(ImageError::Refused)?;
                    let values = raw.map(|bits| match image.format.ty {
                        ty::UINT => bits as u32 as f64,
                        ty::SINT if element_bits < 32 => {
                            let shift = 32 - element_bits;
                            f64::from(((bits as u32) << shift) as i32 >> shift)
                        }
                        ty::SINT => f64::from(bits as u32 as i32),
                        _ => register_float(bits, 32),
                    });
                    let memory_order = pbe.swizzle.map(|from| values[from]);
                    let y = if pbe.flip_vertical { height - 1 - y } else { y };
                    image.write(
                        self.memory,
                        At::new(pbe.level, x, y, store.layer, sample),
                        memory_order,
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// The depth and stencil surfaces the ZLS loads and stores.
struct Surfaces {
    depth: Option<Image>,
    stencil: Option<Image>,
}

fn surface(
    pass: &RenderPass,
    zls: &super::Zls,
    format: Format,
    bits: [u32; 4],
    enabled: bool,
) -> Result<Option<Image>, WorkError> {
    if !enabled {
        return Ok(None);
    }
    let [load_tiling, load_compress, store_tiling, store_compress] = bits.map(|b| pass.zls(b));
    if load_tiling != store_tiling || load_compress != store_compress {
        return Err(WorkError::Refused(
            "ZLS loads and stores of one surface in different layouts",
        ));
    }
    let tiling = if load_tiling {
        Tiling::Twiddled
    } else {
        Tiling::Gpu
    };
    let meta = if load_compress {
        Some((zls.meta, zls.meta_layer_stride()?))
    } else {
        None
    };
    Image::surface(
        format,
        tiling,
        pass.zls_size(),
        pass.layers,
        pass.samples,
        zls.base,
        zls.layer_stride()?,
        meta,
    )
    .map(Some)
    .map_err(WorkError::Refused)
}

impl Surfaces {
    fn new(pass: &RenderPass) -> Result<Self, WorkError> {
        let depth_format = Format {
            channels: if pass.depth_16() {
                channels::R16
            } else {
                channels::R32
            },
            ty: if pass.depth_16() {
                ty::UNORM
            } else {
                ty::FLOAT
            },
            srgb: false,
            srgb_2_channel: false,
        };
        let stencil_format = Format {
            channels: channels::R8,
            ty: ty::UINT,
            srgb: false,
            srgb_2_channel: false,
        };
        Ok(Surfaces {
            depth: surface(
                pass,
                &pass.depth,
                depth_format,
                [
                    zls::Z_LOAD_TILING,
                    zls::Z_LOAD_COMPRESS,
                    zls::Z_STORE_TILING,
                    zls::Z_STORE_COMPRESS,
                ],
                pass.zls(zls::Z_LOAD) || pass.zls(zls::Z_STORE),
            )?,
            stencil: surface(
                pass,
                &pass.stencil,
                stencil_format,
                [
                    zls::S_LOAD_TILING,
                    zls::S_LOAD_COMPRESS,
                    zls::S_STORE_TILING,
                    zls::S_STORE_COMPRESS,
                ],
                pass.zls(zls::S_LOAD) || pass.zls(zls::S_STORE),
            )?,
        })
    }

    /// Initialize a tile's depth and stencil.
    fn load(
        &self,
        memory: &mut dyn Memory,
        pass: &RenderPass,
        tile: &mut Tile,
    ) -> Result<(), WorkError> {
        let clear_depth = if pass.depth_16() {
            (f64::from(pass.depth_clear & 0xffff) / UNORM16_MAX) as f32
        } else {
            f32::from_bits(pass.depth_clear)
        };
        let clear = Sample {
            depth: clear_depth,
            stencil: pass.stencil_clear(),
        };
        tile.zs.fill(clear);
        let (zw, zh) = pass.zls_size();
        for (image, bit, depth) in [
            (&self.depth, zls::Z_LOAD, true),
            (&self.stencil, zls::S_LOAD, false),
        ] {
            let Some(image) = image.as_ref().filter(|_| pass.zls(bit)) else {
                continue;
            };
            for ly in 0..tile.size[1] {
                for lx in 0..tile.size[0] {
                    let (x, y) = (tile.origin[0] + lx, tile.origin[1] + ly);
                    if x >= zw || y >= zh {
                        continue;
                    }
                    for sample in 0..tile.samples {
                        let texel = image
                            .read(memory, At::new(0, x, y, tile.layer, sample))
                            .map_err(image_error)?;
                        let slot = tile.slot([lx, ly], sample);
                        if depth {
                            tile.zs[slot].depth = texel.value[0] as f32;
                        } else {
                            tile.zs[slot].stencil = texel.value[0] as u8;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Store a tile's depth and stencil.
    fn store(
        &self,
        memory: &mut dyn Memory,
        pass: &RenderPass,
        tile: &Tile,
    ) -> Result<(), WorkError> {
        let (zw, zh) = pass.zls_size();
        for (image, bit, depth) in [
            (&self.depth, zls::Z_STORE, true),
            (&self.stencil, zls::S_STORE, false),
        ] {
            let Some(image) = image.as_ref().filter(|_| pass.zls(bit)) else {
                continue;
            };
            for ly in 0..tile.size[1] {
                for lx in 0..tile.size[0] {
                    let (x, y) = (tile.origin[0] + lx, tile.origin[1] + ly);
                    if x >= zw || y >= zh || x >= pass.width || y >= pass.height {
                        continue;
                    }
                    for sample in 0..tile.samples {
                        let stored = tile.zs[tile.slot([lx, ly], sample)];
                        let value = if depth {
                            f64::from(stored.depth)
                        } else {
                            f64::from(stored.stencil)
                        };
                        image
                            .write(
                                memory,
                                At::new(0, x, y, tile.layer, sample),
                                [value, 0.0, 0.0, 0.0],
                            )
                            .map_err(image_error)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn image_error(error: ImageError) -> WorkError {
    match error {
        ImageError::Fault(fault) => WorkError::from(fault),
        ImageError::Refused(reason) => WorkError::Refused(reason),
    }
}

/// A background or end-of-tile program's state.
fn load_program(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    program: &PassProgram,
    cache: &mut Program,
) -> Result<ShaderState, WorkError> {
    let usc = usc::parse(memory, pass.usc_base, program.offset()?)?;
    let mut state = ShaderState::load(
        memory,
        pass.usc_base,
        &usc,
        extended_samplers(field(u64::from(program.counts), 9, 3) as u32),
    )?;
    let mut tile = empty_tile(pass);
    let mut visibility = Visibility::new();
    let positions = [[0.5; 2]; MAX_SAMPLES];
    let mut env = env(memory, pass, &mut tile, &positions, &mut visibility);
    state.run_preshader(&mut env, cache)?;
    Ok(state)
}

fn empty_tile(pass: &RenderPass) -> Tile {
    let size = [pass.tile.0, pass.tile.1];
    let count = (size[0] * size[1] * pass.samples) as usize;
    Tile {
        origin: [0, 0],
        size,
        index: [0, 0],
        layer: 0,
        samples: pass.samples,
        sample_bytes: pass.sample_bytes as usize,
        colour: vec![0; count * pass.sample_bytes as usize],
        zs: vec![
            Sample {
                depth: 0.0,
                stencil: 0
            };
            count
        ],
    }
}

fn env<'a>(
    memory: &'a mut dyn Memory,
    pass: &'a RenderPass,
    tile: &'a mut Tile,
    positions: &'a [[f64; 2]; MAX_SAMPLES],
    visibility: &'a mut Visibility,
) -> FragmentEnv<'a> {
    let all = (1u32 << tile.samples) - 1;
    FragmentEnv {
        memory,
        pass,
        tile,
        lanes: [Lane::default(); SIMD_WIDTH],
        positions,
        all,
        coefficients: Vec::new(),
        tests: None,
        block_stores: false,
        visibility,
    }
}

/// Run the fragment half of `pass` over `binned`.
pub fn run(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    binned: &Binned,
    stats: &mut Stats,
) -> Result<(), WorkError> {
    let positions = coverage::sample_positions(pass.multisample_control, pass.samples);
    let surfaces = Surfaces::new(pass)?;
    let mut program = Program::default();
    let mut pipelines = Vec::with_capacity(binned.fragment_keys.len());
    for words in &binned.fragment_keys {
        pipelines.push(pipeline::load(memory, pass, words, &mut program)?);
    }
    let primitives = primitive::prepare(memory, pass, binned)?;
    let background = load_program(memory, pass, &pass.background, &mut program)?;
    let end_of_tile = load_program(memory, pass, &pass.end_of_tile, &mut program)?;
    let mut visibility = Visibility::new();
    let tiles = [
        pass.width.div_ceil(pass.tile.0),
        pass.height.div_ceil(pass.tile.1),
    ];
    let mut tile = empty_tile(pass);
    for layer in 0..pass.layers {
        for ty in 0..tiles[1] {
            for tx in 0..tiles[0] {
                tile.index = [tx, ty];
                tile.origin = [tx * pass.tile.0, ty * pass.tile.1];
                tile.layer = layer;
                tile.colour.fill(0);
                surfaces.load(memory, pass, &mut tile)?;
                let context = Context {
                    pass,
                    positions: &positions,
                };
                context.background(
                    memory,
                    &mut tile,
                    &background,
                    &mut program,
                    &mut visibility,
                    stats,
                )?;
                let rect = Rect {
                    min: tile.origin,
                    max: [tile.origin[0] + tile.size[0], tile.origin[1] + tile.size[1]],
                };
                for primitive in primitives.iter().filter(|p| p.layer == layer) {
                    let bounds = primitive.bounds.intersect(rect);
                    if bounds.is_empty() {
                        continue;
                    }
                    context.primitive(
                        memory,
                        &mut tile,
                        binned,
                        &pipelines,
                        primitive,
                        bounds,
                        &mut program,
                        &mut visibility,
                        stats,
                    )?;
                }
                context.end_of_tile(
                    memory,
                    &mut tile,
                    &end_of_tile,
                    &mut program,
                    &mut visibility,
                )?;
                surfaces.store(memory, pass, &tile)?;
                stats.tiles += 1;
            }
        }
    }
    for (index, (mode, value)) in visibility {
        let address = pass.visibility + 8 * u64::from(index);
        let result = match mode {
            visibility::COUNTING => {
                let mut old = [0u8; 8];
                memory.read(address, &mut old)?;
                u64::from_le_bytes(old) + value
            }
            _ => u64::from(value > 0),
        };
        memory.write(address, &result.to_le_bytes())?;
    }
    Ok(())
}

struct Context<'a> {
    pass: &'a RenderPass,
    positions: &'a [[f64; 2]; MAX_SAMPLES],
}

/// Lanes of an 8x4 block: lane -> tile-local pixel.
fn block_pixel(origin: [u32; 2], lane: usize) -> [u32; 2] {
    let quad = (lane / 4) as u32;
    let (qx, qy) = (quad % 4, quad / 4);
    [
        origin[0] + 2 * qx + (lane as u32 & 1),
        origin[1] + 2 * qy + (lane as u32 >> 1 & 1),
    ]
}

/// Run one SIMD group to its end.
fn finish(
    group: &mut crate::platform::apple::agx::isa::machine::SimdGroup,
    program: &mut Program,
    env: &mut dyn Env,
    what: &'static str,
) -> Result<(), WorkError> {
    let mut budget = GROUP_BUDGET;
    if group.run(program, env, &mut budget)? == Exit::Barrier {
        return Err(WorkError::Refused(what));
    }
    Ok(())
}

impl Context<'_> {
    fn specials(&self, tile: &Tile, lanes: &[Lane; SIMD_WIDTH], backfacing: bool) -> Specials {
        let samples_log2 = tile.samples.trailing_zeros();
        Specials {
            threadgroup_in_grid: Some([tile.index[0], tile.index[1], tile.layer]),
            threadgroup_size: Some(tile.size),
            samples_log2: Some(samples_log2),
            core_index: Some(0),
            vm_slot: Some(self.pass.vm_slot),
            thread_in_grid: Some(lanes.map(|l| [l.pixel[0], l.pixel[1], tile.layer])),
            thread_in_threadgroup: Some(lanes.map(|l| {
                let local = [
                    l.pixel[0].wrapping_sub(tile.origin[0]),
                    l.pixel[1].wrapping_sub(tile.origin[1]),
                ];
                [local[0], local[1], 0]
            })),
            internal_coverage_mask: Some(lanes.map(|l| l.alive)),
            input_sample_mask: Some(lanes.map(|l| l.covered)),
            backfacing: Some([u32::from(backfacing); SIMD_WIDTH]),
            ..Specials::default()
        }
    }

    fn background(
        &self,
        memory: &mut dyn Memory,
        tile: &mut Tile,
        state: &ShaderState,
        program: &mut Program,
        visibility: &mut Visibility,
        stats: &mut Stats,
    ) -> Result<(), WorkError> {
        let all = (1u32 << tile.samples) - 1;
        for by in (0..tile.size[1]).step_by(GROUP_HEIGHT as usize) {
            for bx in (0..tile.size[0]).step_by(GROUP_WIDTH as usize) {
                let origin = [tile.origin[0] + bx, tile.origin[1] + by];
                let mut lanes = [Lane::default(); SIMD_WIDTH];
                for (lane, state) in lanes.iter_mut().enumerate() {
                    *state = Lane {
                        pixel: block_pixel(origin, lane),
                        covered: all,
                        alive: all,
                        tested: all,
                    };
                }
                let mut group = state.group(SIMD_WIDTH, state.code);
                group.specials = self.specials(tile, &lanes, false);
                let mut env = env(memory, self.pass, tile, self.positions, visibility);
                env.lanes = lanes;
                finish(
                    &mut group,
                    program,
                    &mut env,
                    "a threadgroup barrier in a background program",
                )?;
                stats.fragment_groups += 1;
            }
        }
        Ok(())
    }

    fn end_of_tile(
        &self,
        memory: &mut dyn Memory,
        tile: &mut Tile,
        state: &ShaderState,
        program: &mut Program,
        visibility: &mut Visibility,
    ) -> Result<(), WorkError> {
        let all = (1u32 << tile.samples) - 1;
        let mut lanes = [Lane::default(); SIMD_WIDTH];
        lanes[0] = Lane {
            pixel: tile.origin,
            covered: all,
            alive: all,
            tested: all,
        };
        let mut group = state.group(1, state.code);
        group.specials = self.specials(tile, &lanes, false);
        let mut env = env(memory, self.pass, tile, self.positions, visibility);
        env.lanes = lanes;
        env.block_stores = true;
        finish(
            &mut group,
            program,
            &mut env,
            "a threadgroup barrier in an end-of-tile program",
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn primitive(
        &self,
        memory: &mut dyn Memory,
        tile: &mut Tile,
        binned: &Binned,
        pipelines: &[FragmentPipeline],
        primitive: &Primitive,
        bounds: Rect,
        program: &mut Program,
        visibility: &mut Visibility,
        stats: &mut Stats,
    ) -> Result<(), WorkError> {
        let state = &binned.states[primitive.state];
        let control = state.control;
        let samples = tile.samples as usize;
        // Coverage of the tile's pixels.
        let mut covered = vec![0u32; (tile.size[0] * tile.size[1]) as usize];
        let mut cover = |x: u32, y: u32, mask: u32| {
            let local = [x - tile.origin[0], y - tile.origin[1]];
            covered[(local[1] * tile.size[0] + local[0]) as usize] |= mask;
        };
        let positions = &self.positions[..samples];
        match &primitive.shape {
            Shape::Triangle(v) => coverage::triangle(
                v.clone().map(|v| [v.window[0], v.window[1]]),
                bounds,
                positions,
                &mut cover,
            ),
            Shape::Line(v, width) => {
                let ends = [0, 1].map(|i| [v[i].window[0], v[i].window[1]]);
                for half in coverage::line_quad(ends[0], ends[1], *width)
                    .into_iter()
                    .flatten()
                {
                    coverage::triangle(half, bounds, positions, &mut cover);
                }
            }
            Shape::Point(v, size) => {
                for half in coverage::point_quad([v.window[0], v.window[1]], *size) {
                    coverage::triangle(half, bounds, positions, &mut cover);
                }
            }
        }
        if covered.iter().all(|&m| m == 0) {
            return Ok(());
        }
        let pipeline = match state.fragment {
            Some(index) => Some(&pipelines[index]),
            None if control.tag_write_disable => None,
            None => return Err(WorkError::Refused("a draw without a fragment shader")),
        };
        let tests = self.tests(memory, state, &control, primitive)?;
        for by in (0..tile.size[1]).step_by(GROUP_HEIGHT as usize) {
            for bx in (0..tile.size[0]).step_by(GROUP_WIDTH as usize) {
                let origin = [tile.origin[0] + bx, tile.origin[1] + by];
                let mut lanes = [Lane::default(); SIMD_WIDTH];
                let mut present = 0u32;
                for (lane, slot) in lanes.iter_mut().enumerate() {
                    let pixel = block_pixel(origin, lane);
                    let local = [pixel[0] - tile.origin[0], pixel[1] - tile.origin[1]];
                    let mask = if local[0] < tile.size[0] && local[1] < tile.size[1] {
                        covered[(local[1] * tile.size[0] + local[0]) as usize]
                    } else {
                        0
                    };
                    *slot = Lane {
                        pixel,
                        covered: mask,
                        alive: mask,
                        tested: 0,
                    };
                    if mask != 0 {
                        present |= 0xf << (lane & !3);
                    }
                }
                if present == 0 {
                    continue;
                }
                let mut env = env(memory, self.pass, tile, self.positions, visibility);
                env.lanes = lanes;
                env.tests = Some(Tests {
                    ..tests.clone_tests()
                });
                let early =
                    pipeline.is_none_or(|p| p.properties.early_z) || control.tag_write_disable;
                if early {
                    for lane in 0..SIMD_WIDTH {
                        let all = env.lanes[lane].covered;
                        env.test_samples(lane, all, None, None);
                    }
                }
                let Some(pipeline) = pipeline.filter(|_| !control.tag_write_disable) else {
                    continue;
                };
                let live = (0..SIMD_WIDTH)
                    .filter(|&l| env.lanes[l].alive != 0)
                    .fold(0u32, |m, l| m | 1 << l);
                if live == 0 {
                    continue;
                }
                env.coefficients = coefficients(pipeline, primitive, state, origin)?;
                let mut group = pipeline.shader.group(SIMD_WIDTH, pipeline.shader.code);
                group.present = present;
                group.helpers = present & !live;
                group.specials = self.specials(env.tile, &env.lanes, !primitive.front);
                finish(
                    &mut group,
                    program,
                    &mut env,
                    "a threadgroup barrier in a fragment shader",
                )?;
                // Samples the shader never tested are tested as it ends.
                for lane in 0..SIMD_WIDTH {
                    let all = env.lanes[lane].covered;
                    env.test_samples(lane, all, None, None);
                }
                stats.fragment_groups += 1;
            }
        }
        Ok(())
    }

    /// The depth/stencil state of a primitive.
    fn tests(
        &self,
        _memory: &mut dyn Memory,
        state: &super::geometry::DrawState,
        control: &FragmentControl,
        primitive: &Primitive,
    ) -> Result<Tests, WorkError> {
        let ppp = &state.ppp;
        let (face, stencil) = if primitive.front || !control.two_sided_stencil {
            (
                if primitive.front { ppp.front } else { ppp.back },
                ppp.front_stencil,
            )
        } else {
            (ppp.back, ppp.back_stencil)
        };
        let visibility = match control.visibility_mode {
            visibility::NONE => None,
            mode @ (visibility::COUNTING | visibility::BOOLEAN) => {
                Some((mode, ppp.occlusion_index.unwrap_or(0)))
            }
            _ => {
                return Err(WorkError::Refused(
                    "a visibility mode the description lacks",
                ));
            }
        };
        if control.sample_mask_after_depth_stencil {
            return Err(WorkError::Refused(
                "sample mask after depth/stencil (Mesa never sets it; ordering unrecorded)",
            ));
        }
        Ok(Tests {
            face: FaceState {
                face,
                stencil,
                stencil_test: control.stencil_test,
            },
            depth: plane(primitive, |v| v.window[2]),
            clamp: primitive.depth_clamp,
            depth_16: self.pass.depth_16(),
            visibility,
        })
    }
}

impl Tests {
    fn clone_tests(&self) -> Tests {
        Tests {
            face: self.face,
            depth: self.depth,
            clamp: self.clamp,
            depth_16: self.depth_16,
            visibility: self.visibility,
        }
    }
}

/// The plane of a per-vertex value over a primitive, in window space.
fn plane(primitive: &Primitive, value: impl Fn(&Vertex) -> f64) -> Plane {
    let xy = |v: &Vertex| [v.window[0], v.window[1]];
    match &primitive.shape {
        Shape::Triangle(v) => Plane::triangle(
            [xy(&v[0]), xy(&v[1]), xy(&v[2])],
            [value(&v[0]), value(&v[1]), value(&v[2])],
        ),
        Shape::Line(v, _) => Plane::segment([xy(&v[0]), xy(&v[1])], [value(&v[0]), value(&v[1])]),
        Shape::Point(v, _) => Plane::constant(value(v)),
    }
}

/// A raw 32-bit value in a coefficient register's `C`.
fn raw(bits: u32) -> [f32; 3] {
    [0.0, 0.0, f32::from_bits(bits)]
}

/// The coefficient registers of a fragment group whose pixels start at
/// `origin` (all in one 32x32 region).
fn coefficients(
    pipeline: &FragmentPipeline,
    primitive: &Primitive,
    state: &super::geometry::DrawState,
    origin: [u32; 2],
) -> Result<Vec<[f32; 3]>, WorkError> {
    let mut registers = vec![[0.0f32; 3]; pipeline.registers as usize];
    let fragz = state.ppp.output_select & output::FRAG_COORD_Z != 0;
    let user_base = 1 + u32::from(fragz);
    let register = |p: Plane| p.register(origin[0], origin[1]);
    let words = state.uvs.classes.len();
    for binding in &pipeline.bindings {
        for k in 0..binding.components {
            let cf = (binding.base_register + k) as usize;
            let value = match binding.source {
                source::VARYING => {
                    let slot = binding.base_slot + k;
                    if slot >= pipeline.slots {
                        return Err(WorkError::Refused(
                            "a CF binding past the shader's 32-bit slots",
                        ));
                    }
                    if slot == 0 {
                        register(plane(primitive, |v| v.rhw))
                    } else if slot == 1 && fragz {
                        register(plane(primitive, |v| v.window[2]))
                    } else {
                        let index = POSITION_WORDS + (slot - user_base) as usize;
                        if slot < user_base || index >= words {
                            return Err(WorkError::Refused("a CF binding past the vertex outputs"));
                        }
                        let f = |v: &Vertex| f64::from(f32::from_bits(v.words[index]));
                        match binding.shade_model {
                            shade::LINEAR => register(plane(primitive, f)),
                            shade::PERSPECTIVE => register(plane(primitive, |v| f(v) * v.rhw)),
                            model => {
                                let vertex = match model {
                                    shade::FLAT_VERTEX_0 => 0,
                                    shade::FLAT_VERTEX_1 => 1,
                                    _ => 2,
                                }
                                .min(primitive.flat.len() - 1);
                                raw(primitive.flat[vertex][index])
                            }
                        }
                    }
                }
                source::FRAG_COORD_Z => register(plane(primitive, |v| v.window[2])),
                source::POINT_COORD => match &primitive.shape {
                    Shape::Point(v, size) => {
                        let half = size / 2.0;
                        let along = |centre: f64| Plane {
                            a: 0.0,
                            b: 0.0,
                            c: -(centre - half) / size,
                        };
                        let mut p = along(if k == 0 { v.window[0] } else { v.window[1] });
                        if k == 0 {
                            p.a = 1.0 / size;
                        } else {
                            p.b = 1.0 / size;
                        }
                        let face = if primitive.front {
                            state.ppp.front
                        } else {
                            state.ppp.back
                        };
                        if k == 1 && face.object_type == object::POINT_SPRITE_UV10 {
                            p = Plane {
                                a: -p.a,
                                b: -p.b,
                                c: 1.0 - p.c,
                            };
                        }
                        register(p)
                    }
                    _ => [0.0; 3],
                },
                source::PRIMITIVE_ID => raw(primitive.id),
                _ => unreachable!("bindings are checked when loaded"),
            };
            *registers.get_mut(cf).ok_or(WorkError::Refused(
                "a CF binding past the coefficient registers",
            ))? = value;
        }
    }
    Ok(registers)
}
