//! Texture sampling (`smpf`, `smpi`) and image writes (`imgw`, `imgwblk`).
//!
//! Operands (Public: `AGX2.xml`; Mesa `agx_compile.c` `agx_emit_tex`,
//! `agx_emit_image_store`, `agx_emit_block_image_store`, `agx_pack.c` and
//! `agx_nir_lower_texture.c`):
//! - The texture is a state register, a state register indexed by a 16-bit
//!   register, or bindless: a 24-byte descriptor at a 64-bit uniform heap
//!   base plus a 32-bit byte offset. The sampler is a state register or a
//!   16-bit index into the job's sampler heap (8-byte samplers). The
//!   encoding's "unknown" immediate texture case refuses.
//! - Coordinates are one value per dimension (1D 1, 2D 2, 3D and cube 3),
//!   floats for `smpf` and signed integers for `smpi`/`imgw`, each 16 or 32
//!   bits; `smp` follows them with a 32-bit word for arrays and
//!   multisampling (layer in the low half, or sample low and layer high for
//!   multisampled arrays; absent for `query_lod`), `imgw` with the layer as
//!   one more coordinate. The layer must already be clamped (Mesa clamps
//!   it: "AGX requires the index to be a clamped integer"); one past the
//!   image refuses.
//! - LOD sources by `lod_type`: none (implicit), a bias, an explicit LOD
//!   (an integer level for `smpi`), gradients interleaved per dimension
//!   (`dx.x, dy.x, dx.y, dy.y, ...` as 32-bit floats) with an optional
//!   32-bit minimum slot, or a bias and minimum packed as two halves.
//!   Bias, LOD and minimum are 16-bit; the even modes read registers, the
//!   odd ones uniforms.
//! - The compare/offset operand holds a 32-bit reference, a 16-bit word of
//!   signed 4-bit offsets per dimension, or both (reference first).
//! - Results fill consecutive destination components in mask order;
//!   `query_lod` returns (LOD used, LOD computed). Gathers must not mask
//!   (Mesa: masking "doesn't seem to work properly for gathers").
//! - Implicit LOD differentiates the coordinates across each 2x2 quad of
//!   lanes like `dfdx`/`dfdy` (fine differences); every quad thread must be
//!   present. Cube gradients refuse (Mesa lowers them away).
//! - `imgw` writes a PBE descriptor's image at integer coordinates;
//!   out-of-bounds writes are dropped (Mesa maps robust out-of-bounds stores
//!   to large coordinates for the hardware to discard). A nonzero LOD,
//!   rotation, round-toward-zero and multisampled or cube dimensions (Mesa
//!   lowers both) refuse.
//! - `imgwblk` stores a render target of the current tile through the
//!   stage's [`Env::block_store`], once per group with the lowest active
//!   thread's operands.
//! - `sparse` (residency) and `kill` (helper kill) refuse.

use super::decode::{Instr, Operand, Value};
use super::float::{f64_to_half, half_to_f32};
use super::generated::{Mod, Op};
use super::machine::{
    BlockStore, Env, Error, SIMD_WIDTH, SimdGroup, Step, TEXTURE_STATE_BYTES, UNIFORM_HALVES, lanes,
};
use crate::platform::apple::agx::format::descriptor::{Dimension, Pbe, Sampler, Texture};
use crate::platform::apple::agx::format::image::{At, Image, ImageError};
use crate::platform::apple::agx::format::isa::IsaFormat;
use crate::platform::apple::agx::format::sample::{Lod, Request, query_lod, sample};
use crate::platform::apple::agx::format::texel::{Kind, ty};
use crate::platform::apple::agx::isa::machine::Memory;

/// `smp` source order (`AGX2.xml` group `smp`).
mod smp {
    pub const HEAP: usize = 0;
    pub const TEXTURE: usize = 1;
    pub const SAMPLER: usize = 2;
    pub const COORD: usize = 3;
    pub const LOD: usize = 4;
    pub const COMPARE_OFFSET: usize = 5;
}

/// `imgw`/`imgwblk` source order.
mod imgw {
    pub const DATA: usize = 0;
    pub const HEAP: usize = 1;
    pub const TEXTURE: usize = 2;
    pub const COORD: usize = 3;
    pub const LOD: usize = 4;
}

/// `lod_type` values (`AGX2.xml` enum `lod_type`).
mod lod_type {
    pub const AUTO: u32 = 0;
    pub const BIAS_UNIFORM: u32 = 1;
    pub const EXPLICIT_UNIFORM: u32 = 2;
    pub const GRADIENTS: u32 = 4;
    pub const BIAS: u32 = 5;
    pub const EXPLICIT: u32 = 6;
    pub const BIAS_MIN_UNIFORM: u32 = 9;
    pub const GRADIENTS_MIN: u32 = 12;
    pub const BIAS_MIN: u32 = 13;
}

/// Bits of one offset in the packed offset word.
const OFFSET_BITS: u32 = 4;
/// Bytes of a sampler-heap entry (cmdbuf.xml `Sampler`).
const HEAP_SAMPLER_BYTES: usize = 8;

impl From<ImageError> for Error {
    fn from(error: ImageError) -> Self {
        match error {
            ImageError::Fault(fault) => Error::Fault(fault),
            ImageError::Refused(reason) => Error::Refused(reason),
        }
    }
}

fn dimension(instr: &Instr) -> Result<Dimension, Error> {
    Dimension::from_field(u64::from(instr.modifier(Mod::Dim).unwrap_or(0)))
        .ok_or(Error::Refused("a texture dimension the description lacks"))
}

/// Coordinate values a dimension takes (before any layer/sample word).
fn coordinate_count(dimension: Dimension) -> usize {
    match dimension {
        Dimension::D1 | Dimension::D1Array => 1,
        Dimension::D2
        | Dimension::D2Array
        | Dimension::D2Multisampled
        | Dimension::D2ArrayMultisampled => 2,
        Dimension::D3 | Dimension::Cube | Dimension::CubeArray => 3,
    }
}

/// The base shape a dimension samples, ignoring arrays.
fn base(dimension: Dimension) -> Dimension {
    match dimension {
        Dimension::D1Array => Dimension::D1,
        Dimension::D2Array => Dimension::D2,
        Dimension::D2ArrayMultisampled => Dimension::D2Multisampled,
        Dimension::CubeArray => Dimension::Cube,
        other => other,
    }
}

impl SimdGroup {
    pub(super) fn texture(&mut self, instr: &Instr, env: &mut dyn Env) -> Result<Step, Error> {
        if instr.flag(Mod::Sparse) {
            return Err(Error::Refused("sparse residency reporting is not modeled"));
        }
        match instr.op() {
            Op::Smpf => self.sample(instr, env, false),
            Op::Smpi => self.sample(instr, env, true),
            Op::Imgw => self.image_write(instr, env),
            Op::Imgwblk => self.block_write(instr, env),
            other => unreachable!("{other:?} is not a texture instruction"),
        }
    }

    /// Half `k` past an operand's base in its file.
    fn raw_half(&self, lane: usize, value: Value, k: usize) -> Result<u16, Error> {
        match value {
            Value::Reg(base) => {
                let half = usize::from(base) + k;
                if half >= self.register_limit {
                    return Err(Error::Refused("a register past the shader's allocation"));
                }
                Ok(self.half(lane, half))
            }
            Value::Uniform(base) => {
                let half = usize::from(base) + k;
                if half >= UNIFORM_HALVES {
                    return Err(Error::Refused("a uniform past the uniform file"));
                }
                Ok(self.uniforms[half])
            }
            _ => Err(Error::Refused(
                "a texture operand that is neither register nor uniform",
            )),
        }
    }

    /// The 32-bit value at halves `k`, `k + 1` past an operand's base.
    fn raw32(&self, lane: usize, value: Value, k: usize) -> Result<u32, Error> {
        if let Value::Reg(base) | Value::Uniform(base) = value
            && !(usize::from(base) + k).is_multiple_of(2)
        {
            return Err(Error::Refused("a 32-bit texture operand on an odd half"));
        }
        Ok(u32::from(self.raw_half(lane, value, k)?)
            | u32::from(self.raw_half(lane, value, k + 1)?) << 16)
    }

    /// The 24-byte texture or PBE descriptor a lane names.
    fn descriptor(
        &self,
        lane: usize,
        instr: &Instr,
        heap: usize,
        texture: usize,
        env: &mut dyn Env,
    ) -> Result<[u8; TEXTURE_STATE_BYTES], Error> {
        let source = instr.source(texture);
        let register = |index: usize| {
            self.textures
                .get(index)
                .copied()
                .flatten()
                .ok_or(Error::Refused(
                    "a texture state register no state store loaded",
                ))
        };
        match source.value {
            Value::Ts(index) => register(usize::from(index)),
            Value::Reg(_) if source.size == 16 => {
                register(usize::from(self.raw_half(lane, source.value, 0)?))
            }
            Value::Reg(_) => {
                let Value::Uniform(_) = instr.source(heap).value else {
                    return Err(Error::Refused(
                        "a bindless texture offset without a heap base",
                    ));
                };
                let base = self.bits(
                    lane,
                    &Operand {
                        size: 64,
                        ..instr.source(heap)
                    },
                    0,
                )?;
                let offset = self.raw32(lane, source.value, 0)?;
                let mut state = [0u8; TEXTURE_STATE_BYTES];
                env.read(base.wrapping_add(u64::from(offset)), &mut state)?;
                Ok(state)
            }
            _ => Err(Error::Refused(
                "the texture source's immediate case (unknown)",
            )),
        }
    }

    fn sampler(&self, lane: usize, instr: &Instr, env: &mut dyn Env) -> Result<Sampler, Error> {
        let source = instr.source(smp::SAMPLER);
        let (state, extended) = match source.value {
            Value::Ss(index) => (
                self.samplers
                    .get(usize::from(index))
                    .copied()
                    .flatten()
                    .ok_or(Error::Refused(
                        "a sampler state register no state store loaded",
                    ))?,
                self.extended_samplers,
            ),
            Value::Reg(_) => {
                let index = u32::from(self.raw_half(lane, source.value, 0)?);
                let entry = env.sampler_heap(index).map_err(Error::Refused)?;
                let mut state = [0u8; 24];
                state[..HEAP_SAMPLER_BYTES].copy_from_slice(&entry);
                (state, false)
            }
            _ => return Err(Error::Refused("a sampler operand the encoding lacks")),
        };
        Sampler::decode(&state, extended).map_err(Error::Refused)
    }

    /// One coordinate component as a float (`smpf`) or integer.
    fn coordinate(
        &self,
        lane: usize,
        operand: &Operand,
        k: usize,
        integer: bool,
    ) -> Result<f64, Error> {
        Ok(match (operand.size, integer) {
            (16, false) => f64::from(half_to_f32(self.raw_half(lane, operand.value, k)?)),
            (16, true) => f64::from(self.raw_half(lane, operand.value, k)? as i16),
            (_, false) => f64::from(f32::from_bits(self.raw32(lane, operand.value, 2 * k)?)),
            (_, true) => f64::from(self.raw32(lane, operand.value, 2 * k)? as i32),
        })
    }

    /// The trailing layer/sample word of an `smp` coordinate.
    fn layer_word(&self, lane: usize, operand: &Operand, count: usize) -> Result<u32, Error> {
        if operand.size == 16 {
            return Err(Error::Refused(
                "16-bit coordinates with a layer or sample word (packing unrecorded)",
            ));
        }
        self.raw32(lane, operand.value, 2 * count)
    }

    fn sample(&mut self, instr: &Instr, env: &mut dyn Env, integer: bool) -> Result<Step, Error> {
        if instr.flag(Mod::Kill) {
            return Err(Error::Refused(
                "the helper-kill bit of a sample (unrecorded)",
            ));
        }
        let dim = dimension(instr)?;
        let query = instr.flag(Mod::QueryLod);
        let gather = match instr.modifier(Mod::Gather).unwrap_or(0) {
            0 => None,
            value => Some((value >> 1) as usize),
        };
        let dest = instr.dest();
        let mask = u32::from(dest.mask.unwrap_or(0));
        if gather.is_some() && mask != 0xf {
            return Err(Error::Refused(
                "a masked gather (the hardware masks gathers unreliably)",
            ));
        }
        let lod_type = instr.modifier(Mod::LodType).unwrap_or(lod_type::AUTO);
        let count = coordinate_count(dim);
        let coord = instr.source(smp::COORD);
        let present = self.present;
        let active = self.active();
        // Every present thread's coordinates (implicit LOD reads quad
        // neighbours that may be inactive).
        let mut coords = [None::<[f64; 3]>; SIMD_WIDTH];
        for lane in lanes(present) {
            let mut c = [0.0; 3];
            for (k, slot) in c.iter_mut().enumerate().take(count) {
                *slot = self.coordinate(lane, &coord, k, integer)?;
            }
            coords[lane] = Some(c);
        }
        let mut cache: Option<([u8; TEXTURE_STATE_BYTES], Image, Texture)> = None;
        for lane in lanes(active) {
            let state = self.descriptor(lane, instr, smp::HEAP, smp::TEXTURE, env)?;
            if cache.as_ref().is_none_or(|(cached, ..)| *cached != state) {
                let texture = Texture::decode(&state).map_err(Error::Refused)?;
                if base(texture.dimension) != base(dim) {
                    return Err(Error::Refused(
                        "a sample whose dimension differs from the descriptor's",
                    ));
                }
                let image = Image::from_texture(&texture).map_err(Error::Refused)?;
                cache = Some((state, image, texture));
            }
            let (_, image, texture) = cache.as_ref().expect("the descriptor was just cached");
            let sampler = self.sampler(lane, instr, env)?;
            let mut request = Request {
                coords: coords[lane].expect("active threads are present"),
                texel: None,
                layer: 0,
                sample: 0,
                lod: Lod::Explicit(0.0),
                offset: [0; 3],
                compare: None,
                gather,
            };
            if (dim.arrayed() || dim.multisampled()) && !query {
                let word = self.layer_word(lane, &coord, count)?;
                match (dim.arrayed(), dim.multisampled()) {
                    (true, true) => (request.sample, request.layer) = (word & 0xffff, word >> 16),
                    (false, true) => request.sample = word & 0xffff,
                    _ => request.layer = word & 0xffff,
                }
            }
            if integer {
                request.texel = Some(request.coords.map(|c| c as i64));
            }
            request.lod = self.lod(lane, instr, lod_type, dim, integer, &coords)?;
            self.compare_offset(lane, instr, count, &mut request)?;
            let value = if query {
                query_lod(image, &sampler, &request)
            } else {
                sample(
                    &mut *env as &mut dyn Memory,
                    image,
                    texture.swizzle,
                    &sampler,
                    &request,
                )?
                .value
            };
            let kind = if query || request.compare.is_some() {
                Kind::Float
            } else {
                image.format.kind()
            };
            for (k, c) in (0..4).filter(|c| mask >> c & 1 != 0).enumerate() {
                let bits = result_bits(value[c], kind, dest.size);
                self.put(lane, &dest, k, bits)?;
            }
        }
        Ok(Step::Next)
    }

    /// The request's LOD selection.
    fn lod(
        &self,
        lane: usize,
        instr: &Instr,
        lod_type: u32,
        dim: Dimension,
        integer: bool,
        coords: &[Option<[f64; 3]>; SIMD_WIDTH],
    ) -> Result<Lod, Error> {
        let source = instr.source(smp::LOD).value;
        let half = |k| -> Result<f64, Error> {
            Ok(f64::from(half_to_f32(self.raw_half(lane, source, k)?)))
        };
        let dims = coordinate_count(dim);
        let implicit = |bias: f64, min: Option<f64>| -> Result<Lod, Error> {
            if integer {
                return Err(Error::Refused("an implicit LOD on integer coordinates"));
            }
            let quad = lane & !3;
            let at = |l: usize| {
                coords[l].ok_or(Error::Refused("an implicit LOD with a quad thread missing"))
            };
            let row = quad | (lane & 2);
            let column = quad | (lane & 1);
            let (x0, x1, y0, y1) = (at(row)?, at(row | 1)?, at(column)?, at(column | 2)?);
            Ok(Lod::Derivatives {
                dx: [0, 1, 2].map(|c| x1[c] - x0[c]),
                dy: [0, 1, 2].map(|c| y1[c] - y0[c]),
                bias,
                min,
            })
        };
        let gradients = |min: bool| -> Result<Lod, Error> {
            if dim.cube() {
                return Err(Error::Refused(
                    "explicit cube gradients (Mesa lowers them; layout unrecorded)",
                ));
            }
            let mut dx = [0.0; 3];
            let mut dy = [0.0; 3];
            for c in 0..dims {
                dx[c] = f64::from(f32::from_bits(self.raw32(lane, source, 4 * c)?));
                dy[c] = f64::from(f32::from_bits(self.raw32(lane, source, 4 * c + 2)?));
            }
            let min = if min { Some(half(4 * dims)?) } else { None };
            Ok(Lod::Derivatives {
                dx,
                dy,
                bias: 0.0,
                min,
            })
        };
        match lod_type {
            lod_type::AUTO => implicit(0.0, None),
            lod_type::BIAS | lod_type::BIAS_UNIFORM => implicit(half(0)?, None),
            lod_type::BIAS_MIN | lod_type::BIAS_MIN_UNIFORM => implicit(half(0)?, Some(half(1)?)),
            lod_type::EXPLICIT | lod_type::EXPLICIT_UNIFORM if integer => {
                Ok(Lod::Explicit(f64::from(self.raw_half(lane, source, 0)?)))
            }
            lod_type::EXPLICIT | lod_type::EXPLICIT_UNIFORM => Ok(Lod::Explicit(half(0)?)),
            lod_type::GRADIENTS => gradients(false),
            lod_type::GRADIENTS_MIN => gradients(true),
            _ => Err(Error::Refused("a LOD type the description lacks")),
        }
        .map(|lod| match (integer, lod) {
            // Integer coordinates with no LOD source read the first level.
            (true, Lod::Derivatives { .. }) => Lod::Explicit(0.0),
            (_, lod) => lod,
        })
        .or_else(|error| match (integer, lod_type) {
            (true, lod_type::AUTO) => Ok(Lod::Explicit(0.0)),
            _ => Err(error),
        })
    }

    fn compare_offset(
        &self,
        lane: usize,
        instr: &Instr,
        count: usize,
        request: &mut Request,
    ) -> Result<(), Error> {
        let operand = instr.source(smp::COMPARE_OFFSET);
        let (compare, offset) = match (operand.value, operand.size, operand.count) {
            (Value::None, ..) => (None, None),
            (_, 32, 1) => (Some(0), None),
            (_, _, 1) => (None, Some(0)),
            _ => (Some(0), Some(2)),
        };
        if let Some(k) = compare {
            request.compare = Some(f64::from(f32::from_bits(self.raw32(
                lane,
                operand.value,
                k,
            )?)));
        }
        if let Some(k) = offset {
            let packed = u32::from(self.raw_half(lane, operand.value, k)?);
            for c in 0..count.min(3) {
                let nibble = (packed >> (OFFSET_BITS * c as u32)) & 0xf;
                request.offset[c] = i64::from(((nibble << 28) as i32) >> 28);
            }
        }
        Ok(())
    }

    fn image_write(&mut self, instr: &Instr, env: &mut dyn Env) -> Result<Step, Error> {
        if instr.flag(Mod::Rtz) {
            return Err(Error::Refused(
                "round-toward-zero image writes are not modeled",
            ));
        }
        let dim = dimension(instr)?;
        if dim.cube() || dim.multisampled() {
            return Err(Error::Refused(
                "cube or multisampled image writes (Mesa lowers both)",
            ));
        }
        let count = coordinate_count(dim) + usize::from(dim.arrayed());
        let coord = instr.source(imgw::COORD);
        let data = instr.source(imgw::DATA);
        let lod_operand = instr.source(imgw::LOD);
        let mut cache: Option<([u8; TEXTURE_STATE_BYTES], Image, Pbe)> = None;
        for lane in lanes(self.effective()) {
            let lod = match lod_operand.value {
                Value::Imm(value) => value,
                other => i64::from(self.raw_half(lane, other, 0)?),
            };
            if lod != 0 {
                return Err(Error::Refused(
                    "a nonzero image-write LOD (whether it adds to the descriptor level is unrecorded)",
                ));
            }
            let state = self.descriptor(lane, instr, imgw::HEAP, imgw::TEXTURE, env)?;
            if cache.as_ref().is_none_or(|(cached, ..)| *cached != state) {
                let pbe = Pbe::decode(&state).map_err(Error::Refused)?;
                if pbe.rotate_90 {
                    return Err(Error::Refused(
                        "rotated PBE writes (the rotation's direction is unrecorded)",
                    ));
                }
                let image = Image::from_pbe(&pbe).map_err(Error::Refused)?;
                cache = Some((state, image, pbe));
            }
            let (_, image, pbe) = cache.as_ref().expect("the descriptor was just cached");
            let mut c = [0i64; 4];
            for (k, slot) in c.iter_mut().enumerate().take(count) {
                *slot = self.coordinate(lane, &coord, k, true)? as i64;
            }
            let (x, mut y, layer) = match dim {
                Dimension::D1 => (c[0], 0, 0),
                Dimension::D1Array => (c[0], 0, c[1]),
                Dimension::D2 => (c[0], c[1], 0),
                _ => (c[0], c[1], c[2]),
            };
            let (w, h, layers) = image.level_size(pbe.level);
            if !(0..i64::from(w)).contains(&x)
                || !(0..i64::from(h)).contains(&y)
                || !(0..i64::from(layers)).contains(&layer)
            {
                continue;
            }
            if pbe.flip_vertical {
                y = i64::from(h) - 1 - y;
            }
            let values = self.pbe_values(lane, &data, image)?;
            let memory = pbe.swizzle.map(|from| values[from]);
            image.write(
                &mut *env as &mut dyn Memory,
                At::new(pbe.level, x as u32, y as u32, layer as u32, 0),
                memory,
            )?;
        }
        Ok(Step::Next)
    }

    /// The four data components of a PBE write, as the format's type reads
    /// them.
    fn pbe_values(&self, lane: usize, data: &Operand, image: &Image) -> Result<[f64; 4], Error> {
        let mut values = [0.0; 4];
        for (k, value) in values.iter_mut().enumerate() {
            let bits = if data.size == 16 {
                u32::from(self.raw_half(lane, data.value, k)?)
            } else {
                self.raw32(lane, data.value, 2 * k)?
            };
            *value = match (image.format.ty, data.size) {
                (ty::UINT, _) => f64::from(bits),
                (ty::SINT, 16) => f64::from(bits as u16 as i16),
                (ty::SINT, _) => f64::from(bits as i32),
                (_, 16) => f64::from(half_to_f32(bits as u16)),
                _ => f64::from(f32::from_bits(bits)),
            };
        }
        Ok(values)
    }

    fn block_write(&mut self, instr: &Instr, env: &mut dyn Env) -> Result<Step, Error> {
        if instr.flag(Mod::ExplicitCoords) {
            return Err(Error::Refused(
                "explicit-coordinate block stores (compute imageblocks) are not modeled",
            ));
        }
        let dim = dimension(instr)?;
        let format = IsaFormat::from_field(instr.modifier(Mod::Format).unwrap_or(0))
            .ok_or(Error::Refused("a block-store format the description lacks"))?;
        let lane = self.first_lane(self.active());
        match instr.source(imgw::LOD).value {
            Value::Imm(0) | Value::None => {}
            _ => {
                return Err(Error::Refused(
                    "a block store with a LOD operand (unused by Mesa; meaning unrecorded)",
                ));
            }
        }
        let offset = self.raw32(lane, instr.source(imgw::DATA).value, 0)?;
        let layer = if dim.arrayed() {
            let word = self.raw32(lane, instr.source(imgw::COORD).value, 0)?;
            if dim.multisampled() {
                word >> 16
            } else {
                word & 0xffff
            }
        } else {
            0
        };
        let pbe = self.descriptor(lane, instr, imgw::HEAP, imgw::TEXTURE, env)?;
        env.block_store(&BlockStore {
            offset,
            format,
            pbe,
            layer,
        })?;
        Ok(Step::Next)
    }
}

/// A sampled component as destination bits.
fn result_bits(value: f64, kind: Kind, size: u8) -> u64 {
    let bits = match kind {
        Kind::Float if size == 16 => u32::from(f64_to_half(value)),
        Kind::Float => (value as f32).to_bits(),
        Kind::Uint => value as i64 as u32,
        Kind::Sint => value as i64 as i32 as u32,
    };
    if size == 16 {
        u64::from(bits & 0xffff)
    } else {
        u64::from(bits)
    }
}

/// Lanes of `mask` as a list (tests).
#[cfg(test)]
fn active_list(mask: u32) -> alloc::vec::Vec<usize> {
    lanes(mask).collect()
}

#[cfg(test)]
mod tests {
    use super::super::machine::tests::{CODE, finish, setup};
    use super::*;
    use crate::platform::apple::agx::format::descriptor::Tiling;
    use crate::platform::apple::agx::format::image::tests::rgba8_texture;

    const IMAGE: u64 = CODE + 0x8000;

    /// Pack a texture descriptor the way `Texture::decode` reads it.
    fn texture_state(t: &Texture) -> [u8; 24] {
        let mut d = [0u8; 24];
        let mut put = |start: u32, size: u32, value: u64| {
            for i in 0..size {
                let bit = start + i;
                d[(bit / 8) as usize] &= !(1 << (bit % 8));
                d[(bit / 8) as usize] |= ((value >> i & 1) as u8) << (bit % 8);
            }
        };
        put(0, 4, 2);
        put(4, 2, 0);
        put(6, 7, u64::from(t.channels));
        put(13, 3, u64::from(t.ty));
        for (i, start) in [16, 19, 22, 25].into_iter().enumerate() {
            put(start, 3, i as u64);
        }
        put(28, 14, u64::from(t.width - 1));
        put(42, 14, u64::from(t.height - 1));
        put(66, 36, t.address >> 4);
        put(110, 18, u64::from(t.linear_stride - 16) >> 4);
        d
    }

    /// Nearest, clamp-to-edge sampler bytes (LOD range 0..15).
    fn sampler_state() -> [u8; 24] {
        let mut s = [0u8; 24];
        let max_lod: u64 = 15 * 64;
        let word = max_lod << 10;
        s[..8].copy_from_slice(&word.to_le_bytes());
        s
    }

    #[test]
    fn smpf_samples_a_linear_texture_per_thread() {
        // Each thread samples texel (lane % 4, 0) of a 4x1 RGBA8 image.
        let texture = rgba8_texture(Tiling::Linear, 4, 1, IMAGE);
        let text = "smpf r8_r9_r10_r11, ts0, ss0, r4, 0, 2d, xyzw, auto_lod, a";
        let (mut memory, mut group) = setup(&alloc::format!("{text}\nstop"), 4);
        group.textures[0] = Some(texture_state(&texture));
        group.samplers[0] = Some(sampler_state());
        for x in 0..4u8 {
            memory
                .write(IMAGE + u64::from(x) * 4, &[x * 60, 0, 0, 255])
                .unwrap();
        }
        for lane in active_list(group.present) {
            let s = (lane as f32 + 0.5) / 4.0;
            group.set_reg32(lane, 8, s.to_bits());
            group.set_reg32(lane, 10, 0.5f32.to_bits());
        }
        finish(&mut group, &mut memory).unwrap();
        for lane in 0..4 {
            let red = f32::from_bits(group.reg32(lane, 16));
            assert_eq!(red, (lane as f32 * 60.0) / 255.0, "lane {lane}");
            assert_eq!(f32::from_bits(group.reg32(lane, 22)), 1.0);
        }
    }

    #[test]
    fn imgw_writes_through_the_pbe_and_drops_out_of_bounds() {
        let mut pbe = [0u8; 24];
        let mut put = |start: u32, size: u32, value: u64| {
            for i in 0..size {
                let bit = start + i;
                pbe[(bit / 8) as usize] |= ((value >> i & 1) as u8) << (bit % 8);
            }
        };
        put(0, 4, 2);
        put(6, 7, 0x28);
        put(16, 2, 0);
        put(18, 2, 1);
        put(20, 2, 2);
        put(22, 2, 3);
        put(24, 14, 3);
        put(38, 14, 0);
        put(64, 36, IMAGE >> 4);
        put(104, 21, 16 - 4);
        let text = "imgw r4_r5_r6_r7, ts0, r2, 0, 2d";
        let (mut memory, mut group) = setup(&alloc::format!("{text}\nstop"), 5);
        group.textures[0] = Some(pbe);
        for lane in 0..5 {
            group.set_reg32(lane, 4, lane as u32);
            group.set_reg32(lane, 6, 0);
            for (k, v) in [1.0f32, 0.0, 0.0, 1.0].into_iter().enumerate() {
                group.set_reg32(lane, 8 + 2 * k, v.to_bits());
            }
        }
        finish(&mut group, &mut memory).unwrap();
        let mut row = [0u8; 20];
        memory.read(IMAGE, &mut row).unwrap();
        assert_eq!(&row[..16], &[255, 0, 0, 255].repeat(4)[..]);
        assert_eq!(&row[16..], &[0; 4]);
    }
}
