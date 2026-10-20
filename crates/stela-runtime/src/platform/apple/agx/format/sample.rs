//! Texture sampling: level-of-detail selection, mip and texel filtering,
//! wrapping, borders, cube faces, depth compare and gather.
//!
//! The reference behaviour is the Vulkan texel-filtering chapter (§16),
//! which AGX implements for Mesa's Vulkan driver (Public). Where Vulkan
//! leaves a choice the model takes the plainest one and says so
//! (Inferred): exact (not 8-bit) sub-texel weights; the LOD of a quad from
//! the differences between its threads; anisotropy as up to
//! `max_anisotropy` probes along the major axis; seamless cube texels
//! fetched through the adjacent face their direction selects.
//!
//! - Integer-coordinate requests (`smpi`) address texels directly but
//!   still apply the sampler's wraps, LOD clamp and mip filter (Mesa's
//!   txf sampler relies on clamp-to-border for out-of-bounds zeros and
//!   notes the LOD is "respected by txf").
//! - Borders are in memory order and go through the descriptor swizzle, as
//!   custom borders are packed for (Mesa `agx_border.c`).
//! - Compare tests `reference OP texel` on the texel's first memory
//!   component before the swizzle; unorm references clamp to [0, 1].
//! - Gather returns one swizzled component of the bilinear footprint at
//!   the base level in Vulkan's order (i0,j1), (i1,j1), (i1,j0), (i0,j0).

use super::descriptor::{Border, Channel, Dimension, Filter, MipFilter, Sampler, Wrap};
use super::image::{At, Image, ImageError};
use super::texel::{Kind, ty};
use crate::platform::apple::agx::isa::machine::Memory;
use crate::platform::apple::agx::isa::math;

/// How a request selects its level of detail.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Lod {
    /// From the coordinate's derivatives along x and y (implicit or
    /// explicit gradients), plus a bias and an optional minimum.
    Derivatives {
        dx: [f64; 3],
        dy: [f64; 3],
        bias: f64,
        min: Option<f64>,
    },
    /// An explicit LOD, relative to the view's first level.
    Explicit(f64),
}

/// One thread's sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Request {
    /// Normalized coordinates (texels with `Pixel coordinates`; a direction
    /// for cubes).
    pub coords: [f64; 3],
    /// Integer texel coordinates instead (`smpi`).
    pub texel: Option<[i64; 3]>,
    /// Array layer, or cube index of a cube array.
    pub layer: u32,
    pub sample: u32,
    pub lod: Lod,
    pub offset: [i64; 3],
    pub compare: Option<f64>,
    /// Gather this component (after the swizzle).
    pub gather: Option<usize>,
}

/// A sampled value in register terms.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sampled {
    pub kind: Kind,
    pub value: [f64; 4],
}

/// `Compare func` values.
mod compare {
    pub const LEQUAL: u32 = 0;
    pub const GEQUAL: u32 = 1;
    pub const LESS: u32 = 2;
    pub const GREATER: u32 = 3;
    pub const EQUAL: u32 = 4;
    pub const NOT_EQUAL: u32 = 5;
    pub const ALWAYS: u32 = 6;
}

/// Cube face selection (Vulkan "Cube map face selection"): face, sc, tc
/// and |ma|. Ties go to X, then Y.
pub fn cube_face(r: [f64; 3]) -> (u32, f64, f64, f64) {
    let [x, y, z] = r;
    let (ax, ay, az) = (x.abs(), y.abs(), z.abs());
    if ax >= ay && ax >= az {
        if x >= 0.0 {
            (0, -z, -y, ax)
        } else {
            (1, z, -y, ax)
        }
    } else if ay >= az {
        if y >= 0.0 {
            (2, x, z, ay)
        } else {
            (3, x, -z, ay)
        }
    } else if z >= 0.0 {
        (4, x, -y, az)
    } else {
        (5, -x, -y, az)
    }
}

/// The face coordinates of direction `r` projected on `face`.
fn face_coords(face: u32, r: [f64; 3]) -> (f64, f64) {
    let [x, y, z] = r;
    let (sc, tc, ma) = match face {
        0 => (-z, -y, x),
        1 => (z, -y, -x),
        2 => (x, z, y),
        3 => (x, -z, -y),
        4 => (x, -y, z),
        _ => (-x, -y, -z),
    };
    let ma = ma.abs().max(f64::MIN_POSITIVE);
    (0.5 * (sc / ma + 1.0), 0.5 * (tc / ma + 1.0))
}

/// The direction through face point (`sc`, `tc`) in [-1, 1].
fn face_direction(face: u32, sc: f64, tc: f64) -> [f64; 3] {
    match face {
        0 => [1.0, -tc, -sc],
        1 => [-1.0, -tc, sc],
        2 => [sc, 1.0, tc],
        3 => [sc, -1.0, -tc],
        4 => [sc, -tc, 1.0],
        _ => [-sc, -tc, -1.0],
    }
}

/// Wrap a texel index; `None` selects the border.
fn wrap(i: i64, size: i64, mode: Wrap) -> Option<i64> {
    match mode {
        Wrap::Repeat => Some(i.rem_euclid(size)),
        Wrap::MirroredRepeat => {
            let t = i.rem_euclid(2 * size);
            Some(if t < size { t } else { 2 * size - 1 - t })
        }
        Wrap::ClampToEdge => Some(i.clamp(0, size - 1)),
        Wrap::ClampToBorder | Wrap::ClampGl => (0..size).contains(&i).then_some(i),
        Wrap::MirroredClampToEdge => Some((if i >= 0 { i } else { -(1 + i) }).clamp(0, size - 1)),
    }
}

struct Sampling<'a> {
    memory: &'a mut dyn Memory,
    image: &'a Image,
    sampler: &'a Sampler,
    swizzle: [Channel; 4],
    border: [f64; 4],
    compare: Option<(u32, f64)>,
    layer: u32,
    sample: u32,
    cube: bool,
    dims: usize,
}

fn swizzled(raw: [f64; 4], swizzle: [Channel; 4]) -> [f64; 4] {
    swizzle.map(|channel| match channel {
        Channel::Component(c) => raw[c],
        Channel::One => 1.0,
        Channel::Zero => 0.0,
    })
}

impl Sampling<'_> {
    /// One texel of `level` at integer (unwrapped) indices, swizzled.
    fn texel(&mut self, level: u32, index: [i64; 3]) -> Result<[f64; 4], ImageError> {
        let (w, h, d) = self.image.level_size(level);
        let size = [i64::from(w), i64::from(h), i64::from(d)];
        let mut at = [0i64; 3];
        let mut face = 0u32;
        if self.cube {
            let (i, j) = (index[0], index[1]);
            let n = size[0];
            let base_face = self.layer % 6;
            if (0..n).contains(&i) && (0..n).contains(&j) {
                at = [i, j, 0];
                face = base_face;
            } else if self.sampler.seamful_cube_maps {
                at = [i.clamp(0, n - 1), j.clamp(0, n - 1), 0];
                face = base_face;
            } else {
                let s = (i as f64 + 0.5) / n as f64 * 2.0 - 1.0;
                let t = (j as f64 + 0.5) / n as f64 * 2.0 - 1.0;
                let (f, sc, tc, ma) = cube_face(face_direction(base_face, s, t));
                let to =
                    |c: f64| (math::floor((c / ma + 1.0) * 0.5 * n as f64) as i64).clamp(0, n - 1);
                at = [to(sc), to(tc), 0];
                face = f;
            }
        } else {
            for c in 0..self.dims {
                match wrap(index[c], size[c], self.sampler.wrap[c]) {
                    Some(i) => at[c] = i,
                    None => return Ok(self.border),
                }
            }
        }
        let layer = if self.cube {
            self.layer - self.layer % 6 + face
        } else if self.image.dimension == Dimension::D3 {
            at[2] as u32
        } else {
            self.layer
        };
        let texel = self.image.read(
            self.memory,
            At::new(level, at[0] as u32, at[1] as u32, layer, self.sample),
        )?;
        let mut raw = texel.value;
        if let Some((func, reference)) = self.compare {
            raw[0] = if passes(func, reference, raw[0]) {
                1.0
            } else {
                0.0
            };
        }
        Ok(swizzled(raw, self.swizzle))
    }

    /// Filter `level` at texel-space coordinates `u`.
    fn filter(
        &mut self,
        level: u32,
        u: [f64; 3],
        filter: Filter,
        offset: [i64; 3],
        gather: Option<usize>,
    ) -> Result<[f64; 4], ImageError> {
        let (w, h, d) = self.image.level_size(level);
        let size = [w, h, d].map(f64::from);
        let mut u = u;
        for c in 0..self.dims {
            if !self.cube && self.sampler.wrap[c] == Wrap::ClampGl {
                u[c] = u[c].clamp(0.0, size[c]);
            }
        }
        if gather.is_none() && filter == Filter::Nearest {
            let mut index = [0i64; 3];
            for c in 0..self.dims {
                index[c] = math::floor(u[c]) as i64 + offset[c];
            }
            return self.texel(level, index);
        }
        let mut base = [0i64; 3];
        let mut alpha = [0.0f64; 3];
        for c in 0..self.dims {
            let t = u[c] - 0.5;
            base[c] = math::floor(t) as i64 + offset[c];
            alpha[c] = t - math::floor(t);
        }
        if let Some(component) = gather {
            let mut out = [0.0; 4];
            for (slot, (di, dj)) in [(0, 1), (1, 1), (1, 0), (0, 0)].into_iter().enumerate() {
                out[slot] = self.texel(level, [base[0] + di, base[1] + dj, base[2]])?[component];
            }
            return Ok(out);
        }
        if self.image.format.kind() != Kind::Float {
            return Err(ImageError::Refused("linear filtering of an integer format"));
        }
        let corners = 1usize << self.dims;
        let mut out = [0.0; 4];
        for corner in 0..corners {
            let mut index = base;
            let mut weight = 1.0;
            for c in 0..self.dims {
                let high = corner >> c & 1 == 1;
                index[c] += i64::from(high);
                weight *= if high { alpha[c] } else { 1.0 - alpha[c] };
            }
            if weight == 0.0 {
                continue;
            }
            let texel = self.texel(level, index)?;
            for (o, t) in out.iter_mut().zip(texel) {
                *o += weight * t;
            }
        }
        Ok(out)
    }
}

fn passes(func: u32, reference: f64, texel: f64) -> bool {
    match func {
        compare::LEQUAL => reference <= texel,
        compare::GEQUAL => reference >= texel,
        compare::LESS => reference < texel,
        compare::GREATER => reference > texel,
        compare::EQUAL => reference == texel,
        compare::NOT_EQUAL => reference != texel,
        compare::ALWAYS => true,
        _ => false,
    }
}

/// The border colour in memory order.
fn border(image: &Image, sampler: &Sampler) -> Result<[f64; 4], &'static str> {
    Ok(match sampler.border {
        Border::TransparentBlack => [0.0; 4],
        Border::OpaqueBlack => [0.0, 0.0, 0.0, 1.0],
        Border::OpaqueWhite => [1.0; 4],
        Border::Custom(words) => image.format.border(words)?,
    })
}

/// The LOD selection of a request: (λ' before clamping, λ clamped by the
/// sampler and request minimum, anisotropic probes along the major axis).
fn lod(
    image: &Image,
    sampler: &Sampler,
    lod: Lod,
    dims: usize,
    cube: bool,
) -> (f64, f64, Option<([f64; 3], u32)>) {
    let (min, raw, probes) = match lod {
        Lod::Explicit(value) => (None, value, None),
        Lod::Derivatives { dx, dy, bias, min } => {
            let (w, h, d) = image.level_size(image.first_level);
            let scale = if cube {
                [f64::from(w); 3]
            } else {
                [w, h, d].map(f64::from)
            };
            let length = |v: [f64; 3]| {
                math::sqrt(
                    (0..dims)
                        .map(|c| (v[c] * scale[c]) * (v[c] * scale[c]))
                        .sum::<f64>(),
                )
            };
            let (rx, ry) = (length(dx), length(dy));
            let (rho_max, rho_min, major) = if rx >= ry { (rx, ry, dx) } else { (ry, rx, dy) };
            let limit = f64::from(sampler.max_anisotropy.max(1));
            let eta = if limit <= 1.0 || rho_max == 0.0 {
                1.0
            } else if rho_min == 0.0 {
                limit
            } else {
                (rho_max / rho_min).min(limit)
            };
            let base = math::log2(rho_max / eta);
            let probes = (eta > 1.0).then(|| (major, math::ceil(eta) as u32));
            (min, base + bias, probes)
        }
    };
    let low = min.map_or(f64::from(sampler.min_lod), |m| {
        m.max(f64::from(sampler.min_lod))
    });
    let clamped = raw.max(low).min(f64::from(sampler.max_lod));
    (raw, clamped, probes)
}

/// Dimensions a coordinate addresses, and whether the image is a cube.
fn shape(dimension: Dimension) -> (usize, bool) {
    match dimension {
        Dimension::D1 | Dimension::D1Array => (1, false),
        Dimension::D2
        | Dimension::D2Array
        | Dimension::D2Multisampled
        | Dimension::D2ArrayMultisampled => (2, false),
        Dimension::D3 => (3, false),
        Dimension::Cube | Dimension::CubeArray => (2, true),
    }
}

/// The value and register interpretation of the image's texels.
fn kind_of(image: &Image, request: &Request) -> Kind {
    if request.compare.is_some() {
        Kind::Float
    } else {
        image.format.kind()
    }
}

/// Sample `image` through `sampler` and the descriptor `swizzle`.
pub fn sample(
    memory: &mut dyn Memory,
    image: &Image,
    swizzle: [Channel; 4],
    sampler: &Sampler,
    request: &Request,
) -> Result<Sampled, ImageError> {
    let (dims, cube) = shape(image.dimension);
    let kind = kind_of(image, request);
    let border = swizzled(border(image, sampler)?, swizzle);
    let reference = request.compare.map(|r| {
        let r = if image.format.ty == ty::UNORM {
            math::saturate(r)
        } else {
            r
        };
        (sampler.compare.unwrap_or(compare::ALWAYS), r)
    });
    if request.compare.is_some() && sampler.compare.is_none() {
        return Err(ImageError::Refused(
            "a compare sample through a sampler without compare",
        ));
    }
    let mut coords = request.coords;
    let mut layer = request.layer;
    if image.dimension.multisampled() && request.texel.is_none() {
        return Err(ImageError::Refused(
            "a filtered sample of a multisampled image",
        ));
    }
    if request.sample >= image.samples {
        return Err(ImageError::Refused(
            "a sample index past the image's samples",
        ));
    }
    if cube {
        if request.texel.is_some() {
            return Err(ImageError::Refused("integer coordinates on a cube image"));
        }
        let (face, sc, tc, ma) = cube_face(coords);
        coords = [0.5 * (sc / ma + 1.0), 0.5 * (tc / ma + 1.0), 0.0];
        layer = layer * 6 + face;
    }
    let (_, _, image_layers) = image.level_size(0);
    if image.dimension != Dimension::D3 && layer >= image_layers {
        return Err(ImageError::Refused(
            "an array layer past the image (the hardware wants it clamped)",
        ));
    }
    let mut state = Sampling {
        memory,
        image,
        sampler,
        swizzle,
        border,
        compare: reference,
        layer,
        sample: request.sample,
        cube,
        dims,
    };
    let q = image.last_level - image.first_level;
    let unnormalized = sampler.pixel_coordinates && request.texel.is_none();
    let (lambda, probes) = if unnormalized {
        (0.0, None)
    } else {
        let lod_input = match (request.lod, cube) {
            (Lod::Derivatives { dx, dy, bias, min }, true) => {
                // Project the neighbouring directions onto this face.
                let (face, ..) = cube_face(request.coords);
                let at = |offset: [f64; 3]| {
                    let p = [0, 1, 2].map(|c| request.coords[c] + offset[c]);
                    let (s, t) = face_coords(face, p);
                    [s, t, 0.0]
                };
                let delta = |v: [f64; 3]| {
                    let (a, b) = (at(v), at([0.0; 3]));
                    [a[0] - b[0], a[1] - b[1], 0.0]
                };
                Lod::Derivatives {
                    dx: delta(dx),
                    dy: delta(dy),
                    bias,
                    min,
                }
            }
            (other, _) => other,
        };
        let (_, clamped, probes) = lod(image, sampler, lod_input, dims, cube);
        (clamped, probes)
    };
    let filter = if lambda <= 0.0 {
        sampler.magnify
    } else {
        sampler.minify
    };
    let lambda_level = lambda.clamp(0.0, f64::from(q));
    let levels: [(u32, f64); 2] = match (sampler.mip, request.gather.is_some() || unnormalized) {
        (_, true) | (MipFilter::None, _) => [(0, 1.0), (0, 0.0)],
        (MipFilter::Nearest, _) => {
            let d = if lambda <= 0.5 {
                0.0
            } else {
                (math::ceil(lambda + 0.5) - 1.0).clamp(0.0, f64::from(q))
            };
            [(d as u32, 1.0), (0, 0.0)]
        }
        (MipFilter::Linear, _) => {
            let low = math::floor(lambda_level);
            let delta = lambda_level - low;
            [(low as u32, 1.0 - delta), ((low as u32 + 1).min(q), delta)]
        }
    };
    let mut out = [0.0; 4];
    for (relative, weight) in levels {
        if weight == 0.0 {
            continue;
        }
        let level = image.first_level + relative;
        let value = if let Some(texel) = request.texel {
            let index = [0, 1, 2].map(|c| texel[c] + request.offset[c]);
            state.texel(level, index)?
        } else {
            let (w, h, d) = image.level_size(level);
            let size = [w, h, d].map(f64::from);
            let to_texels = |p: [f64; 3]| -> [f64; 3] {
                if unnormalized {
                    p
                } else {
                    [0, 1, 2].map(|c| p[c] * size[c])
                }
            };
            match probes {
                Some((major, count)) if !cube => {
                    let mut sum = [0.0; 4];
                    for i in 0..count {
                        let t = (f64::from(i) + 0.5) / f64::from(count) - 0.5;
                        let p = [0, 1, 2].map(|c| coords[c] + t * major[c]);
                        let v = state.filter(level, to_texels(p), filter, request.offset, None)?;
                        for (s, v) in sum.iter_mut().zip(v) {
                            *s += v / f64::from(count);
                        }
                    }
                    sum
                }
                _ => state.filter(
                    level,
                    to_texels(coords),
                    filter,
                    request.offset,
                    request.gather,
                )?,
            }
        };
        for (o, v) in out.iter_mut().zip(value) {
            *o += weight * v;
        }
    }
    Ok(Sampled { kind, value: out })
}

/// `query_lod`: the LOD the sampler would use (clamped to the view's
/// levels, 0 without mipmapping) and the computed LOD before clamping,
/// both relative to the first level (Inferred: Mesa returns the result
/// directly as NIR's `lod` query, which is defined so).
pub fn query_lod(image: &Image, sampler: &Sampler, request: &Request) -> [f64; 4] {
    let (dims, cube) = shape(image.dimension);
    let (raw, clamped, _) = lod(image, sampler, request.lod, dims, cube);
    let q = f64::from(image.last_level - image.first_level);
    let used = if sampler.mip == MipFilter::None {
        0.0
    } else {
        clamped.clamp(0.0, q)
    };
    [used, raw, 0.0, 0.0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::format::descriptor::Tiling;
    use crate::platform::apple::agx::format::image::tests::{Bytes, rgba8_texture};

    fn sampler(filter: Filter, wrap_mode: Wrap) -> Sampler {
        Sampler {
            min_lod: 0.0,
            max_lod: 15.0,
            max_anisotropy: 1,
            magnify: filter,
            minify: filter,
            mip: MipFilter::Nearest,
            wrap: [wrap_mode; 3],
            pixel_coordinates: false,
            compare: None,
            border: Border::OpaqueWhite,
            seamful_cube_maps: false,
        }
    }

    fn request(s: f64, t: f64) -> Request {
        Request {
            coords: [s, t, 0.0],
            texel: None,
            layer: 0,
            sample: 0,
            lod: Lod::Explicit(0.0),
            offset: [0; 3],
            compare: None,
            gather: None,
        }
    }

    /// A 4x4 linear RGBA8 image whose red channel is 16 * x + 4 * y.
    fn ramp() -> (Bytes, Image) {
        let mut memory = Bytes::default();
        let image = Image::from_texture(&rgba8_texture(Tiling::Linear, 4, 4, 0x1000)).unwrap();
        for y in 0..4u32 {
            for x in 0..4u32 {
                image
                    .write(
                        &mut memory,
                        At::new(0, x, y, 0, 0),
                        [f64::from(16 * x + 4 * y) / 255.0, 0.0, 0.0, 1.0],
                    )
                    .unwrap();
            }
        }
        (memory, image)
    }

    fn red(memory: &mut Bytes, image: &Image, sampler: &Sampler, request: &Request) -> f64 {
        let identity = [0, 1, 2, 3].map(Channel::Component);
        sample(memory, image, identity, sampler, request)
            .unwrap()
            .value[0]
            * 255.0
    }

    #[test]
    fn nearest_and_bilinear_filtering_match_the_reference_equations() {
        let (mut memory, image) = ramp();
        let nearest = sampler(Filter::Nearest, Wrap::ClampToEdge);
        // Texel (1, 2): 16 + 8.
        assert_eq!(red(&mut memory, &image, &nearest, &request(0.3, 0.6)), 24.0);
        let linear = sampler(Filter::Linear, Wrap::ClampToEdge);
        // u = 1.5 + 0.25, v = 2.5: weights 0.75/0.25 between x = 1 and 2.
        let value = red(&mut memory, &image, &linear, &request(1.75 / 4.0, 0.625));
        assert!((value - (0.75 * 24.0 + 0.25 * 40.0)).abs() < 1e-9);
    }

    #[test]
    fn wraps_and_borders() {
        let (mut memory, image) = ramp();
        let repeat = sampler(Filter::Nearest, Wrap::Repeat);
        assert_eq!(red(&mut memory, &image, &repeat, &request(1.3, 0.1)), 16.0);
        let mirror = sampler(Filter::Nearest, Wrap::MirroredRepeat);
        // u = 4.5 -> mirrored texel 3.
        assert_eq!(
            red(&mut memory, &image, &mirror, &request(1.125, 0.1)),
            48.0
        );
        let border = sampler(Filter::Nearest, Wrap::ClampToBorder);
        assert_eq!(
            red(&mut memory, &image, &border, &request(-0.1, 0.1)),
            255.0
        );
        // Integer coordinates past the edge read the border too.
        let mut fetch = request(0.0, 0.0);
        fetch.texel = Some([4, 0, 0]);
        assert_eq!(red(&mut memory, &image, &border, &fetch), 255.0);
        fetch.texel = Some([2, 3, 0]);
        assert_eq!(red(&mut memory, &image, &border, &fetch), 44.0);
    }

    #[test]
    fn gather_compare_and_cube_faces() {
        let (mut memory, image) = ramp();
        let mut gather = request(0.5, 0.5);
        gather.gather = Some(0);
        let identity = [0, 1, 2, 3].map(Channel::Component);
        let s = sampler(Filter::Linear, Wrap::ClampToEdge);
        let v = sample(&mut memory, &image, identity, &s, &gather)
            .unwrap()
            .value
            .map(|v| v * 255.0);
        // Footprint x 1..2, y 1..2: (i0,j1) (i1,j1) (i1,j0) (i0,j0).
        assert_eq!(v, [24.0, 40.0, 36.0, 20.0]);
        let mut shadow = sampler(Filter::Nearest, Wrap::ClampToEdge);
        shadow.compare = Some(compare::LESS);
        // Texel (3, 3) holds 60/255; the reference clamps to 0.
        let mut probe = request(0.9, 0.9);
        probe.compare = Some(-1.0);
        assert_eq!(
            sample(&mut memory, &image, identity, &shadow, &probe)
                .unwrap()
                .value[0],
            1.0
        );
        assert_eq!(cube_face([0.2, -0.9, 0.1]), (3, 0.2, -0.1, 0.9));
        assert_eq!(face_coords(0, [1.0, 0.0, 0.0]), (0.5, 0.5));
    }

    #[test]
    fn lod_follows_the_derivatives() {
        let image = Image::from_texture(&{
            let mut t = rgba8_texture(Tiling::Gpu, 64, 64, 0x1000);
            t.mipmapped = true;
            t.last_level = 6;
            t
        })
        .unwrap();
        let s = sampler(Filter::Linear, Wrap::Repeat);
        let mut r = request(0.5, 0.5);
        r.lod = Lod::Derivatives {
            dx: [4.0 / 64.0, 0.0, 0.0],
            dy: [0.0, 1.0 / 64.0, 0.0],
            bias: 0.5,
            min: None,
        };
        let [used, raw, ..] = query_lod(&image, &s, &r);
        assert!((used - 2.5).abs() < 1e-12 && (raw - 2.5).abs() < 1e-12);
        // 4:1 anisotropy probes the major axis at the minor axis' LOD.
        let mut aniso = s;
        aniso.max_anisotropy = 4;
        assert!((query_lod(&image, &aniso, &r)[0] - 0.5).abs() < 1e-12);
    }
}
