//! Sample coverage of triangles, lines and points in window coordinates
//! (y down, pixel centres at +0.5).
//!
//! - Vertices snap to 1/256 pixel and edges are evaluated exactly in fixed
//!   point (Inferred: eight sub-pixel bits, the Vulkan minimum of four and
//!   Metal's documented eight).
//! - A sample on an edge is covered only for top and left edges (Vulkan and
//!   Metal's top-left rule; Inferred for the hardware).
//! - Sample positions come from `PPP_MULTISAMPLECTL`: one byte per sample,
//!   x in the low nibble and y in the high one, in sixteenths of a pixel
//!   (Public: Mesa `hk_pack_ppp_multisamplectrl`); a single sample sits at
//!   the pixel centre (Mesa's default `0x88`).
//! - Lines are rectangles of their width centred on the segment (Vulkan's
//!   rectangular lines); points are squares of their size. Both use the
//!   triangle and edge rules, so neighbouring primitives never share a
//!   sample.

use crate::platform::apple::agx::isa::math;

/// Fractional bits of snapped window coordinates.
pub const SUBPIXEL_BITS: u32 = 8;
const ONE: f64 = (1u64 << SUBPIXEL_BITS) as f64;
/// Most samples per pixel.
pub const MAX_SAMPLES: usize = 4;

/// A rectangle of pixels, `min` inclusive and `max` exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub min: [u32; 2],
    pub max: [u32; 2],
}

impl Rect {
    pub fn intersect(self, other: Rect) -> Rect {
        let min = [self.min[0].max(other.min[0]), self.min[1].max(other.min[1])];
        let max = [
            self.max[0].min(other.max[0]).max(min[0]),
            self.max[1].min(other.max[1]).max(min[1]),
        ];
        Rect { min, max }
    }

    pub fn is_empty(&self) -> bool {
        self.min[0] >= self.max[0] || self.min[1] >= self.max[1]
    }
}

/// The sample positions within a pixel.
pub fn sample_positions(packed: u32, samples: u32) -> [[f64; 2]; MAX_SAMPLES] {
    let mut out = [[0.5, 0.5]; MAX_SAMPLES];
    for (s, slot) in out.iter_mut().enumerate().take(samples as usize) {
        let byte = packed >> (8 * s) & 0xff;
        *slot = [f64::from(byte & 0xf) / 16.0, f64::from(byte >> 4) / 16.0];
    }
    out
}

fn snap(value: f64) -> i64 {
    math::round(value * ONE) as i64
}

/// An edge's function at a sample, and whether it is a top or left edge.
struct Edge {
    a: [i64; 2],
    d: [i64; 2],
    top_left: bool,
}

impl Edge {
    fn new(a: [i64; 2], b: [i64; 2]) -> Self {
        let d = [b[0] - a[0], b[1] - a[1]];
        Edge {
            a,
            d,
            top_left: (d[1] == 0 && d[0] > 0) || d[1] < 0,
        }
    }

    fn inside(&self, p: [i64; 2]) -> bool {
        let e = i128::from(self.d[0]) * i128::from(p[1] - self.a[1])
            - i128::from(self.d[1]) * i128::from(p[0] - self.a[0]);
        e > 0 || (e == 0 && self.top_left)
    }
}

/// Twice the signed area of a snapped triangle, positive when its vertices
/// run clockwise on screen (y down).
pub fn doubled_area(v: [[f64; 2]; 3]) -> f64 {
    let s = v.map(|p| p.map(snap));
    let cross =
        (s[1][0] - s[0][0]) * (s[2][1] - s[0][1]) - (s[1][1] - s[0][1]) * (s[2][0] - s[0][0]);
    cross as f64 / (ONE * ONE)
}

/// Call `cover(x, y, mask)` for every pixel of `rect` a triangle covers.
pub fn triangle(
    v: [[f64; 2]; 3],
    rect: Rect,
    positions: &[[f64; 2]],
    mut cover: impl FnMut(u32, u32, u32),
) {
    let mut s = v.map(|p| p.map(snap));
    let area =
        (s[1][0] - s[0][0]) * (s[2][1] - s[0][1]) - (s[1][1] - s[0][1]) * (s[2][0] - s[0][0]);
    if area == 0 {
        return;
    }
    if area < 0 {
        s.swap(1, 2);
    }
    let edges = [
        Edge::new(s[0], s[1]),
        Edge::new(s[1], s[2]),
        Edge::new(s[2], s[0]),
    ];
    let lo = |c: usize| {
        (math::floor(s.iter().map(|p| p[c]).min().unwrap() as f64 / ONE).max(0.0)) as u32
    };
    let hi = |c: usize| {
        (math::ceil(s.iter().map(|p| p[c]).max().unwrap() as f64 / ONE).max(0.0) as u32)
            .saturating_add(1)
    };
    let bounds = Rect {
        min: [lo(0), lo(1)],
        max: [hi(0), hi(1)],
    }
    .intersect(rect);
    let offsets: alloc::vec::Vec<[i64; 2]> = positions.iter().map(|p| p.map(snap)).collect();
    for y in bounds.min[1]..bounds.max[1] {
        for x in bounds.min[0]..bounds.max[0] {
            let mut mask = 0u32;
            for (i, offset) in offsets.iter().enumerate() {
                let p = [
                    (i64::from(x) << SUBPIXEL_BITS) + offset[0],
                    (i64::from(y) << SUBPIXEL_BITS) + offset[1],
                ];
                if edges.iter().all(|e| e.inside(p)) {
                    mask |= 1 << i;
                }
            }
            if mask != 0 {
                cover(x, y, mask);
            }
        }
    }
}

/// The rectangle of a line of `width` pixels, as two triangles.
pub fn line_quad(p0: [f64; 2], p1: [f64; 2], width: f64) -> Option<[[[f64; 2]; 3]; 2]> {
    let d = [p1[0] - p0[0], p1[1] - p0[1]];
    let length = math::sqrt(d[0] * d[0] + d[1] * d[1]);
    if length == 0.0 {
        return None;
    }
    let n = [-d[1] / length * width / 2.0, d[0] / length * width / 2.0];
    let a = [p0[0] + n[0], p0[1] + n[1]];
    let b = [p1[0] + n[0], p1[1] + n[1]];
    let c = [p1[0] - n[0], p1[1] - n[1]];
    let e = [p0[0] - n[0], p0[1] - n[1]];
    Some([[a, b, c], [a, c, e]])
}

/// The square of a point of `size` pixels, as two triangles.
pub fn point_quad(centre: [f64; 2], size: f64) -> [[[f64; 2]; 3]; 2] {
    let h = size / 2.0;
    let (x0, x1, y0, y1) = (centre[0] - h, centre[0] + h, centre[1] - h, centre[1] + h);
    [
        [[x0, y0], [x1, y0], [x1, y1]],
        [[x0, y0], [x1, y1], [x0, y1]],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    const ALL: Rect = Rect {
        min: [0, 0],
        max: [64, 64],
    };

    fn covered(v: [[f64; 2]; 3], positions: &[[f64; 2]]) -> BTreeMap<(u32, u32), u32> {
        let mut out = BTreeMap::new();
        triangle(v, ALL, positions, |x, y, m| {
            out.insert((x, y), m);
        });
        out
    }

    #[test]
    fn shared_edges_cover_each_centre_once() {
        let centre = [[0.5, 0.5]];
        // A 4x4 square split along its diagonal.
        let a = covered([[0.0, 0.0], [4.0, 0.0], [4.0, 4.0]], &centre);
        let b = covered([[0.0, 0.0], [4.0, 4.0], [0.0, 4.0]], &centre);
        assert_eq!(a.len() + b.len(), 16);
        assert!(a.keys().all(|k| !b.contains_key(k)));
        // Winding does not change coverage.
        assert_eq!(covered([[0.0, 0.0], [4.0, 4.0], [4.0, 0.0]], &centre), a);
    }

    #[test]
    fn top_left_edges_own_their_samples() {
        let centre = [[0.5, 0.5]];
        // Edges through pixel centres at x = 0.5 (left) and x = 2.5 (right).
        let t = covered([[0.5, 0.0], [2.5, 0.0], [2.5, 8.0]], &centre);
        assert!(!t.contains_key(&(2, 7)));
        let square = covered([[0.5, 0.5], [2.5, 0.5], [2.5, 2.5]], &centre);
        // The top edge (y = 0.5) owns row 0; the right edge (x = 2.5) does
        // not own column 2.
        assert!(square.contains_key(&(1, 0)));
        assert!(!square.contains_key(&(2, 1)));
    }

    #[test]
    fn sample_positions_unpack_and_cover_per_sample() {
        let p = sample_positions(0xeaa2_6e26, 4);
        assert_eq!(
            p,
            [
                [0.375, 0.125],
                [0.875, 0.375],
                [0.125, 0.625],
                [0.625, 0.875]
            ]
        );
        // A half-pixel-wide sliver covers only the samples left of x = 0.5.
        let sliver = covered([[0.0, 0.0], [0.5, 0.0], [0.5, 1.0]], &p);
        assert_eq!(sliver.get(&(0, 0)), Some(&0b0001));
        let [a, b] = line_quad([0.0, 2.5], [4.0, 2.5], 1.0).unwrap();
        let mut row = BTreeMap::new();
        for t in [a, b] {
            triangle(t, ALL, &[[0.5, 0.5]], |x, y, _| {
                *row.entry((x, y)).or_insert(0) += 1;
            });
        }
        assert_eq!(row.len(), 4);
        assert!(row.iter().all(|(&(_, y), &n)| y == 2 && n == 1));
    }
}
