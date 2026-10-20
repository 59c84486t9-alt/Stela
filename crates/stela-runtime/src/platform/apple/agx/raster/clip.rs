//! Clipping in clip space against the view volume and the user clip
//! distances (Public: the Vulkan "Primitive Clipping" rules the hardware
//! implements for Mesa's driver).
//!
//! - The volume is `-w <= x, y <= w` and, with depth clipping, `0 <= z <=
//!   w` (`-w <= z` under the OpenGL convention of `CR PPP Control`); every
//!   enabled clip distance must be at least 0. A vertex on a plane is
//!   inside.
//! - Polygons are clipped plane by plane (Sutherland–Hodgman); lines by
//!   the same planes; a point outside any plane is discarded.
//! - A new vertex interpolates the position and smooth outputs linearly in
//!   clip space (perspective-correct after the divide) and `linear`
//!   (no-perspective) outputs by the screen-space parameter that keeps them
//!   linear in the window; flat outputs keep the first vertex's value (flat
//!   shading reads the primitive's original vertices).
//! - Each polygon edge remembers whether it is an edge of the original
//!   primitive, for polygon-mode lines that skip clipped edges.

use alloc::vec::Vec;

/// How an output word interpolates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interp {
    Smooth,
    Flat,
    Linear,
}

/// A vertex in clip space with its output words.
#[derive(Debug, Clone, PartialEq)]
pub struct Vertex {
    pub position: [f64; 4],
    pub words: Vec<u32>,
    /// Clip distances (inside when at least 0).
    pub clip: Vec<f64>,
    /// The edge from this vertex to the next is an original edge.
    pub edge: bool,
}

/// Which planes clip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Volume {
    pub depth_clip: bool,
    /// Near plane at `z = -w` (OpenGL) instead of `z = 0`.
    pub opengl_depth: bool,
}

/// Signed distances of `v` to every plane (inside when at least 0).
fn distances(v: &Vertex, volume: Volume) -> Vec<f64> {
    let [x, y, z, w] = v.position;
    let mut d = alloc::vec![w + x, w - x, w + y, w - y];
    if volume.depth_clip {
        d.push(if volume.opengl_depth { w + z } else { z });
        d.push(w - z);
    }
    d.extend(v.clip.iter().copied());
    d
}

/// The vertex a fraction `t` from `a` to `b`.
fn lerp(a: &Vertex, b: &Vertex, t: f64, classes: &[Interp]) -> Vertex {
    let position = [0, 1, 2, 3].map(|c| a.position[c] + t * (b.position[c] - a.position[c]));
    let (wa, wb) = (a.position[3], b.position[3]);
    let denominator = (1.0 - t) * wa + t * wb;
    let s = if denominator == 0.0 {
        t
    } else {
        t * wb / denominator
    };
    let words = a
        .words
        .iter()
        .zip(&b.words)
        .enumerate()
        .map(|(i, (&wa_bits, &wb_bits))| {
            let mix = |f: f64| {
                let (fa, fb) = (
                    f64::from(f32::from_bits(wa_bits)),
                    f64::from(f32::from_bits(wb_bits)),
                );
                ((fa + f * (fb - fa)) as f32).to_bits()
            };
            match classes.get(i).copied().unwrap_or(Interp::Flat) {
                Interp::Smooth => mix(t),
                Interp::Linear => mix(s),
                Interp::Flat => wa_bits,
            }
        })
        .collect();
    let clip = a
        .clip
        .iter()
        .zip(&b.clip)
        .map(|(&ca, &cb)| ca + t * (cb - ca))
        .collect();
    Vertex {
        position,
        words,
        clip,
        edge: false,
    }
}

/// Clip a polygon; the result is empty or has at least three vertices.
pub fn polygon(vertices: Vec<Vertex>, volume: Volume, classes: &[Interp]) -> Vec<Vertex> {
    let planes = distances(&vertices[0], volume).len();
    let mut polygon = vertices;
    for plane in 0..planes {
        if polygon.is_empty() {
            break;
        }
        let d: Vec<f64> = polygon
            .iter()
            .map(|v| distances(v, volume)[plane])
            .collect();
        if d.iter().all(|&x| x >= 0.0) {
            continue;
        }
        let mut out = Vec::new();
        for i in 0..polygon.len() {
            let j = (i + 1) % polygon.len();
            let (a, b) = (&polygon[i], &polygon[j]);
            let (da, db) = (d[i], d[j]);
            if da >= 0.0 {
                let mut kept = a.clone();
                if db < 0.0 {
                    // The edge leaves: the new edge along the plane is not
                    // original.
                    let t = da / (da - db);
                    let mut exit = lerp(a, b, t, classes);
                    kept.edge = a.edge;
                    out.push(kept);
                    exit.edge = false;
                    out.push(exit);
                    continue;
                }
                out.push(kept);
            } else if db >= 0.0 {
                let t = da / (da - db);
                let mut entry = lerp(a, b, t, classes);
                entry.edge = a.edge;
                out.push(entry);
            }
        }
        polygon = out;
    }
    if polygon.len() < 3 {
        Vec::new()
    } else {
        polygon
    }
}

/// Clip a line; `None` when nothing remains.
pub fn line(a: Vertex, b: Vertex, volume: Volume, classes: &[Interp]) -> Option<(Vertex, Vertex)> {
    let (da, db) = (distances(&a, volume), distances(&b, volume));
    let (mut t0, mut t1) = (0.0f64, 1.0f64);
    for (&x, &y) in da.iter().zip(&db) {
        if x < 0.0 && y < 0.0 {
            return None;
        }
        if x < 0.0 {
            t0 = t0.max(x / (x - y));
        } else if y < 0.0 {
            t1 = t1.min(x / (x - y));
        }
    }
    if t0 > t1 {
        return None;
    }
    let start = if t0 > 0.0 {
        lerp(&a, &b, t0, classes)
    } else {
        a.clone()
    };
    let end = if t1 < 1.0 {
        lerp(&a, &b, t1, classes)
    } else {
        b
    };
    Some((start, end))
}

/// Whether a point survives.
pub fn point(v: &Vertex, volume: Volume) -> bool {
    distances(v, volume).iter().all(|&d| d >= 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vertex(x: f64, y: f64, z: f64, w: f64, word: f32) -> Vertex {
        Vertex {
            position: [x, y, z, w],
            words: alloc::vec![word.to_bits()],
            clip: Vec::new(),
            edge: true,
        }
    }

    const VOLUME: Volume = Volume {
        depth_clip: true,
        opengl_depth: false,
    };

    #[test]
    fn a_triangle_crossing_one_plane_gains_a_vertex() {
        let tri = alloc::vec![
            vertex(0.0, 0.0, 0.5, 1.0, 0.0),
            vertex(2.0, 0.0, 0.5, 1.0, 2.0),
            vertex(0.0, 0.5, 0.5, 1.0, 0.0)
        ];
        let out = polygon(tri, VOLUME, &[Interp::Smooth]);
        assert_eq!(out.len(), 4);
        // x = w cuts both edges leaving (2, 0).
        assert!(out.iter().all(|v| v.position[0] <= 1.0 + 1e-12));
        let cut = out
            .iter()
            .find(|v| v.position[1] == 0.0 && v.position[0] == 1.0)
            .unwrap();
        assert_eq!(f32::from_bits(cut.words[0]), 1.0);
        // Exactly one new edge runs along the plane.
        assert_eq!(out.iter().filter(|v| !v.edge).count(), 1);
    }

    #[test]
    fn linear_outputs_interpolate_in_screen_space() {
        // From w = 1 to w = 3 the clip-space midpoint is at screen
        // parameter 3/4... checked with the near plane at z = 0.
        let a = vertex(0.0, 0.0, -1.0, 1.0, 0.0);
        let b = vertex(0.0, 0.0, 1.0, 3.0, 1.0);
        let (start, _) = line(a.clone(), b.clone(), VOLUME, &[Interp::Linear]).unwrap();
        // t = 0.5 (z from -1 to 1); s = 0.5 * 3 / (0.5 * 1 + 0.5 * 3) = 0.75.
        assert_eq!(f32::from_bits(start.words[0]), 0.75);
        let (start, _) = line(a, b, VOLUME, &[Interp::Smooth]).unwrap();
        assert_eq!(f32::from_bits(start.words[0]), 0.5);
        assert!(!point(&vertex(0.0, 0.0, -0.1, 1.0, 0.0), VOLUME));
    }
}
