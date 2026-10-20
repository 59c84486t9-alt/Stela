//! Coefficient planes `<A, B, C>`: a value as `A x + B y + C` over the
//! window (Public: Mesa `agx_nir_lower_interpolation.c`: "A and B are the
//! screen-space partial derivatives of the input, and C is the value at the
//! corner of the tile").
//!
//! Planes are built in window coordinates and moved to the 32x32 region a
//! fragment lies in when loaded: Mesa evaluates them at `pixel % 32 + 0.5`,
//! so `C` is the value at the region's corner.

/// Side of the region coefficients are relative to.
pub const REGION: u32 = 32;

/// A plane in window coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Plane {
    pub a: f64,
    pub b: f64,
    pub c: f64,
}

impl Plane {
    pub const fn constant(value: f64) -> Self {
        Plane {
            a: 0.0,
            b: 0.0,
            c: value,
        }
    }

    /// The plane through three window points with values `f`.
    pub fn triangle(p: [[f64; 2]; 3], f: [f64; 3]) -> Self {
        let (dx1, dy1) = (p[1][0] - p[0][0], p[1][1] - p[0][1]);
        let (dx2, dy2) = (p[2][0] - p[0][0], p[2][1] - p[0][1]);
        let det = dx1 * dy2 - dx2 * dy1;
        if det == 0.0 {
            return Plane::constant(f[0]);
        }
        let (df1, df2) = (f[1] - f[0], f[2] - f[0]);
        let a = (df1 * dy2 - df2 * dy1) / det;
        let b = (df2 * dx1 - df1 * dx2) / det;
        Plane {
            a,
            b,
            c: f[0] - a * p[0][0] - b * p[0][1],
        }
    }

    /// The plane varying along a segment by the projection onto it, and
    /// constant across it (Vulkan line interpolation).
    pub fn segment(p: [[f64; 2]; 2], f: [f64; 2]) -> Self {
        let d = [p[1][0] - p[0][0], p[1][1] - p[0][1]];
        let length2 = d[0] * d[0] + d[1] * d[1];
        if length2 == 0.0 {
            return Plane::constant(f[0]);
        }
        let df = f[1] - f[0];
        let (a, b) = (df * d[0] / length2, df * d[1] / length2);
        Plane {
            a,
            b,
            c: f[0] - a * p[0][0] - b * p[0][1],
        }
    }

    pub fn at(&self, x: f64, y: f64) -> f64 {
        self.a * x + self.b * y + self.c
    }

    /// The register form relative to the region holding pixel (`x`, `y`).
    pub fn register(&self, x: u32, y: u32) -> [f32; 3] {
        let (ox, oy) = (f64::from(x - x % REGION), f64::from(y - y % REGION));
        [
            self.a as f32,
            self.b as f32,
            (self.c + self.a * ox + self.b * oy) as f32,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planes_reproduce_their_vertices_and_move_to_the_region() {
        let p = [[1.0, 1.0], [5.0, 1.0], [1.0, 9.0]];
        let plane = Plane::triangle(p, [2.0, 10.0, 6.0]);
        for (point, value) in p.iter().zip([2.0, 10.0, 6.0]) {
            assert!((plane.at(point[0], point[1]) - value).abs() < 1e-12);
        }
        // In the region at (32, 0), C is the value at x = 32.
        let [a, b, c] = plane.register(40, 3);
        assert_eq!((a, b), (2.0, 0.5));
        assert_eq!(f64::from(c), plane.at(32.0, 0.0));
        let line = Plane::segment([[0.0, 0.0], [4.0, 0.0]], [0.0, 1.0]);
        assert_eq!((line.at(2.0, 7.0), line.a, line.b), (0.5, 0.25, 0.0));
    }
}
