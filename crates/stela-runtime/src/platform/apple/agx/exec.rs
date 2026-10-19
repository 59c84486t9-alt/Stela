//! A bounded GPU work executor: dispatch an AGX shader program over a grid of
//! invocations and write each invocation's computed color to a linear surface,
//! with an in-order completion count.
//!
//! This executes the real decoded AGX shader ISA ([`super::isa`]) on the host.
//! It is a first, honestly-scoped slice of the work the firmware's TA/3D/
//! compute channels drive. What it models:
//!
//! - A compute-style dispatch: each (x, y) invocation runs the program with
//!   its coordinates and the dispatch's uniforms seeded into registers, as the
//!   hardware's iterator and uniform setup do before a shader runs.
//! - A fixed-function store of the invocation's output register to a linear
//!   `R8G8B8A8` surface, modeling the pixel back-end's store (the PBE store is
//!   fixed-function, not shader ISA).
//! - An in-order fence: completed invocations are counted and the stamp only
//!   advances when the whole dispatch has run, so a later dispatch cannot
//!   report completion before an earlier one.
//!
//! What it does **not** yet model (docs/research/agx.md §5): the VDM/CDM/PPP
//! control streams, the tiler and rasterizer, real PBE descriptors, texture
//! sampling and compression, and reading the program and its layout from a
//! firmware work queue. Those are the remaining executor layers.

use super::isa::{self, Registers, RunError};
use alloc::vec::Vec;

/// A linear `R8G8B8A8` surface in host memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surface {
    pub width: u32,
    pub height: u32,
    /// Row-major `width * height` pixels, each 0xAABBGGRR little-endian.
    pub pixels: Vec<u32>,
}

impl Surface {
    pub fn new(width: u32, height: u32) -> Self {
        Surface {
            width,
            height,
            pixels: alloc::vec![0; (width * height) as usize],
        }
    }

    pub fn pixel(&self, x: u32, y: u32) -> u32 {
        self.pixels[(y * self.width + x) as usize]
    }
}

/// Where the dispatch seeds each invocation's inputs and reads its output, as
/// register (16-bit lane) indices. The hardware's iterator/uniform setup fills
/// equivalent registers before the shader runs.
#[derive(Debug, Clone, Copy)]
pub struct Binding {
    /// 32-bit register seeded with the invocation's x coordinate as f32.
    pub x: isa::Reg,
    /// 32-bit register seeded with the invocation's y coordinate as f32.
    pub y: isa::Reg,
    /// The base register for `uniforms`, seeded in order as f32.
    pub uniform_base: isa::Reg,
    /// The 32-bit register holding the four 0..=1 color channels, written as
    /// `out`, `out+2`, `out+4`, `out+6` (R, G, B, A).
    pub out: isa::Reg,
}

/// A compute dispatch: a program, its register bindings and its uniforms.
pub struct Dispatch<'a> {
    pub code: &'a [u8],
    pub binding: Binding,
    pub uniforms: &'a [f32],
    /// 16-bit lanes the shader needs.
    pub lanes: usize,
}

fn channel(value: f32) -> u32 {
    (value.clamp(0.0, 1.0) * 255.0 + 0.5) as u32
}

/// Run `dispatch` over the whole surface and store each invocation's color.
/// Returns the number of invocations completed (the fence value), or the
/// first invocation's run error.
pub fn dispatch(surface: &mut Surface, dispatch: &Dispatch<'_>) -> Result<u64, RunError> {
    let b = dispatch.binding;
    let mut completed = 0u64;
    for y in 0..surface.height {
        for x in 0..surface.width {
            let mut regs = Registers::new(dispatch.lanes);
            regs.write_f32(b.x, x as f32);
            regs.write_f32(b.y, y as f32);
            for (i, &u) in dispatch.uniforms.iter().enumerate() {
                regs.write_f32(b.uniform_base + 2 * i as isa::Reg, u);
            }
            isa::run(dispatch.code, &mut regs)?;
            let rgba = channel(regs.read_f32(b.out))
                | channel(regs.read_f32(b.out + 2)) << 8
                | channel(regs.read_f32(b.out + 4)) << 16
                | channel(regs.read_f32(b.out + 6)) << 24;
            surface.pixels[(y * surface.width + x) as usize] = rgba;
            completed += 1;
        }
    }
    Ok(completed)
}

/// An in-order fence over a sequence of dispatches: the stamp advances only
/// as each dispatch completes, in submission order.
#[derive(Debug, Default)]
pub struct Fence {
    stamp: u64,
}

impl Fence {
    pub fn value(&self) -> u64 {
        self.stamp
    }

    /// Complete the next dispatch, which contributed `invocations`.
    pub fn complete(&mut self, invocations: u64) {
        self.stamp += invocations;
    }
}

#[cfg(test)]
mod tests {
    use super::super::isa::{BinOp, Dest, FloatSrc};
    use super::*;

    fn src(reg: isa::Reg) -> FloatSrc {
        FloatSrc {
            reg,
            size32: true,
            abs: false,
            neg: false,
        }
    }

    fn dest(reg: isa::Reg) -> Dest {
        Dest { reg, size32: true }
    }

    /// A shader computing a horizontal red gradient: R = x * (1/(W-1)),
    /// G = 0, B = 0, A = 1. Registers: r0=x, r2=y, uniforms at r4 (1/(W-1))
    /// and r6 (1.0 constant for A and used as G/B zero via r8 left zero).
    fn gradient_shader() -> (Vec<u8>, Binding) {
        let mut code = Vec::new();
        // r10 = r0 (x) * r4 (1/(W-1)), saturated.
        code.extend_from_slice(&isa::encode_binary(
            BinOp::Mul,
            dest(10),
            src(0),
            src(4),
            true,
        ));
        // A channel register r16 = r6 (1.0) + r8 (0.0).
        code.extend_from_slice(&isa::encode_binary(
            BinOp::Add,
            dest(16),
            src(6),
            src(8),
            true,
        ));
        code.extend_from_slice(&isa::encode_stop());
        // out base r10: R=r10, G=r12 (zero), B=r14 (zero), A=r16.
        (
            code,
            Binding {
                x: 0,
                y: 2,
                uniform_base: 4,
                out: 10,
            },
        )
    }

    #[test]
    fn a_dispatch_runs_the_shader_and_writes_checked_gradient_pixels() {
        let mut surface = Surface::new(4, 2);
        let (code, binding) = gradient_shader();
        // uniform 0 = 1/(W-1) at r4, uniform 1 = 1.0 at r6; r8 stays zero.
        let invocations = dispatch(
            &mut surface,
            &Dispatch {
                code: &code,
                binding,
                uniforms: &[1.0 / 3.0, 1.0],
                lanes: 32,
            },
        )
        .unwrap();
        assert_eq!(invocations, 8);
        // Column x contributes red channel round(x/3 * 255); G=B=0, A=255.
        for y in 0..2 {
            for x in 0..4 {
                let red = ((x as f32 / 3.0) * 255.0 + 0.5) as u32;
                assert_eq!(surface.pixel(x, y), red | 0xff00_0000, "pixel {x},{y}");
            }
        }
    }

    #[test]
    fn the_fence_advances_only_in_submission_order() {
        let mut fence = Fence::default();
        assert_eq!(fence.value(), 0);
        fence.complete(8);
        assert_eq!(fence.value(), 8);
        fence.complete(4);
        assert_eq!(fence.value(), 12);
    }

    #[test]
    fn an_unsupported_program_fails_the_dispatch() {
        let mut surface = Surface::new(2, 2);
        let (_, binding) = gradient_shader();
        assert_eq!(
            dispatch(
                &mut surface,
                &Dispatch {
                    code: &[0, 0, 0, 0, 0, 0],
                    binding,
                    uniforms: &[],
                    lanes: 32,
                },
            ),
            Err(RunError::Unsupported)
        );
    }
}
