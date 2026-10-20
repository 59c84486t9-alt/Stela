//! Depth and stencil tests (cmdbuf.xml `ZS Func`, `Stencil Op`, `Fragment
//! face`, `Fragment face 2`, `Fragment stencil`; the order is the API one,
//! Public: Vulkan "Stencil Test" and "Depth Test").
//!
//! A sample first runs the stencil test (`(reference & read mask) OP
//! (stored & read mask)`), then both depth functions (`fragment OP
//! stored`; cmdbuf.xml: "Both depth functions must pass"). The stencil op
//! for the outcome is applied through the write mask; depth is written on a
//! pass unless both disable bits are set ("If either disable is zeroed,
//! depth is written").

use crate::platform::apple::agx::stream::ppp::{Face, Stencil};

/// `ZS Func` values.
pub mod func {
    pub const NEVER: u32 = 0;
    pub const LESS: u32 = 1;
    pub const EQUAL: u32 = 2;
    pub const LEQUAL: u32 = 3;
    pub const GREATER: u32 = 4;
    pub const NOT_EQUAL: u32 = 5;
    pub const GEQUAL: u32 = 6;
    pub const ALWAYS: u32 = 7;
}

/// `Stencil Op` values.
mod op {
    pub const KEEP: u32 = 0;
    pub const ZERO: u32 = 1;
    pub const REPLACE: u32 = 2;
    pub const INCR_SAT: u32 = 3;
    pub const DECR_SAT: u32 = 4;
    pub const INVERT: u32 = 5;
    pub const INCR_WRAP: u32 = 6;
    pub const DECR_WRAP: u32 = 7;
}

/// `fragment OP stored` for a `ZS Func`.
pub fn compare<T: PartialOrd>(function: u32, fragment: T, stored: T) -> bool {
    match function {
        func::NEVER => false,
        func::LESS => fragment < stored,
        func::EQUAL => fragment == stored,
        func::LEQUAL => fragment <= stored,
        func::GREATER => fragment > stored,
        func::NOT_EQUAL => fragment != stored,
        func::GEQUAL => fragment >= stored,
        _ => true,
    }
}

fn apply(operation: u32, value: u8, reference: u8) -> u8 {
    match operation {
        op::KEEP => value,
        op::ZERO => 0,
        op::REPLACE => reference,
        op::INCR_SAT => value.saturating_add(1),
        op::DECR_SAT => value.saturating_sub(1),
        op::INVERT => !value,
        op::INCR_WRAP => value.wrapping_add(1),
        op::DECR_WRAP => value.wrapping_sub(1),
        _ => value,
    }
}

/// The state one face tests with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaceState {
    pub face: Face,
    pub stencil: Stencil,
    pub stencil_test: bool,
}

/// One sample's stored values and the outcome of testing it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub depth: f32,
    pub stencil: u8,
}

/// Test a fragment sample at `depth` against `stored`, updating it.
/// `quantize` maps a depth to the buffer's representation (Z16 rounds to
/// 16-bit unorm) before comparing and storing. Returns whether it passed.
pub fn test(
    state: &FaceState,
    depth: f32,
    stored: &mut Sample,
    quantize: impl Fn(f32) -> f32,
) -> bool {
    let FaceState {
        face,
        stencil,
        stencil_test,
    } = *state;
    let reference = face.stencil_reference;
    if stencil_test {
        let masked = |v: u8| v & stencil.read_mask;
        if !compare(stencil.compare, masked(reference), masked(stored.stencil)) {
            write_stencil(stored, stencil, stencil.stencil_fail, reference);
            return false;
        }
    }
    let depth = quantize(depth);
    let pass = compare(face.depth_function, depth, stored.depth)
        && compare(face.depth_function_2, depth, stored.depth);
    if stencil_test {
        let operation = if pass {
            stencil.depth_pass
        } else {
            stencil.depth_fail
        };
        write_stencil(stored, stencil, operation, reference);
    }
    if pass && !(face.disable_depth_write && face.disable_depth_write_2) {
        stored.depth = depth;
    }
    pass
}

fn write_stencil(stored: &mut Sample, stencil: Stencil, operation: u32, reference: u8) {
    let new = apply(operation, stored.stencil, reference);
    stored.stencil = (stored.stencil & !stencil.write_mask) | (new & stencil.write_mask);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(depth_function: u32) -> FaceState {
        FaceState {
            face: Face {
                depth_function,
                depth_function_2: func::ALWAYS,
                stencil_reference: 5,
                ..Face::default()
            },
            stencil: Stencil {
                write_mask: 0xff,
                read_mask: 0xff,
                depth_pass: op::REPLACE,
                depth_fail: op::INCR_SAT,
                stencil_fail: op::ZERO,
                compare: func::ALWAYS,
            },
            stencil_test: true,
        }
    }

    #[test]
    fn depth_passes_write_and_failures_keep() {
        let mut stored = Sample {
            depth: 0.5,
            stencil: 1,
        };
        assert!(test(&state(func::LESS), 0.25, &mut stored, |d| d));
        assert_eq!(
            stored,
            Sample {
                depth: 0.25,
                stencil: 5
            }
        );
        assert!(!test(&state(func::LESS), 0.75, &mut stored, |d| d));
        assert_eq!(
            stored,
            Sample {
                depth: 0.25,
                stencil: 6
            }
        );
    }

    #[test]
    fn stencil_failures_skip_the_depth_test_and_writes_honour_disables() {
        let mut s = state(func::ALWAYS);
        s.stencil.compare = func::NEVER;
        let mut stored = Sample {
            depth: 0.5,
            stencil: 9,
        };
        assert!(!test(&s, 0.1, &mut stored, |d| d));
        assert_eq!(
            stored,
            Sample {
                depth: 0.5,
                stencil: 0
            }
        );
        let mut s = state(func::ALWAYS);
        s.face.disable_depth_write = true;
        s.face.disable_depth_write_2 = true;
        assert!(test(&s, 0.1, &mut stored, |d| d));
        assert_eq!(stored.depth, 0.5);
    }
}
