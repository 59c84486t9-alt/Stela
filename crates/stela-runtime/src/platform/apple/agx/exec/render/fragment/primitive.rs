//! Apply the actual 3D scissor/depth-bias/ZLS inputs to captured TA geometry.
//! Geometry preserves its original polygon basis and viewport, without
//! reading these arrays or guessing the later fragment depth format.

use super::super::{
    FragmentInputs,
    geometry::{Binned, Primitive, Shape},
};
use crate::platform::apple::agx::{
    exec::WorkError, isa::machine::Memory, raster::coverage::Rect, stream::read_u32,
};
use alloc::vec::Vec;

const SCISSOR_BYTES: u64 = 16;
const DEPTH_BIAS_BYTES: u64 = 12;

pub(super) fn prepare(
    memory: &mut dyn Memory,
    pass: &FragmentInputs,
    binned: &Binned,
) -> Result<Vec<Primitive>, WorkError> {
    let mut result = Vec::new();
    for original in binned
        .primitives
        .iter()
        .filter(|primitive| primitive.layer < pass.layers)
    {
        let mut primitive = original.clone();
        let state = &binned.states[primitive.state];
        let mut range = (0.0, 1.0);
        if state.control.scissor {
            let index = u64::from(state.ppp.scissor_index)
                .checked_add(primitive.viewport as u64)
                .ok_or(WorkError::Refused("a 3D scissor index wraps"))?;
            let at = entry(pass.scissors, index, SCISSOR_BYTES)?;
            let w0 = read_u32(memory, at)?;
            let w1 = read_u32(memory, at + 4)?;
            let min_z = f32::from_bits(read_u32(memory, at + 8)?);
            let max_z = f32::from_bits(read_u32(memory, at + 12)?);
            primitive.bounds = primitive.bounds.intersect(Rect {
                min: [w0 >> 16, w1 >> 16],
                max: [w0 & 0xffff, w1 & 0xffff],
            });
            range = (min_z, max_z);
        }
        if primitive.bounds.is_empty() {
            continue;
        }
        primitive.depth_clamp = state.ppp.cull.depth_clamp.then_some(range);
        if let Some(basis) = primitive.bias {
            let at = entry(
                pass.depth_biases,
                u64::from(state.ppp.depth_bias_index),
                DEPTH_BIAS_BYTES,
            )?;
            let constant = f64::from(f32::from_bits(read_u32(memory, at)?));
            let slope = f64::from(f32::from_bits(read_u32(memory, at + 4)?));
            let clamp = f64::from(f32::from_bits(read_u32(memory, at + 8)?));
            let r = if pass.depth_16() {
                1.0
            } else {
                basis.float_scale
            };
            let bias = constant * r + slope * basis.slope;
            let bias = if clamp > 0.0 {
                bias.min(clamp)
            } else if clamp < 0.0 {
                bias.max(clamp)
            } else {
                bias
            };
            let apply = |vertex: &mut super::super::geometry::Vertex| {
                vertex.window[2] += bias;
            };
            match &mut primitive.shape {
                Shape::Triangle(vertices) => vertices.iter_mut().for_each(apply),
                Shape::Line(vertices, _) => vertices.iter_mut().for_each(apply),
                Shape::Point(vertex, _) => apply(vertex),
            }
        }
        result.push(primitive);
    }
    Ok(result)
}

fn entry(base: u64, index: u64, bytes: u64) -> Result<u64, WorkError> {
    let offset = index
        .checked_mul(bytes)
        .ok_or(WorkError::Refused("a 3D input array index wraps"))?;
    let start = base
        .checked_add(offset)
        .ok_or(WorkError::Refused("a 3D input array address wraps"))?;
    start
        .checked_add(bytes - 1)
        .ok_or(WorkError::Refused("a 3D input array entry wraps"))?;
    Ok(start)
}

#[cfg(test)]
mod tests {
    use super::super::super::RenderPass;
    use super::*;
    use crate::platform::apple::agx::{
        exec::render::geometry::{DepthBiasBasis, DrawState, Uvs, Vertex},
        isa::machine::{Fault, tests::Flat},
        stream::ppp::{Cull, FragmentControl, PppState},
    };
    use alloc::vec;

    fn geometry() -> Binned {
        let vertex = Vertex {
            window: [4.0, 4.0, 0.25],
            rhw: 1.0,
            words: vec![],
        };
        Binned {
            states: vec![DrawState {
                ppp: PppState {
                    scissor_index: 1,
                    depth_bias_index: 1,
                    cull: Cull {
                        depth_clamp: true,
                        ..Cull::default()
                    },
                    ..PppState::default()
                },
                control: FragmentControl {
                    scissor: true,
                    depth_bias: true,
                    ..FragmentControl::default()
                },
                fragment: None,
                uvs: Uvs {
                    classes: vec![],
                    point_size: None,
                    layer_viewport: None,
                    clip: 0..0,
                },
            }],
            primitives: vec![Primitive {
                state: 0,
                shape: Shape::Triangle([vertex.clone(), vertex.clone(), vertex]),
                flat: vec![],
                front: true,
                layer: 0,
                bounds: Rect {
                    min: [0, 0],
                    max: [32, 32],
                },
                depth_clamp: None,
                id: 0,
                viewport: 1,
                bias: Some(DepthBiasBasis {
                    slope: 0.5,
                    float_scale: 0.125,
                }),
            }],
            ..Binned::default()
        }
    }
    struct Trace {
        flat: Flat,
        reads: Vec<u64>,
        fail: Option<u64>,
    }
    impl Memory for Trace {
        fn read(&mut self, at: u64, bytes: &mut [u8]) -> Result<(), Fault> {
            self.reads.push(at);
            if self.fail == Some(at) {
                return Err(Fault {
                    address: at,
                    write: false,
                });
            }
            self.flat.read(at, bytes)
        }
        fn write(&mut self, _: u64, _: &[u8]) -> Result<(), Fault> {
            panic!("3D primitive preparation must not write")
        }
    }
    #[test]
    fn actual_3d_arrays_format_and_viewport_apply_without_mutating_ta_product() {
        let binned = geometry();
        let before = binned.primitives.clone();
        let mut memory = Trace {
            flat: Flat::new(0x1000, 0x1000),
            reads: vec![],
            fail: None,
        };
        for (i, value) in [
            2 << 16 | 10,
            3 << 16 | 12,
            0.2f32.to_bits(),
            0.8f32.to_bits(),
        ]
        .into_iter()
        .enumerate()
        {
            memory.flat.put(0x1020 + i as u64 * 4, &value.to_le_bytes());
        }
        for (i, value) in [2.0f32, 3.0, 0.0].into_iter().enumerate() {
            memory.flat.put(0x110c + i as u64 * 4, &value.to_le_bytes());
        }
        let mut pass = RenderPass {
            layers: 1,
            scissors: 0x1000,
            depth_biases: 0x1100,
            ..RenderPass::default()
        }
        .fragment_inputs();
        for (format, expected) in [
            (super::super::super::zls::FORMAT_32F, 2.0),
            (super::super::super::zls::FORMAT_16, 3.75),
        ] {
            pass.zls_control = format << super::super::super::zls::Z_FORMAT;
            let result = prepare(&mut memory, &pass, &binned).unwrap();
            assert_eq!(
                result[0].bounds,
                Rect {
                    min: [2, 3],
                    max: [10, 12]
                }
            );
            assert_eq!(result[0].depth_clamp, Some((0.2, 0.8)));
            let Shape::Triangle(vertices) = &result[0].shape else {
                panic!()
            };
            assert!(vertices.iter().all(|v| v.window[2] == expected));
            assert_eq!(binned.primitives, before);
        }
        let sequence = vec![0x1020, 0x1024, 0x1028, 0x102c, 0x110c, 0x1110, 0x1114];
        assert_eq!(&memory.reads[..7], sequence);
        for at in &sequence {
            memory.reads.clear();
            memory.fail = Some(*at);
            assert!(prepare(&mut memory, &pass, &binned).is_err());
            assert_eq!(memory.reads.last(), Some(at));
            assert_eq!(binned.primitives, before);
        }
        memory.fail = None;
        memory.reads.clear();
        pass.layers = 0;
        assert!(prepare(&mut memory, &pass, &binned).unwrap().is_empty());
        assert!(memory.reads.is_empty());
    }
    #[test]
    fn complete_array_extent_wrap_refuses_before_memory_access() {
        for (base, index, bytes) in [(u64::MAX, 0, 16), (u64::MAX - 15, 1, 16), (1, u64::MAX, 12)] {
            assert!(entry(base, index, bytes).is_err());
        }
        let mut binned = geometry();
        binned.primitives[0].viewport = 0;
        binned.states[0].ppp.scissor_index = 0;
        let mut memory = Trace {
            flat: Flat::new(0, 1),
            reads: vec![],
            fail: None,
        };
        let pass = RenderPass {
            layers: 1,
            scissors: u64::MAX - 14,
            ..RenderPass::default()
        }
        .fragment_inputs();
        assert!(prepare(&mut memory, &pass, &binned).is_err());
        assert!(memory.reads.is_empty());
    }
}
