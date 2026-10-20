//! Stage I/O: vertex outputs (`st_var`, `no_var`), fragment coefficient
//! iteration (`iter`, `iterproj`, `ldcf`), the tilebuffer (`ld_tile`,
//! `st_tile`) and coverage (`sample_mask`, `zs_emit`). Each effect goes to
//! the stage through [`Env`]; a stage that lacks one refuses by name.
//!
//! Semantics (Public: Mesa `agx_nir_lower_interpolation.c`, `agx_compile.c`,
//! `agx_pack.c`, `agx_nir_lower_sample_mask.c`; Inferred where marked):
//! - A coefficient register holds `<A, B, C>`; iterating evaluates
//!   `A x + B y + C` at the tile-relative position the interpolation mode
//!   names (rounded once to the destination, Inferred), and `iterproj`
//!   divides by the iterated reciprocal-W register (Mesa: "divide by RHW").
//!   A register source names the coefficient register indirectly. `ldcf`
//!   copies the three coefficients. `fwd`, `elide` and `kill` are scheduling
//!   hints Mesa leaves clear (`TODO: optimize`) and change no value
//!   (Inferred).
//! - `st_var` stores a 32-bit register into a UVS slot (immediate or a
//!   16-bit register); `last` orders nothing in an in-order model.
//! - `ld_tile`/`st_tile` move the masked components, compacted in mask
//!   order, between registers and the samples of the pixel at the byte
//!   offset, in the ISA format.
//! - `sample_mask target, live` and `zs_emit target, zs`: the `zs` operand's
//!   case says whether it is depth (32-bit), stencil (16-bit) or both (a
//!   depth word then the stencil half). A thread left with no sample is
//!   demoted to a helper (Vulkan's demote; Inferred for the hardware).
//! - Helper threads load the tilebuffer but never store to it, and run no
//!   coverage instruction (`SimdGroup::effective`).

use super::decode::{Instr, Operand, Value};
use super::generated::{Imm, Mod, Op};
use super::machine::{Env, Error, Interpolation, SimdGroup, Step, TileAccess, lanes};
use crate::platform::apple::agx::format::isa::IsaFormat;

/// `interpolation` values (`AGX2.xml`).
mod interpolation {
    pub const SAMPLE: u32 = 1;
    pub const CENTROID: u32 = 2;
    pub const SAMPLE_REGISTER: u32 = 3;
}

/// Coefficients in one coefficient register.
const COEFFICIENTS: usize = 3;

fn refused(reason: &'static str) -> Error {
    Error::Refused(reason)
}

impl SimdGroup {
    pub(super) fn stage(&mut self, instr: &Instr, env: &mut dyn Env) -> Result<Step, Error> {
        use Op::*;
        let active = self.active();
        match instr.op() {
            NoVar => env.no_varyings().map_err(refused)?,
            StVar => {
                let (value, slot) = (instr.source(0), instr.source(1));
                for lane in lanes(active) {
                    let slot = self.bits(lane, &slot, 0)? as u32;
                    let value = self.bits(lane, &value, 0)? as u32;
                    env.store_varying(lane, slot, value).map_err(refused)?;
                }
            }
            Iter | Iterproj => {
                let dest = instr.dest();
                let sample_source = instr.source(if instr.op() == Iter { 1 } else { 2 });
                for lane in lanes(active) {
                    let mode = self.interpolation(lane, instr, &sample_source)?;
                    let at = env.interpolation_point(lane, mode).map_err(refused)?;
                    let base = self.coefficient_index(lane, &instr.source(0))?;
                    let divisor = if instr.op() == Iterproj {
                        let Value::Cf(w) = instr.source(1).value else {
                            unreachable!("iterproj's perspective source is a coefficient register")
                        };
                        Some(evaluate(
                            env.coefficient(u32::from(w)).map_err(refused)?,
                            at,
                        ))
                    } else {
                        None
                    };
                    for component in 0..usize::from(dest.count) {
                        let plane = env.coefficient(base + component as u32).map_err(refused)?;
                        let mut value = evaluate(plane, at);
                        if let Some(w) = divisor {
                            value /= w;
                        }
                        let bits =
                            super::super::format::isa::float_register(value, u32::from(dest.size));
                        self.put(lane, &dest, component, bits)?;
                    }
                }
            }
            Ldcf => {
                let dest = instr.dest();
                for lane in lanes(active) {
                    let base = self.coefficient_index(lane, &instr.source(0))?;
                    let plane = env.coefficient(base).map_err(refused)?;
                    for (component, value) in plane.iter().enumerate().take(COEFFICIENTS) {
                        // A 32-bit copy keeps the raw bits: flat integer
                        // varyings travel in the C coefficient.
                        let bits = if dest.size == 32 {
                            u64::from(value.to_bits())
                        } else {
                            super::super::format::isa::float_register(
                                f64::from(*value),
                                u32::from(dest.size),
                            )
                        };
                        self.put(lane, &dest, component, bits)?;
                    }
                }
            }
            LdTile | StTile => {
                let format = IsaFormat::from_field(instr.modifier(Mod::Format).unwrap_or(0))
                    .ok_or(Error::Refused("a tilebuffer format the description lacks"))?;
                let mask = instr.modifier(Mod::Mask).unwrap_or(0);
                let offset = instr.immediate(Imm::Offset).unwrap_or(0) as u32;
                let (data, coords, samples) = if instr.op() == LdTile {
                    (instr.dest(), instr.source(0), instr.source(1))
                } else {
                    (instr.source(0), instr.source(1), instr.source(2))
                };
                // Helpers load the tilebuffer but never store to it.
                let threads = if instr.op() == LdTile {
                    active
                } else {
                    self.effective()
                };
                for lane in lanes(threads) {
                    let explicit = match coords.value {
                        Value::Reg(_) => Some([
                            self.bits(lane, &coords, 0)? as u32,
                            self.bits(lane, &coords, 1)? as u32,
                        ]),
                        _ => None,
                    };
                    let access = TileAccess {
                        lane,
                        offset,
                        format,
                        mask,
                        samples: self.bits(lane, &samples, 0)? as u32,
                        coords: explicit,
                        register_bits: u32::from(data.size),
                    };
                    let slots = mask.count_ones() as usize;
                    if instr.op() == LdTile {
                        let values = env.tile_load(&access).map_err(refused)?;
                        for (slot, value) in values.iter().enumerate().take(slots) {
                            self.put(lane, &data, slot, *value)?;
                        }
                    } else {
                        let mut values = [0u64; 4];
                        for (slot, value) in values.iter_mut().enumerate().take(slots) {
                            *value = self.bits(lane, &data, slot)?;
                        }
                        env.tile_store(&access, values).map_err(refused)?;
                    }
                }
            }
            SampleMask => {
                let (target, live) = (instr.source(0), instr.source(1));
                for lane in lanes(self.effective()) {
                    let target = self.bits(lane, &target, 0)? as u32;
                    let live = self.bits(lane, &live, 0)? as u32;
                    if env.sample_mask(lane, target, live).map_err(refused)? {
                        self.helpers |= 1 << lane;
                    }
                }
            }
            ZsEmit => {
                let (target, zs) = (instr.source(0), instr.source(1));
                for lane in lanes(self.effective()) {
                    let mask = self.bits(lane, &target, 0)? as u32;
                    let (depth, stencil) = self.depth_stencil(lane, &zs)?;
                    if env.zs_emit(lane, mask, depth, stencil).map_err(refused)? {
                        self.helpers |= 1 << lane;
                    }
                }
            }
            other => unreachable!("{other:?} is not a stage instruction"),
        }
        Ok(Step::Next)
    }

    fn interpolation(
        &self,
        lane: usize,
        instr: &Instr,
        sample: &Operand,
    ) -> Result<Interpolation, Error> {
        Ok(match instr.modifier(Mod::Interpolation).unwrap_or(0) {
            interpolation::SAMPLE | interpolation::SAMPLE_REGISTER => {
                Interpolation::Sample(self.bits(lane, sample, 0)? as u32)
            }
            interpolation::CENTROID => Interpolation::Centroid,
            _ => Interpolation::Center,
        })
    }

    /// A coefficient register named directly or through a register.
    fn coefficient_index(&self, lane: usize, operand: &Operand) -> Result<u32, Error> {
        match operand.value {
            Value::Cf(cf) => Ok(u32::from(cf)),
            _ => Ok(self.bits(
                lane,
                &Operand {
                    size: 16,
                    ..*operand
                },
                0,
            )? as u32),
        }
    }

    /// The depth and stencil a `zs` operand carries.
    fn depth_stencil(&self, lane: usize, zs: &Operand) -> Result<(Option<f32>, Option<u8>), Error> {
        match zs.value {
            Value::None => Ok((None, None)),
            Value::Reg(_) if zs.count == 3 => {
                let low = self.bits(lane, zs, 0)?;
                let high = self.bits(lane, zs, 1)?;
                let stencil = self.bits(lane, zs, 2)?;
                let depth = f32::from_bits((low | high << 16) as u32);
                Ok((Some(depth), Some(stencil as u8)))
            }
            Value::Reg(_) if zs.size == 32 => {
                Ok((Some(f32::from_bits(self.bits(lane, zs, 0)? as u32)), None))
            }
            Value::Reg(_) => Ok((None, Some(self.bits(lane, zs, 0)? as u8))),
            _ => Err(Error::Refused(
                "a depth/stencil operand that is not a register",
            )),
        }
    }
}

/// `A x + B y + C`.
fn evaluate(plane: [f32; 3], at: [f32; 2]) -> f64 {
    f64::from(plane[0]) * f64::from(at[0])
        + f64::from(plane[1]) * f64::from(at[1])
        + f64::from(plane[2])
}

#[cfg(test)]
mod tests {
    use super::super::machine::tests::{Flat, finish, setup};
    use super::super::machine::{ExecError, Fault, Memory};
    use super::*;
    use alloc::vec::Vec;

    /// A fragment stage over [`Flat`] memory with fixed planes and a tile.
    struct Fragment {
        memory: Flat,
        planes: Vec<[f32; 3]>,
        tile: [[u64; 4]; 32],
        stores: Vec<(usize, u32, u32)>,
        depth: Vec<(usize, Option<f32>, Option<u8>)>,
    }

    impl Memory for Fragment {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
            self.memory.read(address, buffer)
        }
        fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault> {
            self.memory.write(address, data)
        }
    }

    impl Env for Fragment {
        fn coefficient(&mut self, cf: u32) -> Result<[f32; 3], &'static str> {
            self.planes
                .get(cf as usize)
                .copied()
                .ok_or("no such coefficient register")
        }
        fn interpolation_point(
            &mut self,
            lane: usize,
            _mode: Interpolation,
        ) -> Result<[f32; 2], &'static str> {
            Ok([lane as f32 + 0.5, 0.5])
        }
        fn tile_load(&mut self, access: &TileAccess) -> Result<[u64; 4], &'static str> {
            Ok(self.tile[access.lane])
        }
        fn tile_store(
            &mut self,
            access: &TileAccess,
            values: [u64; 4],
        ) -> Result<(), &'static str> {
            self.tile[access.lane] = values;
            Ok(())
        }
        fn zs_emit(
            &mut self,
            lane: usize,
            _mask: u32,
            depth: Option<f32>,
            stencil: Option<u8>,
        ) -> Result<bool, &'static str> {
            self.depth.push((lane, depth, stencil));
            Ok(false)
        }
        fn store_varying(
            &mut self,
            lane: usize,
            slot: u32,
            value: u32,
        ) -> Result<(), &'static str> {
            self.stores.push((lane, slot, value));
            Ok(())
        }
    }

    fn fragment(text: &str, threads: usize) -> (Fragment, SimdGroup) {
        let (memory, group) = setup(&alloc::format!("{text}\nstop"), threads);
        let env = Fragment {
            memory,
            planes: alloc::vec![[1.0, 2.0, 3.0], [0.0, 0.0, 0.5], [0.0, 0.0, 4.0]],
            tile: [[0; 4]; 32],
            stores: Vec::new(),
            depth: Vec::new(),
        };
        (env, group)
    }

    fn run(env: &mut Fragment, group: &mut SimdGroup) -> Result<(), ExecError> {
        group
            .run(
                &mut super::super::machine::Program::default(),
                env,
                &mut 1000,
            )
            .map(|_| ())
    }

    #[test]
    fn iteration_evaluates_planes_and_projects() {
        let (mut env, mut group) = fragment("iter r6, cf1\niter r7, cf0\nldcf r8_r9_r10, cf0", 2);
        run(&mut env, &mut group).unwrap();
        for lane in 0..2 {
            let x = lane as f32 + 0.5;
            assert_eq!(f32::from_bits(group.reg32(lane, 12)), 0.5);
            assert_eq!(f32::from_bits(group.reg32(lane, 14)), x + 1.0 + 3.0);
            assert_eq!(f32::from_bits(group.reg32(lane, 20)), 3.0);
        }
    }

    #[test]
    fn varyings_and_depth_reach_the_stage() {
        let (mut env, mut group) = fragment("st_var r1, 2\nzs_emit 255, r2", 2);
        for lane in 0..2 {
            group.set_reg32(lane, 2, 40 + lane as u32);
            group.set_reg32(lane, 4, 0.25f32.to_bits());
        }
        run(&mut env, &mut group).unwrap();
        assert_eq!(env.stores, [(0, 2, 40), (1, 2, 41)]);
        assert_eq!(env.depth, [(0, Some(0.25), None), (1, Some(0.25), None)]);
    }

    #[test]
    fn tile_stores_carry_the_masked_components() {
        let (mut env, mut group) = fragment("st_tile r0_r1_r2_r3, 0, 255, 0, u8norm, xyzw", 1);
        // r0l is the nesting counter; the stored registers start at r0.
        group.set_reg32(0, 2, 7);
        run(&mut env, &mut group).unwrap();
        assert_eq!(env.tile[0][1], 7);
    }

    #[test]
    fn stage_effects_outside_their_stage_refuse() {
        let (mut memory, mut group) = setup("iter r6, cf1\nstop", 1);
        assert!(matches!(
            finish(&mut group, &mut memory),
            Err(ExecError::Refused { op: Op::Iter, .. })
        ));
    }
}
