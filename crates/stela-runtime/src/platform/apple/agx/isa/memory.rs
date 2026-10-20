//! Memory: device `load`/`store`/`atomic`, threadgroup `lload`/`lstore`/
//! `latomic`, the per-thread stack, uniform stores from the preamble, and
//! the texture and sampler state loads.
//!
//! Addressing (Public: Mesa `agx_nir_lower_address.c`, `agx_compile.c`,
//! `agx_pack.c`, `agx_lower_spill.c`):
//! - Device: a 64-bit base plus the index shifted by `shift` and scaled by
//!   the format's element size; component `c` of the mask is element `c`
//!   after it. A register index is sign- or zero-extended by its `zx` bit,
//!   an immediate is the encoded signed or unsigned 16-bit value. Atomics
//!   scale a 32-bit index by 4 with no shift (`shift_must_match`).
//! - Threadgroup memory: a 16-bit byte base (register, uniform or zero) plus
//!   the index scaled by the element size (Inferred: Mesa always passes a
//!   zero index).
//! - The stack: a byte offset (Mesa spills at `stack_offs_B`), shifted by
//!   `shift`, into the thread's scratch, which `stack_adjust` grows and
//!   shrinks in 4-byte units (Mesa reserves `DIV_ROUND_UP(bytes, 4) + 10`);
//!   an access past the adjusted size refuses.
//! - `cmpxchg` takes its operands as a register pair (new, compare) (Mesa
//!   `agx_emit_atomic`) and returns the old value like every atomic.
//! - Loaded components fill consecutive destination registers in mask
//!   order (Inferred for gapped masks; Mesa only emits prefix masks).
//!
//! Every thread's access completes in lane order (Inferred: the order of
//! simultaneous atomics in one group is not architecturally visible beyond
//! their returned values, and Metal leaves it unspecified).
//! `uniform_store` copies the lowest active thread's registers into the
//! shared uniform file (the preamble runs one thread). `tex_state_store` and
//! `sampler_state_store` load a 24-byte texture descriptor, or an 8-byte
//! sampler with its 16-byte border when the shader declares extended
//! samplers, from a heap address plus a byte offset (Mesa
//! `agx_emit_store_preamble`, `nir_bindless_image_agx(offset_B)`).
//! `uniform_store_unk` has no published semantics and refuses.

use super::decode::{Instr, Operand, Value};
use super::generated::{Mod, Op};
use super::machine::{
    Env, Error, SAMPLER_STATE_BYTES, SimdGroup, Step, TEXTURE_STATE_BYTES, UNIFORM_HALVES, lanes,
};
use crate::platform::apple::agx::format::isa::IsaFormat;

/// Bytes of a sampler descriptor (cmdbuf.xml `Sampler`).
const SAMPLER_BYTES: usize = 8;
/// Bytes per `stack_adjust` unit.
const STACK_UNIT: i64 = 4;
/// Bytes of an atomic's operand.
const ATOMIC_BYTES: usize = 4;

/// `atomic` operations (`AGX2.xml` enum `atomic`).
mod atomic {
    pub const ADD: u32 = 0;
    pub const SUB: u32 = 1;
    pub const XCHG: u32 = 2;
    pub const CMPXCHG: u32 = 3;
    pub const UMIN: u32 = 4;
    pub const IMIN: u32 = 5;
    pub const UMAX: u32 = 6;
    pub const IMAX: u32 = 7;
    pub const AND: u32 = 8;
    pub const OR: u32 = 9;
    pub const XOR: u32 = 10;
}

/// Where an access goes.
#[derive(Clone, Copy)]
enum Space {
    Device,
    Threadgroup,
    Stack(usize),
}

impl SimdGroup {
    pub(super) fn memory(&mut self, instr: &Instr, env: &mut dyn Env) -> Result<Step, Error> {
        use Op::*;
        let active = self.active();
        match instr.op() {
            Load | Store | Lload | Lstore | StackLoad | StackStore => {
                let format = format(instr)?;
                let mask = instr.modifier(Mod::Mask).unwrap_or(0);
                let shift = instr.modifier(Mod::Shift).unwrap_or(0);
                let threads = if matches!(instr.op(), Store | Lstore) {
                    self.effective()
                } else {
                    active
                };
                for lane in lanes(threads) {
                    let (space, data, address) = match instr.op() {
                        Load => (
                            Space::Device,
                            instr.dest(),
                            self.device_address(lane, instr, 0, 1)?,
                        ),
                        Store => (
                            Space::Device,
                            instr.source(0),
                            self.device_address(lane, instr, 1, 2)?,
                        ),
                        Lload => (
                            Space::Threadgroup,
                            instr.dest(),
                            self.local_address(lane, instr, 0, 1, format)?,
                        ),
                        Lstore => (
                            Space::Threadgroup,
                            instr.source(0),
                            self.local_address(lane, instr, 1, 2, format)?,
                        ),
                        StackLoad => (
                            Space::Stack(lane),
                            instr.dest(),
                            self.stack_offset(lane, instr, 0)?,
                        ),
                        _ => (
                            Space::Stack(lane),
                            instr.source(0),
                            self.stack_offset(lane, instr, 1)?,
                        ),
                    };
                    let scale = match instr.op() {
                        Load | Store => format.element_bytes() as i128,
                        _ => 1,
                    };
                    let offset = address.1 << shift;
                    let start = address.0 as i128 + offset * scale;
                    let load = matches!(instr.op(), Load | Lload | StackLoad);
                    if load {
                        self.load_lane(env, space, lane, &data, start, format, mask)?;
                    } else {
                        self.store_lane(env, space, lane, &data, start, format, mask)?;
                    }
                }
                Ok(Step::Next)
            }
            Atomic | Latomic => {
                let operation = instr.modifier(Mod::Op).unwrap_or(0);
                // Helpers perform no atomics; their destinations keep their
                // values.
                for lane in lanes(self.effective()) {
                    let address = if instr.op() == Atomic {
                        let (base, index) = self.device_address(lane, instr, 1, 2)?;
                        (Space::Device, base as i128 + index * ATOMIC_BYTES as i128)
                    } else {
                        let (base, index) =
                            self.local_address(lane, instr, 1, 2, IsaFormat::I32)?;
                        (
                            Space::Threadgroup,
                            base as i128 + index * ATOMIC_BYTES as i128,
                        )
                    };
                    self.atomic_lane(env, lane, instr, operation, address)?;
                }
                Ok(Step::Next)
            }
            StackAdjust => {
                let amount = self.int(self.first_lane(active), &instr.source(0))? as i64;
                let size = i64::from(self.stack_pointer) + amount * STACK_UNIT;
                if size < 0 || size > i64::from(self.stack_limit) {
                    return Err(Error::Refused(
                        "stack_adjust past the shader's scratch allocation",
                    ));
                }
                self.stack_pointer = size as u32;
                for stack in self.stack.iter_mut() {
                    stack.resize(size as usize, 0);
                }
                Ok(Step::Next)
            }
            UniformStore => {
                let lane = self.first_lane(active);
                let (dest, source) = (instr.dest(), instr.source(0));
                let Value::Uniform(base) = dest.value else {
                    return Err(Error::Refused("a uniform store to a non-uniform"));
                };
                let halves = usize::from(dest.size / 16);
                for component in 0..usize::from(dest.count) {
                    let value = self.bits(lane, &source, component)?;
                    for half in 0..halves {
                        let at = usize::from(base) + component * halves + half;
                        if at >= UNIFORM_HALVES {
                            return Err(Error::Refused("a uniform past the uniform file"));
                        }
                        self.uniforms[at] = (value >> (16 * half)) as u16;
                    }
                }
                Ok(Step::Next)
            }
            UniformStoreUnk => Err(Error::Refused(
                "uniform_store_unk has no published semantics",
            )),
            TexStateStore | SamplerStateStore => {
                let lane = self.first_lane(active);
                let heap = self.bits(lane, &instr.source(0), 0)?;
                let offset = self.bits(lane, &instr.source(1), 0)? & 0xffff_ffff;
                let address = heap.wrapping_add(offset);
                if instr.op() == TexStateStore {
                    let Value::Ts(register) = instr.dest().value else {
                        unreachable!("tex_state_store names a texture state register")
                    };
                    let mut state = [0u8; TEXTURE_STATE_BYTES];
                    env.read(address, &mut state)?;
                    self.textures[usize::from(register)] = Some(state);
                } else {
                    let Value::Ss(register) = instr.dest().value else {
                        unreachable!("sampler_state_store names a sampler state register")
                    };
                    let mut state = [0u8; SAMPLER_STATE_BYTES];
                    let bytes = if self.extended_samplers {
                        SAMPLER_STATE_BYTES
                    } else {
                        SAMPLER_BYTES
                    };
                    env.read(address, &mut state[..bytes])?;
                    self.samplers[usize::from(register)] = Some(state);
                }
                Ok(Step::Next)
            }
            other => unreachable!("{other:?} is not a memory instruction"),
        }
    }

    /// The lowest active thread, or the lowest present one when none is
    /// active (a uniform effect still names one thread's registers).
    pub(super) fn first_lane(&self, active: u32) -> usize {
        let threads = if active != 0 { active } else { self.present };
        threads.trailing_zeros() as usize % super::machine::SIMD_WIDTH
    }

    /// A device base and (extended) index from sources `base` and `index`.
    fn device_address(
        &self,
        lane: usize,
        instr: &Instr,
        base: usize,
        index: usize,
    ) -> Result<(u64, i128), Error> {
        let base = self.bits(lane, &instr.source(base), 0)?;
        let index_operand = instr.source(index);
        let index = match index_operand.value {
            Value::Imm(value) => i128::from(value),
            _ => self.int(lane, &index_operand)?,
        };
        Ok((base, index))
    }

    /// A threadgroup byte base and element index, pre-scaled.
    fn local_address(
        &self,
        lane: usize,
        instr: &Instr,
        base: usize,
        index: usize,
        format: IsaFormat,
    ) -> Result<(u64, i128), Error> {
        let base = self.bits(lane, &instr.source(base), 0)? & 0xffff;
        let index = match instr.source(index).value {
            Value::Imm(value) => i128::from(value),
            _ => i128::from(super::machine::sign_extend(
                self.bits(lane, &instr.source(index), 0)?,
                16,
            )),
        };
        Ok((base, index * format.element_bytes() as i128))
    }

    fn stack_offset(&self, lane: usize, instr: &Instr, index: usize) -> Result<(u64, i128), Error> {
        let operand = instr.source(index);
        let offset = match operand.value {
            Value::Imm(value) => i128::from(value),
            _ => self.int(lane, &operand)?,
        };
        Ok((0, offset))
    }

    #[allow(clippy::too_many_arguments)]
    fn load_lane(
        &mut self,
        env: &mut dyn Env,
        space: Space,
        lane: usize,
        dest: &Operand,
        start: i128,
        format: IsaFormat,
        mask: u32,
    ) -> Result<(), Error> {
        let bits = u32::from(dest.size);
        if format.packed() {
            check_packed_mask(format, mask)?;
            let mut word = [0u8; 4];
            self.access(env, space, start, &mut word, false)?;
            let values = format.load_packed(u32::from_le_bytes(word), bits);
            for (slot, component) in (0..4).filter(|c| mask >> c & 1 != 0).enumerate() {
                self.put(lane, dest, slot, values[component])?;
            }
            return Ok(());
        }
        let size = format.element_bytes();
        for (slot, component) in (0..4).filter(|c| mask >> c & 1 != 0).enumerate() {
            let mut element = [0u8; 4];
            let at = start + (component * size) as i128;
            self.access(env, space, at, &mut element[..size], false)?;
            let value = format.load(component, &element[..size], bits);
            self.put(lane, dest, slot, value)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn store_lane(
        &mut self,
        env: &mut dyn Env,
        space: Space,
        lane: usize,
        source: &Operand,
        start: i128,
        format: IsaFormat,
        mask: u32,
    ) -> Result<(), Error> {
        let bits = u32::from(source.size);
        if format.packed() {
            check_packed_mask(format, mask)?;
            let mut components = [0u64; 4];
            for (slot, component) in (0..4).filter(|c| mask >> c & 1 != 0).enumerate() {
                components[component] = self.bits(lane, source, slot)?;
            }
            let mut word = format.store_packed(components, bits).to_le_bytes();
            return self.access(env, space, start, &mut word, true);
        }
        let size = format.element_bytes();
        for (slot, component) in (0..4).filter(|c| mask >> c & 1 != 0).enumerate() {
            let value = self.bits(lane, source, slot)?;
            let mut element = format.store(component, value, bits);
            let at = start + (component * size) as i128;
            self.access(env, space, at, &mut element[..size], true)?;
        }
        Ok(())
    }

    fn atomic_lane(
        &mut self,
        env: &mut dyn Env,
        lane: usize,
        instr: &Instr,
        operation: u32,
        (space, address): (Space, i128),
    ) -> Result<(), Error> {
        let source = instr.source(0);
        let value = self.bits(lane, &source, 0)? as u32;
        let mut bytes = [0u8; ATOMIC_BYTES];
        self.access(env, space, address, &mut bytes, false)?;
        let old = u32::from_le_bytes(bytes);
        let new = match operation {
            atomic::ADD => old.wrapping_add(value),
            atomic::SUB => old.wrapping_sub(value),
            atomic::XCHG => value,
            atomic::CMPXCHG => {
                let compare = self.bits(lane, &source, 1)? as u32;
                if old == compare { value } else { old }
            }
            atomic::UMIN => old.min(value),
            atomic::IMIN => (old as i32).min(value as i32) as u32,
            atomic::UMAX => old.max(value),
            atomic::IMAX => (old as i32).max(value as i32) as u32,
            atomic::AND => old & value,
            atomic::OR => old | value,
            atomic::XOR => old ^ value,
            _ => return Err(Error::Refused("an atomic operation the enumeration lacks")),
        };
        let mut bytes = new.to_le_bytes();
        self.access(env, space, address, &mut bytes, true)?;
        self.put(lane, &instr.dest(), 0, u64::from(old))
    }

    /// Read into or write from `buffer` at `address` in `space`.
    fn access(
        &mut self,
        env: &mut dyn Env,
        space: Space,
        address: i128,
        buffer: &mut [u8],
        write: bool,
    ) -> Result<(), Error> {
        let length = buffer.len() as i128;
        match space {
            Space::Device => {
                let address = address as u64;
                if write {
                    env.write(address, buffer)?;
                } else {
                    env.read(address, buffer)?;
                }
                Ok(())
            }
            Space::Threadgroup => {
                let memory = env.threadgroup().ok_or(Error::Refused(
                    "threadgroup memory outside a compute or tile shader",
                ))?;
                if address < 0 || address + length > memory.len() as i128 {
                    return Err(Error::Refused(
                        "a threadgroup-memory access past the allocation",
                    ));
                }
                let range = address as usize..(address + length) as usize;
                if write {
                    memory[range].copy_from_slice(buffer);
                } else {
                    buffer.copy_from_slice(&memory[range]);
                }
                Ok(())
            }
            Space::Stack(lane) => {
                let stack = &mut self.stack[lane];
                if address < 0 || address + length > stack.len() as i128 {
                    return Err(Error::Refused("a stack access past the adjusted scratch"));
                }
                let range = address as usize..(address + length) as usize;
                if write {
                    stack[range].copy_from_slice(buffer);
                } else {
                    buffer.copy_from_slice(&stack[range]);
                }
                Ok(())
            }
        }
    }
}

/// The instruction's format, refusing values the description lacks.
fn format(instr: &Instr) -> Result<IsaFormat, Error> {
    IsaFormat::from_field(instr.modifier(Mod::Format).unwrap_or(0))
        .ok_or(Error::Refused("a memory format the description lacks"))
}

fn check_packed_mask(format: IsaFormat, mask: u32) -> Result<(), Error> {
    if mask >> format.packed_components() != 0 {
        return Err(Error::Refused("a component a packed format does not hold"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::machine::tests::{CODE, Flat, finish, setup};
    use super::super::machine::{ExecError, Exit};
    use super::*;

    const DATA: u64 = CODE + 0x8000;

    /// Point `du0` (uniform halves 0..4) at the data area.
    fn with_data(text: &str, threads: usize) -> (Flat, SimdGroup) {
        let (memory, mut group) = setup(&alloc::format!("{text}\nstop"), threads);
        group.set_uniform64(0, DATA);
        (memory, group)
    }

    #[test]
    fn device_loads_and_stores_scale_the_index() {
        let (mut memory, mut group) = with_data(
            "load r4_r5, du0, r2, i32, xy, a\n\
             store r4, du0, 16, i16, x, a",
            2,
        );
        memory.put(DATA, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
        group.set_reg32(1, 4, 1);
        assert_eq!(finish(&mut group, &mut memory), Ok(Exit::Stopped));
        assert_eq!((group.reg32(0, 8), group.reg32(0, 10)), (1, 2));
        assert_eq!((group.reg32(1, 8), group.reg32(1, 10)), (2, 3));
        // Both threads store their x to element 16 of i16: lane 1 last.
        assert_eq!(memory.get(DATA + 32, 2), &[2, 0]);
    }

    #[test]
    fn normalized_loads_produce_floats() {
        let (mut memory, mut group) = with_data("load r4, du0, 0, u8norm, x, a", 1);
        memory.put(DATA, &[255]);
        finish(&mut group, &mut memory).unwrap();
        assert_eq!(f32::from_bits(group.reg32(0, 8)), 1.0);
    }

    #[test]
    fn atomics_return_the_old_value() {
        let (mut memory, mut group) = with_data(
            "atomic r4, r2, du0, 0, add, coherent1, a\n\
             atomic r6, r8_r9, du0, 1, cmpxchg, coherent1, a",
            3,
        );
        memory.put(DATA, &10u32.to_le_bytes());
        memory.put(DATA + 4, &5u32.to_le_bytes());
        for lane in 0..3 {
            group.set_reg32(lane, 4, 1);
            // Swap in 100 + lane where the value is still 5.
            group.set_reg32(lane, 16, 100 + lane as u32);
            group.set_reg32(lane, 18, 5);
        }
        finish(&mut group, &mut memory).unwrap();
        assert_eq!(memory.u32(DATA), 13);
        assert_eq!([0, 1, 2].map(|lane| group.reg32(lane, 8)), [10, 11, 12]);
        assert_eq!(memory.u32(DATA + 4), 100);
        assert_eq!([0, 1, 2].map(|lane| group.reg32(lane, 12)), [5, 100, 100]);
    }

    #[test]
    fn the_stack_is_bounded_by_its_adjustment() {
        let (mut memory, mut group) = with_data(
            "stack_store r4, 0, i32, x, a\nstack_load r6, 0, i32, x, a",
            1,
        );
        assert!(matches!(
            finish(&mut group, &mut memory),
            Err(ExecError::Refused {
                op: Op::StackStore,
                ..
            })
        ));
        let (mut memory, mut group) = with_data(
            "stack_adjust 1\nstack_store r4, 0, i32, x, a\nstack_load r6, 0, i32, x, a",
            1,
        );
        group.stack_limit = 64;
        group.set_reg32(0, 8, 0xabcd);
        finish(&mut group, &mut memory).unwrap();
        assert_eq!(group.reg32(0, 12), 0xabcd);
    }

    #[test]
    fn uniform_stores_write_the_shared_file() {
        let (mut memory, mut group) = with_data("mov u72, r2", 1);
        group.set_reg32(0, 4, 0x1234_5678);
        finish(&mut group, &mut memory).unwrap();
        assert_eq!((group.uniforms[144], group.uniforms[145]), (0x5678, 0x1234));
    }
}
