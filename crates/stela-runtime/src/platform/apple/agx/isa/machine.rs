//! The SIMD-group interpreter: 32 threads in lockstep over the AGX2 register
//! files, with `r0l` as each thread's nesting counter.
//!
//! State (Public: Mesa's compiler README and `AGX2.xml`; applegpu):
//! - Each thread has 256 16-bit register halves (`r0l` .. `r127h`). A 32-bit
//!   operand is an even-aligned pair, a 64-bit operand two pairs; a vector
//!   operand is consecutive registers of its size.
//! - The SIMD group shares 512 uniform halves, the texture and sampler state
//!   registers, and the program counter.
//! - `r0l` counts how many `pop_exec` operations re-enable an inactive
//!   thread; a thread is active iff it is present and its `r0l` is zero.
//!   Ordinary instructions write active threads only.
//!
//! The run loop fetches through [`Env::read`] at the program counter (a GPU
//! virtual address), decodes once per address, and dispatches to the
//! instruction families (`alu`, `flow`, `lanes`, `memory`, `texture`,
//! `stage`). Every effect the decoder accepts but no model covers refuses
//! with its opcode, so no instruction is ever skipped.

use super::decode::{DecodeError, Instr, MAX_BYTES, Operand, Value, decode};
use super::float::{f64_to_f32_ftz, f64_to_half, half_to_f32, minifloat};
use super::generated::Op;
use crate::platform::apple::agx::format::image::ImageError;
use crate::platform::apple::agx::format::isa::IsaFormat;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Threads per SIMD group.
pub const SIMD_WIDTH: usize = 32;
/// 16-bit register halves per thread.
pub const REGISTER_HALVES: usize = 256;
/// 16-bit uniform halves per SIMD group.
pub const UNIFORM_HALVES: usize = 512;
/// Bytes of one texture state register (a texture or PBE descriptor).
pub const TEXTURE_STATE_BYTES: usize = 24;
/// Bytes of one sampler state register (a sampler descriptor and, for
/// extended states, its border colour).
pub const SAMPLER_STATE_BYTES: usize = 24;
/// Texture and sampler state registers per SIMD group (the `ts`/`ss` fields
/// are seven bits wide in `tex_state_store`).
pub const STATE_REGISTERS: usize = 128;

/// A memory access the address space refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub address: u64,
    pub write: bool,
}

/// A GPU virtual address space as the GPU reaches it (through the job's
/// UAT context).
pub trait Memory {
    /// Read GPU memory at a virtual address.
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault>;
    /// Write GPU memory at a virtual address.
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault>;
}

/// Why a SIMD group stopped before finishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// The word at `pc` does not decode.
    Decode { pc: u64, error: DecodeError },
    /// Code fetch or a data access faulted.
    Fault { pc: u64, fault: Fault },
    /// The instruction is decoded but its effect is not modeled, or its
    /// operands are outside what the hardware defines; `reason` names it.
    Refused {
        pc: u64,
        op: Op,
        reason: &'static str,
    },
    /// `trap` executed.
    Trap { pc: u64 },
    /// The step budget ran out (a runaway loop).
    Runaway { pc: u64 },
}

impl ExecError {
    pub fn pc(&self) -> u64 {
        match *self {
            ExecError::Decode { pc, .. }
            | ExecError::Fault { pc, .. }
            | ExecError::Refused { pc, .. }
            | ExecError::Trap { pc }
            | ExecError::Runaway { pc } => pc,
        }
    }
}

/// How a SIMD group left [`SimdGroup::run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// `stop` executed: the group is finished.
    Stopped,
    /// `barrier` executed: the group waits for the rest of its threadgroup
    /// and resumes at the following instruction.
    Barrier,
}

/// What an instruction asks of the run loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    Next,
    Jump(u64),
    Exit(Exit),
}

/// Values of the special registers a stage provides (`mfsr`). Per-thread
/// values are indexed by lane; `None` refuses the read by name.
#[derive(Debug, Clone, Default)]
pub struct Specials {
    pub threadgroup_in_grid: Option<[u32; 3]>,
    pub threads_per_threadgroup: Option<[u32; 3]>,
    pub dispatch_threads_per_threadgroup: Option<[u32; 3]>,
    /// Tile width and height in pixels (fragment).
    pub threadgroup_size: Option<[u32; 2]>,
    pub samples_log2: Option<u32>,
    pub core_index: Option<u32>,
    pub vm_slot: Option<u32>,
    pub simdgroup_index_in_threadgroup: Option<u32>,
    pub thread_in_threadgroup: Option<[[u32; 3]; SIMD_WIDTH]>,
    pub thread_index_in_threadgroup: Option<[u32; SIMD_WIDTH]>,
    pub thread_in_grid: Option<[[u32; 3]; SIMD_WIDTH]>,
    pub internal_coverage_mask: Option<[u32; SIMD_WIDTH]>,
    pub backfacing: Option<[u32; SIMD_WIDTH]>,
    pub input_sample_mask: Option<[u32; SIMD_WIDTH]>,
}

/// The effects a SIMD group has outside its own state. Memory is required;
/// every stage-specific effect defaults to a named refusal, and each stage
/// implements the ones it has.
pub trait Env: Memory {
    /// The threadgroup's memory (compute; the imageblock in fragment).
    fn threadgroup(&mut self) -> Option<&mut [u8]> {
        None
    }

    /// Store a 32-bit vertex output into UVS `slot` (`st_var`).
    fn store_varying(&mut self, _lane: usize, _slot: u32, _value: u32) -> Result<(), &'static str> {
        Err("st_var outside a vertex shader")
    }

    /// The vertex shader declares no outputs (`no_var`).
    fn no_varyings(&mut self) -> Result<(), &'static str> {
        Err("no_var outside a vertex shader")
    }

    /// Coefficient register `cf` component `component`: the plane
    /// `a * x + b * y + c` over the primitive (fragment).
    fn coefficient(&mut self, _cf: u32) -> Result<[f32; 3], &'static str> {
        Err("coefficient registers outside a fragment shader")
    }

    /// The position `iter` evaluates coefficients at for `lane`: the pixel
    /// centre, the sample `sample` or the centroid (fragment).
    fn interpolation_point(
        &mut self,
        _lane: usize,
        _mode: Interpolation,
    ) -> Result<[f32; 2], &'static str> {
        Err("iter outside a fragment shader")
    }

    /// Load the masked components of a tilebuffer pixel (`ld_tile`), as
    /// register bits in mask order.
    fn tile_load(&mut self, _access: &TileAccess) -> Result<[u64; 4], &'static str> {
        Err("ld_tile outside a fragment shader")
    }

    /// Store the masked components (register bits in mask order) into a
    /// tilebuffer pixel (`st_tile`).
    fn tile_store(&mut self, _access: &TileAccess, _values: [u64; 4]) -> Result<(), &'static str> {
        Err("st_tile outside a fragment shader")
    }

    /// `sample_mask target, live`: of the samples in `target`, test those in
    /// `live` and kill the rest (Mesa `agx_nir_lower_sample_mask.c`).
    /// Returns whether the thread has no sample left, which demotes it to a
    /// helper.
    fn sample_mask(
        &mut self,
        _lane: usize,
        _target: u32,
        _live: u32,
    ) -> Result<bool, &'static str> {
        Err("sample_mask outside a fragment shader")
    }

    /// Emit depth and/or stencil for the samples in `mask` and run their
    /// tests (`zs_emit`). Returns whether the thread has no sample left.
    fn zs_emit(
        &mut self,
        _lane: usize,
        _mask: u32,
        _depth: Option<f32>,
        _stencil: Option<u8>,
    ) -> Result<bool, &'static str> {
        Err("zs_emit outside a fragment shader")
    }

    /// Entry `index` of the job's sampler heap (8-byte samplers), for a
    /// sample whose sampler is a register index.
    fn sampler_heap(&mut self, _index: u32) -> Result<[u8; 8], &'static str> {
        Err("a sampler-heap index in a job without a sampler heap")
    }

    /// `imgwblk`: store a render target of the current tile into the image
    /// a PBE descriptor names.
    fn block_store(&mut self, _store: &BlockStore) -> Result<(), ImageError> {
        Err(ImageError::Refused(
            "imgwblk outside an end-of-tile program",
        ))
    }
}

/// One `imgwblk`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStore {
    /// Byte offset of the render target within a tilebuffer sample.
    pub offset: u32,
    /// The tilebuffer's physical format of the target.
    pub format: IsaFormat,
    /// The PBE descriptor.
    pub pbe: [u8; TEXTURE_STATE_BYTES],
    /// The layer of a layered render.
    pub layer: u32,
}

/// Where `iter` evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interpolation {
    Center,
    Sample(u32),
    Centroid,
}

/// One thread's tilebuffer access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TileAccess {
    pub lane: usize,
    /// Byte offset of the render target within a sample (Mesa
    /// `agx_tilebuffer_offset_B`).
    pub offset: u32,
    pub format: IsaFormat,
    /// Components accessed.
    pub mask: u32,
    /// Samples addressed (a mask).
    pub samples: u32,
    /// Explicit pixel coordinates within the tile, when given.
    pub coords: Option<[u32; 2]>,
    /// Bits of each register component (16 or 32).
    pub register_bits: u32,
}

/// Decoded instructions by address, shared by the SIMD groups of a launch.
#[derive(Debug, Default)]
pub struct Program {
    decoded: BTreeMap<u64, Instr>,
}

impl Program {
    fn fetch(&mut self, env: &mut dyn Env, pc: u64) -> Result<Instr, ExecError> {
        if let Some(instr) = self.decoded.get(&pc) {
            return Ok(*instr);
        }
        // Read as much of the longest form as is mapped: code may end at a
        // page with nothing after it.
        let mut bytes = [0u8; MAX_BYTES];
        let mut available = MAX_BYTES;
        while env.read(pc, &mut bytes[..available]).is_err() {
            if available == 2 {
                return Err(ExecError::Fault {
                    pc,
                    fault: Fault {
                        address: pc,
                        write: false,
                    },
                });
            }
            available /= 2;
        }
        let instr = decode(&bytes[..available]).map_err(|error| ExecError::Decode { pc, error })?;
        self.decoded.insert(pc, instr);
        Ok(instr)
    }
}

/// One SIMD group's architectural state.
pub struct SimdGroup {
    regs: Box<[[u16; REGISTER_HALVES]; SIMD_WIDTH]>,
    pub uniforms: [u16; UNIFORM_HALVES],
    /// Threads that exist (a partial group masks the rest).
    pub present: u32,
    /// Present threads that are fragment helpers (derivatives only).
    pub helpers: u32,
    /// Halves the USC `Registers` word allocates; accesses past it refuse.
    pub register_limit: usize,
    pub textures: [Option<[u8; TEXTURE_STATE_BYTES]>; STATE_REGISTERS],
    pub samplers: [Option<[u8; SAMPLER_STATE_BYTES]>; STATE_REGISTERS],
    /// The shader declares extended samplers: each sampler state carries
    /// its border colour (cmdbuf.xml `Sampler states` "extended").
    pub extended_samplers: bool,
    pub specials: Specials,
    /// Per-thread scratch (`stack_*`), grown by `stack_adjust`.
    pub(super) stack: Vec<Vec<u8>>,
    pub(super) stack_pointer: u32,
    /// Bytes of scratch per thread the USC spill size grants.
    pub stack_limit: u32,
    pub pc: u64,
    /// The base the `call`/`ret` link values are relative to: code
    /// addresses are 32-bit offsets from the USC execution base.
    pub code_base: u64,
}

impl SimdGroup {
    /// A group of `threads` present threads starting at `pc`, all registers
    /// zero and every present thread active.
    pub fn new(threads: usize, pc: u64) -> Self {
        let present = if threads >= SIMD_WIDTH {
            u32::MAX
        } else {
            (1u32 << threads) - 1
        };
        SimdGroup {
            regs: Box::new([[0; REGISTER_HALVES]; SIMD_WIDTH]),
            uniforms: [0; UNIFORM_HALVES],
            present,
            helpers: 0,
            register_limit: REGISTER_HALVES,
            textures: [None; STATE_REGISTERS],
            samplers: [None; STATE_REGISTERS],
            extended_samplers: false,
            specials: Specials::default(),
            stack: alloc::vec![Vec::new(); SIMD_WIDTH],
            stack_pointer: 0,
            stack_limit: 0,
            pc,
            code_base: pc & !0xffff_ffff,
        }
    }

    /// The active threads: present with a zero nesting counter.
    pub fn active(&self) -> u32 {
        let mut mask = 0;
        for lane in lanes(self.present) {
            if self.regs[lane][0] == 0 {
                mask |= 1 << lane;
            }
        }
        mask
    }

    /// The active threads whose side effects land: helpers compute values
    /// for their quad's derivatives but write no memory, tilebuffer or
    /// coverage (Vulkan and Metal helper invocations; Inferred for the
    /// hardware).
    pub fn effective(&self) -> u32 {
        self.active() & !self.helpers
    }

    /// A register half of a thread.
    pub fn half(&self, lane: usize, half: usize) -> u16 {
        self.regs[lane][half]
    }

    pub fn set_half(&mut self, lane: usize, half: usize, value: u16) {
        self.regs[lane][half] = value;
    }

    /// A 32-bit register (`index` in halves, even).
    pub fn reg32(&self, lane: usize, half: usize) -> u32 {
        u32::from(self.regs[lane][half]) | u32::from(self.regs[lane][half + 1]) << 16
    }

    pub fn set_reg32(&mut self, lane: usize, half: usize, value: u32) {
        self.regs[lane][half] = value as u16;
        self.regs[lane][half + 1] = (value >> 16) as u16;
    }

    pub fn set_uniform32(&mut self, half: usize, value: u32) {
        self.uniforms[half] = value as u16;
        self.uniforms[half + 1] = (value >> 16) as u16;
    }

    pub fn set_uniform64(&mut self, half: usize, value: u64) {
        self.set_uniform32(half, value as u32);
        self.set_uniform32(half + 2, (value >> 32) as u32);
    }

    /// Run until `stop` or a threadgroup barrier. `budget` counts down one
    /// per instruction.
    pub fn run(
        &mut self,
        program: &mut Program,
        env: &mut dyn Env,
        budget: &mut u64,
    ) -> Result<Exit, ExecError> {
        loop {
            if *budget == 0 {
                return Err(ExecError::Runaway { pc: self.pc });
            }
            *budget -= 1;
            let pc = self.pc;
            let instr = program.fetch(env, pc)?;
            let step = self
                .execute(&instr, env)
                .map_err(|error| error.at(pc, instr.op()))?;
            match step {
                Step::Next => self.pc = pc + instr.len as u64,
                Step::Jump(target) => self.pc = target,
                Step::Exit(exit) => {
                    self.pc = pc + instr.len as u64;
                    return Ok(exit);
                }
            }
        }
    }

    fn execute(&mut self, instr: &Instr, env: &mut dyn Env) -> Result<Step, Error> {
        use Op::*;
        match instr.op() {
            Ldimm16 | Ldimm32 | Mfsr | Iadd | Isub | Imul | Imadd | Imsub | U8ToF | S8ToF
            | FToU16 | FToS16 | U16ToF | S16ToF | FToU32 | FToS32 | U32ToF | S32ToF | Shl | Shr
            | Bfi | Bfeil | Extr | Shlhi | Shrhi | Asr | Asrh | Ffma | Hfma | Fadd | Fmul
            | Hadd | Hmul | NotA | Mov | Not | MovA | Zero | And | Andn1 | Andn2 | Xor | Or
            | Nor | Xnor | Orn1 | Orn2 | Nand | One | Bitrev | Popcnt | Ffs | Intl | Floor
            | Rsqrts | Rcp | Rsqrt | Sinr | Sinc | Log2 | Exp2 | Ceil | Trunc | Rint | Icsel
            | Fcsel => self.alu(instr),
            Dfdx | Dfdy | Ballot | IcmpBallot | FcmpBallot | Shuffle | Quad | Simd => {
                self.lanes(instr)
            }
            Stop
            | Trap
            | JmpIncomplete
            | Ret
            | CallReg
            | JmpAny
            | Call
            | JmpNone
            | PopExec
            | IfIcmp
            | ElseIcmp
            | WhileIcmp
            | UpdateExec
            | IfFcmp
            | ElseFcmp
            | WhileFcmp
            | Barrier
            | Wait
            | Doorbell
            | JmpIfSkippingDoorbell
            | Pixwait
            | Pixrel
            | MemoryBarrier
            | ImageBarrier1
            | ImageBarrier2
            | ImageBarrier3
            | ImageBarrier4
            | FlushMemoryToTexture
            | MemoryBarrier2
            | MemoryBarrier3
            | UnknownBarrier1
            | UnknownBarrier2
            | DeviceBarrier1
            | DeviceBarrier2
            | Map
            | Unmap => self.flow(instr, env),
            Load | Store | Atomic | Latomic | StackLoad | StackStore | StackAdjust
            | UniformStore | UniformStoreUnk | TexStateStore | SamplerStateStore | Lload
            | Lstore => self.memory(instr, env),
            Smpf | Smpi | Imgw | Imgwblk => self.texture(instr, env),
            NoVar | StVar | LdTile | StTile | SampleMask | ZsEmit | Iter | Iterproj | Ldcf => {
                self.stage(instr, env)
            }
        }
    }

    // Operand access.

    /// Check a register operand of `halves` halves per component.
    fn register(&self, half: u16, halves: usize, count: usize) -> Result<usize, Error> {
        let half = usize::from(half);
        if halves > 1 && half % 2 != 0 {
            return Err(Error::Refused(
                "a 32- or 64-bit register operand on an odd half",
            ));
        }
        if half + halves * count > self.register_limit {
            return Err(Error::Refused("a register past the shader's allocation"));
        }
        Ok(half)
    }

    /// The raw bits of component `component` of a source (zero-extended to
    /// 64 bits). Immediates give their value; minifloats their f32 bits.
    pub(super) fn bits(
        &self,
        lane: usize,
        operand: &Operand,
        component: usize,
    ) -> Result<u64, Error> {
        let halves = usize::from(operand.size / 16);
        let read = |file: &[u16], base: usize| -> u64 {
            (0..halves).fold(0u64, |value, i| {
                value | u64::from(file[base + i]) << (16 * i)
            })
        };
        match operand.value {
            Value::Reg(half) => {
                let base = self.register(half, halves, component + 1)? + component * halves;
                Ok(read(&self.regs[lane][..], base))
            }
            Value::Uniform(half) => {
                let base = usize::from(half) + component * halves;
                if halves > 1 && half % 2 != 0 {
                    return Err(Error::Refused(
                        "a 32- or 64-bit uniform operand on an odd half",
                    ));
                }
                if base + halves > UNIFORM_HALVES {
                    return Err(Error::Refused("a uniform past the uniform file"));
                }
                Ok(read(&self.uniforms[..], base))
            }
            Value::Imm(value) => Ok(value as u64),
            Value::Fimm(value) => Ok(u64::from(minifloat(value).to_bits())),
            Value::None => Ok(0),
            Value::Cf(_) | Value::Ts(_) | Value::Ss(_) => {
                Err(Error::Refused("a state register as an ALU source"))
            }
        }
    }

    /// An integer source, extended to 64 bits by its `sx` flag (immediates
    /// are never sign-extended).
    pub(super) fn int(&self, lane: usize, operand: &Operand) -> Result<i128, Error> {
        let bits = self.bits(lane, operand, 0)?;
        if let Value::Imm(value) = operand.value {
            return Ok(i128::from(value));
        }
        let size = u32::from(operand.size);
        Ok(if operand.sx {
            i128::from(sign_extend(bits, size))
        } else {
            i128::from(bits)
        })
    }

    /// A float source as f64: halves exactly, f32 with denormals flushed,
    /// minifloats exactly; then `abs` and `neg` (applegpu `FloatSrc`).
    pub(super) fn float(&self, lane: usize, operand: &Operand) -> Result<f64, Error> {
        let bits = self.bits(lane, operand, 0)?;
        let mut value = match operand.value {
            Value::Fimm(byte) => f64::from(minifloat(byte)),
            Value::Imm(_) => return Err(Error::Refused("an integer immediate as a float source")),
            _ if operand.size == 16 => f64::from(half_to_f32(bits as u16)),
            _ if operand.size == 32 => f64::from(flush_f32(f32::from_bits(bits as u32))),
            _ => return Err(Error::Refused("a 64-bit float source")),
        };
        if operand.abs {
            value = value.abs();
        }
        if operand.neg {
            value = -value;
        }
        Ok(value)
    }

    /// Write `value`'s low bits to component `component` of a register
    /// destination of the operand's size.
    pub(super) fn put(
        &mut self,
        lane: usize,
        operand: &Operand,
        component: usize,
        value: u64,
    ) -> Result<(), Error> {
        let halves = usize::from(operand.size / 16);
        match operand.value {
            Value::Reg(half) => {
                let base = self.register(half, halves, component + 1)? + component * halves;
                for i in 0..halves {
                    self.regs[lane][base + i] = (value >> (16 * i)) as u16;
                }
                Ok(())
            }
            Value::None => Ok(()),
            _ => Err(Error::Refused("a destination that is not a register")),
        }
    }

    /// Write a float result rounded to the destination's size: halves to
    /// nearest even without flushing, f32 to nearest even with denormal
    /// results flushed (applegpu `saturate_and_set_thread_result`).
    pub(super) fn put_float(
        &mut self,
        lane: usize,
        dest: &Operand,
        value: f64,
    ) -> Result<(), Error> {
        let bits = match dest.size {
            16 => u64::from(f64_to_half(value)),
            32 => u64::from(f64_to_f32_ftz(value).to_bits()),
            _ => return Err(Error::Refused("a 64-bit float destination")),
        };
        self.put(lane, dest, 0, bits)
    }
}

/// An instruction-level failure, given its address by the run loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    Refused(&'static str),
    Fault(Fault),
    Trap,
}

impl Error {
    fn at(self, pc: u64, op: Op) -> ExecError {
        match self {
            Error::Refused(reason) => ExecError::Refused { pc, op, reason },
            Error::Fault(fault) => ExecError::Fault { pc, fault },
            Error::Trap => ExecError::Trap { pc },
        }
    }
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Error::Fault(fault)
    }
}

/// The lanes set in `mask`, lowest first.
pub(super) fn lanes(mask: u32) -> impl Iterator<Item = usize> {
    (0..SIMD_WIDTH).filter(move |lane| mask >> lane & 1 != 0)
}

pub(super) fn sign_extend(value: u64, bits: u32) -> i64 {
    if bits >= 64 {
        value as i64
    } else {
        ((value << (64 - bits)) as i64) >> (64 - bits)
    }
}

/// An f32 with a subnormal value flushed to a zero of its sign.
pub(super) fn flush_f32(value: f32) -> f32 {
    if value.is_subnormal() {
        f32::from_bits(value.to_bits() & 0x8000_0000)
    } else {
        value
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A flat little-endian GPU memory for tests: `bytes` at `base`.
    pub(crate) struct Flat {
        pub base: u64,
        pub bytes: Vec<u8>,
    }

    impl Flat {
        pub fn new(base: u64, size: usize) -> Self {
            Flat {
                base,
                bytes: alloc::vec![0; size],
            }
        }

        pub fn put(&mut self, address: u64, data: &[u8]) {
            let at = (address - self.base) as usize;
            self.bytes[at..at + data.len()].copy_from_slice(data);
        }

        pub fn get(&self, address: u64, length: usize) -> &[u8] {
            let at = (address - self.base) as usize;
            &self.bytes[at..at + length]
        }

        pub fn u32(&self, address: u64) -> u32 {
            u32::from_le_bytes(self.get(address, 4).try_into().unwrap())
        }
    }

    impl Env for Flat {}

    impl Memory for Flat {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
            let fault = Fault {
                address,
                write: false,
            };
            let at = address.checked_sub(self.base).ok_or(fault)? as usize;
            let bytes = self.bytes.get(at..at + buffer.len()).ok_or(fault)?;
            buffer.copy_from_slice(bytes);
            Ok(())
        }

        fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault> {
            let fault = Fault {
                address,
                write: true,
            };
            let at = address.checked_sub(self.base).ok_or(fault)? as usize;
            self.bytes
                .get_mut(at..at + data.len())
                .ok_or(fault)?
                .copy_from_slice(data);
            Ok(())
        }
    }

    pub(crate) const CODE: u64 = 0x1_0000_0000;

    /// Assemble `text` at [`CODE`] in a memory with room for data after it,
    /// and a group of `threads` threads at its start.
    pub(crate) fn setup(text: &str, threads: usize) -> (Flat, SimdGroup) {
        let code = super::super::assemble::program(text);
        let mut memory = Flat::new(CODE, 0x10000);
        memory.put(CODE, &code);
        (memory, SimdGroup::new(threads, CODE))
    }

    /// Run a group to `stop` with a generous budget.
    pub(crate) fn finish(group: &mut SimdGroup, memory: &mut Flat) -> Result<Exit, ExecError> {
        group.run(&mut Program::default(), memory, &mut 100_000)
    }

    #[test]
    fn the_nesting_counter_masks_threads() {
        let (mut memory, mut group) = setup("stop", 4);
        assert_eq!(group.active(), 0xf);
        group.set_half(1, 0, 2);
        assert_eq!(group.active(), 0b1101);
        assert_eq!(finish(&mut group, &mut memory), Ok(Exit::Stopped));
    }

    #[test]
    fn registers_outside_the_allocation_refuse() {
        let (mut memory, mut group) = setup("mov r10, r1\nstop", 1);
        group.register_limit = 16;
        assert!(matches!(
            finish(&mut group, &mut memory),
            Err(ExecError::Refused { op: Op::Mov, .. })
        ));
    }

    #[test]
    fn undecodable_and_unmapped_code_refuses() {
        let mut memory = Flat::new(CODE, 4);
        memory.put(CODE, &[0xff, 0xff]);
        let mut group = SimdGroup::new(1, CODE);
        assert!(matches!(
            finish(&mut group, &mut memory),
            Err(ExecError::Decode { pc: CODE, .. })
        ));
        let mut group = SimdGroup::new(1, CODE + 0x100);
        assert!(matches!(
            finish(&mut group, &mut memory),
            Err(ExecError::Fault { .. })
        ));
        let (mut memory, mut group) = setup("jmp_any 0", 1);
        assert_eq!(
            group.run(&mut Program::default(), &mut memory, &mut 10),
            Err(ExecError::Runaway { pc: CODE })
        );
    }
}
