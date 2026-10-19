//! The GPU execution engine: what the data masters do with a work command's
//! control stream (docs/research/agx.md §5.6 and §5.4).
//!
//! [`compute`] runs a CDM stream: each launch's USC state is loaded into
//! SIMD groups of 32 threads, threadgroups run one after another with their
//! SIMD groups meeting at `barrier`, and the preshader runs once before the
//! main shader. Execution is in order and completes before the next block
//! is read, so a launch sees every earlier launch's writes and barriers
//! need no cache work.

pub mod compute;

use super::isa::machine::{
    Env, ExecError, Exit, Memory, Program, SAMPLER_STATE_BYTES, STATE_REGISTERS, SimdGroup,
    TEXTURE_STATE_BYTES, UNIFORM_HALVES,
};
use super::stream::StreamError;
use super::stream::usc::UscState;

/// Instructions one SIMD group may run between barriers before the work is
/// a runaway.
pub const GROUP_BUDGET: u64 = 1 << 28;

/// Why GPU work stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkError {
    Stream(StreamError),
    Shader(ExecError),
    /// A launch or draw asks for something the model does not cover.
    Refused(&'static str),
}

impl From<StreamError> for WorkError {
    fn from(error: StreamError) -> Self {
        WorkError::Stream(error)
    }
}

impl From<ExecError> for WorkError {
    fn from(error: ExecError) -> Self {
        WorkError::Shader(error)
    }
}

impl From<super::isa::machine::Fault> for WorkError {
    fn from(fault: super::isa::machine::Fault) -> Self {
        WorkError::Stream(StreamError::Fault(fault))
    }
}

/// Bytes of a texture state in a USC `Texture` table (cmdbuf.xml `Texture`).
const TEXTURE_BYTES: u64 = 24;
/// Bytes of a compact and an extended sampler state (`Sampler`, plus
/// `Border` when extended; Mesa `agxdecode_usc`).
const SAMPLER_BYTES: u64 = 8;
const EXTENDED_SAMPLER_BYTES: u64 = 24;

/// A shader's state as its USC words load it, ready to start SIMD groups.
pub struct ShaderState {
    pub uniforms: [u16; UNIFORM_HALVES],
    pub textures: [Option<[u8; TEXTURE_STATE_BYTES]>; STATE_REGISTERS],
    pub samplers: [Option<[u8; SAMPLER_STATE_BYTES]>; STATE_REGISTERS],
    pub extended_samplers: bool,
    pub register_limit: usize,
    pub stack_limit: u32,
    /// The main shader's first instruction.
    pub code: u64,
    /// The preshader's first instruction.
    pub preshader: Option<u64>,
    /// The USC execution base (call and return offsets are relative to it).
    pub code_base: u64,
}

impl ShaderState {
    /// Load `usc`'s uniforms and state tables from memory.
    pub fn load(
        memory: &mut dyn Memory,
        usc_base: u64,
        usc: &UscState,
        extended_samplers: bool,
    ) -> Result<Self, WorkError> {
        let code = usc
            .code
            .ok_or(WorkError::Refused("a USC word list without a Shader word"))?;
        let register_limit = usc.register_halves.ok_or(WorkError::Refused(
            "a USC word list without a Registers word",
        ))?;
        let mut state = ShaderState {
            uniforms: [0; UNIFORM_HALVES],
            textures: [None; STATE_REGISTERS],
            samplers: [None; STATE_REGISTERS],
            extended_samplers,
            register_limit: register_limit as usize,
            stack_limit: usc.spill_bytes,
            code: usc_base.wrapping_add(u64::from(code)),
            preshader: usc
                .preshader
                .map(|offset| usc_base.wrapping_add(u64::from(offset))),
            code_base: usc_base,
        };
        for load in &usc.uniforms {
            let end = (load.start + load.halves) as usize;
            if end > UNIFORM_HALVES {
                return Err(WorkError::Refused(
                    "a USC uniform load past the uniform file",
                ));
            }
            let mut bytes = alloc::vec![0u8; 2 * load.halves as usize];
            memory.read(load.address, &mut bytes)?;
            for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
                state.uniforms[load.start as usize + i] = u16::from_le_bytes([pair[0], pair[1]]);
            }
        }
        for load in &usc.textures {
            for i in 0..load.count {
                let register = (load.start + i) as usize;
                let mut descriptor = [0u8; TEXTURE_STATE_BYTES];
                memory.read(load.address + TEXTURE_BYTES * u64::from(i), &mut descriptor)?;
                *state.textures.get_mut(register).ok_or(WorkError::Refused(
                    "a USC texture load past the state registers",
                ))? = Some(descriptor);
            }
        }
        let stride = if extended_samplers {
            EXTENDED_SAMPLER_BYTES
        } else {
            SAMPLER_BYTES
        };
        for load in &usc.samplers {
            for i in 0..load.count {
                let register = (load.start + i) as usize;
                let mut descriptor = [0u8; SAMPLER_STATE_BYTES];
                memory.read(
                    load.address + stride * u64::from(i),
                    &mut descriptor[..stride as usize],
                )?;
                *state.samplers.get_mut(register).ok_or(WorkError::Refused(
                    "a USC sampler load past the state registers",
                ))? = Some(descriptor);
            }
        }
        Ok(state)
    }

    /// A SIMD group of `threads` threads at `pc` with this state.
    pub fn group(&self, threads: usize, pc: u64) -> SimdGroup {
        let mut group = SimdGroup::new(threads, pc);
        group.uniforms = self.uniforms;
        group.textures = self.textures;
        group.samplers = self.samplers;
        group.extended_samplers = self.extended_samplers;
        group.register_limit = self.register_limit;
        group.stack_limit = self.stack_limit;
        group.code_base = self.code_base;
        group
    }

    /// Run the preshader, if any, on one thread and keep the uniforms it
    /// writes (Mesa: the preamble "writes directly to uniform registers").
    pub fn run_preshader(
        &mut self,
        env: &mut dyn Env,
        program: &mut Program,
    ) -> Result<(), WorkError> {
        let Some(pc) = self.preshader else {
            return Ok(());
        };
        let mut group = self.group(1, pc);
        let mut budget = GROUP_BUDGET;
        match group.run(program, env, &mut budget)? {
            Exit::Stopped => {}
            Exit::Barrier => {
                return Err(WorkError::Refused("a threadgroup barrier in a preshader"));
            }
        }
        self.uniforms = group.uniforms;
        self.textures = group.textures;
        self.samplers = group.samplers;
        Ok(())
    }
}
