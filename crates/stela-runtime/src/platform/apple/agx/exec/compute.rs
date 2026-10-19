//! Compute dispatch: a CDM stream's launches over their grids.
//!
//! Semantics (Public: cmdbuf.xml, Mesa `hk_cmd_dispatch.c`, the `sr` enum;
//! Inferred where marked):
//! - The global size counts threads (Mesa multiplies group counts by the
//!   local size); a grid that is not a multiple of the local size has
//!   partial threadgroups at its far edges whose missing threads are not
//!   present, and `threads_per_threadgroup` reports the partial size while
//!   `dispatch_threads_per_threadgroup` keeps the launch's (Metal's
//!   non-uniform threadgroups; Inferred split between the two registers).
//! - Threads of a threadgroup are numbered x fastest; SIMD group `i` holds
//!   threads `32i .. 32i + 31`.
//! - Threadgroups run one at a time in grid order (any order is valid; Metal
//!   promises none); threadgroup memory starts zeroed (Inferred: its initial
//!   contents are undefined).
//! - A threadgroup's SIMD groups each run to `barrier` or `stop`, then
//!   those at the barrier resume together; a group that stopped no longer
//!   takes part.
//! - `core_index` is 0 (the model is one core) and `vm_slot` the job's
//!   context (Inferred).

use super::{GROUP_BUDGET, ShaderState, WorkError};
use crate::platform::apple::agx::isa::machine::{
    Env, Exit, Fault, Memory, Program, SIMD_WIDTH, SimdGroup, Specials,
};
use crate::platform::apple::agx::stream::cdm::{Command, Launch, Walker, extended_samplers};
use crate::platform::apple::agx::stream::usc;
use alloc::vec;
use alloc::vec::Vec;

/// What a CDM stream did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub launches: u64,
    pub barriers: u64,
    pub threadgroups: u64,
}

/// A compute job: the stream, the USC base its offsets are relative to, and
/// the UAT context it runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job {
    pub stream: u64,
    pub usc_base: u64,
    pub vm_slot: u32,
}

/// Run every launch of the job's CDM stream.
pub fn run(memory: &mut dyn Memory, job: &Job) -> Result<Stats, WorkError> {
    let mut walker = Walker::new(job.stream);
    let mut stats = Stats::default();
    while let Some(command) = walker.next(memory)? {
        match command {
            Command::Launch(launch) => {
                stats.threadgroups += dispatch(memory, job, &launch)?;
                stats.launches += 1;
            }
            Command::Barrier(_) => stats.barriers += 1,
        }
    }
    Ok(stats)
}

/// The environment of a compute SIMD group: the job's memory and its
/// threadgroup's memory.
struct ComputeEnv<'a> {
    memory: &'a mut dyn Memory,
    shared: &'a mut [u8],
}

impl Memory for ComputeEnv<'_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
        self.memory.read(address, buffer)
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault> {
        self.memory.write(address, data)
    }
}

impl Env for ComputeEnv<'_> {
    fn threadgroup(&mut self) -> Option<&mut [u8]> {
        Some(self.shared)
    }
}

/// Run one launch; returns the threadgroups it ran.
pub fn dispatch(memory: &mut dyn Memory, job: &Job, launch: &Launch) -> Result<u64, WorkError> {
    let (global, local) = launch.sizes(memory)?;
    if local.contains(&0) {
        return Err(WorkError::Refused("a launch with an empty local size"));
    }
    let usc = usc::parse(memory, job.usc_base, u64::from(launch.pipeline))?;
    let shared_bytes = match usc.shared {
        Some(shared) if shared.uses_shared_memory => {
            if shared.layout != usc::layout::VERTEX_COMPUTE {
                return Err(WorkError::Refused(
                    "a compute launch with a tile-shaped Shared layout",
                ));
            }
            shared.bytes_per_threadgroup as usize
        }
        _ => 0,
    };
    let mut state = ShaderState::load(
        memory,
        job.usc_base,
        &usc,
        extended_samplers(launch.sampler_states),
    )?;
    let mut program = Program::default();
    {
        let mut none: [u8; 0] = [];
        let mut env = ComputeEnv {
            memory,
            shared: &mut none,
        };
        state.run_preshader(&mut env, &mut program)?;
    }
    let groups = [0, 1, 2].map(|axis| global[axis].div_ceil(local[axis]));
    let threads_per_group = local.iter().map(|&n| n as usize).product::<usize>();
    let mut count = 0u64;
    let mut shared = vec![0u8; shared_bytes];
    for gz in 0..groups[2] {
        for gy in 0..groups[1] {
            for gx in 0..groups[0] {
                let group = [gx, gy, gz];
                shared.fill(0);
                let mut env = ComputeEnv {
                    memory,
                    shared: &mut shared,
                };
                threadgroup(
                    &mut env,
                    &mut program,
                    &state,
                    job,
                    group,
                    global,
                    local,
                    threads_per_group,
                )?;
                count += 1;
            }
        }
    }
    Ok(count)
}

#[allow(clippy::too_many_arguments)]
fn threadgroup(
    env: &mut ComputeEnv,
    program: &mut Program,
    state: &ShaderState,
    job: &Job,
    group: [u32; 3],
    global: [u32; 3],
    local: [u32; 3],
    threads: usize,
) -> Result<(), WorkError> {
    let origin = [0, 1, 2].map(|axis| group[axis] * local[axis]);
    let actual = [0, 1, 2].map(|axis| local[axis].min(global[axis] - origin[axis]));
    let simd_groups = threads.div_ceil(SIMD_WIDTH);
    let mut groups: Vec<SimdGroup> = Vec::with_capacity(simd_groups);
    for index in 0..simd_groups {
        let mut simd = state.group(SIMD_WIDTH, state.code);
        let mut present = 0u32;
        let mut in_group = [[0u32; 3]; SIMD_WIDTH];
        let mut in_grid = [[0u32; 3]; SIMD_WIDTH];
        let mut linear = [0u32; SIMD_WIDTH];
        for lane in 0..SIMD_WIDTH {
            let t = index * SIMD_WIDTH + lane;
            if t >= threads {
                break;
            }
            let t = t as u32;
            let position = [
                t % local[0],
                t / local[0] % local[1],
                t / (local[0] * local[1]),
            ];
            if (0..3).any(|axis| position[axis] >= actual[axis]) {
                continue;
            }
            present |= 1 << lane;
            in_group[lane] = position;
            in_grid[lane] = [0, 1, 2].map(|axis| origin[axis] + position[axis]);
            linear[lane] = t;
        }
        simd.present = present;
        simd.specials = Specials {
            threadgroup_in_grid: Some(group),
            threads_per_threadgroup: Some(actual),
            dispatch_threads_per_threadgroup: Some(local),
            core_index: Some(0),
            vm_slot: Some(job.vm_slot),
            simdgroup_index_in_threadgroup: Some(index as u32),
            thread_in_threadgroup: Some(in_group),
            thread_index_in_threadgroup: Some(linear),
            thread_in_grid: Some(in_grid),
            ..Specials::default()
        };
        if present != 0 {
            groups.push(simd);
        }
    }
    let mut running: Vec<bool> = vec![true; groups.len()];
    while running.iter().any(|&r| r) {
        for (simd, running) in groups.iter_mut().zip(running.iter_mut()) {
            if !*running {
                continue;
            }
            let mut budget = GROUP_BUDGET;
            if simd.run(program, env, &mut budget)? == Exit::Stopped {
                *running = false;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::isa::assemble::program;
    use crate::platform::apple::agx::isa::machine::tests::Flat;
    use crate::platform::apple::agx::stream::tests::words;

    const BASE: u64 = 0x1_0000_0000;
    const PIPELINE: u64 = 0x100;
    const CODE: u64 = 0x200;
    const UNIFORMS: u64 = 0x800;
    const OUTPUT: u64 = 0x1000;
    const STREAM: u64 = 0x3000;

    /// A memory with a USC list (shared bytes, uniforms at u0 = the output
    /// address) and `code` at [`CODE`], and a CDM stream launching it over
    /// `global` threads in groups of `local`.
    fn job(code: &str, global: [u32; 3], local: [u32; 3], shared: u32) -> Flat {
        let mut memory = Flat::new(BASE, 0x8000);
        let mut usc = alloc::vec::Vec::new();
        let shared_word = 0x4d | u32::from(shared > 0) << 8 | 0x24 << 10 | (shared / 256) << 24;
        usc.extend_from_slice(&shared_word.to_le_bytes());
        usc.extend_from_slice(&(0x8d_u32 | 8 << 8).to_le_bytes());
        let uniform = 0x1d | 4 << 20 | ((BASE + UNIFORMS) >> 2) << 26;
        usc.extend_from_slice(&uniform.to_le_bytes());
        usc.extend_from_slice(&[0x0d, 0]);
        usc.extend_from_slice(&(CODE as u32).to_le_bytes());
        usc.extend_from_slice(&[0x88, 0]);
        memory.put(BASE + PIPELINE, &usc);
        memory.put(BASE + CODE, &program(code));
        memory.put(BASE + UNIFORMS, &(BASE + OUTPUT).to_le_bytes());
        let mut stream = alloc::vec![1 << 1, (PIPELINE as u32 >> 6) << 6];
        stream.extend_from_slice(&global);
        stream.extend_from_slice(&local);
        stream.push(2 << 29);
        words(&mut memory, BASE + STREAM, &stream);
        memory
    }

    fn launch(memory: &mut Flat) -> Result<Stats, WorkError> {
        run(
            memory,
            &Job {
                stream: BASE + STREAM,
                usc_base: BASE,
                vm_slot: 1,
            },
        )
    }

    #[test]
    fn each_thread_writes_its_grid_position_squared_plus_one() {
        // out[i] = i * i + 1 over a 70-thread grid of 32-thread groups: the
        // last threadgroup is partial.
        let mut memory = job(
            "mov r2, thread_in_grid_x\n\
             imadd r3, r2, r2, 1\n\
             store r3, du0, r2, i32, x, a\n\
             stop",
            [70, 1, 1],
            [32, 1, 1],
            0,
        );
        let stats = launch(&mut memory).unwrap();
        assert_eq!(
            stats,
            Stats {
                launches: 1,
                barriers: 0,
                threadgroups: 3
            }
        );
        for i in 0..72u64 {
            let expected = if i < 70 { (i * i + 1) as u32 } else { 0 };
            assert_eq!(memory.u32(BASE + OUTPUT + 4 * i), expected, "thread {i}");
        }
    }

    #[test]
    fn threadgroup_memory_and_barriers_exchange_between_simd_groups() {
        // 64 threads per group: each stores its index to shared memory,
        // barriers, then reads its mirror (63 - t) and writes it out.
        let mut memory = job(
            "mov r2, thread_index_in_threadgroup\n\
             iadd r4l, r2l, r2l\n\
             iadd r4l, r4l, r4l\n\
             lstore r2, r4l, 0, i32, x\n\
             barrier\n\
             isub r5, 63, r2\n\
             iadd r6l, r5l, r5l\n\
             iadd r6l, r6l, r6l\n\
             lload r7, r6l, 0, i32, x\n\
             mov r8, thread_in_grid_x\n\
             store r7, du0, r8, i32, x, a\n\
             stop",
            [128, 1, 1],
            [64, 1, 1],
            256,
        );
        launch(&mut memory).unwrap();
        for i in 0..128u64 {
            assert_eq!(
                memory.u32(BASE + OUTPUT + 4 * i),
                63 - (i as u32 % 64),
                "thread {i}"
            );
        }
    }
}
