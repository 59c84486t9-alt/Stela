//! The engines a workload runs in: the hosted PE, the ordinary block
//! runtime, and the native blocks of one build run by a minimal dispatcher.
use super::fixtures::{Arena, PADDING, PADDING_SPAN, PADDING_STEP};
use super::{ADDRESS_SPACE, RET};
use anyhow::{Result, bail, ensure};
use std::sync::Arc;
use stela_compiler::{GuestAddress, GuestState, TargetCpu, block::BlockProfile};
use stela_runtime::blocks::{BlockRuntime, StopReason, ThreadState};
use stela_runtime::hosted::{hardware::Hardware, host::ProcessHost, pe, tables::Tables};
use stela_runtime::machine::{Chip, Machine, NoDevices, Stop};

/// One prepared function in one engine.
pub(super) trait Runner {
    /// Run one call from `state`; the final state and executed blocks.
    fn call(&mut self, state: &GuestState) -> Result<(GuestState, u64)>;
    /// The bytes and digest of the native code it runs, where the engine
    /// tells.
    fn native(&self) -> Option<(usize, String)>;
}

pub(super) struct Hosted {
    machine: Box<Machine<ProcessHost, NoDevices>>,
    entry: u64,
    stop: u64,
    /// The native bytes and digest of the function's blocks.
    native: (usize, String),
}

/// The engine whose compilation of a function's blocks [`compile_blocks`]
/// reproduces.
#[derive(Clone, Copy, Debug)]
pub(super) enum Profile {
    /// The ordinary block runtime: its plan with resident loops.
    Ordinary,
    /// The hosted PE: the system-mode profile with the checks of its
    /// SCTLR_EL1 at EL0 (SA0 set, A and nAA clear).
    System,
}

/// One compiled block of a function.
pub(super) struct NativeBlock {
    pub(super) pc: u64,
    pub(super) code: Vec<u8>,
    /// It takes the resident-loop budget ABI.
    pub(super) resident: bool,
}

/// Every block statically reachable from `entry`, compiled as `profile`'s
/// engine compiles it.
pub(super) fn compile_blocks(
    code: &[u8],
    entry: u64,
    profile: Profile,
) -> Result<Vec<NativeBlock>> {
    use stela_compiler::block::{CompilationPlan, analyze_with_profile};
    use stela_compiler::x86_64::MemoryChecks;
    let target = TargetCpu::detect();
    let block_profile = match profile {
        Profile::Ordinary => BlockProfile::Ordinary,
        Profile::System => BlockProfile::SystemModeV1,
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut pending = vec![entry];
    let mut blocks = vec![];
    while let Some(pc) = pending.pop() {
        if !(entry..entry + code.len() as u64).contains(&pc) || !seen.insert(pc) {
            continue;
        }
        let source = &code[(pc - entry) as usize..];
        let analysis =
            analyze_with_profile(source, GuestAddress(pc), block_profile).map_err(refused)?;
        let plan = CompilationPlan::new(source, GuestAddress(pc), block_profile, target)
            .map_err(refused)?;
        let plan = match profile {
            Profile::Ordinary => plan.with_resident_loops(),
            Profile::System => plan
                .with_memory_checks(MemoryChecks::system(true, false, true, false))
                .map_err(refused)?,
        };
        let resident = plan.profile() == BlockProfile::OrdinaryResidentV1;
        let compiled = plan.compile().map_err(refused)?;
        blocks.push(NativeBlock {
            pc,
            code: compiled.native.x86_64_code,
            resident,
        });
        pending.extend(
            analysis
                .static_successors
                .iter()
                .map(|successor| successor.target.0),
        );
    }
    blocks.sort_by_key(|block| block.pc);
    Ok(blocks)
}

/// A compiler refusal as an error.
fn refused(error: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("the compiler refused: {error:?}")
}

/// The total bytes and a digest of `blocks`' native code.
pub(super) fn digest(blocks: &[NativeBlock]) -> (usize, String) {
    let digests: String = blocks
        .iter()
        .map(|block| stela_runtime::sha256(&block.code))
        .collect();
    (
        blocks.iter().map(|block| block.code.len()).sum(),
        stela_runtime::sha256(digests.as_bytes()),
    )
}

impl Hosted {
    /// The engine, its code arena already holding the code of a padding
    /// function the round sizes: the hosted engine places each block after
    /// the last, so this spreads the workload's code over different
    /// alignments in different rounds, the same in both builds.
    pub(super) fn new(
        entry: u64,
        stop: u64,
        code: &[u8],
        arena: &mut Arena,
        round: usize,
    ) -> Result<Self> {
        let hardware = Hardware::of(Chip::AppleM2, 1 << 34)?;
        let chip = hardware.chip;
        let target = TargetCpu::detect();
        let tables = Arc::new(Tables::new()?);
        let keys = pe::Keys::random()?;
        let cpu = pe::user_thread(chip, entry, &tables, &keys, pe::UserJop::Enabled);
        let mut machine = Box::new(Machine::new(
            cpu,
            ProcessHost::new(tables)?,
            NoDevices,
            pe::profile(&hardware, target)?,
            target,
        ));
        let mut breakpoints = pe::vectors().to_vec();
        breakpoints.push(stop);
        machine.set_breakpoints(&breakpoints);
        let mut hosted = Self {
            machine,
            entry: arena.address(PADDING),
            stop,
            native: digest(&compile_blocks(code, entry, Profile::System)?),
        };
        const ADD_X0_ONE: u32 = 0x9100_0400;
        let padding: Vec<u8> = std::iter::repeat_n(ADD_X0_ONE, round * PADDING_STEP % PADDING_SPAN)
            .chain([RET])
            .flat_map(u32::to_le_bytes)
            .collect();
        arena.write(PADDING, &padding);
        let mut state = GuestState::default();
        state.x[30] = stop;
        hosted.call(&state)?;
        hosted.entry = entry;
        Ok(hosted)
    }
}

impl Runner for Hosted {
    fn call(&mut self, state: &GuestState) -> Result<(GuestState, u64)> {
        let blocks = self.machine.statistics.blocks;
        self.machine.cpu.state = state.clone();
        self.machine.cpu.pc = self.entry;
        match self.machine.run(0) {
            Stop::Breakpoint(pc) if pc == self.stop => {}
            stop => bail!(
                "hosted run stopped with {stop:?} at {:#x}",
                self.machine.cpu.pc
            ),
        }
        Ok((
            self.machine.cpu.state.clone(),
            self.machine.statistics.blocks - blocks,
        ))
    }

    fn native(&self) -> Option<(usize, String)> {
        Some(self.native.clone())
    }
}

pub(super) struct Blocks {
    runtime: BlockRuntime,
    entry: u64,
    stop: u64,
    code_bytes: usize,
    _cache: tempfile::TempDir,
}

impl Blocks {
    pub(super) fn new(entry: u64, stop: u64, code: &[u8]) -> Result<Self> {
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE,
            cache.path().to_owned(),
            BlockProfile::Ordinary,
            TargetCpu::detect(),
        );
        runtime.register_code(GuestAddress(entry), code.to_vec())?;
        Ok(Self {
            runtime,
            entry,
            stop,
            code_bytes: code.len(),
            _cache: cache,
        })
    }
}

impl Runner for Blocks {
    fn call(&mut self, state: &GuestState) -> Result<(GuestState, u64)> {
        let mut thread = ThreadState {
            registers: state.clone(),
            pc: GuestAddress(self.entry),
        };
        // SAFETY: the unchanged function reads only the arena's prepared
        // inputs and returns to the stop address.
        let outcome = unsafe {
            self.runtime
                .run(&mut thread, Some(GuestAddress(self.stop)), usize::MAX)?
        };
        ensure!(
            outcome.reason == StopReason::StopAddress,
            "block run stopped with {:?}",
            outcome.reason
        );
        Ok((thread.registers, outcome.blocks_executed as u64))
    }

    fn native(&self) -> Option<(usize, String)> {
        let manifests: Vec<_> = (0..self.code_bytes as u64)
            .step_by(4)
            .filter_map(|offset| {
                self.runtime
                    .loaded_manifest(GuestAddress(self.entry + offset))
            })
            .collect();
        let digests: String = manifests
            .iter()
            .map(|manifest| manifest.native_sha256.as_str())
            .collect();
        Some((
            manifests.iter().map(|manifest| manifest.native_bytes).sum(),
            stela_runtime::sha256(digests.as_bytes()),
        ))
    }
}

/// A native block's return: the next guest PC and the exit kind.
#[repr(C)]
struct Exit {
    pc: u64,
    kind: u64,
}

/// The block ABI, with the resident-loop budget as the second argument,
/// which other blocks ignore.
type Entry = unsafe extern "sysv64" fn(*mut GuestState, *mut LoopBudget) -> Exit;
use stela_compiler::block::{ExitKind, loop_budget::LoopBudget};

/// One build's native blocks of a function, run by the smallest dispatcher:
/// look the PC up, call the block, follow its next PC. Every build's blocks
/// run under the same dispatcher in the same process, so only the native
/// code differs. Blocks are 64-byte aligned after a start offset the round
/// sets.
pub(super) struct Native {
    base: *mut u8,
    bytes: usize,
    offsets: std::collections::BTreeMap<u64, usize>,
    entry: u64,
    stop: u64,
    native: (usize, String),
}

const BLOCK_ALIGNMENT: usize = 64;
const START_STEP: usize = 16;

impl Native {
    pub(super) fn new(blocks: &[NativeBlock], entry: u64, stop: u64, round: usize) -> Result<Self> {
        let shift = round * START_STEP % BLOCK_ALIGNMENT;
        let mut offsets = std::collections::BTreeMap::new();
        let mut end = shift;
        for block in blocks {
            offsets.insert(block.pc, end);
            end = (end + block.code.len()).next_multiple_of(BLOCK_ALIGNMENT) + shift;
        }
        let bytes = end.next_multiple_of(super::PAGE);
        // SAFETY: a fresh private anonymous mapping owned by this value.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        ensure!(base != libc::MAP_FAILED, "cannot map native blocks");
        let base = base.cast::<u8>();
        for block in blocks {
            // SAFETY: inside the mapping, which the layout sized.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    block.code.as_ptr(),
                    base.add(offsets[&block.pc]),
                    block.code.len(),
                );
            }
        }
        // SAFETY: the mapping just made.
        let status =
            unsafe { libc::mprotect(base.cast(), bytes, libc::PROT_READ | libc::PROT_EXEC) };
        let native = Self {
            base,
            bytes,
            offsets,
            entry,
            stop,
            native: digest(blocks),
        };
        ensure!(status == 0, "cannot make native blocks executable");
        Ok(native)
    }
}

impl Drop for Native {
    fn drop(&mut self) {
        // SAFETY: the mapping this value owns.
        unsafe { libc::munmap(self.base.cast(), self.bytes) };
    }
}

impl Runner for Native {
    fn call(&mut self, state: &GuestState) -> Result<(GuestState, u64)> {
        let mut state = state.clone();
        let mut budget = LoopBudget::new(usize::MAX >> 1);
        let (mut pc, mut blocks) = (self.entry, 0);
        while pc != self.stop {
            let Some(&offset) = self.offsets.get(&pc) else {
                bail!("no native block at {pc:#x}");
            };
            // SAFETY: an executable copy of a block compiled for this
            // function, whose accesses reach only the arena's inputs.
            let exit = unsafe {
                let entry: Entry = core::mem::transmute(self.base.add(offset));
                entry(&mut state, &mut budget)
            };
            blocks += 1;
            ensure!(
                exit.kind <= ExitKind::Return as u64,
                "block {pc:#x} exited with kind {}",
                exit.kind
            );
            pc = exit.pc;
        }
        Ok((state, blocks))
    }

    fn native(&self) -> Option<(usize, String)> {
        Some(self.native.clone())
    }
}
