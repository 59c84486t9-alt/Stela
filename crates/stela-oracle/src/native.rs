//! Run Stela's native translation of a case at the guest's own addresses.
use crate::{
    CODE_PAGE, CODE_REGION, CODE_REGION_BYTES, Case, DATA_BYTES, DATA_WINDOW, Outcome, SVCR_SM,
    SVCR_ZA, Scalable,
};
use anyhow::{Context, Result, ensure};
use std::{
    ptr::NonNull,
    sync::{Mutex, OnceLock},
};
use stela_compiler::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::scalable::{ScalableMode, VectorLength, features::ScalableFeature},
    block::{BlockProfile, ExitKind},
    context::{ExecutionContext, ScalableStateView},
    extended::block::ExtendedBlockProfile,
};
use stela_runtime::{
    blocks::{BlockRuntime, ThreadState},
    scalable::{ScalableState, block::PreparedScalableBlock},
};

const PAGE_BYTES: usize = 0x1000;
const INSTRUCTION_BYTES: usize = 4;
const RET: u32 = 0xd65f_03c0;
const ADDRESS_SPACE: u64 = 1;
/// Bytes of each Z register held in the guest state's V register.
const V_BYTES: usize = 16;

/// Host mappings at the guest code region and data window. One process-wide
/// instance exists; the lock serializes every native case.
struct Windows {
    code: NonNull<u8>,
    data: NonNull<u8>,
}

// SAFETY: the mappings are owned for the process lifetime and only touched
// while the surrounding mutex is held.
unsafe impl Send for Windows {}

fn windows() -> Result<&'static Mutex<Windows>> {
    static WINDOWS: OnceLock<Mutex<Windows>> = OnceLock::new();
    if let Some(windows) = WINDOWS.get() {
        return Ok(windows);
    }
    let windows = Windows {
        code: map_at(CODE_REGION, CODE_REGION_BYTES)?,
        data: map_at(DATA_WINDOW, DATA_BYTES)?,
    };
    Ok(WINDOWS.get_or_init(|| Mutex::new(windows)))
}

/// Map fresh RW memory at exactly `address`, refusing to replace a mapping.
fn map_at(address: u64, bytes: usize) -> Result<NonNull<u8>> {
    // SAFETY: a hinted anonymous mapping never replaces existing memory; the
    // result is checked against the requested address before use.
    let pointer = unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    ensure!(pointer != libc::MAP_FAILED, "cannot map {address:#x}");
    if pointer as u64 != address {
        // SAFETY: release the mapping the kernel placed elsewhere.
        unsafe { libc::munmap(pointer, bytes) };
        anyhow::bail!("{address:#x} is already mapped in this process");
    }
    NonNull::new(pointer.cast()).context("null mapping")
}

/// Executable copy of native code, unmapped on drop.
pub struct Executable {
    pointer: NonNull<u8>,
    bytes: usize,
}

impl Executable {
    fn new(code: &[u8]) -> Result<Self> {
        ensure!(!code.is_empty(), "empty native code");
        let bytes = code.len().next_multiple_of(PAGE_BYTES);
        // SAFETY: fresh anonymous RW memory, checked before use.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        ensure!(pointer != libc::MAP_FAILED, "cannot map native code");
        let executable = Self {
            pointer: NonNull::new(pointer.cast()).context("null mapping")?,
            bytes,
        };
        // SAFETY: the mapping holds at least `code.len()` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), executable.pointer.as_ptr(), code.len());
            ensure!(
                libc::mprotect(pointer, bytes, libc::PROT_READ | libc::PROT_EXEC) == 0,
                "cannot make native code executable"
            );
        }
        Ok(executable)
    }
}

impl Drop for Executable {
    fn drop(&mut self) {
        // SAFETY: this object owns the whole mapping.
        unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.bytes) };
    }
}

fn mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: STMXCSR stores the 32-bit control register to a valid location.
    unsafe { std::arch::asm!("stmxcsr [{}]", in(reg) &mut value, options(nostack)) };
    value
}

fn set_mxcsr(value: u32) {
    // SAFETY: restores a value previously read from MXCSR.
    unsafe { std::arch::asm!("ldmxcsr [{}]", in(reg) &value, options(nostack)) };
}

/// Stela's native translation of one case's code at [`CODE_PAGE`].
pub enum Translation {
    /// A leaf ending in RET X30; execution falls through past the case.
    Leaf(Executable),
    /// A production block dispatcher over the case's code, run for one block.
    Block {
        runtime: BlockRuntime,
        _cache: tempfile::TempDir,
    },
    /// A context leaf over guest and scalable state, without a memory service.
    Context(Executable),
    /// A contextual scalable block whose numerical exits the runtime completes.
    ScalableBlock(PreparedScalableBlock, ExtendedBlockProfile),
}

impl Translation {
    /// Translate `words` and a closing RET as a leaf.
    pub fn leaf(words: &[u32]) -> Result<Self> {
        let source: Vec<u8> = words
            .iter()
            .chain(&[RET])
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let native = stela_compiler::compile_for_target(&source, GuestAddress(CODE_PAGE), target())
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(Self::Leaf(Executable::new(&native.x86_64_code)?))
    }

    /// Translate `words` as ordinary blocks, refusing words Stela declines.
    pub fn block(words: &[u32]) -> Result<Self> {
        let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        stela_compiler::block::compile_for_target(
            &source,
            GuestAddress(CODE_PAGE),
            BlockProfile::Ordinary,
            target(),
        )
        .map_err(|error| anyhow::anyhow!(error))?;
        let cache = tempfile::tempdir()?;
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE,
            cache.path().to_owned(),
            BlockProfile::Ordinary,
            target(),
        );
        runtime.register_code(GuestAddress(CODE_PAGE), source)?;
        Ok(Self::Block {
            runtime,
            _cache: cache,
        })
    }

    /// Wrap a compiled register-only context leaf.
    pub fn context(native: &[u8]) -> Result<Self> {
        Ok(Self::Context(Executable::new(native)?))
    }

    /// Prepare `words` as one contextual scalable block under `profile`.
    pub fn scalable_block(words: &[u32], profile: ExtendedBlockProfile) -> Result<Self> {
        let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let block =
            PreparedScalableBlock::prepare(&source, GuestAddress(CODE_PAGE), profile, target())?;
        Ok(Self::ScalableBlock(block, profile))
    }

    /// Run the translation against `case`'s state and data window.
    ///
    /// # Safety
    ///
    /// The original must have completed on the oracle, so every access stays
    /// in the windows.
    pub unsafe fn run(&mut self, case: &Case) -> Result<Outcome> {
        let windows = windows()?.lock().expect("native windows lock");
        // SAFETY: both windows are owned, writable and sized as copied here.
        unsafe {
            let page = (CODE_PAGE - CODE_REGION) as usize;
            let code = std::slice::from_raw_parts_mut(windows.code.as_ptr().add(page), PAGE_BYTES);
            code.fill(0);
            for (word, bytes) in case.code.iter().zip(code.as_chunks_mut::<4>().0) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            std::slice::from_raw_parts_mut(windows.data.as_ptr(), DATA_BYTES)
                .copy_from_slice(&case.data);
        }
        let saved = mxcsr();
        let mut scalable_result = None;
        let result = match self {
            Self::Leaf(executable) => {
                let mut state = case.state.clone();
                // SAFETY: the mapping holds a leaf that follows the guest-state ABI.
                let leaf: extern "sysv64" fn(*mut GuestState) =
                    unsafe { std::mem::transmute(executable.pointer.as_ptr()) };
                leaf(&mut state);
                Ok((state, CODE_PAGE + (case.steps * INSTRUCTION_BYTES) as u64))
            }
            Self::ScalableBlock(block, profile) => {
                scalable_block(block, *profile, case).map(|(state, next_pc, scalable)| {
                    scalable_result = Some(scalable);
                    (state, next_pc)
                })
            }
            Self::Context(executable) => context(executable, case).map(|(state, scalable)| {
                scalable_result = Some(scalable);
                (state, CODE_PAGE + (case.steps * INSTRUCTION_BYTES) as u64)
            }),
            Self::Block { runtime, .. } => {
                let mut thread = ThreadState {
                    registers: case.state.clone(),
                    pc: GuestAddress(CODE_PAGE),
                };
                // SAFETY: trusted case code whose accesses stay in the windows.
                unsafe { runtime.run(&mut thread, None, case.steps) }
                    .map(|_| (thread.registers, thread.pc.0))
            }
        };
        set_mxcsr(saved);
        let (state, next_pc) = result?;
        // SAFETY: the data window stays mapped and is no longer written.
        let data = unsafe { std::slice::from_raw_parts(windows.data.as_ptr(), DATA_BYTES) }.into();
        Ok(Outcome {
            state,
            next_pc,
            data,
            scalable: scalable_result,
            exception: None,
        })
    }
}

/// Invoke a scalable block on runtime-owned state, completing a numerical exit.
fn scalable_block(
    block: &PreparedScalableBlock,
    profile: ExtendedBlockProfile,
    case: &Case,
) -> Result<(GuestState, u64, Scalable)> {
    let initial = case
        .scalable
        .as_ref()
        .context("scalable blocks need scalable state")?;
    let svl = initial.svl;
    let length = VectorLength::from_bytes(svl).context("unsupported SVL")?;
    let mode = ScalableMode::from_svcr(initial.svcr).context("unsupported SVCR")?;
    let sme2 = profile
        .scalable()
        .features()
        .contains(ScalableFeature::Sme2);
    let mut thread = ThreadState {
        registers: case.state.clone(),
        pc: GuestAddress(CODE_PAGE),
    };
    let mut scalable = ScalableState::new(length, sme2);
    scalable.apply_mode(&mut thread.registers, mode)?;
    thread.registers.v = case.state.v;
    thread.registers.fpsr = case.state.fpsr;
    scalable.set_tpidr2_el0(initial.tpidr2);
    if mode.streaming() {
        for (register, z) in initial.z.chunks_exact(svl).enumerate() {
            scalable.write_z(&mut thread.registers, register as u8, z)?;
        }
        for (register, p) in initial.p.chunks_exact(svl / 8).enumerate() {
            scalable.write_predicate(register as u8, p)?;
        }
        // The low part of each Z register is the case's V register.
        thread.registers.v = case.state.v;
    }
    if mode.za_enabled() {
        scalable.write_za(0, &initial.za)?;
        if sme2 {
            scalable.write_zt0(0, &initial.zt0)?;
        }
    }
    let mut context = ExecutionContext::default();
    // SAFETY: trusted single-instruction source over runtime-owned state.
    let exit = unsafe { block.invoke(&mut thread, &mut scalable, &mut context)? };
    if exit.kind == ExitKind::ScalableNumerical as u64 {
        block
            .complete_numerical(&mut thread, &mut scalable, exit)
            .map_err(|error| anyhow::anyhow!("numerical completion: {error:?}"))?;
    }
    let mut result = Scalable {
        svcr: scalable.mode().svcr(),
        tpidr2: scalable.tpidr2_el0(),
        ..initial.clone()
    };
    if scalable.mode().streaming() {
        for (register, z) in result.z.chunks_exact_mut(svl).enumerate() {
            scalable.read_z(&thread.registers, register as u8, z)?;
        }
        for (register, p) in result.p.chunks_exact_mut(svl / 8).enumerate() {
            scalable.read_predicate(register as u8, p)?;
        }
    }
    if scalable.mode().za_enabled() {
        scalable.read_za(0, &mut result.za)?;
        if sme2 {
            scalable.read_zt0(0, &mut result.zt0)?;
        }
    }
    Ok((thread.registers, thread.pc.0, result))
}

/// Call a context leaf with the case's scalable banks behind a state view.
fn context(executable: &Executable, case: &Case) -> Result<(GuestState, Scalable)> {
    let initial = case
        .scalable
        .as_ref()
        .context("context leaves need scalable state")?;
    let svl = initial.svl;
    let mut z_upper: Vec<u8> = initial
        .z
        .chunks_exact(svl)
        .flat_map(|z| z[V_BYTES..].iter().copied())
        .collect();
    let mut p = initial.p.clone();
    let mut ffr = vec![0; svl / 8];
    let mut za = initial.za.clone();
    let mut zt0 = initial.zt0;
    let mut view = ScalableStateView {
        svl_bytes: u16::try_from(svl)?,
        reserved: [0; 6],
        svcr: initial.svcr,
        tpidr2_el0: initial.tpidr2,
        fpmr: 0,
        z_upper: z_upper.as_mut_ptr(),
        predicates: p.as_mut_ptr(),
        ffr: ffr.as_mut_ptr(),
        za: za.as_mut_ptr(),
        zt0: zt0.as_mut_ptr(),
    };
    let mut context = ExecutionContext {
        scalable: &mut view,
        ..ExecutionContext::default()
    };
    let mut state = case.state.clone();
    // SAFETY: the mapping holds a context leaf over these live buffers.
    let leaf: extern "sysv64" fn(*mut GuestState, *mut ExecutionContext) =
        unsafe { std::mem::transmute(executable.pointer.as_ptr()) };
    leaf(&mut state, &mut context);
    let mut result = Scalable {
        svcr: view.svcr,
        tpidr2: view.tpidr2_el0,
        ..initial.clone()
    };
    // Banks the original keeps disabled are not observable; keep them as given.
    if result.svcr & SVCR_SM != 0 {
        for (index, z) in result.z.chunks_exact_mut(svl).enumerate() {
            z[..8].copy_from_slice(&state.v[index][0].to_le_bytes());
            z[8..V_BYTES].copy_from_slice(&state.v[index][1].to_le_bytes());
            z[V_BYTES..].copy_from_slice(&z_upper[index * (svl - V_BYTES)..][..svl - V_BYTES]);
        }
        result.p = p;
    }
    if result.svcr & SVCR_ZA != 0 {
        result.za = za;
        result.zt0 = zt0;
    }
    Ok((state, result))
}

fn target() -> TargetCpu {
    TargetCpu::detect()
}
