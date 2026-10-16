//! Run Stela's native translation of a case at the guest's own addresses.
use super::{
    CODE_PAGE, CODE_REGION, CODE_REGION_BYTES, Case, DATA_BYTES, DATA_WINDOW, Outcome, Scalable,
};
use anyhow::{Context, Result, ensure};
use std::{
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock},
};
use stela_compiler::{
    GuestAddress, GuestState, TargetCpu,
    aarch64::scalable::{ScalableMode, VectorLength, features::ScalableFeature},
    block::{BlockProfile, ExitKind},
    context::{
        ExecutionContext,
        memory::{MemoryImplementationProfile, MemoryRequirements, SpAlignmentRequirement},
    },
    extended::{ScalableProfile, block::ExtendedBlockProfile},
};
use stela_runtime::{
    blocks::{BlockRuntime, ThreadState},
    memory::{
        backing::{AccessPermissions, MemoryBacking, MemoryView},
        domain::{MappingAttributes, MemoryDomain, MemorySystem, MemoryThread},
        policy::{LowerAddressProfile, MemoryControls, TagCheckFaultMode},
    },
    scalable::{
        ScalableState,
        block::PreparedScalableBlock,
        leaf::{PreparedScalableLeaf, ScalableLeafExit},
    },
};

const PAGE_BYTES: usize = 0x1000;
const INSTRUCTION_BYTES: usize = 4;
const RET: u32 = 0xd65f_03c0;
const ADDRESS_SPACE: u64 = 1;
/// The memory service's exclusive-reservation granule and lock stripes.
const RESERVATION_GRANULE: u64 = 16;
const RESERVATION_STRIPES: usize = 16;
/// Lower address bits of the harness's stage 1 translation (T0SZ = 25).
const ADDRESS_BITS: u8 = 39;

/// Host mappings at the guest code region and data window. One process-wide
/// instance exists; the lock serializes every native case.
struct Windows {
    code: NonNull<u8>,
    data: NonNull<u8>,
}

// SAFETY: the mappings live for the whole process and are only touched while
// the surrounding mutex is held.
unsafe impl Send for Windows {}

fn windows() -> Result<&'static Mutex<Windows>> {
    static WINDOWS: OnceLock<Mutex<Windows>> = OnceLock::new();
    if let Some(windows) = WINDOWS.get() {
        return Ok(windows);
    }
    let windows = Windows {
        code: map_at(CODE_REGION, CODE_REGION_BYTES, libc::PROT_READ)?,
        data: map_at(DATA_WINDOW, DATA_BYTES, libc::PROT_READ | libc::PROT_WRITE)?,
    };
    Ok(WINDOWS.get_or_init(|| Mutex::new(windows)))
}

/// Map fresh zeroed memory at exactly `address`, refusing to replace a mapping.
fn map_at(address: u64, bytes: usize, protection: libc::c_int) -> Result<NonNull<u8>> {
    // SAFETY: a hinted anonymous mapping never replaces existing memory; the
    // result is checked against the requested address before use.
    let pointer = unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            bytes,
            protection,
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

/// Change the protection of one page of the code region.
///
/// # Safety
/// `page` must be a page of the code region mapping.
unsafe fn protect(page: *mut u8, protection: libc::c_int) -> Result<()> {
    // SAFETY: the caller passes a page of a mapping this process owns.
    let status = unsafe { libc::mprotect(page.cast(), PAGE_BYTES, protection) };
    ensure!(status == 0, "cannot protect the code page");
    Ok(())
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
    /// A scalable context leaf with a checked memory service over the window.
    ScalableLeaf(PreparedScalableLeaf, ScalableProfile),
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

    /// Prepare `words` and a closing RET as a scalable leaf under `profile`, or
    /// `None` when the standalone memory service cannot admit its requirements.
    pub fn scalable_leaf(words: &[u32], profile: ScalableProfile) -> Result<Option<Self>> {
        let source: Vec<u8> = words
            .iter()
            .chain(&[RET])
            .flat_map(|word| word.to_le_bytes())
            .collect();
        let leaf =
            PreparedScalableLeaf::prepare(&source, GuestAddress(CODE_PAGE), profile, target())?;
        let requirements = leaf.identity().memory_requirements;
        let windows = windows()?.lock().expect("native windows lock");
        let admitted = memory_thread(&windows, requirements)?
            .prepare(requirements)
            .is_ok();
        Ok(admitted.then_some(Self::ScalableLeaf(leaf, profile)))
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
    /// The case must have completed on the oracle, so every access stays inside
    /// the windows.
    pub unsafe fn run(&mut self, case: &Case) -> Result<Outcome> {
        let windows = windows()?.lock().expect("native windows lock");
        // SAFETY: both windows are owned and sized as copied here; the code page
        // is writable only while its code is installed.
        unsafe {
            let page = windows
                .code
                .as_ptr()
                .add((CODE_PAGE - CODE_REGION) as usize);
            protect(page, libc::PROT_READ | libc::PROT_WRITE)?;
            let code = std::slice::from_raw_parts_mut(page, PAGE_BYTES);
            code.fill(0);
            for (word, bytes) in case.code.iter().zip(code.as_chunks_mut::<4>().0) {
                bytes.copy_from_slice(&word.to_le_bytes());
            }
            protect(page, libc::PROT_READ)?;
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
            Self::ScalableLeaf(leaf, profile) => {
                scalable_leaf(leaf, *profile, &windows, case).map(|(state, scalable)| {
                    scalable_result = Some(scalable);
                    (state, CODE_PAGE + (case.steps * INSTRUCTION_BYTES) as u64)
                })
            }
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

/// Runtime-owned state for a scalable case under `profile`.
fn load_scalable(case: &Case, profile: ScalableProfile) -> Result<(ThreadState, ScalableState)> {
    let initial = case
        .scalable
        .as_ref()
        .context("scalable forms need scalable state")?;
    let svl = initial.svl;
    let mode = ScalableMode::from_svcr(initial.svcr).context("unsupported SVCR")?;
    let sme2 = profile.features().contains(ScalableFeature::Sme2);
    let mut thread = ThreadState {
        registers: case.state.clone(),
        pc: GuestAddress(CODE_PAGE),
    };
    let mut scalable = ScalableState::new(
        VectorLength::from_bytes(svl).context("unsupported SVL")?,
        sme2,
    );
    scalable.apply_mode(&mut thread.registers, mode)?;
    scalable.set_tpidr2_el0(initial.tpidr2);
    if mode.streaming() {
        for (register, z) in initial.z.chunks_exact(svl).enumerate() {
            scalable.write_z(&mut thread.registers, register as u8, z)?;
        }
        for (register, p) in initial.p.chunks_exact(svl / 8).enumerate() {
            scalable.write_predicate(register as u8, p)?;
        }
    }
    if mode.za_enabled() {
        scalable.write_za(0, &initial.za)?;
        if sme2 {
            scalable.write_zt0(0, &initial.zt0)?;
        }
    }
    // Entering streaming mode resets V and FPSR; the low part of each Z
    // register is the case's V register.
    thread.registers.v = case.state.v;
    thread.registers.fpsr = case.state.fpsr;
    Ok((thread, scalable))
}

/// Read back the banks the final mode enables; others keep their initial bytes.
fn store_scalable(case: &Case, thread: &ThreadState, scalable: &ScalableState) -> Result<Scalable> {
    let initial = case
        .scalable
        .as_ref()
        .context("scalable forms need scalable state")?;
    let svl = initial.svl;
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
        if scalable.has_zt0_storage() {
            scalable.read_zt0(0, &mut result.zt0)?;
        }
    }
    Ok(result)
}

/// Invoke a scalable block on runtime-owned state, completing a numerical exit.
fn scalable_block(
    block: &PreparedScalableBlock,
    profile: ExtendedBlockProfile,
    case: &Case,
) -> Result<(GuestState, u64, Scalable)> {
    let (mut thread, mut scalable) = load_scalable(case, profile.scalable())?;
    let mut context = ExecutionContext::default();
    // SAFETY: trusted single-instruction source over runtime-owned state.
    let exit = unsafe { block.invoke(&mut thread, &mut scalable, &mut context)? };
    if exit.kind == ExitKind::ScalableNumerical as u64 {
        block
            .complete_numerical(&mut thread, &mut scalable, exit)
            .map_err(|error| anyhow::anyhow!("numerical completion: {error:?}"))?;
    }
    let result = store_scalable(case, &thread, &scalable)?;
    Ok((thread.registers, thread.pc.0, result))
}

/// Execute a scalable leaf with a checked memory service over the data window.
fn scalable_leaf(
    leaf: &PreparedScalableLeaf,
    profile: ScalableProfile,
    windows: &Windows,
    case: &Case,
) -> Result<(GuestState, Scalable)> {
    let (mut thread, mut scalable) = load_scalable(case, profile)?;
    let mut memory = memory_thread(windows, leaf.identity().memory_requirements)?;
    let mut context = ExecutionContext::default();
    // SAFETY: the windows are owned, disjoint from every register store and
    // accessed only through this domain during the call.
    let exit = unsafe {
        leaf.execute(
            &mut thread.registers,
            &mut scalable,
            &mut memory,
            &mut context,
        )?
    };
    ensure!(
        matches!(exit, ScalableLeafExit::Returned),
        "native leaf exited with {exit:?}"
    );
    let result = store_scalable(case, &thread, &scalable)?;
    Ok((thread.registers, result))
}

/// A memory domain over the data window and the read-only code region, the
/// memory EL0 may access on the oracle, under the harness's controls: 39-bit addresses and
/// no tag checks. Cases keep SP 16-byte aligned, so either SP alignment policy
/// the leaf requires behaves as the original.
fn memory_thread(
    windows: &Windows,
    requirements: MemoryRequirements,
) -> Result<MemoryThread<MemoryControls>> {
    let permissions = |writable| AccessPermissions {
        readable: true,
        writable,
        executable: false,
    };
    let attributes = MappingAttributes {
        tagged: false,
        shareable: true,
    };
    let view = |host: NonNull<u8>, guest: u64, bytes: usize, writable: bool| -> Result<_> {
        let permissions = permissions(writable);
        // SAFETY: each window is a live private mapping for the process lifetime,
        // writable exactly when its view is.
        let backing = unsafe { MemoryBacking::new(host, bytes, permissions, Arc::new(())) }
            .map_err(|error| anyhow::anyhow!("window backing: {error:?}"))?;
        let view = MemoryView::new(backing, guest, 0, bytes, permissions)
            .map_err(|error| anyhow::anyhow!("window view: {error:?}"))?;
        Ok((view, attributes))
    };
    let views = vec![
        view(windows.data, DATA_WINDOW, DATA_BYTES, true)?,
        view(windows.code, CODE_REGION, CODE_REGION_BYTES, false)?,
    ];
    let system = MemorySystem::new(RESERVATION_GRANULE, RESERVATION_STRIPES)
        .map_err(|error| anyhow::anyhow!("memory system: {error:?}"))?;
    let domain = MemoryDomain::new(system, views, TargetCpu::Baseline)
        .map_err(|error| anyhow::anyhow!("memory domain: {error:?}"))?;
    let lower = LowerAddressProfile::new(ADDRESS_BITS, false)
        .map_err(|error| anyhow::anyhow!("address profile: {error:?}"))?;
    let controls =
        MemoryControls::new(lower, false, false, false, TagCheckFaultMode::Ignore, false)
            .with_effective_sp_alignment(
                requirements.required_sp_alignment != SpAlignmentRequirement::Disabled,
            )
            .with_implementation_profile(MemoryImplementationProfile::ScalableTagChecks);
    Ok(domain.thread(controls))
}

fn target() -> TargetCpu {
    TargetCpu::detect()
}
