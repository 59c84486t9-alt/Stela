//! Owned initial segment mappings for trusted, unrelocated entry-code research.
//! This preserves pending dyld/process work and does not validate an Apple launch.
use super::{block_image::BlockImage, load_plan::LoadPlan};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_compiler::GuestAddress;
use stela_runtime::{
    blocks::{BlockRuntime, RunOutcome, ThreadState},
    memory::{MemoryRegion, MemoryRegionSpec, OwnedMemory, host_page_size},
};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub struct StackSpec {
    pub base: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct StackMapping {
    pub base: u64,
    pub bytes: u64,
    pub guard_bytes: u64,
    pub initial_sp: u64,
}

#[derive(Debug, Serialize)]
pub struct UnreservedGuard {
    pub segment: String,
    pub guest_address: u64,
    pub virtual_bytes: u64,
}

#[derive(Debug)]
pub struct MappedImage {
    runtime: BlockRuntime,
    memory: OwnedMemory,
    plan: LoadPlan,
    unreserved_guards: Vec<UnreservedGuard>,
    stack: Option<StackMapping>,
}

impl MappedImage {
    /// Copy file-backed bytes, zero-fill segment tails, apply initial data
    /// protections and register immutable instruction snapshots. Guest execute
    /// permission never gives original Arm bytes host execute permission.
    /// Preferred addresses must be available; no host mappings are replaced.
    /// Relocations, imports, signatures and initializers are not applied.
    pub fn load(data: &[u8], cache: PathBuf, stack: Option<StackSpec>) -> Result<Self> {
        let image = BlockImage::from_slice(data)?;
        let plan = image.plan().clone();
        let mut specs = Vec::new();
        let mut unreserved_guards = Vec::new();
        for segment in &plan.segments {
            if segment.guest.bytes == 0 {
                continue;
            }
            if segment.initial_protection == 0 && segment.file.bytes == 0 {
                // __PAGEZERO may span 4 GiB and overlap native-process address
                // reservations. It is recorded, never replaced/reserved here;
                // no guest null/guard-fault guarantee follows from this loader.
                unreserved_guards.push(UnreservedGuard {
                    segment: segment.name.clone(),
                    guest_address: segment.guest.address,
                    virtual_bytes: segment.guest.bytes,
                });
                continue;
            }
            let start = usize::try_from(segment.file.offset)?;
            let end = usize::try_from(
                segment
                    .file
                    .offset
                    .checked_add(segment.file.bytes)
                    .context("segment file extent overflow")?,
            )?;
            specs.push(MemoryRegionSpec {
                guest_address: segment.guest.address,
                virtual_bytes: segment.guest.bytes,
                initial_bytes: data
                    .get(start..end)
                    .context("segment file extent changed")?
                    .to_vec(),
                readable: segment.initial_protection & 1 != 0,
                writable: segment.initial_protection & 2 != 0,
                executable: segment.initial_protection & 4 != 0,
            });
        }
        let stack = if let Some(spec) = stack {
            let page = host_page_size()? as u64;
            ensure!(
                spec.bytes >= page && spec.bytes.is_multiple_of(page),
                "research stack size must be a positive host-page multiple"
            );
            let low = spec
                .base
                .checked_sub(page)
                .context("stack guard address underflow")?;
            let high = spec
                .base
                .checked_add(spec.bytes)
                .context("stack address overflow")?;
            for base in [low, high] {
                specs.push(MemoryRegionSpec {
                    guest_address: base,
                    virtual_bytes: page,
                    initial_bytes: vec![],
                    readable: false,
                    writable: false,
                    executable: false,
                });
            }
            specs.push(MemoryRegionSpec {
                guest_address: spec.base,
                virtual_bytes: spec.bytes,
                initial_bytes: vec![],
                readable: true,
                writable: true,
                executable: false,
            });
            Some(StackMapping {
                base: spec.base,
                bytes: spec.bytes,
                guard_bytes: page,
                initial_sp: high & !15,
            })
        } else {
            None
        };
        let memory = OwnedMemory::map(specs)?;
        let mut runtime = BlockRuntime::new(1, cache);
        for region in image.regions() {
            runtime.register_code(
                GuestAddress(region.guest_address()),
                region.bytes().to_vec(),
            )?;
        }
        Ok(Self {
            runtime,
            memory,
            plan,
            unreserved_guards,
            stack,
        })
    }

    pub fn plan(&self) -> &LoadPlan {
        &self.plan
    }
    pub fn regions(&self) -> &[MemoryRegion] {
        self.memory.regions()
    }
    pub fn unreserved_guards(&self) -> &[UnreservedGuard] {
        &self.unreserved_guards
    }
    pub fn stack(&self) -> Option<&StackMapping> {
        self.stack.as_ref()
    }
    pub fn read_snapshot(&self, address: u64, bytes: usize) -> Result<Vec<u8>> {
        self.memory.read_snapshot(address, bytes)
    }

    /// Run under the native block direct-RAM profile while every segment/stack
    /// mapping is alive and exclusively owned by this image.
    ///
    /// # Safety
    /// Code must be trusted and every accessed address must lie within suitable
    /// live mappings or caller-owned direct RAM. Accessed data must not require
    /// any still-pending relocation/import/initializer. Guest writes must not
    /// alias runtime/state/host objects or immutable instruction snapshots.
    /// Caller supplies the required entry ABI and excludes concurrent mutation.
    /// PAC/GCS/guarded transfer semantics, process startup and exception delivery
    /// remain unsupported; native faults may terminate the host process. Skipped
    /// guards and page padding are not hardware guest-bounds guarantees.
    pub unsafe fn run(
        &mut self,
        state: &mut ThreadState,
        stop: Option<GuestAddress>,
        budget: usize,
    ) -> Result<RunOutcome> {
        unsafe { self.runtime.run(state, stop, budget) }
    }
}
