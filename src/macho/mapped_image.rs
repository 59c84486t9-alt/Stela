//! Owned segment mappings with checked placement and chained pointer rebases.
//! This preserves pending dyld/process work and does not validate an Apple launch.
use super::{
    chained_fixups::{self, FixupPlan},
    load_plan::{self, LoadPlan},
};
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
    fixups: FixupPlan,
    mapped_entry: u64,
}

/// Slide ordinary image addresses without truncating a negative delta or overflow.
fn relocated(address: u64, preferred_base: u64, load_base: u64) -> Result<u64> {
    u64::try_from(i128::from(address) + i128::from(load_base) - i128::from(preferred_base))
        .context("slid image address overflow")
}

impl MappedImage {
    /// Copy file-backed bytes, zero-fill segment tails, apply initial data
    /// protections and register immutable instruction snapshots. Guest execute
    /// permission never gives original Arm bytes host execute permission.
    /// Selected addresses must be available; no host mappings are replaced.
    /// Unauthenticated chained rebases are applied before final protections;
    /// imports, authenticated pointers, signatures and initializers remain pending.
    pub fn load(
        data: &[u8],
        cache: PathBuf,
        stack: Option<StackSpec>,
        image_base: Option<u64>,
    ) -> Result<Self> {
        let plan = load_plan::plan(data)?;
        let preferred_base = plan
            .segments
            .iter()
            .find(|segment| segment.name == "__TEXT")
            .context("missing preferred image base")?
            .guest
            .address;
        let load_base = image_base.unwrap_or(preferred_base);
        ensure!(
            (i128::from(load_base) - i128::from(preferred_base)) % 0x4000 == 0,
            "image slide must be a multiple of the Apple profile's 16 KiB page size"
        );
        ensure!(
            !plan.payloads.iter().any(|payload| payload.file.bytes != 0
                && matches!(
                    payload.role.as_str(),
                    "rebase" | "bind" | "weak_bind" | "lazy_bind"
                )),
            "legacy dyld rebase/bind streams are unsupported by mapped execution"
        );
        let fixups = chained_fixups::plan(data, &plan, load_base)?;
        let mapped_entry = relocated(plan.entry.guest_address, preferred_base, load_base)?;
        let mut initial = Vec::with_capacity(plan.segments.len());
        for segment in &plan.segments {
            let start = usize::try_from(segment.file.offset)?;
            let end = usize::try_from(
                segment
                    .file
                    .offset
                    .checked_add(segment.file.bytes)
                    .context("segment file extent overflow")?,
            )?;
            initial.push(
                data.get(start..end)
                    .context("segment file extent changed")?
                    .to_vec(),
            );
        }
        // Preflight every patch before mapping any host memory. The source image
        // remains unchanged, and code snapshots use the same initialized bytes.
        for rebase in &fixups.rebases {
            ensure!(
                rebase.value < (1u64 << 47),
                "tagged or noncanonical chained pointer requires guest address translation"
            );
            let segment = plan
                .segments
                .get(rebase.segment_index)
                .context("fixup segment index changed")?;
            ensure!(
                segment.maximum_protection & 2 != 0 && segment.initial_protection & 4 == 0,
                "chained rebases require a non-executable segment with writable maximum protection"
            );
            let offset = rebase
                .file_offset
                .checked_sub(segment.file.offset)
                .context("fixup precedes segment file range")?;
            ensure!(
                rebase.guest_address
                    == relocated(
                        segment
                            .guest
                            .address
                            .checked_add(offset)
                            .context("fixup address overflow")?,
                        preferred_base,
                        load_base
                    )?,
                "fixup file and guest placement disagree"
            );
            let start = usize::try_from(offset)?;
            let end = start.checked_add(8).context("fixup patch range overflow")?;
            let slot = initial[rebase.segment_index]
                .get_mut(start..end)
                .context("fixup exceeds initialized segment bytes")?;
            ensure!(
                slot == rebase.raw.to_le_bytes(),
                "fixup source bytes changed"
            );
            slot.copy_from_slice(&rebase.value.to_le_bytes());
        }
        let mut specs = Vec::new();
        let mut unreserved_guards = Vec::new();
        let mut code = Vec::new();
        for (segment, bytes) in plan.segments.iter().zip(initial) {
            if segment.guest.bytes == 0 {
                continue;
            }
            ensure!(
                segment.flags & object::macho::SG_READ_ONLY == 0
                    || segment.initial_protection & 1 != 0,
                "read-only-after-fixups segment requires declared read permission"
            );
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
            let guest_address = relocated(segment.guest.address, preferred_base, load_base)?;
            ensure!(
                segment.initial_protection & 6 != 6,
                "writable guest code is unsupported"
            );
            if segment.initial_protection & 4 != 0 && !bytes.is_empty() {
                code.push((guest_address, bytes.clone()));
            }
            specs.push(MemoryRegionSpec {
                guest_address,
                virtual_bytes: segment.guest.bytes,
                initial_bytes: bytes,
                readable: segment.initial_protection & 1 != 0,
                writable: segment.initial_protection & 2 != 0
                    && segment.flags & object::macho::SG_READ_ONLY == 0,
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
        for (address, bytes) in code {
            runtime.register_code(GuestAddress(address), bytes)?;
        }
        Ok(Self {
            runtime,
            memory,
            plan,
            unreserved_guards,
            stack,
            fixups,
            mapped_entry,
        })
    }

    pub fn plan(&self) -> &LoadPlan {
        &self.plan
    }
    pub fn fixups(&self) -> &FixupPlan {
        &self.fixups
    }
    pub fn mapped_entry(&self) -> u64 {
        self.mapped_entry
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_preserves_offsets_for_both_slide_directions_without_wrapping() {
        assert_eq!(
            relocated(0x1_0000_1234, 0x1_0000_0000, 0x400_0000_0000).unwrap(),
            0x400_0000_1234
        );
        assert_eq!(
            relocated(0x400_0000_1234, 0x400_0000_0000, 0x1_0000_0000).unwrap(),
            0x1_0000_1234
        );
        assert_eq!(relocated(0x8000, 0x10000, 0x10000).unwrap(), 0x8000);
        assert!(relocated(0, 0x10000, 0).is_err());
        assert!(relocated(u64::MAX, 0, 1).is_err());
    }
}
