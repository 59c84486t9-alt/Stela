//! A set of images bound to each other through chained fixups and run from an
//! entry point (not a full dyld or process loader).
use super::{
    chained_fixups::{self, DecodedFixups, RebaseFixup},
    exports::{self, Export},
    load_plan::{self, LoadPlan},
    mapped_image::{self, StackMapping, StackSpec},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::BTreeMap, path::PathBuf};
use stela_compiler::GuestAddress;
use stela_runtime::{
    blocks::{BlockRuntime, RunOutcome, ThreadState},
    memory::{MemoryRegion, OwnedMemory},
};

pub struct ImageInput {
    pub data: Vec<u8>,
    pub container_sha256: String,
    pub slice_offset: u64,
    pub load_base: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyLink {
    pub requester: usize,
    pub ordinal: usize,
    pub provider: usize,
}

#[derive(Debug, Serialize)]
pub struct Binding {
    pub import_index: u32,
    pub library_ordinal: i32,
    pub name: String,
    pub provider_image: usize,
    pub address: u64,
    pub addend: i64,
    pub value: u64,
    pub guest_address: u64,
    pub raw: u64,
    pub file_offset: u64,
    pub segment_index: usize,
    pub pointer_format: u16,
}

#[derive(Debug, Serialize)]
pub struct ImageReceipt {
    pub index: usize,
    pub container_sha256: String,
    pub slice_offset: u64,
    pub plan: LoadPlan,
    pub load_base: u64,
    pub exports: Vec<Export>,
    pub fixups: DecodedFixups,
    pub bindings: Vec<Binding>,
    pub applied_rebases: usize,
    pub applied_binds: usize,
}

#[derive(Debug, Serialize)]
pub struct UnreservedGuard {
    pub image_index: usize,
    pub segment: String,
    pub guest_address: u64,
    pub virtual_bytes: u64,
}

#[derive(Debug)]
pub struct LinkedImages {
    runtime: BlockRuntime,
    memory: OwnedMemory,
    images: Vec<ImageReceipt>,
    guards: Vec<UnreservedGuard>,
    stack: StackMapping,
    entry: u64,
}

fn binding_value(address: u64, addend: i64) -> Result<u64> {
    let value = u64::try_from(i128::from(address) + i128::from(addend))
        .context("bound symbol address/addend overflow")?;
    ensure!(
        value < (1u64 << 47),
        "bound symbol requires tagged/noncanonical guest address translation"
    );
    Ok(value)
}

fn resolve_bindings(
    images: &[ImageReceipt],
    links: Option<&[DependencyLink]>,
) -> Result<Vec<Vec<Binding>>> {
    let mut linked = BTreeMap::new();
    if let Some(links) = links {
        for link in links {
            ensure!(
                link.requester < images.len()
                    && link.provider > 0
                    && link.provider < images.len()
                    && link.ordinal > 0
                    && link.ordinal <= images[link.requester].plan.dependencies.len(),
                "invalid discovered dependency link"
            );
            ensure!(
                linked
                    .insert((link.requester, link.ordinal), link.provider)
                    .is_none(),
                "duplicate discovered dependency link"
            );
        }
    }
    let mut providers = BTreeMap::new();
    for image in &images[1..] {
        let id = image
            .plan
            .dylib_identity
            .as_ref()
            .context("library has no install identity")?;
        ensure!(
            providers.insert(id.name.as_str(), image.index).is_none(),
            "duplicate provided dylib install identity {:?}",
            id.name
        );
    }
    let exports: Vec<BTreeMap<_, _>> = images
        .iter()
        .map(|image| {
            image
                .exports
                .iter()
                .map(|export| (export.name.as_str(), export))
                .collect()
        })
        .collect();
    let mut resolved = Vec::with_capacity(images.len());
    for image in images {
        let mut rows = Vec::new();
        if !image.fixups.binds.is_empty() {
            ensure!(
                image.plan.header_flags & object::macho::MH_TWOLEVEL != 0
                    && images[0].plan.header_flags & object::macho::MH_FORCE_FLAT == 0,
                "linked binding requires a two-level namespace without forced flat lookup"
            );
        }
        for slot in &image.fixups.binds {
            let import = image
                .fixups
                .imports
                .get(slot.import_index as usize)
                .context("bind import index changed")?;
            ensure!(
                !import.weak,
                "weak import/coalescing resolution is unsupported for {:?}",
                import.name
            );
            ensure!(
                import.library_ordinal > 0,
                "special/self/flat library ordinal {} is unsupported for {:?}",
                import.library_ordinal,
                import.name
            );
            let dependency = image
                .plan
                .dependencies
                .get(import.library_ordinal as usize - 1)
                .context("bind dependency ordinal exceeds load commands")?;
            ensure!(
                dependency.command == object::macho::LC_LOAD_DYLIB,
                "binding through nonordinary dependency command {:#x} is unsupported",
                dependency.command
            );
            let provider = if links.is_some() {
                *linked
                    .get(&(image.index, import.library_ordinal as usize))
                    .with_context(|| {
                        format!(
                            "missing discovered dependency {:?} for symbol {:?}",
                            dependency.name, import.name
                        )
                    })?
            } else {
                *providers.get(dependency.name.as_str()).with_context(|| {
                    format!(
                        "missing provided dylib {:?} for symbol {:?}",
                        dependency.name, import.name
                    )
                })?
            };
            let symbol = exports[provider]
                .get(import.name.as_str())
                .with_context(|| {
                    format!(
                        "undefined symbol {:?} in provided dylib {:?}",
                        import.name, dependency.name
                    )
                })?;
            ensure!(
                symbol.flags & 4 == 0,
                "weak export/coalescing resolution is unsupported for {:?}",
                import.name
            );
            rows.push(Binding {
                import_index: slot.import_index,
                library_ordinal: import.library_ordinal,
                name: import.name.clone(),
                provider_image: provider,
                address: symbol.address,
                addend: slot.addend,
                value: binding_value(symbol.address, slot.addend)?,
                guest_address: slot.guest_address,
                raw: slot.raw,
                file_offset: slot.file_offset,
                segment_index: slot.segment_index,
                pointer_format: slot.pointer_format,
            });
        }
        resolved.push(rows);
    }
    Ok(resolved)
}

fn bound_write(binding: &Binding) -> RebaseFixup {
    RebaseFixup {
        segment_index: binding.segment_index,
        file_offset: binding.file_offset,
        guest_address: binding.guest_address,
        raw: binding.raw,
        value: binding.value,
        pointer_format: binding.pointer_format,
    }
}

impl LinkedImages {
    /// Plan and bind every image, then allocate all their memory at once. Input
    /// zero is the MH_EXECUTE; the others must be MH_DYLIBs with unique install
    /// names. No dependency search or initializers run; unreferenced
    /// dependencies are reported.
    pub fn load(inputs: Vec<ImageInput>, cache: PathBuf, stack: StackSpec) -> Result<Self> {
        Self::load_with_links(inputs, cache, stack, None)
    }

    /// Bind using requester/ordinal edges discovered from the guest filesystem.
    /// Selected file provenance authorizes a provider whose install identity can
    /// differ from its load-path spelling. No install-name fallback fills holes.
    pub fn load_discovered(
        inputs: Vec<ImageInput>,
        cache: PathBuf,
        stack: StackSpec,
        links: &[DependencyLink],
    ) -> Result<Self> {
        Self::load_with_links(inputs, cache, stack, Some(links))
    }

    fn load_with_links(
        inputs: Vec<ImageInput>,
        cache: PathBuf,
        stack: StackSpec,
        links: Option<&[DependencyLink]>,
    ) -> Result<Self> {
        ensure!(
            !inputs.is_empty() && inputs.len() <= 32,
            "linked image set requires 1..32 explicit images"
        );
        let mut images = Vec::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            let plan = if index == 0 {
                load_plan::plan(&input.data)?
            } else {
                load_plan::plan_library(&input.data)?
            };
            let load_base = input
                .load_base
                .unwrap_or(mapped_image::preferred_base(&plan)?);
            let fixups = chained_fixups::decode(&input.data, &plan, load_base)?;
            let exports = exports::parse(&input.data, &plan, load_base)?;
            images.push(ImageReceipt {
                index,
                container_sha256: input.container_sha256.clone(),
                slice_offset: input.slice_offset,
                plan,
                load_base,
                exports,
                applied_rebases: fixups.rebases.len(),
                fixups,
                bindings: vec![],
                applied_binds: 0,
            });
        }
        let bindings = resolve_bindings(&images, links)?;
        let mut specs = Vec::new();
        let mut code = Vec::new();
        let mut guards = Vec::new();
        for ((image, input), bindings) in images.iter_mut().zip(&inputs).zip(bindings) {
            let mut writes = image.fixups.rebases.clone();
            writes.extend(bindings.iter().map(bound_write));
            let prepared =
                mapped_image::prepare_segments(&input.data, &image.plan, image.load_base, &writes)?;
            specs.extend(prepared.specs);
            code.extend(prepared.code);
            guards.extend(
                prepared
                    .unreserved_guards
                    .into_iter()
                    .map(|guard| UnreservedGuard {
                        image_index: image.index,
                        segment: guard.segment,
                        guest_address: guard.guest_address,
                        virtual_bytes: guard.virtual_bytes,
                    }),
            );
            image.applied_binds = bindings.len();
            image.bindings = bindings;
        }
        let stack = mapped_image::add_stack(&mut specs, Some(stack))?
            .context("missing linked research stack")?;
        let entry = mapped_image::relocated(
            images[0].plan.executable_entry()?.guest_address,
            mapped_image::preferred_base(&images[0].plan)?,
            images[0].load_base,
        )?;
        let memory = OwnedMemory::map(specs)?;
        let mut runtime = BlockRuntime::new(1, cache);
        for (address, source) in code {
            runtime.register_code(GuestAddress(address), source)?;
        }
        Ok(Self {
            runtime,
            memory,
            images,
            guards,
            stack,
            entry,
        })
    }

    pub fn images(&self) -> &[ImageReceipt] {
        &self.images
    }
    pub fn regions(&self) -> &[MemoryRegion] {
        self.memory.regions()
    }
    pub fn guards(&self) -> &[UnreservedGuard] {
        &self.guards
    }
    pub fn stack(&self) -> &StackMapping {
        &self.stack
    }
    pub fn entry(&self) -> u64 {
        self.entry
    }
    pub fn read_snapshot(&self, address: u64, bytes: usize) -> Result<Vec<u8>> {
        self.memory.read_snapshot(address, bytes)
    }

    /// Run from the entry point across the source of every image.
    ///
    /// # Safety
    /// All code must be trusted and the entry state must satisfy its ABI.
    /// Accesses must stay in live direct RAM that aliases no host state. Bound
    /// targets must need no pending initializer, TLS, signature, PAC or other
    /// launch work. There is no guest fault delivery or process isolation, so a
    /// native fault may terminate the process. Nothing may mutate the images
    /// concurrently.
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
mod tests;
