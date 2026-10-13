//! Explicit Apple image sets with two-level chained binding and shared dispatch.
//! This is trusted entry research, not dyld or a complete macOS process loader.
use super::{
    chained_fixups::{self, DecodedFixups, RebaseFixup},
    exports::{self, Export},
    load_plan::{self, LoadPlan},
    mapped_image::{self, StackMapping, StackSpec},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use stela_compiler::GuestAddress;
use stela_runtime::{
    blocks::{BlockRuntime, RunOutcome, ThreadState},
    memory::{MemoryRegion, OwnedMemory},
};
use std::{collections::BTreeMap, path::PathBuf};

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
    /// Plan and bind every supplied image before atomically allocating the entire
    /// memory set. Input zero is MH_EXECUTE; later inputs must be MH_DYLIB with
    /// unique install identities. No dependency search, host substitution or
    /// initializers occur. Unreferenced dependencies remain explicit in receipts.
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

    /// Dispatch across the immutable source windows of every owned image.
    ///
    /// # Safety
    /// All code must be trusted, entry state must satisfy the research ABI, and
    /// accesses must stay in live suitable direct RAM without aliasing host state.
    /// Bound targets must require no pending initializer, TLS, signature, PAC or
    /// other launch work. Guest fault delivery and process isolation are absent;
    /// native faults may terminate this process. No concurrent mutation is allowed.
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
    use super::super::{
        chained_fixups::{BindFixup, Import},
        load_plan::{Dependency, EntryPoint},
    };
    use super::*;

    fn image(index: usize, identity: Option<&str>, name: &str, address: u64) -> ImageReceipt {
        ImageReceipt {
            index,
            container_sha256: String::new(),
            slice_offset: 0,
            load_base: 0,
            exports: vec![Export {
                name: name.into(),
                flags: 0,
                value: address,
                address,
            }],
            plan: LoadPlan {
                schema_version: 2,
                file_type: if index == 0 { 2 } else { 6 },
                dylib_identity: identity.map(|name| Dependency {
                    command: 0xd,
                    name: name.into(),
                    timestamp: 0,
                    current_version: 0,
                    compatibility_version: 0,
                }),
                slice_sha256: String::new(),
                slice_bytes: 0,
                cpu_type: 0x100000c,
                cpu_subtype: 0,
                architecture: "arm64".into(),
                header_flags: object::macho::MH_TWOLEVEL,
                segments: vec![],
                entry: Some(EntryPoint {
                    image_offset: 0,
                    file_offset: 0,
                    guest_address: 0,
                    stack_size: 0,
                }),
                dependencies: vec![Dependency {
                    command: 0xc,
                    name: "@rpath/a.dylib".into(),
                    timestamp: 0,
                    current_version: 0,
                    compatibility_version: 0,
                }],
                dylinker: None,
                rpaths: vec![],
                payloads: vec![],
                deferred_commands: vec![],
                execution_supported: false,
                unresolved_requirements: vec![],
            },
            fixups: DecodedFixups {
                authenticated_rebases: vec![],
                authenticated_binds: vec![],
                preferred_base: 0,
                load_base: 0,
                pointer_formats: vec![6],
                rebases: vec![],
                imports: vec![Import {
                    library_ordinal: 1,
                    weak: false,
                    name: "_f".into(),
                    addend: 3,
                }],
                binds: if index == 0 {
                    vec![BindFixup {
                        segment_index: 0,
                        file_offset: 0,
                        guest_address: 0,
                        raw: 1 << 63,
                        pointer_format: 6,
                        import_index: 0,
                        inline_addend: 4,
                        addend: 7,
                    }]
                } else {
                    vec![]
                },
            },
            bindings: vec![],
            applied_rebases: 0,
            applied_binds: 0,
        }
    }

    #[test]
    fn binding_selects_declared_provider_and_adds_combined_addend_once() {
        let images = vec![
            image(0, None, "_f", 0x1000),
            image(1, Some("@rpath/a.dylib"), "_f", 0x2000),
            image(2, Some("@rpath/b.dylib"), "_f", 0x3000),
        ];
        let result = resolve_bindings(&images, None).unwrap();
        assert_eq!(
            (
                result[0][0].provider_image,
                result[0][0].address,
                result[0][0].value
            ),
            (1, 0x2000, 0x2007)
        );
        assert!(result[1].is_empty() && result[2].is_empty());
    }

    #[test]
    fn discovered_bindings_use_selected_file_edges_without_install_name_fallback() {
        let mut images = vec![
            image(0, None, "_main", 0),
            image(1, Some("@rpath/b.dylib"), "_f", 0x2000),
        ];
        assert!(resolve_bindings(&images, None).is_err());
        let link = DependencyLink {
            requester: 0,
            ordinal: 1,
            provider: 1,
        };
        assert_eq!(
            resolve_bindings(&images, Some(std::slice::from_ref(&link))).unwrap()[0][0].value,
            0x2007
        );
        images[1].plan.dylib_identity.as_mut().unwrap().name = "@rpath/a.dylib".into();
        assert!(resolve_bindings(&images, Some(&[])).is_err());
        assert!(resolve_bindings(&images, Some(&[link.clone(), link])).is_err());
        assert!(
            resolve_bindings(
                &images,
                Some(&[DependencyLink {
                    requester: 0,
                    ordinal: 1,
                    provider: 0
                }])
            )
            .is_err()
        );
    }

    #[test]
    fn binding_declines_missing_duplicate_weak_and_flat_resolution() {
        let mut images = vec![
            image(0, None, "_main", 0),
            image(1, Some("@rpath/b.dylib"), "_f", 0x2000),
        ];
        assert!(resolve_bindings(&images, None).is_err());
        images[1].plan.dylib_identity.as_mut().unwrap().name = "@rpath/a.dylib".into();
        images.push(image(2, Some("@rpath/a.dylib"), "_f", 0x3000));
        assert!(resolve_bindings(&images, None).is_err());
        images.pop();
        images[0].fixups.imports[0].weak = true;
        assert!(resolve_bindings(&images, None).is_err());
        images[0].fixups.imports[0].weak = false;
        for ordinal in [-3, -2, -1, 0, 2] {
            images[0].fixups.imports[0].library_ordinal = ordinal;
            assert!(resolve_bindings(&images, None).is_err());
        }
        images[0].fixups.imports[0].library_ordinal = 1;
        images[0].plan.header_flags = 0;
        assert!(resolve_bindings(&images, None).is_err());
        images[0].plan.header_flags = object::macho::MH_TWOLEVEL;
        images[1].exports[0].name = "_missing".into();
        assert!(resolve_bindings(&images, None).is_err());
    }

    #[test]
    fn bound_addends_check_both_directions_and_native_address_boundary() {
        assert_eq!(binding_value(0x2000, -7).unwrap(), 0x1ff9);
        assert!(binding_value(0, -1).is_err());
        assert!(binding_value(u64::MAX, 1).is_err());
        assert!(binding_value(1 << 47, 0).is_err());
        assert_eq!(binding_value((1 << 47) - 1, 0).unwrap(), (1 << 47) - 1);
    }
}
