//! Persistent, image-backed and normal-thread paths refuse the context ABI.
use anyhow::Result;
use std::path::Path;
use stela_compiler::{GuestAddress, GuestState, TargetCpu, context::CONTEXT_BLOCK_ABI};
use stela_core::{sha256, write_json};
use stela_runtime::{
    Manifest, Prepared,
    blocks::{BlockRuntime, ThreadState},
    dispatch::LeafDispatcher,
    prepare_block_for_target, prepare_leaf_for_target,
};

const BASE: GuestAddress = GuestAddress(0x1000);
const NOP: u32 = 0xd503_201f;
const RET: u32 = 0xd65f_03c0;

fn source() -> Vec<u8> {
    [NOP, RET]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect()
}

fn substitute_context_abi(prepared: &Prepared) -> Result<()> {
    let directory = &prepared.directory;
    let path = directory.join("manifest.json");
    let mut manifest: Manifest = serde_json::from_slice(&std::fs::read(&path)?)?;
    manifest.identity.abi = CONTEXT_BLOCK_ABI.into();
    write_json(&path, &manifest)?;
    write_json(
        &directory.join("manifest.sha256.json"),
        &sha256(&std::fs::read(path)?),
    )?;
    Ok(())
}

fn one_cache_entry(root: &Path) -> Result<usize> {
    Ok(std::fs::read_dir(root)?.count())
}

#[test]
fn validly_checksummed_context_block_is_refused_by_persistent_aot_loaders() -> Result<()> {
    for block in [false, true] {
        let root = tempfile::tempdir()?;
        let bytes = source();
        let current = if block {
            prepare_block_for_target(
                &bytes,
                BASE,
                root.path(),
                Default::default(),
                TargetCpu::Baseline,
            )?
            .prepared
        } else {
            prepare_leaf_for_target(&bytes, BASE, root.path(), TargetCpu::Baseline)?
        };
        let native_before = std::fs::read(current.directory.join("native.bin"))?;
        substitute_context_abi(&current)?;
        let result = if block {
            prepare_block_for_target(
                &bytes,
                BASE,
                root.path(),
                Default::default(),
                TargetCpu::Baseline,
            )
            .map(|value| value.prepared)
        } else {
            prepare_leaf_for_target(&bytes, BASE, root.path(), TargetCpu::Baseline)
        };
        assert!(result.is_err());
        assert_eq!(
            std::fs::read(current.directory.join("native.bin"))?,
            native_before
        );
        assert_eq!(one_cache_entry(root.path())?, 1);
    }
    Ok(())
}

#[test]
fn registered_image_snapshot_and_normal_thread_refuse_context_block_cache() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new_for_target(
        1,
        root.path().to_owned(),
        Default::default(),
        TargetCpu::Baseline,
    );
    // BlockImage/linked-image callers register exact ARM source through this same path.
    runtime.register_code(BASE, source())?;
    let prepared = runtime.prepare(BASE)?.prepared;
    substitute_context_abi(&prepared)?;
    assert!(runtime.prepare(BASE).is_err());
    let mut state = ThreadState {
        pc: BASE,
        registers: GuestState::default(),
    };
    state.registers.x[0] = 0x1234;
    let before = state.registers.clone();
    // SAFETY: The registered NOP/RET source has no RAM effects. Corrupt ABI
    // metadata must fail during preparation, before any RX entry or guest RET.
    assert!(unsafe { runtime.run(&mut state, None, 1) }.is_err());
    assert_eq!(state.pc, BASE);
    assert_eq!(state.registers, before);
    assert!(runtime.loaded_manifest(BASE).is_none());
    Ok(())
}

#[test]
fn existing_leaf_registry_cannot_resolve_a_context_block_identity() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut dispatcher = LeafDispatcher::new(1, root.path().to_owned());
    dispatcher.register(BASE, source())?;
    let resolved = dispatcher.resolve(BASE)?;
    substitute_context_abi(resolved.prepared())?;
    assert!(dispatcher.resolve(BASE).is_err());
    Ok(())
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn normal_thread_rejects_a_numerical_exit_before_pc_or_instruction_commit() -> Result<()> {
    use stela_compiler::block::ExitKind;
    const MOV_RAX_IMMEDIATE: [u8; 2] = [0x48, 0xb8];
    const MOV_EDX_IMMEDIATE: u8 = 0xba;
    const RETURN: u8 = 0xc3;
    let root = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new_for_target(
        1,
        root.path().to_owned(),
        Default::default(),
        TargetCpu::Baseline,
    );
    runtime.register_code(BASE, source())?;
    let prepared = runtime.prepare(BASE)?.prepared;
    // A deliberately invalid native body: a no-effect struct-return that asks
    // an ordinary engine for the context-only service exit.
    let mut native = MOV_RAX_IMMEDIATE.to_vec();
    native.extend(BASE.0.to_le_bytes());
    native.push(MOV_EDX_IMMEDIATE);
    native.extend((ExitKind::ScalableNumerical as u32).to_le_bytes());
    native.push(RETURN);
    let mut manifest = prepared.manifest;
    manifest.native_bytes = native.len();
    manifest.native_sha256 = sha256(&native);
    std::fs::write(prepared.directory.join("native.bin"), &native)?;
    write_json(&prepared.directory.join("manifest.json"), &manifest)?;
    write_json(
        &prepared.directory.join("manifest.sha256.json"),
        &sha256(&std::fs::read(prepared.directory.join("manifest.json"))?),
    )?;
    let mut state = ThreadState {
        pc: BASE,
        registers: GuestState::default(),
    };
    let before = state.registers.clone();
    // SAFETY: the body only sets RAX/RDX and touches no guest state or RAM.
    let error = unsafe { runtime.run(&mut state, None, 1) }.unwrap_err();
    assert!(error.to_string().contains("requires owned scalable entry"));
    assert_eq!(state.pc, BASE);
    assert_eq!(state.registers, before);
    Ok(())
}
