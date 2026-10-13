//! A bounded original-dyld startup probe, not an application launcher.
//! Only the reviewed register-only prefix and optionally its first software PAC
//! operation run. Main/dyld segments and argument memory stay owned together.
use crate::macho::{load_plan, mapped_image};
use anyhow::{Context, Result, ensure};
use stela_compiler::{GuestAddress, GuestState};
use stela_runtime::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    memory::OwnedMemory,
    process::{ProcessArguments, plan_kernel_args},
};
use std::path::{Path, PathBuf};

pub struct Options {
    pub dyld_slide: u64,
    pub image_base: u64,
    pub stack_base: u64,
    pub stack_bytes: u64,
    pub cache_dir: PathBuf,
    pub software_pauth_ib_key: Option<PathBuf>,
}

fn instruction(data: &[u8], plan: &load_plan::LoadPlan, address: u64) -> Result<u32> {
    let end = address
        .checked_add(4)
        .context("instruction extent overflow")?;
    let segment = plan
        .segments
        .iter()
        .find(|s| {
            s.initial_protection & 5 == 5
                && s.guest.address <= address
                && s.guest
                    .address
                    .checked_add(s.file.bytes)
                    .is_some_and(|limit| end <= limit)
        })
        .context("startup instruction is outside readable executable file bytes")?;
    let offset = segment
        .file
        .offset
        .checked_add(address - segment.guest.address)
        .context("instruction file offset overflow")?;
    let start = usize::try_from(offset)?;
    let end = start
        .checked_add(4)
        .context("instruction file extent overflow")?;
    Ok(u32::from_le_bytes(
        data.get(start..end)
            .context("startup instruction is truncated")?
            .try_into()?,
    ))
}

/// Whitelist exact startup semantics before the direct-RAM unsafe boundary.
/// The final B target is recovered independently of the compiler decoder.
fn startup_target(words: [u32; 5], entry: u64) -> Result<u64> {
    ensure!(
        words[..4] == [0x910003e0, 0x927cec1f, 0xd280001d, 0xd280001e],
        "dyld probe requires reviewed MOV X0,SP; AND SP,X0,~15; MOV FP,0; MOV LR,0 prefix"
    );
    ensure!(
        words[4] & 0xfc000000 == 0x14000000,
        "dyld startup requires direct B"
    );
    let delta = i64::from(((words[4] & 0x03ffffff) << 6) as i32 >> 6) * 4;
    let branch_pc = entry
        .checked_add(16)
        .context("startup branch PC overflow")?;
    u64::try_from(i128::from(branch_pc) + i128::from(delta)).context("startup target overflow")
}

pub fn probe(
    dyld_path: &Path,
    executable: &Path,
    args: &ProcessArguments,
    options: Options,
) -> Result<serde_json::Value> {
    let dyld_data = std::fs::read(dyld_path)?;
    let (dyld_offset, dyld_bytes) = crate::apple_slice(&dyld_data, dyld_path, None)?;
    let dyld = load_plan::plan_dynamic_linker(dyld_bytes)?;
    let main_data = std::fs::read(executable)?;
    let (main_offset, main_bytes) = crate::apple_slice(&main_data, executable, None)?;
    let main = load_plan::plan(main_bytes)?;
    ensure!(
        main.dylinker.as_deref() == Some(dyld.install_name.as_str()),
        "executable LC_LOAD_DYLINKER differs from supplied dyld identity"
    );
    ensure!(
        dyld.thread.cpsr & !0xf0000000 == 0 && dyld.thread.pad == 0,
        "startup probe supports only NZCV CPSR bits and zero thread-state padding"
    );
    let words = (0..5)
        .map(|i| {
            instruction(
                dyld_bytes,
                &dyld.image,
                dyld.thread
                    .pc
                    .checked_add(i * 4)
                    .context("startup extent overflow")?,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let target = startup_target(words.as_slice().try_into()?, dyld.thread.pc)?;
    ensure!(
        instruction(dyld_bytes, &dyld.image, target)? == 0xd503237f,
        "reviewed dyld startup boundary must be original PACIBSP"
    );
    let dyld_preferred = mapped_image::preferred_base(&dyld.image)?;
    let dyld_base = dyld_preferred
        .checked_add(options.dyld_slide)
        .context("dyld slide overflow")?;
    let entry = dyld
        .thread
        .pc
        .checked_add(options.dyld_slide)
        .context("dyld entry slide overflow")?;
    let target_pc = target
        .checked_add(options.dyld_slide)
        .context("dyld target slide overflow")?;
    let context = options
        .software_pauth_ib_key
        .as_deref()
        .map(|path| crate::pauth_context(path, 0x534f524544594c44))
        .transpose()?;
    let stop = if context.is_some() {
        target_pc
            .checked_add(4)
            .context("dyld PAC continuation overflow")?
    } else {
        target_pc
    };
    let main_text = main
        .segments
        .iter()
        .find(|s| s.name == "__TEXT")
        .context("main image requires __TEXT")?;
    ensure!(
        main_text.file.offset == 0
            && main_text.file.bytes >= 32
            && main_text.initial_protection & 1 != 0,
        "main Mach header requires readable file-backed __TEXT at file offset zero"
    );
    let arguments = plan_kernel_args(
        options.stack_base,
        options.stack_bytes,
        options.image_base,
        executable.as_os_str().as_encoded_bytes(),
        args,
    )?;
    // No fixups are applied. Original dyld's self-rebase/cache handoff must be
    // reviewed before executing beyond the whitelisted startup instructions.
    let mut main_mapping =
        mapped_image::prepare_segments(main_bytes, &main, options.image_base, &[])?;
    let dyld_mapping = mapped_image::prepare_segments(dyld_bytes, &dyld.image, dyld_base, &[])?;
    main_mapping.specs.extend(dyld_mapping.specs);
    let stack = mapped_image::add_stack(
        &mut main_mapping.specs,
        Some(mapped_image::StackSpec {
            base: options.stack_base,
            bytes: options.stack_bytes,
        }),
    )?;
    let mut memory = OwnedMemory::map(main_mapping.specs)?;
    arguments.install(&mut memory)?;
    let before = memory.read_snapshot(arguments.payload_address, arguments.initial_bytes.len())?;
    ensure!(
        before == arguments.initial_bytes,
        "installed argument bytes differ from plan"
    );
    ensure!(
        memory.read_snapshot(options.image_base, 32)? == main_bytes[..32],
        "mapped main header differs"
    );
    let mut runtime = BlockRuntime::new_with_profile(
        0x534f524544594c44,
        options.cache_dir,
        crate::block_profile(context.is_some()),
    );
    for (address, bytes) in dyld_mapping.code {
        runtime.register_code(GuestAddress(address), bytes)?;
    }
    let mut thread = ThreadState {
        pc: GuestAddress(entry),
        registers: GuestState {
            x: dyld.thread.x,
            sp: arguments.raw_sp,
            nzcv: dyld.thread.cpsr,
            ..Default::default()
        },
    };
    let initial = crate::register_json(&thread.registers);
    // SAFETY: exact whitelist permits only register changes/direct exit, plus
    // the optional validated software PACIBSP helper. Explicit stop precedes
    // every other target instruction. Owned mappings remain live throughout.
    let outcome = unsafe {
        if let Some(context) = &context {
            runtime.run_with_pauth(&mut thread, Some(GuestAddress(stop)), 3, context)?
        } else {
            runtime.run(&mut thread, Some(GuestAddress(stop)), 2)?
        }
    };
    ensure!(
        outcome.reason == StopReason::StopAddress
            && outcome.blocks_executed == (if context.is_some() { 2 } else { 1 })
            && thread.pc.0 == stop,
        "dyld startup did not stop after the reviewed instructions"
    );
    let after = memory.read_snapshot(arguments.payload_address, arguments.initial_bytes.len())?;
    ensure!(
        before == after,
        "register-only startup changed argument memory"
    );
    let target_analysis = match stela_compiler::block::analyze(
        &0xd503237fu32.to_le_bytes(),
        GuestAddress(target_pc),
    ) {
        Ok(analysis) => serde_json::json!({"supported":true,"analysis":analysis}),
        Err(error) => serde_json::json!({"supported":false,"detail":error.to_string()}),
    };
    let selected_profile_target_analysis = match stela_compiler::block::analyze_with_profile(
        &0xd503237fu32.to_le_bytes(),
        GuestAddress(target_pc),
        runtime.profile(),
    ) {
        Ok(analysis) => serde_json::json!({"supported":true,"analysis":analysis}),
        Err(error) => serde_json::json!({"supported":false,"detail":error.to_string()}),
    };
    Ok(serde_json::json!({
        "schema_version":1,"kind":"original_dyld_startup_prefix_probe",
        "dyld":{"path":dyld_path,"container_sha256":stela_core::sha256(&dyld_data),"slice_offset":dyld_offset,"plan":dyld,"slide":options.dyld_slide},
        "main":{"path":executable,"container_sha256":stela_core::sha256(&main_data),"slice_offset":main_offset,"plan":main,"load_base":options.image_base},
        "arguments":arguments,"process_arguments":args,"stack":stack,"mapped_regions":memory.regions(),
        "unreserved_guards":{"main":main_mapping.unreserved_guards,"dyld":dyld_mapping.unreserved_guards},
        "argument_payload_sha256":stela_core::sha256(&before),"argument_payload_after_sha256":stela_core::sha256(&after),
        "entry_pc":entry,"stop_pc":stop,"target_pc":target_pc,"original_prefix_words":words,
        "software_pauth_profile":context.as_ref().map(|context| context.profile_id()),
        "pauth_instruction_executed":context.is_some(),"abi":runtime.profile().abi(),
        "pauth_source_sha256":stela_core::sha256(include_bytes!("../crates/stela-runtime/src/pauth.rs")),
        "initial_state":initial,"state":crate::register_json(&thread.registers),"pc":thread.pc.0,
        "outcome":outcome,"target_instruction":"PACIBSP","target_analysis":target_analysis,
        "target_analysis_profile":"ordinary","selected_profile_target_analysis":selected_profile_target_analysis,
        "fixups_applied":false,"native_executed":true,"complete_binary_verified":false,
        "compiler_source_sha256":stela_core::sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "probe_source_sha256":stela_core::sha256(include_bytes!("dyld_entry.rs")),
        "process_source_sha256":stela_core::sha256(include_bytes!("../crates/stela-runtime/src/process.rs")),
        "unresolved_requirements":["remaining PAC operations and authenticated fixups","dyld self-rebase and shared-cache handoff","initializers, TLS and guest process services","full original application execution"]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn startup_whitelist_recovers_signed_branch_and_declines_changed_effects() {
        let mut words = [0x910003e0, 0x927cec1f, 0xd280001d, 0xd280001e, 0x1400ae18];
        assert_eq!(startup_target(words, 0x4bf0).unwrap(), 0x30460);
        assert_eq!(startup_target(words, 0x40000004bf0).unwrap(), 0x40000030460);
        for index in 0..4 {
            let mut changed = words;
            changed[index] ^= 1;
            assert!(startup_target(changed, 0x4bf0).is_err());
        }
        words[4] = 0x17ffffff;
        assert_eq!(startup_target(words, 0x1000).unwrap(), 0x100c);
        words[4] = 0x97ffffff; // BL is not this reviewed prefix.
        assert!(startup_target(words, 0x1000).is_err());
        words[4] = 0x17fffffb; // -20 from entry+16 underflows entry zero.
        assert!(startup_target(words, 0).is_err());
        assert!(startup_target(words, u64::MAX - 15).is_err());
    }
}
