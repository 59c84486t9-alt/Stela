//! Native execution of trusted raw code for compiler validation.
use crate::{args::*, compile::block_profile, input::*};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
#[command(group(clap::ArgGroup::new("software_pauth_context").args(["software_pauth_ib_key", "software_pauth_keys"])))]
pub(crate) struct RunBlocks {
    input: PathBuf,
    /// Use the host's CPU features, or a portable feature tier.
    #[arg(long,default_value="native",value_parser=parse_cpu_target)]
    cpu_target: stela_compiler::TargetCpu,
    #[arg(long, default_value = "0x100000", value_parser = parse_address)]
    guest_base: u64,
    #[arg(long, value_parser = parse_address)]
    entry: Option<u64>,
    #[arg(long, value_parser = parse_address)]
    stop_pc: Option<u64>,
    #[arg(long)]
    state: Option<PathBuf>,
    #[arg(long, default_value_t = 10000)]
    block_budget: usize,
    #[arg(long, default_value = ".stela/cache/blocks-v1")]
    cache_dir: PathBuf,
    /// Enable software IB/SP authentication with the given {low, high} key.
    #[arg(long)]
    software_pauth_ib_key: Option<PathBuf>,
    /// Explicit IA/IB/DA/DB low/high key pairs for the software ARM profile.
    #[arg(long)]
    software_pauth_keys: Option<PathBuf>,
    /// Owned data mappings for trusted raw-code execution.
    #[arg(long)]
    memory: Option<PathBuf>,
    #[arg(long, requires = "memory", value_parser = parse_memory_query)]
    read_memory: Vec<MemoryQuery>,
}

impl RunBlocks {
    pub(crate) fn run(self) -> Result<()> {
        let Self {
            input,
            cpu_target,
            guest_base,
            entry,
            stop_pc,
            state,
            block_budget,
            cache_dir,
            software_pauth_ib_key,
            software_pauth_keys,
            memory: memory_path,
            read_memory,
        } = self;
        use stela_engine::blocks::BlockRuntime;
        use stela_engine::blocks::ThreadState;
        const ADDRESS_SPACE_ID: u64 = 1;
        ensure!(
            block_budget <= 1_000_000,
            "research block budget exceeds 1,000,000"
        );
        let registers: RegisterInput = if let Some(path) = state {
            serde_json::from_slice(&std::fs::read(path)?)?
        } else {
            RegisterInput::default()
        };
        ensure!(
            registers.nzcv & !0xf0000000 == 0,
            "only architectural NZCV bits31:28 are supported"
        );
        let mut thread = ThreadState {
            pc: stela_compiler::GuestAddress(entry.unwrap_or(guest_base)),
            registers: stela_compiler::GuestState {
                x: registers.x,
                sp: registers.sp,
                nzcv: registers.nzcv,
                v: registers.v,
                fpcr: registers.fpcr,
                fpsr: registers.fpsr,
                ..Default::default()
            },
        };
        let source = std::fs::read(input)?;
        let source_hash = stela_formats::sha256(&source);
        let context = if let Some(path) = software_pauth_keys.as_deref() {
            Some(pauth_all_keys_context(path, ADDRESS_SPACE_ID)?)
        } else {
            software_pauth_ib_key
                .as_deref()
                .map(|path| pauth_context(path, ADDRESS_SPACE_ID))
                .transpose()?
        };
        let memory = raw_memory(memory_path.as_deref())?;
        let memory_before = memory_hashes(&memory)?;
        let snapshot_total = read_memory.iter().try_fold(0usize, |total, query| {
            total
                .checked_add(query.bytes)
                .context("memory snapshot overflow")
        })?;
        ensure!(
            snapshot_total <= 1024 * 1024,
            "memory snapshots exceed 1 MiB"
        );
        let mut runtime = BlockRuntime::new_for_target(
            ADDRESS_SPACE_ID,
            cache_dir,
            block_profile(context.is_some(), false, false),
            cpu_target,
        );
        runtime.register_code(stela_compiler::GuestAddress(guest_base), source)?;
        // SAFETY: this research command accepts trusted raw code. The runtime
        // owns the native blocks; memory and PAuth mappings remain alive through
        // dispatch, and the code's native accesses must stay in those mappings.
        let outcome = unsafe {
            if let Some(context) = &context {
                runtime.run_with_pauth(
                    &mut thread,
                    stop_pc.map(stela_compiler::GuestAddress),
                    block_budget,
                    context,
                )?
            } else {
                runtime.run(
                    &mut thread,
                    stop_pc.map(stela_compiler::GuestAddress),
                    block_budget,
                )?
            }
        };
        let memory_after = memory_hashes(&memory)?;
        let memory_reads = read_memory.iter().map(|query| -> Result<_> { Ok(serde_json::json!({
            "address":query.address,"bytes":query.bytes,"hex":hex::encode(memory.read_snapshot(query.address,query.bytes)?)
        })) }).collect::<Result<Vec<_>>>()?;
        let memory_report = serde_json::json!({"memory_regions":memory.regions(),"memory_before":memory_before,
            "memory_after":memory_after,"memory_reads":memory_reads});
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"kind":"native_block_run",
            "source_sha256":source_hash,"guest_base":guest_base,"pc":thread.pc.0,"state":register_json(&thread.registers),
            "outcome":outcome,"abi":runtime.profile().abi(),"target_cpu":runtime.target_cpu().id(),"memory":memory_report,
            "software_pauth_profile":context.as_ref().map(|context|context.profile_id()),
            "compiler_source_sha256":stela_compiler::SOURCE_SHA256,
            "complete_binary_verified":false}))?
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Cli, Command};
    use clap::Parser;

    #[test]
    fn raw_runner_accepts_memory_and_pointer_authentication() {
        let parsed = Cli::try_parse_from([
            "stela-dev",
            "run-blocks",
            "raw.bin",
            "--memory",
            "memory.json",
            "--software-pauth-keys",
            "keys.json",
            "--read-memory",
            "0x1000:8",
        ])
        .unwrap();
        assert!(matches!(parsed.command, Command::RunBlocks(_)));
    }
}
