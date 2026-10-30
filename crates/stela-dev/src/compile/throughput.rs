//! How fast the system-mode engine's compiler translates a body of real
//! guest code: every block of a raw ARM64 region, in order, as the engine
//! prepares it, timed on this host. A profiler run over `--repeat` passes
//! shows where compilation spends its time.
use crate::args::*;
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{path::PathBuf, time::Instant};
use stela_compiler::x86_64::{MemoryChecks, NativeSystem};
use stela_contracts::Chip;
use stela_engine::machine::engine::{Description, Preparation, Prepared, window};

#[derive(Args)]
pub(crate) struct CompileThroughput {
    /// Raw little-endian ARM64 code, such as a kernel's `__TEXT_EXEC`.
    input: PathBuf,
    /// The guest address of the input's first byte.
    #[arg(long, value_parser = parse_address)]
    guest_base: u64,
    /// Use the host's CPU features, or a portable feature tier.
    #[arg(long, default_value = "native", value_parser = parse_cpu_target)]
    cpu_target: stela_compiler::TargetCpu,
    /// Compile the translated variant, whose accesses check their address
    /// against the host placement.
    #[arg(long)]
    translated: bool,
    /// Compile the region this many times.
    #[arg(long, default_value_t = 1)]
    repeat: u32,
}

impl CompileThroughput {
    pub(crate) fn run(self) -> Result<()> {
        let code = std::fs::read(&self.input)
            .with_context(|| format!("reading {}", self.input.display()))?;
        ensure!(
            !code.is_empty() && code.len().is_multiple_of(4),
            "the input holds whole instructions"
        );
        let checks = MemoryChecks::system(true, false, true, false);
        let preparation = Preparation::from_description(&Description {
            chip: Chip::AppleM2,
            target: self.cpu_target,
            fp: true,
            checks: if self.translated {
                checks.with_translation(0)
            } else {
                checks
            },
            scalable: None,
            system: NativeSystem::NONE,
            withheld: 0,
        })
        .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;
        let mut totals = Totals::default();
        let started = Instant::now();
        for _ in 0..self.repeat {
            totals = Totals::default();
            let mut offset = 0;
            while offset < code.len() {
                let pc = self.guest_base + offset as u64;
                let source = &code[offset..(offset + window(pc)).min(code.len())];
                offset += match preparation.prepare(source, pc, source.len()) {
                    Ok(Prepared::Block { compiled, .. }) => {
                        totals.blocks += 1;
                        totals.instructions += compiled.source_bytes / 4;
                        totals.native_bytes += compiled.native.x86_64_code.len();
                        compiled.source_bytes.max(4)
                    }
                    Ok(Prepared::Checked(_) | Prepared::FloatingPointTrap) => 4,
                    Err(_) => {
                        totals.refused += 1;
                        4
                    }
                };
            }
        }
        let nanoseconds = started.elapsed().as_nanos() / u128::from(self.repeat.max(1));
        println!(
            "blocks={} instructions={} refused={} native_bytes={} ns={nanoseconds} ns/block={} ns/instruction={}",
            totals.blocks,
            totals.instructions,
            totals.refused,
            totals.native_bytes,
            nanoseconds / totals.blocks.max(1) as u128,
            nanoseconds / totals.instructions.max(1) as u128,
        );
        Ok(())
    }
}

/// One pass's blocks, their instructions and native code, and the words no
/// block could be compiled from.
#[derive(Default)]
struct Totals {
    blocks: usize,
    instructions: usize,
    native_bytes: usize,
    refused: usize,
}
