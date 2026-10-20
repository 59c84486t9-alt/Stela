//! The host floor audit: every registry sample compiled for the x86-64-v2
//! floor ([`TargetCpu::X86_64_V2`]) must emit only instructions that tier
//! has, and must compile wherever a larger tier does.
//!
//! The floor comes in the two forms a v2 host takes: with AVX hardware,
//! whose 16-byte SSE loads are atomic, or an Intel processor without AVX
//! (Nehalem, Westmere, the Atom cores), whose loads within a cache line
//! are ([`TargetCpu::LineAtomic`]). Every v2 processor without AVX that
//! OpenCore boots is an Intel one.
//!
//! Each sample word is compiled alone as a system-mode block (the bare-metal
//! engine's profile) and as an ordinary block (the hosted engine's), for the
//! floors and for the complete SSE4.2, AVX2 and AVX-512 tiers. The whole
//! native code, out-of-line paths included, is disassembled with LLVM,
//! following jumps over skipped bytes as the DIT audit does. Instructions
//! of extensions above v2 (AES, PCLMULQDQ, SHA, BMI1, BMI2, LZCNT, MOVBE,
//! ADX, VEX and EVEX encodings, ...) are counted per tier; on the floor any
//! of them, or a refusal a larger tier does not have, fails the audit.
use crate::{
    amx::kernels::objdump,
    dit::{reachable, registry_forms, split, toolchain_objdump},
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use stela_compiler::{
    GuestAddress, TargetCpu,
    block::{BlockProfile, CompilationPlan},
};

/// Where each audited block is compiled.
const BASE: u64 = 0x10_0000;
/// The instruction after the audited one, so that the audited one does not
/// end the block by itself.
const NOP: u32 = 0xd503_201f;

#[derive(Args)]
pub struct FloorAudit {
    /// LLVM disassembler; defaults to `llvm-objdump` on `PATH`, from Xcode or
    /// from the Rust toolchain.
    #[arg(long)]
    objdump: Option<PathBuf>,
    /// Only forms whose id contains this text.
    #[arg(long)]
    form: Option<String>,
    /// Forms to name for each extension.
    #[arg(long, default_value_t = 8)]
    show: usize,
}

/// The extension above x86-64-v2 that `mnemonic` (lowercase, prefixes
/// dropped) belongs to, if any.
pub fn above_floor(mnemonic: &str) -> Option<&'static str> {
    const MASKS: [&str; 9] = [
        "kmov", "kand", "kor", "kxor", "knot", "kshift", "kunpck", "ktest", "kadd",
    ];
    Some(match mnemonic {
        "verr" | "verw" => return None,
        _ if MASKS.iter().any(|prefix| mnemonic.starts_with(prefix)) => "AVX-512 opmask",
        _ if mnemonic.starts_with('v') => "VEX/EVEX (AVX, AVX2, FMA, F16C, AVX-512)",
        _ if mnemonic.starts_with("aes") => "AES-NI",
        // LLVM spells the immediate forms pclmullqlqdq, pclmulhqlqdq, ...
        _ if mnemonic.starts_with("pclmul") => "PCLMULQDQ",
        _ if mnemonic.starts_with("sha1") || mnemonic.starts_with("sha256") => "SHA",
        _ if mnemonic.starts_with("gf2p8") => "GFNI",
        "andn" | "bextr" | "blsi" | "blsmsk" | "blsr" | "tzcnt" => "BMI1",
        "bzhi" | "mulx" | "pdep" | "pext" | "rorx" | "sarx" | "shlx" | "shrx" => "BMI2",
        "lzcnt" => "LZCNT",
        "movbe" => "MOVBE",
        "adcx" | "adox" => "ADX",
        "prefetchw" | "prefetchwt1" => "PRFCHW",
        "rdrand" => "RDRAND",
        "rdseed" => "RDSEED",
        "clflushopt" => "CLFLUSHOPT",
        "clwb" => "CLWB",
        "extrq" | "insertq" | "movntsd" | "movntss" => "SSE4a",
        "xgetbv" | "xsave" | "xrstor" | "xsaveopt" | "xsavec" => "XSAVE",
        _ => return None,
    })
}

/// The larger tiers audited.
const LARGER: usize = 3;

/// The tiers audited, the [`LARGER`] ones first, then the floors.
fn tiers() -> [(&'static str, TargetCpu); 5] {
    [
        ("avx512", TargetCpu::Avx512Complete),
        ("avx2", TargetCpu::Avx2Complete),
        ("sse42", TargetCpu::Sse42Complete),
        ("v2-avx", TargetCpu::X86_64_V2.with_atomic_load16()),
        ("v2-intel", TargetCpu::X86_64_V2.with_line_atomic()),
    ]
}

/// The whole native code of `word` compiled alone under `profile`.
fn compiled(word: u32, profile: BlockProfile, target: TargetCpu) -> Result<Vec<u8>, String> {
    let source: Vec<u8> = [word, NOP].iter().flat_map(|w| w.to_le_bytes()).collect();
    CompilationPlan::new(&source, GuestAddress(BASE), profile, target)
        .and_then(CompilationPlan::compile)
        .map(|block| block.native.x86_64_code)
        .map_err(|error| error.0)
}

/// What one tier emitted across the samples.
#[derive(Default)]
struct Tally {
    /// Extension: mnemonics and the forms using them.
    above: BTreeMap<&'static str, (BTreeSet<String>, BTreeSet<String>)>,
    /// Form: a refusal of one of its samples.
    refused: BTreeMap<String, String>,
    compiled: usize,
}

impl FloorAudit {
    pub fn run(self) -> Result<()> {
        let objdump = self
            .objdump
            .or_else(objdump)
            .or_else(toolchain_objdump)
            .context("no llvm-objdump: pass --objdump")?;
        let directory = tempfile::tempdir()?;
        let forms = registry_forms()?;
        let mut tallies: Vec<Tally> = tiers().iter().map(|_| Tally::default()).collect();
        // Disassembly is the cost; identical code is disassembled once.
        let mut seen: BTreeMap<Vec<u8>, BTreeSet<(&'static str, String)>> = BTreeMap::new();
        for (id, (_, words)) in &forms {
            if self
                .form
                .as_ref()
                .is_some_and(|wanted| !id.contains(wanted))
            {
                continue;
            }
            for &word in words {
                for profile in [BlockProfile::SystemModeV1, BlockProfile::Ordinary] {
                    for ((_, target), tally) in tiers().iter().zip(&mut tallies) {
                        let code = match compiled(word, profile, *target) {
                            Ok(code) => code,
                            Err(error) => {
                                tally
                                    .refused
                                    .entry(format!("{id} ({profile:?})"))
                                    .or_insert(error);
                                continue;
                            }
                        };
                        tally.compiled += 1;
                        let found = match seen.get(&code) {
                            Some(found) => found.clone(),
                            None => {
                                let found: BTreeSet<_> = reachable(&objdump, &directory, &code)?
                                    .iter()
                                    .filter_map(|line| {
                                        let mnemonic = split(line).0;
                                        above_floor(mnemonic)
                                            .map(|extension| (extension, mnemonic.to_owned()))
                                    })
                                    .collect();
                                seen.insert(code, found.clone());
                                found
                            }
                        };
                        for (extension, mnemonic) in found {
                            let entry = tally.above.entry(extension).or_default();
                            entry.0.insert(mnemonic);
                            entry.1.insert(id.clone());
                        }
                    }
                }
            }
        }
        for ((name, target), tally) in tiers().iter().zip(&tallies) {
            println!(
                "{name} ({}): {} blocks compiled, {} forms with a refusal",
                target.id(),
                tally.compiled,
                tally.refused.len()
            );
            for (extension, (mnemonics, users)) in &tally.above {
                let named: Vec<&str> = users.iter().take(self.show).map(String::as_str).collect();
                println!(
                    "  {extension}: {} in {} forms: {}{}",
                    mnemonics.iter().cloned().collect::<Vec<_>>().join(" "),
                    users.len(),
                    named.join(" "),
                    if users.len() > named.len() {
                        " ..."
                    } else {
                        ""
                    }
                );
            }
        }
        let (larger, floors) = tallies.split_at(LARGER);
        let mut failures = 0;
        for ((name, _), floor) in tiers()[LARGER..].iter().zip(floors) {
            for (extension, (_, users)) in &floor.above {
                failures += users.len();
                let users: Vec<&str> = users.iter().map(String::as_str).collect();
                println!("{name} violation: {extension} in {}", users.join(" "));
            }
            for (form, error) in &floor.refused {
                if larger.iter().any(|tally| !tally.refused.contains_key(form)) {
                    failures += 1;
                    println!("{name} refusal: {form}: {error}");
                }
            }
        }
        ensure!(failures == 0, "{failures} floor failures");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_above_the_floor_are_named_and_v2_instructions_are_not() {
        for (mnemonic, extension) in [
            ("vpxor", "VEX/EVEX (AVX, AVX2, FMA, F16C, AVX-512)"),
            ("kmovw", "AVX-512 opmask"),
            ("aesenc", "AES-NI"),
            ("pclmulqdq", "PCLMULQDQ"),
            ("pclmulhqlqdq", "PCLMULQDQ"),
            ("sha256rnds2", "SHA"),
            ("tzcnt", "BMI1"),
            ("andn", "BMI1"),
            ("shlx", "BMI2"),
            ("lzcnt", "LZCNT"),
            ("movbe", "MOVBE"),
        ] {
            assert_eq!(above_floor(mnemonic), Some(extension), "{mnemonic}");
        }
        for mnemonic in [
            "popcnt",
            "crc32",
            "pshufb",
            "ptest",
            "pcmpgtq",
            "pcmpestri",
            "cmpxchg16b",
            "phminposuw",
            "insertps",
            "bsf",
            "bsr",
            "verw",
            "movdqa",
            "pblendvb",
        ] {
            assert_eq!(above_floor(mnemonic), None, "{mnemonic}");
        }
    }
}
