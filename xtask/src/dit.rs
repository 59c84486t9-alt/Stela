//! The FEAT_DIT timing audit: whether the native code the system-mode
//! compiler emits for each data-independent-time A64 instruction has timing
//! independent of the data it processes.
//!
//! Arm's DIT register description (`AArch64-dit.xml` of the pinned System
//! register XML) lists the instructions, grouped by encoding class. Each
//! class's title is an `iclass_sect` of the pinned A64 instruction XML's
//! `encodingindex.xml`, which names the encodings (the form IDs of Stela's
//! registries) of each listed mnemonic. Every registry sample of such a form
//! is compiled as a one-instruction system-mode block for each audited host
//! tier, and the native code of the instruction (its source-map range) is
//! disassembled and classified:
//! - every x86 instruction must be one Intel lists as having data operand
//!   independent timing under IA32_UARCH_MISC_CTL.DOITM ([`DOIT`]);
//! - a conditional branch or an indexed memory operand makes timing depend
//!   on what decides it. For the data-processing classes that is data; for
//!   the load and store classes it is the address (the software MMU's
//!   lookup), which DIT leaves free, so only the instruction list applies.
//!
//! The result is `isa/dit-timing-audit.json`, bound to the archives and the
//! compiler sources it audited. It is evidence for FEAT_DIT, not a proof:
//! a verdict of `constant` means the emitted instructions are all on Intel's
//! list and nothing branches on or indexes by the data. Exclusive,
//! unprivileged and pointer-authenticated loads and stores end their block,
//! and the engine performs them ([`ENGINE_PERFORMED`]): their verdict
//! `engine` rests on a review of that source, whose digest the ledger keeps.
use crate::{
    amx::kernels::{listing, objdump},
    tools::root,
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use stela_compiler::{
    GuestAddress, TargetCpu,
    block::{BlockProfile, CompilationPlan},
};
use stela_runtime::sha256;

/// The audit ledger.
pub const LEDGER: &str = "isa/dit-timing-audit.json";
/// The DIT register page inside the pinned System register XML archive.
const DIT_PAGE: &str = "AArch64-dit.xml";
/// The encoding index inside the pinned A64 instruction XML archive.
const ENCODING_INDEX: &str = "encodingindex.xml";
/// The registries whose forms the system-mode compiler admits on the M2.
const REGISTRIES: [&str; 3] = [
    "isa/apple-silicon-reviewed-forms.json",
    "isa/apple-silicon-block-forms.json",
    "isa/a64-service-forms.json",
];
/// The pinned A64 instruction XML archive, as the registries record it.
const ISA_SHA256: &str = "63a01a1696483bbe2edfef9e0f0cd053d6c1c619ec0587876cb7a60bb344f354";
const ISA_DIRECTORY: &str = "ISA_A64_xml_A_profile-2026-06";
/// Intel's list, as published at
/// <https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/data-operand-independent-timing-instructions.html>.
pub const DOIT_SOURCE: &str = "https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/resources/data-operand-independent-timing-instructions.html";
/// The classes outside the M2 profile: it has neither SME nor SVE.
const ABSENT_CLASSES: [&str; 2] = [
    "If FEAT_SME is implemented, SME encodings",
    "If FEAT_SVE is implemented, SVE encodings",
];
/// The class-title prefixes of the extensions outside the M2 profile.
const ABSENT_EXTENSIONS: [&str; 2] = ["SVE ", "SME "];
/// The top-level class whose timing may depend on the address.
const LOADS_AND_STORES: &str = "Loads and Stores";
/// Where each audited block is compiled.
const BASE: u64 = 0x10_0000;

/// The names of [`TargetCpu::DATA_INDEPENDENT_TIMING_TIERS`] in the ledger.
const TIMING_TIER_NAMES: [&str; 3] = ["avx512-dit", "avx2-dit", "sse42-dit"];

/// The host tiers audited: the SSE2 baseline every x86-64 host has, the
/// AVX2 and AVX-512 tiers with every other optional feature the compiler
/// uses, and the tiers the system engine compiles PSTATE.DIT code for
/// ([`TargetCpu::data_independent_timing_target`]).
fn tiers() -> Vec<(&'static str, TargetCpu)> {
    let mut tiers = vec![
        ("baseline", TargetCpu::Baseline),
        ("avx2", TargetCpu::Avx2Complete),
        ("avx512", TargetCpu::Avx512Complete),
    ];
    tiers.extend(TIMING_TIER_NAMES.into_iter().zip(
        TargetCpu::DATA_INDEPENDENT_TIMING_TIERS.map(TargetCpu::with_data_independent_timing),
    ));
    tiers
}

/// The listed classes whose instructions end a system-mode block for the
/// engine to perform in Rust, which no disassembly of block code covers:
/// each class and the engine source that performs it. That source branches
/// and indexes only on the address, its translation, permissions, alignment,
/// watchpoints and the Exclusives monitor; it copies the data without a
/// branch or an index on it (reviewed, verdict `engine`).
const ENGINE_PERFORMED: [(&str, &str); 4] = [
    (
        "Load/store exclusive register",
        "crates/stela-runtime/src/machine/engine/exclusive.rs",
    ),
    (
        "Load/store exclusive pair",
        "crates/stela-runtime/src/machine/engine/exclusive.rs",
    ),
    (
        "Load/store register (unprivileged)",
        "crates/stela-runtime/src/machine/engine/unprivileged.rs",
    ),
    (
        "Load/store register (pac)",
        "crates/stela-runtime/src/machine/engine.rs",
    ),
];
/// The refusal of a form that ends its block.
const ENDS_BLOCK: &str = "the instruction ends its block";

/// Intel's data operand independent timing instructions, lowercase. Every
/// CMOVcc and SETcc condition is listed; [`listed`] folds them.
#[rustfmt::skip]
const DOIT: &[&str] = &[
    "adc", "adcx", "add", "adox", "aesdec", "aesdeclast", "aesenc", "aesenclast", "aesimc",
    "aeskeygenassist", "and", "andn", "bswap", "bt", "btc", "btr", "bts", "cmp", "cqo", "dec",
    "gf2p8affineinvqb", "gf2p8affineqb", "gf2p8mulb", "imul", "inc", "lddqu", "lea", "mov",
    "movaps", "movd", "movddup", "movdq2q", "movdqa", "movdqu", "movntdq", "movntdqa", "movq",
    "movsb", "movsd", "movshdup", "movsldup", "movsq", "movss", "movsw", "movsx", "movsxd",
    "movups", "movzx", "mpsadbw", "mul", "mulx", "neg", "not", "or", "pabsb", "pabsd", "pabsw",
    "packssdw", "packsswb", "packusdw", "packuswb", "paddb", "paddd", "paddq", "paddsb", "paddsw",
    "paddusb", "paddusw", "paddw", "palignr", "pand", "pandn", "pavgb", "pavgw", "pblendvb",
    "pblendw", "pclmulqdq", "pcmpeqb", "pcmpeqd", "pcmpeqq", "pcmpeqw", "pcmpgtb", "pcmpgtd",
    "pcmpgtq", "pcmpgtw", "pextrb", "pextrd", "pextrq", "pextrw", "phaddd", "phaddsw", "phaddw",
    "phminposuw", "phsubd", "phsubsw", "phsubw", "pinsrb", "pinsrd", "pinsrq", "pinsrw",
    "pmaddubsw", "pmaddwd", "pmaxsb", "pmaxsw", "pmaxub", "pmaxud", "pmaxuw", "pminsb", "pminsw",
    "pminub", "pminud", "pminuw", "pmovmskb", "pmovsxbd", "pmovsxbq", "pmovsxbw", "pmovsxdq",
    "pmovsxwd", "pmovsxwq", "pmovzxbd", "pmovzxbq", "pmovzxbw", "pmovzxdq", "pmovzxwd", "pmovzxwq",
    "pmuldq", "pmulhrsw", "pmulhuw", "pmulhw", "pmulld", "pmullw", "pmuludq", "pop", "por",
    "psadbw", "pshufb", "pshufd", "pshufhw", "pshuflw", "psignb", "psignd", "psignw", "pslld",
    "pslldq", "psllq", "psllw", "psrad", "psraw", "psrld", "psrldq", "psrlq", "psrlw", "psubb",
    "psubd", "psubq", "psubsb", "psubsw", "psubusb", "psubusw", "psubw", "ptest", "punpckhbw",
    "punpckhdq", "punpckhqdq", "punpckhwd", "punpcklbw", "punpckldq", "punpcklqdq", "punpcklwd",
    "push", "pxor", "rol", "ror", "rorx", "sar", "sbb", "sha1msg1", "sha1msg2", "sha1nexte",
    "sha1rnds4", "sha256msg1", "sha256msg2", "sha256rnds2", "shl", "shld", "shlx", "shr", "shrd",
    "shrx", "sub", "test", "vaesdec", "vaesdeclast", "vaesenc", "vaesenclast", "vaesimc",
    "vaeskeygenassist", "valignd", "valignq", "vblendmpd", "vblendmps", "vbroadcastf128",
    "vbroadcastf32x2", "vbroadcastf32x4", "vbroadcastf32x8", "vbroadcastf64x2", "vbroadcastf64x4",
    "vbroadcasti128", "vbroadcasti32x2", "vbroadcasti32x4", "vbroadcasti32x8", "vbroadcasti64x2",
    "vbroadcasti64x4", "vbroadcastsd", "vbroadcastss", "vcompresspd", "vcompressps", "vdbpsadbw",
    "vexpandpd", "vexpandps", "vextractf128", "vextractf32x4", "vextractf32x8", "vextractf64x2",
    "vextractf64x4", "vextracti128", "vextracti32x4", "vextracti32x8", "vextracti64x2",
    "vextracti64x4", "vgf2p8affineinvqb", "vgf2p8affineqb", "vgf2p8mulb", "vinsertf128",
    "vinsertf32x4", "vinsertf32x8", "vinsertf64x2", "vinsertf64x4", "vinserti128", "vinserti32x4",
    "vinserti32x8", "vinserti64x2", "vinserti64x4", "vlddqu", "vmovd", "vmovddup", "vmovdqa",
    "vmovdqa32", "vmovdqa64", "vmovdqu", "vmovdqu16", "vmovdqu32", "vmovdqu64", "vmovdqu8",
    "vmovntdq", "vmovntdqa", "vmovq", "vmovsd", "vmovshdup", "vmovsldup", "vmpsadbw", "vpabsb",
    "vpabsd", "vpabsq", "vpabsw", "vpackssdw", "vpacksswb", "vpackusdw", "vpackuswb", "vpaddb",
    "vpaddd", "vpaddq", "vpaddsb", "vpaddsw", "vpaddusb", "vpaddusw", "vpaddw", "vpalignr", "vpand",
    "vpandd", "vpandn", "vpandnd", "vpandnq", "vpandq", "vpavgb", "vpavgw", "vpblendd", "vpblendmb",
    "vpblendmd", "vpblendmq", "vpblendmw", "vpblendvb", "vpblendw", "vpbroadcastb", "vpbroadcastd",
    "vpbroadcastmb2q", "vpbroadcastmw2d", "vpbroadcastq", "vpbroadcastw", "vpclmulqdq", "vpcmpb",
    "vpcmpeqb", "vpcmpeqd", "vpcmpeqq", "vpcmpeqw", "vpcmpgtb", "vpcmpgtd", "vpcmpgtq", "vpcmpgtw",
    "vpcmpq", "vpcmpub", "vpcmpud", "vpcmpuq", "vpcmpuw", "vpcmpw", "vperm2f128", "vperm2i128",
    "vpermd", "vpermi2d", "vpermi2pd", "vpermi2ps", "vpermi2q", "vpermi2w", "vpermilpd",
    "vpermilps", "vpermpd", "vpermps", "vpermq", "vpermt2d", "vpermt2pd", "vpermt2ps", "vpermt2q",
    "vpermt2w", "vpermw", "vpextrb", "vpextrd", "vpextrq", "vpextrw", "vphaddd", "vphaddsw",
    "vphaddw", "vphminposuw", "vphsubd", "vphsubsw", "vphsubw", "vpinsrb", "vpinsrd", "vpinsrq",
    "vpinsrw", "vplzcntd", "vplzcntq", "vpmadd52huq", "vpmadd52luq", "vpmaddubsw", "vpmaddwd",
    "vpmaxsb", "vpmaxsq", "vpmaxsw", "vpmaxub", "vpmaxud", "vpmaxuq", "vpmaxuw", "vpminsb",
    "vpminsq", "vpminsw", "vpminub", "vpminud", "vpminuq", "vpminuw", "vpmovb2m", "vpmovd2m",
    "vpmovdb", "vpmovdw", "vpmovm2b", "vpmovm2d", "vpmovm2q", "vpmovm2w", "vpmovmskb", "vpmovq2m",
    "vpmovqb", "vpmovqd", "vpmovqw", "vpmovsdb", "vpmovsdw", "vpmovsqb", "vpmovsqd", "vpmovsqw",
    "vpmovswb", "vpmovsxbd", "vpmovsxbq", "vpmovsxbw", "vpmovsxdq", "vpmovsxwd", "vpmovsxwq",
    "vpmovusdb", "vpmovusdw", "vpmovusqb", "vpmovusqd", "vpmovusqw", "vpmovuswb", "vpmovw2m",
    "vpmovwb", "vpmovzxbd", "vpmovzxbq", "vpmovzxbw", "vpmovzxdq", "vpmovzxwd", "vpmovzxwq",
    "vpmuldq", "vpmulhrsw", "vpmulhuw", "vpmulhw", "vpmulld", "vpmullq", "vpmullw", "vpmuludq",
    "vpor", "vpord", "vporq", "vprold", "vprolq", "vprolvd", "vprolvq", "vprord", "vprorq",
    "vprorvd", "vprorvq", "vpsadbw", "vpshldd", "vpshldq", "vpshldvd", "vpshldvq", "vpshldvw",
    "vpshldw", "vpshrdd", "vpshrdq", "vpshrdvd", "vpshrdvq", "vpshrdvw", "vpshrdw", "vpshufb",
    "vpshufd", "vpshufhw", "vpshuflw", "vpsignb", "vpsignd", "vpsignw", "vpslld", "vpslldq",
    "vpsllq", "vpsllvd", "vpsllvq", "vpsllvw", "vpsllw", "vpsrad", "vpsraq", "vpsravd", "vpsravq",
    "vpsravw", "vpsraw", "vpsrld", "vpsrldq", "vpsrlq", "vpsrlvd", "vpsrlvq", "vpsrlvw", "vpsrlw",
    "vpsubb", "vpsubd", "vpsubq", "vpsubsb", "vpsubsw", "vpsubusb", "vpsubusw", "vpsubw",
    "vpternlogd", "vpternlogq", "vptest", "vptestmb", "vptestmd", "vptestmq", "vptestmw",
    "vptestnmb", "vptestnmd", "vptestnmq", "vptestnmw", "vpunpckhbw", "vpunpckhdq", "vpunpckhqdq",
    "vpunpckhwd", "vpunpcklbw", "vpunpckldq", "vpunpcklqdq", "vpunpcklwd", "vpxor", "vpxord",
    "vpxorq", "vshuff32x4", "vshuff64x2", "vshufi32x4", "vshufi64x2", "vzeroall", "vzeroupper",
    "xor", "xorps",
];

/// Instructions that carry no data: unconditional control within the
/// lowering, padding, and the UD2 a failed alignment check traps with.
const DATALESS: [&str; 3] = ["jmp", "nop", "ud2"];

#[derive(Args)]
pub struct DitAudit {
    /// The pinned System register XML archive
    /// (`SysReg_xml_A_profile-2026-06.tar.gz`), the source of the DIT list.
    #[arg(long)]
    sysreg: PathBuf,
    /// The pinned A64 instruction XML archive
    /// (`ISA_A64_xml_A_profile-2026-06.tar.gz`), the source of each class's
    /// encodings.
    #[arg(long)]
    isa: PathBuf,
    /// LLVM disassembler; defaults to `llvm-objdump` on `PATH`, from Xcode or
    /// from the Rust toolchain.
    #[arg(long)]
    objdump: Option<PathBuf>,
    /// Print the disassembly of these forms' samples on each tier.
    #[arg(long)]
    listing: Vec<String>,
}

/// One listed instruction: the class path and the mnemonic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Listed {
    top: String,
    class: String,
    mnemonic: String,
}

impl DitAudit {
    pub fn run(self) -> Result<()> {
        let objdump = self
            .objdump
            .or_else(objdump)
            .or_else(toolchain_objdump)
            .context("no llvm-objdump: pass --objdump")?;
        let directory = tempfile::tempdir()?;
        let sysreg = verified(&self.sysreg, crate::system_matrix::resets::SHA256)?;
        extract(
            &self.sysreg,
            directory.path(),
            &format!("{}/{DIT_PAGE}", crate::system_matrix::resets::DIRECTORY),
        )?;
        let isa = verified(&self.isa, ISA_SHA256)?;
        extract(
            &self.isa,
            directory.path(),
            &format!("{ISA_DIRECTORY}/{ENCODING_INDEX}"),
        )?;
        let page = fs::read_to_string(
            directory
                .path()
                .join(crate::system_matrix::resets::DIRECTORY)
                .join(DIT_PAGE),
        )?;
        let index = fs::read_to_string(directory.path().join(ISA_DIRECTORY).join(ENCODING_INDEX))?;
        let listed = parse_list(&page)?;
        let classes = parse_index(&index)?;
        let forms = registry_forms()?;
        let mut rows = Vec::new();
        let mut summary: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        let mut absent = BTreeSet::new();
        let mut unmatched = BTreeSet::new();
        // A form listed under two classes (LDAPUR, STLR) or as both halves
        // (SHRN, SHRN2) is audited once.
        let mut audited = BTreeSet::new();
        for entry in &listed {
            if ABSENT_CLASSES.contains(&entry.top.as_str()) {
                absent.insert(entry.top.clone());
                continue;
            }
            // An SVE or SME class listed outside those sections.
            if ABSENT_EXTENSIONS
                .iter()
                .any(|extension| entry.class.starts_with(extension))
            {
                absent.insert(entry.class.clone());
                continue;
            }
            // A list title that names no encoding class (Flag Manipulation)
            // takes the mnemonic's encodings in every class.
            let encodings: Vec<&(String, String)> = match classes.get(&entry.class) {
                Some(encodings) => encodings.iter().collect(),
                None => classes.values().flatten().collect(),
            };
            let named = |wanted: &str| -> Vec<&String> {
                encodings
                    .iter()
                    .filter(|(_, mnemonic)| mnemonic == wanted)
                    .map(|(id, _)| id)
                    .collect()
            };
            // A "2" mnemonic (RSHRN2, SADDL2) is the upper-half form of the
            // same encoding.
            let mut ids = named(&entry.mnemonic);
            if ids.is_empty()
                && let Some(lower) = entry.mnemonic.strip_suffix('2')
            {
                ids = named(lower);
            }
            if ids.is_empty() {
                unmatched.insert(format!("{}: {}", entry.class, entry.mnemonic));
                continue;
            }
            for id in ids {
                if !audited.insert(id.clone()) {
                    continue;
                }
                let row = audit(entry, id, forms.get(id), &objdump, &directory)?;
                if self.listing.contains(id)
                    && let Some((_, words)) = forms.get(id)
                {
                    for (tier, target) in tiers() {
                        for &word in words {
                            let listing = match instruction_code(word, target) {
                                Ok(code) => reachable(&objdump, &directory, &code)?.join("\n"),
                                Err(error) => error,
                            };
                            println!("{id} {word:#010x} {tier}:\n{listing}\n");
                        }
                    }
                }
                for (tier, _) in tiers() {
                    let verdict = row[tier]["verdict"].as_str().unwrap_or("absent").to_owned();
                    *summary
                        .entry(tier.to_owned())
                        .or_default()
                        .entry(verdict)
                        .or_default() += 1;
                }
                rows.push(row);
            }
        }
        let ledger = json!({
            "schema_version": 1,
            "kind": "dit_timing_audit",
            "sources": {
                "dit_list": format!("{}/{DIT_PAGE}", crate::system_matrix::resets::DIRECTORY),
                "sysreg_archive_sha256": sysreg,
                "encoding_index": format!("{ISA_DIRECTORY}/{ENCODING_INDEX}"),
                "isa_archive_sha256": isa,
                "doit_list": DOIT_SOURCE,
                "compiler_sha256": compiler_digest()?,
                "engine_sha256": engine_digests()?,
            },
            "profile": "system-mode-v1 on the M2: no SME or SVE classes",
            "absent_classes": absent,
            "unmatched": unmatched,
            "tiers": tiers().into_iter().map(|(name, _)| name).collect::<Vec<_>>(),
            "summary": summary,
            "forms": rows,
        });
        fs::write(root().join(LEDGER), format!("{ledger:#}\n"))?;
        println!("wrote {LEDGER}");
        println!("{:#}", ledger["summary"]);
        Ok(())
    }
}

/// The archive's SHA-256, which must be `expected`.
fn verified(path: &Path, expected: &str) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let digest = sha256(&bytes);
    ensure!(
        digest == expected,
        "{} is not the pinned archive",
        path.display()
    );
    Ok(digest)
}

fn extract(archive: &Path, directory: &Path, member: &str) -> Result<()> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(directory)
        .arg(member)
        .status()?;
    ensure!(status.success(), "cannot extract {member}");
    Ok(())
}

/// `llvm-objdump` from the Rust toolchain's `llvm-tools`.
pub(crate) fn toolchain_objdump() -> Option<PathBuf> {
    let output = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    let sysroot = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    fs::read_dir(sysroot.join("lib/rustlib"))
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("bin/llvm-objdump"))
        .find(|path| path.is_file())
}

/// The listed instructions: each list item's title, the nested item titles
/// below the top-level ones, and the `<instruction>` names of each item.
fn parse_list(page: &str) -> Result<Vec<Listed>> {
    let mut listed = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut rest = page;
    // Walk the item and list tags in order, tracking the open item titles.
    loop {
        let next = ["<listitem><content>", "</listitem>"]
            .iter()
            .filter_map(|tag| rest.find(tag).map(|at| (at, *tag)))
            .min();
        let Some((at, tag)) = next else { break };
        rest = &rest[at + tag.len()..];
        if tag == "</listitem>" {
            stack.pop();
            continue;
        }
        let title_end = rest.find(':').unwrap_or(0);
        let title = unescape(rest[..title_end].trim());
        // The item's own text runs to its nested list or its end.
        let body_end = ["<list ", "<list>", "</content>"]
            .iter()
            .filter_map(|tag| rest.find(tag))
            .min()
            .unwrap_or(rest.len());
        let body = &rest[..body_end];
        stack.push(title.clone());
        let mut instructions = body;
        while let Some(start) = instructions.find("<instruction>") {
            let after = &instructions[start + "<instruction>".len()..];
            let end = after
                .find("</instruction>")
                .context("unclosed instruction")?;
            listed.push(Listed {
                top: stack.first().cloned().unwrap_or_default(),
                class: title.clone(),
                mnemonic: after[..end].trim().to_owned(),
            });
            instructions = &after[end..];
        }
    }
    ensure!(!listed.is_empty(), "{DIT_PAGE} lists no instruction");
    listed.sort();
    listed.dedup();
    Ok(listed)
}

fn unescape(text: &str) -> String {
    text.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// Each encoding class's title and its encodings with their mnemonics.
fn parse_index(index: &str) -> Result<BTreeMap<String, Vec<(String, String)>>> {
    let mut classes: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for section in index.split("<iclass_sect ").skip(1) {
        let title = attribute(section, "title").context("iclass_sect without a title")?;
        let section = section.split("</iclass_sect>").next().unwrap_or_default();
        let encodings = classes.entry(unescape(&title)).or_default();
        for row in section.split("<tr class=\"instructiontable\"").skip(1) {
            let Some(id) = attribute(row, "encname") else {
                continue;
            };
            // An encoding's name starts with its mnemonic.
            let mnemonic = id.split('_').next().unwrap_or_default().to_owned();
            encodings.push((id, mnemonic));
        }
    }
    ensure!(!classes.is_empty(), "{ENCODING_INDEX} has no classes");
    Ok(classes)
}

fn attribute(text: &str, name: &str) -> Option<String> {
    let start = text.find(&format!("{name}=\""))? + name.len() + 2;
    let end = text[start..].find('"')?;
    Some(text[start..start + end].to_owned())
}

/// Each registry form by ID: its status and sample words.
pub(crate) fn registry_forms() -> Result<BTreeMap<String, (String, Vec<u32>)>> {
    let mut forms = BTreeMap::new();
    for registry in REGISTRIES {
        let text = fs::read_to_string(root().join(registry))?;
        let value: Value = serde_json::from_str(&text)?;
        for form in value["forms"].as_array().into_iter().flatten() {
            let Some(id) = form["id"].as_str() else {
                continue;
            };
            let words = form["smoke_samples"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|sample| sample["word"].as_str())
                .map(|word| u32::from_str_radix(word.trim_start_matches("0x"), 16))
                .collect::<Result<Vec<_>, _>>()?;
            let status = form["status"].as_str().unwrap_or("open").to_owned();
            forms.insert(id.to_owned(), (status, words));
        }
    }
    Ok(forms)
}

/// One form's row: its verdict on each tier.
fn audit(
    entry: &Listed,
    id: &str,
    form: Option<&(String, Vec<u32>)>,
    objdump: &Path,
    directory: &tempfile::TempDir,
) -> Result<Value> {
    let mut row = Map::new();
    row.insert("form".into(), json!(id));
    row.insert("class".into(), json!(entry.class));
    row.insert("mnemonic".into(), json!(entry.mnemonic));
    let Some((status, words)) = form else {
        row.insert("registry".into(), json!("absent"));
        return Ok(Value::Object(row));
    };
    row.insert("registry".into(), json!(status));
    let address_free = entry.top == LOADS_AND_STORES;
    let engine = ENGINE_PERFORMED
        .iter()
        .find(|(class, _)| *class == entry.class)
        .map(|(_, source)| *source);
    if let Some(source) = engine {
        row.insert("engine".into(), json!(source));
    }
    for (tier, target) in tiers() {
        let mut verdicts = BTreeSet::new();
        let mut unlisted = BTreeSet::new();
        let mut refusals = BTreeSet::new();
        let (mut branches, mut indexed, mut calls) = (0u64, 0u64, 0u64);
        for &word in words {
            let code = match instruction_code(word, target) {
                Ok(code) => code,
                Err(error) if error == ENDS_BLOCK && engine.is_some() => {
                    verdicts.insert("engine");
                    continue;
                }
                Err(error) => {
                    refusals.insert(error);
                    continue;
                }
            };
            for line in reachable(objdump, directory, &code)? {
                let line = line.as_str();
                let (mnemonic, operands) = split(line);
                // A prefix the disassembler prints on its own line.
                if mnemonic.is_empty() {
                    continue;
                }
                if mnemonic.starts_with('j') && mnemonic != "jmp" {
                    branches += 1;
                } else if mnemonic == "call" {
                    calls += 1;
                } else if !listed(mnemonic) {
                    unlisted.insert(mnemonic.to_owned());
                }
                if indexed_memory(mnemonic, operands) {
                    indexed += 1;
                }
            }
        }
        if !refusals.is_empty() {
            verdicts.insert("refused");
        }
        if !unlisted.is_empty() {
            verdicts.insert("unlisted");
        }
        if calls != 0 {
            verdicts.insert("helper");
        }
        if !address_free && branches != 0 {
            verdicts.insert("branch");
        }
        if !address_free && indexed != 0 {
            verdicts.insert("indexed");
        }
        let verdict = if words.is_empty() {
            "unsampled".to_owned()
        } else if verdicts.is_empty() {
            "constant".to_owned()
        } else {
            verdicts.into_iter().collect::<Vec<_>>().join("+")
        };
        row.insert(
            tier.into(),
            json!({
                "verdict": verdict,
                "unlisted": unlisted,
                "branches": branches,
                "indexed": indexed,
                "calls": calls,
                "refusals": refusals,
            }),
        );
    }
    Ok(Value::Object(row))
}

/// The instructions of `code` that execute: an unconditional jump forward
/// over bytes no branch enters skips data the compiler embeds (lookup
/// tables, shuffle masks), which a linear disassembly would decode as code.
/// A branch into those bytes from before the jump or from after them makes
/// them code.
pub(crate) fn reachable(
    objdump: &Path,
    directory: &tempfile::TempDir,
    code: &[u8],
) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut start = 0usize;
    'segment: while start < code.len() {
        let text = listing(&objdump.to_path_buf(), directory, &code[start..], true)?;
        let mut parsed = Vec::new();
        for line in text.lines() {
            let (address, instruction) = line
                .split_once(':')
                .with_context(|| format!("no address in {line:?}"))?;
            let address = usize::from_str_radix(address.trim(), 16)? + start;
            parsed.push((address, instruction.trim().to_owned()));
        }
        let target = |instruction: &str| -> Option<usize> {
            let (mnemonic, operands) = split(instruction);
            let offset = operands.split_whitespace().next()?.strip_prefix("0x")?;
            (mnemonic.starts_with('j'))
                .then(|| usize::from_str_radix(offset, 16).ok())
                .flatten()
                .map(|offset| offset + start)
        };
        let targets: Vec<(usize, usize)> = parsed
            .iter()
            .filter_map(|(address, line)| Some((*address, target(line)?)))
            .collect();
        for (address, instruction) in &parsed {
            lines.push(instruction.clone());
            if split(instruction).0 != "jmp" {
                continue;
            }
            let Some(destination) = target(instruction) else {
                continue;
            };
            // Only branches outside the skipped bytes count: the bytes
            // themselves decode as noise.
            let skipped = *address + 1..destination;
            let entered = targets
                .iter()
                .any(|(from, to)| !skipped.contains(from) && skipped.contains(to));
            if destination > *address && !entered {
                start = destination;
                continue 'segment;
            }
        }
        break;
    }
    Ok(lines)
}

/// The native code of `word` compiled alone as a system-mode block: its
/// source-map range, which ends where the block's exit begins.
fn instruction_code(word: u32, target: TargetCpu) -> Result<Vec<u8>, String> {
    // A second instruction marks where the first one's code ends.
    const NOP: u32 = 0xd503_201f;
    let source: Vec<u8> = [word, NOP].iter().flat_map(|w| w.to_le_bytes()).collect();
    let compiled = CompilationPlan::new(
        &source,
        GuestAddress(BASE),
        BlockProfile::SystemModeV1,
        target,
    )
    .and_then(CompilationPlan::compile)
    .map_err(|error| error.0)?;
    let map = &compiled.native.source_map;
    let start = map
        .iter()
        .find(|(pc, _)| pc.0 == BASE)
        .map(|(_, offset)| *offset)
        .ok_or("the instruction ends its block")?;
    let end = map
        .iter()
        .find(|(pc, _)| pc.0 == BASE + 4)
        .map(|(_, offset)| *offset)
        .ok_or("the instruction ends its block")?;
    Ok(compiled.native.x86_64_code[start..end].to_vec())
}

/// A listing line's mnemonic (prefixes dropped) and operands.
pub(crate) fn split(line: &str) -> (&str, &str) {
    let mut rest = line.trim();
    loop {
        let (word, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        if matches!(
            word,
            "lock" | "rep" | "repe" | "repne" | "data16" | "cs" | "ds"
        ) {
            rest = tail.trim_start();
            continue;
        }
        return (word, tail.trim());
    }
}

/// Whether Intel lists `mnemonic`, or it carries no data.
fn listed(mnemonic: &str) -> bool {
    mnemonic.starts_with("cmov")
        || (mnemonic.starts_with("set") && mnemonic.len() <= 6)
        || mnemonic == "movabs"
        || mnemonic == "sal"
        || DATALESS.contains(&mnemonic)
        || DOIT.contains(&mnemonic)
}

/// A memory operand whose address adds a scaled or second register: a lookup
/// indexed by a computed value.
fn indexed_memory(mnemonic: &str, operands: &str) -> bool {
    // LEA uses memory-address syntax for arithmetic, without accessing
    // memory. Flag packing uses its scaled register form to combine bits.
    mnemonic != "lea" && indexed_operand(operands)
}

fn indexed_operand(operands: &str) -> bool {
    operands.split('[').skip(1).any(|memory| {
        let memory = memory.split(']').next().unwrap_or_default();
        if memory.contains('*') {
            return true;
        }
        let registers = memory
            .split(['+', '-'])
            .map(str::trim)
            .filter(|term| {
                term.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && *term != "rip"
            })
            .count();
        registers > 1
    })
}

/// Each engine source of [`ENGINE_PERFORMED`] with its SHA-256, so a change
/// to one shows that its review needs repeating.
fn engine_digests() -> Result<BTreeMap<&'static str, String>> {
    ENGINE_PERFORMED
        .iter()
        .map(|(_, source)| Ok((*source, sha256(&fs::read(root().join(source))?))))
        .collect()
}

/// SHA-256 over the compiler's sources, each as its path and digest.
fn compiler_digest() -> Result<String> {
    fn walk(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, files)?;
            } else {
                files.push(path);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(&root().join("crates/stela-compiler/src"), &mut files)?;
    files.sort();
    let mut listing = String::new();
    for file in files {
        let relative = file.strip_prefix(root())?.display().to_string();
        listing.push_str(&format!("{relative}\0{}\n", sha256(&fs::read(&file)?)));
    }
    Ok(sha256(listing.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_lines_classify_their_instructions_and_operands() {
        assert_eq!(
            split("lock xadd qword ptr [rax], rcx"),
            ("xadd", "qword ptr [rax], rcx")
        );
        assert!(listed("cmovne") && listed("setb") && listed("pclmulqdq") && listed("jmp"));
        assert!(!listed("crc32") && !listed("lzcnt") && !listed("div") && !listed("bsr"));
        assert!(indexed_operand("eax, dword ptr [rax + 4*rcx]"));
        assert!(indexed_operand("eax, dword ptr [r14 + rax]"));
        assert!(!indexed_operand("eax, dword ptr [rip + 0x10]"));
        assert!(!indexed_operand("rax, qword ptr [rbp + 0x108]"));
        assert!(!indexed_memory("lea", "eax, [rax + 4*rdx]"));
        assert!(indexed_memory("mov", "eax, dword ptr [rax + 4*rdx]"));
        assert!(indexed_memory("add", "eax, dword ptr [rax + rdx]"));
    }

    #[test]
    fn the_list_parser_keeps_each_class_and_its_top_level() {
        let page = "<list><listitem><content>Data Processing -- Immediate: <list>\
            <listitem><content>Bitfield: <instruction>BFM</instruction>, and \
            <instruction>UBFM</instruction>.</content>\n</listitem></list>\n</content>\
            </listitem><listitem><content>Flag Manipulation: <instruction>CFINV</instruction>.\
            </content>\n</listitem></list>";
        let listed = parse_list(page).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|entry| (
                    entry.top.as_str(),
                    entry.class.as_str(),
                    entry.mnemonic.as_str()
                ))
                .collect::<Vec<_>>(),
            [
                ("Data Processing -- Immediate", "Bitfield", "BFM"),
                ("Data Processing -- Immediate", "Bitfield", "UBFM"),
                ("Flag Manipulation", "Flag Manipulation", "CFINV"),
            ]
        );
    }
}
