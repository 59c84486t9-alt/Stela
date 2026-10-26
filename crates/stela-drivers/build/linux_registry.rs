// SPDX-License-Identifier: MIT
//! Actual selected-object registration manifest. No source-body scan or linking.
//! Requires the already retained object 0.37 and sha2 0.10 build dependencies.
use object::{Architecture, BinaryFormat, Object, ObjectKind, ObjectSection, ObjectSymbol,
             RelocationKind, RelocationTarget, SectionKind, SymbolKind};
use super::inputs::{self, Inputs, Key, Limits, Request, RootId};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fmt::Write as _, path::PathBuf};

type Result<T> = std::result::Result<T, String>;
const PREFIX: &str = "stela_linux_reg__";
const ABI: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetAbi { ElfSysv, MachOSysv, CoffWin64Lp64 }
impl TargetAbi {
    fn format(self) -> BinaryFormat {
        match self { Self::ElfSysv => BinaryFormat::Elf, Self::MachOSysv => BinaryFormat::MachO,
                     Self::CoffWin64Lp64 => BinaryFormat::Coff }
    }
}
#[derive(Clone, Debug)]
pub struct Input { pub root: usize, pub relative: PathBuf, pub sha256: inputs::Hash }
#[derive(Clone, Debug)]
pub struct InputRoot { pub label: String, pub selected: PathBuf }
#[derive(Clone, Copy, Debug)]
pub struct RoleLimits {
    pub cohort_bytes: u64, pub source_bytes: u64, pub compiler_bytes: u64,
    pub dependency_bytes: u64, pub object_bytes: u64,
}
#[derive(Clone, Copy)]
enum Role { Cohort, Source, Compiler, Dependency, Object }
impl RoleLimits {
    fn cap(self, role: Role) -> u64 {
        match role { Role::Cohort => self.cohort_bytes, Role::Source => self.source_bytes,
            Role::Compiler => self.compiler_bytes, Role::Dependency => self.dependency_bytes,
            Role::Object => self.object_bytes }
    }
}
struct UnitKeys { source: Key, compiler: Key, dependencies: Vec<Key>, object: Key }
/* Explicit roots are reviewed directory capabilities, never inferred from an
 * input's parent or widened to the entire filesystem. The shared reader owns
 * canonicalization, conflicting pins, limits, safe opens and final rechecks. */
fn prepare_inputs(plan: &Plan) -> Result<(Inputs, Vec<RootId>, Key, Vec<UnitKeys>)> {
    let mut owner = Inputs::new(plan.input_limits)?;
    let mut roots = Vec::new();
    for root in &plan.roots {
        let id = owner.add_root(&root.selected)?;
        if owner.root_path(id)?.parent().is_none() { return Err("filesystem-wide input root is not an authorized plan capability".into()); }
        roots.push(id);
    }
    let mut uses = vec![(&plan.cohort,Role::Cohort)];
    for unit in &plan.units {
        uses.push((&unit.source,Role::Source)); uses.push((&unit.compiler,Role::Compiler));
        for dependency in &unit.dependencies { uses.push((dependency,Role::Dependency)); }
        uses.push((&unit.object,Role::Object));
    }
    let mut requests = Vec::new();
    for (input,role) in uses {
        requests.push(Request { root: *roots.get(input.root).ok_or("input references unknown reviewed root")?,
            relative: &input.relative, expected_sha256: Some(input.sha256), max_bytes: plan.role_limits.cap(role) });
    }
    // All expected hashes/role caps are preflighted together before content.
    let keys = owner.prepare(&requests)?;
    let mut keys = keys.into_iter();
    let cohort = keys.next().ok_or("missing prepared cohort key")?;
    let mut units = Vec::new();
    for unit in &plan.units {
        let source = keys.next().ok_or("missing prepared source key")?;
        let compiler = keys.next().ok_or("missing prepared compiler key")?;
        let mut dependencies = Vec::new();
        for _ in &unit.dependencies { dependencies.push(keys.next().ok_or("missing prepared dependency key")?); }
        let object = keys.next().ok_or("missing prepared object key")?;
        units.push(UnitKeys { source, compiler, dependencies, object });
    }
    if keys.next().is_some() { return Err("unexpected prepared input keys".into()); }
    Ok((owner,roots,cohort,units))
}
#[derive(Clone, Debug)]
pub struct Group {
    pub token: String, pub ordinal: u32, pub module_name: String,
    pub module_file: String, pub provenance: String,
}
#[derive(Clone, Debug)]
pub struct Unit {
    pub token: String, pub ordinal: u32, pub group_token: String,
    pub source: Input, pub source_label: String, pub provenance: String,
    pub object: Input,
    /// Exact compiler executable identity, hashed separately from arguments.
    pub compiler: Input,
    /// Exact ordered argv used for THIS source occurrence (no shell string).
    pub options: Vec<String>,
    /// Complete captured include/config/generated-header dependency closure.
    pub dependencies: Vec<Input>,
}
#[derive(Clone, Debug)]
pub struct Plan {
    pub roots: Vec<InputRoot>, pub input_limits: Limits, pub role_limits: RoleLimits,
    pub domain_token: String, pub domain_ordinal: u32, pub target: TargetAbi,
    pub target_triple: String, pub image_symbol: String,
    /// Hash of the separately reviewed selected-source/Kbuild plan.
    pub cohort: Input,
    /// Explicit Kbuild order, including units which emit no registrations.
    pub groups: Vec<Group>, pub units: Vec<Unit>,
}
#[derive(Debug)]
pub struct Manifest { pub c_source: String, pub receipt: String, pub records: usize }
#[derive(Clone, Debug)]
struct Record { symbol: String, code: char, sequence: u32 }
fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn token(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic()) && bytes.all(|b| b.is_ascii_alphanumeric())
}
fn identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b == b'_' || b.is_ascii_alphabetic()) &&
        bytes.all(|b| b == b'_' || b.is_ascii_alphanumeric())
}
/* The exported owner root occupies a disjoint reviewed C identifier family.
 * C keywords and plain array names cannot satisfy this shape. Actual generated
 * names are checked independently too, including future namespace extensions. */
fn image_namespace(name: &str) -> Result<()> {
    let middle = name.strip_prefix("stela_linux_").and_then(|s| s.strip_suffix("_image"));
    if !identifier(name) || !middle.is_some_and(|s| identifier(s) &&
        s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)) {
        return Err("image symbol requires stela_linux_<identifier>_image namespace".into());
    }
    Ok(())
}
fn image_collision(image: &str, generated: &str) -> Result<()> {
    if image == generated { return Err(format!("image symbol collides with generated identifier: {generated}")); }
    Ok(())
}
fn validate_image_name(plan: &Plan) -> Result<()> {
    image_namespace(&plan.image_symbol)?;
    for name in ["inits","exits","parameters","infos","devices","setups","groups","units"] {
        image_collision(&plan.image_symbol,name)?;
    }
    for group in &plan.groups {
        image_collision(&plan.image_symbol,&group_symbol(&plan.domain_token,&group.token))?;
    }
    for unit in &plan.units {
        image_collision(&plan.image_symbol,&unit_symbol(&plan.domain_token,&unit.token))?;
        image_collision(&plan.image_symbol,&format!("stela_linux_capture__{}__{}",plan.domain_token,unit.token))?;
    }
    Ok(())
}
fn text(s: &str) -> bool { !s.is_empty() && !s.contains('\0') }
fn c_string(s: &str) -> String {
    let mut out = String::from("\"");
    for b in s.bytes() {
        match b { b'"' => out.push_str("\\\""), b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)), _ => write!(out, "\\{b:03o}").unwrap() }
    }
    out.push('"'); out
}
fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch { '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"),
            c if c <= '\u{1f}' => write!(out, "\\u{:04x}", u32::from(c)).unwrap(),
            c => out.push(c) }
    }
    out.push('"'); out
}
fn group_symbol(domain: &str, group: &str) -> String { format!("stela_linux_group__{domain}__{group}") }
fn unit_symbol(domain: &str, unit: &str) -> String { format!("stela_linux_unit__{domain}__{unit}") }
fn logical_name(name: &str, format: BinaryFormat) -> &str {
    if format == BinaryFormat::MachO { name.strip_prefix('_').unwrap_or(name) } else { name }
}
fn parse_record(name: &str, domain: &str, unit: &str) -> Result<Record> {
    let suffix = name.strip_prefix(PREFIX).ok_or_else(|| format!("invalid registration prefix: {name}"))?;
    let fields: Vec<_> = suffix.split("__").collect();
    if fields.len() != 4 || fields[0] != domain || fields[1] != unit ||
        !token(fields[0]) || !token(fields[1]) { return Err(format!("wrong/malformed registration identity: {name}")); }
    let code = match fields[2] { "i"=>'i', "m"=>'m', "x"=>'x', "e"=>'e', "p"=>'p',
        "s"=>'s', "a"=>'a', "f"=>'f', "d"=>'d', "c"=>'c',
        _ => return Err(format!("unknown registration kind: {name}")) };
    let sequence: u32 = fields[3].parse().map_err(|_| format!("invalid counter: {name}"))?;
    if fields[3] != sequence.to_string() { return Err(format!("noncanonical counter: {name}")); }
    Ok(Record { symbol: name.to_owned(), code, sequence })
}
fn record_type(code: char) -> &'static str {
    match code { 'i'|'m'|'c' => "stela_linux_init_record", 'x'|'e' => "stela_linux_exit_record",
        'p' => "stela_linux_parameter_record", 's'|'a' => "stela_linux_setup_record",
        'f' => "stela_linux_info_record", 'd' => "stela_linux_device_record", _ => unreachable!() }
}
fn record_kind(code: char) -> u16 {
    match code { 'i'=>1, 'm'=>2, 'x'=>3, 'e'=>4, 'p'=>5, 's'=>6, 'a'=>7, 'f'=>8, 'd'=>9, 'c'=>10, _=>unreachable!() }
}
fn validate_header(bytes: &[u8], record: &Record, ordinal: u32) -> Result<()> {
    let abi = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let kind = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    let level = i8::from_le_bytes([bytes[6]]); let flags = bytes[7];
    let unit = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let seq = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let level_ok = match record.code { 'i' => (-3..=7).contains(&level) && level != -1,
        'm' => level == 6, 'c' => level == -4, 'p' => (-1..=7).contains(&level), _ => level == -1 };
    let flags_ok = flags == 0 || (record.code == 'i' && (1..=7).contains(&level) && flags == 1);
    if abi != ABI || kind != record_kind(record.code) || unit != ordinal || seq != record.sequence ||
        !level_ok || !flags_ok { return Err(format!("record prefix disagrees with selected ABI: {}", record.symbol)); }
    Ok(())
}
fn scan(plan: &Plan, unit: &Unit, bytes: &[u8]) -> Result<Vec<Record>> {
    let file = object::File::parse(bytes).map_err(|e| format!("{}: ordinary object required: {e}", unit.object.relative.display()))?;
    // COFF's container is 32-bit even for AMD64; its machine field supplies
    // the architecture. ELF and Mach-O additionally require their 64-bit form.
    if file.format() != plan.target.format() || file.kind() != ObjectKind::Relocatable ||
        file.architecture() != Architecture::X86_64 || !file.is_little_endian() ||
        (file.format() != BinaryFormat::Coff && !file.is_64()) {
        return Err(format!("{}: wrong target/relocatable LP64 object format", unit.object.relative.display()));
    }
    if file.symbol_table().is_none() { return Err("object lacks a registration-inspectable symbol table".into()); }
    for section in file.sections() {
        let name = section.name().map_err(|e| e.to_string())?;
        if name.starts_with(".gnu.lto_") || name.starts_with(".llvm.lto") ||
            matches!(name, ".llvmbc" | ".llvmcmd" | "__bitcode" | "__bundle") {
            return Err(format!("LTO/embedded bitcode not admitted: {name}"));
        }
    }
    let anchor_name = format!("stela_linux_capture__{}__{}", plan.domain_token, unit.token);
    let mut anchor_count = 0;
    for symbol in file.symbols() {
        let Ok(raw) = symbol.name() else { continue; };
        if logical_name(raw,file.format()) != anchor_name { continue; }
        anchor_count += 1;
        if !symbol.is_definition() || !symbol.is_global() || symbol.is_weak() || symbol.is_common() ||
            symbol.kind() != SymbolKind::Data || (symbol.size() != 0 && symbol.size() != 8) {
            return Err("capture anchor must be a strong pointer data definition".into());
        }
        let section = file.section_by_index(symbol.section_index().ok_or("missing anchor section")?).map_err(|e|e.to_string())?;
        let offset = symbol.address().checked_sub(section.address()).ok_or("invalid anchor address")?;
        if symbol.address() % 8 != 0 || section.align() < 8 ||
            !matches!(section.kind(),SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel) {
            return Err("capture anchor requires ordinary aligned initialized data".into());
        }
        let data = section.data().map_err(|e|e.to_string())?;
        let start = usize::try_from(offset).map_err(|e|e.to_string())?;
        let end = start.checked_add(8).ok_or("anchor extent overflow")?;
        if data.get(start..end).ok_or("truncated capture anchor")?.iter().any(|b| *b != 0) {
            return Err("capture anchor has a nonzero implicit addend".into());
        }
        let mut references = 0;
        for (address, relocation) in section.relocations() {
            if address != offset { continue; }
            let RelocationTarget::Symbol(index) = relocation.target() else { return Err("anchor must reference actual unit symbol".into()); };
            let target = file.symbol_by_index(index).map_err(|e|e.to_string())?;
            if relocation.kind() != RelocationKind::Absolute || relocation.size() != 64 || relocation.addend() != 0 ||
                logical_name(target.name().map_err(|e|e.to_string())?,file.format()) != unit_symbol(&plan.domain_token,&unit.token) {
                return Err("capture anchor references wrong unit/ABI".into());
            }
            references += 1;
        }
        if references != 1 { return Err("capture anchor requires exactly one unit relocation".into()); }
    }
    if anchor_count != 1 { return Err("exactly one per-TU capture anchor required; missing opt-in header".into()); }
    let mut records = Vec::new(); let mut sequences = BTreeSet::new(); let mut names = BTreeSet::new();
    for symbol in file.symbols() {
        let raw = symbol.name_bytes().map_err(|e| e.to_string())?;
        let mut reserved = raw;
        while let Some(rest) = reserved.strip_prefix(b"_") { reserved = rest; }
        if !reserved.starts_with(b"stela_linux_reg_") && reserved != b"stela_linux_reg" { continue; }
        let raw_name = std::str::from_utf8(raw).map_err(|e| e.to_string())?;
        let decorated = if file.format() == BinaryFormat::MachO { "_stela_linux_reg__" } else { PREFIX };
        if !raw_name.starts_with(decorated) { return Err(format!("malformed platform registration symbol: {raw_name}")); }
        let name = logical_name(raw_name, file.format());
        let record = parse_record(name, &plan.domain_token, &unit.token)?;
        if symbol.is_undefined() || symbol.is_common() || symbol.is_weak() || !symbol.is_global() ||
            !symbol.is_definition() || symbol.kind() != SymbolKind::Data {
            return Err(format!("registration must be a strong external data definition: {name}"));
        }
        if !names.insert(name.to_owned()) || !sequences.insert(record.sequence) {
            return Err(format!("duplicate registration symbol/counter: {name}"));
        }
        let index = symbol.section_index().ok_or_else(|| format!("missing data section: {name}"))?;
        let section = file.section_by_index(index).map_err(|e| e.to_string())?;
        if !matches!(section.kind(), SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel) {
            return Err(format!("registration not in ordinary initialized data: {name}"));
        }
        let size = if record.code == 'd' { 56 } else { 48 };
        if symbol.size() != 0 && symbol.size() != size { return Err(format!("wrong registration object size: {name}")); }
        if symbol.address() % 8 != 0 || section.align() < 8 { return Err(format!("unaligned registration: {name}")); }
        let offset = symbol.address().checked_sub(section.address()).ok_or_else(|| format!("invalid record address: {name}"))?;
        let data = section.data().map_err(|e| e.to_string())?;
        let start = usize::try_from(offset).map_err(|e| e.to_string())?;
        let end = start.checked_add(usize::try_from(size).unwrap()).ok_or("record extent overflow")?;
        let record_bytes = data.get(start..end).ok_or_else(|| format!("truncated record data: {name}"))?;
        validate_header(record_bytes, &record, unit.ordinal)?;
        for (address, _) in section.relocations() {
            if address >= offset && address < offset + size &&
                ![16,24,32,40].contains(&(address-offset)) {
                return Err(format!("relocation corrupts fixed record bytes: {name}"));
            }
        }
        for (slot, expected) in [(16, group_symbol(&plan.domain_token, &unit.group_token)),
                                 (24, unit_symbol(&plan.domain_token, &unit.token))] {
            let slot_index = usize::try_from(slot).unwrap();
            if record_bytes[slot_index..slot_index+8].iter().any(|b| *b != 0) {
                return Err(format!("identity has a nonzero implicit addend: {name}+{slot}"));
            }
            let mut seen = false;
            for (address, relocation) in section.relocations() {
                if address != offset + slot { continue; }
                if seen || relocation.kind() != RelocationKind::Absolute || relocation.size() != 64 || relocation.addend() != 0 {
                    return Err(format!("malformed identity relocation: {name}+{slot}"));
                }
                let RelocationTarget::Symbol(target) = relocation.target() else {
                    return Err(format!("identity must reference actual manifest symbol: {name}+{slot}"));
                };
                let target = file.symbol_by_index(target).map_err(|e| e.to_string())?;
                if logical_name(target.name().map_err(|e| e.to_string())?, file.format()) != expected {
                    return Err(format!("wrong group/unit identity: {name}+{slot}"));
                }
                seen = true;
            }
            if !seen { return Err(format!("missing strong identity relocation: {name}+{slot}")); }
        }
        records.push(record);
    }
    records.sort_by_key(|record| record.sequence);
    Ok(records)
}
fn validate_plan(plan: &Plan) -> Result<()> {
    validate_image_name(plan)?;
    if plan.target == TargetAbi::CoffWin64Lp64 && plan.target_triple != "x86_64-pc-cygwin" {
        return Err("LP64 COFF requires reviewed x86_64-pc-cygwin target".into());
    }
    if !token(&plan.domain_token) || !identifier(&plan.image_symbol) || !text(&plan.target_triple) || plan.units.is_empty() {
        return Err("explicit nonempty domain/target/image/source cohort required".into());
    }
    let mut root_labels = BTreeSet::new();
    if plan.roots.is_empty() || plan.roots.iter().any(|r| !text(&r.label) || !root_labels.insert(&r.label)) {
        return Err("explicit uniquely labeled reviewed input roots required".into());
    }
    let mut group_tokens = BTreeSet::new(); let mut group_ordinals = BTreeSet::new();
    for group in &plan.groups {
        if !token(&group.token) || !text(&group.module_name) || !text(&group.module_file) || !text(&group.provenance) ||
            group.module_name == "stela-linux" || !group_tokens.insert(&group.token) || !group_ordinals.insert(group.ordinal) {
            return Err("invalid/duplicate Kbuild group or forbidden fallback module".into());
        }
    }
    let groups: BTreeMap<_,_> = plan.groups.iter().map(|g| (g.token.as_str(),g)).collect();
    let mut unit_tokens = BTreeSet::new(); let mut unit_ordinals = BTreeSet::new(); let mut object_paths = BTreeSet::new();
    let mut used_groups = BTreeSet::new();
    for unit in &plan.units {
        let group = groups.get(unit.group_token.as_str()).ok_or("unit references missing Kbuild group")?;
        if !token(&unit.token) || !text(&unit.source_label) || !text(&unit.provenance) ||
            !unit_tokens.insert(&unit.token) || !unit_ordinals.insert(unit.ordinal) || !object_paths.insert((unit.object.root,&unit.object.relative)) {
            return Err("invalid/duplicate TU occurrence, ordinal or actual object".into());
        }
        used_groups.insert(&unit.group_token);
        let definitions = [format!("-DSTELA_LINUX_REG_DOMAIN={}",plan.domain_token),
            format!("-DSTELA_LINUX_REG_UNIT={}",unit.token), format!("-DSTELA_LINUX_REG_UNIT_ORDINAL={}",unit.ordinal),
            format!("-DSTELA_LINUX_REG_GROUP_SYMBOL={}",group_symbol(&plan.domain_token,&unit.group_token)),
            format!("-DKBUILD_MODNAME={}",c_string(&group.module_name)), format!("-DKBUILD_MODFILE={}",c_string(&group.module_file))];
        for definition in &definitions {
            if unit.options.iter().filter(|s| *s == definition).count() != 1 { return Err(format!("missing/duplicate exact capture definition: {definition}")); }
            let key = definition.split('=').next().unwrap();
            if unit.options.iter().filter(|s| s.split('=').next() == Some(key)).count() != 1 {
                return Err(format!("conflicting compiler definition: {key}"));
            }
        }
        if unit.options.iter().any(|s| s == "-flto" || s.starts_with("-flto=") || s.contains('\0')) {
            return Err("LTO/NUL compiler options refused".into());
        }
        if unit.dependencies.is_empty() { return Err("complete captured dependency closure required".into()); }
    }
    if used_groups.len() != plan.groups.len() { return Err("orphan build group".into()); }
    Ok(())
}
/// Genuine compiler-produced object cases, explicitly supplied by the hosted
/// integration harness. Missing inputs fail; no environment-based silent skip.
#[derive(Debug)]
pub struct QualificationCase {
    pub plan: Plan,
    pub expected_records: Option<usize>,
    pub expected_error: Option<String>,
}
fn qualification_shape(cases: &[QualificationCase]) -> Result<()> {
    if cases.is_empty() { return Err("real-object qualification cases required".into()); }
    for case in cases {
        match (case.expected_records,&case.expected_error) {
            (Some(_),None) => (),
            (None,Some(needle)) if !needle.trim().is_empty() => (),
            _ => return Err("qualification requires exactly one count or nonempty error pattern".into()),
        }
    }
    Ok(())
}
pub fn qualify(cases: &[QualificationCase]) -> Result<()> {
    // Validate the ENTIRE list before any generator/file access, so an invalid
    // later expectation cannot run earlier cases or pass on unrelated failure.
    qualification_shape(cases)?;
    for case in cases {
        match (generate(&case.plan), case.expected_records, &case.expected_error) {
            (Ok(manifest), Some(expected), None) if manifest.records == expected => (),
            (Err(error), None, Some(expected)) if error.contains(expected) => (),
            (result, _, _) => return Err(format!("qualification expectation mismatch: {result:?}")),
        }
    }
    Ok(())
}
fn receipt_input(out: &mut String, label: &str, input: &Input, key: Key, unit: Option<&str>) -> Result<()> {
    let relative = input.relative.to_str().ok_or("receipt path must be UTF-8")?;
    writeln!(out,"{{\"role\":{},\"unit\":{},\"selected_root\":{},\"relative\":{},\"key\":{},\"sha256\":{}}}",
        json_string(label),unit.map(json_string).unwrap_or_else(|| "null".to_owned()),
        input.root,json_string(relative),key.index(),json_string(&hex(&input.sha256))).unwrap(); Ok(())
}
fn identity_json(identity: &inputs::Identity) -> String {
    format!("{{\"device\":{},\"inode\":{},\"mode\":{},\"bytes\":{},\"mtime_secs\":{},\"mtime_nanos\":{},\"ctime_secs\":{},\"ctime_nanos\":{}}}",
        identity.device,identity.inode,identity.mode,identity.bytes,identity.mtime_secs,identity.mtime_nanos,identity.ctime_secs,identity.ctime_nanos)
}
fn receipt_bindings(out: &mut String, bindings: &inputs::Bindings) -> Result<()> {
    for root in &bindings.roots {
        writeln!(out,"{{\"final_root\":{},\"path\":{},\"identity\":{}}}",root.root.index(),
            json_string(root.path.to_str().ok_or("root receipt path must be UTF-8")?),identity_json(&root.identity)).unwrap();
    }
    for binding in &bindings.files {
        writeln!(out,"{{\"final_input\":{},\"path\":{},\"bytes\":{},\"sha256\":{},\"identity\":{}}}",binding.key.index(),
            json_string(binding.path.to_str().ok_or("input receipt path must be UTF-8")?),binding.bytes,
            json_string(&hex(&binding.sha256)),identity_json(&binding.identity)).unwrap();
    }
    let stats = &bindings.stats;
    writeln!(out,"{{\"input_stats\":{{\"unique_files\":{},\"unique_bytes\":{},\"bytes_hashed\":{},\"bytes_returned\":{},\"metadata_cache_hits\":{}}}}}",
        stats.unique_files,stats.unique_bytes,stats.bytes_hashed,stats.bytes_returned,stats.metadata_cache_hits).unwrap();
    Ok(())
}
/// Pure generation after bounded reads. Caller writes outputs only after all
/// validation succeeds, then compiles C with the SAME target and reviewed ABI.
/// Root reachability is NOT independent ALL-selected-object link qualification.
pub fn generate(plan: &Plan) -> Result<Manifest> {
    validate_plan(plan)?;
    let (mut inputs,roots,cohort_key,unit_keys) = prepare_inputs(plan)?;
    inputs.verify(cohort_key)?;
    let mut receipt = String::new();
    writeln!(receipt,"{{\"schema\":1,\"target_abi\":{},\"target_triple\":{},\"domain\":{},\"domain_ordinal\":{},\"image_symbol\":{}}}",
        json_string(&format!("{:?}",plan.target)),json_string(&plan.target_triple),json_string(&plan.domain_token),plan.domain_ordinal,json_string(&plan.image_symbol)).unwrap();
    writeln!(receipt,"{{\"input_limits\":{{\"max_unique_files\":{},\"max_unique_bytes\":{},\"max_roots\":{},\"max_directory_entries\":{}}}}}",
        plan.input_limits.max_unique_files,plan.input_limits.max_unique_bytes,
        plan.input_limits.max_roots,plan.input_limits.max_directory_entries).unwrap();
    writeln!(receipt,"{{\"role_limits\":{{\"cohort_bytes\":{},\"source_bytes\":{},\"compiler_bytes\":{},\"dependency_bytes\":{},\"object_bytes\":{}}}}}",
        plan.role_limits.cohort_bytes,plan.role_limits.source_bytes,plan.role_limits.compiler_bytes,
        plan.role_limits.dependency_bytes,plan.role_limits.object_bytes).unwrap();
    receipt_input(&mut receipt,"reviewed_cohort",&plan.cohort,cohort_key,None)?;
    for (index,(root,id)) in plan.roots.iter().zip(&roots).enumerate() {
        writeln!(receipt,"{{\"selected_root\":{},\"binding_root\":{},\"label\":{},\"selected_path\":{}}}",index,id.index(),
            json_string(&root.label),json_string(root.selected.to_str().ok_or("selected root path must be UTF-8")?)).unwrap();
    }
    let mut observed = Vec::new(); let mut names = BTreeSet::new();
    for (unit,keys) in plan.units.iter().zip(&unit_keys) {
        // Compiler and common headers retain hashes/identity only. Repeated
        // verify calls enforce each role without compiler-sized byte caches.
        inputs.verify(keys.source)?; inputs.verify(keys.compiler)?;
        receipt_input(&mut receipt,"source",&unit.source,keys.source,Some(&unit.token))?;
        receipt_input(&mut receipt,"compiler",&unit.compiler,keys.compiler,Some(&unit.token))?;
        for (dependency,key) in unit.dependencies.iter().zip(&keys.dependencies) {
            inputs.verify(*key)?; receipt_input(&mut receipt,"dependency",dependency,*key,Some(&unit.token))?;
        }
        let records = {
            let bytes = inputs.read(keys.object)?;
            receipt_input(&mut receipt,"object",&unit.object,keys.object,Some(&unit.token))?;
            scan(plan,unit,&bytes)?
        }; // The actual object buffer is released before the next TU.
        let argv = unit.options.iter().map(|v| json_string(v)).collect::<Vec<_>>().join(",");
        writeln!(receipt,"{{\"unit\":{},\"ordinal\":{},\"group\":{},\"source_label\":{},\"provenance\":{},\"argv\":[{}],\"registrations\":{}}}",
            json_string(&unit.token),unit.ordinal,json_string(&unit.group_token),json_string(&unit.source_label),json_string(&unit.provenance),argv,records.len()).unwrap();
        for record in &records {
            image_collision(&plan.image_symbol,&record.symbol)?;
            if !names.insert(record.symbol.clone()) { return Err(format!("duplicate cohort registration: {}",record.symbol)); }
            writeln!(receipt,"{{\"registration\":{},\"unit\":{},\"sequence\":{},\"type\":{}}}",json_string(&record.symbol),json_string(&unit.token),record.sequence,json_string(record_type(record.code))).unwrap();
        }
        observed.extend(records);
    }
    let mut c = String::from("/* Generated from actual selected objects; do not edit. */\n#include <stela/registry.h>\n");
    for group in &plan.groups {
        writeln!(c,"const struct stela_linux_build_group {} = {{ {}U, {}U, {}U, 0, {}, {}, {} }};",
            group_symbol(&plan.domain_token,&group.token),ABI,plan.domain_ordinal,group.ordinal,
            c_string(&group.module_name),c_string(&group.module_file),c_string(&group.provenance)).unwrap();
        writeln!(receipt,"{{\"group\":{},\"ordinal\":{},\"module_name\":{},\"module_file\":{},\"provenance\":{}}}",json_string(&group.token),group.ordinal,json_string(&group.module_name),json_string(&group.module_file),json_string(&group.provenance)).unwrap();
    }
    for unit in &plan.units {
        writeln!(c,"const struct stela_linux_build_unit {} = {{ {}U, {}U, &{}, {}, {} }};",
            unit_symbol(&plan.domain_token,&unit.token),ABI,unit.ordinal,group_symbol(&plan.domain_token,&unit.group_token),
            c_string(&unit.source_label),c_string(&unit.provenance)).unwrap();
    }
    for record in &observed { writeln!(c,"extern const struct {} {};",record_type(record.code),record.symbol).unwrap(); }
    let sets = [("inits","imc","stela_linux_init_record"),("exits","xe","stela_linux_exit_record"),
        ("parameters","p","stela_linux_parameter_record"),("infos","f","stela_linux_info_record"),
        ("devices","d","stela_linux_device_record"),("setups","sa","stela_linux_setup_record")];
    let mut counts = Vec::new();
    for (name,codes,ty) in sets {
        let records: Vec<_> = observed.iter().filter(|r| codes.contains(r.code)).collect();
        counts.push(records.len());
        if records.is_empty() { continue; }
        writeln!(c,"static const struct {ty} *const {name}[] = {{").unwrap();
        for record in records { writeln!(c," &{},",record.symbol).unwrap(); }
        c.push_str("};\n");
    }
    c.push_str("static const struct stela_linux_build_group *const groups[] = {\n");
    for group in &plan.groups { writeln!(c," &{},",group_symbol(&plan.domain_token,&group.token)).unwrap(); }
    c.push_str("};\nstatic const struct stela_linux_build_unit *const units[] = {\n");
    for unit in &plan.units { writeln!(c," &{},",unit_symbol(&plan.domain_token,&unit.token)).unwrap(); }
    writeln!(c,"}};\nconst struct stela_linux_registry_image {} = {{ {}U, 0,",plan.image_symbol,ABI).unwrap();
    for ((name,_,_),count) in sets.iter().zip(counts) { writeln!(c," {}, {count},",if count == 0 { "0" } else { name }).unwrap(); }
    writeln!(c," groups, {}, units, {}\n}};",plan.groups.len(),plan.units.len()).unwrap();
    writeln!(receipt,"{{\"generated_c_sha256\":{},\"whole_selected_object_link\":\"UNRUN\",\"runtime\":\"UNRUN\"}}",json_string(&hex(&digest(c.as_bytes())))).unwrap();
    // Consuming final validation rehashes each UNIQUE consumed file once,
    // checks roots/identities and closes all retained reader descriptors.
    // No output is returned or published if these final checks refuse.
    let bindings = inputs.finish()?;
    receipt_bindings(&mut receipt,&bindings)?;
    Ok(Manifest { c_source: c, receipt, records: observed.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Authored empty COFF containers exercise the external object-reader
    // contract. They deliberately lack the still-mandatory capture anchor.
    fn coff_header(machine: u16) -> [u8; 20] {
        let mut bytes = [0; 20];
        bytes[..2].copy_from_slice(&machine.to_le_bytes());
        bytes
    }
    #[test]
    fn amd64_coff_reaches_capture_validation_despite_container_width() {
        let bytes = coff_header(object::pe::IMAGE_FILE_MACHINE_AMD64);
        let file = object::File::parse(bytes.as_slice()).unwrap();
        assert_eq!(file.architecture(), Architecture::X86_64);
        assert!(!file.is_64());
        let mut plan = policy_plan();
        plan.target = TargetAbi::CoffWin64Lp64;
        let error = scan(&plan, &plan.units[0], &bytes).unwrap_err();
        assert_eq!(error, "exactly one per-TU capture anchor required; missing opt-in header");
    }
    #[test]
    fn coff_architecture_and_target_mismatches_still_refuse() {
        let mut plan = policy_plan();
        plan.target = TargetAbi::CoffWin64Lp64;
        for machine in [object::pe::IMAGE_FILE_MACHINE_I386, object::pe::IMAGE_FILE_MACHINE_ARM64] {
            let error = scan(&plan, &plan.units[0], &coff_header(machine)).unwrap_err();
            assert!(error.ends_with("wrong target/relocatable LP64 object format"));
        }
        for target in [TargetAbi::ElfSysv, TargetAbi::MachOSysv] {
            plan.target = target;
            let error = scan(&plan, &plan.units[0], &coff_header(object::pe::IMAGE_FILE_MACHINE_AMD64)).unwrap_err();
            assert!(error.ends_with("wrong target/relocatable LP64 object format"));
        }
    }
    #[test]
    fn registration_identity_is_canonical_and_tu_scoped() {
        let record = parse_record("stela_linux_reg__D1__U2__p__17","D1","U2").unwrap();
        assert_eq!((record.code,record.sequence),('p',17));
        for bad in ["stela_linux_reg__D1__U3__p__17","stela_linux_reg__D1__U2__p__017",
            "stela_linux_reg__D1__U2__p__4294967296","stela_linux_reg__D1__U2__z__0",
            "stela_linux_reg__D1__U2__p__0__extra"] { assert!(parse_record(bad,"D1","U2").is_err()); }
    }
    #[test]
    fn string_encoders_keep_c_bytes_and_json_controls_unambiguous() {
        assert_eq!(c_string("a\n0\"\\"),"\"a\\0120\\\"\\\\\"");
        assert_eq!(json_string("a\n\"\\"),"\"a\\u000a\\\"\\\\\"");
    }
    fn policy_plan() -> Plan {
        let input = Input { root: 0, relative: PathBuf::from("unused"), sha256: [0;32] };
        Plan {
            roots: vec![InputRoot { label: "reviewed".into(), selected: PathBuf::from("never-opened") }],
            input_limits: Limits { max_unique_files: 32, max_unique_bytes: 1024*1024*1024,
                max_roots: 2, max_directory_entries: 32 },
            // Explicit compiler cap admits the known ~290-MB retained tool;
            // small fixtures exercise accounting without allocating that size.
            role_limits: RoleLimits { cohort_bytes: 1024, source_bytes: 1024,
                compiler_bytes: 512*1024*1024, dependency_bytes: 1024, object_bytes: 1024 },
            domain_token: "Fixture".into(), domain_ordinal: 1, target: TargetAbi::ElfSysv,
            target_triple: "x86_64-unknown-linux-gnu".into(), image_symbol: "stela_linux_fixture_image".into(),
            cohort: input.clone(),
            groups: vec![Group { token: "image".into(), ordinal: 1, module_name: "fixture".into(),
                module_file: "fixtures/fixture".into(), provenance: "authored policy fixture".into() }],
            units: vec![Unit { token: "image".into(), ordinal: 1, group_token: "image".into(),
                source: input.clone(), source_label: "fixture.c".into(), provenance: "authored policy fixture".into(),
                object: input.clone(), compiler: input.clone(), options: Vec::new(), dependencies: vec![input] }],
        }
    }
    #[test]
    fn image_names_reject_keywords_arrays_and_generated_identities() {
        for allowed in ["stela_linux_fixture_image","stela_linux_video_fixture_image"] {
            assert!(image_namespace(allowed).is_ok());
        }
        let mut plan = policy_plan();
        for forbidden in ["for","struct","_Generic","inits","exits","parameters","infos",
            "devices","setups","groups","units","stela_linux__image","stela_linux_9bad_image",
            "stela_linux_bad-image","stela_linux_fixture_image;", "stela_linux_fixture_image\n"] {
            plan.image_symbol = forbidden.into();
            assert!(validate_image_name(&plan).is_err(),"accepted {forbidden}");
        }
        for collision in [group_symbol("Fixture","image"),unit_symbol("Fixture","image"),
            "stela_linux_capture__Fixture__image".into()] {
            assert!(image_namespace(&collision).is_ok());
            plan.image_symbol = collision;
            assert!(validate_image_name(&plan).unwrap_err().contains("collides"));
        }
        let record = "stela_linux_reg__Fixture__image__i__0";
        assert!(image_collision(record,record).is_err());
    }
    #[test]
    fn all_qualification_expectations_are_checked_before_generation() {
        for (count,error) in [(None,None),(Some(0),Some("bad")),(None,Some("")),(None,Some(" \t\n"))] {
            let cases = [
                QualificationCase { plan: policy_plan(), expected_records: Some(0), expected_error: None },
                QualificationCase { plan: policy_plan(), expected_records: count, expected_error: error.map(str::to_owned) },
            ];
            // The first deliberately incomplete plan would fail generation;
            // reaching that error would prove whole-list preflight was lost.
            assert_eq!(qualify(&cases).unwrap_err(),
                "qualification requires exactly one count or nonempty error pattern");
        }
        assert!(qualification_shape(&[]).is_err());
        assert!(qualification_shape(&[
            QualificationCase { plan: policy_plan(), expected_records: Some(0), expected_error: None },
            QualificationCase { plan: policy_plan(), expected_records: None, expected_error: Some("hash mismatch".into()) },
        ]).is_ok());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct FixtureDirectory(PathBuf);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl FixtureDirectory {
        fn new() -> Self {
            use std::{fs::DirBuilder, os::unix::fs::DirBuilderExt,
                sync::atomic::{AtomicUsize,Ordering}};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let parent = std::env::temp_dir();
            for _ in 0..16 {
                let path = parent.join(format!("stela-registry-input-{}-{}",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed)));
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("fixture directory: {error}"),
                }
            }
            panic!("fixture directory collision bound exhausted");
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            if let Err(error) = std::fs::remove_dir_all(&self.0)
                && !std::thread::panicking()
            {
                panic!("fixture directory cleanup: {error}");
            }
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn shared_input_verification_deduplicates_roles_without_compiler_bytes() {
        let directory = FixtureDirectory::new();
        std::fs::write(directory.0.join("shared"),b"abc").unwrap();
        let mut plan = policy_plan(); plan.roots[0].selected = directory.0.clone();
        let shared = Input { root: 0, relative: PathBuf::from("shared"), sha256: digest(b"abc") };
        plan.cohort = shared.clone(); plan.units[0].source = shared.clone();
        plan.units[0].compiler = shared.clone(); plan.units[0].dependencies = vec![shared];
        let (mut owner,_,cohort,units) = prepare_inputs(&plan).unwrap();
        assert_eq!(cohort,units[0].source); assert_eq!(cohort,units[0].compiler);
        assert_eq!(cohort,units[0].dependencies[0]);
        owner.verify(cohort).unwrap();
        for _ in 0..100 { owner.verify(units[0].compiler).unwrap(); }
        let bindings = owner.finish().unwrap();
        assert_eq!(bindings.stats.unique_files,1);
        assert_eq!(bindings.stats.unique_bytes,3);
        assert_eq!(bindings.stats.bytes_returned,0);
        assert_eq!(bindings.stats.bytes_hashed,6); // one initial + one final pass
        assert_eq!(bindings.stats.metadata_cache_hits,100);
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn conflicting_role_pins_refuse_before_any_file_content_is_read() {
        let directory = FixtureDirectory::new();
        let mut plan = policy_plan(); plan.roots[0].selected = directory.0.clone();
        // The shared file intentionally does not exist: conflict refusal must
        // precede reading it, not accidentally pass on an unrelated I/O error.
        let shared = Input { root: 0, relative: PathBuf::from("absent"), sha256: [1;32] };
        plan.cohort = shared.clone(); plan.units[0].compiler = Input { sha256: [2;32], ..shared };
        let error = match prepare_inputs(&plan) { Err(error) => error, Ok(_) => panic!("conflicting pins accepted") };
        assert!(error.contains("conflicting expected hashes"),"wrong refusal: {error}");
    }

}
