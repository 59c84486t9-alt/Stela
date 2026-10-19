//! Generate the pinned Darwin service catalogs from an xnu source tree:
//! the BSD system-call table (`bsd/kern/syscalls.master`), the Mach-trap
//! table (`osfmk/kern/syscall_sw.c`) and the kernel-served MIG routines
//! (`osfmk/mach/*.defs`, see [`mig`]). The rows are derived the way the kernel
//! build derives them, so the runtime's `generated` tables are reproducible
//! from a named source drop rather than edited by hand.
use crate::tools::{exec, root};
use anyhow::{Context, Result, bail, ensure};
use std::{fmt::Write as _, path::PathBuf, process::Command};

const BSD_MASTER: &str = "bsd/kern/syscalls.master";
const MACH_TABLE: &str = "osfmk/kern/syscall_sw.c";
const BSD_OUTPUT: &str = "crates/stela-runtime/src/darwin/catalog/generated.rs";
const MACH_OUTPUT: &str = "crates/stela-runtime/src/mach/catalog/generated.rs";
const MIG_OUTPUT: &str = "crates/stela-runtime/src/mach/mig/generated.rs";

mod mig;
/// `MACH_TRAP_TABLE_COUNT` in `osfmk/kern/syscall_sw.h`.
const MACH_TRAP_TABLE_COUNT: usize = 128;
/// The placeholder routines `syscalls.master` uses for unassigned numbers.
const BSD_PLACEHOLDERS: [&str; 2] = ["nosys", "enosys"];
/// The routine `mach_trap_table` uses for unassigned indices.
const MACH_PLACEHOLDER: &str = "kern_invalid";

#[derive(clap::Args)]
pub struct DarwinCatalogs {
    /// Root of an xnu source tree (an apple-oss-distributions/xnu checkout).
    #[arg(long)]
    xnu: PathBuf,
    /// Fail instead of writing when a generated table differs.
    #[arg(long)]
    check: bool,
}

impl DarwinCatalogs {
    pub fn run(&self) -> Result<()> {
        let master = read(&self.xnu, BSD_MASTER)?;
        let table = read(&self.xnu, MACH_TABLE)?;
        let bsd = render_bsd(&bsd_rows(&master)?);
        let mach = render_mach(&mach_rows(&table)?);
        let (subsystems, routines) = mig::collect(&self.xnu)?;
        let mig = mig::render(&subsystems, &routines);
        let mut stale = Vec::new();
        for (output, text) in [(BSD_OUTPUT, bsd), (MACH_OUTPUT, mach), (MIG_OUTPUT, mig)] {
            let path = root().join(output);
            let formatted = rustfmt(&text)?;
            let current = std::fs::read_to_string(&path).unwrap_or_default();
            if current == formatted {
                println!("{output}: up to date");
                continue;
            }
            if self.check {
                stale.push(output);
            } else {
                std::fs::write(&path, formatted)
                    .with_context(|| format!("cannot write {}", path.display()))?;
                println!("{output}: regenerated");
            }
        }
        ensure!(
            stale.is_empty(),
            "generated catalogs differ from the xnu source: {}",
            stale.join(", ")
        );
        Ok(())
    }
}

fn read(xnu: &std::path::Path, relative: &str) -> Result<String> {
    let path = xnu.join(relative);
    let bytes = std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `rustfmt` the generated text, as the checked-in tables are formatted.
fn rustfmt(text: &str) -> Result<String> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("generated.rs");
    std::fs::write(&path, text)?;
    exec(
        Command::new("rustfmt")
            .args(["--edition", "2024", "--config-path"])
            .arg(root().join("rustfmt.toml"))
            .arg(&path),
    )?;
    Ok(std::fs::read_to_string(&path)?)
}

/// One `syscalls.master` row as `makesyscalls.sh` reads it into `sysent`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BsdRow {
    number: u16,
    name: String,
    argument_count: usize,
    return_type: &'static str,
    reserved: bool,
}

/// `makesyscalls.sh`'s `sy_return_type` munging of the C return type.
fn return_type(c_type: &str) -> Option<&'static str> {
    Some(match c_type {
        "int" => "Int",
        "u_int" | "mach_port_name_t" | "uint32_t" => "UnsignedInt",
        "user_ssize_t" => "SignedSize",
        "user_size_t" => "Size",
        "user_addr_t" => "Address",
        "off_t" => "Offset",
        "uint64_t" => "Unsigned64",
        "void" => "None",
        _ => return None,
    })
}

/// Every numbered `{ prototype }` of `syscalls.master`. Comment (`;`) and
/// preprocessor lines are dropped first; where conditional branches give one
/// number both a real call and a placeholder, the real call is kept.
fn bsd_rows(master: &str) -> Result<Vec<BsdRow>> {
    let joined = master
        .lines()
        .filter(|line| {
            let line = line.trim();
            !(line.is_empty() || line.starts_with(';') || line.starts_with('#'))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut rows = std::collections::BTreeMap::<u16, BsdRow>::new();
    let mut rest = joined.as_str();
    while let Some(open) = rest.find('{') {
        let line_start = rest[..open].rfind('\n').map_or(0, |at| at + 1);
        let header: Vec<&str> = rest[line_start..open].split_whitespace().collect();
        let close = rest[open..]
            .find('}')
            .map(|at| open + at)
            .context("unterminated syscalls.master prototype")?;
        let body = rest[open + 1..close]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        rest = &rest[close + 1..];
        // `NUMBER AUDIT FILES { prototype }`.
        let [number, _audit, _files] = header[..] else {
            continue;
        };
        let Ok(number) = number.parse::<u16>() else {
            continue;
        };
        let row = parse_bsd_prototype(number, &body.replace("NO_SYSCALL_STUB", ""))?;
        if let Some(previous) = rows.get(&number)
            && row.reserved
            && !previous.reserved
        {
            continue;
        }
        rows.insert(number, row);
    }
    let rows: Vec<BsdRow> = rows.into_values().collect();
    for (index, row) in rows.iter().enumerate() {
        ensure!(
            usize::from(row.number) == index,
            "syscalls.master is not dense at {index}"
        );
    }
    Ok(rows)
}

/// `RET NAME(ARGS);` → the row. Each C parameter is one LP64 register slot.
fn parse_bsd_prototype(number: u16, prototype: &str) -> Result<BsdRow> {
    let prototype = prototype.trim().trim_end_matches(';').trim();
    let open = prototype
        .find('(')
        .with_context(|| format!("syscall {number}: no parameter list in {prototype:?}"))?;
    ensure!(
        prototype.ends_with(')'),
        "syscall {number}: malformed prototype {prototype:?}"
    );
    let head = prototype[..open].trim_end();
    let name_start = head
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(0, |at| at + 1);
    let name = &head[name_start..];
    let c_return = head[..name_start].trim();
    ensure!(
        !name.is_empty() && !c_return.is_empty(),
        "syscall {number}: cannot split {prototype:?}"
    );
    let arguments = prototype[open + 1..prototype.len() - 1].trim();
    let argument_count = match arguments {
        "" | "void" => 0,
        _ => arguments.matches(',').count() + 1,
    };
    let Some(return_type) = return_type(c_return) else {
        bail!("syscall {number} {name}: unmapped return type {c_return:?}");
    };
    Ok(BsdRow {
        number,
        name: name.into(),
        argument_count,
        return_type,
        reserved: BSD_PLACEHOLDERS.contains(&name),
    })
}

/// One `mach_trap_table` row on the arm64 (LP64) path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MachRow {
    index: u32,
    name: String,
    argument_count: usize,
    returns_port: bool,
    reserved: bool,
}

/// The `MACH_TRAP(routine, arg_count, words, munge[, .flags])` rows of
/// `mach_trap_table`, keeping the `__LP64__`/`__arm64__` branch of each
/// conditional and dropping its `#else`.
fn mach_rows(source: &str) -> Result<Vec<MachRow>> {
    let start = source
        .find("mach_trap_table[MACH_TRAP_TABLE_COUNT]")
        .context("syscall_sw.c has no mach_trap_table")?;
    let body = &source[start..];
    let end = body.find("\n};").context("unterminated mach_trap_table")?;
    let mut rows = std::collections::BTreeMap::<u32, MachRow>::new();
    let mut skip = false;
    for line in body[..end].lines() {
        let line = line.trim();
        if let Some(condition) = line
            .strip_prefix('#')
            .map(str::trim_start)
            .and_then(|directive| directive.strip_prefix("if"))
        {
            skip = !(condition.contains("__LP64__") || condition.contains("__arm64__"));
            continue;
        }
        if line.starts_with("#else") {
            skip = !skip;
            continue;
        }
        if line.starts_with("#endif") {
            skip = false;
            continue;
        }
        let Some(row) = parse_mach_row(line)? else {
            continue;
        };
        if !skip {
            rows.insert(row.index, row);
        }
    }
    let rows: Vec<MachRow> = rows.into_values().collect();
    ensure!(
        rows.len() == MACH_TRAP_TABLE_COUNT,
        "mach_trap_table has {} rows, expected {MACH_TRAP_TABLE_COUNT}",
        rows.len()
    );
    for (index, row) in rows.iter().enumerate() {
        ensure!(
            row.index as usize == index,
            "mach_trap_table is not dense at {index}"
        );
    }
    Ok(rows)
}

/// `/* N */ MACH_TRAP(routine, arg_count, ...)`, or `None` for other lines.
fn parse_mach_row(line: &str) -> Result<Option<MachRow>> {
    let Some(comment) = line.strip_prefix("/*") else {
        return Ok(None);
    };
    let Some((index, rest)) = comment.split_once("*/") else {
        return Ok(None);
    };
    let Ok(index) = index.trim().parse::<u32>() else {
        return Ok(None);
    };
    let Some(arguments) = rest.trim_start().strip_prefix("MACH_TRAP(") else {
        return Ok(None);
    };
    let mut fields = arguments.split(',').map(str::trim);
    let name = fields
        .next()
        .with_context(|| format!("Mach trap {index}: no routine"))?;
    let argument_count = fields
        .next()
        .with_context(|| format!("Mach trap {index}: no argument count"))?
        .parse()
        .with_context(|| format!("Mach trap {index}: argument count"))?;
    Ok(Some(MachRow {
        index,
        name: name.into(),
        argument_count,
        returns_port: line.contains(".mach_trap_returns_port = 1"),
        reserved: name == MACH_PLACEHOLDER,
    }))
}

fn reserved(flag: bool) -> &'static str {
    if flag {
        "Reserved::Yes"
    } else {
        "Reserved::No"
    }
}

fn render_bsd(rows: &[BsdRow]) -> String {
    let mut text = String::from(
        "//! The pinned BSD system-call catalog, generated by `cargo xtask\n\
         //! darwin-catalogs` from xnu's `bsd/kern/syscalls.master`. Do not edit\n\
         //! by hand.\n\
         //!\n\
         //! Each row is the call's number, name, argument count (one 64-bit\n\
         //! register slot each under the arm64 LP64 ABI; `void` is zero) and\n\
         //! return-register munging, derived exactly as `makesyscalls.sh`\n\
         //! derives `sy_narg` and `sy_return_type`. Placeholder `enosys`/\n\
         //! `nosys` numbers are retained as reserved rows so the dispatcher\n\
         //! names them rather than treating them as absent.\n\
         use super::{CatalogEntry, Reserved};\n\
         use crate::darwin::BsdReturnType::*;\n\n\
         pub(super) const CATALOG: &[CatalogEntry] = &[\n",
    );
    for row in rows {
        let _ = writeln!(
            text,
            "    CatalogEntry {{ number: {}, name: {:?}, argument_count: {}, return_type: {}, reserved: {} }},",
            row.number,
            row.name,
            row.argument_count,
            row.return_type,
            reserved(row.reserved)
        );
    }
    text.push_str("];\n");
    text
}

fn render_mach(rows: &[MachRow]) -> String {
    let mut text = String::from(
        "//! The pinned Mach-trap catalog, generated by `cargo xtask\n\
         //! darwin-catalogs` from xnu's `osfmk/kern/syscall_sw.c`\n\
         //! `mach_trap_table`. Do not edit by hand.\n\
         //!\n\
         //! A userspace Mach trap passes `x16 = -index`; each row is that\n\
         //! index, the routine's name, its 64-bit argument count on the\n\
         //! arm64 path, and whether it returns a port name. `kern_invalid`\n\
         //! slots are reserved.\n\
         use super::{MachTrapEntry, Reserved};\n\n\
         pub(super) const CATALOG: &[MachTrapEntry] = &[\n",
    );
    for row in rows {
        let _ = writeln!(
            text,
            "    MachTrapEntry {{ index: {}, name: {:?}, argument_count: {}, returns_port: {}, reserved: {} }},",
            row.index,
            row.name,
            row.argument_count,
            row.returns_port,
            reserved(row.reserved)
        );
    }
    text.push_str("];\n");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bsd_rows_follow_makesyscalls_and_prefer_real_calls() {
        let master = "\
; comment line\n\
#include <sys/param.h>\n\
0\tAUE_NULL\tALL\t{ int nosys(void); }   { indirect syscall }\n\
1\tAUE_EXIT\tALL\t{ void exit(int rval) NO_SYSCALL_STUB; }\n\
#if CONFIG_X\n\
2\tAUE_NULL\tALL\t{ user_ssize_t read(int fd, user_addr_t cbuf,\n\t\tuser_size_t nbyte); }\n\
#else\n\
2\tAUE_NULL\tALL\t{ int enosys(void); }\n\
#endif\n";
        let rows = bsd_rows(master).unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].reserved && rows[0].argument_count == 0);
        assert_eq!(
            rows[1],
            BsdRow {
                number: 1,
                name: "exit".into(),
                argument_count: 1,
                return_type: "None",
                reserved: false
            }
        );
        assert_eq!((rows[2].name.as_str(), rows[2].argument_count), ("read", 3));
        assert_eq!(rows[2].return_type, "SignedSize");
        assert!(parse_bsd_prototype(9, "struct x f(void)").is_err());
    }

    #[test]
    fn mach_rows_keep_the_lp64_branch() {
        let mut table =
            String::from("const mach_trap_t mach_trap_table[MACH_TRAP_TABLE_COUNT] = {\n");
        for index in 0..MACH_TRAP_TABLE_COUNT {
            match index {
                26 => table.push_str(
                    "/* 26 */ MACH_TRAP(mach_reply_port, 0, 0, NULL, .mach_trap_returns_port = 1),\n",
                ),
                47 => table.push_str(
                    "#if defined(__LP64__) || defined(__arm64__)\n\
                     /* 47 */ MACH_TRAP(mach_msg2_trap, 8, 16, munge_wwwwwwwwwwwwwwww),\n\
                     #else\n\
                     /* 47 */ MACH_TRAP(kern_invalid, 0, 0, NULL),\n\
                     #endif\n",
                ),
                _ => {
                    let _ = writeln!(table, "/* {index} */ MACH_TRAP(kern_invalid, 0, 0, NULL),");
                }
            }
        }
        table.push_str("};\n");
        let rows = mach_rows(&table).unwrap();
        assert!(rows[26].returns_port && !rows[26].reserved);
        assert_eq!(
            (rows[47].name.as_str(), rows[47].argument_count),
            ("mach_msg2_trap", 8)
        );
        assert!(rows[0].reserved);
    }
}
