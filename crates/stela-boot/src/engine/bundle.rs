//! The J473AP kernel boot bundle: `bundle.json` and the files it lists, as
//! prepared on the host by `stela boot prepare` (the iBoot side of the
//! hand-off). This places each region at its guest physical address after
//! checking its SHA-256, fills the patch slots only the running machine knows
//! (DRAM size, entropy, timebase) and returns the entry state.
use crate::{handoff::File, layout, output};
use alloc::{format, string::String, vec, vec::Vec};
use core::arch::asm;
use serde_json::Value;
use stela_runtime::machine::Host;

/// The counter frequency the machine presents in CNTFRQ_EL0.
const TIMEBASE_HZ: u64 = 24_000_000;

pub struct Entry {
    pub pc: u64,
    pub x0: u64,
    pub dram_base: u64,
    pub regions: usize,
    pub patches: usize,
    pub kept: Vec<String>,
}

fn file<'a>(files: &'a [File], name: &str) -> Result<&'a [u8], String> {
    let file = files
        .iter()
        .find(|file| file.name() == name)
        .ok_or_else(|| format!("bundle file {name} was not read"))?;
    // SAFETY: the loader left every bundle file allocated; the physmap maps it.
    Ok(unsafe {
        core::slice::from_raw_parts(
            layout::physical(file.contents.physical) as *const u8,
            file.contents.bytes as usize,
        )
    })
}

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("bundle field {key} is missing or not a number"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("bundle field {key} is missing or not text"))
}

fn random_word() -> Result<u64, String> {
    for _ in 0..32 {
        let (value, ok): (u64, u8);
        // SAFETY: RDRAND is present (checked by the caller); it writes only
        // its destination and the carry flag.
        unsafe {
            asm!("rdrand {}", "setc {}", out(reg) value, out(reg_byte) ok, options(nomem, nostack))
        };
        if ok != 0 {
            return Ok(value);
        }
    }
    Err("RDRAND returned no entropy".into())
}

fn entropy(bytes: usize) -> Result<Vec<u8>, String> {
    if core::arch::x86_64::__cpuid(1).ecx & (1 << 30) == 0 {
        return Err("the boot bundle needs entropy and this CPU has no RDRAND".into());
    }
    let mut data = Vec::with_capacity(bytes);
    while data.len() < bytes {
        data.extend(random_word()?.to_le_bytes());
    }
    data.truncate(bytes);
    Ok(data)
}

/// The value a patch slot takes on this machine; `None` keeps the prepared bytes.
fn patch_value(
    patch: &Value,
    dram_base: u64,
    phys_base: u64,
    ram_bytes: u64,
) -> Result<Option<Vec<u8>>, String> {
    let bytes = number(patch, "bytes")? as usize;
    let field = text(patch, "field")?;
    let u64_le = |value: u64| Ok(Some(value.to_le_bytes().to_vec()));
    match text(patch, "source")? {
        "dram-size" => match field {
            "/chosen dram-size" | "boot_args.memSizeActual" => u64_le(ram_bytes),
            "boot_args.memSize" => u64_le(dram_base + ram_bytes - phys_base),
            _ => Err(format!("unknown dram-size field {field}")),
        },
        "entropy" => entropy(bytes).map(Some),
        "timebase" if bytes == 8 => u64_le(TIMEBASE_HZ),
        // No guest framebuffer yet: -v boots keep the prepared zeros.
        "framebuffer" => Ok(None),
        "boot-args" => Ok(None),
        other => Err(format!("unknown patch source {other} for {field}")),
    }
}

/// Load the bundle into guest DRAM `[dram_base, dram_base + ram_bytes)`.
pub fn load(
    host: &mut impl Host,
    files: &[File],
    dram_base: u64,
    ram_bytes: u64,
) -> Result<Entry, String> {
    let manifest: Value = serde_json::from_slice(file(files, "bundle.json")?)
        .map_err(|_| String::from("bundle.json is not JSON"))?;
    if number(&manifest, "schema_version")? != 1 {
        return Err("unsupported boot bundle schema".into());
    }
    let options = manifest.get("options").ok_or("bundle has no options")?;
    if number(options, "dram_base")? != dram_base {
        return Err(format!(
            "bundle DRAM base {:#x} differs from the machine's {dram_base:#x}",
            number(options, "dram_base")?
        ));
    }
    let phys_base = number(options, "phys_base")?;
    let regions = manifest
        .get("regions")
        .and_then(Value::as_array)
        .ok_or("bundle has no regions")?;
    for region in regions {
        let name = text(region, "name")?;
        let contents = file(files, text(region, "file")?)?;
        let offset = number(region, "file_offset")? as usize;
        let bytes = number(region, "bytes")? as usize;
        let memory = number(region, "memory_bytes")?;
        let guest = number(region, "guest_pa")?;
        let slice = contents
            .get(offset..offset + bytes)
            .ok_or_else(|| format!("region {name} lies outside its file"))?;
        let digest = stela_runtime::sha256(slice);
        if digest != text(region, "sha256")? {
            return Err(format!(
                "region {name} has SHA-256 {digest}, not the bundle's"
            ));
        }
        if guest < dram_base || guest + memory > dram_base + ram_bytes || memory < bytes as u64 {
            return Err(format!("region {name} does not fit guest DRAM"));
        }
        if !host.write_ram(guest, slice)
            || !host.write_ram(guest + bytes as u64, &vec![0; memory as usize - bytes])
        {
            return Err(format!("region {name} could not be written"));
        }
        output::arguments(format_args!(
            "REGION {name} pa={guest:#x} bytes={bytes:#x} memory={memory:#x} sha256={digest}\n"
        ));
    }
    let patches = manifest
        .get("patches")
        .and_then(Value::as_array)
        .ok_or("bundle has no patches")?;
    let mut kept = Vec::new();
    for patch in patches {
        let field = text(patch, "field")?;
        let Some(value) = patch_value(patch, dram_base, phys_base, ram_bytes)? else {
            kept.push(String::from(field));
            continue;
        };
        if value.len() != number(patch, "bytes")? as usize {
            return Err(format!("patch {field} has the wrong size"));
        }
        let region_name = text(patch, "region")?;
        let region = regions
            .iter()
            .find(|region| region.get("name").and_then(Value::as_str) == Some(region_name))
            .ok_or_else(|| format!("patch {field} names a missing region"))?;
        let offset = number(patch, "file_offset")?;
        let start = number(region, "file_offset")?;
        if text(region, "file")? != text(patch, "file")?
            || offset < start
            || offset + value.len() as u64 > start + number(region, "bytes")?
        {
            return Err(format!("patch {field} lies outside region {region_name}"));
        }
        let guest = number(region, "guest_pa")? + (offset - start);
        if !host.write_ram(guest, &value) {
            return Err(format!("patch {field} could not be written"));
        }
    }
    let entry = manifest.get("entry").ok_or("bundle has no entry")?;
    Ok(Entry {
        pc: number(entry, "physical_address")?,
        x0: number(&manifest, "entry_x0")?,
        dram_base,
        regions: regions.len(),
        patches: patches.len() - kept.len(),
        kept,
    })
}
