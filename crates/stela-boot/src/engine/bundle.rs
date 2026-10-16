//! The kernel boot bundle: `bundle.json` and the files it lists, as prepared
//! on the host by `stela boot prepare` (the iBoot side of the hand-off).
//! `stela_runtime::boot_bundle` checks every region's SHA-256, writes the
//! regions and their zero tails into guest DRAM, and fills the patch slots
//! only the running machine knows; this supplies the machine's side: guest
//! RAM through the engine's host, RDSEED or RDRAND entropy and the timebase.
//! The format is `docs/design/runtime.md#kernel-boot-bundle`.
use crate::{handoff::File, layout, output};
use alloc::{format, string::String, vec::Vec};
use core::arch::{
    asm,
    x86_64::{__cpuid, __cpuid_count},
};
use stela_runtime::{
    boot_bundle::{MANIFEST_FILE, Machine, Manifest},
    machine::Host,
};

/// The counter frequency the machine presents in CNTFRQ_EL0.
const TIMEBASE_HZ: u64 = 24_000_000;
/// Attempts per 64-bit word before an entropy instruction counts as failed.
const ENTROPY_RETRIES: usize = 128;
const CPUID_RDRAND: u32 = 1 << 30;
const CPUID_RDSEED: u32 = 1 << 18;

pub struct Entry {
    pub pc: u64,
    pub x0: u64,
    pub dram_base: u64,
    pub regions: usize,
    pub patches: usize,
    pub kept: Vec<String>,
}

fn contents(file: &File) -> &'static [u8] {
    // SAFETY: the loader left every bundle file allocated; the physmap maps it.
    unsafe {
        core::slice::from_raw_parts(
            layout::physical(file.contents.physical) as *const u8,
            file.contents.bytes as usize,
        )
    }
}

/// One 64-bit word from RDSEED or RDRAND, retried while the source is busy.
fn random_word(seed: bool) -> Option<u64> {
    for _ in 0..ENTROPY_RETRIES {
        let (value, ok): (u64, u8);
        // SAFETY: the caller checked CPUID for the instruction; it writes
        // only its destination and the flags.
        unsafe {
            if seed {
                asm!("rdseed {}", "setc {}", out(reg) value, out(reg_byte) ok, options(nomem, nostack));
            } else {
                asm!("rdrand {}", "setc {}", out(reg) value, out(reg_byte) ok, options(nomem, nostack));
            }
        }
        if ok != 0 {
            return Some(value);
        }
        core::hint::spin_loop();
    }
    None
}

/// Fill `buffer` from RDSEED, or from RDRAND on a CPU without RDSEED. A CPU
/// with neither is refused: the kernel's seeds must not be predictable.
fn entropy(buffer: &mut [u8]) -> Result<(), &'static str> {
    let seed = __cpuid_count(7, 0).ebx & CPUID_RDSEED != 0;
    let rand = __cpuid(1).ecx & CPUID_RDRAND != 0;
    if !seed && !rand {
        return Err("this CPU has neither RDSEED nor RDRAND");
    }
    for chunk in buffer.chunks_mut(8) {
        let word = random_word(seed).ok_or(if seed {
            "RDSEED returned no entropy"
        } else {
            "RDRAND returned no entropy"
        })?;
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    Ok(())
}

/// Load the bundle into guest DRAM `[dram_base, dram_base + ram_bytes)`.
pub fn load(
    host: &mut impl Host,
    files: &[File],
    dram_base: u64,
    ram_bytes: u64,
) -> Result<Entry, String> {
    let named = |name: &str| files.iter().find(|file| file.name() == name).map(contents);
    let json = named(MANIFEST_FILE).ok_or("bundle.json was not read")?;
    let manifest = Manifest::parse(json).map_err(|e| format!("{e}"))?;
    let verified = manifest.verify(&named).map_err(|e| format!("{e}"))?;
    let machine = Machine {
        dram_base,
        ram_bytes,
        timebase_hz: TIMEBASE_HZ,
        // No guest framebuffer yet: the prepared zeros stay.
        framebuffer: None,
        boot_args: None,
    };
    let image = verified
        .load(&machine, &mut entropy, &mut |pa, data| {
            host.write_ram(pa, data)
        })
        .map_err(|e| format!("{e}"))?;
    for region in &image.regions {
        output::arguments(format_args!(
            "REGION {} pa={:#x} bytes={:#x} memory={:#x}\n",
            region.name, region.guest_pa, region.bytes, region.memory_bytes
        ));
    }
    Ok(Entry {
        pc: image.entry_pa,
        x0: image.x0,
        dram_base,
        regions: image.regions.len(),
        patches: image.patches.len(),
        kept: image.kept,
    })
}
