//! Patches applied once regions are placed: CPU frequencies, addresses, NVRAM
//! and boot arguments.

use super::*;

pub(super) fn cpu_frequency_patches(tree: &DeviceTree, region: &Region) -> Result<Vec<Patch>> {
    let bytes = tree.serialize();
    let mut patches = vec![];
    for cpu in cpu_nodes(tree)? {
        for property in CPU_FREQUENCY_PROPERTIES {
            let at = tree.locate(&cpu, property)?;
            patches.push(Patch {
                source: PatchSource::Timebase,
                required: false,
                region: region.name.clone(),
                file: region.file.clone(),
                file_offset: at.value_offset as u64,
                bytes: at.value_bytes as u64,
                encoding: Encoding::U64Le,
                field: format!("{cpu} {property}"),
                prepared_hex: hex::encode(
                    &bytes[at.value_offset..at.value_offset + at.value_bytes],
                ),
                rule: "CNTFRQ_EL0 the machine presents, in Hz".into(),
            });
        }
    }
    Ok(patches)
}

pub(super) fn device_tree_patches(tree: &DeviceTree, region: &Region) -> Result<Vec<Patch>> {
    let mut patches = vec![];
    let slots: &[(&str, &str, PatchSource, bool, Encoding, &str)] = &[
        (
            "/chosen",
            "dram-size",
            PatchSource::DramSize,
            false,
            Encoding::U64Le,
            "installed guest DRAM bytes",
        ),
        (
            "/chosen",
            "random-seed",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/chosen",
            "cl4-entropy",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/chosen/hibernation",
            "key-sptm-ctrr",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/chosen/hibernation",
            "key-xnu-ctrr",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/vram",
            "reg",
            PatchSource::Framebuffer,
            false,
            Encoding::Bytes,
            "u64 framebuffer base, u64 framebuffer bytes",
        ),
    ];
    let bytes = tree.serialize();
    for &(path, property, source, required, encoding, rule) in slots {
        let Ok(at) = tree.locate(path, property) else {
            bail!("DeviceTree has no patch slot {path} {property}");
        };
        patches.push(Patch {
            source,
            required,
            region: region.name.clone(),
            file: region.file.clone(),
            file_offset: at.value_offset as u64,
            bytes: at.value_bytes as u64,
            encoding,
            field: format!("{path} {property}"),
            prepared_hex: hex::encode(&bytes[at.value_offset..at.value_offset + at.value_bytes]),
            rule: rule.into(),
        });
    }
    // iBoot fills the display configuration in place, only where the
    // template has it (26A434 J473 iBoot 0x24148..0x2425c).
    for (property, rule) in [
        (
            "display-rotation",
            "u32 degrees, from boot_args.Video.v_depth bits 8..15",
        ),
        (
            "display-scale",
            "u32 scale, boot_args.Video.v_depth bits 16..23 plus one",
        ),
        (
            "display-boot-rotation",
            "u32 degrees, from boot_args.Video.v_depth bits 24..31",
        ),
    ] {
        let Ok(at) = tree.locate("/chosen", property) else {
            continue;
        };
        patches.push(Patch {
            source: PatchSource::Framebuffer,
            required: false,
            region: region.name.clone(),
            file: region.file.clone(),
            file_offset: at.value_offset as u64,
            bytes: at.value_bytes as u64,
            encoding: Encoding::Bytes,
            field: format!("/chosen {property}"),
            prepared_hex: hex::encode(&bytes[at.value_offset..at.value_offset + at.value_bytes]),
            rule: rule.into(),
        });
    }
    // Native IOMobileFramebufferAP::allocate_carveout reads these capacities
    // (original mac13j VA 0xfffffe000ad95600..ad95638).
    // The same runtime Framebuffer supplies Video and these scalar slots;
    // never keep the physical board's 4096x2160 capacity for another GOP.
    for profile in stela_soc_data::board::EXTERNAL_OUTPUTS
        .iter()
        .filter(|p| p.admitted)
    {
        let path = format!("/arm-io/{}", profile.pipe);
        let Some(pipe) = tree.node(&path).filter(|node| {
            node.property("compatible").is_some_and(|p| {
                p.value
                    .split(|&b| b == 0)
                    .any(|name| name == profile.compatible.as_bytes())
            })
        }) else {
            continue;
        };
        let geometry = ["framebuffer-width", "framebuffer-height"];
        if geometry.iter().all(|name| pipe.property(name).is_none()) {
            continue;
        }
        for property in geometry {
            let at = tree.locate(&path, property)?;
            ensure!(
                at.value_bytes == 4,
                "{path} {property} is not one native u32"
            );
            patches.push(Patch {
                source: PatchSource::Framebuffer,
                required: true,
                region: region.name.clone(),
                file: region.file.clone(),
                file_offset: at.value_offset as u64,
                bytes: 4,
                encoding: Encoding::Bytes,
                field: format!("{path} {property}"),
                prepared_hex: hex::encode(&bytes[at.value_offset..at.value_offset + 4]),
                rule: "the actual single native GOP scanout dimensions, also used by boot_args.Video and the DCP".into(),
            });
        }
    }
    Ok(patches)
}

/// iBoot's NOR hand-off: the machine replaces the prepared empty bank with
/// its persistent NOR's current bank; without one the prepared bank stands
/// and variables last one boot.
pub(super) fn nvram_patches(tree: &DeviceTree, region: &Region) -> Result<Vec<Patch>> {
    let bytes = tree.serialize();
    ["nvram-proxy-data", "nvram-current-bank"]
        .into_iter()
        .map(|property| {
            let at = tree.locate("/chosen", property)?;
            Ok(Patch {
                source: PatchSource::Nvram,
                required: false,
                region: region.name.clone(),
                file: region.file.clone(),
                file_offset: at.value_offset as u64,
                bytes: at.value_bytes as u64,
                encoding: Encoding::Bytes,
                field: format!("/chosen {property}"),
                prepared_hex: hex::encode(
                    &bytes[at.value_offset..at.value_offset + at.value_bytes],
                ),
                rule: "the persistent NOR's newest valid NVRAM bank and its index".into(),
            })
        })
        .collect()
}

pub(super) fn boot_args_patches(region: &Region, bytes: &[u8]) -> Vec<Patch> {
    use boot_args::offset;
    let fields: &[(&str, usize, usize, PatchSource, Encoding, &str)] = &[
        (
            "memSize",
            offset::MEM_SIZE,
            8,
            PatchSource::DramSize,
            Encoding::U64Le,
            "dram-base + guest DRAM bytes - physBase",
        ),
        (
            "memSizeActual",
            offset::MEM_SIZE_ACTUAL,
            8,
            PatchSource::DramSize,
            Encoding::U64Le,
            "guest DRAM bytes",
        ),
        (
            "Video.v_baseAddr",
            offset::VIDEO_BASE,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "framebuffer guest physical address",
        ),
        (
            "Video.v_display",
            offset::VIDEO_DISPLAY,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "1 for a graphical boot, 0 with -v (m1n1 set_bootargs)",
        ),
        (
            "Video.v_rowBytes",
            offset::VIDEO_ROW_BYTES,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "bytes per scanline",
        ),
        (
            "Video.v_width",
            offset::VIDEO_WIDTH,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "pixels",
        ),
        (
            "Video.v_height",
            offset::VIDEO_HEIGHT,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "pixels",
        ),
        (
            "Video.v_depth",
            offset::VIDEO_DEPTH,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "bits per pixel in bits 0..8",
        ),
        (
            "CommandLine",
            offset::COMMAND_LINE,
            boot_args::BOOT_LINE_LENGTH,
            PatchSource::BootArgs,
            Encoding::CString,
            "kernel boot-args",
        ),
    ];
    fields
        .iter()
        .map(|&(field, at, length, source, encoding, rule)| Patch {
            source,
            required: false,
            region: region.name.clone(),
            file: region.file.clone(),
            file_offset: at as u64,
            bytes: length as u64,
            encoding,
            field: format!("boot_args.{field}"),
            prepared_hex: hex::encode(&bytes[at..at + length]),
            rule: rule.into(),
        })
        .collect()
}
