//! Board device firmware from the IPSW itself.
//!
//! The engine's HPM model runs the Type-C controller image a Mac's own
//! board carries (`USB-C_<personality>.bin`, named by the DeviceTree's
//! `usbc-fw-personality`). The IPSW has no member holding it for Apple
//! silicon (`EFI/USBCUpdater` holds Intel Macs' images); the restore ramdisk
//! carries it as `/usr/standalone/firmware/<name>` for restored to flash. So
//! `stela-dev boot prepare` reads the board the bundle's DeviceTree describes
//! ([`stela_soc_data::board::board`], as the engine reads it), and takes
//! each image it names from the same IPSW's decoded restore ramdisk. The
//! source map records the ramdisk member, its SHA-256 and the path inside
//! it. `--board-firmware` replaces this with the user's own files.
use super::Decoded;
use anyhow::{Context, Result, bail};
use stela_loader::boot_bundle::{Bundle, DEVICE_TREE_FILE, Source};
use {
    stela_formats::apfs, stela_formats::apfs::Container, stela_formats::payload::ReadAt,
    stela_soc_data::board,
};

/// Where the restore ramdisk keeps the board's firmware images.
pub(super) const DIRECTORY: &str = "usr/standalone/firmware";

/// The firmware images the bundle's board runs, or why its DeviceTree is
/// not a board the engine models.
pub(super) fn needed(bundle: &Bundle) -> Result<Vec<String>, String> {
    let (_, tree) = bundle
        .files
        .iter()
        .find(|(name, _)| name == DEVICE_TREE_FILE)
        .ok_or("the bundle has no DeviceTree")?;
    Ok(board::board(tree)?.firmware_files())
}

/// Decoded bytes as a reader source.
struct Slice<'a>(&'a [u8]);

impl ReadAt for Slice<'_> {
    type Error = &'static str;
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        let start = usize::try_from(offset).map_err(|_| "offset out of range")?;
        let bytes = start
            .checked_add(buffer.len())
            .and_then(|end| self.0.get(start..end))
            .ok_or("read past the end")?;
        buffer.copy_from_slice(bytes);
        Ok(())
    }
}

/// Each of `names` from `directory` of the decoded restore ramdisk's APFS
/// volumes, with its source.
pub(super) fn from_ramdisk(
    ramdisk: &Decoded,
    directory: &str,
    names: &[String],
) -> Result<Vec<(String, Decoded)>> {
    let member = &ramdisk.source.member;
    let mut source = Slice(&ramdisk.bytes);
    let offsets = apfs::containers(&mut source)
        .with_context(|| format!("the restore ramdisk {member} holds no APFS container"))?;
    let [offset] = offsets[..] else {
        bail!(
            "the restore ramdisk {member} holds {} APFS containers, not one",
            offsets.len()
        );
    };
    let mut container = Container::open(source, offset)?;
    let volumes = container.volumes()?;
    names
        .iter()
        .map(|name| {
            let path = format!("{directory}/{name}")
                .trim_start_matches('/')
                .to_owned();
            let (volume, inode) = volumes
                .iter()
                .find_map(|volume| {
                    let inode = volume.lookup(&mut container.device, &path, true).ok()?;
                    Some((volume, inode))
                })
                .with_context(|| {
                    format!(
                        "the restore ramdisk {member} has no /{path}, which the DeviceTree's \
                         board names; give it with --board-firmware"
                    )
                })?;
            let bytes = volume.read(&mut container.device, &inode)?;
            let digest = stela_formats::sha256(&bytes);
            let source = Source {
                component: "BoardFirmware".into(),
                member: member.clone(),
                container_sha256: ramdisk.source.container_sha256.clone(),
                payload_type: "raw".into(),
                description: format!(
                    "board device firmware /{path} in the {} (decoded SHA-256 {})",
                    ramdisk.source.component, ramdisk.source.decoded_sha256
                ),
                decoded_bytes: bytes.len() as u64,
                decoded_sha256: digest,
            };
            Ok((
                name.clone(),
                Decoded {
                    bytes,
                    source,
                    declared_digest: None,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime's APFS fixture: one volume whose root holds
    /// `pattern.bin`.
    fn ramdisk() -> Decoded {
        let compressed =
            include_bytes!("../../../stela-formats/tests/fixtures/apfs/preboot.img.gz");
        assert_eq!(compressed[3], 0, "gzip -n: no optional header fields");
        let bytes = miniz_oxide::inflate::decompress_to_vec(&compressed[10..compressed.len() - 8])
            .expect("gzip -n deflate stream");
        let digest = stela_formats::sha256(&bytes);
        Decoded {
            source: Source {
                component: "RestoreRamDisk".into(),
                member: "ramdisk.dmg".into(),
                container_sha256: "c".repeat(64),
                payload_type: "rdsk".into(),
                description: String::new(),
                decoded_bytes: bytes.len() as u64,
                decoded_sha256: digest,
            },
            bytes,
            declared_digest: None,
        }
    }

    #[test]
    fn named_images_come_from_the_ramdisk_with_their_source() {
        let ramdisk = ramdisk();
        let found = from_ramdisk(&ramdisk, "", &["pattern.bin".into()]).unwrap();
        let [(name, image)] = &found[..] else {
            panic!("one image");
        };
        let pattern: Vec<u8> = (0..300_000u32)
            .map(|i| ((i * 7 + i / 251) & 0xff) as u8)
            .collect();
        assert_eq!((name.as_str(), &image.bytes), ("pattern.bin", &pattern));
        assert_eq!(image.source.member, "ramdisk.dmg");
        assert_eq!(image.source.container_sha256, "c".repeat(64));
        assert_eq!(image.source.decoded_sha256, stela_formats::sha256(&pattern));
        assert!(
            image
                .source
                .description
                .starts_with("board device firmware /pattern.bin in the RestoreRamDisk"),
            "{}",
            image.source.description
        );

        let Err(error) = from_ramdisk(&ramdisk, DIRECTORY, &["USB-C_HPM,47.bin".into()]) else {
            panic!("an image the ramdisk lacks is refused");
        };
        assert_eq!(
            error.to_string(),
            "the restore ramdisk ramdisk.dmg has no /usr/standalone/firmware/USB-C_HPM,47.bin, \
             which the DeviceTree's board names; give it with --board-firmware"
        );
    }
}
