//! The volume recoveryOS first roots from, which holds BaseSystem as a disk
//! image.
//!
//! A Mac's iBoot boots recoveryOS from the Recovery volume. It forwards
//! BaseSystem's root hash (`base_system_root_hash.img4`) as `/chosen/
//! secure-boot-hashes base-system-volume-auth-blob` and passes
//! `rp0=file://` with `/usr/standalone/firmware/arm64eBaseSystem.dmg` (J473
//! iBoot string table). XNU's imageboot then attaches that image through
//! DiskImages and roots from its BaseSystem volume (`bsd/kern/imageboot.c`).
//! APFS authenticates that volume with the forwarded hash, because the
//! attached container is virtual and an APFS root is already mounted
//! (`stela_loader::boot_policy::require_image_boot`).
//!
//! On a blank disk Stela has no Recovery volume, so the bundle's ramdisk takes
//! its place. It is an unsealed APFS volume that holds only the decrypted
//! BaseSystem image, unchanged, at the same path. The kernel roots from it as
//! `md0`, the same way it roots a restore ramdisk. The volume is made with the
//! host's `hdiutil` and checked with Stela's own APFS reader before use.
use crate::apfs::open_image;
use anyhow::{Context, Result, bail, ensure};
use std::{ffi::OsString, path::Path, process::Command};
use stela_runtime::{
    apfs::{self, Container, btree::Seal},
    payload::ReadAt,
};

/// The BaseSystem image's path on the volume, as iBoot names it below a
/// Recovery volume's boot objects.
pub const IMAGE_PATH: &str = "usr/standalone/firmware/arm64eBaseSystem.dmg";
/// The image-boot argument naming [`IMAGE_PATH`] from the volume's root.
pub const IMAGE_BOOT_ARG: &str = "rp0=file:///usr/standalone/firmware/arm64eBaseSystem.dmg";
const HDIUTIL: &str = "/usr/bin/hdiutil";
const VOLUME_NAME: &str = "Stela recoveryOS";
const STAGE_DIRECTORY: &str = "recovery-volume";
/// `hdiutil` names a raw image `.dmg`, adding the suffix to any other name.
const VOLUME_FILE: &str = "recovery-volume.dmg";

/// `hdiutil create` for an unsealed APFS container of `stage`'s files, with
/// no partition map, as a raw image: block zero is the container superblock,
/// as a memory device needs.
fn create_arguments(stage: &Path, output: &Path) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = [
        "create", "-quiet", "-fs", "APFS", "-layout", "NONE", "-format", "UDRW", "-volname",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    arguments.push(VOLUME_NAME.into());
    arguments.push("-srcfolder".into());
    arguments.push(stage.into());
    arguments.push(output.into());
    arguments
}

/// The volume for `image`, the decrypted BaseSystem UDIF image, built in
/// `work` (on the same file system as `image`, which is linked, not copied,
/// into the staging tree). At most `limit` bytes.
pub fn build(image: &Path, work: &Path, limit: u64) -> Result<Vec<u8>> {
    let image_bytes = std::fs::metadata(image)
        .with_context(|| format!("cannot read {}", image.display()))?
        .len();
    let stage = work.join(STAGE_DIRECTORY);
    let target = stage.join(IMAGE_PATH);
    std::fs::create_dir_all(target.parent().expect("the image path has directories"))?;
    std::fs::hard_link(image, &target)
        .with_context(|| format!("cannot link {} into the volume", image.display()))?;
    let output = work.join(VOLUME_FILE);
    let status = Command::new(HDIUTIL)
        .args(create_arguments(&stage, &output))
        .status()
        .with_context(|| format!("cannot run {HDIUTIL}"))?;
    ensure!(status.success(), "hdiutil create failed: {status}");
    let bytes = std::fs::metadata(&output)?.len();
    ensure!(
        bytes <= limit,
        "the recoveryOS volume is {bytes} bytes, more than {limit}"
    );
    check(&output, image_bytes)?;
    Ok(std::fs::read(&output)?)
}

/// The volume must be one unsealed APFS container at offset zero whose one
/// volume holds the image at [`IMAGE_PATH`] with its full length.
fn check(volume_image: &Path, image_bytes: u64) -> Result<()> {
    let mut source = open_image(volume_image)?;
    let offsets = apfs::containers(&mut source)?;
    ensure!(
        offsets == [0],
        "the recoveryOS volume image must start with its container; found containers at {offsets:?}"
    );
    let mut container = Container::open(source, 0)?;
    let volumes = container.volumes()?;
    let [volume] = &volumes[..] else {
        bail!(
            "the recoveryOS container holds {} volumes, not one",
            volumes.len()
        );
    };
    ensure!(
        volume.seal(&mut container.device)?.is_none(),
        "the recoveryOS volume is sealed; APFS roots a sealed volume from a memory device only \
         by snapshot"
    );
    let inode = volume
        .lookup(&mut container.device, IMAGE_PATH, false)
        .with_context(|| format!("the recoveryOS volume has no {IMAGE_PATH}"))?;
    ensure!(
        inode.logical_size() == image_bytes,
        "{IMAGE_PATH} holds {} bytes, not the image's {image_bytes}",
        inode.logical_size()
    );
    Ok(())
}

/// An image's bytes as a reader source.
struct Memory(Vec<u8>);

impl ReadAt for Memory {
    type Error = &'static str;
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        let start = usize::try_from(offset).map_err(|_| "offset out of range")?;
        let bytes = self
            .0
            .get(start..start + buffer.len())
            .ok_or("read past the end")?;
        buffer.copy_from_slice(bytes);
        Ok(())
    }
}

/// The seal of the file system BaseSystem roots from, read from its APFS
/// partition: the hash its forwarded root-hash record must name.
pub fn base_system_seal(partition: Vec<u8>) -> Result<Seal> {
    let mut container = Container::open(Memory(partition), 0)?;
    let volumes = container.volumes()?;
    let [volume] = &volumes[..] else {
        bail!(
            "the BaseSystem container holds {} volumes, not one",
            volumes.len()
        );
    };
    volume
        .root_seal(&mut container.device)?
        .context("the BaseSystem volume is not sealed")
}

/// The forwarded root hash must be the seal of the image the kernel roots
/// from: `im4p` (`BaseSystemVolume`, type `csys`) holds a root-hash record,
/// as an installed system's `isys` does.
pub fn check_root_hash(seal: &Seal, im4p: &[u8]) -> Result<()> {
    let object = stela_loader::im4p::parse(im4p)?;
    ensure!(
        object.payload_type == "csys" && object.compression_algorithm.is_none(),
        "the BaseSystem root hash is not an uncompressed csys object"
    );
    let (hash, bytes) = stela_loader::installed::root_hash_record(object.payload)?;
    ensure!(
        hash == seal.hash && bytes == seal.root.as_slice(),
        "the BaseSystem root hash {} is not the seal {} of the BaseSystem image",
        hex::encode(bytes),
        hex::encode(&seal.root)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_image_boot_argument_names_the_image_path_from_the_root() {
        assert_eq!(IMAGE_BOOT_ARG, format!("rp0=file:///{IMAGE_PATH}"));
        assert!(stela_loader::boot_policy::require_image_boot(IMAGE_BOOT_ARG).is_ok());
    }

    #[test]
    fn hdiutil_makes_a_raw_unpartitioned_apfs_image_of_the_stage() {
        let arguments = create_arguments(Path::new("/w/stage"), Path::new("/w/out.img"));
        let text: Vec<_> = arguments.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            text,
            [
                "create",
                "-quiet",
                "-fs",
                "APFS",
                "-layout",
                "NONE",
                "-format",
                "UDRW",
                "-volname",
                VOLUME_NAME,
                "-srcfolder",
                "/w/stage",
                "/w/out.img"
            ]
        );
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        // RFC 1952 as `gzip -n` writes it: a 10-byte header, a raw deflate
        // stream, then CRC-32 and size.
        assert_eq!(&data[..4], &[0x1f, 0x8b, 8, 0]);
        miniz_oxide::inflate::decompress_to_vec(&data[10..data.len() - 8]).unwrap()
    }

    /// `make-recovery-volume.sh`'s volume, holding 4096 bytes as the image.
    fn fixture_volume(work: &Path) -> PathBuf {
        let path = work.join("volume.dmg");
        let compressed =
            include_bytes!("../../tests/fixtures/recovery-volume/recovery-volume.img.gz");
        std::fs::write(&path, gunzip(compressed)).unwrap();
        path
    }

    #[test]
    fn the_volume_must_hold_the_whole_image_unsealed_at_its_path() {
        let work = tempfile::tempdir().unwrap();
        let volume = fixture_volume(work.path());
        check(&volume, 4096).unwrap();
        assert!(check(&volume, 4095).is_err());
        let blank = work.path().join("blank.img");
        std::fs::write(&blank, vec![0u8; 8192]).unwrap();
        assert!(check(&blank, 0).is_err());
    }

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match body.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend([0x81, n as u8]),
            n => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend(body);
        out
    }

    fn root_hash_object(payload_type: &str, record: &[u8]) -> Vec<u8> {
        let body = [
            der(0x16, b"IM4P"),
            der(0x16, payload_type.as_bytes()),
            der(0x16, b"root hash"),
            der(0x04, record),
        ]
        .concat();
        der(0x30, &body)
    }

    #[test]
    fn the_root_hash_must_name_the_seal_of_the_image() {
        // The runtime's sealed fixture and the record Apple's sealer wrote.
        let sealed = gunzip(include_bytes!(
            "../../../stela-runtime/tests/fixtures/apfs/sealed.img.gz"
        ));
        let record = include_bytes!("../../../stela-runtime/tests/fixtures/apfs/sealed.root_hash");
        let seal = base_system_seal(sealed).unwrap();
        check_root_hash(&seal, &root_hash_object("csys", record)).unwrap();
        let mut other = record.to_vec();
        other[16] ^= 1;
        assert!(check_root_hash(&seal, &root_hash_object("csys", &other)).is_err());
        assert!(check_root_hash(&seal, &root_hash_object("isys", record)).is_err());
        assert!(base_system_seal(vec![0u8; 8192]).is_err());
    }
}
