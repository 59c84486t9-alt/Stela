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
//! On a blank disk Stela has no Recovery volume, so the bundle carries one in
//! memory. It is an unsealed APFS volume that holds only the decrypted
//! BaseSystem image, unchanged, at the same path. DiskImages attaches it from
//! `/chosen boot-ramdmg-size` and `boot-ramdmg-extents`, and `/chosen
//! boot-uuid` names its volume as iBoot names a Recovery volume
//! (`stela_loader::root_selection::Root::RamImage`), with no `rd=`: with
//! `rd=md0` APFS would take `md0` again for the image root
//! (`stela_loader::boot_policy::refuse_ramdisk_image_root`).
//!
//! The volume is an APFS container with no partition map, so block zero is
//! the container superblock. DiskImages reads it as a raw read-write image
//! (`KDIReadWriteDiskImage`) whose whole disk an APFS container scheme
//! claims, a case its `findAppropriateIOMediaObject` names ("whole=TRUE,
//! leaf=FALSE AppleAPFSContainerScheme child"). Stela writes it itself
//! (`format`), so every host makes the same volume, and checks it with its
//! own APFS reader before use.
use anyhow::{Context, Result, bail, ensure};
use std::path::Path;
use stela_runtime::{
    apfs::{self, Container, btree::Seal},
    payload::ReadAt,
};

mod format;

/// The BaseSystem image's path on the volume, as iBoot names it below a
/// Recovery volume's boot objects.
pub const IMAGE_PATH: &str = "usr/standalone/firmware/arm64eBaseSystem.dmg";
/// The image-boot argument naming [`IMAGE_PATH`] from the volume's root.
pub const IMAGE_BOOT_ARG: &str = "rp0=file:///usr/standalone/firmware/arm64eBaseSystem.dmg";
const VOLUME_NAME: &str = "Stela recoveryOS";

/// The volume for `image`, the decrypted BaseSystem UDIF image, at most
/// `limit` bytes. Returns the volume image and its volume's UUID, which
/// `/chosen boot-uuid` names.
pub fn build(image: &Path, limit: u64) -> Result<(Vec<u8>, String)> {
    let mut file =
        std::fs::File::open(image).with_context(|| format!("cannot read {}", image.display()))?;
    let image_bytes = file.metadata()?.len();
    let identity = format::Identity {
        volume_uuid: random_uuid()?,
        container_uuid: random_uuid()?,
        time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
            .try_into()?,
    };
    let volume = format::container(
        VOLUME_NAME,
        IMAGE_PATH,
        &mut file,
        image_bytes,
        &identity,
        limit,
    )
    .context("cannot write the recoveryOS volume")?;
    let uuid = check(&volume, image_bytes)?;
    Ok((volume, uuid))
}

/// A random (version 4) UUID.
fn random_uuid() -> Result<[u8; 16]> {
    let mut uuid = [0u8; 16];
    getrandom::getrandom(&mut uuid).map_err(|error| anyhow::anyhow!("no random bytes: {error}"))?;
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(uuid)
}

/// The volume must be one unsealed APFS container at offset zero whose one
/// volume holds the image at [`IMAGE_PATH`] with its full length. Returns
/// the volume's UUID in the upper-case form of its `IOMedia` `UUID`, which
/// AppleFileSystemDriver compares with `boot-uuid`.
fn check(volume_image: &[u8], image_bytes: u64) -> Result<String> {
    let mut source = Memory(volume_image);
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
    // An unsealed first root mounts its live file system. A sealed one would
    // need a root snapshot, or BaseSystem's path, which needs an earlier root.
    ensure!(
        volume.seal(&mut container.device)?.is_none(),
        "the recoveryOS volume is sealed; recoveryOS first roots from an unsealed volume"
    );
    let inode = volume
        .lookup(&mut container.device, IMAGE_PATH, false)
        .with_context(|| format!("the recoveryOS volume has no {IMAGE_PATH}"))?;
    ensure!(
        inode.logical_size() == image_bytes,
        "{IMAGE_PATH} holds {} bytes, not the image's {image_bytes}",
        inode.logical_size()
    );
    Ok(apfs::uuid_text(&volume.uuid))
}

/// An image's bytes as a reader source.
struct Memory<B>(B);

impl<B: AsRef<[u8]>> ReadAt for Memory<B> {
    type Error = &'static str;
    fn len(&self) -> u64 {
        self.0.as_ref().len() as u64
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        let start = usize::try_from(offset).map_err(|_| "offset out of range")?;
        let bytes = self
            .0
            .as_ref()
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

    #[test]
    fn the_image_boot_argument_names_the_image_path_from_the_root() {
        assert_eq!(IMAGE_BOOT_ARG, format!("rp0=file:///{IMAGE_PATH}"));
        assert!(stela_loader::boot_policy::require_image_boot(IMAGE_BOOT_ARG).is_ok());
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        // RFC 1952 as `gzip -n` writes it: a 10-byte header, a raw deflate
        // stream, then CRC-32 and size.
        assert_eq!(&data[..4], &[0x1f, 0x8b, 8, 0]);
        miniz_oxide::inflate::decompress_to_vec(&data[10..data.len() - 8]).unwrap()
    }

    #[test]
    fn the_volume_must_hold_the_whole_image_unsealed_at_its_path() {
        // `make-recovery-volume.sh`'s volume from Apple's `hdiutil`, holding
        // 4096 bytes as the image.
        let volume = gunzip(include_bytes!(
            "../../tests/fixtures/recovery-volume/recovery-volume.img.gz"
        ));
        let uuid = check(&volume, 4096).unwrap();
        // The form `/chosen boot-uuid` takes: 36 characters, upper case.
        assert!(stela_loader::boot_selection::parse_uuid(uuid.as_bytes()).is_some());
        assert_eq!((uuid.len(), uuid.to_ascii_uppercase()), (36, uuid.clone()));
        assert!(check(&volume, 4095).is_err());
        assert!(check(&[0u8; 8192], 0).is_err());
    }

    #[test]
    fn the_written_volume_holds_the_image_as_the_reader_finds_it() {
        let work = tempfile::tempdir().unwrap();
        let image = work.path().join("BaseSystem.dmg");
        let content: Vec<u8> = (0..3 * 4096 + 100).map(|i| (i * 7 % 251) as u8).collect();
        std::fs::write(&image, &content).unwrap();
        let (volume, uuid) = build(&image, 64 << 20).unwrap();
        assert_eq!(volume.len() % 4096, 0);
        assert!(stela_loader::boot_selection::parse_uuid(uuid.as_bytes()).is_some());

        let mut container = Container::open(Memory(&volume[..]), 0).unwrap();
        let volumes = container.volumes().unwrap();
        assert_eq!(volumes[0].name, VOLUME_NAME);
        let inode = volumes[0]
            .lookup(&mut container.device, IMAGE_PATH, false)
            .unwrap();
        assert_eq!(
            volumes[0].read(&mut container.device, &inode).unwrap(),
            content
        );
        assert!(build(&image, 1 << 20).is_err());
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
