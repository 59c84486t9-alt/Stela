//! Download straight into FAT32 pieces; no complete IPSW is cached on the PC.
use super::*;
use std::io::{self, BufReader};

pub(in super::super) struct Download {
    pub image: restore::Image,
    pub bytes: u64,
    etag: String,
}

impl Download {
    pub(in super::super) fn prepare(
        image: restore::Image,
        model: &str,
        boot: &Path,
    ) -> Result<Self> {
        ensure!(
            image.sha1.is_some(),
            "the catalog provides no checksum for this full installer"
        );
        let source = restore::open_image(&image)?;
        let download = Self {
            bytes: source.size(),
            etag: source.etag().into(),
            image,
        };
        restore::payload::trim(source, model, boot)?;
        ensure!(
            restore::payload::identity(boot, model)?.1 == download.image.build,
            "the catalog download contains a different macOS build"
        );
        Ok(download)
    }

    pub(in super::super) fn write(
        &self,
        volume: &Path,
        model: &str,
        piece_bytes: u64,
    ) -> Result<Written> {
        let source = restore::open_image(&self.image)?;
        ensure!(
            source.size() == self.bytes && source.etag() == self.etag,
            "the download changed after boot-file preparation; run setup again"
        );
        write_from(source, volume, model, &self.image, self.bytes, piece_bytes)
    }
}

fn write_from(
    mut source: impl Read,
    volume: &Path,
    model: &str,
    image: &restore::Image,
    total: u64,
    piece_bytes: u64,
) -> Result<Written> {
    ensure!(
        piece_bytes > 0
            && piece_bytes <= stela_formats::payload::MAX_SLICE_BYTES
            && piece_bytes.is_multiple_of(HASH_BLOCK_BYTES),
        "invalid FAT32 piece size"
    );
    let sizes = piece_sizes(total, piece_bytes);
    ensure!(
        !sizes.is_empty() && sizes.len() <= MAX_PIECES,
        "invalid download size or piece size"
    );
    let directory = directory(volume, &image.build);
    fs::create_dir_all(&directory)?;
    let manifest_path = directory.join(MANIFEST_FILE);
    if manifest_path.exists() {
        fs::remove_file(&manifest_path)?;
    }
    let mut pieces = Vec::new();
    let mut piece_blocks = Vec::new();
    let mut whole = Whole::default();
    let progress = crate::progress::Phase::bytes("Downloading macOS onto USB", total);
    for (index, &size) in sizes.iter().enumerate() {
        let mut file = fs::File::create(directory.join(format!("{}.partial", piece_name(index))))?;
        let mut hashes = Hashes::default();
        stream(&mut source, size, |bytes| {
            file.write_all(bytes)?;
            hashes.update(bytes);
            whole.sha256.update(bytes);
            whole.sha1.update(bytes);
            progress.advance(bytes.len() as u64);
            Ok(())
        })?;
        file.sync_all()?;
        let (sha256, blocks) = hashes.finish();
        pieces.push(Piece {
            bytes: size,
            sha256,
        });
        piece_blocks.extend(blocks);
    }
    ensure!(
        source.read(&mut [0])? == 0,
        "download exceeds the expected image size"
    );
    let sha256 = hex::encode(whole.sha256.finalize());
    let sha1 = hex::encode(whole.sha1.finalize());
    ensure!(
        image
            .sha1
            .as_ref()
            .is_some_and(|expected| expected.eq_ignore_ascii_case(&sha1)),
        "download differs from the catalog digest"
    );
    progress.finish();
    let progress = crate::progress::Phase::bytes("Verifying USB", total);
    for (index, piece) in pieces.iter().enumerate() {
        let path = directory.join(piece_name(index));
        let partial = directory.join(format!("{}.partial", piece_name(index)));
        ensure!(
            hash_file(&partial, piece.bytes, &progress)?.0 == piece.sha256,
            "USB data does not read back as written"
        );
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(partial, path)?;
    }
    progress.finish();
    let joined = Joined {
        directory: directory.clone(),
        piece_bytes,
        total,
        position: 0,
        current: None,
    };
    let mut inventory = restore::payload::inventory_from(
        BufReader::with_capacity(1024 * 1024, joined),
        restore::payload::VerifiedSource {
            image: Path::new(&image.url)
                .file_name()
                .map(Path::new)
                .context("image URL has no file name")?,
            model,
            digest: (total, sha256),
        },
    )?;
    ensure!(
        inventory.manifest.product_build == image.build,
        "download contains a different macOS build"
    );
    inventory.manifest.source.catalog_sha1 = Some(sha1);
    inventory.manifest.layout = Layout::Pieces {
        piece_bytes,
        pieces,
        block_hashes: BlockHashes {
            file: PIECE_HASHES_FILE.into(),
            block_bytes: HASH_BLOCK_BYTES,
            sha256: stela_formats::sha256(&piece_blocks),
        },
    };
    inventory.manifest.validate().map_err(anyhow::Error::msg)?;
    efi::write_atomic(&directory.join(PIECE_HASHES_FILE), &piece_blocks, false)?;
    efi::write_atomic(&directory.join(BLOCK_HASHES_FILE), &inventory.blocks, false)?;
    let json = inventory.manifest.to_json();
    efi::write_atomic(&manifest_path, json.as_bytes(), false)?;
    Ok(Written {
        wrote: sizes.len(),
        kept: 0,
        manifest_sha256: stela_formats::sha256(json.as_bytes()),
    })
}

/// A bounded reader over the downloaded pieces, for ZIP's random accesses.
struct Joined {
    directory: PathBuf,
    piece_bytes: u64,
    total: u64,
    position: u64,
    current: Option<(u64, fs::File)>,
}

impl Read for Joined {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.position == self.total || bytes.is_empty() {
            return Ok(0);
        }
        let index = self.position / self.piece_bytes;
        if self.current.as_ref().is_none_or(|(old, _)| *old != index) {
            self.current = Some((
                index,
                fs::File::open(self.directory.join(piece_name(index as usize)))?,
            ));
        }
        let offset = self.position % self.piece_bytes;
        let file = &mut self.current.as_mut().unwrap().1;
        file.seek(SeekFrom::Start(offset))?;
        let count = bytes
            .len()
            .min((self.piece_bytes - offset).min(self.total - self.position) as usize);
        let count = file.read(&mut bytes[..count])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "USB image is truncated",
            ));
        }
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for Joined {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.total) + i128::from(n),
        };
        if position < 0 || position > i128::from(self.total) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside USB image",
            ));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_verifies_before_publication() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let ipsw = temp.path().join("source.ipsw");
        crate::efi::synthetic_ipsw(&ipsw)?;
        let bytes = fs::read(&ipsw)?;
        let image = restore::Image {
            version: "test".into(),
            build: restore::payload::SYNTHETIC_BUILD.into(),
            models: vec![restore::payload::SYNTHETIC_MODEL.into()],
            url: "https://updates.cdn-apple.com/source.ipsw".into(),
            sha1: Some(hex::encode(Sha1::digest(&bytes))),
        };
        let volume = temp.path().join("usb");
        let written = write_from(
            &bytes[..],
            &volume,
            restore::payload::SYNTHETIC_MODEL,
            &image,
            bytes.len() as u64,
            HASH_BLOCK_BYTES,
        )?;
        assert!(!written.manifest_sha256.is_empty());
        assert!(
            written.wrote > 1,
            "the fixture must exercise joined-piece reads"
        );
        let manifest = fs::read(directory(&volume, &image.build).join(MANIFEST_FILE))?;
        let manifest = stela_formats::payload::PayloadManifest::parse(&manifest)
            .map_err(anyhow::Error::msg)?;
        assert!(matches!(manifest.layout, Layout::Pieces { .. }));
        assert_eq!(manifest.source.sha256, Some(stela_formats::sha256(&bytes)));
        let mut damaged = bytes.clone();
        damaged[0] ^= 1;
        let mut oversized = bytes.clone();
        oversized.push(0);
        for (index, bad_bytes) in [damaged, bytes[..bytes.len() - 1].to_vec(), oversized]
            .into_iter()
            .enumerate()
        {
            let bad = temp.path().join(format!("bad-{index}"));
            assert!(
                write_from(
                    &bad_bytes[..],
                    &bad,
                    restore::payload::SYNTHETIC_MODEL,
                    &image,
                    bytes.len() as u64,
                    HASH_BLOCK_BYTES
                )
                .is_err()
            );
            assert!(!directory(&bad, &image.build).join(MANIFEST_FILE).exists());
        }
        Ok(())
    }
}
