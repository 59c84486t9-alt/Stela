//! Initialize durable storage only for an explicitly staged FDR diagnostic.
//! Existing commits are validated and preserved, never replaced by the seed.
use super::Record;
use crate::efi;
use anyhow::{Context, Result, ensure};
use std::{fs, io::ErrorKind, path::Path};
use stela_runtime::{
    pc::fdr_store,
    restore::fdr::{self, Diagnostic},
};

pub(super) fn prepare(record: &Record, dry_run: bool) -> Result<String> {
    let mut report = String::new();
    for medium in &record.media {
        if prepare_directory(&medium.directory(), dry_run)? {
            report.push_str(
                "  FDR storage    initialize a 4 MiB journal from the staged diagnostic\n",
            );
        }
    }
    Ok(report)
}

fn prepare_directory(directory: &Path, dry_run: bool) -> Result<bool> {
    let seed = match fs::read(directory.join(fdr::FILE)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("cannot read staged FDR diagnostic"),
    };
    let initial =
        Diagnostic::decode(&seed).map_err(|e| anyhow::anyhow!("invalid FDR seed: {e}"))?;
    let path = directory.join(fdr::STATE_FILE);
    match fs::read(&path) {
        Ok(image) => {
            let snapshot = fdr_store::read_image(&image)?.context(
                "existing FDR journal is uninitialized; preserve it and repair explicitly",
            )?;
            let stored = Diagnostic::decode(&snapshot)
                .map_err(|e| anyhow::anyhow!("invalid FDR stored binding: {e}"))?;
            ensure!(
                initial.same_identity(&stored),
                "FDR journal belongs to another machine/build"
            );
            return Ok(false);
        }
        Err(error) if error.kind() == ErrorKind::NotFound => (),
        Err(error) => return Err(error).context("cannot read FDR journal"),
    }
    if !dry_run {
        let image = fdr_store::initial_image(&seed)?;
        efi::write_atomic(&path, &image, true)?;
        ensure!(
            fs::read(&path)? == image,
            "FDR journal readback differs after initialization"
        );
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_runtime::restore::plist::{self, Limits, Value};

    #[test]
    fn initialization_is_opt_in_atomic_and_never_replaces_committed_records() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!prepare_directory(dir.path(), false).unwrap());
        let value = Value::dict([
            ("DiagnosticVersion", Value::Integer(1)),
            ("ECID", Value::Integer(42)),
            ("ChipID", Value::Integer(8)),
            ("BoardID", Value::Integer(9)),
            ("Build", Value::from("test")),
            ("Model", Value::from("test")),
            (
                "FDRMemoryStoreData",
                Value::dict([("class-own", Value::Data(vec![1]))]),
            ),
        ]);
        let seed = plist::encode_binary(&value, Limits::default()).unwrap();
        fs::write(dir.path().join(fdr::FILE), &seed).unwrap();
        assert!(prepare_directory(dir.path(), true).unwrap());
        let path = dir.path().join(fdr::STATE_FILE);
        assert!(!path.exists());
        assert!(prepare_directory(dir.path(), false).unwrap());
        assert_eq!(
            fdr_store::read_image(&fs::read(&path).unwrap()).unwrap(),
            Some(seed.clone())
        );
        let initial = Diagnostic::decode(&seed).unwrap();
        let committed = initial.with_records(Value::dict([])).unwrap();
        let image = fdr_store::initial_image(&committed).unwrap();
        fs::write(&path, &image).unwrap();
        assert!(!prepare_directory(dir.path(), false).unwrap());
        assert_eq!(fs::read(&path).unwrap(), image);
        fs::write(&path, vec![7; fdr_store::FILE_BYTES]).unwrap();
        assert!(prepare_directory(dir.path(), false).is_err());
        assert_eq!(fs::read(&path).unwrap(), vec![7; fdr_store::FILE_BYTES]);
    }
}
