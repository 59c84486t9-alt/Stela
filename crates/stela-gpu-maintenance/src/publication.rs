//! Publish staged maintenance components and preserve recoverable rename state.
use anyhow::{Context, Result, ensure};
use std::os::unix::fs::MetadataExt;
use std::{
    fs::{self, File},
    path::PathBuf,
};

pub(super) const RECEIPT: &str = ".stela-gpu-install.json";

pub(super) struct Publication {
    pub staged: PathBuf,
    pub destination: PathBuf,
    pub backup: Option<PathBuf>,
    installed: bool,
}

impl Publication {
    pub fn new(staged: PathBuf, destination: PathBuf) -> Self {
        Self {
            staged,
            destination,
            backup: None,
            installed: false,
        }
    }

    pub fn publish(&mut self) -> Result<()> {
        let parent = self.destination.parent().unwrap().to_owned();
        self.publish_with_sync(|| File::open(parent)?.sync_all())
    }

    fn publish_with_sync(&mut self, sync: impl FnOnce() -> std::io::Result<()>) -> Result<()> {
        match fs::symlink_metadata(&self.destination) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                ensure!(
                    metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                    "GPU destination is not a root-owned protected directory"
                );
                let receipt_path = self.destination.join(RECEIPT);
                let metadata = fs::symlink_metadata(&receipt_path)
                    .context("refusing to replace a bundle not installed by Stela maintenance")?;
                ensure!(
                    metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                    "GPU ownership receipt is not a root-owned protected regular file"
                );
                let receipt: serde_json::Value = serde_json::from_slice(&fs::read(receipt_path)?)?;
                ensure!(
                    receipt["installer"] == "stela-gpu-maintenance-v1",
                    "GPU destination has no Stela maintenance ownership receipt"
                );
                let backup = self.destination.with_file_name(format!(
                    ".{}.previous-{}",
                    self.destination.file_name().unwrap().to_string_lossy(),
                    std::process::id()
                ));
                ensure!(
                    fs::symlink_metadata(&backup)
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                    "GPU backup path already exists or cannot be inspected"
                );
                fs::rename(&self.destination, &backup)?;
                self.backup = Some(backup);
            }
        }
        fs::rename(&self.staged, &self.destination)?;
        self.installed = true;
        sync()?;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        if self.installed {
            fs::rename(&self.destination, &self.staged)?;
            self.installed = false;
        }
        if let Some(backup) = &self.backup {
            fs::rename(backup, &self.destination)?;
            self.backup = None;
        }
        File::open(self.destination.parent().unwrap())?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_restores_a_new_publication_to_staging() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staged = root.path().join("staged");
        fs::create_dir(&staged)?;
        let mut publication = Publication::new(staged.clone(), root.path().join("installed"));
        publication.publish()?;
        assert!(publication.destination.is_dir());
        publication.rollback()?;
        assert!(staged.is_dir());
        assert!(!publication.destination.exists());
        Ok(())
    }

    #[test]
    fn a_directory_sync_failure_can_roll_back_the_published_component() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staged = root.path().join("staged");
        let destination = root.path().join("installed");
        fs::create_dir(&staged)?;
        fs::write(staged.join("new"), b"new")?;
        let mut publication = Publication::new(staged.clone(), destination.clone());
        assert!(
            publication
                .publish_with_sync(|| Err(std::io::Error::other("injected sync failure")))
                .is_err()
        );
        assert!(destination.join("new").is_file());
        publication.rollback()?;
        assert!(!destination.exists());
        assert!(staged.join("new").is_file());
        Ok(())
    }

    #[test]
    fn a_failed_backup_restore_keeps_its_recovery_path() -> Result<()> {
        let root = tempfile::tempdir()?;
        let backup = root.path().join("backup");
        fs::create_dir(&backup)?;
        fs::write(backup.join("old"), b"old")?;
        let mut publication = Publication::new(
            root.path().join("staged"),
            root.path().join("absent/installed"),
        );
        publication.backup = Some(backup.clone());
        assert!(publication.rollback().is_err());
        assert_eq!(publication.backup, Some(backup));
        fs::create_dir(root.path().join("absent"))?;
        publication.rollback()?;
        assert!(publication.destination.join("old").is_file());
        assert!(publication.backup.is_none());
        Ok(())
    }

    #[test]
    fn a_dangling_destination_symlink_is_refused() -> Result<()> {
        let root = tempfile::tempdir()?;
        let staged = root.path().join("staged");
        let destination = root.path().join("installed");
        fs::create_dir(&staged)?;
        std::os::unix::fs::symlink(root.path().join("absent"), &destination)?;
        let mut publication = Publication::new(staged.clone(), destination.clone());
        assert!(publication.publish().is_err());
        assert!(staged.is_dir());
        assert!(fs::symlink_metadata(destination)?.file_type().is_symlink());
        Ok(())
    }
}
