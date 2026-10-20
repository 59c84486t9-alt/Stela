//! The store's service side, which `stelad` runs
//! (`docs/design/runtime.md#stelad`): while a store is served, processes
//! prove nothing and leave their compiled blocks in the service's spool;
//! the service proves and writes them, translates installed images ahead
//! of time from their files, and keeps the store within its bound.
use super::{
    COUNTERS, Config, LAYOUT, SERVICE_FILE, SERVICE_WORKERS, SPOOL_DIRECTORY, SPOOL_EXTENSION,
    ahead, configure, image, read_bounded, shared, spool, write_replacing,
};
use crate::machine::{Description, Preparation};
use anyhow::{Context as _, Result};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

/// The images the service translated, by model and path, with the
/// file it read.
const IMAGES_FILE: &str = "images.json";
/// The longest a service run waits for its proofs.
const SERVICE_WAIT: Duration = Duration::from_secs(60 * 60);
/// The largest image file translated.
const MAX_IMAGE_BYTES: u64 = 1 << 30;

/// What one service run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Offers taken from the spool.
    pub spooled: u64,
    /// Image files translated, and those unchanged since their last run.
    pub images: u64,
    pub unchanged: u64,
    /// Blocks prepared from image files.
    pub blocks: u64,
    pub proven: u64,
    pub records: u64,
    pub evicted: u64,
}

/// The spool processes leave their offers in, for the service's watch.
pub fn spool_directory(config: &Config) -> PathBuf {
    config.home.join(LAYOUT).join(SPOOL_DIRECTORY)
}

/// Mark the store as served, or no longer (`stelad`'s install and removal).
pub fn set_served(config: &Config, served: bool) -> Result<()> {
    let marker = config.home.join(LAYOUT).join(SERVICE_FILE);
    if served {
        write_replacing(&marker, env!("CARGO_PKG_VERSION").as_bytes())
            .with_context(|| format!("cannot write {}", marker.display()))
    } else {
        match std::fs::remove_file(&marker) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("cannot remove {}", marker.display()))
            }
            _ => Ok(()),
        }
    }
}

/// A file's identity for the images record: size, modification time and
/// inode.
fn fingerprint(path: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some(format!(
        "{}:{}:{}",
        metadata.len(),
        metadata.mtime(),
        metadata.ino()
    ))
}

/// Serve the store `config` names once: prove and write the spooled offers,
/// translate the arm64 slices of `images` that changed since the last run
/// for processes modeling the Mac `model`, wait for every proof, and evict
/// past the bound.
pub fn serve(config: Config, images: &[PathBuf], model: &str) -> Result<Report> {
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    let _ = SERVICE_WORKERS.set(workers.div_ceil(2));
    set_served(&config, true)?;
    configure(Some(config.clone()));
    let shared = shared().context("the translation store is not configured")?;
    let disk = shared
        .disk
        .as_ref()
        .context("the translation store has no home")?;
    let before = (
        COUNTERS.proven.load(Ordering::Relaxed),
        COUNTERS.records_written.load(Ordering::Relaxed),
        COUNTERS.evicted.load(Ordering::Relaxed),
    );
    let mut report = Report {
        spooled: take_spool(shared, &spool_directory(&config)),
        ..Report::default()
    };
    let record_path = disk.namespace.join(IMAGES_FILE);
    let mut record: BTreeMap<String, String> = read_bounded(&record_path)
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    let mut preparation = None;
    for path in images {
        // A file is translated again for another model.
        let key = format!("{model} {}", path.display());
        let Some(print) = fingerprint(path) else {
            continue;
        };
        if record.get(&key) == Some(&print) {
            report.unchanged += 1;
            continue;
        }
        let preparation = match &preparation {
            Some(preparation) => Arc::clone(preparation),
            None => {
                let made = crate::hosted::preparation(model)?;
                preparation = Some(made.clone());
                made
            }
        };
        report.blocks += translate_file(shared, path, &preparation);
        report.images += 1;
        record.insert(key, print);
    }
    shared.finish(Instant::now() + SERVICE_WAIT);
    if report.images != 0 {
        let bytes = serde_json::to_vec_pretty(&record)?;
        write_replacing(&record_path, &bytes)
            .with_context(|| format!("cannot write {}", record_path.display()))?;
    }
    report.proven = COUNTERS.proven.load(Ordering::Relaxed) - before.0;
    report.records = COUNTERS.records_written.load(Ordering::Relaxed) - before.1;
    report.evicted = COUNTERS.evicted.load(Ordering::Relaxed) - before.2;
    Ok(report)
}

/// Queue every offer of this translator's spool files for proof and remove
/// the files; another translator's files are removed unread.
fn take_spool(shared: &'static super::Shared, directory: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return 0;
    };
    let prefix = shared.translator.hex();
    let mut preparations: Vec<(Description, Arc<Preparation>)> = Vec::new();
    let mut taken = 0;
    for path in entries.filter_map(|entry| entry.ok().map(|entry| entry.path())) {
        if path
            .extension()
            .is_none_or(|extension| extension != SPOOL_EXTENSION)
        {
            continue;
        }
        let ours = path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(&prefix));
        let offers = ours
            .then(|| read_bounded(&path))
            .flatten()
            .and_then(|bytes| spool::decode(&bytes, &shared.translator))
            .unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        for spooled in offers {
            let preparation = match preparations
                .iter()
                .find(|(description, _)| *description == spooled.description)
            {
                Some((_, preparation)) => preparation.clone(),
                None => {
                    let made = Arc::new(Preparation::from_description(&spooled.description));
                    preparations.push((spooled.description, made.clone()));
                    made
                }
            };
            if let Some(offer) = spooled.offer(preparation) {
                shared.prepare(offer);
                taken += 1;
            }
        }
    }
    taken
}

/// Prepare every block the arm64 slices of the file at `path` name and
/// reach inside their `__TEXT`: the blocks prepared.
fn translate_file(
    shared: &'static super::Shared,
    path: &Path,
    preparation: &Arc<Preparation>,
) -> u64 {
    let readable = std::fs::metadata(path).is_ok_and(|metadata| metadata.len() <= MAX_IMAGE_BYTES);
    let Some(bytes) = readable.then(|| std::fs::read(path).ok()).flatten() else {
        return 0;
    };
    let mut prepared = 0;
    for file in image::file_images(bytes.into()) {
        let Some(read) = image::read(&file, file.header) else {
            continue;
        };
        prepared += translate_image(shared, &file, preparation, &read);
    }
    prepared
}

/// Prepare `image`'s entries and their successors inside its `__TEXT` on
/// the host's threads: the blocks prepared.
fn translate_image(
    shared: &'static super::Shared,
    memory: &image::FileImage,
    preparation: &Arc<Preparation>,
    image: &image::Image,
) -> u64 {
    struct Work {
        queue: VecDeque<u64>,
        seen: HashSet<u64>,
        busy: usize,
        prepared: u64,
    }
    let work = Mutex::new(Work {
        queue: image.entries.iter().copied().collect(),
        seen: image.entries.iter().copied().collect(),
        busy: 0,
        prepared: 0,
    });
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let pc = {
                        let mut work = super::lock(&work);
                        match work.queue.pop_front() {
                            Some(pc) => {
                                work.busy += 1;
                                pc
                            }
                            None if work.busy == 0 => return,
                            None => {
                                drop(work);
                                std::thread::yield_now();
                                continue;
                            }
                        }
                    };
                    let successors = ahead::prepare_at(shared, memory, preparation, pc);
                    let mut work = super::lock(&work);
                    work.busy -= 1;
                    if let Some(successors) = successors {
                        work.prepared += 1;
                        for successor in successors {
                            if successor & 3 == 0
                                && image.text.contains(&successor)
                                && work.seen.insert(successor)
                            {
                                work.queue.push_back(successor);
                            }
                        }
                    }
                }
            });
        }
    });
    super::lock(&work).prepared
}

#[cfg(test)]
mod tests {
    use super::super::{Role, SPOOL_BATCH, Shared};
    use super::*;
    use crate::machine::{Offer, test_preparation};
    use crate::translations::Digest;

    /// An offer of `add x0, x0, #1; ret` at `pc`.
    fn offer(pc: u64) -> Offer {
        let preparation = Arc::new(test_preparation());
        let page = pc & !(crate::translations::PAGE_BYTES as u64 - 1);
        let mut input: Vec<u8> = [0x9100_0400u32, 0xd65f_03c0]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        preparation.admit(&mut input);
        Offer {
            key: Digest::of(&pc.to_le_bytes()),
            page,
            pc,
            context: preparation.context(page),
            block: preparation.compile_input(&input, pc).unwrap(),
            input,
            preparation,
            successors: Vec::new(),
        }
    }

    #[test]
    fn a_served_process_spools_its_offers_in_batches_and_the_service_writes_them() {
        let home = tempfile::tempdir().unwrap();
        let config = Config {
            home: home.path().to_path_buf(),
            bound: 1 << 30,
        };
        let spool = spool_directory(&config);
        let served = Shared::leaked(Some(&config), Role::Served);
        for index in 0..SPOOL_BATCH as u64 {
            served.prepare(offer(0x1_0000_0000 + index * 8));
        }
        assert_eq!(
            std::fs::read_dir(&spool).unwrap().count(),
            1,
            "a full batch is spooled"
        );
        served.prepare(offer(0x2_0000_0000));
        served.finish(Instant::now());
        assert_eq!(
            std::fs::read_dir(&spool).unwrap().count(),
            2,
            "the rest at the end"
        );
        let namespace = &served.disk.as_ref().unwrap().namespace;
        assert!(!namespace.exists(), "a served process writes no records");

        let service = Shared::leaked(Some(&config), Role::Service { workers: 2 });
        assert_eq!(take_spool(service, &spool), SPOOL_BATCH as u64 + 1);
        assert_eq!(std::fs::read_dir(&spool).unwrap().count(), 0);
        service.finish(Instant::now() + SERVICE_WAIT);
        let shard = Shared::path(
            service.disk.as_ref().unwrap(),
            &Digest::of(&0x2_0000_0000u64.to_le_bytes()),
        );
        assert!(
            shard.is_file(),
            "the service proved and wrote the last offer"
        );
    }
}
