//! Preparing a setup's boot bundles on this computer and fetching the
//! restore images they are prepared from.
use super::{
    Environment, InstallImage, MARGIN, Request,
    bundle::{self, Kind},
    ecid::Ecid,
    host::Host,
    record::Record,
};
use crate::{boot, restore};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
};
use stela_runtime::builds;

/// A boot bundle prepared on this computer, not yet copied.
pub(super) struct Prepared {
    pub(super) build: String,
    pub(super) ecid: Option<Ecid>,
    pub(super) kind: Kind,
    pub(super) personalized: bool,
    pub(super) generation: bundle::Generation,
    pub(super) directory: tempfile::TempDir,
    pub(super) bytes: u64,
}

pub(super) type PreparedSetup = (String, String, Vec<Prepared>);

impl Prepared {
    pub(super) fn path(&self) -> PathBuf {
        self.directory.path().join(BUNDLE_LEAF)
    }
}

/// The directory a bundle is prepared into, inside its temporary one.
pub(super) const BUNDLE_LEAF: &str = "bundle";

/// Prepare `ipsw`'s restore bundles of every kind setup writes
/// ([`bundle::RESTORE_KINDS`]) for the machine `ecid`, under Apple's
/// personalized ticket. Returns the image's version and build too.
pub(super) fn prepare_restore_bundles(
    environment: &Environment<'_>,
    ipsw: &Path,
    model: &str,
    ecid: Ecid,
) -> Result<PreparedSetup> {
    let (product_version, build) = restore::payload::identity(ipsw, model)?;
    let mut prepared = Vec::new();
    for kind in bundle::RESTORE_KINDS {
        let (_, _, bundles) = prepare_kind(
            environment,
            BundleOptions {
                kind,
                tss: true,
                ipsw,
                model,
                build: Some(&build),
                ecids: &[Some(ecid)],
            },
        )?;
        prepared.extend(bundles);
    }
    Ok((product_version, build, prepared))
}

/// Refuse `ipsw`, of macOS `build`, unless setup supports that build.
pub(super) fn supported(environment: &Environment<'_>, ipsw: &Path, build: &str) -> Result<()> {
    builds::find_in(environment.builds, build)
        .map(drop)
        .map_err(|error| anyhow::anyhow!("{}: {error}", ipsw.display()))
}

/// Source identity and personalization choices for one kind of boot bundle.
pub(super) struct BundleOptions<'a> {
    pub(super) kind: Kind,
    /// Request personalization through the TSS service.
    pub(super) tss: bool,
    pub(super) ipsw: &'a Path,
    pub(super) model: &'a str,
    pub(super) build: Option<&'a str>,
    pub(super) ecids: &'a [Option<Ecid>],
}

/// Prepare the selected bundle kind for each machine; verify the requested
/// build and return its product version, build and prepared bundles.
pub(super) fn prepare_kind(
    environment: &Environment<'_>,
    options: BundleOptions<'_>,
) -> Result<(String, String, Vec<Prepared>)> {
    let BundleOptions {
        kind,
        tss,
        ipsw,
        model,
        build,
        ecids,
    } = options;
    let (product_version, found) = restore::payload::identity(ipsw, model)?;
    if let Some(build) = build {
        ensure!(
            found == build,
            "{} holds macOS build {found}, not {build}",
            ipsw.display()
        );
    }
    supported(environment, ipsw, &found)?;
    let mut prepared = Vec::new();
    for &ecid in ecids {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join(BUNDLE_LEAF);
        let prepare = match kind {
            Kind::Restore => environment.prepare_restore,
            Kind::Update => environment.prepare_update,
        };
        let personalized = tss;
        let progress =
            crate::progress::Phase::spinner(format!("Preparing {} boot files", kind.label()));
        prepare(RamdiskOptions {
            ipsw,
            model,
            ecid,
            personalized,
            output: &output,
        })
        .with_context(|| format!("preparing the {} boot bundle", kind.label()))?;
        progress.finish();
        let generation = bundle::generation(&output)?;
        ensure!(
            generation == environment.generation(),
            "the prepared bundle is {generation}, not the {} this stela and its stela.efi use",
            environment.generation()
        );
        let bytes = bundle::bytes(&output)?;
        prepared.push(Prepared {
            build: found.clone(),
            ecid,
            kind,
            personalized,
            generation,
            directory,
            bytes,
        });
    }
    Ok((product_version, found, prepared))
}

/// Copy prepared bundles to the record's volume and record them, as
/// bundles of its active generation.
pub(super) fn copy_bundles(record: &mut Record, prepared: &[Prepared]) -> Result<()> {
    let generation = record.generation();
    for bundle in prepared {
        ensure!(
            bundle.generation == generation,
            "a {} bundle cannot be one of this setup's {generation} bundles",
            bundle.generation
        );
        let destination = bundle::directory_of(
            &record.volume,
            bundle::Identity {
                kind: bundle.kind,
                build: &bundle.build,
                ecid: bundle.ecid,
                generation,
            },
        );
        fs::create_dir_all(destination.parent().unwrap())?;
        let digest = bundle::install(&bundle.path(), &destination)?;
        // Read back, so a USB that loses writes is found now, not at boot.
        let problems = bundle::verify(&destination, &digest);
        ensure!(
            problems.is_empty(),
            "the copied bundle does not read back as written: {}",
            problems.join("; ")
        );
        record.bundles.retain(|b| {
            !b.same_kind(bundle::Identity {
                kind: bundle.kind,
                build: &bundle.build,
                ecid: bundle.ecid,
                generation,
            })
        });
        record.bundles.push(bundle::Bundle {
            build: bundle.build.clone(),
            ecid: bundle.ecid,
            schema: generation.schema,
            revision: generation.revision,
            manifest_sha256: digest,
            kind: bundle.kind,
            personalized: bundle.personalized,
        });
    }
    Ok(())
}

/// Whether `volume` has room for `prepared`.
pub(super) fn check_space(host: &dyn Host, volume: &Path, prepared: &[Prepared]) -> Result<()> {
    let need: u64 = prepared.iter().map(|p| p.bytes).sum::<u64>() + MARGIN;
    let free = host.volume(volume)?.free_bytes;
    ensure!(
        free >= need,
        "{} has {:.1} GB free; the boot bundles need {:.1} GB",
        volume.display(),
        free as f64 / 1e9,
        need as f64 / 1e9
    );
    Ok(())
}

/// Where `--fetch` keeps downloaded restore images: the host's per-user cache.
pub(crate) fn download_dir() -> PathBuf {
    std::env::temp_dir().join("Stela/images")
}

/// Download `--build`'s image, or reuse a complete earlier download: the
/// whole IPSW for an offline install medium, else its recovery members,
/// which prepare the boot bundles.
pub(super) fn fetch(command: &Request) -> Result<PathBuf> {
    let directory = command.download_dir.clone().unwrap_or_else(download_dir);
    match command.install_image {
        Some(InstallImage::Offline) => fetch_image(&directory, &command.build, command.model()),
        _ => fetch_recovery(&directory, &command.build, command.model()),
    }
}

/// Copy `build`'s recovery members for `model` from Apple's servers into
/// `directory` (`restore::fetch_recovery`), or reuse an earlier complete
/// copy: setup's install medium needs no more of the image.
pub(super) fn fetch_recovery(directory: &Path, build: &str, model: &str) -> Result<PathBuf> {
    ensure!(
        build.bytes().all(|c| c.is_ascii_alphanumeric())
            && model
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b','),
        "unexpected build or model identifier"
    );
    let path = directory.join(format!("Recovery_{build}_{}.ipsw", model.replace(',', "_")));
    if path.is_file() {
        let archive = zip::ZipArchive::new(fs::File::open(&path)?)
            .with_context(|| format!("{} is not a complete archive", path.display()))?;
        ensure!(
            archive.comment() == restore::payload::RECOVERY_COMMENT,
            "{} is not a recovery archive; move it away",
            path.display()
        );
        eprintln!("Using downloaded boot files");
        return Ok(path);
    }
    let images = restore::catalog()?;
    let image = restore::select(&images, Some(build), Some(model))?;
    fs::create_dir_all(directory)?;
    let bytes = restore::fetch_recovery(&image, model, &path)?;
    eprintln!("Downloaded {:.2} GB of boot files", bytes as f64 / 1e9);
    Ok(path)
}

/// Download `build`'s restore image for `model` from Apple's catalog into
/// `directory`, or reuse a complete earlier download from the same entry.
pub(crate) fn fetch_image(directory: &Path, build: &str, model: &str) -> Result<PathBuf> {
    let images = restore::catalog()?;
    let image = restore::select(&images, Some(build), Some(model))?;
    ensure!(
        image.build.bytes().all(|c| c.is_ascii_alphanumeric())
            && image
                .version
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.'),
        "unexpected catalog identifiers"
    );
    let path = directory.join(format!(
        "UniversalMac_{}_{}_Restore.ipsw",
        image.version, image.build
    ));
    if path.is_file()
        && let Some(receipt) = restore::receipt(&path)?
    {
        // Reused only as the catalog entry it was downloaded from.
        ensure!(
            receipt.image == image && receipt.catalog_sha1_verified,
            "{} was downloaded from another catalog entry than Apple lists for macOS {} now; \
             move it away, or pass it with --ipsw",
            path.display(),
            image.build
        );
        eprintln!("Using the downloaded macOS image");
    } else {
        restore::download(&image, &path)?;
    }
    Ok(path)
}

/// The console boot-args of the bundles setup prepares: the kernel's text
/// on the screen (`-v`) and on the debug UART, which the engine records in
/// the boot log as `GUEST|` lines, so a run on a PC can be read afterwards.
pub(super) const CONSOLE_BOOT_ARGS: &str = "--boot-args=-v serial=3 serial-device-name=uart0";

/// Inputs and destination for one erase or update restore bundle.
pub(super) struct RamdiskOptions<'a> {
    pub(super) ipsw: &'a Path,
    pub(super) model: &'a str,
    pub(super) ecid: Option<Ecid>,
    /// Request an AP ticket; ecid must be set.
    pub(super) personalized: bool,
    pub(super) output: &'a Path,
}

/// `stela-dev boot prepare --restore` for the IPSW, model and machine into
/// `output`: the restore bundle the Install macOS choice boots.
pub(super) fn prepare_restore(options: RamdiskOptions<'_>) -> Result<()> {
    prepare_ramdisk(options, false)
}

/// `stela-dev boot prepare --restore --update`: the update restore bundle the
/// Update macOS choice boots.
pub(super) fn prepare_update(options: RamdiskOptions<'_>) -> Result<()> {
    prepare_ramdisk(options, true)
}

/// A restore bundle of the model's erase or, with `update`, update restore
/// identity; `personalized`, under the AP ticket Apple's signing service
/// issues for the machine, which the restore's `--tss` choice needs. Then
/// the engine's own board check of the prepared DeviceTree
/// (`machine::soc::board`), so a model the engine cannot run is refused
/// before the USB changes rather than when the PC boots it.
fn prepare_ramdisk(options: RamdiskOptions<'_>, update: bool) -> Result<()> {
    let RamdiskOptions {
        ipsw,
        model,
        ecid,
        personalized,
        output,
    } = options;
    let mut line: Vec<String> = [
        "--ipsw",
        ipsw.to_str().context("IPSW path is not UTF-8")?,
        "--model",
        model,
        "--restore",
        "--output",
        output.to_str().context("temporary path is not UTF-8")?,
        CONSOLE_BOOT_ARGS,
    ]
    .map(str::to_owned)
    .into();
    if update {
        line.push("--update".into());
    }
    if let Some(ecid) = ecid {
        line.extend(["--ecid".into(), ecid.to_string()]);
    }
    if personalized {
        ensure!(
            ecid.is_some(),
            "a personalized restore bundle needs an ECID"
        );
        line.push("--tss".into());
    }
    boot::prepare(&line)?;
    let tree = fs::read(output.join("devicetree.adt"))?;
    stela_runtime::machine::soc::board(&tree)
        .map_err(|reason| anyhow::anyhow!("Stela cannot run {model} yet: {reason}"))?;
    Ok(())
}
