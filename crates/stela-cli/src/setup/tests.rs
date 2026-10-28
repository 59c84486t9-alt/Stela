use super::record::{RECORD_KIND, RECORD_SCHEMA};
use super::*;
use host::{Cpu, Disk, Partition, PartitionInfo, Volume};
use std::collections::BTreeMap;
use stela_loader::mount_interface::Choices;
use stela_runtime::machine::apple::nor::nvram::Variables;

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn partitions_are_named_alone_or_by_device_path() {
    use clap::Parser as _;
    let crate::Command::Setup(setup) = crate::Cli::try_parse_from([
        "stela",
        "setup",
        "--usb",
        "/dev/sdb",
        "--target",
        "/dev/nvme0n1p2",
        "--nor",
        "sdc3",
    ])
    .unwrap()
    .command
    else {
        panic!("not a setup");
    };
    let setup = setup.request();
    assert_eq!(setup.target.as_deref(), Some("nvme0n1p2"));
    assert_eq!(setup.nor.as_deref(), Some("sdc3"));
}

/// A computer whose volumes and disks the test declares.
pub(super) struct FakeHost {
    pub(super) volumes: BTreeMap<PathBuf, (FileSystem, u64, Option<&'static str>)>,
    pub(super) disks: Vec<Disk>,
    /// Partitions of the PC's disk, each backed by an image file.
    pub(super) partitions: BTreeMap<String, (PartitionInfo, PathBuf)>,
    pub(super) serials: BTreeMap<String, String>,
    pub(super) cpu: Cpu,
    /// The partitions `unmount` unmounted, in order.
    pub(super) unmounted: std::cell::RefCell<Vec<String>>,
    /// Where `mount` mounts a partition; others refuse.
    pub(super) mountable: BTreeMap<String, PathBuf>,
}

impl FakeHost {
    fn new(
        volumes: BTreeMap<PathBuf, (FileSystem, u64, Option<&'static str>)>,
        disks: Vec<Disk>,
    ) -> Self {
        Self {
            volumes,
            disks,
            partitions: BTreeMap::new(),
            serials: BTreeMap::new(),
            cpu: Cpu { entropy: true },
            unmounted: Default::default(),
            mountable: BTreeMap::new(),
        }
    }

    fn image(&self, identifier: &str) -> Result<&Path> {
        self.partitions
            .get(identifier)
            .map(|(_, path)| path.as_path())
            .context("no such partition")
    }
}

impl Host for FakeHost {
    fn partition(&self, identifier: &str) -> Result<PartitionInfo> {
        let mut info = self
            .partitions
            .get(identifier)
            .map(|(info, _)| info.clone())
            .context("no such partition")?;
        if self
            .unmounted
            .borrow()
            .iter()
            .any(|done| done == identifier)
        {
            info.mount = None;
            info.container = None;
        }
        Ok(info)
    }
    fn unmount(&self, partition: &PartitionInfo) -> Result<()> {
        self.unmounted
            .borrow_mut()
            .push(partition.identifier.clone());
        Ok(())
    }
    fn mount(&self, identifier: &str) -> Result<PathBuf> {
        self.mountable
            .get(identifier)
            .cloned()
            .context("permission denied")
    }
    fn serial(&self, disk: &str) -> Result<Option<String>> {
        Ok(self.serials.get(disk).cloned())
    }
    // Images may be sparse files as large as the partition, so they
    // are read and written in place.
    fn read(&self, identifier: &str, offset: u64, length: usize) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = fs::File::open(self.image(identifier)?)?;
        ensure!(
            offset + length as u64 <= file.metadata()?.len(),
            "read past the partition"
        );
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; length];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn write(&self, identifier: &str, offset: u64, data: &[u8]) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(self.image(identifier)?)?;
        ensure!(
            offset + data.len() as u64 <= file.metadata()?.len(),
            "write past the partition"
        );
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        Ok(())
    }
    fn cpu(&self) -> Result<Cpu> {
        Ok(self.cpu)
    }
    fn volume(&self, path: &Path) -> Result<Volume> {
        let (filesystem, free_bytes, disk) = self
            .volumes
            .iter()
            .filter(|(root, _)| path.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())
            .map(|(_, v)| v.clone())
            .context("no such volume")?;
        Ok(Volume {
            filesystem,
            free_bytes,
            disk: disk.map(str::to_owned),
        })
    }
    fn disks(&self) -> Result<Vec<Disk>> {
        Ok(self.disks.clone())
    }
}

fn disk(id: &str, contents: &[(&str, Option<&Path>)]) -> Disk {
    Disk {
        identifier: id.into(),
        name: format!("Disk {id}"),
        bytes: 128 * GIB,
        removal: match id {
            "disk5" => host::Removal::Usb,
            "disk6" => host::Removal::Typed,
            _ => host::Removal::Fixed,
        },
        system: id == "disk0",
        partitions: contents
            .iter()
            .enumerate()
            .map(|(i, (content, mount))| Partition {
                identifier: format!("{id}s{}", i + 1),
                content: (*content).into(),
                mount: mount.map(Path::to_path_buf),
            })
            .collect(),
    }
}

/// A `stela.efi` stand-in with this tree's mount interface.
fn efi_image(tag: &[u8]) -> Vec<u8> {
    let mut image = b"MZ".to_vec();
    image.extend_from_slice(tag);
    image.extend_from_slice(&mount_interface::marker(mount_interface::CURRENT));
    image
}

/// A USB (disk5) with an empty EFI partition and a data volume, HFS+ or
/// FAT, and this computer's system disk (disk0).
struct Fixture {
    _dir: tempfile::TempDir,
    esp: PathBuf,
    data: PathBuf,
    ipsw: PathBuf,
    efi: PathBuf,
    host: FakeHost,
}

fn fixture(esp_free: u64, fat_data: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let esp = dir.path().join("ESP");
    let data = dir.path().join("Data");
    fs::create_dir_all(&esp).unwrap();
    fs::create_dir_all(&data).unwrap();
    let data_filesystem = if fat_data {
        FileSystem::Fat
    } else {
        FileSystem::Hfs
    };
    let ipsw = dir.path().join("Synthetic.ipsw");
    efi::synthetic_ipsw(&ipsw).unwrap();
    let efi = dir.path().join("stela.efi");
    fs::write(&efi, efi_image(b"stela")).unwrap();
    let host = FakeHost::new(
        [
            (esp.clone(), (FileSystem::Fat, esp_free, Some("disk5"))),
            (data.clone(), (data_filesystem, 100 * GIB, Some("disk5"))),
            (
                dir.path().to_path_buf(),
                (FileSystem::Apfs, 100 * GIB, Some("disk0")),
            ),
        ]
        .into(),
        vec![
            disk("disk0", &[("EFI", None), ("Apple_APFS", None)]),
            disk("disk5", &[("EFI", Some(&esp)), ("Apple_HFS", Some(&data))]),
        ],
    );
    Fixture {
        _dir: dir,
        esp,
        data,
        ipsw,
        efi,
        host,
    }
}

fn command(f: &Fixture, usb: &Path) -> Request {
    Request {
        action: Action::Create,
        usb: usb.to_path_buf(),
        ipsw: Some(f.ipsw.clone()),
        fetch: false,
        install_image: None,
        download_dir: None,
        efi: Some(f.efi.clone()),
        model: Some(restore::payload::SYNTHETIC_MODEL.into()),
        build: restore::payload::SYNTHETIC_BUILD.into(),
        dry_run: false,
        target: None,
        nor: None,
        disk_serial: None,
        erase_target: false,
        initialize_nor: false,
        install: None,
        ecid: None,
        new_ecid: false,
        // Every setup installs macOS, which needs the opt-in.
        tss: true,
        no_tss: false,
        profile: false,
        no_profile: false,
        verify_on_read: false,
        install_volume: None,
        default_install: None,
        remove_install: None,
        chooser_timeout: None,
        // The smallest store: its spare is allocated at the bound, and
        // `snapshot` reads every file it compares. The default bound's
        // shrinking to fit is `translations::choose`'s to test.
        translation_store_bytes: Some(translations::MIN_PACK_BYTES),
        host_firmware_cache: None,
        confirm_disk: None,
    }
}

/// The generation of the bundles this tree prepares.
fn current() -> bundle::Generation {
    bundle::Generation {
        schema: mount_interface::CURRENT.bundle_schema,
        revision: stela_loader::boot_bundle::REVISION,
    }
}

/// A stand-in for `boot prepare --restore`: the synthetic IPSW has no
/// kernel to prepare. The bundle's byte names the machine.
fn fake_prepare_restore(
    _: &Path,
    _: &str,
    ecid: Option<Ecid>,
    _: bool,
    output: &Path,
) -> Result<()> {
    let byte = ecid.map_or(0x5a, |e| e.0 as u8) ^ 0xa5;
    bundle::tests::write(output, current(), &[byte; 2048])
}

/// A stand-in for `boot prepare --restore --update`.
fn fake_prepare_update(
    _: &Path,
    _: &str,
    ecid: Option<Ecid>,
    _: bool,
    output: &Path,
) -> Result<()> {
    let byte = ecid.map_or(0x5a, |e| e.0 as u8) ^ 0x3c;
    bundle::tests::write(output, current(), &[byte; 1024])
}

/// The synthetic IPSW's inventory: it names no AEA member to fetch a
/// key for.
fn fake_inventory(ipsw: &Path, model: &str) -> Result<restore::payload::Inventory> {
    restore::payload::inventory(ipsw, model, false, None, None)
}

/// The synthetic IPSW's inventory as if it were on Apple's servers.
fn fake_remote_inventory(ipsw: &Path, model: &str) -> Result<restore::payload::Inventory> {
    let layout = stela_runtime::payload::Layout::Remote {
        url: "http://updates-http.example.test/Synthetic.ipsw".into(),
        etag: "\"synthetic\"".into(),
    };
    let bytes = fs::metadata(ipsw)?.len();
    restore::payload::remote_inventory(fs::File::open(ipsw)?, ipsw, bytes, layout, model, None)
}

fn environment(host: &FakeHost) -> Environment<'_> {
    Environment {
        host,
        download: None,
        prepare_restore: &fake_prepare_restore,
        prepare_update: &fake_prepare_update,
        inventory: &fake_inventory,
        remote_inventory: &fake_remote_inventory,
        piece_bytes: medium::tests::PIECE_BYTES,
        interface: mount_interface::CURRENT,
        bundle_revision: stela_loader::boot_bundle::REVISION,
        builds: SYNTHETIC_BUILDS,
    }
}

/// The synthetic images' builds, as supported ones.
const SYNTHETIC_BUILDS: &[builds::Build] = &[
    synthetic_build(restore::payload::SYNTHETIC_BUILD),
    synthetic_build("STELA2"),
    synthetic_build("STELA3"),
];

const fn synthetic_build(build: &'static str) -> builds::Build {
    builds::Build {
        build,
        version: "27.0",
        dcp_link_version: builds::DEFAULT.dcp_link_version,
        rtkit_version: builds::DEFAULT.rtkit_version,
    }
}

#[test]
fn a_build_outside_the_table_is_not_prepared() {
    let f = fixture(64 * GIB, true);
    let environment = Environment {
        builds: builds::SUPPORTED,
        ..environment(&f.host)
    };
    let error = setup(&environment, command(&f, &f.esp))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(&format!(
            "macOS build {} is not supported",
            restore::payload::SYNTHETIC_BUILD
        )),
        "{error}"
    );
    assert!(error.contains(builds::DEFAULT.build), "{error}");
}

/// Stand-ins for the restore and update restore `boot prepare` of a
/// stela whose loader prepares `revision`; each bundle's byte names its
/// machine, kind and revision.
fn preparers(revision: u32) -> [Box<Prepare>; 2] {
    let of = |kind: u8, bytes: usize| -> Box<Prepare> {
        Box::new(
            move |_: &Path, _: &str, ecid: Option<Ecid>, _: bool, output: &Path| {
                let byte = ecid.map_or(0x5a, |e| e.0 as u8) ^ kind ^ revision as u8;
                let generation = bundle::Generation {
                    revision,
                    ..current()
                };
                bundle::tests::write(output, generation, &vec![byte; bytes])
            },
        )
    };
    [of(0xa5, 2048), of(0x3c, 1024)]
}

/// The environment of a stela whose loader prepares `revision`.
fn environment_at<'a>(
    host: &'a FakeHost,
    preparers: &'a [Box<Prepare>; 2],
    revision: u32,
) -> Environment<'a> {
    Environment {
        prepare_restore: &*preparers[0],
        prepare_update: &*preparers[1],
        bundle_revision: revision,
        ..environment(host)
    }
}

/// Every file under `root`, with its bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else {
                files.insert(entry.path(), fs::read(entry.path()).unwrap());
            }
        }
    }
    files
}

fn record(f: &Fixture) -> Record {
    stela_runtime::read_json(&f.esp.join(RECORD)).unwrap()
}

/// The active build's restore bundle of `ecid`'s machine.
fn bundle_of(f: &Fixture, ecid: Option<Ecid>) -> PathBuf {
    let record = record(f);
    bundle::directory_of(
        Kind::Restore,
        &record.volume,
        &record.build,
        ecid,
        record.generation(),
    )
}

#[test]
fn setup_installs_from_the_usb_and_uninstall_restores_it() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let volume = stela_volume(&f);
    let before = (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume));
    let host = &f.host;

    // A setup installs macOS, which needs the signing opt-in.
    let mut no_tss = command(&f, &f.esp);
    no_tss.tss = false;
    let error = setup(&environment(host), no_tss).unwrap_err().to_string();
    assert!(error.contains("needs --tss"), "{error}");
    assert!(error.contains("gs.apple.com"), "{error}");
    assert_eq!(
        (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume)),
        before
    );

    let mut dry = command(&f, &f.esp);
    dry.dry_run = true;
    let plan = setup(&environment(host), dry).unwrap();
    assert!(plan.contains("Dry run: nothing was changed."), "{plan}");
    assert!(plan.contains("the disk's own recoveryOS"), "{plan}");
    assert!(plan.contains("ECID           0x"), "{plan}");
    assert!(plan.contains("restore        "), "{plan}");
    assert!(!plan.contains("recoveryOS     "), "{plan}");
    assert_eq!(
        (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume)),
        before
    );

    let report = setup(&environment(host), command(&f, &f.esp)).unwrap();
    assert!(report.contains("stela setup uninstall"), "{report}");
    assert!(report.contains("pick the PC disk"), "{report}");
    let record = record(&f);
    let ecid = record.installs[0].ecid.unwrap();
    assert_ne!(ecid.0, 0);
    let options = fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
    assert_eq!(
        options,
        format!(
            "--system --storage @disk --nor @disk --preboot @disk --ecid {ecid} \
             --external-disks --guest-network --tss\n"
        )
    );
    assert!(!options.contains("--bundle"), "{options}");
    // The only bundle is the machine's restore bundle.
    assert_eq!(record.bundles.len(), 1);
    assert_eq!(record.bundles[0].kind, Kind::Restore);
    let bundle = bundle_of(&f, Some(ecid));
    assert_eq!(
        fs::read(bundle.join("ramdisk.img")).unwrap(),
        vec![ecid.0 as u8 ^ 0xa5; 2048]
    );
    assert!(bundle::verify(&bundle, &record.bundles[0].manifest_sha256).is_empty());
    assert!(!f.esp.join("EFI/stela/source.bin").exists());
    let choices = Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    let names: Vec<&str> = choices.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["macOS", INSTALL_CHOICE]);
    assert_eq!(
        fs::read(f.esp.join(efi::LOADER)).unwrap(),
        efi_image(b"stela")
    );
    assert!(record.complete);
    assert_eq!(record.schema_version, RECORD_SCHEMA);
    // A second setup is refused until the first is undone.
    let again = setup(&environment(host), command(&f, &f.esp));
    assert!(
        again
            .unwrap_err()
            .to_string()
            .contains("stela setup uninstall")
    );
    // The only install is not removed alone.
    let error = rerun(&f, |c| {
        c.action = Action::Configure;
        c.remove_install = Some("macOS".into());
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("only one"), "{error}");

    let dry = uninstall(&environment(host), &f.esp, true).unwrap();
    assert!(dry.contains("Dry run"));
    assert!(bundle.is_dir());
    let done = uninstall(&environment(host), &f.esp, false).unwrap();
    assert!(done.contains("Done."));
    assert_eq!(
        (snapshot(&f.esp), snapshot(&f.data), snapshot(&volume)),
        before
    );
}

#[test]
fn a_stela_efi_of_another_interface_is_refused() {
    let f = fixture(64 * GIB, false);
    fs::write(&f.efi, b"MZ without a marker").unwrap();
    let error = setup(&environment(&f.host), command(&f, &f.esp))
        .unwrap_err()
        .to_string();
    assert!(error.contains("no Stela mount interface marker"), "{error}");
    let other = mount_interface::Interface {
        options_revision: mount_interface::OPTIONS_REVISION + 1,
        ..mount_interface::CURRENT
    };
    let mut image = b"MZ".to_vec();
    image.extend_from_slice(&mount_interface::marker(other));
    fs::write(&f.efi, image).unwrap();
    let error = setup(&environment(&f.host), command(&f, &f.esp))
        .unwrap_err()
        .to_string();
    assert!(error.contains("stela.cfg option revision"), "{error}");
    assert!(!f.esp.join(RECORD).exists());
}

#[test]
fn the_bundles_go_to_the_usb_s_fat32_data_partition() {
    // The firmware cannot read HFS+, so the USB has no data partition.
    let f = fixture(GIB / 32, false);
    let error = setup(&environment(&f.host), command(&f, &f.data))
        .unwrap_err()
        .to_string();
    assert!(error.contains("not FAT32"), "{error}");
    assert!(
        error.contains("boot bundles and the install medium"),
        "{error}"
    );
    // A FAT data partition holds the bundle and the online install's
    // inventory under `stela/`; the EFI partition keeps only the boot
    // loader and its configuration.
    let mut f = fixture(GIB / 32, false);
    add_stela(&mut f);
    let volume = stela_volume(&f);
    let mut online = command(&f, &volume);
    online.install_image = Some(InstallImage::Online);
    setup(&environment(&f.host), online).unwrap();
    let ecid = record(&f).installs[0].ecid;
    assert!(bundle_of(&f, ecid).join("ramdisk.img").is_file());
    assert!(bundle_of(&f, ecid).starts_with(volume.join("stela/boot")));
    assert!(volume.join("stela/install").is_dir());
    assert!(!f.esp.join("stela").exists());
    assert!(f.esp.join(efi::LOADER).is_file());
    uninstall(&environment(&f.host), &volume, false).unwrap();
    assert!(!volume.join("stela").exists());
}

#[test]
fn usbs_setup_cannot_boot_from_are_explained_and_left_unchanged() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    // A USB without an EFI partition, one whose partition is not
    // mounted, and one that already boots another loader.
    let dir = tempfile::tempdir().unwrap();
    let mut host = FakeHost::new(f.host.volumes.clone(), Vec::new());
    host.volumes
        .insert(dir.path().to_path_buf(), (FileSystem::Fat, GIB, None));
    let error = setup(&environment(&host), command(&f, dir.path()))
        .unwrap_err()
        .to_string();
    assert!(error.contains("names its whole disk"), "{error}");
    let mut host = FakeHost::new(f.host.volumes.clone(), f.host.disks.clone());
    host.partitions = f.host.partitions.clone();
    // An unmounted EFI partition is mounted, or the error says why not.
    host.disks[1].partitions[0].mount = None;
    let error = setup(&environment(&host), command(&f, &f.data))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("disk5s1, which could not be mounted"),
        "{error}"
    );
    host.mountable.insert("disk5s1".into(), f.esp.clone());
    let mut dry = command(&f, &f.data);
    dry.dry_run = true;
    let plan = setup(&environment(&host), dry).unwrap();
    assert!(plan.contains(&f.esp.display().to_string()), "{plan}");
    let loader = f.esp.join(efi::LOADER);
    fs::create_dir_all(loader.parent().unwrap()).unwrap();
    fs::write(&loader, b"MZopencore").unwrap();
    let before = snapshot(&f.esp);
    let error = setup(&environment(&f.host), command(&f, &f.esp))
        .unwrap_err()
        .to_string();
    assert!(error.contains("another loader"), "{error}");
    assert_eq!(snapshot(&f.esp), before);
    // An internal EFI partition is another system's boot partition.
    let f = fixture(64 * GIB, false);
    let mut host = FakeHost::new(f.host.volumes.clone(), f.host.disks.clone());
    host.volumes
        .insert(f.esp.clone(), (FileSystem::Fat, 64 * GIB, Some("disk0")));
    host.disks[0].partitions[0].mount = Some(f.esp.clone());
    let error = setup(&environment(&host), command(&f, &f.esp))
        .unwrap_err()
        .to_string();
    assert!(error.contains("internal disk"), "{error}");
}

#[test]
fn older_setups_are_still_read_and_undone() {
    // Schema 1, with a payload and a target.
    let f = fixture(64 * GIB, false);
    let before = snapshot(&f.esp);
    efi::add_mount(&f.esp, &f.efi, None, Some("--install-mode verify\n")).unwrap();
    let payload = f.esp.join("EFI/stela/images/26A434");
    let bundles = f.esp.join("EFI/stela/boot/26A434");
    for directory in [&payload, &bundles] {
        fs::create_dir_all(directory).unwrap();
        fs::write(directory.join("file"), b"x").unwrap();
    }
    let record = serde_json::json!({
        "schema_version": 1,
        "kind": RECORD_KIND,
        "build": "26A434",
        "model": "Mac14,3",
        "target": "the disk with serial number EMPTY2",
        "esp": f.esp,
        "payload_volume": f.esp,
        "payload_directory": payload,
        "bundle_directory": bundles,
        "created_directories": [
            f.esp.join("EFI/stela/images"),
            f.esp.join("EFI/stela/boot"),
        ],
        "options": "--install-mode verify\n",
        "complete": true,
    });
    stela_runtime::write_json(&f.esp.join(RECORD), &record).unwrap();
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert_eq!(snapshot(&f.esp), before);

    // Schema 7, with a recoveryOS bundle on the USB: this stela no longer
    // reads it, and uninstalls it.
    let f = fixture(64 * GIB, false);
    let before = snapshot(&f.esp);
    efi::add_mount(&f.esp, &f.efi, None, Some("--system\n")).unwrap();
    let build = f.esp.join("EFI/stela/boot/STELA1");
    let recovery = build.join("recovery-0000000000000001");
    let restore = build.join("restore-0000000000000001");
    bundle::tests::write(&recovery, bundle::Generation::FIRST, b"old").unwrap();
    bundle::tests::write(&restore, bundle::Generation::FIRST, b"old").unwrap();
    let disk = installed::InstalledDisk {
        apple_region: REGION.into(),
        apple_region_serial: SERIAL.into(),
        apple_region_guid: REGION_GUID.into(),
        nor: NOR.into(),
        nor_serial: SERIAL.into(),
        nor_guid: NOR_GUID.into(),
        machine_state_offset: None,
        external_disks: false,
    };
    let mut install = serde_json::to_value(&disk).unwrap();
    install["name"] = "macOS".into();
    install["ecid"] = "0x1".into();
    let record = serde_json::json!({
        "schema_version": 7,
        "kind": RECORD_KIND,
        "build": "STELA1",
        "model": "Mac14,3",
        "esp": f.esp,
        "volume": f.esp,
        "bundle_directory": build,
        "created_directories": [build, f.esp.join("EFI/stela/boot")],
        "options": "--system\n",
        "complete": true,
        "recovery_builds": ["STELA1"],
        "ecid": "0x1",
        "installs": [install],
        "bundles": [
            {"build": "STELA1", "ecid": "0x1", "schema": 1, "manifest_sha256": ""},
            {"build": "STELA1", "ecid": "0x1", "schema": 1, "manifest_sha256": "",
             "kind": "restore", "personalized": true},
        ],
    });
    stela_runtime::write_json(&f.esp.join(RECORD), &record).unwrap();
    let error = read_record(&environment(&f.host), &f.esp)
        .unwrap_err()
        .to_string();
    assert!(error.contains("schema 7 setup"), "{error}");
    assert!(error.contains("recoveryOS bundle"), "{error}");
    assert!(error.contains("stela setup uninstall"), "{error}");
    let error = rerun(&f, |c| c.action = Action::Status)
        .unwrap_err()
        .to_string();
    assert!(error.contains("no longer reads"), "{error}");
    let dry = uninstall(&environment(&f.host), &f.esp, true).unwrap();
    assert!(dry.contains("keep     install \"macOS\""), "{dry}");
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert_eq!(snapshot(&f.esp), before);

    // Schema 8, which kept the data partition's bundles, install medium
    // and translation store under `EFI/stela`: refused, and uninstalled
    // from where it wrote them.
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let volume = stela_volume(&f);
    let before = (snapshot(&f.esp), snapshot(&volume));
    efi::add_mount(&f.esp, &f.efi, None, Some("--system\n")).unwrap();
    let old = volume.join("EFI/stela");
    let build = old.join("boot/STELA1");
    bundle::tests::write(
        &build.join("restore-0000000000000001"),
        bundle::Generation::FIRST,
        b"old",
    )
    .unwrap();
    for (directory, file) in [("install/STELA1", "payload.json"), ("store", "store.cfg")] {
        fs::create_dir_all(old.join(directory)).unwrap();
        fs::write(old.join(directory).join(file), b"x").unwrap();
    }
    let mut install = serde_json::to_value(&disk).unwrap();
    install["name"] = "macOS".into();
    install["ecid"] = "0x1".into();
    let record = serde_json::json!({
        "schema_version": 8,
        "kind": RECORD_KIND,
        "build": "STELA1",
        "model": "Mac14,3",
        "esp": f.esp,
        "volume": volume,
        "bundle_directory": build,
        "created_directories": [build, old.join("boot")],
        "options": "--system\n",
        "complete": true,
        "builds": ["STELA1"],
        "installs": [install],
        "bundles": [
            {"build": "STELA1", "ecid": "0x1", "schema": 1, "manifest_sha256": "",
             "personalized": true},
        ],
        "media": [
            {"build": "STELA1", "volume": volume, "partition_guid": STELA_GUID,
             "manifest_sha256": ""},
        ],
        "translations": {"volume": volume, "pack_bytes": translations::MIN_PACK_BYTES},
    });
    stela_runtime::write_json(&f.esp.join(RECORD), &record).unwrap();
    let error = read_record(&environment(&f.host), &f.esp)
        .unwrap_err()
        .to_string();
    assert!(error.contains("under EFI/"), "{error}");
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert_eq!((snapshot(&f.esp), snapshot(&volume)), before);
    assert!(!old.join("boot").exists());
}

const REGION: &str = "disk1s2";
const NOR: &str = "disk1s3";
const REGION_GUID: &str = "5E1A0000-0000-4000-8000-000000000001";
const NOR_GUID: &str = "5E1A0000-0000-4000-8000-000000000002";
const REGION2: &str = "disk2s2";
const NOR2: &str = "disk2s3";
const REGION2_GUID: &str = "5E1A0000-0000-4000-8000-000000000003";
const NOR2_GUID: &str = "5E1A0000-0000-4000-8000-000000000004";
const SERIAL: &str = "STELAPC01";
const SERIAL2: &str = "STELAPC02";
/// Bytes of each synthetic partition image: the probe reads and a NOR.
const IMAGE_BYTES: usize = stela_runtime::pc::boot_log::PARTITION_BYTES as usize;
const MIB: u64 = 1024 * 1024;

/// Give `f`'s PC a disk (`disk1`, or `disk2` with `second`) with an
/// Apple region and a NOR partition, backed by synthetic images that
/// start with `region` and `nor`.
fn add_disk(f: &mut Fixture, second: bool, region: &[u8], nor: &[u8]) {
    add_stela(f);
    let (disk, serial, partitions) = if second {
        (
            "disk2",
            SERIAL2,
            [(REGION2, REGION2_GUID, region), (NOR2, NOR2_GUID, nor)],
        )
    } else {
        (
            "disk1",
            SERIAL,
            [(REGION, REGION_GUID, region), (NOR, NOR_GUID, nor)],
        )
    };
    for ((identifier, guid, head), bytes) in partitions.into_iter().zip([100 * GIB, 256 * MIB]) {
        let path = f._dir.path().join(format!("{identifier}.img"));
        let mut image = vec![0u8; IMAGE_BYTES];
        image[..head.len()].copy_from_slice(head);
        fs::write(&path, image).unwrap();
        let info = PartitionInfo {
            identifier: identifier.into(),
            disk: disk.into(),
            guid: guid.to_ascii_lowercase(),
            bytes,
            content: "Apple_APFS".into(),
            mount: None,
            container: None,
        };
        f.host.partitions.insert(identifier.into(), (info, path));
    }
    f.host.serials.insert(disk.into(), serial.into());
}

fn add_installed_disk(f: &mut Fixture, region: &[u8], nor: &[u8]) {
    add_disk(f, false, region, nor);
}

fn installed_command(f: &Fixture) -> Request {
    let mut command = command(f, &f.esp);
    command.target = Some(REGION.into());
    command.nor = Some(NOR.into());
    command.tss = true;
    command
}

/// The USB's FAT32 data partition, which holds the install medium.
const STELA_PARTITION: &str = "disk5s3";
const STELA_GUID: &str = "5E1A0000-0000-4000-8000-0000000000aa";

fn stela_volume(f: &Fixture) -> PathBuf {
    f._dir.path().join("STELA")
}

/// Give the USB its FAT32 data partition, once.
fn add_stela(f: &mut Fixture) {
    let volume = stela_volume(f);
    if volume.exists() {
        return;
    }
    fs::create_dir_all(&volume).unwrap();
    f.host
        .volumes
        .insert(volume.clone(), (FileSystem::Fat, 100 * GIB, Some("disk5")));
    let usb = f
        .host
        .disks
        .iter_mut()
        .find(|d| d.identifier == "disk5")
        .unwrap();
    usb.partitions.push(Partition {
        identifier: STELA_PARTITION.into(),
        content: "Microsoft Basic Data".into(),
        mount: Some(volume.clone()),
    });
    let info = PartitionInfo {
        identifier: STELA_PARTITION.into(),
        disk: "disk5".into(),
        guid: STELA_GUID.into(),
        bytes: 100 * GIB,
        content: "Microsoft Basic Data".into(),
        mount: Some(volume.clone()),
        container: None,
    };
    let image = f._dir.path().join("stela-partition.img");
    f.host
        .partitions
        .insert(STELA_PARTITION.into(), (info, image));
}

fn partition_bytes(f: &Fixture, identifier: &str) -> Vec<u8> {
    fs::read(f.host.image(identifier).unwrap()).unwrap()
}

fn nvram_of(f: &Fixture, nor: &str) -> Variables {
    let bytes = partition_bytes(f, nor)[..stela_runtime::machine::apple::nor::CAPACITY].to_vec();
    let image = stela_runtime::machine::apple::nor::Image::from_bytes(bytes).unwrap();
    Variables::parse(image.bank(image.current_bank().unwrap()).unwrap()).unwrap()
}

fn nvram(f: &Fixture) -> Variables {
    nvram_of(f, NOR)
}

/// Give the USB an unmounted raw partition, as the Mac's internal SSD.
fn add_stick_ssd(f: &mut Fixture, identifier: &str, guid: &str) {
    add_stela(f);
    let usb = f
        .host
        .disks
        .iter_mut()
        .find(|d| d.identifier == "disk5")
        .unwrap();
    usb.partitions.push(Partition {
        identifier: identifier.into(),
        content: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF".into(),
        mount: None,
    });
    // Sparse, as large as the partition: the machine state is its tail.
    let path = f._dir.path().join(format!("{identifier}.img"));
    fs::File::create(&path).unwrap().set_len(100 * GIB).unwrap();
    let info = PartitionInfo {
        identifier: identifier.into(),
        disk: "disk5".into(),
        guid: guid.to_ascii_lowercase(),
        bytes: 100 * GIB,
        content: "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF".into(),
        mount: None,
        container: None,
    };
    f.host.partitions.insert(identifier.into(), (info, path));
    f.host.serials.insert("disk5".into(), "STICK01".into());
}

#[test]
fn a_raw_partition_of_the_usb_is_the_macs_ssd_and_the_pc_disks_external() {
    let mut f = fixture(64 * GIB, false);
    add_stick_ssd(&mut f, "disk5s4", REGION_GUID);
    let mut no_tss = command(&f, &f.esp);
    no_tss.tss = false;
    let error = setup(&environment(&f.host), no_tss)
        .unwrap_err()
        .to_string();
    assert!(error.contains("needs --tss"), "{error}");
    let mut opted = command(&f, &f.esp);
    opted.tss = true;
    let report = setup(&environment(&f.host), opted).unwrap();
    assert!(report.contains("external drives"), "{report}");
    let record = record(&f);
    assert!(record.tss);
    let disk = &record.installs[0].disk;
    assert_eq!(disk.apple_region, "disk5s4");
    assert!(disk.external_disks);
    let options = fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
    assert!(
        options.contains(&format!("--storage STICK01:{REGION_GUID}")),
        "{options}"
    );
    assert!(options.contains("--external-disks"), "{options}");
    let choices = fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
    let install = choices
        .lines()
        .find(|line| line.starts_with(INSTALL_CHOICE))
        .unwrap();
    assert!(install.contains("--development-restore"), "{install}");
    assert!(install.contains("--tss"), "{install}");

    // Two raw partitions name no one internal SSD.
    let mut f = fixture(64 * GIB, false);
    add_stick_ssd(&mut f, "disk5s4", REGION_GUID);
    add_stick_ssd(&mut f, "disk5s5", REGION2_GUID);
    let mut opted = command(&f, &f.esp);
    opted.tss = true;
    let error = setup(&environment(&f.host), opted).unwrap_err().to_string();
    assert!(error.contains("several unmounted partitions"), "{error}");
}

#[test]
fn a_whole_usb_disk_is_erased_first_and_an_internal_one_refused() {
    let f = fixture(64 * GIB, true);
    let whole = |usb: &str| f.host.whole_disk(Path::new(usb)).unwrap();
    assert_eq!(whole("/dev/disk5").as_deref(), Some("disk5"));
    assert_eq!(whole("disk0").as_deref(), Some("disk0"));
    let esp = f.esp.to_str().unwrap();
    for volume in [
        esp,
        "/Volumes/STELA",
        "disk5s1",
        "disk",
        "/dev/rdisk5",
        "disk12",
    ] {
        assert_eq!(whole(volume), None, "{volume}");
    }
    let mut dry = command(&f, Path::new("disk5"));
    dry.dry_run = true;
    let report = setup(&environment(&f.host), dry).unwrap();
    assert!(report.contains("would erase disk5"), "{report}");
    let mut internal = command(&f, Path::new("disk0"));
    internal.dry_run = true;
    let error = setup(&environment(&f.host), internal)
        .unwrap_err()
        .to_string();
    assert!(error.contains("internal disk"), "{error}");
    // An SD card is erased only with its model or size typed back.
    let mut host = FakeHost::new(f.host.volumes.clone(), f.host.disks.clone());
    host.disks.push(disk("disk6", &[]));
    let mut card = command(&f, Path::new("disk6"));
    card.dry_run = true;
    let error = setup(&environment(&host), card).unwrap_err().to_string();
    assert!(error.contains("--confirm-disk"), "{error}");
    for typed in ["Disk disk6", "137.4 GB"] {
        let mut card = command(&f, Path::new("disk6"));
        card.dry_run = true;
        card.confirm_disk = Some(typed.into());
        let report = setup(&environment(&host), card).unwrap();
        assert!(report.contains("would erase disk6"), "{report}");
    }
    // Without an image, the USB is left as it was: no erase is tried.
    let mut no_image = command(&f, Path::new("disk5"));
    no_image.ipsw = None;
    let error = setup(&environment(&f.host), no_image)
        .unwrap_err()
        .to_string();
    assert!(error.contains("pass --ipsw"), "{error}");
}

#[test]
fn portable_usb_preparation_refuses_signing_failures_and_small_disks_before_erase() {
    let mut f = fixture(64 * GIB, true);
    let before = (snapshot(&f.esp), snapshot(&f.data));
    let mut opted = command(&f, Path::new("disk5"));
    opted.tss = true;
    let fail = |_: &Path, _: &str, _: Option<Ecid>, _: bool, _: &Path| {
        bail!("signing service unavailable")
    };
    let env = Environment {
        prepare_restore: &fail,
        ..environment(&f.host)
    };
    let error = setup(&env, opted).unwrap_err();
    assert!(format!("{error:#}").contains("signing service unavailable"));
    assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);

    f.host
        .disks
        .iter_mut()
        .find(|d| d.identifier == "disk5")
        .unwrap()
        .bytes = 1;
    let mut opted = command(&f, Path::new("disk5"));
    opted.tss = true;
    let error = setup(&environment(&f.host), opted).unwrap_err();
    assert!(
        error.to_string().contains("USB needs at least"),
        "{error:#}"
    );
    assert_eq!((snapshot(&f.esp), snapshot(&f.data)), before);
}

#[test]
fn a_usb_replaced_while_preparing_is_refused_even_at_the_same_disk_number() {
    let mut f = fixture(64 * GIB, true);
    f.host.serials.insert("disk5".into(), "original".into());
    let selected = wizard::Usb::from_disk(&f.host.disks[1], &f.host);
    selected.verify(&f.host).unwrap();
    f.host.serials.insert("disk5".into(), "replacement".into());
    assert!(selected.verify(&f.host).is_err());
    f.host.serials.insert("disk5".into(), "original".into());
    f.host.disks[1].system = true;
    assert!(selected.verify(&f.host).is_err());
    f.host.disks.pop();
    assert!(selected.verify(&f.host).is_err());
}

#[test]
fn a_signing_setup_without_a_target_installs_on_the_disk_chosen_in_stela_efi() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    // The authoring computer need not have the target's CPU features.
    f.host.cpu.entropy = false;
    let mut opted = command(&f, &f.esp);
    opted.tss = true;
    let report = setup(&environment(&f.host), opted).unwrap();
    assert!(report.contains("pick the PC disk"), "{report}");
    let record = record(&f);
    assert!(record.installs[0].disk.is_chosen());
    let medium = record.active_medium().unwrap();
    assert!(!medium.remote && medium.problems().is_empty(), "{medium:?}");
    let choices = fs::read_to_string(f.esp.join("EFI/stela/choices.cfg")).unwrap();
    let install = choices
        .lines()
        .find(|line| line.starts_with(INSTALL_CHOICE))
        .unwrap();
    assert!(install.contains("--storage @disk --nor @disk"), "{install}");
    assert!(
        install.contains(&format!("--install {}", medium.firmware_manifest())),
        "{install}"
    );
    assert!(install.contains("--install-source"), "{install}");
    let mut joined = Vec::new();
    for index in 0.. {
        let piece = medium
            .directory()
            .join(stela_runtime::payload::piece_name(index));
        let Ok(bytes) = fs::read(piece) else { break };
        joined.extend(bytes);
    }
    assert_eq!(joined, fs::read(&f.ipsw).unwrap());
    let options = fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
    assert!(options.contains("--preboot @disk"), "{options}");
    // This computer never reaches the chosen disk's machine state.
    let error = rerun(&f, |c| c.action = Action::ResetNvram)
        .unwrap_err()
        .to_string();
    assert!(error.contains("chosen in stela.efi"), "{error}");
}

fn rerun(f: &Fixture, configure: impl Fn(&mut Request)) -> Result<String> {
    let mut command = command(f, &f.esp);
    command.ipsw = None;
    command.model = None;
    // Commands on an existing setup leave the opt-in as it is.
    command.tss = false;
    configure(&mut command);
    command.dispatch(&environment(&f.host))
}

#[test]
fn another_file_system_on_a_target_is_unmounted_and_erased_now_and_on_repair() {
    let mut apfs = vec![0u8; 64];
    apfs[32..36].copy_from_slice(b"NXSB");
    let erased = |f: &Fixture| {
        fs::read(&f.host.partitions[REGION].1).unwrap()[..IMAGE_BYTES / 2]
            .iter()
            .all(|&byte| byte == 0)
    };
    // A mounted container is refused, and with --erase-target setup
    // unmounts and erases it, so the PC's OS stops mounting it.
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &apfs, &[]);
    f.host.partitions.get_mut(REGION).unwrap().0.container = Some("disk9".into());
    let error = setup(&environment(&f.host), installed_command(&f))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("--erase-target, which unmounts and erases"),
        "{error}"
    );
    let mut erase = installed_command(&f);
    erase.erase_target = true;
    setup(&environment(&f.host), erase).unwrap();
    assert_eq!(*f.host.unmounted.borrow(), [REGION]);
    assert!(erased(&f));
    // One an existing install's region gains is a problem `status`
    // names and `repair --erase-target` erases.
    let path = f.host.partitions[REGION].1.clone();
    let mut image = fs::read(&path).unwrap();
    image[..apfs.len()].copy_from_slice(&apfs);
    fs::write(&path, image).unwrap();
    let error = rerun(&f, |c| c.action = Action::Status)
        .unwrap_err()
        .to_string();
    assert!(error.contains("holds another file system"), "{error}");
    let report = rerun(&f, |c| c.action = Action::Repair).unwrap();
    assert!(
        report.contains("pass --erase-target to erase it"),
        "{report}"
    );
    assert!(!erased(&f));
    rerun(&f, |c| {
        c.action = Action::Repair;
        c.erase_target = true;
    })
    .unwrap();
    assert!(erased(&f));
}

#[test]
fn an_install_reads_the_image_from_the_usb_offline_or_streams_it_online() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    // Online: the USB holds the inventory alone, and the Install choice
    // names no partition to read the IPSW from.
    let mut online = installed_command(&f);
    online.install_image = Some(InstallImage::Online);
    let report = setup(&environment(&f.host), online).unwrap();
    assert!(report.contains("streaming the restore image"), "{report}");
    let written = record(&f);
    assert_eq!(written.install_image, Some(InstallImage::Online));
    let medium = written.active_medium().cloned().unwrap();
    assert!(medium.remote && medium.problems().is_empty(), "{medium:?}");
    let choices = fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
    let install = choices
        .lines()
        .find(|line| line.starts_with(INSTALL_CHOICE))
        .unwrap();
    assert!(
        install.contains(&format!("--install {}", medium.firmware_manifest())),
        "{install}"
    );
    assert!(!install.contains("--install-source"), "{install}");
    // The choice is the setup's.
    let error = rerun(&f, |c| c.install_image = Some(InstallImage::Offline))
        .unwrap_err()
        .to_string();
    assert!(error.contains("--install-image goes with"), "{error}");
    // Repair turns it offline: the IPSW in pieces on the USB.
    let switch = |image| {
        rerun(&f, |c| {
            c.action = Action::Repair;
            c.ipsw = Some(f.ipsw.clone());
            c.install_image = Some(image);
        })
        .unwrap();
        record(&f).active_medium().cloned().unwrap()
    };
    let offline = switch(InstallImage::Offline);
    assert!(
        !offline.remote && offline.problems().is_empty(),
        "{offline:?}"
    );
    let first_piece = offline
        .directory()
        .join(stela_runtime::payload::piece_name(0));
    assert!(first_piece.is_file());
    // Back online, the pieces go.
    let online = switch(InstallImage::Online);
    assert!(online.remote && online.problems().is_empty(), "{online:?}");
    assert!(!first_piece.exists());
}

#[test]
fn an_offline_install_needs_the_system_image_a_recovery_archive_leaves_out() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    let recovery = f._dir.path().join("Recovery.ipsw");
    restore::payload::trim(
        fs::File::open(&f.ipsw).unwrap(),
        restore::payload::SYNTHETIC_MODEL,
        &recovery,
    )
    .unwrap();
    assert!(restore::payload::holds_system_image(&f.ipsw).unwrap());
    assert!(!restore::payload::holds_system_image(&recovery).unwrap());
    let mut offline = installed_command(&f);
    offline.ipsw = Some(recovery.clone());
    offline.install_image = Some(InstallImage::Offline);
    offline.dry_run = true;
    let error = format!("{:#}", setup(&environment(&f.host), offline).unwrap_err());
    assert!(error.contains("only the recovery members"), "{error}");
    // By default such an image streams the install instead.
    let mut default = installed_command(&f);
    default.ipsw = Some(recovery);
    setup(&environment(&f.host), default).unwrap();
    let record = record(&f);
    assert_eq!(record.install_image, None);
    assert!(record.active_medium().unwrap().remote);
}

#[test]
fn an_installed_disk_boots_macos_or_recoveryos_and_keeps_its_partitions() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    let before = snapshot(&f.esp);
    let stela_before = snapshot(&stela_volume(&f));
    let disks = (partition_bytes(&f, REGION), partition_bytes(&f, NOR));

    // A local image does not remove the signing requirement. Refuse
    // before writing the USB or either target partition.
    let mut no_tss = installed_command(&f);
    no_tss.tss = false;
    let error = setup(&environment(&f.host), no_tss)
        .unwrap_err()
        .to_string();
    assert!(error.contains("needs --tss"), "{error}");
    assert!(error.contains("gs.apple.com"), "{error}");
    assert_eq!(snapshot(&f.esp), before);

    let mut dry = installed_command(&f);
    dry.dry_run = true;
    let plan = setup(&environment(&f.host), dry).unwrap();
    assert!(plan.contains("install medium "), "{plan}");
    assert!(plan.contains(STELA_GUID), "{plan}");
    assert!(plan.contains("restore        "), "{plan}");
    assert_eq!(snapshot(&stela_volume(&f)), stela_before);
    assert!(
        plan.contains("Apple region   disk1s2 (serial STELAPC01"),
        "{plan}"
    );
    assert!(plan.contains("is blank: install macOS onto it"), "{plan}");
    assert!(plan.contains("Dry run"), "{plan}");
    assert_eq!(snapshot(&f.esp), before);

    let mut tss = installed_command(&f);
    tss.tss = true;
    let report = setup(&environment(&f.host), tss).unwrap();
    assert!(report.contains("gs.apple.com"), "{report}");
    let record = record(&f);
    let ecid = record.installs[0].ecid.unwrap();
    // The restore boots under the ticket Apple personalized for it.
    assert!(
        record
            .restore_bundle(Kind::Restore, Some(ecid))
            .is_some_and(|b| b.personalized)
    );
    let region = format!("{SERIAL}:{REGION_GUID}");
    let line = format!(
        "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --preboot {region} \
         --ecid {ecid} --tss"
    );
    assert_eq!(
        fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
        format!("{line}\n")
    );
    // The startup choices hold the install and Install macOS, and open
    // on their own.
    let choices = Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    assert_eq!(choices.timeout_seconds, CHOOSER_SECONDS);
    assert_eq!(choices.entries.len(), 2);
    assert_eq!(choices.entries[0].name, "macOS");
    assert_eq!(choices.entries[0].options, line);
    // stela.efi routes a disk without an installed system to the disk's
    // System Recovery, and refuses one that holds none.
    let mut selection = stela_loader::boot_selection::select(
        &Variables::parse(&stela_runtime::machine::apple::nor::nvram::empty_bank()).unwrap(),
    )
    .unwrap();
    selection.missing_boot_media();
    assert!(stela_loader::boot_selection::route(&line, Some(&selection)).is_err());
    selection.system_on_disk = true;
    let (routed, _) = stela_loader::boot_selection::route(&line, Some(&selection)).unwrap();
    assert!(routed.contains(&format!("--preboot {region}")), "{routed}");
    assert!(routed.ends_with("--system-recovery"), "{routed}");
    // Install macOS restores the install medium onto the disk
    // with the machine's restore bundle.
    let build = restore::payload::SYNTHETIC_BUILD;
    assert_eq!(choices.entries[1].name, INSTALL_CHOICE);
    assert_eq!(
        choices.entries[1].options,
        format!(
            "--system --storage {region} --nor {SERIAL}:{NOR_GUID} --bundle \
             \\stela\\boot\\{build}\\{} --ecid {ecid} \
             --install \\stela\\install\\{build}\\payload.json --install-source \
             {} --development-restore --tss",
            bundle::leaf_of(Kind::Restore, Some(ecid), current()),
            STELA_GUID.to_ascii_uppercase()
        )
    );
    let restore_bundle = record.restore_bundle(Kind::Restore, Some(ecid)).unwrap();
    assert!(
        bundle::verify(
            &restore_bundle.directory(&record.volume),
            &restore_bundle.manifest_sha256
        )
        .is_empty()
    );
    // The medium is the IPSW in pieces on the USB's FAT32 partition.
    let medium = record.active_medium().cloned().unwrap();
    assert_eq!(
        (medium.volume.as_path(), medium.partition_guid.as_str()),
        (stela_volume(&f).as_path(), STELA_GUID)
    );
    assert!(medium.problems().is_empty());
    let mut joined = Vec::new();
    for index in 0.. {
        let piece = medium
            .directory()
            .join(stela_runtime::payload::piece_name(index));
        let Ok(bytes) = fs::read(piece) else { break };
        joined.extend(bytes);
    }
    assert_eq!(joined, fs::read(&f.ipsw).unwrap());
    // Status finds a damaged piece by name.
    let first = medium
        .directory()
        .join(stela_runtime::payload::piece_name(0));
    let piece = fs::read(&first).unwrap();
    fs::write(&first, &piece[1..]).unwrap();
    let status = format!(
        "{:#}",
        rerun(&f, |c| c.action = Action::Status).unwrap_err()
    );
    assert!(status.contains("ipsw.000 holds"), "{status}");
    fs::write(&first, &piece).unwrap();
    // --verify-on-read is the engine's, on the Install choice alone.
    let mut verify = record.clone();
    verify.verify_on_read = true;
    let line = verify.install_line(&verify.installs[0]).unwrap().unwrap();
    assert!(line.contains("--install-source"), "{line}");
    assert!(
        line.trim_end()
            .ends_with("--verify-on-read --development-restore --tss"),
        "{line}"
    );
    // Setup itself writes neither partition.
    assert_eq!(
        (partition_bytes(&f, REGION), partition_bytes(&f, NOR)),
        disks
    );
    // Turning the signing opt-in off removes the Install choice.
    let off = rerun(&f, |c| {
        c.action = Action::Configure;
        c.no_tss = true;
    })
    .unwrap();
    assert!(off.contains("TSS/FDR        off"), "{off}");
    assert!(
        !fs::read_to_string(f.esp.join("EFI/stela/stela.cfg"))
            .unwrap()
            .contains("--tss")
    );
    let choices = Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    assert_eq!(choices.entries.len(), 1);
    // Its personalized restore bundle no longer serves the setup.
    let off = self::record(&f);
    assert_eq!(
        off.restore_bundle(Kind::Restore, off.installs[0].ecid),
        None
    );
    assert_eq!(off.missing_restore_bundles().len(), 1);

    // The engine profile turns on for every choice, and off again.
    let on = rerun(&f, |c| {
        c.action = Action::Configure;
        c.profile = true;
    })
    .unwrap();
    assert!(on.contains("profile        on"), "{on}");
    let config = || fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap();
    assert!(config().trim_end().ends_with("--profile"), "{}", config());
    let choices = Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    assert!(
        choices
            .entries
            .iter()
            .all(|e| e.options.ends_with("--profile"))
    );
    rerun(&f, |c| {
        c.action = Action::Configure;
        c.no_profile = true;
    })
    .unwrap();
    assert!(!config().contains("--profile"));

    // The next boot is chosen in NVRAM, which a dry run leaves alone.
    let dry = rerun(&f, |c| {
        c.action = Action::NextBoot(NextBoot::Recovery);
        c.dry_run = true;
    })
    .unwrap();
    assert!(
        dry.contains("one-time-boot-command=recover-system"),
        "{dry}"
    );
    assert_eq!(partition_bytes(&f, NOR), disks.1);
    rerun(&f, |c| c.action = Action::NextBoot(NextBoot::Recovery)).unwrap();
    let variables = nvram(&f);
    assert_eq!(
        stela_loader::boot_selection::select(&variables)
            .unwrap()
            .target,
        stela_loader::boot_selection::Target::SystemRecovery
    );
    rerun(&f, |c| c.action = Action::NextBoot(NextBoot::Macos)).unwrap();
    assert_eq!(
        stela_loader::boot_selection::select(&nvram(&f))
            .unwrap()
            .target,
        stela_loader::boot_selection::Target::MacOs { safe: false }
    );
    // A partition whose GUID is no longer the recorded one is not
    // written: its identifier now names another partition.
    let nor = partition_bytes(&f, NOR);
    f.host.partitions.get_mut(NOR).unwrap().0.guid = REGION2_GUID.into();
    let error = rerun(&f, |c| c.action = Action::NextBoot(NextBoot::Recovery))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not this install's NOR partition"),
        "{error}"
    );
    assert_eq!(partition_bytes(&f, NOR), nor);
    f.host.partitions.get_mut(NOR).unwrap().0.guid = NOR_GUID.to_ascii_lowercase();

    // Uninstall restores the USB and keeps the installed disk and NVRAM.
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert_eq!(snapshot(&f.esp), before);
    assert_eq!(snapshot(&stela_volume(&f)), stela_before);
    assert!(!stela_volume(&f).join("stela").exists());
    assert_eq!(partition_bytes(&f, REGION), disks.0);
    assert_eq!(partition_bytes(&f, NOR), nor);
}

#[test]
fn installed_disks_that_would_lose_data_or_cannot_boot_are_refused() {
    let refusal = |f: &Fixture, configure: &dyn Fn(&mut Request)| {
        let mut command = installed_command(f);
        configure(&mut command);
        setup(&environment(&f.host), command)
            .unwrap_err()
            .to_string()
    };
    // An Apple region with another file system needs --erase-target.
    let mut apfs = vec![0u8; 64];
    apfs[32..36].copy_from_slice(b"NXSB");
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &apfs, &[]);
    assert!(refusal(&f, &|_| {}).contains("--erase-target"));
    let mut dry = installed_command(&f);
    dry.erase_target = true;
    dry.dry_run = true;
    let plan = setup(&environment(&f.host), dry).unwrap();
    assert!(plan.contains("setup erases (--erase-target)"), "{plan}");
    // A NOR partition with other bytes needs --initialize-nor.
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], b"not a NOR image");
    assert!(refusal(&f, &|_| {}).contains("--initialize-nor"));
    let mut initialize = installed_command(&f);
    initialize.initialize_nor = true;
    setup(&environment(&f.host), initialize).unwrap();
    assert_eq!(
        stela_loader::boot_selection::select(&nvram(&f))
            .unwrap()
            .target,
        stela_loader::boot_selection::Target::MacOs { safe: false }
    );
    // So does a SEP area after the NOR image that holds other bytes; the
    // flag blanks it and keeps the NOR image.
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    let capacity = stela_runtime::machine::apple::nor::CAPACITY;
    let path = f.host.partitions[NOR].1.clone();
    let mut image = fs::read(&path).unwrap();
    image[capacity..capacity + 8].copy_from_slice(b"not SEP!");
    fs::write(&path, image).unwrap();
    assert!(refusal(&f, &|_| {}).contains("--initialize-nor"));
    let mut initialize = installed_command(&f);
    initialize.initialize_nor = true;
    setup(&environment(&f.host), initialize).unwrap();
    let bytes = partition_bytes(&f, NOR);
    assert!(bytes[capacity..].iter().all(|&b| b == 0));
    assert!(bytes[..capacity].iter().all(|&b| b == 0));
    // A guest disk is kept and booted.
    let mut gpt = vec![0u8; 520];
    gpt[512..520].copy_from_slice(b"EFI PART");
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &gpt, &[]);
    let mut dry = installed_command(&f);
    dry.dry_run = true;
    assert!(
        setup(&environment(&f.host), dry)
            .unwrap()
            .contains("already holds a guest disk")
    );
    // Mounted or in-use partitions, the PC's limits and serials.
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    f.host.partitions.get_mut(REGION).unwrap().0.container = Some("disk4".into());
    assert!(refusal(&f, &|_| {}).contains("APFS container disk4"));
    f.host.partitions.get_mut(REGION).unwrap().0.container = None;
    f.host.partitions.get_mut(NOR).unwrap().0.mount = Some("/Volumes/x".into());
    assert!(refusal(&f, &|_| {}).contains("is mounted"));
    f.host.partitions.get_mut(NOR).unwrap().0.mount = None;
    assert!(refusal(&f, &|c| c.nor = Some(REGION.into())).contains("two partitions"));
    f.host.cpu.entropy = false;
    assert!(refusal(&f, &|_| {}).contains("RDSEED"));
    f.host.cpu.entropy = true;
    assert!(refusal(&f, &|c| c.disk_serial = Some("OTHER".into())).contains("reports serial"));
    f.host.serials.clear();
    assert!(refusal(&f, &|_| {}).contains("--disk-serial"));
    let mut given = installed_command(&f);
    given.disk_serial = Some(SERIAL.into());
    given.dry_run = true;
    setup(&environment(&f.host), given).unwrap();
    // Nothing was written by any refusal.
    assert!(!f.esp.join(RECORD).exists());
}

/// A SEP roots record, as the SEP model provisions one.
fn provision_sep(f: &Fixture, nor: &str) {
    let capacity = stela_runtime::machine::apple::nor::CAPACITY;
    let path = f.host.partitions[nor].1.clone();
    let mut image = fs::read(&path).unwrap();
    let mut record = vec![0u8; 8 + 2 * 32];
    record[..8].copy_from_slice(b"STSEPR01");
    record[8..].fill(0x42);
    use sha2::{Digest, Sha256};
    let sum = Sha256::digest(&record);
    record.extend_from_slice(&sum);
    image[capacity..capacity + record.len()].copy_from_slice(&record);
    fs::write(&path, image).unwrap();
    assert_eq!(
        stela_runtime::machine::apple::sep_state::blank(
            &partition_bytes(f, nor)
                [capacity..capacity + stela_runtime::machine::apple::sep_state::ROOTS_BYTES]
        ),
        Ok(false)
    );
}

#[test]
fn machine_state_of_an_earlier_machine_keeps_its_ecid() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    provision_sep(&f, NOR);
    let error = setup(&environment(&f.host), installed_command(&f))
        .unwrap_err()
        .to_string();
    assert!(error.contains("--ecid"), "{error}");
    let mut known = installed_command(&f);
    known.ecid = Some(Ecid(0x1234));
    setup(&environment(&f.host), known).unwrap();
    assert_eq!(record(&f).installs[0].ecid, Some(Ecid(0x1234)));
    assert!(bundle_of(&f, Some(Ecid(0x1234))).is_dir());
}

#[test]
fn a_second_disk_is_a_second_machine_chosen_at_startup() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    add_disk(&mut f, true, &[], &[]);
    setup(&environment(&f.host), installed_command(&f)).unwrap();
    let record1 = record(&f);
    let first = record1.installs[0].ecid.unwrap();
    let kinds: Vec<Kind> = record1.bundles.iter().map(|b| b.kind).collect();
    assert_eq!(kinds, [Kind::Restore]);
    assert!(record1.active_medium().unwrap().problems().is_empty());
    let add = |target: &str, nor: &str, ipsw: bool, dry_run: bool| {
        rerun(&f, |c| {
            c.target = Some(target.into());
            c.nor = Some(nor.into());
            c.ipsw = ipsw.then(|| f.ipsw.clone());
            c.dry_run = dry_run;
            c.tss = true;
        })
    };
    // The second is a new machine and needs its own bundle, which it
    // restores with from the IPSW.
    let error = add(REGION2, NOR2, false, false).unwrap_err().to_string();
    assert!(error.contains("is installed from the macOS"), "{error}");
    let before = snapshot(&f.esp);
    assert!(add(REGION2, NOR2, true, true).unwrap().contains("Dry run"));
    assert_eq!(snapshot(&f.esp), before);
    add(REGION2, NOR2, true, false).unwrap();
    let record2 = record(&f);
    let second = record2.installs[1].ecid.unwrap();
    assert_ne!(second, first);
    assert_eq!(record2.installs[1].name, "macOS 2");
    assert_eq!(
        fs::read(bundle_of(&f, Some(second)).join("ramdisk.img")).unwrap(),
        vec![second.0 as u8 ^ 0xa5; 2048]
    );
    // The same partitions are not added twice.
    assert!(
        add(REGION2, NOR2, true, false)
            .unwrap_err()
            .to_string()
            .contains("already belongs")
    );
    let choices =
        || Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    assert_eq!(choices().timeout_seconds, CHOOSER_SECONDS);
    let names: Vec<String> = choices().entries.into_iter().map(|e| e.name).collect();
    assert_eq!(
        names,
        [
            "macOS",
            "macOS - Install macOS",
            "macOS 2",
            "macOS 2 - Install macOS"
        ]
    );
    // Each install restores with its own machine's restore bundle.
    let restore2 = bundle::directory_of(
        Kind::Restore,
        &record2.volume,
        &record2.build,
        Some(second),
        record2.generation(),
    );
    assert!(choices().entries[3].options.contains(&format!(
        "--bundle \\stela\\boot\\{}\\restore-{}",
        record2.build,
        second.digits()
    )));
    // The default moves, and stela.cfg with it.
    rerun(&f, |c| {
        c.action = Action::Configure;
        c.default_install = Some("macOS 2".into());
    })
    .unwrap();
    assert_eq!(choices().entries[0].name, "macOS 2");
    assert!(
        fs::read_to_string(f.esp.join("EFI/stela/stela.cfg"))
            .unwrap()
            .contains(&format!("{SERIAL2}:{NOR2_GUID}"))
    );
    // Each install's next boot is its own NVRAM.
    rerun(&f, |c| {
        c.action = Action::NextBoot(NextBoot::Recovery);
        c.install = Some("macOS".into());
    })
    .unwrap();
    assert_eq!(
        stela_loader::boot_selection::select(&nvram_of(&f, NOR))
            .unwrap()
            .target,
        stela_loader::boot_selection::Target::SystemRecovery
    );
    assert!(partition_bytes(&f, NOR2).iter().all(|&b| b == 0));
    // A model other than the setup's is refused for an install.
    let mut f2 = rerun(&f, |c| {
        c.target = Some(REGION2.into());
        c.nor = Some(NOR2.into());
        c.model = Some("Mac14,2".into());
    })
    .unwrap_err()
    .to_string();
    assert!(f2.contains("same model"), "{f2}");
    // Removing an install keeps its partitions and drops its bundle.
    let nor2 = partition_bytes(&f, NOR2);
    f2 = rerun(&f, |c| {
        c.action = Action::Configure;
        c.remove_install = Some("macOS 2".into());
    })
    .unwrap();
    assert!(f2.contains(&format!("--ecid {second}")), "{f2}");
    assert!(!bundle_of(&f, Some(second)).exists());
    assert!(!restore2.exists());
    assert_eq!(partition_bytes(&f, NOR2), nor2);
    // The list still opens on its own while the USB can install macOS.
    assert_eq!(choices().timeout_seconds, CHOOSER_SECONDS);
    assert_eq!(choices().entries[1].name, INSTALL_CHOICE);
    assert_eq!(record(&f).installs.len(), 1);
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert!(!f.esp.join("EFI/stela").exists());
}

#[test]
fn same_stela_update_replenishes_only_the_cache_and_preserves_custom_options() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let mut first = command(&f, &f.esp);
    first.translation_store_bytes = Some(translations::MIN_PACK_BYTES);
    setup(&environment(&f.host), first).unwrap();
    let store = record(&f).translations.unwrap();
    let spare = store.directory().join(translations::SPARE);
    fs::remove_file(&spare).unwrap();
    let pack = translations::tests::write_pack(&store.directory(), [4; 32], 100);
    let pack_bytes = fs::read(&pack).unwrap();
    let options = f.esp.join(efi::OPTIONS);
    let custom = b"--system --watch 0x1000,0x10\n";
    fs::write(&options, custom).unwrap();
    let before_record = fs::read(f.esp.join(RECORD)).unwrap();
    let before_efi = fs::read(f.esp.join(efi::LOADER)).unwrap();
    let update = |dry_run| {
        rerun(&f, |c| {
            c.action = Action::UpdateStela;
            c.dry_run = dry_run;
        })
    };
    assert!(update(true).unwrap().contains("Dry run"));
    assert!(!spare.exists());
    assert_eq!(fs::read(&options).unwrap(), custom);
    assert!(update(false).unwrap().contains("prepare the cache"));
    assert_eq!(fs::metadata(&spare).unwrap().len(), store.pack_bytes);
    assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
    assert_eq!(fs::read(&options).unwrap(), custom);
    assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_record);
    assert_eq!(fs::read(f.esp.join(efi::LOADER)).unwrap(), before_efi);
    // Retry after a partial allocation repairs the spare without an update.
    fs::write(&spare, [0; 64]).unwrap();
    fs::remove_file(store.directory().join(translations::CONFIG)).unwrap();
    update(false).unwrap();
    assert!(store.config_intact() && store.spare_ready());
    assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
    assert_eq!(fs::read(&options).unwrap(), custom);
    assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_record);
    assert!(update(false).unwrap().contains("already installed"));
}

#[test]
fn cache_spare_failure_blocks_efi_activation_and_update_or_rollback_can_retry() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let mut first = command(&f, &f.esp);
    first.translation_store_bytes = Some(translations::MIN_PACK_BYTES);
    setup(&environment(&f.host), first).unwrap();
    let store = record(&f).translations.unwrap();
    let spare = store.directory().join(translations::SPARE);
    let pack = translations::tests::write_pack(&store.directory(), [4; 32], 100);
    let pack_bytes = fs::read(&pack).unwrap();
    let active = f.esp.join(efi::LOADER);
    let old_efi = fs::read(&active).unwrap();
    let config = fs::read(f.esp.join(efi::OPTIONS)).unwrap();
    let new = f._dir.path().join("new.efi");
    let new_efi = efi_image(b"stela-2");
    fs::write(&new, &new_efi).unwrap();
    let update = || {
        rerun(&f, |c| {
            c.action = Action::UpdateStela;
            c.efi = Some(new.clone());
        })
    };
    fs::remove_file(&spare).unwrap();
    fs::create_dir(&spare).unwrap();
    assert!(update().unwrap_err().to_string().contains("cannot create"));
    assert_eq!(fs::read(&active).unwrap(), old_efi);
    assert_eq!(fs::read(f.esp.join(efi::OPTIONS)).unwrap(), config);
    assert!(record(&f).pending.is_some());
    assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
    fs::remove_dir(&spare).unwrap();
    update().unwrap();
    assert_eq!(fs::read(&active).unwrap(), new_efi);
    assert!(record(&f).pending.is_none() && store.spare_ready());
    assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
    // A rollback also prepares its cold-cache destination before activation.
    fs::remove_file(&spare).unwrap();
    fs::create_dir(&spare).unwrap();
    let before_rollback = fs::read(f.esp.join(RECORD)).unwrap();
    assert!(
        rerun(&f, |c| {
            c.action = Action::Rollback;
            c.dry_run = true;
        })
        .unwrap()
        .contains("Dry run")
    );
    assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_rollback);
    assert!(rerun(&f, |c| c.action = Action::Rollback).is_err());
    assert_eq!(fs::read(&active).unwrap(), new_efi);
    assert_eq!(fs::read(f.esp.join(RECORD)).unwrap(), before_rollback);
    fs::remove_dir(&spare).unwrap();
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    assert_eq!(fs::read(&active).unwrap(), old_efi);
    assert!(store.spare_ready());
    assert_eq!(fs::read(&pack).unwrap(), pack_bytes);
}

#[test]
fn stela_update_and_rollback_with_disabled_cache_create_no_store() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let mut first = command(&f, &f.esp);
    first.translation_store_bytes = Some(0);
    setup(&environment(&f.host), first).unwrap();
    assert!(record(&f).translations.is_none());
    let new = f._dir.path().join("new.efi");
    fs::write(&new, efi_image(b"stela-2")).unwrap();
    rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(new.clone());
    })
    .unwrap();
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    assert!(!f.esp.join(translations::DIRECTORY).exists());
    assert!(record(&f).translations.is_none());
    assert_eq!(
        fs::read(f.esp.join(efi::LOADER)).unwrap(),
        fs::read(&f.efi).unwrap()
    );
}

#[test]
fn stela_updates_keep_the_old_version_and_roll_back() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let before = snapshot(&f.esp);
    setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
    let tool = f.esp.join(efi::LOADER);
    let config = fs::read(f.esp.join(efi::OPTIONS)).unwrap();
    let new = f._dir.path().join("new.efi");
    fs::write(&new, efi_image(b"stela-2")).unwrap();
    let update = |dry_run: bool| {
        rerun(&f, |c| {
            c.action = Action::UpdateStela;
            c.efi = Some(new.clone());
            c.dry_run = dry_run;
        })
    };
    assert!(update(true).unwrap().contains("Dry run"));
    assert_eq!(fs::read(&tool).unwrap(), efi_image(b"stela"));
    // Packs of four translators and a damaged one: the update keeps the
    // three newest intact ones.
    let packs = record(&f).translations.unwrap().directory();
    assert!(packs.join(translations::CONFIG).is_file());
    let written: Vec<PathBuf> = (0..4u8)
        .map(|n| {
            let path = translations::tests::write_pack(&packs, [n; 32], 100);
            fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(
                    std::time::SystemTime::UNIX_EPOCH
                        + std::time::Duration::from_secs(1000 + u64::from(n)),
                )
                .unwrap();
            path
        })
        .collect();
    fs::write(packs.join(translations::pack_name(&[0xab; 32])), b"STLT").unwrap();
    let report = update(false).unwrap();
    assert!(
        report.contains("translates anew into its own pack"),
        "{report}"
    );
    assert!(
        report.contains(&written[0].display().to_string()),
        "{report}"
    );
    assert!(!written[0].exists() && written[1..].iter().all(|path| path.exists()));
    assert_eq!(
        fs::read_dir(&packs).unwrap().count(),
        5,
        "store.cfg, three packs and the spare"
    );
    assert!(packs.join(translations::SPARE).exists());
    assert_eq!(fs::read(&tool).unwrap(), efi_image(b"stela-2"));
    // Only the loader changed: stela.cfg stays.
    assert_eq!(fs::read(f.esp.join(efi::OPTIONS)).unwrap(), config);
    assert!(update(false).unwrap().contains("already installed"));
    let record1 = record(&f);
    assert_eq!(record1.stela_versions.len(), 2);
    assert_eq!(record1.history.len(), 1);
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    assert_eq!(fs::read(&tool).unwrap(), efi_image(b"stela"));
    assert!(
        rerun(&f, |c| c.action = Action::Rollback)
            .unwrap_err()
            .to_string()
            .contains("no update")
    );
    // A stela.efi of another interface is refused.
    fs::write(&new, b"MZ old build").unwrap();
    assert!(
        update(false)
            .unwrap_err()
            .to_string()
            .contains("not the stela.efi")
    );
    fs::write(&new, efi_image(b"stela-2")).unwrap();
    update(false).unwrap();
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert_eq!(snapshot(&f.esp), before);
}

#[test]
fn a_stela_update_to_a_new_bundle_schema_prepares_new_bundles_and_rolls_back() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
    let old_schema = record(&f).bundle_schema;
    let next_schema = old_schema.checked_add(1).unwrap();
    let ecid = record(&f).installs[0].ecid;
    let old = bundle_of(&f, ecid);
    // The Install macOS choice names the restore bundle.
    let options = || fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
    let first = options();
    // A later stela and stela.efi read the next schema.
    let newer = mount_interface::Interface {
        bundle_schema: next_schema,
        ..mount_interface::CURRENT
    };
    let next_generation = bundle::Generation {
        schema: next_schema,
        ..current()
    };
    let prepare = move |_: &Path, _: &str, ecid: Option<Ecid>, _: bool, output: &Path| {
        bundle::tests::write(
            output,
            next_generation,
            &[ecid.map_or(0, |e| e.0 as u8) ^ 0xff; 64],
        )
    };
    let environment = Environment {
        prepare_restore: &prepare,
        interface: newer,
        ..environment(&f.host)
    };
    let new = f._dir.path().join("new.efi");
    let mut image = b"MZstela-3".to_vec();
    image.extend_from_slice(&mount_interface::marker(newer));
    fs::write(&new, image).unwrap();
    let update = |ipsw: bool| {
        let mut command = command(&f, &f.esp);
        command.ipsw = ipsw.then(|| f.ipsw.clone());
        command.model = None;
        command.action = Action::UpdateStela;
        command.efi = Some(new.clone());
        command.dispatch(&environment)
    };
    let error = update(false).unwrap_err().to_string();
    assert!(error.contains(&format!("schema {next_schema}")), "{error}");
    assert!(error.contains("--ipsw"), "{error}");
    update(true).unwrap();
    let record2 = record(&f);
    assert_eq!(record2.bundle_schema, next_schema);
    let migrated = bundle_of(&f, ecid);
    let leaf = bundle::leaf_of(Kind::Restore, ecid, next_generation);
    assert!(
        migrated.ends_with(&leaf) && leaf.contains(&format!("-s{next_schema}")),
        "{leaf}"
    );
    assert!(
        options()
            .split_ascii_whitespace()
            .any(|word| word.ends_with(&leaf)),
        "{}",
        options()
    );
    // The old bundle stays for the rollback, which boots it again.
    assert!(old.join("bundle.json").is_file());
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    assert_eq!(options(), first);
    assert!(!migrated.exists());
    assert_eq!(record(&f).bundle_schema, old_schema);
}

#[test]
fn a_stela_update_prepares_the_bundles_of_a_new_revision_and_rolls_back() {
    // A setup with an install, made before setups recorded revisions.
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    let (older, newer) = (preparers(0), preparers(1));
    let old = environment_at(&f.host, &older, 0);
    setup(&old, installed_command(&f)).unwrap();
    let path = f.esp.join(RECORD);
    let mut json: serde_json::Value = stela_runtime::read_json(&path).unwrap();
    json.as_object_mut().unwrap().remove("bundle_revision");
    for kept in json["bundles"].as_array_mut().unwrap() {
        kept.as_object_mut().unwrap().remove("revision");
    }
    stela_runtime::write_json(&path, &json).unwrap();
    let first = record(&f);
    assert_eq!(first.bundle_revision, 0);
    let ecid = first.installs[0].ecid;
    let options = || fs::read_to_string(f.esp.join(efi::OPTIONS)).unwrap();
    let choices = || fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
    let (first_options, first_choices) = (options(), choices());
    let directories = |revision: u32| -> Vec<PathBuf> {
        let generation = bundle::Generation {
            revision,
            ..current()
        };
        vec![bundle::directory_of(
            Kind::Restore,
            &first.volume,
            &first.build,
            ecid,
            generation,
        )]
    };
    // A later stela prepares revision 1, with the same stela.efi.
    let new = environment_at(&f.host, &newer, 1);
    let run = |configure: &dyn Fn(&mut Request)| {
        let mut command = command(&f, &f.esp);
        command.ipsw = None;
        command.model = None;
        configure(&mut command);
        command.dispatch(&new)
    };
    let status = run(&|c| c.action = Action::Status).unwrap_err().to_string();
    assert!(
        status.contains("boot bundles are revision 0, and this stela prepares revision 1"),
        "{status}"
    );
    assert!(status.contains("stela setup update stela"), "{status}");
    // Other changes that prepare bundles wait for the update.
    let repair = run(&|c| {
        c.action = Action::Repair;
        c.ipsw = Some(f.ipsw.clone());
    });
    assert!(
        repair
            .unwrap_err()
            .to_string()
            .contains("stela setup update stela"),
        "the repair is refused"
    );
    let update = |ipsw: bool, dry_run: bool| {
        run(&|c| {
            c.action = Action::UpdateStela;
            c.ipsw = ipsw.then(|| f.ipsw.clone());
            c.dry_run = dry_run;
        })
    };
    let refusal = update(false, false).unwrap_err().to_string();
    assert!(
        refusal.contains(&format!("schema {} revision 1", current().schema)),
        "{refusal}"
    );
    assert!(refusal.contains("--ipsw or --fetch"), "{refusal}");
    let before = (snapshot(&f.esp), snapshot(&stela_volume(&f)));
    let plan = update(true, true).unwrap();
    assert!(!plan.contains("is already installed"), "{plan}");
    for directory in directories(1) {
        assert!(plan.contains(&directory.display().to_string()), "{plan}");
    }
    assert_eq!((snapshot(&f.esp), snapshot(&stela_volume(&f))), before);
    update(true, false).unwrap();
    let updated = record(&f);
    assert_eq!(updated.bundle_revision, 1);
    assert_eq!(updated.stela_version, first.stela_version);
    for (old, new) in directories(0).iter().zip(directories(1)) {
        assert_eq!(bundle::generation(&new).unwrap().revision, 1);
        // The revision 0 bundles stay for the rollback.
        assert_eq!(bundle::generation(old).unwrap().revision, 0);
    }
    let [restore] = &directories(1)[..] else {
        unreachable!()
    };
    let leaf = restore.file_name().unwrap().to_string_lossy().into_owned();
    assert!(choices().contains(&leaf), "{}", choices());
    assert!(
        run(&|c| c.action = Action::Status)
            .unwrap()
            .contains("No problems found.")
    );
    // Bundles of the current revision are left alone: a new stela.efi
    // needs no restore image, and the same one is no update.
    assert!(update(false, false).unwrap().contains("already installed"));
    // Going back to the earlier stela boots its kept bundles, and undoing
    // that keeps them for the first update's rollback.
    let mut back = command(&f, &f.esp);
    (back.ipsw, back.model, back.action) = (None, None, Action::UpdateStela);
    back.dispatch(&old).unwrap();
    assert_eq!(record(&f).bundle_revision, 0);
    run(&|c| c.action = Action::Rollback).unwrap();
    assert_eq!(record(&f).bundles, updated.bundles);
    let new_efi = f._dir.path().join("new.efi");
    fs::write(&new_efi, efi_image(b"stela-2")).unwrap();
    let report = run(&|c| {
        c.action = Action::UpdateStela;
        c.efi = Some(new_efi.clone());
    })
    .unwrap();
    assert!(!report.contains("stay for rollback"), "{report}");
    assert_eq!(record(&f).bundles, updated.bundles);
    // Each rollback undoes one update: the second boots the revision 0
    // bundles again and removes the revision 1 ones.
    run(&|c| c.action = Action::Rollback).unwrap();
    assert_eq!(record(&f).bundles, updated.bundles);
    run(&|c| c.action = Action::Rollback).unwrap();
    let rolled = record(&f);
    assert_eq!(rolled.bundle_revision, 0);
    assert_eq!(rolled.stela_version, first.stela_version);
    assert!(
        rolled
            .stela_versions
            .contains(first.stela_version.as_ref().unwrap())
    );
    assert_eq!((options(), choices()), (first_options, first_choices));
    assert!(directories(1).iter().all(|d| !d.exists()));
    assert!(
        directories(0)
            .iter()
            .all(|d| d.join(bundle::MANIFEST).is_file())
    );
    let mut status = command(&f, &f.esp);
    (status.ipsw, status.model, status.action) = (None, None, Action::Status);
    assert!(
        status
            .dispatch(&old)
            .is_ok_and(|text| text.contains("No problems found.")),
        "the earlier stela finds its setup as it left it"
    );
}

#[test]
fn stela_updates_remove_bundles_no_kept_version_boots() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let preparers: Vec<_> = (0..4).map(preparers).collect();
    setup(
        &environment_at(&f.host, &preparers[0], 0),
        command(&f, &f.esp),
    )
    .unwrap();
    let ecid = record(&f).installs[0].ecid;
    let directory = |revision: u32| {
        let record = record(&f);
        let generation = bundle::Generation {
            revision,
            ..current()
        };
        bundle::directory_of(
            Kind::Restore,
            &record.volume,
            &record.build,
            ecid,
            generation,
        )
    };
    for revision in 1..4 {
        let image = f._dir.path().join(format!("stela-{revision}.efi"));
        fs::write(&image, efi_image(format!("stela-{revision}").as_bytes())).unwrap();
        let mut command = command(&f, &f.esp);
        command.model = None;
        command.action = Action::UpdateStela;
        command.efi = Some(image);
        let environment = environment_at(&f.host, &preparers[revision as usize], revision);
        command.dispatch(&environment).unwrap();
    }
    // Four versions: the first is no longer kept, nor are its bundles.
    let record = record(&f);
    assert_eq!(record.stela_versions.len(), update::KEEP);
    assert_eq!(record.history.len(), update::KEEP - 1);
    assert!(!directory(0).exists());
    for revision in 1..4 {
        assert!(directory(revision).join(bundle::MANIFEST).is_file());
    }
    assert_eq!(record.bundles.len(), 3);
}

#[test]
fn os_updates_add_restore_bundles_and_interrupted_updates_finish_or_roll_back() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    let before = snapshot(&f.esp);
    setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
    let ecid = record(&f).installs[0].ecid;
    let newer = f._dir.path().join("Newer.ipsw");
    restore::payload::synthetic_ipsw_of(&newer, "STELA2").unwrap();
    let update = |dry_run: bool| {
        rerun(&f, |c| {
            c.action = Action::UpdateOs;
            c.ipsw = Some(newer.clone());
            c.dry_run = dry_run;
        })
    };
    // The Install macOS choice names the build's restore bundle.
    let options = || fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap();
    let first = options();
    assert!(update(true).unwrap().contains("Dry run"));
    assert_eq!(options(), first);
    let report = update(false).unwrap();
    assert!(report.contains("choose Install macOS"), "{report}");
    assert!(report.contains("Update volume"), "{report}");
    assert!(options().contains("\\boot\\STELA2\\restore-"));
    let leaf = bundle::leaf_of(Kind::Restore, ecid, current());
    assert!(
        stela_volume(&f)
            .join(format!("stela/boot/STELA2/{leaf}/bundle.json"))
            .is_file()
    );
    // The old build stays for rollback.
    let old = bundle::directory_of(
        Kind::Restore,
        &stela_volume(&f),
        restore::payload::SYNTHETIC_BUILD,
        ecid,
        current(),
    );
    assert!(old.join("bundle.json").is_file());
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    assert_eq!(options(), first);
    assert!(!stela_volume(&f).join("stela/boot/STELA2").exists());

    // An update interrupted after it was recorded refuses other updates,
    // finishes when run again, and rolls back otherwise.
    let mut record1 = record(&f);
    record1.pending = Some(update::Change::Os {
        from: restore::payload::SYNTHETIC_BUILD.into(),
        to: "STELA2".into(),
    });
    write_record(&f.esp, &record1).unwrap();
    let partial = stela_volume(&f).join(format!("stela/boot/STELA2/{leaf}.partial"));
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("partial"), b"x").unwrap();
    let other = rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(f.efi.clone());
    });
    assert!(other.unwrap_err().to_string().contains("interrupted"));
    update(false).unwrap();
    assert!(options().contains("STELA2"));
    assert!(!partial.exists());
    record1 = record(&f);
    record1.pending = record1.history.last().cloned();
    write_record(&f.esp, &record1).unwrap();
    let undo = rerun(&f, |c| c.action = Action::Rollback).unwrap();
    assert!(undo.contains("interrupted macOS update"), "{undo}");
    assert_eq!(options(), first);
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert_eq!(snapshot(&f.esp), before);
}

#[test]
fn os_updates_of_an_install_write_the_new_medium_and_restore_it_keeping_the_data() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    setup(&environment(&f.host), installed_command(&f)).unwrap();
    let ecid = record(&f).installs[0].ecid.unwrap();
    assert_eq!(record(&f).media.len(), 1);
    assert!(
        rerun(&f, |c| c.action = Action::Status)
            .unwrap()
            .contains("No problems found.")
    );
    let disks = (partition_bytes(&f, REGION), partition_bytes(&f, NOR));
    let choices =
        || Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    let names: Vec<String> = choices().entries.into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["macOS", INSTALL_CHOICE]);
    let first = restore::payload::SYNTHETIC_BUILD;
    let newer = f._dir.path().join("Newer.ipsw");
    restore::payload::synthetic_ipsw_of(&newer, "STELA2").unwrap();
    let update_to = |ipsw: &Path, dry_run: bool| {
        rerun(&f, |c| {
            c.action = Action::UpdateOs;
            c.ipsw = Some(ipsw.to_path_buf());
            c.dry_run = dry_run;
        })
    };
    let before = snapshot(&f.esp);
    let plan = update_to(&newer, true).unwrap();
    assert!(plan.contains("install medium"), "{plan}");
    assert!(plan.contains("keeps"), "{plan}");
    assert_eq!(snapshot(&f.esp), before);
    update_to(&newer, false).unwrap();
    let record1 = record(&f);
    assert_eq!(record1.build, "STELA2");
    let media: Vec<&str> = record1.media.iter().map(|m| m.build.as_str()).collect();
    assert_eq!(media, [first, "STELA2"], "the old medium is kept");
    assert!(record1.active_medium().unwrap().problems().is_empty());
    assert!(record1.restore_bundle(Kind::Restore, Some(ecid)).is_some());
    for entry in &choices().entries[1..2] {
        assert!(
            entry.options.contains("\\boot\\STELA2\\")
                && entry.options.contains("\\install\\STELA2\\payload.json"),
            "{}",
            entry.options
        );
    }
    let status = rerun(&f, |c| c.action = Action::Status).unwrap();
    assert!(status.contains("kept medium"), "{status}");
    // The update writes no disk of the PC.
    assert_eq!(
        (partition_bytes(&f, REGION), partition_bytes(&f, NOR)),
        disks
    );
    // A rollback drops the new medium and restores the old choices.
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    let record2 = record(&f);
    assert_eq!(record2.build, first);
    let media: Vec<&str> = record2.media.iter().map(|m| m.build.as_str()).collect();
    assert_eq!(media, [first]);
    assert!(!medium::directory(&stela_volume(&f), "STELA2").exists());
    assert!(
        choices().entries[1]
            .options
            .contains(&format!("\\boot\\{first}\\"))
    );
    // Two updates on, only the newest two media are kept.
    update_to(&newer, false).unwrap();
    let newest = f._dir.path().join("Newest.ipsw");
    restore::payload::synthetic_ipsw_of(&newest, "STELA3").unwrap();
    update_to(&newest, false).unwrap();
    let media: Vec<String> = record(&f).media.into_iter().map(|m| m.build).collect();
    assert_eq!(media, ["STELA2", "STELA3"]);
    assert!(!medium::directory(&stela_volume(&f), first).exists());
    assert!(
        rerun(&f, |c| c.action = Action::Status)
            .unwrap()
            .contains("No problems found.")
    );
    // Rolling back past the pruned medium says how to write it again.
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    let undo = rerun(&f, |c| c.action = Action::Rollback).unwrap();
    assert!(undo.contains("no longer kept"), "{undo}");
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert!(!f.esp.join("EFI/stela").exists());
    assert!(!stela_volume(&f).join("stela/install").exists());
}

#[test]
fn status_reports_everything_and_repair_puts_back_what_the_record_says() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    setup(&environment(&f.host), installed_command(&f)).unwrap();
    let status = || rerun(&f, |c| c.action = Action::Status);
    let report = status().unwrap();
    assert!(report.contains("No problems found."), "{report}");
    assert!(report.contains("Install \"macOS\" (default)"), "{report}");
    assert!(report.contains("ECID           0x"), "{report}");
    assert!(report.contains("no installed macOS yet"), "{report}");
    assert!(report.contains("NVRAM          blank"), "{report}");
    assert!(report.contains("SEP state      blank"), "{report}");
    assert!(report.contains("intact"), "{report}");
    // Status changes nothing.
    let before = snapshot(&f.esp);
    status().unwrap();
    assert_eq!(snapshot(&f.esp), before);

    // A damaged bundle, tool and stela.cfg are found ...
    let ecid = record(&f).installs[0].ecid;
    let ramdisk = bundle_of(&f, ecid).join("ramdisk.img");
    fs::write(&ramdisk, [0u8; 10]).unwrap();
    fs::write(f.esp.join(LOADER_PATH), b"MZ damaged").unwrap();
    fs::write(f.esp.join("EFI/stela/stela.cfg"), b"--system\n").unwrap();
    let error = status().unwrap_err().to_string();
    assert!(error.contains("problems:"), "{error}");
    assert!(error.contains("ramdisk.img"), "{error}");
    assert!(error.contains("not the version setup installed"), "{error}");
    assert!(error.contains("stela.cfg differs"), "{error}");
    // ... and the bundle needs the restore image to be repaired.
    let error = rerun(&f, |c| c.action = Action::Repair)
        .unwrap_err()
        .to_string();
    assert!(error.contains("--ipsw"), "{error}");
    let damaged = snapshot(&f.esp);
    rerun(&f, |c| {
        c.action = Action::Repair;
        c.ipsw = Some(f.ipsw.clone());
        c.dry_run = true;
    })
    .unwrap();
    assert_eq!(snapshot(&f.esp), damaged);
    rerun(&f, |c| {
        c.action = Action::Repair;
        c.ipsw = Some(f.ipsw.clone());
    })
    .unwrap();
    // The bundle is the machine's own again, with its ECID.
    assert_eq!(record(&f).installs[0].ecid, ecid);
    assert_eq!(
        fs::read(&ramdisk).unwrap(),
        vec![ecid.unwrap().0 as u8 ^ 0xa5; 2048]
    );
    assert_eq!(snapshot(&f.esp), before);
    status().unwrap();

    // A machine an older setup made without an ECID gets one.
    let mut old = record(&f);
    old.installs[0].ecid = None;
    write_record(&f.esp, &old).unwrap();
    let error = status().unwrap_err().to_string();
    assert!(error.contains("has no ECID"), "{error}");
    rerun(&f, |c| {
        c.action = Action::Repair;
        c.ipsw = Some(f.ipsw.clone());
    })
    .unwrap();
    let repaired = record(&f);
    let new = repaired.installs[0].ecid.unwrap();
    assert!(bundle_of(&f, Some(new)).join("bundle.json").is_file());
    status().unwrap();
}

#[test]
fn no_maintenance_operation_writes_the_installed_disk_or_another_partition() {
    let mut f = fixture(64 * GIB, false);
    // An installed macOS: the Apple region holds the guest's own GPT,
    // and its containers' bytes after it stand for the user's data.
    let mut region = vec![0u8; 64 * 1024];
    region[512..520].copy_from_slice(b"EFI PART");
    for (n, byte) in region[1024..].iter_mut().enumerate() {
        *byte = (n % 251) as u8;
    }
    add_installed_disk(&mut f, &region, &[]);
    // A partition of another system on the same disk.
    let foreign = f._dir.path().join("disk1s4.img");
    fs::write(&foreign, vec![0xa5; IMAGE_BYTES]).unwrap();
    f.host.partitions.insert(
        "disk1s4".into(),
        (
            PartitionInfo {
                identifier: "disk1s4".into(),
                disk: "disk1".into(),
                guid: "5e1a0000-0000-4000-8000-0000000000ff".into(),
                bytes: 50 * GIB,
                content: "Apple_HFS".into(),
                mount: None,
                container: None,
            },
            foreign.clone(),
        ),
    );
    let disks = || {
        (
            partition_bytes(&f, REGION),
            partition_bytes(&f, NOR),
            fs::read(&foreign).unwrap(),
            snapshot(&f.data),
        )
    };
    let before = disks();
    let report = setup(&environment(&f.host), installed_command(&f)).unwrap();
    assert!(report.contains("guest disk"), "{report}");
    assert_eq!(disks(), before, "setup");
    let new = f._dir.path().join("new.efi");
    fs::write(&new, efi_image(b"stela-2")).unwrap();
    let newer = f._dir.path().join("Newer.ipsw");
    restore::payload::synthetic_ipsw_of(&newer, "STELA2").unwrap();
    type Step<'a> = (&'a str, &'a dyn Fn(&mut Request));
    let steps: [Step<'_>; 7] = [
        ("status", &|c| c.action = Action::Status),
        ("update-stela", &|c| {
            c.action = Action::UpdateStela;
            c.efi = Some(new.clone());
        }),
        ("rollback", &|c| c.action = Action::Rollback),
        ("update-os", &|c| {
            c.action = Action::UpdateOs;
            c.ipsw = Some(newer.clone());
        }),
        ("rollback", &|c| c.action = Action::Rollback),
        ("repair", &|c| {
            c.action = Action::Repair;
            c.ipsw = Some(f.ipsw.clone());
        }),
        ("status", &|c| c.action = Action::Status),
    ];
    for (name, step) in steps {
        rerun(&f, step).unwrap_or_else(|error| panic!("{name}: {error:#}"));
        assert_eq!(disks(), before, "{name}");
    }
    uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert_eq!(disks(), before, "uninstall");
}

#[test]
fn a_bundle_copy_stopped_between_its_renames_is_found_and_put_back() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    setup(&environment(&f.host), installed_command(&f)).unwrap();
    let before = snapshot(&f.esp);
    let directory = bundle_of(&f, record(&f).installs[0].ecid);
    // The stop came after the old bundle was set aside, before the new
    // copy was renamed into place.
    let (partial, previous) = bundle::siblings(&directory).unwrap();
    fs::rename(&directory, &previous).unwrap();
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("ramdisk.img"), b"half").unwrap();
    let error = rerun(&f, |c| c.action = Action::Status)
        .unwrap_err()
        .to_string();
    assert!(error.contains("set aside"), "{error}");
    assert!(error.contains("stopped part way"), "{error}");
    // A dry run says so and changes nothing, and needs no restore image.
    let interrupted = snapshot(&f.esp);
    let dry = rerun(&f, |c| {
        c.action = Action::Repair;
        c.dry_run = true;
    })
    .unwrap();
    assert!(dry.contains("would put right"), "{dry}");
    assert_eq!(snapshot(&f.esp), interrupted);
    let report = rerun(&f, |c| c.action = Action::Repair).unwrap();
    assert!(report.contains("put back"), "{report}");
    assert!(!partial.exists() && !previous.exists());
    assert_eq!(snapshot(&f.esp), before);
    rerun(&f, |c| c.action = Action::Status).unwrap();
}

#[test]
fn nvram_resets_and_machine_state_backs_up_and_restores_to_its_own_machine() {
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    add_disk(&mut f, true, &[], &[]);
    setup(&environment(&f.host), installed_command(&f)).unwrap();
    provision_sep(&f, NOR);
    rerun(&f, |c| c.action = Action::NextBoot(NextBoot::Recovery)).unwrap();
    let capacity = stela_runtime::machine::apple::nor::CAPACITY;
    let sep = |f: &Fixture| partition_bytes(f, NOR)[capacity..].to_vec();
    let sep_before = sep(&f);

    // A reset needs the partition named again, and keeps the SEP state.
    let error = rerun(&f, |c| c.action = Action::ResetNvram)
        .unwrap_err()
        .to_string();
    assert!(error.contains("--nor"), "{error}");
    let error = rerun(&f, |c| {
        c.action = Action::ResetNvram;
        c.nor = Some(NOR2.into());
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("not this install's NOR"), "{error}");
    let state = partition_bytes(&f, NOR);
    rerun(&f, |c| {
        c.action = Action::ResetNvram;
        c.nor = Some(NOR.into());
        c.dry_run = true;
    })
    .unwrap();
    assert_eq!(partition_bytes(&f, NOR), state);
    // Back up before the reset.
    let file = f._dir.path().join("machine.state");
    rerun(&f, |c| c.action = Action::BackupState(file.clone())).unwrap();
    #[cfg(unix)]
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&file).unwrap().permissions())
            & 0o777,
        0o600
    );
    assert!(
        rerun(&f, |c| c.action = Action::BackupState(file.clone()))
            .unwrap_err()
            .to_string()
            .contains("exists")
    );
    rerun(&f, |c| {
        c.action = Action::ResetNvram;
        c.nor = Some(NOR.into());
    })
    .unwrap();
    assert_eq!(
        stela_loader::boot_selection::select(&nvram(&f))
            .unwrap()
            .target,
        stela_loader::boot_selection::Target::MacOs { safe: false }
    );
    assert_eq!(sep(&f), sep_before);
    let status = rerun(&f, |c| c.action = Action::Status).unwrap();
    assert!(status.contains("SEP state      provisioned"), "{status}");
    assert!(status.contains("next boot      macOS"), "{status}");

    // The backup restores only to its own machine.
    let mut second = installed_command(&f);
    second.target = Some(REGION2.into());
    second.nor = Some(NOR2.into());
    second.install = Some("Other".into());
    second.model = None;
    second.dispatch(&environment(&f.host)).unwrap();
    let error = rerun(&f, |c| {
        c.action = Action::RestoreState(file.clone());
        c.install = Some("Other".into());
        c.nor = Some(NOR2.into());
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("restored only to that machine"), "{error}");
    let damaged = f._dir.path().join("damaged.state");
    let mut bytes = fs::read(&file).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&damaged, bytes).unwrap();
    let error = rerun(&f, |c| {
        c.action = Action::RestoreState(damaged.clone());
        c.nor = Some(NOR.into());
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("damaged"), "{error}");
    rerun(&f, |c| {
        c.action = Action::RestoreState(file.clone());
        c.nor = Some(NOR.into());
    })
    .unwrap();
    assert_eq!(partition_bytes(&f, NOR), state);
    assert_eq!(
        stela_loader::boot_selection::select(&nvram(&f))
            .unwrap()
            .target,
        stela_loader::boot_selection::Target::SystemRecovery
    );
    // --nor alone names nothing to do.
    assert!(rerun(&f, |c| c.nor = Some(NOR.into())).is_err());
}

#[test]
fn boot_log_prints_the_install_s_log_and_names_a_missing_one() {
    use stela_runtime::pc::boot_log::{LOG_BYTES, OFFSET, PARTITION_BYTES};
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    let plan = setup(&environment(&f.host), installed_command(&f)).unwrap();
    assert!(plan.contains("also keeps stela.efi's boot log"), "{plan}");
    let path = f.host.image(NOR).unwrap().to_path_buf();
    let mut bytes = fs::read(&path).unwrap();
    bytes.resize(PARTITION_BYTES as usize, 0);
    fs::write(&path, &bytes).unwrap();
    let error = format!(
        "{:#}",
        rerun(&f, |c| c.action = Action::BootLog).unwrap_err()
    );
    assert!(error.contains("the log region is blank"), "{error}");

    let region = crate::boot_log::tests::region(&["NOR persistent fresh=true\n"]);
    bytes[OFFSET as usize..(OFFSET + LOG_BYTES) as usize].copy_from_slice(&region);
    fs::write(&path, &bytes).unwrap();
    let state = partition_bytes(&f, NOR);
    let text = rerun(&f, |c| c.action = Action::BootLog).unwrap();
    assert!(
        text.contains("(disk1s3): Stela boot log: 1 boots, 47 bytes\n"),
        "{text}"
    );
    assert!(
        text.ends_with("=== STELA BOOT 1 ===\nNOR persistent fresh=true\n"),
        "{text}"
    );
    assert_eq!(partition_bytes(&f, NOR), state);
    // The USB's own log, which setup preallocates, comes first.
    let usb = crate::boot_log::tests::region(&["CHOICE 3 (Install macOS)\n"]);
    fs::write(f.esp.join(efi::BOOT_LOG), &usb).unwrap();
    let text = rerun(&f, |c| c.action = Action::BootLog).unwrap();
    assert!(text.starts_with("Boot log on the USB ("), "{text}");
    assert!(text.contains("CHOICE 3 (Install macOS)\n"), "{text}");
    assert!(
        text.ends_with("=== STELA BOOT 1 ===\nNOR persistent fresh=true\n"),
        "{text}"
    );
    // The log is optional: a smaller partition is noted, not refused,
    // and the USB's log still prints.
    f.host.partitions.get_mut(NOR).unwrap().0.bytes = PARTITION_BYTES - 1;
    let text = rerun(&f, |c| c.action = Action::BootLog).unwrap();
    assert!(text.starts_with("Boot log on the USB ("), "{text}");
    assert!(text.ends_with("without one\n"), "{text}");
    fs::write(f.esp.join(efi::BOOT_LOG), vec![0; LOG_BYTES as usize]).unwrap();
    let error = format!(
        "{:#}",
        rerun(&f, |c| c.action = Action::BootLog).unwrap_err()
    );
    assert!(
        error.contains("has no boot log: the log region is blank\n"),
        "{error}"
    );
    assert!(error.ends_with("without one"), "{error}");
    let mut again = installed_command(&f);
    again.target = Some(REGION2.into());
    again.nor = Some(NOR2.into());
    add_disk(&mut f, true, &[], &[]);
    f.host.partitions.get_mut(NOR2).unwrap().0.bytes = PARTITION_BYTES - 1;
    again.install = Some("Other".into());
    again.model = None;
    again.dry_run = true;
    let plan = again.dispatch(&environment(&f.host)).unwrap();
    assert!(plan.contains("boots without a boot log"), "{plan}");
}

/// The Apple region of a one-partition install: 100 GiB, a sparse image.
const SPLIT_BYTES: u64 = 100 * GIB;

/// Give `f`'s PC a disk (`disk1`, or `disk2` with `second`) whose Apple
/// region alone is set up, as a sparse image of the whole partition
/// that starts with `head`.
fn add_split_disk(f: &mut Fixture, second: bool, head: &[u8]) {
    add_stela(f);
    let (disk, serial, identifier, guid) = if second {
        ("disk2", SERIAL2, REGION2, REGION2_GUID)
    } else {
        ("disk1", SERIAL, REGION, REGION_GUID)
    };
    let path = f._dir.path().join(format!("{identifier}.img"));
    let file = fs::File::create(&path).unwrap();
    file.set_len(SPLIT_BYTES).unwrap();
    drop(file);
    let info = PartitionInfo {
        identifier: identifier.into(),
        disk: disk.into(),
        guid: guid.to_ascii_lowercase(),
        bytes: SPLIT_BYTES,
        content: "Apple_APFS".into(),
        mount: None,
        container: None,
    };
    f.host.partitions.insert(identifier.into(), (info, path));
    f.host.serials.insert(disk.into(), serial.into());
    f.host.write(identifier, 0, head).unwrap();
}

/// Where the region's machine state starts.
fn tail() -> u64 {
    stela_runtime::pc::machine_state::split(SPLIT_BYTES)
        .unwrap()
        .state_offset()
}

fn split_command(f: &Fixture) -> Request {
    let mut command = command(f, &f.esp);
    command.target = Some(REGION.into());
    command.tss = true;
    command
}

/// The region's machine state: its NOR image and SEP area.
fn state_of(f: &Fixture, identifier: &str) -> Vec<u8> {
    let bytes = stela_runtime::machine::apple::nor::CAPACITY
        + stela_runtime::machine::apple::sep_state::BYTES as usize;
    f.host.read(identifier, tail(), bytes).unwrap()
}

fn tail_nvram(f: &Fixture) -> Variables {
    let capacity = stela_runtime::machine::apple::nor::CAPACITY;
    let image = stela_runtime::machine::apple::nor::Image::from_bytes(
        state_of(f, REGION)[..capacity].to_vec(),
    )
    .unwrap();
    Variables::parse(image.bank(image.current_bank().unwrap()).unwrap()).unwrap()
}

fn next_target(variables: &Variables) -> stela_loader::boot_selection::Target {
    stela_loader::boot_selection::select(variables)
        .unwrap()
        .target
}

/// A guest disk's primary GPT header at LBA 1 of 512-byte blocks, whose
/// backup header is at `backup`.
fn guest_gpt(backup: u64) -> Vec<u8> {
    let mut head = vec![0u8; 1024];
    head[512..520].copy_from_slice(b"EFI PART");
    head[512 + 32..512 + 40].copy_from_slice(&backup.to_le_bytes());
    head[512 + 48..512 + 56].copy_from_slice(&(backup - 33).to_le_bytes());
    head
}

#[test]
fn one_partition_keeps_the_machine_state_in_its_tail_outside_the_guest() {
    use stela_runtime::machine::apple::nor::CAPACITY;
    let mut f = fixture(64 * GIB, false);
    add_split_disk(&mut f, false, &[]);
    let mut dry = split_command(&f);
    dry.dry_run = true;
    let plan = setup(&environment(&f.host), dry).unwrap();
    assert!(
        plan.contains(&format!(
            "machine state  the tail of disk1s2 from byte {:#x}",
            tail()
        )),
        "{plan}"
    );
    assert!(
        plan.contains(&format!(
            "recoveryOS sees the {:#x} bytes before it as the Mac's SSD",
            tail()
        )),
        "{plan}"
    );
    assert!(plan.contains("also keeps stela.efi's boot log"), "{plan}");
    assert!(!f.esp.join(RECORD).exists());

    setup(&environment(&f.host), split_command(&f)).unwrap();
    let record = record(&f);
    let disk = &record.installs[0].disk;
    assert_eq!(disk.machine_state_offset, Some(tail()));
    assert_eq!(
        (
            disk.nor.as_str(),
            disk.nor_serial.as_str(),
            disk.nor_guid.as_str()
        ),
        (REGION, SERIAL, REGION_GUID)
    );
    // The record keeps the choice, and the boot line names the region as
    // both the SSD and the machine state.
    let json = fs::read_to_string(f.esp.join(RECORD)).unwrap();
    assert!(
        json.contains(&format!("\"machine_state_offset\": {}", tail())),
        "{json}"
    );
    let ecid = record.installs[0].ecid.unwrap();
    let region = format!("{SERIAL}:{REGION_GUID}");
    let restore = format!(
        "\\stela\\boot\\{}\\{}",
        restore::payload::SYNTHETIC_BUILD,
        bundle::leaf_of(Kind::Restore, Some(ecid), current())
    );
    assert_eq!(
        fs::read_to_string(f.esp.join("EFI/stela/stela.cfg")).unwrap(),
        format!(
            "--system --storage {region} --nor {region} --preboot {region} --ecid {ecid} \
             --tss\n"
        )
    );
    let choices = Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    assert!(
        choices.entries[1].options.starts_with(&format!(
            "--system --storage {region} --nor {region} --bundle {restore} --ecid {ecid} "
        )),
        "{}",
        choices.entries[1].options
    );
    // Setup itself wrote neither the SSD nor the machine state.
    assert!(
        f.host
            .read(REGION, 0, 1 << 20)
            .unwrap()
            .iter()
            .all(|&b| b == 0)
    );
    assert!(state_of(&f, REGION).iter().all(|&b| b == 0));

    // NVRAM is the tail's: the next boot is chosen there.
    rerun(&f, |c| c.action = Action::NextBoot(NextBoot::Recovery)).unwrap();
    assert_eq!(
        next_target(&tail_nvram(&f)),
        stela_loader::boot_selection::Target::SystemRecovery
    );
    assert!(
        f.host
            .read(REGION, 0, 1 << 20)
            .unwrap()
            .iter()
            .all(|&b| b == 0)
    );
    let status = rerun(&f, |c| c.action = Action::Status).unwrap();
    assert!(
        status.contains(&format!(
            "machine state  the tail of disk1s2 from byte {:#x}",
            tail()
        )),
        "{status}"
    );
    assert!(
        status.contains("next boot      System Recovery"),
        "{status}"
    );
    assert!(status.contains("SEP state      blank"), "{status}");
    assert!(status.contains("No problems found."), "{status}");

    // A provisioned SEP area in the tail backs up, survives a reset and
    // restores, each command addressing the tail.
    let mut roots = vec![0u8; 8 + 2 * 32];
    roots[..8].copy_from_slice(b"STSEPR01");
    roots[8..].fill(0x42);
    use sha2::{Digest, Sha256};
    let sum = Sha256::digest(&roots);
    roots.extend_from_slice(&sum);
    f.host
        .write(REGION, tail() + CAPACITY as u64, &roots)
        .unwrap();
    let state = state_of(&f, REGION);
    let file = f._dir.path().join("split.state");
    rerun(&f, |c| c.action = Action::BackupState(file.clone())).unwrap();
    let error = rerun(&f, |c| c.action = Action::ResetNvram)
        .unwrap_err()
        .to_string();
    assert!(error.contains("Apple region, whose last bytes"), "{error}");
    let reset = rerun(&f, |c| {
        c.action = Action::ResetNvram;
        c.nor = Some(REGION.into());
    })
    .unwrap();
    assert!(
        reset.contains(&format!("(disk1s2 from byte {:#x})", tail())),
        "{reset}"
    );
    assert_eq!(
        next_target(&tail_nvram(&f)),
        stela_loader::boot_selection::Target::MacOs { safe: false }
    );
    assert_eq!(state_of(&f, REGION)[CAPACITY..], state[CAPACITY..]);
    let status = rerun(&f, |c| c.action = Action::Status).unwrap();
    assert!(status.contains("SEP state      provisioned"), "{status}");
    rerun(&f, |c| {
        c.action = Action::RestoreState(file.clone());
        c.nor = Some(REGION.into());
    })
    .unwrap();
    assert_eq!(state_of(&f, REGION), state);
    assert_eq!(
        next_target(&tail_nvram(&f)),
        stela_loader::boot_selection::Target::SystemRecovery
    );

    // The boot log is read from the tail too.
    let error = format!(
        "{:#}",
        rerun(&f, |c| c.action = Action::BootLog).unwrap_err()
    );
    assert!(error.contains("the log region is blank"), "{error}");
    let log = crate::boot_log::tests::region(&["MACHINE STATE in the target's tail\n"]);
    f.host
        .write(REGION, tail() + stela_runtime::pc::boot_log::OFFSET, &log)
        .unwrap();
    let text = rerun(&f, |c| c.action = Action::BootLog).unwrap();
    assert!(
        text.contains(&format!(
            "(disk1s2 from byte {:#x}): Stela boot log: 1 boots",
            tail()
        )),
        "{text}"
    );
    assert!(
        text.ends_with("=== STELA BOOT 1 ===\nMACHINE STATE in the target's tail\n"),
        "{text}"
    );
    assert!(
        f.host
            .read(REGION, 0, 1 << 20)
            .unwrap()
            .iter()
            .all(|&b| b == 0)
    );

    // A resized partition moves the tail: nothing is written there.
    f.host.partitions.get_mut(REGION).unwrap().0.bytes = SPLIT_BYTES - (1 << 20);
    let error = rerun(&f, |c| c.action = Action::NextBoot(NextBoot::Macos))
        .unwrap_err()
        .to_string();
    assert!(error.contains("was resized"), "{error}");
    let error = rerun(&f, |c| c.action = Action::Status)
        .unwrap_err()
        .to_string();
    assert!(error.contains("was resized"), "{error}");
    f.host.partitions.get_mut(REGION).unwrap().0.bytes = SPLIT_BYTES;
    assert_eq!(state_of(&f, REGION), state);

    let removed = uninstall(&environment(&f.host), &f.esp, false).unwrap();
    assert!(
        removed.contains("install \"macOS\": disk1s2 keep macOS"),
        "{removed}"
    );
    assert_eq!(state_of(&f, REGION), state);
}

#[test]
fn the_tail_is_checked_and_an_existing_guest_disk_is_never_converted() {
    let refusal = |f: &Fixture, configure: &dyn Fn(&mut Request)| {
        let mut command = split_command(f);
        configure(&mut command);
        setup(&environment(&f.host), command)
            .unwrap_err()
            .to_string()
    };
    // A tail holding other bytes needs --initialize-nor, which writes a
    // fresh image there and leaves the SSD alone.
    let mut f = fixture(64 * GIB, false);
    add_split_disk(&mut f, false, &[]);
    f.host.write(REGION, tail(), b"not a NOR image").unwrap();
    let error = refusal(&f, &|_| {});
    assert!(error.contains("disk1s2's machine state"), "{error}");
    assert!(error.contains("--initialize-nor"), "{error}");
    let mut initialize = split_command(&f);
    initialize.initialize_nor = true;
    setup(&environment(&f.host), initialize).unwrap();
    assert_eq!(
        next_target(&tail_nvram(&f)),
        stela_loader::boot_selection::Target::MacOs { safe: false }
    );
    assert!(
        f.host
            .read(REGION, 0, 1 << 20)
            .unwrap()
            .iter()
            .all(|&b| b == 0)
    );

    // A guest disk that spans the whole partition is not converted; one
    // inside the SSD, laid out by an earlier one-partition install, is
    // kept.
    let blocks = SPLIT_BYTES / 512;
    let mut f = fixture(64 * GIB, false);
    add_split_disk(&mut f, false, &guest_gpt(blocks - 1));
    let error = refusal(&f, &|c| c.erase_target = true);
    assert!(error.contains("is not converted"), "{error}");
    assert!(error.contains("--nor"), "{error}");
    let mut f = fixture(64 * GIB, false);
    add_split_disk(&mut f, false, &guest_gpt(tail() / 512 - 1));
    let mut dry = split_command(&f);
    dry.dry_run = true;
    let plan = setup(&environment(&f.host), dry).unwrap();
    assert!(plan.contains("already holds a guest disk"), "{plan}");

    // The SSD before the tail must still hold 64 GB.
    let mut f = fixture(64 * GIB, false);
    add_split_disk(&mut f, false, &[]);
    f.host.partitions.get_mut(REGION).unwrap().0.bytes = 64_000_000_000;
    assert!(refusal(&f, &|_| {}).contains("before the machine state"));

    // An install with a machine-state partition of its own keeps it: its
    // Apple region is not added again as a one-partition install.
    let mut f = fixture(64 * GIB, false);
    add_installed_disk(&mut f, &[], &[]);
    setup(&environment(&f.host), installed_command(&f)).unwrap();
    let before = snapshot(&f.esp);
    let error = rerun(&f, |c| {
        c.target = Some(REGION.into());
        c.install = Some("Again".into());
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("not converted"), "{error}");
    assert_eq!(snapshot(&f.esp), before);
    // Its separate partition still holds its machine state.
    let record = record(&f);
    assert_eq!(record.installs[0].disk.machine_state_offset, None);
    assert!(
        record
            .options
            .contains(&format!("--nor {SERIAL}:{NOR_GUID}")),
        "{}",
        record.options
    );

    // A further disk can be a one-partition install beside it.
    add_split_disk(&mut f, true, &[]);
    let added = rerun(&f, |c| {
        c.target = Some(REGION2.into());
        c.install = Some("Other".into());
        c.ipsw = Some(f.ipsw.clone());
    })
    .unwrap();
    assert!(
        added.contains("machine state  the tail of disk2s2"),
        "{added}"
    );
    let record = self::record(&f);
    assert_eq!(record.installs[1].disk.machine_state_offset, Some(tail()));
    let choices = Choices::parse(&fs::read_to_string(f.esp.join(CHOICES_PATH)).unwrap()).unwrap();
    let region2 = format!("{SERIAL2}:{REGION2_GUID}");
    assert!(
        choices.entries[2]
            .options
            .contains(&format!("--storage {region2} --nor {region2}")),
        "{}",
        choices.entries[2].options
    );
    // Its Install choice restores onto the region with the tail kept.
    assert_eq!(choices.entries[3].name, "Other - Install macOS");
    for entry in &choices.entries[3..4] {
        assert!(
            entry
                .options
                .contains(&format!("--storage {region2} --nor {region2} --bundle")),
            "{}",
            entry.options
        );
    }
}
#[test]
fn observed_firmware_setup_action_requires_capability_and_preserves_dry_run() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
    let inventory = f._dir.path().join("observed-firmware.json");
    fs::write(&inventory, br#"{"schema":1,"complete":true,"requirements":[{"name":"rtl_nic/rtl8168e-3.fw","target":{"driver":"realtek","hardware":"10ec:8168","revision":"xid-2c8","board":null},"minimum_bytes":4}]}"#).unwrap();
    let before = snapshot(&f.esp);
    assert!(
        rerun(&f, |c| {
            c.action = Action::HostFirmwareFetch(inventory.clone());
            c.dry_run = true;
        })
        .unwrap_err()
        .to_string()
        .contains("predates host firmware")
    );
    assert_eq!(snapshot(&f.esp), before);
    let capable = f._dir.path().join("firmware-capable.efi");
    let mut image = efi_image(b"observed-firmware-capable");
    let mut legacy_marker = stela_loader::host_firmware::MOUNT_CAPABILITY;
    legacy_marker[20] = 1;
    image.extend_from_slice(&legacy_marker);
    fs::write(&capable, image).unwrap();
    rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(capable.clone());
    })
    .unwrap();
    let before = snapshot(&f.esp);
    let cache = f._dir.path().join("firmware-cache");
    let report = rerun(&f, |c| {
        c.action = Action::HostFirmwareFetch(inventory.clone());
        c.host_firmware_cache = Some(cache.clone());
        c.dry_run = true;
    })
    .unwrap();
    assert!(report.contains("1 exact observed bindings"));
    assert!(report.contains("3872 bytes"));
    assert_eq!(snapshot(&f.esp), before);
    assert!(!cache.exists());
}

#[test]
fn large_firmware_refuses_legacy_install_update_rollback_and_reinstall_before_writes() {
    use sha2::{Digest, Sha256};
    use stela_loader::host_firmware::{DIRECTORY, MOUNT_CAPABILITY, Package};
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
    let legacy = f._dir.path().join("firmware-v1.efi");
    let mut marker = MOUNT_CAPABILITY;
    marker[20] = 1;
    let mut image = efi_image(b"firmware-v1");
    image.extend_from_slice(&marker);
    fs::write(&legacy, image).unwrap();
    rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(legacy.clone());
    })
    .unwrap();
    let source = f._dir.path().join("large-package");
    fs::create_dir(&source).unwrap();
    let bytes = vec![0x5a; 16 * 1024 * 1024 + 1];
    fs::write(source.join("data.bin"), &bytes).unwrap();
    fs::write(source.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
        "schema":1,"images":[{"name":"fixture/large.bin","path":"data.bin",
        "length":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),
        "target":{"driver":"fixture","hardware":"synthetic","revision":"v1","board":null},
        "provenance":{"source":"synthetic","revision":"v1","member":"fixture/large.bin","license":"CC0-1.0"}}]
    })).unwrap()).unwrap();
    drop(bytes);
    let before = snapshot(&f.esp);
    for dry in [true, false] {
        let error = rerun(&f, |c| {
            c.action = Action::HostFirmwareInstall(source.clone());
            c.dry_run = dry;
        })
        .unwrap_err();
        assert!(error.to_string().contains("image limit"), "{error:#}");
        assert_eq!(snapshot(&f.esp), before);
    }
    let current = f._dir.path().join("firmware-v2.efi");
    let mut image = efi_image(b"firmware-v2");
    image.extend_from_slice(&MOUNT_CAPABILITY);
    fs::write(&current, image).unwrap();
    rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(current.clone());
    })
    .unwrap();
    rerun(&f, |c| {
        c.action = Action::HostFirmwareInstall(source.clone())
    })
    .unwrap();
    let loaded = Package::read(&f.esp.join(DIRECTORY)).unwrap();
    assert_eq!(loaded.inventory(), (1, 16 * 1024 * 1024 + 1));
    assert!(loaded.check_mount(&fs::read(&current).unwrap()).is_ok());
    assert!(loaded.check_mount(&fs::read(&legacy).unwrap()).is_err());
    let before = snapshot(&f.esp);
    let error = rerun(&f, |c| c.action = Action::Rollback).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot load installed host firmware"),
        "{error:#}"
    );
    assert_eq!(snapshot(&f.esp), before);
    let error = rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(legacy.clone());
    })
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("cannot load installed host firmware"),
        "{error:#}"
    );
    assert_eq!(snapshot(&f.esp), before);

    // Uninstall retains independently managed host firmware. A new setup
    // must check it during planning, even when there is no setup record.
    let firmware_before = snapshot(&f.esp.join(DIRECTORY));
    rerun(&f, |c| c.action = Action::Uninstall).unwrap();
    assert!(!f.esp.join(RECORD).exists());
    assert_eq!(snapshot(&f.esp.join(DIRECTORY)), firmware_before);
    let before = snapshot(&f.esp);
    for candidate in [&legacy, &f.efi] {
        for dry in [true, false] {
            let mut reinstall = command(&f, &f.esp);
            reinstall.efi = Some(candidate.clone());
            reinstall.dry_run = dry;
            let error = setup(&environment(&f.host), reinstall).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("cannot load installed host firmware"),
                "{error:#}"
            );
            assert_eq!(snapshot(&f.esp), before);
        }
    }
    let mut reinstall = command(&f, &f.esp);
    reinstall.efi = Some(current.clone());
    reinstall.dry_run = true;
    setup(&environment(&f.host), reinstall).unwrap();
    assert_eq!(snapshot(&f.esp), before);
    let mut reinstall = command(&f, &f.esp);
    reinstall.efi = Some(current);
    setup(&environment(&f.host), reinstall).unwrap();
    assert!(record(&f).complete);
    assert_eq!(snapshot(&f.esp.join(DIRECTORY)), firmware_before);
}

#[test]
fn host_firmware_action_validates_dry_run_and_publishes_separately_from_guest_bundles() {
    let mut f = fixture(64 * GIB, false);
    add_stela(&mut f);
    setup(&environment(&f.host), command(&f, &f.esp)).unwrap();
    let source = f._dir.path().join("firmware-package");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("data.bin"), b"abc").unwrap();
    fs::write(source.join("manifest.json"), serde_json::to_vec(&serde_json::json!({
        "schema": 1, "images": [{"name":"Vendor/FW.bin", "path":"data.bin", "length":3,
        "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "target":{"driver":"fixture","hardware":"synthetic","revision":"v1","board":null},
        "provenance":{"source":"synthetic","revision":"v1","member":"fixtures/abc.bin","license":"CC0-1.0"}}]
    })).unwrap()).unwrap();
    let old = snapshot(&f.esp);
    let mut unsupported = command(&f, &f.esp);
    unsupported.action = Action::HostFirmwareInstall(source.clone());
    assert!(
        unsupported
            .dispatch(&environment(&f.host))
            .unwrap_err()
            .to_string()
            .contains("predates host firmware")
    );
    assert_eq!(snapshot(&f.esp), old);
    let aware = f._dir.path().join("firmware-aware.efi");
    let mut image = efi_image(b"firmware-aware");
    let mut legacy_marker = stela_loader::host_firmware::MOUNT_CAPABILITY;
    legacy_marker[20] = 1;
    image.extend_from_slice(&legacy_marker);
    fs::write(&aware, image).unwrap();
    rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(aware.clone());
    })
    .unwrap();
    let before = snapshot(&f.esp);
    let mut dry = command(&f, &f.esp);
    dry.action = Action::HostFirmwareInstall(source.clone());
    dry.dry_run = true;
    let report = dry.dispatch(&environment(&f.host)).unwrap();
    assert!(report.contains("1 verified resources, 3 bytes"));
    assert_eq!(snapshot(&f.esp), before);
    let mut write = command(&f, &f.esp);
    write.action = Action::HostFirmwareInstall(source.clone());
    write.dispatch(&environment(&f.host)).unwrap();
    let published = f.esp.join(stela_loader::host_firmware::MANIFEST_PATH);
    assert!(published.is_file());
    for (path, bytes) in &before {
        assert_eq!(&fs::read(path).unwrap(), bytes);
    }
    let active = fs::read(&published).unwrap();
    let firmware_before = snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY));
    let new_efi = f._dir.path().join("firmware-test-update.efi");
    let mut image = efi_image(b"firmware-test-update");
    image.extend_from_slice(&stela_loader::host_firmware::MOUNT_CAPABILITY);
    fs::write(&new_efi, image).unwrap();
    rerun(&f, |c| {
        c.action = Action::UpdateStela;
        c.efi = Some(new_efi.clone());
    })
    .unwrap();
    assert_eq!(
        snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY)),
        firmware_before
    );
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    let new_os = f._dir.path().join("firmware-test-update.ipsw");
    restore::payload::synthetic_ipsw_of(&new_os, "STELA2").unwrap();
    rerun(&f, |c| {
        c.action = Action::UpdateOs;
        c.ipsw = Some(new_os.clone());
    })
    .unwrap();
    assert_eq!(
        snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY)),
        firmware_before
    );
    rerun(&f, |c| c.action = Action::Rollback).unwrap();
    rerun(&f, |c| c.action = Action::Repair).unwrap();
    assert_eq!(
        snapshot(&f.esp.join(stela_loader::host_firmware::DIRECTORY)),
        firmware_before
    );
    let before_downgrade = snapshot(&f.esp);
    assert!(
        rerun(&f, |c| {
            c.action = Action::UpdateStela;
            c.efi = Some(f.efi.clone());
        })
        .unwrap_err()
        .to_string()
        .contains("cannot load installed host firmware")
    );
    assert_eq!(snapshot(&f.esp), before_downgrade);
    assert!(
        rerun(&f, |c| c.action = Action::Rollback)
            .unwrap_err()
            .to_string()
            .contains("cannot load installed host firmware")
    );
    assert_eq!(snapshot(&f.esp), before_downgrade);
    fs::write(source.join("data.bin"), b"abd").unwrap();
    let mut corrupt = command(&f, &f.esp);
    corrupt.action = Action::HostFirmwareInstall(source);
    assert!(corrupt.dispatch(&environment(&f.host)).is_err());
    assert_eq!(fs::read(published).unwrap(), active);
}
