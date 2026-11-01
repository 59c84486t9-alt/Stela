//! macOS owns APFS writes, directory trust and the native arm64e disk link.
//! Private ABI declarations are bounded by the 26A434 libbootpolicy and
//! libsystem_sandbox evidence recorded in docs/research/gpu-maintenance.md.
use super::{
    BUNDLE_PATH, Install, KEXT, PLUGIN, Payload, executable, policy,
    publication::{Publication, RECEIPT},
};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha384};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
};
use stela_loader::{im4m::Value, local_policy::LocalPolicy};

const TRUST_CLASS: &CStr = c"KernelExtensionManagement";

struct Library(*mut c_void);

impl Library {
    fn open(path: &CStr) -> Result<Self> {
        // SAFETY: the name is terminated and names a system-owned library.
        let library = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        ensure!(!library.is_null(), "cannot open {}", path.to_string_lossy());
        Ok(Self(library))
    }

    fn symbol(&self, name: &CStr) -> Result<*mut c_void> {
        // SAFETY: this handle stays open throughout every use of the symbol.
        let symbol = unsafe { libc::dlsym(self.0, name.as_ptr()) };
        ensure!(!symbol.is_null(), "macOS lacks {}", name.to_string_lossy());
        Ok(symbol)
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: open returned this handle and only this owner closes it.
        unsafe {
            libc::dlclose(self.0);
        }
    }
}

type Trusted = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
type RestrictedMkdir = unsafe extern "C" fn(*const c_char, libc::mode_t, *const c_char) -> c_int;

struct DirectoryTrust {
    _library: Library,
    check: Trusted,
    mkdir: RestrictedMkdir,
}

impl DirectoryTrust {
    fn open() -> Result<Self> {
        let library = Library::open(c"/usr/lib/system/libsystem_sandbox.dylib")?;
        // SAFETY: the declarations match Apple's staging.m and the target ABI.
        let check = unsafe {
            std::mem::transmute::<*mut c_void, Trusted>(
                library.symbol(c"rootless_check_trusted_class")?,
            )
        };
        // SAFETY: same, with Darwin's mode_t from libc.
        let mkdir = unsafe {
            std::mem::transmute::<*mut c_void, RestrictedMkdir>(
                library.symbol(c"rootless_mkdir_restricted")?,
            )
        };
        Ok(Self {
            _library: library,
            check,
            mkdir,
        })
    }

    fn verify(&self, path: &Path) -> Result<()> {
        let name = cpath(path)?;
        // SAFETY: both strings remain live and terminated through the call.
        let result = unsafe { (self.check)(name.as_ptr(), TRUST_CLASS.as_ptr()) };
        ensure!(
            result == 0,
            "macOS does not trust {} as KernelExtensionManagement (result {result})",
            path.display()
        );
        Ok(())
    }

    fn create(&self, path: &Path) -> Result<()> {
        let name = cpath(path)?;
        // SAFETY: the path and class are terminated; the parent was checked.
        let result = unsafe { (self.mkdir)(name.as_ptr(), 0o755, TRUST_CLASS.as_ptr()) };
        ensure!(
            result == 0,
            "macOS refused protected directory {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        self.verify(path)
    }
}

fn cpath(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("path contains a NUL")
}

fn mounted_apfs(path: &Path) -> Result<u64> {
    let name = cpath(path)?;
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: statfs receives a terminated path and writable storage of its
    // platform-defined size. A successful call initializes the entire struct.
    let result = unsafe { libc::statfs(name.as_ptr(), info.as_mut_ptr()) };
    ensure!(
        result == 0,
        "cannot inspect mounted volume {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful call above initialized info and both arrays
    // contain terminated filesystem and mount names under Darwin's contract.
    let info = unsafe { info.assume_init() };
    // SAFETY: statfs's fixed filesystem-name array is terminated by the kernel.
    let filesystem = unsafe { CStr::from_ptr(info.f_fstypename.as_ptr()) };
    // SAFETY: the mount-name array is terminated by the kernel too.
    let mount = unsafe { CStr::from_ptr(info.f_mntonname.as_ptr()) };
    ensure!(
        filesystem == c"apfs" && mount.to_bytes() == path.as_os_str().as_bytes(),
        "{} is not the root of a mounted APFS volume",
        path.display()
    );
    let metadata = fs::metadata(path)?;
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "mounted volume root is not root-owned and protected: {}",
        path.display()
    );
    Ok(metadata.dev())
}

fn status(command: &mut Command) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("running {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn sync_tree(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "installation acquired a symlink: {}",
        path.display()
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            sync_tree(&entry?.path())?;
        }
    } else {
        ensure!(metadata.is_file(), "installation acquired a special file");
    }
    File::open(path)?.sync_all()?;
    Ok(())
}

fn full_sync(path: &Path) -> Result<()> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    file.sync_all()?;
    // SAFETY: F_FULLFSYNC takes no third argument. This live file descriptor
    // is on the APFS volume whose previously synced writes must be durable.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) };
    ensure!(
        result == 0,
        "APFS full sync failed for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}

/// No component between the writable volume and its destination may redirect
/// writes or admit an unprivileged replacement while maintenance is running.
fn parent(volume: &Path, relative: &str) -> Result<PathBuf> {
    let mut path = volume.to_owned();
    for component in relative.split('/') {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new().mode(0o755).create(&path)?;
                File::open(path.parent().unwrap())?.sync_all()?;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "maintenance destination is not a root-owned, protected directory: {}",
            path.display()
        );
    }
    Ok(path)
}

fn prepare(trust: &DirectoryTrust, parent: &Path, name: &str) -> Result<Publication> {
    let staged = parent.join(format!(".stela-{}-{name}", std::process::id()));
    match fs::symlink_metadata(&staged) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => anyhow::bail!("staging path already exists: {}", staged.display()),
    }
    trust.create(&staged)?;
    Ok(Publication::new(staged, parent.join(name)))
}

fn copy(payload: &Payload, source: &Path, name: &str, target: &Path) -> Result<()> {
    let prefix = format!("{name}/");
    for (path, digest) in &payload.files {
        let Some(relative) = path.strip_prefix(&prefix) else {
            continue;
        };
        let bytes = fs::read(source.join(path))?;
        ensure!(
            *digest == stela_formats::sha256(&bytes),
            "GPU source changed during maintenance: {path}"
        );
        let destination = target.join(relative);
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(destination.parent().unwrap())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        file.write_all(&bytes)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
    }
    let executable = target.join("Contents/MacOS/StelaGPU");
    if executable.try_exists()? {
        fs::set_permissions(executable, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

type Nonce = unsafe extern "C" fn() -> c_int;
type DigestNonce = unsafe extern "C" fn(*mut u8) -> c_int;
type Paired =
    unsafe extern "C" fn(*const c_char, *const u8, *const c_char, u32, *const c_void) -> c_int;
type Create = unsafe extern "C" fn(
    *const c_char,
    *const u8,
    *const u8,
    *const c_char,
    u32,
    *const c_void,
    u64,
) -> c_int;
type WithSplat = unsafe extern "C" fn(
    *const c_char,
    *const u8,
    *const c_char,
    *const c_char,
    u32,
    *const c_void,
) -> c_int;

struct PolicyUpdate {
    _library: Library,
    begin: Nonce,
    end: Nonce,
    digest: DigestNonce,
    paired: Paired,
    create: Create,
    with_splat: WithSplat,
    root: CString,
    manifest: CString,
    splat: Option<CString>,
    group: [u8; 16],
    directory: PathBuf,
    next_stage: [u8; 48],
    commit_started: bool,
    written: Option<PathBuf>,
}

fn bp_status(operation: &str, result: c_int) -> Result<()> {
    ensure!(
        result == 0,
        "libbootpolicy {operation} failed with status {result}"
    );
    Ok(())
}

impl PolicyUpdate {
    fn open(options: &Install, root: &Path, group_directory: &Path) -> Result<Self> {
        let library = Library::open(c"/usr/lib/libbootpolicy.dylib")?;
        macro_rules! load {
            ($name:literal, $kind:ty) => {{
                let name = CString::new($name)?;
                // SAFETY: each type is the pinned libbootpolicy ABI. The
                // library remains live while any function pointer is used.
                unsafe { std::mem::transmute::<*mut c_void, $kind>(library.symbol(&name)?) }
            }};
        }
        let begin = load!("bootpolicy_update_local_policy_nonce_begin", Nonce);
        let end = load!("bootpolicy_update_local_policy_nonce_end", Nonce);
        let digest = load!(
            "bootpolicy_get_proposed_local_policy_nonce_digest",
            DigestNonce
        );
        let paired = load!("bootpolicy_create_paired_recoveryos_local_policy", Paired);
        let create = load!("bootpolicy_create_local_policy_ex2", Create);
        let with_splat = load!("bootpolicy_create_local_policy_with_splat", WithSplat);
        let manifest = fs::canonicalize(&options.manifest)?;
        ensure!(
            manifest.starts_with(group_directory),
            "next-stage manifest is outside the selected Preboot volume group"
        );
        let manifest_bytes = fs::read(&manifest)?;
        stela_loader::im4m::parse(&manifest_bytes).context("next-stage input is not an IM4M")?;
        let splat = options
            .splat
            .as_ref()
            .map(|path| -> Result<_> {
                let path = fs::canonicalize(path)?;
                ensure!(
                    path.starts_with(group_directory),
                    "splat manifest is outside the selected Preboot group"
                );
                stela_loader::im4m::parse(&fs::read(&path)?)
                    .context("splat input is not an IM4M")?;
                cpath(&path)
            })
            .transpose()?;
        Ok(Self {
            _library: library,
            begin,
            end,
            digest,
            paired,
            create,
            with_splat,
            root: cpath(root)?,
            manifest: cpath(&manifest)?,
            splat,
            group: options.volume_group,
            directory: parent(group_directory, "LocalPolicy")?,
            next_stage: Sha384::digest(manifest_bytes).into(),
            commit_started: false,
            written: None,
        })
    }
}

impl policy::Update for PolicyUpdate {
    fn begin(&mut self) -> Result<()> {
        // SAFETY: the ABI takes no arguments, as in restored's call sequence.
        bp_status("nonce begin", unsafe { (self.begin)() })
    }

    fn write_and_verify(&mut self) -> Result<()> {
        let mut nonce = [0; 48];
        // SAFETY: the output is the library's required 48-byte SHA-384 buffer.
        bp_status("proposed nonce digest", unsafe {
            (self.digest)(nonce.as_mut_ptr())
        })?;
        for suffix in [".img4", ".recovery.img4"] {
            for digest in [hex::encode(nonce), hex::encode_upper(nonce)] {
                let path = self.directory.join(format!("{digest}{suffix}"));
                match fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => anyhow::bail!(
                        "refusing to overwrite an existing policy at {}",
                        path.display()
                    ),
                }
            }
        }
        // SAFETY: all input buffers stay live; no ACM authorisation is
        // invented. 2 requests Reduced Security. Custom OS type 4 reads the
        // paired policy from this same group, as restored does.
        bp_status("paired recoveryOS policy", unsafe {
            (self.paired)(
                self.root.as_ptr(),
                self.group.as_ptr(),
                self.manifest.as_ptr(),
                2,
                std::ptr::null(),
            )
        })?;
        let result = if let Some(splat) = &self.splat {
            // SAFETY: the same pinned ABI, with a terminated splat path.
            unsafe {
                (self.with_splat)(
                    self.root.as_ptr(),
                    self.group.as_ptr(),
                    self.manifest.as_ptr(),
                    splat.as_ptr(),
                    2,
                    std::ptr::null(),
                )
            }
        } else {
            // SAFETY: type 4 does not use recoveryOS UUID (argument 1).
            unsafe {
                (self.create)(
                    self.root.as_ptr(),
                    self.group.as_ptr(),
                    self.group.as_ptr(),
                    self.manifest.as_ptr(),
                    2,
                    std::ptr::null(),
                    4,
                )
            }
        };
        bp_status("macOS policy", result)?;
        let path = self.directory.join(format!("{}.img4", hex::encode(nonce)));
        // libbootpolicy writes hex in uppercase; select that exact spelling
        // on a case-sensitive Preboot filesystem too.
        let path = if path.try_exists()? {
            path
        } else {
            self.directory
                .join(format!("{}.img4", hex::encode_upper(nonce)))
        };
        let bytes = fs::read(&path)
            .with_context(|| format!("libbootpolicy did not write {}", path.display()))?;
        let parsed = LocalPolicy::parse(&path.to_string_lossy(), &bytes)?;
        ensure!(
            parsed.volume_group == Some(self.group)
                && parsed.nsih == Some(hex::encode_upper(self.next_stage)),
            "new LocalPolicy names another volume or next stage"
        );
        let property = |name: &str| {
            parsed
                .properties
                .iter()
                .find(|property| property.name == name)
                .map(|property| &property.value)
        };
        ensure!(
            property("lpnh") == Some(&Value::Data(nonce.to_vec())),
            "new LocalPolicy names another nonce"
        );
        ensure!(
            property("smb2") == Some(&Value::Boolean(true))
                && property("sip0") == Some(&Value::Integer(0x201)),
            "maintenance boot has no bounded GPU kext grant; boot this system through a Stela image with GPU drivers"
        );
        for name in ["auxp", "auxi", "auxr"] {
            ensure!(
                matches!(property(name), Some(Value::Data(bytes)) if bytes.len() == 48),
                "new LocalPolicy lacks {name}"
            );
        }
        File::open(&path)?.sync_all()?;
        // The macOS policy consumes the paired policy. Both files must reach
        // durable storage before SEP blesses their proposed nonce.
        let paired = self
            .directory
            .join(format!("{}.recovery.img4", hex::encode(nonce)));
        let paired = if paired.try_exists()? {
            paired
        } else {
            self.directory
                .join(format!("{}.recovery.img4", hex::encode_upper(nonce)))
        };
        File::open(&paired)?.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        File::open(self.directory.parent().unwrap())?.sync_all()?;
        full_sync(&paired)?;
        full_sync(&path)?;
        self.written = Some(path);
        Ok(())
    }

    fn commit(&mut self) -> Result<()> {
        self.commit_started = true;
        // SAFETY: no-argument nonce end is the durable transaction boundary.
        bp_status("nonce end", unsafe { (self.end)() })
    }
}

pub(super) fn install(options: Install) -> Result<()> {
    // SAFETY: geteuid has no arguments or side effects.
    let effective_uid = unsafe { libc::geteuid() };
    ensure!(
        effective_uid == 0,
        "GPU maintenance installation requires root"
    );
    let payload_root = fs::canonicalize(&options.payload)?;
    let payload = Payload::load(&payload_root)?;
    let data = fs::canonicalize(&options.data_volume)?;
    let preboot = fs::canonicalize(&options.preboot)?;
    ensure!(
        data != preboot && data.is_dir() && preboot.is_dir(),
        "Data and Preboot must be separate mounted directories"
    );
    let data_fsid = mounted_apfs(&data)?;
    let preboot_fsid = mounted_apfs(&preboot)?;
    ensure!(
        data_fsid != preboot_fsid,
        "Data and Preboot refer to the same APFS volume"
    );
    let group = format_uuid(options.volume_group);
    let group_directory = fs::canonicalize(preboot.join(&group))
        .context("selected Preboot volume group is absent")?;
    ensure!(
        group_directory.parent() == Some(preboot.as_path()),
        "Preboot group redirects outside its mounted volume"
    );
    let group_metadata = fs::metadata(&group_directory)?;
    ensure!(
        group_metadata.is_dir() && group_metadata.uid() == 0 && group_metadata.mode() & 0o022 == 0,
        "Preboot group is not a root-owned protected directory"
    );
    let mut policy = PolicyUpdate::open(&options, &preboot, &group_directory)?;
    let trust = DirectoryTrust::open()?;
    let extensions = parent(&data, "Library/Extensions")?;
    let bundles = parent(&data, "Library/GPUBundles")?;
    let mut kext = prepare(&trust, &extensions, KEXT)?;
    let mut plugin = prepare(&trust, &bundles, PLUGIN)?;
    copy(&payload, &payload_root, KEXT, &kext.staged)?;
    copy(&payload, &payload_root, PLUGIN, &plugin.staged)?;
    let mut link = Command::new(&options.linker);
    link.args([
        "-arch",
        "arm64e",
        "-kext",
        "-undefined",
        "dynamic_lookup",
        "-no_adhoc_codesign",
        "-platform_version",
        "macos",
        "27.0",
        "27.0",
    ]);
    for path in payload
        .files
        .keys()
        .filter(|path| path.starts_with(&format!("{KEXT}/")) && path.ends_with(".o"))
    {
        link.arg(
            kext.staged
                .join(path.strip_prefix(&format!("{KEXT}/")).unwrap()),
        );
    }
    let disk_executable = kext.staged.join("StelaGPU");
    status(link.arg("-o").arg(&disk_executable))
        .context("on-disk kext link needs Apple's native arm64e linker")?;
    let mut bytes = fs::read(&disk_executable)?;
    let mut source_uuid = [0; 16];
    hex::decode_to_slice(&payload.kext_uuid, &mut source_uuid)?;
    executable::set_uuid(&mut bytes, source_uuid)?;
    fs::write(&disk_executable, bytes)?;
    fs::set_permissions(&disk_executable, fs::Permissions::from_mode(0o755))?;
    let receipt = serde_json::to_vec_pretty(&serde_json::json!({
        "installer": "stela-gpu-maintenance-v1", "volume_group": group,
        "kext_path": BUNDLE_PATH, "source_uuid": payload.kext_uuid, "source_files": payload.files,
        "disk_executable_unsigned_sha256": stela_formats::sha256(&fs::read(&disk_executable)?)
    }))?;
    for publication in [&kext, &plugin] {
        fs::write(publication.staged.join(RECEIPT), &receipt)?;
        fs::set_permissions(
            publication.staged.join(RECEIPT),
            fs::Permissions::from_mode(0o644),
        )?;
        File::open(publication.staged.join(RECEIPT))?.sync_all()?;
        File::open(&publication.staged)?.sync_all()?;
        trust.verify(&publication.staged)?;
    }
    // Include the ownership receipt in the kext's resource seal. No file
    // inside it may be added after codesign has sealed the bundle.
    status(
        Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(&kext.staged),
    )?;
    status(
        Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(&kext.staged),
    )?;
    sync_tree(&kext.staged)?;
    sync_tree(&plugin.staged)?;
    let result = (|| {
        kext.publish()?;
        plugin.publish()?;
        trust.verify(&kext.destination)?;
        trust.verify(&plugin.destination)?;
        full_sync(&kext.destination.join(RECEIPT))?;
        policy::transact(&mut policy)
    })();
    if let Err(error) = result {
        if !policy.commit_started {
            let plugin_rollback = plugin
                .rollback()
                .and_then(|()| full_sync(&plugin.staged.join(RECEIPT)));
            let kext_rollback = kext
                .rollback()
                .and_then(|()| full_sync(&kext.staged.join(RECEIPT)));
            let failures = [
                ("Metal bundle", plugin_rollback),
                ("GPU kext", kext_rollback),
            ]
            .into_iter()
            .filter_map(|(component, result)| {
                result
                    .err()
                    .map(|failure| format!("{component}: {failure:#}"))
            })
            .collect::<Vec<_>>();
            if !failures.is_empty() {
                return Err(error.context(format!(
                    "rollback failed; retain staging and backups for recovery: {}",
                    failures.join("; ")
                )));
            }
        }
        return Err(error.context(format!(
            "maintenance recovery paths: kext staging {}, backup {}; Metal staging {}, backup {}",
            kext.staged.display(),
            kext.backup
                .as_ref()
                .map_or_else(|| "none".into(), |path| path.display().to_string()),
            plugin.staged.display(),
            plugin
                .backup
                .as_ref()
                .map_or_else(|| "none".into(), |path| path.display().to_string()),
        )));
    }
    for publication in [&kext, &plugin] {
        if let Some(backup) = &publication.backup {
            println!("Previous component retained at {}", backup.display());
        }
    }
    println!(
        "GPU files installed; LocalPolicy committed at {}. Reboot through the matching Stela image to activate.",
        policy.written.as_ref().unwrap().display()
    );
    Ok(())
}

fn format_uuid(uuid: [u8; 16]) -> String {
    let hex = hex::encode_upper(uuid);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
