//! `sysctl` and `sysctlbyname` (`bsd/kern/kern_newsysctl.c`).
//!
//! The kernel the guest runs on is the host's, so the kernel's own
//! variables (`kern.*`, `vm.*`, `vfs.*`, `net.*`, ...) are the host's and
//! are forwarded, except the guest system's identity: the kernel's
//! (`kern.version` and `kern.osrelease`), from the kernel version its
//! install recorded, and the release launchd publishes at boot
//! (`kern.osversion`, `kern.osproductversion`, `kern.iossupportversion`),
//! from its `SystemVersion.plist` ([`Release`]). The machine is the modeled Apple-silicon one: the `hw.*`
//! and `machdep.*` namespaces are owned here and answered as an arm64 XNU
//! release kernel answers them (`bsd/kern/kern_mib.c`,
//! `bsd/dev/arm64/sysctl.c`) for [`Hardware`] and the PE's identification
//! registers. An owned name absent from the original ARM publication
//! (`machdep.cpu.vendor`, ...) is `ENOENT`; a published name whose
//! contents this model does not yet answer stops the process naming it.
//! Compatibility names such as `hw.optional.avx2_0` have metadata in the
//! original ARM kernel, independently of content support here.
//!
//! Numeric and textual requests share a process-local namespace. Existing
//! host OIDs retain their names; a published member absent on the host
//! receives a synthetic child OID under its published parent branch.
use super::{Call, Kernel, Outcome, forward};
use crate::darwin::catalog;
use crate::hosted::darwin::{EFAULT, EINVAL, ENOENT, ENOMEM, EPERM, ERANGE};
use crate::hosted::{
    forward as host,
    hardware::{self, Hardware},
    memory,
};
use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use std::sync::OnceLock;

mod metadata;
mod namespace;

/// `CTL_MAXNAME`.
const MAX_NAME: u64 = 12;
const INT_BYTES: u64 = 4;
const CTL_UNSPEC: i32 = 0;
const CTL_KERN: i32 = 1;
const CTL_HW: i32 = 6;
const CTL_MACHDEP: i32 = 7;
/// The `sysctl.*` meta names under `CTL_UNSPEC`.
const META_NAME: i32 = 1;
const META_NEXT: i32 = 2;
const META_NAME_TO_OID: i32 = 3;
const META_FORMAT: i32 = 4;
const META_DESCRIPTION: i32 = 5;
/// The second component of a synthetic number: above every `OID_AUTO`
/// number the host can assign.
const SYNTHETIC: i32 = 0x4000_0000;
const CTLTYPE_INT: u32 = 2;
const CTLTYPE_STRING: u32 = 3;
const CTLTYPE_QUAD: u32 = 4;
const CTLTYPE_OPAQUE: u32 = 5;
const CTLFLAG_RD: u32 = 0x8000_0000;
const CTLFLAG_KERN: u32 = 0x0100_0000;
const CTLFLAG_LOCKED: u32 = 0x0080_0000;
const LITTLE_ENDIAN: i32 = 1234;
const CACHE_ENTRIES: usize = 10;

/// The namespaces whose variables describe the machine.
const OWNED: &[&str] = &["hw.", "machdep."];

/// Variables the installed guest system answers, absent when it did not
/// record them (an imported or development root), never the host's.
const INSTALLED: &[&str] = &[
    "kern.version",
    "kern.osrelease",
    "kern.osversion",
    "kern.osproductversion",
    "kern.iossupportversion",
];

/// The OS cryptex's version file, which CoreFoundation reads first.
const OS_CRYPTEX_SYSTEM_VERSION: &str =
    "System/Cryptexes/OS/System/Library/CoreServices/SystemVersion.plist";

/// The prefix of XNU's `version[]`, before `osrelease[]`.
const KERNEL_VERSION_PREFIX: &str = "Darwin Kernel Version ";

/// The guest system's release, from its `SystemVersion.plist`, which
/// launchd publishes at boot (`kern.osversion`, `kern.osproductversion`,
/// `kern.iossupportversion`): the OS cryptex's, then the system volume's,
/// as CoreFoundation looks them up, under the first guest root holding
/// one. Without one the variables are absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Release {
    pub(crate) build: Option<String>,
    pub(crate) product_version: Option<String>,
    pub(crate) ios_support_version: Option<String>,
}

impl Release {
    pub(crate) fn read(roots: &[PathBuf]) -> Result<Self> {
        let path = [OS_CRYPTEX_SYSTEM_VERSION, crate::preboot::SYSTEM_VERSION]
            .iter()
            .flat_map(|path| roots.iter().map(move |root| root.join(path)))
            .find(|path| path.is_file());
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let bytes =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        let plist = crate::restore::plist::decode(&bytes, Default::default())
            .map_err(|error| anyhow!("{} is not a property list: {error:?}", path.display()))?;
        let field = |key: &str| {
            plist
                .get(key)
                .and_then(|value| value.string().ok())
                .map(str::to_owned)
        };
        Ok(Self {
            build: field("ProductBuildVersion"),
            product_version: field("ProductVersion"),
            ios_support_version: field("iOSSupportVersion"),
        })
    }
}

/// `osrelease[]` of a kernel version: "Darwin Kernel Version 27.0.0: ..."
/// names release 27.0.0.
fn kernel_release(version: &str) -> Option<&str> {
    let (release, _) = version
        .strip_prefix(KERNEL_VERSION_PREFIX)?
        .split_once(':')?;
    Some(release)
}

/// Machine variables that are the host's own: its memory and byte order.
const HOST_MACHINE: &[&str] = &[
    "hw.memsize",
    "hw.memsize_usable",
    "hw.physmem",
    "hw.usermem",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// `SYSCTL_OUT` of an `int`.
    Int(i32),
    /// `SYSCTL_OUT` of a `long long`.
    Quad(i64),
    /// `sysctl_io_number` of a `long long`: a 4-byte buffer receives it as
    /// an `int` when it fits.
    Number(i64),
    /// A NUL-terminated string.
    String(String),
    Opaque(Vec<u8>),
    /// A `CTLTYPE_QUAD` handler that writes a byte buffer of its own size.
    QuadBytes(Vec<u8>),
    /// The arm64 kernel's handler fails with this errno.
    Fails(u64),
    /// A failing handler still declares a quad in oidfmt.
    FailsQuad(u64),
}

impl Value {
    fn kind(&self) -> u32 {
        match self {
            Self::Int(_) | Self::Fails(_) => CTLTYPE_INT,
            Self::Quad(_) | Self::Number(_) | Self::QuadBytes(_) | Self::FailsQuad(_) => {
                CTLTYPE_QUAD
            }
            Self::String(_) => CTLTYPE_STRING,
            Self::Opaque(_) => CTLTYPE_OPAQUE,
        }
    }

    fn format(&self) -> &'static str {
        match self {
            Self::Int(_) | Self::Fails(_) => "I",
            Self::Quad(_)
            | Self::Number(_)
            | Self::Opaque(_)
            | Self::QuadBytes(_)
            | Self::FailsQuad(_) => "Q",
            Self::String(_) => "A",
        }
    }

    /// The bytes `SYSCTL_OUT` produces for a buffer of `buffer` bytes.
    fn bytes(&self, buffer: Option<u64>) -> Result<Vec<u8>, u64> {
        Ok(match self {
            Self::Int(value) => value.to_le_bytes().to_vec(),
            Self::Quad(value) => value.to_le_bytes().to_vec(),
            Self::Number(value) if buffer == Some(INT_BYTES) => i32::try_from(*value)
                .map_err(|_| ERANGE)?
                .to_le_bytes()
                .to_vec(),
            Self::Number(value) => value.to_le_bytes().to_vec(),
            Self::String(value) => {
                let mut bytes = value.as_bytes().to_vec();
                bytes.push(0);
                bytes
            }
            Self::Opaque(bytes) | Self::QuadBytes(bytes) => bytes.clone(),
            Self::Fails(errno) | Self::FailsQuad(errno) => return Err(*errno),
        })
    }
}

/// The machine variables of one hosted machine.
#[derive(Debug, Clone)]
pub(crate) struct Model {
    entries: Vec<(String, Value)>,
    namespace: OnceLock<namespace::Namespace>,
}

/// One performance level's cores and caches (`ml_cpu_get_info_type`).
/// One performance level: every core of one type (`cpu_type_for_perflevel`).
struct Level {
    name: &'static str,
    /// The type's cores in all its clusters (`ml_get_cpu_number_type`).
    cores: i32,
    maximum: i32,
    /// The cores sharing one L2: the type's first cluster's
    /// (`ml_cpu_cache_sharing(2, type)`).
    cores_per_l2: i32,
    /// The type's caches (`ml_cpu_get_info_type`), the L2 one cluster's.
    l1i: i64,
    l1d: i64,
    l2: i64,
}

impl Model {
    pub(crate) fn new(
        hardware: &Hardware,
        features: &[(&'static str, bool)],
        release: &Release,
    ) -> Self {
        let cpus = i32::from(hardware.cpus());
        let active = i32::from(hardware.active_cpus());
        let levels = levels(hardware);
        // Unscoped cache variables describe the lowest performance level.
        let lowest = levels.last().expect("a machine has a performance level");
        let page = memory::PAGE_BYTES as i64;
        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut add = |name: &str, value: Value| entries.push((name.to_owned(), value));
        for name in [
            "hw.ncpu",
            "hw.physicalcpu_max",
            "hw.logicalcpu_max",
            "machdep.cpu.cores_per_package",
            "machdep.cpu.logical_per_package",
        ] {
            add(name, Value::Int(cpus));
        }
        for name in [
            "hw.activecpu",
            "hw.physicalcpu",
            "hw.logicalcpu",
            "machdep.cpu.core_count",
            "machdep.cpu.thread_count",
        ] {
            add(name, Value::Int(active));
        }
        add("hw.byteorder", Value::Int(LITTLE_ENDIAN));
        add("hw.cputype", Value::Int(hardware::CPU_TYPE_ARM64 as i32));
        add(
            "hw.cpusubtype",
            Value::Int(hardware::CPU_SUBTYPE_ARM64E as i32),
        );
        add("hw.cpu64bit_capable", Value::Int(1));
        add("hw.cpufamily", Value::Int(hardware.cpu_family as i32));
        add("hw.cpusubfamily", Value::Int(hardware.cpu_subfamily as i32));
        if hardware.has_cache_sharing() {
            let mut config = [0u64; CACHE_ENTRIES];
            config[0] = u64::from(hardware.cpus());
            config[1] = 1;
            config[2] = lowest.cores_per_l2 as u64;
            add("hw.cacheconfig", Value::Opaque(words(&config)));
        }
        // XNU's sizes array is independent of cacheconfig's sharing map.
        // These are the virtual ARM cache-identification capacities, also
        // retained by uniform CPU0 execution, never measured host caches.
        let mut sizes = [0u64; CACHE_ENTRIES];
        sizes[0] = hardware.memory_bytes;
        sizes[1] = lowest.l1d as u64;
        sizes[2] = lowest.l2 as u64;
        add("hw.cachesize", Value::Opaque(words(&sizes)));
        add("hw.pagesize", Value::Number(page));
        add("hw.pagesize32", Value::Number(page));
        add("hw.pagesize_compat", Value::Int(page as i32));
        for name in [
            "hw.busfrequency",
            "hw.busfrequency_min",
            "hw.busfrequency_max",
            "hw.cpufrequency",
            "hw.cpufrequency_min",
            "hw.cpufrequency_max",
            "hw.busfrequency_compat",
            "hw.cpufrequency_compat",
        ] {
            // Release arm64 kernels publish no bus or CPU frequency.
            add(
                name,
                if name.ends_with("_compat") {
                    Value::Fails(ENOENT)
                } else {
                    Value::FailsQuad(ENOENT)
                },
            );
        }
        let line = i64::from(hardware.cache_line);
        add("hw.cachelinesize", Value::Quad(line));
        add("hw.cachelinesize_compat", Value::Int(line as i32));
        add("hw.l1icachesize", Value::Quad(lowest.l1i));
        add("hw.l1icachesize_compat", Value::Int(lowest.l1i as i32));
        add("hw.l1dcachesize", Value::Quad(lowest.l1d));
        add("hw.l1dcachesize_compat", Value::Int(lowest.l1d as i32));
        add("hw.l2cachesize", Value::Quad(lowest.l2));
        add("hw.l2cachesize_compat", Value::Int(lowest.l2 as i32));
        // Declared Apple profiles have no virtual L3. A native host's L3
        // capacity cannot replace this architectural absence.
        add("hw.l3cachesize", Value::FailsQuad(EINVAL));
        add("hw.l3cachesize_compat", Value::Fails(EINVAL));
        let timebase = crate::hosted::host::COUNTER_HZ as i64;
        add("hw.tbfrequency", Value::Number(timebase));
        add("hw.tbfrequency_compat", Value::Int(timebase as i32));
        add("hw.packages", Value::Int(1));
        add("hw.use_kernelmanagerd", Value::Int(1));
        add("hw.nperflevels", Value::Int(levels.len() as i32));
        add("hw.machine", Value::String("arm64".into()));
        add("hw.model", Value::String(hardware.model.into()));
        add("hw.product", Value::String(hardware.model.into()));
        add("hw.target", Value::String(hardware.target.into()));
        add("hw.vectorunit", Value::Int(1));
        for (index, level) in levels.iter().enumerate() {
            let prefix = format!("hw.perflevel{index}.");
            for field in ["physicalcpu", "logicalcpu"] {
                add(&format!("{prefix}{field}"), Value::Int(level.cores));
            }
            for field in ["physicalcpu_max", "logicalcpu_max"] {
                add(&format!("{prefix}{field}"), Value::Int(level.maximum));
            }
            if hardware.has_cache_sharing() {
                add(
                    &format!("{prefix}cpusperl2"),
                    Value::Int(level.cores_per_l2),
                );
            }
            add(
                &format!("{prefix}l1icachesize"),
                Value::Int(level.l1i as i32),
            );
            add(
                &format!("{prefix}l1dcachesize"),
                Value::Int(level.l1d as i32),
            );
            add(&format!("{prefix}l2cachesize"), Value::Int(level.l2 as i32));
            add(&format!("{prefix}l3cachesize"), Value::Fails(EINVAL));
            add(&format!("{prefix}cpusperl3"), Value::Fails(EINVAL));
            add(&format!("{prefix}name"), Value::String(level.name.into()));
        }
        add("hw.optional.floatingpoint", Value::Int(1));
        add("hw.optional.arm64", Value::Int(1));
        add(
            "hw.optional.watchpoint",
            Value::Int(hardware.watchpoints as i32),
        );
        add(
            "hw.optional.breakpoint",
            Value::Int(hardware.breakpoints as i32),
        );
        add("hw.optional.ucnormal_mem", Value::Int(1));
        let feature = |name: &str| {
            features
                .iter()
                .find(|(feature, _)| *feature == name)
                .is_some_and(|(_, present)| *present)
        };
        for (name, present) in features {
            add(
                &format!("hw.optional.arm.{name}"),
                Value::Int((*present).into()),
            );
        }
        add(
            "hw.optional.arm.caps",
            Value::QuadBytes(crate::hosted::features::capability_buffer(features).to_vec()),
        );
        // The streaming vector length in bytes, which XNU always publishes
        // and gives as 0 without SME (`arm_sme_svl_b`). A presented SME's
        // length is not in the identification, so it stays unanswered.
        if !feature("FEAT_SME") {
            add("hw.optional.arm.sme_max_svl_b", Value::Int(0));
        }
        for (legacy, name) in [
            ("neon", "AdvSIMD"),
            ("neon_hpfp", "AdvSIMD_HPFPCvt"),
            ("neon_fp16", "FEAT_FP16"),
            ("armv8_crc32", "FEAT_CRC32"),
            ("armv8_gpi", "FEAT_PACIMP"),
            ("armv8_1_atomics", "FEAT_LSE"),
            ("armv8_2_fhm", "FEAT_FHM"),
            ("armv8_2_sha512", "FEAT_SHA512"),
            ("armv8_2_sha3", "FEAT_SHA3"),
            ("armv8_3_compnum", "FEAT_FCMA"),
        ] {
            add(
                &format!("hw.optional.{legacy}"),
                Value::Int(feature(name).into()),
            );
        }
        add(
            "machdep.cpu.brand_string",
            Value::String(hardware.brand.into()),
        );
        add(
            "machdep.virtual_address_size",
            Value::Int(crate::hosted::tables::ADDRESS_BITS as i32),
        );
        add("machdep.ptrauth_enabled", Value::Int(1));
        // The kernelcache the board boots names its release, build date and
        // xnu tag, as the guest system's install recorded it.
        if let Some(version) = &hardware.kernel_version {
            add("kern.version", Value::String(version.clone()));
            if let Some(release) = kernel_release(version) {
                add("kern.osrelease", Value::String(release.into()));
            }
        }
        for (name, value) in [
            ("kern.osversion", &release.build),
            ("kern.osproductversion", &release.product_version),
            ("kern.iossupportversion", &release.ios_support_version),
        ] {
            if let Some(value) = value {
                add(name, Value::String(value.clone()));
            }
        }
        Self {
            entries,
            namespace: OnceLock::new(),
        }
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|(entry, _)| entry == name)
    }
}

fn levels(hardware: &Hardware) -> Vec<Level> {
    // Descending performance, as `cpu_type_for_perflevel` orders them.
    [true, false]
        .into_iter()
        .filter_map(|performance| {
            let mut clusters = hardware
                .clusters
                .iter()
                .filter(|cluster| cluster.performance == performance);
            let first = clusters.next()?;
            let others: i32 = clusters.map(|cluster| i32::from(cluster.cores)).sum();
            Some(Level {
                name: if performance {
                    "Performance"
                } else {
                    "Efficiency"
                },
                cores: if hardware.native_availability().is_some() {
                    i32::from(hardware.active_cpus())
                } else {
                    i32::from(first.cores) + others
                },
                maximum: if hardware.native_availability().is_some() {
                    i32::from(hardware.cpus())
                } else {
                    i32::from(first.cores) + others
                },
                cores_per_l2: first.cores.into(),
                l1i: first.l1i_bytes.into(),
                l1d: first.l1d_bytes.into(),
                l2: first.l2_bytes.into(),
            })
        })
        .collect()
}

fn words(values: &[u64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

/// How one machine variable resolves.
enum Lookup {
    Modeled(usize),
    /// The host's own variable.
    Host,
    /// The arm64 kernel publishes no such variable.
    Absent,
}

fn lookup(model: &Model, name: &str) -> Result<Lookup> {
    if let Some(index) = model.index(name) {
        return Ok(Lookup::Modeled(index));
    }
    if !OWNED.iter().any(|prefix| name.starts_with(prefix)) && !INSTALLED.contains(&name)
        || HOST_MACHINE.contains(&name)
    {
        return Ok(Lookup::Host);
    }
    if INSTALLED.contains(&name) {
        return Ok(Lookup::Absent);
    }
    if metadata::info(name).is_some() || name.starts_with("hw.features.") {
        crate::hosted::unsupported::refuse!(
            ENOENT,
            "the hosted machine model does not answer sysctl {name}"
        );
    }
    Ok(Lookup::Absent)
}

pub(super) fn call(kernel: &mut Kernel, call: &Call) -> Result<Option<Outcome>> {
    Ok(Some(match call.entry.name {
        "sysctl" => by_number(kernel, call)?,
        "sys_sysctlbyname" => by_name(kernel, call)?,
        _ => return Ok(None),
    }))
}

/// The request's old and new buffers (`struct sysctl_req`).
struct Request {
    old: u64,
    old_length: u64,
    new: u64,
}

impl Request {
    fn of(call: &Call) -> Self {
        Self {
            old: call.argument(2),
            old_length: call.argument(3),
            new: call.argument(4),
        }
    }

    /// `sysctl_root` over one modeled value: report or copy it out, and
    /// write the length back as `sysctl` does on success and on `ENOMEM`.
    fn answer(&self, value: &Value) -> Outcome {
        if self.new != 0 {
            return Outcome::Error(EPERM);
        }
        let buffer = if self.old_length == 0 {
            None
        } else {
            // XNU's fuulong returns -1 for an unreadable oldlenp; the
            // syscall reports EFAULT when it later publishes the length.
            Some(memory::read_u64(self.old_length).unwrap_or(u64::MAX))
        };
        let offered = if self.old == 0 { None } else { buffer };
        let bytes = match value.bytes(offered) {
            Ok(bytes) => bytes,
            Err(errno) => return Outcome::Error(errno),
        };
        self.out(&bytes)
    }

    fn out(&self, bytes: &[u8]) -> Outcome {
        self.out_parts(&[bytes])
    }

    /// `sysctl_old_user` copies one complete SYSCTL_OUT at a time. A
    /// short part is not copied or counted; earlier complete parts remain.
    fn out_parts(&self, parts: &[&[u8]]) -> Outcome {
        let capacity = if self.old_length == 0 {
            0
        } else {
            memory::read_u64(self.old_length).unwrap_or(u64::MAX)
        };
        let mut reported = 0u64;
        let mut error = None;
        for part in parts {
            let length = part.len() as u64;
            if self.old != 0 {
                if length > capacity.saturating_sub(reported) {
                    error = Some(ENOMEM);
                    break;
                }
                let Some(address) = self.old.checked_add(reported) else {
                    return Outcome::Error(EFAULT);
                };
                if !part.is_empty() && !memory::write(address, part) {
                    return Outcome::Error(EFAULT);
                }
            }
            reported += length;
        }
        if self.old_length != 0 && !memory::write_u64(self.old_length, reported) {
            return Outcome::Error(EFAULT);
        }
        error.map_or(Outcome::value(0), Outcome::Error)
    }
}

fn by_name(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let (pointer, length) = (call.argument(0), call.argument(1));
    if length >= crate::hosted::darwin::MAX_PATH as u64 {
        return Ok(Outcome::Error(namespace::ENAMETOOLONG));
    }
    let Some(bytes) = memory::read(pointer, length as usize) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let name = namespace::c_name(&bytes);
    if let Some(outcome) =
        namespace::named_value(&kernel.process.sysctl, &name, &Request::of(call))?
    {
        return Ok(outcome);
    }
    Ok(match lookup(&kernel.process.sysctl, &name)? {
        Lookup::Modeled(index) => Request::of(call).answer(&kernel.process.sysctl.entries[index].1),
        Lookup::Host => forward(kernel, call)?,
        Lookup::Absent => Outcome::Error(ENOENT),
    })
}

fn by_number(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let (pointer, count) = (call.argument(0), call.argument(1));
    if !(2..=MAX_NAME).contains(&count) {
        return Ok(Outcome::Error(EINVAL));
    }
    let Some(bytes) = memory::read(pointer, (count * INT_BYTES) as usize) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let oid: Vec<i32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| i32::from_le_bytes(*chunk))
        .collect();
    let request = Request::of(call);
    if oid[0] == CTL_UNSPEC {
        return meta(kernel, call, &oid, &request);
    }
    if ![CTL_KERN, CTL_HW, CTL_MACHDEP].contains(&oid[0]) {
        return forward(kernel, call);
    }
    if let Some(outcome) = namespace::numeric_value(&kernel.process.sysctl, &oid, &request)? {
        return Ok(outcome);
    }
    let Some(name) = host_name(&oid)? else {
        return forward(kernel, call);
    };
    Ok(match lookup(&kernel.process.sysctl, &name)? {
        Lookup::Modeled(index) => request.answer(&kernel.process.sysctl.entries[index].1),
        Lookup::Host => forward(kernel, call)?,
        Lookup::Absent => Outcome::Error(ENOENT),
    })
}

/// The host's dotted name for a numeric name, if it has one.
fn host_name(oid: &[i32]) -> Result<Option<String>> {
    let mut query = vec![CTL_UNSPEC, META_NAME];
    query.extend_from_slice(oid);
    let mut buffer = vec![0u8; 1024];
    let mut length = buffer.len() as u64;
    let number = catalog_number("sysctl")?;
    let returned = host::bsd(
        number,
        &[
            query.as_ptr() as u64,
            query.len() as u64,
            buffer.as_mut_ptr() as u64,
            &raw mut length as u64,
            0,
            0,
        ],
    );
    if returned.carry {
        return Ok(None);
    }
    let end = buffer[..length as usize]
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(length as usize);
    Ok(Some(String::from_utf8_lossy(&buffer[..end]).into_owned()))
}

fn catalog_number(name: &str) -> Result<u16> {
    (0..=u16::MAX)
        .map_while(catalog::entry)
        .find(|entry| entry.name == name)
        .map(|entry| entry.number)
        .with_context(|| format!("{name} is not in the BSD catalog"))
}

/// Metadata is resolved through the same owned namespace as value reads.
fn meta(kernel: &mut Kernel, call: &Call, oid: &[i32], request: &Request) -> Result<Outcome> {
    match namespace::answer(&kernel.process.sysctl, call, oid, request)? {
        Some(answer) => Ok(answer),
        None => forward(kernel, call),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Chip;

    /// A synthetic kernel version, as an install records it, and release.
    const VERSION: &str = "Darwin Kernel Version 1.2.3: synthetic; root:test~1/RELEASE_TEST";

    fn release() -> Release {
        Release {
            build: Some("0Z0".into()),
            product_version: Some("9.8.7".into()),
            ios_support_version: Some("6.5".into()),
        }
    }

    fn model() -> Model {
        let mut hardware = Hardware::of(Chip::AppleM2, 1 << 34).unwrap();
        hardware.kernel_version = Some(VERSION.into());
        Model::new(
            &hardware,
            &[("FEAT_LSE", true), ("AdvSIMD", true)],
            &release(),
        )
    }

    #[test]
    fn the_release_is_the_guest_systems_version_file() -> Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join(crate::preboot::SYSTEM_VERSION);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(
            &path,
            "<plist><dict><key>ProductBuildVersion</key><string>0Z0</string>\
             <key>ProductVersion</key><string>9.8.7</string>\
             <key>iOSSupportVersion</key><string>6.5</string></dict></plist>",
        )?;
        assert_eq!(Release::read(&[root.path().to_owned()])?, release());
        // The OS cryptex's file comes first.
        let cryptex = root.path().join(OS_CRYPTEX_SYSTEM_VERSION);
        std::fs::create_dir_all(cryptex.parent().unwrap())?;
        std::fs::write(
            &cryptex,
            "<plist><dict><key>ProductBuildVersion</key><string>1Y1</string></dict></plist>",
        )?;
        let read = Release::read(&[root.path().to_owned()])?;
        assert_eq!(read.build.as_deref(), Some("1Y1"));
        assert_eq!(read.product_version, None);
        assert_eq!(Release::read(&[])?, Release::default());
        assert_eq!(kernel_release(VERSION), Some("1.2.3"));
        assert_eq!(kernel_release("Darwin Kernel Version"), None);
        Ok(())
    }

    #[test]
    fn shared_execution_retains_architectural_capacities_without_inventing_sharing() {
        let observed = hardware::DarwinAvailability {
            maximum_slots: 16,
            available_slots: 12,
            physical_active: Some(6),
            physical_maximum: Some(8),
            logical_active: Some(12),
            logical_maximum: Some(16),
        };
        let hardware = Hardware::of_soc(0x6000, 1 << 34)
            .unwrap()
            .with_availability(observed)
            .unwrap();
        let model = Model::new(&hardware, &[], &release());
        let value = |name: &str| model.entries[model.index(name).unwrap()].1.clone();
        for name in [
            "hw.ncpu",
            "hw.physicalcpu_max",
            "hw.logicalcpu_max",
            "machdep.cpu.cores_per_package",
            "machdep.cpu.logical_per_package",
            "hw.perflevel0.physicalcpu_max",
            "hw.perflevel0.logicalcpu_max",
        ] {
            assert_eq!(value(name), Value::Int(8), "{name}");
        }
        for name in [
            "hw.activecpu",
            "hw.physicalcpu",
            "hw.logicalcpu",
            "machdep.cpu.core_count",
            "machdep.cpu.thread_count",
            "hw.perflevel0.physicalcpu",
            "hw.perflevel0.logicalcpu",
        ] {
            assert_eq!(value(name), Value::Int(6), "{name}");
        }
        assert_eq!(value("hw.nperflevels"), Value::Int(1));
        assert_eq!(
            value("hw.perflevel0.name"),
            Value::String("Efficiency".into())
        );
        assert_eq!(value("hw.cachelinesize"), Value::Quad(128));
        assert_eq!(value("hw.l1icachesize"), Value::Quad(128 << 10));
        assert_eq!(value("hw.l1dcachesize"), Value::Quad(64 << 10));
        assert_eq!(value("hw.l2cachesize"), Value::Quad(4 << 20));
        assert_eq!(value("hw.l1icachesize_compat"), Value::Int(128 << 10));
        assert_eq!(value("hw.l1dcachesize_compat"), Value::Int(64 << 10));
        assert_eq!(value("hw.l2cachesize_compat"), Value::Int(4 << 20));
        assert_eq!(value("hw.l3cachesize"), Value::FailsQuad(EINVAL));
        assert_eq!(value("hw.l3cachesize_compat"), Value::Fails(EINVAL));
        let mut sizes = [0; CACHE_ENTRIES];
        sizes[0] = 1 << 34;
        sizes[1] = 64 << 10;
        sizes[2] = 4 << 20;
        assert_eq!(value("hw.cachesize"), Value::Opaque(words(&sizes)));
        for (name, capacity) in [
            ("l1icachesize", 128 << 10),
            ("l1dcachesize", 64 << 10),
            ("l2cachesize", 4 << 20),
        ] {
            let full = value(&format!("hw.{name}"));
            assert_eq!(full.kind(), CTLTYPE_QUAD);
            assert_eq!(full.bytes(Some(4)).unwrap().len(), 8);
            let compat = value(&format!("hw.{name}_compat"));
            assert_eq!(compat.kind(), CTLTYPE_INT);
            assert_eq!(compat.bytes(None).unwrap().len(), 4);
            let level = value(&format!("hw.perflevel0.{name}"));
            assert_eq!(level, Value::Int(capacity));
            assert_eq!(level.bytes(None).unwrap().len(), 4);
        }
        assert_eq!(value("hw.perflevel0.l3cachesize"), Value::Fails(EINVAL));
        assert_eq!(value("hw.perflevel0.cpusperl3"), Value::Fails(EINVAL));
        for name in ["hw.cacheconfig", "hw.perflevel0.cpusperl2"] {
            assert!(model.index(name).is_none(), "{name}");
            assert!(metadata::info(name).is_some(), "{name}");
            assert!(lookup(&model, name).is_err(), "{name}");
        }
    }

    #[test]
    fn shared_cache_capacities_follow_each_presented_cpu0_not_the_host_budget() {
        for name in hardware::models() {
            let source = Hardware::of_model(name, 1 << 34).unwrap();
            let cpu0 = source.clusters[0];
            for (active, maximum) in [(1, 1), (3, 8), (16, 32)] {
                let shared = source
                    .clone()
                    .with_availability(hardware::DarwinAvailability {
                        maximum_slots: maximum * 2,
                        available_slots: active * 2,
                        physical_active: Some(active),
                        physical_maximum: Some(maximum),
                        logical_active: Some(active * 2),
                        logical_maximum: Some(maximum * 2),
                    })
                    .unwrap();
                let model = Model::new(&shared, &[], &release());
                let profile =
                    crate::hosted::pe::profile(&shared, stela_compiler::TargetCpu::detect())
                        .unwrap();
                let caches = profile.processors[0].caches.unwrap();
                assert_eq!(caches.clidr(), 0b100_011, "{name}");
                let decode = |selector| {
                    // Arm CCSIDR_EL1 without CCIDX: LineSize, NumSets,
                    // Associativity. Decode the real hosted CPU0 identity,
                    // independently of the service's capacity fields.
                    let id = caches.ccsidr(selector);
                    let line = 16u64 << (id & 7);
                    assert_eq!(line, u64::from(shared.cache_line), "{name}");
                    line * ((id >> 13 & 0x7fff) + 1) * ((id >> 3 & 0x3ff) + 1)
                };
                for (field, capacity, selector) in [
                    ("l1icachesize", cpu0.l1i_bytes, 1),
                    ("l1dcachesize", cpu0.l1d_bytes, 0),
                    ("l2cachesize", cpu0.l2_bytes, 2),
                ] {
                    assert_eq!(u64::from(capacity), decode(selector), "{name}");
                    let value = |name: &str| &model.entries[model.index(name).unwrap()].1;
                    assert_eq!(
                        value(&format!("hw.{field}")),
                        &Value::Quad(capacity.into()),
                        "{name}"
                    );
                    assert_eq!(
                        value(&format!("hw.perflevel0.{field}")),
                        &Value::Int(capacity as i32),
                        "{name}"
                    );
                }
                assert!(model.index("hw.cacheconfig").is_none(), "{name}");
                assert!(model.index("hw.perflevel0.cpusperl2").is_none(), "{name}");
            }
        }
    }

    /// One performance level per core type: its cores in every cluster,
    /// and the cores sharing one L2 its first cluster's.
    #[test]
    fn perflevels_are_core_types_and_l2_sharing_is_one_cluster() {
        let value = |model: &Model, name: &str| model.entries[model.index(name).unwrap()].1.clone();
        let m2 = model();
        let m1_pro = Model::new(&Hardware::of_soc(0x6000, 1 << 34).unwrap(), &[], &release());
        for (model, cpus, subfamily, levels) in [
            (&m2, 8, hardware::CPUSUBFAMILY_ARM_HG, [(4, 4), (4, 4)]),
            (&m1_pro, 10, hardware::CPUSUBFAMILY_ARM_HS, [(8, 4), (2, 2)]),
        ] {
            assert_eq!(value(model, "hw.ncpu"), Value::Int(cpus));
            assert_eq!(
                value(model, "hw.cpusubfamily"),
                Value::Int(subfamily as i32)
            );
            assert_eq!(value(model, "hw.nperflevels"), Value::Int(2));
            assert!(model.index("hw.perflevel2.physicalcpu").is_none());
            for (index, (cores, per_l2)) in levels.into_iter().enumerate() {
                let field = |name: &str| value(model, &format!("hw.perflevel{index}.{name}"));
                assert_eq!(field("physicalcpu"), Value::Int(cores));
                assert_eq!(field("logicalcpu_max"), Value::Int(cores));
                assert_eq!(field("cpusperl2"), Value::Int(per_l2));
            }
            // `hw.cacheconfig` describes the lowest level.
            let Value::Opaque(config) = value(model, "hw.cacheconfig") else {
                panic!("hw.cacheconfig is not opaque");
            };
            assert_eq!(
                u64::from_le_bytes(config[16..24].try_into().unwrap()),
                levels[1].1 as u64
            );
        }
        let hardware = Hardware::of_soc(0x6000, 1 << 34).unwrap();
        let performance = hardware
            .clusters
            .iter()
            .find(|cluster| cluster.performance)
            .unwrap();
        // The board's own debug pairs.
        assert_eq!(
            value(&m1_pro, "hw.optional.breakpoint"),
            Value::Int(hardware.breakpoints as i32)
        );
        assert_eq!(
            value(&m1_pro, "hw.perflevel0.l2cachesize"),
            Value::Int(performance.l2_bytes as i32)
        );
    }

    #[test]
    fn machine_variables_follow_the_arm64_kernel() {
        let model = model();
        let value = |name: &str| &model.entries[model.index(name).unwrap()].1;
        assert_eq!(value("hw.ncpu"), &Value::Int(8));
        assert_eq!(value("hw.pagesize"), &Value::Number(16384));
        assert_eq!(value("hw.l1icachesize"), &Value::Quad(128 << 10));
        assert_eq!(
            value("hw.perflevel0.name"),
            &Value::String("Performance".into())
        );
        assert_eq!(value("hw.perflevel0.l2cachesize"), &Value::Int(16 << 20));
        assert_eq!(value("hw.optional.armv8_1_atomics"), &Value::Int(1));
        assert_eq!(value("hw.optional.arm.FEAT_LSE"), &Value::Int(1));
        assert_eq!(value("hw.optional.neon"), &Value::Int(1));
        assert_eq!(value("hw.optional.armv8_2_sha3"), &Value::Int(0));
        assert_eq!(value("hw.optional.arm.sme_max_svl_b"), &Value::Int(0));
        let Value::QuadBytes(caps) = value("hw.optional.arm.caps") else {
            panic!("hw.optional.arm.caps is not a byte buffer");
        };
        assert_eq!(caps.len(), 12);
        assert_ne!(caps[0] & 1 << 6, 0, "FEAT_LSE");
        assert_eq!(
            Value::Number(16384).bytes(Some(4)).unwrap(),
            16384i32.to_le_bytes()
        );
        assert_eq!(
            Value::Number(16384).bytes(Some(8)).unwrap(),
            16384i64.to_le_bytes()
        );
        assert!(lookup(&model, "hw.optional.avx2_0").is_err());
        assert!(matches!(lookup(&model, "kern.ostype"), Ok(Lookup::Host)));
        assert_eq!(value("kern.osrelease"), &Value::String("1.2.3".into()));
        assert_eq!(value("kern.version"), &Value::String(VERSION.into()));
        assert_eq!(value("kern.osversion"), &Value::String("0Z0".into()));
        assert_eq!(
            value("kern.osproductversion"),
            &Value::String("9.8.7".into())
        );
        assert_eq!(
            value("kern.iossupportversion"),
            &Value::String("6.5".into())
        );
        // Without the install's record, or the guest's version file, the
        // variables are absent, not the host's.
        let unrecorded = Model::new(
            &Hardware::of(Chip::AppleM2, 1 << 34).unwrap(),
            &[],
            &Release::default(),
        );
        for name in INSTALLED {
            assert!(
                matches!(lookup(&unrecorded, name), Ok(Lookup::Absent)),
                "{name}"
            );
        }
        assert!(matches!(lookup(&model, "hw.memsize"), Ok(Lookup::Host)));
        assert!(lookup(&model, "machdep.wake_abstime").is_err());
        assert!(model.index("hw.optional.arm.FEAT_LSE").is_some());
    }

    #[test]
    fn host_names_static_numbers() {
        assert_eq!(
            host_name(&[CTL_HW, 7]).unwrap().as_deref(),
            Some("hw.pagesize_compat")
        );
    }
}
