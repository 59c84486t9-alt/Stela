//! `sysctl` and `sysctlbyname` (`bsd/kern/kern_newsysctl.c`).
//!
//! The kernel the guest runs on is the host's, so the kernel's own
//! variables (`kern.*`, `vm.*`, `vfs.*`, `net.*`, ...) are the host's and
//! are forwarded, except the kernel's identity (`kern.version`,
//! `kern.osrelease` and `kern.osversion`), which names the 26A434 arm64
//! kernel. The machine is the modeled Apple-silicon one: the `hw.*`
//! and `machdep.*` namespaces are owned here and answered as an arm64 XNU
//! release kernel answers them (`bsd/kern/kern_mib.c`,
//! `bsd/dev/arm64/sysctl.c`) for [`Hardware`] and the PE's identification
//! registers. An owned name the arm64 kernel does not publish (the x86
//! host's `hw.optional.avx2_0`, `machdep.cpu.vendor`, ...) is `ENOENT`, as
//! it is there; an arm64 name this model does not yet answer stops the
//! process naming it.
//!
//! Numeric names reach the model through the host's `oid2name`: the static
//! numbers are the same source on both kernels, and an `OID_AUTO` number
//! the host assigned names the same variable. A modeled name the host does
//! not know receives a synthetic number from `name2oid`.
use super::{Call, Kernel, Outcome, forward};
use crate::darwin::catalog;
use crate::hosted::darwin::{EFAULT, EINVAL, ENOENT, ENOMEM, EPERM, ERANGE};
use crate::hosted::{
    forward as host,
    hardware::{self, Hardware},
    memory,
};
use anyhow::{Context, Result, bail};

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

const KERNEL_RELEASE: &str = "27.0.0";
/// The OS build the kernel belongs to (`kern.osversion`).
const OS_BUILD: &str = "26A434";

/// The namespaces whose variables describe the machine.
const OWNED: &[&str] = &["hw.", "machdep."];

/// Machine variables that are the host's own: its memory and byte order.
const HOST_MACHINE: &[&str] = &[
    "hw.memsize",
    "hw.memsize_usable",
    "hw.physmem",
    "hw.usermem",
];

/// arm64 release-kernel machine variables and nodes this model does not
/// answer yet.
const UNMODELED: &[&str] = &[
    "hw",
    "hw.optional",
    "hw.optional.arm",
    "hw.optional.arm.sme_max_svl_b",
    "hw.perflevel0",
    "hw.perflevel1",
    "hw.memfrequency",
    "hw.memfrequency_min",
    "hw.memfrequency_max",
    "hw.prffrequency",
    "hw.prffrequency_min",
    "hw.prffrequency_max",
    "hw.fixfrequency",
    "hw.osenvironment",
    "hw.ephemeral_storage",
    "hw.use_recovery_securityd",
    "hw.serialdebugmode",
    "hw.mempath",
    "hw.epoch",
    "hw.engineering_sample",
    "hw.l2settings",
    "hw.l3settings",
    "machdep",
    "machdep.cpu",
    "machdep.wfe_rec_max",
    "machdep.wfe_allowed",
    "machdep.idle_timer_wfe",
    "machdep.idle_io_wfe_masked",
    "machdep.idle_io_wfe_unmasked",
    "machdep.wfe_rec_none",
    "machdep.wfe_rec_override_mat",
    "machdep.wfe_rec_clamp",
    "machdep.wake_abstime",
    "machdep.time_since_reset",
    "machdep.wake_conttime",
    "machdep.deferred_ipi_timeout",
    "machdep.ctrr_type",
    "machdep.user_idle_level",
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
}

impl Value {
    fn kind(&self) -> u32 {
        match self {
            Self::Int(_) | Self::Fails(_) => CTLTYPE_INT,
            Self::Quad(_) | Self::Number(_) | Self::QuadBytes(_) => CTLTYPE_QUAD,
            Self::String(_) => CTLTYPE_STRING,
            Self::Opaque(_) => CTLTYPE_OPAQUE,
        }
    }

    fn format(&self) -> &'static str {
        match self {
            Self::Int(_) | Self::Fails(_) => "I",
            Self::Quad(_) | Self::Number(_) | Self::Opaque(_) | Self::QuadBytes(_) => "Q",
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
            Self::Fails(errno) => return Err(*errno),
        })
    }
}

/// The machine variables of one hosted machine.
#[derive(Debug, Clone)]
pub(crate) struct Model {
    entries: Vec<(String, Value)>,
}

/// One performance level's cores and caches (`ml_cpu_get_info_type`).
/// One performance level: every core of one type (`cpu_type_for_perflevel`).
struct Level {
    name: &'static str,
    /// The type's cores in all its clusters (`ml_get_cpu_number_type`).
    cores: i32,
    /// The cores sharing one L2: the type's first cluster's
    /// (`ml_cpu_cache_sharing(2, type)`).
    cores_per_l2: i32,
    /// The type's caches (`ml_cpu_get_info_type`), the L2 one cluster's.
    l1i: i64,
    l1d: i64,
    l2: i64,
}

impl Model {
    pub(crate) fn new(hardware: &Hardware, features: &[(&'static str, bool)]) -> Self {
        let cpus = i32::from(hardware.cpus());
        let levels = levels(hardware);
        // Unscoped cache variables describe the lowest performance level.
        let lowest = levels.last().expect("a machine has a performance level");
        let page = memory::PAGE_BYTES as i64;
        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut add = |name: &str, value: Value| entries.push((name.to_owned(), value));
        for name in [
            "hw.ncpu",
            "hw.activecpu",
            "hw.physicalcpu",
            "hw.physicalcpu_max",
            "hw.logicalcpu",
            "hw.logicalcpu_max",
            "machdep.cpu.cores_per_package",
            "machdep.cpu.core_count",
            "machdep.cpu.logical_per_package",
            "machdep.cpu.thread_count",
        ] {
            add(name, Value::Int(cpus));
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
        let mut config = [0u64; CACHE_ENTRIES];
        config[0] = u64::from(hardware.cpus());
        config[1] = 1;
        config[2] = lowest.cores_per_l2 as u64;
        add("hw.cacheconfig", Value::Opaque(words(&config)));
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
            add(name, Value::Fails(ENOENT));
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
        // Apple SoCs report no L3 (`l3_cache_size == UINT32_MAX`).
        add("hw.l3cachesize", Value::Fails(EINVAL));
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
            for field in [
                "physicalcpu",
                "physicalcpu_max",
                "logicalcpu",
                "logicalcpu_max",
            ] {
                add(&format!("{prefix}{field}"), Value::Int(level.cores));
            }
            add(
                &format!("{prefix}cpusperl2"),
                Value::Int(level.cores_per_l2),
            );
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
        // The 26A434 kernelcache the board boots names its release, build
        // date and xnu tag.
        add(
            "kern.version",
            Value::String(hardware.kernel_version.into()),
        );
        add("kern.osrelease", Value::String(KERNEL_RELEASE.into()));
        add("kern.osversion", Value::String(OS_BUILD.into()));
        Self { entries }
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.entries.iter().position(|(entry, _)| entry == name)
    }

    fn synthetic(&self, oid: &[i32]) -> Option<usize> {
        match oid {
            [_, number] if *number >= SYNTHETIC => {
                let index = (*number - SYNTHETIC) as usize;
                (index < self.entries.len()).then_some(index)
            }
            _ => None,
        }
    }

    fn synthetic_oid(&self, index: usize) -> [i32; 2] {
        let top = if self.entries[index].0.starts_with("machdep.") {
            CTL_MACHDEP
        } else {
            CTL_HW
        };
        [top, SYNTHETIC + index as i32]
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
                cores: i32::from(first.cores) + others,
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
    if !OWNED.iter().any(|prefix| name.starts_with(prefix)) || HOST_MACHINE.contains(&name) {
        return Ok(Lookup::Host);
    }
    if UNMODELED.contains(&name) {
        bail!("the hosted machine model does not answer sysctl {name}");
    }
    Ok(Lookup::Absent)
}

pub(super) const CALLS: &[&str] = &["sysctl", "sys_sysctlbyname"];

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
            match memory::read_u64(self.old_length) {
                Some(length) => Some(length),
                None => return Outcome::Error(EFAULT),
            }
        };
        let offered = if self.old == 0 { None } else { buffer };
        let bytes = match value.bytes(offered) {
            Ok(bytes) => bytes,
            Err(errno) => return Outcome::Error(errno),
        };
        self.out(&bytes)
    }

    fn out(&self, bytes: &[u8]) -> Outcome {
        let total = bytes.len() as u64;
        let mut error = None;
        let mut reported = total;
        if self.old != 0 {
            let capacity = if self.old_length == 0 {
                0
            } else {
                memory::read_u64(self.old_length).unwrap_or(0)
            };
            let copied = total.min(capacity);
            if !memory::write(self.old, &bytes[..copied as usize]) {
                return Outcome::Error(EFAULT);
            }
            if copied != total {
                error = Some(ENOMEM);
                reported = capacity;
            }
        }
        if self.old_length != 0 && !memory::write_u64(self.old_length, reported) {
            return Outcome::Error(EFAULT);
        }
        error.map_or(Outcome::value(0), Outcome::Error)
    }
}

fn by_name(kernel: &mut Kernel, call: &Call) -> Result<Outcome> {
    let (pointer, length) = (call.argument(0), call.argument(1));
    let Some(bytes) = memory::read(pointer, length as usize) else {
        return Ok(Outcome::Error(EFAULT));
    };
    let name = String::from_utf8_lossy(&bytes)
        .trim_end_matches('\0')
        .to_owned();
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
    if let Some(index) = kernel.process.sysctl.synthetic(&oid) {
        return Ok(request.answer(&kernel.process.sysctl.entries[index].1));
    }
    if ![CTL_KERN, CTL_HW, CTL_MACHDEP].contains(&oid[0]) {
        return forward(kernel, call);
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

/// The `CTL_UNSPEC` names: `oid2name`, `name2oid` and `oidfmt` answer
/// synthetic numbers and modeled names; enumeration would walk the host's
/// machine namespaces and is refused.
fn meta(kernel: &mut Kernel, call: &Call, oid: &[i32], request: &Request) -> Result<Outcome> {
    let model = &kernel.process.sysctl;
    match oid[1] {
        META_NAME => {
            if let Some(index) = model.synthetic(&oid[2..]) {
                let mut name = model.entries[index].0.clone().into_bytes();
                name.push(0);
                return Ok(request.out(&name));
            }
            forward(kernel, call)
        }
        META_NEXT => bail!(
            "sysctl enumeration (CTL_UNSPEC.2) over the modeled machine namespaces is not \
             implemented"
        ),
        META_NAME_TO_OID => {
            let Some(bytes) = memory::read(call.argument(4), call.argument(5) as usize) else {
                return Ok(Outcome::Error(EFAULT));
            };
            let name = String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_owned();
            match lookup(model, &name)? {
                Lookup::Host => forward(kernel, call),
                Lookup::Absent => Ok(Outcome::Error(ENOENT)),
                Lookup::Modeled(index) => {
                    let outcome = forward(kernel, call)?;
                    if outcome != Outcome::Error(ENOENT) {
                        return Ok(outcome);
                    }
                    let oid = kernel.process.sysctl.synthetic_oid(index);
                    let bytes: Vec<u8> = oid.iter().flat_map(|part| part.to_le_bytes()).collect();
                    let reply = Request {
                        old: call.argument(2),
                        old_length: call.argument(3),
                        new: 0,
                    };
                    Ok(reply.out(&bytes))
                }
            }
        }
        META_FORMAT => {
            if let Some(index) = model.synthetic(&oid[2..]) {
                let value = &model.entries[index].1;
                let mut bytes = (value.kind() | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED)
                    .to_le_bytes()
                    .to_vec();
                bytes.extend(value.format().as_bytes());
                bytes.push(0);
                return Ok(request.out(&bytes));
            }
            forward(kernel, call)
        }
        _ => forward(kernel, call),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::Chip;

    fn model() -> Model {
        let hardware = Hardware::of(Chip::AppleM2, 1 << 34).unwrap();
        Model::new(&hardware, &[("FEAT_LSE", true), ("AdvSIMD", true)])
    }

    /// One performance level per core type: its cores in every cluster,
    /// and the cores sharing one L2 its first cluster's.
    #[test]
    fn perflevels_are_core_types_and_l2_sharing_is_one_cluster() {
        let value = |model: &Model, name: &str| model.entries[model.index(name).unwrap()].1.clone();
        let m2 = model();
        let m1_pro = Model::new(&Hardware::of_soc(0x6000, 1 << 34).unwrap(), &[]);
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
        // The board's own kernelcache and debug pairs.
        assert!(
            matches!(value(&m1_pro, "kern.version"), Value::String(version)
            if version.ends_with("RELEASE_ARM64_T6000"))
        );
        let hardware = Hardware::of_soc(0x6000, 1 << 34).unwrap();
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
        assert!(matches!(
            lookup(&model, "hw.optional.avx2_0"),
            Ok(Lookup::Absent)
        ));
        assert!(matches!(lookup(&model, "kern.ostype"), Ok(Lookup::Host)));
        assert_eq!(value("kern.osrelease"), &Value::String("27.0.0".into()));
        assert!(matches!(value("kern.version"), Value::String(version)
            if version.starts_with("Darwin Kernel Version 27.0.0:")
                && version.ends_with("RELEASE_ARM64_T8112")));
        assert!(matches!(lookup(&model, "hw.memsize"), Ok(Lookup::Host)));
        assert!(lookup(&model, "machdep.wake_abstime").is_err());
        let index = model.index("hw.optional.arm.FEAT_LSE").unwrap();
        let oid = model.synthetic_oid(index);
        assert_eq!(model.synthetic(&oid), Some(index));
    }

    #[test]
    fn host_names_static_numbers() {
        assert_eq!(
            host_name(&[CTL_HW, 7]).unwrap().as_deref(),
            Some("hw.pagesize_compat")
        );
    }
}
