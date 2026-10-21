//! The pinned `kern_newsysctl.c` metadata family, sharing the machine
//! namespace with value reads. Host OIDs retain their names; model-only
//! leaves have stable process-local synthetic OIDs. Enumeration merges
//! both without exposing the host's x86-only machine variables.
use super::*;

type Oid = Vec<i32>;
type HostResult<T> = std::result::Result<T, u64>;
pub(super) const ENAMETOOLONG: u64 = 63;
const EISDIR: u64 = 21;
const PATH_MAX: usize = crate::hosted::darwin::MAX_PATH;

trait Host {
    fn query(&self, operation: i32, oid: &[i32], new: Option<&[u8]>) -> HostResult<Vec<u8>>;
}

struct Native;

impl Host for Native {
    fn query(&self, operation: i32, oid: &[i32], new: Option<&[u8]>) -> HostResult<Vec<u8>> {
        let mut query = vec![CTL_UNSPEC, operation];
        query.extend_from_slice(oid);
        let mut buffer = vec![0u8; PATH_MAX];
        let mut length = buffer.len() as u64;
        let returned = host::bsd(
            super::super::number_of("sysctl"),
            &[
                query.as_ptr() as u64,
                query.len() as u64,
                buffer.as_mut_ptr() as u64,
                &raw mut length as u64,
                new.map_or(0, |s| s.as_ptr() as u64),
                new.map_or(0, |s| s.len() as u64),
            ],
        );
        if returned.carry {
            return Err(returned.rax);
        }
        buffer.truncate(length as usize);
        Ok(buffer)
    }
}

/// OIDs are chosen once for one process's immutable hardware model, so
/// a name lookup and a later enumeration cannot assign different aliases.
#[derive(Debug, Clone)]
pub(super) struct Namespace {
    leaves: Vec<(Oid, usize)>,
}

impl Namespace {
    fn new(model: &Model, host: &impl Host) -> HostResult<Self> {
        let mut leaves = Vec::with_capacity(model.entries.len());
        for (index, (name, _)) in model.entries.iter().enumerate() {
            let oid = match host.query(META_NAME_TO_OID, &[], Some(name.as_bytes())) {
                Ok(bytes) => decode_oid(&bytes)?,
                Err(ENOENT) => model.synthetic_oid(index).to_vec(),
                Err(error) => return Err(error),
            };
            leaves.push((oid, index));
        }
        leaves.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Self { leaves })
    }

    fn get(model: &Model) -> HostResult<&Self> {
        if model.namespace.get().is_none() {
            // A transient host failure is not cached; a later request may
            // retry. Concurrent initializers derive the same immutable OIDs.
            let namespace = Self::new(model, &Native)?;
            let _ = model.namespace.set(namespace);
        }
        Ok(model.namespace.get().expect("initialized namespace"))
    }

    fn oid(&self, index: usize) -> &Oid {
        &self
            .leaves
            .iter()
            .find(|(_, leaf)| *leaf == index)
            .expect("every modeled leaf has an OID")
            .0
    }

    fn index(&self, model: &Model, oid: &[i32]) -> Option<usize> {
        model.synthetic(oid).or_else(|| {
            self.leaves
                .iter()
                .find(|(candidate, _)| candidate == oid)
                .map(|(_, index)| *index)
        })
    }

    fn next(&self, model: &Model, after: &[i32], host: &impl Host) -> HostResult<Oid> {
        let modeled = self
            .leaves
            .iter()
            .find(|(oid, _)| oid.as_slice() > after)
            .map(|(oid, _)| oid.clone());
        let mut cursor = after.to_vec();
        loop {
            let candidate = match host.query(META_NEXT, &cursor, None) {
                Ok(bytes) => decode_oid(&bytes)?,
                Err(ENOENT) => return modeled.ok_or(ENOENT),
                Err(error) => return Err(error),
            };
            if candidate <= cursor {
                return Err(EINVAL);
            }
            if modeled.as_ref().is_some_and(|oid| *oid <= candidate) {
                return Ok(modeled.unwrap());
            }
            let bytes = host.query(META_NAME, &candidate, None)?;
            let name = c_name(&bytes);
            // Published but unmodeled ARM variables remain discoverable.
            // Reading their contents still reports the existing explicit
            // limit; enumeration must neither invent nor hide those values.
            if visible(model, &name) {
                return Ok(candidate);
            }
            cursor = candidate;
        }
    }
}

fn decode_oid(bytes: &[u8]) -> HostResult<Oid> {
    if bytes.is_empty()
        || !bytes.len().is_multiple_of(INT_BYTES as usize)
        || bytes.len() > MAX_NAME as usize * INT_BYTES as usize
    {
        return Err(EINVAL);
    }
    Ok(bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| i32::from_le_bytes(*b))
        .collect())
}

pub(super) fn c_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn visible(model: &Model, name: &str) -> bool {
    model.index(name).is_some()
        || UNMODELED.contains(&name)
        || HOST_MACHINE.contains(&name)
        || !OWNED.iter().any(|prefix| name.starts_with(prefix)) && !INSTALLED.contains(&name)
}

/// Return `None` only for a host-owned request. No raw guest pointer is
/// passed to the host while constructing or filtering namespace metadata.
pub(super) fn answer(
    model: &Model,
    call: &Call,
    oid: &[i32],
    request: &Request,
) -> Result<Option<Outcome>> {
    if ![
        META_NAME,
        META_NEXT,
        META_NAME_TO_OID,
        META_FORMAT,
        META_DESCRIPTION,
    ]
    .contains(&oid[1])
    {
        return Ok(None);
    }
    if oid[1] == META_NAME_TO_OID && oid.len() != 2 {
        return Ok(Some(Outcome::Error(EISDIR)));
    }
    if request.new != 0 && oid[1] != META_NAME_TO_OID {
        return Ok(Some(Outcome::Error(EPERM)));
    }
    let namespace = match Namespace::get(model) {
        Ok(namespace) => namespace,
        Err(error) => return Ok(Some(Outcome::Error(error))),
    };
    if oid[1] == META_NEXT {
        return Ok(Some(match namespace.next(model, &oid[2..], &Native) {
            Ok(next) => request.out(&encode_oid(&next)),
            Err(error) => Outcome::Error(error),
        }));
    }
    if oid[1] == META_NAME_TO_OID {
        let length = call.argument(5) as usize;
        if length == 0 {
            return Ok(Some(Outcome::Error(ENOENT)));
        }
        if length >= PATH_MAX {
            return Ok(Some(Outcome::Error(ENAMETOOLONG)));
        }
        let Some(bytes) = memory::read(call.argument(4), length) else {
            return Ok(Some(Outcome::Error(EFAULT)));
        };
        let name = c_name(&bytes);
        let name = name.strip_suffix('.').unwrap_or(&name);
        return Ok(match lookup(model, name)? {
            Lookup::Host => None,
            Lookup::Absent => Some(Outcome::Error(ENOENT)),
            Lookup::Modeled(index) => Some(request.out(&encode_oid(namespace.oid(index)))),
        });
    }
    let target = &oid[2..];
    if let Some(index) = namespace.index(model, target) {
        let (name, value) = &model.entries[index];
        return Ok(Some(match oid[1] {
            META_NAME => name_out(request, name),
            META_FORMAT => format_out(request, name, value),
            META_DESCRIPTION => {
                let description = description(name);
                let mut bytes = description.as_bytes().to_vec();
                bytes.push(0);
                request.out(&bytes)
            }
            _ => return Ok(None),
        }));
    }
    // An extra component after a modeled leaf is advisory numeric text
    // for oid2name, and a malformed leaf request for oidfmt/oiddescr.
    for length in 2..target.len() {
        if let Some(index) = namespace.index(model, &target[..length]) {
            return Ok(Some(if oid[1] == META_NAME {
                let mut name = model.entries[index].0.clone();
                for component in &target[length..] {
                    name.push_str(&format!(".{component}"));
                }
                name_out(request, &name)
            } else {
                Outcome::Error(EISDIR)
            }));
        }
    }
    if target.get(1).is_some_and(|number| *number >= SYNTHETIC) {
        return Ok(Some(Outcome::Error(ENOENT)));
    }
    if let Some(name) = host_name(target)?
        && let Lookup::Absent = lookup(model, &name)?
    {
        return Ok(Some(Outcome::Error(ENOENT)));
    }
    Ok(None)
}

fn encode_oid(oid: &[i32]) -> Vec<u8> {
    oid.iter()
        .flat_map(|component| component.to_le_bytes())
        .collect()
}

fn name_out(request: &Request, name: &str) -> Outcome {
    let mut parts: Vec<&[u8]> = Vec::new();
    for (index, part) in name.split('.').enumerate() {
        if index != 0 {
            parts.push(b".");
        }
        parts.push(part.as_bytes());
    }
    parts.push(b"\0");
    request.out_parts(&parts)
}

/// Public flags from the pinned ARM declarations. SYSCTL_PROC/INT add
/// OID2 and PERMANENT; OID_AUTO is the only kernel-private bit masked by
/// sysctl_sysctl_oidfmt. Modeled identity remains read-only in this adapter.
fn flags(name: &str) -> u32 {
    const OID2: u32 = 0x0040_0000;
    const PERMANENT: u32 = 0x0020_0000;
    const MASKED: u32 = 0x0400_0000;
    let mut flags = CTLFLAG_RD | OID2 | PERMANENT;
    if name != "machdep.ptrauth_enabled" {
        flags |= CTLFLAG_LOCKED;
    }
    if name.ends_with("_compat")
        || matches!(
            name,
            "hw.machine" | "hw.model" | "hw.target" | "hw.product" | "hw.vectorunit"
        )
    {
        flags |= MASKED;
    } else if !name.starts_with("machdep.cpu.")
        && !matches!(
            name,
            "hw.cacheconfig" | "hw.cachesize" | "machdep.virtual_address_size"
        )
    {
        flags |= CTLFLAG_KERN;
    }
    flags
}

fn description(name: &str) -> &str {
    match name {
        "hw.nperflevels" => "Number of performance levels supported by this system",
        "machdep.cpu.brand_string" => "CPU brand string",
        "machdep.cpu.cores_per_package" => "CPU cores per package",
        "machdep.cpu.core_count" => "Number of enabled cores per package",
        "machdep.cpu.logical_per_package" => "CPU logical cpus per package",
        "machdep.cpu.thread_count" => "Number of enabled threads per package",
        "machdep.virtual_address_size" => {
            "Number of addressable bits in userspace virtual addresses"
        }
        "kern.osproductversion" => "The ProductVersion from SystemVersion.plist",
        "kern.iossupportversion" => "The iOSSupportVersion from SystemVersion.plist",
        _ => "",
    }
}

fn format_out(request: &Request, name: &str, value: &Value) -> Outcome {
    let kind = (value.kind() | flags(name)).to_le_bytes();
    let mut format = value.format().as_bytes().to_vec();
    format.push(0);
    request.out_parts(&[&kind, &format])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Tree(BTreeMap<Oid, String>);

    impl Host for Tree {
        fn query(&self, operation: i32, oid: &[i32], new: Option<&[u8]>) -> HostResult<Vec<u8>> {
            match operation {
                META_NAME_TO_OID => self
                    .0
                    .iter()
                    .find(|(_, name)| name.as_bytes() == new.unwrap())
                    .map(|(oid, _)| encode_oid(oid))
                    .ok_or(ENOENT),
                META_NAME => self
                    .0
                    .get(oid)
                    .map(|name| {
                        let mut bytes = name.as_bytes().to_vec();
                        bytes.push(0);
                        bytes
                    })
                    .ok_or(ENOENT),
                META_NEXT => self
                    .0
                    .keys()
                    .find(|candidate| candidate.as_slice() > oid)
                    .map(|oid| encode_oid(oid))
                    .ok_or(ENOENT),
                _ => panic!("unexpected metadata operation"),
            }
        }
    }

    fn model() -> Model {
        Model {
            entries: vec![
                ("hw.pagesize".into(), Value::Number(16384)),
                ("hw.optional.arm.FEAT_LSE".into(), Value::Int(1)),
                (
                    "machdep.cpu.brand_string".into(),
                    Value::String("Synthetic ARM CPU".into()),
                ),
                ("kern.osrelease".into(), Value::String("1.2.3".into())),
            ],
            namespace: OnceLock::new(),
        }
    }

    fn request(bytes: &mut [u8], length: &mut u64) -> Request {
        Request {
            old: bytes.as_mut_ptr() as u64,
            old_length: length as *mut _ as u64,
            new: 0,
        }
    }

    fn call(new: &[u8]) -> Call {
        Call {
            entry: catalog::entry(super::super::super::number_of("sysctl")).unwrap(),
            arguments: [0, 0, 0, 0, new.as_ptr() as u64, new.len() as u64, 0, 0],
        }
    }

    #[test]
    fn enumeration_merges_aliases_filters_host_only_and_keeps_unmodeled_values_discoverable() {
        let model = model();
        let tree = Tree(BTreeMap::from([
            (vec![1, 1], "kern.ostype".into()),
            (vec![6, 7], "hw.pagesize".into()),
            (vec![6, 8], "hw.optional.avx2_0".into()),
            (vec![6, 9], "hw.memsize".into()),
            (vec![7, 1, 1], "machdep.cpu.vendor".into()),
            (vec![7, 1, 2], "machdep.cpu.brand_string".into()),
            (vec![7, 2], "machdep.wake_abstime".into()),
            (vec![8, 1], "net.inet.test".into()),
        ]));
        let namespace = Namespace::new(&model, &tree).unwrap();
        let mut seen = Vec::new();
        let mut cursor = vec![];
        while let Ok(next) = namespace.next(&model, &cursor, &tree) {
            assert!(next > cursor);
            cursor = next.clone();
            seen.push(next);
        }
        assert_eq!(
            seen,
            vec![
                vec![1, 1],
                model.synthetic_oid(3).to_vec(),
                vec![6, 7],
                vec![6, 9],
                model.synthetic_oid(1).to_vec(),
                vec![7, 1, 2],
                vec![7, 2],
                vec![8, 1],
            ]
        );
        for (oid, index) in &namespace.leaves {
            assert_eq!(namespace.index(&model, oid), Some(*index));
            assert_eq!(namespace.oid(*index), oid);
        }
        assert_eq!(namespace.next(&model, &[i32::MAX], &tree), Err(ENOENT));
        assert_eq!(
            Namespace::new(&model, &tree).unwrap().leaves,
            namespace.leaves
        );
    }

    #[test]
    fn synthetic_oids_are_scoped_and_read_metadata_uses_the_guest_type() {
        let model = model();
        let mut bytes = [0xa5; 128];
        let mut length = bytes.len() as u64;
        let oid = model.synthetic_oid(1);
        let mut query = vec![CTL_UNSPEC, META_NAME];
        query.extend(oid);
        assert_eq!(
            answer(
                &model,
                &call(&[]),
                &query,
                &request(&mut bytes, &mut length)
            )
            .unwrap(),
            Some(Outcome::value(0))
        );
        assert_eq!(&bytes[..length as usize], b"hw.optional.arm.FEAT_LSE\0");
        let mut wrong = oid;
        wrong[0] = CTL_KERN;
        assert_eq!(model.synthetic(&wrong), None);
        for operation in [META_NAME, META_FORMAT, META_DESCRIPTION] {
            let query = [CTL_UNSPEC, operation, wrong[0], wrong[1]];
            length = 128;
            assert_eq!(
                answer(
                    &model,
                    &call(&[]),
                    &query,
                    &request(&mut bytes, &mut length)
                )
                .unwrap(),
                Some(Outcome::Error(ENOENT))
            );
        }
        // Even a native OID must describe the guest's 64-bit pagesize
        // handler rather than the x86 host's format or integer width.
        let namespace = Namespace::get(&model).unwrap();
        let mut query = vec![CTL_UNSPEC, META_FORMAT];
        query.extend(namespace.oid(0));
        length = 128;
        answer(
            &model,
            &call(&[]),
            &query,
            &request(&mut bytes, &mut length),
        )
        .unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) & 15,
            CTLTYPE_QUAD
        );
        assert_eq!(&bytes[4..length as usize], b"Q\0");
        let cloned = model.clone();
        assert_eq!(Namespace::get(&cloned).unwrap().leaves, namespace.leaves);
    }

    #[test]
    fn name_to_oid_validates_copyin_and_round_trips_c_names_and_descriptions() {
        let model = model();
        let mut bytes = [0xa5; 128];
        let mut length = 128;
        for name in [
            b"hw.optional.arm.FEAT_LSE".as_slice(),
            b"hw.optional.arm.FEAT_LSE.",
            b"hw.optional.arm.FEAT_LSE\0ignored",
        ] {
            length = 128;
            assert_eq!(
                answer(
                    &model,
                    &call(name),
                    &[0, META_NAME_TO_OID],
                    &request(&mut bytes, &mut length)
                )
                .unwrap(),
                Some(Outcome::value(0))
            );
            assert_eq!(
                decode_oid(&bytes[..length as usize]).unwrap(),
                model.synthetic_oid(1)
            );
        }
        for (name, expected) in [
            (vec![], ENOENT),
            (vec![b'x'; PATH_MAX], ENAMETOOLONG),
            (b"hw.optional.avx2_0".to_vec(), ENOENT),
        ] {
            assert_eq!(
                answer(
                    &model,
                    &call(&name),
                    &[0, META_NAME_TO_OID],
                    &request(&mut bytes, &mut length)
                )
                .unwrap(),
                Some(Outcome::Error(expected))
            );
        }
        let mut bad = call(b"x");
        bad.arguments[4] = 1;
        assert_eq!(
            answer(
                &model,
                &bad,
                &[0, META_NAME_TO_OID],
                &request(&mut bytes, &mut length)
            )
            .unwrap(),
            Some(Outcome::Error(EFAULT))
        );
        let mut query = vec![0, META_DESCRIPTION];
        query.extend(model.synthetic_oid(2));
        length = 128;
        answer(
            &model,
            &call(&[]),
            &query,
            &request(&mut bytes, &mut length),
        )
        .unwrap();
        assert_eq!(&bytes[..length as usize], b"CPU brand string\0");
        query[1] = META_FORMAT;
        query.push(9);
        length = 128;
        assert_eq!(
            answer(
                &model,
                &call(&[]),
                &query,
                &request(&mut bytes, &mut length)
            )
            .unwrap(),
            Some(Outcome::Error(EISDIR))
        );
        let mut readonly = request(&mut bytes, &mut length);
        readonly.new = 1;
        assert_eq!(
            answer(&model, &call(&[]), &[0, META_NEXT], &readonly).unwrap(),
            Some(Outcome::Error(EPERM))
        );
    }

    /// Compare complete and short SYSCTL_OUT chunks against the native
    /// kernel, including oidfmt's separately copied kind and format.
    #[test]
    fn copyout_chunks_match_the_native_kernel_for_every_short_buffer() {
        for oid in [vec![1, 1], vec![0, META_FORMAT, 1, 1]] {
            let mut full = [0u8; 128];
            let mut total = 128u64;
            let returned = host::bsd(
                super::super::super::number_of("sysctl"),
                &[
                    oid.as_ptr() as u64,
                    oid.len() as u64,
                    full.as_mut_ptr() as u64,
                    &raw mut total as u64,
                    0,
                    0,
                ],
            );
            assert!(!returned.carry);
            let data = &full[..total as usize];
            let parts = if oid[0] == 0 {
                vec![&data[..4], &data[4..]]
            } else {
                vec![data]
            };
            for capacity in 0..=total + 2 {
                let mut native = [0xa5; 128];
                let mut native_length = capacity;
                let result = host::bsd(
                    super::super::super::number_of("sysctl"),
                    &[
                        oid.as_ptr() as u64,
                        oid.len() as u64,
                        native.as_mut_ptr() as u64,
                        &raw mut native_length as u64,
                        0,
                        0,
                    ],
                );
                let mut guest = [0xa5; 128];
                let mut guest_length = capacity;
                let answer = request(&mut guest, &mut guest_length).out_parts(&parts);
                let expected = if result.carry {
                    Outcome::Error(result.rax)
                } else {
                    Outcome::value(0)
                };
                assert_eq!(
                    (answer, guest_length, guest),
                    (expected, native_length, native),
                    "oid={oid:?}, capacity={capacity}"
                );
            }
            let mut size = 0;
            assert_eq!(
                Request {
                    old: 0,
                    old_length: &raw mut size as u64,
                    new: 0
                }
                .out_parts(&parts),
                Outcome::value(0)
            );
            assert_eq!(size, total);
            let mut size = 128;
            assert_eq!(
                Request {
                    old: 1,
                    old_length: &raw mut size as u64,
                    new: 0
                }
                .out_parts(&parts),
                Outcome::Error(EFAULT)
            );
            assert_eq!(size, 128);
            assert_eq!(
                Request {
                    old: 0,
                    old_length: 1,
                    new: 0
                }
                .out_parts(&parts),
                Outcome::Error(EFAULT)
            );
        }
    }

    #[test]
    fn modeled_values_preserve_errors_lengths_and_canaries() {
        // Pinned sysctl/fuulong ordering: an unreadable oldlenp is the
        // all-ones size until the final length publication faults. This
        // case is source-backed; its native control remains unqualified.
        let mut bytes = [0xa5; 16];
        let late_fault = Request {
            old: bytes.as_mut_ptr() as u64,
            old_length: 1,
            new: 0,
        };
        assert_eq!(
            late_fault.answer(&Value::String("ARM".into())),
            Outcome::Error(EFAULT)
        );
        assert_eq!(&bytes[..4], b"ARM\0");
        assert!(bytes[4..].iter().all(|&byte| byte == 0xa5));
        assert_eq!(
            late_fault.answer(&Value::FailsQuad(ENOENT)),
            Outcome::Error(ENOENT)
        );
        let cases = [
            Value::Int(7),
            Value::Quad(1 << 35),
            Value::Number(16384),
            Value::String("ARM".into()),
            Value::Opaque(vec![1, 2, 3, 4, 5]),
            Value::QuadBytes(vec![1; 12]),
        ];
        for value in cases {
            for capacity in 0..=16 {
                let expected = value.bytes(Some(capacity)).unwrap();
                let mut bytes = [0xa5; 32];
                let mut length = capacity;
                let result = request(&mut bytes, &mut length).answer(&value);
                if expected.len() as u64 > capacity {
                    assert_eq!(
                        (result, length, bytes),
                        (Outcome::Error(ENOMEM), 0, [0xa5; 32])
                    );
                } else {
                    assert_eq!(result, Outcome::value(0));
                    assert_eq!(length, expected.len() as u64);
                    assert_eq!(&bytes[..expected.len()], expected);
                    assert!(bytes[expected.len()..].iter().all(|&byte| byte == 0xa5));
                }
            }
        }
        for (value, error, kind) in [
            (Value::Fails(EINVAL), EINVAL, CTLTYPE_INT),
            (Value::FailsQuad(ENOENT), ENOENT, CTLTYPE_QUAD),
            (Value::Number(i64::MAX), ERANGE, CTLTYPE_QUAD),
        ] {
            let mut bytes = [0xa5; 16];
            let mut length = 4;
            assert_eq!(
                request(&mut bytes, &mut length).answer(&value),
                Outcome::Error(error)
            );
            assert_eq!((length, bytes), (4, [0xa5; 16]));
            assert_eq!(value.kind(), kind);
            let mut write = request(&mut bytes, &mut length);
            write.new = 1;
            assert_eq!(write.answer(&value), Outcome::Error(EPERM));
        }
    }

    #[test]
    fn a_copyout_fault_keeps_completed_chunks_and_does_not_publish_a_length() {
        const HOST_PAGE: usize = memory::HOST_PAGE_MASK as usize + 1;
        struct Pages(*mut libc::c_void);
        impl Drop for Pages {
            fn drop(&mut self) {
                // SAFETY: exactly the mapping this test owns, including
                // the inaccessible guard page; no Rust references remain.
                assert_eq!(unsafe { libc::munmap(self.0, 2 * HOST_PAGE) }, 0);
            }
        }
        // SAFETY: anonymous private scratch pages, released by Pages.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * HOST_PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let pages = Pages(mapping);
        let guard = mapping as u64 + HOST_PAGE as u64;
        // SAFETY: the second page of this owned mapping.
        assert_eq!(
            unsafe { libc::mprotect(guard as *mut _, HOST_PAGE, libc::PROT_NONE) },
            0
        );
        let oid = [0i32, META_FORMAT, 1, 1];
        let metadata = Native.query(META_FORMAT, &[1, 1], None).unwrap();
        let mut native_length = 128u64;
        let returned = host::bsd(
            super::super::super::number_of("sysctl"),
            &[
                oid.as_ptr() as u64,
                oid.len() as u64,
                guard - 4,
                &raw mut native_length as u64,
                0,
                0,
            ],
        );
        assert!(returned.carry);
        assert_eq!((returned.rax, native_length), (EFAULT, 128));
        let prefix = memory::read(guard - 4, 4).unwrap();
        assert_eq!(prefix, metadata[..4]);
        assert!(memory::write(guard - 4, &[0xa5; 4]));
        let mut guest_length = 128u64;
        let request = Request {
            old: guard - 4,
            old_length: &raw mut guest_length as u64,
            new: 0,
        };
        assert_eq!(
            request.out_parts(&[&metadata[..4], &metadata[4..]]),
            Outcome::Error(EFAULT)
        );
        assert_eq!(guest_length, native_length);
        assert_eq!(memory::read(guard - 4, 4).unwrap(), prefix);
        drop(pages);
    }
}
