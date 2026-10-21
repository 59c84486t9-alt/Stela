//! The pinned `kern_newsysctl.c` metadata family, sharing the machine
//! namespace with value reads. Host OIDs retain their names; model-only
//! members have stable hierarchical process-local synthetic OIDs.
//! Enumeration merges the static ARM publication with unowned host data.
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

/// One published variable or branch. Metadata is independent of whether
/// its contents are modeled, host-owned or explicitly unsupported.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    oid: Oid,
    name: String,
    info: metadata::Info,
    value: Option<usize>,
}

#[derive(Debug, Clone)]
pub(super) struct Namespace {
    members: Vec<Member>,
}

impl Namespace {
    fn new(model: &Model, host: &impl Host) -> HostResult<Self> {
        Self::with_publications(model, host, metadata::DECLARATIONS)
    }

    fn with_publications(
        model: &Model,
        host: &impl Host,
        declarations: &[metadata::Declaration],
    ) -> HostResult<Self> {
        let mut members = Vec::new();
        for (index, (name, value)) in model.entries.iter().enumerate() {
            let info = metadata::info(name)
                .unwrap_or(metadata::Info {
                    flags: value.kind() | CTLFLAG_RD | CTLFLAG_KERN | CTLFLAG_LOCKED,
                    format: value.format(),
                    description: "",
                })
                .read_only();
            members.push(Member {
                oid: vec![],
                name: name.clone(),
                info,
                value: Some(index),
            });
        }
        for &(name, flags, format, description) in declarations {
            if members.iter().any(|member| member.name == name)
                || INSTALLED.contains(&name) && model.index(name).is_none()
            {
                continue;
            }
            members.push(Member {
                oid: vec![],
                name: name.to_owned(),
                info: metadata::Info {
                    flags,
                    format,
                    description,
                },
                value: None,
            });
        }
        // Every synthetic leaf is a child of its real namespace branch.
        // This is necessary for sysctl's prefix-bounded subtree traversal.
        let names: Vec<String> = members.iter().map(|member| member.name.clone()).collect();
        for name in names {
            let mut prefix = name.as_str();
            while let Some((parent, _)) = prefix.rsplit_once('.') {
                if !members.iter().any(|member| member.name == parent) {
                    let Some(info) = metadata::info(parent).filter(|info| info.node()) else {
                        return Err(EINVAL);
                    };
                    members.push(Member {
                        oid: vec![],
                        name: parent.into(),
                        info,
                        value: None,
                    });
                }
                prefix = parent;
            }
        }
        let mut namespace = Self { members };
        for index in 0..namespace.members.len() {
            namespace.assign(index, host)?;
        }
        namespace.members.sort_by(|a, b| a.oid.cmp(&b.oid));
        Ok(namespace)
    }

    fn assign(&mut self, index: usize, host: &impl Host) -> HostResult<Oid> {
        if !self.members[index].oid.is_empty() {
            return Ok(self.members[index].oid.clone());
        }
        let name = self.members[index].name.clone();
        let oid = match host.query(META_NAME_TO_OID, &[], Some(name.as_bytes())) {
            Ok(bytes) => decode_oid(&bytes)?,
            Err(ENOENT) => {
                if let Some((parent, _)) = name.rsplit_once('.') {
                    let Some(parent) = self.members.iter().position(|member| member.name == parent)
                    else {
                        return Err(EINVAL);
                    };
                    let mut oid = self.assign(parent, host)?;
                    oid.push(SYNTHETIC + index as i32);
                    if oid.len() > MAX_NAME as usize - 2 {
                        return Err(EINVAL);
                    }
                    oid
                } else {
                    vec![match name.as_str() {
                        "kern" => CTL_KERN,
                        "hw" => CTL_HW,
                        "machdep" => CTL_MACHDEP,
                        _ => return Err(ENOENT),
                    }]
                }
            }
            Err(error) => return Err(error),
        };
        self.members[index].oid = oid.clone();
        Ok(oid)
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

    fn named(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|member| member.name == name)
    }

    fn numbered(&self, oid: &[i32]) -> Option<&Member> {
        self.members.iter().find(|member| member.oid == oid)
    }

    fn next(&self, model: &Model, after: &[i32], host: &impl Host) -> HostResult<Oid> {
        let modeled = self
            .members
            .iter()
            .find(|member| !member.info.node() && member.oid.as_slice() > after)
            .map(|member| member.oid.clone());
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
            if visible(model, &c_name(&bytes)) {
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
    if INSTALLED.contains(&name) {
        return model.index(name).is_some();
    }
    model.index(name).is_some()
        || metadata::info(name).is_some()
        || HOST_MACHINE.contains(&name)
        || !OWNED.iter().any(|prefix| name.starts_with(prefix))
}

/// A content request must never use metadata as a successful data value.
fn read_member(model: &Model, member: &Member, request: &Request) -> Result<Option<Outcome>> {
    if let Some(index) = member.value {
        return Ok(Some(request.answer(&model.entries[index].1)));
    }
    if member.info.node() {
        return Ok(Some(Outcome::Error(ENOENT)));
    }
    if HOST_MACHINE.contains(&member.name.as_str()) {
        return Ok(None);
    }
    // sysctl_hw_generic rejects a published inactive perflevel before
    // reading its field. Its metadata and subtree nevertheless exist.
    if let Some(suffix) = member.name.strip_prefix("hw.perflevel")
        && let Some((level, _)) = suffix.split_once('.')
        && let Ok(level) = level.parse::<i32>()
        && let Some(index) = model.index("hw.nperflevels")
        && let Value::Int(count) = &model.entries[index].1
        && level >= *count
    {
        return Ok(Some(Outcome::Error(ENOENT)));
    }
    crate::hosted::unsupported::refuse!(
        ENOENT,
        "the hosted machine model does not answer sysctl {} (its metadata is published)",
        member.name
    )
}

pub(super) fn named_value(model: &Model, name: &str, request: &Request) -> Result<Option<Outcome>> {
    if model.index(name).is_none() && metadata::info(name).is_none() {
        return Ok(None);
    }
    let namespace = match Namespace::get(model) {
        Ok(namespace) => namespace,
        Err(error) => return Ok(Some(Outcome::Error(error))),
    };
    match namespace.named(name) {
        Some(member) => read_member(model, member, request),
        None => Ok(None),
    }
}

pub(super) fn numeric_value(
    model: &Model,
    oid: &[i32],
    request: &Request,
) -> Result<Option<Outcome>> {
    let namespace = match Namespace::get(model) {
        Ok(namespace) => namespace,
        Err(error) => return Ok(Some(Outcome::Error(error))),
    };
    match namespace.numbered(oid) {
        Some(member) => read_member(model, member, request),
        None => Ok(None),
    }
}

/// Return None for a host-owned metadata request. Names and numeric OIDs
/// share the same publication; content support is a separate decision.
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
        if let Some(member) = namespace.named(name) {
            return Ok(Some(request.out(&encode_oid(&member.oid))));
        }
        return Ok(match lookup(model, name)? {
            Lookup::Host => None,
            _ => Some(Outcome::Error(ENOENT)),
        });
    }
    let target = &oid[2..];
    if let Some(member) = namespace.numbered(target) {
        return Ok(Some(match oid[1] {
            META_NAME => name_out(request, &member.name),
            META_FORMAT => format_out(request, member.info),
            META_DESCRIPTION => {
                let mut bytes = member.info.description.as_bytes().to_vec();
                bytes.push(0);
                request.out(&bytes)
            }
            _ => unreachable!("non-lookup metadata operations were handled"),
        }));
    }
    for length in 1..target.len() {
        if let Some(member) = namespace
            .numbered(&target[..length])
            .filter(|member| !member.info.node())
        {
            return Ok(Some(if oid[1] == META_NAME {
                let mut name = member.name.clone();
                for component in &target[length..] {
                    name.push_str(&format!(".{component}"));
                }
                name_out(request, &name)
            } else {
                Outcome::Error(EISDIR)
            }));
        }
    }
    if target.iter().any(|number| *number >= SYNTHETIC) {
        return Ok(Some(Outcome::Error(ENOENT)));
    }
    if let Some(name) = host_name(target)?
        && !visible(model, &name)
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

fn format_out(request: &Request, info: metadata::Info) -> Outcome {
    let mut format = info.format.as_bytes().to_vec();
    format.push(0);
    request.out_parts(&[&info.flags.to_le_bytes(), &format])
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
    fn synthetic_children_stay_inside_their_published_subtree() {
        let model = model();
        let tree = Tree::default();
        let declarations: Vec<_> = metadata::DECLARATIONS
            .iter()
            .copied()
            .filter(|entry| entry.0 == "hw.optional.arm.FEAT_CPA")
            .collect();
        let namespace = Namespace::with_publications(&model, &tree, &declarations).unwrap();
        let parent = &namespace.named("hw.optional.arm").unwrap().oid;
        assert_eq!(parent.len(), 3);
        let mut cursor = parent.clone();
        let mut names = Vec::new();
        while let Ok(next) = namespace.next(&model, &cursor, &tree) {
            if !next.starts_with(parent) {
                break;
            }
            names.push(namespace.numbered(&next).unwrap().name.clone());
            cursor = next;
        }
        names.sort();
        assert_eq!(
            names,
            ["hw.optional.arm.FEAT_CPA", "hw.optional.arm.FEAT_LSE"]
        );
        let member = namespace.named("hw.optional.arm.FEAT_CPA").unwrap();
        assert_eq!(member.info.flags & metadata::TYPE_MASK, CTLTYPE_INT);
        let mut bytes = [0xa5; 64];
        let mut length = 64;
        assert!(read_member(&model, member, &request(&mut bytes, &mut length)).is_err());
        assert_eq!((bytes, length), ([0xa5; 64], 64));
    }

    #[test]
    fn publication_is_independent_of_content_and_inactive_perflevels() {
        let mut model = model();
        model.entries.push(("hw.nperflevels".into(), Value::Int(2)));
        let namespace = Namespace::get(&model).unwrap();
        let mut bytes = [0xa5; 128];
        let mut length = 128;
        // Real registrations remain visible even when the adapter has
        // not implemented their data handler. Never return host x86 caps.
        let avx = namespace.named("hw.optional.avx2_0").unwrap();
        assert_eq!(avx.info.format, "I");
        assert!(read_member(&model, avx, &request(&mut bytes, &mut length)).is_err());
        assert_eq!((length, bytes), (128, [0xa5; 128]));
        assert!(
            namespace.named("hw.cputhreadtype").is_none(),
            "NOAUTO and no SMT"
        );
        assert!(
            namespace.named("machdep.wfe_allowed").is_none(),
            "debug-only"
        );
        assert!(
            namespace.named("hw.memfrequency").is_none(),
            "absent from the release publication"
        );
        for member in namespace
            .members
            .iter()
            .filter(|member| member.name.starts_with("hw.perflevel2."))
        {
            assert_eq!(
                read_member(&model, member, &request(&mut bytes, &mut length)).unwrap(),
                Some(Outcome::Error(ENOENT)),
                "{}",
                member.name
            );
        }
        for name in [
            "hw",
            "hw.optional",
            "hw.optional.arm",
            "hw.perflevel0",
            "hw.perflevel2",
            "machdep.cpu",
        ] {
            assert_eq!(
                read_member(
                    &model,
                    namespace.named(name).unwrap(),
                    &request(&mut bytes, &mut length)
                )
                .unwrap(),
                Some(Outcome::Error(ENOENT))
            );
        }
        assert_eq!(
            namespace.named("hw.perflevel2.name").unwrap().info.format,
            "A"
        );
        assert_eq!(
            namespace
                .named("hw.engineering_sample")
                .unwrap()
                .info
                .format,
            ""
        );
        assert!(
            namespace
                .named("hw.features.allows_security_research")
                .is_none(),
            "dynamic driver registration"
        );
    }

    #[test]
    fn branch_metadata_matches_the_native_common_abi() {
        let model = model();
        let namespace = Namespace::get(&model).unwrap();
        for name in ["hw", "hw.optional", "machdep", "machdep.cpu"] {
            let member = namespace.named(name).unwrap();
            let native_oid = decode_oid(
                &Native
                    .query(META_NAME_TO_OID, &[], Some(name.as_bytes()))
                    .unwrap(),
            )
            .unwrap();
            let native = Native.query(META_FORMAT, &native_oid, None).unwrap();
            let mut bytes = [0xa5; 128];
            let mut length = 128;
            assert_eq!(
                format_out(&request(&mut bytes, &mut length), member.info),
                Outcome::value(0)
            );
            assert_eq!(&bytes[..length as usize], native, "{name}");
        }
    }

    #[test]
    fn enumeration_merges_aliases_filters_host_only_and_keeps_unmodeled_values_discoverable() {
        let model = model();
        let tree = Tree(BTreeMap::from([
            (vec![1, 1], "kern.ostype".into()),
            (vec![6, 7], "hw.pagesize".into()),
            (vec![6, 8], "hw.optional.host_only_fixture".into()),
            (vec![6, 9], "hw.memsize".into()),
            (vec![7, 1, 1], "machdep.cpu.vendor".into()),
            (vec![7, 1, 2], "machdep.cpu.brand_string".into()),
            (vec![7, 2], "machdep.wake_abstime".into()),
            (vec![8, 1], "net.inet.test".into()),
        ]));
        let namespace = Namespace::with_publications(&model, &tree, &[]).unwrap();
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
                namespace.named("kern.osrelease").unwrap().oid.clone(),
                vec![6, 7],
                vec![6, 9],
                namespace
                    .named("hw.optional.arm.FEAT_LSE")
                    .unwrap()
                    .oid
                    .clone(),
                vec![7, 1, 2],
                vec![7, 2],
                vec![8, 1],
            ]
        );
        for member in &namespace.members {
            assert_eq!(namespace.numbered(&member.oid), Some(member));
            assert_eq!(namespace.named(&member.name), Some(member));
        }
        assert_eq!(namespace.next(&model, &[i32::MAX], &tree), Err(ENOENT));
        assert_eq!(
            Namespace::with_publications(&model, &tree, &[])
                .unwrap()
                .members,
            namespace.members
        );
    }

    #[test]
    fn synthetic_oids_are_scoped_and_read_metadata_uses_the_guest_type() {
        let model = model();
        let mut bytes = [0xa5; 128];
        let mut length = bytes.len() as u64;
        let namespace = Namespace::get(&model).unwrap();
        let oid = namespace
            .named("hw.optional.arm.FEAT_LSE")
            .unwrap()
            .oid
            .clone();
        assert!(oid.starts_with(&namespace.named("hw.optional.arm").unwrap().oid));
        let mut query = vec![CTL_UNSPEC, META_NAME];
        query.extend_from_slice(&oid);
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
        let mut wrong = oid.clone();
        wrong[0] = CTL_KERN;
        assert!(namespace.numbered(&wrong).is_none());
        for operation in [META_NAME, META_FORMAT, META_DESCRIPTION] {
            let mut query = vec![CTL_UNSPEC, operation];
            query.extend_from_slice(&wrong);
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
        query.extend_from_slice(&namespace.named("hw.pagesize").unwrap().oid);
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
        assert_eq!(Namespace::get(&cloned).unwrap().members, namespace.members);
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
                Namespace::get(&model)
                    .unwrap()
                    .named("hw.optional.arm.FEAT_LSE")
                    .unwrap()
                    .oid
            );
        }
        for (name, expected) in [
            (vec![], ENOENT),
            (vec![b'x'; PATH_MAX], ENAMETOOLONG),
            (b"hw.optional.host_only_fixture".to_vec(), ENOENT),
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
        query.extend_from_slice(
            &Namespace::get(&model)
                .unwrap()
                .named("machdep.cpu.brand_string")
                .unwrap()
                .oid,
        );
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
