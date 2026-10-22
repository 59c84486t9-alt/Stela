//! Generation-specific original DART topology and native placement gates.
use super::{DartInstance, IOMMU_MAPPER, Iommu, Node, name_of, power_resources};
use crate::platform::apple::dart::{self, Profile};
use alloc::{format, string::String, vec::Vec};

/// Every visible DART requirement, preserving separate translation windows.
/// Modern t8110 and qualified T6000 paired capture retain distinct cacheless
/// owners; FPAD and unqualified DMA routing remain explicit requirements.
pub(super) fn iommus(
    io: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Vec<Iommu>, String> {
    let mut found = Vec::new();
    let mut failure = None;
    super::apertures::visit(io, translate, &mut |node, translate| {
        if failure.is_some() || !is_dart(node) {
            return;
        }
        match iommu(node, translate) {
            Ok(iommu) => found.push(iommu),
            Err(error) => failure = Some(error),
        }
    })
    .ok_or("DeviceTree walk failed")?;
    match failure {
        Some(error) => Err(error),
        None => {
            let mut handles = Vec::new();
            for bank in &found {
                for &(handle, _) in &bank.mappers {
                    if handles.contains(&handle) {
                        return Err(format!(
                            "DART mapper phandle {handle:#x} has ambiguous native DMA routing"
                        ));
                    }
                    handles.push(handle);
                }
            }
            Ok(found)
        }
    }
}

pub(super) fn iommu(
    node: &Node<'_>,
    translate: &dyn Fn(u64, u64) -> Option<u64>,
) -> Result<Iommu, String> {
    let path = format!("/arm-io/{}", name_of(node));
    let profile = node
        .property("compatible")
        .and_then(Profile::from_compatible)
        .ok_or_else(|| {
            format!("{path} requires an unsupported or conflicting native DART generation")
        })?;
    if profile != Profile::T8110 {
        legacy_requirements(profile, |key| node.property(key))
            .map_err(|reason| format!("{path} {reason}"))?;
    }
    let reg = node.pairs("reg").unwrap_or_default();
    if node
        .property("reg")
        .is_none_or(|bytes| bytes.len() != reg.len() * 16)
    {
        return Err(format!("{path} has incomplete reg pairs"));
    }
    let descriptors = node.property("instance").unwrap_or_default();
    let descriptor_bytes = if profile == Profile::T8110 { 16 } else { 12 };
    if descriptors.is_empty()
        || !descriptors.len().is_multiple_of(descriptor_bytes)
        || descriptors.len() / descriptor_bytes != reg.len()
    {
        return Err(format!(
            "{path} instance descriptors do not match its reg entries"
        ));
    }
    let mut instances = Vec::new();
    let mut apf = None;
    let mut smmu = None;
    for (reg_index, (descriptor, &(offset, bytes))) in descriptors
        .chunks_exact(descriptor_bytes)
        .zip(&reg)
        .enumerate()
    {
        let (number, owner_start) = if profile == Profile::T8110 {
            (
                u32::from_le_bytes(descriptor[4..8].try_into().expect("instance number")),
                8,
            )
        } else {
            (instances.len() as u32, 4)
        };
        match &descriptor[..4] {
            b"TRAD" if apf.is_none() && smmu.is_none() && number as usize == instances.len() => {
                let physical = translate(offset, bytes)
                    .filter(|at| at.is_multiple_of(dart::DAPF_BYTES) && bytes == dart::DAPF_BYTES)
                    .ok_or_else(|| {
                        format!("{path} DART instance is not one translated aligned 16 KiB block")
                    })?;
                if instances
                    .iter()
                    .any(|i: &DartInstance| i.physical == physical)
                {
                    return Err(format!("{path} has duplicate DART register windows"));
                }
                instances.push(DartInstance {
                    physical,
                    bytes,
                    number,
                    reg_index,
                    owner: descriptor[owner_start..owner_start + 8]
                        .try_into()
                        .expect("eight-byte owner"),
                });
            }
            b"FPAD" if instances.len() == 1 && number == 0 && apf.is_none() && smmu.is_none() => {
                apf = Some((offset, bytes))
            }
            b"UMMS"
                if instances.len() == 1
                    && (profile != Profile::T8110 || number == 0)
                    && apf.is_none()
                    && smmu.is_none() =>
            {
                let physical = translate(offset, bytes)
                    .filter(|at| at.is_multiple_of(dart::DAPF_BYTES) && bytes == dart::DAPF_BYTES)
                    .ok_or_else(|| {
                        format!("{path} SMMU instance is not one translated aligned 16 KiB block")
                    })?;
                smmu = Some((physical, bytes));
            }
            _ => {
                return Err(format!(
                    "{path} has unsupported instance kinds, numbering or APF topology"
                ));
            }
        }
    }
    if instances.is_empty() {
        return Err(format!("{path} has no TRAD instance"));
    }
    let apf = match apf {
        None => None,
        Some((filter, filter_bytes)) => {
            let at = translate(filter, dart::DAPF_BYTES)
                .filter(|at| {
                    at.is_multiple_of(dart::DAPF_BYTES) && filter_bytes == dart::DAPF_BYTES
                })
                .ok_or_else(|| format!("{path} APF is not one aligned 16 KiB block"))?;
            let slices = node
                .first_u32("n-apfs-instance-0")
                .and_then(|count| usize::try_from(count).ok())
                .filter(|&count| count > 0 && count as u64 * 0x40 <= dart::DAPF_BYTES)
                .ok_or_else(|| format!("{path} has no n-apfs-instance-0 slice count"))?;
            Some((at, slices))
        }
    };
    let streams = node
        .first_u32("sid-count")
        .or_else(|| (profile != Profile::T8110).then_some(16))
        .and_then(|count| u16::try_from(count).ok())
        .filter(|&count| count > 0 && usize::from(count) <= profile.stream_limit())
        .ok_or_else(|| format!("{path} sid-count exceeds the selected native DART profile"))?;
    let irq = node
        .first_u32("interrupts")
        .filter(|irq| u16::try_from(*irq).is_ok())
        .ok_or_else(|| {
            format!("{path} requires an interrupt within the native AIC input encoding")
        })?;
    let clock_gates = power_resources::gate_ids(node, &path, "clock-gates")?;
    let power_gates = power_resources::gate_ids(node, &path, "power-gates")?;
    let retention = node.property("retention").is_some();
    if retention && node.property("no-sleep").is_some() {
        return Err(format!(
            "{path} retention and no-sleep are mutually exclusive"
        ));
    }
    let mut mappers = Vec::new();
    let mut mapper_failure = None;
    node.visit(&mut |child| {
        if child.compatible(IOMMU_MAPPER) {
            let word = |key| {
                child
                    .property(key)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok().map(u32::from_le_bytes))
            };
            match (word("AAPL,phandle"), word("reg")) {
                (Some(handle), Some(sid)) => mappers.push((handle, sid)),
                _ => {
                    mapper_failure = Some(format!(
                        "{path} mapper requires one native phandle and SID word"
                    ))
                }
            }
        }
    })
    .ok_or("DeviceTree walk failed")?;
    if let Some(error) = mapper_failure {
        return Err(error);
    }
    let sids = if profile == Profile::T8110 {
        match node.property("sid") {
            None => Vec::new(),
            Some(bytes) if bytes.len().is_multiple_of(4) => node
                .cells32("sid")
                .filter(|sids| sids.iter().all(|sid| *sid < u32::from(streams)))
                .ok_or_else(|| format!("{path} has malformed or out-of-range sid entries"))?,
            Some(_) => return Err(format!("{path} has incomplete sid cells")),
        }
    } else {
        match node.property("sids") {
            None => Vec::new(),
            Some(bytes) => {
                let bitmap =
                    u32::from_le_bytes(bytes.try_into().expect("validated legacy SID bitmap"));
                (0..u32::from(streams))
                    .filter(|sid| bitmap & (1 << sid) != 0)
                    .collect()
            }
        }
    };
    if sids
        .iter()
        .enumerate()
        .any(|(index, sid)| sids[..index].contains(sid))
    {
        return Err(format!("{path} has duplicate sid entries"));
    }
    let remap_bytes = node.property("remap").unwrap_or_default();
    if !remap_bytes.len().is_multiple_of(4) {
        return Err(format!("{path} remap is not padded byte pairs"));
    }
    let remap = remap_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .filter(|pair| **pair != [0, 0])
        .map(|pair| (pair[0], pair[1]))
        .collect::<Vec<_>>();
    profile
        .validate_remaps(usize::from(streams), &remap)
        .map_err(|reason| format!("{path} {reason}"))?;
    let vm_base = match node.property("vm-base") {
        None => 0,
        Some(bytes) if profile != Profile::T8110 => u64::from(u32::from_le_bytes(
            bytes.try_into().expect("validated legacy vm-base"),
        )),
        Some(bytes) => u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| format!("{path} vm-base is not one 64-bit address"))?,
        ),
    };
    if mappers.iter().any(|&(_, sid)| sid >= u32::from(streams)) {
        return Err(format!("{path} mapper SID exceeds its native DART profile"));
    }
    if !remap.is_empty() {
        for &(_, context) in &mappers {
            profile
                .mapper_input_stream(usize::from(streams), context as usize, &remap)
                .map_err(|reason| format!("{path} {reason}"))?;
        }
    }
    if profile != Profile::T8110 && instances.len() > 1 && !mappers.is_empty() {
        return Err(format!(
            "{path} requires explicit legacy multi-instance DMA routing"
        ));
    }
    Ok(Iommu {
        profile,
        instances,
        sids,
        remap,
        vm_base,
        smmu,
        streams,
        irq,
        mappers,
        apf,
        clock_gates,
        power_gates,
        retention,
    })
}

/// Recognize DART requirements even when a generation cannot be admitted.
/// Unknown families must produce a named requirement instead of disappearing.
fn is_dart(node: &Node<'_>) -> bool {
    node.property("compatible").is_some_and(|bytes| {
        bytes
            .split(|&byte| byte == 0)
            .any(|name| name.starts_with(b"dart,"))
    })
}

/// Pure optional-feature gate shared with public compatible admission.
/// Legacy FPAD counts as a translation descriptor plus an appended filter
/// window; accepting it as a modern standalone APF would misplace registers.
pub(super) fn legacy_requirements<'a>(
    profile: Profile,
    property: impl Fn(&str) -> Option<&'a [u8]>,
) -> Result<(), &'static str> {
    if profile == Profile::T8110 {
        return Ok(());
    }
    let streams = match property("sid-count") {
        None => 16,
        Some(bytes) => u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| "has an incomplete legacy sid-count")?,
        ),
    };
    if streams > 16 {
        return Err(
            "requires a legacy stream layout beyond the supported 16-SID profile (including USB4's 64-SID layout)",
        );
    }
    if streams == 0 {
        return Err("has an empty native DART stream set");
    }
    if property("page-size") != Some(0x4000u32.to_le_bytes().as_slice()) {
        return Err("requires an explicit supported legacy 16 KiB page-size");
    }
    let descriptors = property("instance").ok_or("has no legacy 12-byte instance descriptors")?;
    if descriptors.is_empty() || !descriptors.len().is_multiple_of(12) {
        return Err("has incomplete legacy 12-byte instance descriptors");
    }
    if descriptors.len() / 12 > 5 {
        return Err(
            "requires a legacy descriptor count beyond the recovered five-instance topology",
        );
    }
    for descriptor in descriptors.as_chunks::<12>().0 {
        match &descriptor[..4] {
            b"TRAD" => (),
            b"FPAD" => {
                return Err(
                    "requires unsupported legacy FPAD translation and appended-filter semantics",
                );
            }
            b"UMMS"
                if profile == Profile::T6000
                    && descriptors.len() == 24
                    && &descriptors[..4] == b"TRAD"
                    && &descriptors[12..16] == b"UMMS" =>
            {
                // The declared cacheless UMMS lacks lock capability. Original
                // SPTM permits the differing TRAD/UMMS modes under this exact
                // policy; preserve both source presence properties.
                if property("never-lock") != Some(&[])
                    || property("ignore-inconsistent-hw-locks") != Some(&[])
                {
                    return Err("requires qualified empty-presence UMMS lock policies");
                }
            }
            b"UMMS" => return Err("requires unsupported legacy UMMS capture semantics"),
            _ => return Err("requires an unknown legacy DART instance kind"),
        }
    }
    if (0..5).any(|index| {
        property(&format!("filter-data-instance-{index}")).is_some()
            || property(&format!("dapf-instance-{index}")).is_some()
            || property(&format!("n-apfs-instance-{index}")).is_some()
    }) {
        return Err("requires unsupported legacy address-permission filter semantics");
    }
    for flag in ["never-lock", "ignore-inconsistent-hw-locks"] {
        if property(flag).is_some_and(|bytes| !bytes.is_empty()) {
            return Err("requires qualified empty-presence legacy lock policies");
        }
    }
    let reg = property("reg").ok_or("has no legacy register windows")?;
    if reg.len() != descriptors.len() / 12 * 16 {
        return Err("legacy translation descriptors do not match their physical reg ordinals");
    }
    if reg.as_chunks::<16>().0.iter().any(|pair| {
        u64::from_le_bytes(pair[8..16].try_into().expect("complete reg size")) != dart::DAPF_BYTES
    }) {
        return Err("requires unsupported legacy DART register geometry");
    }
    if property("sid").is_some() {
        return Err("requires legacy sids bitmap semantics, not a modern sid list");
    }
    if let Some(bytes) = property("sids") {
        let bitmap = u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| "requires the unsupported legacy wide SID bitmap")?,
        );
        if bitmap >> streams != 0 {
            return Err("has legacy sids bits outside the native stream set");
        }
    }
    if let Some(bytes) = property("remap") {
        if !bytes.len().is_multiple_of(4) {
            return Err("has incomplete padded legacy remap entries");
        }
        if bytes.iter().any(|&byte| byte != 0) {
            if descriptors
                .as_chunks::<12>()
                .0
                .iter()
                .filter(|d| &d[..4] == b"TRAD")
                .count()
                != 1
            {
                return Err("requires explicit legacy multi-instance DMA remap routing");
            }
            let mut remaps = Vec::new();
            for pair in bytes.as_chunks::<2>().0 {
                if pair != &[0, 0] {
                    remaps.push((pair[0], pair[1]));
                }
            }
            profile.validate_remaps(streams as usize, &remaps)?;
        }
    }
    if property("vm-base").is_some_and(|bytes| bytes.len() != 4) {
        return Err("requires one legacy 32-bit vm-base address");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::adt::encode;
    use crate::machine::soc::tests::flat_fixture_extent;
    use alloc::vec;

    fn bytes64(values: &[u64]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn legacy(
        compatible: &[u8],
        descriptors: &[u8],
        registers: &[u64],
        extra: &[(&str, &[u8])],
        children: &[Vec<u8>],
    ) -> Vec<u8> {
        let registers = bytes64(registers);
        let page = 0x4000u32.to_le_bytes();
        let irq = 1035u32.to_le_bytes();
        let mut properties = vec![
            ("name", b"dart\0".as_slice()),
            ("compatible", compatible),
            ("instance", descriptors),
            ("reg", registers.as_slice()),
            ("page-size", page.as_slice()),
            ("interrupts", irq.as_slice()),
        ];
        // Explicit replacements avoid duplicate properties in malformed cases.
        for &(key, value) in extra {
            if let Some(slot) = properties.iter_mut().find(|(existing, _)| *existing == key) {
                slot.1 = value;
            } else {
                properties.push((key, value));
            }
        }
        encode(&properties, children)
    }

    #[test]
    fn legacy_layout_preserves_original_owner_bytes_register_ordinals_and_bitmap_sids() {
        // Original J274AP/J314SAP USB descriptor bytes, independently of
        // their unsupported remap requirement. This fixture admits only MMIO
        // topology; it does not claim that either complete USB node is admitted.
        let descriptors = [b"TRADDARTLLT\0".as_slice(), b"TRADDARTBLK\0"].concat();
        for (compatible, profile, base) in [
            (b"dart,t8020\0".as_slice(), Profile::T8020, 0x382f00000),
            (b"dart,t6000\0".as_slice(), Profile::T6000, 0x702f00000),
        ] {
            let tree = legacy(
                compatible,
                &descriptors,
                &[base, 0x4000, base + 0x80000, 0x4000],
                &[
                    ("sids", &0xbu32.to_le_bytes()),
                    ("vm-base", &0x80000000u32.to_le_bytes()),
                ],
                &[],
            );
            let node = Node::root(&tree).unwrap();
            let bank = iommu(
                &node,
                &flat_fixture_extent(&|offset| offset.checked_add(0x200000000)),
            )
            .unwrap();
            assert_eq!(bank.profile, profile);
            assert_eq!(bank.streams, 16);
            assert_eq!(bank.vm_base, 0x80000000);
            assert_eq!(bank.sids, [0, 1, 3]);
            assert_eq!(
                bank.instances
                    .iter()
                    .map(|instance| (instance.number, instance.reg_index))
                    .collect::<Vec<_>>(),
                [(0, 0), (1, 1)]
            );
            assert_eq!(bank.instances[0].owner, *b"DARTLLT\0");
            assert_eq!(bank.instances[1].owner, *b"DARTBLK\0");
            assert_eq!(bank.instances[1].physical, base + 0x80000 + 0x200000000);
            assert!(super::super::models(
                core::str::from_utf8(&compatible[..compatible.len() - 1]).unwrap(),
                |key| node.property(key)
            ));
        }
    }

    #[test]
    fn legacy_native_feature_gates_match_public_admission_and_leave_requirements_named() {
        let descriptor = b"TRADDART\0\0\0\0";
        for (extra, requirement) in [
            (vec![("sid-count", 64u32.to_le_bytes().to_vec())], "16-SID"),
            (
                vec![("page-size", 0x1000u32.to_le_bytes().to_vec())],
                "16 KiB page-size",
            ),
            (
                vec![("reg", bytes64(&[0x382f00000, 0x8000]))],
                "register geometry",
            ),
            (
                vec![("remap", vec![0, 0])],
                "incomplete padded legacy remap",
            ),
            (
                vec![("filter-data-instance-0", vec![0; 0x40])],
                "address-permission filter",
            ),
            (
                vec![("sids", 0x10000u32.to_le_bytes().to_vec())],
                "outside the native",
            ),
            (
                vec![("sids", 1u64.to_le_bytes().to_vec())],
                "wide SID bitmap",
            ),
            (
                vec![("sid", 0u32.to_le_bytes().to_vec())],
                "not a modern sid list",
            ),
            (
                vec![("vm-base", 0u64.to_le_bytes().to_vec())],
                "32-bit vm-base",
            ),
            (
                vec![("instance", b"FPADDARTLLT\0".to_vec())],
                "FPAD translation and appended-filter",
            ),
            (
                vec![("instance", b"UMMSSMMURT\0\0".to_vec())],
                "UMMS capture",
            ),
        ] {
            let extra = extra
                .iter()
                .map(|(key, value)| (*key, value.as_slice()))
                .collect::<Vec<_>>();
            let tree = legacy(
                b"dart,t8020\0",
                descriptor,
                &[0x382f00000, 0x4000],
                &extra,
                &[],
            );
            let node = Node::root(&tree).unwrap();
            assert!(
                iommu(&node, &flat_fixture_extent(&Some))
                    .unwrap_err()
                    .contains(requirement),
                "{requirement}"
            );
            assert!(!super::super::models("dart,t8020", |key| node.property(key)));
        }
    }

    #[test]
    fn t6000_paired_capture_requires_its_exact_unlocked_policy_and_order() {
        let descriptors = b"TRADDART\0\0\0\0UMMSSMMU\0\0\0\0";
        let registers = [0x89304000, 0x4000, 0x89300000, 0x4000];
        for flags in [
            vec![],
            vec![("never-lock", &[][..])],
            vec![
                ("never-lock", &[][..]),
                ("ignore-inconsistent-hw-locks", &[1][..]),
            ],
        ] {
            let bytes = legacy(b"dart,t6000\0", descriptors, &registers, &flags, &[]);
            assert!(iommu(&Node::root(&bytes).unwrap(), &flat_fixture_extent(&Some)).is_err());
        }
        let flags = [
            ("never-lock", &[][..]),
            ("ignore-inconsistent-hw-locks", &[][..]),
        ];
        let bytes = legacy(b"dart,t6000\0", descriptors, &registers, &flags, &[]);
        let bank = iommu(&Node::root(&bytes).unwrap(), &flat_fixture_extent(&Some)).unwrap();
        assert_eq!(bank.instances.len(), 1);
        assert_eq!(bank.instances[0].reg_index, 0);
        assert_eq!(bank.smmu, Some((0x89300000, 0x4000)));
        for descriptors in [
            b"UMMSSMMU\0\0\0\0TRADDART\0\0\0\0".as_slice(),
            b"TRADDART\0\0\0\0TRADDART\0\0\0\0",
        ] {
            let bytes = legacy(b"dart,t6000\0", descriptors, &registers, &flags, &[]);
            if &descriptors[..4] == b"UMMS" {
                assert!(iommu(&Node::root(&bytes).unwrap(), &flat_fixture_extent(&Some)).is_err());
            } else {
                assert_eq!(
                    iommu(&Node::root(&bytes).unwrap(), &flat_fixture_extent(&Some))
                        .unwrap()
                        .instances
                        .len(),
                    2
                );
            }
        }
    }

    #[test]
    fn t6000_remaps_do_not_admit_an_unselected_translation_owner() {
        let one = b"TRADDART\0\0\0\0";
        let descriptors = [one.as_slice(), one].concat();
        let bytes = legacy(
            b"dart,t6000\0",
            &descriptors,
            &[0x89304000, 0x4000, 0x8930c000, 0x4000],
            &[("remap", &[0, 1, 0, 0])],
            &[],
        );
        let node = Node::root(&bytes).unwrap();
        assert!(
            iommu(&node, &flat_fixture_extent(&Some))
                .unwrap_err()
                .contains("multi-instance DMA remap")
        );
        assert!(!super::super::models("dart,t6000", |key| node.property(key)));
        // M1 (`dart,t8020`) SPTM checks the same remap bytes (T8103 VA
        // 0xfffffff0270dc51c..0xfffffff0270dc564).
        for compatible in [b"dart,t8020\0", b"dart,t6000\0"] {
            for remap in [[5, 0, 6, 0], [5, 0, 0, 0], [0, 1, 1, 0], [5, 0, 5, 1]] {
                let bytes = legacy(
                    compatible,
                    one,
                    &[0x89304000, 0x4000],
                    &[("remap", &remap)],
                    &[],
                );
                let node = Node::root(&bytes).unwrap();
                assert_eq!(
                    iommu(&node, &flat_fixture_extent(&Some)).is_ok(),
                    remap[1] == 0 && remap[3] == 0
                );
            }
        }
    }

    #[test]
    fn mapper_sid_and_multi_instance_dma_require_actual_native_routing() {
        let mapper = |sid: u32| {
            encode(
                &[
                    ("name", b"mapper\0"),
                    ("compatible", b"iommu-mapper\0"),
                    ("AAPL,phandle", &7u32.to_le_bytes()),
                    ("reg", &sid.to_le_bytes()),
                ],
                &[],
            )
        };
        let one = b"TRADDART\0\0\0\0";
        let tree = legacy(
            b"dart,t6000\0",
            one,
            &[0x702f00000, 0x4000],
            &[],
            &[mapper(15)],
        );
        assert_eq!(
            iommu(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some))
                .unwrap()
                .mappers,
            [(7, 15)]
        );
        let tree = legacy(
            b"dart,t6000\0",
            one,
            &[0x702f00000, 0x4000],
            &[],
            &[mapper(16)],
        );
        assert!(
            iommu(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some))
                .unwrap_err()
                .contains("mapper SID")
        );
        let first = legacy(
            b"dart,t6000\0",
            one,
            &[0x702f00000, 0x4000],
            &[],
            &[mapper(1)],
        );
        let second = legacy(
            b"dart,t6000\0",
            one,
            &[0x702f80000, 0x4000],
            &[],
            &[mapper(2)],
        );
        let tree = encode(&[("name", b"arm-io\0")], &[first, second]);
        assert!(
            iommus(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some))
                .unwrap_err()
                .contains("ambiguous native DMA routing")
        );
        let two = [one.as_slice(), one].concat();
        let tree = legacy(
            b"dart,t6000\0",
            &two,
            &[0x702f00000, 0x4000, 0x702f80000, 0x4000],
            &[],
            &[mapper(1)],
        );
        assert!(
            iommu(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some))
                .unwrap_err()
                .contains("multi-instance DMA routing")
        );
    }

    #[test]
    fn native_family_traversal_keeps_mixed_groups_and_refuses_unknown_generations() {
        let one = b"TRADDART\0\0\0\0";
        let legacy = legacy(b"dart,t6000\0", one, &[0x702f00000, 0x4000], &[], &[]);
        let modern = encode(
            &[
                ("name", b"dart-modern\0"),
                ("compatible", b"dart,t8110\0"),
                (
                    "instance",
                    &[b"TRAD".as_slice(), &[0; 4], b"DART\0\0\0\0"].concat(),
                ),
                ("reg", &bytes64(&[0x703000000, 0x4000])),
                ("sid-count", &64u32.to_le_bytes()),
                ("sid", &15u32.to_le_bytes()),
                ("interrupts", &1u32.to_le_bytes()),
                ("vm-base", &0x100000000u64.to_le_bytes()),
            ],
            &[],
        );
        let tree = encode(&[("name", b"arm-io\0")], &[legacy, modern]);
        let banks = iommus(&Node::root(&tree).unwrap(), &flat_fixture_extent(&Some)).unwrap();
        assert_eq!(
            banks.iter().map(|bank| bank.profile).collect::<Vec<_>>(),
            [Profile::T6000, Profile::T8110]
        );
        assert_eq!(banks[1].sids, [15]);
        assert_eq!(banks[1].vm_base, 0x100000000);
        let unknown = encode(&[("compatible", b"dart,gen3\0dart,t8110\0")], &[]);
        assert!(
            iommus(&Node::root(&unknown).unwrap(), &flat_fixture_extent(&Some))
                .unwrap_err()
                .contains("unsupported or conflicting")
        );
        assert!(!super::super::models("dart,gen3", |_| None));
        let node = Node::root(&unknown).unwrap();
        assert!(!super::super::models("dart,t8110", |key| node.property(key)));
    }
}
