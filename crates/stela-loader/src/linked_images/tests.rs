use super::super::{
    chained_fixups::{BindFixup, Import},
    load_plan::{Dependency, EntryPoint},
};
use super::*;

fn image(index: usize, identity: Option<&str>, name: &str, address: u64) -> ImageReceipt {
    ImageReceipt {
        index,
        container_sha256: String::new(),
        slice_offset: 0,
        load_base: 0,
        exports: vec![Export {
            name: name.into(),
            flags: 0,
            value: address,
            address,
        }],
        plan: LoadPlan {
            schema_version: 2,
            file_type: if index == 0 { 2 } else { 6 },
            dylib_identity: identity.map(|name| Dependency {
                command: 0xd,
                name: name.into(),
                timestamp: 0,
                current_version: 0,
                compatibility_version: 0,
            }),
            slice_sha256: String::new(),
            slice_bytes: 0,
            cpu_type: 0x100000c,
            cpu_subtype: 0,
            architecture: "arm64".into(),
            header_flags: object::macho::MH_TWOLEVEL,
            segments: vec![],
            entry: Some(EntryPoint {
                image_offset: 0,
                file_offset: 0,
                guest_address: 0,
                stack_size: 0,
            }),
            dependencies: vec![Dependency {
                command: 0xc,
                name: "@rpath/a.dylib".into(),
                timestamp: 0,
                current_version: 0,
                compatibility_version: 0,
            }],
            dylinker: None,
            rpaths: vec![],
            payloads: vec![],
            deferred_commands: vec![],
            execution_supported: false,
            unresolved_requirements: vec![],
        },
        fixups: DecodedFixups {
            authenticated_rebases: vec![],
            authenticated_binds: vec![],
            preferred_base: 0,
            load_base: 0,
            pointer_formats: vec![6],
            rebases: vec![],
            imports: vec![Import {
                library_ordinal: 1,
                weak: false,
                name: "_f".into(),
                addend: 3,
            }],
            binds: if index == 0 {
                vec![BindFixup {
                    segment_index: 0,
                    file_offset: 0,
                    guest_address: 0,
                    raw: 1 << 63,
                    pointer_format: 6,
                    import_index: 0,
                    inline_addend: 4,
                    addend: 7,
                }]
            } else {
                vec![]
            },
        },
        bindings: vec![],
        applied_rebases: 0,
        applied_binds: 0,
    }
}

#[test]
fn binding_selects_declared_provider_and_adds_combined_addend_once() {
    let images = vec![
        image(0, None, "_f", 0x1000),
        image(1, Some("@rpath/a.dylib"), "_f", 0x2000),
        image(2, Some("@rpath/b.dylib"), "_f", 0x3000),
    ];
    let result = resolve_bindings(&images, None).unwrap();
    assert_eq!(
        (
            result[0][0].provider_image,
            result[0][0].address,
            result[0][0].value
        ),
        (1, 0x2000, 0x2007)
    );
    assert!(result[1].is_empty() && result[2].is_empty());
}

#[test]
fn discovered_bindings_use_selected_file_edges_without_install_name_fallback() {
    let mut images = vec![
        image(0, None, "_main", 0),
        image(1, Some("@rpath/b.dylib"), "_f", 0x2000),
    ];
    assert!(resolve_bindings(&images, None).is_err());
    let link = DependencyLink {
        requester: 0,
        ordinal: 1,
        provider: 1,
    };
    assert_eq!(
        resolve_bindings(&images, Some(std::slice::from_ref(&link))).unwrap()[0][0].value,
        0x2007
    );
    images[1].plan.dylib_identity.as_mut().unwrap().name = "@rpath/a.dylib".into();
    assert!(resolve_bindings(&images, Some(&[])).is_err());
    assert!(resolve_bindings(&images, Some(&[link.clone(), link])).is_err());
    assert!(
        resolve_bindings(
            &images,
            Some(&[DependencyLink {
                requester: 0,
                ordinal: 1,
                provider: 0
            }])
        )
        .is_err()
    );
}

#[test]
fn binding_declines_missing_duplicate_weak_and_flat_resolution() {
    let mut images = vec![
        image(0, None, "_main", 0),
        image(1, Some("@rpath/b.dylib"), "_f", 0x2000),
    ];
    assert!(resolve_bindings(&images, None).is_err());
    images[1].plan.dylib_identity.as_mut().unwrap().name = "@rpath/a.dylib".into();
    images.push(image(2, Some("@rpath/a.dylib"), "_f", 0x3000));
    assert!(resolve_bindings(&images, None).is_err());
    images.pop();
    images[0].fixups.imports[0].weak = true;
    assert!(resolve_bindings(&images, None).is_err());
    images[0].fixups.imports[0].weak = false;
    for ordinal in [-3, -2, -1, 0, 2] {
        images[0].fixups.imports[0].library_ordinal = ordinal;
        assert!(resolve_bindings(&images, None).is_err());
    }
    images[0].fixups.imports[0].library_ordinal = 1;
    images[0].plan.header_flags = 0;
    assert!(resolve_bindings(&images, None).is_err());
    images[0].plan.header_flags = object::macho::MH_TWOLEVEL;
    images[1].exports[0].name = "_missing".into();
    assert!(resolve_bindings(&images, None).is_err());
}

#[test]
fn bound_addends_check_both_directions_and_native_address_boundary() {
    assert_eq!(binding_value(0x2000, -7).unwrap(), 0x1ff9);
    assert!(binding_value(0, -1).is_err());
    assert!(binding_value(u64::MAX, 1).is_err());
    assert!(binding_value(1 << 47, 0).is_err());
    assert_eq!(binding_value((1 << 47) - 1, 0).unwrap(), (1 << 47) - 1);
}
