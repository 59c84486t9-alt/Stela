#[test]
fn descriptor_projection_defines_only_the_archive_owned_cohort() {
    let mut plan = policy_plan();
    let mut group = plan.groups[0].clone();
    group.token = "Class".into();
    group.ordinal = 2;
    group.module_name = "class".into();
    group.module_file = "class/class".into();
    plan.groups.push(group);
    let mut unit = plan.units[0].clone();
    unit.token = "Class".into();
    unit.ordinal = 2;
    unit.group_token = "Class".into();
    plan.units.push(unit);
    let source = descriptors(
        &plan,
        &["image".into()],
        &["image".into()],
        &mut String::new(),
    );
    for kind in ["group", "unit"] {
        let shared = format!("stela_linux_{kind}__Fixture__image");
        let owned = format!("stela_linux_{kind}__Fixture__Class");
        assert!(source.contains(&format!(
            "extern const struct stela_linux_build_{kind} {shared};"
        )));
        assert!(!source.contains(&format!("{shared} =")));
        assert_eq!(source.matches(&format!("{owned} =")).count(), 1);
    }
    assert!(source.contains("&stela_linux_group__Fixture__Class"));
    assert!(!source.contains("stela_linux_registry_image"));
    assert!(!source.contains("static const"));
}

use super::*;

// Authored empty COFF containers exercise the external object-reader
// contract. They lack the still-mandatory capture anchor.
fn coff_header(machine: u16) -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes[..2].copy_from_slice(&machine.to_le_bytes());
    bytes
}
#[test]
fn amd64_coff_reaches_capture_validation_despite_container_width() {
    let bytes = coff_header(object::pe::IMAGE_FILE_MACHINE_AMD64);
    let file = object::File::parse(bytes.as_slice()).unwrap();
    assert_eq!(file.architecture(), Architecture::X86_64);
    assert!(!file.is_64());
    let mut plan = policy_plan();
    plan.target = TargetAbi::CoffWin64Lp64;
    let error = scan(&plan, &plan.units[0], &bytes).unwrap_err();
    assert_eq!(
        error,
        "exactly one per-TU capture anchor required; missing opt-in header"
    );
}
#[test]
fn coff_architecture_and_target_mismatches_still_refuse() {
    let mut plan = policy_plan();
    plan.target = TargetAbi::CoffWin64Lp64;
    for machine in [
        object::pe::IMAGE_FILE_MACHINE_I386,
        object::pe::IMAGE_FILE_MACHINE_ARM64,
    ] {
        let error = scan(&plan, &plan.units[0], &coff_header(machine)).unwrap_err();
        assert!(error.ends_with("wrong target/relocatable LP64 object format"));
    }
    for target in [TargetAbi::ElfSysv, TargetAbi::MachOSysv] {
        plan.target = target;
        let error = scan(
            &plan,
            &plan.units[0],
            &coff_header(object::pe::IMAGE_FILE_MACHINE_AMD64),
        )
        .unwrap_err();
        assert!(error.ends_with("wrong target/relocatable LP64 object format"));
    }
}
#[test]
fn registration_identity_is_canonical_and_tu_scoped() {
    let record = parse_record("stela_linux_reg__D1__U2__p__17", "D1", "U2").unwrap();
    assert_eq!((record.code, record.sequence), ('p', 17));
    for bad in [
        "stela_linux_reg__D1__U3__p__17",
        "stela_linux_reg__D1__U2__p__017",
        "stela_linux_reg__D1__U2__p__4294967296",
        "stela_linux_reg__D1__U2__z__0",
        "stela_linux_reg__D1__U2__p__0__extra",
    ] {
        assert!(parse_record(bad, "D1", "U2").is_err());
    }
}
#[test]
fn string_encoders_keep_c_bytes_and_json_controls_unambiguous() {
    assert_eq!(c_string("a\n0\"\\"), "\"a\\0120\\\"\\\\\"");
    assert_eq!(json_string("a\n\"\\"), "\"a\\u000a\\\"\\\\\"");
}
fn policy_plan() -> Plan {
    let input = Input {
        root: 0,
        relative: PathBuf::from("unused"),
        sha256: [0; 32],
    };
    Plan {
        roots: vec![InputRoot {
            label: "reviewed".into(),
            selected: PathBuf::from("never-opened"),
        }],
        input_limits: Limits {
            max_unique_files: 32,
            max_unique_bytes: 1024 * 1024 * 1024,
            max_roots: 2,
        },
        // Explicit compiler cap admits the known ~290-MB kept tool;
        // small fixtures exercise accounting without allocating that size.
        role_limits: RoleLimits {
            cohort_bytes: 1024,
            source_bytes: 1024,
            compiler_bytes: 512 * 1024 * 1024,
            dependency_bytes: 1024,
            object_bytes: 1024,
        },
        domain_token: "Fixture".into(),
        domain_ordinal: 1,
        target: TargetAbi::ElfSysv,
        target_triple: "x86_64-unknown-linux-gnu".into(),
        image_symbol: "stela_linux_fixture_image".into(),
        cohort: input.clone(),
        groups: vec![Group {
            token: "image".into(),
            ordinal: 1,
            module_name: "fixture".into(),
            module_file: "fixtures/fixture".into(),
            provenance: "authored policy fixture".into(),
        }],
        units: vec![Unit {
            token: "image".into(),
            ordinal: 1,
            group_token: "image".into(),
            source: input.clone(),
            source_label: "fixture.c".into(),
            provenance: "authored policy fixture".into(),
            object: input.clone(),
            compiler: input.clone(),
            options: Vec::new(),
            working_directory: std::env::current_dir().unwrap(),
            dependencies: vec![input],
        }],
    }
}
#[test]
fn image_names_reject_keywords_arrays_and_generated_identities() {
    for allowed in [
        "stela_linux_fixture_image",
        "stela_linux_video_fixture_image",
    ] {
        assert!(image_namespace(allowed).is_ok());
    }
    let mut plan = policy_plan();
    for forbidden in [
        "for",
        "struct",
        "_Generic",
        "inits",
        "exits",
        "parameters",
        "infos",
        "devices",
        "setups",
        "groups",
        "units",
        "stela_linux__image",
        "stela_linux_9bad_image",
        "stela_linux_bad-image",
        "stela_linux_fixture_image;",
        "stela_linux_fixture_image\n",
    ] {
        plan.image_symbol = forbidden.into();
        assert!(validate_image_name(&plan).is_err(), "accepted {forbidden}");
    }
    for collision in [
        group_symbol("Fixture", "image"),
        unit_symbol("Fixture", "image"),
        "stela_linux_capture__Fixture__image".into(),
    ] {
        assert!(image_namespace(&collision).is_ok());
        plan.image_symbol = collision;
        assert!(validate_image_name(&plan).unwrap_err().contains("collides"));
    }
    let record = "stela_linux_reg__Fixture__image__i__0";
    assert!(image_collision(record, record).is_err());
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct FixtureDirectory(PathBuf);
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl FixtureDirectory {
    fn new() -> Self {
        use std::{
            fs::DirBuilder,
            os::unix::fs::DirBuilderExt,
            sync::atomic::{AtomicUsize, Ordering},
        };
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let parent = std::env::temp_dir();
        for _ in 0..16 {
            let path = parent.join(format!(
                "stela-registry-input-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("fixture directory: {error}"),
            }
        }
        panic!("fixture directory collision bound exhausted");
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0)
            && !std::thread::panicking()
        {
            panic!("fixture directory cleanup: {error}");
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn shared_input_verification_deduplicates_roles_without_compiler_bytes() {
    let directory = FixtureDirectory::new();
    std::fs::write(directory.0.join("shared"), b"abc").unwrap();
    let mut plan = policy_plan();
    plan.roots[0].selected = directory.0.clone();
    let shared = Input {
        root: 0,
        relative: PathBuf::from("shared"),
        sha256: digest(b"abc"),
    };
    plan.cohort = shared.clone();
    plan.units[0].source = shared.clone();
    plan.units[0].compiler = shared.clone();
    plan.units[0].dependencies = vec![shared];
    let (mut owner, _, cohort, units) = prepare_inputs(&plan).unwrap();
    assert_eq!(cohort, units[0].source);
    assert_eq!(cohort, units[0].compiler);
    assert_eq!(cohort, units[0].dependencies[0]);
    owner.verify(cohort).unwrap();
    for _ in 0..100 {
        owner.verify(units[0].compiler).unwrap();
    }
    let bindings = owner.finish().unwrap();
    assert_eq!(bindings.stats.unique_files, 1);
    assert_eq!(bindings.stats.unique_bytes, 3);
    assert_eq!(bindings.stats.bytes_returned, 0);
    assert_eq!(bindings.stats.bytes_hashed, 6); // one initial + one final pass
    assert_eq!(bindings.stats.metadata_cache_hits, 100);
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn conflicting_role_pins_refuse_before_any_file_content_is_read() {
    let directory = FixtureDirectory::new();
    let mut plan = policy_plan();
    plan.roots[0].selected = directory.0.clone();
    // The shared file does not exist: conflict refusal must
    // precede reading it, not accidentally pass on an unrelated I/O error.
    let shared = Input {
        root: 0,
        relative: PathBuf::from("absent"),
        sha256: [1; 32],
    };
    plan.cohort = shared.clone();
    plan.units[0].compiler = Input {
        sha256: [2; 32],
        ..shared
    };
    let error = match prepare_inputs(&plan) {
        Err(error) => error,
        Ok(_) => panic!("conflicting pins accepted"),
    };
    assert!(
        error.contains("conflicting expected hashes"),
        "wrong refusal: {error}"
    );
}
