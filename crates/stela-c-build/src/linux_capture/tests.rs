//! Imported artifacts cannot grant new roots or alter the reviewed cohort.
use super::*;
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    boundary: Boundary<'static>,
    linux: PathBuf,
    captured: Vec<Captured>,
}
fn fixture() -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let workspace = root.join("workspace");
    let linux = workspace.join("linux");
    let output = root.join("shared-output");
    let tools = root.join("toolchain");
    for directory in [&linux, &output, &tools] {
        fs::create_dir_all(directory).unwrap();
    }
    let compiler = tools.join("clang");
    fs::write(&compiler, b"fixture compiler identity").unwrap();
    let boundary = Boundary {
        output: output.clone(),
        compiler,
        units: COMMON,
        profiles: vec![
            Profile {
                directory: workspace.clone(),
                options: vec!["-Dfixture=1".into()]
            };
            COMMON.len()
        ],
        placements: COMMON
            .iter()
            .map(|spec| Placement {
                source: linux.join(format!("{}.c", spec.source)),
                output: output.clone(),
                roots: vec![workspace.clone(), tools.clone(), output.clone()],
            })
            .collect(),
    };
    let captured = COMMON
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            let source = boundary.placements[index].source.clone();
            let token = spec.scope.token();
            Captured {
                unit: (*spec).into(),
                scope: spec.scope,
                source: source.clone(),
                reviewed_roots: boundary.roots(),
                ordinal: spec.scope.global_ordinal,
                object: boundary.output.join(format!("captured-{token}.o")),
                compiler: boundary.compiler.clone(),
                token,
                options: vec!["-Dfixture=1".into()],
                directory: workspace.clone(),
                dependencies: vec![source],
                pins: BTreeMap::new(),
            }
        })
        .collect();
    Fixture {
        _temporary: temporary,
        boundary,
        linux,
        captured,
    }
}
fn encode(captured: &[Captured]) -> Vec<u8> {
    fn field(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    fn file(bytes: &mut Vec<u8>, path: &Path) {
        field(bytes, path.to_str().unwrap());
        bytes.extend_from_slice(&[1; 32]);
    }
    let mut bytes = b"STELA-LINUX-CAPTURE-3\0".to_vec();
    bytes.extend_from_slice(&(captured.len() as u32).to_le_bytes());
    for unit in captured {
        field(&mut bytes, unit.scope.slice);
        field(&mut bytes, unit.scope.group);
        for ordinal in [
            unit.scope.group_ordinal,
            unit.scope.unit_ordinal,
            unit.scope.global_ordinal,
        ] {
            bytes.extend_from_slice(&ordinal.to_le_bytes());
        }
        for value in [
            &unit.unit.source,
            &unit.unit.module,
            &unit.unit.file,
            &unit.token,
        ] {
            field(&mut bytes, value);
        }
        bytes.extend_from_slice(&unit.ordinal.to_le_bytes());
        file(&mut bytes, &unit.object);
        file(&mut bytes, &unit.compiler);
        file(&mut bytes, &unit.source);
        field(&mut bytes, unit.directory.to_str().unwrap());
        bytes.extend_from_slice(&(unit.options.len() as u32).to_le_bytes());
        for option in &unit.options {
            field(&mut bytes, option);
        }
        bytes.extend_from_slice(&(unit.dependencies.len() as u32).to_le_bytes());
        for dependency in &unit.dependencies {
            file(&mut bytes, dependency);
        }
    }
    bytes
}

#[test]
fn reviewed_common_cohort_retains_pins_and_only_caller_owned_roots() {
    let fixture = fixture();
    let observed = decode(&encode(&fixture.captured), &fixture.boundary).unwrap();
    assert_eq!(observed.len(), 3);
    for (index, unit) in observed.iter().enumerate() {
        identity(unit, COMMON[index], index).unwrap();
        assert_eq!(unit.reviewed_roots, fixture.boundary.roots());
        assert_eq!(unit.pin(&unit.object), Some([1; 32]));
        assert_eq!(unit.pin(&unit.compiler), Some([1; 32]));
        assert_eq!(unit.pin(&unit.source), Some([1; 32]));
    }
}

#[test]
fn imported_cohort_identity_order_and_count_are_exact() {
    let fixture = fixture();
    for field in ["source", "module", "module file", "token", "ordinal"] {
        let mut changed = fixture.captured.clone();
        match field {
            "source" => changed[0].unit.source = "lib/sort".into(),
            "module" => changed[0].unit.module = "other".into(),
            "module file" => changed[0].unit.file = "lib/other".into(),
            "token" => changed[0].token = "other".into(),
            "ordinal" => changed[0].ordinal = 2,
            _ => unreachable!(),
        }
        assert!(matches!(decode(&encode(&changed), &fixture.boundary),
            Err(ImportError::Identity { index: 0, field: rejected }) if rejected == field));
    }
    let mut changed = fixture.captured.clone();
    changed.swap(0, 1);
    assert!(matches!(
        decode(&encode(&changed), &fixture.boundary),
        Err(ImportError::Identity { index: 0, .. })
    ));
    for count in [2, 4] {
        let mut changed = fixture.captured.clone();
        changed.resize(count, fixture.captured[0].clone());
        assert!(matches!(
            decode(&encode(&changed), &fixture.boundary),
            Err(ImportError::Schema("reviewed cohort count differs"))
        ));
    }
}

#[test]
fn metadata_cannot_select_object_source_compiler_or_dependency_roots() {
    let fixture = fixture();
    let unrelated = fixture._temporary.path().join("unreviewed");
    for (field, path) in [
        ("shared output", unrelated.join("captured-rtmutexapi.o")),
        (
            "shared output",
            fixture.boundary.output.join("../captured-rtmutexapi.o"),
        ),
        ("Linux source", unrelated.join("rtmutex_api.c")),
        ("Linux source", fixture.linux.join("kernel/locking/other.c")),
        (
            "compiler",
            fixture.boundary.compiler.with_file_name("other-clang"),
        ),
        ("dependency roots", unrelated.join("header.h")),
        (
            "dependency roots",
            fixture.boundary.output.join("../header.h"),
        ),
    ] {
        let mut changed = fixture.captured.clone();
        match field {
            "shared output" => changed[0].object = path,
            "Linux source" => changed[0].source = path,
            "compiler" => changed[0].compiler = path,
            "dependency roots" => changed[0].dependencies = vec![path],
            _ => unreachable!(),
        }
        assert!(
            matches!(decode(&encode(&changed), &fixture.boundary),
            Err(ImportError::Path { index: 0, field: rejected }) if rejected == field),
            "{field}"
        );
    }
}

#[test]
fn malformed_versions_lengths_truncation_and_trailing_bytes_refuse() {
    for bad in ["", "ff", &"x".repeat(64)] {
        assert!(matches!(expected_digest(bad), Err(ImportError::Schema(_))));
    }
    let fixture = fixture();
    let bytes = encode(&fixture.captured);
    for length in [0, 21, 25, bytes.len() - 1] {
        assert!(matches!(
            decode(&bytes[..length], &fixture.boundary),
            Err(ImportError::Schema(_))
        ));
    }
    let mut changed = bytes.clone();
    changed[20] = b'1';
    assert!(matches!(
        decode(&changed, &fixture.boundary),
        Err(ImportError::Schema("unsupported cohort version"))
    ));
    let mut changed = bytes.clone();
    changed[26..30].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        decode(&changed, &fixture.boundary),
        Err(ImportError::Schema("field/count exceeds limit"))
    ));
    let mut changed = bytes;
    changed.push(0);
    assert!(matches!(
        decode(&changed, &fixture.boundary),
        Err(ImportError::Schema("trailing cohort bytes"))
    ));
}

#[test]
fn duplicate_paths_with_conflicting_pins_refuse() {
    let fixture = fixture();
    let mut bytes = encode(&fixture.captured);
    let source = fixture.captured[0].source.to_str().unwrap().as_bytes();
    let position = bytes
        .windows(source.len())
        .rposition(|window| window == source)
        .unwrap();
    bytes[position + source.len()] = 2;
    assert!(matches!(
        decode(&bytes, &fixture.boundary),
        Err(ImportError::Schema("conflicting input pins"))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn bounded_import_reads_only_the_caller_selected_output_and_rejects_symlinks() {
    let fixture = fixture();
    let bytes = encode(&fixture.captured);
    let digest = cohort_digest(&bytes);
    let selected = || Import {
        output: &fixture.boundary.output,
        compiler: &fixture.boundary.compiler,
        units: COMMON,
        placements: &fixture.boundary.placements,
        profiles: &fixture.boundary.profiles,
        sha256: &digest,
    };
    let path = fixture.boundary.output.join("captured-units.bin");
    fs::write(&path, &bytes).unwrap();
    assert_eq!(read(selected()).unwrap().len(), 3);
    let mut tampered = bytes.clone();
    tampered.push(0);
    fs::write(&path, tampered).unwrap();
    assert!(matches!(read(selected()), Err(ImportError::Input(_))));
    fs::remove_file(&path).unwrap();
    let external = fixture._temporary.path().join("outside-cohort.bin");
    fs::write(&external, encode(&fixture.captured)).unwrap();
    std::os::unix::fs::symlink(&external, &path).unwrap();
    assert!(matches!(read(selected()), Err(ImportError::Input(_))));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn owned_cohort_resolves_output_alias_without_admitting_foreign_inputs() {
    let fixture = fixture();
    let output = &fixture.boundary.output;
    let alias = fixture._temporary.path().join("output-alias");
    std::os::unix::fs::symlink(output, &alias).unwrap();
    let listing = "rtmutex kernel/locking/rtmutex_api\n";
    let path = write_cohort(&alias, "fixture", listing);
    assert_eq!(path, output.join("fixture-units.txt"));
    let past = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567_890);
    fs::File::open(&path).unwrap().set_modified(past).unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(write_cohort(&alias, "fixture", listing), path);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    let mut snapshot = Snapshot::new(std::slice::from_ref(output));
    let input = snapshot.input(&path, None, 64 << 10);
    assert_eq!(input.relative, Path::new("fixture-units.txt"));
    snapshot.finish();
    let mut foreign = Snapshot::new(&fixture.boundary.placements[0].roots[..1]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            foreign.input(&path, None, 64 << 10);
        }))
        .is_err()
    );
    let external = fixture._temporary.path().join("foreign-units.txt");
    fs::write(&external, listing).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&external, &path).unwrap();
    let mut snapshot = Snapshot::new(std::slice::from_ref(output));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            snapshot.input(&path, None, 64 << 10);
        }))
        .is_err()
    );
}
#[test]
fn composed_objects_use_only_callers_exact_placements() {
    let mut f = fixture();
    let second = f._temporary.path().join("second-producer");
    fs::create_dir(&second).unwrap();
    f.boundary.placements[1].output = second.clone();
    f.boundary.placements[1].roots.push(second.clone());
    f.captured[1].object = second.join(format!("captured-{}.o", f.captured[1].token));
    let bytes = encode(&f.captured);
    assert!(decode(&bytes, &f.boundary).is_ok());
    f.boundary.placements[1].output = f.boundary.output.clone();
    assert!(matches!(
        decode(&bytes, &f.boundary),
        Err(ImportError::Path {
            index: 1,
            field: "shared output"
        })
    ));
    f.boundary.placements.clear();
    assert!(matches!(
        decode(&bytes, &f.boundary),
        Err(ImportError::Schema("declared placement count differs"))
    ));
}

#[test]
fn explicit_scope_rejects_basename_collision_and_legacy_format() {
    let f = fixture();
    let mut specs = COMMON.to_vec();
    specs[1].source = "other/rtmutex_api";
    assert_ne!(specs[0].scope.token(), specs[1].scope.token());
    let mut changed = f.captured.clone();
    changed[0].scope.slice = "unreviewed";
    assert!(decode(&encode(&changed), &f.boundary).is_err());
    let mut changed = f.captured.clone();
    changed[1].scope.global_ordinal = changed[0].scope.global_ordinal;
    assert!(decode(&encode(&changed), &f.boundary).is_err());
    let mut bytes = encode(&f.captured);
    bytes[20] = b'1';
    assert!(decode(&bytes, &f.boundary).is_err());
    let mut specs = COMMON.to_vec();
    specs[1].scope = specs[0].scope;
    assert!(validate_units(&specs).is_err());
}

#[test]
fn composition_requires_the_exact_ordered_scoped_slices() {
    let f = fixture();
    let c = decode(&encode(&f.captured), &f.boundary).unwrap();
    let composed = compose(COMMON, &[&c[..1], &c[1..]]).unwrap();
    assert_eq!(composed.len(), 3);
    assert!(compose(COMMON, &[&c[1..], &c[..1]]).is_err());
    assert!(compose(COMMON, &[&c[..1], &c[..1], &c[2..]]).is_err());
    assert!(compose(COMMON, &[&c[..2]]).is_err());
    let mut changed = c.clone();
    changed[0].pins.clear();
    assert!(compose(COMMON, &[&changed]).is_err());
    let mut changed = c.clone();
    changed[1].object = changed[0].object.clone();
    assert!(compose(COMMON, &[&changed]).is_err());
}

#[test]
fn terminal_header_and_sources_are_independently_pinned() {
    let fixture = fixture();
    let header = fixture.linux.join("shared-autoconf.h");
    fs::write(&header, b"shared configuration").unwrap();
    let mut captured = decode(&encode(&fixture.captured), &fixture.boundary).unwrap();
    for unit in &mut captured {
        unit.dependencies.push(header.clone());
        unit.pins.insert(header.clone(), [1; 32]);
    }
    let expected = "01".repeat(32);
    require_header_pin(&captured, &header, &expected).unwrap();
    require_source_pins(&captured, &[&expected, &expected, &expected]).unwrap();
    captured[1].pins.insert(header.clone(), [2; 32]);
    assert!(require_header_pin(&captured, &header, &expected).is_err());
    captured[1].pins.insert(header.clone(), [1; 32]);
    captured[1].dependencies.retain(|path| path != &header);
    assert!(require_header_pin(&captured, &header, &expected).is_err());
    let source = captured[2].source.clone();
    captured[2].pins.insert(source, [2; 32]);
    assert!(require_source_pins(&captured, &[&expected, &expected, &expected]).is_err());
}

#[test]
fn imported_options_cannot_replace_the_caller_command() {
    let fixture = fixture();
    for replacement in [
        vec!["-Dfixture=0".into()],
        vec![],
        vec!["-Dfixture=1".into(), "--target=foreign".into()],
    ] {
        let mut changed = fixture.captured.clone();
        changed[0].options = replacement;
        assert!(matches!(
            decode(&encode(&changed), &fixture.boundary),
            Err(ImportError::Identity {
                index: 0,
                field: "compiler command profile"
            })
        ));
    }
}

#[test]
fn relative_options_keep_their_exact_producer_directory_and_order() {
    let mut fixture = fixture();
    for (profile, unit) in fixture
        .boundary
        .profiles
        .iter_mut()
        .zip(&mut fixture.captured)
    {
        profile.options = vec!["-isystem".into(), "include".into(), "-Dfixture=1".into()];
        unit.options = profile.options.clone();
    }
    assert!(decode(&encode(&fixture.captured), &fixture.boundary).is_ok());
    let mut changed = fixture.captured.clone();
    changed[0].options.swap(0, 1);
    assert!(matches!(
        decode(&encode(&changed), &fixture.boundary),
        Err(ImportError::Identity {
            field: "compiler command profile",
            ..
        })
    ));
    let mut changed = fixture.captured.clone();
    changed[0].directory = fixture._temporary.path().to_path_buf();
    assert!(matches!(
        decode(&encode(&changed), &fixture.boundary),
        Err(ImportError::Identity {
            field: "compiler command profile",
            ..
        })
    ));
}

#[test]
fn command_profiles_are_required_for_every_owned_occurrence() {
    let mut fixture = fixture();
    fixture.boundary.profiles.pop();
    assert!(matches!(
        decode(&encode(&fixture.captured), &fixture.boundary),
        Err(ImportError::Schema(
            "declared compiler profile count differs"
        ))
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn placement_keeps_root_aliases_but_refuses_below_root_source_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("original");
    let output = temporary.path().join("output");
    fs::create_dir_all(root.join("nested")).unwrap();
    fs::create_dir(&output).unwrap();
    let source = root.join("nested/source.c");
    fs::write(&source, "int owned_source;\n").unwrap();
    let alias = temporary.path().join("root-alias");
    std::os::unix::fs::symlink(&root, &alias).unwrap();
    assert!(Placement::new(&alias.join("nested/source.c"), &output, &[&alias]).is_ok());
    let alias_source = root.join("leaf.c");
    std::os::unix::fs::symlink(&source, &alias_source).unwrap();
    assert!(matches!(
        Placement::new(&alias_source, &output, &[&root]),
        Err(ImportError::Input(_))
    ));
    let nested = root.join("other");
    std::os::unix::fs::symlink(root.join("nested"), &nested).unwrap();
    assert!(matches!(
        Placement::new(&nested.join("source.c"), &output, &[&root]),
        Err(ImportError::Input(_))
    ));
}
