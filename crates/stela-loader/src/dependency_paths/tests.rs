use super::*;

fn context(rpaths: &[RPath]) -> PathContext<'_> {
    PathContext {
        executable: "/Applications/Demo.app/Contents/MacOS/Demo",
        loader: "/Applications/Demo.app/Contents/Frameworks/A.framework/Versions/A/A",
        rpaths,
    }
}
fn rpath(owner: &str, value: &str) -> RPath {
    RPath {
        owner: owner.into(),
        value: value.into(),
    }
}

#[test]
fn direct_tokens_anchor_to_requester_or_global_executable() {
    let ctx = context(&[]);
    assert_eq!(
        candidates("@loader_path/Helpers/libB.dylib", &ctx).unwrap(),
        ["/Applications/Demo.app/Contents/Frameworks/A.framework/Versions/A/Helpers/libB.dylib"]
    );
    assert_eq!(
        candidates("@executable_path/../Frameworks/libB.dylib", &ctx).unwrap(),
        ["/Applications/Demo.app/Contents/Frameworks/libB.dylib"]
    );
    assert_eq!(
        candidates("@loader_path", &ctx).unwrap(),
        ["/Applications/Demo.app/Contents/Frameworks/A.framework/Versions/A"]
    );
    assert_eq!(
        candidates("@executable_path", &ctx).unwrap(),
        ["/Applications/Demo.app/Contents/MacOS"]
    );
}

#[test]
fn nearest_ancestor_order_and_defining_owner_are_preserved() {
    let rpaths = [
        rpath("/Bundle/Libraries/Leaf.dylib", "@loader_path/leaf-first"),
        rpath(
            "/Bundle/Libraries/Leaf.dylib",
            "@executable_path/leaf-second",
        ),
        rpath("/Bundle/Plugins/Parent.dylib", "@loader_path/parent-first"),
        rpath("/Bundle/Plugins/Parent.dylib", "/shared/parent-second"),
        rpath(
            "/Applications/Demo.app/Contents/MacOS/Demo",
            "@loader_path/main-last",
        ),
    ];
    assert_eq!(
        candidates("@rpath/libTarget.dylib", &context(&rpaths)).unwrap(),
        [
            "/Bundle/Libraries/leaf-first/libTarget.dylib",
            "/Applications/Demo.app/Contents/MacOS/leaf-second/libTarget.dylib",
            "/Bundle/Plugins/parent-first/libTarget.dylib",
            "/shared/parent-second/libTarget.dylib",
            "/Applications/Demo.app/Contents/MacOS/main-last/libTarget.dylib",
        ]
    );
}

#[test]
fn lexical_normalization_deduplicates_without_reordering() {
    let rpaths = [
        rpath("/a/loader", "/z//./lib"),
        rpath("/a/loader", "/a/lib"),
        rpath("/a/loader", "/z/tmp/../lib/"),
    ];
    assert_eq!(
        candidates("@rpath//Sub/../libA.dylib", &context(&rpaths)).unwrap(),
        ["/z/lib/libA.dylib", "/a/lib/libA.dylib"]
    );
    assert_eq!(
        candidates("//System/Library/./Frameworks/Unused/../A", &context(&[])).unwrap(),
        ["/System/Library/Frameworks/A"]
    );
    assert_eq!(
        candidates("/usr/lib/../lib/libé.dylib", &context(&[])).unwrap(),
        ["/usr/lib/libé.dylib"]
    );
}

#[test]
fn root_escape_is_refused_for_inputs_and_every_expansion() {
    for name in [
        "/../libA",
        "/a/../../libA",
        "@executable_path/../../../../../../libA",
        "@loader_path/../../../../../../../../../../libA",
    ] {
        assert!(
            candidates(name, &context(&[]))
                .unwrap_err()
                .to_string()
                .contains("escapes virtual root")
        );
    }
    let rpaths = [rpath("/a/owner", "@loader_path/../../lib")];
    assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
    let rpaths = [rpath("/a/owner", "/safe")];
    assert!(candidates("@rpath/../../outside", &context(&rpaths)).is_err());
    // A suffix may leave its search directory while remaining in guest root.
    assert_eq!(
        candidates("@rpath/../sibling/libA", &context(&rpaths)).unwrap(),
        ["/sibling/libA"]
    );
}

#[test]
fn unsupported_tokens_relative_paths_and_recursive_rpaths_fail() {
    for name in [
        "",
        "libA.dylib",
        "./libA",
        "../libA",
        "@rpath",
        "@rpath/",
        "@unknown/libA",
        "@loader_pathology/libA",
        "@executable_pathology/libA",
        "@rpathname/libA",
    ] {
        assert!(
            candidates(name, &context(&[])).is_err(),
            "accepted {name:?}"
        );
    }
    for value in ["@rpath/nested", "@rpath", "@unknown/path", "relative/path"] {
        let rpaths = [rpath("/a/loader", value)];
        assert!(
            candidates("@rpath/libA", &context(&rpaths)).is_err(),
            "accepted LC_RPATH {value:?}"
        );
    }
    assert!(candidates("@rpath/libA", &context(&[])).unwrap().is_empty());
}

#[test]
fn null_and_excessive_paths_are_rejected_without_truncation() {
    assert!(candidates("/lib\0A", &context(&[])).is_err());
    let invalid_context = PathContext {
        executable: "/a\0main",
        loader: "/a/loader",
        rpaths: &[],
    };
    assert!(candidates("/libA", &invalid_context).is_err());
    let rpaths = [rpath("/a\0owner", "/lib")];
    assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
    let rpaths = [rpath("/a/owner", "/lib\0")];
    assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
    let long = format!("/{}", "a".repeat(MAX_GUEST_PATH_BYTES));
    assert!(candidates(&long, &context(&[])).is_err());
    let rpaths = [rpath(
        "/a/owner",
        &format!("/{}", "a".repeat(MAX_GUEST_PATH_BYTES - 2)),
    )];
    assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
    let rpaths = vec![rpath("/a/owner", "/lib"); MAX_RPATHS + 1];
    assert!(candidates("@rpath/libA", &context(&rpaths)).is_err());
}

#[test]
fn root_level_owners_and_dot_components_stay_posix_paths() {
    let rpaths = [rpath("/library", "@loader_path/./lib")];
    let ctx = PathContext {
        executable: "/main",
        loader: "/requester",
        rpaths: &rpaths,
    };
    assert_eq!(candidates("@loader_path/./libA", &ctx).unwrap(), ["/libA"]);
    assert_eq!(
        candidates("@executable_path/libA", &ctx).unwrap(),
        ["/libA"]
    );
    assert_eq!(candidates("@rpath/libA", &ctx).unwrap(), ["/lib/libA"]);
    assert_eq!(
        candidates("/literal/@unknown/libA", &ctx).unwrap(),
        ["/literal/@unknown/libA"]
    );
    assert_eq!(candidates("/a/..", &ctx).unwrap(), ["/"]);
}
