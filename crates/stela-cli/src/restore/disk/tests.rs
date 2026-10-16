use super::*;
use std::os::unix::fs::symlink;

#[test]
fn guest_paths_follow_links_only_inside_the_volume() -> Result<()> {
    let volume = tempfile::tempdir()?;
    let root = volume.path();
    fs::create_dir_all(root.join("usr/lib"))?;
    fs::write(root.join("usr/lib/libz.dylib"), b"z")?;
    symlink("libz.dylib", root.join("usr/lib/libz.1.dylib"))?;
    symlink("/usr/lib", root.join("lib"))?;
    symlink("../../../../etc/passwd", root.join("usr/lib/escape"))?;
    assert_eq!(
        resolve(root, "/usr/lib/libz.1.dylib")?,
        root.join("usr/lib/libz.dylib")
    );
    assert_eq!(
        resolve(root, "/lib/libz.dylib")?,
        root.join("usr/lib/libz.dylib")
    );
    assert!(resolve(root, "/usr/lib/escape").is_err());
    assert!(resolve(root, "usr/lib/libz.dylib").is_err());
    assert!(resolve(root, "/usr/lib").is_err());
    Ok(())
}
