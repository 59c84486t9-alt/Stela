use super::*;
use std::process::Command;

#[test]
fn the_job_sets_the_key_once_and_removes_itself() {
    let job = plist::Value::from_reader_xml(job().unwrap().as_slice()).unwrap();
    let job = job.as_dictionary().unwrap();
    assert_eq!(job["Label"].as_string(), Some(LABEL));
    assert_eq!(job["RunAtLoad"].as_boolean(), Some(true));
    assert_eq!(job["StandardOutPath"].as_string(), Some(LOG));
    let arguments = job["ProgramArguments"].as_array().unwrap();
    assert_eq!(arguments[0].as_string(), Some("/bin/sh"));
    let script = arguments[2].as_string().unwrap();
    assert_eq!(script, super::script());
    for needed in [
        "domain=/Library/Preferences/.GlobalPreferences\n",
        "key=disable-buffer-compression\n",
        // A value already there is kept, whatever it is.
        "if /usr/bin/defaults read \"$domain\" \"$key\" >/dev/null 2>&1; then",
        "elif /usr/bin/defaults write \"$domain\" \"$key\" -bool YES; then",
        "/bin/rm -f /Library/LaunchDaemons/org.stela.StelaGPU.compression.plist\n",
    ] {
        assert!(script.contains(needed), "{needed}");
    }
    let status = Command::new("sh")
        .args(["-n", "-c", script])
        .status()
        .unwrap();
    assert!(status.success(), "the script is not POSIX shell");
}

#[test]
fn the_header_names_what_the_kext_reads_and_stages() {
    let header = header().unwrap();
    assert!(header.contains(
        "#define STELA_COMPRESSION_PREFERENCES_PATH \
         \"/System/Volumes/Data/Library/Preferences/.GlobalPreferences.plist\"\n"
    ));
    assert!(header.contains(
        "#define STELA_COMPRESSION_JOB_PATH \
         \"/System/Volumes/Data/Library/LaunchDaemons/org.stela.StelaGPU.compression.plist\"\n"
    ));
    assert!(header.contains("static const unsigned char stela_compression_job[] = {"));
    // The kext looks for the key the job writes.
    let policy = include_str!("../../../../guest/stela-gpu/kext/compression_policy.h");
    assert!(policy.contains(&format!("#define STELA_COMPRESSION_KEY \"{KEY}\"\n")));
}
