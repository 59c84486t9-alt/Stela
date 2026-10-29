//! A decoded kernelcache's XNU `version[]` string, which `kern.version` and
//! `host_kernel_version` report: "Darwin Kernel Version ...", ending at its
//! NUL. The kernel keeps copies of it, and they must agree.
use crate::Result;
use alloc::{collections::BTreeSet, string::String};
use stela_contracts::refuse;

/// The prefix of XNU's `version[]`.
pub const PREFIX: &[u8] = b"Darwin Kernel Version ";

/// The one `version[]` string in `kernelcache`, or why there is none.
pub fn read(kernelcache: &[u8]) -> Result<String> {
    let mut found = BTreeSet::new();
    let mut rest = kernelcache;
    while let Some(start) = rest
        .windows(PREFIX.len())
        .position(|window| window == PREFIX)
    {
        let tail = &rest[start..];
        let end = tail
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(refuse!("the kernel version string is not terminated"))?;
        let version = core::str::from_utf8(&tail[..end])
            .map_err(|_| refuse!("the kernel version string is not UTF-8"))?;
        found.insert(String::from(version));
        rest = &tail[end..];
    }
    let mut versions = found.into_iter();
    match (versions.next(), versions.next()) {
        (Some(version), None) => Ok(version),
        (None, _) => Err(refuse!("the kernelcache has no kernel version string").into()),
        (Some(_), Some(_)) => {
            Err(refuse!("the kernelcache has differing kernel version strings").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A synthetic kernelcache: padding, then `copies` NUL-terminated copies
    /// of `version`.
    fn kernelcache(version: &[u8], copies: usize) -> Vec<u8> {
        let mut data = alloc::vec![0xa5u8; 16];
        for _ in 0..copies {
            data.extend_from_slice(version);
            data.extend_from_slice(&[0, 0x5a]);
        }
        data
    }

    #[test]
    fn the_version_is_its_one_terminated_string() {
        let version = b"Darwin Kernel Version 1.2.3: synthetic; root:test~1/RELEASE_TEST";
        assert_eq!(
            read(&kernelcache(version, 2)).unwrap().as_bytes(),
            version.as_slice()
        );
        let mut differing = kernelcache(version, 1);
        differing.extend_from_slice(b"Darwin Kernel Version 9\0");
        assert!(read(&differing).is_err());
        assert!(read(&kernelcache(b"no version", 1)).is_err());
        assert!(read(b"Darwin Kernel Version unterminated").is_err());
    }
}
