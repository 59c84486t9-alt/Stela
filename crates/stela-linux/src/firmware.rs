//! Exact-authority synchronous firmware lookup. Every request uses its own
//! immutable catalogue window; no cross-request name-only cache exists.
use super::catalogue::Authority;
use core::ffi::{CStr, c_char, c_int, c_void};
use stela_driver_core::firmware::{
    Catalog, Error as CatalogError, ErrorKind, Provider, Requirement, Target,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidEncoding,
    Catalog(CatalogError),
}
impl Error {
    pub fn errno(&self) -> i32 {
        match self {
            Self::InvalidEncoding => -22,
            Self::Catalog(error) => match error.kind {
                ErrorKind::Missing | ErrorKind::Truncated { actual: 0, .. } => -2,
                ErrorKind::WrongTarget => -13,
                ErrorKind::InvalidName
                | ErrorKind::InvalidTarget(_)
                | ErrorKind::InvalidRequirement => -22,
                _ => -74,
            },
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEncoding => f.write_str("firmware name is not UTF-8"),
            Self::Catalog(error) => core::fmt::Display::fmt(error, f),
        }
    }
}
impl core::error::Error for Error {}

fn from_catalog<'a>(
    catalog: &'a Catalog,
    target: Target<'_>,
    name: &CStr,
) -> Result<&'a [u8], Error> {
    let name = name.to_str().map_err(|_| Error::InvalidEncoding)?;
    catalog
        .load(Requirement {
            name,
            target,
            minimum_bytes: 1,
        })
        .map(|image| image.bytes())
        .map_err(Error::Catalog)
}
/// Borrow immutable bytes from this actual enrolled authority. The caller's
/// authority reference retains its original source/configuration, exact code
/// queue and catalogue. This is not a native upload or driver-context grant.
pub fn lookup<'a>(authority: &'a Authority, name: &CStr) -> Result<&'a [u8], Error> {
    from_catalog(authority.catalog(), authority.target(), name)
}

/// C's shared request adapter holds the real original device lease throughout
/// this borrow and copies bytes before releasing that lease.
///
/// # Safety
/// `authority` is the live Rust-created Authority of that acquired C lease.
/// `name` is the original valid NUL-terminated sync API input, and output slots
/// are valid writable pointers. Caller is on the canonical checked Linux task;
/// it keeps the actual source/code/runtime roots. No driver context is owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stela_linux_firmware_image(
    authority: *const c_void,
    name: *const c_char,
    data: *mut *const u8,
    size: *mut usize,
) -> c_int {
    if data.is_null() || size.is_null() {
        return -22;
    }
    // SAFETY: valid independent writable output slots under the caller contract.
    unsafe {
        data.write(core::ptr::null());
        size.write(0);
    }
    if authority.is_null() || name.is_null() {
        return -22;
    }
    // SAFETY: real acquired device ref keeps this actual authority alive; name
    // is the API input valid for this synchronous call, never cached/retained.
    let (authority, name) = unsafe { (&*authority.cast::<Authority>(), CStr::from_ptr(name)) };
    match lookup(authority, name) {
        Ok(bytes) => {
            // SAFETY: writable slots; C's lease keeps these immutable bytes
            // readable through its completed independent snapshot copy.
            unsafe {
                data.write(bytes.as_ptr());
                size.write(bytes.len());
            }
            0
        }
        Err(error) => error.errno(),
    }
}

#[cfg(test)]
mod tests;
