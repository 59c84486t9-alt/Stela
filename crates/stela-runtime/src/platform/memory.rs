//! Host memory allocation; the freestanding build uses the loader's frames.
#[cfg(feature = "std")]
pub(crate) type Error = std::io::Error;
#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub(crate) enum Error {
    Boot(crate::platform::boot::MountError),
    InvalidLayout(alloc::string::String),
}
#[cfg(not(feature = "std"))]
impl Error {
    pub(crate) fn other(detail: impl Into<alloc::string::String>) -> Self {
        Self::InvalidLayout(detail.into())
    }
}
#[cfg(not(feature = "std"))]
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLayout(detail) => f.write_str(detail),
            Self::Boot(error) => error.fmt(f),
        }
    }
}
#[cfg(not(feature = "std"))]
impl core::error::Error for Error {}

#[cfg(not(feature = "std"))]
impl From<crate::platform::boot::MountError> for Error {
    fn from(error: crate::platform::boot::MountError) -> Self {
        Self::Boot(error)
    }
}
