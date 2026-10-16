//! Host allocation error retains its original API. Freestanding resource
//! production is unavailable until the actual loader/frame owner is joined.
#[cfg(feature = "std")]
pub(crate) type Error = std::io::Error;
#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub(crate) enum Error {
    Unavailable,
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
            Self::Unavailable => {
                f.write_str("freestanding RAM allocation/protection owner is not mounted")
            }
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
