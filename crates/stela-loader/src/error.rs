//! Why an image, manifest or boot input could not be read.
use alloc::boxed::Box;
use core::fmt;
use stela_contracts::Refusal;
use stela_formats::{
    apfs::ApfsError, builds::Unsupported, img4::Img4Error, lzfse::LzfseError, preboot::PrebootError,
};
use stela_soc_data::board::assigned::Requirement;

#[derive(Debug)]
pub enum Error {
    /// The input breaks a format rule or a boot requirement.
    Refused(Refusal),
    /// The error of a nested input, with what was being read.
    Within { context: Refusal, cause: Box<Error> },
    /// The target names a build Stela does not support.
    UnsupportedBuild(Unsupported),
    /// An Image4 container is malformed.
    Image4(Img4Error),
    /// An LZFSE payload does not decode.
    Lzfse(LzfseError),
    /// An APFS container could not be read.
    Apfs(ApfsError),
    /// A Preboot volume holds no usable boot directory or object.
    Preboot(PrebootError),
    /// The assigned CPU topology no longer satisfies its plan.
    TopologyChanged(Requirement),
    /// A manifest or receipt is not the JSON its type expects.
    Json(serde_json::Error),
    /// The pointer signer refused a fixup.
    Signing(Box<dyn core::error::Error + Send + Sync>),
    /// A Mach-O image could not be parsed.
    Object(object::read::Error),
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::Within { context, cause } => write!(f, "{context}: {cause}"),
            Self::UnsupportedBuild(error) => write!(f, "{error}"),
            Self::Image4(error) => write!(f, "{error}"),
            Self::Lzfse(error) => write!(f, "LZFSE payload does not decode: {error}"),
            Self::Apfs(error) => write!(f, "{error}"),
            Self::Preboot(error) => write!(f, "{error}"),
            Self::TopologyChanged(requirement) => {
                write!(f, "topology plan changed: {requirement:?}")
            }
            Self::Json(error) => write!(f, "{error}"),
            Self::Signing(error) => write!(f, "cannot sign a fixup pointer: {error}"),
            Self::Object(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Refused(_) | Self::TopologyChanged(_) => None,
            Self::UnsupportedBuild(error) => Some(error),
            Self::Image4(error) => Some(error),
            Self::Lzfse(error) => Some(error),
            Self::Apfs(error) => Some(error),
            Self::Preboot(error) => Some(error),
            Self::Within { cause, .. } => Some(cause.as_ref()),
            Self::Json(error) => Some(error),
            Self::Signing(error) => Some(error.as_ref()),
            Self::Object(error) => Some(error),
        }
    }
}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<Unsupported> for Error {
    fn from(error: Unsupported) -> Self {
        Self::UnsupportedBuild(error)
    }
}

impl From<Img4Error> for Error {
    fn from(error: Img4Error) -> Self {
        Self::Image4(error)
    }
}

impl From<LzfseError> for Error {
    fn from(error: LzfseError) -> Self {
        Self::Lzfse(error)
    }
}

impl From<ApfsError> for Error {
    fn from(error: ApfsError) -> Self {
        Self::Apfs(error)
    }
}

impl From<PrebootError> for Error {
    fn from(error: PrebootError) -> Self {
        Self::Preboot(error)
    }
}

impl From<Requirement> for Error {
    fn from(requirement: Requirement) -> Self {
        Self::TopologyChanged(requirement)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl Error {
    /// Keep the error of a pointer signer the loader does not know.
    pub(crate) fn signing(error: impl core::error::Error + Send + Sync + 'static) -> Self {
        Self::Signing(Box::new(error))
    }
}

impl From<object::read::Error> for Error {
    fn from(error: object::read::Error) -> Self {
        Self::Object(error)
    }
}

/// Say what was being read when a nested input failed; `context` runs
/// only on failure.
pub trait Within<T> {
    fn within(self, context: impl FnOnce() -> Refusal) -> Result<T>;
}

impl<T, E: Into<Error>> Within<T> for core::result::Result<T, E> {
    fn within(self, context: impl FnOnce() -> Refusal) -> Result<T> {
        self.map_err(|cause| Error::Within {
            context: context(),
            cause: Box::new(cause.into()),
        })
    }
}
