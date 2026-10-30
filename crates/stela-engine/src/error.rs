//! Why the engine could not prepare, load or run guest code.
use crate::{
    blocks::PauthFault,
    memory::{SharedBindingError, domain::PublicationFault},
    pauth::AuthenticationError,
};
use alloc::collections::TryReserveError;
use core::fmt;
use stela_compiler::{CompileError, TargetCpu, TargetParseError, block::BlockAnalysisError};
use stela_contracts::Refusal;

#[derive(Debug)]
pub enum Error {
    /// A check on guest code, an artifact or engine state failed.
    Refused(Refusal),
    /// The compiler refused the guest code.
    Compile(CompileError),
    /// The host CPU lacks features the generated code requires.
    HostLacks(TargetCpu),
    /// Generated code names a CPU target this compiler does not know.
    Target(TargetParseError),
    /// A pointer-authentication instruction did not complete.
    PointerAuthentication(PauthFault),
    /// Guest memory could not be bound to its shared domain.
    Binding(SharedBindingError),
    /// A host write into published guest memory stopped part way.
    Publication(PublicationFault),
    /// The checked memory contract refused an entry or its finalization.
    ProcessMemory(crate::system::process_memory::ProcessMemoryError),
    #[cfg(feature = "std")]
    Finalization(alloc::boxed::Box<crate::execution::checked_memory::FinalizationFailure>),
    /// The host could not allocate engine storage.
    Allocation(TryReserveError),
    /// A manifest, receipt or ledger is not the JSON its type expects.
    Json(serde_json::Error),
    /// A host file, mapping or memory operation failed.
    #[cfg(feature = "std")]
    Io {
        operation: Refusal,
        error: std::io::Error,
    },
    /// A translation cache entry fails validation; removing it rebuilds it.
    #[cfg(feature = "std")]
    InvalidCacheEntry {
        directory: std::path::PathBuf,
        cause: alloc::boxed::Box<Error>,
    },
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::Compile(error) => write!(f, "{error}"),
            Self::HostLacks(target) => {
                write!(
                    f,
                    "host CPU lacks generated-code requirements {}",
                    target.id()
                )
            }
            Self::Target(error) => write!(f, "{error}"),
            Self::PointerAuthentication(fault) => write!(f, "{fault}"),
            Self::Binding(error) => write!(f, "{error}"),
            Self::Publication(fault) => write!(f, "{fault}"),
            Self::ProcessMemory(error) => write!(f, "{error}"),
            #[cfg(feature = "std")]
            Self::Finalization(failure) => write!(f, "{failure}"),
            Self::Allocation(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
            #[cfg(feature = "std")]
            Self::Io { operation, error } => write!(f, "cannot {operation}: {error}"),
            #[cfg(feature = "std")]
            Self::InvalidCacheEntry { directory, cause } => write!(
                f,
                "invalid cached translation {} (remove it to rebuild): {cause}",
                directory.display()
            ),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Refused(_)
            | Self::Compile(_)
            | Self::HostLacks(_)
            | Self::Target(_)
            | Self::PointerAuthentication(_) => None,
            Self::Binding(error) => Some(error),
            Self::Publication(fault) => Some(fault),
            Self::ProcessMemory(error) => Some(error),
            #[cfg(feature = "std")]
            Self::Finalization(failure) => Some(failure.as_ref()),
            Self::Allocation(error) => Some(error),
            Self::Json(error) => Some(error),
            #[cfg(feature = "std")]
            Self::Io { error, .. } => Some(error),
            #[cfg(feature = "std")]
            Self::InvalidCacheEntry { cause, .. } => Some(cause.as_ref()),
        }
    }
}

impl From<Refusal> for Error {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<CompileError> for Error {
    fn from(error: CompileError) -> Self {
        Self::Compile(error)
    }
}

impl From<BlockAnalysisError> for Error {
    fn from(error: BlockAnalysisError) -> Self {
        Self::Compile(error.into())
    }
}

impl From<TargetParseError> for Error {
    fn from(error: TargetParseError) -> Self {
        Self::Target(error)
    }
}

impl From<PauthFault> for Error {
    fn from(fault: PauthFault) -> Self {
        Self::PointerAuthentication(fault)
    }
}

impl From<AuthenticationError> for Error {
    fn from(error: AuthenticationError) -> Self {
        Self::PointerAuthentication(error.into())
    }
}

impl From<SharedBindingError> for Error {
    fn from(error: SharedBindingError) -> Self {
        Self::Binding(error)
    }
}

impl From<PublicationFault> for Error {
    fn from(fault: PublicationFault) -> Self {
        Self::Publication(fault)
    }
}

impl From<crate::system::process_memory::ProcessMemoryError> for Error {
    fn from(error: crate::system::process_memory::ProcessMemoryError) -> Self {
        Self::ProcessMemory(error)
    }
}

#[cfg(feature = "std")]
impl From<crate::execution::checked_memory::FinalizationFailure> for Error {
    fn from(failure: crate::execution::checked_memory::FinalizationFailure) -> Self {
        Self::Finalization(alloc::boxed::Box::new(failure))
    }
}

impl From<TryReserveError> for Error {
    fn from(error: TryReserveError) -> Self {
        Self::Allocation(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Name the operation a failed host I/O call was performing.
#[cfg(feature = "std")]
pub(crate) trait Io<T> {
    fn io(self, operation: impl Into<Refusal>) -> Result<T>;
}

#[cfg(feature = "std")]
impl<T> Io<T> for std::io::Result<T> {
    fn io(self, operation: impl Into<Refusal>) -> Result<T> {
        self.map_err(|error| Error::Io {
            operation: operation.into(),
            error,
        })
    }
}
