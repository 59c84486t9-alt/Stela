//! Command-line value failures with the rejected input or architectural limit.
use std::{
    error::Error,
    fmt,
    num::{ParseIntError, TryFromIntError},
};

#[derive(Debug, PartialEq, Eq)]
pub enum ArgumentError {
    CpuTarget {
        value: String,
        detail: String,
    },
    Address {
        value: String,
        detail: String,
    },
    Unsigned {
        value: String,
        source: ParseIntError,
    },
    HostSize {
        value: u64,
        source: TryFromIntError,
    },
    MemoryQuery {
        value: String,
    },
    MemoryLimit {
        bytes: u64,
        maximum: u64,
    },
    VectorLength {
        bytes: usize,
    },
    ScalableMode {
        bits: u64,
    },
}

impl fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CpuTarget { value, detail } => write!(f, "CPU target {value:?}: {detail}"),
            Self::Address { value, detail } => write!(f, "address {value:?}: {detail}"),
            Self::Unsigned { value, source } => write!(f, "unsigned integer {value:?}: {source}"),
            Self::HostSize { value, source } => write!(f, "host byte count {value}: {source}"),
            Self::MemoryQuery { value } => {
                write!(f, "memory query {value:?}: expected ADDRESS:BYTES")
            }
            Self::MemoryLimit { bytes, maximum } => write!(
                f,
                "memory snapshot {bytes} exceeds image memory limit {maximum}"
            ),
            Self::VectorLength { bytes } => {
                write!(f, "SVL bytes {bytes} must be one of 16, 32, 64, 128 or 256")
            }
            Self::ScalableMode { bits } => write!(f, "SVCR {bits} must be in 0..=3"),
        }
    }
}

impl Error for ArgumentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Unsigned { source, .. } => Some(source),
            Self::HostSize { source, .. } => Some(source),
            _ => None,
        }
    }
}
