//! Value parsers of the development commands' arguments.

mod error;
pub use error::ArgumentError;
pub use stela_cli::args::parse_address;

pub fn parse_cpu_target(value: &str) -> Result<stela_compiler::TargetCpu, ArgumentError> {
    if value == "native" {
        Ok(stela_compiler::TargetCpu::detect())
    } else {
        value
            .parse::<stela_compiler::TargetCpu>()
            .map_err(|detail| ArgumentError::CpuTarget {
                value: value.to_owned(),
                detail: detail.to_string(),
            })
    }
}

#[derive(Debug, Clone)]
pub struct MemoryQuery {
    pub address: u64,
    pub bytes: usize,
}

pub fn parse_memory_query(value: &str) -> Result<MemoryQuery, ArgumentError> {
    let (address, bytes) = value
        .split_once(':')
        .ok_or_else(|| ArgumentError::MemoryQuery {
            value: value.to_owned(),
        })?;
    let address = address_value(address)?;
    let size = address_value(bytes)?;
    let bytes = usize::try_from(size).map_err(|source| ArgumentError::HostSize {
        value: size,
        source,
    })?;
    let maximum = stela_engine::memory::MAX_IMAGE_MEMORY_BYTES;
    if size > maximum {
        return Err(ArgumentError::MemoryLimit {
            bytes: size,
            maximum,
        });
    }
    Ok(MemoryQuery { address, bytes })
}

pub fn parse_scalable_vector_length(
    value: &str,
) -> Result<stela_compiler::aarch64::scalable::VectorLength, ArgumentError> {
    let bytes = value
        .parse::<usize>()
        .map_err(|source| ArgumentError::Unsigned {
            value: value.to_owned(),
            source,
        })?;
    stela_compiler::aarch64::scalable::VectorLength::from_bytes(bytes)
        .ok_or(ArgumentError::VectorLength { bytes })
}

pub fn parse_scalable_mode(
    value: &str,
) -> Result<stela_compiler::aarch64::scalable::ScalableMode, ArgumentError> {
    let bits = value
        .parse::<u64>()
        .map_err(|source| ArgumentError::Unsigned {
            value: value.to_owned(),
            source,
        })?;
    stela_compiler::aarch64::scalable::ScalableMode::from_svcr(bits)
        .ok_or(ArgumentError::ScalableMode { bits })
}

fn address_value(value: &str) -> Result<u64, ArgumentError> {
    parse_address(value).map_err(|detail| ArgumentError::Address {
        value: value.to_owned(),
        detail: detail.to_string(),
    })
}
