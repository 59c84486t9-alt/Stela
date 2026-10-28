//! Value parsers of the development commands' arguments.
use std::path::PathBuf;
pub use stela_cli::args::parse_address;

pub fn parse_cpu_target(value: &str) -> Result<stela_compiler::TargetCpu, String> {
    if value == "native" {
        Ok(stela_compiler::TargetCpu::detect())
    } else {
        value.parse()
    }
}

#[derive(Debug, Clone)]
pub struct MemoryQuery {
    pub address: u64,
    pub bytes: usize,
}

pub fn parse_memory_query(value: &str) -> Result<MemoryQuery, String> {
    let (address, bytes) = value.split_once(':').ok_or("expected ADDRESS:BYTES")?;
    let address = parse_address(address)?;
    let bytes = usize::try_from(parse_address(bytes)?).map_err(|error| error.to_string())?;
    if bytes as u64 > stela_runtime::memory::MAX_IMAGE_MEMORY_BYTES {
        return Err("memory snapshot exceeds image memory limit".into());
    }
    Ok(MemoryQuery { address, bytes })
}

#[derive(Debug, Clone)]
pub struct LibraryInput {
    pub path: PathBuf,
    pub base: u64,
}

pub fn parse_library(value: &str) -> Result<LibraryInput, String> {
    let (path, base) = value
        .rsplit_once('@')
        .ok_or("expected LIBRARY_PATH@ADDRESS")?;
    if path.is_empty() {
        return Err("library path is empty".into());
    }
    Ok(LibraryInput {
        path: path.into(),
        base: parse_address(base)?,
    })
}

pub fn parse_arm_kernel_page_shift(
    value: &str,
) -> Result<stela_runtime::commpage::KernelPageSize, String> {
    use stela_runtime::commpage::KernelPageSize;
    match value {
        "12" => Ok(KernelPageSize::FourKiB),
        "14" => Ok(KernelPageSize::SixteenKiB),
        _ => Err("ARM kernel page shift must be 12 or 14; arm64 user shift is 14".into()),
    }
}

pub fn parse_scalable_vector_length(
    value: &str,
) -> Result<stela_compiler::aarch64::scalable::VectorLength, String> {
    let bytes = value.parse::<usize>().map_err(|error| error.to_string())?;
    stela_compiler::aarch64::scalable::VectorLength::from_bytes(bytes)
        .ok_or_else(|| "SVL bytes must be one of 16, 32, 64, 128 or 256".into())
}

pub fn parse_scalable_mode(
    value: &str,
) -> Result<stela_compiler::aarch64::scalable::ScalableMode, String> {
    let bits = value.parse::<u64>().map_err(|error| error.to_string())?;
    stela_compiler::aarch64::scalable::ScalableMode::from_svcr(bits)
        .ok_or_else(|| "SVCR must be in 0..=3".into())
}
