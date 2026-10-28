//! Value parsers shared by command arguments.

pub fn parse_address(value: &str) -> Result<u64, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|e| e.to_string())
}
