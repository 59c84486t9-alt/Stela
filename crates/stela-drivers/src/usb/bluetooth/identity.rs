//! USB device-descriptor identity fields shared by vendor initializers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DescriptorIdentity {
    pub(super) vendor: u16,
    pub(super) product: u16,
    pub(super) revision: u16,
}
pub(super) fn read(descriptor: &[u8; 18]) -> DescriptorIdentity {
    DescriptorIdentity {
        vendor: u16::from_le_bytes([descriptor[8], descriptor[9]]),
        product: u16::from_le_bytes([descriptor[10], descriptor[11]]),
        revision: u16::from_le_bytes([descriptor[12], descriptor[13]]),
    }
}
#[cfg(test)]
mod tests;
