//! Little-endian fields in byte buffers. `le16`, `le32` and `le64` index like
//! a slice and panic past the end, for buffers whose length is already
//! checked; the `get_` forms return `None` instead.

pub fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(field(bytes, at))
}
pub fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(field(bytes, at))
}
pub fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(field(bytes, at))
}
pub fn get_le16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(get_field(bytes, at)?))
}
pub fn get_le32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(get_field(bytes, at)?))
}

fn field<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().unwrap()
}
fn get_field<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_read_little_endian_and_checked_forms_refuse_overruns() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(le16(&bytes, 1), 0x0302);
        assert_eq!(le32(&bytes, 0), 0x0403_0201);
        assert_eq!(le64(&bytes, 1), 0x0908_0706_0504_0302);
        assert_eq!(get_le16(&bytes, 7), Some(0x0908));
        assert_eq!(get_le16(&bytes, 8), None);
        assert_eq!(get_le32(&bytes, 6), None);
        assert_eq!(get_le32(&bytes, usize::MAX), None);
    }
}
