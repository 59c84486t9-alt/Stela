//! Fixed-width fields in byte buffers, and the page sizes Stela's crates
//! share.
//!
//! `le16` to `be64` and [`array`] index like a slice and panic past the end,
//! for buffers whose length is already checked; the `get_` forms return
//! `None` instead.

/// The x86 host's base page.
pub const HOST_PAGE_BYTES: u64 = 0x1000;
/// The 16 KiB page of Apple's ARM guests.
pub const GUEST_PAGE_BYTES: u64 = 0x4000;

/// The `N` bytes at `at`.
pub fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().unwrap()
}

/// The `N` bytes at `at`, or `None` past the end.
pub fn get_array<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

macro_rules! fields {
    ($($name:ident, $get:ident, $type:ty, $from:ident;)*) => {$(
        pub fn $name(bytes: &[u8], at: usize) -> $type {
            <$type>::$from(array(bytes, at))
        }

        pub fn $get(bytes: &[u8], at: usize) -> Option<$type> {
            Some(<$type>::$from(get_array(bytes, at)?))
        }
    )*};
}

fields! {
    le16, get_le16, u16, from_le_bytes;
    le32, get_le32, u32, from_le_bytes;
    le64, get_le64, u64, from_le_bytes;
    be16, get_be16, u16, from_be_bytes;
    be32, get_be32, u32, from_be_bytes;
    be64, get_be64, u64, from_be_bytes;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_read_in_their_byte_order_and_checked_forms_refuse_overruns() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(le16(&bytes, 1), 0x0302);
        assert_eq!(le32(&bytes, 0), 0x0403_0201);
        assert_eq!(le64(&bytes, 1), 0x0908_0706_0504_0302);
        assert_eq!(be16(&bytes, 1), 0x0203);
        assert_eq!(be32(&bytes, 0), 0x0102_0304);
        assert_eq!(be64(&bytes, 1), 0x0203_0405_0607_0809);
        assert_eq!(array::<3>(&bytes, 6), [7, 8, 9]);
        assert_eq!(get_le16(&bytes, 7), Some(0x0908));
        assert_eq!(get_be16(&bytes, 7), Some(0x0809));
        assert_eq!(get_le16(&bytes, 8), None);
        assert_eq!(get_le32(&bytes, 6), None);
        assert_eq!(get_be64(&bytes, 2), None);
        assert_eq!(get_le64(&bytes, 1), Some(0x0908_0706_0504_0302));
        assert_eq!(get_le32(&bytes, usize::MAX), None);
        assert_eq!(get_array::<2>(&bytes, 8), None);
    }
}
