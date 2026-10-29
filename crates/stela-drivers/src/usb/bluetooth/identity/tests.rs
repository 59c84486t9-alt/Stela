//! Descriptor byte layout and unchanged sentinel identity values.
use super::*;
#[test]
fn device_identity_reads_little_endian_fields_at_the_usb_offsets() {
    let mut descriptor = [0xa5; 18];
    descriptor[8..14].copy_from_slice(&[0x34, 0x12, 0x78, 0x56, 0xbc, 0x9a]);
    let expected = DescriptorIdentity {
        vendor: 0x1234,
        product: 0x5678,
        revision: 0x9abc,
    };
    assert_eq!(read(&descriptor), expected);
    descriptor[..8].fill(0x5a);
    descriptor[14..].fill(0x5a);
    assert_eq!(read(&descriptor), expected);
}
#[test]
fn descriptor_identity_preserves_zero_and_all_ones_values() {
    assert_eq!(
        read(&[0; 18]),
        DescriptorIdentity {
            vendor: 0,
            product: 0,
            revision: 0
        }
    );
    assert_eq!(
        read(&[0xff; 18]),
        DescriptorIdentity {
            vendor: 0xffff,
            product: 0xffff,
            revision: 0xffff
        }
    );
}
