//! Recovered request layouts, not an implementation of keybag security.
//!
//! 26A434 AppleSEPKeyStore kernel file offsets: create's AP wrapper at
//! 0x2d25350 calls `__ipc_create_keybag_v4` (0x2d5840c); copy at 0x2d253dc
//! calls `__ipc_copy_keybag_v1` (0x2d5880c). Load (0x2d25688), unload
//! (0x2d25430) and UUID (0x2d25710) use variant 0. Codec ranges are below.
//! Parsing never grants authorization or creates a handle. Even a completely
//! decoded request refuses until its bag type, parent, authentication, flags,
//! exported representation and durable key lifecycle have proven semantics.
use super::Fields;
use crate::Result;
use stela_contracts::refuse;

pub(super) const CREATE: u8 = 1;
pub(super) const COPY: u8 = 2;
pub(super) const LOAD: u8 = 3;
pub(super) const UNLOAD: u8 = 5;
pub(super) const UUID: u8 = 6;
pub(super) const UNIMPLEMENTED: &str =
    "SEP keystore keybag security and durable key lifecycle are not implemented";

pub(super) fn recognizes(command: u8) -> bool {
    matches!(command, CREATE | COPY | LOAD | UNLOAD | UUID)
}

/// Validate the complete body of the variants the current AP wrappers use.
/// Field names describe AP argument flow; they do not assign SEP semantics.
pub(super) fn validate(command: u8, variant: u32, fields: &mut Fields<'_>) -> Result<()> {
    let expected = match command {
        CREATE => 4,
        COPY => 1,
        LOAD | UNLOAD | UUID => 0,
        _ => {
            return Err(refuse!(
                "SEP keystore command has no recovered keybag codec"
            ));
        }
    };
    if variant != expected {
        return Err(refuse!(
            "SEP keystore keybag command variant is not modeled"
        ));
    }
    let _session = fields.lword()?;
    match command {
        // _code_ipc_create_keybag, variant 4 request: 0x2d3cf28..0x2d3d010.
        // The fourth blob uses a descriptor helper; its wire form is still
        // length + bytes + pad4. The reply is variant 4, a handle and a blob.
        CREATE => {
            let _bag_type = fields.word()?;
            let _parent_handle = fields.word()?;
            let _passcode = fields.blob()?;
            let _acm = fields.blob()?;
            let _extension = fields.blob()?;
            let _descriptor_blob = fields.blob()?;
            let _flags = fields.lword()?;
        }
        // _code_ipc_copy_keybag v1: 0x2d3d278..0x2d3d2d4; reply one blob.
        COPY => {
            let _handle = fields.word()?;
            let _query = fields.blob()?;
        }
        // _code_ipc_load_keybag: 0x2d3d458..0x2d3d48c; reply one handle.
        LOAD => {
            let _serialized_bag = fields.blob()?;
        }
        // _code_ipc_unload_keybag: 0x2d3d8f0..0x2d3d924; reply no fields.
        // _code_ipc_copy_keybag_uuid: 0x2d3daa4..0x2d3dad4; reply one blob.
        UNLOAD | UUID => {
            let _handle = fields.word()?;
        }
        _ => unreachable!(),
    }
    fields.end()
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn blob(bytes: &mut Vec<u8>, value: &[u8]) {
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
    }

    pub(in super::super) fn body(command: u8) -> (u32, Vec<u8>) {
        let mut bytes = 0x1234_5678_9abc_def0u64.to_le_bytes().to_vec();
        let variant = match command {
            CREATE => {
                bytes.extend_from_slice(&7u32.to_le_bytes());
                bytes.extend_from_slice(&(-1i32).to_le_bytes());
                for value in [&b"passcode"[..], &b"acm"[..], &b"x"[..], &b"fourth"[..]] {
                    blob(&mut bytes, value);
                }
                bytes.extend_from_slice(&0x100u64.to_le_bytes());
                4
            }
            COPY => {
                bytes.extend_from_slice(&(-11i32).to_le_bytes());
                blob(&mut bytes, b"query");
                1
            }
            LOAD => {
                blob(&mut bytes, b"opaque serialized bag");
                0
            }
            UNLOAD | UUID => {
                bytes.extend_from_slice(&(-11i32).to_le_bytes());
                0
            }
            _ => unreachable!(),
        };
        (variant, bytes)
    }

    #[test]
    fn keybag_variants_have_command_specific_lengths_and_no_accepted_prefixes_or_trailers() {
        for command in [CREATE, COPY, LOAD, UNLOAD, UUID] {
            let (variant, bytes) = body(command);
            let decode =
                |variant, bytes: &[u8]| validate(command, variant, &mut Fields { bytes, at: 0 });
            assert_eq!(decode(variant, &bytes), Ok(()));
            assert!(decode(variant + 1, &bytes).is_err());
            for end in 0..bytes.len() {
                assert!(
                    decode(variant, &bytes[..end]).is_err(),
                    "command {command} prefix {end}"
                );
            }
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(&[0; 4]);
            assert!(decode(variant, &trailing).is_err());
        }
        // Both length addition and source bounds are checked before slicing.
        for length in [u32::MAX, u32::MAX - 1, 0x7fff_ffff] {
            let mut bytes = vec![0; 8];
            bytes.extend_from_slice(&length.to_le_bytes());
            assert!(
                validate(
                    LOAD,
                    0,
                    &mut Fields {
                        bytes: &bytes,
                        at: 0
                    }
                )
                .is_err()
            );
        }
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_AKS_TEXT"]
    fn original_libaks_builders_bind_public_selectors_and_uuid_capacity() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_AKS_TEXT").unwrap()).unwrap();
        assert_eq!(bytes.len(), 579_648);
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(&bytes)),
            "3a688ee90028e1dc3a8e735a272821a6c90ea8479d598fa29846cad598bdbc52"
        );
        let movz = |at: usize, register: u32, value: u32| {
            let word = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            assert_eq!(word & 0xffe0_001f, 0x5280_0000 | register);
            assert_eq!((word >> 5) & 0xffff, value);
        };
        movz(0x62148, 1, 2); // create selector
        movz(0x6214c, 3, 7); // create's seven scalar inputs
        movz(0x623f0, 1, 6); // load selector
        movz(0x62594, 1, 3); // save selector
        movz(0x62680, 1, 0x17); // UUID selector
        movz(0x62654, 8, 16); // UUID output capacity
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_AKS_KERNEL"]
    fn original_keybag_builders_bind_commands_variants_and_field_helpers() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_AKS_KERNEL").unwrap()).unwrap();
        assert_eq!(bytes.len(), 125_026_304);
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(&bytes)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        for (at, command) in [
            (0x2d58500, CREATE),
            (0x2d5887c, COPY),
            (0x2d3a45c, LOAD),
            (0x2d3a5bc, UNLOAD),
            (0x2d58a40, UUID),
        ] {
            // MOVZ W1,#command in the AP-to-SEP wrapper, not the public
            // IOConnect selector (which has a different command number).
            assert_eq!(word(at) & 0xffe0_001f, 0x5280_0001);
            assert_eq!((word(at) >> 5) & 0xffff, u32::from(command));
        }
        assert_eq!(word(0x725a40), 4); // create wrapper's variant initializer
        assert_eq!(word(0x725870), 1); // copy wrapper's variant initializer
        let helpers = |start: usize, end: usize| {
            (start..end)
                .step_by(4)
                .filter_map(|at| {
                    let instruction = word(at);
                    if instruction >> 26 != 0b100101 {
                        return None;
                    }
                    // BL's signed immediate26, in units of four bytes.
                    let displacement = ((instruction << 6) as i32 >> 4) as isize;
                    Some(at.wrapping_add_signed(displacement))
                })
                .collect::<Vec<_>>()
        };
        let word_helper = 0x2d5dba4;
        let lword = 0x2d5dd70;
        let blob = 0x2d5dbfc;
        let descriptor = 0x2d5ddc8;
        assert_eq!(
            helpers(0x2d3cf28, 0x2d3d010),
            [
                lword,
                word_helper,
                word_helper,
                blob,
                blob,
                blob,
                descriptor,
                lword
            ]
        );
        assert_eq!(helpers(0x2d3d278, 0x2d3d2b0), [lword, word_helper]);
        assert_eq!(helpers(0x2d3d2c4, 0x2d3d2d4), [blob]);
        assert_eq!(helpers(0x2d3d458, 0x2d3d48c), [lword, blob]);
        assert_eq!(helpers(0x2d3d8f0, 0x2d3d924), [lword, word_helper]);
        assert_eq!(helpers(0x2d3daa4, 0x2d3dad4), [lword, word_helper]);
        // The refusal byte 0xff is sign-extended to -1 by sep_deliver_msg,
        // then the generic IOReturn failure entry is selected by this table.
        assert_eq!(word(0x725990 + 38 * 4), 0xe000_02bc);
    }
}
