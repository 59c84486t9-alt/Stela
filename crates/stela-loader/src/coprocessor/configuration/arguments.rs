//! Embedded argument policy for a source-checked initial native preparation.
//!
//! The selected policy owner establishes that its complete callback/write graph
//! keeps the embedded record. This helper checks that original record and its
//! consumer bounds; it does not infer override absence from empty bytes/hashes.
use super::{Action, Field, Provenance, source_record};
use crate::coprocessor::Staged;
use anyhow::{Result, ensure};

const ARGUMENTS: u32 = u32::from_be_bytes(*b"bArg");
const NATIVE_ARGUMENT_BYTES: usize = 1024;

pub struct Embedded {
    /// Explicit Preserve decision for the existing complete patchbay policy.
    pub field: Field,
    /// Native bounded byte length, excluding the first NUL if present. This is
    /// not a UTF-8 length, a reset-register argument or an entropy request.
    pub native_length: usize,
}

impl Staged {
    /// Firmware 0xdd68 copies the original count/data and 0x13be8 bounds length to
    /// 1024. 0xd99c rejects option widths >= that length. The selected initial
    /// native format 1 producers do not replace bArg; an alternate callback or
    /// override policy needs its own validation before choosing this action.
    pub fn embedded_arguments(&self, selected_provider: Provenance) -> Result<Embedded> {
        selected_provider.validate()?;
        let (_, bytes) = source_record(self, ARGUMENTS)?;
        ensure!(
            bytes.len() == NATIVE_ARGUMENT_BYTES,
            "embedded native argument record width is not qualified"
        );
        let native_length = bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(NATIVE_ARGUMENT_BYTES);
        Ok(Embedded {
            field: Field {
                tag: ARGUMENTS,
                action: Action::Preserve,
                provenance: selected_provider,
            },
            native_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coprocessor::{
        configuration::tests::{config_policy, provenance},
        tests::{fixture, prepare, w32, w64},
    };
    use alloc::vec::Vec;

    fn original() -> Vec<u8> {
        let mut b = fixture();
        w32(&mut b, 0x1220, NATIVE_ARGUMENT_BYTES as u32);
        w64(&mut b, 32 + 232 + 40, (36 + NATIVE_ARGUMENT_BYTES) as u64);
        b
    }
    #[test]
    fn empty_nontext_and_unterminated_embedded_bytes_keep_native_bounds_and_all_bytes() -> Result<()>
    {
        for (prefix, expected) in [(&[][..], 0), (&[0xff, 0xfe, 0x81][..], 3)] {
            let mut b = original();
            b[0x1224..0x1624].fill(0);
            b[0x1224..0x1224 + prefix.len()].copy_from_slice(prefix);
            let p = prepare(&b)?;
            let mut policy = config_policy(p.plan());
            let s = p.stage(0x800000, 0x3000)?;
            let embedded = s.embedded_arguments(provenance())?;
            assert_eq!(embedded.native_length, expected);
            *policy
                .fields
                .iter_mut()
                .find(|f| f.tag == ARGUMENTS)
                .unwrap() = embedded.field;
            let before = s.bytes().to_vec();
            let c = s.configure(policy)?;
            assert_eq!(c.bytes(), before);
        }
        let mut b = original();
        b[0x1224..0x1624].fill(0xa5);
        let s = prepare(&b)?.stage(0x800000, 0x3000)?;
        assert_eq!(s.embedded_arguments(provenance())?.native_length, 1024);
        Ok(())
    }
    #[test]
    fn missing_wrong_width_stale_record_and_unqualified_provider_refuse() -> Result<()> {
        assert!(
            prepare(&fixture())?
                .stage(0x800000, 0x3000)?
                .embedded_arguments(provenance())
                .is_err()
        );
        let mut b = original();
        w32(&mut b, 0x121c, 0x1234);
        assert!(
            prepare(&b)?
                .stage(0x800000, 0x3000)?
                .embedded_arguments(provenance())
                .is_err()
        );
        let mut s = prepare(&original())?.stage(0x800000, 0x3000)?;
        let mut claim = provenance();
        claim.coordinates.clear();
        assert!(s.embedded_arguments(claim).is_err());
        s.bytes[0x224] ^= 1;
        assert!(s.embedded_arguments(provenance()).is_err());
        Ok(())
    }
}
