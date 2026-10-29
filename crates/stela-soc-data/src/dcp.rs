//! Immutable external display-pipe interface identity.
use crate::Result;
use stela_contracts::refuse;
pub const AVIPC_SERVICE_NAME: &str = "dcpav-controller-epic";
/// Identity of the one backed external output. The unnumbered DCPEXT and
/// numbered DCPEXT0/1 use the same original firmware protocol, but publish
/// distinct AFKEPV2 interface names. This does not model an internal panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExternalIdentity {
    #[default]
    Unnumbered,
    /// The external pipe ordinal, not the AFKEPV2 interface ID or unit.
    Numbered(u8),
}

impl ExternalIdentity {
    pub fn interface_name(self) -> Result<alloc::string::String> {
        // t600xdcp_restore 0xf9434..0xf944c formats %s%c:%s:%u. Its external
        // instance byte 0 yields E; 1..10 yield 0..9. Each model has one
        // controller (unit 0) and an independently allocated interface ID.
        let suffix = match self {
            Self::Unnumbered => 'E',
            Self::Numbered(index @ 0..=9) => char::from(b'0' + index),
            Self::Numbered(_) => {
                return Err(refuse!(
                    "DCP external pipe ordinal exceeds the native single-character identity"
                ));
            }
        };
        Ok(alloc::format!("dispext{suffix}:{}:0", AVIPC_SERVICE_NAME))
    }
}
