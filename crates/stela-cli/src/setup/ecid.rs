//! Each Stela machine's ECID: the 64-bit exclusive chip identifier a Mac's
//! fuses hold, which iBoot publishes as `/chosen/unique-chip-id` and every
//! personalization names. Stela draws one at random for each machine, once,
//! as OpenCore's `ApECID` setups do, never zero; the machine's LocalPolicy
//! and SEP state are bound to it, so setup keeps it in the setup record and
//! in machine-state backups, reuses it for every bundle it prepares again,
//! and uses another only when asked (`--new-ecid`).
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io::Read;

/// One machine's ECID; the record keeps it as `0x` and 16 digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Ecid(pub(super) u64);

impl Ecid {
    /// The 16 hexadecimal digits that name its bundle directories.
    pub(super) fn digits(self) -> String {
        format!("{:016X}", self.0)
    }

    /// An ECID given as hexadecimal, with or without `0x`.
    pub(super) fn parse(value: &str) -> Result<Self> {
        let hex = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);
        ensure!(
            !hex.is_empty() && hex.len() <= 16 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{value:?} is not a 64-bit hexadecimal ECID"
        );
        let ecid = u64::from_str_radix(hex, 16)?;
        ensure!(ecid != 0, "an ECID is never zero");
        Ok(Self(ecid))
    }

    /// A fresh random, nonzero ECID from the operating system's generator.
    pub(super) fn generate() -> Result<Self> {
        let mut random = std::fs::File::open("/dev/urandom").context("cannot open /dev/urandom")?;
        loop {
            let mut bytes = [0u8; 8];
            random.read_exact(&mut bytes)?;
            let ecid = u64::from_le_bytes(bytes);
            if ecid != 0 {
                return Ok(Self(ecid));
            }
        }
    }
}

/// As `stela boot prepare --ecid` and the record take it.
impl std::fmt::Display for Ecid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

impl Serialize for Ecid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Ecid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecids_are_hexadecimal_nonzero_and_round_trip() {
        let ecid = Ecid::generate().unwrap();
        assert_ne!(ecid.0, 0);
        assert_eq!(Ecid::parse(&ecid.to_string()).unwrap(), ecid);
        assert_eq!(Ecid::parse(&ecid.digits()).unwrap(), ecid);
        assert_eq!(Ecid(0x1a).to_string(), "0x000000000000001a");
        assert_eq!(Ecid(0x1a).digits(), "000000000000001A");
        let json = serde_json::to_string(&Ecid(0x1a)).unwrap();
        assert_eq!(json, r#""0x000000000000001a""#);
        assert_eq!(serde_json::from_str::<Ecid>(&json).unwrap(), Ecid(0x1a));
        assert!(serde_json::from_str::<Ecid>(r#""0x0""#).is_err());
        for bad in ["", "0x", "0", "0x0", "g1", "0x1_0", "11112222333344445"] {
            assert!(Ecid::parse(bad).is_err(), "{bad:?}");
        }
    }
}
