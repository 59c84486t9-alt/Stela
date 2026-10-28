//! Source-qualified monotonic PMU key, separate from mutable stored SMC keys.
use super::code;
use crate::platform::apple::pmu::RtcClock;

pub(super) const KEY: u32 = code(b"CLKM");

/// Declared key interface recovered from the original raw keyR consumer and
/// independently observed on the T6000/26B118 reference. This does not claim
/// that reference firmware or its persistent epoch is a 26A434 handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcKeyProfile {
    /// Six little-endian 32768 Hz ticks, hex_, attributes0x94. The original
    /// caller zero-initializes its eight-byte destination before raw keyR.
    Hex48Little,
}

impl RtcKeyProfile {
    /// Match the complete original helper descriptor to its resolved SMC PMU
    /// provider. A phandle alone cannot assign a key or an oscillator owner.
    pub fn from_function(cells: &[u32], provider: u32) -> Result<Self, &'static str> {
        if provider != 0 && cells == [provider, code(b"keyR"), KEY] {
            Ok(Self::Hex48Little)
        } else {
            Err("SMC RTC helper/provider descriptor is unqualified")
        }
    }
}

pub(super) struct RtcBinding {
    pub clock: RtcClock,
    pub profile: RtcKeyProfile,
}
impl RtcBinding {
    pub fn info(&self) -> (usize, u32, u8) {
        match self.profile {
            RtcKeyProfile::Hex48Little => (6, code(b"hex_"), 0x94),
        }
    }
    pub fn value(&self) -> Result<[u8; 6], &'static str> {
        let ticks = self.clock.published_ticks()?;
        let bytes = ticks.to_le_bytes();
        Ok(bytes[..6].try_into().expect("six bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires original26A434 KC and J314s DT via STELA_TEST_PMGR_M1_KERNELCACHE/STELA_TEST_SPMI_DT"]
    fn original_rtc_helper_uses_raw_keyr_with_actual_interface_dispatch() {
        use stela_contracts::adt::Node;
        let bytes =
            std::fs::read(std::env::var("STELA_TEST_PMGR_M1_KERNELCACHE").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&bytes),
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
        );
        for (offset, size, hash) in [
            (
                0x2d1a218usize,
                72usize,
                "d08a96ef899cc11c536f8ee094cf764752578a5f8314a5f2ea1a2926836782ec",
            ), // keyR-call
            (
                0x2d1ab9cusize,
                268usize,
                "0b5bfecb144acfe12f275ac5ad4937ac7ddd2cf652bbf0a0438dc2b8b5c8c1e2",
            ), // function-keyinfo-init
            (
                0x2d1c30cusize,
                72usize,
                "9ef7e3db5882f36704178784eed6061ea492aa65835aaef1ee0d45da66f11553",
            ), // interface-raw-read
            (
                0x1297da8usize,
                8usize,
                "8a28bc49444a53af788aeca4eb0463722d80b542b760aa43c72c0831eedb9591",
            ), // interface-vtable-read
            (
                0x1297dd0usize,
                8usize,
                "879004d5e221313c9753f36cf99a90e62a78799f62f8eedf8dafbc7277950446",
            ), // interface-vtable-info
            (
                0x129b368usize,
                8usize,
                "637afed02db44ce911daf66a6c43d07606d1ae1a4a8b5e2568c09d20836fc705",
            ), // keys-vtable-read
            (
                0x2d37944usize,
                64usize,
                "80e4650c6d6c323ab0172a637301117d78b5e627ba352fb88f2d8c5d7906644f",
            ), // family-raw-read
            (
                0x2d379c4usize,
                76usize,
                "1aa162895f62c19f9bb94420c87ffd9d24d5ce5269032133a27294cb11aa6c4f",
            ), // family-swizzle
            (
                0x1296830usize,
                144usize,
                "75116a830458f5c956208dc7bca7294d7c96456af8a1520ff5f78e7b3108ce89",
            ), // user-method-table
            (
                0x2d384a4usize,
                80usize,
                "9ce2fc643cb95178a5e93010afc948aff1f957fefcb0b15f97e0ddeb9db40e13",
            ), // user-read-command
            (
                0x2d386a8usize,
                120usize,
                "05c0da6d64a1387c72682220b486f10404cd352e51babf197434fef97e419a72",
            ), // user-info-command
            (
                0x2d5d898usize,
                32usize,
                "ca64e17e6970fc19ae5c5bc6c4d98fac69b8b45176fe2d6dbc811d6034ea8c18",
            ), // rtc-helper-select
            (
                0x2d5daa8usize,
                60usize,
                "78438ce52684c37823fe375b17516d85fba789d02d7dcea29b063fe7c790a8f5",
            ), // rtc-helper-call
            (
                0x2d5db30usize,
                32usize,
                "c4844ba0b3f1a9ae4e64a25e0d1bc735e99421941c160db0a1d085fbaa72f27d",
            ), // rtc-tick-units
        ] {
            assert_eq!(
                stela_formats::sha256(&bytes[offset..offset + size]),
                hash,
                "source span {offset:#x}"
            );
        }
        for (offset, target) in [
            (0x1297da8, 0xfffffe0009d2030c),
            (0x1297dd0, 0xfffffe0009d204e4),
            (0x129b368, 0xfffffe0009d29168),
        ] {
            let value = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            assert_eq!(0xfffffe0007004000 + (value & 0x3fffffff), target);
        }
        let data = std::fs::read(std::env::var("STELA_TEST_SPMI_DT").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&data),
            "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
        );
        let root = Node::root(&data).unwrap();
        let io = root.child("arm-io").unwrap();
        let smc = io.child("smc").unwrap();
        let nub = smc.child("iop-smc-nub").unwrap();
        let provider = nub
            .child("smc-pmu")
            .unwrap()
            .first_u32("AAPL,phandle")
            .unwrap();
        let node = io.child("nub-spmi0").unwrap().child("spmi-mpmu").unwrap();
        let cells = node.cells32("function-rtc_read_helper").unwrap();
        assert_eq!(provider, 0xb6);
        assert_eq!(cells, [0xb6, 0x6b657952, 0x434c4b4d]);
        assert_eq!(
            RtcKeyProfile::from_function(&cells, provider),
            Ok(RtcKeyProfile::Hex48Little)
        );
    }
}
