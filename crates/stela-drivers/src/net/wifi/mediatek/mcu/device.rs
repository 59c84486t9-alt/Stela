// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Initial station-interface DEV_INFO/BSS_BASIC requests, not associated BSS
//! configuration. Preserve allocated caller indices and source command
//! order; command construction cannot establish an acknowledged firmware context.
use super::runtime::Command;
use crate::net::Mac;

/// Native interface resources. `band_index` is the source
/// firmware resource selector (MT7921/22 initially0, non-MLO MT7925 initiallyff),
/// not the RF 2.4/5GHz band. This codec does not allocate these indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub bss_index: u8,
    pub omac_index: u8,
    pub band_index: u8,
    pub wmm_index: u8,
    pub link_index: u8,
    pub broadcast_wcid: u16,
    pub address: Mac,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidAddress,
    InvalidBss,
    InvalidOmac,
    InvalidWmm,
    InvalidWcid,
    UnsupportedLink,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek initial station context: {self:?}")
    }
}
impl core::error::Error for Error {}

/// The exact two source requests in submission order. Only ordinary
/// station/non-MLO registration is supported; an AP/P2P/NAN context is not
/// silently represented by the station connection type.
pub struct Requests {
    context: Context,
    enable: bool,
    device: [u8; 16],
    bss: [u8; 36],
}
impl Requests {
    pub fn station(context: Context, enable: bool) -> Result<Self, Error> {
        if context.address.is_multicast() || context.address.0 == [0; 6] {
            return Err(Error::InvalidAddress);
        }
        if context.bss_index >= 4 {
            return Err(Error::InvalidBss);
        }
        if context.omac_index > 63 {
            return Err(Error::InvalidOmac);
        }
        if context.wmm_index >= 4 {
            return Err(Error::InvalidWmm);
        }
        if context.broadcast_wcid >= 20 {
            return Err(Error::InvalidWcid);
        }
        if context.link_index != 0 {
            return Err(Error::UnsupportedLink);
        }
        let mut device = [0; 16];
        device[0] = context.omac_index;
        device[1] = context.band_index;
        device[6..8].copy_from_slice(&12u16.to_le_bytes()); // DEV_INFO_ACTIVE0
        device[8] = u8::from(enable);
        device[9] = context.link_index;
        device[10..16].copy_from_slice(&context.address.0);
        let mut bss = [0; 36];
        bss[0] = context.bss_index;
        bss[6..8].copy_from_slice(&32u16.to_le_bytes()); // UNI_BSS_INFO_BASIC0
        bss[8] = u8::from(enable);
        bss[9] = context.omac_index;
        bss[10] = if context.omac_index > 0x10 {
            0
        } else {
            context.omac_index
        };
        bss[11] = context.band_index;
        bss[12..16].copy_from_slice(&0x0001_0001u32.to_le_bytes()); // INFRA|STA
        bss[16] = 1; // Source initial context, not client association state.
        bss[17] = context.wmm_index;
        bss[24..26].copy_from_slice(&context.broadcast_wcid.to_le_bytes());
        bss[30..32].copy_from_slice(&context.broadcast_wcid.to_le_bytes());
        bss[35] = context.link_index;
        // BSSID, beacon/DTIM, PHY and rates remain source-zero.
        // Association-specific BSS updates are separate real command payloads.
        Ok(Self {
            context,
            enable,
            device,
            bss,
        })
    }
    pub fn context(&self) -> Context {
        self.context
    }
    pub fn enabling(&self) -> bool {
        self.enable
    }
    pub fn first(&self) -> (Command, &[u8]) {
        if self.enable {
            (Command::DeviceInfo, &self.device)
        } else {
            (Command::BssInfo, &self.bss)
        }
    }
    pub fn second(&self) -> (Command, &[u8]) {
        if self.enable {
            (Command::BssInfo, &self.bss)
        } else {
            (Command::DeviceInfo, &self.device)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    fn context() -> Context {
        Context {
            bss_index: 2,
            omac_index: 2,
            band_index: 0xff,
            wmm_index: 2,
            link_index: 0,
            broadcast_wcid: 17,
            address: Mac([2, 1, 2, 3, 4, 5]),
        }
    }
    #[test]
    fn source_initial_context_order_is_distinct_from_associated_bss_state() {
        for enable in [false, true] {
            for omac in [0, 3, 0x10, 0x11, 0x3f] {
                let context = Context {
                    omac_index: omac,
                    ..context()
                };
                let request = Requests::station(context, enable).unwrap();
                assert_eq!(request.context(), context);
                assert_eq!(request.enabling(), enable);
                let ((first, _), (second, _)) = (request.first(), request.second());
                assert_eq!(
                    (first, second),
                    if enable {
                        (Command::DeviceInfo, Command::BssInfo)
                    } else {
                        (Command::BssInfo, Command::DeviceInfo)
                    }
                );
                assert_eq!(
                    &request.device[..10],
                    &[omac, 0xff, 0, 0, 0, 0, 12, 0, u8::from(enable), 0]
                );
                assert_eq!(&request.device[10..], &context.address.0);
                assert_eq!(request.bss[10], if omac > 0x10 { 0 } else { omac });
                assert_eq!(&request.bss[12..18], &[1, 0, 1, 0, 1, 2]);
                assert_eq!(&request.bss[18..24], &[0; 6]);
                assert_eq!(&request.bss[24..32], &[17, 0, 0, 0, 0, 0, 17, 0]);
                assert_eq!(&request.bss[32..], &[0; 4]);
            }
        }
    }
    #[test]
    fn invalid_resources_and_unimplemented_multi_link_contexts_refuse() {
        for (context, expected) in [
            (
                Context {
                    address: Mac([1; 6]),
                    ..context()
                },
                Error::InvalidAddress,
            ),
            (
                Context {
                    address: Mac([0; 6]),
                    ..context()
                },
                Error::InvalidAddress,
            ),
            (
                Context {
                    bss_index: 4,
                    ..context()
                },
                Error::InvalidBss,
            ),
            (
                Context {
                    omac_index: 64,
                    ..context()
                },
                Error::InvalidOmac,
            ),
            (
                Context {
                    wmm_index: 4,
                    ..context()
                },
                Error::InvalidWmm,
            ),
            (
                Context {
                    broadcast_wcid: 20,
                    ..context()
                },
                Error::InvalidWcid,
            ),
            (
                Context {
                    link_index: 1,
                    ..context()
                },
                Error::UnsupportedLink,
            ),
        ] {
            assert!(matches!(Requests::station(context, true), Err(actual) if actual == expected));
        }
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_DEVICE_ORACLE"]
    fn unchanged_initial_device_helper_matches_both_full_requests_in_source_order() {
        let root = std::path::PathBuf::from(
            std::env::var_os("STELA_MT792X_DEVICE_ORACLE").expect("device oracle directory"),
        );
        for chip in [7921, 7922, 7925] {
            let trace = std::fs::read(root.join(alloc::format!("{chip}.trace"))).unwrap();
            let mut cursor = 0;
            for i in 0..320usize {
                let mut address = core::array::from_fn(|j| (2 + i * 7 + j) as u8);
                address[0] &= 0xfe;
                let context = Context {
                    bss_index: ((i / 2) % 4) as u8,
                    omac_index: ((i * 7) % 64) as u8,
                    band_index: if chip == 7925 { 0xff } else { 0 },
                    wmm_index: ((i / 8) % 4) as u8,
                    link_index: 0,
                    broadcast_wcid: ((i * 3) % 20) as u16,
                    address: Mac(address),
                };
                let request = Requests::station(context, (i / 64) % 2 != 0).unwrap();
                for (command, body) in [request.first(), request.second()] {
                    assert_eq!(trace[cursor], command as u8, "chip {chip} context {i}");
                    let n = usize::from(trace[cursor + 1]);
                    cursor += 2;
                    assert_eq!(body, &trace[cursor..cursor + n], "chip {chip} context {i}");
                    cursor += n;
                }
            }
            assert_eq!(cursor, trace.len());
        }
    }
}
