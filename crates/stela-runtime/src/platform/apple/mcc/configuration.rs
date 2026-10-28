//! Explicit initial software control images, separate from physical reset.
//!
//! T6000 startup saves every DCS +13cc word unchanged. Its mode0 path restores
//! those saved words, while mode1 writes the first alternate dramcfg-data word
//! to every channel. Neither consumer decodes capacity or validates initial
//! bits. Creating zeroed control backing is a Stela policy, not recovered Apple
//! DRAM timing, an alternate-mode selection or authority to settle later writes.
use super::{CHANNELS, GROUPS};
use alloc::{vec, vec::Vec};

/// Actual software configuration for a newly owned controller. Quotas start
/// at zero; weights are a declared policy, not measured Apple reset values.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub dram: Vec<[u32; CHANNELS as usize]>,
    pub weights: [u8; GROUPS as usize],
}
impl Configuration {
    /// Allocate a complete zeroed software control image before publication.
    /// The original consumer accepts and saves these opaque initial words;
    /// there is no RAM-capacity encoding or copy from alternate dramcfg-data.
    /// All 32 quota weights remain an explicit caller-selected policy.
    ///
    /// This grants no physical DRAM programming/settlement, power supply or
    /// lifecycle authority. Pass the actual resource's lifecycle separately to
    /// Controller::initialized_cacheless. Subsequent DRAM writes retain their
    /// ordinary pending-effect/readback contract, including a restore of zero.
    pub fn zeroed_control_image(
        apertures: usize,
        weights: [u8; GROUPS as usize],
    ) -> Result<Self, &'static str> {
        validate(apertures, &weights)?;
        Ok(Self {
            dram: vec![[0; CHANNELS as usize]; apertures],
            weights,
        })
    }

    pub(super) fn validate(&self) -> Result<u8, &'static str> {
        validate(self.dram.len(), &self.weights)
    }
}

fn validate(apertures: usize, weights: &[u8; GROUPS as usize]) -> Result<u8, &'static str> {
    if !(1..=16).contains(&apertures) {
        return Err("MCC aperture count exceeds original source capacity");
    }
    if weights.iter().any(|&weight| weight == 0 || weight > 0x7f) {
        return Err("MCC quota policy weight is outside its source field");
    }
    Ok(apertures as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use {
        crate::platform::apple::mcc::APERTURE_BYTES, crate::platform::apple::mcc::Controller,
        crate::platform::apple::mcc::DCS_BASE, crate::platform::apple::mcc::DCS_STRIDE,
        crate::platform::apple::mcc::Origin, crate::platform::apple::mcc::RequestKind,
        stela_contracts::bus::Access, stela_contracts::bus::Bus, stela_contracts::bus::Lifecycle,
        stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
        stela_contracts::bus::Width, stela_contracts::interrupt::InterruptLatch,
    };

    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    const BASE: u64 = 0x200000000;

    #[test]
    fn whole_control_images_check_geometry_and_every_explicit_weight() {
        let weights = core::array::from_fn(|group| group as u8 + 1);
        for apertures in [1, 2, 4, 16] {
            let configuration = Configuration::zeroed_control_image(apertures, weights).unwrap();
            assert_eq!(configuration.dram, vec![[0; 4]; apertures]);
            assert_eq!(configuration.weights, weights);
        }
        for apertures in [0, 17, usize::MAX] {
            assert!(Configuration::zeroed_control_image(apertures, weights).is_err());
        }
        for group in 0..32 {
            for value in [0, 128, u8::MAX] {
                let mut invalid = weights;
                invalid[group] = value;
                assert!(Configuration::zeroed_control_image(4, invalid).is_err());
            }
        }
    }

    #[test]
    fn mounted_created_image_has_real_zero_words_and_preserves_pending_restore_effects() {
        let configuration = Configuration::zeroed_control_image(4, [1; 32]).unwrap();
        let owner = Controller::initialized_cacheless(configuration, LIVE).unwrap();
        assert_eq!(owner.origin(), Origin::StelaInitialized);
        let mut bus = Bus::new();
        for aperture in 0..4 {
            let id = bus.add(Box::new(owner.view(aperture).unwrap()));
            for offset in owner.register_offsets() {
                bus.map(
                    id,
                    BASE + u64::from(aperture) * APERTURE_BYTES + offset,
                    4,
                    offset,
                )
                .unwrap();
            }
        }
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(3, 17, &mut pins);
        let mut saved = Vec::new();
        for channel in 0..16 {
            let address = BASE
                + (channel >> 2) * APERTURE_BYTES
                + DCS_BASE
                + (channel & 3) * DCS_STRIDE
                + super::super::DRAM_CONFIG;
            saved.push(bus.read(address, Width::Word, &mut access).unwrap());
            assert_eq!(saved.last(), Some(&0));
            assert_eq!(
                bus.read(
                    BASE + (channel >> 2) * APERTURE_BYTES + 0xa07c,
                    Width::Word,
                    &mut access
                ),
                Ok(1 << 16)
            );
        }
        assert!(owner.requests().is_empty());
        // Original mode0 restores the saved word. Even restoring the same0
        // does not establish native DRAM effects or synchronous settlement.
        let address = BASE + DCS_BASE + super::super::DRAM_CONFIG;
        bus.write(address, Width::Word, saved[0], &mut access)
            .unwrap();
        assert!(bus.read(address, Width::Word, &mut access).is_err());
        assert_eq!(owner.requests().len(), 1);
        let request = owner.requests()[0];
        assert_eq!(request.kind, RequestKind::DramConfiguration { channel: 0 });
        assert_eq!(
            (request.previous.value, request.written, request.at),
            (0, 0, 17)
        );
        assert_eq!(request.previous.known, u64::from(u32::MAX));
        assert_eq!(
            bus.read(address + DCS_STRIDE, Width::Word, &mut access),
            Ok(0)
        );
    }

    #[test]
    fn lifecycle_is_supplied_independently_and_retained_pause_keeps_the_created_image() {
        let configuration = Configuration::zeroed_control_image(1, [127; 32]).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        for paused in [
            LifecycleState {
                clocked: false,
                ..LIVE
            },
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
            LifecycleState {
                powered: false,
                ..LIVE
            },
        ] {
            let owner = Controller::initialized_cacheless(configuration.clone(), paused).unwrap();
            assert_eq!(owner.lifecycle_state(), paused);
            let initial = owner.observations();
            let mut view = owner.view(0).unwrap();
            assert!(
                view.read(
                    DCS_BASE + super::super::DRAM_CONFIG,
                    Width::Word,
                    &mut access,
                )
                .is_err()
            );
            view.check_lifecycle(LIVE).unwrap();
            view.set_lifecycle(LIVE, &mut access);
            assert_eq!(owner.observations(), initial);
            assert_eq!(owner.origin(), Origin::StelaInitialized);
        }
        for unavailable in [
            LifecycleState {
                reset: true,
                ..LIVE
            },
            LifecycleState {
                powered: false,
                retention: false,
                ..LIVE
            },
        ] {
            assert!(Controller::initialized_cacheless(configuration.clone(), unavailable).is_err());
        }
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_MCC_KERNELCACHE"]
    fn original_t6000_opaque_control_save_and_restore_consumers() {
        use sha2::{Digest, Sha256};
        let path =
            std::env::var("STELA_TEST_MCC_KERNELCACHE").expect("original mac13j kernelcache");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
        );
        for (start, end, expected) in [
            (
                0x2e45ff0,
                0x2e46cec,
                "c3537b04baa3275219c7707c1b969168ded3a6bb267b5e9c21a1f135de6b2656",
            ),
            (
                0x2e48d74,
                0x2e48f28,
                "7e0b1acedcd9e68c2bd9a7fcdde7b595e24142c7e63bc9807b9a10ad3f45af08",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), expected);
        }
    }
}
