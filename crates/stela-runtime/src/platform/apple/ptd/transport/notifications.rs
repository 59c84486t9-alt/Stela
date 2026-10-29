//! PMP-local PTD source levels on the actual publication owner. Original
//! t6000pmp table 0x81300 and IRQ wrappers 0x12618..0x12660 register route r
//! through RTKit-local IRQ 1+r, encoded in namespace 0x10000. These are not AP
//! AIC numbers or ASC messages. See docs/research/apple-mcc.md.
use super::{NotificationOwner, Ptd, ROUTES, Range};
use alloc::rc::Rc;
use stela_contracts::bus::LifecycleState;
use stela_soc_data::ptd::Geometry;

/// Original native descriptor geometry, independently cross-checked by the
/// source DeviceTree's 0xc00-byte update alias.
const LOCAL_ENTRIES: u32 = 384;
const RTKIT_LOCAL_NAMESPACE: u32 = 0x10000;
const FIRST_LOCAL_IRQ: u32 = 1;

/// Native implemented entries, independently of the addressable update alias.
/// T6000 file0x57780 declares 384/16; T8112 file0x355f8 declares 256/16.
/// Both original test objects register route r on RTKit-local IRQ 1+r.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeProfile {
    T6000,
    T8112,
}
impl NativeProfile {
    pub fn entries(self) -> u32 {
        match self {
            Self::T6000 => LOCAL_ENTRIES,
            Self::T8112 => 256,
        }
    }
}

/// A PTD output in the original PMP-local interrupt namespace. A number alone
/// grants no authority to clear a pending publication or report service ACKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalIrq(u8);

impl LocalIrq {
    pub fn from_route(route: u8) -> Option<Self> {
        (usize::from(route) < ROUTES).then_some(Self(route))
    }

    pub fn route(self) -> u8 {
        self.0
    }

    pub fn rtkit_number(self) -> u32 {
        RTKIT_LOCAL_NAMESPACE | (FIRST_LOCAL_IRQ + u32::from(self.0))
    }
}

/// The source levels lent to a native PMP owner from this exact PTD object.
/// There is no copied line bank, event-erasing pop, callback execution, RTKit
/// enable mask or acknowledgement here. Pending entries/control on the same
/// publication bank determine these levels. RTKit callback registration and
/// actual native service effects remain the recipient's obligations.
#[derive(Clone)]
pub struct LocalNotifications(Ptd);

impl LocalNotifications {
    /// Admit exactly one native recipient before any publication. Aliases keep
    /// this admission for the bank's whole retained lifetime, including after an
    /// abandoned recipient. Dropping a native owner is not a qualified reset.
    pub(crate) fn claim_pmp_recipient(&self) -> Result<(), &'static str> {
        let mut state = self.0.0.borrow_mut();
        if state.pmp_recipient_admitted {
            return Err("PTD actual bank already admitted its native PMP recipient");
        }
        if state.serial != 0 {
            return Err("native PMP recipient must precede actual PTD publication admission");
        }
        state.pmp_recipient_admitted = true;
        Ok(())
    }

    /// Check actual backing identity, including after cloning an alias. Equal
    /// numeric ranges on a different object do not satisfy this check.
    pub fn owns(&self, bank: &Ptd) -> bool {
        Rc::ptr_eq(&self.0.0, &bank.0)
    }

    /// The actual bank whose source levels this recipient observes.
    pub fn bank(&self) -> &Ptd {
        &self.0
    }

    /// Raw level bitmap before recipient RTKit masking or callback dispatch.
    /// Retained pauses keep existing source levels; this does not authorize
    /// running a paused recipient or invent a completed callback.
    pub fn asserted(&self) -> u16 {
        self.0
            .0
            .borrow()
            .asserted
            .iter()
            .enumerate()
            .fold(0, |bits, (route, &level)| {
                bits | (u16::from(level) << route)
            })
    }

    pub fn level(&self, irq: LocalIrq) -> bool {
        self.0.0.borrow().asserted[usize::from(irq.0)]
    }
}

impl Ptd {
    /// Admit the caller's source-qualified native profile on the actual bank.
    /// An alias can address more update positions than this controller implements;
    /// that larger extent never creates additional entries or local sources.
    pub fn initialized_local_profile(
        profile: NativeProfile,
        geometry: Geometry,
        ranges: &[Range],
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications), &'static str> {
        let entries = profile.entries();
        if entries as usize > geometry.entries() {
            return Err("native PTD implemented entries exceed its physical update alias");
        }
        Self::new_local(entries, ranges, lifecycle)
    }

    /// Allocate the qualified native geometry and its actual PMP-local output
    /// owner together, before admitting any source/client. This is explicit
    /// Stela initialization, not retained Apple reset or RTOS-ready state.
    /// Every entry is unpublished, interrupts disabled, and local levels low.
    pub fn initialized_local(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications), &'static str> {
        if entries != LOCAL_ENTRIES {
            return Err("PMP-local PTD notification geometry is not qualified");
        }
        Self::new_local(entries, ranges, lifecycle)
    }

    fn new_local(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
    ) -> Result<(Self, LocalNotifications), &'static str> {
        let bank = Self::initialized(entries, ranges, lifecycle, [None; ROUTES])?;
        bank.0.borrow_mut().notification_owner = NotificationOwner::PmpLocal;
        let notifications = LocalNotifications(bank.clone());
        Ok((bank, notifications))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {
        crate::platform::apple::ptd::transport::Entry, stela_contracts::bus::Access,
        stela_contracts::bus::Lifecycle, stela_contracts::bus::MmioDevice,
        stela_contracts::bus::MmioError, stela_contracts::bus::Width,
        stela_contracts::interrupt::InterruptLatch, stela_soc_data::ptd::UPDATE_OFFSET,
    };

    fn lifecycle() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }

    #[test]
    fn t8112_implements_256_entries_inside_its_larger_actual_alias() {
        let geometry = Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 0x4000)).unwrap();
        assert_eq!(geometry.entries(), 2048);
        assert_eq!(NativeProfile::T8112.entries(), 256);
        let ranges = [Range {
            id: 1,
            start: 0,
            count: 256,
            name: "test".into(),
        }];
        let (mut bank, local) =
            Ptd::initialized_local_profile(NativeProfile::T8112, geometry, &ranges, lifecycle())
                .unwrap();
        let mut latch = InterruptLatch::new();
        write(
            &mut bank,
            0x18400 + 31 * 4,
            Width::Word,
            15 << 28,
            0,
            &mut latch,
        )
        .unwrap();
        write(
            &mut bank,
            0x18200 + 7 * 4,
            Width::Word,
            1 << 31,
            0,
            &mut latch,
        )
        .unwrap();
        write(
            &mut bank,
            UPDATE_OFFSET + 255 * 8,
            Width::Double,
            73,
            5,
            &mut latch,
        )
        .unwrap();
        assert_eq!(local.asserted(), 1 << 15);
        assert!(latch.take_aic_inputs().is_empty());
        assert!(
            write(
                &mut bank,
                UPDATE_OFFSET + 256 * 8,
                Width::Double,
                74,
                6,
                &mut latch
            )
            .is_err()
        );
        assert_eq!(
            local
                .bank()
                .consume_entry(255, &mut Access::new(0, 7, &mut latch))
                .unwrap()
                .value,
            73
        );
        assert_eq!(local.asserted(), 0);
        let oversized = [Range {
            count: 257,
            ..ranges[0].clone()
        }];
        assert!(
            Ptd::initialized_local_profile(NativeProfile::T8112, geometry, &oversized, lifecycle())
                .is_err()
        );
        let short = Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 255 * 8)).unwrap();
        assert!(
            Ptd::initialized_local_profile(NativeProfile::T8112, short, &ranges, lifecycle())
                .is_err()
        );
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "oracle: STELA_TEST_PMP_T8112"]
    fn original_t8112_native_geometry_and_local_route_keep_the_same_bank() {
        use sha2::{Digest, Sha256};
        let data = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        for (start, end, expected) in [
            (
                0x4bfd8,
                0x4bff8,
                "7a9c6b5f22ae1ac5b045f15140a9517e713571b1032e1c5c29cb419daa869d2c",
            ),
            (
                0x457d8,
                0x45810,
                "1e689e3daa7f5c3d24fd6cd4133ce7e83ecc470c1c89dd17952d45ff41f90fc7",
            ),
            (
                0x355f8,
                0x35608,
                "731acbf6bab262e48fc73bc42d99f9137b822fef627f200c09235a91ba7193cb",
            ),
            (
                0x1f92c,
                0x1fb6c,
                "77d6585ceb801c22e14bda542eb2023c5538944290ef75268bd04ea1aa07bea0",
            ),
            (
                0x80d8,
                0x8104,
                "9cae0be36271023e5690bc960c5a05ff8b057886eb533dc09cc3f8b3072e8b22",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&data[start..end])), expected);
        }
        assert_eq!(
            u32::from_le_bytes(data[0x355f8..0x355fc].try_into().unwrap()),
            NativeProfile::T8112.entries()
        );
        assert_eq!(
            u32::from_le_bytes(data[0x355fc..0x35600].try_into().unwrap()),
            16
        );
        assert_eq!(
            u64::from_le_bytes(data[0x457d8..0x457e0].try_into().unwrap()),
            0x23b3c0000
        );
    }

    fn ranges() -> [Range; 1] {
        [Range {
            id: 1,
            start: 0,
            count: LOCAL_ENTRIES,
            name: "declared test bank".into(),
        }]
    }

    fn write(
        bank: &mut Ptd,
        offset: u64,
        width: Width,
        value: u64,
        now: u64,
        latch: &mut InterruptLatch,
    ) -> Result<(), MmioError> {
        bank.write(offset, width, value, &mut Access::new(0, now, latch))
    }

    #[test]
    fn each_local_route_tracks_actual_publication_and_consumption_without_ap_wires() {
        let (mut bank, notifications) =
            Ptd::initialized_local(384, &ranges(), lifecycle()).unwrap();
        assert!(notifications.owns(&bank));
        assert!(notifications.owns(&bank.clone()));
        let (unrelated, _) = Ptd::initialized_local(384, &ranges(), lifecycle()).unwrap();
        assert!(!notifications.owns(&unrelated));
        let mut latch = InterruptLatch::new();
        write(&mut bank, 0x18400, Width::Word, 0x76543210, 0, &mut latch).unwrap();
        write(&mut bank, 0x18404, Width::Word, 0xfedcba98, 0, &mut latch).unwrap();
        write(&mut bank, 0x18200, Width::Word, 0xffff, 0, &mut latch).unwrap();
        assert_eq!(notifications.asserted(), 0);
        for route in 0..16 {
            let irq = LocalIrq::from_route(route).unwrap();
            assert_eq!(irq.route(), route);
            assert_eq!(irq.rtkit_number(), 0x10001 + u32::from(route));
            write(
                &mut bank,
                UPDATE_OFFSET + u64::from(route) * 8,
                Width::Double,
                0x123400 + u64::from(route),
                7,
                &mut latch,
            )
            .unwrap();
            assert!(notifications.level(irq));
            assert_eq!(
                notifications.asserted(),
                u16::try_from((1u32 << (u32::from(route) + 1)) - 1).unwrap()
            );
        }
        assert!(LocalIrq::from_route(16).is_none());
        assert!(latch.take_aic_inputs().is_empty());
        assert_eq!(latch.pins(0), Default::default());
        for route in 0..16 {
            let entry = notifications
                .bank()
                .consume_entry(u32::from(route), &mut Access::new(0, 8, &mut latch))
                .unwrap();
            assert_eq!(
                entry,
                Entry {
                    value: 0x123400 + u64::from(route),
                    metadata: 7 << 10 | 2
                }
            );
            assert!(!notifications.level(LocalIrq::from_route(route).unwrap()));
        }
        assert_eq!(notifications.asserted(), 0);
        assert!(latch.take_aic_inputs().is_empty());
    }

    #[test]
    fn local_levels_follow_mask_route_overwrite_and_retained_lifecycle_on_same_object() {
        let (mut bank, notifications) =
            Ptd::initialized_local(384, &ranges(), lifecycle()).unwrap();
        let mut latch = InterruptLatch::new();
        write(&mut bank, UPDATE_OFFSET, Width::Double, 41, 1, &mut latch).unwrap();
        assert_eq!(notifications.asserted(), 0); // Entry pending, source disabled.
        write(&mut bank, 0x18200, Width::Word, 1, 2, &mut latch).unwrap();
        assert_eq!(notifications.asserted(), 1);
        write(&mut bank, 0x18400, Width::Word, 15, 3, &mut latch).unwrap();
        assert_eq!(notifications.asserted(), 1 << 15);
        write(&mut bank, UPDATE_OFFSET, Width::Double, 42, 4, &mut latch).unwrap();
        assert_eq!(notifications.asserted(), 1 << 15);
        let paused = LifecycleState {
            clocked: false,
            ..lifecycle()
        };
        bank.check_lifecycle(paused).unwrap();
        bank.set_lifecycle(paused, &mut Access::new(0, 5, &mut latch));
        assert_eq!(notifications.asserted(), 1 << 15);
        assert!(write(&mut bank, UPDATE_OFFSET, Width::Double, 99, 6, &mut latch).is_err());
        assert!(
            notifications
                .bank()
                .consume_entry(0, &mut Access::new(0, 6, &mut latch))
                .is_err()
        );
        assert!(
            bank.check_lifecycle(LifecycleState {
                reset: true,
                ..lifecycle()
            })
            .is_err()
        );
        bank.set_lifecycle(lifecycle(), &mut Access::new(0, 7, &mut latch));
        write(&mut bank, 0x18300, Width::Word, 1, 8, &mut latch).unwrap();
        assert_eq!(notifications.asserted(), 0);
        write(&mut bank, 0x18200, Width::Word, 1, 9, &mut latch).unwrap();
        assert_eq!(notifications.asserted(), 1 << 15);
        drop(bank); // Recipient retains the exact bank, not a copied line image.
        let entry = notifications
            .bank()
            .consume_entry(0, &mut Access::new(0, 10, &mut latch))
            .unwrap();
        assert_eq!(
            entry,
            Entry {
                value: 42,
                metadata: 4 << 10 | 3
            }
        );
        assert_eq!(notifications.asserted(), 0);
    }

    #[test]
    fn native_geometry_last_update_and_service_outputs_remain_independent() {
        for entries in [0, 383, 385, 2048] {
            assert!(Ptd::initialized_local(entries, &ranges(), lifecycle()).is_err());
        }
        let (mut bank, notifications) =
            Ptd::initialized_local(384, &ranges(), lifecycle()).unwrap();
        let mut latch = InterruptLatch::new();
        write(
            &mut bank,
            0x18400 + 47 * 4,
            Width::Word,
            15 << 28,
            0,
            &mut latch,
        )
        .unwrap();
        write(
            &mut bank,
            0x18200 + 11 * 4,
            Width::Word,
            1 << 31,
            0,
            &mut latch,
        )
        .unwrap();
        write(
            &mut bank,
            UPDATE_OFFSET + 383 * 8,
            Width::Double,
            0x55,
            1,
            &mut latch,
        )
        .unwrap();
        assert_eq!(notifications.asserted(), 1 << 15);
        for (offset, width) in [
            (UPDATE_OFFSET + 384 * 8, Width::Double),
            (UPDATE_OFFSET, Width::Word),
        ] {
            assert!(write(&mut bank, offset, width, 0xffff, 2, &mut latch).is_err());
        }
        assert_eq!(bank.requests().len(), 1);
        // A native AP request produces its actual local transport input only.
        // It cannot create PMP-STATUS or a separate power-service ACK entry.
        write(
            &mut bank,
            0x18200 + 7 * 4,
            Width::Word,
            1 << 24,
            3,
            &mut latch,
        )
        .unwrap();
        write(
            &mut bank,
            UPDATE_OFFSET + 248 * 8,
            Width::Double,
            0xcafe,
            4,
            &mut latch,
        )
        .unwrap();
        assert_eq!(notifications.asserted(), 1 << 15 | 1);
        for entry in [1, 256] {
            assert_eq!(
                notifications
                    .bank()
                    .consume_entry(entry, &mut Access::new(0, 5, &mut latch))
                    .unwrap(),
                Entry {
                    value: 0,
                    metadata: 0
                }
            );
        }
        assert_eq!(notifications.asserted(), 1 << 15 | 1);
        assert_eq!(bank.requests().len(), 2);
    }
}
