//! Canonical RAM service join for the actual T8112 DCS channel owner.
//! This component is composed into the prepared memory resource; it does not
//! create another AMCC/PTD owner or qualify missing PMP service producers.
use crate::platform::apple::dcs::native::CHANNELS;
use crate::platform::apple::dcs::native::ChannelConfiguration;
use crate::platform::apple::dcs::native::ChannelProgress;
use crate::platform::apple::dcs::native::Controller;
use alloc::{sync::Arc, vec::Vec};
use stela_contracts::bus::Access;
use stela_contracts::bus::Lifecycle;
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::MmioDevice;
use stela_contracts::bus::MmioError;
use stela_contracts::bus::Width;
use stela_engine::memory::CanonicalRamService;
use stela_engine::memory::RegisteredSystemRam;

/// Exact channel backing and canonical guest RAM association. Clones retain
/// the same controller, lifecycle, pending effects and actual memory identity.
#[derive(Clone)]
pub struct NativeDcs {
    controller: Controller,
    ram: Arc<RegisteredSystemRam>,
}
impl NativeDcs {
    pub fn initialized(
        configuration: Vec<ChannelConfiguration>,
        lifecycle: LifecycleState,
        ram: Arc<RegisteredSystemRam>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            controller: Controller::initialized(configuration, lifecycle)?,
            ram,
        })
    }
    pub fn progress(&self) -> [ChannelProgress; CHANNELS] {
        self.controller.progress()
    }
    pub fn requires_ram_access(&self, offset: u64, width: Width) -> bool {
        self.controller.requires_ram_access(offset, width)
    }
    fn live_drain(
        &self,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<(usize, u16), &'static str> {
        if !memory.belongs_to(&self.ram) {
            return Err("native DCS drain borrowed another actual RAM owner");
        }
        memory
            .validate_current()
            .map_err(|_| "native DCS drain lost actual RAM generation/writer exclusion")?;
        self.controller.drain_control(offset, width)
    }
    /// Observe the empty synchronous frontend while its actual native workers,
    /// writer gates and exclusive synchronous device borrows remain held. No
    /// ordinary ready word is saved when this live service ends.
    ///
    /// # Safety
    /// Every actual PE/native job is stopped. The same canonical RAM service
    /// and all synchronous device borrows remain held; no transfer can advance
    /// or reenter. No autonomous firmware, raw DMA or external publisher can
    /// touch guest RAM. Pending I/O is permitted only while the actual borrows
    /// exclude its progress. Free gates alone do not establish this contract.
    pub unsafe fn read_ram_drain(
        &self,
        offset: u64,
        width: Width,
        memory: &CanonicalRamService<'_>,
    ) -> Result<u64, &'static str> {
        let (_, high) = self.live_drain(offset, width, memory)?;
        Ok(u64::from(high) << 16)
    }
    /// Consume the source full32 low16-clear under this exact live RAM owner.
    /// The original guest's barriers and330us delay remain separate operations.
    ///
    /// # Safety
    /// The complete closed-producer/exclusive-device contract of read_ram_drain
    /// holds throughout this consuming write under the same canonical service.
    pub unsafe fn write_ram_drain(
        &self,
        offset: u64,
        width: Width,
        value: u64,
        at: u64,
        memory: &CanonicalRamService<'_>,
    ) -> Result<(), &'static str> {
        self.live_drain(offset, width, memory)?;
        self.controller.record_ram_drain(offset, width, value, at)
    }
}
impl Lifecycle for NativeDcs {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        self.controller.check_lifecycle(proposed)
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        self.controller.set_lifecycle(proposed, access);
    }
}
impl MmioDevice for NativeDcs {
    fn name(&self) -> &'static str {
        self.controller.name()
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        self.controller.read(offset, width, access)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        self.controller.write(offset, width, value, access)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::dcs::native::{CHANNEL_STRIDE, CHANNELS, Effect, Request};
    const CONFIG_EC8: u64 = 0xec8;
    const CONFIG_ED0: u64 = 0xed0;
    const GATING: u64 = 0x18;
    const REFRESH: u64 = 0x41c;
    const DRAIN: u64 = 0xa40;
    use core::{cell::UnsafeCell, ptr::NonNull};
    use stela_contracts::interrupt::InterruptLatch;
    use stela_engine::memory::ReservedSystemRamRange;
    use stela_engine::memory::system_ram::fixture;

    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    #[repr(C, align(16))]
    struct Storage(UnsafeCell<[u8; 128]>);
    // SAFETY: after registration these stable fixture bytes have no ordinary
    // references; reached accesses participate in the actual fixture memory.
    unsafe impl Sync for Storage {}
    fn ram() -> Arc<RegisteredSystemRam> {
        let storage = Arc::new(Storage(UnsafeCell::new([0; 128])));
        let range = ReservedSystemRamRange {
            source_pa: 0x800000000,
            host_pa: 0x400000,
            host_base: NonNull::new(storage.0.get().cast()).unwrap(),
            bytes: 128,
        };
        // SAFETY: the registered fixture retains these complete stable bytes.
        Arc::new(unsafe { fixture(&[range], storage) })
    }
    fn configuration() -> Vec<ChannelConfiguration> {
        (0..CHANNELS)
            .map(|channel| ChannelConfiguration {
                ec8: 0x91ab_0000 + channel as u32,
                ed0: 0x4c00_0000 + channel as u32,
                gating: 0x8899_0000,
                drain_high: 0xa100 + channel as u16,
            })
            .collect()
    }
    fn controller(ram: &Arc<RegisteredSystemRam>) -> NativeDcs {
        NativeDcs::initialized(configuration(), LIVE, Arc::clone(ram)).unwrap()
    }

    #[test]
    fn all_eight_actual_channels_retain_their_own_opaque_control_images() {
        let ram = ram();
        let mut owner = controller(&ram);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 9, &mut latch);
        for channel in 0..CHANNELS {
            let base = channel as u64 * CHANNEL_STRIDE;
            assert_eq!(
                owner.read(base + CONFIG_EC8, Width::Word, &mut access),
                Ok(0x91ab_0000 + channel as u64)
            );
            assert_eq!(
                owner.read(base + CONFIG_ED0, Width::Word, &mut access),
                Ok(0x4c00_0000 + channel as u64)
            );
            assert_eq!(
                owner.read(base + REFRESH, Width::Word, &mut access),
                Ok(0x14a)
            );
            for offset in [0x4000, DRAIN] {
                assert!(owner.read(base + offset, Width::Word, &mut access).is_err());
            }
            assert!(
                owner
                    .read(base + CONFIG_EC8, Width::Double, &mut access)
                    .is_err()
            );
        }
        assert!(
            owner
                .read(
                    CHANNELS as u64 * CHANNEL_STRIDE + CONFIG_ED0,
                    Width::Word,
                    &mut access
                )
                .is_err()
        );
        assert_eq!(owner.progress(), [ChannelProgress::default(); CHANNELS]);
        assert!(
            NativeDcs::initialized(configuration()[..7].to_vec(), LIVE, Arc::clone(&ram)).is_err()
        );
        assert!(
            NativeDcs::initialized(
                configuration(),
                LifecycleState {
                    reset: true,
                    ..LIVE
                },
                Arc::clone(&ram)
            )
            .is_err()
        );
    }

    #[test]
    fn live_drain_requires_exact_ram_and_does_not_leave_an_ordinary_ready_word() {
        let ram = ram();
        let mut owner = controller(&ram);
        let foreign_ram = self::ram();
        let foreign = foreign_ram.try_service().unwrap().unwrap();
        let memory = ram.try_service().unwrap().unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 17, &mut latch);
        // SAFETY: this fixture has no native frames/jobs, asynchronous DMA or
        // external publishers; the exact registered all-writer services stay
        // held through each read/write. This is not production host admission.
        unsafe {
            assert!(owner.read_ram_drain(DRAIN, Width::Word, &foreign).is_err());
            assert!(owner.read_ram_drain(DRAIN, Width::Double, &memory).is_err());
            for channel in 0..CHANNELS {
                let offset = channel as u64 * CHANNEL_STRIDE + DRAIN;
                let expected = (0xa100 + channel as u64) << 16;
                assert!(owner.requires_ram_access(offset, Width::Word));
                assert_eq!(
                    owner.read_ram_drain(offset, Width::Word, &memory),
                    Ok(expected)
                );
                assert!(
                    owner
                        .write_ram_drain(offset, Width::Word, expected | 1, 17, &memory)
                        .is_err()
                );
                assert!(
                    owner
                        .write_ram_drain(offset, Width::Word, expected ^ (1 << 16), 17, &memory)
                        .is_err()
                );
                owner
                    .write_ram_drain(offset, Width::Word, expected, 17, &memory)
                    .unwrap();
                assert!(owner.read(offset, Width::Word, &mut access).is_err());
            }
        }
        for (channel, progress) in owner.progress().into_iter().enumerate() {
            assert_eq!(progress.completed_drains, 1);
            assert!(progress.pending_configuration.is_none());
            let request = progress.latest_drain.unwrap();
            assert_eq!(request.channel, channel);
            assert_eq!(request.serial, channel as u64 + 1);
            assert_eq!(
                request.effect,
                Effect::Drain {
                    preserved_high: 0xa100 + channel as u16
                }
            );
        }
    }

    #[test]
    fn pending_configuration_is_retained_and_never_becomes_a_drain_or_power_ack() {
        let ram = ram();
        let mut owner = controller(&ram);
        let mut alias = owner.clone();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(3, 77, &mut latch);
        for value in [0x8898_0000, 0x8899_1000] {
            assert!(
                owner
                    .write(GATING, Width::Word, value, &mut access)
                    .is_err()
            );
        }
        assert_eq!(owner.progress(), [ChannelProgress::default(); CHANNELS]);
        owner
            .write(GATING, Width::Word, 0x8899_1100, &mut access)
            .unwrap();
        assert_eq!(
            alias.progress()[0].pending_configuration,
            Some(Request {
                serial: 1,
                channel: 0,
                at: 77,
                effect: Effect::Configuration {
                    offset: GATING,
                    value: 0x8899_1100
                }
            })
        );
        assert!(alias.read(GATING, Width::Word, &mut access).is_err());
        assert!(
            alias
                .write(GATING, Width::Word, 0x8899_0000, &mut access)
                .is_err()
        );
        assert!(
            owner
                .check_lifecycle(LifecycleState {
                    clocked: false,
                    ..LIVE
                })
                .is_err()
        );
        let memory = ram.try_service().unwrap().unwrap();
        // SAFETY: same closed synchronous fixture producer set as above.
        unsafe {
            assert!(
                owner
                    .read_ram_drain(CHANNEL_STRIDE + DRAIN, Width::Word, &memory)
                    .is_err()
            );
        }
        assert_eq!(
            owner.progress()[0].pending_configuration,
            alias.progress()[0].pending_configuration
        );
        assert!(
            owner
                .progress()
                .iter()
                .all(|state| state.completed_drains == 0)
        );
    }

    #[test]
    fn retained_lifecycle_pauses_all_aliases_without_reinitializing_controls() {
        let ram = ram();
        let mut owner = controller(&ram);
        let mut alias = owner.clone();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 9, &mut latch);
        let paused = LifecycleState {
            clocked: false,
            ..LIVE
        };
        owner.check_lifecycle(paused).unwrap();
        owner.set_lifecycle(paused, &mut access);
        assert!(alias.read(CONFIG_ED0, Width::Word, &mut access).is_err());
        let memory = ram.try_service().unwrap().unwrap();
        // SAFETY: exact closed fixture producer set; lifecycle independently refuses.
        unsafe {
            assert!(alias.read_ram_drain(DRAIN, Width::Word, &memory).is_err());
        }
        alias.check_lifecycle(LIVE).unwrap();
        alias.set_lifecycle(LIVE, &mut access);
        assert_eq!(
            owner.read(CONFIG_ED0, Width::Word, &mut access),
            Ok(0x4c00_0000)
        );
        assert!(
            owner
                .check_lifecycle(LifecycleState {
                    reset: true,
                    ..LIVE
                })
                .is_err()
        );
        assert!(
            owner
                .check_lifecycle(LifecycleState {
                    powered: false,
                    retention: false,
                    ..LIVE
                })
                .is_err()
        );
    }
}
