//! Owned NHI transport retirement; router/tunnel/root removal is separate.
use super::{Connection, Host, Refusal, transport::SharedChannel};
use crate::bus::{
    dma::mapping::DmaError,
    irq::IrqError,
    pci::{ConfigSpace, Function, owned::OwnedConfig, requester::preparation::Attachment},
    thunderbolt::cold::{self, MappedRegisters},
};
use alloc::{boxed::Box, sync::Arc};
use core::mem::ManuallyDrop;

pub(super) struct Owners {
    pub(super) function: Function<OwnedConfig>,
    pub(super) attachment: Attachment,
    pub(super) registers: Arc<MappedRegisters>,
    pub(super) software: Option<Arc<SharedChannel>>,
    pub(super) minimum: alloc::rc::Rc<dyn crate::bus::pci::power::Timer>,
}
struct Resources {
    location: alloc::string::String,
    connection: Option<Box<Connection>>,
    owners: ManuallyDrop<Box<Owners>>,
}
struct Kept(Option<Box<Resources>>);
impl Drop for Kept {
    fn drop(&mut self) {
        core::mem::forget(self.0.take());
    }
}
#[derive(Debug)]
pub enum Error {
    Protocol(Refusal),
    Config(crate::bus::pci::ConfigError),
    Reset(cold::Error),
    Dma(DmaError),
    Irq(IrqError),
    Identity,
    BusMaster,
}
pub struct Failure {
    pub error: Error,
    _retained: Kept,
}
/// The NHI host transport has stopped/unmapped/detached. This still retains the
/// actual CM/router/tunnel/platform/configuration/MMIO/root graph; it grants no
/// whole USB4 domain, sibling tunnel, power or global notification-root teardown.
pub struct RetiredTransport {
    kept: Kept,
}
impl RetiredTransport {
    pub fn location(&self) -> &str {
        &self.kept.0.as_ref().expect("retained USB4 graph").location
    }
}

impl Host {
    /// Retire this actual polled NHI transport, retaining its topology graph.
    ///
    /// # Safety
    /// Original owning CPU/root process/deferred context and calibrated clock;
    /// no concurrent configuration/reset/removal/shared-power writer exists.
    /// Prior firmware IRQ/work ownership was genuinely excluded by the original
    /// cold platform grant. This transport published no Stela IRQ action (all
    /// rings are NO_INTERRUPT, MSI/MSI-X/INTx remain disabled); it cannot be used
    /// for a later interrupt-enabled transport. Original root/control/format
    /// remains retained for late notifications. Peer/bypass traffic is separately
    /// excluded/drained. No sibling tunnel/root reset or removal is authorized.
    #[expect(
        clippy::result_large_err,
        reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
    )]
    pub unsafe fn retire_transport(self) -> Result<RetiredTransport, Failure> {
        let Host {
            location,
            connection,
            _owners: owners,
        } = self;
        let mut kept = Kept(Some(Box::new(Resources {
            location,
            connection: Some(ManuallyDrop::into_inner(connection)),
            owners,
        })));
        let result = (|| {
            let resources = kept.0.as_deref_mut().expect("original USB4 host");
            let owners = &mut **resources.owners;
            owners.minimum.check().map_err(|error| {
                Error::Reset(cold::Error::Reset(crate::block::BlockError::PciPower(
                    error,
                )))
            })?;
            if !owners
                .attachment
                .matches_config(owners.function.config())
                .map_err(Error::Dma)?
            {
                return Err(Error::Identity);
            }
            owners
                .registers
                .check(&mut owners.function)
                .map_err(Error::Reset)?;
            // Match actual native register owner, not BDF/label. Moving/swapping
            // an ICM value between two public connections cannot stop its peer.
            match (
                resources
                    .connection
                    .as_deref_mut()
                    .expect("original connection"),
                &owners.software,
            ) {
                (Connection::Firmware { icm, .. }, None) => {
                    if !icm.shares_registers(&owners.registers) {
                        return Err(Error::Identity);
                    }
                }
                (Connection::Software { .. }, Some(_)) => {}
                _ => return Err(Error::Identity),
            }
            // Gate the real software sender and join all NHI accesses under its
            // lock. Keeping the future retains routers/tunnels/platform owners;
            // no mask/readback is represented as interrupt/work completion.
            match (
                resources
                    .connection
                    .as_deref_mut()
                    .expect("original connection"),
                &owners.software,
            ) {
                (Connection::Firmware { icm, .. }, None) => icm
                    .disable()
                    .map_err(|error| Error::Protocol(Refusal::Icm(error)))?,
                (Connection::Software { .. }, Some(channel)) => channel
                    .close()
                    .map_err(|error| Error::Protocol(Refusal::Channel(error)))?,
                _ => unreachable!(),
            }
            let command = owners.function.config().read16(4).map_err(Error::Config)?;
            if command == u16::MAX {
                return Err(Error::BusMaster);
            }
            owners
                .function
                .set_bus_master(false)
                .map_err(Error::Config)?;
            // Full supported PCI FLR discards latent old NHI jobs; merely
            // disabled options/HRR/polled indices could not prove this boundary.
            cold::reset(&mut owners.function, owners.minimum.as_ref()).map_err(Error::Reset)?;
            owners
                .registers
                .check(&mut owners.function)
                .map_err(Error::Reset)?;
            owners
                .attachment
                .validate_irq_actions()
                .map_err(Error::Irq)?;
            let domain = owners.attachment.domain();
            // SAFETY: actual source publishers closed, supported FLR stopped
            // this same function, all backing/control owners remain retained.
            unsafe { domain.drain_posted_writes() }.map_err(Error::Dma)?;
            match (
                resources
                    .connection
                    .as_deref_mut()
                    .expect("original connection"),
                &owners.software,
            ) {
                (Connection::Firmware { icm, .. }, None) => {
                    // SAFETY: exact original host rings, real FLR/payload drain,
                    // source-excluded IRQ/work and no reentry after disable.
                    unsafe { icm.release() }
                        .map_err(|error| Error::Protocol(Refusal::Icm(error)))?;
                }
                (Connection::Software { .. }, Some(channel)) => {
                    // SAFETY: exact actual permanently closed channel, same
                    // FLR/payload/IRQ proof; the kept future cannot touch rings.
                    unsafe { channel.release() }
                        .map_err(|error| Error::Protocol(Refusal::Channel(error)))?;
                }
                _ => unreachable!(),
            }
            if owners.software.is_none() {
                // Firmware ICM has no software topology/platform owner inside
                // its host transport. Its actual rings were released, so free
                // CPU buffers now. Firmware-owned tunnels remain independent.
                drop(resources.connection.take());
            }
            // SAFETY: same function stopped; own payload completed and every
            // transport DMA mapping quiescently unmapped. No Stela action/grant
            // was published; concrete Attachment checks actual pending/action
            // state and original root before detaching. Old root stays retained.
            let detached = unsafe { owners.attachment.detach() }.map_err(Error::Dma)?;
            owners
                .attachment
                .release_irq_pins(detached)
                .map_err(|failed| Error::Irq(failed.error))?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(RetiredTransport { kept }),
            Err(error) => Err(Failure {
                error,
                _retained: kept,
            }),
        }
    }
}
