//! Select a storage alternate before configuration, using this host's
//! stream policy. Capability planning never claims an endpoint configuration ACK.
use super::*;
use crate::usb::xhci::{Controller, FULL_SPEED, HIGH_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS};

/// One kept alternate and its endpoint inventory.
#[derive(Clone, Debug)]
pub enum Binding {
    Bot {
        interface: Interface,
        endpoints: [Endpoint; 2],
    },
    Uas(uas::Binding),
}
impl Binding {
    pub(crate) fn endpoints(&self) -> Vec<Endpoint> {
        match self {
            Self::Bot { endpoints, .. } => endpoints.to_vec(),
            Self::Uas(binding) => binding.endpoints().to_vec(),
        }
    }
    pub(crate) fn setting(&self) -> (u8, u8) {
        match self {
            Self::Bot { interface, .. } => (interface.number, interface.alternate),
            Self::Uas(binding) => (binding.interface(), binding.alternate()),
        }
    }
    pub(crate) fn uas(&self) -> bool {
        matches!(self, Self::Uas(_))
    }
}

pub(super) fn select(
    device: &Device,
    interface: &Interface,
    all: &[Interface],
    controller: Option<&Controller>,
) -> Result<Binding, &'static str> {
    let candidates = || {
        all.iter()
            .filter(|i| i.number == interface.number && i.class == CLASS && i.subclass == SCSI)
    };
    let mut failure = "no supported SCSI storage alternate";
    for candidate in candidates().filter(|i| i.protocol == 0x62) {
        let binding = match uas::Binding::new(device, candidate) {
            Ok(binding) => binding,
            Err(error) => {
                failure = error;
                continue;
            }
        };
        let endpoints = binding.endpoints();
        if endpoints
            .iter()
            .any(|e| e.validate_context(device.speed).is_err())
        {
            failure = "UAS has unsupported speed-specific endpoints";
            continue;
        }
        match device.speed {
            FULL_SPEED | HIGH_SPEED => return Ok(Binding::Uas(binding)),
            SUPER_SPEED | SUPER_SPEED_PLUS => {
                if let Some(controller) = controller
                    && controller
                        .stream_capacity_for_device(
                            device.id,
                            &endpoints,
                            &binding.stream_endpoints(),
                            uas::REQUESTED_STREAMS,
                        )
                        .is_ok()
                {
                    return Ok(Binding::Uas(binding));
                }
                failure = "UAS requires this host's qualified bulk stream capacity";
            }
            _ => failure = "unsupported UAS device speed",
        }
    }
    super::bot::supported(device)?;
    for candidate in candidates().filter(|i| i.protocol == BULK_ONLY) {
        let bulk = |input: bool| {
            candidate
                .endpoints
                .iter()
                .copied()
                .find(|e| e.kind() == 2 && e.is_in() == input)
        };
        if let (Some(input), Some(output)) = (bulk(true), bulk(false)) {
            if [input, output]
                .iter()
                .any(|e| e.validate_context(device.speed).is_err())
            {
                failure = "BOT has unsupported speed-specific endpoints";
                continue;
            }
            return Ok(Binding::Bot {
                interface: candidate.clone(),
                endpoints: [input, output],
            });
        }
        failure = "mass storage interface without two bulk endpoints";
    }
    Err(failure)
}

pub(in crate::usb) fn discover(
    controller: Shared,
    device: &Device,
    binding: Binding,
    dma: &mut dyn DmaAllocator,
    failures: &mut Vec<(String, BlockError)>,
) -> Result<(UsbStorage, Vec<UsbDisk>), BlockError> {
    match binding {
        Binding::Bot {
            interface,
            endpoints,
        } => {
            if interface.alternate != 0 {
                controller.borrow_mut().device(device.id)?.control(
                    setup(
                        0x01,
                        crate::usb::descriptor::SET_INTERFACE,
                        u16::from(interface.alternate),
                        u16::from(interface.number),
                        0,
                    ),
                    &[],
                )?;
            }
            super::discover_retained(controller, device, &interface, endpoints, dma, failures)
        }
        Binding::Uas(binding) => {
            // SAFETY: the one binder acknowledged this exact configuration and
            // owns disjoint interface/endpoint settings. Its common endpoint
            // pass excludes UAS; this constructor alone configures all four.
            unsafe { super::discover_uas_retained(controller, device, binding, dma, failures) }
        }
    }
}
