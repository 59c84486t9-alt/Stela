//! Binding each interface of a configured device to its class driver.
use super::*;

/// Binds every interface of `device` a driver here takes: one
/// configuration, its endpoints configured together.
#[cfg(test)]
pub(crate) fn bind(shared: &Shared, device: Device, dma: &mut dyn DmaAllocator, found: &mut Found) {
    bind_with_provider(
        shared,
        device,
        dma,
        found,
        &crate::firmware::HandoffProvider::new(None),
    );
}

pub(crate) fn bind_with_provider(
    shared: &Shared,
    device: Device,
    dma: &mut dyn DmaAllocator,
    found: &mut Found,
    firmware: &dyn crate::firmware::Provider,
) {
    let all = interfaces(&device.configuration);
    let mut endpoints = Vec::new();
    let mut plans = Vec::new();
    let mut selected_settings = Vec::new();
    for interface in all.iter().filter(|i| configuration::primary(i)) {
        let plan =
            configuration::plan_with_controller(&device, interface, &all, Some(&shared.borrow()));
        match plan {
            Ok(plan) => {
                selected_settings.extend(plan.settings(interface.number));
                if !matches!(&plan, Plan::Storage(binding) if binding.uas()) {
                    endpoints.extend(plan.endpoints().iter().copied());
                }
                plans.push((interface.clone(), plan));
            }
            Err(why) => found.unused.push((
                format!(
                    "{} interface {} ({:02x}/{:02x}/{:02x})",
                    device.location,
                    interface.number,
                    interface.class,
                    interface.subclass,
                    interface.protocol
                ),
                why,
            )),
        }
    }
    if plans.is_empty() {
        return;
    }
    // Revalidate the actual plans immediately before SET_CONFIGURATION. A
    // controller error since inventory selection may now force UAS to BOT.
    if let Err(reason) = configuration::active_settings(&all, &selected_settings) {
        found
            .failures
            .push((device.location.clone(), BlockError::Unsupported(reason)));
        return;
    }
    let configured = {
        let mut controller = shared.borrow_mut();
        let value = device.configuration_value();
        during(
            format!("slot {} EP0 SET_CONFIGURATION value={value}", device.slot),
            controller.set_configuration(device.slot, value),
        )
        .and_then(|()| {
            if endpoints.is_empty() {
                Ok(())
            } else {
                during(
                    format!("slot {} Configure Endpoint", device.slot),
                    controller.configure(device.slot, &endpoints, None, dma),
                )
            }
        })
    };
    if let Err((operation, error)) = configured {
        found.failures.push((
            format!("{} {} {operation}", device.location, device.name()),
            error,
        ));
        return;
    }
    for (interface, plan) in plans {
        let location = format!("{} interface {}", device.location, interface.number);
        crate::working(&location);
        let result = match plan {
            Plan::Storage(binding) => storage::discover_binding(
                shared.clone(),
                &device,
                binding,
                dma,
                &mut found.failures,
            )
            .map(|(owner, disks)| {
                found.storage.push(owner);
                found.disks.extend(disks);
            }),
            Plan::Hid(endpoint) => {
                hid::UsbInput::new(shared.clone(), &device, &interface, endpoint, dma).map(
                    |input| match input {
                        Some(input) => found.inputs.push(input),
                        None => found.unused.push((location.clone(), hid::NO_REPORTS)),
                    },
                )
            }
            Plan::Ethernet(plan) => cdc::UsbNet::new(shared.clone(), &device, plan, dma)
                .map(|link| found.links.push(link)),
            Plan::VendorEthernet(binding) => {
                match ethernet::UsbEthernet::new(shared.clone(), &device, binding, dma, firmware) {
                    Ok(link) => found.vendor_links.push(link),
                    Err(error) => found.vendor_failures.push((location.clone(), error)),
                }
                Ok(())
            }
            Plan::Audio(binding) => audio::UsbAudio::attach(shared.clone(), &device, binding, dma)
                .map(|owner| found.audio.push(owner)),
            Plan::BluetoothBootloader(binding) => {
                bluetooth::ath3k::UsbBootloader::attach(shared.clone(), binding, dma).map(
                    |mut owner| {
                        let _ = owner.initialize_with_provider(firmware);
                        found.bootloaders.push(owner);
                    },
                )
            }
            Plan::Bluetooth(binding) => {
                bluetooth::UsbHci::attach(shared.clone(), &device, binding, dma)
                    .map(|transport| found.bluetooth.push(transport))
            }
        };
        if let Err(error) = result {
            found.failures.push((location, error));
        }
    }
}

/// What a class driver will use of an interface.
pub enum Plan {
    /// UAC2 function, initially at zero-bandwidth streaming alternates.
    Audio(audio::Binding),
    /// Bulk IN, bulk OUT.
    Storage(storage::Binding),
    /// The interrupt IN endpoint.
    Hid(Endpoint),
    /// A CDC Ethernet adapter's interfaces and endpoints.
    Ethernet(cdc::Binding),
    /// A vendor Ethernet candidate whose constructor validates chip startup.
    VendorEthernet(ethernet::Binding),
    /// Legacy Bluetooth HCI interrupt and bulk endpoints.
    Bluetooth(bluetooth::Binding),
    /// Pre-HCI raw firmware downloader, terminal until real reenumeration.
    BluetoothBootloader(bluetooth::ath3k::Binding),
}

impl Plan {
    pub(super) fn settings(&self, interface: u8) -> Vec<(u8, u8)> {
        match self {
            Self::Audio(binding) => binding.settings(),
            Self::Storage(binding) => vec![binding.setting()],
            Self::VendorEthernet(binding) => vec![binding.setting()],
            Self::Ethernet(binding) => vec![(interface, 0), binding.data_setting()],
            _ => vec![(interface, 0)],
        }
    }
    pub(super) fn endpoints(&self) -> Vec<Endpoint> {
        match self {
            Self::Audio(_) => Vec::new(),
            Self::Storage(binding) => binding.endpoints(),
            Self::Hid(endpoint) => vec![*endpoint],
            Self::Ethernet(binding) => binding.endpoints(),
            Self::VendorEthernet(binding) => binding.endpoints(),
            Self::Bluetooth(binding) => binding.endpoints(),
            Self::BluetoothBootloader(binding) => binding.endpoints(),
        }
    }
}
