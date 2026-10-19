//! The mount's own network client: one HTTP POST at a time over the host's
//! first network adapter, for the restore client's signing-server request
//! (`--tss`) and the connectivity check (`--network-check`).
//!
//! UEFI's Simple Network Protocol ends with boot services, and the request
//! is made during the restore, long after ExitBootServices, so the client
//! runs the runtime's IPv4 stack (`stela_runtime::net`) over the adapter's
//! after-EBS driver (`pc::virtio_net`, or `pc::xhci::ecm` for a USB
//! Ethernet adapter). Its registers and DMA pages are
//! identity-mapped in the loader's root, so every frame moves inside that
//! root (`storage::RestoreRoot`), as block and input I/O do.
use super::storage::RestoreRoot;
use crate::output;
use alloc::{format, string::String, vec::Vec};
use stela_runtime::{
    machine::apple::AppleDevices,
    net::{Link, Mac, NetError, Stack},
    pc::{self, storage::Adapter},
};

/// The host's network adapters and the loader root they are reached in.
pub struct Links {
    pub devices: Vec<Adapter>,
    pub root: u64,
}

struct RootLink {
    device: Adapter,
    root: u64,
}

impl Link for RootLink {
    fn mac(&self) -> Mac {
        self.device.mac()
    }
    fn carrier(&mut self) -> bool {
        // SAFETY: the loader root `storage::open` captured maps this
        // device; the engine is serialized.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.device.carrier()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        // SAFETY: as in `carrier`.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.device.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, NetError> {
        // SAFETY: as in `carrier`.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.device.receive()
    }
}

pub struct HostNetwork {
    stack: Stack<RootLink, pc::Clock>,
}

impl HostNetwork {
    /// The first adapter, configured by DHCP now so that a missing network
    /// fails at mount start rather than in the middle of a restore.
    pub fn open(links: Links, clock: pc::Clock) -> Result<Self, String> {
        let Some(device) = links.devices.into_iter().next() else {
            return Err(String::from(
                "no host network adapter: the mount drives virtio-net and USB CDC-ECM adapters after ExitBootServices",
            ));
        };
        output::arguments(format_args!(
            "NETWORK adapter {} mac={}\n",
            device.location(),
            device.mac()
        ));
        let mut stack = Stack::new(
            RootLink {
                device,
                root: links.root,
            },
            clock,
        );
        let config = stack.dhcp().map_err(|error| format!("{error}"))?;
        output::arguments(format_args!(
            "NETWORK address={} mask={} router={:?} dns={:?}\n",
            config.address, config.mask, config.router, config.dns
        ));
        Ok(Self { stack })
    }

    /// One POST to `http://host/path`; the response body on a 2xx status.
    /// Plain HTTP: a TLS client is a follow-up.
    pub fn post(
        &mut self,
        host: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        let result = self.stack.post(host, path, &[], content_type, body);
        match &result {
            Ok(reply) => output::arguments(format_args!(
                "NETWORK POST http://{host}{path} sent={} received={}\n",
                body.len(),
                reply.len()
            )),
            Err(error) => output::arguments(format_args!(
                "NETWORK POST http://{host}{path} refused: {error}\n"
            )),
        }
        result
    }
}

/// The restore client's way to Apple's signing service (`--tss`).
impl stela_runtime::restore::tss::Transport for HostNetwork {
    fn post(
        &mut self,
        host: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> stela_runtime::restore::Result<Vec<u8>> {
        HostNetwork::post(self, host, path, content_type, body)
            .map_err(|error| stela_runtime::restore::Error::Transport(format!("{error}")))
    }
}

/// Frames moved each way per poll, so a busy link cannot hold the engine.
const FRAMES_PER_POLL: usize = 32;

/// The guest's USB Ethernet adapter bridged to a host adapter of its own
/// (`--guest-network`). The adapter keeps the host adapter's station
/// address, so the guest is that adapter on the host's network and the
/// adapter needs no promiscuous mode. Frames move between engine slices.
pub struct GuestNetwork {
    link: RootLink,
    up: Option<bool>,
    /// The first link refusal, reported once.
    refused: bool,
}

impl GuestNetwork {
    /// The second adapter when the mount's own client (`wants_client`)
    /// keeps the first, otherwise the first.
    pub fn open(links: &mut Links, wants_client: bool) -> Result<Self, String> {
        let index = usize::from(wants_client);
        if links.devices.len() <= index {
            return Err(format!(
                "the guest network needs host network adapter {} of its own; {} found",
                index + 1,
                links.devices.len()
            ));
        }
        let device = links.devices.remove(index);
        output::arguments(format_args!(
            "GUEST NETWORK adapter {} mac={}\n",
            device.location(),
            device.mac()
        ));
        Ok(Self {
            link: RootLink {
                device,
                root: links.root,
            },
            up: None,
            refused: false,
        })
    }

    pub fn mac(&self) -> Mac {
        self.link.mac()
    }

    pub fn poll(&mut self, devices: &mut AppleDevices) {
        let status = devices.network_status();
        let up = status.is_some_and(|(up, _)| up);
        if self.up != Some(up) {
            self.up = Some(up);
            let counters = status.map(|(_, counters)| counters).unwrap_or_default();
            output::arguments(format_args!(
                "GUEST NETWORK link {} {counters:?}\n",
                if up { "up" } else { "down" }
            ));
        }
        for _ in 0..FRAMES_PER_POLL {
            let Some(frame) = devices.network_take() else {
                break;
            };
            if let Err(error) = self.link.transmit(&frame) {
                self.refuse(error);
            }
        }
        for _ in 0..FRAMES_PER_POLL {
            match self.link.receive() {
                Ok(Some(frame)) => {
                    // Without an attached adapter the frame has nowhere to go.
                    let _ = devices.network_deliver(&frame);
                }
                Ok(None) => break,
                Err(error) => {
                    self.refuse(error);
                    break;
                }
            }
        }
    }

    fn refuse(&mut self, error: NetError) {
        if !core::mem::replace(&mut self.refused, true) {
            output::arguments(format_args!("GUEST NETWORK refused: {error}\n"));
        }
    }
}

/// `http://HOST[:PORT]/PATH` as the host and the path.
pub fn split_url(url: &str) -> Result<(&str, &str), &'static str> {
    let rest = url
        .strip_prefix("http://")
        .ok_or("only http:// URLs are supported")?;
    let at = rest.find('/').ok_or("URL without a path")?;
    let (host, path) = rest.split_at(at);
    if host.is_empty() {
        return Err("URL without a host");
    }
    Ok((host, path))
}
