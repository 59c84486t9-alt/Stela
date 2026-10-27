//! The mount's own network client over the host's first network adapter:
//! the restore client's signing-server requests (`--tss`), the
//! connectivity check (`--network-check`) and a remote install image's
//! ranged downloads (`engine::remote`), which share it.
//!
//! UEFI's Simple Network Protocol ends with boot services, and the request
//! is made during the restore, long after ExitBootServices, so the client
//! runs the runtime's IPv4 stack (`stela_runtime::net`) over the adapter's
//! after-EBS driver (`stela_drivers::net::virtio`, `stela_drivers::net::igc`
//! for an Intel I225/I226, `stela_drivers::net::e1000e` for an Intel 82574L,
//! `stela_drivers::net::igb` for supported Intel 82575–I211 copper adapters,
//! or `stela_drivers::usb::cdc` for a USB Ethernet
//! adapter). Its registers and DMA pages are identity-mapped in the
//! loader's root, so every frame moves inside that root
//! (`storage::RestoreRoot`), as block and input I/O do.
use super::storage::RestoreRoot;
use crate::output;
use alloc::{format, rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;
use stela_drivers::{
    Clock,
    net::{Link, LinkError, Mac},
    probe::Adapter,
};
use stela_runtime::{
    machine::apple::AppleDevices,
    net::{NetError, Stack, Transfer, stack::DOWNLOAD_BUFFER},
};

/// One restore-time opaque TCP relay window. TLS stays end to end between the
/// original Apple guest process and its requested server.
pub const RELAY_BUFFER: usize = 1 << 20;

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
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        // SAFETY: as in `carrier`.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.device.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        // SAFETY: as in `carrier`.
        let _root = unsafe { RestoreRoot::enter(self.root) };
        self.device.receive()
    }
}

/// The PC's clock, moving the screen's running step as the stack waits.
struct Ticking(Clock);

impl stela_runtime::net::Clock for Ticking {
    fn now_us(&self) -> u64 {
        crate::status::tick();
        self.0.now_us()
    }
}

pub struct HostNetwork {
    stack: Stack<RootLink, Ticking>,
    /// The address and adapter, for the screen.
    description: String,
}

impl HostNetwork {
    /// The first adapter, configured by DHCP now so that a missing network
    /// is reported at mount start rather than in the middle of a restore.
    pub fn open(links: Links, clock: Clock) -> Result<Self, String> {
        let Some(device) = links.devices.into_iter().next() else {
            return Err(String::from(
                "no host network adapter: the mount drives virtio-net, Intel I225/I226, Intel 82574L, supported Intel 82575–I211 copper and USB CDC Ethernet adapters after ExitBootServices",
            ));
        };
        output::arguments(format_args!("NETWORK driver={}\n", device.driver()));
        output::arguments(format_args!(
            "NETWORK adapter {} mac={}\n",
            device.location(),
            device.mac()
        ));
        let location = String::from(device.location());
        crate::status::progress(&format!("adapter {location}"));
        let mut stack = Stack::new(
            RootLink {
                device,
                root: links.root,
            },
            Ticking(clock),
        );
        let config = stack.dhcp().map_err(|error| format!("{error}"))?;
        output::arguments(format_args!(
            "NETWORK address={} router={:?} dns={:?}\n",
            config.address, config.router, config.dns
        ));
        let description = format!("{} on adapter {location}", config.address.address());
        Ok(Self { stack, description })
    }

    /// The address and adapter, as the screen names them.
    pub fn describe(&self) -> &str {
        &self.description
    }

    /// One POST to `http://host/path`; the response body on a 2xx status.
    /// Plain HTTP: a TLS client is a follow-up.
    pub fn post(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        let result = self.stack.post(host, path, headers, content_type, body);
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

    /// Opens a download of `request`'s response from `host`.
    pub fn download(&mut self, host: &str, request: Vec<u8>) -> Result<Transfer, NetError> {
        self.stack.open(host, request, DOWNLOAD_BUFFER)
    }

    /// What has arrived for `transfer`, without waiting (`Stack::read`).
    pub fn read(
        &mut self,
        transfer: &mut Transfer,
        take: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<bool, NetError> {
        self.stack.read(transfer, take)
    }

    pub fn close(&mut self, transfer: Transfer) {
        self.stack.close(transfer);
    }

    /// Opens one opaque TCP stream for the restore reverse proxy.
    pub fn connect(&mut self, host: &str, port: u16) -> Result<Transfer, NetError> {
        self.stack.open_raw(host, port, RELAY_BUFFER)
    }

    /// Sends caller-retained opaque bytes, returning zero under backpressure.
    pub fn relay_write(
        &mut self,
        transfer: &mut Transfer,
        bytes: &[u8],
    ) -> Result<usize, NetError> {
        self.stack.write(transfer, bytes)
    }

    /// Receives opaque bytes. `take` owns framing and reports when the remote
    /// close has completed the relay.
    pub fn relay_read(
        &mut self,
        transfer: &mut Transfer,
        take: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<bool, NetError> {
        self.stack.read(transfer, take)
    }
}

/// The host network, shared by the signing transport and a remote install
/// image; the engine is serialized, so a borrow never overlaps another.
#[derive(Clone)]
pub struct Shared(pub Rc<RefCell<HostNetwork>>);

/// The restore client's way to Apple's signing service (`--tss`).
impl stela_runtime::restore::tss::Transport for Shared {
    fn post(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> stela_runtime::restore::Result<Vec<u8>> {
        self.0
            .borrow_mut()
            .post(host, path, headers, content_type, body)
            .map_err(|error| stela_runtime::restore::Error::Transport(format!("{error}")))
    }
}

/// The signing transport when the host network did not open: every request
/// is refused with the reason, so a restore stops at its first signing
/// request.
pub struct Offline(pub String);

impl stela_runtime::restore::tss::Transport for Offline {
    fn post(
        &mut self,
        host: &str,
        path: &str,
        _headers: &[(&str, &str)],
        _content_type: &str,
        _body: &[u8],
    ) -> stela_runtime::restore::Result<Vec<u8>> {
        Err(stela_runtime::restore::Error::Transport(format!(
            "no host network for http://{host}{path}: {}",
            self.0
        )))
    }
}

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
        // The guest's queues are the only bound: every frame it queued goes
        // out, and frames come in while its receive queue has room. The rest
        // wait in the host adapter's ring, which drops on overflow as the
        // hardware does.
        let frames: Vec<_> = core::iter::from_fn(|| devices.network_take()).collect();
        self.transmit(frames);
        while devices.network_room() {
            match self.link.receive() {
                Ok(Some(frame)) => {
                    // Without an attached adapter the frame has nowhere to go.
                    let _ = devices.network_deliver(&frame);
                }
                Ok(None) => break,
                Err(error) => {
                    self.refuse(error.into());
                    break;
                }
            }
        }
    }

    /// The frames the guest queued, taken from its devices, for
    /// [`Self::transmit`] to send without them.
    pub fn queued(devices: &mut AppleDevices) -> Vec<Vec<u8>> {
        core::iter::from_fn(|| devices.network_take()).collect()
    }

    pub fn transmit(&mut self, frames: Vec<Vec<u8>>) {
        for frame in frames {
            if let Err(error) = self.link.transmit(&frame) {
                self.refuse(error.into());
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
