//! The mount's own network client over the host's first network adapter:
//! the restore client's signing-server requests (`--tss`), the
//! connectivity check (`--network-check`) and a remote install image's
//! ranged downloads (`engine::remote`), which share it.
//!
//! UEFI's Simple Network Protocol ends with boot services, and the request
//! is made during the restore, long after ExitBootServices, so the client
//! runs the runtime's dual-stack client (`stela_runtime::net`) over the adapter's
//! after-EBS driver (`stela_drivers::net::virtio`, `stela_drivers::net::igc`
//! for an Intel I225/I226, `stela_drivers::net::e1000e` for an Intel 82574L,
//! `stela_drivers::net::igb` for supported Intel 82575–I211 copper adapters,
//! or `stela_drivers::usb::cdc` for a USB Ethernet
//! adapter). Its registers and DMA pages are identity-mapped in the
//! loader's root, so every frame moves inside that root
//! (`storage::RestoreRoot`), as block and input I/O do.
mod security;
use super::storage::RestoreRoot;
use crate::output;
use alloc::{format, rc::Rc, string::String, sync::Arc, vec::Vec};
use core::cell::RefCell;
use stela_drivers::{
    Clock,
    net::{Link, LinkError, Mac},
    probe::Adapter,
};
use stela_runtime::{
    machine::apple::AppleDevices,
    net::{
        HttpRequest, HttpTransfer, NetError, Stack, TlsUnavailable, Transfer,
        stack::DOWNLOAD_BUFFER,
    },
};

/// One restore-time opaque TCP relay window. TLS stays end to end between the
/// original Apple guest process and its requested server.
pub const RELAY_BUFFER: usize = 1 << 20;

/// What the screen says when DHCP gives the first adapter no lease.
const NO_LEASE: &str = "No automatic network address. Connect Ethernet or Wi-Fi to a network with DHCPv4 or IPv6 router advertisements, or use an Offline installer. Stateful DHCPv6 is unsupported.";

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
        // device.
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
    fn signals(&self) -> bool {
        self.device.signals()
    }
}

/// The PC's clock, moving the screen's running step as the stack waits.
struct Ticking(Clock);

impl stela_runtime::net::Clock for Ticking {
    fn now_us(&self) -> Result<u64, stela_runtime::net::ClockError> {
        crate::status::tick();
        self.0
            .try_now_us()
            .map_err(stela_runtime::net::ClockError::Calibration)
    }
    /// The adapter's completion signal wakes the boot processor, which runs
    /// the stack.
    fn sleep(&self, until_us: u64) -> Result<(), stela_runtime::net::ClockError> {
        let now = self
            .0
            .try_now_us()
            .map_err(stela_runtime::net::ClockError::Calibration)?;
        if until_us > now {
            super::host::sleep_for(until_us - now);
        }
        Ok(())
    }
}

pub struct HostNetwork {
    stack: Stack<RootLink, Ticking>,
    security: Result<Arc<stela_tls::ClientConfig>, TlsUnavailable>,
    /// The address and adapter, for the screen.
    description: String,
}

impl HostNetwork {
    /// Try each native adapter until DHCPv4 or IPv6 SLAAC provides a usable
    /// address. A failed adapter keeps its diagnostic while the next is tried.
    pub fn open(links: Links, clock: Clock) -> Result<Self, String> {
        let security = security::native();
        let mut failures = Vec::new();
        for device in links.devices {
            let location = String::from(device.location());
            output::arguments(format_args!(
                "NETWORK candidate driver={} adapter={location} mac={}\n",
                device.driver(),
                device.mac()
            ));
            crate::status::progress(&format!("adapter {location}"));
            let mut seed = [0u8; 8];
            crate::random::fill(&mut seed).map_err(|_| {
                String::from("secure host entropy is unavailable for the network stack")
            })?;
            let mut stack = Stack::new(
                RootLink {
                    device,
                    root: links.root,
                },
                Ticking(clock),
                u64::from_le_bytes(seed),
            )
            .map_err(|error| format!("{error}"))?;
            match stack.automatic() {
                Ok(config) => {
                    output::arguments(format_args!(
                        "NETWORK adapter={location} addresses={:?} dns={:?}\n",
                        config.addresses, config.dns
                    ));
                    let description = format!("{:?} on adapter {location}", config.addresses);
                    return Ok(Self {
                        stack,
                        description,
                        security,
                    });
                }
                Err(error) => {
                    output::arguments(format_args!("NETWORK adapter {location} failed: {error}\n"));
                    failures.push(format!("{location}: {error}"));
                }
            }
        }
        if failures.is_empty() {
            Err(String::from("no native host network adapter is available"))
        } else {
            Err(format!("{NO_LEASE} {}", failures.join("; ")))
        }
    }

    /// The address and adapter, as the screen names them.
    pub fn describe(&self) -> &str {
        &self.description
    }

    /// Initial plaintext endpoint used by the signing transport; redirects
    /// retain the full resulting URL and can never downgrade an HTTPS hop.
    pub fn post(
        &mut self,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        self.post_url(&format!("http://{host}{path}"), headers, content_type, body)
    }
    pub fn post_url(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        let result = self
            .stack
            .post_url(url, headers, content_type, body, self.security.clone());
        match &result {
            Ok(reply) => output::arguments(format_args!(
                "NETWORK POST {url} sent={} received={}\n",
                body.len(),
                reply.len()
            )),
            Err(error) => output::arguments(format_args!("NETWORK POST {url} refused: {error}\n")),
        }
        result
    }
    pub fn check_url(&self, url: &str) -> Result<(), NetError> {
        let destination = stela_runtime::net::http::Url::parse(url).map_err(NetError::Url)?;
        if destination.scheme == stela_runtime::net::http::Scheme::Https {
            self.security
                .as_ref()
                .map_err(|error| NetError::TlsUnavailable(*error))?;
        }
        Ok(())
    }
    pub fn download(
        &mut self,
        url: &str,
        first: u64,
        last: u64,
        etag: &str,
    ) -> Result<HttpTransfer, NetError> {
        self.stack.open_http(
            url,
            HttpRequest::range(first, last, Some(etag)),
            DOWNLOAD_BUFFER,
            self.security.clone(),
        )
    }
    pub fn read_download(
        &mut self,
        transfer: &mut HttpTransfer,
        take: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<bool, NetError> {
        self.stack.read_http(transfer, take)
    }
    pub fn close_download(&mut self, transfer: HttpTransfer) {
        self.stack.close_http(transfer);
    }

    pub fn close(&mut self, transfer: Transfer) {
        self.stack.close(transfer);
    }

    /// Waits up to `micros` for the adapter's next frame (`Stack::wait`).
    pub fn wait(&mut self, micros: u64) -> Result<(), NetError> {
        self.stack.wait(micros)
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
/// image; only the service reaches it, which one core at a time holds, so a
/// borrow never overlaps another.
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
