//! The mount's own network client: one HTTP POST at a time over the host's
//! first network adapter, for the restore client's signing-server request
//! (`--tss`) and the connectivity check (`--network-check`).
//!
//! UEFI's Simple Network Protocol ends with boot services, and the request
//! is made during the restore, long after ExitBootServices, so the client
//! runs the runtime's IPv4 stack (`stela_runtime::net`) over the adapter's
//! after-EBS driver (`pc::virtio_net`). Its registers and DMA pages are
//! identity-mapped in the loader's root, so every frame moves inside that
//! root (`storage::RestoreRoot`), as block and input I/O do.
use super::storage::RestoreRoot;
use crate::output;
use alloc::{format, string::String, vec::Vec};
use stela_runtime::{
    net::{Link, Mac, NetError, Stack},
    pc::{self, virtio_net::VirtioNet},
};

/// The host's network adapters and the loader root they are reached in.
pub struct Links {
    pub devices: Vec<VirtioNet>,
    pub root: u64,
}

struct RootLink {
    device: VirtioNet,
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
                "no host network adapter: the mount drives virtio-net after ExitBootServices",
            ));
        };
        output::arguments(format_args!(
            "NETWORK adapter {} mac={}\n",
            device.location,
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
