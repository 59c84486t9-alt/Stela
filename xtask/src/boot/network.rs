//! A run's networks: the host peers each adapter talks to, and the
//! network check the mount runs over them.
use super::{NetworkModel, Run, lan, network_check};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command as Process};

/// The network check a run asks the mount for: `--network-check URL`, or
/// `--network-self-check`'s fixture and its URL.
pub(super) struct Check {
    fixture: Option<network_check::Fixture>,
    url: Option<String>,
    /// The TCP port a requested URL names, which the peer must have seen.
    port: Option<u16>,
}

impl Check {
    /// Start the fixture, and name the check's URL in `options`.
    pub(super) fn start(arguments: &Run, options: &mut String) -> Result<Self> {
        let fixture = arguments
            .network_self_check
            .then(network_check::Fixture::start)
            .transpose()?;
        let url = arguments
            .network_check
            .clone()
            .or_else(|| fixture.as_ref().map(|fixture| fixture.url.clone()));
        if let Some(url) = &url {
            let https = url.starts_with("https://");
            ensure!(
                (https || url.starts_with("http://")) && !url.contains(char::is_whitespace),
                "the network check is one http:// or https:// URL"
            );
            ensure!(
                !https || arguments.kvm,
                "an https:// network check needs --kvm: native TLS dates certificates by the invariant TSC, which TCG does not offer"
            );
            options.push_str(&format!(" --network-check {url}"));
        }
        let port = arguments
            .network_check
            .as_deref()
            .map(network_check::port)
            .transpose()?;
        Ok(Self { fixture, url, port })
    }

    /// Check what the mount reported against the peer's log. The check's
    /// peer bytes are kept in `network-check-peer.txt`, as the listener may
    /// still append to its log.
    pub(super) fn verify(
        &self,
        arguments: &Run,
        output: &Path,
        serial: &str,
    ) -> Result<Option<Result<Value, network_check::VerificationError>>> {
        let peer_path = output.join(if arguments.usb_network {
            "usb-network.log"
        } else {
            "network.log"
        });
        let peer = fs::read_to_string(peer_path).unwrap_or_default();
        let snapshot = self
            .fixture
            .as_ref()
            .map(|_| output.join("network-check-peer.txt"));
        if let Some(path) = &snapshot {
            fs::write(path, &peer)?;
        }
        let driver = expected_driver(arguments);
        Ok(self.url.as_ref().map(|url| {
            network_check::verify(serial, self.fixture.as_ref(), self.port, driver, &peer)?;
            Ok(json!({
                "passed": true,
                "url": url,
                "driver": driver,
                "peer_snapshot": snapshot,
                "expected_body": self.fixture.as_ref().map(|fixture| json!({
                    "bytes": network_check::BODY_BYTES,
                    "sha256": fixture.sha256,
                })),
                "model": if arguments.usb_network {
                    "usb-net"
                } else {
                    arguments.network_model.unwrap_or(NetworkModel::Virtio).device()
                },
            }))
        }))
    }
}

/// The driver the mount must report the check through.
fn expected_driver(arguments: &Run) -> &'static str {
    if arguments.usb_network {
        "usb-cdc"
    } else {
        match arguments.network_model.unwrap_or(NetworkModel::Virtio) {
            NetworkModel::Virtio => "virtio-net",
            NetworkModel::E1000e => "e1000e",
            NetworkModel::Igb => "igb",
        }
    }
}

/// `--network`'s adapter for the mount, then `--guest-network`'s, each with
/// its own peer. The guest's comes second, so the mount gives the guest the
/// second adapter when both are present.
pub(super) fn attach(arguments: &Run, output: &Path, command: &mut Process) -> Result<()> {
    if arguments.network {
        let port = lan::listen(output.join("network.log")).context("start the network peer")?;
        let model = arguments.network_model.unwrap_or(NetworkModel::Virtio);
        let bus = match model {
            NetworkModel::E1000e | NetworkModel::Igb => {
                // Exercise physical NIC drivers behind a PCIe bridge. For
                // e1000e this also checks the endpoint/parent ASPM workaround.
                command.args([
                    "-device",
                    "pcie-root-port,id=host-net-port,chassis=1,bus=pcie.0",
                ]);
                ",bus=host-net-port"
            }
            NetworkModel::Virtio => "",
        };
        command
            .arg("-netdev")
            .arg(format!(
                "stream,id=host-net,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={port}"
            ))
            .arg("-device")
            .arg(format!("{},netdev=host-net{bus}", model.device()));
    }
    if arguments.guest_network {
        let port = lan::listen(output.join("guest-network.log"))
            .context("start the guest network peer")?;
        command
            .arg("-netdev")
            .arg(format!(
                "stream,id=guest-net,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={port}"
            ))
            .args(["-device", "virtio-net-pci,netdev=guest-net"]);
    }
    Ok(())
}

/// `--usb-network`'s CDC adapter on the host's USB controller.
pub(super) fn attach_usb(arguments: &Run, output: &Path, command: &mut Process) -> Result<()> {
    if arguments.usb_network {
        let port =
            lan::listen(output.join("usb-network.log")).context("start the USB network peer")?;
        command
            .arg("-netdev")
            .arg(format!(
                "stream,id=usb-net,server=off,addr.type=inet,addr.host=127.0.0.1,addr.port={port}"
            ))
            .args(["-device", "usb-net,netdev=usb-net,bus=host-usb.0"]);
    }
    Ok(())
}
