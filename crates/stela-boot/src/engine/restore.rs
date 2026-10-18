//! Opt-in, unqualified restore option experiment. The host source is an exact
//! read-only IPSW extent on an explicitly selected partition. It is never an
//! ANS namespace or a pointer into translated memory. Live USB qualification
//! and the complete intact SEP trust route remain research requirements.
use super::bundle::{self, Bytes};
use crate::{handoff::Handoff, output};
use alloc::{boxed::Box, format, string::String};
use core::task::Poll;
use stela_runtime::{
    machine::apple::{AppleDevices, MuxStream, UsbId},
    payload::PayloadManifest,
    pc::block::BlockDevice,
    restore::{answers::Answers, driver::Driver, route::Route, source::Extent, store::Store},
};
type Reader = Extent<Bytes<Box<dyn BlockDevice>>>;
pub struct Experiment {
    usb: UsbId,
    driver: Driver<Reader, MuxStream>,
    terminal: bool,
    ledger: usize,
}
impl Experiment {
    pub fn new(
        source: Box<dyn BlockDevice>,
        usb: UsbId,
        handoff: &Handoff,
        identity: usize,
    ) -> Result<Self, String> {
        let file = handoff.files[..handoff.file_count]
            .iter()
            .find(|f| f.name() == "restore-payload.json")
            .ok_or("restore inventory was not loaded")?;
        let manifest =
            PayloadManifest::parse(bundle::contents(file)).map_err(|e| format!("{e}"))?;
        let reader =
            Extent::new(Bytes::new(source), manifest.source.bytes).map_err(|e| format!("{e}"))?;
        output::arguments(format_args!(
            "RESTORE STUDY UNQUALIFIED build={} source_sha256={} manifest_sha256={} identity={} bytes={}\n",
            manifest.product_build,
            manifest.source.sha256,
            manifest.source.build_manifest_sha256,
            identity,
            manifest.source.bytes
        ));
        let store = Store::open(reader, manifest, identity).map_err(|e| format!("{e}"))?;
        let driver = Driver::new(Answers::new(store), Route::StelaFirmwareStudy)
            .map_err(|e| format!("{e}"))?;
        Ok(Self {
            usb,
            driver,
            terminal: false,
            ledger: 0,
        })
    }
    pub fn poll(&mut self, devices: &mut AppleDevices) {
        if self.terminal {
            return;
        }
        let mut client = devices
            .usb_client(self.usb)
            .unwrap_or_else(|e| output::fatal(e));
        let result = self.driver.poll(&mut client);
        for message in &self.driver.session.ledger()[self.ledger..] {
            output::arguments(format_args!("RESTORE STUDY ledger={message:?}\n"));
        }
        self.ledger = self.driver.session.ledger().len();
        match result {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.terminal = true;
                output::arguments(format_args!(
                    "RESTORE STUDY protocol complete; installed boot is unqualified\n"
                ));
            }
            Poll::Ready(Err(error)) => {
                output::arguments(format_args!("RESTORE STUDY REFUSED {error}\n"));
                // Preserve the guest stop context and refuse further writes.
                // The experiment has no automatic reboot/retry or fallback.
                output::fatal("restore study failed; inspect the session ledger")
            }
        }
    }
}
