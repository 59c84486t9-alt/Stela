//! The restore host: Stela's native restore client driving the guest's
//! `restored` over the USB controller's device port.
//!
//! Two sources feed it. The install medium (`--install`) is the IPSW as
//! pieces on the USB's FAT32 partition. [`Mode::Install`] erases the stick
//! SSD and installs recoveryOS without the macOS system image; macOS is
//! installed from recoveryOS. [`Mode::Update`] (`--update-restore`) runs
//! Apple's stock update. The opt-in, unqualified option study
//! (`--restore-study`) reads an exact IPSW extent on an explicitly selected
//! raw partition with the study's options ([`Mode::Study`]). Neither source
//! is an ANS namespace or a pointer into translated memory. Live USB
//! qualification and the complete intact SEP trust route remain research
//! requirements.
use super::bundle::{self, Bytes};
use crate::{
    handoff::Handoff,
    output,
    system::{RESTORE_BLOCKS_FILE, RESTORE_INVENTORY_FILE},
};
use alloc::{boxed::Box, format, string::String};
use core::task::Poll;
use stela_drivers::block::BlockDevice;
use stela_runtime::{
    machine::apple::{AppleDevices, MuxStream, UsbId},
    payload::{PayloadManifest, Purpose, ReadAt},
    restore::{
        answers::Answers,
        driver::Driver,
        route::Route,
        source::Extent,
        store::{Store, Verify},
    },
};

/// The bundle's boot manifest (`stela_loader::boot_bundle`).
const BOOT_MANIFEST_FILE: &str = "boot-manifest.im4m";

/// Which restore the host runs, and how it reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The user's install: the inventory's Erase identity, restored without
    /// the macOS system image ([`Route::Recovery`]).
    Install,
    /// The same, with the inventory's Update identity: restored_update
    /// installs over the installed system and keeps its data.
    Update,
    /// The option study, with its explicit identity.
    Study,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Install => "INSTALL",
            Self::Update => "UPDATE",
            Self::Study => "RESTORE STUDY",
        }
    }
}

/// Any IPSW source, its errors described.
pub struct Source(Box<dyn ReadAt<Error = String>>);

struct Described<R>(R);

impl<R: ReadAt> ReadAt for Described<R> {
    type Error = String;
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), String> {
        self.0.read_at(offset, buffer).map_err(|e| format!("{e:?}"))
    }
}

impl Source {
    pub fn new<R: ReadAt + 'static>(reader: R) -> Self {
        Self(Box::new(Described(reader)))
    }

    /// The study's raw source: the IPSW from the partition's first byte.
    pub fn extent(partition: Box<dyn BlockDevice>, bytes: u64) -> Result<Self, String> {
        Ok(Self::new(
            Extent::new(Bytes::new(partition), bytes).map_err(|e| format!("{e}"))?,
        ))
    }
}

impl ReadAt for Source {
    type Error = String;
    fn len(&self) -> u64 {
        self.0.len()
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), String> {
        self.0.read_at(offset, buffer)
    }
}

/// The restore inventory the loader read.
pub fn inventory(handoff: &Handoff) -> Result<PayloadManifest, String> {
    let file = handoff.files[..handoff.file_count]
        .iter()
        .find(|f| f.name() == RESTORE_INVENTORY_FILE)
        .ok_or("restore inventory was not loaded")?;
    PayloadManifest::parse(bundle::contents(file)).map_err(|e| format!("{e}"))
}

/// A file the loader read beside the inventory.
pub fn inventory_file(handoff: &Handoff, name: &str) -> Option<&'static [u8]> {
    handoff.files[..handoff.file_count]
        .iter()
        .find(|f| f.name() == name)
        .map(bundle::contents)
}

pub struct Experiment {
    usb: UsbId,
    driver: Driver<Source, MuxStream>,
    terminal: bool,
    ledger: usize,
    mode: Mode,
}
impl Experiment {
    /// The study runs `identity`; the install the inventory's one Erase
    /// identity, and the update its one Update identity. The payload is
    /// checked block by block as the restore reads it when its hashes are
    /// recorded, and every member before StartRestore otherwise, unless
    /// `verify` is [`Verify::OnRead`], which refuses a payload without them.
    pub fn new(
        source: Source,
        usb: UsbId,
        handoff: &Handoff,
        mode: Mode,
        identity: Option<usize>,
        verify: Verify,
        signer: Option<stela_runtime::restore::tss::Signer>,
    ) -> Result<Self, String> {
        let manifest = inventory(handoff)?;
        let purpose = match mode {
            Mode::Update => Purpose::Update,
            Mode::Install | Mode::Study => Purpose::Erase,
        };
        let identity = match identity {
            Some(identity) => identity,
            None => manifest
                .restore_identity(purpose)
                .map_err(|e| format!("{e}"))? as usize,
        };
        // Recorded block hashes check each block as the restore reads it;
        // without them every member is read whole first, to build them.
        let recorded = manifest.block_hashes.is_some();
        let verify = match (recorded, verify) {
            (true, _) => Verify::OnRead,
            (false, Verify::OnRead) => {
                return Err(String::from(
                    "--verify-on-read needs the payload's recorded block hashes, and this restore inventory names none",
                ));
            }
            (false, Verify::Full) => Verify::Full,
        };
        output::arguments(format_args!(
            "{} build={} source_sha256={} manifest_sha256={} identity={} bytes={} hashes={} verify={}\n",
            match mode {
                Mode::Study => "RESTORE STUDY UNQUALIFIED",
                mode => mode.label(),
            },
            manifest.product_build,
            manifest.source.sha256,
            manifest.source.build_manifest_sha256,
            identity,
            manifest.source.bytes,
            if recorded { "recorded" } else { "scan" },
            match verify {
                Verify::Full => "full",
                Verify::OnRead => "on-read",
            }
        ));
        let mut store = Store::open(source, manifest, identity).map_err(|e| format!("{e}"))?;
        store.set_verify(verify);
        if recorded {
            // Both modes check reads against the manifest's recorded hashes.
            let blocks = inventory_file(handoff, RESTORE_BLOCKS_FILE)
                .ok_or("the restore inventory's block hashes were not loaded")?;
            store
                .adopt_block_hashes(blocks)
                .map_err(|e| format!("{e}"))?;
        }
        let mut answers = Answers::new(store);
        if signer.is_some() {
            answers.signer = signer;
            // The bundle boots under the AP ticket Apple personalized for it,
            // which also answers RootTicket.
            let booted = inventory_file(handoff, BOOT_MANIFEST_FILE)
                .ok_or("--tss needs the bundle's boot manifest")?;
            answers.boot_with(booted.to_vec()).map_err(|error| {
                format!(
                    "--tss needs a bundle whose boot manifest Apple personalized for this machine \
                     (stela boot prepare --tss): {error}"
                )
            })?;
        }
        // Serve the system-image content-key GET from the inventory's keys.
        answers
            .stage_system_image_keys()
            .map_err(|e| format!("{e}"))?;
        if let Some(seconds) = handoff.wall_seconds {
            // The firmware's time at the handoff, carried forward on the TSC.
            let (tsc, hz) = (handoff.wall_tsc, handoff.tsc_hz);
            answers.clock = Some(Box::new(move || {
                seconds + (super::host::rdtsc() - tsc) / hz
            }));
        }
        let route = match mode {
            Mode::Install => Route::Recovery,
            Mode::Update => Route::Stock,
            Mode::Study => Route::StelaFirmwareStudy,
        };
        let driver = Driver::new(answers, route).map_err(|e| format!("{e}"))?;
        Ok(Self {
            usb,
            driver,
            terminal: false,
            ledger: 0,
            mode,
        })
    }
    pub fn poll(&mut self, devices: &mut AppleDevices) {
        if self.terminal {
            return;
        }
        let label = self.mode.label();
        let mut client = devices
            .usb_client(self.usb)
            .unwrap_or_else(|e| output::fatal(e));
        let result = self.driver.poll(&mut client);
        for message in &self.driver.session.ledger()[self.ledger..] {
            output::arguments(format_args!("{label} ledger={message:?}\n"));
        }
        self.ledger = self.driver.session.ledger().len();
        match result {
            Poll::Pending => {}
            Poll::Ready(Ok(())) => {
                self.terminal = true;
                output::arguments(format_args!(
                    "{}\n",
                    match self.mode {
                        Mode::Install =>
                            "INSTALL protocol complete; restart into recoveryOS (Stela)",
                        Mode::Update => "UPDATE protocol complete; reboot into macOS (Stela)",
                        Mode::Study => {
                            "RESTORE STUDY protocol complete; installed boot is unqualified"
                        }
                    }
                ));
            }
            Poll::Ready(Err(error)) => {
                output::arguments(format_args!("{label} REFUSED {error}\n"));
                // Preserve the guest stop context and refuse further writes.
                // The restore has no automatic reboot/retry or fallback.
                output::fatal(&format!(
                    "{} failed: {}",
                    match self.mode {
                        Mode::Install => "the install",
                        Mode::Update => "the update",
                        Mode::Study => "the restore study",
                    },
                    error.summary()
                ))
            }
        }
    }
}
