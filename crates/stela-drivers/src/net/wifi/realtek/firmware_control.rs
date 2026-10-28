// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! Native register-mailbox state and initial firmware calibration control.
//! Publication, mailbox availability, DMA release and raw RFK status are
//! separate observations. None creates OS/air or independent stop authority.
use super::{
    features::Report,
    identity::{Chip, Profile},
    io::{self, Io},
    registers::*,
    transmit,
};
use crate::bus::dma::memory::PageSource;

// Native access widths are kept at each use (REG_ARFR4 and CIP are byte
// observations in the source handshake).
const BT_IQK_BUSY: u32 = 0x600000;
const INFORM_RFK_STATUS: u32 = 0x6d;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
    Packet(transmit::Error),
    WrongProfile,
    UnsupportedLayout,
    InvalidState,
    InitialMailboxBusy(u8),
    MailboxTimeout { mailbox: u8 },
    Timeout { register: u32 },
    StaleRfk,
    StaleIqk,
    Clock,
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Hardware(e)
    }
}
impl From<transmit::Error> for Error {
    fn from(e: transmit::Error) -> Self {
        Self::Packet(e)
    }
}
/// Register publication only. This is not command completion or DMA retirement.
#[derive(Debug)]
pub struct Published {
    mailbox: u8,
}
impl Published {
    pub fn mailbox(&self) -> u8 {
        self.mailbox
    }
}
/// Source RFK status observed after the finish command; the source reuses a
/// sticky one-bit field. This record deliberately proves no fresh finish ACK,
/// coexistence handoff, calibration completion or TX permission.
#[derive(Debug)]
pub struct RfkFinishObservation {
    publication: Published,
    status: u8,
}
impl RfkFinishObservation {
    pub fn publication(&self) -> &Published {
        &self.publication
    }
    pub fn raw_status(&self) -> u8 {
        self.status
    }
}
/// Cold initial IQK's new AA observation after a non-AA baseline and real DMA
/// command publication. Firmware DMA/key/radio/policy retirement is separate.
#[derive(Debug)]
pub struct InitialIqkObservation {
    baseline: u8,
    status: u8,
}
impl InitialIqkObservation {
    pub fn baseline(&self) -> u8 {
        self.baseline
    }
    pub fn status(&self) -> u8 {
        self.status
    }
}
/// Same retained native Io, moved here after bootstrap; no second BAR/config,
/// mapping or requester owner is acquired. Mailbox cursor persists until actual
/// stop, never reset merely because a command times out or a status is seen.
pub struct Control<I: Io> {
    io: Option<I>,
    profile: Profile,
    next_box: u8,
    poisoned: bool,
    published: bool,
    rfk_active: bool,
    iqk_used: bool,
    clock_last: u64,
}
impl<I: Io> Drop for Control<I> {
    fn drop(&mut self) {
        if (self.poisoned || self.published)
            && let Some(io) = self.io.as_mut()
        {
            io.quarantine();
        }
    }
}
struct PacketAttempt<'a, R: transmit::Registers> {
    rings: &'a mut transmit::Rings<R>,
    done: bool,
}
impl<R: transmit::Registers> Drop for PacketAttempt<'_, R> {
    fn drop(&mut self) {
        if !self.done {
            self.rings.quarantine_firmware();
        }
    }
}
impl<I: Io> Control<I> {
    /// # Safety
    /// Consume the genuine serialized native control Io for this actual
    /// requester, Report and uninterrupted freshly downloaded firmware epoch.
    /// Its actual register-mailbox cursor is the initial zero, no old commands
    /// or competing native/IRQ/firmware/reset worker exist, and mailbox status
    /// is genuinely idle. Real MAC/PHY/HCI initialization/queues/pins/claims,
    /// native clock calibration and CPU affinity remain valid. Caller keeps
    /// operational TX gated pending genuine complete radio/policy qualification.
    /// Fingerprints, copied receipts or numeric counters are not ownership.
    pub unsafe fn new(io: I, report: &Report) -> Result<Self, Error> {
        let profile = io.profile();
        let mut c = Self {
            io: Some(io),
            profile,
            next_box: 0,
            poisoned: true,
            published: false,
            rfk_active: false,
            iqk_used: false,
            clock_last: 0,
        };
        if profile.chip() != Chip::Rtl8822C || report.profile() != profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 {
            return Err(Error::UnsupportedLayout);
        }
        c.verify()?;
        let now = c.io()?.now_us()?;
        c.clock_last = now;
        let state = c.io()?.read8(REG_HMETFR)?;
        if state & 15 != 0 {
            return Err(Error::InitialMailboxBusy(state));
        }
        c.verify()?;
        c.poisoned = false;
        Ok(c)
    }
    pub fn quarantined(&self) -> bool {
        self.poisoned
    }
    pub fn next_mailbox(&self) -> u8 {
        self.next_box
    }
    fn io(&mut self) -> Result<&mut I, Error> {
        self.io.as_mut().ok_or(Error::InvalidState)
    }
    fn verify(&mut self) -> Result<(), Error> {
        let expected = self.profile.observed().sys_cfg1;
        if self.io()?.read32(REG_SYS_CFG1)? != expected {
            return Err(Error::WrongProfile);
        }
        if self.io()?.read16(REG_MCUFW_CTRL)? & FW_READY_MASK != FW_READY {
            return Err(io::Error::FirmwareNotReady { debug: 0 }.into());
        }
        Ok(())
    }
    fn ready(&self) -> Result<(), Error> {
        if self.poisoned || self.io.is_none() {
            Err(Error::InvalidState)
        } else {
            Ok(())
        }
    }
    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        self.poisoned = result.is_err();
        if result.is_err()
            && let Some(io) = self.io.as_mut()
        {
            io.quarantine();
        }
        result
    }
    fn now(&mut self) -> Result<u64, Error> {
        let now = self.io()?.now_us()?;
        if now < self.clock_last {
            return Err(Error::Clock);
        }
        self.clock_last = now;
        Ok(now)
    }
    fn poll(
        &mut self,
        register: u32,
        timeout: u64,
        delay: u64,
        mut sample: impl FnMut(&mut I) -> Result<bool, io::Error>,
    ) -> Result<(), Error> {
        let start = self.now()?;
        let end = start.checked_add(timeout).ok_or(Error::Clock)?;
        // Exact wall-time predicate and final post-expiry sample from source.
        // The independent count guard detects an unqualified stalled clock.
        for _ in 0..(timeout / delay + 3) * 2 {
            let now = self.now()?;
            let expired = now > end;
            if sample(self.io()?)? {
                return Ok(());
            }
            if expired {
                return Err(Error::Timeout { register });
            }
            self.io()?.delay_us(delay);
            let after = self.now()?;
            if after <= now {
                return Err(Error::Clock);
            }
        }
        Err(Error::Clock)
    }
    fn publish_rfk(&mut self, start: bool) -> Result<Published, Error> {
        self.verify()?;
        let mailbox = self.next_box;
        // Source atomic budget: 3,000,000 ns minus 100,000+one ns per failed
        // iteration, with one final condition sample after budget expiry.
        let mut available = false;
        for index in 0..31 {
            let state = self.io()?.read8(REG_HMETFR)?;
            if state & (1 << mailbox) == 0 {
                available = true;
                break;
            }
            if index < 30 {
                self.io()?.delay_us(100);
            }
        }
        if !available {
            return Err(Error::MailboxTimeout { mailbox });
        }
        self.published = true;
        self.io()?
            .write32(REG_HMEBOX0_EX + u32::from(mailbox) * 4, 0)?;
        self.io()?.write32(
            REG_HMEBOX0 + u32::from(mailbox) * 4,
            INFORM_RFK_STATUS | (u32::from(start) << 8),
        )?;
        self.next_box = (mailbox + 1) % 4;
        self.verify()?;
        Ok(Published { mailbox })
    }
    /// Begin source GAPK's RFK handshake from a genuinely non-set baseline.
    /// BT IQK must be observed idle; no source timeout-skip fallback is minted.
    ///
    /// # Safety
    /// Actual same retained device/firmware/channel/board epoch, genuine held
    /// native→OS/coexistence authority, required current power/RF calibration
    /// emission permission/gates and exclusive RFK worker. Operational TX and
    /// competing BT/WiFi/reset/IRQ/RF/PHY work remain genuinely stopped. A raw
    /// BT-idle status does not replace actual retained BT/coexistence ownership.
    /// This establishes only a new observed source start-status bit, not GAPK,
    /// finish completion, DMA stop or permission for normal TX.
    pub unsafe fn begin_rfk(&mut self) -> Result<Published, Error> {
        self.ready()?;
        if self.rfk_active {
            return Err(Error::InvalidState);
        }
        self.poisoned = true;
        let result = (|| {
            self.verify()?;
            if self.io()?.read8(REG_ARFR4)? & 1 != 0 {
                return Err(Error::StaleRfk);
            }
            self.poll(REG_PMC_DBG_CTRL1, 600000, 20, |io| {
                Ok(io.read32(REG_PMC_DBG_CTRL1)? & BT_IQK_BUSY == 0)
            })?;
            let publication = self.publish_rfk(true)?;
            self.rfk_active = true;
            self.poll(
                REG_ARFR4,
                100000,
                20,
                |io| Ok(io.read8(REG_ARFR4)? & 1 == 1),
            )?;
            self.verify()?;
            Ok(publication)
        })();
        self.finish(result)
    }
    /// Observe the source finish-status condition after actual finish mailbox
    /// publication. Sticky status is explicitly not promoted to a fresh ACK.
    ///
    /// # Safety
    /// Same actual retained source RFK session/authority as begin_rfk. GAPK work
    /// has genuinely completed/stopped and all source restore obligations hold.
    /// Real firmware/coexistence handoff and radio qualification remain caller-
    /// owned; this observation cannot authorize a later ordinary transmission.
    pub unsafe fn finish_rfk(&mut self) -> Result<RfkFinishObservation, Error> {
        self.ready()?;
        if !self.rfk_active {
            return Err(Error::InvalidState);
        }
        self.poisoned = true;
        let result = (|| {
            let publication = self.publish_rfk(false)?;
            self.poll(
                REG_ARFR4,
                100000,
                20,
                |io| Ok(io.read8(REG_ARFR4)? & 1 == 1),
            )?;
            let status = self.io()?.read8(REG_ARFR4)?;
            self.verify()?;
            self.rfk_active = false;
            Ok(RfkFinishObservation {
                publication,
                status,
            })
        })();
        self.finish(result)
    }
    /// Publish and observe the one cold initial source clear=1/segment=0 IQK.
    /// Requires a non-AA baseline; no prior completion or DMA consumer index
    /// can satisfy this command. A post-expiry final fresh AA is source-valid.
    ///
    /// # Safety
    /// Rings and this control are the same actual requester/firmware epoch,
    /// not matching fingerprints. Real source PHYDM and GAPK completed, actual
    /// firmware/coexistence handoff is independently qualified, current channel/
    /// power and genuine native→OS/calibration emission authority held; ordinary
    /// RX/TX and competing reset/RFK/IRQ workers remain quiesced. IQK can emit
    /// calibration signals. Source ready status is not DPK, applied policy or
    /// normal-TX permission. Real command DMA and firmware retirement remain
    /// independently owned through actual completion or acknowledged stop.
    pub unsafe fn initial_iqk<R: transmit::Registers>(
        &mut self,
        rings: &mut transmit::Rings<R>,
        source: &dyn PageSource,
    ) -> Result<InitialIqkObservation, Error> {
        self.ready()?;
        if self.rfk_active || self.iqk_used {
            return Err(Error::InvalidState);
        }
        if rings.profile()? != self.profile {
            return Err(Error::WrongProfile);
        }
        self.poisoned = true;
        let mut packet = PacketAttempt { rings, done: false };
        let result = (|| {
            self.verify()?;
            let baseline = self.io()?.read8(REG_RPT_CIP)?;
            if baseline == 0xaa {
                return Err(Error::StaleIqk);
            }
            self.iqk_used = true;
            // SAFETY: caller holds real same native rings/control/authority;
            // status was sampled before this exact command publication.
            unsafe { packet.rings.initial_iqk_command(source) }?;
            self.published = true;
            let poll = self.poll(REG_RPT_CIP, 300000, 20000, |io| {
                Ok(io.read8(REG_RPT_CIP)? == 0xaa)
            });
            // Source clears REG_IQKSTAT after the poll even for a pure timeout.
            // Any error remains terminal; this is never rollback/stop proof.
            self.io()?.write8(REG_IQKSTAT, 0)?;
            poll?;
            self.verify()?;
            Ok(InitialIqkObservation {
                baseline,
                status: 0xaa,
            })
        })();
        packet.done = result.is_ok();
        self.finish(result)
    }
    /// Return the same native Io only after actual independent shutdown.
    ///
    /// # Safety
    /// Vendor DMA/firmware/RFK/autonomous RX/TX, PCI requester activity, posted
    /// interrupts and native callbacks/work have genuinely stopped and drained;
    /// rings/pins remain retained until actual quiescence and all users retired.
    /// Mailbox free, raw finish bit, IQK AA, masking and queue emptiness are not
    /// stop proof. No future firmware command can change this device epoch.
    pub unsafe fn release_after_stop(&mut self) -> Result<I, Error> {
        self.published = false;
        self.rfk_active = false;
        self.poisoned = false;
        self.io.take().ok_or(Error::InvalidState)
    }
}

#[cfg(test)]
pub(super) mod tests {
    extern crate std;
    use super::*;
    use alloc::{sync::Arc, vec, vec::Vec};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    pub(in crate::net::wifi::realtek) struct Owner(pub Arc<AtomicUsize>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    pub(in crate::net::wifi::realtek) struct Model {
        pub profile: Profile,
        bytes: Vec<u8>,
        pub events: Vec<[u32; 4]>,
        pub calls: usize,
        pub fail: Option<usize>,
        pub panic_at: Option<usize>,
        pub mutate_at: Option<(usize, u32, usize, u32)>,
        pub quarantine: usize,
        pub now: u64,
        pub frozen: bool,
        pub regress: bool,
        pub clock_available: bool,
        pub busy_reads: usize,
        pub busy_target: u8,
        pub busy_other: u8,
        pub busy_seen: usize,
        pub bt_idle_after: usize,
        pub bt_reads: usize,
        pub rfk_after: Option<usize>,
        pub rfk_reads: usize,
        pub rfk_pending: bool,
        pub iqk_after: Option<usize>,
        pub iqk_reads: usize,
        pub trigger: Arc<AtomicBool>,
        pub dropped: usize,
    }
    pub(in crate::net::wifi::realtek) struct Bus {
        pub model: Arc<Mutex<Model>>,
        owner: Option<Arc<Owner>>,
    }
    impl Model {
        pub fn set(&mut self, r: u32, width: usize, value: u32) {
            self.bytes[r as usize..r as usize + width]
                .copy_from_slice(&value.to_le_bytes()[..width]);
        }
        pub fn get(&self, r: u32, width: usize) -> u32 {
            let mut v = [0; 4];
            v[..width].copy_from_slice(&self.bytes[r as usize..r as usize + width]);
            u32::from_le_bytes(v)
        }
        fn operation(&mut self) -> Result<(), io::Error> {
            self.calls += 1;
            if let Some((at, register, width, value)) = self.mutate_at
                && self.calls == at
            {
                self.set(register, width, value);
            }
            if self.panic_at == Some(self.calls) {
                panic!("modeled control unwind");
            }
            if self.fail == Some(self.calls) {
                return Err(io::Error::Register);
            }
            Ok(())
        }
        pub fn clear_log(&mut self) {
            self.calls = 0;
            self.events.clear();
        }
    }
    pub(in crate::net::wifi::realtek) fn bus(
        profile: Profile,
    ) -> (Bus, Arc<Mutex<Model>>, Arc<Owner>, Arc<AtomicUsize>) {
        let dropped = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Owner(dropped.clone()));
        let mut m = Model {
            profile,
            bytes: vec![0; 0x5000],
            events: Vec::new(),
            calls: 0,
            fail: None,
            panic_at: None,
            mutate_at: None,
            quarantine: 0,
            now: 0,
            frozen: false,
            regress: false,
            clock_available: true,
            busy_reads: 0,
            busy_target: 0,
            busy_other: 0,
            busy_seen: 0,
            bt_idle_after: 0,
            bt_reads: 0,
            rfk_after: Some(0),
            rfk_reads: 0,
            rfk_pending: false,
            iqk_after: Some(0),
            iqk_reads: 0,
            trigger: Arc::new(AtomicBool::new(false)),
            dropped: 0,
        };
        m.set(REG_SYS_CFG1, 4, profile.observed().sys_cfg1);
        m.set(REG_MCUFW_CTRL, 2, 0xc078);
        let state = Arc::new(Mutex::new(m));
        (
            Bus {
                model: state.clone(),
                owner: Some(owner.clone()),
            },
            state,
            owner,
            dropped,
        )
    }
    // SAFETY: exclusively serialized byte-register and clock/firmware-response
    // model with retained actual model owner, not physical readiness evidence.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            self.model.lock().unwrap_or_else(|e| e.into_inner()).profile
        }
        fn read8(&mut self, r: u32) -> Result<u8, io::Error> {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            m.operation()?;
            let v = match r {
                0x1cc => {
                    let v = m.busy_other
                        | if m.busy_seen < m.busy_reads {
                            1 << m.busy_target
                        } else {
                            0
                        };
                    m.busy_seen += 1;
                    v
                }
                0x49c => {
                    if m.rfk_pending {
                        if m.rfk_after.is_some_and(|at| m.rfk_reads >= at) {
                            let old = m.get(r, 1) | 1;
                            m.set(r, 1, old);
                        }
                        m.rfk_reads += 1;
                    }
                    m.get(r, 1) as u8
                }
                0x2d9c => {
                    if m.trigger.load(Ordering::SeqCst) {
                        if m.iqk_after.is_some_and(|at| m.iqk_reads >= at) {
                            m.set(r, 1, 0xaa);
                        }
                        m.iqk_reads += 1;
                    }
                    m.get(r, 1) as u8
                }
                _ => m.get(r, 1) as u8,
            };
            m.events.push([0, r, 1, u32::from(v)]);
            Ok(v)
        }
        fn read16(&mut self, r: u32) -> Result<u16, io::Error> {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            m.operation()?;
            let v = m.get(r, 2);
            m.events.push([0, r, 2, v]);
            Ok(v as u16)
        }
        fn read32(&mut self, r: u32) -> Result<u32, io::Error> {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            m.operation()?;
            let v = if r == 0xa8 {
                let v = if m.bt_reads < m.bt_idle_after {
                    1 << 21
                } else {
                    0
                };
                m.bt_reads += 1;
                v
            } else {
                m.get(r, 4)
            };
            m.events.push([0, r, 4, v]);
            Ok(v)
        }
        fn write8(&mut self, r: u32, v: u8) -> Result<(), io::Error> {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            m.operation()?;
            m.set(r, 1, u32::from(v));
            m.events.push([1, r, 1, u32::from(v)]);
            Ok(())
        }
        fn write16(&mut self, r: u32, v: u16) -> Result<(), io::Error> {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            m.operation()?;
            m.set(r, 2, u32::from(v));
            m.events.push([1, r, 2, u32::from(v)]);
            Ok(())
        }
        fn write32(&mut self, r: u32, v: u32) -> Result<(), io::Error> {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            m.operation()?;
            m.set(r, 4, v);
            m.events.push([1, r, 4, v]);
            if (0x1d0..0x1e0).contains(&r) {
                m.rfk_pending = true;
                m.rfk_reads = 0;
            }
            Ok(())
        }
        fn delay_us(&mut self, us: u64) {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            if !m.frozen {
                m.now = m.now.checked_add(us).unwrap();
            }
            m.events.push([2, 0, 0, us as u32]);
        }
        fn now_us(&mut self) -> Result<u64, io::Error> {
            let mut m = self.model.lock().unwrap_or_else(|e| e.into_inner());
            m.operation()?;
            if !m.clock_available {
                return Err(io::Error::InvalidClock);
            }
            Ok(if m.regress {
                m.now.saturating_sub(1)
            } else {
                m.now
            })
        }
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), io::Error> {
            panic!("not a download")
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), io::Error> {
            panic!("not a DMA completion")
        }
        fn quarantine(&mut self) {
            self.model
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .quarantine += 1;
            if let Some(owner) = self.owner.take() {
                core::mem::forget(owner);
            }
        }
    }
    impl Drop for Bus {
        fn drop(&mut self) {
            self.model.lock().unwrap_or_else(|e| e.into_inner()).dropped += 1;
        }
    }
    fn fixture() -> (
        Control<Bus>,
        Arc<Mutex<Model>>,
        Arc<Owner>,
        Arc<AtomicUsize>,
    ) {
        let (_, report) = super::super::phy::control_fixture();
        let (io, m, o, d) = bus(report.profile());
        let c = unsafe { Control::new(io, &report) }.unwrap();
        m.lock().unwrap().clear_log();
        (c, m, o, d)
    }
    fn source_events(events: &[[u32; 4]]) -> Vec<[u32; 4]> {
        events
            .iter()
            .copied()
            .filter(|e| !(e[0] == 0 && (e[1] == 0xf0 || e[1] == 0x80)))
            .collect()
    }
    #[test]
    #[ignore = "oracle: STELA_REALTEK_WIFI_FIRMWARE_CONTROL_ORACLE"]
    fn every_mailbox_busy_boundary_and_complete_source_rfk_traces_match() {
        let dir = std::path::PathBuf::from(
            std::env::var("STELA_REALTEK_WIFI_FIRMWARE_CONTROL_ORACLE").unwrap(),
        );
        let bytes = std::fs::read(dir.join("mailbox.bin")).unwrap();
        let mut offset = 0;
        let mut cases = 0;
        while offset < bytes.len() {
            let h: [u32; 7] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    bytes[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 28;
            let (mut c, m, _, _) = fixture();
            c.next_box = h[0] as u8;
            {
                let mut s = m.lock().unwrap();
                s.busy_reads = h[2] as usize;
                s.busy_seen = 0;
                s.busy_target = h[0] as u8;
                s.busy_other = h[3] as u8;
            }
            assert_eq!(
                c.publish_rfk(h[1] != 0).is_ok(),
                h[6] != 0,
                "mailbox {cases}"
            );
            assert_eq!(u32::from(c.next_mailbox()), h[4]);
            let source = &bytes[offset..offset + h[5] as usize * 16];
            offset += source.len();
            let actual = source_events(&m.lock().unwrap().events);
            let actual: Vec<u8> = actual
                .into_iter()
                .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
                .collect();
            assert_eq!(actual, source, "mailbox {cases}");
            cases += 1;
        }
        assert_eq!(cases, 264);
        let bytes = std::fs::read(dir.join("rfk.bin")).unwrap();
        let mut offset = 0;
        let mut cases = 0;
        while offset < bytes.len() {
            let h: [u32; 5] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    bytes[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 20;
            let (mut c, m, _, _) = fixture();
            {
                let mut s = m.lock().unwrap();
                s.bt_idle_after = h[0] as usize;
                s.rfk_after = Some(h[1] as usize);
            }
            unsafe { c.begin_rfk() }.unwrap();
            assert_eq!(u32::from(c.next_mailbox()), h[3]);
            assert_eq!(h[4], 0);
            let mut actual = source_events(&m.lock().unwrap().events);
            assert_eq!(actual.remove(0), [0, 0x49c, 1, 0], "added freshness fence");
            let actual: Vec<u8> = actual
                .into_iter()
                .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
                .collect();
            let source = &bytes[offset..offset + h[2] as usize * 16];
            offset += source.len();
            assert_eq!(actual, source, "RFK start {cases}");
            let h: [u32; 2] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    bytes[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 8;
            m.lock().unwrap().clear_log();
            let observed = unsafe { c.finish_rfk() }.unwrap();
            assert_eq!(observed.raw_status() & 1, 1);
            assert_eq!(u32::from(c.next_mailbox()), h[1]);
            let mut actual = source_events(&m.lock().unwrap().events);
            assert_eq!(
                actual.pop(),
                Some([0, 0x49c, 1, 1]),
                "extra labeled raw snapshot"
            );
            let actual: Vec<u8> = actual
                .into_iter()
                .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
                .collect();
            let source = &bytes[offset..offset + h[0] as usize * 16];
            offset += source.len();
            assert_eq!(actual, source, "RFK finish {cases}");
            cases += 1;
        }
        assert_eq!(cases, 32);
    }
    #[test]
    fn mailbox_last_atomic_read_order_rotation_and_real_owner_lifetime() {
        for mailbox in 0..4 {
            let (mut c, m, owner, dropped) = fixture();
            c.next_box = mailbox;
            {
                let mut s = m.lock().unwrap();
                s.busy_target = mailbox;
                s.busy_reads = 30;
                s.busy_seen = 0;
            }
            let result = c.publish_rfk(true).unwrap();
            assert_eq!(result.mailbox(), mailbox);
            assert_eq!(c.next_mailbox(), (mailbox + 1) % 4);
            let s = m.lock().unwrap();
            let events = source_events(&s.events);
            assert_eq!(
                events.iter().filter(|e| e[0] == 0 && e[1] == 0x1cc).count(),
                31
            );
            assert_eq!(events.iter().filter(|e| e[0] == 2).count(), 30);
            assert_eq!(
                &events[events.len() - 2..],
                &[
                    [1, 0x1f0 + u32::from(mailbox) * 4, 4, 0],
                    [1, 0x1d0 + u32::from(mailbox) * 4, 4, 0x16d]
                ]
            );
            drop(s);
            drop(c);
            assert!(m.lock().unwrap().quarantine >= 1);
            assert_eq!(Arc::strong_count(&owner), 2);
            drop(owner);
            assert_eq!(dropped.load(Ordering::SeqCst), 0);
        }
        let (mut c, m, _, _) = fixture();
        {
            let mut s = m.lock().unwrap();
            s.busy_reads = 31;
            s.busy_seen = 0;
        }
        assert_eq!(
            c.publish_rfk(true).unwrap_err(),
            Error::MailboxTimeout { mailbox: 0 }
        );
        assert_eq!(c.next_mailbox(), 0);
        assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
    }
    #[test]
    fn fresh_start_and_sticky_finish_are_distinct_from_actual_completion() {
        let (mut c, m, _, _) = fixture();
        {
            let mut s = m.lock().unwrap();
            s.bt_idle_after = 3;
            s.rfk_after = Some(2);
        }
        let start = unsafe { c.begin_rfk() }.unwrap();
        assert_eq!(start.mailbox(), 0);
        assert_eq!(c.next_mailbox(), 1);
        // Real source finish reports bit1 even if the new finish request's
        // responder never runs. Preserve that fact without minting a new ACK.
        m.lock().unwrap().rfk_after = None;
        let finish = unsafe { c.finish_rfk() }.unwrap();
        assert_eq!(finish.raw_status() & 1, 1);
        assert_eq!(finish.publication().mailbox(), 1);
        assert_eq!(c.next_mailbox(), 2);
        assert_eq!(unsafe { c.begin_rfk() }.unwrap_err(), Error::StaleRfk);
        assert!(c.quarantined());
    }
    #[test]
    fn missing_clock_stale_status_deadline_and_uncertain_reads_cannot_start_calibration() {
        let (_, report) = super::super::phy::control_fixture();
        let (io, m, _, _) = bus(report.profile());
        m.lock().unwrap().clock_available = false;
        assert!(matches!(
            unsafe { Control::new(io, &report) },
            Err(Error::Hardware(io::Error::InvalidClock))
        ));
        assert!(m.lock().unwrap().quarantine >= 1);
        let (mut c, m, _, _) = fixture();
        m.lock().unwrap().set(REG_ARFR4, 1, 1);
        assert_eq!(unsafe { c.begin_rfk() }.unwrap_err(), Error::StaleRfk);
        assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
        let (mut c, m, _, _) = fixture();
        {
            let mut s = m.lock().unwrap();
            s.bt_idle_after = usize::MAX;
            s.frozen = true;
        }
        assert_eq!(unsafe { c.begin_rfk() }.unwrap_err(), Error::Clock);
        assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
        let (mut c, m, _, _) = fixture();
        m.lock().unwrap().bt_idle_after = usize::MAX;
        assert_eq!(
            unsafe { c.begin_rfk() }.unwrap_err(),
            Error::Timeout { register: 0xa8 }
        );
        assert!(!m.lock().unwrap().events.iter().any(|e| e[0] == 1));
        let (mut c, m, _, _) = fixture();
        m.lock().unwrap().rfk_after = None;
        assert_eq!(
            unsafe { c.begin_rfk() }.unwrap_err(),
            Error::Timeout { register: 0x49c }
        );
        assert!(m.lock().unwrap().events.iter().any(|e| e[0] == 1));
        assert!(c.quarantined());
    }
    #[test]
    fn every_start_finish_io_error_unwind_and_shutdown_retains_actual_control_owner() {
        let (mut c, m, _, _) = fixture();
        unsafe { c.begin_rfk() }.unwrap();
        let start_total = m.lock().unwrap().calls;
        for at in 1..=start_total {
            let (mut c, m, _, _) = fixture();
            m.lock().unwrap().fail = Some(at);
            assert!(unsafe { c.begin_rfk() }.is_err(), "start{at}");
            assert!(c.quarantined());
            assert!(m.lock().unwrap().quarantine >= 1);
        }
        let (mut c, m, _, _) = fixture();
        unsafe { c.begin_rfk() }.unwrap();
        m.lock().unwrap().clear_log();
        unsafe { c.finish_rfk() }.unwrap();
        let end_total = m.lock().unwrap().calls;
        for at in 1..=end_total {
            let (mut c, m, _, _) = fixture();
            unsafe { c.begin_rfk() }.unwrap();
            m.lock().unwrap().clear_log();
            m.lock().unwrap().fail = Some(at);
            assert!(unsafe { c.finish_rfk() }.is_err(), "finish{at}");
            assert!(c.quarantined());
        }
        let (mut c, m, _, _) = fixture();
        m.lock().unwrap().panic_at = Some(8);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe { c.begin_rfk() }))
                .is_err()
        );
        assert!(c.quarantined());
        drop(c);
        assert!(m.lock().unwrap_or_else(|e| e.into_inner()).quarantine >= 1);
        let (mut c, m, owner, dropped) = fixture();
        unsafe { c.begin_rfk() }.unwrap();
        unsafe { c.finish_rfk() }.unwrap();
        let io = unsafe { c.release_after_stop() }.unwrap();
        drop(c);
        assert_eq!(m.lock().unwrap().quarantine, 0);
        drop(io);
        assert_eq!(Arc::strong_count(&owner), 1);
        drop(owner);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
}
