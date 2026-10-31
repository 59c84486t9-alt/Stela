// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! An RTL8822C's registers and rings beneath its [`Rtl8822c`] station: what
//! rtw88's `mac80211.c`, `pci.c`, `sec.c` and `rtw_set_channel` do for
//! mac80211. Each step takes the radio's only worker, so nothing here locks.
//!
//! [`Rtl8822c`]: super::station::Rtl8822c
use super::{
    bootstrap::{Native, Up},
    coex::{self, Coex, Link},
    commands::{self, Report},
    descriptor::Packet,
    dynamic::{self, Dynamic},
    features,
    firmware_control::Control,
    interrupt::Controller,
    io::{Bar, Io},
    phy::{
        FactorySheet, PhyInitialized,
        channel_power::{Geometry, Limits, Width as ChannelWidth},
    },
    receive::{self, Ring},
    regd,
    registers::{REG_BCN_CTRL, REG_CR},
    station::{CamKey, Device, Incoming, MAC_ID, Received},
    transmit::{self, Queue, Rings},
};
use crate::{
    Mac,
    bus::dma::memory::PageSource,
    wifi::Band,
    wifi::station::{
        operations::ChannelDefinition,
        phy::{AccessCategory, Width},
    },
};
use alloc::{format, string::String, vec::Vec};
use core::fmt::Debug;

/// `rtw_vif_port[0]`.
const REG_MAC_ADDRESS: u32 = 0x610;
const REG_BSSID: u32 = 0x618;
const REG_AID: u32 = 0x6a8;
const AID_MASK: u32 = 0x7ff;
const NET_TYPE_MASK: u32 = 0x30000;
/// `RTW_NET_NO_LINK` and `RTW_NET_MGD_LINKED`.
const NET_NO_LINK: u32 = 0;
const NET_LINKED: u32 = 2;
/// `BIT_EN_BCN_FUNCTION`.
const BEACON_FUNCTION: u8 = 1 << 3;
/// `REG_RCR`'s `BIT_CBSSID_BCN`.
const REG_RCR: u32 = 0x608;
const OWN_BEACONS: u32 = 1 << 7;
/// `ac_to_edca_param`, by the ACI an AP's parameters name.
const EDCA: [u32; 4] = [0x508, 0x50c, 0x504, 0x500];
/// `RTW_SEC_CMD_REG`, `RTW_SEC_WRITE_REG` and their command.
const REG_CAM_COMMAND: u32 = 0x670;
const REG_CAM_WRITE: u32 = 0x674;
const CAM_WRITE: u32 = (1 << 31) | (1 << 16);
/// `REG_NCTL0`'s `BIT_SEL_PATH`, and `REG_DPD_CTL1_S0`'s `BIT_PS_EN`.
const REG_NCTL0: u32 = 0x1b00;
const SELECT_PATH: u32 = 3 << 1;
const REG_DPD_CTL1: u32 = 0x1b08;
const POWER_SAVE: u32 = 1 << 7;
/// `rtw8822c_dig`: each path's gain within one register.
const REG_GAIN: u32 = 0x1d70;
const GAIN_MASKS: [u32; 2] = [0x7f, 0x7f00];
/// `rtw8822c_false_alarm_statistics`' counters, their resets and clock gate.
const REG_CCK_ENABLE: u32 = 0x1c3c;
const CCK_BLOCK: u32 = 1 << 1;
const REG_CCK_ALARMS: u32 = 0x1a5c;
const REG_OFDM_ALARMS: [u32; 5] = [0x2d04, 0x2d08, 0x2d0c, 0x2d10, 0x2d20];
const REG_ALARM_RESET: u32 = 0x1a2c;
const CCK_ALARM_RESET: u32 = 3 << 14;
const OFDM_ALARM_RESET: u32 = 3 << 12;
const REG_RX_BREAK: u32 = 0x1d2c;
const RX_CLOCK_GATE: u32 = 1 << 31;
const REG_COUNTER_CONTROL: u32 = 0x1eb4;
const ALL_COUNTERS_RESET: u32 = 1 << 25;
/// `RRSR_INIT_2G` and `RRSR_INIT_5G`, the rates a response may use.
const REG_RRSR: u32 = 0x440;
const RESPONSE_RATES_2GHZ: u32 = 0x15f;
const RESPONSE_RATES_5GHZ: u32 = 0x150;
/// Frames a look at the receive ring takes, which [`Ring::poll`] holds to the
/// ring's own size.
const RECEIVE_BUDGET: usize = 512;
/// `DBI_TO_MBI(6)`, the antenna gain cfg80211 reads regulatory.db's EIRP under,
/// and the 3 dB of two chains sending one frame. rtw88 keeps to the sheet
/// alone; a board's real antennas are not known here.
const ANTENNA_AND_COMBINING_MBM: i32 = 600 + 301;

fn failed<E: Debug>(step: &'static str) -> impl FnOnce(E) -> String {
    move |error| format!("{step}: {error:?}")
}

/// What `definition`'s channels are to the PHY.
fn geometry(definition: &ChannelDefinition) -> Result<Geometry, String> {
    let number = |frequency: u32| {
        let base = if frequency < 5000 { 2407 } else { 5000 };
        ((frequency - base) / 5) as u8
    };
    let primary = definition.control.number as u8;
    let center = number(definition.center1_mhz);
    let (width, forty, eighty) = match definition.width {
        Width::Mhz20 => (ChannelWidth::Mhz20, None, None),
        Width::Mhz40 => (ChannelWidth::Mhz40, Some(center), None),
        Width::Mhz80 => {
            // rtw_get_channel_params: the 40 MHz half the primary lies in.
            let forty = if primary > center {
                center + 4
            } else {
                center - 4
            };
            (ChannelWidth::Mhz80, Some(forty), Some(center))
        }
        _ => return Err(String::from("a channel wider than the RTL8822C's 80 MHz")),
    };
    Geometry::new(primary, width, forty, eighty).map_err(failed("channel"))
}

/// The hardware an attached RTL8822C station runs on.
pub struct Hardware {
    control: Control<Native>,
    interrupts: Controller<Bar>,
    receive: Ring<Bar>,
    transmit: Rings<Bar>,
    /// Taken while a channel changes; gone if one failed part way.
    phy: Option<PhyInitialized>,
    coex: Coex,
    report: features::Report,
    pages: &'static dyn PageSource,
    /// The 2.4 and 5 GHz factory sheets of the country.
    sheets: (FactorySheet, FactorySheet),
    /// `rtwdev->need_rfk`: the channel changed outside a scan.
    calibrate: bool,
    band: Band,
    connected: bool,
    address: Mac,
    bssid: Mac,
    dynamic: Dynamic,
    /// `dm_info->cck_gi_u_bnd` and `cck_gi_l_bnd`.
    cck_bounds: [u8; 2],
    /// `si->ra_report.desc_rate`.
    peer_rate: u8,
    /// The MSI reaches the core that looks for frames.
    vector: bool,
    limitations: Vec<&'static str>,
}

impl Hardware {
    /// `rtw_ops_add_interface`'s first station on `up`, under `alpha2`.
    ///
    /// # Safety
    /// `up` comes from [`super::bootstrap::bring_up`] with nothing since, and
    /// `vector` says its function raises an MSI the caller has routed.
    pub unsafe fn new(up: Up, alpha2: [u8; 2], vector: bool) -> Result<Self, String> {
        let Up {
            mut control,
            mut interrupts,
            receive,
            transmit,
            phy,
            report,
            coex,
            mac,
            pages,
            ..
        } = up;
        let initial = phy.factory().calibration().initial();
        let (gains, cck_bounds) = (initial.igi_history(), initial.cck_bounds());
        let io = control.io().map_err(failed("registers"))?;
        write_address(io, REG_MAC_ADDRESS, mac).map_err(failed("address"))?;
        set_mask(io, REG_CR, NET_TYPE_MASK, NET_NO_LINK).map_err(failed("net type"))?;
        io.write8(REG_BCN_CTRL, BEACON_FUNCTION)
            .map_err(failed("beacon control"))?;
        if vector {
            // SAFETY: the caller's routed MSI, and this worker handles it.
            unsafe { interrupts.enable(false) }.map_err(failed("interrupts"))?;
        }
        Ok(Self {
            control,
            interrupts,
            receive,
            transmit,
            phy: Some(phy),
            coex,
            report,
            pages,
            sheets: regd::sheets(alpha2),
            calibrate: true,
            band: Band::Ghz2,
            connected: false,
            address: mac,
            bssid: Mac([0; 6]),
            dynamic: Dynamic::new(gains),
            cck_bounds,
            peer_rate: 0,
            vector,
            limitations: Vec::new(),
        })
    }

    /// `rtw_coex_run_coex` for the link as it now stands.
    fn run_coex(&mut self) -> Result<(), String> {
        let link = Link {
            five_ghz: self.band == Band::Ghz5,
            connected: self.connected,
        };
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: this worker owns the radio, and its frames wait for it.
        let run = unsafe { self.coex.run(io, &self.report, link) }.map_err(failed("coex"))?;
        if run.bluetooth_unscheduled {
            self.limitations.push("Bluetooth's schedule on 2.4 GHz");
        }
        self.commands(&run)
    }

    fn commands(&mut self, run: &coex::Run) -> Result<(), String> {
        for &command in &run.commands {
            self.control
                .command(command)
                .map_err(failed("coex command"))?;
        }
        Ok(())
    }

    /// `rtw8822c_false_alarm_statistics`: what was counted, and a new count.
    fn false_alarms(&mut self) -> Result<u16, String> {
        let io = self.control.io().map_err(failed("registers"))?;
        let cck_enabled = io.read32(REG_CCK_ENABLE).map_err(failed("alarms"))? & CCK_BLOCK != 0;
        let cck = io.read16(REG_CCK_ALARMS).map_err(failed("alarms"))?;
        let mut counts = [0; 5];
        for (count, register) in counts.iter_mut().zip(REG_OFDM_ALARMS) {
            *count = io.read32(register).map_err(failed("alarms"))?;
        }
        let [one, two, three, four, five] = counts;
        let (low, high) = (|word: u32| word & 0xffff, |word: u32| word >> 16);
        let total = high(one)
            + low(two)
            + high(two)
            + low(three)
            + low(four)
            + high(four)
            + low(five)
            + high(five)
            + if cck_enabled { u32::from(cck) } else { 0 };
        let mut reset = |register, mask, value| {
            set_mask(io, register, mask, value).map_err(failed("alarm reset"))
        };
        reset(REG_ALARM_RESET, CCK_ALARM_RESET, 0)?;
        reset(REG_ALARM_RESET, CCK_ALARM_RESET, 2)?;
        reset(REG_ALARM_RESET, OFDM_ALARM_RESET, 0)?;
        reset(REG_ALARM_RESET, OFDM_ALARM_RESET, 2)?;
        reset(REG_RX_BREAK, RX_CLOCK_GATE, 0)?;
        reset(REG_COUNTER_CONTROL, ALL_COUNTERS_RESET, 1)?;
        reset(REG_COUNTER_CONTROL, ALL_COUNTERS_RESET, 0)?;
        reset(REG_RX_BREAK, RX_CLOCK_GATE, 1)?;
        Ok(total as u16)
    }

    /// `rtw_phy_dig_write`.
    fn write_gain(&mut self, gain: u8) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        for mask in GAIN_MASKS {
            set_mask(io, REG_GAIN, mask, u32::from(gain)).map_err(failed("gain"))?;
        }
        Ok(())
    }

    /// `rtw8822c_rfk_power_save`.
    fn calibration_power_save(&mut self, on: bool) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        for path in 0..2 {
            set_mask(io, REG_NCTL0, SELECT_PATH, path).map_err(failed("path"))?;
            set_mask(io, REG_DPD_CTL1, POWER_SAVE, u32::from(!on)).map_err(failed("power save"))?;
        }
        Ok(())
    }
}

/// `rtw_write32_mask`.
fn set_mask(io: &mut Native, register: u32, mask: u32, value: u32) -> Result<(), super::io::Error> {
    let old = io.read32(register)?;
    io.write32(
        register,
        (old & !mask) | ((value << mask.trailing_zeros()) & mask),
    )
}

/// `rtw_vif_write_addr`.
fn write_address(io: &mut Native, register: u32, address: Mac) -> Result<(), super::io::Error> {
    for (at, byte) in address.0.into_iter().enumerate() {
        io.write8(register + at as u32, byte)?;
    }
    Ok(())
}

/// `rtw_aifsn_to_aifs` and `__rtw_conf_tx` of one queue.
fn edca_word(category: &AccessCategory, band: Band, short_slot: bool) -> u32 {
    let slot = if short_slot { 9 } else { 20 };
    let sifs = if band == Band::Ghz5 { 16 } else { 10 };
    let aifs = u32::from(category.aifsn) * slot + sifs;
    (u32::from(category.txop_32us) << 16)
        | (u32::from(category.ecw_max) << 12)
        | (u32::from(category.ecw_min) << 8)
        | aifs
}

/// `rtw_sec_write_cam`'s eight words of `key`.
fn cam_words(key: &CamKey<'_>) -> [u32; 8] {
    let [a, b, c, d, e, f] = key.peer.0.map(u32::from);
    let mut words = [0; 8];
    words[0] = u32::from(key.index & 3)
        | (u32::from(key.kind & 7) << 2)
        | (u32::from(key.group) << 6)
        | (1 << 15)
        | (a << 16)
        | (b << 24);
    words[1] = c | (d << 8) | (e << 16) | (f << 24);
    for (word, bytes) in words[2..6].iter_mut().zip(key.material.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    words
}

/// `rtw_rx_addr_match_iter`: whether `bytes` came from the BSS, to the station
/// or as a beacon, so that its signal describes the link.
fn describes_link(bytes: &[u8], address: Mac, bssid: Mac) -> bool {
    bytes.get(10..16) == Some(&bssid.0[..])
        && (bytes.get(4..10) == Some(&address.0[..]) || bytes.first() == Some(&0x80))
}

/// What one `rtw_rx_query_rx_desc` packet gives the station, with the signal it
/// came in on.
fn incoming(
    packet: &receive::Packet<'_>,
    cck_bounds: [u8; 2],
) -> Option<(Incoming, Option<dynamic::Signal>)> {
    let facts = &packet.facts;
    if facts.firmware {
        return Report::parse(packet.payload).map(|report| (Incoming::Report(report), None));
    }
    if facts.crc_error {
        return None;
    }
    // IEEE80211_HW_RX_INCLUDES_FCS.
    let length = packet.payload.len().checked_sub(4)?;
    let signal = if facts.phy_present {
        dynamic::phy_status(packet.driver_info, cck_bounds)
    } else {
        None
    };
    let frame = Received {
        bytes: packet.payload[..length].to_vec(),
        tsf: facts.tsf_low,
        decrypted: facts.hardware_decrypted,
        icv_error: facts.icv_error,
        signal_dbm: signal.map(|signal| signal.power_dbm),
    };
    Some((Incoming::Frame(frame), signal))
}

impl Device for Hardware {
    /// `rtw_set_channel`, and `rtw_phy_set_tx_power_level` under `eirp_mbm`.
    fn tune(
        &mut self,
        definition: &ChannelDefinition,
        scanning: bool,
        eirp_mbm: i32,
    ) -> Result<(), String> {
        let geometry = geometry(definition)?;
        let phy = self.phy.take().ok_or("the PHY failed a channel change")?;
        let band = definition.control.band;
        let limits = Limits {
            factory_sheet: if band == Band::Ghz2 {
                self.sheets.0
            } else {
                self.sheets.1
            },
            max_eirp_mbm: eirp_mbm,
            antenna_and_combining_mbm: [ANTENNA_AND_COMBINING_MBM; 2],
            sar_quarter_dbm: None,
            remnant_cck: 0,
            remnant_ofdm: [0; 2],
        };
        let plan = phy
            .factory_power()
            .plan_channel_power(geometry, limits)
            .map_err(failed("channel power"))?;
        let io = self.control.io().map_err(failed("registers"))?;
        // SAFETY: the only worker owns the radio and its frames wait for it.
        let set =
            unsafe { phy.set_channel(io, &self.report, geometry) }.map_err(failed("channel"))?;
        self.band = band;
        // SAFETY: as above, with `plan` made for this channel.
        let programmed = unsafe { set.program_channel_power(io, &self.report, plan) }
            .map_err(failed("transmit power"))?;
        self.phy = Some(programmed.into_phy());
        self.calibrate |= !scanning;
        self.run_coex()
    }

    /// `rtw_chip_prepare_tx`: `rtw8822c_phy_calibration` once a channel needs it.
    fn prepare_transmit(&mut self) -> Result<(), String> {
        if !core::mem::take(&mut self.calibrate) {
            return Ok(());
        }
        self.calibration_power_save(false)?;
        // SAFETY: the only worker owns the radio and its frames wait for it.
        unsafe { self.control.iqk(&mut self.transmit, self.pages) }.map_err(failed("iqk"))?;
        self.limitations
            .push("gain and predistortion calibration on an RTL8822C");
        self.calibration_power_save(true)
    }

    fn transmit(&mut self, queue: Queue, packet: &Packet, mpdu: &[u8]) -> Result<bool, String> {
        match self
            .transmit
            .frame(queue, self.pages, &packet.encode(), mpdu)
        {
            Ok(()) => Ok(true),
            Err(transmit::Error::Full) => Ok(false),
            Err(error) => Err(format!("transmit: {error:?}")),
        }
    }

    /// `rtw_pci_interrupt_threadfn`: the causes first, so that what arrives
    /// while the rings drain raises the MSI again.
    fn receive(&mut self, sink: &mut dyn FnMut(Incoming)) -> Result<(), String> {
        if self.vector {
            self.interrupts.capture().map_err(failed("interrupt"))?;
        }
        let (cck_bounds, address, bssid) = (self.cck_bounds, self.address, self.bssid);
        let (dynamic, peer_rate) = (&mut self.dynamic, &mut self.peer_rate);
        self.receive
            .poll(RECEIVE_BUDGET, |packet| {
                let Some((item, signal)) = incoming(&packet, cck_bounds) else {
                    return;
                };
                if let (Some(signal), Incoming::Frame(frame)) = (signal, &item)
                    && describes_link(&frame.bytes, address, bssid)
                {
                    dynamic.heard(signal.rssi);
                }
                if let Incoming::Report(Report::Rate {
                    mac_id: MAC_ID,
                    rate,
                    ..
                }) = &item
                {
                    *peer_rate = *rate;
                }
                sink(item);
            })
            .map_err(failed("receive"))?;
        self.transmit
            .reclaim_frames()
            .map_err(failed("transmit reclaim"))?;
        self.transmit
            .reclaim_h2c()
            .map_err(failed("command reclaim"))?;
        if self.vector {
            // SAFETY: this worker is the handler, between its capture and now.
            unsafe { self.interrupts.enable(false) }.map_err(failed("interrupt"))?;
        }
        Ok(())
    }

    fn command(&mut self, command: (u32, u32)) -> Result<(), String> {
        self.control.command(command).map_err(failed("command"))
    }

    /// `rtw_vif_port_config`.
    fn set_port(&mut self, bssid: Mac, aid: u16, linked: bool) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        write_address(io, REG_BSSID, bssid).map_err(failed("bssid"))?;
        set_mask(io, REG_AID, AID_MASK, u32::from(aid)).map_err(failed("aid"))?;
        let net_type = if linked { NET_LINKED } else { NET_NO_LINK };
        set_mask(io, REG_CR, NET_TYPE_MASK, net_type).map_err(failed("net type"))?;
        if self.connected != linked {
            self.dynamic.forget();
            self.peer_rate = 0;
        }
        self.bssid = bssid;
        self.connected = linked;
        self.run_coex()
    }

    /// `rtw_ops_configure_filter`'s `FIF_BCN_PRBRESP_PROMISC`.
    fn filter_beacons(&mut self, own_only: bool) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        set_mask(io, REG_RCR, OWN_BEACONS, u32::from(own_only)).map_err(failed("receive filter"))
    }

    fn set_edca(&mut self, edca: &[AccessCategory; 4], short_slot: bool) -> Result<(), String> {
        let band = self.band;
        let io = self.control.io().map_err(failed("registers"))?;
        for category in edca {
            let register = EDCA[usize::from(category.aci & 3)];
            io.write32(register, edca_word(category, band, short_slot))
                .map_err(failed("edca"))?;
        }
        Ok(())
    }

    fn write_key(&mut self, key: &CamKey<'_>) -> Result<(), String> {
        let words = cam_words(key);
        let address = u32::from(key.entry) << 3;
        let io = self.control.io().map_err(failed("registers"))?;
        for at in (0..8).rev() {
            io.write32(REG_CAM_WRITE, words[at])
                .map_err(failed("cam"))?;
            io.write32(REG_CAM_COMMAND, CAM_WRITE | (address + at as u32))
                .map_err(failed("cam"))?;
        }
        Ok(())
    }

    /// `rtw_sec_clear_cam`.
    fn clear_key(&mut self, entry: u8) -> Result<(), String> {
        let io = self.control.io().map_err(failed("registers"))?;
        io.write32(REG_CAM_WRITE, 0).map_err(failed("cam"))?;
        io.write32(REG_CAM_COMMAND, CAM_WRITE | (u32::from(entry) << 3))
            .map_err(failed("cam"))
    }

    /// `rtw_phy_dynamic_mechanism` as far as it goes: the RSSI firmware rates
    /// by, gain against false alarms, and the rates of responses.
    fn watchdog(&mut self, stbc: bool) -> Result<u8, String> {
        let linked = self.connected;
        self.dynamic.sample(linked);
        if linked {
            self.control
                .command(commands::rssi(MAC_ID, self.dynamic.rssi(), stbc))
                .map_err(failed("rssi"))?;
        }
        let alarms = self.false_alarms()?;
        if let Some(gain) = self.dynamic.gain(alarms, linked) {
            self.write_gain(gain)?;
        }
        if linked {
            let rates = if self.band == Band::Ghz5 {
                RESPONSE_RATES_5GHZ
            } else {
                RESPONSE_RATES_2GHZ
            };
            let peer_rate = self.peer_rate;
            let io = self.control.io().map_err(failed("registers"))?;
            io.write32(REG_RRSR, rates & dynamic::response_rates(peer_rate))
                .map_err(failed("response rates"))?;
        }
        Ok(self.dynamic.level())
    }

    /// `rtw_phy_dig_set_max_coverage`, and `rtw_phy_dig_reset` after.
    fn scanning(&mut self, scanning: bool) -> Result<(), String> {
        self.write_gain(if scanning {
            dynamic::MAX_COVERAGE
        } else {
            self.dynamic.current_gain()
        })
    }

    fn signals(&self) -> bool {
        self.vector
    }

    fn limitation(&mut self) -> Option<&'static str> {
        self.limitations.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi::Channel;

    fn definition(frequency_mhz: u16, width: Width, center1_mhz: u32) -> ChannelDefinition {
        ChannelDefinition {
            control: Channel {
                band: Band::Ghz5,
                number: (frequency_mhz - 5000) / 5,
                frequency_mhz,
            },
            width,
            center1_mhz,
            center2_mhz: None,
            punctured: 0,
        }
    }

    #[test]
    fn an_80_mhz_channel_names_the_half_its_primary_lies_in() {
        let wide = geometry(&definition(5220, Width::Mhz80, 5210)).unwrap();
        assert_eq!(wide.primary(), 44);
        assert_eq!(wide.centers()[1], Some(46));
        assert_eq!(wide.centers()[2], Some(42));
        let low = geometry(&definition(5180, Width::Mhz80, 5210)).unwrap();
        assert_eq!(low.centers()[1], Some(38));
        assert!(geometry(&definition(5180, Width::Mhz160, 5250)).is_err());
    }

    #[test]
    fn a_queue_word_holds_its_parameters_in_rtw88s_fields() {
        let category = AccessCategory {
            aci: 0,
            admission_control: false,
            aifsn: 3,
            ecw_min: 4,
            ecw_max: 10,
            txop_32us: 94,
        };
        assert_eq!(
            edca_word(&category, Band::Ghz5, true),
            (94 << 16) | 0xa400 | 43
        );
        assert_eq!(edca_word(&category, Band::Ghz2, false) & 0xff, 70);
    }

    #[test]
    fn a_cam_entry_lays_out_its_address_and_key() {
        let material: [u8; 16] = core::array::from_fn(|at| at as u8);
        let key = CamKey {
            entry: 4,
            index: 1,
            kind: 4,
            group: true,
            peer: Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            material: &material,
        };
        let words = cam_words(&key);
        assert_eq!(words[0], 0xbbaa_8051);
        assert_eq!(words[1], 0xffee_ddcc);
        assert_eq!(words[2], 0x0302_0100);
        assert_eq!(words[5], 0x0f0e_0d0c);
        assert_eq!(words[6..], [0, 0]);
    }
}
