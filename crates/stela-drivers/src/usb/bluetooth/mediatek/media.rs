// SPDX-License-Identifier: ISC
// Copyright (C) 2021 MediaTek Inc.
//! This PC's MT7925 SCO/ISO media transport. Bluetooth services, HCI credits and
//! connection policy remain with the host/guest stack; plans do not assert radio
//! readiness. SCO uses USBiso; MT7925 ISO uses the third interrupt interface.
mod binding;
mod framing;
mod session;
use crate::block::BlockError;
pub(in crate::usb::bluetooth) use binding::service_bytes;
pub use binding::{AirMode, Bindings, Pair, Voice};
use core::fmt;
pub use framing::Kind;
pub use session::{Lifecycle, Loss, MediaIo, Read, Received, Session, SetupReport};
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Unsupported(&'static str),
    Descriptor(&'static str),
    Packet(&'static str),
    Transport(BlockError),
    Hci(crate::usb::bluetooth::Error),
    OutputCompletion {
        kind: Kind,
        status: crate::usb::xhci::IsoStatus,
        expected: usize,
        actual: usize,
    },
    Controller {
        status: u8,
        event: alloc::vec::Vec<u8>,
    },
    Cleanup {
        cause: alloc::boxed::Box<Error>,
        media: Option<BlockError>,
        base: Option<crate::usb::bluetooth::Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MT7925 media {self:?}")
    }
}
impl core::error::Error for Error {}
impl From<BlockError> for Error {
    fn from(error: BlockError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(test)]
pub(in crate::usb::bluetooth) mod tests {
    use super::*;
    use crate::bus::dma::{DmaAllocator, DmaBuffer};
    use crate::usb::{
        bluetooth::{Binding, Hci, InitializationReport, Io, Pipe},
        xhci::{self, Device, HIGH_SPEED},
    };
    use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
    pub(in crate::usb::bluetooth) fn binding() -> Binding {
        let mut c = vec![9, 2, 0, 0, 3, 1, 0, 0x80, 50];
        c.extend_from_slice(&[
            9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0, 1, 7, 5, 0x82, 2, 0, 2, 0, 7, 5, 2,
            2, 0, 2, 0,
        ]);
        c.extend_from_slice(&[9, 4, 1, 0, 0, 0xe0, 1, 1, 0]);
        for alt in 1..=6 {
            c.extend_from_slice(&[
                9,
                4,
                1,
                alt,
                2,
                0xe0,
                1,
                1,
                0,
                7,
                5,
                0x83,
                1,
                17 * alt,
                0,
                1,
                7,
                5,
                3,
                1,
                17 * alt,
                0,
                1,
            ]);
        }
        c.extend_from_slice(&[
            9, 4, 2, 0, 0, 0xe0, 1, 1, 0, 9, 4, 2, 1, 2, 0xe0, 1, 1, 0, 7, 5, 0x85, 3, 0, 2, 1, 7,
            5, 5, 3, 0, 2, 1,
        ]);
        let len = c.len() as u16;
        c[2..4].copy_from_slice(&len.to_le_bytes());
        let d = Device {
            id: crate::usb::xhci::SlotId::fixture(1),
            slot: 1,
            speed: HIGH_SPEED,
            location: "synthetic MT7925 media descriptors".into(),
            descriptor: [
                18, 1, 0, 2, 0xe0, 1, 1, 64, 0xd3, 0x13, 2, 0x36, 0, 1, 0, 0, 0, 1,
            ],
            configurations: vec![c.clone()],
            configuration: c,
            manufacturer: None,
            product: None,
            serial: None,
            language: None,
            vendor_ethernet_tcr: None,
            vendor_ethernet_revision: None,
        };
        Binding::new(&d, &xhci::interfaces(&d.configuration)[0]).unwrap()
    }
    struct NoDma;
    impl DmaAllocator for NoDma {
        fn allocate(&mut self, _: usize, _: usize) -> core::result::Result<DmaBuffer, BlockError> {
            panic!("pure model must not allocate DMA")
        }
    }
    #[derive(Default)]
    struct Model {
        events: VecDeque<Vec<u8>>,
        sco: VecDeque<Read>,
        iso: VecDeque<Read>,
        writes: Vec<(Kind, Vec<u8>)>,
        actions: Vec<&'static str>,
        now: core::cell::Cell<u64>,
        tick: u64,
        fail_quiesce: bool,
        output_status: Option<crate::usb::xhci::IsoStatus>,
        status: Option<u8>,
        no_complete: bool,
        reset_credits: u8,
    }
    impl Io for Model {
        fn control(&mut self, _: [u8; 8], p: &[u8]) -> core::result::Result<(), BlockError> {
            if p == [3, 0x0c, 0] {
                self.actions.push("hci-reset");
                if !self.no_complete {
                    self.events.push_back(vec![
                        0xff,
                        1,
                        0xbb,
                        0x0e,
                        4,
                        self.reset_credits,
                        3,
                        0x0c,
                        self.status.unwrap_or(0),
                    ]);
                }
                return Ok(());
            }
            assert_eq!(p, [0x98, 0xfd, 2, 8, 1]);
            self.actions.push("fd98");
            if !self.no_complete {
                self.events.push_back(vec![
                    0x0f,
                    4,
                    0,
                    1,
                    0x98,
                    0xfd,
                    0x0e,
                    4,
                    2,
                    0x98,
                    0xfd,
                    self.status.unwrap_or(0),
                    0xff,
                    1,
                    0xaa,
                ]);
            }
            Ok(())
        }
        fn receive(&mut self, p: Pipe) -> core::result::Result<Option<Vec<u8>>, BlockError> {
            Ok(if p == Pipe::Event {
                self.events.pop_front()
            } else {
                None
            })
        }
        fn write_acl(&mut self, _: &[u8]) -> core::result::Result<(), BlockError> {
            Ok(())
        }
        fn quiesce_bulk(&mut self) -> core::result::Result<(), BlockError> {
            Ok(())
        }
        fn close(&mut self) -> core::result::Result<(), BlockError> {
            self.actions.push("base-close");
            Ok(())
        }
        fn now_us(&self) -> u64 {
            let n = self.now.get();
            self.now
                .set(n + if self.tick == 0 { 1000 } else { self.tick });
            n
        }
    }
    impl MediaIo for Model {
        fn start_iso(
            &mut self,
            p: Pair,
            _: &mut dyn DmaAllocator,
        ) -> core::result::Result<(), BlockError> {
            assert_eq!(p.interface, 2);
            self.actions.push("iso-posted");
            Ok(())
        }
        fn replace_sco(
            &mut self,
            old: Option<Pair>,
            next: Option<Pair>,
            _: &mut dyn DmaAllocator,
        ) -> core::result::Result<(), BlockError> {
            self.actions.push(if old.is_some() {
                "sco-drain-drop-set-configure"
            } else {
                "sco-set-configure"
            });
            assert_ne!(old, next);
            Ok(())
        }
        fn read_media(&mut self, k: Kind) -> core::result::Result<Option<Read>, BlockError> {
            Ok(match k {
                Kind::Sco => self.sco.pop_front(),
                Kind::Iso => self.iso.pop_front(),
            })
        }
        fn write_media(&mut self, k: Kind, p: &[u8]) -> Result<()> {
            self.writes.push((k, p.to_vec()));
            if let Some(status) = self.output_status {
                return Err(Error::OutputCompletion {
                    kind: k,
                    status,
                    expected: p.len(),
                    actual: 0,
                });
            }
            Ok(())
        }
        fn quiesce_media(&mut self) -> core::result::Result<(), BlockError> {
            self.actions.push("quiesce");
            if self.fail_quiesce {
                Err(BlockError::Timeout)
            } else {
                Ok(())
            }
        }
        fn reset_media_epoch(&mut self) -> core::result::Result<(), BlockError> {
            self.actions.push("reset-drain-sco-alt0");
            if self.fail_quiesce {
                return Err(BlockError::Timeout);
            }
            self.sco.clear();
            self.iso.clear();
            Ok(())
        }
        fn resume_media(&mut self) -> core::result::Result<(), BlockError> {
            self.actions.push("resume");
            Ok(())
        }
        fn close_media(&mut self) -> core::result::Result<(), BlockError> {
            self.actions.push("media-close");
            Ok(())
        }
    }
    fn hci(model: Model) -> Hci<Model> {
        use super::super::{
            Chip, FirmwareMetadata, Identity, OwnedReport, RecoveryPolicy, UsbIdentity, WmtEvent,
        };
        use crate::usb::bluetooth::FirmwareReceipt;
        let mut h = Hci::from_io(binding(), model);
        h.initialization = Some(Box::new(Ok(InitializationReport::MediaTek(OwnedReport {
            identity: Identity {
                usb: UsbIdentity {
                    vendor: 0x13d3,
                    product: 0x3602,
                    revision: 0x100,
                },
                legacy_device_id: 0,
                device_id: 0x7925,
                firmware_version: 0,
                flavor: 0,
                chip: Chip::Mt7925,
            },
            firmware: Box::new(FirmwareReceipt {
                name: "synthetic".into(),
                length: 1,
                sha256: [0; 32],
                source: "synthetic".into(),
                revision: "1".into(),
                member: "synthetic".into(),
                license: "CC0-1.0".into(),
                target_driver: "synthetic".into(),
                target_hardware: "synthetic".into(),
                target_revision: "synthetic".into(),
                target_board: None,
            }),
            metadata: FirmwareMetadata {
                header: [0; 32],
                global_descriptor: [0; 64],
                sections: Vec::new(),
                length: 1,
                sha256: [0; 32],
            },
            sections: Vec::new(),
            function_enable: WmtEvent { raw: Vec::new() },
            auxiliary_hci_events: Vec::new(),
            reset_completion: vec![0x0e, 4, 1, 3, 0x0c, 0],
            local_version: [0; 9],
            address: [1; 6],
            recovery: RecoveryPolicy::FreshRebindRequired,
        }))));
        h
    }
    #[test]
    fn command_complete_is_required_and_async_events_preserved_before_handoff() {
        let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
        assert_eq!(s.setup_report().completion, [0x0e, 4, 2, 0x98, 0xfd, 0]);
        assert_eq!(s.setup_report().command_credits, 2);
        assert_eq!(s.hci.io.actions, ["iso-posted", "fd98"]);
        assert_eq!(
            s.poll().unwrap(),
            [
                Received::Hci(crate::usb::bluetooth::Packet::Event(vec![
                    0x0f, 4, 0, 1, 0x98, 0xfd
                ])),
                Received::Hci(crate::usb::bluetooth::Packet::Event(vec![0xff, 1, 0xaa]))
            ]
        );
        for m in [
            Model {
                status: Some(0x0c),
                ..Model::default()
            },
            Model {
                no_complete: true,
                ..Model::default()
            },
        ] {
            assert!(Session::start(hci(m), &mut NoDma, 1).is_err());
        }
        assert!(Session::start(hci(Model::default()), &mut NoDma, 0).is_err());
        assert!(Session::start(Hci::from_io(binding(), Model::default()), &mut NoDma, 1).is_err());
        let mut wrong = hci(Model::default());
        if let Some(Ok(InitializationReport::MediaTek(r))) = wrong.initialization.as_deref_mut() {
            r.identity.chip = super::super::Chip::Mt7922;
        }
        assert!(Session::start(wrong, &mut NoDma, 1).is_err());
    }
    #[test]
    fn media_loss_alt_transition_and_quiescence_never_reassemble_old_partial() {
        let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
        s.poll().unwrap();
        assert!(s.submit(Kind::Sco, &[1, 0, 0]).is_err());
        s.set_voice(
            Voice {
                connections: 1,
                air_mode: AirMode::Cvsd,
                voice_setting: 0,
            },
            &mut NoDma,
        )
        .unwrap();
        s.hci.io.sco.extend([
            Read::Data(vec![1, 0, 2, 9]),
            Read::Loss(Loss::MissedService),
            Read::Data(vec![2, 0, 1, 8]),
        ]);
        assert!(s.poll().unwrap().is_empty());
        assert_eq!(
            s.poll().unwrap(),
            [Received::Loss(Kind::Sco, Loss::MissedService)]
        );
        assert_eq!(s.poll().unwrap(), [Received::Sco(vec![2, 0, 1, 8])]);
        s.submit(Kind::Iso, &[1, 0, 1, 0, 0xaa]).unwrap();
        assert_eq!(s.hci.io.writes[0].1.len(), 264);
        assert!(s.hci.io.writes[0].1[5..].iter().all(|b| *b == 0));
        s.hci.io.sco.push_back(Read::Data(vec![2]));
        s.poll().unwrap();
        s.set_voice(
            Voice {
                connections: 1,
                air_mode: AirMode::Transparent,
                voice_setting: 0,
            },
            &mut NoDma,
        )
        .unwrap();
        s.hci.io.sco.push_back(Read::Data(vec![3, 0, 1, 7]));
        assert_eq!(s.poll().unwrap(), [Received::Sco(vec![3, 0, 1, 7])]);
        s.quiesce().unwrap();
        assert!(s.poll().is_err());
        assert!(s.submit(Kind::Iso, &[1, 0, 0, 0]).is_err());
        s.resume().unwrap();
        assert_eq!(s.lifecycle(), Lifecycle::Running);
        s.hci.io.fail_quiesce = true;
        assert!(s.quiesce().is_err());
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
        assert!(s.resume().is_err());
        assert!(s.close().is_err());
        assert!(
            s.hci
                .io
                .actions
                .ends_with(&["quiesce", "media-close", "base-close"])
        );
    }
    #[test]
    fn setup_refuses_duplicate_short_wrong_status_or_late_completion() {
        let vectors = [
            vec![0x0e, 4, 1, 0x98, 0xfd, 0, 0x0e, 4, 1, 0x98, 0xfd, 0],
            vec![0x0e, 3, 1, 0x98, 0xfd],
            vec![0x0f, 4, 0x0c, 1, 0x98, 0xfd],
            vec![0x0f, 4, 0, 1, 0x98, 0xfd], // Status alone never completes setup.
            vec![0x0e, 4, 1, 0x99, 0xfd, 0],
        ];
        for bytes in vectors {
            let m = Model {
                no_complete: true,
                events: VecDeque::from([bytes]),
                ..Model::default()
            };
            assert!(Session::start(hci(m), &mut NoDma, 1).is_err());
        }
        assert!(
            Session::start(
                hci(Model {
                    tick: 6_000_000,
                    ..Model::default()
                }),
                &mut NoDma,
                1
            )
            .is_err()
        );
        // Complete CC with additional return bytes is retained verbatim; source
        // does not define an exact proprietary return-parameter structure.
        let m = Model {
            no_complete: true,
            events: VecDeque::from([vec![0x0e, 5, 0, 0x98, 0xfd, 0, 0xaa]]),
            ..Model::default()
        };
        let s = Session::start(hci(m), &mut NoDma, 1).unwrap();
        assert_eq!(
            s.setup_report().completion,
            [0x0e, 5, 0, 0x98, 0xfd, 0, 0xaa]
        );
        assert_eq!(s.setup_report().command_credits, 0);
    }
    #[test]
    fn losses_reset_partial_and_closed_or_failed_sessions_cannot_restart_or_reset() {
        for loss in [
            Loss::MissedService,
            Loss::Transaction,
            Loss::Babble,
            Loss::Bandwidth,
            Loss::BufferOverrun,
        ] {
            let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
            s.poll().unwrap();
            s.hci.io.iso.extend([
                Read::Data(vec![1, 0, 3, 0, 8]),
                Read::Loss(loss),
                Read::Data(vec![2, 0, 1, 0, 7]),
            ]);
            assert!(s.poll().unwrap().is_empty());
            assert_eq!(s.poll().unwrap(), [Received::Loss(Kind::Iso, loss)]);
            assert_eq!(s.poll().unwrap(), [Received::Iso(vec![2, 0, 1, 0, 7])]);
            for opcode in [0xfc6fu16, 0xfd98] {
                let [lo, hi] = opcode.to_le_bytes();
                assert!(s.submit_command(&[lo, hi, 0]).is_err());
            }
            assert_eq!(s.lifecycle(), Lifecycle::Running);
            s.close().unwrap();
            s.close().unwrap();
            assert!(s.resume().is_err());
            assert!(s.poll().is_err());
            assert!(s.submit_acl(&[1, 0, 0, 0]).is_err());
        }
        let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
        s.poll().unwrap();
        s.hci.io.iso.push_back(Read::Data(vec![1, 0, 0xff, 0xff]));
        assert!(s.poll().is_err());
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
        assert!(s.resume().is_err());
    }
    #[test]
    fn output_loss_preserves_exact_status_and_counts_and_cannot_credit_delivery() {
        use crate::usb::xhci::IsoStatus;
        let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
        s.set_voice(
            Voice {
                connections: 1,
                air_mode: AirMode::Cvsd,
                voice_setting: 0,
            },
            &mut NoDma,
        )
        .unwrap();
        s.hci.io.output_status = Some(IsoStatus::MissedService);
        let error = s.submit(Kind::Sco, &[1, 0, 2, 9, 8]).unwrap_err();
        match error {
            Error::Cleanup {
                cause,
                media: None,
                base: None,
            } => assert_eq!(
                *cause,
                Error::OutputCompletion {
                    kind: Kind::Sco,
                    status: IsoStatus::MissedService,
                    expected: 5,
                    actual: 0
                }
            ),
            other => panic!("lost typed output diagnostic: {other:?}"),
        }
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
        assert!(s.resume().is_err());
        assert_eq!(s.hci.io.writes.len(), 1);
        assert!(s.submit(Kind::Sco, &[1, 0, 0]).is_err());
        assert_eq!(s.hci.io.writes.len(), 1);
    }
    #[test]
    fn ordinary_reset_after_vendor_setup_forwards_actual_completion_and_credits_without_fd98_reapply()
     {
        let mut s = Session::start(
            hci(Model {
                reset_credits: 3,
                ..Model::default()
            }),
            &mut NoDma,
            1,
        )
        .unwrap();
        s.submit_command(&[3, 0x0c, 0]).unwrap();
        assert_eq!(
            s.hci.io.actions,
            [
                "iso-posted",
                "fd98",
                "reset-drain-sco-alt0",
                "hci-reset",
                "resume"
            ]
        );
        assert_eq!(s.last_reset().unwrap().completion, [0x0e, 4, 3, 3, 0x0c, 0]);
        assert_eq!(s.last_reset().unwrap().command_credits, 3);
        assert_eq!(
            s.poll().unwrap(),
            [
                Received::Hci(crate::usb::bluetooth::Packet::Event(vec![
                    0x0f, 4, 0, 1, 0x98, 0xfd
                ])),
                Received::Hci(crate::usb::bluetooth::Packet::Event(vec![0xff, 1, 0xaa])),
                Received::Hci(crate::usb::bluetooth::Packet::Event(vec![0xff, 1, 0xbb])),
                Received::Hci(crate::usb::bluetooth::Packet::Event(vec![
                    0x0e, 4, 3, 3, 0x0c, 0
                ])),
            ]
        );
        assert_eq!(s.lifecycle(), Lifecycle::Running);
    }
    #[test]
    fn ordinary_reset_retires_active_voice_and_partial_media_until_new_actual_voice_selection() {
        let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
        s.poll().unwrap();
        s.set_voice(
            Voice {
                connections: 1,
                air_mode: AirMode::Cvsd,
                voice_setting: 0,
            },
            &mut NoDma,
        )
        .unwrap();
        s.hci.io.sco.push_back(Read::Data(vec![1, 0, 2, 8]));
        s.hci.io.iso.push_back(Read::Data(vec![1, 0, 2, 0, 8]));
        assert!(s.poll().unwrap().is_empty());
        s.submit_command(&[3, 0x0c, 0]).unwrap();
        assert_eq!(s.last_reset().unwrap().command_credits, 0); // Preserve actual zero, never invent credit.
        assert!(s.submit(Kind::Sco, &[1, 0, 0]).is_err());
        assert!(
            s.poll()
                .unwrap()
                .iter()
                .all(|p| matches!(p, Received::Hci(_)))
        );
        s.set_voice(
            Voice {
                connections: 1,
                air_mode: AirMode::Cvsd,
                voice_setting: 0,
            },
            &mut NoDma,
        )
        .unwrap();
        s.hci.io.sco.push_back(Read::Data(vec![2, 0, 1, 7]));
        s.hci.io.iso.push_back(Read::Data(vec![2, 0, 1, 0, 6]));
        assert_eq!(
            s.poll().unwrap(),
            [
                Received::Iso(vec![2, 0, 1, 0, 6]),
                Received::Sco(vec![2, 0, 1, 7])
            ]
        );
    }
    #[test]
    fn reset_requires_real_matching_success_cc_and_known_media_retirement() {
        for response in [
            vec![0x0f, 4, 0, 1, 3, 0x0c],
            vec![0x0e, 4, 1, 4, 0x0c, 0],
            vec![0x0e, 4, 1, 3, 0x0c, 0x0c],
            vec![0x0e, 3, 1, 3, 0x0c],
            vec![0x0e, 5, 1, 3, 0x0c, 0, 0xaa],
            vec![0x0e, 4, 1, 3, 0x0c, 0, 0x0e, 4, 1, 3, 0x0c, 0],
        ] {
            let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
            s.poll().unwrap();
            s.hci.io.no_complete = true;
            s.hci.io.events.push_back(response);
            assert!(s.submit_command(&[3, 0x0c, 0]).is_err());
            assert_eq!(s.lifecycle(), Lifecycle::Failed);
            assert!(!s.hci.io.actions.contains(&"resume"));
            assert!(s.resume().is_err());
        }
        let mut s = Session::start(hci(Model::default()), &mut NoDma, 1).unwrap();
        assert!(s.submit_command(&[3, 0x0c, 1, 0]).is_err());
        assert_eq!(s.lifecycle(), Lifecycle::Running);
        s.hci.io.fail_quiesce = true;
        assert!(s.submit_command(&[3, 0x0c, 0]).is_err());
        assert!(!s.hci.io.actions.contains(&"hci-reset"));
        assert_eq!(s.lifecycle(), Lifecycle::Failed);
    }
}
