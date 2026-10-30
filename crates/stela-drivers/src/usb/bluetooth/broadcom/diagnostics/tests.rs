// SPDX-License-Identifier: MIT
//! Independent diagnostic peer and real native bulk endpoints/retirement.
use super::*;
use crate::{
    bus::dma::DmaBuffer,
    usb::{bluetooth::Pipe, xhci},
};
use alloc::{collections::VecDeque, vec, vec::Vec};
struct NoDma;
impl DmaAllocator for NoDma {
    fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, BlockError> {
        panic!("logical peer allocates no DMA")
    }
}
#[derive(Default)]
struct Model {
    starts: Vec<Pair>,
    writes: Vec<[u8; 2]>,
    records: VecDeque<Vec<u8>>,
    events: VecDeque<Vec<u8>>,
    acl: VecDeque<Vec<u8>>,
    commands: Vec<Vec<u8>>,
    close: usize,
    fail_close: bool,
    fail_write: bool,
    fail_read: bool,
    stale: bool,
}
impl Io for Model {
    fn validate(&self) -> Result<(), BlockError> {
        if self.stale {
            Err(BlockError::Unsupported("stale diagnostic fixture"))
        } else {
            Ok(())
        }
    }
    fn control(&mut self, _: [u8; 8], packet: &[u8]) -> Result<(), BlockError> {
        self.commands.push(packet.to_vec());
        Ok(())
    }
    fn receive(&mut self, pipe: Pipe) -> Result<Option<Vec<u8>>, BlockError> {
        Ok(match pipe {
            Pipe::Event => self.events.pop_front(),
            Pipe::Acl => self.acl.pop_front(),
        })
    }
    fn write_acl(&mut self, packet: &[u8]) -> Result<(), BlockError> {
        self.commands.push(packet.to_vec());
        Ok(())
    }
    fn quiesce_bulk(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
    fn close(&mut self) -> Result<(), BlockError> {
        self.close += 1;
        if self.fail_close {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
    fn now_us(&self) -> u64 {
        0
    }
}
impl DiagnosticIo for Model {
    fn diagnostic_retirement(&self) -> Option<&Retirement> {
        None
    }
    fn start_diagnostics(
        &mut self,
        pair: Pair,
        _: &mut dyn DmaAllocator,
    ) -> Result<(), BlockError> {
        self.starts.push(pair);
        Ok(())
    }
    fn read_diagnostic(&mut self) -> Result<Option<Vec<u8>>, BlockError> {
        if self.fail_read {
            Err(BlockError::Timeout)
        } else {
            Ok(self.records.pop_front())
        }
    }
    fn write_diagnostic(&mut self, bytes: [u8; 2]) -> Result<(), BlockError> {
        self.writes.push(bytes);
        if self.fail_write {
            Err(BlockError::Timeout)
        } else {
            Ok(())
        }
    }
}
fn fixture(
    sub: u16,
) -> (
    xhci::Device,
    crate::firmware::Catalog,
    super::super::tests::DiagnosticScript,
) {
    let (mut device, catalog, replies) = super::super::tests::diagnostic_fixture(sub);
    device.configuration.extend([
        9, 4, 1, 0, 0, 0xe0, 1, 1, 0, 9, 4, 2, 0, 2, 0xff, 0xff, 0xff, 0, 7, 5, 0x83, 2, 64, 0, 0,
        7, 5, 3, 2, 64, 0, 0,
    ]);
    device.configuration[4] = 3;
    let n = device.configuration.len() as u16;
    device.configuration[2..4].copy_from_slice(&n.to_le_bytes());
    device.configurations = vec![device.configuration.clone()];
    (device, catalog, replies)
}
fn binding(device: &xhci::Device) -> Binding {
    Binding::new(
        device,
        &crate::usb::descriptor::interfaces(&device.configuration)[0],
    )
    .unwrap()
}
fn hci(sub: u16) -> Hci<Model> {
    let (device, _, _) = fixture(sub);
    let mut h = Hci::from_io(binding(&device), Model::default());
    h.initialization = Some(Box::new(Ok(InitializationReport::Broadcom(
        super::super::tests::initialized_diagnostic_report(sub),
    ))));
    h
}

#[test]
fn broadcom_diagnostic_controls_preserve_wire_and_usb_record_boundaries() {
    for sub in [0x2105, 0x220e, 0x410e] {
        let mut owner = Session::start(hci(sub), &mut NoDma).unwrap();
        assert_eq!(owner.pair().input.address, 0x83);
        assert_eq!(owner.pair().output.address, 3);
        assert_eq!(owner.last_delivery(), None);
        owner.set_enabled(true).unwrap();
        owner.set_enabled(false).unwrap();
        assert_eq!(owner.hci.io.writes, [[0xf0, 1], [0xf0, 0]]);
        assert_eq!(owner.last_delivery(), Some(false));
        owner
            .hci
            .io
            .records
            .extend([vec![], vec![0x0e, 4, 1, 3, 0x0c, 0], vec![0x80; MAX_RECORD]]);
        assert_eq!(owner.poll().unwrap(), [Received::Diagnostic(vec![])]);
        assert_eq!(
            owner.poll().unwrap(),
            [Received::Diagnostic(vec![0x0e, 4, 1, 3, 0x0c, 0])]
        );
        assert_eq!(
            owner.poll().unwrap(),
            [Received::Diagnostic(vec![0x80; MAX_RECORD])]
        );
        assert!(owner.poll().unwrap().is_empty());
        assert!(owner.hci.io.commands.is_empty());
        assert_eq!(owner.initialization().before.version.subversion(), sub);
        owner.close().unwrap();
        assert_eq!(owner.state(), State::Closed);
    }
}

#[test]
fn broadcom_diagnostic_binding_and_initialization_refuse_before_native_start() {
    let raw = Hci::from_io(binding(&fixture(0x220e).0), Model::default());
    assert!(matches!(plan(&raw), Err(Error::Unsupported(_))));
    assert!(raw.io.starts.is_empty());
    for case in 0..6 {
        let mut h = hci(0x220e);
        match case {
            0 => h.binding.device.descriptor[12] ^= 1,
            1 => h.binding.device.configuration.truncate(39),
            2 => {
                let n = h.binding.device.configuration.len();
                h.binding.device.configuration[n - 5] = 2;
            }
            3 => {
                let n = h.binding.device.configuration.len();
                h.binding.device.configuration[n - 6] = 0x83;
            }
            4 => h.binding.device.speed = xhci::SUPER_SPEED,
            _ => h.io.stale = true,
        }
        assert!(plan(&h).is_err(), "case{case}");
        assert!(h.io.starts.is_empty());
        assert!(h.io.writes.is_empty());
    }
}

#[test]
fn broadcom_diagnostic_read_error_keeps_prior_hci_and_enable_error_keeps_delivery_history() {
    let mut owner = Session::start(hci(0x220e), &mut NoDma).unwrap();
    owner.set_enabled(true).unwrap();
    owner.hci.io.fail_write = true;
    owner.hci.io.fail_close = true;
    let Error::Enable { enabled, cause } = owner.set_enabled(false).unwrap_err() else {
        panic!()
    };
    assert!(!enabled);
    assert_eq!(cause.cleanup, Some(BlockError::Timeout));
    assert_eq!(owner.last_delivery(), Some(true));
    assert_eq!(owner.state(), State::Failed);
    let before = owner.hci.io.writes.len();
    assert!(owner.set_enabled(true).is_err());
    assert_eq!(owner.hci.io.writes.len(), before);
    let mut owner = Session::start(hci(0x220e), &mut NoDma).unwrap();
    owner.hci.io.events.push_back(vec![0xff, 1, 0x42]);
    owner.hci.io.fail_read = true;
    assert!(owner.poll().is_err());
    assert_eq!(
        owner.take_pending_observations(),
        [Received::Hci(Packet::Event(vec![0xff, 1, 0x42]))]
    );
    assert!(owner.take_pending_observations().is_empty());
    assert_eq!(owner.state(), State::Failed);
}

#[test]
fn broadcom_diagnostic_stale_generation_cannot_publish_mode_or_consume_pending_records() {
    let mut owner = Session::start(hci(0x220e), &mut NoDma).unwrap();
    owner.hci.io.records.push_back(vec![0xaa]);
    owner.hci.io.stale = true;
    assert!(owner.set_enabled(true).is_err());
    assert!(owner.poll().is_err());
    assert!(owner.close().is_err());
    assert!(owner.hci.io.writes.is_empty());
    assert_eq!(owner.hci.io.records.len(), 1);
    assert_eq!(owner.hci.io.close, 0);
}

#[test]
fn broadcom_diagnostic_original_source_modes_and_oversized_records_are_explicit() {
    use sha2::{Digest, Sha256};
    let trace = include_str!("../../../../../tests/reference/broadcom-diag.txt");
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "95f00d586eec282be6aa284b982786b7e32481d697d2e6bd9e4023026f134939"
    );
    let mut owner = Session::start(hci(0x220e), &mut NoDma).unwrap();
    let (mut count, mut native) = (0, 0);
    for row in trace.lines() {
        let v: Vec<i32> = row.split_whitespace().map(|v| v.parse().unwrap()).collect();
        assert_eq!(v.len(), 10);
        count += 1;
        if v[5] == 0 {
            assert_eq!((v[0], v[1], v[2], v[4], v[6], v[9]), (1, 1, 1, 0, 1, 3));
            owner.set_enabled(v[3] != 0).unwrap();
            assert_eq!(owner.hci.io.writes.last(), Some(&[v[7] as u8, v[8] as u8]));
            native += 1;
        }
    }
    assert_eq!((count, native), (64, 2));
    let over = vec![0xaa; MAX_RECORD + 1];
    owner.hci.io.records.push_back(over.clone());
    let Error::Record { record, cause } = owner.poll().unwrap_err() else {
        panic!()
    };
    assert_eq!(record, over);
    assert!(
        matches!(cause.kind,ErrorKind::TooLarge{maximum:MAX_RECORD,actual}if actual==MAX_RECORD+1)
    );
    assert_eq!(owner.state(), State::Failed);
}

#[test]
fn broadcom_diagnostic_real_native_bulk_mode_records_and_failed_retirement_own_dma() {
    use crate::bus::dma::RegionAllocator;
    use alloc::rc::Rc;
    use core::cell::RefCell;
    for fault in 0..3 {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: exclusively kept aligned fixture backing outlives DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, model) = xhci::model::cancellation_controller(&mut dma);
        let controller = Rc::new(RefCell::new(controller));
        let (mut d, catalog, replies) = fixture(0x220e);
        d.id = controller.borrow().test_device_id(1).unwrap();
        model.borrow_mut().control_script = replies;
        model.borrow_mut().incoming_bulk.insert(7, VecDeque::new());
        model.borrow_mut().outgoing_bulk.insert(6, vec![]);
        let mut h = Hci::attach(controller, &d, binding(&d), &mut dma).unwrap();
        h.initialize_with_provider(
            &catalog,
            crate::usb::bluetooth::intel::PlatformInputs::default(),
        )
        .unwrap();
        assert!(model.borrow().control_script.is_empty());
        let mut owner = h.into_broadcom_diagnostics(&mut dma).unwrap();
        owner.set_enabled(true).unwrap();
        assert_eq!(model.borrow().outgoing_bulk[&6], [vec![0xf0, 1]]);
        model
            .borrow_mut()
            .extend_bulk(7, [vec![0xa5; MAX_RECORD], vec![]]);
        assert_eq!(
            owner.poll().unwrap(),
            [Received::Diagnostic(vec![0xa5; MAX_RECORD])]
        );
        assert_eq!(owner.poll().unwrap(), [Received::Diagnostic(vec![])]);
        assert!(model.borrow().outgoing.is_empty()); // No ACL OUT substitution.
        assert!(owner.poll().unwrap().is_empty()); // Real idle diagnostic RX TD.
        if fault != 0 {
            if fault == 1 {
                model.borrow_mut().short_bulk_out = true;
                model.borrow_mut().fail = Some((15, 19));
            } else {
                model.borrow_mut().halt_transfer = Some(6);
                model.borrow_mut().fail = Some((16, 19));
            }
            let Error::Enable { enabled, cause } = owner.set_enabled(false).unwrap_err() else {
                panic!()
            };
            assert!(!enabled);
            assert!(cause.cleanup.is_some());
            assert_eq!(owner.last_delivery(), Some(true));
            let retired = owner.retirement().unwrap();
            assert_eq!(retired.output_intent, Some([0xf0, 0]));
            assert_eq!(
                retired.output,
                if fault == 1 {
                    Some(xhci::TransferCancellation::Completed(1))
                } else {
                    None
                }
            );
            assert_eq!(owner.state(), State::Failed);
            let before = backing.clone();
            let n = model.borrow().outgoing_bulk[&6].len();
            assert!(owner.set_enabled(false).is_err());
            assert_eq!(backing, before);
            assert_eq!(model.borrow().outgoing_bulk[&6].len(), n);
        } else {
            owner.set_enabled(false).unwrap();
            model.borrow_mut().extend_bulk(7, [vec![0x42, 0, 0xaa]]);
            owner.close().unwrap();
            assert_eq!(owner.state(), State::Closed);
            let input = owner.retirement().unwrap().input.as_ref().unwrap();
            assert_eq!(input.outcome, xhci::TransferCancellation::Completed(3));
            assert_eq!(input.bytes, [0x42, 0, 0xaa]);
        }
    }
}

#[test]
fn broadcom_diagnostic_reentrant_allocator_cannot_retire_foreign_endpoint_or_dma() {
    use crate::bus::dma::RegionAllocator;
    use crate::usb::xhci::{Shared, SlotId, TransferTicket};
    use alloc::rc::Rc;
    use core::cell::RefCell;
    struct Foreign {
        buffer: DmaBuffer,
        ticket: TransferTicket,
        before: Vec<u8>,
    }
    struct Reentrant<'a> {
        dma: &'a mut RegionAllocator,
        controller: Shared,
        id: SlotId,
        endpoint: Endpoint,
        foreign: Rc<RefCell<Option<Foreign>>>,
    }
    impl DmaAllocator for Reentrant<'_> {
        fn allocate(&mut self, bytes: usize, align: usize) -> Result<DmaBuffer, BlockError> {
            let buffer = self.dma.allocate(bytes, align)?;
            if self.foreign.borrow().is_none() {
                let mut controller = self.controller.borrow_mut();
                let mut device = controller.device(self.id)?;
                // This is a distinct endpoint owner, installed only
                // after the diagnostic adapter's allocation admission check.
                device.configure(&[self.endpoint], None, self.dma)?;
                let mut foreign = self.dma.allocate(64, 64)?;
                foreign.bytes_mut().fill(0xa7);
                let before = foreign.bytes().to_vec();
                let ticket = device.submit_ticket(self.endpoint.dci(), foreign.physical(), 64)?;
                *self.foreign.borrow_mut() = Some(Foreign {
                    buffer: foreign,
                    ticket,
                    before,
                });
            }
            Ok(buffer)
        }
    }
    let mut backing = vec![0u64; 128 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: exclusively kept fixture memory outlives both native owners.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let (controller, model) = xhci::model::cancellation_controller(&mut dma);
    let controller = Rc::new(RefCell::new(controller));
    let (mut d, catalog, replies) = fixture(0x220e);
    d.id = controller.borrow().test_device_id(1).unwrap();
    model.borrow_mut().control_script = replies;
    model.borrow_mut().incoming_bulk.insert(7, VecDeque::new());
    let mut h = Hci::attach(controller.clone(), &d, binding(&d), &mut dma).unwrap();
    h.initialize_with_provider(
        &catalog,
        crate::usb::bluetooth::intel::PlatformInputs::default(),
    )
    .unwrap();
    assert!(model.borrow().control_script.is_empty());
    let pair = plan(&h).unwrap();
    let foreign = Rc::new(RefCell::new(None));
    let mut allocator = Reentrant {
        dma: &mut dma,
        controller: controller.clone(),
        id: d.id,
        endpoint: pair.input,
        foreign: foreign.clone(),
    };
    let outcome = h.into_broadcom_diagnostics(&mut allocator);
    let Error::Transport(error) = outcome.err().expect("foreign endpoint must refuse") else {
        panic!()
    };
    assert!(error.cleanup.is_none());
    let foreign = foreign.borrow();
    let foreign = foreign.as_ref().unwrap();
    assert_eq!(foreign.buffer.bytes(), foreign.before);
    assert!(model.borrow().active[7].is_some());
    assert_eq!(model.borrow().state(7), 1); // Real foreign TD remains Running.
    let mut controller = controller.borrow_mut();
    let mut device = controller.device(d.id).unwrap();
    assert_eq!(device.completed_ticket(&foreign.ticket), None); // Ticket was not cancelled or made stale.
    device.cancel_ticket(&foreign.ticket).unwrap();
    device.deconfigure(&[pair.input]).unwrap();
}
