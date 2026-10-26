// SPDX-License-Identifier: MIT
//! Unowned topology controls cannot disturb any actual current root transfer.
use super::*;

#[test]
fn unowned_hub_port_and_reserved_controls_refuse_before_mmio_and_current_dma() {
    let (mut c, m, id, pipes) = attached();
    let current = c.submit_bulk_in(input(&pipes), 3, 1_000_000).unwrap();
    let before = {
        let p = m.lock().unwrap();
        (
            p.io,
            p.device.clone(),
            p.cpu_syncs,
            p.device_syncs,
            p.setup_trace.clone(),
        )
    };
    for setup in [
        [0x23, 3, 4, 0, 1, 0, 0, 0], // Hub PORT_RESET could create address0.
        [0x23, 3, 8, 0, 1, 0, 0, 0], // Untracked port power.
        [0x23, 1, 1, 0, 1, 0, 0, 0],
        [0xa3, 0, 0, 0, 1, 0, 4, 0], // Topology status belongs to that owner.
        [0x5f, 0x55, 0, 0, 0, 0, 0, 0],
        [0x60, 0, 0, 0, 0, 0, 0, 0],
        [0, 7, 0, 0, 0, 0, 0, 0], // Raw SET_DESCRIPTOR is a standard mutation.
    ] {
        let result = if setup[0] & 0x80 != 0 {
            c.control_in(&id, setup).map(|_| ())
        } else {
            c.control_out(&id, setup, &[])
        };
        assert!(matches!(result, Err(Error::Unsupported(_))));
        let after = {
            let p = m.lock().unwrap();
            (
                p.io,
                p.device.clone(),
                p.cpu_syncs,
                p.device_syncs,
                p.setup_trace.clone(),
            )
        };
        assert_eq!(after, before);
    }
    assert_eq!(c.poll(&current).unwrap().unwrap().data, [0, 1, 2]);
    c.shutdown().unwrap();
}

#[test]
fn admitted_root_device_class_vendor_and_standard_reads_still_use_actual_ep0() {
    let (mut c, m, id, _) = attached();
    for setup in [
        [0x21, 0xff, 0, 0, 0, 0, 0, 0],
        [0x41, 0x55, 0, 0, 0, 0, 0, 0],
    ] {
        let before = m.lock().unwrap().setup_trace.len();
        c.control_out(&id, setup, &[]).unwrap();
        assert_eq!(m.lock().unwrap().setup_trace[before], setup);
    }
    let request = [0x40, 0x56, 0, 0, 0, 0, 3, 0];
    c.control_out(&id, request, &[9, 8, 7]).unwrap();
    assert_eq!(m.lock().unwrap().received, [9, 8, 7]);
    assert_eq!(
        c.control_in(&id, [0x80, 0, 0, 0, 0, 0, 2, 0]).unwrap(),
        [0, 0]
    );
    c.shutdown().unwrap();
}
