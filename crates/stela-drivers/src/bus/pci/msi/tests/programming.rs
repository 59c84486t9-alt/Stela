// SPDX-License-Identifier: GPL-2.0-only
//! PCI MSI programming fixtures.
use super::*;
use crate::bus::pci::regs;

#[test]
fn programming_order_and_register_widths() {
    for wide in [false, true] {
        for mask in [false, true] {
            let (mut helper, model) = attach(fixture(wide, mask));
            let message = if wide {
                MsiMessage {
                    address: 0x1234_5678_fee0_1000,
                    ..MESSAGE
                }
            } else {
                MESSAGE
            };
            // SAFETY: this message belongs to the synthetic fixture route; its exact
            // RAM config/root owners remain held and no source is active.
            unsafe { helper.program(message) }.unwrap();
            {
                let m = model.lock().unwrap();
                let writes: Vec<_> = m
                    .events
                    .iter()
                    .filter_map(|e| {
                        if let Event::Write(o, w, v) = e {
                            Some((*o, *w, *v))
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(writes[0], (regs::COMMAND, 2, 0x507));
                let disabled = writes
                    .iter()
                    .position(|(o, w, v)| *o == 0x52 && *w == 2 && v & u32::from(ENABLE) == 0)
                    .unwrap();
                let address = writes.iter().position(|(o, _, _)| *o == 0x54).unwrap();
                assert!(disabled < address);
                assert_eq!(m.get(regs::STATUS, 2), 0xa510);
                assert_eq!(m.get(0x52, 2) & u32::from(ENABLE | MME), 0);
                assert_eq!(m.get(0x52, 2) & u32::from(MMC), 5 << 1);
                assert_eq!(m.get(0x54, 4), message.address as u32);
                if wide {
                    assert_eq!(m.get(0x58, 4), (message.address >> 32) as u32);
                }
                assert_eq!(m.get(if wide { 0x5c } else { 0x58 }, 2), message.data);
                assert_eq!(m.get(if wide { 0x5e } else { 0x5a }, 2), 0x5a5a);
                if mask {
                    assert_eq!(m.get(if wide { 0x60 } else { 0x5c }, 4), 0xa5a5_0003);
                }
            }
            // SAFETY: programming kept the synthetic route and original RAM
            // config/root guards. No physical callback or device source exists.
            unsafe { helper.unmask() }.unwrap();
            {
                let m = model.lock().unwrap();
                assert_eq!(m.get(0x52, 2) & u32::from(ENABLE | MME), 1);
                if mask {
                    assert_eq!(m.get(if wide { 0x60 } else { 0x5c }, 4), 0xa5a5_0002);
                }
            }
            helper.mask().unwrap();
            // SAFETY: Reversible masking kept the same programmed route and kept
            // owners; this RAM model has no source or callback to race re-enabling.
            unsafe { helper.unmask() }.unwrap();
            helper.disable().unwrap();
            assert_eq!(
                // SAFETY: Disabling revoked the message, but the original model owners
                // remain live. Rejection must precede any delivery enable.
                unsafe { helper.unmask() },
                Err(MsiError::NotProgrammed)
            );
            // SAFETY: independent model source/CPU callbacks have drained.
            let (function, root) = unsafe { helper.release() }.unwrap();
            assert_eq!(function.address.device, 2);
            drop((function, root));
            assert_eq!(helper.mask(), Err(MsiError::Released));
        }
    }
}
#[test]
fn mask_bitmap_preserves_other_vectors() {
    let f = fixture(true, true);
    f.model.lock().unwrap().put(0x60, 4, u32::MAX);
    let (mut helper, model) = attach(f);
    // SAFETY: The all-ones mask is data in this live RAM config; MESSAGE belongs to
    // the synthetic fixture route and no source is active.
    unsafe { helper.program(MESSAGE) }.unwrap();
    assert_eq!(model.lock().unwrap().get(0x60, 4), u32::MAX);
    // SAFETY: The programmed fixture route and owners remain held; unmask only
    // updates the mutex-protected modeled vector-zero bit.
    unsafe { helper.unmask() }.unwrap();
    assert_eq!(model.lock().unwrap().get(0x60, 4), !1u32);
    helper.mask().unwrap();
    assert_eq!(model.lock().unwrap().get(0x60, 4), u32::MAX);
    drop(
        // SAFETY: This RAM fixture has no device, posted message, callback or deferred
        // work; masking completed synchronously before owner release.
        unsafe { helper.release() }.unwrap(),
    );
}
#[test]
fn message_and_authorization_preflight() {
    let (mut helper, model) = attach(fixture(false, false));
    assert_eq!(
        // SAFETY: The live fixture keeps its route/config owners but has no programmed
        // message; this negative call must fail without enabling delivery.
        unsafe { helper.unmask() },
        Err(MsiError::NotProgrammed)
    );
    for message in [
        MsiMessage {
            address: 1 << 32,
            ..MESSAGE
        },
        MsiMessage {
            address: MESSAGE.address | 1,
            ..MESSAGE
        },
        MsiMessage {
            data: 1 << 16,
            ..MESSAGE
        },
    ] {
        assert_eq!(
            // SAFETY: Each invalid message is tested only against the live isolated
            // RAM model, with no source or callback; validation must reject the
            // value.
            unsafe { helper.program(message) },
            Err(MsiError::InvalidMessage)
        );
    }
    assert!(
        !model
            .lock()
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::Write(..)))
    );
    drop(
        // SAFETY: No message was admitted and the fixture has no asynchronous users or
        // DMA. Returning the original RAM config/root owners is safe.
        unsafe { helper.release() }.unwrap(),
    );
}
