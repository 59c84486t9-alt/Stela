// SPDX-License-Identifier: GPL-2.0-only
//! Stop disconnect and containment unwind are separate real frontiers.
use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};
fn effects(f: &Fixture) -> Vec<usize> {
    vec![
        f.peer.state.lock().unwrap().events.len(),
        f.peer.command.load(Ordering::Relaxed),
        usize::from(f.peer.msi.load(Ordering::Relaxed)),
        f.peer.callbacks.load(Ordering::Relaxed),
        f.peer.masks.load(Ordering::Relaxed),
        f.peer.drains.load(Ordering::Relaxed),
        f.config_counts.contexts.load(Ordering::Relaxed),
        f.config_counts.unmaps.load(Ordering::Relaxed),
        f.bar_counts.unmaps.load(Ordering::Relaxed),
        f.peer.root_drops.load(Ordering::Relaxed),
        f.peer.domain_drops.load(Ordering::Relaxed),
    ]
}
fn queue(f: &Fixture, malformed: bool) {
    let mut message = hostif(0x85, 7, &input_bytes());
    if malformed {
        message.push(0);
    }
    f.peer.push_client(message);
}
#[test]
fn disconnect_prefix_and_primary_survive_stop_and_later_containment_unwinds() {
    for malformed in [false, true] {
        let primary = Error::Protocol("truncated HostIF header");
        let mut baseline = running();
        queue(&baseline, malformed);
        let start = baseline.peer.state.lock().unwrap().events.len();
        assert_eq!(
            baseline.driver.stop(),
            Err(if malformed {
                primary
            } else {
                Error::PostedMsiRetirementUnavailable
            })
        );
        let offset = {
            let state = baseline.peer.state.lock().unwrap();
            let offset = state.events[start..]
                .windows(2)
                .position(|pair| pair[0] == (true, I2H, 0) && !pair[1].0 && pair[1].1 == FWSTS)
                .expect("actual input mailbox acknowledgement and posted read");
            // Engine.receive runs after this posted read and before the next
            // foreign register call. For valid input it queued the prefix;
            // for the malformed suffix stop now holds the returned primary.
            if malformed {
                assert!(state.events[start + offset + 2].0);
                assert_eq!(state.events[start + offset + 2].1, PIMR);
            }
            offset + 3
        };
        let mut f = running();
        queue(&f, malformed);
        {
            let mut state = f.peer.state.lock().unwrap();
            state.panic_event_at = Some(state.events.len() + offset);
        }
        assert!(catch_unwind(AssertUnwindSafe(|| f.driver.stop())).is_err());
        let before = effects(&f);
        let registry = f.peer.registry.load(Ordering::Acquire);
        assert!(!registry.is_null());
        // SAFETY: this is the same live isolated fixture registry and its
        // original route/source/callback/RAM owners remain with this Native.
        assert!(unsafe { &*registry }.dispatch(f.peer.vector.load(Ordering::Acquire)));
        assert_eq!(effects(&f), before, "late ISR cannot read or mask endpoint");
        let expected = if malformed {
            primary
        } else {
            Error::StopInterrupted
        };
        assert_eq!(f.driver.failure(), Some(expected));
        let polled = f.driver.poll_inputs();
        assert_eq!(polled.first_error, Some(expected));
        assert_eq!(polled.reports.len(), 1);
        assert_eq!(polled.reports[0].bytes, input_bytes());
        assert_eq!(
            polled.later_errors,
            if malformed {
                vec![Error::StopInterrupted]
            } else {
                vec![]
            }
        );
        assert_eq!(f.driver.service(), Err(expected));
        assert_eq!(f.driver.start(), Err(expected));
        assert_eq!(f.driver.stop(), Err(expected));
        assert_eq!(f.driver.get_report(7, ReportKind::Input, 1), Err(expected));
        assert_eq!(f.driver.set_feature(7, &[1, 2, 3, 4]), Err(expected));
        let repeated = f.driver.poll_inputs();
        assert!(repeated.reports.is_empty());
        assert!(repeated.later_errors.is_empty());
        assert_eq!(effects(&f), before);
        retained(&f);
        let peer = f.peer.clone();
        let counts = f.config_counts.clone();
        let bars = f.bar_counts.clone();
        drop(f.driver);
        assert_eq!(peer.state.lock().unwrap().events.len(), before[0]);
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(bars.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(peer.domain_drops.load(Ordering::Relaxed), 0);
    }
}
