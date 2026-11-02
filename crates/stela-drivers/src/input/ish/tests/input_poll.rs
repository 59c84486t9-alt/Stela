// SPDX-License-Identifier: GPL-2.0-only
//! Validated input prefix and deny-only interrupted-pass controls.
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

#[test]
fn malformed_later_aggregate_retains_the_validated_report_and_primary_cause() {
    let mut f = running();
    let report = hostif(0x85, 7, &input_bytes());
    let mut body = vec![0x34, 0x12, 2, 0x55];
    body.extend_from_slice(&(report.len() as u16).to_le_bytes());
    body.extend_from_slice(&report);
    // The second size says four bytes, which cannot hold a HostIF header.
    body.extend_from_slice(&4u16.to_le_bytes());
    body.extend_from_slice(&[0; 4]);
    f.peer.push_client(hostif(0x86, 0, &body));
    let polled = f.driver.poll_inputs();
    assert_eq!(
        polled.first_error,
        Some(Error::Protocol(
            "aggregate report smaller than HostIF header"
        ))
    );
    assert_eq!(polled.reports.len(), 1);
    assert_eq!(polled.reports[0].bytes, input_bytes());
    assert_eq!(polled.reports[0].aggregate_total_size, Some(0x1234));
    assert_eq!(polled.reports[0].aggregate_flags, Some(0x55));
    assert!(f.driver.devices().is_empty());
    assert!(f.driver.firmware().is_none());
    let before = effects(&f);
    assert_eq!(f.driver.service(), Err(Error::Terminal));
    assert_eq!(f.driver.start(), Err(Error::Terminal));
    assert!(f.driver.poll_inputs().reports.is_empty());
    assert_eq!(effects(&f), before);
    retained(&f);
}

#[test]
fn post_pop_replenish_refusal_keeps_all_completed_reports() {
    let mut f = running();
    for count in [20, 13] {
        f.peer.push_client(
            (0..count)
                .flat_map(|_| hostif(5, 7, &input_bytes()))
                .collect(),
        );
    }
    f.driver.service().unwrap();
    native::poll_controls::saturate_transmit(&mut f.driver);
    // A real busy mailbox prevents those queued management frames publishing.
    f.peer.raw_write(H2I, BUSY);
    let polled = f.driver.poll_inputs();
    assert_eq!(
        polled.first_error,
        Some(Error::Protocol("bounded IPC transmit queue"))
    );
    assert_eq!(
        polled.reports.len(),
        33,
        "popped report plus the retained queue"
    );
    assert!(
        polled
            .reports
            .iter()
            .all(|report| report.bytes == input_bytes())
    );
    let before = effects(&f);
    assert_eq!(f.driver.service(), Err(Error::Terminal));
    assert!(f.driver.poll_inputs().reports.is_empty());
    assert_eq!(effects(&f), before);
    retained(&f);
}

#[test]
fn interrupted_pump_before_and_after_pop_denies_every_later_physical_path() {
    let mut baseline = running();
    baseline.peer.push_client(hostif(0x85, 7, &input_bytes()));
    let start = baseline.peer.state.lock().unwrap().events.len();
    let result = baseline.driver.poll_inputs();
    assert_eq!(result.first_error, None);
    assert_eq!(result.reports.len(), 1);
    let count = baseline.peer.state.lock().unwrap().events.len() - start;
    assert!(count > 1);
    for cut in [1, count] {
        let mut f = running();
        f.peer.push_client(hostif(0x85, 7, &input_bytes()));
        let start = f.peer.state.lock().unwrap().events.len();
        f.peer.state.lock().unwrap().panic_event_at = Some(start + cut);
        assert!(catch_unwind(AssertUnwindSafe(|| f.driver.poll_inputs())).is_err());
        let before = effects(&f);
        // Even before the process seals local state, the unwind guard has
        // closed endpoint access in the actual already-published callback.
        let registry = f.peer.registry.load(Ordering::Acquire);
        assert!(!registry.is_null());
        // SAFETY: this is the same live isolated fixture registry; its source,
        // route, RAM backing and callback remain retained by this model Native.
        assert!(unsafe { &*registry }.dispatch(f.peer.vector.load(Ordering::Acquire)));
        assert_eq!(effects(&f), before);
        assert_eq!(f.driver.failure(), Some(Error::InputPollInterrupted));
        assert_eq!(f.driver.service(), Err(Error::InputPollInterrupted));
        assert_eq!(f.driver.start(), Err(Error::InputPollInterrupted));
        assert_eq!(f.driver.stop(), Err(Error::InputPollInterrupted));
        assert_eq!(
            f.driver.get_report(7, ReportKind::Input, 1),
            Err(Error::InputPollInterrupted)
        );
        assert_eq!(
            f.driver.set_feature(7, &[1, 2, 3, 4]),
            Err(Error::InputPollInterrupted)
        );
        let polled = f.driver.poll_inputs();
        assert_eq!(polled.first_error, Some(Error::InputPollInterrupted));
        assert_eq!(polled.reports.len(), usize::from(cut == count));
        if cut == count {
            assert_eq!(polled.reports[0].bytes, input_bytes());
        }
        assert_eq!(effects(&f), before);
        retained(&f);
        let peer = f.peer.clone();
        let configs = f.config_counts.clone();
        let bars = f.bar_counts.clone();
        drop(f.driver);
        assert_eq!(peer.state.lock().unwrap().events.len(), before[0]);
        assert_eq!(configs.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(bars.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(peer.domain_drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn cleanup_unwind_preserves_primary_access_error_and_queued_input() {
    let mut f = running();
    f.peer.push_client(hostif(0x85, 7, &input_bytes()));
    f.driver.service().unwrap();
    {
        let mut state = f.peer.state.lock().unwrap();
        state.access_fault = Some(PIMR);
        // The failed read returns without an event. The containment write is
        // the first foreign callback after record has latched the primary.
        state.panic_event_at = Some(state.events.len() + 1);
    }
    assert!(catch_unwind(AssertUnwindSafe(|| f.driver.poll_inputs())).is_err());
    let before = effects(&f);
    let polled = f.driver.poll_inputs();
    assert_eq!(polled.first_error, Some(Error::Access(PIMR)));
    assert_eq!(polled.later_errors, [Error::InputPollInterrupted]);
    assert_eq!(polled.reports.len(), 1);
    assert_eq!(polled.reports[0].bytes, input_bytes());
    assert_eq!(f.driver.stop(), Err(Error::Access(PIMR)));
    assert_eq!(f.driver.service(), Err(Error::Access(PIMR)));
    assert_eq!(effects(&f), before);
    retained(&f);
}

#[test]
fn primary_parse_failure_and_later_containment_failure_both_survive() {
    fn queue_bad(f: &Fixture) {
        let mut message = hostif(0x85, 7, &input_bytes());
        message.push(0); // Validated input followed by a truncated header.
        f.peer.push_client(message);
    }
    let mut baseline = running();
    queue_bad(&baseline);
    let start = baseline.peer.state.lock().unwrap().events.len();
    assert_eq!(
        baseline.driver.poll_inputs().first_error,
        Some(Error::Protocol("truncated HostIF header"))
    );
    let boundary = {
        let state = baseline.peer.state.lock().unwrap();
        let offset = state.events[start..]
            .windows(2)
            .position(|pair| pair[0] == (true, I2H, 0) && !pair[1].0 && pair[1].1 == FWSTS)
            .expect("same mailbox acknowledgement followed by posted read");
        offset + 2
    };
    let mut f = running();
    queue_bad(&f);
    {
        let mut state = f.peer.state.lock().unwrap();
        state.access_fault_event_at = Some((state.events.len() + boundary, PIMR));
    }
    let polled = f.driver.poll_inputs();
    assert_eq!(
        polled.first_error,
        Some(Error::Protocol("truncated HostIF header"))
    );
    assert_eq!(polled.later_errors, [Error::Access(PIMR)]);
    assert_eq!(f.driver.cleanup_failure(), Some(Error::Access(PIMR)));
    assert_eq!(polled.reports.len(), 1);
    assert_eq!(polled.reports[0].bytes, input_bytes());
    retained(&f);
}

#[test]
fn stop_failure_keeps_input_completed_during_disconnect_before_dma_refusal() {
    let mut f = running();
    f.peer.push_client(hostif(0x85, 7, &input_bytes()));
    f.peer.state.lock().unwrap().stuck_dma = true;
    assert_eq!(
        f.driver.stop(),
        Err(Error::Timeout("actual firmware DMA stop"))
    );
    let before = effects(&f);
    let polled = f.driver.poll_inputs();
    assert_eq!(
        polled.first_error,
        Some(Error::Timeout("actual firmware DMA stop"))
    );
    assert_eq!(polled.reports.len(), 1);
    assert_eq!(polled.reports[0].bytes, input_bytes());
    assert_eq!(f.driver.service(), Err(Error::Terminal));
    assert_eq!(effects(&f), before);
    retained(&f);
}
