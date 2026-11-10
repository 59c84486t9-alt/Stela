//! A device whose only interrupt is an APIC interrupt, read on a timer.
use super::*;

fn polled() -> (Device<Model, Polled, Time>, Rc<RefCell<Hardware>>) {
    let time = Rc::new(Cell::new(0));
    let h = Rc::new(RefCell::new(Hardware::new(time.clone(), 0x06cb, 0x1234)));
    h.borrow_mut().idle_zero = true;
    let device = Device::new(
        Model(h.clone()),
        Polled(h.clone()),
        Time(time.clone()),
        Rc::new(MinimumTime(time)),
        Address::SevenBit(0x2c),
        0x20,
        100,
    )
    .unwrap();
    (device, h)
}

#[test]
fn a_polled_device_resets_after_the_delay_and_reads_until_empty() {
    let (mut d, h) = polled();
    // A report left from before the reset is read and discarded.
    h.borrow_mut().input.push_back(Hardware::frame(&[17, 1, 2]));
    d.initialize().unwrap();
    assert!(d.is_ready());
    assert_eq!(d.reset_completion(), Some(ResetCompletion::PolledDelay));
    assert_eq!(d.discarded_before_start(), 1);
    assert_eq!(h.borrow().reset_count, 1);
    assert!(h.borrow().input.is_empty());
    assert_eq!(d.report_descriptor(), REPORT_DESCRIPTOR);
}

#[test]
fn an_empty_polled_register_is_no_report_and_data_is_delivered() {
    let (mut d, h) = polled();
    d.initialize().unwrap();
    assert_eq!(d.poll().unwrap(), None);
    assert!(d.is_ready());
    h.borrow_mut().input.push_back(Hardware::frame(&[17, 5, 6]));
    assert_eq!(d.poll().unwrap(), Some(InputReport::Data(vec![17, 5, 6])));
    assert_eq!(d.poll().unwrap(), None);
}
