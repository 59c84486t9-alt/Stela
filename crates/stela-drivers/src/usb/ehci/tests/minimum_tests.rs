use super::*;
#[test]
fn failed_actual_minimum_keeps_same_cause_and_original_controller_without_later_io() {
    let (mut controller, model, id, _) = attached();
    model.lock().unwrap().minimum_fail = true;
    let before = {
        let m = model.lock().unwrap();
        (m.io, m.writes.clone(), m.unmapped, m.retired)
    };
    let cause = Error::Minimum(crate::bus::pci::power::Error::Clock);
    assert_eq!(controller.wait_minimum(6_000_000), Err(cause));
    assert_eq!(controller.wait_minimum(1), Err(cause));
    assert_eq!(controller.validate(&id), Err(cause));
    assert_eq!(controller.shutdown(), Err(cause));
    let after = {
        let m = model.lock().unwrap();
        (m.io, m.writes.clone(), m.unmapped, m.retired)
    };
    assert_eq!(after, before);
    drop(controller);
    let m = model.lock().unwrap();
    assert_eq!((m.io, m.writes.clone(), m.unmapped, m.retired), before);
}
