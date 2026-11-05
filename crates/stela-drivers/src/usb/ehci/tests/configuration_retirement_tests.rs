use super::*;
#[test]
fn exact_irq_or_mapping_retirement_denial_keeps_owner_and_first_cause_without_retry_io() {
    for pin_failure in [true, false] {
        let (mut controller, model, _, _) = attached();
        let cause = if pin_failure {
            model.lock().unwrap().pin_error = Some(crate::bus::irq::IrqError::Route);
            Error::Irq(crate::bus::irq::IrqError::Route)
        } else {
            let error = Error::Mapping(crate::bus::mmio::owned::Error::Unavailable);
            model.lock().unwrap().resource_error = Some(error);
            error
        };
        assert_eq!(controller.shutdown(), Err(cause));
        let before = {
            let m = model.lock().unwrap();
            (m.io, m.writes.clone(), m.unmapped, m.retired, m.detached)
        };
        assert!(!before.3);
        assert_eq!(controller.shutdown(), Err(cause));
        assert_eq!(controller.wait_minimum(1), Err(cause));
        assert_eq!(controller.recover(), Err(cause));
        drop(controller);
        let m = model.lock().unwrap();
        assert_eq!(
            (m.io, m.writes.clone(), m.unmapped, m.retired, m.detached),
            before
        );
    }
}
