//! Release observations derive from exact retained backing geometry.
use super::*;
use crate::platform::work::ReleasedStackGeometry;
#[test]
fn actual_stack_shape_keeps_entry_eligibility_separate_from_geometry() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let stack = support::mapped(kernel(), 0, &dropped);
    let cold = ReleasedStackGeometry::of(&stack, true);
    let entered = ReleasedStackGeometry::of(&stack, false);
    assert_eq!(cold.usable_bytes(), stack.bounds().len());
    assert_eq!(cold.guard_bytes(), stack.guard.end - stack.guard.start);
    assert!(cold.supports(kernel()));
    assert!(entered.supports(kernel()));
    assert!(cold.unstarted());
    assert!(!entered.unstarted());
    assert_ne!(cold, entered);
    assert!(!cold.supports(StackRequirement::exact(32 * 1024, 4096, 4096).unwrap()));
    assert!(!cold.supports(StackRequirement::at_least(16 * 1024, 4096, 8192).unwrap()));
    assert!(cold.supports(StackRequirement::at_least(16 * 1024, 4096, 4096).unwrap()));
    if let Some(alignment) = cold
        .alignment()
        .checked_mul(2)
        .filter(|n| *n <= isize::MAX as usize)
    {
        assert!(!cold.supports(StackRequirement::exact(16 * 1024, alignment, 4096).unwrap()));
    }
    assert_eq!(dropped.load(Ordering::Relaxed), 0);
    drop(stack);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}
#[test]
fn physical_base_alignment_is_not_copied_from_the_requested_descriptor() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let stack = support::mapped(kernel(), 4096, &dropped);
    let shape = ReleasedStackGeometry::of(&stack, true);
    assert_eq!(shape.alignment(), 4096);
    assert!(!shape.supports(kernel()));
    assert!(shape.supports(StackRequirement::exact(16 * 1024, 4096, 4096).unwrap()));
    assert!(shape.unstarted());
    drop(stack);
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
}
