//! Independent DART fault sources wired to one physical AIC input.
//!
//! Original J314s firmware and surface DART nodes both name AIC873. The
//! grouping boundary is a software ownership boundary, not a wired-OR gate.
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;
use stela_contracts::interrupt::AicInput;

/// Keep one owner per physical input across every logical DART group on
/// that input. Bind each translator before publishing its MMIO aperture.
#[derive(Clone)]
pub struct SharedIrq {
    pub(super) input: AicInput,
    levels: Rc<RefCell<Vec<bool>>>,
}

impl SharedIrq {
    pub fn new(input: AicInput) -> Self {
        Self {
            input,
            levels: Rc::new(RefCell::new(Vec::new())),
        }
    }

    pub(super) fn source(&self) -> (Rc<RefCell<Vec<bool>>>, usize) {
        let mut levels = self.levels.borrow_mut();
        let index = levels.len();
        levels.push(false);
        (self.levels.clone(), index)
    }
}
