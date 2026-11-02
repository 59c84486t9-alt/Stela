//! Forwarding register/clock peers and actual provider Drop witnesses.
use super::super::*;
#[derive(Clone, Copy)]
pub(super) enum Mode {
    Before,
    After,
    PanicBefore,
    PanicAfter,
}
impl Mode {
    pub(super) fn after(self) -> bool {
        matches!(self, Self::After | Self::PanicAfter)
    }
    pub(super) fn panics(self) -> bool {
        matches!(self, Self::PanicBefore | Self::PanicAfter)
    }
}
pub(super) struct Control {
    pub(super) cut: Option<usize>,
    pub(super) mode: Mode,
    pub(super) attempts: Vec<Access>,
    pub(super) effects: Vec<Access>,
    pub(super) clock_calls: usize,
    pub(super) clock_cut: Option<usize>,
    pub(super) drops: u8,
}
impl Control {
    pub(super) fn new() -> Self {
        Self {
            cut: None,
            mode: Mode::Before,
            attempts: Vec::new(),
            effects: Vec::new(),
            clock_calls: 0,
            clock_cut: None,
            drops: 0,
        }
    }
    fn clock(&mut self) -> bool {
        self.clock_calls += 1;
        self.clock_cut == Some(self.clock_calls)
    }
}
pub(super) fn cause() -> IoError {
    IoError::Mmio(crate::bus::mmio::owned::Error::Assignment(
        crate::bus::pci::assignment::Error::Context,
    ))
}
pub(super) struct Gate {
    original: RegisterModel,
    control: Rc<RefCell<Control>>,
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.control.borrow_mut().drops |= 1;
    }
}
impl Gate {
    fn begin(&self, access: Access) -> Option<Mode> {
        let mut control = self.control.borrow_mut();
        control.attempts.push(access);
        (control.cut == Some(control.attempts.len())).then_some(control.mode)
    }
    fn cut(mode: Option<Mode>, after: bool) -> Result<(), IoError> {
        if let Some(mode) = mode.filter(|mode| mode.after() == after) {
            assert!(!mode.panics(), "register callback interrupted");
            return Err(cause());
        }
        Ok(())
    }
}
impl Registers for Gate {
    fn read32(&mut self, offset: usize) -> Result<u32, IoError> {
        let access = Access::Read { offset };
        let mode = self.begin(access);
        Self::cut(mode, false)?;
        let value = self.original.read32(offset)?;
        self.control.borrow_mut().effects.push(access);
        Self::cut(mode, true)?;
        Ok(value)
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), IoError> {
        let access = Access::Write { offset, value };
        let mode = self.begin(access);
        Self::cut(mode, false)?;
        self.original.write32(offset, value)?;
        self.control.borrow_mut().effects.push(access);
        Self::cut(mode, true)
    }
}
pub(super) struct ClockGate {
    original: ModelTimer,
    control: Rc<RefCell<Control>>,
}
impl Drop for ClockGate {
    fn drop(&mut self) {
        self.control.borrow_mut().drops |= 2;
    }
}
impl ClockGate {
    fn check(&self) {
        let panic = self.control.borrow_mut().clock();
        assert!(!panic, "timer callback interrupted");
    }
}
impl Timer for ClockGate {
    fn check_duration(&self, us: u64) -> Result<(), crate::ClockError> {
        self.check();
        self.original.check_duration(us)
    }
    fn now_us(&self) -> u64 {
        self.check();
        self.original.now_us()
    }
    fn start(&self) -> u64 {
        self.check();
        self.original.start()
    }
    fn elapsed_us(&self, start: u64) -> u64 {
        self.check();
        self.original.elapsed_us(start)
    }
    fn relax(&self) {
        self.check();
        self.original.relax();
    }
}
pub(super) type Engine = DesignWare<Gate, ClockGate>;
pub(super) fn providers(control: &Rc<RefCell<Control>>) -> (Gate, ClockGate, Rc<RefCell<Model>>) {
    let (registers, timer) = model(2, 2);
    let peer = registers.0.clone();
    (
        Gate {
            original: registers,
            control: control.clone(),
        },
        ClockGate {
            original: timer,
            control: control.clone(),
        },
        peer,
    )
}
pub(super) fn engine() -> (Engine, Rc<RefCell<Control>>, Rc<RefCell<Model>>) {
    let control = Rc::new(RefCell::new(Control::new()));
    let (registers, timer, peer) = providers(&control);
    (
        DesignWare::new(registers, timer, config()).unwrap(),
        control,
        peer,
    )
}
pub(super) fn transfer(engine: &mut Engine) -> Result<(), Error> {
    engine.transaction(Address::SevenBit(0x2c), &mut [Operation::Write(&[1, 2, 3])])
}
