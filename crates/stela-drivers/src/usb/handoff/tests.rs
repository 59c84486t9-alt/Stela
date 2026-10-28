use super::*;
use alloc::{collections::BTreeMap, vec::Vec};

fn clock() -> Clock {
    Clock {
        ticks_per_microsecond: 1,
    }
}

/// A model's reaction to one write: its words, the offset and the value.
type React = fn(&mut BTreeMap<usize, u32>, usize, u32);

/// Dword registers with an optional reaction to each write.
#[derive(Default)]
struct Model {
    words: BTreeMap<usize, u32>,
    writes: Vec<(usize, u32)>,
    react: Option<React>,
}

impl Model {
    fn with(words: &[(usize, u32)]) -> Self {
        Self {
            words: words.iter().copied().collect(),
            ..Self::default()
        }
    }
    fn word(&self, offset: usize) -> u32 {
        self.words.get(&offset).copied().unwrap_or(0)
    }
}

impl Dwords for Model {
    fn read32(&mut self, offset: usize) -> u32 {
        self.word(offset)
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.writes.push((offset, value));
        self.words.insert(offset, value);
        if let Some(react) = self.react {
            react(&mut self.words, offset, value);
        }
    }
}

impl Registers for Model {
    fn read8(&mut self, offset: usize) -> u8 {
        (self.word(offset & !3) >> ((offset & 3) * 8)) as u8
    }
    fn read16(&mut self, offset: usize) -> u16 {
        (self.word(offset & !3) >> ((offset & 2) * 8)) as u16
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.write32(offset, u32::from(value));
    }
}

/// Configuration space as dwords, with a reaction to each byte or dword write.
struct Config {
    words: [u32; 64],
    react: fn(&mut [u32; 64], u16),
}

impl Config {
    fn new(react: fn(&mut [u32; 64], u16)) -> Self {
        Self {
            words: [0; 64],
            react,
        }
    }
}

impl ConfigSpace for Config {
    fn read32(&self, offset: u16) -> u32 {
        self.words[usize::from(offset / 4)]
    }
    fn write32(&mut self, offset: u16, value: u32) {
        self.words[usize::from(offset / 4)] = value;
        (self.react)(&mut self.words, offset);
    }
    fn write8(&mut self, offset: u16, value: u8) {
        let word = &mut self.words[usize::from(offset / 4)];
        let shift = (offset & 3) * 8;
        *word = *word & !(0xff << shift) | u32::from(value) << shift;
        (self.react)(&mut self.words, offset);
    }
}

const EECP: u16 = 0x68;

fn ehci_registers() -> Model {
    // CAPLENGTH 0x20, EECP 0x68; the controller halts once RUN clears.
    let mut model = Model::with(&[(0, 0x20), (EHCI_HCCPARAMS, u32::from(EECP) << 8)]);
    model.react = Some(|words, offset, _| {
        let stopped = words.get(&(0x20 + EHCI_USBCMD)).copied().unwrap_or(0) & EHCI_RUN == 0;
        if (offset == 0x20 + EHCI_USBCMD || offset == 0x20 + EHCI_USBSTS) && stopped {
            words.insert(0x20 + EHCI_USBSTS, EHCI_HALTED);
        }
    });
    model
}

#[test]
fn ehci_firmware_releases_its_semaphore_and_its_smis_go_off() {
    let _time = crate::test_clock::virtualize();
    let mut config = Config::new(|words, offset| {
        // Firmware lets go once the OS Owned byte is set.
        if offset == EECP + 3 {
            words[usize::from(EECP / 4)] &= !EHCI_BIOS_OWNED;
        }
    });
    config.words[usize::from(EECP / 4)] = EHCI_LEGSUP | EHCI_BIOS_OWNED;
    config.words[usize::from(EECP / 4) + 1] = 0xe03f_0001;
    let mut registers = ehci_registers();
    registers.words.insert(0x20 + EHCI_USBCMD, EHCI_RUN);
    let handed = ehci(&mut config, &mut registers, 0x400, clock()).unwrap();
    assert_eq!(
        handed,
        Handed {
            from_firmware: true,
            forced: false
        }
    );
    assert_eq!(config.words[usize::from(EECP / 4)], EHCI_LEGSUP | 1 << 24);
    assert_eq!(config.words[usize::from(EECP / 4) + 1], 0);
    assert!(registers.writes.contains(&(0x20 + EHCI_CONFIGFLAG, 0)));
    assert_eq!(registers.word(0x20 + EHCI_USBINTR), 0);
    assert_eq!(registers.word(0x20 + EHCI_USBCMD) & EHCI_RUN, 0);
}

#[test]
fn ehci_firmware_that_keeps_its_semaphore_is_forced_out() {
    let _time = crate::test_clock::virtualize();
    let mut config = Config::new(|_, _| {});
    config.words[usize::from(EECP / 4)] = EHCI_LEGSUP | EHCI_BIOS_OWNED;
    let handed = ehci(&mut config, &mut ehci_registers(), 0x400, clock()).unwrap();
    assert!(handed.from_firmware && handed.forced);
    assert_eq!(config.words[usize::from(EECP / 4)] & EHCI_BIOS_OWNED, 0);
}

#[test]
fn ehci_capability_loop_without_legacy_support_is_malformed() {
    let _time = crate::test_clock::virtualize();
    let mut config = Config::new(|_, _| {});
    // A vendor capability pointing at itself.
    config.words[usize::from(EECP / 4)] = u32::from(EECP) << 8 | 0x0a;
    assert_eq!(
        ehci(&mut config, &mut ehci_registers(), 0x400, clock()),
        Err(Error::Malformed)
    );
}

#[test]
fn ohci_routing_returns_on_ownership_change_or_is_cleared() {
    let _time = crate::test_clock::virtualize();
    for releases in [true, false] {
        let mut registers = Model::with(&[
            (OHCI_CONTROL, OHCI_CTRL_IR | OHCI_CTRL_RWC | 0x80),
            (OHCI_FMINTERVAL, 0x2edf),
        ]);
        if releases {
            registers.react = Some(|words, offset, value| {
                if offset == OHCI_CMDSTATUS && value & OHCI_OCR != 0 {
                    *words.get_mut(&OHCI_CONTROL).unwrap() &= !OHCI_CTRL_IR;
                }
            });
        }
        let handed = ohci(&mut registers, 0x1000, clock()).unwrap();
        assert_eq!(
            handed,
            Handed {
                from_firmware: true,
                forced: !releases
            }
        );
        assert_eq!(registers.word(OHCI_CONTROL), OHCI_CTRL_RWC);
        assert_eq!(registers.word(OHCI_FMINTERVAL), 0x2edf);
        assert!(registers.writes.contains(&(OHCI_INTRDISABLE, u32::MAX)));
    }
}

#[test]
fn uhci_set_up_by_firmware_is_reset_with_legacy_support_cleared() {
    let _time = crate::test_clock::virtualize();
    let mut config = Config::new(|_, _| {});
    config.words[usize::from(UHCI_LEGSUP / 4)] = 0x2010;
    let mut ports = Model::with(&[(UHCI_USBCMD, u32::from(UHCI_RUN | UHCI_CONFIGURE))]);
    let handed = uhci(&mut config, &mut ports, clock()).unwrap();
    assert!(handed.from_firmware);
    assert_eq!(config.read16(UHCI_LEGSUP), UHCI_LEGSUP_RWC);
    assert_eq!(
        ports.writes,
        [
            (UHCI_USBCMD, u32::from(UHCI_HCRESET)),
            (UHCI_USBINTR, 0),
            (UHCI_USBCMD, 0)
        ]
    );
}

#[test]
fn uhci_left_suspended_by_firmware_is_untouched() {
    let _time = crate::test_clock::virtualize();
    let mut config = Config::new(|_, _| {});
    let mut ports = Model::with(&[(UHCI_USBCMD, u32::from(UHCI_CONFIGURE | UHCI_EGSM))]);
    assert_eq!(
        uhci(&mut config, &mut ports, clock()),
        Ok(Handed::default())
    );
    assert!(ports.writes.is_empty());
}

#[test]
fn xhci_legacy_support_is_taken_and_the_controller_halted() {
    let _time = crate::test_clock::virtualize();
    // CAPLENGTH 0x20, xECP at dword 0x100 / 4; a protocol capability first.
    let mut registers = Model::with(&[
        (0, 0x20),
        (XHCI_HCCPARAMS1, (0x100 / 4) << 16),
        (0x100, 2 | 4 << 8),
        (0x110, XHCI_LEGACY | XHCI_BIOS_OWNED),
        (0x114, 0xe001_e011),
        (0x20 + XHCI_USBCMD, XHCI_RUN | XHCI_IRQS),
    ]);
    registers.react = Some(|words, offset, value| {
        if offset == 0x110 && value & XHCI_OS_OWNED != 0 {
            *words.get_mut(&0x110).unwrap() &= !XHCI_BIOS_OWNED;
        }
        if offset == 0x20 + XHCI_USBCMD && value & XHCI_RUN == 0 {
            words.insert(0x20 + XHCI_USBSTS, XHCI_HALTED);
        }
    });
    let handed = xhci(&mut registers, 0x1000, clock()).unwrap();
    assert_eq!(
        handed,
        Handed {
            from_firmware: true,
            forced: false
        }
    );
    assert_eq!(registers.word(0x110), XHCI_LEGACY | XHCI_OS_OWNED);
    // The SMI enables are clear and the RW1C events written back.
    assert_eq!(registers.word(0x114), XHCI_LEGACY_SMI_EVENTS);
    assert_eq!(registers.word(0x20 + XHCI_USBCMD), 0);
}

#[test]
fn registers_reading_all_ones_refuse_the_handoff() {
    let _time = crate::test_clock::virtualize();
    let mut gone = Model::with(&[(XHCI_HCCPARAMS1, u32::MAX), (OHCI_CONTROL, u32::MAX)]);
    assert_eq!(xhci(&mut gone, 0x1000, clock()), Err(Error::Removed));
    assert_eq!(ohci(&mut gone, 0x1000, clock()), Err(Error::Removed));
}

#[test]
fn only_usb_host_interfaces_have_a_kind() {
    assert_eq!(Kind::of([0x0c, 0x03, 0x20]), Some(Kind::Ehci));
    assert_eq!(Kind::of([0x0c, 0x03, 0xfe]), None);
    assert_eq!(Kind::of([0x0c, 0x05, 0x00]), None);
}
