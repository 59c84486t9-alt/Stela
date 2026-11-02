use super::*;
use crate::bus::pci::power;
struct FailedWait;
// SAFETY: private isolated device-model fault source; no physical permission.
unsafe impl power::Timer for FailedWait {
    fn check(&self) -> Result<(), power::Error> {
        Ok(())
    }
    fn wait_us(&self, _: u64) -> Result<(), power::Error> {
        Err(power::Error::Clock)
    }
}
#[test]
fn uhci_minimum_failure_leaves_reset_asserted_without_following_stores() {
    let mut config = Config::new(|_, _| {});
    config.words[usize::from(UHCI_LEGSUP / 4)] = 0x2010;
    let mut ports = Model::with(&[(UHCI_USBCMD, u32::from(UHCI_RUN | UHCI_CONFIGURE))]);
    assert_eq!(
        uhci(&mut config, &mut ports, &FailedWait),
        Err(Error::Minimum(power::Error::Clock))
    );
    assert_eq!(ports.writes, [(UHCI_USBCMD, u32::from(UHCI_HCRESET))]);
    assert_eq!(config.read16(UHCI_LEGSUP).unwrap(), UHCI_LEGSUP_RWC);
}
#[test]
fn xhci_failed_firmware_grace_does_not_force_the_semaphore_or_clear_smis() {
    let _time = crate::test_clock::virtualize();
    let mut registers =
        Model::with(&[(0x100, XHCI_LEGACY | XHCI_BIOS_OWNED), (0x104, 0xe001_e011)]);
    assert_eq!(
        xhci_legacy(&mut registers, 0x100, clock(), &FailedWait),
        Err(power::Error::Clock)
    );
    assert_eq!(
        registers.writes,
        [(0x100, XHCI_LEGACY | XHCI_BIOS_OWNED | XHCI_OS_OWNED)]
    );
    assert_eq!(registers.word(0x104), 0xe001_e011);
}
