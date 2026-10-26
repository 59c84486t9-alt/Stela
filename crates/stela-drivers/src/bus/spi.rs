//! Native SPI controller backends. Discovery, board wiring and peripheral
//! protocols remain separate from the controller's actual wire operations.
//!
//! [`amd`] implements the AMDI0061/AMDI0062 opcode/FIFO engine and bounded
//! index-mode memory operations.
//! [`pxa2xx`] implements six Intel LPSS SSP PIO layouts; the retained PCI
//! reset/remap/clock adapter is [`crate::bus::lpss::spi`]. THC/QuickSPI and
//! AMD HID2 DMA are distinct controllers.
pub mod amd;
pub mod pxa2xx;
