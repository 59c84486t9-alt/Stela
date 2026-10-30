// SPDX-License-Identifier: MIT
//! Owned image metadata shared by explicit native Bluetooth initializers.
//! Receipts keep integrity/provenance evidence without firmware/provider borrows.
use crate::firmware::Image;
use alloc::string::String;

/// Owned receipt survives a later-stage failure without borrowing its provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareReceipt {
    pub name: String,
    pub length: usize,
    pub sha256: [u8; 32],
    pub source: String,
    pub revision: String,
    pub member: String,
    pub license: String,
    pub target_driver: String,
    pub target_hardware: String,
    pub target_revision: String,
    pub target_board: Option<String>,
}
impl From<Image<'_>> for FirmwareReceipt {
    fn from(image: Image<'_>) -> Self {
        let p = image.provenance();
        let t = image.target();
        Self {
            name: image.name().into(),
            length: image.bytes().len(),
            sha256: image.sha256(),
            source: p.source.into(),
            revision: p.revision.into(),
            member: p.member.into(),
            license: p.license.into(),
            target_driver: t.driver.into(),
            target_hardware: t.hardware.into(),
            target_revision: t.revision.into(),
            target_board: t.board.map(Into::into),
        }
    }
}
