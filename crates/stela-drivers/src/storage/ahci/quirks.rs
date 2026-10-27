//! Linux libata's `__ata_dev_quirks`: device quirks by IDENTIFY model
//! number and firmware revision, as `ata_dev_quirks` finds them.

/// `ATA_QUIRK_*`. The driver acts on the public ones; the rest concern
/// devices or commands it does not drive (ATAPI, HPA, TRIM, FUA, the
/// bridge limits and the log directory) and keep the table whole.
pub(super) const DISABLE: u32 = 1 << 0;
pub(super) const NODMA: u32 = 1 << 1;
pub(super) const NONCQ: u32 = 1 << 2;
pub(super) const NOLPM: u32 = 1 << 3;
pub(super) const WD_BROKEN_LPM: u32 = 1 << 4;
pub(super) const BROKEN_FPDMA_AA: u32 = 1 << 5;
pub(super) const NO_DMA_LOG: u32 = 1 << 6;
pub(super) const NOSETXFER: u32 = 1 << 7;
pub(super) const LINK_1_5_GBPS: u32 = 1 << 8;
const MAX_SEC: u32 = 1 << 9;
const MAX_SEC_LBA48: u32 = 1 << 10;
const ATAPI_MOD16_DMA: u32 = 1 << 11;
const FIRMWARE_WARN: u32 = 1 << 12;
const MAX_TRIM_128M: u32 = 1 << 13;
const BROKEN_HPA: u32 = 1 << 14;
const HPA_SIZE: u32 = 1 << 15;
const IVB: u32 = 1 << 16;
const BRIDGE_OK: u32 = 1 << 17;
const NO_NCQ_TRIM: u32 = 1 << 18;
const ZERO_AFTER_TRIM: u32 = 1 << 19;
const NOTRIM: u32 = 1 << 20;
const NO_FUA: u32 = 1 << 21;
const NO_NCQ_ON_ATI: u32 = 1 << 22;
const NO_LPM_ON_ATI: u32 = 1 << 23;
const NO_LOG_DIR: u32 = 1 << 24;

/// A model number glob, an optional firmware revision glob and the quirks.
type Entry = (&'static [u8], Option<&'static [u8]>, u32);

/// The first matching entry decides.
const QUIRKS: &[Entry] = &[
    (b"WDC AC11000H", None, NODMA),
    (b"WDC AC22100H", None, NODMA),
    (b"WDC AC32500H", None, NODMA),
    (b"WDC AC33100H", None, NODMA),
    (b"WDC AC31600H", None, NODMA),
    (b"WDC AC32100H", Some(b"24.09P07"), NODMA),
    (b"WDC AC23200L", Some(b"21.10N21"), NODMA),
    (b"Compaq CRD-8241B", None, NODMA),
    (b"CRD-8400B", None, NODMA),
    (b"CRD-848[02]B", None, NODMA),
    (b"CRD-84", None, NODMA),
    (b"SanDisk SDP3B", None, NODMA),
    (b"SanDisk SDP3B-64", None, NODMA),
    (b"SANYO CD-ROM CRD", None, NODMA),
    (b"HITACHI CDR-8", None, NODMA),
    (b"HITACHI CDR-8[34]35", None, NODMA),
    (b"Toshiba CD-ROM XM-6202B", None, NODMA),
    (b"TOSHIBA CD-ROM XM-1702BC", None, NODMA),
    (b"CD-532E-A", None, NODMA),
    (b"E-IDE CD-ROM CR-840", None, NODMA),
    (b"CD-ROM Drive/F5A", None, NODMA),
    (b"WPI CDD-820", None, NODMA),
    (b"SAMSUNG CD-ROM SC-148C", None, NODMA),
    (b"SAMSUNG CD-ROM SC", None, NODMA),
    (b"ATAPI CD-ROM DRIVE 40X MAXIMUM", None, NODMA),
    (b"_NEC DV5800A", None, NODMA),
    (b"SAMSUNG CD-ROM SN-124", Some(b"N001"), NODMA),
    (b"Seagate STT20000A", None, NODMA),
    (b" 2GB ATA Flash Disk", Some(b"ADMA428M"), NODMA),
    (b"VRFDFC22048UCHC-TE*", None, NODMA),
    (b"Config  Disk", None, DISABLE),
    (b"ASMT109x- Config", None, DISABLE),
    (b"TORiSAN DVD-ROM DRD-N216", None, MAX_SEC),
    (b"QUANTUM DAT    DAT72-000", None, ATAPI_MOD16_DMA),
    (b"Slimtype DVD A  DS8A8SH", None, MAX_SEC_LBA48),
    (b"Slimtype DVD A  DS8A9SH", None, MAX_SEC_LBA48),
    (b"ST380013AS", Some(b"3.20"), MAX_SEC),
    (b"LITEON CX1-JB*-HP", None, MAX_SEC),
    (b"LITEON EP1-*", None, MAX_SEC),
    (b"DELLBOSS VD", Some(b"MV.R00-0"), MAX_SEC),
    (b"WDC WD740ADFD-00", None, NONCQ),
    (b"WDC WD740ADFD-00NLR1", None, NONCQ),
    (b"FUJITSU MHT2060BH", None, NONCQ),
    (b"Maxtor *", Some(b"BANC*"), NONCQ),
    (b"Maxtor 7V300F0", Some(b"VA111630"), NONCQ),
    (b"ST380817AS", Some(b"3.42"), NONCQ),
    (b"ST3160023AS", Some(b"3.42"), NONCQ),
    (b"OCZ CORE_SSD", Some(b"02.10104"), NONCQ),
    (b"ST31500341AS", Some(b"SD1[5-9]"), NONCQ | FIRMWARE_WARN),
    (b"ST31000333AS", Some(b"SD1[5-9]"), NONCQ | FIRMWARE_WARN),
    (b"ST3640[36]23AS", Some(b"SD1[5-9]"), NONCQ | FIRMWARE_WARN),
    (b"ST3320[68]13AS", Some(b"SD1[5-9]"), NONCQ | FIRMWARE_WARN),
    (b"ADATA SU680", None, NOLPM),
    (b"ST1000DM010-2EP102", None, NOLPM),
    (b"ST2000DM008-2FR102", None, NOLPM),
    (b"ST1000LM024 HN-M101MBB", None, BROKEN_FPDMA_AA | NOLPM),
    (b"VB0250EAVER", Some(b"HPG7"), BROKEN_FPDMA_AA),
    (b"HTS541060G9SA00", Some(b"MB3OC60D"), NONCQ),
    (b"HTS541080G9SA00", Some(b"MB4OC60D"), NONCQ),
    (b"HTS541010G9SA00", Some(b"MBZOC60D"), NONCQ),
    (b"C300-CTFDDAC128MAG", Some(b"0001"), NONCQ),
    (b"SanDisk SD[789]*", None, MAX_TRIM_128M),
    (b"HDS724040KLSA80", Some(b"KFAOA20N"), BROKEN_HPA),
    (b"WDC WD3200JD-00KLB0", Some(b"WD-WCAMR1130137"), BROKEN_HPA),
    (b"WDC WD2500JD-00HBB0", Some(b"WD-WMAL71490727"), BROKEN_HPA),
    (b"MAXTOR 6L080L4", Some(b"A93.0500"), BROKEN_HPA),
    (b"OCZ-VERTEX", Some(b"1.30"), BROKEN_HPA),
    (b"ST340823A", None, HPA_SIZE),
    (b"ST320413A", None, HPA_SIZE),
    (b"ST310211A", None, HPA_SIZE),
    (b"QUANTUM FIREBALLlct10 05", Some(b"A03.0900"), IVB),
    (b"TSSTcorp CDDVDW SH-S202[HJN]", Some(b"SB0[01]"), IVB),
    (b"MTRON MSP-SATA*", None, BRIDGE_OK),
    (b"BUFFALO HD-QSU2/R5", None, BRIDGE_OK),
    (b"QEMU HARDDISK", Some(b"2.5+"), BRIDGE_OK),
    (b"WD My Book", None, LINK_1_5_GBPS),
    (b"Seagate FreeAgent GoFlex", None, LINK_1_5_GBPS),
    (b"PIONEER DVD-RW  DVRTD08", None, NOSETXFER),
    (b"PIONEER DVD-RW  DVRTD08A", None, NOSETXFER),
    (b"PIONEER DVD-RW  DVR-215", None, NOSETXFER),
    (b"PIONEER DVD-RW  DVR-212D", None, NOSETXFER),
    (b"PIONEER DVD-RW  DVR-216D", None, NOSETXFER),
    (b"PIONEER BD-RW   BDR-207M", None, NOLPM),
    (b"PIONEER BD-RW   BDR-205", None, NOLPM),
    (b"CT*0BX*00SSD1", None, NOLPM),
    (
        b"Crucial_CT512MX100*",
        Some(b"MU01"),
        NO_NCQ_TRIM | ZERO_AFTER_TRIM | NOLPM,
    ),
    (b"Crucial_CT512MX100*", None, ZERO_AFTER_TRIM | NOLPM),
    (
        b"Crucial_CT480M500*",
        None,
        NO_NCQ_TRIM | ZERO_AFTER_TRIM | NOLPM,
    ),
    (
        b"Crucial_CT960M500*",
        None,
        NO_NCQ_TRIM | ZERO_AFTER_TRIM | NOLPM,
    ),
    (b"R3SL240G", None, NOLPM),
    (b"Apacer AS340*", None, NOLPM),
    (b"PNY CS900 1TB SSD", None, NOLPM),
    (b"MD619HXCLDE3TC", Some(b"TCVAID"), NOLPM),
    (b"MD619GXCLDE3TC", Some(b"TCV35D"), NOLPM),
    (b"SAMSUNG MZMPC128HBFU-000MV", Some(b"CXM14M1Q"), NOLPM),
    (b"SAMSUNG SSD PM830 mSATA *", Some(b"CXM13D1Q"), NOLPM),
    (b"SAMSUNG MZ7TD256HAFV-000L9", None, NOLPM),
    (b"SAMSUNG MZ7TE512HMHP-000L1", Some(b"EXT06L0Q"), NOLPM),
    (
        b"Micron_M500IT_*",
        Some(b"MU01"),
        NO_NCQ_TRIM | ZERO_AFTER_TRIM,
    ),
    (b"Micron_M500_*", None, NO_NCQ_TRIM | ZERO_AFTER_TRIM),
    (
        b"Micron_M5[15]0_*",
        Some(b"MU01"),
        NO_NCQ_TRIM | ZERO_AFTER_TRIM,
    ),
    (b"Micron_1100_*", None, NO_NCQ_TRIM | ZERO_AFTER_TRIM),
    (b"Crucial_CT*M500*", None, NO_NCQ_TRIM | ZERO_AFTER_TRIM),
    (
        b"Crucial_CT*M550*",
        Some(b"MU01"),
        NO_NCQ_TRIM | ZERO_AFTER_TRIM,
    ),
    (
        b"Crucial_CT*MX100*",
        Some(b"MU01"),
        NO_NCQ_TRIM | ZERO_AFTER_TRIM,
    ),
    (
        b"Samsung SSD 840 EVO*",
        None,
        NO_NCQ_TRIM | NO_DMA_LOG | ZERO_AFTER_TRIM,
    ),
    (b"Samsung SSD 840*", None, NO_NCQ_TRIM | ZERO_AFTER_TRIM),
    (b"Samsung SSD 850*", None, NO_NCQ_TRIM | ZERO_AFTER_TRIM),
    (
        b"Samsung SSD 860*",
        None,
        NO_NCQ_TRIM | ZERO_AFTER_TRIM | NO_NCQ_ON_ATI | NO_LPM_ON_ATI,
    ),
    (
        b"Samsung SSD 870*",
        None,
        NO_NCQ_TRIM | ZERO_AFTER_TRIM | NO_NCQ_ON_ATI | NO_LPM_ON_ATI,
    ),
    (
        b"SAMSUNG*MZ7LH*",
        None,
        NO_NCQ_TRIM | ZERO_AFTER_TRIM | NO_NCQ_ON_ATI | NO_LPM_ON_ATI,
    ),
    (b"FCCT*M500*", None, NO_NCQ_TRIM | ZERO_AFTER_TRIM),
    (b"SuperSSpeed S238*", None, NOTRIM),
    (b"M88V29*", None, NOTRIM),
    (b"INTEL*SSDSC2MH*", None, 0),
    (b"Micron*", None, ZERO_AFTER_TRIM),
    (b"Crucial*", None, ZERO_AFTER_TRIM),
    (
        b"INTEL SSDSC2KG480G8",
        Some(b"XCV10120"),
        ZERO_AFTER_TRIM | MAX_SEC,
    ),
    (b"INTEL*SSD*", None, ZERO_AFTER_TRIM),
    (b"SSD*INTEL*", None, ZERO_AFTER_TRIM),
    (b"Samsung*SSD*", None, ZERO_AFTER_TRIM),
    (b"SAMSUNG*SSD*", None, ZERO_AFTER_TRIM),
    (b"SAMSUNG*MZ7KM*", None, ZERO_AFTER_TRIM),
    (b"ST[1248][0248]0[FH]*", None, ZERO_AFTER_TRIM),
    (b"WDC WD800JD-*", None, WD_BROKEN_LPM),
    (b"WDC WD1200JD-*", None, WD_BROKEN_LPM),
    (b"WDC WD1600JD-*", None, WD_BROKEN_LPM),
    (b"WDC WD2000JD-*", None, WD_BROKEN_LPM),
    (b"WDC WD2500JD-*", None, WD_BROKEN_LPM),
    (b"WDC WD3000JD-*", None, WD_BROKEN_LPM),
    (b"WDC WD3200JD-*", None, WD_BROKEN_LPM),
    (b"WDC WD100EFGX-68CPLN0", None, NOLPM),
    (b"WDC WD102KFBX-68M95N0", None, NOLPM),
    (b"WDC WD141KFGX-68FH9N0", None, NOLPM),
    (b"WD Green 2.5 480GB", None, NOLPM),
    (b"SATADOM-ML 3ME", None, NO_LOG_DIR),
    (b"Maxtor", Some(b"BANC1G10"), NO_FUA),
    (b"WDC*WD2500J*", None, NO_FUA),
    (b"OCZ-VERTEX*", None, NO_FUA),
    (b"INTEL*SSDSC2CT*", None, NO_FUA),
];

/// Linux `ata_dev_quirks` for the IDENTIFY strings with trailing spaces
/// removed (`ata_id_c_string`).
pub(super) fn quirks(model: &[u8], firmware: &[u8]) -> u32 {
    QUIRKS
        .iter()
        .find(|(pattern, revision, _)| {
            glob_match(pattern, model)
                && revision.is_none_or(|revision| glob_match(revision, firmware))
        })
        .map_or(0, |entry| entry.2)
}

/// Linux `glob_match`: `?`, `*`, `[...]` classes with ranges and `!`, and
/// `\` escapes.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let at = |bytes: &[u8], index: usize| bytes.get(index).copied().unwrap_or(0);
    let (mut p, mut t) = (0, 0);
    let mut back: Option<(usize, usize)> = None;
    loop {
        let c = at(text, t);
        t += 1;
        let mut d = at(pattern, p);
        p += 1;
        let literal = match d {
            b'?' => {
                if c == 0 {
                    return false;
                }
                continue;
            }
            b'*' => {
                if at(pattern, p) == 0 {
                    return true;
                }
                t -= 1;
                back = Some((p, t));
                continue;
            }
            b'[' if c != 0 => {
                let inverted = at(pattern, p) == b'!';
                let mut class = p + usize::from(inverted);
                let mut a = at(pattern, class);
                class += 1;
                let mut matched = false;
                let mut malformed = false;
                loop {
                    let mut b = a;
                    if a == 0 {
                        malformed = true;
                        break;
                    }
                    if at(pattern, class) == b'-' && at(pattern, class + 1) != b']' {
                        b = at(pattern, class + 1);
                        if b == 0 {
                            malformed = true;
                            break;
                        }
                        class += 2;
                    }
                    matched |= a <= c && c <= b;
                    a = at(pattern, class);
                    class += 1;
                    if a == b']' {
                        break;
                    }
                }
                if malformed {
                    true
                } else if matched == inverted {
                    false
                } else {
                    p = class;
                    continue;
                }
            }
            b'[' => return false,
            b'\\' => {
                d = at(pattern, p);
                p += 1;
                true
            }
            _ => true,
        };
        if literal && c == d {
            if d == 0 {
                return true;
            }
            continue;
        }
        // Try again from the last `*`, one character later in the text.
        match back {
            Some((star, from)) if c != 0 => {
                p = star;
                t = from + 1;
                back = Some((star, t));
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quirks_follow_ata_dev_quirks_and_glob_match() {
        assert!(glob_match(b"ST3640[36]23AS", b"ST3640623AS"));
        assert!(!glob_match(b"ST3640[36]23AS", b"ST3640523AS"));
        assert!(glob_match(b"SD1[5-9]", b"SD17"));
        assert!(glob_match(b"Crucial_CT*MX100*", b"Crucial_CT512MX100SSD1"));
        assert!(!glob_match(b"Maxtor *", b"Maxtor"));
        assert!(glob_match(b"[!a]x", b"bx") && !glob_match(b"[!a]x", b"ax"));
        // The firmware revision narrows an entry; the first match decides.
        assert_eq!(quirks(b"ST31500341AS", b"SD17"), NONCQ | FIRMWARE_WARN);
        assert_eq!(quirks(b"ST31500341AS", b"CC1H"), 0);
        assert_eq!(
            quirks(b"Samsung SSD 840 EVO 250GB", b"EXT0BB6Q"),
            NO_NCQ_TRIM | NO_DMA_LOG | ZERO_AFTER_TRIM
        );
        assert_eq!(quirks(b"INTEL SSDSC2MH120A2", b"PPG4"), 0);
        assert_eq!(quirks(b"INTEL SSDSC2BW240A4", b"DC32"), ZERO_AFTER_TRIM);
    }
}
