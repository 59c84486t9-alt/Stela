//! The boot log's identity line: which `stela.efi` ran on which PC, so a
//! log a user sends can be matched to a build and to hardware.
use alloc::{format, string::String};

/// What the line names.
pub struct Identity<'a> {
    /// `stela.efi`'s version (its crate version).
    pub version: &'a str,
    /// The CPU's brand string ([`brand`]).
    pub cpu: &'a str,
    /// CPUID leaf 1's EAX: family, model and stepping.
    pub signature: u32,
    /// Every byte the firmware's memory map describes as RAM.
    pub ram_bytes: u64,
    pub firmware_vendor: &'a str,
    pub firmware_revision: u32,
}

/// The CPU brand string CPUID leaves 0x8000_0002..=0x8000_0004 hold, as
/// their EAX, EBX, ECX and EDX in order, without its padding.
pub fn brand(words: [u32; 12]) -> String {
    let mut bytes = [0u8; 48];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().into()
}

/// `HOST version=… cpu="…" family=… model=… stepping=… ram=… firmware="…"`.
pub fn line(identity: &Identity<'_>) -> String {
    let signature = identity.signature;
    let base_family = (signature >> 8) & 0xf;
    let family = if base_family == 0xf {
        base_family + ((signature >> 20) & 0xff)
    } else {
        base_family
    };
    let model = if base_family == 0x6 || base_family == 0xf {
        ((signature >> 12) & 0xf0) | ((signature >> 4) & 0xf)
    } else {
        (signature >> 4) & 0xf
    };
    format!(
        "HOST version={} cpu=\"{}\" family={family:#x} model={model:#x} stepping={} ram={:.1}GB \
         firmware=\"{}\" revision={:#x}\n",
        identity.version,
        identity.cpu,
        signature & 0xf,
        identity.ram_bytes as f64 / 1e9,
        identity.firmware_vendor,
        identity.firmware_revision
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_line_names_build_cpu_ram_and_firmware() {
        let text = b"Intel(R) Core(TM) i7-12700K\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let mut words = [0u32; 12];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes(text[index * 4..index * 4 + 4].try_into().unwrap());
        }
        let cpu = brand(words);
        assert_eq!(cpu, "Intel(R) Core(TM) i7-12700K");
        // Alder Lake: family 6, model 0x97, stepping 2.
        let line = line(&Identity {
            version: "0.1.0",
            cpu: &cpu,
            signature: 0x0009_0672,
            ram_bytes: 16_000_000_000,
            firmware_vendor: "EDK II",
            firmware_revision: 0x10000,
        });
        assert_eq!(
            line,
            "HOST version=0.1.0 cpu=\"Intel(R) Core(TM) i7-12700K\" family=0x6 model=0x97 \
             stepping=2 ram=16.0GB firmware=\"EDK II\" revision=0x10000\n"
        );
        // AMD Zen 4: family 0x19 from the extended family.
        let zen = super::line(&Identity {
            signature: 0x00a6_0f12,
            ..Identity {
                version: "0.1.0",
                cpu: "AMD Ryzen 7 7700X",
                signature: 0,
                ram_bytes: 0,
                firmware_vendor: "AMI",
                firmware_revision: 0,
            }
        });
        assert!(zen.contains("family=0x19 model=0x61 stepping=2"), "{zen}");
    }
}
