//! Independent native HDA evidence. WAV proves actual playback bytes; the null
//! backend proves capture DMA replaces a poisoned ring, not microphone audio.
use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Child, Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};
use stela_formats::sha256;

const RING_BYTES: usize = 16_384;
const MIN_WRAPS: u64 = 5;
const MIN_COMPLETIONS: u64 = 20;
const MIN_WAV_RINGS: usize = 3;
pub const WAV: &str = "audio-playback.wav";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(super) enum Mode {
    /// Capture actual PCM to a WAV and compare repeated deterministic samples.
    Playback,
    /// Exercise playback and capture DMA with QEMU's silent null audio backend.
    Duplex,
    /// Measure WAV PCM on an existing direct fixed-gain path, with codec power
    /// explicitly unqualified (for a device lacking mandatory FG power caps).
    TransportPlayback,
    /// Measure both DMA engines on that bounded path, using a silent source.
    TransportDuplex,
}

impl Mode {
    pub(super) fn option(self) -> &'static str {
        match self {
            Self::Playback => "playback",
            Self::Duplex => "duplex",
            Self::TransportPlayback => "transport-playback",
            Self::TransportDuplex => "transport-duplex",
        }
    }

    fn playback(self) -> bool {
        matches!(self, Self::Playback | Self::TransportPlayback)
    }

    fn transport(self) -> bool {
        matches!(self, Self::TransportPlayback | Self::TransportDuplex)
    }

    fn duplex(self) -> bool {
        !self.playback()
    }

    pub(super) fn attach(self, command: &mut Command, output: &Path) {
        command.arg("-audiodev").arg(if self.playback() {
            format!(
                "wav,id=host-audio,path={},out.frequency=48000,out.channels=2,out.format=s16",
                super::option_path(&output.join(WAV))
            )
        } else {
            "none,id=host-audio".into()
        });
        command.args([
            "-device",
            "intel-hda,id=host-hda",
            "-device",
            if self.transport() {
                "hda-duplex,id=host-codec,bus=host-hda.0,audiodev=host-audio,mixer=off"
            } else {
                "hda-duplex,id=host-codec,bus=host-hda.0,audiodev=host-audio"
            },
        ]);
    }
}

/// QMP quit follows the mount's terminal serial marker. It runs QEMU's normal
/// backend cleanup, unlike isa-debug-exit. The original WAV is never repaired.
pub(super) fn wait_for_stop(
    child: &mut Child,
    serial: &Path,
    limit: Duration,
) -> Result<Option<ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let stopped = fs::read_to_string(serial)
            .unwrap_or_default()
            .lines()
            .any(|line| line.starts_with("STELA STOPPED code="));
        if stopped {
            let stdin = child.stdin.as_mut().context("audio QMP input is missing")?;
            stdin.write_all(b"{\"execute\":\"qmp_capabilities\",\"id\":\"audio-capabilities\"}\n{\"execute\":\"qom-set\",\"arguments\":{\"path\":\"/machine/peripheral/host-codec\",\"property\":\"realized\",\"value\":false},\"id\":\"audio-close\"}\n{\"execute\":\"quit\",\"id\":\"audio-quit\"}\n")?;
            stdin.flush()?;
            return crate::tools::wait(child, limit.saturating_sub(started.elapsed()));
        }
        if started.elapsed() >= limit {
            crate::tools::stop(child);
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn normal_exit(code: u8, stdout: &str) -> Result<()> {
    ensure!(code == 0, "QEMU did not exit normally through QMP: {code}");
    for id in ["audio-capabilities", "audio-close", "audio-quit"] {
        ensure!(
            stdout
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .any(|response| response["id"] == id
                    && response["return"]
                        .as_object()
                        .is_some_and(|value| value.is_empty())
                    && response.get("error").is_none()),
            "QMP did not acknowledge {id}"
        );
    }
    Ok(())
}

/// Preserve isa-debug-exit's guest status independently of QMP's host-process
/// exit. A successful QMP quit must never turn a guest fatal stop into success.
pub(super) fn guest_exit(serial: &str) -> Result<u8> {
    let line = one_line(serial, "STELA STOPPED")?;
    let hex = line
        .strip_prefix("STELA STOPPED code=0x")
        .and_then(|value| value.strip_suffix("; power off to continue"))
        .context("malformed terminal stop marker")?;
    ensure!(
        !hex.is_empty() && hex.len() <= 2 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid terminal stop code"
    );
    let code = u8::from_str_radix(hex, 16)?;
    ensure!(
        code <= 0x7f,
        "terminal stop code cannot be represented as an exit status"
    );
    Ok((code << 1) | 1)
}

fn pcm() -> Vec<u8> {
    let mut result = Vec::with_capacity(RING_BYTES);
    for frame in 0..RING_BYTES / 4 {
        let sample = ((frame * 73 + 123) % 20_001) as i16 - 10_000;
        result.extend_from_slice(&sample.to_le_bytes());
        result.extend_from_slice(&(-sample).to_le_bytes());
    }
    result
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str> {
    let prefix = format!("{name}=");
    let mut found = line
        .split_ascii_whitespace()
        .filter_map(|word| word.strip_prefix(&prefix));
    let value = found
        .next()
        .with_context(|| format!("missing {name} in {line}"))?;
    ensure!(found.next().is_none(), "duplicate {name} in {line}");
    Ok(value)
}

fn number(line: &str, name: &str) -> Result<u64> {
    field(line, name)?
        .parse()
        .with_context(|| format!("invalid {name} in {line}"))
}

fn one_line<'a>(serial: &'a str, prefix: &str) -> Result<&'a str> {
    let mut lines = serial
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(prefix));
    let line = lines.next().with_context(|| format!("missing {prefix}"))?;
    ensure!(lines.next().is_none(), "duplicate {prefix}");
    Ok(line)
}

fn serial(mode: Mode, serial: &str) -> Result<Value> {
    ensure!(
        !serial
            .lines()
            .any(|line| line.contains("AUDIO CHECK failed")
                || line.contains("FATAL")
                || line.contains("PANIC")),
        "audio run contains a failure marker"
    );
    let header = one_line(serial, "AUDIO CHECK mode=")?;
    ensure!(
        field(header, "mode")? == format!("{mode:?}"),
        "audio mode mismatch"
    );
    ensure!(
        number(header, "rate")? == 48_000
            && number(header, "bits")? == 16
            && number(header, "channels")? == 2
            && number(header, "ring_bytes")? == RING_BYTES as u64,
        "unexpected PCM contract"
    );
    ensure!(
        field(header, "playback_sha256")? == sha256(&pcm()),
        "incorrect playback prefill digest"
    );
    let scope = if mode.transport() {
        "transport-only"
    } else {
        "standard-analog-route"
    };
    let power_gate = if mode.transport() {
        "unsupported-function-group-power"
    } else {
        "passed"
    };
    ensure!(
        field(header, "scope")? == scope && field(header, "power_gate")? == power_gate,
        "audio scope/power gate mismatch"
    );
    let mut streams = Vec::new();
    for name in if mode.duplex() {
        &["playback", "capture"][..]
    } else {
        &["playback"][..]
    } {
        if mode.transport() {
            let direction = if *name == "playback" {
                "Playback"
            } else {
                "Capture"
            };
            let binding = one_line(
                serial,
                &format!("AUDIO CHECK transport_binding direction={direction} "),
            )?;
            ensure!(
                number(binding, "power_caps")? == 0,
                "transport power limitation is missing"
            );
            ensure!(
                field(binding, "pin_readback")?
                    == if *name == "playback" { "0x40" } else { "0x20" },
                "transport pin was not already enabled"
            );
            for id in ["group", "pin", "converter"] {
                ensure!(
                    (1..=127).contains(&number(binding, id)?),
                    "invalid transport node"
                );
            }
        }
        let line = one_line(serial, &format!("AUDIO CHECK stream={name} "))?;
        let wraps = number(line, "wraps")?;
        let completions = number(line, "completions")?;
        let changes = number(line, "changes")?;
        ensure!(
            (MIN_WRAPS..=64).contains(&wraps),
            "{name} ring wrap count out of bounds"
        );
        ensure!(
            (MIN_COMPLETIONS..=1024).contains(&completions),
            "{name} descriptor completion count out of bounds"
        );
        ensure!(
            (MIN_COMPLETIONS..=100_000).contains(&changes),
            "{name} has insufficient/bogus position progression"
        );
        ensure!(
            (1..=5_100_000).contains(&number(line, "elapsed_us")?)
                && (1..=40_000).contains(&number(line, "max_poll_gap_us")?),
            "{name} observation timing is out of bounds"
        );
        ensure!(
            number(line, "final_position")? < RING_BYTES as u64,
            "{name} final position outside ring"
        );
        ensure!(
            field(line, "stopped")? == "true" && number(line, "dma_errors")? == 0,
            "{name} did not stop without observed DMA errors"
        );
        streams.push(json!({"direction": name, "wraps": wraps, "completions": completions, "changes": changes}));
    }
    let capture = if mode.duplex() {
        let route = one_line(serial, "AUDIO CHECK capture_route=")?;
        ensure!(
            field(route, "capture_prefill")? == "a5",
            "missing capture poison prefill"
        );
        let line = one_line(serial, "AUDIO CHECK capture bytes=")?;
        ensure!(
            number(line, "bytes")? == RING_BYTES as u64
                && number(line, "changed")? == RING_BYTES as u64,
            "capture DMA did not overwrite the complete poisoned ring"
        );
        let digest = sha256(&vec![0; RING_BYTES]);
        ensure!(
            field(line, "sha256")? == digest,
            "null-backend capture is not the expected silent PCM"
        );
        Some(
            json!({"bytes": RING_BYTES, "sha256": digest, "source": "QEMU null backend; no injected microphone signal"}),
        )
    } else {
        None
    };
    ensure!(
        one_line(serial, "AUDIO CHECK shutdown=")? == "AUDIO CHECK shutdown=quiesced",
        "controller did not quiesce"
    );
    ensure!(
        one_line(serial, "AUDIO CHECK passed")? == "AUDIO CHECK passed",
        "audio did not pass"
    );
    Ok(
        json!({"mode": mode.option(), "scope": scope, "power_gate": power_gate, "streams": streams, "capture": capture, "shutdown": "quiesced"}),
    )
}

fn le16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

/// Parse finalized RIFF, including size and format, before comparing audio.
fn wav(bytes: &[u8]) -> Result<&[u8]> {
    ensure!(
        bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WAVE",
        "invalid WAV header"
    );
    ensure!(
        le32(bytes, 4) as usize + 8 == bytes.len(),
        "WAV was not finalized or is truncated"
    );
    let mut offset = 12;
    let mut format = false;
    let mut data = None;
    while offset < bytes.len() {
        ensure!(bytes.len() - offset >= 8, "truncated WAV chunk header");
        let size = le32(bytes, offset + 4) as usize;
        let start = offset + 8;
        let end = start
            .checked_add(size)
            .filter(|end| *end <= bytes.len())
            .context("truncated WAV chunk")?;
        match &bytes[offset..offset + 4] {
            b"fmt " => {
                ensure!(!format && size >= 16, "invalid/duplicate WAV format");
                let fmt = &bytes[start..end];
                ensure!(
                    le16(fmt, 0) == 1
                        && le16(fmt, 2) == 2
                        && le32(fmt, 4) == 48_000
                        && le32(fmt, 8) == 192_000
                        && le16(fmt, 12) == 4
                        && le16(fmt, 14) == 16,
                    "WAV is not stereo 48kHz signed 16-bit PCM"
                );
                format = true;
            }
            b"data" => {
                ensure!(
                    data.is_none() && size.is_multiple_of(4),
                    "invalid/duplicate WAV data"
                );
                data = Some(&bytes[start..end]);
            }
            _ => {}
        }
        offset = end
            .checked_add(size & 1)
            .filter(|end| *end <= bytes.len())
            .context("missing WAV chunk padding")?;
    }
    ensure!(format, "missing WAV format");
    data.context("missing WAV PCM data")
}

fn compare_pcm(data: &[u8]) -> Result<Value> {
    let expected = pcm();
    let required = RING_BYTES * MIN_WAV_RINGS;
    // A voice can precede/follow playback with silence. Every intervening byte
    // must match the cyclic PCM; a good excerpt cannot hide a corrupt period.
    for start in (0..data.len().saturating_sub(required).saturating_add(1)).step_by(4) {
        if data.get(start..start + 128) != Some(&expected[..128]) {
            continue;
        }
        ensure!(
            data[..start].iter().all(|byte| *byte == 0),
            "unexpected WAV samples precede the deterministic PCM"
        );
        let matched = data[start..]
            .iter()
            .zip(expected.iter().cycle())
            .take_while(|(actual, expected)| actual == expected)
            .count();
        if matched >= required && data[start + matched..].iter().all(|byte| *byte == 0) {
            return Ok(
                json!({"pcm_bytes": data.len(), "matched_bytes": matched, "matched_rings": matched / RING_BYTES,
                "start_byte": start, "ring_sha256": sha256(&expected), "pcm_sha256": sha256(data)}),
            );
        }
    }
    bail!("WAV lacks {MIN_WAV_RINGS} complete contiguous deterministic PCM rings")
}

pub(super) fn verify(mode: Mode, log: &str, output: &Path) -> Result<Value> {
    let mut report = serial(mode, log)?;
    if mode.playback() {
        let bytes =
            fs::read(output.join(WAV)).context("independent WAV playback evidence is missing")?;
        report["wav"] = compare_pcm(wav(&bytes)?)?;
    }
    report["passed"] = json!(true);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(mode: Mode) -> String {
        let mut log = format!(
            "AUDIO CHECK mode={mode:?} scope={} power_gate={} rate=48000 bits=16 channels=2 ring_bytes={RING_BYTES} playback_sha256={}\n",
            if mode.transport() {
                "transport-only"
            } else {
                "standard-analog-route"
            },
            if mode.transport() {
                "unsupported-function-group-power"
            } else {
                "passed"
            },
            sha256(&pcm())
        );
        for direction in if mode.duplex() {
            &["playback", "capture"][..]
        } else {
            &["playback"][..]
        } {
            if mode.transport() {
                log.push_str(&format!("AUDIO CHECK transport_binding direction={} group=1 power_caps=0 pin=3 pin_readback={} converter=2\n", if *direction == "playback" { "Playback" } else { "Capture" }, if *direction == "playback" { "0x40" } else { "0x20" }));
            }
            log.push_str(&format!("AUDIO CHECK stream={direction} changes=100 wraps=5 completions=20 final_position=0 elapsed_us=430000 max_poll_gap_us=500 stopped=true dma_errors=0\n"));
        }
        if mode.duplex() {
            log.push_str(&format!("AUDIO CHECK capture_route=[4, 5] capture_prefill=a5\nAUDIO CHECK capture bytes={RING_BYTES} changed={RING_BYTES} sha256={}\n", sha256(&vec![0; RING_BYTES])));
        }
        log.push_str("AUDIO CHECK shutdown=quiesced\nAUDIO CHECK passed\n");
        log
    }

    #[test]
    fn normal_exit_requires_qmp_acknowledgement_and_success_status() {
        let responses = "{\"return\":{},\"id\":\"audio-capabilities\"}\n{\"return\":{},\"id\":\"audio-close\"}\n{\"return\":{},\"id\":\"audio-quit\"}\n";
        normal_exit(0, responses).unwrap();
        assert!(normal_exit(33, responses).is_err());
        assert!(normal_exit(0, "").is_err());
        assert!(normal_exit(0, &responses.replace("audio-quit", "wrong-id")).is_err());
        assert!(
            normal_exit(
                0,
                &responses.replace("\"return\":{}", "\"error\":{\"class\":\"GenericError\"}")
            )
            .is_err()
        );
    }

    #[test]
    fn successful_audio_and_qmp_preserve_a_fatal_guest_stop_without_a_scenario_verifier() {
        let audio = log(Mode::TransportDuplex);
        serial(Mode::TransportDuplex, &audio).unwrap();
        normal_exit(0, "{\"return\":{},\"id\":\"audio-capabilities\"}\n{\"return\":{},\"id\":\"audio-close\"}\n{\"return\":{},\"id\":\"audio-quit\"}\n").unwrap();
        let fatal = format!("{audio}STELA STOPPED code=0x11; power off to continue\n");
        assert_eq!(guest_exit(&fatal).unwrap(), 35);
        assert_eq!(guest_exit(&fatal.replace("0x11", "0x10")).unwrap(), 33);
        for invalid in [
            audio,
            format!("{fatal}{fatal}"),
            fatal.replace("0x11", "bad"),
            fatal.replace("0x11", "0x80"),
            fatal.replace("0x11", "0x"),
            fatal.replace("; power off to continue", ""),
        ] {
            assert!(guest_exit(&invalid).is_err());
        }
    }

    #[test]
    fn serial_requires_progress_mode_complete_capture_and_shutdown() {
        for mode in [
            Mode::Playback,
            Mode::Duplex,
            Mode::TransportPlayback,
            Mode::TransportDuplex,
        ] {
            let log = log(mode);
            serial(mode, &log).unwrap();
            for (from, to) in [
                ("wraps=5", "wraps=0"),
                ("changes=100", "changes=0"),
                ("completions=20", "completions=0"),
                ("dma_errors=0", "dma_errors=8"),
                ("stopped=true", "stopped=false"),
                (
                    if mode.transport() {
                        "scope=transport-only"
                    } else {
                        "scope=standard-analog-route"
                    },
                    "scope=fabricated",
                ),
                (
                    if mode.transport() {
                        "power_gate=unsupported-function-group-power"
                    } else {
                        "power_gate=passed"
                    },
                    "power_gate=hidden",
                ),
                ("shutdown=quiesced", "shutdown=failed"),
                ("AUDIO CHECK passed", "AUDIO CHECK failed: transport"),
            ] {
                assert!(serial(mode, &log.replace(from, to)).is_err(), "{from}");
            }
            assert!(
                serial(
                    if mode == Mode::Playback {
                        Mode::Duplex
                    } else {
                        Mode::Playback
                    },
                    &log
                )
                .is_err()
            );
            assert!(serial(mode, &format!("{log}FATAL DMA\n")).is_err());
        }
        let duplex = log(Mode::Duplex);
        assert!(
            serial(
                Mode::Duplex,
                &duplex.replace("changed=16384", "changed=4096")
            )
            .is_err()
        );
        assert!(
            serial(
                Mode::Duplex,
                &duplex.replace(
                    &sha256(&vec![0; RING_BYTES]),
                    &sha256(&vec![0xa5; RING_BYTES])
                )
            )
            .is_err()
        );
    }

    #[test]
    fn independent_payload_requires_multiple_exact_rings() {
        let mut data = vec![0; 32];
        data.extend(pcm().repeat(MIN_WAV_RINGS));
        let verified = compare_pcm(&data).unwrap();
        assert_eq!(verified["start_byte"], 32);
        assert!(compare_pcm(&vec![0; data.len()]).is_err());
        assert!(compare_pcm(&pcm().repeat(MIN_WAV_RINGS - 1)).is_err());
        data[32 + RING_BYTES + 100] ^= 1;
        assert!(compare_pcm(&data).is_err());
        let mut corrupted = pcm().repeat(MIN_WAV_RINGS + 1);
        corrupted[100] ^= 1;
        assert!(compare_pcm(&corrupted).is_err());
        let missing =
            std::env::temp_dir().join(format!("stela-no-audio-evidence-{}", std::process::id()));
        assert!(verify(Mode::Playback, &log(Mode::Playback), &missing).is_err());
    }

    fn wave(data: &[u8]) -> Vec<u8> {
        let mut bytes = b"RIFF".to_vec();
        bytes.extend_from_slice(&(36 + data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(b"WAVEfmt \x10\0\0\0\x01\0\x02\0");
        bytes.extend_from_slice(&48_000u32.to_le_bytes());
        bytes.extend_from_slice(&192_000u32.to_le_bytes());
        bytes.extend_from_slice(b"\x04\0\x10\0data");
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(data);
        bytes
    }

    #[test]
    fn wav_requires_finalized_lengths_and_exact_format() {
        let data = pcm().repeat(MIN_WAV_RINGS);
        let bytes = wave(&data);
        assert_eq!(wav(&bytes).unwrap(), data);
        for length in [0, 4, 12, 20, bytes.len() - 1] {
            assert!(wav(&bytes[..length]).is_err());
        }
        let mut wrong = bytes.clone();
        wrong[24] ^= 1;
        assert!(wav(&wrong).is_err());
        let mut unfinished = bytes;
        unfinished[4..8].fill(0);
        assert!(wav(&unfinished).is_err());
    }
}
