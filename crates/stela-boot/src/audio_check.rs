//! Explicit native HDA validation after ExitBootServices. This exercises a
//! finite cyclic PCM buffer, not a guest audio bridge or an OEM speaker policy.
use crate::Result;
use crate::output;
use alloc::{vec, vec::Vec};
use stela_contracts::refuse;
use stela_drivers::{
    Handoff,
    audio::{
        Direction, PcmFormat,
        hda::{
            AnalogRoute, CodecGraph, Controller, PinOptions, StreamId, Verb, Vref, WidgetKind, pci,
        },
    },
    bus::{dma::RegionAllocator, i2c::Timer, pci::Function},
};

mod registers;
use samples::{PERIOD_BYTES, PERIODS, Progress, RING_BYTES, pcm};
use stela_boot_core::audio_check_samples as samples;

/// PCI base class 03h.
const DISPLAY_CLASS: u8 = 0x03;
/// Reserved at the end of the host-driver DMA region; storage keeps its prefix.
pub const DMA_BYTES: u64 = 1024 * 1024;
const FORMAT: PcmFormat = PcmFormat {
    rate: 48_000,
    bits: 16,
    channels: 2,
};

use stela_boot_core::options::AudioCheck;

const POLL_US: u64 = 500;
const DEADLINE_US: u64 = 5_000_000;

/// Refuse ambiguous routes. Validation never guesses an OEM output from a
/// codec/vendor identity. This bounded mode requires one standard analog path
/// per direction; more complex boards need explicit platform routing policy.
fn route(graph: &CodecGraph, direction: Direction) -> Result<AnalogRoute> {
    let converter_kind = match direction {
        Direction::Playback => WidgetKind::Output,
        Direction::Capture => WidgetKind::Input,
    };
    let pin_capability = match direction {
        Direction::Playback => 1 << 4,
        Direction::Capture => 1 << 5,
    };
    let widgets: Vec<_> = graph
        .groups
        .iter()
        .flat_map(|group| &group.widgets)
        .collect();
    let mut routes = Vec::new();
    for pin in widgets.iter().filter(|widget| {
        widget.kind == WidgetKind::Pin && widget.pin_capabilities.unwrap_or(0) & pin_capability != 0
    }) {
        for converter in widgets.iter().filter(|widget| {
            widget.kind == converter_kind
                && widget.channels() == FORMAT.channels
                && widget.pcm.supports(FORMAT)
        }) {
            if let Ok(route) = graph.analog_route(direction, pin.node, converter.node) {
                routes.push(route);
            }
        }
    }
    if routes.len() != 1 {
        return Err(refuse!(
            "codec {address} has {routes_len} standard {direction} routes; explicit unambiguous routing required",
            address = graph.address,
            routes_len = routes.len(),
            ?direction
        ));
    }
    Ok(routes.remove(0))
}

/// An explicitly narrower diagnostic for a direct, fixed-gain path whose pin
/// is already enabled. It does not configure or credit function-group power.
/// A missing mandatory D0 capability remains an explicit strict-route failure.
/// This uses graph/readback data and never identifies an emulator.
fn bind_transport<R: stela_drivers::audio::hda::Registers, T: Timer>(
    controller: &mut Controller<R, T>,
    graph: &CodecGraph,
    route: &AnalogRoute,
    stream: StreamId,
) -> Result<()> {
    let group = graph
        .groups
        .iter()
        .find(|group| {
            group
                .widgets
                .iter()
                .any(|widget| widget.node == route.converter())
        })
        .ok_or(refuse!("transport route has no function group"))?;
    if group.power_states != Some(0) {
        return Err(refuse!(
            "transport-only diagnostic requires the explicit unsupported function-group power capability"
        ));
    }
    if route.nodes().len() != 2 {
        return Err(refuse!(
            "transport-only diagnostic requires a direct pin/converter path"
        ));
    }
    for node in route.nodes() {
        let widget = graph
            .widget(*node)
            .ok_or(refuse!("transport widget is missing"))?;
        if widget.power_states.is_some()
            || widget.input_amplifier.is_some_and(|caps| caps != 0)
            || widget.output_amplifier.is_some_and(|caps| caps != 0)
            || widget.channels() != FORMAT.channels
        {
            return Err(refuse!(
                "transport-only diagnostic requires fixed-gain widgets without independent power controls"
            ));
        }
    }
    let pin = controller
        .verb(
            Verb::short(graph.address, route.pin(), 0xf07, 0)
                .map_err(|error| refuse!("pin read verb: {error}", ?error))?,
        )
        .map_err(|error| refuse!("pin readback: {error}", ?error))?;
    let expected = match route.direction() {
        Direction::Playback => 1 << 6,
        Direction::Capture => 1 << 5,
    };
    if pin != expected {
        return Err(refuse!(
            "transport pin {pin} is not already enabled: {pin2:#x}, expected {expected:#x}",
            pin = route.pin(),
            pin2 = pin,
            expected
        ));
    }
    output::arguments(format_args!(
        "AUDIO CHECK transport_binding direction={:?} group={} power_caps=0 pin={} pin_readback={pin:#x} converter={}\n",
        route.direction(),
        group.node,
        route.pin(),
        route.converter()
    ));
    controller
        .bind_converter(graph, route.converter(), stream, 0)
        .map_err(|error| refuse!("transport converter bind: {error}", ?error))
}

/// # Safety
/// The platform explicitly grants sole ownership of one powered conventional
/// HDA controller, including firmware/AML/SMM exclusion. The handoff's ECAM and
/// BARs are mapped uncached at identity addresses; its final DMA_BYTES of
/// coherent identity-mapped RAM are exclusively reserved for this check for the
/// boot, even on failure. The loader identity root must still be active.
pub unsafe fn run(handoff: &Handoff, mode: AudioCheck) -> Result<()> {
    let dma_start = handoff
        .dma
        .end
        .checked_sub(DMA_BYTES)
        .filter(|start| *start >= handoff.dma.start)
        .ok_or(refuse!(
            "host DMA reservation is too small for the audio check"
        ))?;
    // SAFETY: this tail is reserved exclusively; storage uses only the prefix.
    let mut dma = unsafe { RegionAllocator::new(dma_start..handoff.dma.end) };
    let mut functions = Vec::new();
    for window in &handoff.ecam {
        if !handoff.is_mapped(&window.range()) {
            return Err(refuse!("audio ECAM window is not mapped"));
        }
        // SAFETY: mapped and exclusively owned as required by the caller.
        let all = unsafe { Function::enumerate(window) };
        // A GPU's display-audio function (Linux `get_bound_vga`: function 0
        // of the same device is a display controller) has no analog route.
        let display = |function: &Function| {
            all.iter().any(|other| {
                other.address.function == 0
                    && other.address.segment == function.address.segment
                    && other.address.bus == function.address.bus
                    && other.address.device == function.address.device
                    && other.class[0] == DISPLAY_CLASS
            })
        };
        let analog: Vec<usize> = (0..all.len())
            .filter(|&index| pci::identify(&all[index]).is_ok() && !display(&all[index]))
            .collect();
        functions.extend(
            all.into_iter()
                .enumerate()
                .filter(|(index, _)| analog.contains(index))
                .map(|(_, function)| function),
        );
    }
    if functions.len() != 1 {
        return Err(refuse!(
            "audio qualification requires one supported conventional HDA controller, found {functions_len}",
            functions_len = functions.len()
        ));
    }
    let mut function = functions.remove(0);
    let bar = function.bars()[0].ok_or(refuse!("HDA has no BAR0"))?;
    let range = bar.memory().ok_or(refuse!("HDA BAR0 is not memory"))?;
    if !handoff.is_mapped(&range) {
        return Err(refuse!("HDA BAR0 was not mapped uncached"));
    }
    output::arguments(format_args!(
        "AUDIO CHECK pci={} vendor={:04x} device={:04x} bar={range:x?} ownership=exclusive-legacy dma={dma_start:#x}..{:#x}\n",
        function.address, function.vendor, function.device, handoff.dma.end,
    ));
    // SAFETY: explicit platform ownership, live mapped BAR and coherent DMA.
    let prepared = unsafe {
        pci::prepare(
            &mut function,
            bar,
            &handoff.clock,
            pci::Ownership::ExclusiveLegacy,
        )
    }
    .map_err(|error| refuse!("PCI prepare: {error}", ?error))?;
    let config = prepared.config();
    // SAFETY: the prepared PCI function and mapping remain exclusively owned.
    let registers =
        unsafe { prepared.claim_mmio() }.map_err(|error| refuse!("MMIO claim: {error}", ?error))?;
    let registers = registers::Observed::new(registers);
    let snapshot = registers.clone();
    // SAFETY: all controller, MMIO and DMA ownership prerequisites above hold.
    let mut controller = unsafe { Controller::new(registers, handoff.clock, &mut dma, config) }
        .map_err(|error| refuse!("controller start: {error}", ?error))?;
    let result = (|| {
        output::arguments(format_args!(
            "AUDIO CHECK capabilities={:?} codecs={:#x}\n",
            controller.capabilities(),
            controller.codec_mask()
        ));
        let mut graphs = Vec::new();
        for address in 0..15 {
            if controller.codec_mask() & (1 << address) == 0 {
                continue;
            }
            let graph = controller.enumerate_codec(address).map_err(|error| {
                refuse!("codec {address} enumeration: {error}", address, ?error)
            })?;
            output::arguments(format_args!("AUDIO CHECK graph={graph:?}\n"));
            graphs.push(graph);
        }
        if graphs.len() != 1 {
            return Err(refuse!(
                "audio qualification requires one unambiguous codec"
            ));
        }
        let graph = &graphs[0];
        let playback_route = route(graph, Direction::Playback)?;
        let playback = controller
            .allocate_stream(Direction::Playback, FORMAT, PERIOD_BYTES, PERIODS, &mut dma)
            .map_err(|error| refuse!("playback allocation: {error}", ?error))?;
        if mode.transport() {
            bind_transport(&mut controller, graph, &playback_route, playback)?;
        } else {
            controller
                .configure_analog_route(
                    graph,
                    &playback_route,
                    playback,
                    0,
                    PinOptions::Playback {
                        headphone: false,
                        eapd: None,
                    },
                )
                .map_err(|error| refuse!("playback route: {error}", ?error))?;
        }
        let capture = if mode.duplex() {
            let capture_route = route(graph, Direction::Capture)?;
            let capture = controller
                .allocate_stream(Direction::Capture, FORMAT, PERIOD_BYTES, PERIODS, &mut dma)
                .map_err(|error| refuse!("capture allocation: {error}", ?error))?;
            if mode.transport() {
                bind_transport(&mut controller, graph, &capture_route, capture)?;
            } else {
                controller
                    .configure_analog_route(
                        graph,
                        &capture_route,
                        capture,
                        0,
                        PinOptions::Capture {
                            vref: Vref::HighImpedance,
                        },
                    )
                    .map_err(|error| refuse!("capture route: {error}", ?error))?;
            }
            controller
                .fill_capture(capture, 0xa5)
                .map_err(|error| refuse!("capture prefill: {error}", ?error))?;
            output::arguments(format_args!(
                "AUDIO CHECK capture_route={:?} capture_prefill=a5\n",
                capture_route.nodes()
            ));
            Some(capture)
        } else {
            None
        };
        let pcm = pcm();
        controller
            .write_pcm(playback, 0, &pcm)
            .map_err(|error| refuse!("PCM prefill: {error}", ?error))?;
        output::arguments(format_args!(
            "AUDIO CHECK mode={mode:?} scope={} power_gate={} playback_route={:?} rate={} bits={} channels={} ring_bytes={} playback_sha256={}\n",
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
            playback_route.nodes(),
            FORMAT.rate,
            FORMAT.bits,
            FORMAT.channels,
            RING_BYTES,
            stela_formats::sha256(&pcm)
        ));
        if let Some(capture) = capture {
            controller
                .start(capture)
                .map_err(|error| refuse!("capture start: {error}", ?error))?;
        }
        controller
            .start(playback)
            .map_err(|error| refuse!("playback start: {error}", ?error))?;
        let mut streams = vec![("playback", playback, Progress::default())];
        if let Some(capture) = capture {
            streams.push(("capture", capture, Progress::default()));
        }
        let start = handoff.clock.now_us();
        let mut previous_poll = start;
        let mut max_poll_gap = 0;
        loop {
            let now = handoff.clock.now_us();
            // Less than half of the 85ms ring duration; a delayed poll cannot
            // silently be counted as uninterrupted/precisely measured DMA.
            max_poll_gap = max_poll_gap.max(now.saturating_sub(previous_poll));
            if max_poll_gap > 40_000 {
                return Err(refuse!("audio polling gap exceeds observation bound"));
            }
            previous_poll = now;
            for (name, stream, progress) in &mut streams {
                let status = controller
                    .status(*stream)
                    .map_err(|error| refuse!("{name} DMA: {error}", name = *name, ?error))?;
                if !status.running {
                    return Err(refuse!("{name} stream stopped unexpectedly", name = *name));
                }
                progress.observe(status.position_bytes, status.period_completed);
            }
            if streams.iter().all(|(_, _, progress)| progress.passed()) {
                break;
            }
            if now.saturating_sub(start) >= DEADLINE_US {
                return Err(refuse!(
                    "audio progression timed out: {streams}",
                    streams = ?streams
                        .iter()
                        .map(|(name, _, progress)| (*name, progress.wraps, progress.completions))
                        .collect::<Vec<_>>()
                ));
            }
            handoff.clock.delay(POLL_US);
        }
        for (name, stream, progress) in streams {
            controller
                .stop(stream)
                .map_err(|error| refuse!("{name} stop: {error}", name, ?error))?;
            let status = controller
                .status(stream)
                .map_err(|error| refuse!("{name} final status: {error}", name, ?error))?;
            if status.running {
                return Err(refuse!("{name} did not stop", name));
            }
            output::arguments(format_args!(
                "AUDIO CHECK stream={name} changes={} wraps={} completions={} final_position={} elapsed_us={} max_poll_gap_us={} stopped=true dma_errors=0\n",
                progress.changes,
                progress.wraps,
                progress.completions,
                status.position_bytes,
                handoff.clock.now_us().saturating_sub(start),
                max_poll_gap
            ));
        }
        if let Some(capture) = capture {
            let mut capture_pcm = vec![0; RING_BYTES];
            controller
                .read_pcm(capture, 0, &mut capture_pcm)
                .map_err(|error| refuse!("capture read: {error}", ?error))?;
            let changed = capture_pcm.iter().filter(|byte| **byte != 0xa5).count();
            output::arguments(format_args!(
                "AUDIO CHECK capture bytes={} changed={} sha256={}\n",
                capture_pcm.len(),
                changed,
                stela_formats::sha256(&capture_pcm)
            ));
            if changed != RING_BYTES {
                return Err(refuse!(
                    "capture DMA did not replace the complete prefilled ring"
                ));
            }
        }
        Ok(())
    })();
    if result.is_err() {
        snapshot.report(dma_start..handoff.dma.end);
    }
    let shutdown = controller
        .shutdown()
        .map_err(|error| refuse!("controller shutdown: {error}", ?error));
    if shutdown.is_ok() {
        output::arguments(format_args!("AUDIO CHECK shutdown=quiesced\n"));
    }
    match (result, shutdown) {
        (Err(error), Err(shutdown)) => {
            return Err(refuse!("{error}; also {shutdown}", %error, %shutdown));
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }
    output::arguments(format_args!("AUDIO CHECK passed\n"));
    Ok(())
}
