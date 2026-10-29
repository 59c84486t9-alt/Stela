//! Recovered gen3 table/data effects, with explicit context validation.
//!
//! The original software walk/leaf builder and fault levels are pinned in
//! `docs/research/dart-iommu.md`. This is not a gen3 MMIO profile: full VA
//! context, untranslated/bypass, security/APF, remap, IRQ and ordering are
//! still independently required. Explicit software contexts can bind their
//! recovered bounds/geometry; native out-of-context faults remain unchecked.
use super::context::{Context, Geometry, PAGE_BYTES as PAGE};
use super::descriptor::Encoding;
use super::handoff::Handoff;
use super::streams::{self, Command, Snapshot};
use crate::Result;
use crate::dart::gen3::fault::{Capture, Code, Level, Record};
use alloc::{vec, vec::Vec};
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::dma::DmaError, stela_contracts::dma::Iommu,
    stela_contracts::dma::Memory,
};

const PA_BITS: u32 = 42;
const TRANSLATE: u32 = 1;
const CONTEXT: u32 = 1 << 3;
const TTBR_VALID: u32 = 1;
const TTBR_ADDRESS: u32 = 0x3fff_fffc;
const ENTRY_VALID: u64 = 1;
const NO_WRITE: u64 = 1 << 2;
const NO_READ: u64 = 1 << 3;
const SUBPAGE_UNIT: u64 = 4;

#[derive(Clone, Copy, Default)]
struct Stream {
    enabled: bool,
    config: u32,
    ttbr: u32,
    context: Option<Context>,
}

pub struct Tables {
    streams: Vec<Stream>,
    encoding: Encoding,
    faults: Capture,
    quiesced: bool,
}

impl Tables {
    pub fn new(streams: usize) -> Result<Self> {
        Self::with_encoding(streams, Encoding::Shift4)
    }

    /// Bind the original builder's explicit RAM encoding. Native revision
    /// and mode validation belong to the profile owner; this constructor
    /// does not infer them from software context or expose an MMIO profile.
    pub fn with_encoding(streams: usize, encoding: Encoding) -> Result<Self> {
        let faults = Capture::new(streams)?;
        Ok(Self {
            streams: vec![Stream::default(); streams],
            encoding,
            faults,
            quiesced: false,
        })
    }

    /// Set only the recovered zero-context translation configurations. The
    /// register owner must enforce protection and supply lifecycle before
    /// calling; this does not implement missing register-security domains.
    pub fn configure(&mut self, sid: usize, config: u32, ttbr: u32) -> Result<()> {
        self.configure_stream(sid, config, ttbr, None)
    }

    /// Bind source-validated software bounds before allowing a high-window
    /// walk. This is not native context/security or MMIO profile admission.
    pub fn configure_context(
        &mut self,
        sid: usize,
        config: u32,
        ttbr: u32,
        context: Context,
    ) -> Result<()> {
        if Geometry::from_tcr(config) != context.geometry() {
            return Err(refuse!(
                "gen3 DART TCR geometry disagrees with its validated context"
            ));
        }
        self.configure_stream(sid, config, ttbr, Some(context))
    }

    /// Use the original native-client root validation for RAM
    /// walks. This still exposes no native MMIO profile: filter, security,
    /// fault metadata and publication completion remain independent gates.
    pub fn configure_handoff(&mut self, sid: usize, ttbr: u32, handoff: Handoff) -> Result<()> {
        if self.encoding != handoff.encoding() {
            return Err(refuse!(
                "gen3 DART RAM encoding disagrees with the qualified handoff"
            ));
        }
        self.configure_stream(sid, handoff.config(), ttbr, Some(handoff.context()))
    }

    fn configure_stream(
        &mut self,
        sid: usize,
        config: u32,
        ttbr: u32,
        context: Option<Context>,
    ) -> Result<()> {
        if config & !(TRANSLATE | CONTEXT) != 0 {
            return Err(refuse!(
                "gen3 DART stream context, remap or filter configuration is unsupported"
            ));
        }
        if ttbr & !(TTBR_VALID | TTBR_ADDRESS) != 0 {
            return Err(refuse!("gen3 DART TTBR contains unmodeled fields"));
        }
        let stream = self.streams.get_mut(sid).ok_or(refuse!(
            "gen3 DART configuration SID is outside its native bounds"
        ))?;
        stream.config = config;
        stream.ttbr = ttbr;
        stream.context = context;
        Ok(())
    }

    pub fn set_enabled(&mut self, sid: usize, enabled: bool) -> Result<()> {
        self.streams
            .get_mut(sid)
            .ok_or(refuse!("gen3 DART enable SID is outside its native bounds"))?
            .enabled = enabled;
        Ok(())
    }

    /// The original readable set-side words. Clear-side readback is not
    /// inferred from an ignored posted-write drain read in the source.
    pub fn read_streams(&self, offset: u64) -> Result<u32> {
        if streams::word(offset, streams::DISABLE).is_ok() {
            return Err(refuse!(
                "gen3 DART clear-side stream readback is unqualified"
            ));
        }
        let word = streams::word(offset, streams::ENABLE)?;
        streams::validate(self.streams.len(), word, 0)?;
        Ok(
            self.streams[word * 32..self.streams.len().min((word + 1) * 32)]
                .iter()
                .enumerate()
                .fold(0, |bits, (sid, stream)| {
                    bits | u32::from(stream.enabled) << sid
                }),
        )
    }

    /// Execute a native set/clear word without changing unselected streams,
    /// translation bindings or pending faults. Validate every bit first.
    pub fn stream_command(&mut self, command: Command) -> Result<()> {
        streams::validate(self.streams.len(), command.word(), command.bits())?;
        let first = command.word() * 32;
        let last = self.streams.len().min(first + 32);
        for (sid, stream) in self.streams[first..last].iter_mut().enumerate() {
            if command.bits() & (1 << sid) != 0 {
                stream.enabled = command.enabled();
            }
        }
        Ok(())
    }

    /// Execute the recovered stream shutdown after the owning
    /// boundary's DSB SY. This saves enable words and disables only
    /// translating streams. It does not claim physical power/reset effects,
    /// clear fault evidence or synthesize MMIO write/error completion.
    pub fn save_disable_translation(&mut self) -> Snapshot {
        let words = (0..self.streams.len().div_ceil(32))
            .map(|word| {
                self.read_streams(streams::ENABLE + word as u64 * 4)
                    .unwrap()
            })
            .collect();
        for stream in &mut self.streams {
            if stream.config & TRANSLATE != 0 {
                stream.enabled = false;
            }
        }
        Snapshot::new(self.streams.len(), words)
    }

    /// Execute the original set-side restore of saved words. This
    /// ORs their bits; it does not replace or clear newly enabled streams.
    /// The register owner must restore/check other state before calling.
    pub fn restore_enables(&mut self, snapshot: &Snapshot) -> Result<()> {
        if snapshot.streams() != self.streams.len() {
            return Err(refuse!(
                "gen3 DART saved enable state belongs to a different SID geometry"
            ));
        }
        for (word, bits) in snapshot.words().iter().copied().enumerate() {
            self.stream_command(Command::decode(streams::ENABLE + word as u64 * 4, bits)?)?;
        }
        Ok(())
    }

    pub fn set_quiesced(&mut self, quiesced: bool) {
        self.quiesced = quiesced;
    }

    pub fn faults(&self) -> &Capture {
        &self.faults
    }

    pub fn acknowledge_faults(&mut self, word: usize, bits: u32) -> Result<()> {
        self.faults.acknowledge(word, bits)
    }

    fn walk(
        &self,
        memory: &mut dyn Memory,
        sid: usize,
        iova: u64,
        last: u64,
        write: bool,
    ) -> Result<u64, WalkError> {
        if self.quiesced {
            return Err(DmaError::Unsupported(refuse!("gen3 DART DMA is quiesced")).into());
        }
        let stream = self.streams.get(sid).ok_or(DmaError::Unsupported(refuse!(
            "gen3 DART incoming stream is outside its native bounds"
        )))?;
        if !stream.enabled {
            return Err(DmaError::Unsupported(refuse!(
                "gen3 DART disabled-stream fault classification"
            ))
            .into());
        }
        if stream.config & TRANSLATE == 0 {
            return Err(
                DmaError::Unsupported(refuse!("gen3 DART untranslated or bypass stream")).into(),
            );
        }
        let indices = match stream.context {
            Some(context) => context.transfer(iova, last),
            None => Geometry::from_tcr(stream.config).zero_indices(iova),
        }
        .map_err(DmaError::Unsupported)?;
        if stream.ttbr & TTBR_VALID == 0 {
            return Err(WalkError::Fault(Code::Invalid, Level::Ttbr));
        }
        let mut table = u64::from(stream.ttbr & TTBR_ADDRESS) << 12;
        if let Some(context) = indices.context() {
            table = next(memory, table, context, Level::Cte, self.encoding)?;
        }
        table = next(memory, table, indices.segment(), Level::Ste, self.encoding)?;
        let leaf = read(memory, table, indices.page())?;
        if leaf & ENTRY_VALID == 0 {
            return Err(WalkError::Fault(Code::Invalid, Level::Pte));
        }
        let target = self.encoding.target(leaf, PA_BITS, PAGE, true)?;
        if write && leaf & NO_WRITE != 0 {
            return Err(WalkError::Fault(Code::Write, Level::Pte));
        }
        if !write && leaf & NO_READ != 0 {
            return Err(WalkError::Fault(Code::Read, Level::Pte));
        }
        let offset = iova & (PAGE - 1);
        let first_unit = leaf >> 52 & 0xfff;
        let last_unit = leaf >> 40 & 0xfff;
        if offset / SUBPAGE_UNIT < first_unit || (last & (PAGE - 1)) / SUBPAGE_UNIT > last_unit {
            return Err(WalkError::Fault(Code::Region, Level::Pte));
        }
        Ok(target + offset)
    }
}

enum WalkError {
    Fault(Code, Level),
    Dma(DmaError),
}

impl From<DmaError> for WalkError {
    fn from(error: DmaError) -> Self {
        Self::Dma(error)
    }
}

fn read(memory: &mut dyn Memory, table: u64, index: u16) -> Result<u64, DmaError> {
    let mut bytes = [0; 8];
    if !memory.read(table + u64::from(index) * 8, &mut bytes) {
        return Err(DmaError::Memory);
    }
    Ok(u64::from_le_bytes(bytes))
}

fn next(
    memory: &mut dyn Memory,
    table: u64,
    index: u16,
    level: Level,
    encoding: Encoding,
) -> Result<u64, WalkError> {
    let entry = read(memory, table, index)?;
    if entry & ENTRY_VALID == 0 {
        return Err(WalkError::Fault(Code::Invalid, level));
    }
    Ok(encoding.target(entry, PA_BITS, PAGE, false)?)
}

impl Iommu for Tables {
    fn page(&self) -> u64 {
        PAGE
    }

    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        sid: usize,
        iova: u64,
        last: u64,
        write: bool,
        _: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        debug_assert!(last >= iova && last / PAGE == iova / PAGE);
        match self.walk(memory, sid, iova, last, write) {
            Ok(physical) => Ok(physical),
            Err(WalkError::Dma(error)) => Err(error),
            Err(WalkError::Fault(code, level)) => {
                let record = Record {
                    code,
                    level,
                    address: iova,
                    write,
                };
                self.faults
                    .capture(sid, record)
                    .map_err(DmaError::Unsupported)?;
                Err(DmaError::Fault(record.class()))
            }
        }
    }
}

#[cfg(test)]
mod tests;
