//! Counter sampling: `sampleCountersInBuffer:atSampleIndex:withBarrier:`,
//! pass and encoder boundary samples, and `resolveCounters:…`.
//!
//! Timestamp samples are timestamp queries. Statistic samples are running
//! sums of pipeline-statistics queries: from its first statistic sample a
//! command buffer counts in intervals of one query each. An interval ends at
//! every sample, at render pass instance and segment boundaries (which no
//! query may span) and around patch draws, whose synthesized vertex stage
//! Metal does not count. A sample is the sum of the intervals before it, so
//! the difference of two samples of one command buffer counts exactly the
//! work between them; samples of different command buffers share no
//! baseline.
use super::{BufferRef, CommandBuffer, Encoder, Recorder, Resolver};
use crate::gpu::metal::{
    binding::AccumulateArguments,
    error::{Result, ensure},
    hazard::Use,
    vulkan::{
        Access, PipelineStages, PipelineStatistics,
        command::Command,
        object::{QueryPool, QueryType},
    },
};
use alloc::vec::Vec;

/// The statistics a pipeline-statistics query counts. Vulkan returns them
/// in bit order: vertex invocations, clipping invocations, clipping
/// primitives, fragment invocations, control patches, evaluation
/// invocations, compute invocations.
pub const STATISTICS: PipelineStatistics = PipelineStatistics::VERTEX_SHADER_INVOCATIONS
    .union(PipelineStatistics::CLIPPING_INVOCATIONS)
    .union(PipelineStatistics::CLIPPING_PRIMITIVES)
    .union(PipelineStatistics::FRAGMENT_SHADER_INVOCATIONS)
    .union(PipelineStatistics::TESSELLATION_CONTROL_SHADER_PATCHES)
    .union(PipelineStatistics::TESSELLATION_EVALUATION_SHADER_INVOCATIONS)
    .union(PipelineStatistics::COMPUTE_SHADER_INVOCATIONS);
const STATISTIC_COUNT: u32 = STATISTICS.bits().count_ones();
const VERTEX_INVOCATIONS: u32 = 0;

/// Bytes of one `MTLCounterResultStatistic`.
pub const STATISTIC_SAMPLE_BYTES: u64 = 64;

/// The query result each `MTLCounterResultStatistic` member sums, in member
/// order: tessellation input patches, vertex invocations, post-tessellation
/// vertex invocations, clipper invocations, clipper primitives out, fragment
/// invocations, fragments passed and compute kernel invocations. Vulkan has
/// no fragments-passed statistic (occlusion queries count samples), so that
/// member keeps `MTLCounterErrorValue`.
const STATISTIC_MEMBERS: [Option<u32>; 8] = [
    Some(4),
    Some(VERTEX_INVOCATIONS),
    Some(5),
    Some(1),
    Some(2),
    Some(3),
    None,
    Some(6),
];

/// `MTLCounterErrorValue`, which unsampled and unsupported values hold.
pub const COUNTER_ERROR_VALUE: u64 = u64::MAX;

/// Where one counter sample lands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterSample {
    Timestamp {
        pool: QueryPool,
        query: u32,
    },
    /// The device address of the sample's `MTLCounterResultStatistic`.
    Statistic(u64),
}

/// The samples `resolveCounters:inRange:…` copies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterRange {
    Timestamps {
        pool: QueryPool,
        first: u32,
        count: u32,
    },
    /// The range's `MTLCounterResultStatistic`s.
    Statistics(BufferRef),
}

/// The statistics a command buffer counts.
#[derive(Debug, Default)]
pub(super) struct Statistics {
    /// The pool queries come from: (pool, next query, query count).
    pool: Option<(QueryPool, u32, u32)>,
    /// The counting interval's query and whether it holds a patch draw.
    active: Option<(QueryPool, u32, bool)>,
    /// Ended intervals in order.
    intervals: Vec<(QueryPool, u32, bool)>,
    /// Unresolved samples: destination and the intervals before it.
    samples: Vec<(u64, u32)>,
}

impl Recorder {
    /// Ends the counting interval, if statistics count.
    pub(super) fn pause_statistics(&mut self) {
        let Some(statistics) = self.statistics.as_mut() else {
            return;
        };
        if let Some((pool, query, tessellated)) = statistics.active.take() {
            statistics.intervals.push((pool, query, tessellated));
            self.push(Command::EndQuery { pool, query });
        }
    }

    /// Starts the next interval, if statistics count.
    pub(super) fn resume_statistics(
        &mut self,
        resolver: &mut dyn Resolver,
        tessellated: bool,
    ) -> Result<()> {
        let Some(statistics) = self.statistics.as_mut() else {
            return Ok(());
        };
        debug_assert!(statistics.active.is_none());
        let (pool, query) = match statistics.pool {
            Some((pool, next, count)) if next < count => {
                statistics.pool = Some((pool, next + 1, count));
                (pool, next)
            }
            _ => {
                let (pool, count) = resolver.query_pool(QueryType::PipelineStatistics)?;
                ensure(count > 0, "statistics pools hold queries")?;
                statistics.pool = Some((pool, 1, count));
                self.query_pools.push((QueryType::PipelineStatistics, pool));
                (pool, 0)
            }
        };
        statistics.active = Some((pool, query, tessellated));
        self.push(Command::BeginQuery {
            pool,
            query,
            precise: false,
        });
        Ok(())
    }

    /// Records a statistic sample of the intervals so far; the first starts
    /// counting.
    pub(super) fn sample_statistics(
        &mut self,
        resolver: &mut dyn Resolver,
        destination: u64,
    ) -> Result<()> {
        self.statistics.get_or_insert_default();
        self.pause_statistics();
        let statistics = self.statistics.as_mut().expect("statistics count");
        let ended = statistics.intervals.len() as u32;
        statistics.samples.push((destination, ended));
        self.resume_statistics(resolver, false)
    }

    /// Ends the interval and starts the next: at a boundary no query spans,
    /// or around a patch draw (`tessellated`).
    pub(super) fn split_statistics(
        &mut self,
        resolver: &mut dyn Resolver,
        tessellated: bool,
    ) -> Result<()> {
        self.pause_statistics();
        self.resume_statistics(resolver, tessellated)
    }

    /// Writes every unresolved statistic sample: the ended intervals'
    /// results gather in upload memory, patch draws' vertex invocations are
    /// cleared, and the accumulate kernel sums each member's results. Runs
    /// outside render passes.
    pub(super) fn resolve_statistics(&mut self, resolver: &mut dyn Resolver) -> Result<()> {
        let Some(statistics) = self.statistics.as_mut() else {
            return Ok(());
        };
        if statistics.samples.is_empty() {
            return Ok(());
        }
        let samples = core::mem::take(&mut statistics.samples);
        let ended = samples.iter().map(|&(_, ended)| ended).max().unwrap_or(0) as usize;
        let intervals = statistics.intervals[..ended].to_vec();
        let interval_bytes = u64::from(STATISTIC_COUNT) * 8;
        let scratch = self.upload(
            resolver,
            &alloc::vec![0; (ended as u64 * interval_bytes).max(8) as usize],
            8,
        )?;
        self.access(Use::new(
            PipelineStages::ALL_TRANSFER,
            Access::TRANSFER_WRITE,
        ));
        // Consecutive queries of one pool copy together.
        let mut start = 0;
        while start < intervals.len() {
            let (pool, first, _) = intervals[start];
            let count = intervals[start..]
                .iter()
                .zip(first..)
                .take_while(|((next_pool, query, _), expected)| {
                    *next_pool == pool && query == expected
                })
                .count();
            self.push(Command::CopyQueryResults {
                pool,
                first,
                count: count as u32,
                dst: scratch.buffer,
                offset: scratch.offset + start as u64 * interval_bytes,
                stride: interval_bytes,
                wait: true,
            });
            start += count;
        }
        let tessellated = intervals
            .iter()
            .enumerate()
            .filter(|(_, interval)| interval.2);
        let mut cleared = false;
        for (index, _) in tessellated {
            if !cleared {
                self.access(Use::new(
                    PipelineStages::ALL_TRANSFER,
                    Access::TRANSFER_WRITE,
                ));
                cleared = true;
            }
            self.push(Command::FillBuffer {
                buffer: scratch.buffer,
                offset: scratch.offset
                    + index as u64 * interval_bytes
                    + u64::from(VERTEX_INVOCATIONS) * 8,
                size: 8,
                data: 0,
            });
        }
        let runs: Vec<_> = samples
            .iter()
            .flat_map(|&(destination, ended)| {
                STATISTIC_MEMBERS.iter().zip((0..).step_by(8)).filter_map(
                    move |(member, offset)| {
                        member.map(|result| (result, ended, destination + offset))
                    },
                )
            })
            .collect();
        let count = runs.len() as u32;
        let arguments = AccumulateArguments {
            results: scratch.address,
            stride: STATISTIC_COUNT,
            runs,
        };
        let arguments = self.upload(
            resolver,
            &arguments.encode(),
            AccumulateArguments::ALIGNMENT,
        )?;
        self.access(Use::new(
            PipelineStages::COMPUTE_SHADER,
            Access::SHADER_READ | Access::SHADER_WRITE,
        ));
        self.push(Command::AccumulateResults {
            arguments: arguments.address,
            runs: count,
        });
        Ok(())
    }
}

impl CommandBuffer {
    /// `sampleCountersInBuffer:atSampleIndex:withBarrier:` and encoder
    /// boundary samples. A timestamp with `barrier` follows the work so
    /// far, otherwise it is taken as soon as the GPU reaches it; statistics
    /// count the work recorded before the sample either way.
    pub fn sample_counters(
        &mut self,
        resolver: &mut dyn Resolver,
        sample: CounterSample,
        barrier: bool,
    ) -> Result<()> {
        let stage = if barrier {
            PipelineStages::ALL_COMMANDS
        } else {
            PipelineStages::TOP_OF_PIPE
        };
        match (sample, &mut self.encoder) {
            (CounterSample::Timestamp { pool, query }, Encoder::Render(render)) => {
                // Queries reset outside render pass instances.
                render.timestamp_resets.push((pool, query));
                self.recorder
                    .push(Command::WriteTimestamp { pool, query, stage });
            }
            (CounterSample::Timestamp { pool, query }, _) => {
                if barrier {
                    self.recorder.full_barrier();
                }
                self.recorder.push(Command::ResetQueryPool {
                    pool,
                    first: query,
                    count: 1,
                });
                self.recorder
                    .push(Command::WriteTimestamp { pool, query, stage });
            }
            (CounterSample::Statistic(destination), _) => {
                ensure(
                    destination.is_multiple_of(8),
                    "statistic samples are 8-byte aligned",
                )?;
                self.recorder.sample_statistics(resolver, destination)?;
            }
        }
        Ok(())
    }

    /// `resolveCounters:inRange:destinationBuffer:destinationOffset:`.
    /// Samples never taken resolve to [`COUNTER_ERROR_VALUE`].
    pub fn resolve_counters(
        &mut self,
        resolver: &mut dyn Resolver,
        range: CounterRange,
        destination: BufferRef,
        offset: u64,
    ) -> Result<()> {
        self.blit()?;
        ensure(
            offset.is_multiple_of(8),
            "counter results are 8-byte aligned",
        )?;
        match range {
            CounterRange::Timestamps { pool, first, count } => {
                let dst = destination.at(offset, u64::from(count) * 8)?;
                // Untaken samples stay unavailable, so the copy leaves the
                // error value; the barrier makes taken ones available.
                self.recorder.full_barrier();
                self.recorder.push(Command::FillBuffer {
                    buffer: destination.buffer,
                    offset: dst,
                    size: u64::from(count) * 8,
                    data: u32::MAX,
                });
                self.recorder.access(Use::new(
                    PipelineStages::ALL_TRANSFER,
                    Access::TRANSFER_WRITE,
                ));
                self.recorder.push(Command::CopyQueryResults {
                    pool,
                    first,
                    count,
                    dst: destination.buffer,
                    offset: dst,
                    stride: 8,
                    wait: false,
                });
            }
            CounterRange::Statistics(samples) => {
                let dst = destination.at(offset, samples.length)?;
                self.recorder.resolve_statistics(resolver)?;
                self.recorder.access(Use::new(
                    PipelineStages::ALL_TRANSFER,
                    Access::TRANSFER_READ | Access::TRANSFER_WRITE,
                ));
                self.recorder.push(Command::CopyBuffer {
                    src: samples.buffer,
                    dst: destination.buffer,
                    regions: alloc::vec![crate::gpu::metal::vulkan::command::BufferCopy {
                        src_offset: samples.offset,
                        dst_offset: dst,
                        size: samples.length,
                    }],
                });
                // The accumulate kernel replaced the pipeline and push
                // constants.
                self.bindings.reset();
            }
        }
        Ok(())
    }
}
