//! Implicit hazard tracking at command granularity.
//!
//! Metal orders a command buffer's encoders (and a serial compute encoder's
//! dispatches, and a blit encoder's commands) for every tracked resource,
//! and leaves untracked resources to fences and barriers. On one queue, a
//! global memory barrier between a write and the next access orders both
//! kinds, so fences need no commands of their own. The tracker remembers the
//! stages that wrote or read since the last barrier and emits one only when
//! the next use depends on them: read after write, write after write, and
//! (as an execution dependency) write after read. Read-only sequences never
//! wait.
use super::vulkan::{Access, PipelineStages, command::Barrier};

/// What a command does to memory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Use {
    pub stages: PipelineStages,
    pub access: Access,
}

impl Use {
    pub const fn new(stages: PipelineStages, access: Access) -> Self {
        Self { stages, access }
    }

    fn writes(&self) -> bool {
        self.access.intersects(Access::WRITES)
    }

    fn reads(&self) -> bool {
        !self.access.difference(Access::WRITES).is_empty()
    }
}

/// Everything a render pass may touch: its attachments, vertex input and
/// every graphics shader stage.
pub const RENDER_PASS: Use = Use::new(
    PipelineStages::ALL_GRAPHICS,
    Access::MEMORY_READ.union(Access::MEMORY_WRITE),
);

/// Orders all earlier work before all later work. Command buffers start
/// with it, which orders them after everything submitted before.
pub const FULL: Barrier = Barrier {
    src_stages: PipelineStages::ALL_COMMANDS,
    src_access: Access::MEMORY_WRITE,
    dst_stages: PipelineStages::ALL_COMMANDS,
    dst_access: Access::MEMORY_READ.union(Access::MEMORY_WRITE),
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hazards {
    write_stages: PipelineStages,
    write_access: Access,
    read_stages: PipelineStages,
}

impl Hazards {
    /// The barrier `next` needs, if any; records `next` as pending.
    pub fn access(&mut self, next: Use) -> Option<Barrier> {
        let after_write = !self.write_stages.is_empty() && (next.reads() || next.writes());
        let after_read = !self.read_stages.is_empty() && next.writes();
        let barrier = (after_write || after_read).then(|| {
            let barrier = Barrier {
                src_stages: self.write_stages.union(self.read_stages),
                src_access: self.write_access,
                dst_stages: next.stages,
                dst_access: if after_write {
                    next.access
                } else {
                    Access::EMPTY
                },
            };
            *self = Self::default();
            barrier
        });
        if next.writes() {
            self.write_stages |= next.stages;
            self.write_access |= next.access.intersection(Access::WRITES);
        }
        if next.reads() {
            self.read_stages |= next.stages;
        }
        barrier
    }

    /// A barrier ordering everything pending before everything after, as
    /// Metal's explicit memory barriers and command-buffer starts require.
    pub fn full(&mut self) -> Option<Barrier> {
        let pending = *self != Self::default();
        *self = Self::default();
        pending.then_some(FULL)
    }

    /// Makes pending writes visible to the host, for managed resources the
    /// CPU reads after completion.
    pub fn host(&mut self) -> Option<Barrier> {
        let pending = !self.write_stages.is_empty();
        pending.then(|| {
            let barrier = Barrier {
                src_stages: self.write_stages,
                src_access: self.write_access,
                dst_stages: PipelineStages::HOST,
                dst_access: Access::HOST_READ,
            };
            *self = Self {
                write_stages: PipelineStages::EMPTY,
                write_access: Access::EMPTY,
                ..*self
            };
            barrier
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPUTE_READ: Use = Use::new(PipelineStages::COMPUTE_SHADER, Access::SHADER_READ);
    const COMPUTE_WRITE: Use = Use::new(
        PipelineStages::COMPUTE_SHADER,
        Access::SHADER_READ.union(Access::SHADER_WRITE),
    );
    const COPY: Use = Use::new(
        PipelineStages::ALL_TRANSFER,
        Access::TRANSFER_READ.union(Access::TRANSFER_WRITE),
    );

    #[test]
    fn read_only_sequences_never_wait() {
        let mut hazards = Hazards::default();
        assert_eq!(hazards.access(COMPUTE_READ), None);
        assert_eq!(hazards.access(COMPUTE_READ), None);
        assert_eq!(hazards.full(), Some(FULL));
        assert_eq!(hazards.full(), None, "nothing pending after a full barrier");
    }

    #[test]
    fn writes_order_later_reads_and_writes() {
        let mut hazards = Hazards::default();
        assert_eq!(
            hazards.access(COMPUTE_WRITE),
            None,
            "the first write has nothing to wait for"
        );
        let barrier = hazards.access(COPY).unwrap();
        assert_eq!(barrier.src_stages, PipelineStages::COMPUTE_SHADER);
        assert_eq!(barrier.src_access, Access::SHADER_WRITE);
        assert_eq!(barrier.dst_stages, PipelineStages::ALL_TRANSFER);
        assert_eq!(barrier.dst_access, COPY.access);
        let barrier = hazards.access(COMPUTE_READ).unwrap();
        assert_eq!(barrier.src_access, Access::TRANSFER_WRITE);
    }

    #[test]
    fn writes_after_reads_need_only_execution_order() {
        let mut hazards = Hazards::default();
        assert_eq!(hazards.access(COMPUTE_READ), None);
        let barrier = hazards.access(COMPUTE_WRITE).unwrap();
        assert_eq!(
            (barrier.src_access, barrier.dst_access),
            (Access::EMPTY, Access::EMPTY)
        );
        assert_eq!(barrier.src_stages, PipelineStages::COMPUTE_SHADER);
    }

    #[test]
    fn host_barriers_publish_writes() {
        let mut hazards = Hazards::default();
        assert_eq!(hazards.host(), None);
        hazards.access(COMPUTE_WRITE);
        let barrier = hazards.host().unwrap();
        assert_eq!(
            (barrier.dst_stages, barrier.dst_access),
            (PipelineStages::HOST, Access::HOST_READ)
        );
        assert_eq!(hazards.host(), None);
    }
}
