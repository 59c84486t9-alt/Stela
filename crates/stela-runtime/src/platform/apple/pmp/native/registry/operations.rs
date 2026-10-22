//! Retained cold-start and native registry operation retirement.
use super::*;

impl<B: memory::Backend> Owner<B>
where
    B::Mapping: PublicationMapping,
{
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
        self.claim.check()?;
        // The separate original class4 callback can run while class3 waits for
        // its AP reply. Retain the actual entry identity captured at delivery.
        if self.received.is_some() && !self.plan.as_ref().is_some_and(|p| p.callback_active) {
            return self.incoming_step(access);
        }
        while self.plan.is_some() {
            let p = self.plan.as_ref().unwrap();
            if let Some(reason) = p.failed {
                return Err(reason);
            }
            let Some(op) = p.ops.get(p.cursor).copied() else {
                self.plan = None;
                if self.received.is_some() {
                    return self.incoming_step(access);
                }
                return Ok(Progress::Idle);
            };
            let mut request = p.request.clone();
            request.operation = p.cursor;
            match op {
                Operation::InitializeMemory => {
                    if !p.memory_started {
                        self.memory.begin_init()?;
                        self.plan.as_mut().unwrap().memory_started = true;
                    }
                    if let Progress::Busy { deadline } = self.memory.advance(access)? {
                        return Ok(Progress::Busy { deadline });
                    }
                    let Some(memory::Completion::Initialized(regions)) =
                        self.memory.take_completion()?
                    else {
                        return Ok(Progress::Busy { deadline: None });
                    };
                    self.regions = Some(regions);
                    self.plan.as_mut().unwrap().memory_started = false;
                }
                Operation::Allocate(target, bytes) => {
                    if !p.memory_started {
                        self.memory.begin_allocate(bytes)?;
                        self.plan.as_mut().unwrap().memory_started = true;
                    }
                    if let Progress::Busy { deadline } = self.memory.advance(access)? {
                        return Ok(Progress::Busy { deadline });
                    }
                    let Some(result) = self.memory.take_completion()? else {
                        return Ok(Progress::Busy { deadline: None });
                    };
                    let memory::Completion::Allocated(Some(allocation)) = result else {
                        let reason = "PMP registry actual AP allocation failed; reached resource prefix retained";
                        self.plan.as_mut().unwrap().failed = Some(reason);
                        return Err(reason);
                    };
                    match target {
                        Target::Outgoing => self.outgoing = Some(allocation),
                        Target::Incoming => self.incoming = Some(allocation),
                        Target::Temporary => self.temporary = Some(allocation),
                    }
                    self.plan.as_mut().unwrap().memory_started = false;
                }
                Operation::FreeTemporary => {
                    let allocation = self.allocation(Target::Temporary)?;
                    if !p.memory_started {
                        self.memory.begin_free(&allocation)?;
                        self.plan.as_mut().unwrap().memory_started = true;
                    }
                    if let Progress::Busy { deadline } = self.memory.advance(access)? {
                        return Ok(Progress::Busy { deadline });
                    }
                    let Some(memory::Completion::Freed(_)) = self.memory.take_completion()? else {
                        return Ok(Progress::Busy { deadline: None });
                    };
                    self.temporary = None;
                    self.plan.as_mut().unwrap().memory_started = false;
                }
                Operation::Prepare(target) | Operation::Complete(target) => {
                    let operation = if matches!(op, Operation::Prepare(_)) {
                        Synchronization::Prepare
                    } else {
                        Synchronization::Complete
                    };
                    match self.sync(target, &request, operation, access) {
                        Step::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                        Step::Refused(reason) => return Err(reason),
                        Step::Retired { refusal } => {
                            self.plan.as_mut().unwrap().cursor += 1;
                            if let Some(reason) = refusal {
                                return Err(reason);
                            }
                            continue;
                        }
                    }
                }
                Operation::WriteInit => {
                    let mut bytes = [0; 16];
                    bytes[..8].copy_from_slice(&self.bus(Target::Outgoing)?.to_le_bytes());
                    bytes[8..].copy_from_slice(&self.bus(Target::Incoming)?.to_le_bytes());
                    let step = self
                        .memory
                        .mapping(self.temporary.as_ref().unwrap())?
                        .write_publication(&request, &bytes, access);
                    if let Some(progress) = self.retire(step)? {
                        return Ok(progress);
                    }
                    continue;
                }
                Operation::WriteDescriptor => {
                    let p = self.plan.as_ref().unwrap();
                    let bytes =
                        wire::descriptor(p.configuration.as_ref().unwrap(), p.data.len(), p.index);
                    let step = self
                        .memory
                        .mapping(self.temporary.as_ref().unwrap())?
                        .write_publication(&request, &bytes, access);
                    if let Some(progress) = self.retire(step)? {
                        return Ok(progress);
                    }
                    continue;
                }
                Operation::WriteOutgoing => {
                    let step = self
                        .memory
                        .mapping(self.outgoing.as_ref().unwrap())?
                        .write_publication(&request, &p.data, access);
                    if let Some(progress) = self.retire(step)? {
                        return Ok(progress);
                    }
                    continue;
                }
                Operation::Send(_) => return Ok(Progress::Busy { deadline: None }),
                Operation::Wait => {
                    if p.reply.is_none() {
                        return Ok(Progress::Busy { deadline: None });
                    }
                }
                Operation::ResolveAdd => {
                    let p = self.plan.as_mut().unwrap();
                    let configuration = p.configuration.as_ref().unwrap();
                    let bytes = p.reply.map_or(p.data.len(), |v| v as usize);
                    if bytes > BUFFER_BYTES as usize
                        || (!p.data.is_empty() && bytes != 0 && bytes != p.data.len())
                    {
                        let reason = "PMP registry AP add returned an unqualified length; reached remote entry retained";
                        p.failed = Some(reason);
                        return Err(reason);
                    }
                    if bytes != 0 && configuration.local_value() && p.data.is_empty() {
                        p.ops
                            .extend([Operation::Prepare(Target::Outgoing), Operation::ReadDefault]);
                    }
                    p.ops.push(Operation::CommitAdd);
                }
                Operation::ReadDefault => {
                    let p = self.plan.as_mut().unwrap();
                    let bytes = p.reply.unwrap() as usize;
                    let value = p.value.get_or_insert_with(|| alloc::vec![0;bytes]);
                    let step = self
                        .memory
                        .mapping(self.outgoing.as_ref().unwrap())?
                        .read_publication(&request, value, access);
                    if let Some(progress) = self.retire(step)? {
                        return Ok(progress);
                    }
                    continue;
                }
                Operation::CommitInit => {
                    self.initialized = true;
                    self.completion = Some(Completion::Initialized);
                }
                Operation::CommitAdd => {
                    let p = self.plan.as_mut().unwrap();
                    let bytes = p.reply.map_or(p.data.len(), |v| v as usize);
                    if bytes == 0 {
                        self.completion = Some(Completion::Added(None));
                    } else {
                        let record = Record {
                            object: Rc::new(()),
                            configuration: p.configuration.take().unwrap(),
                            bytes,
                            value: p.value.take(),
                            callback: p.callback.take(),
                        };
                        let index = p.index;
                        self.entries[index] = Some(record);
                        self.completion = Some(Completion::Added(Some(self.entry(index))));
                    }
                }
                Operation::CommitRemove => {
                    let index = p.index;
                    let entry = self.entry(index);
                    let result = p.reply;
                    self.entries[index] = None;
                    self.completion = Some(Completion::Removed {
                        entry,
                        ap_result: result,
                    });
                }
                Operation::ApplyLocalCallback => {
                    let p = self.plan.as_mut().unwrap();
                    let record = self.entries[p.index].as_mut().unwrap();
                    if let Some(callback) = &mut record.callback {
                        p.callback_active = true;
                        match callback.apply(
                            &request,
                            u16::try_from(p.index).unwrap(),
                            Input::Local(&p.data),
                            access,
                        ) {
                            CallbackStep::Busy { deadline } => {
                                return Ok(Progress::Busy { deadline });
                            }
                            CallbackStep::Refused(reason) => return Err(reason),
                            CallbackStep::Retired { refusal, .. } => {
                                self.plan.as_mut().unwrap().callback_active = false;
                                self.plan.as_mut().unwrap().cursor += 1;
                                if let Some(reason) = refusal {
                                    return Err(reason);
                                }
                                continue;
                            }
                        }
                    }
                }
                Operation::CommitSet => {
                    let index = p.index;
                    self.completion = Some(Completion::Set {
                        entry: self.entry(index),
                        ap_bytes: p.reply,
                    });
                }
            }
            self.plan.as_mut().unwrap().cursor += 1;
        }
        Ok(Progress::Idle)
    }
}
