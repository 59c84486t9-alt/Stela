//! Events, counter sample buffers and waits on the queue.
use super::{
    Call, Object, Service, known,
    wire::{
        CounterSetCode, Empty, EventValueRequest, Fault, Handle, NewCounterBufferRequest,
        ResolveCountersRequest, ResolveCountersResponse, Value, WaitEventRequest, WaitRequest,
        WaitResponse,
    },
};
use crate::metal::{
    device::{CounterBufferId, EventId, queue::CounterSet},
    shader::Compiler,
    vulkan::backend::Backend,
};
use alloc::vec::Vec;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn event_signaled_value(&mut self, call: &mut Call) -> Result<(), Fault> {
        let Handle { handle } = call.request()?;
        let event = self.object::<EventId>(call.connection, handle)?;
        let value = self.device.signaled_value(event)?;
        call.reply(&Value { value })
    }

    pub(super) fn set_event_signaled_value(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: EventValueRequest = call.request()?;
        let event = self.object::<EventId>(call.connection, request.event)?;
        self.device.set_signaled_value(event, request.value)?;
        call.reply(&Empty {})
    }

    pub(super) fn wait_event(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: WaitEventRequest = call.request()?;
        let event = self.object::<EventId>(call.connection, request.event)?;
        let reached = self
            .device
            .wait_event(event, request.value, request.timeout)?;
        call.reply(&waited(reached))
    }

    pub(super) fn wait(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: WaitRequest = call.request()?;
        let reached = self.device.wait(request.serial, request.timeout)?;
        call.reply(&waited(reached))
    }

    pub(super) fn new_counter_buffer(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewCounterBufferRequest = call.request()?;
        let set = match known(CounterSetCode::from_raw(request.counter_set), "counter set")? {
            CounterSetCode::Timestamp => CounterSet::Timestamp,
            CounterSetCode::Statistic => CounterSet::Statistic,
        };
        let count =
            u32::try_from(request.sample_count).map_err(|_| Fault::malformed("sample count"))?;
        let buffer = self.device.new_counter_sample_buffer(set, count)?;
        let handle = self.hold(call.connection, Object::CounterBuffer(buffer))?;
        call.reply(&handle)
    }

    pub(super) fn resolve_counters(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: ResolveCountersRequest = call.request()?;
        let buffer = self.object::<CounterBufferId>(call.connection, request.buffer)?;
        let range = |value| u32::try_from(value).map_err(|_| Fault::malformed("sample range"));
        let (first, count) = (range(request.first)?, range(request.count)?);
        let values = self.device.resolve_counters(buffer, first, count)?;
        let data: Vec<u8> = values
            .iter()
            .flatten()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        call.write_fitting(request.out, &data)?;
        call.reply(&ResolveCountersResponse {
            resolved: values.is_some().into(),
            reserved: 0,
            length: data.len() as u64,
        })
    }
}

fn waited(reached: bool) -> WaitResponse {
    WaitResponse {
        reached: reached.into(),
        reserved: 0,
    }
}
