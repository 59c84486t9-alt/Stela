use super::super::{Error, Segment, Semaphore, submit_single_segment};
use crate::metal::vulkan::{command::SparseBind, object::Image};
use alloc::vec;
use ash::vk::{self, Handle};
use core::{cell::Cell, ffi::c_void};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Packet {
    wait: Option<(u64, u64)>,
    signal: Option<(u64, u64)>,
    buffer: u64,
}

struct Calls {
    packet: Cell<Option<Packet>>,
    result: vk::Result,
}

unsafe extern "system" fn submit(
    queue: vk::Queue,
    count: u32,
    infos: *const vk::SubmitInfo2<'_>,
    fence: vk::Fence,
) -> vk::Result {
    assert_eq!(count, 1);
    assert_eq!(fence, vk::Fence::null());
    // SAFETY: the test uses its own kept Calls allocation for this queue.
    let calls = unsafe { &*(queue.as_raw() as *const Calls) };
    // SAFETY: the one submitted packet stays live throughout this call.
    let info = unsafe { &*infos };
    assert_eq!(info.command_buffer_info_count, 1);
    assert!(info.flags.is_empty() && info.p_next.is_null());
    // SAFETY: the packet contains one live command-buffer record.
    let buffer = unsafe { &*info.p_command_buffer_infos };
    assert_eq!(buffer.device_mask, 0);
    let semaphore = |count: u32, info: *const vk::SemaphoreSubmitInfo<'_>| {
        assert!(count <= 1);
        (count == 1).then(|| {
            // SAFETY: the nonempty record stays live throughout this call.
            let info = unsafe { &*info };
            assert!(info.stage_mask == vk::PipelineStageFlags2::ALL_COMMANDS);
            assert_eq!(info.device_index, 0);
            (info.semaphore.as_raw(), info.value)
        })
    };
    let previous = calls.packet.replace(Some(Packet {
        wait: semaphore(info.wait_semaphore_info_count, info.p_wait_semaphore_infos),
        signal: semaphore(
            info.signal_semaphore_info_count,
            info.p_signal_semaphore_infos,
        ),
        buffer: buffer.command_buffer.as_raw(),
    }));
    assert!(previous.is_none());
    calls.result
}

fn device() -> ash::Device {
    // SAFETY: the tests invoke only the typed submit callback.
    unsafe {
        ash::Device::load_with(
            |name| match name.to_bytes() {
                b"vkQueueSubmit2" => submit as *const c_void,
                _ => core::ptr::null(),
            },
            vk::Device::null(),
        )
    }
}

#[test]
fn single_segment_keeps_the_exact_vulkan_packet_and_error() {
    let device = device();
    for wait in [None, Some((7, 20))] {
        for signal in [None, Some((8, 50))] {
            let segment = Segment {
                waits: wait
                    .map(|(id, value)| (Semaphore(id), value))
                    .into_iter()
                    .collect(),
                signals: signal
                    .map(|(id, value)| (Semaphore(id), value))
                    .into_iter()
                    .collect(),
                ..Segment::default()
            };
            for (result, outcome) in [
                (vk::Result::SUCCESS, Ok(())),
                (vk::Result::ERROR_DEVICE_LOST, Err(Error::DeviceLost)),
                (
                    vk::Result::ERROR_OUT_OF_HOST_MEMORY,
                    Err(Error::OutOfMemory),
                ),
            ] {
                let calls = Calls {
                    packet: Cell::new(None),
                    result,
                };
                let queue = vk::Queue::from_raw(&calls as *const Calls as u64);
                assert_eq!(
                    submit_single_segment(
                        &device,
                        queue,
                        core::slice::from_ref(&segment),
                        &[vk::CommandBuffer::from_raw(9)],
                    ),
                    Some(outcome),
                );
                assert_eq!(
                    calls.packet.get(),
                    Some(Packet {
                        wait,
                        signal,
                        buffer: 9
                    })
                );
            }
        }
    }
}

#[test]
fn single_segment_leaves_complex_packets_to_batch_submission() {
    let device = device();
    let calls = Calls {
        packet: Cell::new(None),
        result: vk::Result::SUCCESS,
    };
    let queue = vk::Queue::from_raw(&calls as *const Calls as u64);
    let buffer = vk::CommandBuffer::from_raw(9);
    assert_eq!(submit_single_segment(&device, queue, &[], &[]), None);
    assert_eq!(
        submit_single_segment(
            &device,
            queue,
            &[Segment::default(), Segment::default()],
            &[buffer; 2],
        ),
        None,
    );
    for segment in [
        Segment {
            waits: vec![(Semaphore(7), 20), (Semaphore(8), 40)],
            ..Segment::default()
        },
        Segment {
            signals: vec![(Semaphore(7), 20), (Semaphore(8), 40)],
            ..Segment::default()
        },
        Segment {
            binds: vec![SparseBind::Opaque {
                image: Image(10),
                offset: 0,
                size: 4096,
                memory: None,
            }],
            ..Segment::default()
        },
    ] {
        assert_eq!(
            submit_single_segment(&device, queue, &[segment], &[buffer]),
            None
        );
    }
    assert!(calls.packet.get().is_none());
}
