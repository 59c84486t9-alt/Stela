use super::{Memory, TestService, call, connect, service_on, status, texture};
use crate::metal::{
    abi::StorageMode,
    device::fixture::MockBackend,
    service::wire::{
        BufferResponse, Empty, EventValueRequest, Handle, NewBufferRequest, Operation,
        ShareObjectRequest, ShareToken, Status, TextureResponse, Value,
    },
};
use core::num::NonZeroU64;

const TOKEN: [u64; 2] = [0x1234, 0x5678];

fn new_event(service: &mut TestService, connection: NonZeroU64) -> u64 {
    let event: Handle = call(
        service,
        connection,
        Operation::NewEvent,
        &Empty {},
        &mut Memory::default(),
    )
    .unwrap();
    event.handle
}

fn share(
    service: &mut TestService,
    connection: NonZeroU64,
    handle: u64,
    token: [u64; 2],
) -> Result<[u64; 2], super::Outcome> {
    let request = ShareObjectRequest { handle, token };
    let memory = &mut Memory::default();
    let shared: ShareToken = call(
        service,
        connection,
        Operation::ShareObject,
        &request,
        memory,
    )?;
    Ok(shared.token)
}

fn open_event(
    service: &mut TestService,
    connection: NonZeroU64,
    token: [u64; 2],
) -> Result<u64, super::Outcome> {
    let opened: Handle = call(
        service,
        connection,
        Operation::OpenSharedEvent,
        &ShareToken { token },
        &mut Memory::default(),
    )?;
    Ok(opened.handle)
}

fn signaled(service: &mut TestService, connection: NonZeroU64, handle: u64) -> Status {
    status(call::<_, Value>(
        service,
        connection,
        Operation::EventSignaledValue,
        &Handle { handle },
        &mut Memory::default(),
    ))
}

fn release(service: &mut TestService, connection: NonZeroU64, handle: u64) {
    call::<_, Empty>(
        service,
        connection,
        Operation::Release,
        &Handle { handle },
        &mut Memory::default(),
    )
    .unwrap();
}

#[test]
fn a_shared_event_is_one_event_in_both_connections() {
    let mut service = service_on(MockBackend::new());
    let (first, second) = (connect(&mut service), connect(&mut service));
    let event = new_event(&mut service, first);
    let token = share(&mut service, first, event, TOKEN).unwrap();
    let opened = open_event(&mut service, second, token).unwrap();

    call::<_, Empty>(
        &mut service,
        first,
        Operation::SetEventSignaledValue,
        &EventValueRequest { event, value: 7 },
        &mut Memory::default(),
    )
    .unwrap();
    let value: Value = call(
        &mut service,
        second,
        Operation::EventSignaledValue,
        &Handle { handle: opened },
        &mut Memory::default(),
    )
    .unwrap();
    assert_eq!(value.value, 7);
}

#[test]
fn an_object_keeps_its_first_token() {
    let mut service = service_on(MockBackend::new());
    let (first, second) = (connect(&mut service), connect(&mut service));
    let event = new_event(&mut service, first);
    assert_eq!(share(&mut service, first, event, TOKEN).unwrap(), TOKEN);
    assert_eq!(share(&mut service, first, event, [1, 2]).unwrap(), TOKEN);
    let opened = open_event(&mut service, second, TOKEN).unwrap();
    assert_eq!(share(&mut service, second, opened, [3, 4]).unwrap(), TOKEN);

    let other = new_event(&mut service, first);
    assert_eq!(
        status(share(&mut service, first, other, TOKEN)),
        Status::Invalid
    );
}

#[test]
fn a_shared_object_lives_until_its_last_handle_goes() {
    let mut service = service_on(MockBackend::new());
    let (first, second) = (connect(&mut service), connect(&mut service));
    let event = new_event(&mut service, first);
    share(&mut service, first, event, TOKEN).unwrap();
    let opened = open_event(&mut service, second, TOKEN).unwrap();

    release(&mut service, first, event);
    assert_eq!(signaled(&mut service, second, opened), Status::Ok);

    // A connection that closes gives up its holds as a release does, and the
    // last hold ends the token.
    let third = connect(&mut service);
    open_event(&mut service, third, TOKEN).unwrap();
    service.disconnect(third).unwrap();
    assert_eq!(signaled(&mut service, second, opened), Status::Ok);
    release(&mut service, second, opened);
    assert_eq!(
        status(open_event(&mut service, second, TOKEN)),
        Status::Invalid
    );
}

#[test]
fn only_events_and_textures_are_shared_and_a_token_opens_its_kind() {
    let mut service = service_on(MockBackend::new());
    let (first, second) = (connect(&mut service), connect(&mut service));
    let memory = &mut Memory::default();
    let buffer: BufferResponse = call(
        &mut service,
        first,
        Operation::NewBuffer,
        &NewBufferRequest {
            length: 4096,
            // Private storage: the CPU's buffers are imported.
            options: (StorageMode::Private as u64) << 4,
        },
        memory,
    )
    .unwrap();
    assert_eq!(
        status(share(&mut service, first, buffer.handle, TOKEN)),
        Status::Invalid
    );

    let texture: TextureResponse = call(
        &mut service,
        first,
        Operation::NewTexture,
        &texture(StorageMode::Private),
        memory,
    )
    .unwrap();
    share(&mut service, first, texture.handle, TOKEN).unwrap();
    assert_eq!(
        status(open_event(&mut service, second, TOKEN)),
        Status::Invalid
    );
    let opened: TextureResponse = call(
        &mut service,
        second,
        Operation::OpenSharedTexture,
        &ShareToken { token: TOKEN },
        memory,
    )
    .unwrap();
    assert_eq!(opened.resource_id, texture.resource_id);
    assert_eq!(opened.allocated_size, texture.allocated_size);
    assert_ne!(opened.handle, 0);
}
