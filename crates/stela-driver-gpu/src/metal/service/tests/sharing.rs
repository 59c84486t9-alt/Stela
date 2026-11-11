use super::{Memory, TestService, call, connect, new_buffer, service_on, status, texture};
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

/// Commits for `connection` a command buffer held until `event` reaches 1.
fn hold_for(service: &mut TestService, connection: NonZeroU64, event: u64) {
    use crate::metal::service::wire::commands::{CommandBufferCode, EventCommand};
    let mut stream = super::Stream::default();
    let wait = EventCommand { event, value: 1 };
    stream.push(CommandBufferCode::WaitForEvent.raw(), &wait, &[]);
    super::commit(service, connection, &stream).unwrap();
    assert!(service.device().holds());
}

fn signal(service: &mut TestService, connection: NonZeroU64, event: u64) {
    call::<_, Empty>(
        service,
        connection,
        Operation::SetEventSignaledValue,
        &EventValueRequest { event, value: 1 },
        &mut Memory::default(),
    )
    .unwrap();
}

fn destroyed_images(service: &mut TestService) -> usize {
    use crate::metal::vulkan::backend::Object;
    let destroyed = &service.device().backend().destroyed;
    destroyed
        .iter()
        .filter(|object| matches!(object, Object::Image(_)))
        .count()
}

/// A texture one connection shares stays while another connection that
/// held it has a command buffer held for an event, after both released it;
/// an unshared texture of the sharer is freed at once.
#[test]
fn a_shared_texture_waits_for_every_holders_held_work() {
    let mut service = service_on(MockBackend::new());
    let (reader, owner) = (connect(&mut service), connect(&mut service));
    let memory = &mut Memory::default();
    let shared: TextureResponse = call(
        &mut service,
        owner,
        Operation::NewTexture,
        &texture(StorageMode::Shared),
        memory,
    )
    .unwrap();
    share(&mut service, owner, shared.handle, TOKEN).unwrap();
    let opened: TextureResponse = call(
        &mut service,
        reader,
        Operation::OpenSharedTexture,
        &ShareToken { token: TOKEN },
        memory,
    )
    .unwrap();
    let event = new_event(&mut service, reader);
    hold_for(&mut service, reader, event);
    release(&mut service, reader, opened.handle);
    release(&mut service, owner, shared.handle);
    let own: TextureResponse = call(
        &mut service,
        owner,
        Operation::NewTexture,
        &texture(StorageMode::Shared),
        memory,
    )
    .unwrap();
    release(&mut service, owner, own.handle);
    service.device().poll().unwrap();
    assert_eq!(
        destroyed_images(&mut service),
        1,
        "only the unshared texture"
    );
    signal(&mut service, reader, event);
    service.device().backend().finish();
    service.device().poll().unwrap();
    assert_eq!(destroyed_images(&mut service), 2);
    assert_eq!(service.device().memory().deferred, 0);
}

/// A connection that closes frees what only it could read though another
/// connection's command buffer waits for an event it shared; what the
/// waiting connection releases of its own older objects stays, is reported
/// once at a close, and goes when that connection closes too.
#[test]
fn closing_connections_free_what_only_they_could_read() {
    let mut service = service_on(MockBackend::new());
    let (waiting, signaller) = (connect(&mut service), connect(&mut service));
    let event = new_event(&mut service, waiting);
    share(&mut service, waiting, event, TOKEN).unwrap();
    open_event(&mut service, signaller, TOKEN).unwrap();
    let older = new_buffer(&mut service, waiting, StorageMode::Private);
    hold_for(&mut service, waiting, event);
    new_buffer(&mut service, signaller, StorageMode::Private);
    call::<_, TextureResponse>(
        &mut service,
        signaller,
        Operation::NewTexture,
        &texture(StorageMode::Shared),
        &mut Memory::default(),
    )
    .unwrap();
    // The signaller crashes: its objects go though the wait remains.
    service.disconnect(signaller).unwrap();
    service.device().poll().unwrap();
    let memory = service.device().memory();
    assert_eq!((memory.deferred, memory.pinned), (0, 0), "{memory:?}");
    assert_eq!(destroyed_images(&mut service), 1);
    assert!(service.refused.is_empty(), "nothing held work keeps");
    assert!(service.device().holds(), "Metal keeps the wait");

    release(&mut service, waiting, older);
    assert!(service.device().memory().pinned > 0);
    let other = connect(&mut service);
    service.disconnect(other).unwrap();
    let reports = service
        .refused
        .iter()
        .filter(|line| line.contains("wait for events"))
        .count();
    assert_eq!(reports, 1, "{:?}", service.refused);
    let other = connect(&mut service);
    service.disconnect(other).unwrap();
    let reports = service
        .refused
        .iter()
        .filter(|line| line.contains("wait for events"))
        .count();
    assert_eq!(reports, 1, "reported once");

    service.disconnect(waiting).unwrap();
    service.device().poll().unwrap();
    let memory = service.device().memory();
    assert_eq!((memory.deferred, memory.pinned), (0, 0), "{memory:?}");
    assert!(!service.device().holds());
}
