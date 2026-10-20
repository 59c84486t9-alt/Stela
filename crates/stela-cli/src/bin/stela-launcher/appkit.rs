//! The launcher's AppKit side, through the Objective-C runtime's C
//! interface: an `NSApplication` whose delegate collects
//! `application:openURLs:` events and starts the hosted launches, alerts,
//! and the hand-off of a launch's end to the main thread.
use super::{Launcher, command, tail};
use std::ffi::{CStr, CString, OsString, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Mutex, MutexGuard};

type Id = *mut c_void;
type Sel = *mut c_void;

// AppKit brings Foundation; its classes are looked up by name.
#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_allocateClassPair(superclass: Id, name: *const c_char, extra: usize) -> Id;
    fn objc_registerClassPair(class: Id);
    fn class_addMethod(class: Id, name: Sel, imp: *const c_void, types: *const c_char) -> i8;
    fn objc_msgSend();
    static _dispatch_main_q: c_void;
    fn dispatch_async_f(
        queue: *const c_void,
        context: *mut c_void,
        work: extern "C" fn(*mut c_void),
    );
}

/// `NSApplicationActivationPolicyRegular`: a Dock icon and a menu bar.
const ACTIVATION_POLICY_REGULAR: isize = 0;

fn class(name: &CStr) -> Id {
    // SAFETY: a lookup by a NUL-terminated name.
    unsafe { objc_getClass(name.as_ptr()) }
}

fn selector(name: &CStr) -> Sel {
    // SAFETY: registration of a NUL-terminated name.
    unsafe { sel_registerName(name.as_ptr()) }
}

/// `objc_msgSend` as the function type of the method it calls.
macro_rules! send {
    ($receiver:expr, $selector:literal $(, $argument:expr => $kind:ty)* ; $result:ty) => {{
        let function: extern "C" fn(Id, Sel $(, $kind)*) -> $result =
            // SAFETY: objc_msgSend takes the receiver, the selector and the
            // method's own arguments, and returns its result.
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        function($receiver, selector($selector) $(, $argument)*)
    }};
}

/// An `NSString` of `text`.
fn string(text: &str) -> Id {
    let text = CString::new(text.replace('\0', " ")).unwrap_or_default();
    send!(class(c"NSString"), c"stringWithUTF8String:", text.as_ptr() => *const c_char; Id)
}

/// The UTF-8 bytes of an `NSString`.
fn bytes(string: Id) -> Vec<u8> {
    if string.is_null() {
        return vec![];
    }
    let text: *const c_char = send!(string, c"UTF8String"; *const c_char);
    if text.is_null() {
        return vec![];
    }
    // SAFETY: NSString returns a NUL-terminated buffer it keeps alive.
    unsafe { CStr::from_ptr(text) }.to_bytes().to_vec()
}

fn application() -> Id {
    send!(class(c"NSApplication"), c"sharedApplication"; Id)
}

/// Show a modal alert with `title` and `text`.
pub(super) fn alert(title: &str, text: &str) {
    let app = application();
    send!(app, c"activateIgnoringOtherApps:", 1 => i8; ());
    let alert: Id = send!(class(c"NSAlert"), c"alloc"; Id);
    let alert: Id = send!(alert, c"init"; Id);
    send!(alert, c"setMessageText:", string(title) => Id; ());
    send!(alert, c"setInformativeText:", string(text) => Id; ());
    let _: isize = send!(alert, c"runModal"; isize);
}

/// The launcher's state, shared by the delegate and the waiting threads.
struct State {
    launcher: Launcher,
    /// Whether launching finished: events before it go to the first launch.
    launched: bool,
    pending: Vec<OsString>,
    /// The hosted launches still running, by host process ID.
    running: Vec<u32>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn state() -> MutexGuard<'static, Option<State>> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Start a hosted launch with `arguments`, output to the log; the alert to
/// show when it cannot start and nothing else runs, which the caller shows
/// once it no longer holds the state.
fn start(state: &mut State, arguments: &[OsString]) -> Option<(String, String)> {
    let launcher = &state.launcher;
    let log = launcher.log.parent().map(std::fs::create_dir_all);
    let file = log.and_then(Result::ok).and_then(|()| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&launcher.log)
            .ok()
    });
    let mut command = command(launcher, arguments);
    command.stdin(std::process::Stdio::null());
    if let Some(mut file) = file {
        use std::io::Write;
        let _ = writeln!(file, "--- {:?}", command);
        if let (Ok(out), Ok(err)) = (file.try_clone(), file.try_clone()) {
            command.stdout(out).stderr(err);
        }
    }
    match command.spawn() {
        Ok(mut child) => {
            let id = child.id();
            state.running.push(id);
            std::thread::spawn(move || {
                let success = child.wait().is_ok_and(|status| status.success());
                on_main(Box::new(move || ended(id, success)));
            });
            None
        }
        Err(error) => state.running.is_empty().then(|| {
            (
                format!("{} cannot open", launcher.name),
                format!("{} cannot run: {error}", launcher.stela.display()),
            )
        }),
    }
}

/// Show a launch's failure to start and end, with the state released.
fn failed(failure: Option<(String, String)>) {
    if let Some((title, text)) = failure {
        alert(&title, &text);
        terminate();
    }
}

/// A hosted launch ended: report a failure, and end with the last one.
fn ended(id: u32, success: bool) {
    let (failure, last) = {
        let mut guard = state();
        let Some(state) = guard.as_mut() else { return };
        state.running.retain(|&running| running != id);
        let failure = (!success).then(|| {
            (
                format!("{} stopped", state.launcher.name),
                format!(
                    "{}\n\nThe full output is in {}.",
                    tail(&state.launcher.log),
                    state.launcher.log.display()
                ),
            )
        });
        (failure, state.running.is_empty())
    };
    if let Some((title, text)) = failure {
        alert(&title, &text);
    }
    if last {
        terminate();
    }
}

fn terminate() {
    send!(application(), c"terminate:", std::ptr::null_mut() => Id; ());
}

/// Run `work` on the main thread.
fn on_main(work: Box<dyn FnOnce() + Send>) {
    extern "C" fn trampoline(context: *mut c_void) {
        // SAFETY: the context is the box `on_main` leaked for this call.
        let work = unsafe { Box::from_raw(context.cast::<Box<dyn FnOnce() + Send>>()) };
        work();
    }
    let context = Box::into_raw(Box::new(work)).cast::<c_void>();
    // SAFETY: the main queue outlives the process; the trampoline frees
    // the context.
    unsafe { dispatch_async_f(&raw const _dispatch_main_q, context, trampoline) }
}

/// `application:openURLs:`: files by path, other URLs as text.
extern "C" fn open_urls(_this: Id, _command: Sel, _application: Id, urls: Id) {
    let count: usize = send!(urls, c"count"; usize);
    let arguments: Vec<OsString> = (0..count)
        .map(|index| {
            let url: Id = send!(urls, c"objectAtIndex:", index => usize; Id);
            let file: i8 = send!(url, c"isFileURL"; i8);
            let text: Id = if file != 0 {
                send!(url, c"path"; Id)
            } else {
                send!(url, c"absoluteString"; Id)
            };
            std::ffi::OsStr::from_bytes(&bytes(text)).to_owned()
        })
        .collect();
    let failure = {
        let mut guard = state();
        let Some(state) = guard.as_mut() else { return };
        if !state.launched {
            state.pending.extend(arguments);
            return;
        }
        start(state, &arguments)
    };
    failed(failure);
}

/// `applicationDidFinishLaunching:`: the first launch, with every document
/// that came with it.
extern "C" fn finished_launching(_this: Id, _command: Sel, _notification: Id) {
    let failure = {
        let mut guard = state();
        let Some(state) = guard.as_mut() else { return };
        state.launched = true;
        let arguments = std::mem::take(&mut state.pending);
        start(state, &arguments)
    };
    failed(failure);
}

/// `applicationWillTerminate:`: stop the hosted launches still running.
extern "C" fn will_terminate(_this: Id, _command: Sel, _notification: Id) {
    let guard = state();
    let Some(state) = guard.as_ref() else { return };
    for &id in &state.running {
        // SAFETY: a signal to a child this launcher started.
        unsafe { libc::kill(id as libc::pid_t, libc::SIGTERM) };
    }
}

/// The delegate class, registered once.
fn delegate_class() -> Id {
    // SAFETY: a new class under NSObject with three methods of the given
    // type encodings, registered before use.
    unsafe {
        let delegate =
            objc_allocateClassPair(class(c"NSObject"), c"StelaLauncherDelegate".as_ptr(), 0);
        let methods: [(&CStr, *const c_void, &CStr); 3] = [
            (
                c"application:openURLs:",
                open_urls as *const c_void,
                c"v@:@@",
            ),
            (
                c"applicationDidFinishLaunching:",
                finished_launching as *const c_void,
                c"v@:@",
            ),
            (
                c"applicationWillTerminate:",
                will_terminate as *const c_void,
                c"v@:@",
            ),
        ];
        for (name, implementation, types) in methods {
            class_addMethod(delegate, selector(name), implementation, types.as_ptr());
        }
        objc_registerClassPair(delegate);
        delegate
    }
}

/// Run the application until the last hosted launch ends.
pub(super) fn run(launcher: Launcher, arguments: Vec<OsString>) -> ! {
    *state() = Some(State {
        launcher,
        launched: false,
        pending: arguments,
        running: vec![],
    });
    let app = application();
    let _: i8 = send!(app, c"setActivationPolicy:", ACTIVATION_POLICY_REGULAR => isize; i8);
    let delegate: Id = send!(delegate_class(), c"alloc"; Id);
    let delegate: Id = send!(delegate, c"init"; Id);
    send!(app, c"setDelegate:", delegate => Id; ());
    send!(app, c"run"; ());
    std::process::exit(0)
}
