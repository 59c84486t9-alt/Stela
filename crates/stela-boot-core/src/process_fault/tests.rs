use super::*;

const SERVER: Range<u64> = 0x9000..0x9100;

fn fault(rip: u64, rsp: u64, error: u64) -> Frame {
    Frame {
        vector: PAGE_FAULT,
        cs: 0x08,
        rip,
        rsp,
        error,
        rflags: 0x46,
        ..Frame::default()
    }
}

#[test]
fn stores_a_call_at_the_faulting_instruction() {
    let mut frame = fault(0x4321, 0x7_0f00, WRITE | 1);
    let redirect = Redirect::plan(&frame, 0x5_0040, SERVER).unwrap();
    assert_eq!(redirect.rsp, 0x7_0f00 - 24);
    assert_eq!(redirect.words, [0x5_0040, 1, 0x4321]);
    let registers = frame;
    redirect.apply(&mut frame, SERVER.start);
    assert_eq!((frame.rip, frame.rsp), (SERVER.start, 0x7_0f00 - 24));
    // The server's RET pops the instruction's address into RIP and leaves
    // RSP where the fault found it; nothing else in the frame changes.
    let ret = redirect.rsp + 8 * (WORDS as u64 - 1);
    assert_eq!(ret + 8, registers.rsp);
    assert_eq!(redirect.words[WORDS - 1], registers.rip);
    frame.rip = registers.rip;
    frame.rsp = registers.rsp;
    assert_eq!(format!("{frame:?}"), format!("{registers:?}"));
}

#[test]
fn reads_say_so() {
    let frame = fault(0x4321, 0x7_0f00, 0);
    let redirect = Redirect::plan(&frame, 0x5_0040, SERVER).unwrap();
    assert_eq!(redirect.words[1], 0);
}

#[test]
fn refuses_other_vectors_and_user_code() {
    let mut frame = fault(0x4321, 0x7_0f00, 0);
    frame.vector = 13;
    assert_eq!(
        Redirect::plan(&frame, 0x5_0040, SERVER),
        Err(Refused::NotPageFault)
    );
    let mut frame = fault(0x4321, 0x7_0f00, 0);
    frame.cs = 0x2b;
    assert_eq!(Redirect::plan(&frame, 0x5_0040, SERVER), Err(Refused::User));
}

#[test]
fn refuses_a_fault_in_the_servers_entry() {
    let frame = fault(SERVER.start + 4, 0x7_0f00, 0);
    assert_eq!(
        Redirect::plan(&frame, 0x5_0040, SERVER),
        Err(Refused::Server)
    );
    let frame = fault(SERVER.end, 0x7_0f00, 0);
    assert!(Redirect::plan(&frame, 0x5_0040, SERVER).is_ok());
}

#[test]
fn refuses_a_stack_the_words_do_not_fit() {
    let frame = fault(0x4321, 0x7_0f04, 0);
    assert_eq!(
        Redirect::plan(&frame, 0x5_0040, SERVER),
        Err(Refused::Stack)
    );
    let frame = fault(0x4321, 16, 0);
    assert_eq!(
        Redirect::plan(&frame, 0x5_0040, SERVER),
        Err(Refused::Stack)
    );
}

#[test]
fn refuses_a_stack_that_ran_into_the_faulting_page() {
    // RSP at the top of the faulting page: the words would go there.
    let frame = fault(0x4321, 0x7_1000, 0);
    assert_eq!(
        Redirect::plan(&frame, 0x7_0ff8, SERVER),
        Err(Refused::OwnStack)
    );
    // RSP just above a page boundary: the lowest word crosses into the
    // faulting page below.
    let frame = fault(0x4321, 0x7_1010, 0);
    assert_eq!(
        Redirect::plan(&frame, 0x7_0000, SERVER),
        Err(Refused::OwnStack)
    );
    // A fault on the page RSP points into, but above every word: still the
    // stack's own page, and still refused.
    let frame = fault(0x4321, 0x7_0800, 0);
    assert_eq!(
        Redirect::plan(&frame, 0x7_0900, SERVER),
        Err(Refused::OwnStack)
    );
    // The page above the stack is another mapping.
    let frame = fault(0x4321, 0x7_0800, 0);
    assert!(Redirect::plan(&frame, 0x7_1000, SERVER).is_ok());
}
