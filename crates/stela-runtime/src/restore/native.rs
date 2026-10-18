//! Translate the native mux API's empty windows into Pending, not EOF. This
//! adapter only borrows the USB service for the current scheduler poll.
use super::{Error, Result, driver::Ports};
use crate::machine::apple::{MuxState, MuxStream, MuxStreamState, UsbClient};
use core::task::Poll;
fn transport(error: &'static str) -> Error {
    Error::Transport(error.into())
}
impl Ports for UsbClient<'_> {
    type Handle = MuxStream;
    fn open(&mut self, port: u16) -> Poll<Result<MuxStream>> {
        match self.mux_state() {
            MuxState::Negotiating => Poll::Pending,
            MuxState::Failed => Poll::Ready(Err(transport("usbmux negotiation failed"))),
            MuxState::Active => {
                if self.control_ready() {
                    Poll::Ready(UsbClient::open(self, port).map_err(transport))
                } else {
                    Poll::Pending
                }
            }
        }
    }
    fn read(&mut self, h: MuxStream, b: &mut [u8]) -> Poll<Result<usize>> {
        if self.mux_state() == MuxState::Failed {
            return Poll::Ready(Err(transport("usbmux failed")));
        }
        let state = self.state(h).map_err(transport)?;
        match state {
            MuxStreamState::Connecting => return Poll::Pending,
            MuxStreamState::Refused | MuxStreamState::Reset => {
                return Poll::Ready(Err(transport("usbmux peer refused/reset stream")));
            }
            _ => {}
        }
        if !self.control_ready() {
            return Poll::Pending;
        }
        let n = UsbClient::read(self, h, b).map_err(transport)?;
        if n == 0 && !b.is_empty() && state == MuxStreamState::Open {
            Poll::Pending
        } else {
            Poll::Ready(Ok(n))
        }
    }
    fn write(&mut self, h: MuxStream, b: &[u8]) -> Poll<Result<usize>> {
        if self.mux_state() == MuxState::Failed {
            return Poll::Ready(Err(transport("usbmux failed")));
        }
        match self.state(h).map_err(transport)? {
            MuxStreamState::Connecting => Poll::Pending,
            MuxStreamState::Open => {
                let n = UsbClient::write(self, h, b).map_err(transport)?;
                if n == 0 && !b.is_empty() {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(n))
                }
            }
            _ => Poll::Ready(Err(transport(
                "usbmux stream closed/refused/reset during write",
            ))),
        }
    }
    fn close(&mut self, h: MuxStream) -> Poll<Result<()>> {
        let state = self.state(h).map_err(transport)?;
        if matches!(state, MuxStreamState::Connecting | MuxStreamState::Open)
            && !self.control_ready()
        {
            return Poll::Pending;
        }
        UsbClient::close(self, h).map_err(transport)?;
        Poll::Ready(self.release(h).map_err(transport))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::usb::{
        mux::{Mux, tests::connected},
        session::Session,
    };
    #[test]
    fn native_readiness_empty_windows_short_writes_and_release_use_real_mux() {
        let mut negotiating = Session::new();
        let mut client = UsbClient::test_session(&mut negotiating);
        assert!(Ports::open(&mut client, 62078).is_pending());
        let (mux, id) = connected();
        let mut session = Session::test_mux(mux);
        let mut client = UsbClient::test_session(&mut session);
        let mut bytes = [0; 4];
        assert!(Ports::read(&mut client, id, &mut bytes).is_pending());
        assert_eq!(Ports::write(&mut client, id, b"abc"), Poll::Ready(Ok(3)));
        let Poll::Ready(Ok(other)) = Ports::open(&mut client, 1234) else {
            panic!("open");
        };
        assert_eq!(client.state(other), Ok(MuxStreamState::Connecting));
        assert!(Ports::read(&mut client, other, &mut bytes).is_pending());
        assert!(Ports::write(&mut client, other, b"x").is_pending());
        // Fill the actual bounded mux queue/window. Zero must become Pending.
        let mut blocked = false;
        for _ in 0..1000 {
            match Ports::write(&mut client, id, b"x") {
                Poll::Pending => {
                    blocked = true;
                    break;
                }
                Poll::Ready(v) => assert_eq!(v.unwrap(), 1),
            }
        }
        assert!(blocked);
        assert!(!client.control_ready());
        assert!(Ports::open(&mut client, 2345).is_pending());
        assert!(Ports::close(&mut client, other).is_pending());
        assert_eq!(client.state(other), Ok(MuxStreamState::Connecting));
        assert!(Ports::read(&mut client, id, &mut bytes).is_pending());
        // A fresh real mux lets us verify close/release without draining the
        // deliberately full transmit queue used above.
        let (mux, id) = connected();
        let mut session = Session::test_mux(mux);
        let mut client = UsbClient::test_session(&mut session);
        UsbClient::close(&mut client, id).unwrap();
        assert_eq!(Ports::read(&mut client, id, &mut bytes), Poll::Ready(Ok(0)));
        assert_eq!(Ports::close(&mut client, id), Poll::Ready(Ok(())));
        assert!(matches!(
            Ports::read(&mut client, id, &mut bytes),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Ports::write(&mut client, id, b"x"),
            Poll::Ready(Err(_))
        ));
    }
    #[test]
    fn failed_mux_is_an_error_even_when_stream_state_was_open() {
        let (mut mux, id) = connected();
        assert!(mux.receive(&[0; 16]).is_err());
        let mut session = Session::test_mux(mux);
        let mut client = UsbClient::test_session(&mut session);
        assert!(matches!(Ports::open(&mut client, 1), Poll::Ready(Err(_))));
        assert!(matches!(
            Ports::read(&mut client, id, &mut [0]),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Ports::write(&mut client, id, b"x"),
            Poll::Ready(Err(_))
        ));
        // Generation-invalid handles are independently rejected.
        let mut mux = Mux::new();
        mux.reset().unwrap();
        let mut session = Session::test_mux(mux);
        let mut client = UsbClient::test_session(&mut session);
        assert!(matches!(Ports::close(&mut client, id), Poll::Ready(Err(_))));
    }
}
