//! The streams Mesa's Rust prints to, which reach the host's log.
use core::fmt;

unsafe extern "C" {
    fn stela_libc_log(text: *const u8, size: usize);
}

/// What a failed call into the C library left in `errno`, which is all Mesa
/// reads of one here.
#[derive(Debug)]
pub struct Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidData,
    InvalidInput,
    Other,
}

impl Error {
    pub fn last_os_error() -> Self {
        Self
    }

    pub fn new<E>(_: ErrorKind, _: E) -> Self {
        Self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("C library error")
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub trait Write {
    fn write(&mut self, bytes: &[u8]) -> Result<usize>;

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
        self.write(bytes).map(|_| ())
    }

    fn write_fmt(&mut self, arguments: fmt::Arguments<'_>) -> Result<()> {
        let text = alloc_crate::fmt::format(arguments);
        self.write_all(text.as_bytes())
    }
}

pub struct Stderr;

pub fn stderr() -> Stderr {
    Stderr
}

impl Write for Stderr {
    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        // SAFETY: the C library copies out of the live slice.
        unsafe { stela_libc_log(bytes.as_ptr(), bytes.len()) };
        Ok(bytes.len())
    }
}

/// `BufWriter`, writing straight through: its only stream is unbuffered.
pub struct BufWriter<W>(W);

impl<W: Write> BufWriter<W> {
    pub fn new(inner: W) -> Self {
        Self(inner)
    }
}

impl<W: Write> Write for BufWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        self.0.write(bytes)
    }
}

#[doc(hidden)]
pub fn _log(arguments: fmt::Arguments<'_>) {
    let _ = Stderr.write_fmt(arguments);
}
