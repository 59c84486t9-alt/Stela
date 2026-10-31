//! There are no files: a debug dump Mesa asks for fails to open.
use crate::io;

pub struct File;

impl File {
    pub fn create(_: &str) -> io::Result<Self> {
        Err(io::Error::last_os_error())
    }
}

impl io::Write for File {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
}
