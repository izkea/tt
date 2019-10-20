#![allow(unused_must_use)]
// a wrapper over the RawFd, the code is copied from tun/platform/posix/fd.rs: Fd
// but without implementing the Drop trait
extern crate libc;
use std::io::{self, Read, Write};
use std::os::unix::io::RawFd;

pub struct TunFd(pub RawFd);

impl TunFd {
	pub fn new(value: RawFd) -> TunFd {
            assert!(value >= 0);
		TunFd(value)
	}
}

impl Read for TunFd {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		unsafe {
			let amount = libc::read(self.0, buf.as_mut_ptr() as *mut _, buf.len());

			if amount < 0 {
				return Err(io::Error::last_os_error().into());
			}

			Ok(amount as usize)
		}
	}
}

impl Write for TunFd {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		unsafe {
			let amount = libc::write(self.0, buf.as_ptr() as *const _, buf.len());

			if amount < 0 {
				return Err(io::Error::last_os_error().into());
			}

			Ok(amount as usize)
		}
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}
