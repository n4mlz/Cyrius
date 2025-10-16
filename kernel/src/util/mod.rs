pub mod lazylock;
pub mod spinlock;
pub mod stream;

use crate::arch::{Arch, api::ArchDevice};
use crate::util::stream::{StreamError, WriteOps};

#[macro_export]
macro_rules! cast {
    ($n:expr) => {
        num_traits::cast($n).unwrap()
    };
}

pub struct Writer;

impl core::fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        match Arch::console().write(s.as_bytes()) {
            Ok(written) if written == s.len() => Ok(()),
            Ok(_) => Err(core::fmt::Error),
            Err(StreamError::WouldBlock) => Err(core::fmt::Error),
            Err(StreamError::Unsupported) => Err(core::fmt::Error),
            Err(StreamError::Transport(_)) => Err(core::fmt::Error),
        }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        use core::fmt::Write;
        let _ = write!($crate::util::Writer, $($arg)*);
    });
}

#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => ({
        $crate::print!("{}\n", format_args!($($arg)*));
    });
}
