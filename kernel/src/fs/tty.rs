use alloc::collections::VecDeque;
use alloc::sync::Arc;

use crate::arch::Arch;
use crate::arch::api::ArchDevice;
use crate::fs::{File, FileType, Metadata, VfsError};
use crate::util::lazylock::LazyLock;
use crate::util::spinlock::SpinLock;
use crate::util::stream::{ReadOps, WriteOps};

const TTY_BUFFER_LIMIT: usize = 4096;

pub struct Tty {
    input: SpinLock<VecDeque<u8>>,
    output: SpinLock<VecDeque<u8>>,
}

impl Tty {
    pub fn new() -> Self {
        Self {
            input: SpinLock::new(VecDeque::new()),
            output: SpinLock::new(VecDeque::new()),
        }
    }

    pub fn push_input(&self, data: &[u8]) {
        let mut guard = self.input.lock();
        for byte in data {
            guard.push_back(*byte);
        }
    }

    pub fn drain_output(&self) -> alloc::vec::Vec<u8> {
        let mut guard = self.output.lock();
        guard.drain(..).collect()
    }

    pub fn clear_output(&self) {
        let mut guard = self.output.lock();
        guard.clear();
    }

    fn record_output(&self, data: &[u8]) {
        let mut guard = self.output.lock();
        for byte in data {
            guard.push_back(*byte);
        }
        while guard.len() > TTY_BUFFER_LIMIT {
            let _ = guard.pop_front();
        }
    }

    fn read_from_input(&self, buf: &mut [u8]) -> usize {
        let mut guard = self.input.lock();
        let mut read = 0usize;
        while read < buf.len() {
            if let Some(byte) = guard.pop_front() {
                buf[read] = byte;
                read += 1;
            } else {
                break;
            }
        }
        read
    }
}

impl File for Tty {
    fn metadata(&self) -> Result<Metadata, VfsError> {
        Ok(Metadata {
            file_type: FileType::File,
            size: 0,
        })
    }

    fn read_at(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, VfsError> {
        let mut total = self.read_from_input(buf);
        if total < buf.len() {
            let console = Arch::console();
            let read = console
                .read(&mut buf[total..])
                .map_err(|_| VfsError::UnderlyingDevice)?;
            total += read;
        }
        Ok(total)
    }

    fn write_at(&self, _offset: usize, data: &[u8]) -> Result<usize, VfsError> {
        let console = Arch::console();
        let written = console
            .write(data)
            .map_err(|_| VfsError::UnderlyingDevice)?;
        self.record_output(&data[..written]);
        Ok(written)
    }
}

fn init_tty() -> Arc<Tty> {
    Arc::new(Tty::new())
}

static GLOBAL_TTY: LazyLock<Arc<Tty>> = LazyLock::new_const(init_tty);

pub fn global_tty() -> Arc<Tty> {
    GLOBAL_TTY.get().clone()
}
