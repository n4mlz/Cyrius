use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{File, VfsError};
use crate::util::spinlock::SpinLock;

pub type Fd = u32;

#[derive(Clone)]
pub struct OpenFile {
    file: Arc<dyn File>,
    offset: usize,
}

impl OpenFile {
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, VfsError> {
        let read = self.file.read_at(self.offset, buf)?;
        self.offset = self.offset.checked_add(read).ok_or(VfsError::Corrupted)?;
        Ok(read)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, VfsError> {
        let written = self.file.write_at(self.offset, data)?;
        self.offset = self
            .offset
            .checked_add(written)
            .ok_or(VfsError::Corrupted)?;
        Ok(written)
    }
}

pub struct FdTable {
    inner: SpinLock<FdTableInner>,
    next_fd: AtomicU32,
}

impl FdTable {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(FdTableInner::new()),
            next_fd: AtomicU32::new(3),
        }
    }

    pub fn open_file(&self, file: Arc<dyn File>) -> Result<Fd, VfsError> {
        let mut guard = self.inner.lock();
        let fd = guard.allocate_fd(self.next_fd.fetch_add(1, Ordering::AcqRel));
        guard.set(fd, OpenFile { file, offset: 0 })?;
        Ok(fd)
    }

    pub fn read(&self, fd: Fd, buf: &mut [u8]) -> Result<usize, VfsError> {
        let mut guard = self.inner.lock();
        let file = guard.get_mut(fd)?;
        file.read(buf)
    }

    pub fn write(&self, fd: Fd, data: &[u8]) -> Result<usize, VfsError> {
        let mut guard = self.inner.lock();
        let file = guard.get_mut(fd)?;
        file.write(data)
    }

    pub fn close(&self, fd: Fd) -> Result<(), VfsError> {
        let mut guard = self.inner.lock();
        guard.clear(fd)
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

struct FdTableInner {
    slots: Vec<Option<OpenFile>>,
}

impl FdTableInner {
    const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    fn allocate_fd(&mut self, suggested: u32) -> Fd {
        if let Some(index) = self.slots.iter().position(|entry| entry.is_none()) {
            return index as Fd;
        }
        let fd = suggested as usize;
        if fd >= self.slots.len() {
            self.slots.resize(fd + 1, None);
        }
        fd as Fd
    }

    fn set(&mut self, fd: Fd, entry: OpenFile) -> Result<(), VfsError> {
        let index = fd as usize;
        if index >= self.slots.len() {
            self.slots.resize(index + 1, None);
        }
        self.slots[index] = Some(entry);
        Ok(())
    }

    fn get_mut(&mut self, fd: Fd) -> Result<&mut OpenFile, VfsError> {
        self.slots
            .get_mut(fd as usize)
            .and_then(|entry| entry.as_mut())
            .ok_or(VfsError::NotFound)
    }

    fn clear(&mut self, fd: Fd) -> Result<(), VfsError> {
        if let Some(slot) = self.slots.get_mut(fd as usize) {
            *slot = None;
            Ok(())
        } else {
            Err(VfsError::NotFound)
        }
    }
}
