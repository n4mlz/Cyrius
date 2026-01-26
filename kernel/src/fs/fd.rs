use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{DeviceNode, File, VfsError};
use crate::util::spinlock::SpinLock;
use crate::util::stream::{ControlError, ControlRequest};

pub type Fd = u32;

#[derive(Clone)]
pub enum OpenEntry {
    File(Arc<dyn File>),
    Device(Arc<dyn DeviceNode>),
}

#[derive(Clone)]
pub struct OpenHandle {
    entry: OpenEntry,
    offset: usize,
}

impl OpenHandle {
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, VfsError> {
        let read = match &self.entry {
            OpenEntry::File(file) => file.read_at(self.offset, buf)?,
            OpenEntry::Device(dev) => dev.read_at(self.offset, buf)?,
        };
        self.offset = self.offset.checked_add(read).ok_or(VfsError::Corrupted)?;
        Ok(read)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, VfsError> {
        let written = match &self.entry {
            OpenEntry::File(file) => file.write_at(self.offset, data)?,
            OpenEntry::Device(dev) => dev.write_at(self.offset, data)?,
        };
        self.offset = self
            .offset
            .checked_add(written)
            .ok_or(VfsError::Corrupted)?;
        Ok(written)
    }

    pub fn control(&self, request: &ControlRequest<'_>) -> Result<u64, ControlError> {
        match &self.entry {
            OpenEntry::File(_) => Err(ControlError::Unsupported),
            OpenEntry::Device(dev) => dev.control(request),
        }
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
        guard.set(
            fd,
            OpenHandle {
                entry: OpenEntry::File(file),
                offset: 0,
            },
        )?;
        Ok(fd)
    }

    pub fn open_device(&self, device: Arc<dyn DeviceNode>) -> Result<Fd, VfsError> {
        let mut guard = self.inner.lock();
        let fd = guard.allocate_fd(self.next_fd.fetch_add(1, Ordering::AcqRel));
        guard.set(
            fd,
            OpenHandle {
                entry: OpenEntry::Device(device),
                offset: 0,
            },
        )?;
        Ok(fd)
    }

    pub fn open_fixed(&self, fd: Fd, file: Arc<dyn File>) -> Result<(), VfsError> {
        let mut guard = self.inner.lock();
        if guard.exists(fd) {
            return Err(VfsError::AlreadyExists);
        }
        guard.set(
            fd,
            OpenHandle {
                entry: OpenEntry::File(file),
                offset: 0,
            },
        )?;
        Ok(())
    }

    pub fn open_fixed_device(&self, fd: Fd, device: Arc<dyn DeviceNode>) -> Result<(), VfsError> {
        let mut guard = self.inner.lock();
        if guard.exists(fd) {
            return Err(VfsError::AlreadyExists);
        }
        guard.set(
            fd,
            OpenHandle {
                entry: OpenEntry::Device(device),
                offset: 0,
            },
        )?;
        Ok(())
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

    pub fn control(&self, fd: Fd, request: &ControlRequest<'_>) -> Result<u64, ControlError> {
        let mut guard = self.inner.lock();
        let file = guard.get_mut(fd).map_err(|_| ControlError::Invalid)?;
        file.control(request)
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

struct FdTableInner {
    slots: Vec<Option<OpenHandle>>,
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

    fn set(&mut self, fd: Fd, entry: OpenHandle) -> Result<(), VfsError> {
        let index = fd as usize;
        if index >= self.slots.len() {
            self.slots.resize(index + 1, None);
        }
        self.slots[index] = Some(entry);
        Ok(())
    }

    fn exists(&self, fd: Fd) -> bool {
        self.slots
            .get(fd as usize)
            .and_then(|entry| entry.as_ref())
            .is_some()
    }

    fn get_mut(&mut self, fd: Fd) -> Result<&mut OpenHandle, VfsError> {
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
