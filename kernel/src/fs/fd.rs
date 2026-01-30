use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::{File, Path, VfsError};
use crate::util::spinlock::SpinLock;

pub type Fd = u32;

#[derive(Clone)]
pub struct FdEntry {
    file: Arc<dyn File>,
    close_on_exec: bool,
    dir_offset: u64,
    path: Option<Path>,
}

impl FdEntry {
    pub fn new(file: Arc<dyn File>) -> Self {
        Self {
            file,
            close_on_exec: false,
            dir_offset: 0,
            path: None,
        }
    }

    pub fn new_with_path(file: Arc<dyn File>, path: Path) -> Self {
        Self {
            file,
            close_on_exec: false,
            dir_offset: 0,
            path: Some(path),
        }
    }

    pub fn file(&self) -> &Arc<dyn File> {
        &self.file
    }

    pub fn close_on_exec(&self) -> bool {
        self.close_on_exec
    }

    pub fn set_close_on_exec(&mut self, value: bool) {
        self.close_on_exec = value;
    }

    pub fn dir_offset(&self) -> u64 {
        self.dir_offset
    }

    pub fn set_dir_offset(&mut self, value: u64) {
        self.dir_offset = value;
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_ref()
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
        guard.set(fd, FdEntry::new(file))?;
        Ok(fd)
    }

    pub fn open_file_with_path(&self, file: Arc<dyn File>, path: Path) -> Result<Fd, VfsError> {
        let mut guard = self.inner.lock();
        let fd = guard.allocate_fd(self.next_fd.fetch_add(1, Ordering::AcqRel));
        guard.set(fd, FdEntry::new_with_path(file, path))?;
        Ok(fd)
    }

    pub fn open_fixed(&self, fd: Fd, file: Arc<dyn File>) -> Result<(), VfsError> {
        let mut guard = self.inner.lock();
        if guard.exists(fd) {
            return Err(VfsError::AlreadyExists);
        }
        guard.set(fd, FdEntry::new(file))?;
        Ok(())
    }

    pub fn read(&self, fd: Fd, buf: &mut [u8]) -> Result<usize, VfsError> {
        let guard = self.inner.lock();
        let entry = guard.get(fd)?;
        entry.file().read(buf)
    }

    pub fn write(&self, fd: Fd, data: &[u8]) -> Result<usize, VfsError> {
        let guard = self.inner.lock();
        let entry = guard.get(fd)?;
        entry.file().write(data)
    }

    pub fn close(&self, fd: Fd) -> Result<(), VfsError> {
        let mut guard = self.inner.lock();
        guard.clear(fd)
    }

    pub fn dup_min(&self, src: Fd, min: Fd, close_on_exec: bool) -> Result<Fd, VfsError> {
        let mut guard = self.inner.lock();
        let entry = guard.get(src)?.clone();
        let mut entry = entry;
        entry.set_close_on_exec(close_on_exec);
        let fd = guard.allocate_fd_from(min);
        guard.set(fd, entry)?;
        Ok(fd)
    }

    pub fn get_fd_flags(&self, fd: Fd) -> Result<u32, VfsError> {
        let guard = self.inner.lock();
        let entry = guard.get(fd)?;
        Ok(if entry.close_on_exec() { 1 } else { 0 })
    }

    pub fn set_fd_flags(&self, fd: Fd, flags: u32) -> Result<(), VfsError> {
        let mut guard = self.inner.lock();
        let entry = guard
            .slots
            .get_mut(fd as usize)
            .and_then(|slot| slot.as_mut())
            .ok_or(VfsError::NotFound)?;
        entry.set_close_on_exec(flags & 1 != 0);
        Ok(())
    }

    pub fn entry(&self, fd: Fd) -> Result<FdEntry, VfsError> {
        let guard = self.inner.lock();
        guard.get(fd).cloned()
    }

    pub fn dir_offset(&self, fd: Fd) -> Result<u64, VfsError> {
        let guard = self.inner.lock();
        let entry = guard.get(fd)?;
        Ok(entry.dir_offset())
    }

    pub fn set_dir_offset(&self, fd: Fd, offset: u64) -> Result<(), VfsError> {
        let mut guard = self.inner.lock();
        let entry = guard
            .slots
            .get_mut(fd as usize)
            .and_then(|slot| slot.as_mut())
            .ok_or(VfsError::NotFound)?;
        entry.set_dir_offset(offset);
        Ok(())
    }

    pub fn clone_from(&self, other: &FdTable) {
        let other_guard = other.inner.lock();
        let mut guard = self.inner.lock();
        guard.slots = other_guard.slots.clone();
        self.next_fd
            .store(other.next_fd.load(Ordering::Acquire), Ordering::Release);
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

struct FdTableInner {
    slots: Vec<Option<FdEntry>>,
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

    fn allocate_fd_from(&mut self, min: Fd) -> Fd {
        if let Some((index, _)) = self
            .slots
            .iter()
            .enumerate()
            .skip(min as usize)
            .find(|(_, entry)| entry.is_none())
        {
            return index as Fd;
        }
        let fd = min as usize;
        if fd >= self.slots.len() {
            self.slots.resize(fd + 1, None);
        }
        fd as Fd
    }

    fn set(&mut self, fd: Fd, entry: FdEntry) -> Result<(), VfsError> {
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

    fn get(&self, fd: Fd) -> Result<&FdEntry, VfsError> {
        self.slots
            .get(fd as usize)
            .and_then(|entry| entry.as_ref())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::devfs::global_tty_node;
    use crate::println;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn fd_table_clone_copies_entries() {
        println!("[test] fd_table_clone_copies_entries");

        let src = FdTable::new();
        let dst = FdTable::new();
        let tty = global_tty_node()
            .open(crate::fs::OpenOptions::new(0))
            .expect("open tty");
        src.open_fixed(10, tty).expect("open fixed");

        dst.clone_from(&src);
        assert!(dst.entry(10).is_ok(), "cloned fd missing");
    }
}
