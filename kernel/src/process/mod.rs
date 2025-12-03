use alloc::{string::ToString, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{Arch, api::ArchThread};
use crate::fs::{DirEntry, Fd, FdTable, NodeRef, PathComponent, VfsError, VfsPath, with_vfs};
use crate::thread::ThreadId;
use crate::util::spinlock::SpinLock;

pub type ProcessId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    AlreadyInitialised,
    NotInitialised,
    NotFound,
    DuplicateThread,
    ThreadNotAttached,
}

pub struct ProcessFs {
    pub cwd: VfsPath,
    pub fd_table: FdTable,
}

impl ProcessFs {
    pub fn new() -> Self {
        Self {
            cwd: VfsPath::root(),
            fd_table: FdTable::new(),
        }
    }

    pub fn set_cwd(&mut self, path: VfsPath) {
        self.cwd = path;
    }
}

impl Default for ProcessFs {
    fn default() -> Self {
        Self::new()
    }
}

/// Global table that tracks processes and their associated threads.
///
/// # Implementation note
///
/// At this point, each process does not have an individual address space and all share the kernel's address space.
/// When implementing userland in the future, it will be necessary to properly duplicate and isolate `ArchThread::AddressSpace` here.
pub struct ProcessTable {
    inner: SpinLock<ProcessTableInner>,
    initialised: AtomicBool,
}

impl ProcessTable {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(ProcessTableInner::new()),
            initialised: AtomicBool::new(false),
        }
    }

    pub fn init_kernel(&self) -> Result<ProcessId, ProcessError> {
        if self
            .initialised
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(self
                .inner
                .lock()
                .kernel_pid
                .expect("kernel process must exist"));
        }

        let mut inner = self.inner.lock();
        if inner.kernel_pid.is_some() {
            return Err(ProcessError::AlreadyInitialised);
        }

        let process = Process::kernel(0, "kernel");
        inner.kernel_pid = Some(process.id);
        inner.next_pid = 1;
        inner.processes.push(process);

        Ok(0)
    }

    pub fn kernel_process_id(&self) -> Option<ProcessId> {
        let inner = self.inner.lock();
        inner.kernel_pid
    }

    pub fn create_kernel_process(&self, name: &'static str) -> Result<ProcessId, ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let pid = inner.next_pid;
        let process = Process::kernel(pid, name);
        inner.next_pid = pid.checked_add(1).expect("process id overflow");
        inner.processes.push(process);
        Ok(pid)
    }

    pub fn create_user_process(&self, name: &'static str) -> Result<ProcessId, ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let pid = inner.next_pid;
        let process = Process::user(pid, name);
        inner.next_pid = pid.checked_add(1).expect("process id overflow");
        inner.processes.push(process);
        Ok(pid)
    }

    pub fn attach_thread(&self, pid: ProcessId, tid: ThreadId) -> Result<(), ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(ProcessError::NotFound)?;

        if process.threads.contains(&tid) {
            return Err(ProcessError::DuplicateThread);
        }

        process.threads.push(tid);
        Ok(())
    }

    pub fn detach_thread(&self, pid: ProcessId, tid: ThreadId) -> Result<(), ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(ProcessError::NotFound)?;

        if let Some(index) = process.threads.iter().position(|&id| id == tid) {
            process.threads.swap_remove(index);
            Ok(())
        } else {
            Err(ProcessError::ThreadNotAttached)
        }
    }

    pub fn thread_count(&self, pid: ProcessId) -> Option<usize> {
        let inner = self.inner.lock();
        inner.process(pid).map(|proc| proc.threads.len())
    }

    pub fn address_space(&self, pid: ProcessId) -> Option<<Arch as ArchThread>::AddressSpace> {
        let inner = self.inner.lock();
        inner.process(pid).map(|proc| proc.address_space.clone())
    }

    pub fn open_path(&self, pid: ProcessId, raw_path: &str) -> Result<Fd, VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.fs.cwd)?;
        let file = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
            NodeRef::File(file) => Ok(file),
            NodeRef::Directory(_) => Err(VfsError::NotFile),
        })?;
        process.fs.fd_table.open_file(file)
    }

    pub fn read_fd(&self, pid: ProcessId, fd: Fd, buf: &mut [u8]) -> Result<usize, VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        process.fs.fd_table.read(fd, buf)
    }

    pub fn write_fd(&self, pid: ProcessId, fd: Fd, data: &[u8]) -> Result<usize, VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        process.fs.fd_table.write(fd, data)
    }

    pub fn close_fd(&self, pid: ProcessId, fd: Fd) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        process.fs.fd_table.close(fd)
    }

    pub fn change_dir(&self, pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.fs.cwd)?;
        let dir = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) => Err(VfsError::NotDirectory),
        })?;
        process.fs.set_cwd(abs);
        // Keep dir alive by ensuring mount lookup remains valid; cwd path suffices.
        drop(dir);
        Ok(())
    }

    pub fn list_dir(&self, pid: ProcessId, raw_path: &str) -> Result<Vec<DirEntry>, VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.fs.cwd)?;
        let dir = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) => Err(VfsError::NotDirectory),
        })?;
        dir.read_dir()
    }

    pub fn remove_path(&self, pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.fs.cwd)?;
        let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
        let name = abs
            .components()
            .last()
            .ok_or(VfsError::InvalidPath)?
            .as_str()
            .to_string();
        let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) => Err(VfsError::NotDirectory),
        })?;
        dir.remove(&name)
    }

    pub fn write_path(&self, pid: ProcessId, raw_path: &str, data: &[u8]) -> Result<(), VfsError> {
        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.fs.cwd)?;
        let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
        let name = abs
            .components()
            .last()
            .ok_or(VfsError::InvalidPath)?
            .as_str()
            .to_string();
        let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) => Err(VfsError::NotDirectory),
        })?;
        let component = PathComponent::new(name.as_str());
        let file = match dir.lookup(&component) {
            Ok(NodeRef::File(f)) => f,
            Ok(NodeRef::Directory(_)) => return Err(VfsError::NotFile),
            Err(VfsError::NotFound) => dir.create_file(&name)?,
            Err(e) => return Err(e),
        };
        file.truncate(0)?;
        let _ = file.write_at(0, data)?;
        Ok(())
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

pub static PROCESS_TABLE: ProcessTable = ProcessTable::new();

struct ProcessTableInner {
    processes: Vec<Process>,
    kernel_pid: Option<ProcessId>,
    next_pid: ProcessId,
}

impl ProcessTableInner {
    const fn new() -> Self {
        Self {
            processes: Vec::new(),
            kernel_pid: None,
            next_pid: 0,
        }
    }

    fn process(&self, pid: ProcessId) -> Option<&Process> {
        self.processes.iter().find(|proc| proc.id == pid)
    }

    fn process_mut(&mut self, pid: ProcessId) -> Option<&mut Process> {
        self.processes.iter_mut().find(|proc| proc.id == pid)
    }
}

struct Process {
    id: ProcessId,
    _name: &'static str,
    address_space: <Arch as ArchThread>::AddressSpace,
    _state: ProcessState,
    #[allow(dead_code)]
    kind: ProcessKind,
    threads: Vec<ThreadId>,
    fs: ProcessFs,
}

impl Process {
    fn kernel(id: ProcessId, name: &'static str) -> Self {
        Self {
            id,
            _name: name,
            address_space: <Arch as ArchThread>::current_address_space(),
            _state: ProcessState::Active,
            kind: ProcessKind::Kernel,
            threads: Vec::new(),
            fs: ProcessFs::new(),
        }
    }

    fn user(id: ProcessId, name: &'static str) -> Self {
        Self {
            id,
            _name: name,
            address_space: <Arch as ArchThread>::current_address_space(),
            _state: ProcessState::Active,
            kind: ProcessKind::User,
            threads: Vec::new(),
            fs: ProcessFs::new(),
        }
    }
}

fn absolute_path(raw: &str, cwd: &VfsPath) -> Result<VfsPath, VfsError> {
    let path = VfsPath::parse(raw)?;
    if path.is_absolute() {
        Ok(path)
    } else {
        cwd.join(&path)
    }
}

#[derive(Clone, Copy, Debug)]
enum ProcessState {
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessKind {
    Kernel,
    User,
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;
    use crate::{println, test::kernel_test_case};

    #[kernel_test_case]
    fn kernel_process_shares_address_space() {
        println!("[test] kernel_process_shares_address_space");

        let pid = PROCESS_TABLE.init_kernel().expect("kernel init");
        let a = PROCESS_TABLE
            .address_space(pid)
            .expect("kernel address space");
        let b = PROCESS_TABLE
            .address_space(pid)
            .expect("kernel address space clone");

        assert!(Arc::ptr_eq(a.inner(), b.inner()));
    }

    #[kernel_test_case]
    fn create_user_process_assigns_pid() {
        println!("[test] create_user_process_assigns_pid");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process("user-proc")
            .expect("create user process");
        assert!(pid > 0);
        let addr_space = PROCESS_TABLE
            .address_space(pid)
            .expect("user address space");
        let ref_again = PROCESS_TABLE
            .address_space(pid)
            .expect("user address space clone");
        assert!(Arc::ptr_eq(addr_space.inner(), ref_again.inner()));
    }
}
