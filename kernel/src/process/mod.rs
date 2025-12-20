use alloc::{string::ToString, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::arch::{Arch, api::ArchThread};
use crate::fs::{DirEntry, Fd, FdTable, NodeRef, PathComponent, VfsError, VfsPath, with_vfs};
use crate::syscall::Abi;
use crate::thread::ThreadId;
use crate::util::spinlock::SpinLock;

pub type ProcessId = u64;
pub type ProcessHandle = Arc<ProcessControl>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    AlreadyInitialised,
    NotInitialised,
    NotFound,
    DuplicateThread,
    ThreadNotAttached,
}

pub struct ProcessFs {
    pub fd_table: FdTable,
    cwd: SpinLock<VfsPath>,
}

impl ProcessFs {
    pub fn new() -> Self {
        Self {
            fd_table: FdTable::new(),
            cwd: SpinLock::new(VfsPath::root()),
        }
    }

    pub fn set_cwd(&self, path: VfsPath) {
        let mut guard = self.cwd.lock();
        *guard = path;
    }

    pub fn cwd(&self) -> VfsPath {
        let guard = self.cwd.lock();
        guard.clone()
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

        let process = Arc::new(ProcessControl::kernel(0, "kernel", Abi::Host));
        inner.kernel_pid = Some(process.id());
        inner.next_pid = 1;
        inner.processes.push(process);

        Ok(0)
    }

    pub fn kernel_process_id(&self) -> Option<ProcessId> {
        let inner = self.inner.lock();
        inner.kernel_pid
    }

    pub fn process_handle(&self, pid: ProcessId) -> Result<ProcessHandle, ProcessError> {
        let inner = self.inner.lock();
        inner.process(pid).cloned().ok_or(ProcessError::NotFound)
    }

    pub fn create_kernel_process(&self, name: &'static str) -> Result<ProcessId, ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let pid = inner.next_pid;
        let process = Arc::new(ProcessControl::kernel(pid, name, Abi::Host));
        inner.next_pid = pid.checked_add(1).expect("process id overflow");
        inner.processes.push(process);
        Ok(pid)
    }

    pub fn create_user_process(&self, name: &'static str) -> Result<ProcessId, ProcessError> {
        self.create_user_process_with_abi(name, Abi::Host)
    }

    pub fn create_user_process_with_abi(
        &self,
        name: &'static str,
        abi: Abi,
    ) -> Result<ProcessId, ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let pid = inner.next_pid;
        let process = Arc::new(ProcessControl::user(pid, name, abi));
        inner.next_pid = pid.checked_add(1).expect("process id overflow");
        inner.processes.push(process);
        Ok(pid)
    }

    pub fn attach_thread(&self, pid: ProcessId, tid: ThreadId) -> Result<(), ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let process = self.process_handle(pid)?;
        process.attach_thread(tid)
    }

    pub fn detach_thread(&self, pid: ProcessId, tid: ThreadId) -> Result<(), ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let process = self.process_handle(pid)?;
        let _ = process.detach_thread(tid)?;
        Ok(())
    }

    pub fn thread_count(&self, pid: ProcessId) -> Option<usize> {
        let process = self.process_handle(pid).ok()?;
        Some(process.thread_count())
    }

    pub fn address_space(&self, pid: ProcessId) -> Option<<Arch as ArchThread>::AddressSpace> {
        let process = self.process_handle(pid).ok()?;
        Some(process.address_space())
    }

    pub fn abi(&self, pid: ProcessId) -> Option<Abi> {
        let process = self.process_handle(pid).ok()?;
        Some(process.abi())
    }

    pub fn open_path(&self, pid: ProcessId, raw_path: &str) -> Result<Fd, VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.cwd())?;
        let file = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
            NodeRef::File(file) => Ok(file),
            NodeRef::Directory(_) | NodeRef::Symlink(_) => Err(VfsError::NotFile),
        })?;
        process.fd_table().open_file(file)
    }

    pub fn read_fd(&self, pid: ProcessId, fd: Fd, buf: &mut [u8]) -> Result<usize, VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        process.fd_table().read(fd, buf)
    }

    pub fn write_fd(&self, pid: ProcessId, fd: Fd, data: &[u8]) -> Result<usize, VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        process.fd_table().write(fd, data)
    }

    pub fn close_fd(&self, pid: ProcessId, fd: Fd) -> Result<(), VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        process.fd_table().close(fd)
    }

    pub fn change_dir(&self, pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.cwd())?;
        let dir = with_vfs(|vfs| match vfs.open_absolute(&abs)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
        })?;
        process.set_cwd(abs);
        // Keep dir alive by ensuring mount lookup remains valid; cwd path suffices.
        drop(dir);
        Ok(())
    }

    pub fn list_dir(&self, pid: ProcessId, raw_path: &str) -> Result<Vec<DirEntry>, VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.cwd())?;
        with_vfs(|vfs| vfs.read_dir(&abs))
    }

    pub fn remove_path(&self, pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.cwd())?;
        let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
        let name = abs
            .components()
            .last()
            .ok_or(VfsError::InvalidPath)?
            .as_str()
            .to_string();
        let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
        })?;
        dir.remove(&name)
    }

    pub fn write_path(&self, pid: ProcessId, raw_path: &str, data: &[u8]) -> Result<(), VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.cwd())?;
        match with_vfs(|vfs| vfs.open_absolute(&abs)) {
            Ok(NodeRef::File(f)) => {
                f.truncate(0)?;
                let _ = f.write_at(0, data)?;
                Ok(())
            }
            Ok(NodeRef::Directory(_)) | Ok(NodeRef::Symlink(_)) => Err(VfsError::NotFile),
            Err(VfsError::NotFound) => {
                let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
                let name = abs
                    .components()
                    .last()
                    .ok_or(VfsError::InvalidPath)?
                    .as_str()
                    .to_string();
                let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
                    NodeRef::Directory(dir) => Ok(dir),
                    NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
                })?;
                let file = dir.create_file(&name)?;
                file.truncate(0)?;
                let _ = file.write_at(0, data)?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn create_dir(&self, pid: ProcessId, raw_path: &str) -> Result<(), VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let abs = absolute_path(raw_path, &process.cwd())?;
        let parent = abs.parent().ok_or(VfsError::InvalidPath)?;
        let name = abs
            .components()
            .last()
            .ok_or(VfsError::InvalidPath)?
            .as_str()
            .to_string();
        let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
        })?;
        match dir.create_dir(&name) {
            Ok(_) => Ok(()),
            Err(VfsError::AlreadyExists) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub fn symlink(&self, pid: ProcessId, target: &str, link_path: &str) -> Result<(), VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let link_abs = absolute_path(link_path, &process.cwd())?;
        let parent = link_abs.parent().ok_or(VfsError::InvalidPath)?;
        let name = link_abs
            .components()
            .last()
            .ok_or(VfsError::InvalidPath)?
            .as_str()
            .to_string();

        let dir = with_vfs(|vfs| match vfs.open_absolute(&parent)? {
            NodeRef::Directory(dir) => Ok(dir),
            NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
        })?;

        dir.create_symlink(&name, target)?;
        Ok(())
    }

    pub fn hard_link(
        &self,
        pid: ProcessId,
        existing_path: &str,
        link_path: &str,
    ) -> Result<(), VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        let src_abs = absolute_path(existing_path, &process.cwd())?;
        let link_abs = absolute_path(link_path, &process.cwd())?;

        let parent = link_abs.parent().ok_or(VfsError::InvalidPath)?;
        let name = link_abs
            .components()
            .last()
            .ok_or(VfsError::InvalidPath)?
            .as_str()
            .to_string();

        let (node, dir) = with_vfs(|vfs| {
            let node = match vfs.open_absolute(&src_abs)? {
                NodeRef::File(f) => NodeRef::File(f),
                NodeRef::Directory(_) => return Err(VfsError::NotDirectory),
                NodeRef::Symlink(_) => return Err(VfsError::NotFile),
            };
            let dir = match vfs.open_absolute(&parent)? {
                NodeRef::Directory(dir) => Ok(dir),
                NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
            }?;
            Ok((node, dir))
        })?;

        dir.link(&name, node)
    }

    pub fn cwd(&self, pid: ProcessId) -> Result<VfsPath, VfsError> {
        let process = self.process_handle(pid).map_err(|_| VfsError::NotFound)?;
        Ok(process.cwd())
    }
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

pub static PROCESS_TABLE: ProcessTable = ProcessTable::new();

struct ProcessTableInner {
    processes: Vec<ProcessHandle>,
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

    fn process(&self, pid: ProcessId) -> Option<&ProcessHandle> {
        self.processes.iter().find(|proc| proc.id() == pid)
    }
}

pub struct ProcessControl {
    id: ProcessId,
    _name: &'static str,
    address_space: <Arch as ArchThread>::AddressSpace,
    state: AtomicU8,
    #[allow(dead_code)]
    kind: ProcessKind,
    threads: SpinLock<Vec<ThreadId>>,
    fs: ProcessFs,
    abi: Abi,
}

impl ProcessControl {
    fn kernel(id: ProcessId, name: &'static str, abi: Abi) -> Self {
        Self {
            id,
            _name: name,
            address_space: <Arch as ArchThread>::current_address_space(),
            state: AtomicU8::new(ProcessState::Created as u8),
            kind: ProcessKind::Kernel,
            threads: SpinLock::new(Vec::new()),
            fs: ProcessFs::new(),
            abi,
        }
    }

    fn user(id: ProcessId, name: &'static str, abi: Abi) -> Self {
        Self {
            id,
            _name: name,
            address_space: <Arch as ArchThread>::current_address_space(),
            state: AtomicU8::new(ProcessState::Created as u8),
            kind: ProcessKind::User,
            threads: SpinLock::new(Vec::new()),
            fs: ProcessFs::new(),
            abi,
        }
    }

    pub fn id(&self) -> ProcessId {
        self.id
    }

    pub fn abi(&self) -> Abi {
        self.abi
    }

    pub fn address_space(&self) -> <Arch as ArchThread>::AddressSpace {
        self.address_space.clone()
    }

    pub fn state(&self) -> ProcessState {
        ProcessState::from_raw(self.state.load(Ordering::Acquire))
    }

    pub fn mark_ready(&self) {
        self.set_state_if_alive(ProcessState::Ready);
    }

    pub fn mark_running(&self) {
        self.set_state_if_alive(ProcessState::Running);
    }

    #[allow(dead_code)]
    pub fn mark_waiting(&self) {
        self.set_state_if_alive(ProcessState::Waiting);
    }

    pub fn mark_terminated(&self) {
        self.state
            .store(ProcessState::Terminated as u8, Ordering::Release);
    }

    pub fn thread_count(&self) -> usize {
        let guard = self.threads.lock();
        guard.len()
    }

    pub fn attach_thread(&self, tid: ThreadId) -> Result<(), ProcessError> {
        let mut guard = self.threads.lock();
        if guard.contains(&tid) {
            return Err(ProcessError::DuplicateThread);
        }
        guard.push(tid);
        drop(guard);
        if matches!(self.state(), ProcessState::Created) {
            self.mark_ready();
        }
        Ok(())
    }

    pub fn detach_thread(&self, tid: ThreadId) -> Result<bool, ProcessError> {
        let mut guard = self.threads.lock();
        if let Some(index) = guard.iter().position(|&id| id == tid) {
            guard.swap_remove(index);
        } else {
            return Err(ProcessError::ThreadNotAttached);
        }
        let empty = guard.is_empty();
        drop(guard);
        if empty {
            self.mark_terminated();
        }
        Ok(empty)
    }

    pub fn cwd(&self) -> VfsPath {
        self.fs.cwd()
    }

    pub fn set_cwd(&self, path: VfsPath) {
        self.fs.set_cwd(path);
    }

    pub fn fd_table(&self) -> &FdTable {
        &self.fs.fd_table
    }

    fn set_state_if_alive(&self, state: ProcessState) {
        if matches!(self.state(), ProcessState::Terminated) {
            return;
        }
        self.state.store(state as u8, Ordering::Release);
    }
}

fn absolute_path(raw: &str, cwd: &VfsPath) -> Result<VfsPath, VfsError> {
    if raw.starts_with('/') {
        return VfsPath::parse(raw);
    }

    let mut components = cwd.components().to_vec();
    for part in raw.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            components.pop();
            continue;
        }
        if part.len() > 255 {
            return Err(VfsError::NameTooLong);
        }
        components.push(PathComponent::new(part));
    }

    Ok(VfsPath::from_components(true, components))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Created = 0,
    Ready = 1,
    Running = 2,
    Waiting = 3,
    Terminated = 4,
}

impl ProcessState {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Ready,
            2 => Self::Running,
            3 => Self::Waiting,
            4 => Self::Terminated,
            _ => Self::Created,
        }
    }
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
    use crate::{println, syscall::Abi, test::kernel_test_case};

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

    #[kernel_test_case]
    fn process_default_abi_is_host() {
        println!("[test] process_default_abi_is_host");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process("abi-proc")
            .expect("create user process");
        let abi = PROCESS_TABLE.abi(pid).expect("abi present");
        assert_eq!(abi, Abi::Host);
    }

    #[kernel_test_case]
    fn process_abi_is_set_at_creation() {
        println!("[test] process_abi_is_set_at_creation");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process_with_abi("abi-linux", Abi::Linux)
            .expect("create linux process");
        let abi = PROCESS_TABLE.abi(pid).expect("abi present");
        assert_eq!(abi, Abi::Linux);
    }
}
