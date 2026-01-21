use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use atomic_enum::atomic_enum;

use crate::arch::{Arch, api::ArchThread};
use crate::fs::{FdTable, VfsPath};
use crate::mem::addr::VirtAddr;
use crate::syscall::Abi;
use crate::thread::ThreadId;
use crate::util::spinlock::SpinLock;

pub mod fs;

pub type ProcessId = u64;
pub type ProcessHandle = Arc<Process>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    AlreadyInitialised,
    NotInitialised,
    NotFound,
    DuplicateThread,
    ThreadNotAttached,
    AddressSpace(crate::arch::api::UserAddressSpaceError),
}

pub struct ProcessFs {
    pub fd_table: FdTable,
    cwd: SpinLock<VfsPath>,
}

impl ProcessFs {
    pub fn new() -> Self {
        let fs = Self {
            fd_table: FdTable::new(),
            cwd: SpinLock::new(VfsPath::root()),
        };
        fs.install_stdio();
        fs
    }

    fn install_stdio(&self) {
        let tty = crate::fs::tty::global_tty();
        self.fd_table
            .open_fixed(0, tty.clone())
            .expect("install stdin");
        self.fd_table
            .open_fixed(1, tty.clone())
            .expect("install stdout");
        self.fd_table.open_fixed(2, tty).expect("install stderr");
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

        let process = Arc::new(Process::kernel(0, "kernel", Abi::Host));
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
        let process = Arc::new(Process::kernel(pid, name, Abi::Host));
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
        let space = <Arch as ArchThread>::create_user_address_space()
            .map_err(ProcessError::AddressSpace)?;
        self.create_user_process_with_abi_and_space(name, abi, space)
    }

    pub fn create_user_process_with_abi_and_space(
        &self,
        name: &'static str,
        abi: Abi,
        space: <Arch as ArchThread>::AddressSpace,
    ) -> Result<ProcessId, ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let pid = inner.next_pid;
        let process = Arc::new(Process::user(pid, name, abi, space));
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

    pub fn has_child(&self, parent: ProcessId) -> bool {
        self.processes_snapshot()
            .iter()
            .any(|proc| proc.parent() == Some(parent))
    }

    pub fn is_child(&self, parent: ProcessId, child: ProcessId) -> bool {
        self.process_handle(child)
            .ok()
            .and_then(|proc| proc.parent())
            .map(|pid| pid == parent)
            .unwrap_or(false)
    }

    pub fn find_terminated_child(&self, parent: ProcessId) -> Option<ProcessId> {
        for proc in self.processes_snapshot() {
            if proc.parent() != Some(parent) {
                continue;
            }
            if proc.is_reaped() {
                continue;
            }
            if matches!(proc.state(), ProcessState::Terminated) {
                return Some(proc.id());
            }
        }
        None
    }

    // File-system operations moved to `process::fs`.
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

impl ProcessTable {
    fn processes_snapshot(&self) -> Vec<ProcessHandle> {
        let inner = self.inner.lock();
        inner.processes.iter().cloned().collect()
    }
}

pub struct Process {
    id: ProcessId,
    name: &'static str,
    address_space: <Arch as ArchThread>::AddressSpace,
    state: AtomicProcessState,
    #[allow(dead_code)]
    kind: ProcessKind,
    threads: SpinLock<Vec<ThreadId>>,
    fs: ProcessFs,
    parent: SpinLock<Option<ProcessId>>,
    exit_code: SpinLock<Option<i32>>,
    reaped: SpinLock<bool>,
    brk: SpinLock<BrkState>,
    abi: Abi,
}

impl Process {
    fn kernel(id: ProcessId, name: &'static str, abi: Abi) -> Self {
        Self {
            id,
            name,
            address_space: <Arch as ArchThread>::current_address_space(),
            state: AtomicProcessState::new(ProcessState::Created),
            kind: ProcessKind::Kernel,
            threads: SpinLock::new(Vec::new()),
            fs: ProcessFs::new(),
            parent: SpinLock::new(None),
            exit_code: SpinLock::new(None),
            reaped: SpinLock::new(false),
            brk: SpinLock::new(BrkState::empty()),
            abi,
        }
    }

    fn user(
        id: ProcessId,
        name: &'static str,
        abi: Abi,
        address_space: <Arch as ArchThread>::AddressSpace,
    ) -> Self {
        Self {
            id,
            name,
            address_space,
            state: AtomicProcessState::new(ProcessState::Created),
            kind: ProcessKind::User,
            threads: SpinLock::new(Vec::new()),
            fs: ProcessFs::new(),
            parent: SpinLock::new(None),
            exit_code: SpinLock::new(None),
            reaped: SpinLock::new(false),
            brk: SpinLock::new(BrkState::empty()),
            abi,
        }
    }

    pub fn id(&self) -> ProcessId {
        self.id
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn abi(&self) -> Abi {
        self.abi
    }

    pub fn address_space(&self) -> <Arch as ArchThread>::AddressSpace {
        self.address_space.clone()
    }

    pub fn state(&self) -> ProcessState {
        self.state.load(Ordering::Acquire)
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
            .store(ProcessState::Terminated, Ordering::Release);
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

    pub fn parent(&self) -> Option<ProcessId> {
        *self.parent.lock()
    }

    pub fn set_parent(&self, parent: ProcessId) {
        let mut guard = self.parent.lock();
        *guard = Some(parent);
    }

    pub fn exit_code(&self) -> Option<i32> {
        *self.exit_code.lock()
    }

    pub fn set_exit_code(&self, code: i32) {
        let mut guard = self.exit_code.lock();
        *guard = Some(code);
    }

    pub fn is_reaped(&self) -> bool {
        *self.reaped.lock()
    }

    pub fn mark_reaped(&self) {
        let mut guard = self.reaped.lock();
        *guard = true;
    }

    pub fn brk_state(&self) -> BrkState {
        *self.brk.lock()
    }

    pub fn set_brk_state(&self, state: BrkState) {
        let mut guard = self.brk.lock();
        *guard = state;
    }

    pub fn set_brk_base(&self, base: VirtAddr) {
        let mut guard = self.brk.lock();
        guard.base = base;
        guard.current = base;
    }

    fn set_state_if_alive(&self, state: ProcessState) {
        if matches!(self.state(), ProcessState::Terminated) {
            return;
        }
        self.state.store(state, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
pub struct BrkState {
    pub base: VirtAddr,
    pub current: VirtAddr,
}

impl BrkState {
    const fn empty() -> Self {
        Self {
            base: VirtAddr::new(0),
            current: VirtAddr::new(0),
        }
    }
}

#[atomic_enum]
pub enum ProcessState {
    Created = 0,
    Ready = 1,
    Running = 2,
    Waiting = 3,
    Terminated = 4,
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
