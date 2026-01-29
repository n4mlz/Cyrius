use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use atomic_enum::atomic_enum;

use crate::arch::{Arch, api::ArchThread};
use crate::container::Container;
use crate::fs::{FdTable, Path};
use crate::mem::addr::VirtAddr;
use crate::syscall::Abi;
use crate::thread::ThreadId;
use crate::util::spinlock::SpinLock;

pub mod fs;

pub type ProcessId = u64;
pub type ProcessHandle = Arc<Process>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    NotInitialised,
    NotFound,
    Terminated,
    DuplicateThread,
    ThreadNotAttached,
    AddressSpace(crate::arch::api::UserAddressSpaceError),
}

pub struct ProcessFs {
    pub fd_table: FdTable,
    cwd: SpinLock<Path>,
}

impl ProcessFs {
    pub fn new() -> Self {
        let fs = Self {
            fd_table: FdTable::new(),
            cwd: SpinLock::new(Path::root()),
        };
        fs.install_stdio();
        fs
    }

    fn install_stdio(&self) {
        // NOTE: stdin/stdout/stderr share the same open file description (dup-like).
        let tty = crate::fs::devfs::global_tty_node();
        let tty_file = tty
            .clone()
            .open(crate::fs::OpenOptions::new(0))
            .expect("open tty");
        self.fd_table
            .open_fixed(0, tty_file.clone())
            .expect("install stdin");
        self.fd_table
            .open_fixed(1, tty_file.clone())
            .expect("install stdout");
        self.fd_table
            .open_fixed(2, tty_file)
            .expect("install stderr");
    }

    pub fn set_cwd(&self, path: Path) {
        let mut guard = self.cwd.lock();
        *guard = path;
    }

    pub fn cwd(&self) -> Path {
        let guard = self.cwd.lock();
        guard.clone()
    }

    pub fn clone_from(&self, other: &ProcessFs) {
        self.fd_table.clone_from(&other.fd_table);
        self.set_cwd(other.cwd());
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
/// Kernel processes share the current address space; user processes receive their own
/// address spaces from `ArchThread::create_user_address_space`.
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
        // NOTE: Idempotent initialization; returns PID 0 after the first call.
        let mut inner = self.inner.lock();
        if inner.kernel_pid.is_some() {
            self.initialised.store(true, Ordering::Release);
            crate::println!("[process] init_kernel already initialised");
            return Ok(inner.kernel_pid.expect("kernel process must exist"));
        }

        let process = Arc::new(Process::kernel(0, "kernel", Abi::Host));
        inner.kernel_pid = Some(process.id());
        inner.next_pid = 1;
        inner.processes.push(process);
        self.initialised.store(true, Ordering::Release);
        crate::println!("[process] init_kernel created pid=0");

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
        crate::println!("[process] create_kernel_process pid={} name={}", pid, name);
        Ok(pid)
    }

    /// Create a user process bound to a specific domain.
    ///
    /// The domain decides the ABI and the VFS contract. Callers must choose `Host` vs `Container`
    /// explicitly so container processes cannot accidentally access the host VFS.
    pub fn create_user_process(
        &self,
        name: &'static str,
        domain: ProcessDomain,
    ) -> Result<ProcessId, ProcessError> {
        let space = <Arch as ArchThread>::create_user_address_space()
            .map_err(ProcessError::AddressSpace)?;
        self.create_user_process_with_domain_and_space(name, domain, space)
    }

    pub fn create_user_process_with_domain_and_space(
        &self,
        name: &'static str,
        domain: ProcessDomain,
        space: <Arch as ArchThread>::AddressSpace,
    ) -> Result<ProcessId, ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let pid = inner.next_pid;
        let process = Arc::new(Process::user(pid, name, space, domain));
        inner.next_pid = pid.checked_add(1).expect("process id overflow");
        inner.processes.push(process);
        crate::println!("[process] create_user_process pid={} name={}", pid, name);
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
    // TODO: Implement process reaping/removal; the vector grows monotonically.
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
        inner.processes.to_vec()
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
    domain: ProcessDomain,
    session_id: SpinLock<ProcessId>,
    pgrp_id: SpinLock<ProcessId>,
    controlling_tty: SpinLock<Option<ControllingTty>>,
}

/// Process domain determines the ABI and VFS visibility contract.
///
/// # Contract
/// - Container processes always use the container VFS.
/// - Host processes never access container VFS.
/// - Container processes currently require Linux ABI.
/// - The domain is immutable after process creation.
/// - HostLinux uses Linux ABI while still bound to the host VFS (used for linux-box tests).
///
/// # Temporary note
/// This domain split is temporary. Once container functionality matures, the domain will collapse
/// into ABI selection: host ABI implies non-container process, Linux ABI implies container process.
#[derive(Clone)]
pub enum ProcessDomain {
    Host,
    /// Linux ABI on the host VFS (test helper).
    HostLinux,
    Container(Arc<Container>),
}

impl ProcessDomain {
    pub fn vfs(&self) -> ProcessVfs {
        match self {
            Self::Host => ProcessVfs::Host,
            Self::HostLinux => ProcessVfs::Host,
            Self::Container(container) => ProcessVfs::Container(container.vfs()),
        }
    }

    pub fn abi(&self) -> Abi {
        match self {
            Self::Host => Abi::Host,
            Self::HostLinux => Abi::Linux,
            Self::Container(_) => Abi::Linux,
        }
    }
}

pub enum ProcessVfs {
    Host,
    Container(Arc<crate::fs::Vfs>),
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
            domain: ProcessDomain::Host,
            session_id: SpinLock::new(id),
            pgrp_id: SpinLock::new(id),
            controlling_tty: SpinLock::new(None),
        }
    }

    fn user(
        id: ProcessId,
        name: &'static str,
        address_space: <Arch as ArchThread>::AddressSpace,
        domain: ProcessDomain,
    ) -> Self {
        let abi = domain.abi();
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
            domain,
            session_id: SpinLock::new(id),
            pgrp_id: SpinLock::new(id),
            controlling_tty: SpinLock::new(None),
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

    pub fn domain(&self) -> &ProcessDomain {
        &self.domain
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
        if matches!(self.state(), ProcessState::Terminated) {
            return Err(ProcessError::Terminated);
        }
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

    pub fn cwd(&self) -> Path {
        self.fs.cwd()
    }

    pub fn set_cwd(&self, path: Path) {
        self.fs.set_cwd(path);
    }

    pub fn fd_table(&self) -> &FdTable {
        &self.fs.fd_table
    }

    pub fn clone_fs_from(&self, other: &Process) {
        self.fs.clone_from(&other.fs);
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

    pub fn session_id(&self) -> ProcessId {
        *self.session_id.lock()
    }

    pub fn set_session_id(&self, session: ProcessId) {
        let mut guard = self.session_id.lock();
        *guard = session;
    }

    pub fn pgrp_id(&self) -> ProcessId {
        *self.pgrp_id.lock()
    }

    pub fn set_pgrp_id(&self, pgrp: ProcessId) {
        let mut guard = self.pgrp_id.lock();
        *guard = pgrp;
    }

    pub fn controlling_tty(&self) -> Option<ControllingTty> {
        *self.controlling_tty.lock()
    }

    pub fn has_controlling_tty(&self) -> bool {
        self.controlling_tty.lock().is_some()
    }

    pub fn set_controlling_tty(&self, tty: ControllingTty) {
        let mut guard = self.controlling_tty.lock();
        *guard = Some(tty);
    }

    pub fn clear_controlling_tty(&self) {
        let mut guard = self.controlling_tty.lock();
        *guard = None;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControllingTty {
    Global,
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
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
            .create_user_process("user-proc", ProcessDomain::Host)
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
            .create_user_process("abi-proc", ProcessDomain::Host)
            .expect("create user process");
        let abi = PROCESS_TABLE.abi(pid).expect("abi present");
        assert_eq!(abi, Abi::Host);
    }

    #[kernel_test_case]
    fn process_abi_is_set_at_creation() {
        println!("[test] process_abi_is_set_at_creation");

        let _ = PROCESS_TABLE.init_kernel();
        let container = Arc::new(crate::container::Container::new(
            crate::container::ContainerState {
                oci_version: String::from("1.0.2"),
                id: String::from("test"),
                status: crate::container::ContainerStatus::Created,
                pid: None,
                bundle_path: String::from("/bundle"),
                annotations: Default::default(),
            },
            oci_spec::runtime::Spec::default(),
            crate::container::ContainerContext::new(Arc::new(crate::fs::Vfs::new(
                crate::fs::memfs::MemDirectory::new(),
            ))),
        ));
        let pid = PROCESS_TABLE
            .create_user_process(
                "abi-linux",
                crate::process::ProcessDomain::Container(container),
            )
            .expect("create linux process");
        let abi = PROCESS_TABLE.abi(pid).expect("abi present");
        assert_eq!(abi, Abi::Linux);
    }

    #[kernel_test_case]
    fn process_defaults_session_and_pgrp_to_pid() {
        println!("[test] process_defaults_session_and_pgrp_to_pid");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process("session-proc", ProcessDomain::Host)
            .expect("create user process");
        let proc = PROCESS_TABLE.process_handle(pid).expect("process handle");
        assert_eq!(proc.session_id(), pid);
        assert_eq!(proc.pgrp_id(), pid);
    }

    #[kernel_test_case]
    fn process_default_has_no_controlling_tty() {
        println!("[test] process_default_has_no_controlling_tty");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process("ctty-proc", ProcessDomain::Host)
            .expect("create user process");
        let proc = PROCESS_TABLE.process_handle(pid).expect("process handle");
        assert!(!proc.has_controlling_tty());
    }
}
