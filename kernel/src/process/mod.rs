use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{Arch, api::ArchThread};
use crate::syscall::{AbiFlavor, SyscallPolicy};
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
        self.create_user_process_with(name, AbiFlavor::Host, SyscallPolicy::default())
    }

    pub fn create_user_process_with(
        &self,
        name: &'static str,
        abi: AbiFlavor,
        policy: SyscallPolicy,
    ) -> Result<ProcessId, ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let pid = inner.next_pid;
        let process = Process::user(pid, name, abi, policy);
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

    pub fn abi(&self, pid: ProcessId) -> Option<AbiFlavor> {
        let inner = self.inner.lock();
        inner.process(pid).map(|proc| proc.abi)
    }

    pub fn policy(&self, pid: ProcessId) -> Option<SyscallPolicy> {
        let inner = self.inner.lock();
        inner.process(pid).map(|proc| proc.policy)
    }

    pub fn set_policy(&self, pid: ProcessId, policy: SyscallPolicy) -> Result<(), ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(ProcessError::NotFound)?;
        process.policy = policy;
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
    abi: AbiFlavor,
    policy: SyscallPolicy,
    threads: Vec<ThreadId>,
}

impl Process {
    fn kernel(id: ProcessId, name: &'static str) -> Self {
        Self {
            id,
            _name: name,
            address_space: <Arch as ArchThread>::current_address_space(),
            _state: ProcessState::Active,
            kind: ProcessKind::Kernel,
            abi: AbiFlavor::Host,
            policy: SyscallPolicy::Full,
            threads: Vec::new(),
        }
    }

    fn user(id: ProcessId, name: &'static str, abi: AbiFlavor, policy: SyscallPolicy) -> Self {
        Self {
            id,
            _name: name,
            address_space: <Arch as ArchThread>::current_address_space(),
            _state: ProcessState::Active,
            kind: ProcessKind::User,
            abi,
            policy,
            threads: Vec::new(),
        }
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
    use crate::syscall::{AbiFlavor, SyscallPolicy};
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn kernel_process_shares_address_space() {
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
        assert_eq!(PROCESS_TABLE.abi(pid), Some(AbiFlavor::Host));
        assert_eq!(PROCESS_TABLE.policy(pid), Some(SyscallPolicy::Minimal));
    }

    #[kernel_test_case]
    fn create_linux_process_with_policy() {
        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process_with("ctr-demo", AbiFlavor::Linux, SyscallPolicy::Full)
            .expect("create linux demo process");
        assert!(pid > 0);
        assert_eq!(PROCESS_TABLE.abi(pid), Some(AbiFlavor::Linux));
        assert_eq!(PROCESS_TABLE.policy(pid), Some(SyscallPolicy::Full));
    }
}
