use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{Arch, api::ArchTask};
use crate::util::spinlock::SpinLock;

pub type ProcessId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    AlreadyInitialised,
    NotInitialised,
    NotFound,
    DuplicateTask,
    TaskNotAttached,
}

/// Global table that tracks processes and their associated tasks.
///
/// # Implementation note
///
/// At this point, each process does not have an individual address space and all share the kernel's address space.
/// When implementing userland in the future, it will be necessary to properly duplicate and isolate `ArchTask::AddressSpace` here.
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

    pub fn attach_task(&self, pid: ProcessId, tid: u64) -> Result<(), ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(ProcessError::NotFound)?;

        if process.tasks.contains(&tid) {
            return Err(ProcessError::DuplicateTask);
        }

        process.tasks.push(tid);
        Ok(())
    }

    pub fn detach_task(&self, pid: ProcessId, tid: u64) -> Result<(), ProcessError> {
        if !self.initialised.load(Ordering::Acquire) {
            return Err(ProcessError::NotInitialised);
        }

        let mut inner = self.inner.lock();
        let process = inner.process_mut(pid).ok_or(ProcessError::NotFound)?;

        if let Some(index) = process.tasks.iter().position(|&id| id == tid) {
            process.tasks.swap_remove(index);
            Ok(())
        } else {
            Err(ProcessError::TaskNotAttached)
        }
    }

    pub fn task_count(&self, pid: ProcessId) -> Option<usize> {
        let inner = self.inner.lock();
        inner.process(pid).map(|proc| proc.tasks.len())
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
    _address_space: <Arch as ArchTask>::AddressSpace,
    _state: ProcessState,
    tasks: Vec<u64>,
}

impl Process {
    fn kernel(id: ProcessId, name: &'static str) -> Self {
        Self {
            id,
            _name: name,
            _address_space: <Arch as ArchTask>::current_address_space(),
            _state: ProcessState::Active,
            tasks: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ProcessState {
    Active,
}
