use alloc::{collections::VecDeque, vec::Vec};
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{
    Arch,
    api::{ArchInterrupt, ArchThread, UserStackError},
};
use crate::interrupt::{InterruptServiceRoutine, SYSTEM_TIMER, TimerError};
use crate::mem::addr::VirtAddr;
use crate::process::{PROCESS_TABLE, ProcessError, ProcessHandle, ProcessId};
use crate::syscall;
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::spinlock::SpinLock;

pub type ThreadId = u64;
pub type KernelThreadEntry = fn() -> !;

const KERNEL_STACK_SIZE: usize = 32 * 1024;
const KERNEL_STACK_ALIGN: usize = 16;
const USER_STACK_SIZE: usize = 32 * 1024;

/// Lightweight kernel-managed execution unit representing a single thread of execution.
pub static SCHEDULER: Scheduler = Scheduler::new();
static SCHEDULER_DISPATCH: SchedulerDispatch = SchedulerDispatch;

struct SchedulerDispatch;

pub struct Scheduler {
    inner: SpinLock<SchedulerInner>,
    started: AtomicBool,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(SchedulerInner::new()),
            started: AtomicBool::new(false),
        }
    }

    pub fn init(&self) -> Result<(), SchedulerError> {
        let mut inner = self.inner.lock();
        if inner.initialised {
            return Ok(());
        }

        let kernel_pid = PROCESS_TABLE
            .init_kernel()
            .map_err(SchedulerError::Process)?;
        inner.kernel_process = Some(kernel_pid);

        let kernel_process = PROCESS_TABLE
            .process_handle(kernel_pid)
            .map_err(SchedulerError::Process)?;
        let kernel_space = kernel_process.address_space();

        let bootstrap =
            ThreadControl::bootstrap(0, kernel_process.clone(), "bootstrap", kernel_space.clone());
        PROCESS_TABLE
            .attach_thread(kernel_pid, bootstrap.id)
            .map_err(SchedulerError::Process)?;
        inner.current = Some(bootstrap.id);
        inner.threads.push(bootstrap);
        kernel_process.mark_running();

        let idle_id = inner.next_tid;
        let idle = ThreadControl::idle(idle_id, kernel_process.clone(), kernel_space.clone())
            .map_err(SchedulerError::Spawn)?;
        PROCESS_TABLE
            .attach_thread(kernel_pid, idle_id)
            .map_err(SchedulerError::Process)?;
        inner.next_tid = idle_id.checked_add(1).expect("thread id overflow");
        inner.idle = Some(idle.id);
        inner.threads.push(idle);
        inner.initialised = true;
        syscall::set_current_abi(kernel_process.abi());
        Ok(())
    }

    /// Return the process ID of the currently running thread, if any.
    pub fn current_process_id(&self) -> Option<ProcessId> {
        let inner = self.inner.lock();
        let current = inner.current?;
        inner.thread(current).map(|thread| thread.process_id())
    }

    pub fn spawn_kernel_thread(
        &self,
        name: &'static str,
        entry: KernelThreadEntry,
    ) -> Result<ThreadId, SpawnError> {
        let process = {
            let inner = self.inner.lock();
            if !inner.initialised {
                return Err(SpawnError::SchedulerNotReady);
            }
            inner
                .kernel_process
                .ok_or(SpawnError::Process(ProcessError::NotInitialised))?
        };

        self.spawn_kernel_thread_for_process(process, name, entry)
    }

    pub fn spawn_kernel_thread_for_process(
        &self,
        process: ProcessId,
        name: &'static str,
        entry: KernelThreadEntry,
    ) -> Result<ThreadId, SpawnError> {
        let mut inner = self.inner.lock();
        if !inner.initialised {
            return Err(SpawnError::SchedulerNotReady);
        }

        self.spawn_thread_locked(&mut inner, process, name, entry)
    }

    pub fn spawn_user_thread(
        &self,
        process: ProcessId,
        name: &'static str,
        entry: VirtAddr,
        stack_size: usize,
    ) -> Result<ThreadId, SpawnError> {
        let mut inner = self.inner.lock();
        if !inner.initialised {
            return Err(SpawnError::SchedulerNotReady);
        }

        inner.spawn_user_thread(process, name, entry, stack_size)
    }

    pub fn spawn_user_thread_with_stack(
        &self,
        process: ProcessId,
        name: &'static str,
        entry: VirtAddr,
        user_stack: <Arch as ArchThread>::UserStack,
        stack_pointer: VirtAddr,
    ) -> Result<ThreadId, SpawnError> {
        let mut inner = self.inner.lock();
        if !inner.initialised {
            return Err(SpawnError::SchedulerNotReady);
        }

        inner.spawn_user_thread_with_stack(process, name, entry, user_stack, stack_pointer)
    }

    fn spawn_thread_locked(
        &self,
        inner: &mut SchedulerInner,
        process: ProcessId,
        name: &'static str,
        entry: KernelThreadEntry,
    ) -> Result<ThreadId, SpawnError> {
        let id = inner.next_tid;
        let process_handle = PROCESS_TABLE
            .process_handle(process)
            .map_err(SpawnError::Process)?;
        let address_space = process_handle.address_space();
        let thread = ThreadControl::kernel(id, process_handle, name, entry, address_space)?;
        PROCESS_TABLE
            .attach_thread(process, id)
            .map_err(SpawnError::Process)?;
        inner.next_tid = id.checked_add(1).expect("thread id overflow");
        inner.ready.push_back(id);
        inner.threads.push(thread);
        Ok(id)
    }

    pub fn start(&self) -> Result<(), SchedulerError> {
        {
            let inner = self.inner.lock();
            if !inner.initialised {
                return Err(SchedulerError::NotInitialised);
            }
        }

        if self
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(SchedulerError::AlreadyStarted);
        }

        SYSTEM_TIMER
            .install_handler(&SCHEDULER_DISPATCH)
            .map_err(SchedulerError::Timer)?;

        <Arch as ArchInterrupt>::enable_interrupts();

        Ok(())
    }

    pub fn shutdown(&self) {
        if !self.started.swap(false, Ordering::AcqRel) {
            return;
        }

        SYSTEM_TIMER.clear_handler();
        let _ = SYSTEM_TIMER.stop();
        <Arch as ArchInterrupt>::disable_interrupts();
    }

    pub fn on_timer_tick(&self, frame: &mut CurrentTrapFrame) {
        if !self.started.load(Ordering::Acquire) {
            return;
        }

        self.switch_current(frame, SwitchMode::Requeue);
    }

    /// Terminate the currently running thread and immediately switch to the next runnable one.
    pub fn terminate_current(&self, frame: &mut CurrentTrapFrame) {
        if !self.started.load(Ordering::Acquire) {
            return;
        }

        self.switch_current(frame, SwitchMode::Terminate);
    }

    fn switch_current(&self, frame: &mut CurrentTrapFrame, mode: SwitchMode) {
        let (next_ctx, next_space, next_stack, next_is_user, next_abi, next_process, detach_target) = {
            let mut inner = self.inner.lock();
            let current_id = match inner.current {
                Some(id) => id,
                None => return,
            };
            let idle_id = inner.idle.expect("idle thread must exist");
            let mut detach_target = None;

            if let Some(thread) = inner.thread_mut(current_id) {
                let saved = <Arch as ArchThread>::save_context(frame);
                thread.context = saved;
                let process = thread.process().clone();

                match mode {
                    SwitchMode::Requeue => {
                        if current_id != idle_id {
                            thread.state = ThreadState::Ready;
                            inner.ready.push_back(current_id);
                            process.mark_ready();
                        } else {
                            thread.state = ThreadState::Idle;
                        }
                    }
                    SwitchMode::Terminate => {
                        detach_target = Some((process, current_id));
                        thread.state = ThreadState::Terminated;
                    }
                }
            }

            let next_id = inner.next_runnable(idle_id);
            inner.current = Some(next_id);

            let (ctx, space, stack_top, is_user, abi, process) = inner
                .thread_mut(next_id)
                .map(|thread| {
                    thread.state = if next_id == idle_id {
                        ThreadState::Idle
                    } else {
                        ThreadState::Running
                    };
                    (
                        thread.context.clone(),
                        thread.address_space.clone(),
                        thread.kernel_stack_top(),
                        thread.is_user(),
                        thread.process().abi(),
                        thread.process().clone(),
                    )
                })
                .expect("next thread must exist");

            (ctx, space, stack_top, is_user, abi, process, detach_target)
        };

        if let Some((process, tid)) = detach_target {
            let _ = process.detach_thread(tid);
        }

        syscall::set_current_abi(next_abi);

        next_process.mark_running();

        if next_is_user && let Some(stack_top) = next_stack {
            <Arch as ArchThread>::update_privilege_stack(stack_top);
        }

        unsafe {
            <Arch as ArchThread>::activate_address_space(&next_space);
            <Arch as ArchThread>::restore_context(frame, &next_ctx);
        }
    }
}

impl InterruptServiceRoutine for SchedulerDispatch {
    fn handle(&self, _info: TrapInfo, frame: &mut CurrentTrapFrame) {
        SCHEDULER.on_timer_tick(frame);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SwitchMode {
    Requeue,
    Terminate,
}

#[derive(Debug)]
pub enum SchedulerError {
    NotInitialised,
    AlreadyStarted,
    Timer(TimerError),
    Spawn(SpawnError),
    Process(ProcessError),
}

#[derive(Debug)]
pub enum SpawnError {
    OutOfMemory,
    SchedulerNotReady,
    Process(ProcessError),
    UserStack(UserStackError),
}

struct SchedulerInner {
    threads: Vec<ThreadControl>,
    ready: VecDeque<ThreadId>,
    current: Option<ThreadId>,
    idle: Option<ThreadId>,
    next_tid: ThreadId,
    initialised: bool,
    kernel_process: Option<ProcessId>,
}

impl SchedulerInner {
    const fn new() -> Self {
        Self {
            threads: Vec::new(),
            ready: VecDeque::new(),
            current: None,
            idle: None,
            next_tid: 1,
            initialised: false,
            kernel_process: None,
        }
    }

    fn thread(&self, id: ThreadId) -> Option<&ThreadControl> {
        self.threads.iter().find(|thread| thread.id == id)
    }

    fn thread_mut(&mut self, id: ThreadId) -> Option<&mut ThreadControl> {
        self.threads.iter_mut().find(|thread| thread.id == id)
    }

    fn next_runnable(&mut self, idle_id: ThreadId) -> ThreadId {
        loop {
            let candidate = self.ready.pop_front().unwrap_or(idle_id);
            if candidate == idle_id {
                return idle_id;
            }
            match self.thread(candidate) {
                Some(thread) if thread.state != ThreadState::Terminated => return candidate,
                Some(_) => continue,
                None => continue,
            }
        }
    }

    fn spawn_user_thread(
        &mut self,
        process: ProcessId,
        name: &'static str,
        entry: VirtAddr,
        stack_size: usize,
    ) -> Result<ThreadId, SpawnError> {
        let id = self.next_tid;
        let process_handle = PROCESS_TABLE
            .process_handle(process)
            .map_err(SpawnError::Process)?;
        let address_space = process_handle.address_space();
        let thread =
            ThreadControl::user(id, process_handle, name, entry, address_space, stack_size)?;
        PROCESS_TABLE
            .attach_thread(process, id)
            .map_err(SpawnError::Process)?;
        self.next_tid = id.checked_add(1).expect("thread id overflow");
        self.ready.push_back(id);
        self.threads.push(thread);
        Ok(id)
    }

    fn spawn_user_thread_with_stack(
        &mut self,
        process: ProcessId,
        name: &'static str,
        entry: VirtAddr,
        user_stack: <Arch as ArchThread>::UserStack,
        stack_pointer: VirtAddr,
    ) -> Result<ThreadId, SpawnError> {
        let id = self.next_tid;
        let process_handle = PROCESS_TABLE
            .process_handle(process)
            .map_err(SpawnError::Process)?;
        let address_space = process_handle.address_space();
        let thread = ThreadControl::user_with_stack(
            id,
            process_handle,
            name,
            entry,
            address_space,
            user_stack,
            stack_pointer,
        )?;
        PROCESS_TABLE
            .attach_thread(process, id)
            .map_err(SpawnError::Process)?;
        self.next_tid = id.checked_add(1).expect("thread id overflow");
        self.ready.push_back(id);
        self.threads.push(thread);
        Ok(id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ThreadState {
    Ready,
    Running,
    Idle,
    Terminated,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ThreadKind {
    Kernel,
    User,
}

struct ThreadControl {
    id: ThreadId,
    _name: &'static str,
    process: ProcessHandle,
    context: <Arch as ArchThread>::Context,
    address_space: <Arch as ArchThread>::AddressSpace,
    kernel_stack: Option<KernelStack>,
    #[allow(dead_code)]
    user_stack: Option<<Arch as ArchThread>::UserStack>,
    kind: ThreadKind,
    state: ThreadState,
}

impl ThreadControl {
    fn kernel(
        id: ThreadId,
        process: ProcessHandle,
        name: &'static str,
        entry: KernelThreadEntry,
        address_space: <Arch as ArchThread>::AddressSpace,
    ) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(entry as usize);
        let context = <Arch as ArchThread>::bootstrap_kernel_context(entry_addr, stack_top);

        Ok(Self {
            id,
            _name: name,
            process,
            context,
            address_space,
            kernel_stack: Some(stack),
            user_stack: None,
            kind: ThreadKind::Kernel,
            state: ThreadState::Ready,
        })
    }

    fn user(
        id: ThreadId,
        process: ProcessHandle,
        name: &'static str,
        entry: VirtAddr,
        address_space: <Arch as ArchThread>::AddressSpace,
        stack_size: usize,
    ) -> Result<Self, SpawnError> {
        let stack_size = if stack_size == 0 {
            USER_STACK_SIZE
        } else {
            stack_size
        };
        let kernel_stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let user_stack = <Arch as ArchThread>::allocate_user_stack(&address_space, stack_size)
            .map_err(SpawnError::UserStack)?;
        let context = <Arch as ArchThread>::bootstrap_user_context(
            entry,
            <Arch as ArchThread>::user_stack_top(&user_stack),
        );

        Ok(Self {
            id,
            _name: name,
            process,
            context,
            address_space,
            kernel_stack: Some(kernel_stack),
            user_stack: Some(user_stack),
            kind: ThreadKind::User,
            state: ThreadState::Ready,
        })
    }

    fn user_with_stack(
        id: ThreadId,
        process: ProcessHandle,
        name: &'static str,
        entry: VirtAddr,
        address_space: <Arch as ArchThread>::AddressSpace,
        user_stack: <Arch as ArchThread>::UserStack,
        stack_pointer: VirtAddr,
    ) -> Result<Self, SpawnError> {
        let kernel_stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let context =
            <Arch as ArchThread>::bootstrap_user_context_with_stack_pointer(entry, stack_pointer);

        Ok(Self {
            id,
            _name: name,
            process,
            context,
            address_space,
            kernel_stack: Some(kernel_stack),
            user_stack: Some(user_stack),
            kind: ThreadKind::User,
            state: ThreadState::Ready,
        })
    }

    fn kernel_stack_top(&self) -> Option<VirtAddr> {
        self.kernel_stack.as_ref().map(|stack| stack.top())
    }

    fn is_user(&self) -> bool {
        matches!(self.kind, ThreadKind::User)
    }

    fn process_id(&self) -> ProcessId {
        self.process.id()
    }

    fn process(&self) -> &ProcessHandle {
        &self.process
    }

    fn idle(
        id: ThreadId,
        process: ProcessHandle,
        address_space: <Arch as ArchThread>::AddressSpace,
    ) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(idle_thread as usize);
        let context = <Arch as ArchThread>::bootstrap_kernel_context(entry_addr, stack_top);

        Ok(Self {
            id,
            _name: "idle",
            process,
            context,
            address_space,
            kernel_stack: Some(stack),
            user_stack: None,
            kind: ThreadKind::Kernel,
            state: ThreadState::Idle,
        })
    }

    fn bootstrap(
        id: ThreadId,
        process: ProcessHandle,
        name: &'static str,
        address_space: <Arch as ArchThread>::AddressSpace,
    ) -> Self {
        Self {
            id,
            _name: name,
            process,
            context: <Arch as ArchThread>::Context::default(),
            address_space,
            kernel_stack: None,
            user_stack: None,
            kind: ThreadKind::Kernel,
            state: ThreadState::Running,
        }
    }
}

struct KernelStack {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl KernelStack {
    fn allocate(size: usize) -> Result<Self, SpawnError> {
        let layout = Layout::from_size_align(size, KERNEL_STACK_ALIGN)
            .map_err(|_| SpawnError::OutOfMemory)?;
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        let ptr = NonNull::new(ptr).ok_or(SpawnError::OutOfMemory)?;
        Ok(Self { ptr, layout })
    }

    fn top(&self) -> VirtAddr {
        let base = self.ptr.as_ptr() as usize;
        let top = base + self.layout.size();
        VirtAddr::new(top)
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        unsafe { alloc::alloc::dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

unsafe impl Send for KernelStack {}

fn idle_thread() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::addr::VirtAddr;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn user_thread_context_uses_ring3_segments() {
        println!("[test] user_thread_context_uses_ring3_segments");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process("user-test")
            .expect("create user process");
        let space = PROCESS_TABLE
            .address_space(pid)
            .expect("user address space");

        let handle = PROCESS_TABLE
            .process_handle(pid)
            .expect("user process handle");
        let thread = ThreadControl::user(
            99,
            handle,
            "utest",
            VirtAddr::new(0x4000),
            space,
            USER_STACK_SIZE,
        )
        .expect("spawn user thread");

        assert!(thread.is_user());
        assert!(thread.user_stack.is_some());
        assert_eq!((thread.context.code_segment() & 0x3) as u8, 3);
        assert_eq!((thread.context.stack_segment() & 0x3) as u8, 3);
    }
}
