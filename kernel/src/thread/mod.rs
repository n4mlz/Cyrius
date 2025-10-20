use alloc::{collections::VecDeque, vec::Vec};
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{
    Arch,
    api::{ArchInterrupt, ArchThread},
};
use crate::interrupt::{InterruptServiceRoutine, SYSTEM_TIMER, TimerError};
use crate::mem::addr::VirtAddr;
use crate::process::{PROCESS_TABLE, ProcessError, ProcessId};
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::spinlock::SpinLock;

pub type ThreadId = u64;
pub type KernelThreadEntry = fn() -> !;

const KERNEL_STACK_SIZE: usize = 32 * 1024;
const KERNEL_STACK_ALIGN: usize = 16;

/// Lightweight kernel-managed execution unit representing a single thread of execution.

pub static SCHEDULER: Scheduler = Scheduler::new();
static SCHEDULER_DISPATCH: SchedulerDispatch = SchedulerDispatch;

struct SchedulerDispatch;

pub struct Scheduler {
    inner: SpinLock<SchedulerInner>,
    started: AtomicBool,
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

        let bootstrap = ThreadControl::bootstrap(0, kernel_pid, "bootstrap");
        PROCESS_TABLE
            .attach_thread(kernel_pid, bootstrap.id)
            .map_err(SchedulerError::Process)?;
        inner.current = Some(bootstrap.id);
        inner.threads.push(bootstrap);

        let idle_id = inner.next_tid;
        let idle = ThreadControl::idle(idle_id, kernel_pid).map_err(SchedulerError::Spawn)?;
        PROCESS_TABLE
            .attach_thread(kernel_pid, idle_id)
            .map_err(SchedulerError::Process)?;
        inner.next_tid = idle_id.checked_add(1).expect("thread id overflow");
        inner.idle = Some(idle.id);
        inner.threads.push(idle);
        inner.initialised = true;
        Ok(())
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

    fn spawn_thread_locked(
        &self,
        inner: &mut SchedulerInner,
        process: ProcessId,
        name: &'static str,
        entry: KernelThreadEntry,
    ) -> Result<ThreadId, SpawnError> {
        let id = inner.next_tid;
        let thread = ThreadControl::kernel(id, process, name, entry)?;
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

        let (next_ctx, next_space) = {
            let mut inner = self.inner.lock();
            let current_id = match inner.current {
                Some(id) => id,
                None => return,
            };

            let idle_id = inner.idle.expect("idle thread must exist");

            if let Some(thread) = inner.thread_mut(current_id) {
                let saved = <Arch as ArchThread>::save_context(frame);
                thread.context = saved;

                if current_id != idle_id {
                    thread.state = ThreadState::Ready;
                    inner.ready.push_back(current_id);
                } else {
                    thread.state = ThreadState::Idle;
                }
            }

            let next_id = inner.ready.pop_front().unwrap_or(idle_id);
            inner.current = Some(next_id);

            let (ctx, space) = inner
                .thread_mut(next_id)
                .map(|thread| {
                    thread.state = if next_id == idle_id {
                        ThreadState::Idle
                    } else {
                        ThreadState::Running
                    };
                    (thread.context.clone(), thread.address_space)
                })
                .expect("next thread must exist");

            (ctx, space)
        };

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

    fn thread_mut(&mut self, id: ThreadId) -> Option<&mut ThreadControl> {
        self.threads.iter_mut().find(|thread| thread.id == id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ThreadState {
    Ready,
    Running,
    Idle,
}

struct ThreadControl {
    id: ThreadId,
    _name: &'static str,
    _process: ProcessId,
    context: <Arch as ArchThread>::Context,
    address_space: <Arch as ArchThread>::AddressSpace,
    _stack: Option<KernelStack>,
    state: ThreadState,
}

impl ThreadControl {
    fn kernel(
        id: ThreadId,
        process: ProcessId,
        name: &'static str,
        entry: KernelThreadEntry,
    ) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(entry as usize);
        let context = <Arch as ArchThread>::bootstrap_kernel_context(entry_addr, stack_top);
        let address_space = <Arch as ArchThread>::current_address_space();

        Ok(Self {
            id,
            _name: name,
            _process: process,
            context,
            address_space,
            _stack: Some(stack),
            state: ThreadState::Ready,
        })
    }

    fn idle(id: ThreadId, process: ProcessId) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(idle_thread as usize);
        let context = <Arch as ArchThread>::bootstrap_kernel_context(entry_addr, stack_top);
        let address_space = <Arch as ArchThread>::current_address_space();

        Ok(Self {
            id,
            _name: "idle",
            _process: process,
            context,
            address_space,
            _stack: Some(stack),
            state: ThreadState::Idle,
        })
    }

    fn bootstrap(id: ThreadId, process: ProcessId, name: &'static str) -> Self {
        Self {
            id,
            _name: name,
            _process: process,
            context: <Arch as ArchThread>::Context::default(),
            address_space: <Arch as ArchThread>::current_address_space(),
            _stack: None,
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
