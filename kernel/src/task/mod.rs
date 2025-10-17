use alloc::{collections::VecDeque, vec::Vec};
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{
    Arch,
    api::{ArchInterrupt, ArchTask},
};
use crate::interrupt::{InterruptServiceRoutine, TimerError, SYSTEM_TIMER};
use crate::mem::addr::VirtAddr;
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::spinlock::SpinLock;

pub type TaskId = u64;
pub type KernelTaskEntry = fn() -> !;

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

        let bootstrap = TaskControl::bootstrap(0, "bootstrap");
        inner.current = Some(bootstrap.id);
        inner.tasks.push(bootstrap);

        let idle_id = inner.next_tid;
        let idle = TaskControl::idle(idle_id).map_err(SchedulerError::Spawn)?;
        inner.next_tid += 1;
        inner.idle = Some(idle.id);
        inner.tasks.push(idle);
        inner.initialised = true;
        Ok(())
    }

    pub fn spawn_kernel_thread(
        &self,
        name: &'static str,
        entry: KernelTaskEntry,
    ) -> Result<TaskId, SpawnError> {
        let mut inner = self.inner.lock();
        if !inner.initialised {
            return Err(SpawnError::SchedulerNotReady);
        }

        let id = inner.next_tid;
        let task = TaskControl::kernel(id, name, entry)?;
        inner.next_tid += 1;
        inner.ready.push_back(id);
        inner.tasks.push(task);
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

            let idle_id = inner.idle.expect("idle task must exist");

            if let Some(task) = inner.task_mut(current_id) {
                let saved = <Arch as ArchTask>::save_context(frame);
                task.context = saved;

                if current_id != idle_id {
                    task.state = TaskState::Ready;
                    inner.ready.push_back(current_id);
                } else {
                    task.state = TaskState::Idle;
                }
            }

            let next_id = inner.ready.pop_front().unwrap_or(idle_id);
            inner.current = Some(next_id);

            let (ctx, space) = inner
                .task_mut(next_id)
                .map(|task| {
                    task.state = if next_id == idle_id {
                        TaskState::Idle
                    } else {
                        TaskState::Running
                    };
                    (task.context.clone(), task.address_space)
                })
                .expect("next task must exist");

            (ctx, space)
        };

        unsafe {
            <Arch as ArchTask>::activate_address_space(&next_space);
            <Arch as ArchTask>::restore_context(frame, &next_ctx);
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
}

#[derive(Debug)]
pub enum SpawnError {
    OutOfMemory,
    SchedulerNotReady,
}

struct SchedulerInner {
    tasks: Vec<TaskControl>,
    ready: VecDeque<TaskId>,
    current: Option<TaskId>,
    idle: Option<TaskId>,
    next_tid: TaskId,
    initialised: bool,
}

impl SchedulerInner {
    const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            ready: VecDeque::new(),
            current: None,
            idle: None,
            next_tid: 1,
            initialised: false,
        }
    }

    fn task_mut(&mut self, id: TaskId) -> Option<&mut TaskControl> {
        self.tasks.iter_mut().find(|task| task.id == id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TaskState {
    Ready,
    Running,
    Idle,
}

struct TaskControl {
    id: TaskId,
    _name: &'static str,
    context: <Arch as ArchTask>::Context,
    address_space: <Arch as ArchTask>::AddressSpace,
    _stack: Option<KernelStack>,
    state: TaskState,
}

impl TaskControl {
    fn kernel(id: TaskId, name: &'static str, entry: KernelTaskEntry) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(entry as usize);
        let context = <Arch as ArchTask>::bootstrap_kernel_context(entry_addr, stack_top);
        let address_space = <Arch as ArchTask>::current_address_space();

        Ok(Self {
            id,
            _name: name,
            context,
            address_space,
            _stack: Some(stack),
            state: TaskState::Ready,
        })
    }

    fn idle(id: TaskId) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(idle_thread as usize);
        let context = <Arch as ArchTask>::bootstrap_kernel_context(entry_addr, stack_top);
        let address_space = <Arch as ArchTask>::current_address_space();

        Ok(Self {
            id,
            _name: "idle",
            context,
            address_space,
            _stack: Some(stack),
            state: TaskState::Idle,
        })
    }

    fn bootstrap(id: TaskId, name: &'static str) -> Self {
        Self {
            id,
            _name: name,
            context: <Arch as ArchTask>::Context::default(),
            address_space: <Arch as ArchTask>::current_address_space(),
            _stack: None,
            state: TaskState::Running,
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
