use alloc::{collections::VecDeque, vec::Vec};
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{
    Arch,
    api::{ArchInterrupt, ArchProcess},
};
use crate::interrupt::{InterruptServiceRoutine, SYSTEM_TIMER, TimerError};
use crate::mem::addr::VirtAddr;
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::spinlock::SpinLock;

pub type ProcessId = u64;
pub type KernelEntry = fn() -> !;

const KERNEL_STACK_SIZE: usize = 32 * 1024;
const KERNEL_STACK_ALIGN: usize = 16;

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

        let bootstrap = Process::bootstrap(0, "bootstrap");
        inner.current = Some(bootstrap.id);
        inner.processes.push(bootstrap);

        let idle_id = inner.next_pid;
        let idle = Process::idle(idle_id).map_err(SchedulerError::Spawn)?;
        inner.next_pid += 1;
        inner.idle = Some(idle.id);
        inner.processes.push(idle);
        inner.initialised = true;
        Ok(())
    }

    pub fn spawn_kernel_thread(
        &self,
        name: &'static str,
        entry: KernelEntry,
    ) -> Result<ProcessId, SpawnError> {
        let mut inner = self.inner.lock();
        if !inner.initialised {
            return Err(SpawnError::SchedulerNotReady);
        }

        let id = inner.next_pid;
        let process = Process::kernel(id, name, entry)?;
        inner.next_pid += 1;
        inner.ready.push_back(id);
        inner.processes.push(process);
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

            let idle_id = inner.idle.expect("idle process must exist");

            if let Some(proc) = inner.process_mut(current_id) {
                let saved = <Arch as ArchProcess>::save_context(frame);
                proc.context = saved;

                if current_id != idle_id {
                    proc.state = ProcessState::Ready;
                    inner.ready.push_back(current_id);
                } else {
                    proc.state = ProcessState::Idle;
                }
            }

            let next_id = inner.ready.pop_front().unwrap_or(idle_id);
            inner.current = Some(next_id);

            let (ctx, space) = inner
                .process_mut(next_id)
                .map(|proc| {
                    proc.state = if next_id == idle_id {
                        ProcessState::Idle
                    } else {
                        ProcessState::Running
                    };
                    (proc.context.clone(), proc.address_space)
                })
                .expect("next process must exist");

            (ctx, space)
        };

        unsafe {
            <Arch as ArchProcess>::activate_address_space(&next_space);
            <Arch as ArchProcess>::restore_context(frame, &next_ctx);
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
    processes: Vec<Process>,
    ready: VecDeque<ProcessId>,
    current: Option<ProcessId>,
    idle: Option<ProcessId>,
    next_pid: ProcessId,
    initialised: bool,
}

impl SchedulerInner {
    const fn new() -> Self {
        Self {
            processes: Vec::new(),
            ready: VecDeque::new(),
            current: None,
            idle: None,
            next_pid: 1,
            initialised: false,
        }
    }

    fn process_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.processes.iter_mut().find(|proc| proc.id == id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessState {
    Ready,
    Running,
    Idle,
}

struct Process {
    id: ProcessId,
    _name: &'static str,
    context: <Arch as ArchProcess>::Context,
    address_space: <Arch as ArchProcess>::AddressSpace,
    _stack: Option<KernelStack>,
    state: ProcessState,
}

impl Process {
    fn kernel(id: ProcessId, name: &'static str, entry: KernelEntry) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(entry as usize);
        let context = <Arch as ArchProcess>::bootstrap_kernel_context(entry_addr, stack_top);
        let address_space = <Arch as ArchProcess>::current_address_space();

        Ok(Self {
            id,
            _name: name,
            context,
            address_space,
            _stack: Some(stack),
            state: ProcessState::Ready,
        })
    }

    fn idle(id: ProcessId) -> Result<Self, SpawnError> {
        let stack = KernelStack::allocate(KERNEL_STACK_SIZE)?;
        let stack_top = stack.top();
        let entry_addr = VirtAddr::new(idle_thread as usize);
        let context = <Arch as ArchProcess>::bootstrap_kernel_context(entry_addr, stack_top);
        let address_space = <Arch as ArchProcess>::current_address_space();

        Ok(Self {
            id,
            _name: "idle",
            context,
            address_space,
            _stack: Some(stack),
            state: ProcessState::Idle,
        })
    }

    fn bootstrap(id: ProcessId, name: &'static str) -> Self {
        Self {
            id,
            _name: name,
            context: <Arch as ArchProcess>::Context::default(),
            address_space: <Arch as ArchProcess>::current_address_space(),
            _stack: None,
            state: ProcessState::Running,
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
