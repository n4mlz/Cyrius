//! Syscall ABI glue shared across host and Linux guests.

mod host;
mod linux;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::{Arch, api::ArchInterrupt};
use crate::interrupt::{INTERRUPTS, InterruptServiceRoutine};
use crate::println;
use crate::process::ProcessId;
use crate::thread::{SCHEDULER, ThreadId};
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::spinlock::SpinLock;

use host::HostSyscallTable;
use linux::{LinuxSyscall, LinuxSyscallTable};

/// Execution profile that determines which syscall table to consult for a thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiFlavor {
    Host,
    Linux,
}

impl AbiFlavor {
    pub const fn is_linux(self) -> bool {
        matches!(self, Self::Linux)
    }
}

/// Minimal Seccomp-like policy gates for demo purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallPolicy {
    Minimal,
    Full,
}

impl SyscallPolicy {
    pub const fn default() -> Self {
        Self::Minimal
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Full => "full",
        }
    }

    fn allows_linux(self, call: LinuxSyscall) -> bool {
        match self {
            Self::Minimal => matches!(call, LinuxSyscall::Write | LinuxSyscall::Exit),
            Self::Full => true,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ThreadActivation {
    pub thread_id: ThreadId,
    pub process_id: ProcessId,
    pub abi: AbiFlavor,
    pub policy: SyscallPolicy,
}

#[derive(Clone, Copy)]
struct ActiveThread {
    tid: ThreadId,
    pid: ProcessId,
    policy: SyscallPolicy,
    table: &'static dyn SyscallTable,
}

impl ActiveThread {
    fn runtime(self) -> ThreadRuntime {
        ThreadRuntime {
            tid: self.tid,
            pid: self.pid,
            policy: self.policy,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ThreadRuntime {
    pub tid: ThreadId,
    pub pid: ProcessId,
    pub policy: SyscallPolicy,
}

pub fn init() {
    DISPATCHER.init();
}

pub fn activate_thread(ctx: ThreadActivation) {
    DISPATCHER.activate(ctx);
}

pub struct SyscallContext<'a> {
    frame: &'a mut CurrentTrapFrame,
}

impl<'a> SyscallContext<'a> {
    pub fn new(frame: &'a mut CurrentTrapFrame) -> Self {
        Self { frame }
    }

    pub fn number(&self) -> u64 {
        self.frame.regs.rax
    }

    pub fn arg(&self, index: usize) -> u64 {
        match index {
            0 => self.frame.regs.rdi,
            1 => self.frame.regs.rsi,
            2 => self.frame.regs.rdx,
            3 => self.frame.regs.r10,
            4 => self.frame.regs.r8,
            5 => self.frame.regs.r9,
            _ => 0,
        }
    }

    pub fn set_ret(&mut self, value: u64) {
        self.frame.regs.rax = value;
    }
}

pub trait SyscallTable: Sync {
    fn dispatch(&self, ctx: &mut SyscallContext<'_>, thread: ThreadRuntime) -> SyscallResult;
}

pub type SyscallResult = Result<SyscallOutcome, SyscallError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOutcome {
    Continue,
    Terminate { code: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    Unsupported { number: u64 },
    PolicyDenied { syscall: &'static str },
    Fatal(&'static str),
}

struct SyscallDispatcher {
    initialised: AtomicBool,
    state: SpinLock<SyscallState>,
}

#[derive(Clone, Copy)]
struct SyscallState {
    active: Option<ActiveThread>,
}

impl SyscallState {
    const fn new() -> Self {
        Self { active: None }
    }
}

struct SyscallIsr;

static DISPATCHER: SyscallDispatcher = SyscallDispatcher::new();
static SYSCALL_ISR: SyscallIsr = SyscallIsr;
static HOST_TABLE: HostSyscallTable = HostSyscallTable;
static LINUX_TABLE: LinuxSyscallTable = LinuxSyscallTable;

impl SyscallDispatcher {
    const fn new() -> Self {
        Self {
            initialised: AtomicBool::new(false),
            state: SpinLock::new(SyscallState::new()),
        }
    }

    fn init(&self) {
        if self
            .initialised
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let vector = <Arch as ArchInterrupt>::syscall_vector();
        if let Err(err) = INTERRUPTS.register_handler(vector, &SYSCALL_ISR) {
            panic!("failed to register syscall handler: {err:?}");
        }
    }

    fn activate(&self, ctx: ThreadActivation) {
        let table: &'static dyn SyscallTable = match ctx.abi {
            AbiFlavor::Host => &HOST_TABLE,
            AbiFlavor::Linux => &LINUX_TABLE,
        };

        let mut state = self.state.lock();
        state.active = Some(ActiveThread {
            tid: ctx.thread_id,
            pid: ctx.process_id,
            policy: ctx.policy,
            table,
        });
    }

    fn dispatch(&self, frame: &mut CurrentTrapFrame) {
        let active = {
            let state = self.state.lock();
            state.active
        };

        let Some(active) = active else {
            println!("[syscall] no active thread bound; dropping trap");
            return;
        };

        let mut ctx = SyscallContext::new(frame);
        match active.table.dispatch(&mut ctx, active.runtime()) {
            Ok(SyscallOutcome::Continue) => {}
            Ok(SyscallOutcome::Terminate { code }) => {
                println!("[ctr {}] exit({})", active.pid, code);
                SCHEDULER.terminate_current(frame, code);
            }
            Err(SyscallError::Unsupported { number }) => {
                println!("[ctr {}] unsupported syscall #{number}", active.pid);
                SCHEDULER.terminate_current(frame, -38);
            }
            Err(SyscallError::PolicyDenied { syscall }) => {
                println!("[ctr {}] denied: {}", active.pid, syscall);
                SCHEDULER.terminate_current(frame, -1);
            }
            Err(SyscallError::Fatal(msg)) => {
                println!("[ctr {}] fatal syscall error: {}", active.pid, msg);
                SCHEDULER.terminate_current(frame, -1);
            }
        }
    }
}

impl InterruptServiceRoutine for SyscallIsr {
    fn handle(&self, _info: TrapInfo, frame: &mut CurrentTrapFrame) {
        DISPATCHER.dispatch(frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn policy_allows_subset() {
        assert!(SyscallPolicy::Minimal.allows_linux(LinuxSyscall::Write));
        assert!(SyscallPolicy::Minimal.allows_linux(LinuxSyscall::Exit));
        assert!(!SyscallPolicy::Minimal.allows_linux(LinuxSyscall::GetPid));
        assert!(SyscallPolicy::Full.allows_linux(LinuxSyscall::GetPid));
    }
}
