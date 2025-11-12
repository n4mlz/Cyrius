use core::cmp::min;

use crate::arch::{Arch, api::ArchDevice};
use crate::println;
use crate::util::stream::WriteOps;

use super::{
    SyscallContext, SyscallError, SyscallOutcome, SyscallResult, SyscallTable, ThreadRuntime,
};

pub struct LinuxSyscallTable;

impl SyscallTable for LinuxSyscallTable {
    fn dispatch(&self, ctx: &mut SyscallContext<'_>, thread: ThreadRuntime) -> SyscallResult {
        let nr = ctx.number();
        let call = LinuxSyscall::from_number(nr).ok_or(SyscallError::Unsupported { number: nr })?;

        if !thread.policy.allows_linux(call) {
            return Err(SyscallError::PolicyDenied {
                syscall: call.name(),
            });
        }

        match call {
            LinuxSyscall::Write => self.sys_write(ctx),
            LinuxSyscall::GetPid => self.sys_getpid(ctx, thread),
            LinuxSyscall::Exit => self.sys_exit(ctx),
        }
    }
}

impl LinuxSyscallTable {
    fn sys_write(&self, ctx: &mut SyscallContext<'_>) -> SyscallResult {
        let _fd = ctx.arg(0);
        let buf = ctx.arg(1) as *const u8;
        let len = ctx.arg(2) as usize;
        if len == 0 {
            ctx.set_ret(0);
            return Ok(SyscallOutcome::Continue);
        }

        // User and kernel currently share the same address space, so copying is a direct slice read.
        let bytes = unsafe { core::slice::from_raw_parts(buf, min(len, MAX_WRITE_LEN)) };
        let console = Arch::console();
        if let Err(err) = console.write(bytes) {
            println!("[syscall] console write failed: {err:?}");
            return Err(SyscallError::Fatal("console write failure"));
        }
        ctx.set_ret(bytes.len() as u64);
        Ok(SyscallOutcome::Continue)
    }

    fn sys_getpid(&self, ctx: &mut SyscallContext<'_>, thread: ThreadRuntime) -> SyscallResult {
        ctx.set_ret(thread.pid);
        Ok(SyscallOutcome::Continue)
    }

    fn sys_exit(&self, ctx: &mut SyscallContext<'_>) -> SyscallResult {
        let code = ctx.arg(0) as i32;
        Ok(SyscallOutcome::Terminate { code })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSyscall {
    Write,
    GetPid,
    Exit,
}

impl LinuxSyscall {
    pub fn from_number(nr: u64) -> Option<Self> {
        match nr {
            1 => Some(Self::Write),
            39 => Some(Self::GetPid),
            60 => Some(Self::Exit),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::GetPid => "getpid",
            Self::Exit => "exit",
        }
    }
}

const MAX_WRITE_LEN: usize = 4096;

#[cfg(test)]
mod tests {
    use super::LinuxSyscall;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn decode_linux_numbers() {
        assert_eq!(LinuxSyscall::from_number(1), Some(LinuxSyscall::Write));
        assert_eq!(LinuxSyscall::from_number(39), Some(LinuxSyscall::GetPid));
        assert_eq!(LinuxSyscall::from_number(60), Some(LinuxSyscall::Exit));
        assert_eq!(LinuxSyscall::from_number(2), None);
    }
}
