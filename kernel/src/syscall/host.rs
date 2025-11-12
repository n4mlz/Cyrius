use super::{SyscallContext, SyscallError, SyscallResult, SyscallTable, ThreadRuntime};

pub struct HostSyscallTable;

impl SyscallTable for HostSyscallTable {
    fn dispatch(&self, ctx: &mut SyscallContext<'_>, _thread: ThreadRuntime) -> SyscallResult {
        Err(SyscallError::Unsupported {
            number: ctx.number(),
        })
    }
}
