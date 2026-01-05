use alloc::format;
use alloc::string::{String, ToString};

use crate::fs::VfsPath;
use crate::process::{PROCESS_TABLE, ProcessId};
use crate::syscall::{self, Abi, DispatchResult, HostSyscall, SysError, SyscallInvocation};

#[derive(Debug)]
pub enum OciRuntimeError {
    Fs(crate::fs::VfsError),
    Syscall(SysError),
}

pub fn create_container(
    pid: ProcessId,
    id: &str,
    bundle: &str,
) -> Result<String, OciRuntimeError> {
    let bundle = resolve_abs_path(pid, bundle)?;
    let invocation = SyscallInvocation::new(
        HostSyscall::ContainerCreate as u64,
        [
            id.as_ptr() as u64,
            id.len() as u64,
            bundle.as_ptr() as u64,
            bundle.len() as u64,
            0,
            0,
        ],
    );

    match syscall::dispatch(Abi::Host, &invocation) {
        DispatchResult::Completed(Ok(_)) => Ok(format!("container {id} created")),
        DispatchResult::Completed(Err(err)) => Err(OciRuntimeError::Syscall(err)),
        DispatchResult::Terminate(_) => Err(OciRuntimeError::Syscall(SysError::InvalidArgument)),
    }
}

fn resolve_abs_path(pid: ProcessId, raw: &str) -> Result<String, OciRuntimeError> {
    let cwd = PROCESS_TABLE.cwd(pid).map_err(OciRuntimeError::Fs)?;
    let parsed = VfsPath::parse(raw).map_err(OciRuntimeError::Fs)?;
    let abs = if parsed.is_absolute() {
        parsed
    } else {
        cwd.join(&parsed).map_err(OciRuntimeError::Fs)?
    };
    Ok(abs.to_string())
}
