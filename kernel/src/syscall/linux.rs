use super::{SysError, SysResult, SyscallInvocation};

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxErrno {
    NoSys = 38,
    InvalidArgument = 22,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSyscall {
    Write = 1,
    GetPid = 39,
    Exit = 60,
}

impl LinuxSyscall {
    pub fn from_raw(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Write),
            39 => Some(Self::GetPid),
            60 => Some(Self::Exit),
            _ => None,
        }
    }
}

/// Minimal Linux syscall table supporting write/getpid/exit placeholders.
pub fn dispatch(invocation: &SyscallInvocation) -> SysResult {
    match LinuxSyscall::from_raw(invocation.number) {
        Some(LinuxSyscall::Write) => handle_write(invocation),
        Some(LinuxSyscall::GetPid) => handle_getpid(invocation),
        Some(LinuxSyscall::Exit) => handle_exit(invocation),
        None => Err(SysError::NotImplemented),
    }
}

pub fn encode_result(result: SysResult) -> u64 {
    match result {
        Ok(val) => val,
        Err(err) => {
            let code = errno_for(err) as i64;
            (-code) as u64
        }
    }
}

fn handle_write(_invocation: &SyscallInvocation) -> SysResult {
    Err(SysError::NotImplemented)
}

fn handle_getpid(_invocation: &SyscallInvocation) -> SysResult {
    Err(SysError::NotImplemented)
}

fn handle_exit(_invocation: &SyscallInvocation) -> SysResult {
    Err(SysError::NotImplemented)
}

fn errno_for(err: SysError) -> u16 {
    match err {
        SysError::NotImplemented => LinuxErrno::NoSys as u16,
        SysError::InvalidArgument => LinuxErrno::InvalidArgument as u16,
    }
}
