use super::{SysError, SysResult, SyscallInvocation};

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostErrno {
    NotImplemented = 1,
    InvalidArgument = 2,
}

/// Host ABI dispatch (currently stubbed to ENOSYS for all calls).
pub fn dispatch(_invocation: &SyscallInvocation) -> SysResult {
    Err(SysError::NotImplemented)
}

pub fn encode_result(result: SysResult) -> u64 {
    match result {
        Ok(val) => val,
        Err(err) => encode_error(err),
    }
}

fn encode_error(err: SysError) -> u64 {
    match err {
        SysError::NotImplemented => HostErrno::NotImplemented as u64,
        SysError::InvalidArgument => HostErrno::InvalidArgument as u64,
    }
}
