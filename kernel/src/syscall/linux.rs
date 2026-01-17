use super::{DispatchResult, SysError, SysResult, SyscallInvocation};
use alloc::string::ToString;

use crate::mem::addr::VirtAddr;
use crate::mem::user::{copy_from_user, copy_to_user};
use crate::process::fs as proc_fs;
use crate::thread::SCHEDULER;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxErrno {
    NoSys = 38,
    InvalidArgument = 22,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSyscall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    GetPid = 39,
    Exit = 60,
}

impl LinuxSyscall {
    pub fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Open),
            3 => Some(Self::Close),
            39 => Some(Self::GetPid),
            60 => Some(Self::Exit),
            _ => None,
        }
    }
}

/// Minimal Linux syscall table supporting write/getpid/exit placeholders.
pub fn dispatch(invocation: &SyscallInvocation) -> DispatchResult {
    match LinuxSyscall::from_raw(invocation.number) {
        Some(LinuxSyscall::Read) => DispatchResult::Completed(handle_read(invocation)),
        Some(LinuxSyscall::Write) => DispatchResult::Completed(handle_write(invocation)),
        Some(LinuxSyscall::Open) => DispatchResult::Completed(handle_open(invocation)),
        Some(LinuxSyscall::Close) => DispatchResult::Completed(handle_close(invocation)),
        Some(LinuxSyscall::GetPid) => DispatchResult::Completed(handle_getpid(invocation)),
        Some(LinuxSyscall::Exit) => handle_exit(invocation),
        None => DispatchResult::Completed(Err(SysError::NotImplemented)),
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

fn handle_write(invocation: &SyscallInvocation) -> SysResult {
    const MAX_WRITE: usize = 4096;

    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let len = invocation.arg(2).ok_or(SysError::InvalidArgument)?;
    let len = usize::try_from(len).map_err(|_| SysError::InvalidArgument)?;
    if len == 0 {
        return Ok(0);
    }
    let read_len = len.min(MAX_WRITE);
    let mut buf = [0u8; MAX_WRITE];
    let user_ptr = VirtAddr::new(ptr as usize);
    copy_from_user(&mut buf[..read_len], user_ptr).map_err(|_| SysError::InvalidArgument)?;
    let written = proc_fs::write_fd(pid, fd as u32, &buf[..read_len])
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(written as u64)
}

fn handle_read(invocation: &SyscallInvocation) -> SysResult {
    const MAX_READ: usize = 4096;

    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let len = invocation.arg(2).ok_or(SysError::InvalidArgument)?;
    let len = usize::try_from(len).map_err(|_| SysError::InvalidArgument)?;
    if len == 0 {
        return Ok(0);
    }
    let read_len = len.min(MAX_READ);
    let mut buf = [0u8; MAX_READ];
    let read = proc_fs::read_fd(pid, fd as u32, &mut buf[..read_len])
        .map_err(|_| SysError::InvalidArgument)?;
    let user_ptr = VirtAddr::new(ptr as usize);
    copy_to_user(user_ptr, &buf[..read]).map_err(|_| SysError::InvalidArgument)?;
    Ok(read as u64)
}

fn handle_getpid(_invocation: &SyscallInvocation) -> SysResult {
    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    Ok(pid)
}

fn handle_open(invocation: &SyscallInvocation) -> SysResult {
    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    let ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let flags = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let path = read_c_string(ptr, 256)?;

    let create = (flags & LinuxOpenFlags::Creat as u64) != 0;
    let fd = if create {
        proc_fs::open_path_with_create(pid, &path)
    } else {
        proc_fs::open_path(pid, &path)
    }
    .map_err(|_| SysError::InvalidArgument)?;

    Ok(fd as u64)
}

fn handle_close(invocation: &SyscallInvocation) -> SysResult {
    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    proc_fs::close_fd(pid, fd as u32).map_err(|_| SysError::InvalidArgument)?;
    Ok(0)
}

fn handle_exit(invocation: &SyscallInvocation) -> DispatchResult {
    let code = invocation.arg(0).unwrap_or(0) as i32;
    DispatchResult::Terminate(code)
}

fn errno_for(err: SysError) -> u16 {
    match err {
        SysError::NotImplemented => LinuxErrno::NoSys as u16,
        SysError::InvalidArgument => LinuxErrno::InvalidArgument as u16,
    }
}

#[repr(u64)]
enum LinuxOpenFlags {
    Creat = 0x40,
}

fn read_c_string(ptr: u64, max_len: usize) -> Result<alloc::string::String, SysError> {
    if max_len == 0 {
        return Err(SysError::InvalidArgument);
    }
    let mut buf = alloc::vec![0u8; max_len];
    copy_from_user(&mut buf, VirtAddr::new(ptr as usize)).map_err(|_| SysError::InvalidArgument)?;
    let end = buf
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(SysError::InvalidArgument)?;
    let text = core::str::from_utf8(&buf[..end]).map_err(|_| SysError::InvalidArgument)?;
    Ok(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Directory;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::test::kernel_test_case;
    use crate::thread::SCHEDULER;

    #[kernel_test_case]
    fn write_rejects_unknown_fd() {
        println!("[test] write_rejects_unknown_fd");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let invocation = SyscallInvocation::new(LinuxSyscall::Write as u64, [3, 0, 1, 0, 0, 0]);
        match dispatch(&invocation) {
            DispatchResult::Completed(Err(SysError::InvalidArgument)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn getpid_returns_current_process_id() {
        println!("[test] getpid_returns_current_process_id");

        let kernel_pid = PROCESS_TABLE.init_kernel().expect("kernel init");
        SCHEDULER.init().expect("scheduler init");

        let invocation = SyscallInvocation::new(LinuxSyscall::GetPid as u64, [0; 6]);
        let result = dispatch(&invocation);
        match result {
            DispatchResult::Completed(Ok(pid)) => assert_eq!(pid, kernel_pid),
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn write_reports_length_written() {
        println!("[test] write_reports_length_written");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let msg = b"hi";
        let invocation = SyscallInvocation::new(
            LinuxSyscall::Write as u64,
            [1, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0],
        );
        match dispatch(&invocation) {
            DispatchResult::Completed(Ok(written)) => assert_eq!(written, msg.len() as u64),
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn open_read_close_roundtrip() {
        println!("[test] open_read_close_roundtrip");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        let file = root.create_file("note.txt").expect("create file");
        let payload = b"hello";
        let _ = file.write_at(0, payload).expect("write file");

        let path = b"/note.txt\0";
        let open_invocation = SyscallInvocation::new(
            LinuxSyscall::Open as u64,
            [path.as_ptr() as u64, 0, 0, 0, 0, 0],
        );
        let fd = match dispatch(&open_invocation) {
            DispatchResult::Completed(Ok(fd)) => fd,
            other => panic!("unexpected open result: {:?}", other),
        };

        let mut buf = [0u8; 8];
        let read_invocation = SyscallInvocation::new(
            LinuxSyscall::Read as u64,
            [fd, buf.as_mut_ptr() as u64, payload.len() as u64, 0, 0, 0],
        );
        match dispatch(&read_invocation) {
            DispatchResult::Completed(Ok(read)) => {
                assert_eq!(read as usize, payload.len());
                assert_eq!(&buf[..payload.len()], payload);
            }
            other => panic!("unexpected read result: {:?}", other),
        }

        let close_invocation =
            SyscallInvocation::new(LinuxSyscall::Close as u64, [fd, 0, 0, 0, 0, 0]);
        match dispatch(&close_invocation) {
            DispatchResult::Completed(Ok(0)) => {}
            other => panic!("unexpected close result: {:?}", other),
        }
    }
}
