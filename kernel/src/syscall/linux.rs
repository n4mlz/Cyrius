use super::{DispatchResult, SysError, SysResult, SyscallInvocation};

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::arch::Arch;
use crate::arch::api::{ArchPageTableAccess, ArchThread};
use crate::container::Uts;
use crate::fs::{DirEntry, NodeKind};
use crate::interrupt::INTERRUPTS;
use crate::mem::addr::{
    Addr, MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr, align_down, align_up,
};
use crate::mem::manager;
use crate::mem::paging::{FrameAllocator, MapError, PageTableOps, PhysMapper};
use crate::mem::user::{
    UserMemoryAccess, copy_from_user, copy_to_user, with_user_slice, with_user_slice_mut,
};
use crate::net::{IpAddr, Ipv4Addr, SocketAddr, TcpSocketFile};
use crate::process::fs as proc_fs;
use crate::process::{ControllingTty, PROCESS_TABLE, ProcessHandle, ProcessId};
use crate::thread::SCHEDULER;
use crate::trap::CurrentTrapFrame;
use crate::util::stream::{ControlAccess, ControlError, ControlRequest};

// NOTE: Error mapping is intentionally coarse right now (many failures collapse
// to InvalidArgument/BadAddress). This keeps the syscall surface minimal but is
// not Linux-accurate.

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxErrno {
    NoEntry = 2,
    NoSys = 38,
    InvalidArgument = 22,
    BadAddress = 14,
    NotTty = 25,
    IllegalSeek = 29,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSyscall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Lstat = 6,
    Poll = 7,
    Lseek = 8,
    Mmap = 9,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    Ioctl = 16,
    Writev = 20,
    Uname = 63,
    GetPid = 39,
    GetTimeOfDay = 96,
    Fcntl = 72,
    GetCwd = 79,
    Chdir = 80,
    SetPgid = 109,
    GetPpid = 110,
    GetPgrp = 111,
    SetSid = 112,
    Fork = 57,
    Execve = 59,
    Exit = 60,
    ExitGroup = 231,
    Wait4 = 61,
    GetUid = 102,
    GetGid = 104,
    GetEuid = 107,
    SetUid = 105,
    SetGid = 106,
    GetPgid = 121,
    GetSid = 124,
    ArchPrctl = 158,
    GetDents64 = 217,
    SetTidAddress = 218,
    ClockGetTime = 228,
    Socket = 41,
    Bind = 49,
    Listen = 50,
    Accept = 43,
}

const AF_INET: u16 = 2;
const SOCK_STREAM: u32 = 1;
const SOCKADDR_IN_LEN: usize = 16;

impl LinuxSyscall {
    pub fn from_raw(value: u64) -> Option<Self> {
        let value = value as u32 as u64;
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Open),
            3 => Some(Self::Close),
            4 => Some(Self::Stat),
            6 => Some(Self::Lstat),
            7 => Some(Self::Poll),
            8 => Some(Self::Lseek),
            9 => Some(Self::Mmap),
            11 => Some(Self::Munmap),
            12 => Some(Self::Brk),
            13 => Some(Self::RtSigaction),
            14 => Some(Self::RtSigprocmask),
            16 => Some(Self::Ioctl),
            20 => Some(Self::Writev),
            39 => Some(Self::GetPid),
            63 => Some(Self::Uname),
            96 => Some(Self::GetTimeOfDay),
            72 => Some(Self::Fcntl),
            79 => Some(Self::GetCwd),
            80 => Some(Self::Chdir),
            109 => Some(Self::SetPgid),
            110 => Some(Self::GetPpid),
            111 => Some(Self::GetPgrp),
            112 => Some(Self::SetSid),
            57 => Some(Self::Fork),
            59 => Some(Self::Execve),
            60 => Some(Self::Exit),
            231 => Some(Self::ExitGroup),
            61 => Some(Self::Wait4),
            102 => Some(Self::GetUid),
            104 => Some(Self::GetGid),
            107 => Some(Self::GetEuid),
            105 => Some(Self::SetUid),
            106 => Some(Self::SetGid),
            121 => Some(Self::GetPgid),
            124 => Some(Self::GetSid),
            158 => Some(Self::ArchPrctl),
            217 => Some(Self::GetDents64),
            218 => Some(Self::SetTidAddress),
            228 => Some(Self::ClockGetTime),
            41 => Some(Self::Socket),
            43 => Some(Self::Accept),
            49 => Some(Self::Bind),
            50 => Some(Self::Listen),
            _ => None,
        }
    }
}

/// Minimal Linux syscall table supporting write/getpid/exit placeholders.
///
/// NOTE: `openat` and related syscalls are not implemented yet; userland that
/// relies on them will see ENOSYS.
pub fn dispatch(
    invocation: &SyscallInvocation,
    frame: Option<&mut CurrentTrapFrame>,
) -> DispatchResult {
    match LinuxSyscall::from_raw(invocation.number) {
        Some(LinuxSyscall::Read) => DispatchResult::Completed(handle_read(invocation)),
        Some(LinuxSyscall::Write) => DispatchResult::Completed(handle_write(invocation)),
        Some(LinuxSyscall::Open) => DispatchResult::Completed(handle_open(invocation)),
        Some(LinuxSyscall::Close) => DispatchResult::Completed(handle_close(invocation)),
        Some(LinuxSyscall::Writev) => DispatchResult::Completed(handle_writev(invocation)),
        Some(LinuxSyscall::Stat) => DispatchResult::Completed(handle_stat(invocation)),
        Some(LinuxSyscall::Lstat) => DispatchResult::Completed(handle_lstat(invocation)),
        Some(LinuxSyscall::Poll) => DispatchResult::Completed(handle_poll(invocation)),
        Some(LinuxSyscall::Lseek) => DispatchResult::Completed(handle_lseek(invocation)),
        Some(LinuxSyscall::Mmap) => DispatchResult::Completed(handle_mmap(invocation)),
        Some(LinuxSyscall::Munmap) => DispatchResult::Completed(handle_munmap(invocation)),
        Some(LinuxSyscall::Brk) => DispatchResult::Completed(handle_brk(invocation)),
        Some(LinuxSyscall::Fcntl) => DispatchResult::Completed(handle_fcntl(invocation)),
        Some(LinuxSyscall::Uname) => DispatchResult::Completed(handle_uname(invocation)),
        Some(LinuxSyscall::GetCwd) => DispatchResult::Completed(handle_getcwd(invocation)),
        Some(LinuxSyscall::Chdir) => DispatchResult::Completed(handle_chdir(invocation)),
        Some(LinuxSyscall::SetPgid) => DispatchResult::Completed(handle_setpgid(invocation)),
        Some(LinuxSyscall::GetPpid) => DispatchResult::Completed(handle_getppid(invocation)),
        Some(LinuxSyscall::GetPgrp) => DispatchResult::Completed(handle_getpgrp(invocation)),
        Some(LinuxSyscall::SetSid) => DispatchResult::Completed(handle_setsid(invocation)),
        Some(LinuxSyscall::Fork) => handle_fork(invocation, frame),
        Some(LinuxSyscall::Execve) => handle_execve(invocation, frame),
        Some(LinuxSyscall::Wait4) => DispatchResult::Completed(handle_wait4(invocation)),
        Some(LinuxSyscall::ArchPrctl) => DispatchResult::Completed(handle_arch_prctl(invocation)),
        Some(LinuxSyscall::Ioctl) => DispatchResult::Completed(handle_ioctl(invocation)),
        // These syscalls are stubbed and always report success (0). This is risky
        // because userland may rely on signals/TID state that is not tracked yet.
        Some(LinuxSyscall::RtSigaction) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::RtSigprocmask) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::SetTidAddress) => DispatchResult::Completed(Ok(0)),
        // NOTE: UID/GID syscalls are stubbed to 0 for now; user/cred support is not implemented yet.
        Some(LinuxSyscall::GetUid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::GetGid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::GetEuid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::SetUid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::SetGid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::GetPid) => DispatchResult::Completed(handle_getpid(invocation)),
        Some(LinuxSyscall::GetTimeOfDay) => {
            DispatchResult::Completed(handle_gettimeofday(invocation))
        }
        Some(LinuxSyscall::GetPgid) => DispatchResult::Completed(handle_getpgid(invocation)),
        Some(LinuxSyscall::GetSid) => DispatchResult::Completed(handle_getsid(invocation)),
        Some(LinuxSyscall::GetDents64) => DispatchResult::Completed(handle_getdents64(invocation)),
        Some(LinuxSyscall::ClockGetTime) => {
            DispatchResult::Completed(handle_clock_gettime(invocation))
        }
        Some(LinuxSyscall::Socket) => DispatchResult::Completed(handle_socket(invocation)),
        Some(LinuxSyscall::Bind) => DispatchResult::Completed(handle_bind(invocation)),
        Some(LinuxSyscall::Listen) => DispatchResult::Completed(handle_listen(invocation)),
        Some(LinuxSyscall::Accept) => DispatchResult::Completed(handle_accept(invocation)),
        Some(LinuxSyscall::Exit) => handle_exit(invocation),
        Some(LinuxSyscall::ExitGroup) => handle_exit(invocation),
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

fn handle_open(invocation: &SyscallInvocation) -> SysResult {
    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    let ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let flags = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let path = process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        read_cstring_with_user(&user, ptr)
    })?;

    let create = (flags & LinuxOpenFlags::Creat as u64) != 0;
    let result = if create {
        proc_fs::open_path_with_create(pid, &path, flags)
    } else {
        proc_fs::open_path(pid, &path, flags)
    };

    let fd = result.map_err(|_| SysError::InvalidArgument)?;
    if path == "/dev/tty" && process.session_id() == pid && !process.has_controlling_tty() {
        process.set_controlling_tty(ControllingTty::Global);
    }
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

fn handle_writev(invocation: &SyscallInvocation) -> SysResult {
    const MAX_IOVCNT: usize = 1024;

    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let iov_ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let iov_cnt = invocation.arg(2).ok_or(SysError::InvalidArgument)?;
    let iov_cnt = usize::try_from(iov_cnt).map_err(|_| SysError::InvalidArgument)?;
    if iov_cnt == 0 {
        return Ok(0);
    }
    if iov_cnt > MAX_IOVCNT {
        return Err(SysError::InvalidArgument);
    }

    let mut total = 0u64;
    let ptr = VirtAddr::new(iov_ptr as usize);
    with_user_slice::<LinuxIovec, _, _>(ptr, iov_cnt, |iovecs| {
        writev_from_iovecs(pid, fd as u32, iovecs, &mut total)
    })
    .map_err(|_| SysError::BadAddress)??;

    Ok(total)
}

fn handle_fcntl(invocation: &SyscallInvocation) -> SysResult {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_DUPFD_CLOEXEC: u64 = 1030;

    let pid = current_pid()?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)? as u32;
    let cmd = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let arg = invocation.arg(2).unwrap_or(0);

    match cmd {
        F_DUPFD => {
            let min = u32::try_from(arg).map_err(|_| SysError::InvalidArgument)?;
            proc_fs::dup_fd_min(pid, fd, min, false)
                .map(|val| val as u64)
                .map_err(|_| SysError::InvalidArgument)
        }
        F_DUPFD_CLOEXEC => {
            let min = u32::try_from(arg).map_err(|_| SysError::InvalidArgument)?;
            proc_fs::dup_fd_min(pid, fd, min, true)
                .map(|val| val as u64)
                .map_err(|_| SysError::InvalidArgument)
        }
        F_GETFD => proc_fs::get_fd_flags(pid, fd)
            .map(|val| val as u64)
            .map_err(|_| SysError::InvalidArgument),
        F_SETFD => {
            let flags = u32::try_from(arg).map_err(|_| SysError::InvalidArgument)?;
            proc_fs::set_fd_flags(pid, fd, flags)
                .map(|_| 0)
                .map_err(|_| SysError::InvalidArgument)
        }
        _ => Err(SysError::NotImplemented),
    }
}

fn handle_ioctl(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let cmd = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let arg = invocation.arg(2).unwrap_or(0);

    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;

    process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        let request = crate::util::stream::ControlRequest::new(cmd, arg, &user);
        proc_fs::control_fd(pid, fd as u32, &request).map_err(map_control_error)
    })
}

fn handle_socket(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let domain = invocation.arg(0).ok_or(SysError::InvalidArgument)? as u32;
    let socket_type = invocation.arg(1).ok_or(SysError::InvalidArgument)? as u32;
    let protocol = invocation.arg(2).ok_or(SysError::InvalidArgument)? as u32;

    if domain != AF_INET as u32 {
        return Err(SysError::InvalidArgument);
    }
    if socket_type & 0xff != SOCK_STREAM {
        return Err(SysError::InvalidArgument);
    }
    if protocol != 0 {
        return Err(SysError::InvalidArgument);
    }

    let file = TcpSocketFile::new();
    let fd = proc_fs::open_file(pid, file).map_err(|_| SysError::InvalidArgument)?;
    Ok(fd as u64)
}

fn handle_bind(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)? as u32;
    let addr_ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let addr_len = invocation.arg(2).ok_or(SysError::InvalidArgument)?;
    let addr_len = usize::try_from(addr_len).map_err(|_| SysError::InvalidArgument)?;

    let addr = read_sockaddr_in(addr_ptr, addr_len)?;
    let file = proc_fs::fd_file(pid, fd).map_err(|_| SysError::InvalidArgument)?;
    let socket = file
        .as_ref()
        .as_any()
        .downcast_ref::<TcpSocketFile>()
        .ok_or(SysError::InvalidArgument)?;
    socket.bind(addr).map_err(|_| SysError::InvalidArgument)?;
    Ok(0)
}

fn handle_listen(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)? as u32;
    let _backlog = invocation.arg(1).ok_or(SysError::InvalidArgument)?;

    let file = proc_fs::fd_file(pid, fd).map_err(|_| SysError::InvalidArgument)?;
    let socket = file
        .as_ref()
        .as_any()
        .downcast_ref::<TcpSocketFile>()
        .ok_or(SysError::InvalidArgument)?;
    socket.listen().map_err(|_| SysError::InvalidArgument)?;
    Ok(0)
}

fn handle_accept(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)? as u32;
    let addr_ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let addrlen_ptr = invocation.arg(2).ok_or(SysError::InvalidArgument)?;

    let file = proc_fs::fd_file(pid, fd).map_err(|_| SysError::InvalidArgument)?;
    let socket = file
        .as_ref()
        .as_any()
        .downcast_ref::<TcpSocketFile>()
        .ok_or(SysError::InvalidArgument)?;
    let (stream, remote) = socket.accept().map_err(|_| SysError::InvalidArgument)?;
    let new_socket = TcpSocketFile::new();
    new_socket
        .set_stream(stream)
        .map_err(|_| SysError::InvalidArgument)?;
    let new_fd = proc_fs::open_file(pid, new_socket).map_err(|_| SysError::InvalidArgument)?;

    if addr_ptr != 0 && addrlen_ptr != 0 {
        let len = read_u32(addrlen_ptr)? as usize;
        if len < SOCKADDR_IN_LEN {
            return Err(SysError::InvalidArgument);
        }
        write_sockaddr_in(remote, addr_ptr)?;
        write_u32(addrlen_ptr, SOCKADDR_IN_LEN as u32)?;
    }

    Ok(new_fd as u64)
}

fn handle_getpid(_invocation: &SyscallInvocation) -> SysResult {
    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    Ok(pid)
}

fn handle_getppid(_invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(process.parent().unwrap_or(0))
}

fn handle_getpgrp(_invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    Ok(process.pgrp_id())
}

fn handle_setsid(_invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    if process.session_id() == pid {
        return Err(SysError::InvalidArgument);
    }
    process.set_session_id(pid);
    process.set_pgrp_id(pid);
    process.clear_controlling_tty();
    Ok(pid)
}

fn handle_getpgid(invocation: &SyscallInvocation) -> SysResult {
    let pid = invocation.arg(0).unwrap_or(0);
    let target = if pid == 0 { current_pid()? } else { pid };
    let process = PROCESS_TABLE
        .process_handle(target)
        .map_err(|_| SysError::NotFound)?;
    Ok(process.pgrp_id())
}

fn handle_getsid(invocation: &SyscallInvocation) -> SysResult {
    let pid = invocation.arg(0).unwrap_or(0);
    let target = if pid == 0 { current_pid()? } else { pid };
    let process = PROCESS_TABLE
        .process_handle(target)
        .map_err(|_| SysError::NotFound)?;
    Ok(process.session_id())
}

fn handle_setpgid(invocation: &SyscallInvocation) -> SysResult {
    let pid_arg = invocation.arg(0).unwrap_or(0);
    let pgid_arg = invocation.arg(1).unwrap_or(0);

    let caller_pid = current_pid()?;
    let target_pid = if pid_arg == 0 { caller_pid } else { pid_arg };
    let target_pgid = if pgid_arg == 0 { target_pid } else { pgid_arg };

    let caller = PROCESS_TABLE
        .process_handle(caller_pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let target = PROCESS_TABLE
        .process_handle(target_pid)
        .map_err(|_| SysError::NotFound)?;

    if target_pid != caller_pid && !PROCESS_TABLE.is_child(caller_pid, target_pid) {
        return Err(SysError::InvalidArgument);
    }

    if target.session_id() != caller.session_id() {
        return Err(SysError::InvalidArgument);
    }

    target.set_pgrp_id(target_pgid);
    Ok(0)
}

fn handle_exit(invocation: &SyscallInvocation) -> DispatchResult {
    let code = invocation.arg(0).unwrap_or(0) as i32;
    if let Ok(pid) = current_pid()
        && let Ok(process) = PROCESS_TABLE.process_handle(pid)
    {
        // Store the exit code for wait4; the last exiting thread wins.
        process.set_exit_code(code);
    }
    DispatchResult::Terminate(code)
}

fn handle_stat(invocation: &SyscallInvocation) -> SysResult {
    // TODO: This is a minimal stat: inode/device/mtime fields are zeroed because we do not
    // track them in the current VFS layer. Busybox only needs size/type bits for now.
    let path_ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let stat_ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;

    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let path = process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        read_cstring_with_user(&user, path_ptr)
    })?;
    let stat = proc_fs::stat_path(pid, &path).map_err(|err| match err {
        crate::fs::VfsError::NotFound => SysError::NotFound,
        _ => SysError::InvalidArgument,
    })?;

    let mode = mode_from_meta(stat.kind);
    let stat = LinuxStat::from_meta(mode, stat.size);
    let dst = VirtAddr::new(stat_ptr as usize);
    process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        user.write_bytes(dst, stat.as_bytes())
            .map_err(|_| SysError::BadAddress)?;
        Ok::<(), SysError>(())
    })?;
    Ok(0)
}

fn handle_lstat(invocation: &SyscallInvocation) -> SysResult {
    let path_ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let stat_ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;

    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let path = process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        read_cstring_with_user(&user, path_ptr)
    })?;
    let stat = proc_fs::stat_path_no_follow(pid, &path).map_err(|err| match err {
        crate::fs::VfsError::NotFound => SysError::NotFound,
        _ => SysError::InvalidArgument,
    })?;

    let mode = mode_from_meta(stat.kind);
    let stat = LinuxStat::from_meta(mode, stat.size);
    let dst = VirtAddr::new(stat_ptr as usize);
    process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        user.write_bytes(dst, stat.as_bytes())
            .map_err(|_| SysError::BadAddress)?;
        Ok::<(), SysError>(())
    })?;
    Ok(0)
}

fn handle_lseek(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let offset = invocation.arg(1).ok_or(SysError::InvalidArgument)? as i64;
    let whence = invocation.arg(2).ok_or(SysError::InvalidArgument)?;
    let whence = u32::try_from(whence).map_err(|_| SysError::InvalidArgument)?;
    match proc_fs::seek_fd(pid, fd as u32, offset, whence) {
        Ok(pos) => Ok(pos),
        Err(crate::fs::VfsError::NotFile) => Err(SysError::IllegalSeek),
        Err(crate::fs::VfsError::NotDirectory) => Err(SysError::IllegalSeek),
        Err(crate::fs::VfsError::InvalidPath) => Err(SysError::InvalidArgument),
        Err(crate::fs::VfsError::NotFound) => Err(SysError::InvalidArgument),
        Err(_) => Err(SysError::InvalidArgument),
    }
}

fn handle_getcwd(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let buf_ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let size = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let size = usize::try_from(size).map_err(|_| SysError::InvalidArgument)?;
    if size == 0 {
        return Err(SysError::InvalidArgument);
    }

    let cwd = proc_fs::cwd(pid).map_err(|_| SysError::InvalidArgument)?;
    let text = cwd.to_string();
    let bytes = text.as_bytes();
    if bytes.len().saturating_add(1) > size {
        // NOTE: Linux returns ERANGE here; we currently map to InvalidArgument.
        return Err(SysError::InvalidArgument);
    }
    let user_ptr = VirtAddr::new(buf_ptr as usize);
    copy_to_user(user_ptr, bytes).map_err(|_| SysError::InvalidArgument)?;
    let nul = VirtAddr::new(user_ptr.as_raw() + bytes.len());
    copy_to_user(nul, &[0]).map_err(|_| SysError::InvalidArgument)?;
    Ok((bytes.len() + 1) as u64)
}

/// Encode directory entries for `getdents64` using the per-fd cursor in `FdTable`.
///
/// Implicit dependencies:
/// - The backing `File::readdir` returns entries in a stable order for the lifetime of the open
///   directory handle so the offset cursor remains valid across calls.
/// - Directory entries fit in the caller-provided buffer; if the buffer is too small for the
///   next entry, the syscall returns `EINVAL` instead of looping forever.
fn handle_getdents64(invocation: &SyscallInvocation) -> SysResult {
    const ALIGN: usize = 8;
    const HEADER_LEN: usize = 8 + 8 + 2 + 1;

    let pid = current_pid()?;
    let fd = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let dir_ptr = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let count = invocation.arg(2).ok_or(SysError::InvalidArgument)?;
    let count = usize::try_from(count).map_err(|_| SysError::InvalidArgument)?;
    if count == 0 {
        return Ok(0);
    }

    let entries = proc_fs::read_dir_fd(pid, fd as u32).map_err(|_| SysError::InvalidArgument)?;
    let mut index =
        proc_fs::dir_offset(pid, fd as u32).map_err(|_| SysError::InvalidArgument)? as usize;
    if index >= entries.len() {
        return Ok(0);
    }

    let base = VirtAddr::new(dir_ptr as usize);
    let mut written = 0usize;
    while index < entries.len() {
        let entry = &entries[index];
        let reclen = dirent64_reclen(entry.name.len(), HEADER_LEN, ALIGN)?;
        if written + reclen > count {
            break;
        }
        write_dirent64(base, written, entry, (index + 1) as u64, reclen, HEADER_LEN)?;
        written += reclen;
        index += 1;
    }

    if written == 0 && index < entries.len() {
        let entry = &entries[index];
        let min = dirent64_reclen(entry.name.len(), HEADER_LEN, ALIGN)?;
        if min > count {
            return Err(SysError::InvalidArgument);
        }
    }

    proc_fs::set_dir_offset(pid, fd as u32, index as u64).map_err(|_| SysError::InvalidArgument)?;
    Ok(written as u64)
}

fn handle_chdir(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let path = process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        read_cstring_with_user(&user, ptr)
    })?;
    proc_fs::change_dir(pid, &path).map_err(|_| SysError::InvalidArgument)?;
    Ok(0)
}

fn dirent64_reclen(name_len: usize, header_len: usize, align: usize) -> Result<usize, SysError> {
    let base = header_len
        .checked_add(name_len)
        .and_then(|value| value.checked_add(1))
        .ok_or(SysError::InvalidArgument)?;
    let reclen = align_up(base, align);
    if reclen > u16::MAX as usize {
        return Err(SysError::InvalidArgument);
    }
    Ok(reclen)
}

fn write_dirent64(
    base: VirtAddr,
    offset: usize,
    entry: &DirEntry,
    next_offset: u64,
    reclen: usize,
    header_len: usize,
) -> Result<(), SysError> {
    let dst = base.checked_add(offset).ok_or(SysError::BadAddress)?;
    let mut header = [0u8; 8 + 8 + 2 + 1];
    header[0..8].copy_from_slice(&0u64.to_ne_bytes());
    header[8..16].copy_from_slice(&next_offset.to_ne_bytes());
    header[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
    header[18] = dirent_type(entry.stat.kind);
    copy_to_user(dst, &header).map_err(|_| SysError::BadAddress)?;

    let name = entry.name.as_bytes();
    let name_dst = dst.checked_add(header_len).ok_or(SysError::BadAddress)?;
    copy_to_user(name_dst, name).map_err(|_| SysError::BadAddress)?;
    let nul_dst = name_dst
        .checked_add(name.len())
        .ok_or(SysError::BadAddress)?;
    copy_to_user(nul_dst, &[0]).map_err(|_| SysError::BadAddress)?;

    let pad = reclen.saturating_sub(header_len + name.len() + 1);
    if pad > 0 {
        let pad_dst = nul_dst.checked_add(1).ok_or(SysError::BadAddress)?;
        let zeros = [0u8; 8];
        copy_to_user(pad_dst, &zeros[..pad]).map_err(|_| SysError::BadAddress)?;
    }
    Ok(())
}

fn dirent_type(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Regular => 8,
        NodeKind::Directory => 4,
        NodeKind::Symlink => 10,
        NodeKind::CharDevice => 2,
        NodeKind::BlockDevice => 6,
        NodeKind::Pipe => 1,
        NodeKind::Socket => 12,
    }
}

fn handle_uname(invocation: &SyscallInvocation) -> SysResult {
    let pid = current_pid()?;
    let addr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let uts = match process.domain() {
        crate::process::ProcessDomain::Container(container) => container.context().uts(),
        _ => Uts::default_host(),
    };
    let dst = VirtAddr::new(addr as usize);
    process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        user.write_bytes(dst, uts.as_bytes())
            .map_err(|_| SysError::BadAddress)?;
        Ok::<(), SysError>(())
    })?;
    Ok(0)
}

fn handle_poll(invocation: &SyscallInvocation) -> SysResult {
    const POLLIN: i16 = 0x0001;
    const POLLNVAL: i16 = 0x0020;

    let pid = current_pid()?;
    let fds_ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let nfds = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let timeout_raw = invocation.arg(2).unwrap_or(0);
    let timeout_ms = if timeout_raw == u64::MAX {
        -1
    } else {
        i64::try_from(timeout_raw).map_err(|_| SysError::InvalidArgument)?
    };
    let nfds = usize::try_from(nfds).map_err(|_| SysError::InvalidArgument)?;
    if nfds == 0 {
        return Ok(0);
    }

    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let ptr = VirtAddr::new(fds_ptr as usize);

    loop {
        let ready =
            with_user_slice_mut(ptr, nfds, |fds| poll_once(fds, &process, POLLIN, POLLNVAL))
                .map_err(|_| SysError::BadAddress)?;
        if ready > 0 || timeout_ms == 0 {
            return Ok(ready as u64);
        }
        // NOTE: Timeout handling is intentionally simplified; any non-zero timeout blocks
        // until an event arrives. Poll semantics are coarse (TTY readiness only, others are
        // treated as immediately readable).
        //
        // Syscalls may run with interrupts disabled; enable them so the scheduler can
        // make progress while we wait.
        INTERRUPTS.enable();
        core::hint::spin_loop();
    }
}

fn handle_brk(invocation: &SyscallInvocation) -> SysResult {
    // TODO: This is a minimal brk: no heap upper bound is enforced and errors are coarse.
    let requested = invocation.arg(0).unwrap_or(0);
    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let address_space = process.address_space();
    let mut state = process.brk_state();

    if state.base.as_raw() == 0 {
        return Err(SysError::InvalidArgument);
    }

    if requested == 0 {
        return Ok(state.current.as_raw() as u64);
    }

    let requested = usize::try_from(requested).map_err(|_| SysError::InvalidArgument)?;
    let requested = VirtAddr::new(requested);
    if requested < state.base {
        return Ok(state.current.as_raw() as u64);
    }

    if requested > state.current {
        let page_size = PageSize::SIZE_4K.bytes();
        let start = align_up(state.current.as_raw(), page_size);
        let end = align_up(requested.as_raw(), page_size);
        let map_result = address_space.with_page_table(|table, allocator| {
            for addr in (start..end).step_by(page_size) {
                let page = Page::new(VirtAddr::new(addr), PageSize::SIZE_4K);
                let frame = allocator
                    .allocate(PageSize::SIZE_4K)
                    .ok_or(SysError::InvalidArgument)?;
                // Allow already-mapped pages when the brk range overlaps a page that
                // was mapped earlier (e.g. previous brk growth or non-page-aligned
                // segment tail). This assumes brk_base is placed after loadable
                // segments; if that invariant is broken, overlaps with non-heap
                // mappings could be masked.
                match table.map(page, frame, MemPerm::USER_RW, allocator) {
                    Ok(()) => {}
                    Err(MapError::AlreadyMapped) => {
                        allocator.deallocate(frame);
                        continue;
                    }
                    Err(_) => {
                        allocator.deallocate(frame);
                        return Err(SysError::InvalidArgument);
                    }
                }
                let phys = table
                    .translate(page.start)
                    .map_err(|_| SysError::InvalidArgument)?;
                let mapper = manager::phys_mapper();
                unsafe {
                    core::ptr::write_bytes(mapper.phys_to_virt(phys).into_mut_ptr(), 0, page_size);
                }
            }
            Ok::<_, SysError>(())
        });
        map_result?;
    } else if requested < state.current {
        let page_size = PageSize::SIZE_4K.bytes();
        let start = align_up(requested.as_raw(), page_size);
        let end = align_up(state.current.as_raw(), page_size);
        address_space.with_page_table(|table, allocator| {
            for addr in (start..end).step_by(page_size) {
                let page = Page::new(VirtAddr::new(addr), PageSize::SIZE_4K);
                match table.unmap(page) {
                    Ok(frame) => allocator.deallocate(frame),
                    Err(crate::mem::paging::UnmapError::NotMapped) => {}
                    Err(_) => return Err(SysError::InvalidArgument),
                }
            }
            Ok::<_, SysError>(())
        })?;
    }

    state.current = requested;
    process.set_brk_state(state);
    Ok(state.current.as_raw() as u64)
}

fn handle_fork(
    _invocation: &SyscallInvocation,
    frame: Option<&mut CurrentTrapFrame>,
) -> DispatchResult {
    // TODO: This fork clones the user address space without COW; it copies each user page and
    // rebuilds a stack handle for the cloned region. This is enough for busybox but not a
    // complete Linux fork implementation.
    let frame = match frame {
        Some(frame) => frame,
        None => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };

    let pid = match current_pid() {
        Ok(pid) => pid,
        Err(err) => return DispatchResult::Completed(Err(err)),
    };

    let parent_stack = match SCHEDULER.current_user_stack_info() {
        Some(info) => info,
        None => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };

    let parent_space = match PROCESS_TABLE.address_space(pid) {
        Some(space) => space,
        None => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };
    let child_space = match <Arch as ArchThread>::clone_user_address_space(&parent_space) {
        Ok(space) => space,
        Err(_) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };
    let parent_proc = match PROCESS_TABLE.process_handle(pid) {
        Ok(proc) => proc,
        Err(_) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };
    let child_pid = match PROCESS_TABLE.create_user_process_with_domain_and_space(
        "linux-child",
        parent_proc.domain().clone(),
        child_space.clone(),
    ) {
        Ok(pid) => pid,
        Err(_) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };

    if let Ok(child_proc) = PROCESS_TABLE.process_handle(child_pid) {
        child_proc.set_brk_state(parent_proc.brk_state());
        child_proc.set_parent(pid);
        child_proc.set_session_id(parent_proc.session_id());
        child_proc.set_pgrp_id(parent_proc.pgrp_id());
        child_proc.clone_fs_from(&parent_proc);
        if let Some(tty) = parent_proc.controlling_tty() {
            child_proc.set_controlling_tty(tty);
        }
    }

    let stack_size = parent_stack.size;
    let child_base = parent_stack.base;
    let child_stack = match <Arch as ArchThread>::user_stack_from_existing(
        &child_space,
        child_base,
        stack_size,
    ) {
        Ok(stack) => stack,
        Err(_) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };
    let child_top = <Arch as ArchThread>::user_stack_top(&child_stack);

    let parent_rsp = frame.rsp as usize;
    if parent_rsp < parent_stack.base.as_raw() {
        return DispatchResult::Completed(Err(SysError::InvalidArgument));
    }
    let offset = parent_rsp - parent_stack.base.as_raw();
    let child_rsp = child_base.checked_add(offset).unwrap_or(child_top).as_raw() as u64;

    let mut ctx = <Arch as ArchThread>::save_context(frame);
    <Arch as ArchThread>::set_syscall_return(&mut ctx, 0);
    <Arch as ArchThread>::set_stack_pointer(&mut ctx, VirtAddr::new(child_rsp as usize));

    if let Err(err) =
        SCHEDULER.spawn_user_thread_with_context(child_pid, "linux-fork", ctx, child_stack)
    {
        return DispatchResult::Completed(Err(spawn_error_to_sys(err)));
    }

    DispatchResult::Completed(Ok(child_pid))
}

fn handle_execve(
    invocation: &SyscallInvocation,
    frame: Option<&mut CurrentTrapFrame>,
) -> DispatchResult {
    let frame = match frame {
        Some(frame) => frame,
        None => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };
    let path_ptr = match invocation.arg(0) {
        Some(ptr) => ptr,
        None => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };
    let pid = match current_pid() {
        Ok(pid) => pid,
        Err(err) => return DispatchResult::Completed(Err(err)),
    };
    let process = match PROCESS_TABLE.process_handle(pid) {
        Ok(process) => process,
        Err(_) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };
    let path = match process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        read_cstring_with_user(&user, path_ptr)
    }) {
        Ok(path) => path,
        Err(err) => return DispatchResult::Completed(Err(err)),
    };
    let argv_ptr = invocation.arg(1).unwrap_or(0);
    let envp_ptr = invocation.arg(2).unwrap_or(0);

    // NOTE: Limit argv/envp length to avoid unbounded user input scans.
    let argv = match process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        read_cstring_array_with_user(&user, argv_ptr, 128)
    }) {
        Ok(list) => list,
        Err(err) => return DispatchResult::Completed(Err(err)),
    };
    let envp = match process.address_space().with_page_table(|table, _| {
        let user = UserMemoryAccess::new(table);
        read_cstring_array_with_user(&user, envp_ptr, 128)
    }) {
        Ok(list) => list,
        Err(err) => return DispatchResult::Completed(Err(err)),
    };

    // Drop the previous user stack before clearing mappings so we do not unmap the
    // freshly allocated stack on replacement.
    let old_stack = match SCHEDULER.take_current_user_stack() {
        Ok(stack) => stack,
        Err(err) => {
            return DispatchResult::Completed(Err(spawn_error_to_sys(err)));
        }
    };

    if <Arch as ArchThread>::clear_user_mappings(&process.address_space()).is_err() {
        return DispatchResult::Completed(Err(SysError::InvalidArgument));
    }
    drop(old_stack);

    let program = match crate::loader::linux::load_elf(pid, &path) {
        Ok(program) => program,
        Err(_err) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };

    let auxv = crate::loader::linux::build_auxv(&program, PageSize::SIZE_4K.bytes());
    let argv_refs: alloc::vec::Vec<&str> = argv.iter().map(|s| s.as_str()).collect();
    let envp_refs: alloc::vec::Vec<&str> = envp.iter().map(|s| s.as_str()).collect();
    let stack_top = <Arch as ArchThread>::user_stack_top(&program.user_stack);
    let stack_pointer = match PROCESS_TABLE.address_space(pid) {
        Some(space) => match space.with_page_table(|table, _| {
            crate::loader::linux::initialise_stack_with_args_in_table(
                table, stack_top, &argv_refs, &envp_refs, &auxv,
            )
        }) {
            Ok(ptr) => ptr,
            Err(_err) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
        },
        None => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
    };

    if let Err(err) = SCHEDULER.replace_current_user_stack(program.user_stack) {
        return DispatchResult::Completed(Err(spawn_error_to_sys(err)));
    }

    if let Ok(process) = PROCESS_TABLE.process_handle(pid) {
        process.set_brk_base(program.heap_base);
    }

    frame.rip = program.entry.as_raw() as u64;
    frame.rsp = stack_pointer.as_raw() as u64;
    frame.regs.rax = 0;
    DispatchResult::Completed(Ok(0))
}

fn handle_wait4(invocation: &SyscallInvocation) -> SysResult {
    // TODO: This is a polling wait without a full child/zombie model; it reports exit status from
    // a stored process exit code and marks the child as reaped. This is enough for busybox, but
    // does not implement full Linux wait semantics.
    const ANY_CHILD: i64 = -1;
    const WNOHANG: i32 = 1;

    let pid = invocation.arg(0).ok_or(SysError::InvalidArgument)? as i64;
    let status_ptr = invocation.arg(1).unwrap_or(0);
    let options = invocation.arg(2).unwrap_or(0) as i32;

    let current = current_pid()?;
    if pid == 0 {
        return Err(SysError::InvalidArgument);
    }
    if pid < ANY_CHILD {
        return Err(SysError::InvalidArgument);
    }

    let target_pid = pid as u64;
    let wnohang = options & WNOHANG != 0;

    loop {
        let pid = if target_pid == u64::MAX {
            PROCESS_TABLE.find_terminated_child(current)
        } else if PROCESS_TABLE.is_child(current, target_pid) {
            PROCESS_TABLE
                .process_handle(target_pid)
                .ok()
                .filter(|proc| matches!(proc.state(), crate::process::ProcessState::Terminated))
                .filter(|proc| !proc.is_reaped())
                .map(|proc| proc.id())
        } else {
            return Err(SysError::NotFound);
        };

        if let Some(pid) = pid {
            let exit_code = PROCESS_TABLE
                .process_handle(pid)
                .ok()
                .and_then(|proc| proc.exit_code())
                .unwrap_or(0);
            if let Ok(process) = PROCESS_TABLE.process_handle(pid) {
                process.mark_reaped();
            }
            if status_ptr != 0 {
                let status = encode_wait_status(exit_code);
                let dst = VirtAddr::new(status_ptr as usize);
                copy_to_user(dst, &status.to_ne_bytes()).map_err(|_| SysError::BadAddress)?;
            }
            return Ok(pid);
        }

        if target_pid == u64::MAX && !PROCESS_TABLE.has_child(current) {
            return Err(SysError::NotFound);
        }

        if wnohang {
            return Ok(0);
        }

        // NOTE: Syscalls may run with interrupts disabled; enable them so the scheduler can
        // observe child exits while we wait.
        INTERRUPTS.enable();
        core::hint::spin_loop();
    }
}

fn handle_arch_prctl(invocation: &SyscallInvocation) -> SysResult {
    const ARCH_SET_FS: u64 = 0x1002;

    let code = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let value = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    if code != ARCH_SET_FS {
        return Err(SysError::InvalidArgument);
    }

    // NOTE: This assumes FS base is part of the thread context and restored on context switches.
    crate::arch::x86_64::set_fs_base(value);
    Ok(0)
}

#[repr(C)]
struct LinuxTimeval {
    tv_sec: i64,
    tv_usec: i64,
}

impl LinuxTimeval {
    fn as_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.tv_sec.to_ne_bytes());
        out[8..].copy_from_slice(&self.tv_usec.to_ne_bytes());
        out
    }
}

#[repr(C)]
struct LinuxTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

impl LinuxTimespec {
    fn as_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.tv_sec.to_ne_bytes());
        out[8..].copy_from_slice(&self.tv_nsec.to_ne_bytes());
        out
    }
}

fn handle_gettimeofday(invocation: &SyscallInvocation) -> SysResult {
    let tv_ptr = invocation.arg(0).unwrap_or(0);
    if tv_ptr != 0 {
        // TODO: Provide real wall-clock time once the time source is implemented.
        let tv = LinuxTimeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let dst = VirtAddr::new(tv_ptr as usize);
        copy_to_user(dst, &tv.as_bytes()).map_err(|_| SysError::BadAddress)?;
    }
    Ok(0)
}

fn handle_clock_gettime(invocation: &SyscallInvocation) -> SysResult {
    let tp_ptr = invocation.arg(1).unwrap_or(0);
    if tp_ptr == 0 {
        return Err(SysError::InvalidArgument);
    }
    // TODO: Provide a real clock source once timekeeping is implemented.
    let ts = LinuxTimespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let dst = VirtAddr::new(tp_ptr as usize);
    copy_to_user(dst, &ts.as_bytes()).map_err(|_| SysError::BadAddress)?;
    Ok(0)
}

// NOTE: This is a minimal anonymous mmap implementation for busybox startup.
// It only supports private, anonymous mappings with optional MAP_FIXED and
// ignores file-backed mappings, offsets, and advanced flags.
fn handle_mmap(invocation: &SyscallInvocation) -> SysResult {
    const PROT_READ: u32 = 0x1;
    const PROT_WRITE: u32 = 0x2;
    const PROT_EXEC: u32 = 0x4;
    const MAP_PRIVATE: u32 = 0x02;
    const MAP_FIXED: u32 = 0x10;
    const MAP_ANON: u32 = 0x20;

    let addr = invocation.arg(0).unwrap_or(0);
    let len = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let prot = invocation.arg(2).unwrap_or(0) as u32;
    let flags = invocation.arg(3).unwrap_or(0) as u32;
    let fd = invocation.arg(4).unwrap_or(u64::MAX) as i64;
    let offset = invocation.arg(5).unwrap_or(0);

    if len == 0 {
        return Err(SysError::InvalidArgument);
    }

    if offset != 0 {
        return Err(SysError::NotImplemented);
    }

    if flags & MAP_PRIVATE == 0 {
        return Err(SysError::NotImplemented);
    }

    if flags & MAP_ANON == 0 || fd != -1 {
        return Err(SysError::NotImplemented);
    }

    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let space = process.address_space();

    let page_size = PageSize::SIZE_4K.bytes();
    let len = align_up(len as usize, page_size);
    let fixed = flags & MAP_FIXED != 0;
    let mut target = addr as usize;
    if fixed {
        if !target.is_multiple_of(page_size) {
            return Err(SysError::InvalidArgument);
        }
    } else if target == 0 {
        // NOTE: This reuses the brk state as a simple bump allocator; it can
        // collide with future brk growth and does not model Linux VMAs.
        let brk = process.brk_state();
        target = align_up(brk.current.as_raw(), page_size);
        let next = VirtAddr::new(target + len);
        process.set_brk_state(crate::process::BrkState {
            base: brk.base,
            current: next,
        });
    } else {
        target = align_up(target, page_size);
    }

    let mut perms = MemPerm::USER;
    if prot & PROT_READ != 0 {
        perms |= MemPerm::READ;
    }
    if prot & PROT_WRITE != 0 {
        perms |= MemPerm::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        perms |= MemPerm::EXEC;
    }

    let max_attempts = if fixed { 1 } else { 128 };
    let mut attempts = 0usize;
    let mut mapped = false;

    while attempts < max_attempts && !mapped {
        let attempt_base = target;
        let result = space.with_page_table(|table, allocator| {
            for (mapped_pages, addr) in (attempt_base..attempt_base + len)
                .step_by(page_size)
                .enumerate()
            {
                let page = Page::new(VirtAddr::new(addr), PageSize(page_size));
                if fixed && let Ok(frame) = table.unmap(page) {
                    allocator.deallocate(frame);
                }
                let frame = allocator
                    .allocate(PageSize(page_size))
                    .ok_or(MapError::FrameAllocationFailed)?;
                if let Err(err) = table.map(page, frame, perms, allocator) {
                    if let Ok(frame) = table.unmap(page) {
                        allocator.deallocate(frame);
                    }
                    rollback_mapped(table, allocator, attempt_base, mapped_pages, page_size);
                    return Err(err);
                }

                let phys = match table.translate(page.start) {
                    Ok(phys) => phys,
                    Err(_) => {
                        rollback_mapped(
                            table,
                            allocator,
                            attempt_base,
                            mapped_pages + 1,
                            page_size,
                        );
                        return Err(MapError::InternalError);
                    }
                };
                let mapper = manager::phys_mapper();
                unsafe {
                    let ptr = mapper.phys_to_virt(phys).into_mut_ptr();
                    core::ptr::write_bytes(ptr, 0, page_size);
                }
            }
            Ok::<(), MapError>(())
        });

        match result {
            Ok(()) => {
                mapped = true;
            }
            Err(MapError::AlreadyMapped) if !fixed => {
                target = target
                    .checked_add(page_size)
                    .ok_or(SysError::InvalidArgument)?;
            }
            Err(_) => return Err(SysError::InvalidArgument),
        }

        attempts += 1;
    }

    if !mapped {
        return Err(SysError::InvalidArgument);
    }

    Ok(target as u64)
}

// NOTE: This is a minimal munmap implementation that only tears down page-aligned ranges.
fn handle_munmap(invocation: &SyscallInvocation) -> SysResult {
    let addr = invocation.arg(0).ok_or(SysError::InvalidArgument)? as usize;
    let len = invocation.arg(1).ok_or(SysError::InvalidArgument)? as usize;
    if len == 0 {
        return Err(SysError::InvalidArgument);
    }

    let page_size = PageSize::SIZE_4K.bytes();
    let addr = align_down(addr, page_size);
    let len = align_up(len, page_size);

    let pid = current_pid()?;
    let process = PROCESS_TABLE
        .process_handle(pid)
        .map_err(|_| SysError::InvalidArgument)?;
    let space = process.address_space();

    space
        .with_page_table(|table, allocator| {
            for addr in (addr..addr + len).step_by(page_size) {
                let page = Page::new(VirtAddr::new(addr), PageSize(page_size));
                if let Ok(frame) = table.unmap(page) {
                    allocator.deallocate(frame);
                }
            }
            Ok::<(), SysError>(())
        })
        .map_err(|_| SysError::InvalidArgument)?;

    Ok(0)
}

fn rollback_mapped<T: PageTableOps, A: FrameAllocator>(
    table: &mut T,
    allocator: &mut A,
    base: usize,
    pages: usize,
    page_size: usize,
) {
    let end = base.saturating_add(pages.saturating_mul(page_size));
    for addr in (base..end).step_by(page_size) {
        let page = Page::new(VirtAddr::new(addr), PageSize(page_size));
        if let Ok(frame) = table.unmap(page) {
            allocator.deallocate(frame);
        }
    }
}

fn errno_for(err: SysError) -> u16 {
    match err {
        SysError::NotImplemented => LinuxErrno::NoSys as u16,
        SysError::InvalidArgument => LinuxErrno::InvalidArgument as u16,
        SysError::NotFound => LinuxErrno::NoEntry as u16,
        SysError::BadAddress => LinuxErrno::BadAddress as u16,
        SysError::NotTty => LinuxErrno::NotTty as u16,
        SysError::IllegalSeek => LinuxErrno::IllegalSeek as u16,
    }
}

fn map_control_error(err: crate::util::stream::ControlError) -> SysError {
    match err {
        crate::util::stream::ControlError::Unsupported => SysError::NotTty,
        crate::util::stream::ControlError::Invalid => SysError::InvalidArgument,
        crate::util::stream::ControlError::BadAddress => SysError::BadAddress,
    }
}

fn read_cstring_with_user<T: PageTableOps>(
    user: &UserMemoryAccess<'_, T>,
    ptr: u64,
) -> Result<String, SysError> {
    const MAX: usize = 4096;
    let mut buf = [0u8; MAX];
    let mut len = 0usize;
    while len < MAX {
        let addr = (ptr as usize)
            .checked_add(len)
            .map(VirtAddr::new)
            .ok_or(SysError::InvalidArgument)?;
        user.read_bytes(addr, &mut buf[len..len + 1])
            .map_err(|_| SysError::BadAddress)?;
        if buf[len] == 0 {
            break;
        }
        len += 1;
    }
    if len == MAX && buf[MAX - 1] != 0 {
        return Err(SysError::InvalidArgument);
    }
    let slice = &buf[..len];
    let text = core::str::from_utf8(slice).map_err(|_| SysError::InvalidArgument)?;
    Ok(String::from(text))
}

fn read_u64_with_user<T: PageTableOps>(
    user: &UserMemoryAccess<'_, T>,
    ptr: u64,
) -> Result<u64, SysError> {
    let addr = VirtAddr::new(ptr as usize);
    user.read_u64(addr).map_err(|_| SysError::BadAddress)
}

fn read_u32(ptr: u64) -> Result<u32, SysError> {
    let mut buf = [0u8; 4];
    let addr = VirtAddr::new(ptr as usize);
    copy_from_user(&mut buf, addr).map_err(|_| SysError::BadAddress)?;
    Ok(u32::from_ne_bytes(buf))
}

fn write_u32(ptr: u64, value: u32) -> Result<(), SysError> {
    let addr = VirtAddr::new(ptr as usize);
    copy_to_user(addr, &value.to_ne_bytes()).map_err(|_| SysError::BadAddress)
}

fn read_sockaddr_in(ptr: u64, len: usize) -> Result<SocketAddr, SysError> {
    if len < SOCKADDR_IN_LEN {
        return Err(SysError::InvalidArgument);
    }
    let mut buf = [0u8; SOCKADDR_IN_LEN];
    let addr = VirtAddr::new(ptr as usize);
    copy_from_user(&mut buf, addr).map_err(|_| SysError::BadAddress)?;

    let family = u16::from_ne_bytes([buf[0], buf[1]]);
    if family != AF_INET {
        return Err(SysError::InvalidArgument);
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    Ok(SocketAddr::new(IpAddr::V4(ip), port))
}

fn write_sockaddr_in(addr: SocketAddr, ptr: u64) -> Result<(), SysError> {
    let ip = match addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err(SysError::InvalidArgument),
    };
    let port = addr.port();
    let mut buf = [0u8; SOCKADDR_IN_LEN];
    buf[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    let octets = ip.octets();
    buf[4..8].copy_from_slice(&octets);
    let dst = VirtAddr::new(ptr as usize);
    copy_to_user(dst, &buf).map_err(|_| SysError::BadAddress)
}

fn read_cstring_array_with_user<T: PageTableOps>(
    user: &UserMemoryAccess<'_, T>,
    ptr: u64,
    max: usize,
) -> Result<Vec<String>, SysError> {
    if ptr == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for index in 0..max {
        let offset = index
            .checked_mul(core::mem::size_of::<u64>())
            .ok_or(SysError::InvalidArgument)?;
        let entry_ptr = ptr
            .checked_add(offset as u64)
            .ok_or(SysError::InvalidArgument)?;
        let value = read_u64_with_user(user, entry_ptr)?;
        if value == 0 {
            break;
        }
        out.push(read_cstring_with_user(user, value)?);
    }
    Ok(out)
}

fn current_pid() -> Result<u64, SysError> {
    SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)
}

fn mode_from_meta(kind: NodeKind) -> u32 {
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;
    const REG_PERM: u32 = 0o644;
    const DIR_PERM: u32 = 0o755;
    const LNK_PERM: u32 = 0o777;
    const CHR_PERM: u32 = 0o666;

    match kind {
        NodeKind::Regular => S_IFREG | REG_PERM,
        NodeKind::Directory => S_IFDIR | DIR_PERM,
        NodeKind::Symlink => S_IFLNK | LNK_PERM,
        NodeKind::CharDevice => S_IFCHR | CHR_PERM,
        NodeKind::BlockDevice => S_IFBLK | CHR_PERM,
        NodeKind::Pipe => S_IFIFO | CHR_PERM,
        NodeKind::Socket => S_IFSOCK | CHR_PERM,
    }
}

fn writev_from_iovecs(
    pid: ProcessId,
    fd: u32,
    iovecs: &[LinuxIovec],
    total: &mut u64,
) -> Result<(), SysError> {
    const MAX_WRITE: usize = 4096;
    let mut chunk = [0u8; MAX_WRITE];
    for iov in iovecs {
        let base = usize::try_from(iov.base).map_err(|_| SysError::InvalidArgument)?;
        let len = usize::try_from(iov.len).map_err(|_| SysError::InvalidArgument)?;
        if len == 0 {
            continue;
        }
        let mut offset = 0usize;
        while offset < len {
            let part = (len - offset).min(MAX_WRITE);
            let addr = base
                .checked_add(offset)
                .map(VirtAddr::new)
                .ok_or(SysError::InvalidArgument)?;
            copy_from_user(&mut chunk[..part], addr).map_err(|_| SysError::BadAddress)?;
            let written = proc_fs::write_fd(pid, fd, &chunk[..part])
                .map_err(|_| SysError::InvalidArgument)?;
            *total = total.saturating_add(written as u64);
            if written < part {
                return Ok(());
            }
            offset += part;
        }
    }
    Ok(())
}

fn poll_once(
    fds: &mut [LinuxPollFd],
    process: &ProcessHandle,
    pollin: i16,
    pollnval: i16,
) -> usize {
    // NOTE: Non-TTY FDs are treated as immediately readable; this is a
    // compatibility shortcut for regular files, not pipes/sockets.
    let mut wants_input = false;
    let mut tty_flags = Vec::with_capacity(fds.len());
    for fd in fds.iter_mut() {
        fd.revents = 0;
        if fd.fd < 0 {
            tty_flags.push(false);
            continue;
        }
        if process.fd_table().entry(fd.fd as u32).is_err() {
            fd.revents = pollnval;
            tty_flags.push(false);
            continue;
        }
        let is_tty = file_is_tty(process, fd.fd);
        tty_flags.push(is_tty);
        if (fd.events & pollin) != 0 {
            if is_tty {
                wants_input = true;
            } else {
                fd.revents |= pollin;
            }
        }
    }

    let input_ready = if wants_input {
        crate::device::tty::global_tty().input_available()
    } else {
        false
    };

    let mut ready = 0usize;
    for (fd, is_tty) in fds.iter_mut().zip(tty_flags.iter()) {
        if fd.revents != 0 {
            ready += 1;
            continue;
        }
        if *is_tty && (fd.events & pollin) != 0 && input_ready {
            fd.revents |= pollin;
        }
        if fd.revents != 0 {
            ready += 1;
        }
    }
    ready
}

fn file_is_tty(process: &ProcessHandle, fd: i32) -> bool {
    const IOCTL_TIOCGWINSZ: u64 = 0x5413;

    let entry = match process.fd_table().entry(fd as u32) {
        Ok(entry) => entry,
        Err(_) => return false,
    };
    let mut winsize = LinuxWinsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let access = KernelControlAccess;
    let request = ControlRequest::new(
        IOCTL_TIOCGWINSZ,
        core::ptr::addr_of_mut!(winsize) as u64,
        &access,
    );
    match entry.file().ioctl(&request) {
        Ok(_) => true,
        Err(ControlError::Unsupported) => false,
        Err(_) => false,
    }
}

fn encode_wait_status(code: i32) -> u32 {
    ((code as u32) & 0xFF) << 8
}

fn spawn_error_to_sys(err: crate::thread::SpawnError) -> SysError {
    match err {
        crate::thread::SpawnError::OutOfMemory => SysError::InvalidArgument,
        crate::thread::SpawnError::SchedulerNotReady => SysError::InvalidArgument,
        crate::thread::SpawnError::Process(_) => SysError::InvalidArgument,
        crate::thread::SpawnError::UserStack(_) => SysError::InvalidArgument,
    }
}

#[repr(u64)]
enum LinuxOpenFlags {
    Creat = 0x40,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxIovec {
    base: u64,
    len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxPollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

struct KernelControlAccess;

impl ControlAccess for KernelControlAccess {
    // NOTE: Kernel-only access for ioctl helpers; never expose this to user pointers.
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), ControlError> {
        if dst.is_empty() {
            return Ok(());
        }
        let ptr = addr as *const u8;
        if ptr.is_null() {
            return Err(ControlError::BadAddress);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(ptr, dst.as_mut_ptr(), dst.len());
        }
        Ok(())
    }

    fn write(&self, addr: u64, src: &[u8]) -> Result<(), ControlError> {
        if src.is_empty() {
            return Ok(());
        }
        let ptr = addr as *mut u8;
        if ptr.is_null() {
            return Err(ControlError::BadAddress);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), ptr, src.len());
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atime: i64,
    st_atime_nsec: i64,
    st_mtime: i64,
    st_mtime_nsec: i64,
    st_ctime: i64,
    st_ctime_nsec: i64,
    __reserved: [i64; 3],
}

impl LinuxStat {
    fn from_meta(mode: u32, size: u64) -> Self {
        let size = size as i64;
        let blksize = 4096i64;
        let blocks = (size + 511) / 512;
        Self {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 1,
            st_mode: mode,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: size,
            st_blksize: blksize,
            st_blocks: blocks,
            st_atime: 0,
            st_atime_nsec: 0,
            st_mtime: 0,
            st_mtime_nsec: 0,
            st_ctime: 0,
            st_ctime_nsec: 0,
            __reserved: [0; 3],
        }
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::tty::global_tty;
    use crate::fs::DirNode;
    use crate::mem::addr::VirtAddr;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::process::ProcessDomain;
    use crate::test::kernel_test_case;
    use crate::thread::SCHEDULER;

    #[kernel_test_case]
    fn write_rejects_non_standard_fd() {
        println!("[test] write_rejects_non_standard_fd");

        let invocation = SyscallInvocation::new(LinuxSyscall::Write as u64, [3, 0, 1, 0, 0, 0]);
        match dispatch(&invocation, None) {
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
        let result = dispatch(&invocation, None);
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
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(written)) => assert_eq!(written, msg.len() as u64),
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn writev_reports_length_written() {
        println!("[test] writev_reports_length_written");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let a = b"hi";
        let b = b"there";
        let iov = [
            LinuxIovec {
                base: a.as_ptr() as u64,
                len: a.len() as u64,
            },
            LinuxIovec {
                base: b.as_ptr() as u64,
                len: b.len() as u64,
            },
        ];
        let invocation = SyscallInvocation::new(
            LinuxSyscall::Writev as u64,
            [1, iov.as_ptr() as u64, iov.len() as u64, 0, 0, 0],
        );
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(written)) => {
                assert_eq!(written, (a.len() + b.len()) as u64)
            }
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn poll_reports_tty_input() {
        println!("[test] poll_reports_tty_input");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let tty = global_tty();
        tty.push_input(b"X");

        let mut fds = [LinuxPollFd {
            fd: 0,
            events: 0x0001,
            revents: 0,
        }];
        let invocation = SyscallInvocation::new(
            LinuxSyscall::Poll as u64,
            [fds.as_mut_ptr() as u64, fds.len() as u64, 0, 0, 0, 0],
        );
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(ready)) => {
                assert_eq!(ready, 1);
                assert_eq!(fds[0].revents & 0x0001, 0x0001);
            }
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn getcwd_returns_root_path() {
        println!("[test] getcwd_returns_root_path");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");

        let mut buf = [0u8; 8];
        let invocation = SyscallInvocation::new(
            LinuxSyscall::GetCwd as u64,
            [buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0],
        );
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(len)) => {
                assert_eq!(len, 2);
                assert_eq!(buf[0], b'/');
                assert_eq!(buf[1], 0);
            }
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn fcntl_dupfd_sets_cloexec() {
        println!("[test] fcntl_dupfd_sets_cloexec");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");

        let dup_inv = SyscallInvocation::new(LinuxSyscall::Fcntl as u64, [0, 1030, 10, 0, 0, 0]);
        let new_fd = match dispatch(&dup_inv, None) {
            DispatchResult::Completed(Ok(fd)) => fd as u32,
            other => panic!("unexpected dispatch result: {:?}", other),
        };
        assert_eq!(new_fd, 10);

        let get_inv =
            SyscallInvocation::new(LinuxSyscall::Fcntl as u64, [new_fd as u64, 1, 0, 0, 0, 0]);
        match dispatch(&get_inv, None) {
            DispatchResult::Completed(Ok(flags)) => assert_eq!(flags, 1),
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn stat_reports_file_size() {
        println!("[test] stat_reports_file_size");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");

        let root = crate::fs::memfs::MemDirectory::new();
        crate::fs::force_replace_root(root.clone());
        let file = root.create_file("note").expect("create file");
        let payload = b"abc";
        let handle = file.open(crate::fs::OpenOptions::new(0)).expect("open");
        let _ = handle.write(payload).expect("write");

        let mut stat = core::mem::MaybeUninit::<LinuxStat>::zeroed();
        let path = b"/note\0";
        let invocation = SyscallInvocation::new(
            LinuxSyscall::Stat as u64,
            [path.as_ptr() as u64, stat.as_mut_ptr() as u64, 0, 0, 0, 0],
        );
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(0)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }

        let stat = unsafe { stat.assume_init() };
        assert_eq!(stat.st_size, payload.len() as i64);
        assert_ne!(stat.st_mode, 0);
    }

    #[kernel_test_case]
    fn brk_tracks_current_break() {
        println!("[test] brk_tracks_current_break");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let pid = PROCESS_TABLE.kernel_process_id().expect("kernel pid");
        let process = PROCESS_TABLE.process_handle(pid).expect("process handle");
        process.set_brk_base(VirtAddr::new(0x600000));

        let get_inv = SyscallInvocation::new(LinuxSyscall::Brk as u64, [0, 0, 0, 0, 0, 0]);
        match dispatch(&get_inv, None) {
            DispatchResult::Completed(Ok(val)) => assert_eq!(val, 0x600000),
            other => panic!("unexpected dispatch result: {:?}", other),
        }

        let set_inv = SyscallInvocation::new(LinuxSyscall::Brk as u64, [0x601000, 0, 0, 0, 0, 0]);
        match dispatch(&set_inv, None) {
            DispatchResult::Completed(Ok(val)) => assert_eq!(val, 0x601000),
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn arch_prctl_rejects_unknown_code() {
        println!("[test] arch_prctl_rejects_unknown_code");

        let invocation =
            SyscallInvocation::new(LinuxSyscall::ArchPrctl as u64, [0x9999, 0, 0, 0, 0, 0]);
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Err(SysError::InvalidArgument)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn arch_prctl_accepts_set_fs() {
        println!("[test] arch_prctl_accepts_set_fs");

        let invocation =
            SyscallInvocation::new(LinuxSyscall::ArchPrctl as u64, [0x1002, 0, 0, 0, 0, 0]);
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(0)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn wait4_reports_exit_status() {
        println!("[test] wait4_reports_exit_status");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let parent = PROCESS_TABLE.kernel_process_id().expect("kernel pid");
        let pid = PROCESS_TABLE
            .create_user_process("wait4-test", ProcessDomain::HostLinux)
            .expect("create process");
        let proc = PROCESS_TABLE.process_handle(pid).expect("process handle");
        proc.set_parent(parent);
        proc.set_exit_code(7);
        proc.mark_terminated();

        let mut status = 0u32;
        let invocation = SyscallInvocation::new(
            LinuxSyscall::Wait4 as u64,
            [pid, &mut status as *mut u32 as u64, 0, 0, 0, 0],
        );
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(val)) => assert_eq!(val, pid),
            other => panic!("unexpected dispatch result: {:?}", other),
        }
        assert_eq!(status, 7u32 << 8);
    }

    #[kernel_test_case]
    fn wait4_any_child_picks_terminated_one() {
        println!("[test] wait4_any_child_picks_terminated_one");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let parent = PROCESS_TABLE.kernel_process_id().expect("kernel pid");
        let child = PROCESS_TABLE
            .create_user_process("wait4-any", ProcessDomain::HostLinux)
            .expect("create process");
        let proc = PROCESS_TABLE.process_handle(child).expect("process handle");
        proc.set_parent(parent);
        proc.set_exit_code(3);
        proc.mark_terminated();

        let mut status = 0u32;
        let invocation = SyscallInvocation::new(
            LinuxSyscall::Wait4 as u64,
            [u64::MAX, &mut status as *mut u32 as u64, 0, 0, 0, 0],
        );
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(val)) => assert_eq!(val, child),
            other => panic!("unexpected dispatch result: {:?}", other),
        }
        assert_eq!(status, 3u32 << 8);
    }

    #[kernel_test_case]
    fn wait4_returns_nohang_when_running() {
        println!("[test] wait4_returns_nohang_when_running");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let parent = PROCESS_TABLE.kernel_process_id().expect("kernel pid");
        let child = PROCESS_TABLE
            .create_user_process("wait4-running", ProcessDomain::HostLinux)
            .expect("create process");
        let proc = PROCESS_TABLE.process_handle(child).expect("process handle");
        proc.set_parent(parent);

        let invocation = SyscallInvocation::new(LinuxSyscall::Wait4 as u64, [child, 0, 1, 0, 0, 0]);
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(0)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn stub_syscalls_return_success() {
        println!("[test] stub_syscalls_return_success");

        for num in [
            LinuxSyscall::RtSigaction,
            LinuxSyscall::RtSigprocmask,
            LinuxSyscall::SetTidAddress,
        ] {
            let invocation = SyscallInvocation::new(num as u64, [0; 6]);
            match dispatch(&invocation, None) {
                DispatchResult::Completed(Ok(0)) => {}
                other => panic!("unexpected dispatch result: {:?}", other),
            }
        }
    }

    #[kernel_test_case]
    fn fork_requires_trap_frame() {
        println!("[test] fork_requires_trap_frame");

        let invocation = SyscallInvocation::new(LinuxSyscall::Fork as u64, [0; 6]);
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Err(SysError::InvalidArgument)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn execve_requires_trap_frame() {
        println!("[test] execve_requires_trap_frame");

        let invocation = SyscallInvocation::new(LinuxSyscall::Execve as u64, [0; 6]);
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Err(SysError::InvalidArgument)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn mmap_maps_and_munmaps_pages() {
        println!("[test] mmap_maps_and_munmaps_pages");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");

        const MAP_PRIVATE: u64 = 0x02;
        const MAP_FIXED: u64 = 0x10;
        const MAP_ANON: u64 = 0x20;
        const PROT_READ: u64 = 0x1;
        const PROT_WRITE: u64 = 0x2;

        let addr = 0x500000u64;
        let len = 0x2000u64;
        let mmap = SyscallInvocation::new(
            LinuxSyscall::Mmap as u64,
            [
                addr,
                len,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON | MAP_FIXED,
                u64::MAX,
                0,
            ],
        );
        match dispatch(&mmap, None) {
            DispatchResult::Completed(Ok(val)) => assert_eq!(val, addr),
            other => panic!("unexpected dispatch result: {:?}", other),
        }

        let src = [0xABu8; 16];
        copy_to_user(VirtAddr::new(addr as usize), &src).expect("copy to user");
        let mut dst = [0u8; 16];
        copy_from_user(&mut dst, VirtAddr::new(addr as usize)).expect("copy from user");
        assert_eq!(dst, src);

        let munmap = SyscallInvocation::new(LinuxSyscall::Munmap as u64, [addr, len, 0, 0, 0, 0]);
        match dispatch(&munmap, None) {
            DispatchResult::Completed(Ok(0)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }

        let pid = SCHEDULER.current_process_id().expect("current pid");
        let space = PROCESS_TABLE.address_space(pid).expect("address space");
        space.with_page_table(|table, _| {
            assert!(table.translate(VirtAddr::new(addr as usize)).is_err());
        });
    }
}
