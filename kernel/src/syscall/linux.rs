use super::{DispatchResult, SysError, SysResult, SyscallInvocation};

use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::Arch;
use crate::arch::api::{ArchPageTableAccess, ArchThread};
use crate::fs::NodeKind;
use crate::mem::addr::{
    Addr, MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr, align_down, align_up,
};
use crate::mem::manager;
use crate::mem::paging::{FrameAllocator, MapError, PageTableOps, PhysMapper};
use crate::mem::user::{UserMemoryAccess, copy_from_user, copy_to_user, with_user_slice};
use crate::process::fs as proc_fs;
use crate::process::{ControllingTty, PROCESS_TABLE, ProcessId};
use crate::thread::SCHEDULER;
use crate::trap::CurrentTrapFrame;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxErrno {
    NoEntry = 2,
    NoSys = 38,
    InvalidArgument = 22,
    BadAddress = 14,
    NotTty = 25,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSyscall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Mmap = 9,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    Ioctl = 16,
    Writev = 20,
    GetPid = 39,
    Fcntl = 72,
    SetPgid = 109,
    GetPpid = 110,
    GetPgrp = 111,
    SetSid = 112,
    Fork = 57,
    Execve = 59,
    Exit = 60,
    Wait4 = 61,
    GetUid = 102,
    GetGid = 104,
    SetUid = 105,
    SetGid = 106,
    GetPgid = 121,
    GetSid = 124,
    ArchPrctl = 158,
    SetTidAddress = 218,
}

impl LinuxSyscall {
    pub fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            2 => Some(Self::Open),
            3 => Some(Self::Close),
            4 => Some(Self::Stat),
            9 => Some(Self::Mmap),
            11 => Some(Self::Munmap),
            12 => Some(Self::Brk),
            13 => Some(Self::RtSigaction),
            14 => Some(Self::RtSigprocmask),
            16 => Some(Self::Ioctl),
            20 => Some(Self::Writev),
            39 => Some(Self::GetPid),
            72 => Some(Self::Fcntl),
            109 => Some(Self::SetPgid),
            110 => Some(Self::GetPpid),
            111 => Some(Self::GetPgrp),
            112 => Some(Self::SetSid),
            57 => Some(Self::Fork),
            59 => Some(Self::Execve),
            60 => Some(Self::Exit),
            61 => Some(Self::Wait4),
            102 => Some(Self::GetUid),
            104 => Some(Self::GetGid),
            105 => Some(Self::SetUid),
            106 => Some(Self::SetGid),
            121 => Some(Self::GetPgid),
            124 => Some(Self::GetSid),
            158 => Some(Self::ArchPrctl),
            218 => Some(Self::SetTidAddress),
            _ => None,
        }
    }
}

/// Minimal Linux syscall table supporting write/getpid/exit placeholders.
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
        Some(LinuxSyscall::Mmap) => DispatchResult::Completed(handle_mmap(invocation)),
        Some(LinuxSyscall::Munmap) => DispatchResult::Completed(handle_munmap(invocation)),
        Some(LinuxSyscall::Brk) => DispatchResult::Completed(handle_brk(invocation)),
        Some(LinuxSyscall::Fcntl) => DispatchResult::Completed(handle_fcntl(invocation)),
        Some(LinuxSyscall::SetPgid) => DispatchResult::Completed(handle_setpgid(invocation)),
        Some(LinuxSyscall::GetPpid) => DispatchResult::Completed(handle_getppid(invocation)),
        Some(LinuxSyscall::GetPgrp) => DispatchResult::Completed(handle_getpgrp(invocation)),
        Some(LinuxSyscall::SetSid) => DispatchResult::Completed(handle_setsid(invocation)),
        Some(LinuxSyscall::Fork) => handle_fork(invocation, frame),
        Some(LinuxSyscall::Execve) => handle_execve(invocation, frame),
        Some(LinuxSyscall::Wait4) => DispatchResult::Completed(handle_wait4(invocation)),
        Some(LinuxSyscall::ArchPrctl) => DispatchResult::Completed(handle_arch_prctl(invocation)),
        Some(LinuxSyscall::Ioctl) => DispatchResult::Completed(handle_ioctl(invocation)),
        // These syscalls are currently stubbed and always report success (0).
        Some(LinuxSyscall::RtSigaction) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::RtSigprocmask) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::SetTidAddress) => DispatchResult::Completed(Ok(0)),
        // NOTE: UID/GID syscalls are stubbed to 0 for now; user/cred support is not implemented yet.
        Some(LinuxSyscall::GetUid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::GetGid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::SetUid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::SetGid) => DispatchResult::Completed(Ok(0)),
        Some(LinuxSyscall::GetPid) => DispatchResult::Completed(handle_getpid(invocation)),
        Some(LinuxSyscall::GetPgid) => DispatchResult::Completed(handle_getpgid(invocation)),
        Some(LinuxSyscall::GetSid) => DispatchResult::Completed(handle_getsid(invocation)),
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

fn handle_brk(invocation: &SyscallInvocation) -> SysResult {
    // TODO: This is a grow-only brk; shrinking does not unmap pages and no heap upper bound
    // is enforced yet. The behavior is enough for busybox's basic allocator path.
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
                unsafe {
                    core::ptr::write_bytes(
                        VirtAddr::new(addr).into_mut_ptr(),
                        0,
                        PageSize::SIZE_4K.bytes(),
                    );
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
    let offset = parent_rsp.saturating_sub(parent_stack.base.as_raw());
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
    if let Err(err) = SCHEDULER.clear_current_user_stack() {
        return DispatchResult::Completed(Err(spawn_error_to_sys(err)));
    }

    if <Arch as ArchThread>::clear_user_mappings(&process.address_space()).is_err() {
        return DispatchResult::Completed(Err(SysError::InvalidArgument));
    }

    let program = match crate::loader::linux::load_elf(pid, &path) {
        Ok(program) => program,
        Err(_) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
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
            Err(_) => return DispatchResult::Completed(Err(SysError::InvalidArgument)),
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

        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::halt();
        #[cfg(not(target_arch = "x86_64"))]
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

    crate::arch::x86_64::set_fs_base(value);
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
