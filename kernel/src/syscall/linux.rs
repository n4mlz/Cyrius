use super::{DispatchResult, SysError, SysResult, SyscallInvocation};

use alloc::string::String;
use alloc::vec::Vec;

use crate::arch::Arch;
use crate::arch::api::{ArchPageTableAccess, ArchThread};
use crate::fs::{FileType, VfsPath, with_vfs};
use crate::mem::addr::{Addr, MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr, align_up};
use crate::mem::paging::{FrameAllocator, MapError, PageTableOps};
use crate::mem::user::{UserMemoryAccess, copy_from_user, copy_to_user, with_user_slice};
use crate::process::fs as proc_fs;
use crate::process::{PROCESS_TABLE, ProcessId};
use crate::thread::SCHEDULER;
use crate::trap::CurrentTrapFrame;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxErrno {
    NoEntry = 2,
    NoSys = 38,
    InvalidArgument = 22,
    BadAddress = 14,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxSyscall {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Stat = 4,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    Ioctl = 16,
    Writev = 20,
    GetPid = 39,
    Fork = 57,
    Execve = 59,
    Exit = 60,
    Wait4 = 61,
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
            12 => Some(Self::Brk),
            13 => Some(Self::RtSigaction),
            14 => Some(Self::RtSigprocmask),
            16 => Some(Self::Ioctl),
            20 => Some(Self::Writev),
            39 => Some(Self::GetPid),
            57 => Some(Self::Fork),
            59 => Some(Self::Execve),
            60 => Some(Self::Exit),
            61 => Some(Self::Wait4),
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
        Some(LinuxSyscall::Brk) => DispatchResult::Completed(handle_brk(invocation)),
        Some(LinuxSyscall::Fork) => handle_fork(invocation, frame),
        Some(LinuxSyscall::Execve) => handle_execve(invocation, frame),
        Some(LinuxSyscall::Wait4) => DispatchResult::Completed(handle_wait4(invocation)),
        Some(LinuxSyscall::ArchPrctl) => DispatchResult::Completed(handle_arch_prctl(invocation)),
        // These syscalls are currently stubbed and always report success (0).
        Some(LinuxSyscall::Ioctl) => DispatchResult::Completed(handle_stub(invocation)),
        Some(LinuxSyscall::RtSigaction) => DispatchResult::Completed(handle_stub(invocation)),
        Some(LinuxSyscall::RtSigprocmask) => DispatchResult::Completed(handle_stub(invocation)),
        Some(LinuxSyscall::SetTidAddress) => DispatchResult::Completed(handle_stub(invocation)),
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

fn handle_getpid(_invocation: &SyscallInvocation) -> SysResult {
    let pid = SCHEDULER
        .current_process_id()
        .ok_or(SysError::InvalidArgument)?;
    Ok(pid)
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
    let cwd = proc_fs::cwd(pid).map_err(|_| SysError::InvalidArgument)?;
    let abs = VfsPath::resolve(&path, &cwd).map_err(|_| SysError::InvalidArgument)?;
    let node = with_vfs(|vfs| vfs.open_absolute(&abs)).map_err(|err| match err {
        crate::fs::VfsError::NotFound => SysError::NotFound,
        _ => SysError::InvalidArgument,
    })?;
    let meta = node.metadata().map_err(|_| SysError::InvalidArgument)?;

    let mode = mode_from_meta(meta.file_type);
    let stat = LinuxStat::from_meta(mode, meta.size);
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

fn handle_stub(_invocation: &SyscallInvocation) -> SysResult {
    // Stubbed syscalls currently behave as no-ops and return success.
    Ok(0)
}

fn errno_for(err: SysError) -> u16 {
    match err {
        SysError::NotImplemented => LinuxErrno::NoSys as u16,
        SysError::InvalidArgument => LinuxErrno::InvalidArgument as u16,
        SysError::NotFound => LinuxErrno::NoEntry as u16,
        SysError::BadAddress => LinuxErrno::BadAddress as u16,
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

fn mode_from_meta(file_type: FileType) -> u32 {
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const REG_PERM: u32 = 0o644;
    const DIR_PERM: u32 = 0o755;
    const LNK_PERM: u32 = 0o777;

    match file_type {
        FileType::File => S_IFREG | REG_PERM,
        FileType::Directory => S_IFDIR | DIR_PERM,
        FileType::Symlink => S_IFLNK | LNK_PERM,
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
    use crate::fs::Directory;
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
    fn stat_reports_file_size() {
        println!("[test] stat_reports_file_size");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");

        let root = crate::fs::memfs::MemDirectory::new();
        crate::fs::force_replace_root(root.clone());
        let file = root.create_file("note").expect("create file");
        let payload = b"abc";
        let _ = file.write_at(0, payload).expect("write");

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
            [pid as u64, &mut status as *mut u32 as u64, 0, 0, 0, 0],
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

        let invocation =
            SyscallInvocation::new(LinuxSyscall::Wait4 as u64, [child as u64, 0, 1, 0, 0, 0]);
        match dispatch(&invocation, None) {
            DispatchResult::Completed(Ok(0)) => {}
            other => panic!("unexpected dispatch result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn stub_syscalls_return_success() {
        println!("[test] stub_syscalls_return_success");

        for num in [
            LinuxSyscall::Ioctl,
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
}
