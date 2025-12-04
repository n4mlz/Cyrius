//! Minimal launcher for Linux ELF binaries invoked via the shell.

use alloc::string::{String, ToString};

use crate::fs::{VfsError, VfsPath};
use crate::loader::linux::{self, LinuxLoadError};
use crate::process::{PROCESS_TABLE, ProcessError, ProcessId};
use crate::syscall::Abi;
use crate::thread::{SCHEDULER, SpawnError};

/// Errors surfaced while launching or supervising a Linux guest process.
#[derive(Debug)]
pub enum RunError {
    Path(VfsError),
    Process(ProcessError),
    Loader(LinuxLoadError),
    Spawn(SpawnError),
}

impl From<VfsError> for RunError {
    fn from(err: VfsError) -> Self {
        Self::Path(err)
    }
}

impl From<ProcessError> for RunError {
    fn from(err: ProcessError) -> Self {
        Self::Process(err)
    }
}

impl From<LinuxLoadError> for RunError {
    fn from(err: LinuxLoadError) -> Self {
        Self::Loader(err)
    }
}

impl From<SpawnError> for RunError {
    fn from(err: SpawnError) -> Self {
        Self::Spawn(err)
    }
}

/// Launch a Linux ELF image as a new process, wait until all of its threads finish, and return.
///
/// The loader expects a static, non-PIE ELF64 image and rewrites `syscall` instructions to
/// `int 0x80` to reuse the existing trap vector. File descriptors are not propagated; `write`
/// targets the kernel console directly and other descriptors are rejected.
pub fn run_and_wait(origin_pid: ProcessId, raw_path: &str) -> Result<(), RunError> {
    let abs = absolute_path(origin_pid, raw_path)?;
    crate::println!(
        "[linux] launch {abs} (static ELF64, no PIE or dynamic linking; limited syscalls supported)"
    );
    let pid = launch_process(&abs)?;
    wait_for_exit(pid);
    Ok(())
}

fn launch_process(path: &str) -> Result<ProcessId, RunError> {
    let pid = PROCESS_TABLE.create_user_process("linux-proc")?;
    PROCESS_TABLE.set_abi(pid, Abi::Linux)?;

    let program = linux::load_elf(pid, path)?;
    let _tid = SCHEDULER.spawn_user_thread_with_stack(
        pid,
        "linux-main",
        program.entry,
        program.user_stack,
        program.stack_pointer,
    )?;

    Ok(pid)
}

fn wait_for_exit(pid: ProcessId) {
    while PROCESS_TABLE
        .thread_count(pid)
        .map(|count| count > 0)
        .unwrap_or(false)
    {
        core::hint::spin_loop();
    }
}

fn absolute_path(origin_pid: ProcessId, raw: &str) -> Result<String, RunError> {
    let cwd = PROCESS_TABLE.cwd(origin_pid)?;
    let parsed = VfsPath::parse(raw)?;
    let abs = if parsed.is_absolute() {
        parsed
    } else {
        cwd.join(&parsed)?
    };
    Ok(abs.to_string())
}
