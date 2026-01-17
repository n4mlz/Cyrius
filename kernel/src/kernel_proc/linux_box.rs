//! Minimal launcher for Linux ELF binaries invoked via the shell.

use alloc::string::{String, ToString};

use crate::fs::{VfsError, VfsPath};
use crate::loader::linux::{self, LinuxLoadError};
use crate::process::fs as proc_fs;
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
/// `int 0x80` to reuse the existing trap vector. Standard file descriptors (0/1/2) are backed
/// by the global tty, and other descriptors use the per-process VFS/FdTable.
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
    let pid = PROCESS_TABLE.create_user_process_with_abi("linux-proc", Abi::Linux)?;

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
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::halt();
        #[cfg(not(target_arch = "x86_64"))]
        core::hint::spin_loop();
    }
}

fn absolute_path(origin_pid: ProcessId, raw: &str) -> Result<String, RunError> {
    let cwd = proc_fs::cwd(origin_pid)?;
    let abs = VfsPath::resolve(raw, &cwd)?;
    Ok(abs.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::api::ArchLinuxElfPlatform;
    use crate::fs::Directory;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::fs::tty::global_tty;
    use crate::loader::DefaultLinuxElfPlatform;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::test::kernel_test_case;
    use crate::thread::{SCHEDULER, SchedulerError};
    use alloc::vec;
    use alloc::vec::Vec;
    use core::mem::size_of;

    const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
    const ELF_CLASS_64: u8 = 2;
    const ELF_DATA_LSB: u8 = 1;
    const ELF_VERSION_CURRENT: u8 = 1;
    const ELF_TYPE_EXEC: u16 = 2;
    const PT_LOAD: u32 = 1;

    #[repr(C)]
    struct ProgramHeaderRaw {
        typ: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        _paddr: u64,
        file_size: u64,
        mem_size: u64,
        align: u64,
    }

    #[kernel_test_case]
    fn linux_binary_reads_stdin_and_file() {
        println!("[test] linux_binary_reads_stdin_and_file");

        let _ = PROCESS_TABLE.init_kernel();
        SCHEDULER.init().expect("scheduler init");
        let started = match SCHEDULER.start() {
            Ok(()) => true,
            Err(SchedulerError::AlreadyStarted) => false,
            Err(err) => panic!("scheduler start failed: {:?}", err),
        };

        let root = MemDirectory::new();
        force_replace_root(root.clone());

        let file = root.create_file("msg.txt").expect("create msg.txt");
        let _ = file.write_at(0, b"FILE\n").expect("write msg.txt");

        let elf = build_linux_syscall_elf();
        let bin = root.create_file("demo").expect("create demo");
        let _ = bin.write_at(0, &elf).expect("write demo");

        let tty = global_tty();
        tty.clear_output();
        tty.push_input(b"IN\n");

        let kernel_pid = PROCESS_TABLE.kernel_process_id().expect("kernel pid");
        run_and_wait(kernel_pid, "/demo").expect("run linux demo");

        let output = tty.drain_output();
        assert_eq!(output, b"IN\nFILE\n");

        if started {
            SCHEDULER.shutdown();
        }
    }

    fn build_linux_syscall_elf() -> Vec<u8> {
        const TEXT_OFFSET: usize = 0x1000;
        const DATA_OFFSET: usize = 0x2000;
        const TEXT_VADDR: u64 = 0x400000;
        const DATA_VADDR: u64 = 0x401000;
        const ENTRY: u64 = 0x400080;
        const TEXT_SIZE: usize = 0x200;
        const DATA_SIZE: usize = 0x200;
        const PATH_ADDR: u64 = DATA_VADDR;
        const STDIN_BUF: u64 = DATA_VADDR + 0x20;
        const FILE_BUF: u64 = DATA_VADDR + 0x40;

        let mut buf = vec![0u8; DATA_OFFSET + DATA_SIZE];

        buf[0..4].copy_from_slice(ELF_MAGIC);
        buf[4] = ELF_CLASS_64;
        buf[5] = ELF_DATA_LSB;
        buf[6] = ELF_VERSION_CURRENT;
        buf[16..18].copy_from_slice(&ELF_TYPE_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&DefaultLinuxElfPlatform::machine_id().to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        buf[24..32].copy_from_slice(&ENTRY.to_le_bytes());
        buf[32..40].copy_from_slice(&(64u64).to_le_bytes());
        buf[54..56].copy_from_slice(&(size_of::<ProgramHeaderRaw>() as u16).to_le_bytes());
        buf[56..58].copy_from_slice(&(2u16).to_le_bytes());

        write_ph(
            &mut buf[64..64 + size_of::<ProgramHeaderRaw>()],
            ProgramHeaderRaw {
                typ: PT_LOAD,
                flags: 0x5,
                offset: TEXT_OFFSET as u64,
                vaddr: TEXT_VADDR,
                _paddr: 0,
                file_size: TEXT_SIZE as u64,
                mem_size: TEXT_SIZE as u64,
                align: 0x1000,
            },
        );

        write_ph(
            &mut buf[64 + size_of::<ProgramHeaderRaw>()..64 + 2 * size_of::<ProgramHeaderRaw>()],
            ProgramHeaderRaw {
                typ: PT_LOAD,
                flags: 0x6,
                offset: DATA_OFFSET as u64,
                vaddr: DATA_VADDR,
                _paddr: 0,
                file_size: DATA_SIZE as u64,
                mem_size: DATA_SIZE as u64,
                align: 0x1000,
            },
        );

        let mut code = Vec::new();
        code.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0
        code.extend_from_slice(&[0xBF, 0x00, 0x00, 0x00, 0x00]); // mov edi, 0
        code.extend_from_slice(&[0x48, 0xBE]);
        code.extend_from_slice(&STDIN_BUF.to_le_bytes());
        code.extend_from_slice(&[0xBA, 0x10, 0x00, 0x00, 0x00]); // mov edx, 16
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        code.extend_from_slice(&[0xBF, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
        code.extend_from_slice(&[0x48, 0xBE]);
        code.extend_from_slice(&STDIN_BUF.to_le_bytes());
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0xB8, 0x02, 0x00, 0x00, 0x00]); // mov eax, 2
        code.extend_from_slice(&[0x48, 0xBF]);
        code.extend_from_slice(&PATH_ADDR.to_le_bytes());
        code.extend_from_slice(&[0xBE, 0x00, 0x00, 0x00, 0x00]); // mov esi, 0
        code.extend_from_slice(&[0xBA, 0x00, 0x00, 0x00, 0x00]); // mov edx, 0
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0x48, 0x89, 0xC3]); // mov rbx, rax
        code.extend_from_slice(&[0xB8, 0x00, 0x00, 0x00, 0x00]); // mov eax, 0
        code.extend_from_slice(&[0x48, 0x89, 0xDF]); // mov rdi, rbx
        code.extend_from_slice(&[0x48, 0xBE]);
        code.extend_from_slice(&FILE_BUF.to_le_bytes());
        code.extend_from_slice(&[0xBA, 0x40, 0x00, 0x00, 0x00]); // mov edx, 64
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0x48, 0x89, 0xC2]); // mov rdx, rax
        code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
        code.extend_from_slice(&[0xBF, 0x01, 0x00, 0x00, 0x00]); // mov edi, 1
        code.extend_from_slice(&[0x48, 0xBE]);
        code.extend_from_slice(&FILE_BUF.to_le_bytes());
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0xB8, 0x03, 0x00, 0x00, 0x00]); // mov eax, 3
        code.extend_from_slice(&[0x48, 0x89, 0xDF]); // mov rdi, rbx
        code.extend_from_slice(&[0x0F, 0x05]); // syscall
        code.extend_from_slice(&[0xB8, 0x3C, 0x00, 0x00, 0x00]); // mov eax, 60
        code.extend_from_slice(&[0x31, 0xFF]); // xor edi, edi
        code.extend_from_slice(&[0x0F, 0x05]); // syscall

        let text_base = TEXT_OFFSET + (ENTRY as usize - TEXT_VADDR as usize);
        buf[text_base..text_base + code.len()].copy_from_slice(&code);

        let path_bytes = b"/msg.txt\0";
        let path_offset = DATA_OFFSET;
        buf[path_offset..path_offset + path_bytes.len()].copy_from_slice(path_bytes);

        buf
    }

    fn write_ph(slot: &mut [u8], ph: ProgramHeaderRaw) {
        slot[0..4].copy_from_slice(&ph.typ.to_le_bytes());
        slot[4..8].copy_from_slice(&ph.flags.to_le_bytes());
        slot[8..16].copy_from_slice(&ph.offset.to_le_bytes());
        slot[16..24].copy_from_slice(&ph.vaddr.to_le_bytes());
        slot[24..32].copy_from_slice(&ph._paddr.to_le_bytes());
        slot[32..40].copy_from_slice(&ph.file_size.to_le_bytes());
        slot[40..48].copy_from_slice(&ph.mem_size.to_le_bytes());
        slot[48..56].copy_from_slice(&ph.align.to_le_bytes());
    }
}
