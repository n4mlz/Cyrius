use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::Arch;
use crate::arch::api::ArchDevice;
use crate::device::char::CharDevice;
use crate::fs::DirEntry;
use crate::kernel_proc::{linux_box, oci_runtime, tar};
use crate::loader::linux::LinuxLoadError;
use crate::process::fs as proc_fs;
use crate::process::{PROCESS_TABLE, ProcessError, ProcessId};
use crate::thread::SpawnError;
use crate::{print, println};

const INPUT_BUF: usize = 256;
static SHELL_PID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum ShellError {
    Process(ProcessError),
    Fs(crate::fs::VfsError),
    NotFile,
    Utf8,
    UnknownCommand,
    OciRuntime(oci_runtime::OciRuntimeError),
    Spawn(SpawnError),
    Loader(LinuxLoadError),
    Tar(tar::TarError),
}

struct CommandSpec {
    name: &'static str,
    usage: &'static str,
    handler: fn(ProcessId, &str) -> Result<Option<String>, ShellError>,
}

struct CommandInvocation<'a> {
    spec: &'static CommandSpec,
    args: &'a str,
}

const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "ls",
        usage: "ls [path]",
        handler: cmd_ls,
    },
    CommandSpec {
        name: "cd",
        usage: "cd <path>",
        handler: cmd_cd,
    },
    CommandSpec {
        name: "cat",
        usage: "cat <path>",
        handler: cmd_cat,
    },
    CommandSpec {
        name: "rm",
        usage: "rm <path>",
        handler: cmd_rm,
    },
    CommandSpec {
        name: "wt",
        usage: "wt <path> <content>",
        handler: cmd_write,
    },
    CommandSpec {
        name: "mkdir",
        usage: "mkdir <path>",
        handler: cmd_mkdir,
    },
    CommandSpec {
        name: "pwd",
        usage: "pwd",
        handler: cmd_pwd,
    },
    CommandSpec {
        name: "tar",
        usage: "tar <archive> [dest]",
        handler: cmd_tar,
    },
    CommandSpec {
        name: "oci-runtime",
        usage: "oci-runtime create <id> <bundle>",
        handler: cmd_oci_runtime,
    },
    CommandSpec {
        name: "linux-box",
        usage: "linux-box run <path>",
        handler: cmd_linux_box,
    },
    CommandSpec {
        name: "help",
        usage: "help",
        handler: cmd_help,
    },
];

pub fn spawn_shell() -> Result<(), ProcessError> {
    let pid = PROCESS_TABLE.create_kernel_process("shell")?;
    SHELL_PID.store(pid, Ordering::Release);
    crate::thread::SCHEDULER
        .spawn_kernel_thread_for_process(pid, "shell-main", shell_thread_entry)
        .map(|_| ())
        .map_err(|_| ProcessError::NotFound)
}

fn shell_thread_entry() -> ! {
    let pid = SHELL_PID.load(Ordering::Acquire);
    shell_loop(pid)
}

fn shell_loop(pid: ProcessId) -> ! {
    println!("[shell] ready; type `help` for command list");
    let console = Arch::console();
    let mut buf = [0u8; INPUT_BUF];
    loop {
        print!("$ ");
        let len = read_line(console, &mut buf);
        let line = core::str::from_utf8(&buf[..len]).unwrap_or("");
        match run_command(pid, line) {
            Ok(Some(output)) => println!("{output}"),
            Ok(None) => {}
            Err(err) => println!("err: {:?}", err),
        }
    }
}

pub fn run_command(pid: ProcessId, line: &str) -> Result<Option<String>, ShellError> {
    let cmd = parse_command(line.trim_end_matches(['\n', '\r']))?;
    (cmd.spec.handler)(pid, cmd.args)
}

fn shell_ls(pid: ProcessId, path: Option<&str>) -> Result<Vec<DirEntry>, ShellError> {
    let path = path.unwrap_or(".");
    proc_fs::list_dir(pid, path).map_err(ShellError::Fs)
}

fn shell_cd(pid: ProcessId, path: &str) -> Result<(), ShellError> {
    proc_fs::change_dir(pid, path).map_err(ShellError::Fs)
}

fn shell_cat(pid: ProcessId, path: &str) -> Result<String, ShellError> {
    let fd = proc_fs::open_path(pid, path).map_err(ShellError::Fs)?;
    let mut buf = [0u8; 128];
    let mut out = String::new();
    loop {
        match proc_fs::read_fd(pid, fd, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Ok(text) = core::str::from_utf8(&buf[..n]) {
                    out.push_str(text);
                } else {
                    for b in &buf[..n] {
                        out.push(*b as char);
                    }
                }
            }
            Err(err) => {
                let _ = proc_fs::close_fd(pid, fd);
                return Err(ShellError::Fs(err));
            }
        }
    }
    let _ = proc_fs::close_fd(pid, fd);
    Ok(out)
}

fn shell_rm(pid: ProcessId, path: &str) -> Result<(), ShellError> {
    proc_fs::remove_path(pid, path).map_err(ShellError::Fs)
}

fn shell_write(pid: ProcessId, path: &str, data: &str) -> Result<(), ShellError> {
    proc_fs::write_path(pid, path, data.as_bytes()).map_err(ShellError::Fs)
}

fn shell_mkdir(pid: ProcessId, path: &str) -> Result<(), ShellError> {
    proc_fs::create_dir(pid, path).map_err(ShellError::Fs)
}

fn shell_pwd(pid: ProcessId) -> Result<String, ShellError> {
    let cwd = proc_fs::cwd(pid).map_err(ShellError::Fs)?;
    Ok(cwd.to_string())
}

fn shell_tar(pid: ProcessId, path: &str, dest: Option<&str>) -> Result<(), ShellError> {
    tar::extract_to_ramfs(pid, path, dest).map_err(ShellError::Tar)
}

fn parse_command(line: &str) -> Result<CommandInvocation<'_>, ShellError> {
    let mut parts = line
        .splitn(2, char::is_whitespace)
        .filter(|s| !s.is_empty());
    let name = parts.next().ok_or(ShellError::UnknownCommand)?;
    let args = parts.next().unwrap_or("").trim();
    let spec = COMMANDS
        .iter()
        .find(|spec| spec.name == name)
        .ok_or(ShellError::UnknownCommand)?;
    Ok(CommandInvocation { spec, args })
}

fn format_ls(entries: Vec<DirEntry>) -> String {
    let mut out = String::new();
    for entry in entries {
        let kind = match entry.metadata.file_type {
            crate::fs::FileType::Directory => "d",
            crate::fs::FileType::File => "-",
            crate::fs::FileType::Symlink => "l",
        };
        let line = alloc::format!("{kind} {} {}\n", entry.metadata.size, entry.name);
        out.push_str(&line);
    }
    out
}

fn help_text() -> String {
    let mut out = String::from("commands:\n");
    for spec in COMMANDS {
        out.push_str("  ");
        out.push_str(spec.usage);
        out.push('\n');
    }
    out
}

fn cmd_ls(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let path = args.split_whitespace().next();
    shell_ls(pid, path).map(|entries| Some(format_ls(entries)))
}

fn cmd_cd(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let path = args
        .split_whitespace()
        .next()
        .ok_or(ShellError::UnknownCommand)?;
    shell_cd(pid, path)?;
    Ok(None)
}

fn cmd_cat(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let path = args
        .split_whitespace()
        .next()
        .ok_or(ShellError::UnknownCommand)?;
    shell_cat(pid, path).map(Some)
}

fn cmd_rm(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let path = args
        .split_whitespace()
        .next()
        .ok_or(ShellError::UnknownCommand)?;
    shell_rm(pid, path)?;
    Ok(None)
}

fn cmd_write(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let mut parts = args
        .splitn(2, char::is_whitespace)
        .filter(|s| !s.is_empty());
    let path = parts.next().ok_or(ShellError::UnknownCommand)?;
    let data = parts.next().ok_or(ShellError::UnknownCommand)?;
    shell_write(pid, path, data)?;
    Ok(None)
}

fn cmd_mkdir(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let path = args
        .split_whitespace()
        .next()
        .ok_or(ShellError::UnknownCommand)?;
    shell_mkdir(pid, path)?;
    Ok(None)
}

fn cmd_pwd(pid: ProcessId, _args: &str) -> Result<Option<String>, ShellError> {
    shell_pwd(pid).map(Some)
}

fn cmd_tar(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let mut parts = args.split_whitespace();
    let archive = parts.next().ok_or(ShellError::UnknownCommand)?;
    let dest = parts.next();
    if parts.next().is_some() {
        return Err(ShellError::UnknownCommand);
    }
    shell_tar(pid, archive, dest)?;
    Ok(None)
}

fn cmd_oci_runtime(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let mut parts = args.split_whitespace();
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("create"), Some(id), Some(bundle), None) => {
            let output =
                oci_runtime::create_container(pid, id, bundle).map_err(ShellError::OciRuntime)?;
            Ok(Some(output))
        }
        _ => Err(ShellError::UnknownCommand),
    }
}

fn cmd_linux_box(pid: ProcessId, args: &str) -> Result<Option<String>, ShellError> {
    let mut parts = args.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("run"), Some(path), None) => {
            linux_box::run_and_wait(pid, path).map_err(|err| match err {
                linux_box::RunError::Process(err) => ShellError::Process(err),
                linux_box::RunError::Path(err) => ShellError::Fs(err),
                linux_box::RunError::Loader(err) => ShellError::Loader(err),
                linux_box::RunError::Spawn(err) => ShellError::Spawn(err),
            })?;
            Ok(None)
        }
        _ => Err(ShellError::UnknownCommand),
    }
}

fn cmd_help(_pid: ProcessId, _args: &str) -> Result<Option<String>, ShellError> {
    Ok(Some(help_text()))
}

fn read_line(console: &impl CharDevice, buf: &mut [u8]) -> usize {
    let mut len = 0;
    let mut byte = [0u8; 1];
    loop {
        let read = console.read(&mut byte).unwrap_or(0);
        if read == 0 {
            core::hint::spin_loop();
            continue;
        }
        let b = byte[0];
        if b == b'\r' || b == b'\n' {
            println!("");
            return len;
        }
        match b {
            0x08 | 0x7F => {
                if len > 0 {
                    len -= 1;
                    let _ = console.write(b"\x08 \x08"); // backspace, space, backspace
                }
            }
            _ => {
                if len + 1 < buf.len() {
                    buf[len] = b;
                    len += 1;
                    let _ = console.write(&[b]);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::process::PROCESS_TABLE;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn parse_commands() {
        println!("[test] parse_commands");

        let cmd = parse_command("ls").expect("parse");
        assert_eq!(cmd.spec.name, "ls");
        assert_eq!(cmd.args, "");

        let cmd = parse_command("ls /mnt").expect("parse");
        assert_eq!(cmd.spec.name, "ls");
        assert_eq!(cmd.args, "/mnt");

        let cmd = parse_command("cd /").expect("parse");
        assert_eq!(cmd.spec.name, "cd");
        assert_eq!(cmd.args, "/");

        let cmd = parse_command("cat a").expect("parse");
        assert_eq!(cmd.spec.name, "cat");
        assert_eq!(cmd.args, "a");

        let cmd = parse_command("rm a").expect("parse");
        assert_eq!(cmd.spec.name, "rm");
        assert_eq!(cmd.args, "a");

        let cmd = parse_command("wt a hello").expect("parse");
        assert_eq!(cmd.spec.name, "wt");
        assert_eq!(cmd.args, "a hello");

        let cmd = parse_command("help").expect("parse");
        assert_eq!(cmd.spec.name, "help");
        assert_eq!(cmd.args, "");

        let cmd = parse_command("mkdir /x").expect("parse");
        assert_eq!(cmd.spec.name, "mkdir");
        assert_eq!(cmd.args, "/x");

        let cmd = parse_command("pwd").expect("parse");
        assert_eq!(cmd.spec.name, "pwd");
        assert_eq!(cmd.args, "");

        let cmd = parse_command("linux-box run /mnt/demo1.elf").expect("parse");
        assert_eq!(cmd.spec.name, "linux-box");
        assert_eq!(cmd.args, "run /mnt/demo1.elf");

        let cmd = parse_command("tar busybox.tar").expect("parse");
        assert_eq!(cmd.spec.name, "tar");
        assert_eq!(cmd.args, "busybox.tar");

        let cmd = parse_command("tar busybox.tar /out").expect("parse");
        assert_eq!(cmd.spec.name, "tar");
        assert_eq!(cmd.args, "busybox.tar /out");

        let cmd = parse_command("oci-runtime create demo /bundle").expect("parse");
        assert_eq!(cmd.spec.name, "oci-runtime");
        assert_eq!(cmd.args, "create demo /bundle");
    }

    #[kernel_test_case]
    fn shell_commands_operate_on_memfs() {
        println!("[test] shell_commands_operate_on_memfs");

        let _ = PROCESS_TABLE.init_kernel();
        force_replace_root(MemDirectory::new());
        let pid = PROCESS_TABLE
            .create_kernel_process("shell-test")
            .expect("create process");

        // write file
        run_command(pid, "wt /note hello").expect("wt");
        // list
        let ls_out = run_command(pid, "ls /").expect("ls").unwrap();
        assert!(ls_out.contains("note"), "ls output missing file: {ls_out}");
        // cat
        let cat_out = run_command(pid, "cat /note").expect("cat").unwrap();
        assert!(cat_out.contains("hello"), "cat output mismatch: {cat_out}");
        // remove
        run_command(pid, "rm /note").expect("rm");
        let ls_out2 = run_command(pid, "ls /").expect("ls2").unwrap();
        assert!(
            !ls_out2.contains("note"),
            "file still present after rm: {ls_out2}"
        );

        run_command(pid, "mkdir /dir").expect("mkdir");
        run_command(pid, "cd /dir").expect("cd");
        let pwd_out = run_command(pid, "pwd").expect("pwd").unwrap();
        assert_eq!(pwd_out, "/dir");
    }

    #[kernel_test_case]
    fn tar_command_extracts_archive_into_memfs() {
        println!("[test] tar_command_extracts_archive_into_memfs");

        let _ = PROCESS_TABLE.init_kernel();
        force_replace_root(MemDirectory::new());
        let pid = PROCESS_TABLE
            .create_kernel_process("shell-tar-test")
            .expect("create process");

        let archive = build_test_tar();
        proc_fs::write_path(pid, "/busybox.tar", &archive).expect("write tar archive");

        run_command(pid, "tar /busybox.tar").expect("tar");

        let content = run_command(pid, "cat /dir/hello.txt")
            .expect("cat")
            .unwrap();
        assert_eq!(content, "hello from tar");

        let sym_content = run_command(pid, "cat /dir/hello.sym")
            .expect("cat symlink")
            .unwrap();
        assert_eq!(sym_content, "hello from tar");

        let hard_content = run_command(pid, "cat /dir/sub/hello.hard")
            .expect("cat hardlink")
            .unwrap();
        assert_eq!(hard_content, "hello from tar");

        let sym_up_content = run_command(pid, "cat /dir/sub/hello.sym.up")
            .expect("cat symlink up")
            .unwrap();
        assert_eq!(sym_up_content, "hello from tar");
    }

    fn build_test_tar() -> Vec<u8> {
        let mut archive = Vec::new();
        let data = b"hello from tar";
        archive.extend_from_slice(&build_header(
            "dir/hello.txt",
            data.len() as u64,
            b'0',
            None,
        ));
        archive.extend_from_slice(data);
        pad_to_block(&mut archive);

        archive.extend_from_slice(&build_header("dir/sub/", 0, b'5', None));
        pad_to_block(&mut archive);

        archive.extend_from_slice(&build_header("dir/hello.sym", 0, b'2', Some("hello.txt")));
        pad_to_block(&mut archive);

        archive.extend_from_slice(&build_header(
            "dir/sub/hello.hard",
            0,
            b'1',
            Some("../hello.txt"),
        ));
        pad_to_block(&mut archive);

        archive.extend_from_slice(&build_header(
            "dir/sub/hello.sym.up",
            0,
            b'2',
            Some("../hello.txt"),
        ));
        pad_to_block(&mut archive);

        archive.extend_from_slice(&[0u8; 512]);
        archive.extend_from_slice(&[0u8; 512]);
        archive
    }

    fn build_header(path: &str, size: u64, kind: u8, link: Option<&str>) -> [u8; 512] {
        let mut header = [0u8; 512];
        let name_bytes = path.as_bytes();
        assert!(name_bytes.len() <= 100, "test path too long for header");
        header[..name_bytes.len()].copy_from_slice(name_bytes);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[156] = kind;
        if let Some(link) = link {
            let link_bytes = link.as_bytes();
            assert!(
                link_bytes.len() <= 100,
                "test link name too long for header"
            );
            header[157..157 + link_bytes.len()].copy_from_slice(link_bytes);
        }
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[148..156].fill(b' ');

        let checksum: u32 = header.iter().map(|b| *b as u32).sum();
        let chk = alloc::format!("{checksum:06o}\0 ");
        header[148..148 + chk.len()].copy_from_slice(chk.as_bytes());
        header
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let width = field.len().saturating_sub(1);
        let text = alloc::format!("{value:0width$o}\0", width = width);
        let bytes = text.as_bytes();
        let start = field.len() - bytes.len();
        field.fill(0);
        field[start..start + bytes.len()].copy_from_slice(bytes);
    }

    fn pad_to_block(buf: &mut Vec<u8>) {
        let rem = buf.len() % 512;
        if rem == 0 {
            return;
        }
        buf.extend(core::iter::repeat_n(0u8, 512 - rem));
    }
}
