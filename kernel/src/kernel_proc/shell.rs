use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::Arch;
use crate::arch::api::ArchDevice;
use crate::device::char::CharDevice;
use crate::fs::DirEntry;
use crate::kernel_proc::linux_box;
use crate::loader::linux::LinuxLoadError;
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
    Spawn(SpawnError),
    Loader(LinuxLoadError),
}

#[derive(Debug, PartialEq, Eq)]
enum Command<'a> {
    Ls(Option<&'a str>),
    Cd(&'a str),
    Cat(&'a str),
    Rm(&'a str),
    Write(&'a str, &'a str),
    Mkdir(&'a str),
    Pwd,
    Help,
    LinuxBoxRun(&'a str),
    Unknown,
}

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
    println!("[shell] ready; commands: ls/cd/cat/rm/wt/linux-box/help");
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
    let cmd = parse_command(line.trim_end_matches(['\n', '\r']));
    match cmd {
        Command::Ls(path) => shell_ls(pid, path).map(|entries| Some(format_ls(entries))),
        Command::Cd(path) => {
            shell_cd(pid, path)?;
            Ok(None)
        }
        Command::Cat(path) => shell_cat(pid, path).map(Some),
        Command::Rm(path) => {
            shell_rm(pid, path)?;
            Ok(None)
        }
        Command::Write(path, data) => {
            shell_write(pid, path, data)?;
            Ok(None)
        }
        Command::Mkdir(path) => {
            shell_mkdir(pid, path)?;
            Ok(None)
        }
        Command::Pwd => shell_pwd(pid).map(Some),
        Command::Help => Ok(Some(help_text())),
        Command::LinuxBoxRun(path) => {
            linux_box::run_and_wait(pid, path).map_err(|err| match err {
                linux_box::RunError::Process(err) => ShellError::Process(err),
                linux_box::RunError::Path(err) => ShellError::Fs(err),
                linux_box::RunError::Loader(err) => ShellError::Loader(err),
                linux_box::RunError::Spawn(err) => ShellError::Spawn(err),
            })?;
            Ok(None)
        }
        Command::Unknown => Err(ShellError::UnknownCommand),
    }
}

fn shell_ls(pid: ProcessId, path: Option<&str>) -> Result<Vec<DirEntry>, ShellError> {
    let path = path.unwrap_or(".");
    PROCESS_TABLE.list_dir(pid, path).map_err(ShellError::Fs)
}

fn shell_cd(pid: ProcessId, path: &str) -> Result<(), ShellError> {
    PROCESS_TABLE.change_dir(pid, path).map_err(ShellError::Fs)
}

fn shell_cat(pid: ProcessId, path: &str) -> Result<String, ShellError> {
    let fd = PROCESS_TABLE.open_path(pid, path).map_err(ShellError::Fs)?;
    let mut buf = [0u8; 128];
    let mut out = String::new();
    loop {
        match PROCESS_TABLE.read_fd(pid, fd, &mut buf) {
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
                let _ = PROCESS_TABLE.close_fd(pid, fd);
                return Err(ShellError::Fs(err));
            }
        }
    }
    let _ = PROCESS_TABLE.close_fd(pid, fd);
    Ok(out)
}

fn shell_rm(pid: ProcessId, path: &str) -> Result<(), ShellError> {
    PROCESS_TABLE.remove_path(pid, path).map_err(ShellError::Fs)
}

fn shell_write(pid: ProcessId, path: &str, data: &str) -> Result<(), ShellError> {
    PROCESS_TABLE
        .write_path(pid, path, data.as_bytes())
        .map_err(ShellError::Fs)
}

fn shell_mkdir(pid: ProcessId, path: &str) -> Result<(), ShellError> {
    PROCESS_TABLE.create_dir(pid, path).map_err(ShellError::Fs)
}

fn shell_pwd(pid: ProcessId) -> Result<String, ShellError> {
    let cwd = PROCESS_TABLE.cwd(pid).map_err(ShellError::Fs)?;
    Ok(cwd.to_string())
}

fn parse_command(line: &str) -> Command<'_> {
    let mut parts = line
        .splitn(3, char::is_whitespace)
        .filter(|s| !s.is_empty());
    match parts.next() {
        Some("ls") => Command::Ls(parts.next()),
        Some("cd") => parts.next().map(Command::Cd).unwrap_or(Command::Unknown),
        Some("cat") => parts.next().map(Command::Cat).unwrap_or(Command::Unknown),
        Some("rm") => parts.next().map(Command::Rm).unwrap_or(Command::Unknown),
        Some("pwd") => Command::Pwd,
        Some("mkdir") => parts.next().map(Command::Mkdir).unwrap_or(Command::Unknown),
        Some("wt") => {
            if let (Some(path), Some(rest)) = (parts.next(), parts.next()) {
                Command::Write(path, rest)
            } else {
                Command::Unknown
            }
        }
        Some("help") => Command::Help,
        Some("linux-box") => match (parts.next(), parts.next()) {
            (Some("run"), Some(path)) => Command::LinuxBoxRun(path),
            _ => Command::Unknown,
        },
        Some("") | None => Command::Unknown,
        _ => Command::Unknown,
    }
}

fn format_ls(entries: Vec<DirEntry>) -> String {
    let mut out = String::new();
    for entry in entries {
        let kind = match entry.metadata.file_type {
            crate::fs::FileType::Directory => "d",
            crate::fs::FileType::File => "-",
        };
        let line = alloc::format!("{kind} {} {}\n", entry.metadata.size, entry.name);
        out.push_str(&line);
    }
    out
}

fn help_text() -> String {
    "commands:\n  ls [path]\n  cd <path>\n  cat <path>\n  rm <path>\n  wt <path> <content>\n  mkdir <path>\n  pwd\n  help\n  linux-box run <path>\n"
        .to_string()
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
        assert_eq!(parse_command("ls"), Command::Ls(None));
        assert_eq!(parse_command("ls /mnt"), Command::Ls(Some("/mnt")));
        assert_eq!(parse_command("cd /"), Command::Cd("/"));
        assert_eq!(parse_command("cat a"), Command::Cat("a"));
        assert_eq!(parse_command("rm a"), Command::Rm("a"));
        assert_eq!(parse_command("wt a hello"), Command::Write("a", "hello"));
        assert_eq!(parse_command("help"), Command::Help);
        assert_eq!(parse_command("mkdir /x"), Command::Mkdir("/x"));
        assert_eq!(parse_command("pwd"), Command::Pwd);
        assert_eq!(
            parse_command("linux-box run /mnt/demo1.elf"),
            Command::LinuxBoxRun("/mnt/demo1.elf")
        );
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
}
