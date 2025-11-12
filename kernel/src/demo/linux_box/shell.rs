use alloc::{string::String, vec::Vec};

use crate::arch::{Arch, api::ArchDevice};
use crate::demo::linux_box::runner;
use crate::syscall::SyscallPolicy;
use crate::util::stream::{ReadOps, StreamError};
use crate::{print, println};

#[cfg(not(test))]
use crate::thread::SCHEDULER;

type ConsoleError = <<Arch as ArchDevice>::Console as ReadOps>::Error;

const PROMPT: &str = "OS> ";
const MAX_LINE: usize = 128;

pub fn spawn_shell_thread() {
    #[cfg(not(test))]
    {
        SCHEDULER
            .spawn_kernel_thread("linux-box-shell", shell_thread)
            .expect("spawn linux-box shell");
    }
}

fn shell_thread() -> ! {
    let mut line = String::with_capacity(MAX_LINE);
    loop {
        print_prompt();
        if let Err(err) = read_line(&mut line) {
            println!("[shell] input error: {:?}", err);
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        handle_command(trimmed);
    }
}

fn print_prompt() {
    print!("{}", PROMPT);
}

fn read_line(buf: &mut String) -> Result<(), ConsoleError> {
    buf.clear();
    loop {
        let byte = read_byte()?;
        match byte {
            b'\r' | b'\n' => {
                println!("");
                return Ok(());
            }
            0x08 | 0x7f => {
                if !buf.is_empty() {
                    buf.pop();
                    print!("\u{0008} \u{0008}");
                }
            }
            b if is_printable(b) => {
                if buf.len() < MAX_LINE {
                    buf.push(b as char);
                    print!("{}", b as char);
                }
            }
            _ => {}
        }
    }
}

fn read_byte() -> Result<u8, ConsoleError> {
    let console = Arch::console();
    let mut byte = [0u8; 1];
    loop {
        match console.read(&mut byte) {
            Ok(0) => continue,
            Ok(_) => return Ok(byte[0]),
            Err(StreamError::WouldBlock) => continue,
            Err(err) => return Err(err),
        }
    }
}

fn is_printable(byte: u8) -> bool {
    (byte.is_ascii_graphic()) || byte == b' '
}

fn handle_command(line: &str) {
    let mut parts = line.split_whitespace();
    let Some(cmd0) = parts.next() else {
        return;
    };

    if cmd0 != "linux-box" {
        println!("unknown command: {}", cmd0);
        return;
    }

    let Some(subcmd) = parts.next() else {
        println!("linux-box expects a subcommand");
        return;
    };

    match subcmd {
        "ls" => list_demos(),
        "run" => run_command(parts.collect::<Vec<_>>()),
        other => println!("unknown linux-box subcommand: {}", other),
    }
}

fn list_demos() {
    println!("#=> NAME    TYPE    STATE   CMD");
    for demo in runner::demos() {
        println!(
            "#   {name:<6} {ty:<6} {state:<6} {cmd}",
            name = demo.name,
            ty = "linux",
            state = demo.state.as_str(),
            cmd = demo.cmd
        );
    }
}

fn run_command(args: Vec<&str>) {
    let mut policy = None;
    let mut target = None;
    for arg in args {
        if let Some(rest) = arg.strip_prefix("--policy=") {
            match parse_policy(rest) {
                Some(p) => policy = Some(p),
                None => {
                    println!("invalid policy: {}", rest);
                    return;
                }
            }
            continue;
        }

        if target.is_none() {
            target = Some(arg);
        } else {
            println!("unexpected argument: {}", arg);
            return;
        }
    }

    let Some(name) = target else {
        println!("linux-box run requires a demo name");
        return;
    };

    match runner::run_demo(name, policy) {
        Ok(pid) => {
            let policy =
                policy.unwrap_or_else(|| match runner::demos().iter().find(|d| d.name == name) {
                    Some(spec) => spec.default_policy,
                    None => SyscallPolicy::default(),
                });
            println!("[ctr {pid}] running {name} (policy={})", policy.as_str());
        }
        Err(err) => println!("failed to run {name}: {:?}", err),
    }
}

fn parse_policy(value: &str) -> Option<SyscallPolicy> {
    match value {
        "minimal" => Some(SyscallPolicy::Minimal),
        "full" => Some(SyscallPolicy::Full),
        _ => None,
    }
}
