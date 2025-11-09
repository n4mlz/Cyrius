use std::{path::PathBuf, process};

use anyhow::{Result, bail};
use clap::Parser;

use xtask::{ImageKind, image_bios, run_qemu};

#[derive(Parser)]
struct RunnerCli {
    /// Treat this invocation as a test run (enables isa-debug-exit handling)
    #[arg(long, default_value_t = false)]
    test: bool,

    /// Path to the kernel ELF binary produced by cargo
    #[arg(value_name = "KERNEL")]
    kernel: PathBuf,
}

fn main() {
    let exit_code = match real_main() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("qemu-runner: {err:?}");
            1
        }
    };

    process::exit(exit_code);
}

fn real_main() -> Result<i32> {
    let RunnerCli { test, kernel } = RunnerCli::parse();

    let image = image_bios(
        &kernel,
        if test {
            ImageKind::Test
        } else {
            ImageKind::Run
        },
    )?;

    let status = run_qemu(&image, test, None)?;

    if !test {
        return Ok(status.code().unwrap_or_default());
    }

    match status.code() {
        Some(code) if code & 1 == 1 => match code >> 1 {
            0x20 => Ok(0),
            0x22 => Ok(1),
            other => bail!("unexpected kernel exit code: 0x{other:x}"),
        },
        Some(code) => bail!("unexpected QEMU exit status: {code}"),
        None => bail!("QEMU terminated by signal"),
    }
}
