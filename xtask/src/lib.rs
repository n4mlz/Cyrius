use std::{
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    str,
};

use anyhow::{Context, Result, bail};
use serde_json::Value;

pub fn build_kernel(release: bool) -> Result<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "-p",
        "kernel",
        "--target",
        "x86_64-unknown-none",
        "-Z",
        "build-std=core,compiler_builtins,alloc,panic_abort",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ]);

    if release {
        cmd.arg("--release");
    }

    run_checked(&mut cmd, "cargo build kernel")?;

    let dir = if release {
        "target/x86_64-unknown-none/release"
    } else {
        "target/x86_64-unknown-none/debug"
    };

    Ok(PathBuf::from(dir).join("kernel"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageKind {
    Run,
    Test,
}

pub fn image_bios(kernel: &Path, kind: ImageKind) -> Result<PathBuf> {
    let out = match kind {
        ImageKind::Run => PathBuf::from("target/boot-bios.img"),
        ImageKind::Test => PathBuf::from("target/boot-test.img"),
    };

    let builder = bootloader::DiskImageBuilder::new(kernel.to_path_buf());
    builder
        .create_bios_image(&out)
        .with_context(|| format!("create BIOS image at {}", out.display()))?;

    Ok(out)
}

pub fn build_kernel_tests(release: bool) -> Result<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "test",
        "-p",
        "kernel",
        "--target",
        "x86_64-unknown-none",
        "--no-run",
        "-Z",
        "panic-abort-tests",
        "-Z",
        "build-std=core,compiler_builtins,alloc,panic_abort",
        "-Z",
        "build-std-features=compiler-builtins-mem",
        "--message-format",
        "json",
    ]);

    cmd.env("CARGO_TERM_COLOR", "never");

    if release {
        cmd.arg("--release");
    }

    let output = cmd
        .output()
        .with_context(|| "cargo test kernel (build only)")?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("<invalid utf-8>");
        bail!("cargo test --no-run failed: {stderr}");
    }

    let stdout = str::from_utf8(&output.stdout).unwrap_or("");
    if let Some(path) = parse_executable_from_json(stdout) {
        Ok(path)
    } else {
        bail!("failed to locate test binary path in cargo output")
    }
}

pub fn run_qemu(image: &Path, test: bool) -> Result<ExitStatus> {
    let mut qemu = Command::new("qemu-system-x86_64");
    qemu.args([
        "-m",
        "256M",
        "-serial",
        "stdio",
        "-display",
        "none",
        "-drive",
        &format!("format=raw,file={}", image.display()),
    ]);

    if test {
        qemu.args([
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-no-reboot",
            "-no-shutdown",
        ]);
    }

    qemu.status()
        .with_context(|| format!("qemu failed to start for {}", image.display()))
}

fn run_checked(cmd: &mut Command, what: &str) -> Result<ExitStatus> {
    let status = cmd
        .status()
        .with_context(|| format!("{what} failed to start"))?;

    if !status.success() {
        bail!("{what} failed with {status}");
    }

    Ok(status)
}

fn parse_executable_from_json(output: &str) -> Option<PathBuf> {
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let value: Value = serde_json::from_str(trimmed).ok()?;
            if value.get("reason").and_then(Value::as_str) != Some("compiler-artifact") {
                return None;
            }
            let target_name = value
                .get("target")
                .and_then(|target| target.get("name"))
                .and_then(Value::as_str);
            if target_name != Some("kernel") {
                return None;
            }
            value
                .get("executable")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        })
        .last()
}
