use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
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

#[derive(Clone, Debug, Default)]
pub struct TestBuildOptions {
    pub release: bool,
    pub selector: Option<TestSelector>,
    pub list_only: bool,
}

#[derive(Clone, Debug)]
pub enum TestSelector {
    NamePattern(String),
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

pub fn build_kernel_tests(opts: &TestBuildOptions) -> Result<PathBuf> {
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

    if opts.release {
        cmd.arg("--release");
    }

    configure_test_build(&mut cmd, opts);

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

pub fn run_qemu(image: &Path, test: bool, virtio_blk: Option<&Path>) -> Result<ExitStatus> {
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
        ]);
    }

    if let Some(path) = virtio_blk {
        let drive_arg = format!("if=none,format=raw,file={},id=blk0", path.display());
        qemu.arg("-drive");
        qemu.arg(drive_arg);
        qemu.arg("-device");
        qemu.arg("virtio-blk-pci,drive=blk0,disable-legacy=on");
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
        .next_back()
}

fn configure_test_build(cmd: &mut Command, opts: &TestBuildOptions) {
    if let Some(TestSelector::NamePattern(pattern)) = &opts.selector {
        cmd.env("CYRIUS_TEST_FILTER_KIND", "name");
        cmd.env("CYRIUS_TEST_FILTER_VALUE", pattern);
    }

    if opts.list_only {
        cmd.env("CYRIUS_TEST_LIST_ONLY", "1");
    }
}

pub fn ensure_test_disk(signature: &[u8]) -> Result<PathBuf> {
    let path = PathBuf::from("target/virtio-blk-test.img");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = File::create(&path)?;
    file.set_len(1 << 20)?; // 1 MiB image filled with zeroes
    file.seek(SeekFrom::Start(0))?;

    let mut sector = [0u8; 512];
    let len = signature.len().min(sector.len());
    sector[..len].copy_from_slice(&signature[..len]);
    file.write_all(&sector)?;
    file.flush()?;

    Ok(path)
}
