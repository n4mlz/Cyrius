use anyhow::{Context, Result, bail};
use clap::Parser;
use std::{path::PathBuf, process::Command};

#[derive(Parser)]
#[command(about = "Build kernel, make BIOS image, and run QEMU")]
struct Cli {
    /// Build release profile
    #[arg(long)]
    release: bool,
}

fn main() -> Result<()> {
    let Cli { release } = Cli::parse();

    // build kernel
    let kernel = build_kernel(release)?;

    // make BIOS image
    let img = image_bios(&kernel)?;

    // run qemu
    run_qemu(&img)?;

    Ok(())
}

fn build_kernel(release: bool) -> Result<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "-p",
        "kernel",
        "--target",
        "x86_64-unknown-none",
        "-Z",
        "build-std=core,compiler_builtins",
        "-Z",
        "build-std-features=compiler-builtins-mem",
    ]);
    if release {
        cmd.arg("--release");
    }
    ensure(cmd, "cargo build kernel")?;

    let dir = if release {
        "target/x86_64-unknown-none/release"
    } else {
        "target/x86_64-unknown-none/debug"
    };
    Ok(PathBuf::from(dir).join("kernel"))
}

fn image_bios(kernel: &std::path::Path) -> Result<PathBuf> {
    let out = PathBuf::from("target/boot-bios.img");
    let b = bootloader::DiskImageBuilder::new(kernel.to_path_buf());
    b.create_bios_image(&out).context("create BIOS image")?;
    Ok(out)
}

fn run_qemu(img: &std::path::Path) -> Result<()> {
    let mut qemu = Command::new("qemu-system-x86_64");
    qemu.args([
        "-m",
        "256M",
        "-serial",
        "stdio",
        "-display",
        "none",
        "-drive",
        &format!("format=raw,file={}", img.display()),
    ]);
    ensure(qemu, "qemu")?;
    Ok(())
}

fn ensure(mut cmd: Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("{what} failed to start"))?;
    if !status.success() {
        bail!("{what} failed with {status}");
    }
    Ok(())
}
