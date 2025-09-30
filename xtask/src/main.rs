use anyhow::{Result, bail};
use clap::Parser;

use xtask::{ImageKind, build_kernel, build_kernel_tests, image_bios, run_qemu};

#[derive(Parser)]
#[command(about = "Build kernel, make BIOS image, and run QEMU")]
struct Cli {
    /// Build release profile
    #[arg(long)]
    release: bool,

    /// Build and run test binary instead of the default kernel flow
    #[arg(long)]
    test: bool,

    /// Only build the test binary; skip launching QEMU (implies --test)
    #[arg(long, requires = "test")]
    no_run: bool,
}

fn main() -> Result<()> {
    let Cli {
        release,
        test,
        no_run,
    } = Cli::parse();

    if test {
        run_tests(release, no_run)?;
    } else {
        run_kernel(release)?;
    }

    Ok(())
}

fn run_kernel(release: bool) -> Result<()> {
    let kernel = build_kernel(release)?;
    let img = image_bios(&kernel, ImageKind::Run)?;
    let status = run_qemu(&img, false)?;
    if !status.success() {
        bail!("qemu exited with {status}");
    }
    Ok(())
}

fn run_tests(release: bool, no_run: bool) -> Result<()> {
    let test_binary = build_kernel_tests(release)?;

    if no_run {
        return Ok(());
    }

    let image = image_bios(&test_binary, ImageKind::Test)?;
    let status = run_qemu(&image, true)?;

    match status.code() {
        Some(0x20) => Ok(()),
        Some(0x22) => bail!("kernel tests reported failure"),
        Some(code) => bail!("unexpected QEMU exit status: {code}"),
        None => bail!("QEMU terminated without exit status"),
    }
}
