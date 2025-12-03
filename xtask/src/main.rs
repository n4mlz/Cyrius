use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};

use xtask::{
    ImageKind, TestBuildOptions, TestSelector, build_kernel, build_kernel_tests, image_bios,
    prepare_test_block_image, prepare_test_fat_image, run_qemu,
};

#[derive(Parser)]
#[command(about = "Build kernel, create boot images, and drive QEMU runs")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Run(RunArgs),
    Test(TestArgs),
}

#[derive(Args, Default)]
struct RunArgs {
    /// Build the release profile instead of dev
    #[arg(long)]
    release: bool,
}

#[derive(Args, Default)]
struct TestArgs {
    /// Build the release profile instead of dev
    #[arg(long)]
    release: bool,

    /// Only build the test binary without running QEMU
    #[arg(long)]
    no_run: bool,

    /// Print the discovered test cases without executing them
    #[arg(long, conflicts_with = "no_run")]
    list: bool,

    /// Execute only tests whose name contains the provided pattern
    #[arg(long, value_name = "PATTERN")]
    name: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli
        .command
        .unwrap_or_else(|| Command::Run(RunArgs::default()))
    {
        Command::Run(args) => run_kernel(args.release),
        Command::Test(args) => run_tests(args),
    }
}

fn run_kernel(release: bool) -> Result<()> {
    let kernel = build_kernel(release)?;
    let img = image_bios(&kernel, ImageKind::Run)?;
    let status = run_qemu(&img, false, &[])?;
    if !status.success() {
        bail!("qemu exited with {status}");
    }
    Ok(())
}

fn run_tests(args: TestArgs) -> Result<()> {
    let selector = args.name.map(TestSelector::NamePattern);

    let build_opts = TestBuildOptions {
        release: args.release,
        selector,
        list_only: args.list,
    };

    let test_binary = build_kernel_tests(&build_opts)?;

    if args.no_run {
        return Ok(());
    }

    let block_image = prepare_test_block_image()?;
    let fat_image = prepare_test_fat_image()?;
    let image = image_bios(&test_binary, ImageKind::Test)?;
    let status = run_qemu(&image, true, &[block_image, fat_image])?;

    interpret_test_exit(status)
}

fn interpret_test_exit(status: std::process::ExitStatus) -> Result<()> {
    match status.code() {
        Some(code) if code & 1 == 1 => match code >> 1 {
            0x20 => Ok(()),
            0x22 => bail!("kernel tests reported failure"),
            other => bail!("unexpected kernel exit code: 0x{other:x}"),
        },
        Some(code) => bail!("unexpected QEMU exit status: {code}"),
        None => bail!("QEMU terminated without exit status"),
    }
}
