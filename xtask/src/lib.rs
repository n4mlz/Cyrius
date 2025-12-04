use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    str,
};

use anyhow::{Context, Result, bail};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use serde_json::Value;
use std::io::{Read, Seek, SeekFrom};

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

pub fn run_qemu(image: &Path, test: bool, block_images: &[PathBuf]) -> Result<ExitStatus> {
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

    for (index, extra) in block_images.iter().enumerate() {
        let id = format!("virtio_blk_test{index}");
        qemu.args([
            "-drive",
            &format!("if=none,id={id},format=raw,file={}", extra.display()),
        ]);
        qemu.args([
            "-device",
            &format!("virtio-blk-pci,drive={id},disable-legacy=on"),
        ]);
    }

    if test {
        qemu.args([
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
            "-no-reboot",
        ]);
    }

    qemu.status()
        .with_context(|| format!("qemu failed to start for {}", image.display()))
}

pub fn prepare_test_block_image() -> Result<PathBuf> {
    const IMAGE_PATH: &str = "target/virtio-blk-test.img";
    const SECTOR_BYTES: usize = 512;
    const SECTORS: usize = 64;
    const PATTERN: &[u8] = b"CYRIUSBLKTESTIMG";

    let path = PathBuf::from(IMAGE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }

    let mut image = vec![0u8; SECTOR_BYTES * SECTORS];
    for (index, byte) in image[..SECTOR_BYTES].iter_mut().enumerate() {
        *byte = PATTERN[index % PATTERN.len()];
    }

    fs::write(&path, &image)
        .with_context(|| format!("write virtio-blk test image {}", path.display()))?;

    Ok(path)
}

pub fn prepare_test_fat_image() -> Result<PathBuf> {
    const IMAGE_PATH: &str = "target/fat32-test.img";
    const BYTES_PER_SECTOR: usize = 512;
    const TOTAL_SECTORS: u32 = 2048;
    const RESERVED_SECTORS: u16 = 32;
    const NUM_FATS: u8 = 1;
    const SECTORS_PER_CLUSTER: u8 = 1;
    const FILE_CLUSTER: u32 = 3;
    const ROOT_CLUSTER: u32 = 2;
    const MEDIA_DESCRIPTOR: u8 = 0xF8;
    const FILE_NAME_8DOT3: &[u8; 11] = b"HELLO   TXT";
    const FILE_PAYLOAD: &[u8] = b"Hello from FAT32!\n";

    let fat_size = compute_fat_size(
        TOTAL_SECTORS,
        RESERVED_SECTORS,
        NUM_FATS,
        SECTORS_PER_CLUSTER,
        BYTES_PER_SECTOR as u32,
    );

    let image_bytes = BYTES_PER_SECTOR * TOTAL_SECTORS as usize;
    let mut image = vec![0u8; image_bytes];

    let boot_cfg = BootSectorConfig {
        bytes_per_sector: BYTES_PER_SECTOR as u16,
        sectors_per_cluster: SECTORS_PER_CLUSTER,
        reserved_sectors: RESERVED_SECTORS,
        fats: NUM_FATS,
        fat_size,
        media: MEDIA_DESCRIPTOR,
        total_sectors: TOTAL_SECTORS,
        root_cluster: ROOT_CLUSTER,
    };

    write_boot_sector(&mut image[..BYTES_PER_SECTOR], &boot_cfg);
    write_fsinfo(&mut image[BYTES_PER_SECTOR..BYTES_PER_SECTOR * 2]);

    let fat_offset = BYTES_PER_SECTOR * RESERVED_SECTORS as usize;
    write_fat(
        &mut image[fat_offset..fat_offset + fat_size as usize * BYTES_PER_SECTOR],
        MEDIA_DESCRIPTOR,
        ROOT_CLUSTER,
        FILE_CLUSTER,
    );

    let data_start =
        BYTES_PER_SECTOR * (RESERVED_SECTORS as usize + fat_size as usize * NUM_FATS as usize);
    write_root_directory(
        &mut image[data_start..data_start + BYTES_PER_SECTOR],
        FILE_NAME_8DOT3,
        FILE_CLUSTER,
        FILE_PAYLOAD.len() as u32,
    );

    let file_offset = data_start + (FILE_CLUSTER as usize - 2) * BYTES_PER_SECTOR;
    let file_slice = &mut image[file_offset..file_offset + BYTES_PER_SECTOR];
    file_slice[..FILE_PAYLOAD.len()].copy_from_slice(FILE_PAYLOAD);

    let path = PathBuf::from(IMAGE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }

    fs::write(&path, &image)
        .with_context(|| format!("write FAT32 test image {}", path.display()))?;

    Ok(path)
}

pub fn prepare_host_mnt_image() -> Result<PathBuf> {
    const IMAGE_PATH: &str = "target/mnt.img";
    const BYTES_PER_SECTOR: u16 = 512;
    const IMAGE_BYTES: u64 = 64 * 1024 * 1024;

    let path = PathBuf::from(IMAGE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .with_context(|| format!("open image {}", path.display()))?;
    file.set_len(IMAGE_BYTES)
        .with_context(|| format!("set length for {}", path.display()))?;

    let opts = FormatVolumeOptions::new()
        .bytes_per_sector(BYTES_PER_SECTOR)
        .bytes_per_cluster(u32::from(BYTES_PER_SECTOR))
        .fat_type(FatType::Fat32);
    fatfs::format_volume(&mut file, opts)
        .with_context(|| format!("format FAT32 image {}", path.display()))?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| "rewind image after format")?;

    let mut boot_sector = [0u8; 512];
    file.read_exact(&mut boot_sector)
        .with_context(|| "read boot sector for FAT type check")?;
    let fs_marker = &boot_sector[82..90];
    if fs_marker != b"FAT32   " {
        bail!(
            "formatted host mnt image is not FAT32 (fs marker: {:?})",
            str::from_utf8(fs_marker).unwrap_or("<invalid>")
        );
    }
    file.seek(SeekFrom::Start(0))
        .with_context(|| "rewind image after FAT32 check")?;

    let fs =
        FileSystem::new(file, FsOptions::new()).with_context(|| "mount formatted mnt image")?;

    let host_dir = Path::new("mnt");
    if host_dir.exists() {
        copy_dir_into_fs(&fs, host_dir, "/")?;
    }

    Ok(path)
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

fn compute_fat_size(
    total_sectors: u32,
    reserved_sectors: u16,
    fats: u8,
    sectors_per_cluster: u8,
    bytes_per_sector: u32,
) -> u32 {
    let mut fat_size = 1u32;
    loop {
        let data_sectors = total_sectors
            .saturating_sub(u32::from(reserved_sectors))
            .saturating_sub(u32::from(fats) * fat_size);
        let clusters = data_sectors / u32::from(sectors_per_cluster);
        let fat_bytes = (clusters + 2) * 4;
        let required_sectors = fat_bytes.div_ceil(bytes_per_sector);
        if required_sectors <= fat_size {
            return fat_size;
        }
        fat_size = required_sectors;
    }
}

fn write_boot_sector(sector: &mut [u8], cfg: &BootSectorConfig) {
    sector.fill(0);
    sector[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    sector[3..11].copy_from_slice(b"CYRIUSOS");
    sector[11..13].copy_from_slice(&cfg.bytes_per_sector.to_le_bytes());
    sector[13] = cfg.sectors_per_cluster;
    sector[14..16].copy_from_slice(&cfg.reserved_sectors.to_le_bytes());
    sector[16] = cfg.fats;
    sector[21] = cfg.media;
    sector[32..36].copy_from_slice(&cfg.total_sectors.to_le_bytes());
    sector[36..40].copy_from_slice(&cfg.fat_size.to_le_bytes());
    sector[44..48].copy_from_slice(&cfg.root_cluster.to_le_bytes());
    sector[48..50].copy_from_slice(&1u16.to_le_bytes()); // FSInfo
    sector[50..52].copy_from_slice(&6u16.to_le_bytes()); // Backup boot sector
    sector[64] = 0x80; // Drive number
    sector[66] = 0x29; // Extended boot signature
    sector[67..71].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    sector[71..82].copy_from_slice(b"CYRIUSVFS  "); // volume label (11 bytes, space padded)
    sector[82..90].copy_from_slice(b"FAT32   ");
    sector[510..512].copy_from_slice(&[0x55, 0xAA]);
}

fn write_fsinfo(sector: &mut [u8]) {
    if sector.len() < 512 {
        return;
    }
    sector.fill(0);
    sector[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    sector[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    sector[488..492].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    sector[492..496].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    sector[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
}

fn write_fat(fat: &mut [u8], media: u8, root_cluster: u32, file_cluster: u32) {
    let mut set_entry = |index: usize, value: u32| {
        let start = index * 4;
        fat[start..start + 4].copy_from_slice(&value.to_le_bytes());
    };

    set_entry(0, 0x0FFFFF00 | u32::from(media));
    set_entry(1, 0x0FFFFFFF);
    set_entry(root_cluster as usize, 0x0FFFFFFF);
    set_entry(file_cluster as usize, 0x0FFFFFFF);
}

type FatfsFs = FileSystem<std::fs::File>;

fn copy_dir_into_fs(fs: &FatfsFs, host: &Path, dest: &str) -> Result<()> {
    if dest != "/" {
        let _ = fs.root_dir().create_dir(dest);
    }
    walk_dir(fs, host, dest)?;
    Ok(())
}

fn walk_dir(fs: &FatfsFs, host: &Path, dest: &str) -> Result<()> {
    for entry in fs::read_dir(host).with_context(|| format!("read_dir {}", host.display()))? {
        let entry = entry?;
        let path = entry.path();
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid utf-8 in filename"))?
            .to_string();
        let dest_path = if dest == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", dest, name)
        };

        if entry.file_type()?.is_dir() {
            let _ = fs.root_dir().create_dir(&dest_path);
            walk_dir(fs, &path, &dest_path)?;
        } else if entry.file_type()?.is_file() {
            let mut src =
                std::fs::File::open(&path).with_context(|| format!("open {}", path.display()))?;
            let mut dst = match fs.root_dir().create_file(&dest_path) {
                Ok(f) => f,
                Err(_) => {
                    let mut f = fs
                        .root_dir()
                        .open_file(&dest_path)
                        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    f.truncate().map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    f
                }
            };
            std::io::copy(&mut src, &mut dst)
                .with_context(|| format!("copy {}", path.display()))?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct BootSectorConfig {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    fats: u8,
    fat_size: u32,
    media: u8,
    total_sectors: u32,
    root_cluster: u32,
}

fn write_root_directory(
    cluster: &mut [u8],
    name_8dot3: &[u8; 11],
    file_cluster: u32,
    file_size: u32,
) {
    cluster.fill(0);
    cluster[0..11].copy_from_slice(name_8dot3);
    cluster[11] = 0x20;
    let high = (file_cluster >> 16) as u16;
    let low = file_cluster as u16;
    cluster[20..22].copy_from_slice(&high.to_le_bytes());
    cluster[26..28].copy_from_slice(&low.to_le_bytes());
    cluster[28..32].copy_from_slice(&file_size.to_le_bytes());
}
