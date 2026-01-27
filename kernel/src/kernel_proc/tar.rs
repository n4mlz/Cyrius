use crate::fs::{Path, PathComponent, VfsError};
use crate::process::ProcessId;
use crate::process::fs as proc_fs;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

const TAR_BLOCK_SIZE: usize = 512;
const TAR_VERBOSE: bool = false;

#[derive(Debug)]
pub enum TarError {
    Fs(VfsError),
    InvalidArchive,
    UnsupportedType(u8),
    UnexpectedEof,
    SizeOverflow,
    InvalidUtf8,
    ChecksumMismatch,
}

/// Extracts a POSIX tar archive into the caller's current working directory.
///
/// # Notes
/// - Assumes the current working directory is backed by a writable filesystem such as the in-memory ramfs.
/// - Regular files, directories, symlinks, and hard links are supported. Other entry types fail with `UnsupportedType`.
/// - Archive paths must be relative; absolute paths or `..` segments are rejected by `Path`.
pub fn extract_to_ramfs(
    pid: ProcessId,
    archive_path: &str,
    dest: Option<&str>,
) -> Result<(), TarError> {
    let cwd = proc_fs::cwd(pid).map_err(TarError::Fs)?;
    let base = match dest {
        Some(path) => Path::resolve(path, &cwd).map_err(TarError::Fs)?,
        None => cwd,
    };
    TarExtractor::ensure_dir_chain_static(pid, &base)?;

    let fd = proc_fs::open_path(pid, archive_path, 0).map_err(TarError::Fs)?;
    let mut reader = TarReader::new(pid, fd);
    let result = TarExtractor {
        pid,
        base,
        pending_hardlinks: Vec::new(),
    }
    .extract(&mut reader);
    let _ = proc_fs::close_fd(pid, fd);
    result
}

struct TarExtractor {
    pid: ProcessId,
    base: Path,
    pending_hardlinks: Vec<PendingHardLink>,
}

struct PendingHardLink {
    link: Path,
    parent: Path,
    target: String,
}

impl TarExtractor {
    fn extract(&mut self, reader: &mut TarReader) -> Result<(), TarError> {
        while let Some(entry) = reader.next_entry()? {
            let target = self.target_path(&entry.path)?;
            debug_log("entry", &entry.kind, &target);
            match entry.kind {
                TarEntryKind::Directory => {
                    self.ensure_dir_chain(&target)?;
                    reader.skip_entry_data(entry.size)?;
                }
                TarEntryKind::File => {
                    let parent = target.parent().ok_or(TarError::InvalidArchive)?;
                    self.ensure_dir_chain(&parent)?;
                    let data = reader.read_entry_data(entry.size)?;
                    self.write_file(&target, &data)?;
                }
                TarEntryKind::Symlink { target: link } => {
                    let parent = target.parent().ok_or(TarError::InvalidArchive)?;
                    self.ensure_dir_chain(&parent)?;
                    reader.skip_entry_data(entry.size)?;
                    proc_fs::symlink(self.pid, &link, target.to_string().as_str())
                        .map_err(TarError::Fs)?;
                }
                TarEntryKind::HardLink { target: src } => {
                    let parent = target.parent().ok_or(TarError::InvalidArchive)?;
                    self.ensure_dir_chain(&parent)?;
                    reader.skip_entry_data(entry.size)?;
                    self.pending_hardlinks.push(PendingHardLink {
                        link: target.clone(),
                        parent: parent.clone(),
                        target: src,
                    });
                }
                TarEntryKind::Metadata => {
                    unreachable!("metadata entries are filtered in TarReader")
                }
            }
        }
        self.realise_hardlinks()?;
        Ok(())
    }

    fn target_path(&self, path: &Path) -> Result<Path, TarError> {
        if path.is_absolute() {
            return Err(TarError::InvalidArchive);
        }
        self.base.join(path).map_err(TarError::Fs)
    }

    fn ensure_dir_chain(&self, target: &Path) -> Result<(), TarError> {
        Self::ensure_dir_chain_static(self.pid, target)
    }

    fn ensure_dir_chain_static(pid: ProcessId, target: &Path) -> Result<(), TarError> {
        let mut current = Path::root();
        for component in target.components() {
            current.push(component.clone());
            let raw = current.to_string();
            proc_fs::create_dir(pid, raw.as_str()).map_err(TarError::Fs)?;
        }
        Ok(())
    }

    fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), TarError> {
        proc_fs::write_path(self.pid, path.to_string().as_str(), data).map_err(TarError::Fs)
    }

    fn realise_hardlinks(&self) -> Result<(), TarError> {
        for pending in &self.pending_hardlinks {
            let first = resolve_link_target(&self.base, &pending.parent, pending.target.as_str())?;
            if TAR_VERBOSE {
                crate::println!(
                    "[tar] hardlink target={} link={} resolved={}",
                    pending.target,
                    pending.link,
                    first
                );
            }
            match proc_fs::hard_link(
                self.pid,
                first.to_string().as_str(),
                pending.link.to_string().as_str(),
            ) {
                Ok(()) => continue,
                Err(VfsError::NotFound) => {
                    let root_rel =
                        resolve_link_target(&self.base, &self.base, pending.target.as_str())?;
                    proc_fs::hard_link(
                        self.pid,
                        root_rel.to_string().as_str(),
                        pending.link.to_string().as_str(),
                    )
                    .map_err(TarError::Fs)?;
                }
                Err(e) => return Err(TarError::Fs(e)),
            }
        }
        Ok(())
    }
}

struct TarReader {
    pid: ProcessId,
    fd: crate::fs::Fd,
    pending_path: Option<String>,
    pending_linkpath: Option<String>,
    cursor: u64,
}

impl TarReader {
    fn new(pid: ProcessId, fd: crate::fs::Fd) -> Self {
        Self {
            pid,
            fd,
            pending_path: None,
            pending_linkpath: None,
            cursor: 0,
        }
    }

    fn next_entry(&mut self) -> Result<Option<TarEntry>, TarError> {
        loop {
            let mut header = [0u8; TAR_BLOCK_SIZE];
            self.read_exact(&mut header)?;

            if header.iter().all(|&b| b == 0) {
                return Ok(None);
            }

            validate_checksum(&header)?;

            let name = parse_name(&header)?;
            let link_name = parse_link_name(&header)?;
            let size = parse_octal(&header[124..136])?;
            let size = usize::try_from(size).map_err(|_| TarError::SizeOverflow)?;
            let kind = match header[156] {
                0 | b'0' => TarEntryKind::File,
                b'5' => TarEntryKind::Directory,
                b'1' => {
                    let target = self
                        .pending_linkpath
                        .take()
                        .or_else(|| link_name.clone())
                        .ok_or(TarError::InvalidArchive)?;
                    TarEntryKind::HardLink { target }
                }
                b'2' => {
                    let target = self
                        .pending_linkpath
                        .take()
                        .or_else(|| link_name.clone())
                        .ok_or(TarError::InvalidArchive)?;
                    TarEntryKind::Symlink { target }
                }
                b'x' | b'g' => TarEntryKind::Metadata,
                other => return Err(TarError::UnsupportedType(other)),
            };

            match kind {
                TarEntryKind::Metadata => {
                    let data = self.read_entry_data(size)?;
                    if let Some((path, linkpath)) = parse_pax_fields(&data)? {
                        if let Some(path) = path {
                            self.pending_path = Some(path);
                        }
                        if let Some(linkpath) = linkpath {
                            self.pending_linkpath = Some(linkpath);
                        }
                    }
                    continue;
                }
                _ => {
                    let path = if let Some(override_path) = self.pending_path.take() {
                        Path::parse(&override_path).map_err(TarError::Fs)?
                    } else {
                        Path::parse(&name).map_err(TarError::Fs)?
                    };

                    return Ok(Some(TarEntry { path, size, kind }));
                }
            }
        }
    }

    fn read_entry_data(&mut self, size: usize) -> Result<Vec<u8>, TarError> {
        let mut buf = vec![0; size];
        if size > 0 {
            self.read_exact(&mut buf)?;
        }
        self.skip_padding(size)?;
        Ok(buf)
    }

    fn skip_entry_data(&mut self, size: usize) -> Result<(), TarError> {
        if size > 0 {
            self.skip_bytes(size)?;
        }
        self.skip_padding(size)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TarError> {
        let start_offset = self.cursor;
        let mut filled = 0;
        let log_interval = 64 * 1024;
        let mut next_log = log_interval;
        if TAR_VERBOSE && buf.len() >= TAR_BLOCK_SIZE {
            crate::println!("[tar] read_exact offset={} len={}", self.cursor, buf.len());
        }
        while filled < buf.len() {
            let read =
                proc_fs::read_fd(self.pid, self.fd, &mut buf[filled..]).map_err(TarError::Fs)?;
            if read == 0 {
                return Err(TarError::UnexpectedEof);
            }
            filled += read;
            self.cursor = self
                .cursor
                .checked_add(read as u64)
                .ok_or(TarError::SizeOverflow)?;
            if TAR_VERBOSE && buf.len() > log_interval && filled >= next_log.min(buf.len()) {
                crate::println!(
                    "[tar] read progress offset={} +{}/{}",
                    start_offset,
                    filled,
                    buf.len()
                );
                next_log = next_log.saturating_add(log_interval);
            }
        }
        Ok(())
    }

    fn skip_bytes(&mut self, mut bytes: usize) -> Result<(), TarError> {
        if TAR_VERBOSE && bytes > 0 {
            crate::println!("[tar] skip_bytes offset={} len={}", self.cursor, bytes);
        }
        let mut scratch = [0u8; 256];
        while bytes > 0 {
            let chunk = bytes.min(scratch.len());
            self.read_exact(&mut scratch[..chunk])?;
            bytes -= chunk;
        }
        Ok(())
    }

    fn skip_padding(&mut self, size: usize) -> Result<(), TarError> {
        let rem = size % TAR_BLOCK_SIZE;
        if rem == 0 {
            return Ok(());
        }
        let padding = TAR_BLOCK_SIZE - rem;
        self.skip_bytes(padding)
    }
}

struct TarEntry {
    path: Path,
    size: usize,
    kind: TarEntryKind,
}

enum TarEntryKind {
    File,
    Directory,
    Symlink { target: String },
    HardLink { target: String },
    Metadata,
}

fn parse_name(header: &[u8]) -> Result<String, TarError> {
    let name_bytes = &header[0..100];
    let prefix_bytes = &header[345..500];
    let name = trim_nul(name_bytes);
    let prefix = trim_nul(prefix_bytes);

    let combined = if prefix.is_empty() {
        name
    } else {
        let mut full = prefix;
        if !full.ends_with(b"/") {
            full.push(b'/');
        }
        full.extend_from_slice(&name);
        full
    };

    core::str::from_utf8(&combined)
        .map(|s| s.to_string())
        .map_err(|_| TarError::InvalidUtf8)
}

fn parse_link_name(header: &[u8]) -> Result<Option<String>, TarError> {
    let link_bytes = &header[157..257];
    let trimmed = trim_nul(link_bytes);
    if trimmed.is_empty() {
        Ok(None)
    } else {
        core::str::from_utf8(&trimmed)
            .map(|s| Some(s.to_string()))
            .map_err(|_| TarError::InvalidUtf8)
    }
}

type PaxFields = (Option<String>, Option<String>);

fn parse_pax_fields(data: &[u8]) -> Result<Option<PaxFields>, TarError> {
    // Lines follow the format "<len> key=value\n"; len is ignored here.
    let mut path = None;
    let mut linkpath = None;
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut iter = line.splitn(2, |b| *b == b' ');
        let _len = iter.next();
        if let Some(kv) = iter.next()
            && let Some(eq) = kv.iter().position(|b| *b == b'=')
        {
            let key = &kv[..eq];
            let value = &kv[eq + 1..];
            if key == b"path" {
                path = Some(
                    core::str::from_utf8(value)
                        .map(|s| s.to_string())
                        .map_err(|_| TarError::InvalidUtf8)?,
                );
            } else if key == b"linkpath" {
                linkpath = Some(
                    core::str::from_utf8(value)
                        .map(|s| s.to_string())
                        .map_err(|_| TarError::InvalidUtf8)?,
                );
            }
        }
    }

    if path.is_none() && linkpath.is_none() {
        Ok(None)
    } else {
        Ok(Some((path, linkpath)))
    }
}

fn parse_octal(field: &[u8]) -> Result<u64, TarError> {
    let mut value: u64 = 0;
    let mut seen = false;
    for &b in field {
        if b == 0 || b == b' ' {
            if seen {
                break;
            }
            continue;
        }
        if !(b'0'..=b'7').contains(&b) {
            return Err(TarError::InvalidArchive);
        }
        seen = true;
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add((b - b'0') as u64))
            .ok_or(TarError::SizeOverflow)?;
    }
    Ok(value)
}

fn validate_checksum(header: &[u8]) -> Result<(), TarError> {
    let mut computed: u32 = 0;
    for (i, b) in header.iter().enumerate() {
        if (148..156).contains(&i) {
            computed += b' ' as u32;
        } else {
            computed += *b as u32;
        }
    }
    let stored = parse_octal(&header[148..156])?;
    if computed as u64 != stored {
        return Err(TarError::ChecksumMismatch);
    }
    Ok(())
}

fn trim_nul(field: &[u8]) -> Vec<u8> {
    let mut end = field.len();
    while end > 0 && field[end - 1] == 0 {
        end -= 1;
    }
    field[..end].to_vec()
}

fn resolve_link_target(
    base_root: &Path,
    link_parent: &Path,
    target: &str,
) -> Result<Path, TarError> {
    let mut comps: Vec<PathComponent> = if target.starts_with('/') {
        base_root.components().to_vec()
    } else {
        link_parent.components().to_vec()
    };
    let min_depth = base_root.components().len();
    let path_str = target.strip_prefix('/').unwrap_or(target);

    for part in path_str.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if comps.len() <= min_depth {
                return Err(TarError::InvalidArchive);
            }
            comps.pop();
            continue;
        }
        if part.len() > 255 {
            return Err(TarError::Fs(VfsError::NameTooLong));
        }
        comps.push(PathComponent::new(part));
    }

    Ok(Path::from_components(true, comps))
}

fn debug_log(label: &str, kind: &TarEntryKind, target: &Path) {
    if !TAR_VERBOSE {
        return;
    }
    let kind_text = match kind {
        TarEntryKind::File => "file",
        TarEntryKind::Directory => "dir",
        TarEntryKind::Symlink { .. } => "symlink",
        TarEntryKind::HardLink { .. } => "hardlink",
        TarEntryKind::Metadata => "metadata",
    };
    crate::println!("[tar] {label}: {kind_text} -> {}", target);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::block::SharedBlockDevice;
    use crate::device::virtio::block::with_devices;
    use crate::fs::fat32::FatFileSystem;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::fs::{Path, mount_at};
    use crate::kernel_proc::shell;
    use crate::println;
    use crate::process::PROCESS_TABLE;
    use crate::test::kernel_test_case;
    use alloc::sync::Arc;

    /// Tar fixture generated by `xtask` (via `xtask-assets`) under `target/xtask-assets`.
    const SAMPLE_WITH_LINKS: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/xtask-assets/sample_with_links.tar"
    ));
    /// Tar fixture generated by `xtask` (via `xtask-assets`) under `target/xtask-assets`.
    const BUSYBOX_TAR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/xtask-assets/busybox.tar"
    ));

    fn setup_process(name: &'static str) -> ProcessId {
        let _ = PROCESS_TABLE.init_kernel();
        force_replace_root(MemDirectory::new());
        PROCESS_TABLE
            .create_kernel_process(name)
            .expect("create process")
    }

    fn write_archive(pid: ProcessId, path: &str, data: &[u8]) {
        proc_fs::write_path(pid, path, data).expect("write archive into memfs");
    }

    fn read_all(pid: ProcessId, path: &str) -> Vec<u8> {
        let fd = proc_fs::open_path(pid, path, 0).expect("open path");
        let mut buf = [0u8; 512];
        let mut out = Vec::new();
        loop {
            let read = proc_fs::read_fd(pid, fd, &mut buf).expect("read data");
            if read == 0 {
                break;
            }
            out.extend_from_slice(&buf[..read]);
        }
        let _ = proc_fs::close_fd(pid, fd);
        out
    }

    fn read_text(pid: ProcessId, path: &str) -> String {
        let bytes = read_all(pid, path);
        core::str::from_utf8(&bytes)
            .expect("utf-8 content")
            .to_string()
    }

    fn mount_host_tar(pid: ProcessId, file: &str) -> bool {
        let mount_path = Path::parse("/mnt").expect("mount path");
        let mut mounted = false;
        with_devices(|devices| {
            for dev in devices {
                let shared = SharedBlockDevice::from_arc(dev.clone());
                if let Ok(fs) = FatFileSystem::new(shared) {
                    force_replace_root(MemDirectory::new());
                    let root: Arc<dyn crate::fs::Node> = fs.root_dir();
                    if mount_at(mount_path.clone(), root).is_err() {
                        continue;
                    }
                    let target_path = alloc::format!("/mnt/{file}");
                    if proc_fs::open_path(pid, target_path.as_str(), 0).is_ok() {
                        mounted = true;
                        break;
                    }
                }
            }
        });
        if !mounted {
            force_replace_root(MemDirectory::new());
        }
        mounted
    }

    #[kernel_test_case]
    fn tar_extracts_sample_with_links_into_root() {
        println!("[test] tar_extracts_sample_with_links_into_root");

        let pid = setup_process("tar-sample");
        write_archive(pid, "/sample_with_links.tar", SAMPLE_WITH_LINKS);

        extract_to_ramfs(pid, "/sample_with_links.tar", Some("/")).expect("extract sample tar");

        assert_eq!(
            read_text(pid, "/original.txt"),
            "Hello, World!\nThis is a sample file.\n"
        );
        assert_eq!(
            read_text(pid, "/hardlink.txt"),
            "Hello, World!\nThis is a sample file.\n"
        );
        assert_eq!(
            read_text(pid, "/documents/readme.txt"),
            "Sample document content.\n"
        );
        assert_eq!(
            read_text(pid, "/link_to_readme"),
            "Sample document content.\n"
        );
        assert_eq!(
            read_text(pid, "/link_to_docs/readme.txt"),
            "Sample document content.\n"
        );
        assert_eq!(read_text(pid, "/documents/abs_link"), "test\n");
        assert_eq!(
            read_text(pid, "/data/hardlink_to_original.txt"),
            "Hello, World!\nThis is a sample file.\n"
        );
    }

    #[kernel_test_case]
    fn tar_extracts_sample_from_fat_mount_via_shell() {
        println!("[test] tar_extracts_sample_from_fat_mount_via_shell");

        let pid = setup_process("tar-shell-fat");
        assert!(
            mount_host_tar(pid, "sample_with_links.tar"),
            "no FAT image containing sample_with_links.tar"
        );
        proc_fs::change_dir(pid, "/mnt").expect("change directory to /mnt");

        shell::run_command(pid, "tar sample_with_links.tar /").expect("tar command via shell");

        assert_eq!(
            read_text(pid, "/original.txt"),
            "Hello, World!\nThis is a sample file.\n"
        );
        assert_eq!(
            read_text(pid, "/documents/readme.txt"),
            "Sample document content.\n"
        );

        force_replace_root(MemDirectory::new());
    }

    #[kernel_test_case]
    fn tar_extracts_busybox_from_fat_mount_via_shell() {
        println!("[test] tar_extracts_busybox_from_fat_mount_via_shell");

        let pid = setup_process("tar-busybox-fat");
        assert!(
            mount_host_tar(pid, "busybox.tar"),
            "no FAT image containing busybox.tar"
        );
        proc_fs::change_dir(pid, "/mnt").expect("change directory to /mnt");

        shell::run_command(pid, "tar busybox.tar /out").expect("tar command via shell");

        let whois = read_all(pid, "/out/rootfs/bin/whois");
        assert!(
            !whois.is_empty(),
            "expected whois payload copied from busybox.tar"
        );
        let busybox = read_all(pid, "/out/rootfs/bin/busybox");
        assert_eq!(busybox, whois, "hardlink busybox should mirror whois");

        force_replace_root(MemDirectory::new());
    }

    #[kernel_test_case]
    fn tar_extracts_busybox_tar() {
        println!("[test] tar_extracts_busybox_tar");

        let pid = setup_process("tar-busybox");
        write_archive(pid, "/busybox.tar", BUSYBOX_TAR);

        extract_to_ramfs(pid, "/busybox.tar", Some("/")).expect("extract busybox tar");

        let whois = read_all(pid, "/rootfs/bin/whois");
        assert!(
            !whois.is_empty(),
            "expected non-empty busybox payload for whois"
        );
        let busybox = read_all(pid, "/rootfs/bin/busybox");
        let sh = read_all(pid, "/rootfs/bin/sh");
        assert_eq!(busybox, whois, "busybox hardlink should mirror target");
        assert_eq!(sh, whois, "sh hardlink should mirror target");
    }
}
