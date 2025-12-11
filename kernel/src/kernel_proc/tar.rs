use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::fs::{NodeRef, PathComponent, VfsError, VfsPath, with_vfs};
use crate::process::{PROCESS_TABLE, ProcessId};

const TAR_BLOCK_SIZE: usize = 512;

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
/// - Archive paths must be relative; absolute paths or `..` segments are rejected by `VfsPath`.
pub fn extract_to_ramfs(pid: ProcessId, archive_path: &str) -> Result<(), TarError> {
    let base = PROCESS_TABLE.cwd(pid).map_err(TarError::Fs)?;
    ensure_dir_exists(&base)?;

    let fd = PROCESS_TABLE
        .open_path(pid, archive_path)
        .map_err(TarError::Fs)?;
    let mut reader = TarReader::new(pid, fd);
    let result = TarExtractor { pid, base }.extract(&mut reader);
    let _ = PROCESS_TABLE.close_fd(pid, fd);
    result
}

struct TarExtractor {
    pid: ProcessId,
    base: VfsPath,
}

impl TarExtractor {
    fn extract(&self, reader: &mut TarReader) -> Result<(), TarError> {
        while let Some(entry) = reader.next_entry()? {
            let target = self.target_path(&entry.path)?;
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
                    PROCESS_TABLE
                        .symlink(self.pid, &link, target.to_string().as_str())
                        .map_err(TarError::Fs)?;
                }
                TarEntryKind::HardLink { target: src } => {
                    let parent = target.parent().ok_or(TarError::InvalidArchive)?;
                    self.ensure_dir_chain(&parent)?;
                    reader.skip_entry_data(entry.size)?;
                    let resolved = resolve_link_target(&parent, &src)?;
                    PROCESS_TABLE
                        .hard_link(
                            self.pid,
                            resolved.to_string().as_str(),
                            target.to_string().as_str(),
                        )
                        .map_err(TarError::Fs)?;
                }
                TarEntryKind::Metadata => {
                    unreachable!("metadata entries are filtered in TarReader")
                }
            }
        }
        Ok(())
    }

    fn target_path(&self, path: &VfsPath) -> Result<VfsPath, TarError> {
        if path.is_absolute() {
            return Err(TarError::InvalidArchive);
        }
        self.base.join(path).map_err(TarError::Fs)
    }

    fn ensure_dir_chain(&self, target: &VfsPath) -> Result<(), TarError> {
        let mut current = VfsPath::root();
        for component in target.components() {
            current.push(component.clone());
            let raw = current.to_string();
            PROCESS_TABLE
                .create_dir(self.pid, raw.as_str())
                .map_err(TarError::Fs)?;
        }
        Ok(())
    }

    fn write_file(&self, path: &VfsPath, data: &[u8]) -> Result<(), TarError> {
        PROCESS_TABLE
            .write_path(self.pid, path.to_string().as_str(), data)
            .map_err(TarError::Fs)
    }
}

struct TarReader {
    pid: ProcessId,
    fd: crate::fs::Fd,
    pending_path: Option<String>,
    pending_linkpath: Option<String>,
}

impl TarReader {
    fn new(pid: ProcessId, fd: crate::fs::Fd) -> Self {
        Self {
            pid,
            fd,
            pending_path: None,
            pending_linkpath: None,
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
                        VfsPath::parse(&override_path).map_err(TarError::Fs)?
                    } else {
                        VfsPath::parse(&name).map_err(TarError::Fs)?
                    };

                    return Ok(Some(TarEntry { path, size, kind }));
                }
            }
        }
    }

    fn read_entry_data(&mut self, size: usize) -> Result<Vec<u8>, TarError> {
        let mut buf = Vec::with_capacity(size);
        buf.resize(size, 0);
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
        let mut filled = 0;
        while filled < buf.len() {
            let read = PROCESS_TABLE
                .read_fd(self.pid, self.fd, &mut buf[filled..])
                .map_err(TarError::Fs)?;
            if read == 0 {
                return Err(TarError::UnexpectedEof);
            }
            filled += read;
        }
        Ok(())
    }

    fn skip_bytes(&mut self, mut bytes: usize) -> Result<(), TarError> {
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
    path: VfsPath,
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

fn ensure_dir_exists(path: &VfsPath) -> Result<(), TarError> {
    with_vfs(|vfs| match vfs.open_absolute(path)? {
        NodeRef::Directory(_) => Ok(()),
        NodeRef::File(_) | NodeRef::Symlink(_) => Err(VfsError::NotDirectory),
    })
    .map_err(TarError::Fs)?;
    Ok(())
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
        if !full.ends_with(&[b'/']) {
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

fn parse_pax_fields(data: &[u8]) -> Result<Option<(Option<String>, Option<String>)>, TarError> {
    // Lines follow the format "<len> key=value\n"; len is ignored here.
    let mut path = None;
    let mut linkpath = None;
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut iter = line.splitn(2, |b| *b == b' ');
        let _len = iter.next();
        if let Some(kv) = iter.next() {
            if let Some(eq) = kv.iter().position(|b| *b == b'=') {
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

fn resolve_link_target(base: &VfsPath, target: &str) -> Result<VfsPath, TarError> {
    if target.starts_with('/') {
        return VfsPath::parse(target).map_err(TarError::Fs);
    }

    let mut comps: Vec<PathComponent> = base.components().to_vec();
    for part in target.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if comps.pop().is_none() {
                return Err(TarError::InvalidArchive);
            }
            continue;
        }
        if part.len() > 255 {
            return Err(TarError::Fs(VfsError::NameTooLong));
        }
        comps.push(PathComponent::new(part));
    }

    Ok(VfsPath::from_components(true, comps))
}
