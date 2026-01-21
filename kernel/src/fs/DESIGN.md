# Filesystem Module Design Notes

## Scope
- Provides a read/write VFS surface with mount support: path parsing (absolute or relative to cwd,
  rejects `..`), a root mount, and basic metadata exposure.
- Exposes core traits: `Directory` (lookup/list/create/remove) and `File` (read/write/truncate,
  offset-based), wrapped in `NodeRef` so callers can resolve paths without leaking concrete
  filesystem types.
- Each process owns its own `FdTable` and current working directory; `open` binds a file descriptor
  to that process at allocation time.
- Common filesystem helpers that operate directly on `Directory`/`File` live in `fs::ops`; any
  process-aware path handling stays in `process::fs`.
- A global tty implements the `File` trait so processes can install stdin/stdout/stderr in their
  `FdTable` without exposing UART details.
- TTY reads drain the buffered input first; only when no buffered bytes are available does the
  implementation consult the hardware console to avoid blocking after partial reads.

## VFS Behaviour
- `mount_root` installs a root filesystem; additional filesystems can be mounted at absolute paths
  (e.g. `/mnt`). Path resolution picks the longest matching mount prefix and resolves the tail from
  that mount’s root.
- Directory listings include mount points even if the parent directory does not contain an explicit
  entry, making mounted filesystems visible under their parent (e.g. `/mnt` shows up in `/`).
- `VfsPath::parse` normalises out empty/`.` segments and rejects `..` to keep raw paths strict.
- `VfsPath::resolve` handles relative inputs by folding `..` segments against a base path, clamping
  at the root so callers (process VFS ops, tar extraction, loader) share consistent behaviour.
- Process FDs advance offsets on successful reads/writes. Write/mmap are supported only by
  filesystems that opt in (e.g. memfs); read-only filesystems return `ReadOnly`.
- `FileSystemProbe` abstracts per-filesystem probing so boot-time selection can iterate through
  candidate block devices without hard-coding driver logic in the kernel entrypoint.

## FAT32 Driver (Read-Only)
- `FatFileSystem` wraps a shared `BlockDevice` (via `SharedBlockDevice`); only 512-byte logical
  sectors are accepted to keep the initial implementation simple.
- Short names (8.3) are supported; long filename entries are skipped. Comparisons are normalised to
  ASCII uppercase.
- Long filename entries are parsed to preserve mixed-case host names when present; fallback to
  short-name uppercase normalisation otherwise.
- The BPB is validated strictly as FAT32 (rejects FAT12/16 by requiring zeroed FAT16 fields and a
  root cluster number >= 2) to avoid mounting incompatible images.
- Directory and file nodes cache their cluster chains eagerly; FAT lookups are served from a
  single-sector cache to avoid repeated device traffic.
- The driver is read-only and marks missing features (write, fsync) for future extension once page
  cache and transactional updates are defined.

## MemFS (Writable)
- An in-memory tree of directories/files backed by `SpinLock`-protected vectors, offering simple
  create/read/write/truncate/remove operations.
- Used as the writable root while FAT32 is mounted read-only (e.g. under `/mnt`) for image/asset
  ingestion.
