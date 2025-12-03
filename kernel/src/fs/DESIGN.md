# Filesystem Module Design Notes

## Scope
- Provides a read/write VFS surface with mount support: path parsing (absolute or relative to cwd,
  rejects `..`), a root mount, and basic metadata exposure.
- Exposes core traits: `Directory` (lookup/list/create/remove) and `File` (read/write/truncate,
  offset-based), wrapped in `NodeRef` so callers can resolve paths without leaking concrete
  filesystem types.
- Each process owns its own `FdTable` and current working directory; `open` binds a file descriptor
  to that process at allocation time.

## VFS Behaviour
- `mount_root` installs a root filesystem; additional filesystems can be mounted at absolute paths
  (e.g. `/mnt`). Path resolution picks the longest matching mount prefix and resolves the tail from
  that mount’s root.
- `VfsPath` normalises out empty/`.` segments and rejects `..` to avoid partial relative semantics
  until a full path resolution policy is in place.
- Process FDs advance offsets on successful reads/writes. Write/mmap are supported only by
  filesystems that opt in (e.g. memfs); read-only filesystems return `ReadOnly`.

## FAT32 Driver (Read-Only)
- `FatFileSystem` wraps a shared `BlockDevice` (via `SharedBlockDevice`); only 512-byte logical
  sectors are accepted to keep the initial implementation simple.
- Short names (8.3) are supported; long filename entries are skipped. Comparisons are normalised to
  ASCII uppercase.
- Directory and file nodes cache their cluster chains eagerly; FAT lookups are served from a
  single-sector cache to avoid repeated device traffic.
- The driver is read-only and marks missing features (write, fsync) for future extension once page
  cache and transactional updates are defined.

## MemFS (Writable)
- An in-memory tree of directories/files backed by `SpinLock`-protected vectors, offering simple
  create/read/write/truncate/remove operations.
- Used as the writable root while FAT32 is mounted read-only (e.g. under `/mnt`) for image/asset
  ingestion.
