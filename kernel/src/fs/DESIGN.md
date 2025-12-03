# Filesystem Module Design Notes

## Scope
- Provides a minimal read-only VFS surface: path parsing (absolute only, rejects `..`), a global
  root mount, and basic metadata exposure.
- Exposes two core traits: `Directory` (lookup/list) and `File` (read-only, offset-based), wrapped
  in `NodeRef` so callers can resolve paths without leaking concrete filesystem types.
- A lightweight file descriptor table (`FdTable`) tracks per-handle offsets; it is currently global
  and detached from process state, acting as the future integration point for per-process tables.

## VFS Behaviour
- `mount_root` installs a single root filesystem; test-only helpers can replace it to keep tests
  isolated. Path resolution walks the mount tree starting at root and fails fast on non-directory
  traversal.
- `VfsPath` normalises out empty/`.` segments and rejects `..` to avoid partial relative semantics
  until a full path resolution policy is in place.
- `OPEN_FILE_TABLE` increments offsets on successful reads, enabling simple sequential access; write
  and mmap are intentionally absent until a page cache exists.

## FAT32 Driver (Read-Only)
- `FatFileSystem` wraps a shared `BlockDevice` (via `SharedBlockDevice`); only 512-byte logical
  sectors are accepted to keep the initial implementation simple.
- Short names (8.3) are supported; long filename entries are skipped. Comparisons are normalised to
  ASCII uppercase.
- Directory and file nodes cache their cluster chains eagerly; FAT lookups are served from a
  single-sector cache to avoid repeated device traffic.
- The driver is read-only and marks missing features (write, fsync) for future extension once page
  cache and transactional updates are defined.
