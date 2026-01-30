# Filesystem Module Design Notes

## Scope
- Provides a read/write VFS surface with mount support: path parsing (absolute or relative to cwd,
  rejects `..`), a root mount, and basic metadata exposure.
- Exposes a persistent `Node` abstraction (inode-like) that owns metadata and open-time validation,
  while `File` represents per-open state (offset/flags) and handles I/O operations.
- Directory and symlink responsibilities are split out of `Node` into `DirNode` and
  `SymlinkNode`. The VFS uses dynamic dispatch (`as_dir` / `as_symlink`) instead of routing all
  operations through a single mega-trait.
- Each process owns its own `FdTable` and current working directory; `open` resolves a `Node`,
  calls `Node::open`, and binds the resulting `File` to an FD in the process table. Container
  processes route path resolution through the container VFS instead of the global VFS.
- Common filesystem helpers that operate directly on `Node` live in `fs::ops`; any process-aware
  path handling stays in `process::fs`.
- The VFS differentiates node kinds via `NodeKind` (regular/dir/symlink/device/etc.); device nodes
  are modelled as `NodeKind::CharDevice` and are exposed under `/dev` by `fs::devfs`.
- `NodeStat` is intentionally minimal (`kind` + `size`). Ownership, permission bits, and timestamp
  fields are planned but not implemented yet.
- `NodeKind::{BlockDevice, Pipe, Socket}` are reserved for future node types. The corresponding
  node traits/implementations are not present yet and should be treated as planned work.

## VFS Behaviour
- `mount_root` installs a root filesystem; additional filesystems can be mounted at absolute paths
  (e.g. `/mnt`). Path resolution picks the longest matching mount prefix and resolves the tail from
  that mount’s root.
- Directory listings include mount points even if the parent directory does not contain an explicit
  entry, making mounted filesystems visible under their parent (e.g. `/mnt` shows up in `/`).
- The root node is asserted to be directory-like (`Node::as_dir().is_some()`), matching the
  expectation that mounts are attached to directory nodes.
- `Path::parse` normalises out empty/`.` segments and rejects `..` to keep raw paths strict.
- `Path::resolve` handles relative inputs by folding `..` segments against a base path, clamping
  at the root so callers (process VFS ops, tar extraction, loader) share consistent behaviour.
- Process FDs advance offsets on successful reads/writes. Write support is provided by filesystems
  that opt in (e.g. memfs); read-only filesystems return `ReadOnly`.
- Directory handles store a per-FD directory offset used by the Linux `getdents64` syscall; the
  kernel advances the cursor after emitting each entry.
- `File::seek` allows per-open offsets to be repositioned; regular file handles implement it while
  character devices and directories report `NotFile`.
- Control-plane operations (ioctl-style) are routed through `File::ioctl` and only device-backed
  `File` implementations opt in, keeping ioctl out of regular file nodes.
- `FileSystemProbe` abstracts per-filesystem probing so boot-time selection can iterate through
  candidate block devices without hard-coding driver logic in the kernel entrypoint.

## Layout
- `node/` defines inode-like traits (`Node`, `DirNode`, `SymlinkNode`) plus reusable node
  implementations such as `CharDeviceNode`. See `kernel/src/fs/node/DESIGN.md`.
- `vfs/` contains concrete filesystems (currently memfs and FAT32). See
  `kernel/src/fs/vfs/DESIGN.md`.
- `file.rs` defines the per-open `File` trait, and `path.rs` defines `Path` parsing and
  normalisation shared across the VFS surface.
