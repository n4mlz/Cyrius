# Concrete Filesystems Design Notes

## Scope
- Houses concrete filesystem implementations that satisfy the node/file contracts from
  `kernel/src/fs/node/`.
- Each filesystem is responsible for its own on-disk/in-memory semantics, while the top-level VFS
  (`kernel/src/fs/mod.rs`) handles mount selection and path resolution.

## MemFS (Writable)
- Provides a simple in-memory tree using `SpinLock`-protected maps and buffers.
- Directories implement `DirNode`, regular files implement `Node`, and symlinks implement
  `SymlinkNode`.
- Intended as the default writable root and as a container-private backing store.

## FAT32 (Read-Only)
- Minimal FAT32 reader intended for boot-time asset ingestion.
- Enforces a 512-byte logical sector and a FAT32 BPB to keep the implementation small and
  predictable.
- Directory nodes implement `DirNode`, and file nodes implement `Node`.
- The driver is read-only; write support is deferred until allocation, caching, and crash-safety
  policies are specified.
