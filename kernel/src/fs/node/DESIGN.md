# Node Layer Design Notes

## Scope
- Defines inode-like, persistent abstractions that describe filesystem meaning and open-time
  validation.
- Separates responsibilities by node kind:
  - `Node` covers common metadata and `open`.
  - `DirNode` covers directory-only operations (lookup, create, unlink, link, read_dir).
  - `SymlinkNode` covers symlink-only operations (`readlink`).
- Uses dynamic dispatch (`Node::as_dir`, `Node::as_symlink`) so callers do not need to branch on
  `NodeKind` to access kind-specific behaviour.

## Metadata Contract
- `NodeStat` is intentionally minimal: only `kind` and `size` are present.
- Ownership, permission bits, and timestamps are planned but not implemented yet; they will be
  added once there is an end-to-end story for credentials and timekeeping.

## Planned Node Kinds
- `NodeKind::{BlockDevice, Pipe, Socket}` are reserved for future expansion.
- The corresponding node traits/implementations are not present yet. When they land, they should
  follow the same pattern: a small kind-specific trait plus `Node::as_*` adapters.

## Reusable Implementations
- `CharDeviceNode` adapts a character device driver into a `Node` by returning a device-backed
  `File` from `open`.
- `devfs` wiring lives outside this layer (`kernel/src/fs/devfs.rs`) to keep policy (which device
  nodes exist) separate from mechanism (how a char device becomes a node).
