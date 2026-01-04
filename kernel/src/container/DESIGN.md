# Container Module Design Notes

## Role and Scope
- Owns kernel-resident container metadata: OCI runtime spec (`config.json`) and the mutable state
  required to track lifecycle transitions (status/pid).
- Provides a registry for creating and looking up containers by ID, backed by a `SpinLock`-guarded
  map.
- Allocates a per-container root filesystem instance at create time to keep host and container
  filesystems strictly separated.

## Static vs Dynamic Data
- Static data lives in `ContainerInfo` (`bundle_path`, parsed OCI `Spec`, and the container rootfs
  handle).
- Dynamic state lives in `ContainerState` behind a `SpinLock`, exposing status, pid, and annotations
  similar to the OCI runtime `state` payload.

## OCI Bundle Handling
- The bundle path must be absolute and must contain `config.json` in the global VFS.
- `oci-spec` is used in `no_std` mode to parse the JSON; all path fields remain string-based and no
  host filesystem helpers are used.

## Future Work
- Connect the container rootfs to process creation so container processes see only their own VFS.
- Add state persistence and OCI `state` serialization once the host ABI exposes `container_state`.
