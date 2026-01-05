# Container Module Design Notes

## Role and Scope
- Owns kernel-resident container metadata: OCI runtime spec (`config.json`) and the mutable state
  required to track lifecycle transitions (status/pid).
- Provides a `ContainerTable` for creating and looking up containers by ID, backed by a
  `SpinLock`-guarded map.
- Resolves the bundle rootfs directory specified in `config.json` and stores a handle so container
  processes can be isolated from the host filesystem.

## Static vs Dynamic Data
- `ContainerState` holds the OCI-style runtime state (`ociVersion`, `id`, `status`, `pid`,
  `bundlePath`, `annotations`) and is protected by a `SpinLock`.
- The parsed OCI `Spec` (`config.json`) is stored separately as static metadata.
- `ContainerContext` tracks runtime-managed resources such as the container rootfs handle.

## OCI Bundle Handling
- The bundle path must be absolute and must contain `config.json` in the global VFS.
- `oci-spec` is used in `no_std` mode to parse the JSON; all path fields remain string-based and no
  host filesystem helpers are used.

## Future Work
- Connect the container rootfs to process creation so container processes see only their own VFS.
- Add state persistence and OCI `state` serialization once the host ABI exposes `container_state`.
