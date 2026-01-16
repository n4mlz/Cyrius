# Container Module Design Notes

## Role and Scope
- Owns kernel-resident container metadata: OCI runtime spec (`config.json`) and the mutable state
  required to track lifecycle transitions (status/pid).
- Provides a `ContainerTable` for creating and looking up containers by ID, backed by a
  `ContainerRepository` that encapsulates the lock-protected map.
- Resolves the bundle rootfs directory specified in `config.json` and stores a handle so container
  processes can be isolated from the host filesystem.

## Static vs Dynamic Data
- `ContainerState` holds the OCI-style runtime state (`ociVersion`, `id`, `status`, `pid`,
  `bundlePath`, `annotations`) and is paired with `ContainerContext` inside a single lock.
- The parsed OCI `Spec` (`config.json`) is stored immutably as `Arc<Spec>` so it can be shared
  without additional locking.

## OCI Bundle Handling
- The bundle path must be absolute and must contain `config.json` in the global VFS.
- `SpecLoader` handles reading/parsing `config.json` and resolving the rootfs directory; table
  management stays in `ContainerTable`/`ContainerRepository`.

## Future Work
- Connect the container rootfs to process creation so container processes see only their own VFS.
- Add state persistence and OCI `state` serialization once the host ABI exposes `container_state`.
