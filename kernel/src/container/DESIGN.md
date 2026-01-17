# Container Module Design Notes

## Role and Scope
- Owns kernel-resident container metadata: OCI runtime spec (`config.json`) and the mutable state
  required to track lifecycle transitions (status/pid).
- Provides a `ContainerTable` for creating and looking up containers by ID, backed by a
  `ContainerRepository` that encapsulates the lock-protected map.
- Builds a container-scoped VFS instance rooted at the bundle rootfs directory specified in
  `config.json`, so container processes resolve paths without touching the host VFS.

## Static vs Dynamic Data
- `ContainerState` holds the OCI-style runtime state (`ociVersion`, `id`, `status`, `pid`,
  `bundlePath`, `annotations`) and is paired with `ContainerContext` inside a single lock.
- The parsed OCI `Spec` (`config.json`) is stored immutably as `Arc<Spec>` so it can be shared
  without additional locking.

## OCI Bundle Handling
- The bundle path must be absolute and must contain `config.json` in the global VFS.
- `SpecLoader` handles reading/parsing `config.json` and building the container VFS rooted at the
  resolved rootfs directory; table management stays in `ContainerTable`/`ContainerRepository`.
- The container VFS currently copies the rootfs directory into container-owned memfs, so the mount
  table and storage are isolated from the host VFS.
- The container VFS backing is selected by `CONTAINER_VFS_BACKING` and currently hard-coded to
  ramfs.

## Future Work
- Connect the container rootfs to process creation so container processes see only their own VFS.
- Add state persistence and OCI `state` serialization once the host ABI exposes `container_state`.
