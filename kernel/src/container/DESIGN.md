# Container Module Design Notes

## Role and Scope
- Owns kernel-resident container metadata: OCI runtime spec (`config.json`) and the mutable state
  required to track lifecycle transitions (status/pid).
- Provides a `ContainerTable` for creating and looking up containers by ID, backed by a
  `ContainerRepository` that encapsulates the lock-protected map.
- Builds a container-scoped VFS instance rooted at the bundle rootfs directory specified in
  `config.json`, so container processes resolve paths without touching the host VFS.
- Tracks container-owned process IDs so process visibility stays container-scoped even before
  full PID namespaces exist.

## Static vs Dynamic Data
- `ContainerState` holds the OCI-style runtime state (`ociVersion`, `id`, `status`, `pid`,
  `bundlePath`, `annotations`) and is paired with `ContainerContext` inside a single lock.
- `ContainerMutable` also keeps a process list for the container; the init process PID is mirrored
  in `ContainerState::pid` so OCI `state` reports it consistently.
- The parsed OCI `Spec` (`config.json`) is stored immutably as `Arc<Spec>` so it can be shared
  without additional locking.

## OCI Bundle Handling
- The bundle path must be absolute and must contain `config.json` in the global VFS.
- `SpecLoader` handles reading/parsing `config.json` and building the container VFS rooted at the
  resolved rootfs directory; table management stays in `ContainerTable`/`ContainerRepository`.
- The container VFS currently copies the rootfs directory into container-owned memfs, so the mount
  table and storage are isolated from the host VFS.
- The container VFS injects minimal device nodes (`/dev/tty`, `/dev/console`) backed by the global
  tty device to keep Linux userlands functional without a full devtmpfs implementation.
- The container VFS backing is selected by `CONTAINER_VFS_BACKING` and currently hard-coded to
  ramfs.

## Runtime Start Flow
- `container::runtime` parses `Spec.process`, resolves `args[0]` as the entrypoint, and applies
  `cwd` before loading the ELF image.
- Container init processes are created with Linux ABI and are tied to the container VFS at process
  creation time, ensuring path resolution never touches the host VFS.
- Starting a container transitions status from `Created` to `Running` and stores the init PID.

## Future Work
- Add state persistence and OCI `state` serialization once the host ABI exposes `container_state`.
