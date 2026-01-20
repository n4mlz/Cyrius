# xtask-assets Design Notes

## Role and Scope
- Builds host-side fixtures consumed by kernel tests and QEMU images.
- Outputs all generated artifacts under `target/xtask-assets` to keep the repo clean.

## Subdirectories
- `fixtures/` holds fixture sources; see per-fixture DESIGN.md for details.
- Tar asset generation and external dependencies are described in the relevant subdirectory docs.

## Dependencies
- `cc` toolchain for building the syscall fixture.
- `skopeo` + `umoci` and network access for the OCI-derived busybox tar.
