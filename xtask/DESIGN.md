# xtask Design Notes

## Role and Scope
- Builds the kernel, generates boot images, and orchestrates QEMU test runs.
- Prepares host-side assets under `target/xtask-assets` by delegating to `xtask-assets`.

## Test Flow
- Builds the kernel test binary (`cargo test --no-run` with `build-std`).
- Creates boot images and test block/FAT images.
- Runs QEMU and interprets the test exit code.

## Host Equivalence Checks
- Runs host-side fixtures produced by `xtask-assets`; per-fixture behavior is documented alongside
  each fixture.
