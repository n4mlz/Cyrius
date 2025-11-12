# Demo Catalogue Design Notes

## Purpose
- Provide a minimal, hard-coded list of demo payloads that the kernel can advertise without implementing filesystem or ELF loading.
- Serve upcoming Linux Box experiments by embedding raw Linux binaries directly into the kernel image via `include_bytes!`.
- Keep the catalogue intentionally tiny and discardable after the demo milestone.

## Structure
- `linux_box.rs` exposes `LinuxDemoSpec` entries for each embedded binary plus lightweight metadata (name/type/state/default policy/command string).
- Payload bytes live in the binary through `include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../bin/..."))`, ensuring the kernel build picks files from the repository `bin/` directory.
- `DemoKind`/`DemoState` are enums so future commands (`linux-box ls`) can render meaningful labels without ad-hoc strings in multiple places.

## Usage Expectations
- Higher layers (shell/syscall launcher) will iterate `LINUX_DEMOS` to present `linux-box ls` output.
- When executing, the launcher will choose the binary blob from `payload` and map it into the chosen process address space at a fixed virtual base (documented alongside the loader implementation).
- Default syscall policy is stored per demo; callers may override it (e.g. via CLI flags) before spawning the process.
- This directory intentionally avoids storing runtime state. Any mutable bookkeeping will live in the process/container layer so that tearing down the demos simply removes this module.
