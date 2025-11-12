# Demo Catalogue Design Notes

## Purpose
- Provide a minimal, hard-coded list of demo payloads that the kernel can advertise without implementing filesystem or ELF loading.
- Serve upcoming Linux Box experiments by embedding raw Linux binaries directly into the kernel image via `include_bytes!`.
- Keep the catalogue intentionally tiny and discardable after the demo milestone.

## Structure
- `linux_box/catalog.rs` exposes `LinuxDemoSpec` entries for each embedded binary plus lightweight metadata (name/type/state/default policy/command string).
- Payload bytes live in the binary through `include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../bin/..."))`, ensuring the kernel build picks files from the repository `bin/` directory.
- `DemoKind`/`DemoState` are enums so `linux-box ls` can render meaningful labels without ad-hoc strings in multiple places.
- `linux_box/shell.rs` spawns a dedicated kernel thread after scheduler start, presents the `OS>` prompt, and dispatches `linux-box ls` / `linux-box run` commands. The shell interacts with the UART directly for both input and output so the demo works over the serial console.
- `linux_box/runner.rs` bridges the shell and the process subsystem: it allocates a Linux ABI process, loads the selected payload, and asks the scheduler to spawn a user thread. Policy overrides (via `--policy=`) are translated into `SyscallPolicy` before the process is created.
- `linux_box/loader.rs` pins each payload at a deterministic slot inside the lower canonical address space. It relies on the architecture-specific `map_user_image` helper to map anonymous pages, copy the payload, and drop write permissions before the process runs.

## Usage Expectations
- Higher layers (shell/syscall launcher) will iterate `LINUX_DEMOS` to present `linux-box ls` output.
- When executing, the loader chooses a per-process virtual base (currently a simple slot derived from PID) and maps the payload into the chosen address space using user RX permissions.
- Default syscall policy is stored per demo; callers may override it (e.g. via CLI flags) before spawning the process.
- This directory intentionally avoids storing runtime state beyond the `LoadedImage` handle returned by the loader. Runtime ownership remains with the thread subsystem so reclaiming resources is as simple as letting the thread exit.
