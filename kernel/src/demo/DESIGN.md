# Demo Catalogue Design Notes

## Purpose
- Provide a minimal, hard-coded list of demo payloads that the kernel can advertise without implementing a filesystem.
- Serve upcoming Linux Box experiments by embedding ELF64 Linux binaries directly into the kernel image via `include_bytes!`.
- Keep the catalogue intentionally tiny and discardable after the demo milestone.

## Structure
- `linux_box/catalog.rs` exposes `LinuxDemoSpec` entries for each embedded binary plus lightweight metadata (name/type/state/default policy/command string).
- Payload bytes live in the binary through `include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../elf/..."))`, ensuring the kernel build picks files from the repository `elf/` directory.
- `DemoKind`/`DemoState` are enums so `linux-box ls` can render meaningful labels without ad-hoc strings in multiple places.
- `linux_box/shell.rs` spawns a dedicated kernel thread after scheduler start, presents the `OS>` prompt, and dispatches `linux-box ls` / `linux-box run` commands. The shell interacts with the UART directly for both input and output so the demo works over the serial console.
- `linux_box/runner.rs` bridges the shell and the process subsystem: it allocates a Linux ABI process, loads the selected payload, and asks the scheduler to spawn a user thread. Policy overrides (via `--policy=`) are translated into `SyscallPolicy` before the process is created.
- `linux_box/loader.rs` parses each ELF64 payload (ET_EXEC/ET_DYN, x86_64, little-endian), enumerates `PT_LOAD` program headers, and maps segments at their declared virtual addresses with permissions derived from `PF_X/PF_W`. It relies on the architecture-specific `map_user_image` helper to back each segment with freshly allocated pages, zero the `p_memsz - p_filesz` tail, and drop write permissions before the process runs.

## Usage Expectations
- Higher layers (shell/syscall launcher) will iterate `LINUX_DEMOS` to present `linux-box ls` output.
- When executing, the loader honours the ELF entry point/segment addresses directly (processes currently share the kernel address space, so only one demo should be running at a time). Each `PT_LOAD` segment is zero-initialised before its file contents are copied in, mirroring the behaviour of a real ELF loader.
- Default syscall policy is stored per demo; callers may override it (e.g. via CLI flags) before spawning the process.
- This directory intentionally avoids storing runtime state beyond the `LoadedImage` handle returned by the loader. Runtime ownership remains with the thread subsystem so reclaiming resources is as simple as letting the thread exit.
