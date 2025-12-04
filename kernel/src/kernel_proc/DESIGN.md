# Kernel Processes (Shell / Linux Box)

## Role and Scope
- Groups kernel-resident processes such as the interactive shell and the Linux ELF launcher.
- Lives under `kernel_proc` to keep kernel-only utilities together rather than scattering top-level modules.

## Shell
- Provides a minimal REPL for filesystem operations and a front-end to launch Linux ELF binaries via `linux-box run <path>`.
- Tokenisation is whitespace-based; quoted strings are not supported.
- Errors bubble up from the filesystem (`VfsError`), process table (`ProcessError`), loader (`LinuxLoadError`), and thread spawning (`SpawnError`) without wrapping in an extra linux-box-specific error layer.
- Runs as a kernel thread associated with a kernel process, reusing the process CWD and FD table for all commands.

## Linux Box
- Resolves paths relative to the caller’s CWD, switches the target process ABI to Linux, loads a static ELF64, rewrites `syscall` opcodes to `int 0x80`, and spawns a user thread using the loader-prepared stack pointer.
- Surfaces errors directly from existing subsystems (process table, VFS, ELF loader, thread spawning) for transparency.
- Known constraints: only `write`/`getpid`/`exit` syscalls, static non-PIE ELF64, no dynamic linking.

## Future Work
- Add richer status reporting (exit code, stdout capture) once process lifecycle management and IPC mature.
- Extend the shell parser to handle quoted paths and background execution.
