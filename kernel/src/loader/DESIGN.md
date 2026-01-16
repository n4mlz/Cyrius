# Loader Subsystem Design Notes

## Role and Scope
- Provide program loading utilities. For now this focuses on Linux-compatible ELF64 static binaries; architecture-specific trap glue remains under `arch/`.
- Emits a `LinuxProgram` that bundles the entry point, an allocated user stack, and the initial stack pointer layout suitable for `_start`.

## Linux ELF Loader
- Supports ELF64, little-endian, `ET_EXEC`, `EM_X86_64`, and `PT_LOAD` segments only; dynamic linking, PIE, and relocations are out of scope.
- Parsing, mapping, syscall patching, and stack construction are separated into dedicated loader submodules (`elf`, `map`, `patch`, `stack`) for easier evolution.
- Maps each loadable segment into the target process address space with `USER` permissions derived from ELF `p_flags` (R/W/X). Backing frames are freshly allocated via the global frame allocator.
- Copies file-backed bytes to the mapped region and zero-fills the remaining `p_memsz - p_filesz` portion for `.bss`.
- Rewrites `syscall` instructions (`0x0f 0x05`) in executable segments into `int 0x80` so we can reuse the existing software-interrupt path until proper `SYSCALL/SYSRET` MSR plumbing is added.
- Before mapping a new image, any existing mappings in the target segment range are unmapped and frames are returned to the allocator. This allows repeated loads in the shared kernel address space without colliding at fixed ELF virtual addresses.
- Builds a minimal SysV-style stack: `argc=0`, `argv[0]=NULL`, `envp[0]=NULL`, `AT_NULL` terminator. The stack pointer is 16-byte aligned before pushing.
- Segments are initially mapped writable to populate contents, then write permission is dropped if the ELF flags omit it so CR0.WP=1 でもロード時に落ちない。
- The loader writes directly to user virtual addresses, assuming the kernel shares the active address space with the target process. Once per-process address-space isolation is introduced, we will need a staging map (or copy-on-write) path.

## API Contracts
- `load_elf(pid, path)` resolves paths relative to the process CWD and expects the VFS to be initialised. It returns `LinuxProgram { entry, user_stack, stack_pointer }`.
- Caller is responsible for creating a thread that uses the returned stack pointer instead of the raw top of the allocated stack.
- Assumes the process address space is reachable from the loader context (current design shares the kernel address space across processes).

## Future Work
- Add support for PIE, dynamic linking, and auxiliary vectors (`AT_PHDR`, `AT_ENTRY`, etc.).
- Integrate per-process address spaces once user-mode isolation lands.
- Extend stack construction to carry argv/envp from the caller and populate auxv fields needed by libc.***
