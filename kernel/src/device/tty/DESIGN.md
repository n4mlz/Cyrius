# TTY Device Design Notes

## Role and Scope
- Provide the kernel-resident pseudo tty used as the global console for host and Linux guest
  processes.
- Expose byte-stream read/write and minimal ioctl handling (termios, window size, process group)
  without pulling line discipline or job control into the VFS layer.

## Implementation Notes
- `TtyDevice` is a character device backed by the architecture console (`Arch::console()`).
- Input/output buffers are maintained for tests and for cases where caller-supplied input should
  be consumed before touching hardware.
- Reads block (via halt/spin) until at least one byte is available, so interactive programs do not
  observe spurious EOF when no input is pending.
- Canonical reads perform basic line editing (erase, EOF) and map carriage return to newline to
  keep serial console input usable without a full line discipline.
- Control operations (`ControlOps`) implement the minimal ioctl set required by BusyBox: termios
  getters/setters, window size queries, foreground process-group access, and controlling TTY
  acquisition.

## Ownership and Lifetime
- A single global `TtyDevice` is exposed via `global_tty()`.
- VFS device nodes (`/dev/tty`, `/dev/console`) wrap the global device via `devfs` helper nodes.

## Future Work
- Separate line discipline logic once canonical-mode editing and signals are required.
- Replace the current foreground process-group tracking with full session/job-control checks once
  signal delivery is available.
