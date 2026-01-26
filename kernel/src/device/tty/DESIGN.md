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
- Control operations (`ControlOps`) implement the minimal ioctl set required by BusyBox: termios
  getters/setters and window size queries.

## Ownership and Lifetime
- A single global `TtyDevice` is exposed via `global_tty()`.
- VFS device nodes (`/dev/tty`, `/dev/console`) wrap the global device via `devfs` helper nodes.

## Future Work
- Separate line discipline logic once canonical-mode editing and signals are required.
- Integrate real process-group/session handling instead of the current placeholder pgrp state.
