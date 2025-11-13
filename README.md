## Setup

```sh
rustup install nightly
rustup component add llvm-tools-preview
rustup target add x86_64-unknown-none
```

## Usage

- `cargo xtask run`: Builds the kernel and starts QEMU.
- `cargo xtask test`: Builds and runs all tests.
- `cargo xtask test --no-run`: Only generates the test binary.

All commands can be combined with --release.

## Linux Box Demo

Booting via `cargo xtask run` drops you into the ad-hoc Linux Box shell on the serial console. The
prompt is `OS>` and currently understands the following commands:

```
OS> linux-box ls
#=> NAME    TYPE    STATE   CMD
#   demo1   linux   ready   ./demo1.elf
#   demo2   linux   ready   ./demo2.elf

OS> linux-box run --policy=minimal demo1
step1: hello
[ctr 1] denied: getpid

OS> linux-box run --policy=full demo1
step1: hello
step2: pid=1
step3: done
```

The `--policy` flag selects the syscall filter applied to the container (`minimal` only allows
`write`/`exit`, while `full` currently allows every implemented Linux syscall). Omitting the flag
falls back to each demo's default policy.
