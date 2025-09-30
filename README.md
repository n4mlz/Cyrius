## Setup

```sh
rustup install nightly
rustup component add llvm-tools-preview
rustup target add x86_64-unknown-none
```

## Usage

- `cargo xtask run`: Builds the kernel and starts QEMU.
- `cargo xtask test`: Builds and runs all tests.
- `cargo xtask test --list`: Displays only the list of test cases.
- `cargo xtask test --name foo`: Runs tests whose names contain `foo` (function name or module name).
- `cargo xtask test --no-run`: Only generates the test binary.

All commands can be combined with `--release`.
