//! Syscall ABI glue shared across host and Linux guests.

/// Execution profile that determines which syscall table to consult for a thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiFlavor {
    Host,
    Linux,
}

impl AbiFlavor {
    pub const fn is_linux(self) -> bool {
        matches!(self, Self::Linux)
    }
}

/// Minimal Seccomp-like policy gates for demo purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallPolicy {
    Minimal,
    Full,
}

impl SyscallPolicy {
    pub const fn default() -> Self {
        Self::Minimal
    }
}
