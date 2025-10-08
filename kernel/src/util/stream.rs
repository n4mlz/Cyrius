use core::fmt::Debug;

/// Generic byte-stream error that captures transport failures and abstract I/O issues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError<E: Debug> {
    /// Underlying transport (e.g. MMIO/PIO bus) reported an error.
    Transport(E),
    /// The device would block when configured for non-blocking operation.
    WouldBlock,
    /// The requested operation is not supported by the device.
    Unsupported,
}

impl<E: Debug> StreamError<E> {
    /// Wrap a transport error value.
    pub fn transport(err: E) -> Self {
        Self::Transport(err)
    }
}

/// Read-only byte stream abstraction.
pub trait ReadOps {
    type Error: Debug;

    fn read(&self, buffer: &mut [u8]) -> Result<usize, Self::Error>;
}

/// Write-only byte stream abstraction.
pub trait WriteOps {
    type Error: Debug;

    fn write(&self, buffer: &[u8]) -> Result<usize, Self::Error>;
}
