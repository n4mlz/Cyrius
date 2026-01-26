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

/// Control-plane error for device/file management operations (ioctl-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// The operation is not supported by the target.
    Unsupported,
    /// The provided argument or command is invalid.
    Invalid,
    /// User-provided memory could not be accessed.
    BadAddress,
}

/// Abstraction over user memory access for control operations.
pub trait ControlAccess {
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), ControlError>;
    fn write(&self, addr: u64, src: &[u8]) -> Result<(), ControlError>;
}

/// A control request routed to a file/device.
pub struct ControlRequest<'a> {
    pub command: u64,
    pub arg: u64,
    pub access: &'a dyn ControlAccess,
}

impl<'a> ControlRequest<'a> {
    pub fn new(command: u64, arg: u64, access: &'a dyn ControlAccess) -> Self {
        Self {
            command,
            arg,
            access,
        }
    }

    pub fn read_bytes(&self, dst: &mut [u8]) -> Result<(), ControlError> {
        if dst.is_empty() {
            return Ok(());
        }
        self.access.read(self.arg, dst)
    }

    pub fn write_bytes(&self, src: &[u8]) -> Result<(), ControlError> {
        if src.is_empty() {
            return Ok(());
        }
        self.access.write(self.arg, src)
    }

    pub fn read_struct<T: Copy>(&self) -> Result<T, ControlError> {
        use core::mem::MaybeUninit;

        let mut value = MaybeUninit::<T>::uninit();
        let dst = unsafe {
            core::slice::from_raw_parts_mut(
                value.as_mut_ptr() as *mut u8,
                core::mem::size_of::<T>(),
            )
        };
        self.read_bytes(dst)?;
        Ok(unsafe { value.assume_init() })
    }

    pub fn write_struct<T: Copy>(&self, value: &T) -> Result<(), ControlError> {
        let src = unsafe {
            core::slice::from_raw_parts(value as *const T as *const u8, core::mem::size_of::<T>())
        };
        self.write_bytes(src)
    }
}

/// Control-plane operations for character devices and special files.
pub trait ControlOps {
    fn control(&self, request: &ControlRequest<'_>) -> Result<u64, ControlError>;
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
