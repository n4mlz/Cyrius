use crate::boot::BootInfo;

pub trait ArchPlatform {
    /// Information received from the bootloader
    type ArchEarlyInput;
    /// the architecture-specific portion of the information passed to the portable kernel core
    type ArchBootInfo;

    fn name() -> &'static str;

    /// Performs architecture specific early initialization.
    ///
    /// # Safety
    /// arch_early_init runs before Rust global invariants are established and may access raw pointers.
    unsafe fn arch_early_init(input: Self::ArchEarlyInput)
    -> BootInfo<'static, Self::ArchBootInfo>;

    /// Completes initialization once the portable kernel has taken over.
    fn late_init(boot_info: &BootInfo<'static, Self::ArchBootInfo>);
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}
