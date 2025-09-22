use crate::boot::BootInfo;

pub trait ArchPlatform {
    /// Information received from the bootloader
    type ArchEarlyInput;
    /// the architecture-specific portion of the information passed to the portable kernel core
    type ArchBootInfo;

    fn name() -> &'static str;

    /// build a BootInfo object that abstracts away architecture-specific boot information.
    ///
    /// # Safety
    /// This function runs before Rust global invariants are established and may access raw pointers.
    unsafe fn build_boot_info(input: Self::ArchEarlyInput) -> BootInfo<Self::ArchBootInfo>;

    /// Called after the portable kernel has started to perform architecture-specific initialization.
    fn init(boot_info: &BootInfo<Self::ArchBootInfo>);
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}
