pub trait ArchPlatform {
    fn name() -> &'static str;

    /// platform-specific initialization
    ///
    /// After executing this function, we expect the BSS to be initialized and the stack pointer to be properly set.
    fn init();
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}
