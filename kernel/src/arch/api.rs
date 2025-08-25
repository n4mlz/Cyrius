pub trait ArchPlatform {
    fn name() -> &'static str;
    fn init();
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}
