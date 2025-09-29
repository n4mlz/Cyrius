pub trait ArchPlatform {
    fn name() -> &'static str;
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}
