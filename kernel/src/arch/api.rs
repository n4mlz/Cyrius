use crate::mem::segment::KernelSegments;

pub trait ArchPlatform {
    fn name() -> &'static str;
    fn init();
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}

pub trait ArchBootInfo {
    fn kernel_segments() -> &'static KernelSegments;
}
