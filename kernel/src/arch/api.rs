pub trait ArchPlatform {
    fn name() -> &'static str;
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}

pub trait ArchTrap {
    type Frame: crate::trap::TrapFrame;

    fn init_traps();
}
