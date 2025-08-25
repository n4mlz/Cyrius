pub mod bus;

use crate::arch::api::{ArchDevice, ArchPlatform};
use crate::arch::x86_64::bus::Pio;
use crate::device::char::uart::ns16550::Ns16550;

pub struct X86_64;

impl ArchPlatform for X86_64 {
    fn name() -> &'static str {
        "x86_64"
    }

    fn init() {
        X86_64::console().init();
    }
}

impl ArchDevice for X86_64 {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()> {
        static UART0: Ns16550<u8, Pio> = Ns16550::new(Pio::new(0x3F8), "kernel-console");
        &UART0
    }
}
