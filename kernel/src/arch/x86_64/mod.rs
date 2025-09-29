pub mod bus;

use crate::arch::api::{ArchDevice, ArchPlatform};
use crate::device::char::uart::ns16550::Ns16550;

use self::bus::Pio;

pub struct X86_64;

impl ArchPlatform for X86_64 {
    fn name() -> &'static str {
        "x86_64"
    }
}

impl ArchDevice for X86_64 {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()> {
        static UART0: Ns16550<u8, Pio> = Ns16550::new(Pio::new(0x3F8), "kernel-console");
        &UART0
    }
}
