pub mod boot;
pub mod bus;

use bootloader_api::BootInfo as X86EarlyInput;

use crate::arch::api::{ArchDevice, ArchPlatform};
use crate::boot::BootInfo;
use crate::device::char::uart::ns16550::Ns16550;

use self::bus::Pio;

pub struct X86_64;

#[derive(Copy, Clone, Debug)]
pub struct X86BootInfo {
    pub recursive_index: Option<u16>,
}

impl ArchPlatform for X86_64 {
    type ArchEarlyInput = &'static mut X86EarlyInput;
    type ArchBootInfo = X86BootInfo;

    fn name() -> &'static str {
        "x86_64"
    }

    unsafe fn build_boot_info(input: Self::ArchEarlyInput) -> BootInfo<Self::ArchBootInfo> {
        unsafe { boot::build_boot_info(input) }
    }

    fn init(_boot_info: &BootInfo<Self::ArchBootInfo>) {
        X86_64::console().init();
    }
}

impl ArchDevice for X86_64 {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()> {
        static UART0: Ns16550<u8, Pio> = Ns16550::new(Pio::new(0x3F8), "kernel-console");
        &UART0
    }
}
