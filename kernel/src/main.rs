#![no_std]
#![no_main]
#![feature(trait_alias)]

pub mod arch;
pub mod bus;
pub mod device;
pub mod util;

use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;

use crate::{
    arch::{
        api::{ArchDevice, ArchPlatform},
        Arch,
    },
    device::char::CharDevice,
};

entry_point!(kernel_main);

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    Arch::init();
    CharDevice::write(Arch::console(), b"Hello, world!\n");
    loop {
        core::hint::spin_loop()
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    CharDevice::write(Arch::console(), b"panic!\n");
    loop {
        core::hint::spin_loop()
    }
}
