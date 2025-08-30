#![no_std]
#![no_main]
#![feature(trait_alias, pointer_is_aligned_to)]

pub mod arch;
pub mod device;
pub mod mem;
pub mod util;

use bootloader_api::{BootInfo, entry_point};
use core::panic::PanicInfo;

use crate::arch::{Arch, api::ArchPlatform};

entry_point!(kernel_main);

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    Arch::init();
    println!("Hello, world!");
    loop {
        core::hint::spin_loop()
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    println!("panic!");
    loop {
        core::hint::spin_loop()
    }
}
