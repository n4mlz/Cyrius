#![no_std]
#![no_main]
#![feature(trait_alias, sync_unsafe_cell)]

pub mod arch;
pub mod device;
pub mod mem;
pub mod util;

use core::panic::PanicInfo;

use bootloader_api::{BootInfo, entry_point};

entry_point!(kernel_main);

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
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
