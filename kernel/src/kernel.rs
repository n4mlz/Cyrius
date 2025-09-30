#![no_std]
#![no_main]
#![feature(trait_alias, sync_unsafe_cell)]

pub mod arch;
pub mod device;
pub mod mem;
pub mod trap;
pub mod util;

use core::{arch::asm, panic::PanicInfo};

use bootloader_api::{BootInfo, entry_point};

entry_point!(kernel_main);

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    trap::init();
    println!("Hello, world!");

    // Trigger a breakpoint exception
    unsafe {
        asm!("int3");
    }

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
