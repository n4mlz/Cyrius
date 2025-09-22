#![no_std]
#![no_main]
#![feature(trait_alias, pointer_is_aligned_to, sync_unsafe_cell)]

pub mod arch;
pub mod boot;
pub mod device;
pub mod mem;
pub mod util;

use core::panic::PanicInfo;

use crate::arch::{Arch, api::ArchPlatform};
use crate::boot::BootInfo;

fn kernel_main(boot_info: BootInfo<'static, <Arch as ArchPlatform>::ArchBootInfo>) -> ! {
    Arch::late_init(&boot_info);
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
