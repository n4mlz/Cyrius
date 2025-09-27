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
use crate::util::boot_display;

/// The main entry point for the kernel after architecture specific initialization is complete.
/// This function should be called after constructing the architecture-abstracted BootInfo structure.
fn kernel_main(boot_info: BootInfo<<Arch as ArchPlatform>::ArchBootInfo>) -> ! {
    Arch::late_init(&boot_info);
    boot_display::run_boot_display(&boot_info);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    println!("panic!");
    loop {
        core::hint::spin_loop()
    }
}
