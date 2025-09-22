#![no_std]
#![no_main]
#![feature(
    trait_alias,
    pointer_is_aligned_to,
    sync_unsafe_cell,
    alloc_error_handler
)]

pub mod arch;
pub mod boot;
pub mod device;
pub mod mem;
pub mod util;

extern crate alloc;

use core::panic::PanicInfo;

use crate::arch::{Arch, api::ArchPlatform};
use crate::boot::BootInfo;

/// The main entry point for the kernel after architecture specific initialization is complete.
/// This function should be called after constructing the architecture-abstracted BootInfo structure.
fn kernel_main(boot_info: BootInfo<<Arch as ArchPlatform>::ArchBootInfo>) -> ! {
    Arch::init(&boot_info);
    mem::alloc::init_default_heap();
    heap_allocation_test();
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

fn heap_allocation_test() {
    use alloc::{boxed::Box, vec::Vec};

    let mut data = Vec::with_capacity(32);
    for i in 0..32 {
        data.push(i);
    }

    let checksum: u64 = data.iter().map(|&v| v as u64).sum();
    let boxed = Box::new(checksum);

    println!("heap test checksum={} boxed={:?}", checksum, boxed);

    match mem::alloc::heap_stats() {
        Some(stats) => println!(
            "start={:?} next={:?} end={:?}",
            stats.start, stats.next, stats.end
        ),
        None => println!("heap not initialized"),
    }
}
