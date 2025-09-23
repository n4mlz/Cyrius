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
pub mod trap;
pub mod util;

extern crate alloc;

use core::panic::PanicInfo;

use crate::arch::{Arch, api::ArchPlatform};
use crate::boot::BootInfo;
use crate::mem::alloc::KernelHeap;

/// The main entry point for the kernel after architecture specific initialization is complete.
/// This function should be called after constructing the architecture-abstracted BootInfo structure.
///
/// # Invariant
/// Architecture-specific bootstrap, including MMU setup and heap mapping, must be complete before
/// invoking this function so that all architectures enter with a consistent virtual memory layout.
fn kernel_main(_boot_info: BootInfo<<Arch as ArchPlatform>::ArchBootInfo>) -> ! {
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

    match KernelHeap::global().stats() {
        Some(stats) => println!(
            "phys={:?} virt={:?} next={:?}",
            stats.phys, stats.virt, stats.next
        ),
        None => println!("heap not initialized"),
    }
}
