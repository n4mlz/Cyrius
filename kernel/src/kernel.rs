#![no_std]
#![no_main]
#![feature(trait_alias, sync_unsafe_cell, alloc_error_handler)]
#![cfg_attr(test, feature(custom_test_frameworks))]
#![cfg_attr(test, reexport_test_harness_main = "test_main")]
#![cfg_attr(test, test_runner(crate::test::run_tests))]

extern crate alloc;

pub mod arch;
pub mod device;
pub mod interrupt;
pub mod mem;
#[cfg(test)]
pub mod test;
pub mod trap;
pub mod util;

use core::{arch::asm, panic::PanicInfo};

use crate::arch::{
    Arch,
    api::{ArchDevice, ArchMemory},
};
use crate::interrupt::TimerTicks;
use crate::mem::allocator;
use bootloader_api::{
    BootInfo,
    config::{BootloaderConfig, Mapping},
    entry_point,
};

const BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

const SYSTEM_TIMER_TICKS: TimerTicks = TimerTicks::new(10_000_000);

#[cfg(not(test))]
entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

#[cfg(test)]
entry_point!(test_kernel_main, config = &BOOTLOADER_CONFIG);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    init_runtime(boot_info);
    println!("Hello, world!");

    // Trigger a breakpoint exception
    unsafe {
        asm!("int3");
    }

    loop {
        core::hint::spin_loop()
    }
}

#[cfg(test)]
fn test_kernel_main(boot_info: &'static mut BootInfo) -> ! {
    init_runtime(boot_info);
    test_main();
    test::exit_qemu(test::QemuExitCode::Success)
}

fn init_runtime(boot_info: &'static mut BootInfo) {
    Arch::console().init();

    let heap_range = {
        let info: &'static BootInfo = &*boot_info;
        <Arch as ArchMemory>::locate_kernel_heap(info)
            .unwrap_or_else(|err| panic!("failed to locate kernel heap: {err:?}"))
    };

    allocator::init_heap(heap_range)
        .unwrap_or_else(|err| panic!("failed to initialise kernel heap: {err:?}"));

    interrupt::init(boot_info)
        .unwrap_or_else(|err| panic!("failed to initialise interrupts: {err:?}"));

    trap::init();

    interrupt::init_system_timer(SYSTEM_TIMER_TICKS)
        .unwrap_or_else(|err| panic!("failed to initialise system timer: {err:?}"));

    interrupt::enable();
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("panic: {}", info.message());

    if let Some(location) = info.location() {
        println!(
            "at file '{}' line {} column {}",
            location.file(),
            location.line(),
            location.column()
        );
    }

    loop {
        core::hint::spin_loop()
    }
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[test] panic: {}", info);
    test::exit_qemu(test::QemuExitCode::Failed)
}

#[cfg(test)]
mod tests {
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn test1() {
        assert_eq!(1, 1);
    }

    #[kernel_test_case]
    fn test2() {
        assert_eq!(2, 2);
    }
}
