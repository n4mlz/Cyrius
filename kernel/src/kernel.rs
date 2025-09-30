#![no_std]
#![no_main]
#![feature(trait_alias, sync_unsafe_cell, alloc_error_handler)]
#![cfg_attr(test, feature(custom_test_frameworks))]
#![cfg_attr(test, reexport_test_harness_main = "test_main")]
#![cfg_attr(test, test_runner(crate::test::run_tests))]

extern crate alloc;

pub mod arch;
pub mod device;
pub mod mem;
#[cfg(test)]
pub mod test;
pub mod trap;
pub mod util;

use core::{arch::asm, panic::PanicInfo};

use crate::arch::{Arch, api::ArchDevice};
use bootloader_api::{BootInfo, entry_point};

#[cfg(not(test))]
entry_point!(kernel_main);

#[cfg(test)]
entry_point!(test_kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    Arch::console().init();

    if let Err(err) = mem::init(boot_info) {
        panic!("memory init failed: {:?}", err);
    }

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

#[cfg(test)]
fn test_kernel_main(boot_info: &'static mut BootInfo) -> ! {
    Arch::console().init();

    if let Err(err) = mem::init(boot_info) {
        panic!("memory init failed: {:?}", err);
    }

    trap::init();
    test_main();
    test::exit_qemu(test::QemuExitCode::Success)
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
