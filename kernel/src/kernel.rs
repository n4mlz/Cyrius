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
use crate::device::char::uart::Uart;
use crate::interrupt::{INTERRUPTS, SYSTEM_TIMER, TimerTicks};
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
    Arch::console()
        .init()
        .unwrap_or_else(|err| panic!("failed to initialise console: {err:?}"));

    let heap_range = {
        let info: &'static BootInfo = &*boot_info;
        <Arch as ArchMemory>::locate_kernel_heap(info)
            .unwrap_or_else(|err| panic!("failed to locate kernel heap: {err:?}"))
    };

    allocator::init_heap(heap_range)
        .unwrap_or_else(|err| panic!("failed to initialise kernel heap: {err:?}"));

    INTERRUPTS
        .init(boot_info)
        .unwrap_or_else(|err| panic!("failed to initialise interrupts: {err:?}"));

    SYSTEM_TIMER
        .start_periodic(SYSTEM_TIMER_TICKS)
        .unwrap_or_else(|err| panic!("failed to initialise system timer: {err:?}"));

    INTERRUPTS.enable();
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

    #[kernel_test_case]
    fn lapic_timer_fires() {
        use crate::interrupt::{SYSTEM_TIMER, TimerTicks};
        use core::arch::x86_64::_rdtsc;

        const TSC_TIMEOUT_CYCLES: u64 = 500_000_000; // ~0.1-0.5s depending on host frequency
        const HLT_STRIDE: u32 = 128;

        let _ = SYSTEM_TIMER.stop();
        SYSTEM_TIMER
            .start_periodic(TimerTicks::new(200_000))
            .expect("failed to reconfigure timer for test");

        x86_64::instructions::interrupts::enable();

        let start_ticks = SYSTEM_TIMER.observed_ticks();
        let start_tsc = unsafe { _rdtsc() };
        let mut polls: u32 = 0;

        loop {
            if SYSTEM_TIMER.observed_ticks() > start_ticks {
                SYSTEM_TIMER.stop().ok();
                SYSTEM_TIMER
                    .start_periodic(super::SYSTEM_TIMER_TICKS)
                    .expect("failed to restore system timer configuration");
                return;
            }

            let elapsed = unsafe { _rdtsc().wrapping_sub(start_tsc) };
            if elapsed > TSC_TIMEOUT_CYCLES {
                SYSTEM_TIMER.stop().ok();
                panic!("APIC timer did not tick before timeout (elapsed cycles={elapsed})");
            }

            polls = polls.wrapping_add(1);
            if polls.is_multiple_of(HLT_STRIDE) {
                x86_64::instructions::hlt();
            } else {
                core::hint::spin_loop();
            }
        }
    }
}
