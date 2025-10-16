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
pub mod process;
#[cfg(test)]
pub mod test;
pub mod trap;
pub mod util;

use core::panic::PanicInfo;

use crate::arch::{
    Arch,
    api::{ArchDevice, ArchMemory},
};
use crate::device::char::uart::Uart;
use crate::interrupt::{INTERRUPTS, SYSTEM_TIMER, TimerTicks};
use crate::process::SCHEDULER;
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
    initialise_scheduler();

    println!("[kernel] scheduler started");

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

fn initialise_scheduler() {
    SCHEDULER
        .init()
        .unwrap_or_else(|err| panic!("failed to initialise scheduler: {err:?}"));

    SCHEDULER
        .spawn_kernel_thread("worker-a", scheduler_worker_a)
        .unwrap_or_else(|err| panic!("failed to spawn worker-a: {err:?}"));

    SCHEDULER
        .spawn_kernel_thread("worker-b", scheduler_worker_b)
        .unwrap_or_else(|err| panic!("failed to spawn worker-b: {err:?}"));

    SCHEDULER
        .start()
        .unwrap_or_else(|err| panic!("failed to start scheduler: {err:?}"));
}

fn scheduler_worker_a() -> ! {
    scheduler_worker_loop("worker-a", 'A')
}

fn scheduler_worker_b() -> ! {
    scheduler_worker_loop("worker-b", 'B')
}

fn scheduler_worker_loop(name: &'static str, token: char) -> ! {
    const PRINT_INTERVAL: u64 = 1_000_000;
    let mut counter: u64 = 0;
    loop {
        if counter % PRINT_INTERVAL == 0 {
            let epoch = counter / PRINT_INTERVAL;
            println!("[{name}] heartbeat {token}#{epoch}");
        }
        counter = counter.wrapping_add(1);
        core::hint::spin_loop();
    }
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
    use core::sync::atomic::{AtomicU32, Ordering};

    use crate::{
        interrupt::{INTERRUPTS, SYSTEM_TIMER, TimerTicks},
        process::SCHEDULER,
        test::kernel_test_case,
    };

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

    static TEST_WORKER_A_COUNTER: AtomicU32 = AtomicU32::new(0);
    static TEST_WORKER_B_COUNTER: AtomicU32 = AtomicU32::new(0);

    #[kernel_test_case]
    fn scheduler_switches_tasks() {
        TEST_WORKER_A_COUNTER.store(0, Ordering::Relaxed);
        TEST_WORKER_B_COUNTER.store(0, Ordering::Relaxed);

        SCHEDULER
            .init()
            .expect("scheduler initialisation failed");

        SCHEDULER
            .spawn_kernel_thread("test-worker-a", scheduler_test_worker_a)
            .expect("spawn worker a");
        SCHEDULER
            .spawn_kernel_thread("test-worker-b", scheduler_test_worker_b)
            .expect("spawn worker b");

        SCHEDULER.start().expect("start scheduler");

        const TARGET: u32 = 32;
        let mut spins: u64 = 0;
        while (TEST_WORKER_A_COUNTER.load(Ordering::Relaxed) < TARGET
            || TEST_WORKER_B_COUNTER.load(Ordering::Relaxed) < TARGET)
            && spins < 5_000_000
        {
            spins = spins.wrapping_add(1);
            core::hint::spin_loop();
        }

        let worker_a = TEST_WORKER_A_COUNTER.load(Ordering::Relaxed);
        let worker_b = TEST_WORKER_B_COUNTER.load(Ordering::Relaxed);
        assert!(worker_a >= TARGET, "worker-a observed {worker_a} iterations");
        assert!(worker_b >= TARGET, "worker-b observed {worker_b} iterations");

        SCHEDULER.shutdown();

        SYSTEM_TIMER
            .start_periodic(super::SYSTEM_TIMER_TICKS)
            .expect("failed to restart system timer after scheduler test");
        INTERRUPTS.enable();
    }

    fn scheduler_test_worker_a() -> ! {
        scheduler_test_worker_loop(&TEST_WORKER_A_COUNTER)
    }

    fn scheduler_test_worker_b() -> ! {
        scheduler_test_worker_loop(&TEST_WORKER_B_COUNTER)
    }

    fn scheduler_test_worker_loop(counter: &'static AtomicU32) -> ! {
        loop {
            counter.fetch_add(1, Ordering::Relaxed);
            core::hint::spin_loop();
        }
    }
}
