#![no_std]
#![no_main]
#![feature(trait_alias, sync_unsafe_cell, alloc_error_handler)]
#![cfg_attr(test, feature(custom_test_frameworks))]
#![cfg_attr(test, reexport_test_harness_main = "test_main")]
#![cfg_attr(test, test_runner(crate::test::run_tests))]

extern crate alloc;

use core::convert::TryFrom;
use core::panic::PanicInfo;

pub mod arch;
pub mod demo;
pub mod device;
pub mod interrupt;
pub mod mem;
pub mod process;
pub mod syscall;
#[cfg(test)]
pub mod test;
pub mod thread;
pub mod trap;
pub mod util;

use crate::arch::{
    Arch,
    api::{ArchDevice, ArchMemory},
};
#[cfg(not(test))]
use crate::demo::linux_box::spawn_shell_thread;
use crate::device::char::uart::Uart;
use crate::interrupt::{INTERRUPTS, SYSTEM_TIMER, TimerTicks};
use crate::mem::addr::{AddrRange, PhysAddr};
use crate::mem::allocator;
use crate::mem::manager;
use crate::thread::SCHEDULER;
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

    let phys_offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .unwrap_or_else(|| panic!("bootloader did not provide a physical memory offset"));

    let heap_reserved = AddrRange {
        start: PhysAddr::new(
            usize::try_from(
                (heap_range.start.as_raw() as u64)
                    .checked_sub(phys_offset)
                    .unwrap_or_else(|| panic!("heap start below physical mapping")),
            )
            .unwrap_or_else(|_| panic!("heap start exceeds usize")),
        ),
        end: PhysAddr::new(
            usize::try_from(
                (heap_range.end.as_raw() as u64)
                    .checked_sub(phys_offset)
                    .unwrap_or_else(|| panic!("heap end below physical mapping")),
            )
            .unwrap_or_else(|_| panic!("heap end exceeds usize")),
        ),
    };

    allocator::init_heap(heap_range)
        .unwrap_or_else(|err| panic!("failed to initialise kernel heap: {err:?}"));

    let info: &'static BootInfo = &*boot_info;
    let reserved = [heap_reserved];
    manager::init(info, &reserved)
        .unwrap_or_else(|err| panic!("failed to initialise memory manager: {err:?}"));

    INTERRUPTS
        .init(boot_info)
        .unwrap_or_else(|err| panic!("failed to initialise interrupts: {err:?}"));

    SYSTEM_TIMER
        .start_periodic(SYSTEM_TIMER_TICKS)
        .unwrap_or_else(|err| panic!("failed to initialise system timer: {err:?}"));

    crate::syscall::init();

    INTERRUPTS.enable();
}

fn initialise_scheduler() {
    SCHEDULER
        .init()
        .unwrap_or_else(|err| panic!("failed to initialise scheduler: {err:?}"));

    // SCHEDULER
    //     .spawn_kernel_thread("worker-a", scheduler_worker_a)
    //     .unwrap_or_else(|err| panic!("failed to spawn worker-a: {err:?}"));

    // SCHEDULER
    //     .spawn_kernel_thread("worker-b", scheduler_worker_b)
    //     .unwrap_or_else(|err| panic!("failed to spawn worker-b: {err:?}"));

    #[cfg(not(test))]
    spawn_shell_thread();

    SCHEDULER
        .start()
        .unwrap_or_else(|err| panic!("failed to start scheduler: {err:?}"));
}

// fn scheduler_worker_a() -> ! {
//     scheduler_worker_loop("worker-a", 'A')
// }

// fn scheduler_worker_b() -> ! {
//     scheduler_worker_loop("worker-b", 'B')
// }

// fn scheduler_worker_loop(name: &'static str, token: char) -> ! {
//     const PRINT_INTERVAL: u64 = 1_000_000;
//     let mut counter: u64 = 0;
//     loop {
//         if counter.is_multiple_of(PRINT_INTERVAL) {
//             let epoch = counter / PRINT_INTERVAL;
//             println!("[{name}] heartbeat {token}#{epoch}");
//         }
//         counter = counter.wrapping_add(1);
//         core::hint::spin_loop();
//     }
// }

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
        process::PROCESS_TABLE,
        test::kernel_test_case,
        thread::SCHEDULER,
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

    static TEST_KERNEL_THREAD_COUNTER: AtomicU32 = AtomicU32::new(0);
    static TEST_EXTRA_THREAD_COUNTER: AtomicU32 = AtomicU32::new(0);

    #[kernel_test_case]
    fn scheduler_switches_threads() {
        TEST_KERNEL_THREAD_COUNTER.store(0, Ordering::Relaxed);
        TEST_EXTRA_THREAD_COUNTER.store(0, Ordering::Relaxed);

        SCHEDULER.init().expect("scheduler initialisation failed");

        let kernel_pid = PROCESS_TABLE
            .kernel_process_id()
            .expect("kernel process not initialised");

        let extra_pid = PROCESS_TABLE
            .create_kernel_process("test-process")
            .expect("create extra process");

        SCHEDULER
            .spawn_kernel_thread("test-worker-kernel", scheduler_test_kernel_thread)
            .expect("spawn kernel thread");
        SCHEDULER
            .spawn_kernel_thread_for_process(
                extra_pid,
                "test-worker-extra",
                scheduler_test_extra_thread,
            )
            .expect("spawn extra process thread");

        SCHEDULER.start().expect("start scheduler");

        const TARGET: u32 = 32;
        let mut spins: u64 = 0;
        while (TEST_KERNEL_THREAD_COUNTER.load(Ordering::Relaxed) < TARGET
            || TEST_EXTRA_THREAD_COUNTER.load(Ordering::Relaxed) < TARGET)
            && spins < 5_000_000
        {
            spins = spins.wrapping_add(1);
            core::hint::spin_loop();
        }

        let kernel_iters = TEST_KERNEL_THREAD_COUNTER.load(Ordering::Relaxed);
        let extra_iters = TEST_EXTRA_THREAD_COUNTER.load(Ordering::Relaxed);
        assert!(
            kernel_iters >= TARGET,
            "kernel thread observed {kernel_iters} iterations"
        );
        assert!(
            extra_iters >= TARGET,
            "extra thread observed {extra_iters} iterations"
        );

        let kernel_threads = PROCESS_TABLE
            .thread_count(kernel_pid)
            .expect("kernel process missing");
        let extra_threads = PROCESS_TABLE
            .thread_count(extra_pid)
            .expect("extra process missing");
        assert!(
            kernel_threads >= 3,
            "kernel process thread count {kernel_threads} < 3"
        );
        assert_eq!(
            extra_threads, 1,
            "extra process thread count {extra_threads} != 1"
        );

        SCHEDULER.shutdown();

        SYSTEM_TIMER
            .start_periodic(super::SYSTEM_TIMER_TICKS)
            .expect("failed to restart system timer after scheduler test");
        INTERRUPTS.enable();
    }

    fn scheduler_test_kernel_thread() -> ! {
        scheduler_test_worker_loop(&TEST_KERNEL_THREAD_COUNTER)
    }

    fn scheduler_test_extra_thread() -> ! {
        scheduler_test_worker_loop(&TEST_EXTRA_THREAD_COUNTER)
    }

    fn scheduler_test_worker_loop(counter: &'static AtomicU32) -> ! {
        loop {
            counter.fetch_add(1, Ordering::Relaxed);
            core::hint::spin_loop();
        }
    }
}
