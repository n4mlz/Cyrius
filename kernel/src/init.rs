use core::convert::TryFrom;

use bootloader_api::BootInfo;

use crate::arch::{
    Arch,
    api::{ArchDevice, ArchMemory},
};
use crate::device::char::uart::Uart;
use crate::device::probe;
use crate::fs::init::init_filesystems;
use crate::interrupt::{DEFAULT_SYSTEM_TIMER_TICKS, INTERRUPTS, SYSTEM_TIMER};
use crate::mem::addr::{AddrRange, PhysAddr};
use crate::mem::{allocator, manager};
use crate::thread::SCHEDULER;

pub fn init_runtime(boot_info: &'static mut BootInfo) {
    Arch::console()
        .init()
        .unwrap_or_else(|err| panic!("failed to initialise console: {err:?}"));

    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::init_cpu_features();
    }

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

    crate::arch::x86_64::syscall::init()
        .unwrap_or_else(|err| panic!("failed to initialise syscalls: {err:?}"));

    SYSTEM_TIMER
        .start_periodic(DEFAULT_SYSTEM_TIMER_TICKS)
        .unwrap_or_else(|err| panic!("failed to initialise system timer: {err:?}"));

    INTERRUPTS.enable();

    let discovered_blocks = probe::probe_block_devices();
    if discovered_blocks > 0 {
        crate::println!("[blk] discovered {discovered_blocks} virtio block device(s)",);
    }

    init_filesystems();
}

pub fn initialise_scheduler() {
    SCHEDULER
        .init()
        .unwrap_or_else(|err| panic!("failed to initialise scheduler: {err:?}"));

    init_shell();

    SCHEDULER
        .start()
        .unwrap_or_else(|err| panic!("failed to start scheduler: {err:?}"));
}

fn init_shell() {
    if let Err(err) = crate::kernel_proc::shell::spawn_shell() {
        crate::println!("[shell] failed to start shell: {err:?}");
    }
}
