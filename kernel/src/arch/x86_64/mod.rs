pub mod bus;
pub mod interrupt;
pub mod mem;
mod process;
mod trap;

use bootloader_api::BootInfo;

use crate::arch::api::{
    ArchDevice, ArchInterrupt, ArchMemory, ArchPlatform, ArchProcess, ArchTrap, HeapRegionError,
    InterruptInitError,
};
use crate::device::char::uart::ns16550::Ns16550;
use crate::mem::addr::{AddrRange, VirtAddr};

use self::bus::Pio;

pub struct X86_64;

impl ArchPlatform for X86_64 {
    fn name() -> &'static str {
        "x86_64"
    }
}

impl ArchDevice for X86_64 {
    type Console = Ns16550<u8, Pio>;

    fn console() -> &'static Self::Console {
        static UART0: Ns16550<u8, Pio> = Ns16550::new(Pio::new(0x3F8), "kernel-console");
        &UART0
    }
}

impl ArchTrap for X86_64 {
    type Frame = trap::TrapFrame;

    fn init_traps() {
        trap::init();
    }
}

impl ArchMemory for X86_64 {
    fn locate_kernel_heap(
        boot_info: &'static BootInfo,
    ) -> Result<AddrRange<VirtAddr>, HeapRegionError> {
        self::mem::locate_kernel_heap(boot_info)
    }
}

impl ArchInterrupt for X86_64 {
    type Timer = interrupt::LocalApicTimer;

    fn init_interrupts(boot_info: &'static BootInfo) -> Result<(), InterruptInitError> {
        interrupt::LOCAL_APIC.init(boot_info)
    }

    fn enable_interrupts() {
        interrupt::LOCAL_APIC.enable();
    }

    fn disable_interrupts() {
        interrupt::LOCAL_APIC.disable();
    }

    fn end_of_interrupt(vector: u8) {
        interrupt::LOCAL_APIC.end_of_interrupt(vector);
    }

    fn timer() -> &'static Self::Timer {
        interrupt::LOCAL_APIC.timer()
    }

    fn timer_vector() -> u8 {
        interrupt::TIMER_VECTOR
    }
}

impl ArchProcess for X86_64 {
    type Context = process::Context;
    type AddressSpace = process::AddressSpace;

    fn save_context(frame: &crate::trap::CurrentTrapFrame) -> Self::Context {
        process::Context::from_trap(frame)
    }

    unsafe fn restore_context(
        frame: &mut crate::trap::CurrentTrapFrame,
        ctx: &Self::Context,
    ) {
        process::Context::write_to_trap(ctx, frame);
    }

    fn bootstrap_kernel_context(entry: VirtAddr, stack_top: VirtAddr) -> Self::Context {
        process::Context::for_kernel(entry, stack_top)
    }

    fn current_address_space() -> Self::AddressSpace {
        process::AddressSpace::current()
    }

    unsafe fn activate_address_space(space: &Self::AddressSpace) {
        unsafe { process::AddressSpace::activate(space); }
    }
}
