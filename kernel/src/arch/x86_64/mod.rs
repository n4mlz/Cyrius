pub mod bus;
pub mod interrupt;
pub mod mem;
mod trap;

use bootloader_api::BootInfo;

use crate::arch::api::{
    ArchDevice, ArchInterrupt, ArchMemory, ArchPlatform, ArchTrap, HeapRegionError,
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
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()> {
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
        interrupt::init(boot_info)
    }

    fn enable_interrupts() {
        interrupt::enable();
    }

    fn disable_interrupts() {
        interrupt::disable();
    }

    fn end_of_interrupt(vector: u8) {
        interrupt::end_of_interrupt(vector);
    }

    fn timer() -> &'static Self::Timer {
        interrupt::timer()
    }

    fn timer_vector() -> u8 {
        interrupt::TIMER_VECTOR
    }
}
