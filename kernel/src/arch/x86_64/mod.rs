pub mod boot;
pub mod bus;
pub mod mmu;
pub mod trap;

use bootloader_api::BootInfo as X86EarlyInput;

use crate::arch::api::{ArchDevice, ArchMmu, ArchPlatform};
use crate::boot::BootInfo;
use crate::device::char::uart::ns16550::Ns16550;

use self::bus::Pio;
use self::mmu::X86Mmu;
use self::trap::{X86TrapController, X86TrapFrame, controller as trap_controller};

pub struct X86_64;

#[derive(Copy, Clone, Debug)]
pub struct X86BootInfo {
    pub recursive_index: Option<u16>,
}

impl ArchPlatform for X86_64 {
    type ArchEarlyInput = &'static mut X86EarlyInput;
    type ArchBootInfo = X86BootInfo;
    type ArchMmu = X86Mmu;
    type TrapFrame = X86TrapFrame;
    type TrapController = X86TrapController;

    fn name() -> &'static str {
        "x86_64"
    }

    unsafe fn build_boot_info(input: Self::ArchEarlyInput) -> BootInfo<Self::ArchBootInfo> {
        unsafe { boot::build_boot_info(input) }
    }

    fn init(boot_info: &BootInfo<Self::ArchBootInfo>) {
        X86Mmu::instance()
            .early_init(boot_info)
            .expect("failed to initialize MMU");
        X86_64::console().init();
    }

    fn mmu() -> &'static Self::ArchMmu {
        X86Mmu::instance()
    }

    fn traps() -> &'static Self::TrapController {
        trap_controller()
    }
}

impl ArchDevice for X86_64 {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()> {
        static UART0: Ns16550<u8, Pio> = Ns16550::new(Pio::new(0x3F8), "kernel-console");
        &UART0
    }
}
